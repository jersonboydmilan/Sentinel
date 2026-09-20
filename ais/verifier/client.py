"""Control-plane side of the out-of-process verifier.

``RemoteVerifier`` owns the child process, speaks the signed protocol, and
**fails closed**: a crashed, hung, silent or unauthenticated verifier yields no
verification at all, which means containment policy stays at HOLD. There is no
path where losing the verifier makes containment easier.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from typing import Any

from . import protocol
from .reconstruction import export_records

REPOSITORY_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_TIMEOUT = 15.0


class VerifierUnavailable(RuntimeError):
    """Raised only by ``require_alive``; normal operation fails closed silently."""


@dataclass
class VerifierStats:
    spawned: int = 0
    requests: int = 0
    responses: int = 0
    failures: int = 0
    rejected_signatures: int = 0
    timeouts: int = 0
    last_error: str | None = None
    verifier_pid: int | None = None
    latencies_ms: list[float] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "spawned": self.spawned,
            "requests": self.requests,
            "responses": self.responses,
            "failures": self.failures,
            "rejected_signatures": self.rejected_signatures,
            "timeouts": self.timeouts,
            "last_error": self.last_error,
            "verifier_pid": self.verifier_pid,
            "mean_latency_ms": round(sum(self.latencies_ms) / len(self.latencies_ms), 3)
            if self.latencies_ms
            else None,
        }


class RemoteVerifier:
    """Spawns and drives ``python -m ais.verifier.service``."""

    def __init__(
        self,
        *,
        key: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        executable: str | None = None,
        cwd: str | None = None,
        auto_restart: bool = True,
    ) -> None:
        # The key is operator material: generated here, passed to the child in
        # its environment, and never exposed through a gateway request.
        self._key = key or secrets.token_hex(32)
        self._timeout = timeout
        self._executable = executable or sys.executable
        self._cwd = cwd or REPOSITORY_ROOT
        self._auto_restart = auto_restart
        self._disabled: str | None = None
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._counter = 0
        self.stats = VerifierStats()

    # -- lifecycle ---------------------------------------------------------
    @property
    def alive(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def pid(self) -> int | None:
        return self._process.pid if self._process is not None else None

    @property
    def disabled(self) -> str | None:
        return self._disabled

    def disable(self, reason: str = "verifier taken offline") -> None:
        """Simulate an outage: every call fails closed until ``enable()``.

        Used to test that losing verification loses *containment*, never gains
        it. Distinct from a crash, which the client is allowed to heal by
        respawning - a fresh verifier re-derives everything from the chain, so
        respawning cannot be used to launder a claim.
        """
        self._disabled = reason
        self.close()

    def enable(self) -> None:
        self._disabled = None

    def start(self) -> "RemoteVerifier":
        if self.alive:
            return self
        environment = dict(os.environ)
        environment["AIS_VERIFIER_KEY"] = self._key
        environment["PYTHONPATH"] = self._cwd + os.pathsep + environment.get("PYTHONPATH", "")
        environment.setdefault("PYTHONUNBUFFERED", "1")
        self._process = subprocess.Popen(
            [self._executable, "-m", "ais.verifier.service"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=self._cwd,
            env=environment,
        )
        self.stats.spawned += 1
        self.stats.verifier_pid = self._process.pid
        return self

    def close(self) -> None:
        if self._process is None:
            return
        if self.alive:
            try:
                self._send({"op": "shutdown", "version": protocol.PROTOCOL_VERSION})
                self._process.wait(timeout=2.0)
            except Exception:  # noqa: BLE001 - shutdown is best effort
                self._process.kill()
        for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
            try:
                if stream is not None:
                    stream.close()
            except Exception:  # noqa: BLE001
                pass
        self._process = None

    def __enter__(self) -> "RemoteVerifier":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.close()

    def require_alive(self) -> None:
        if not self.alive:
            raise VerifierUnavailable("verifier process is not running")

    # -- protocol ----------------------------------------------------------
    def _next_id(self) -> tuple[str, str]:
        self._counter += 1
        return f"VRQ-{self._counter:06d}", secrets.token_hex(8)

    def _send(self, payload: dict) -> None:
        assert self._process is not None and self._process.stdin is not None
        self._process.stdin.write(protocol.encode(protocol.signed(self._key, payload)) + "\n")
        self._process.stdin.flush()

    def _call(self, payload: dict) -> dict | None:
        """One signed round trip. Returns ``None`` on any failure (fail closed)."""
        import time

        with self._lock:
            if self._disabled:
                self.stats.failures += 1
                self.stats.last_error = self._disabled
                return None
            if not self.alive:
                if self._process is not None and not self._auto_restart:
                    self.stats.failures += 1
                    self.stats.last_error = "verifier process is not running and auto-restart is disabled"
                    return None
                restarting = self._process is not None
                self.start()
                if restarting:
                    self.stats.last_error = "verifier respawned after an unexpected exit"
            assert self._process is not None and self._process.stdout is not None

            started = time.perf_counter()
            watchdog = threading.Timer(self._timeout, self._on_timeout)
            watchdog.start()
            try:
                self._send(payload)
                line = self._process.stdout.readline()
            except (BrokenPipeError, ValueError, OSError) as exc:
                self.stats.failures += 1
                self.stats.last_error = f"transport:{exc}"
                return None
            finally:
                watchdog.cancel()

            self.stats.requests += 1
            if not line:
                self.stats.failures += 1
                self.stats.last_error = "verifier closed the connection"
                return None

            try:
                response = protocol.decode(line)
            except ValueError as exc:
                self.stats.failures += 1
                self.stats.last_error = f"malformed response: {exc}"
                return None

            if not protocol.verify_signature(self._key, response):
                self.stats.rejected_signatures += 1
                self.stats.last_error = "response signature mismatch"
                return None

            if response.get("request_id") != payload.get("request_id") or response.get("nonce") != payload.get("nonce"):
                self.stats.rejected_signatures += 1
                self.stats.last_error = "response does not answer this request (replay?)"
                return None

            self.stats.responses += 1
            self.stats.latencies_ms.append((time.perf_counter() - started) * 1000.0)
            return response

    def _on_timeout(self) -> None:
        self.stats.timeouts += 1
        self.stats.last_error = "verifier timed out"
        if self._process is not None and self._process.poll() is None:
            self._process.kill()

    # -- operations --------------------------------------------------------
    def ping(self) -> dict | None:
        request_id, nonce = self._next_id()
        return self._call({"op": "ping", "version": protocol.PROTOCOL_VERSION, "request_id": request_id, "nonce": nonce})

    def verify(
        self,
        *,
        audit,
        subject_id: str,
        claimed_classification: str,
        claimed_confidence: float,
        records: list[dict] | None = None,
        expected_head: str | None = None,
    ) -> dict | None:
        """Ask the separate process to reproduce the evidence for a claim."""
        request_id, nonce = self._next_id()
        chain = records if records is not None else export_records(audit)
        head = expected_head if expected_head is not None else audit.head_hash()
        request = protocol.VerifyRequest(
            request_id=request_id,
            nonce=nonce,
            subject_id=subject_id,
            claimed_classification=claimed_classification,
            claimed_confidence=claimed_confidence,
            expected_head=head,
            records=chain,
        )
        response = self._call(request.as_payload())
        if response is None:
            return None
        if response.get("op") == "error":
            self.stats.failures += 1
            self.stats.last_error = f"{response.get('reason')}: {response.get('detail')}"
            return None
        if response.get("subject_id") != subject_id:
            self.stats.rejected_signatures += 1
            self.stats.last_error = "verdict is about a different subject"
            return None
        return response

    def stderr_tail(self, limit: int = 400) -> str:
        if self._process is None or self._process.stderr is None:
            return ""
        try:
            return (self._process.stderr.read() or "")[-limit:]
        except Exception:  # noqa: BLE001
            return ""
