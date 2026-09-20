"""SENTINEL-AUDIT-REMOTE - verification in a separate OS process.

The in-process auditors are logically independent: they read only the audit
chain. This one is *physically* independent. It ships the serialised chain to a
child process that holds no reference to the control plane, and accepts the
verdict only if the response is signed with the operator-established key, is a
reply to this exact request, and reports the chain as intact.

Failure is closed. A crashed, hung, or unauthenticated verifier yields no
verification, and every containment policy that needs one stays at HOLD.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..immune_system.verification import Verification
from ..verifier.client import RemoteVerifier
from ..verifier.reconstruction import export_records
from .base import DefensiveAgent
from .detector import Flag


@dataclass(frozen=True)
class RemoteVerificationFailure:
    subject_id: str
    reason: str

    def as_dict(self) -> dict:
        return {"subject": self.subject_id, "reason": self.reason}


class SentinelAuditRemote(DefensiveAgent):
    NAME = "SENTINEL-AUDIT-REMOTE"
    DECLARED_CAPABILITIES = ("agent.observe", "agent.analyze", "immune.read")
    PURPOSE = "verify evidence from a separate process, using the audit chain alone"

    def __init__(self, plane, observatory, immune, *, verifier: RemoteVerifier | None = None, timeout: float = 15.0) -> None:
        super().__init__(plane, observatory, immune)
        self.verifier = verifier or RemoteVerifier(timeout=timeout)
        self.failures: list[RemoteVerificationFailure] = []
        self._chain_cache: tuple[int, list[dict], str] | None = None

    # -- chain export ------------------------------------------------------
    def _chain(self) -> tuple[list[dict], str]:
        """Export the chain once per audit length, not once per subject."""
        length = len(self.plane.audit)
        if self._chain_cache is not None and self._chain_cache[0] == length:
            return self._chain_cache[1], self._chain_cache[2]
        records = export_records(self.plane.audit)
        head = self.plane.audit.head_hash()
        self._chain_cache = (length, records, head)
        return records, head

    # -- verification ------------------------------------------------------
    def verify(self, flag: Flag) -> Verification | None:
        analysis = self.act("agent.analyze", subject=flag.agent_id, payload={"reason": "verify_flag_cross_process"})
        if not analysis.allowed:
            self.failures.append(RemoteVerificationFailure(flag.agent_id, "analyze_denied"))
            return None

        records, head = self._chain()
        response = self.verifier.verify(
            audit=self.plane.audit,
            subject_id=flag.agent_id,
            claimed_classification=flag.classification.threat_class.value,
            claimed_confidence=flag.classification.confidence,
            records=records,
            expected_head=head,
        )
        if response is None:
            # Fail closed: no verdict at all, which means no containment.
            reason = self.verifier.stats.last_error or "verifier_unavailable"
            self.failures.append(RemoteVerificationFailure(flag.agent_id, reason))
            self.plane.audit.append(
                "verification.unavailable",
                actor_id=self.agent_id,
                subject_id=flag.agent_id,
                payload={"reason": reason, "transport": "cross-process"},
            )
            return None

        return self.immune.verifications.record_remote(
            verifier_id=self.agent_id,
            subject_id=flag.agent_id,
            response=response,
        )

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "SentinelAuditRemote":
        self.verifier.start()
        return self

    def close(self) -> None:
        self.verifier.close()

    def health(self) -> dict:
        return {
            "alive": self.verifier.alive,
            "pid": self.verifier.pid,
            "stats": self.verifier.stats.as_dict(),
            "failures": [failure.as_dict() for failure in self.failures],
        }
