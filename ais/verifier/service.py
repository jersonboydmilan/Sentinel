"""The verifier worker process.

Run as ``python3 -m ais.verifier.service``. It reads signed requests on stdin
and writes signed verdicts on stdout. What it does **not** have is as important
as what it does:

* no reference to the control plane, the authority service or the observatory;
* no ability to submit an action, grant authority or contain anything;
* no input other than a serialised audit chain, whose hashes it recomputes
  itself before looking at a single claim.

If the chain does not verify, or the head hash is not the one the caller
claimed, the verdict is ``REJECTED`` - a compromised control plane cannot coerce
a confirmation by handing over a doctored history.
"""

from __future__ import annotations

import os
import sys

from . import reconstruction
from .protocol import (
    PROTOCOL_VERSION,
    VerifyResponse,
    decode,
    encode,
    error_payload,
    signed,
    verify_signature,
)

KEY_ENVIRONMENT_VARIABLE = "AIS_VERIFIER_KEY"


def handle(request: dict) -> dict:
    """Pure request handling, so the loop stays trivially testable."""
    subject = request.get("subject_id", "")
    claimed = request.get("claimed_classification", "")
    records = request.get("records", [])
    expected_head = request.get("expected_head", "")

    result = reconstruction.verdict_for(
        records,
        subject,
        claimed,
        float(request.get("claimed_confidence", 1.0) or 0.0),
    )
    chain = result["chain"]

    if chain["valid"] and expected_head and chain["head"] != expected_head:
        # The caller's claim about its own history does not match the history it
        # supplied. Treat that as a hostile inconsistency, not a mismatch.
        result = {
            "verdict": "REJECTED",
            "confidence": 0.0,
            "evidence": ["chain_head_mismatch", f"claimed:{expected_head[:16]}", f"computed:{chain['head'][:16]}"],
            "predicates": {},
            "chain": chain,
        }

    response = VerifyResponse(
        request_id=request.get("request_id", ""),
        nonce=request.get("nonce", ""),
        subject_id=subject,
        verdict=result["verdict"],
        confidence=result["confidence"],
        evidence=list(result["evidence"]),
        predicates=result["predicates"],
        chain_valid=bool(chain["valid"]),
        chain_head=chain["head"],
        claimed_classification=claimed,
        verifier_pid=os.getpid(),
    )
    return response.as_payload()


def serve(key: str, stdin=None, stdout=None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = decode(line)
        except ValueError:
            stdout.write(encode(signed(key, error_payload("", "", "malformed_request"))) + "\n")
            stdout.flush()
            continue

        request_id = str(request.get("request_id", ""))
        nonce = str(request.get("nonce", ""))

        if request.get("version") != PROTOCOL_VERSION:
            payload = error_payload(request_id, nonce, "protocol_version_mismatch", str(request.get("version")))
        elif not verify_signature(key, request):
            payload = error_payload(request_id, nonce, "bad_request_signature")
        elif request.get("op") == "shutdown":
            stdout.write(encode(signed(key, {"op": "shutdown", "version": PROTOCOL_VERSION, "request_id": request_id, "nonce": nonce})) + "\n")
            stdout.flush()
            return 0
        elif request.get("op") == "ping":
            payload = {"op": "pong", "version": PROTOCOL_VERSION, "request_id": request_id, "nonce": nonce, "pid": os.getpid()}
        elif request.get("op") == "verify":
            payload = handle(request)
        else:
            payload = error_payload(request_id, nonce, "unknown_op", str(request.get("op")))

        stdout.write(encode(signed(key, payload)) + "\n")
        stdout.flush()
    return 0


def main() -> int:  # pragma: no cover - process entry point
    key = os.environ.get(KEY_ENVIRONMENT_VARIABLE)
    if not key:
        print(f"{KEY_ENVIRONMENT_VARIABLE} is required", file=sys.stderr)
        return 2
    return serve(key)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
