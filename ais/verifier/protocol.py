"""Wire protocol between the control plane and the out-of-process verifier.

Newline-delimited JSON over the child's stdin/stdout. Both directions are
HMAC-signed with a key the operator establishes when the verifier is spawned:

* signing the **request** stops an unrelated local process from driving the
  verifier;
* signing the **response** is what lets the control plane record a verdict as
  having come from the verifier principal rather than from itself.

The key is never derived from agent input and never travels through a gateway
request, so no agent - defensive or otherwise - can mint a verdict.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from ..common.util import canonical_json, constant_time_equal, hmac_hex

PROTOCOL_VERSION = "ais-verify/1"
SIGNATURE_FIELD = "signature"


def sign(key: str, payload: dict) -> str:
    body = {k: v for k, v in payload.items() if k != SIGNATURE_FIELD}
    return hmac_hex(key, canonical_json(body))


def signed(key: str, payload: dict) -> dict:
    return {**payload, SIGNATURE_FIELD: sign(key, payload)}


def verify_signature(key: str, payload: dict) -> bool:
    presented = payload.get(SIGNATURE_FIELD)
    if not isinstance(presented, str):
        return False
    return constant_time_equal(sign(key, payload), presented)


def encode(payload: dict) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def decode(line: str) -> dict:
    return json.loads(line)


@dataclass
class VerifyRequest:
    request_id: str
    nonce: str
    subject_id: str
    claimed_classification: str
    claimed_confidence: float
    expected_head: str
    records: list[dict] = field(default_factory=list)
    op: str = "verify"
    version: str = PROTOCOL_VERSION

    def as_payload(self) -> dict:
        return asdict(self)


@dataclass
class VerifyResponse:
    request_id: str
    nonce: str
    subject_id: str
    verdict: str
    confidence: float
    evidence: list[str]
    predicates: dict[str, Any]
    chain_valid: bool
    chain_head: str
    claimed_classification: str
    verifier_pid: int
    op: str = "verify"
    version: str = PROTOCOL_VERSION

    def as_payload(self) -> dict:
        return asdict(self)


def error_payload(request_id: str, nonce: str, reason: str, detail: str = "") -> dict:
    return {
        "op": "error",
        "version": PROTOCOL_VERSION,
        "request_id": request_id,
        "nonce": nonce,
        "reason": reason,
        "detail": detail[:200],
    }
