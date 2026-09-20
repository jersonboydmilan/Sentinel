"""Verification ledger.

Independent verification is the hinge of the whole containment design: no
irreversible action may rest on the word of the detector that raised the alarm.
The ledger stores verifications produced by SENTINEL-AUDIT, which recomputes
evidence from the audit chain rather than trusting the detector's report.

The gateway records the *claimed* verification reference from a caller; this
ledger is what turns a claim into the fact ``verification_valid``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..common.errors import ControlPlaneError
from ..common.util import IdFactory, LogicalClock, digest_of
from ..control_plane.audit import AuditService
from ..control_plane.authority import AuthorityService


class VerificationError(ControlPlaneError):
    code = "VERIFICATION_ERROR"


@dataclass(frozen=True)
class Verification:
    verification_id: str
    subject_id: str
    verifier_id: str
    verdict: str  # CONFIRMED | REJECTED | INCONCLUSIVE
    confidence: float
    evidence: tuple[str, ...]
    reproduced: bool
    at: int
    classification: str = ""
    evidence_digest: str = ""
    consumed_by: tuple[str, ...] = ()

    @property
    def valid(self) -> bool:
        return self.verdict == "CONFIRMED" and self.reproduced

    def as_dict(self) -> dict:
        return {
            "verification_id": self.verification_id,
            "subject": self.subject_id,
            "verifier": self.verifier_id,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 4),
            "reproduced": self.reproduced,
            "classification": self.classification,
            "evidence": list(self.evidence),
        }


class VerificationLedger:
    def __init__(self, authority: AuthorityService, audit: AuditService, clock: LogicalClock, ids: IdFactory) -> None:
        self._authority = authority
        self._audit = audit
        self._clock = clock
        self._ids = ids
        self._records: dict[str, Verification] = {}

    def record(
        self,
        *,
        verifier_id: str,
        subject_id: str,
        verdict: str,
        confidence: float,
        evidence: Iterable[str],
        reproduced: bool,
        classification: str = "",
    ) -> Verification:
        if verifier_id == subject_id:
            raise VerificationError("an agent may not verify itself", verifier=verifier_id)
        if not self._authority.has(verifier_id, "agent.analyze"):
            raise VerificationError("verifier lacks agent.analyze", verifier=verifier_id)
        evidence = tuple(evidence)
        verification = Verification(
            verification_id=self._ids.new("VER"),
            subject_id=subject_id,
            verifier_id=verifier_id,
            verdict=verdict,
            confidence=max(0.0, min(1.0, confidence)),
            evidence=evidence,
            reproduced=reproduced,
            at=self._clock.now,
            classification=classification,
            evidence_digest=digest_of(sorted(evidence)),
        )
        self._records[verification.verification_id] = verification
        self._audit.append(
            "verification.recorded",
            actor_id=verifier_id,
            subject_id=subject_id,
            payload=verification.as_dict(),
        )
        return verification

    def get(self, verification_id: str) -> Verification | None:
        return self._records.get(verification_id)

    def validate(self, verification_id: str | None, subject_id: str) -> Verification | None:
        """A verification is usable only for the subject it was issued about."""
        if not verification_id:
            return None
        verification = self._records.get(verification_id)
        if verification is None or verification.subject_id != subject_id:
            return None
        return verification if verification.valid else None

    def for_subject(self, subject_id: str) -> list[Verification]:
        return [v for v in self._records.values() if v.subject_id == subject_id]

    def confirmed_for(self, subject_id: str) -> list[Verification]:
        return [v for v in self.for_subject(subject_id) if v.valid]

    def independent_verifiers(self, subject_id: str) -> list[str]:
        """Distinct principals that independently confirmed a finding.

        Multi-party attestation counts *verifiers*, not verifications: one
        auditor repeating itself is one opinion.
        """
        return sorted({v.verifier_id for v in self.confirmed_for(subject_id)})

    def all(self) -> list[Verification]:
        return sorted(self._records.values(), key=lambda v: v.verification_id)


@dataclass
class AuthorizationLedger:
    """External (human) authorizations required for recovery actions."""

    audit: AuditService
    clock: LogicalClock
    ids: IdFactory
    _records: dict[str, dict] = field(default_factory=dict)

    def authorize(self, operator_id: str, subject_id: str, scope: str, note: str = "") -> str:
        reference = self.ids.new("AUTH")
        self._records[reference] = {
            "operator": operator_id,
            "subject": subject_id,
            "scope": scope,
            "note": note,
            "at": self.clock.now,
            "used": False,
        }
        self.audit.append(
            "recovery.authorized",
            actor_id=operator_id,
            subject_id=subject_id,
            payload={"authorization_ref": reference, "scope": scope, "note": note},
        )
        return reference

    def validate(self, reference: str | None, subject_id: str, scope: str) -> bool:
        record = self._records.get(reference or "")
        if not record:
            return False
        return record["subject"] == subject_id and record["scope"] == scope and not record["used"]

    def consume(self, reference: str) -> None:
        if reference in self._records:
            self._records[reference]["used"] = True
