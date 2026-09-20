"""Revocation service.

Revocation is separated from containment because it is the one irreversible
operation in the system (P6). It therefore carries its own evidence bar, its
own audit event type and its own metric.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..common.errors import ContainmentError
from ..common.util import LogicalClock
from .audit import AuditService
from .authority import AuthorityService, Revocation
from .identity import Principal


@dataclass(frozen=True)
class RevocationOutcome:
    subject_id: str
    revocations: tuple[str, ...]
    capabilities: tuple[str, ...]
    reason: str
    verification_ref: str
    at: int


class RevocationService:
    MIN_CONFIDENCE = 0.85

    def __init__(self, authority: AuthorityService, audit: AuditService, clock: LogicalClock) -> None:
        self._authority = authority
        self._audit = audit
        self._clock = clock

    def revoke(
        self,
        actor: Principal,
        subject_id: str,
        *,
        reason: str,
        verification_ref: str,
        confidence: float,
        capabilities: Iterable[str] | None = None,
    ) -> RevocationOutcome:
        if not verification_ref:
            raise ContainmentError("revocation requires independent verification (section 9)")
        if confidence < self.MIN_CONFIDENCE:
            self._audit.append(
                "revocation.blocked_low_confidence",
                actor_id=actor.principal_id,
                subject_id=subject_id,
                payload={"confidence": confidence, "threshold": self.MIN_CONFIDENCE},
            )
            raise ContainmentError(
                "confidence below the irreversible-action threshold",
                confidence=confidence,
                threshold=self.MIN_CONFIDENCE,
            )
        revocations: list[Revocation] = []
        if capabilities is None:
            revocations = self._authority.revoke_all(actor, subject_id, reason)
        else:
            for capability in capabilities:
                revocations.extend(self._authority.revoke_capability(actor, subject_id, capability, reason))
        outcome = RevocationOutcome(
            subject_id=subject_id,
            revocations=tuple(r.revocation_id for r in revocations),
            capabilities=tuple(sorted({r.capability for r in revocations})),
            reason=reason,
            verification_ref=verification_ref,
            at=self._clock.now,
        )
        self._audit.append(
            "revocation.executed",
            actor_id=actor.principal_id,
            subject_id=subject_id,
            payload={
                "revocations": list(outcome.revocations),
                "capabilities": list(outcome.capabilities),
                "confidence": confidence,
                "verification_ref": verification_ref,
                "reason": reason,
            },
        )
        return outcome
