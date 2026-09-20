"""Containment engine.

Containment is a control plane operation, not an agent capability that an agent
happens to call. SENTINEL-CONTAIN asks; the control plane decides. Every entry
point here re-checks the *caller's* authority, so a defensive agent that is
itself compromised gains nothing by calling these methods directly.

Containment actions are ordered by reversibility:

    MONITOR  -> nothing changes, observation only
    RESTRICT -> reversible capability suppression
    ISOLATE  -> reversible: network/delegation capabilities suppressed
    QUARANTINE -> agent moved to a sandbox runtime, still reversible
    REVOKE   -> irreversible authority destruction (highest evidence bar)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from ..common.errors import AuthorityError, ContainmentError
from ..common.util import IdFactory, LogicalClock
from .audit import AuditService
from .authority import AuthorityService, Restriction
from .identity import IdentityService, Principal


class ContainmentAction(str, Enum):
    MONITOR = "MONITOR"
    RESTRICT = "RESTRICT"
    ISOLATE = "ISOLATE"
    QUARANTINE = "QUARANTINE"
    REVOKE = "REVOKE"

    @property
    def reversible(self) -> bool:
        return self is not ContainmentAction.REVOKE

    @property
    def required_capability(self) -> str | None:
        return {
            ContainmentAction.MONITOR: "agent.observe",
            ContainmentAction.RESTRICT: "agent.restrict",
            ContainmentAction.ISOLATE: "agent.isolate",
            ContainmentAction.QUARANTINE: "agent.quarantine",
            ContainmentAction.REVOKE: "agent.revoke",
        }[self]


ISOLATION_CAPABILITIES = ("network.egress", "message.send", "agent.delegate", "agent.create")


@dataclass(frozen=True)
class ContainmentEvent:
    event_id: str
    subject_id: str
    action: ContainmentAction
    actor_id: str
    at: int
    reason: str
    evidence: tuple[str, ...] = ()
    verification_ref: str | None = None
    details: dict = field(default_factory=dict)


class ContainmentEngine:
    def __init__(
        self,
        identity: IdentityService,
        authority: AuthorityService,
        audit: AuditService,
        clock: LogicalClock,
        ids: IdFactory,
    ) -> None:
        self._identity = identity
        self._authority = authority
        self._audit = audit
        self._clock = clock
        self._ids = ids
        self._events: list[ContainmentEvent] = []
        self._quarantined: dict[str, str] = {}
        self._isolated: dict[str, str] = {}
        self.quarantine_manager = None  # wired by ControlPlane to avoid a cycle

    # -- guard rails -------------------------------------------------------
    def _authorize(self, actor: Principal, action: ContainmentAction, subject_id: str, verification_ref: str | None) -> None:
        capability = action.required_capability
        if not actor.is_root_authority:
            if capability and not self._authority.has(actor.principal_id, capability):
                self._audit.append(
                    "containment.denied",
                    actor_id=actor.principal_id,
                    subject_id=subject_id,
                    payload={"action": action.value, "reason": f"missing_{capability}"},
                )
                raise AuthorityError(
                    "defensive agent lacks the required containment capability (P4)",
                    actor=actor.principal_id,
                    required=capability,
                )
            if actor.principal_id == subject_id:
                raise ContainmentError("a defensive agent may not contain itself out of its own restrictions (P5)")
        # Irreversible action requires independent verification (section 9).
        if not action.reversible and not verification_ref:
            raise ContainmentError(
                "irreversible containment requires an independent verification reference",
                action=action.value,
                subject=subject_id,
            )

    def _record(self, subject_id: str, action: ContainmentAction, actor: Principal, reason: str, evidence: Iterable[str], verification_ref: str | None, details: dict | None = None) -> ContainmentEvent:
        event = ContainmentEvent(
            event_id=self._ids.new("CNT"),
            subject_id=subject_id,
            action=action,
            actor_id=actor.principal_id,
            at=self._clock.now,
            reason=reason,
            evidence=tuple(evidence),
            verification_ref=verification_ref,
            details=dict(details or {}),
        )
        self._events.append(event)
        self._audit.append(
            f"containment.{action.value.lower()}",
            actor_id=actor.principal_id,
            subject_id=subject_id,
            payload={
                "event_id": event.event_id,
                "reason": reason,
                "evidence": list(event.evidence),
                "verification_ref": verification_ref,
                **event.details,
            },
        )
        return event

    # -- actions -----------------------------------------------------------
    def monitor(self, actor: Principal, subject_id: str, reason: str, evidence: Iterable[str] = ()) -> ContainmentEvent:
        self._authorize(actor, ContainmentAction.MONITOR, subject_id, None)
        return self._record(subject_id, ContainmentAction.MONITOR, actor, reason, evidence, None)

    def restrict(
        self,
        actor: Principal,
        subject_id: str,
        capabilities: Iterable[str],
        reason: str,
        *,
        evidence: Iterable[str] = (),
        verification_ref: str | None = None,
    ) -> ContainmentEvent:
        self._authorize(actor, ContainmentAction.RESTRICT, subject_id, verification_ref)
        restriction: Restriction = self._authority.restrict(actor, subject_id, capabilities, reason)
        return self._record(
            subject_id,
            ContainmentAction.RESTRICT,
            actor,
            reason,
            evidence,
            verification_ref,
            {"restriction_id": restriction.restriction_id, "capabilities": list(restriction.capabilities)},
        )

    def isolate(
        self,
        actor: Principal,
        subject_id: str,
        reason: str,
        *,
        evidence: Iterable[str] = (),
        verification_ref: str | None = None,
    ) -> ContainmentEvent:
        self._authorize(actor, ContainmentAction.ISOLATE, subject_id, verification_ref)
        held = self._authority.granted(subject_id)
        to_suppress = [c for c in ISOLATION_CAPABILITIES if held.holds(c)]
        if to_suppress:
            self._authority.restrict(actor, subject_id, to_suppress, f"isolation:{reason}")
        self._isolated[subject_id] = reason
        return self._record(
            subject_id,
            ContainmentAction.ISOLATE,
            actor,
            reason,
            evidence,
            verification_ref,
            {"suppressed": to_suppress},
        )

    def quarantine(
        self,
        actor: Principal,
        subject_id: str,
        reason: str,
        *,
        evidence: Iterable[str] = (),
        verification_ref: str | None = None,
    ) -> ContainmentEvent:
        self._authorize(actor, ContainmentAction.QUARANTINE, subject_id, verification_ref)
        if self.quarantine_manager is None:
            raise ContainmentError("quarantine manager is not wired into the control plane")
        environment = self.quarantine_manager.admit(subject_id, reason=reason, actor_id=actor.principal_id)
        held = self._authority.granted(subject_id)
        suppress = [str(c) for c in held]
        if suppress:
            self._authority.restrict(actor, subject_id, suppress, f"quarantine:{reason}")
        self._quarantined[subject_id] = environment.environment_id
        return self._record(
            subject_id,
            ContainmentAction.QUARANTINE,
            actor,
            reason,
            evidence,
            verification_ref,
            {"environment_id": environment.environment_id, "suppressed": suppress},
        )

    def revoke(
        self,
        actor: Principal,
        subject_id: str,
        reason: str,
        *,
        capabilities: Iterable[str] | None = None,
        evidence: Iterable[str] = (),
        verification_ref: str | None = None,
    ) -> ContainmentEvent:
        self._authorize(actor, ContainmentAction.REVOKE, subject_id, verification_ref)
        if capabilities is None:
            revocations = self._authority.revoke_all(actor, subject_id, reason)
        else:
            revocations = []
            for capability in capabilities:
                revocations.extend(self._authority.revoke_capability(actor, subject_id, capability, reason))
        return self._record(
            subject_id,
            ContainmentAction.REVOKE,
            actor,
            reason,
            evidence,
            verification_ref,
            {"revocations": [r.revocation_id for r in revocations]},
        )

    # -- queries -----------------------------------------------------------
    def is_quarantined(self, subject_id: str) -> bool:
        return subject_id in self._quarantined

    def is_isolated(self, subject_id: str) -> bool:
        return subject_id in self._isolated

    def environment_of(self, subject_id: str) -> str | None:
        return self._quarantined.get(subject_id)

    def history(self, subject_id: str | None = None) -> list[ContainmentEvent]:
        if subject_id is None:
            return list(self._events)
        return [e for e in self._events if e.subject_id == subject_id]

    def previously_contained(self, subject_id: str) -> bool:
        return any(e.action is not ContainmentAction.MONITOR for e in self.history(subject_id))

    def release(self, actor: Principal, subject_id: str, *, authorization_ref: str) -> ContainmentEvent:
        """Recovery path: lift reversible containment after external authorization."""
        if not actor.is_root_authority and not self._authority.has(actor.principal_id, "agent.restore"):
            raise AuthorityError("actor lacks agent.restore", actor=actor.principal_id)
        if not authorization_ref:
            raise ContainmentError("release requires an external authorization reference")
        for restriction in self._authority.active_restrictions(subject_id):
            self._authority.lift_restriction(actor, restriction.restriction_id, authorization_ref=authorization_ref)
        self._quarantined.pop(subject_id, None)
        self._isolated.pop(subject_id, None)
        if self.quarantine_manager is not None:
            self.quarantine_manager.release(subject_id)
        return self._record(
            subject_id,
            ContainmentAction.MONITOR,
            actor,
            "released_after_authorized_recovery",
            (),
            authorization_ref,
            {"released": True},
        )
