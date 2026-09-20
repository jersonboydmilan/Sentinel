"""Runtime invariant checker.

The eight architectural principles are not only enforced at their own call
sites; they are re-checked here as *global state predicates* over the control
plane. The checker can run after every gateway decision (``bind`` installs it as
a gateway observer), which turns each principle from a claim about one code path
into a continuously monitored property of the whole system.

A violation is not an exception by default: it is recorded, audited and made
available to tests and benchmarks, so a single violation fails a build rather
than silently changing behaviour at runtime. ``strict=True`` raises instead, for
use in tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..common.errors import ControlPlaneError
from .capabilities import Capability, CapabilitySet, DEFENSIVE_CAPABILITIES


class InvariantViolation(ControlPlaneError):
    code = "INVARIANT_VIOLATION"


@dataclass(frozen=True)
class Violation:
    invariant: str
    title: str
    detail: str
    subject: str | None = None

    def as_dict(self) -> dict:
        return {"invariant": self.invariant, "title": self.title, "detail": self.detail, "subject": self.subject}


INVARIANT_TITLES = {
    "P1": "Intelligence does not equal authority",
    "P2": "Authority is external",
    "P3": "Delegation does not transfer authority",
    "P4": "Detection does not grant offensive authority",
    "P5": "Defensive agents are also controlled agents",
    "P6": "Revocation overrides agent intent",
    "P7": "Default deny",
    "P8": "The SDK is not the security boundary",
}


@dataclass
class InvariantReport:
    checked: int = 0
    violations: tuple[Violation, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.violations

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "checked": self.checked,
            "violations": [v.as_dict() for v in self.violations],
        }


class InvariantChecker:
    """Checks P1-P8 against live control plane state."""

    def __init__(self, plane, *, strict: bool = False) -> None:
        self.plane = plane
        self.strict = strict
        self.history: list[InvariantReport] = []
        self._decisions = 0
        self._executions = 0

    # -- wiring ------------------------------------------------------------
    def bind(self) -> "InvariantChecker":
        """Run the checker after every gateway decision."""
        self.plane.gateway.add_observer(self._on_decision)
        return self

    def _on_decision(self, result) -> None:
        self._decisions += 1
        if result.allowed:
            self._executions += 1
        report = self.check()
        if self.strict and not report.ok:
            raise InvariantViolation(
                "architectural invariant violated",
                violations=[v.as_dict() for v in report.violations],
            )

    # -- checks ------------------------------------------------------------
    def check(self) -> InvariantReport:
        violations: list[Violation] = []
        checks: tuple[Callable[[], Iterable[Violation]], ...] = (
            self._p1_execution_requires_decision,
            self._p2_no_self_grant,
            self._p3_delegation_attenuates,
            self._p4_defensive_namespace_is_not_offensive,
            self._p5_defensive_actions_are_gateway_decisions,
            self._p6_revoked_authority_is_not_effective,
            self._p7_no_allow_without_basis,
            self._p8_tool_calls_match_decisions,
        )
        for check in checks:
            violations.extend(check())
        report = InvariantReport(checked=len(checks), violations=tuple(violations))
        self.history.append(report)
        if not report.ok:
            self.plane.audit.append(
                "invariant.violation",
                actor_id="invariant-checker",
                payload={"violations": [v.as_dict() for v in report.violations]},
            )
        return report

    # P1 -------------------------------------------------------------------
    def _allowed_production_tool_decisions(self) -> int:
        """Decisions that legitimately account for a production tool call.

        Counts ALLOW decisions that named a tool *and* were routed to the
        production registry. Sandboxed (quarantined) decisions are excluded,
        because they invoke the quarantine registry instead.
        """
        registry_name = self.plane.registry.name
        return len(
            self.plane.audit.search(
                event_type="gateway.decision",
                predicate=lambda record: record.payload.get("decision") == "ALLOW"
                and record.payload.get("tool") is not None
                and record.payload.get("registry") == registry_name,
            )
        )

    def _p1_execution_requires_decision(self) -> list[Violation]:
        """Every production tool invocation must be backed by an ALLOW decision."""
        invocations = len(self.plane.registry.invocations)
        accounted = self._allowed_production_tool_decisions()
        if invocations > accounted:
            return [
                Violation(
                    "P1",
                    INVARIANT_TITLES["P1"],
                    f"{invocations} production tool invocations but only {accounted} allowing decisions",
                )
            ]
        return []

    # P2 -------------------------------------------------------------------
    def _p2_no_self_grant(self) -> list[Violation]:
        out = []
        for grant in self.plane.authority.all_grants():
            if grant.granted_by == grant.subject_id:
                out.append(
                    Violation("P2", INVARIANT_TITLES["P2"], f"grant {grant.grant_id} is self-issued", grant.subject_id)
                )
        return out

    # P3 -------------------------------------------------------------------
    def _p3_delegation_attenuates(self) -> list[Violation]:
        out = []
        authority = self.plane.authority
        by_id = {g.grant_id: g for g in authority.all_grants()}
        for grant in by_id.values():
            if not grant.parent_grant_id:
                continue
            parent = by_id.get(grant.parent_grant_id)
            if parent is None:
                out.append(
                    Violation("P3", INVARIANT_TITLES["P3"], f"grant {grant.grant_id} references a missing parent", grant.subject_id)
                )
                continue
            if not Capability.parse(parent.capability).covers(Capability.parse(grant.capability)):
                out.append(
                    Violation(
                        "P3",
                        INVARIANT_TITLES["P3"],
                        f"{grant.grant_id} ({grant.capability}) exceeds parent {parent.grant_id} ({parent.capability})",
                        grant.subject_id,
                    )
                )
            if grant.delegation_depth >= parent.delegation_depth and parent.delegation_depth > 0:
                out.append(
                    Violation(
                        "P3",
                        INVARIANT_TITLES["P3"],
                        f"{grant.grant_id} depth {grant.delegation_depth} not attenuated from parent {parent.delegation_depth}",
                        grant.subject_id,
                    )
                )
            if parent.expires_at is not None and (grant.expires_at is None or grant.expires_at > parent.expires_at):
                out.append(
                    Violation("P3", INVARIANT_TITLES["P3"], f"{grant.grant_id} outlives its parent", grant.subject_id)
                )
        return out

    # P4 -------------------------------------------------------------------
    def _p4_defensive_namespace_is_not_offensive(self) -> list[Violation]:
        out = []
        for principal in self.plane.identity.all_principals():
            if principal.kind.value != "DEFENSIVE_AGENT":
                continue
            held = self.plane.authority.granted(principal.principal_id)
            operational = [str(c) for c in held if str(c) not in DEFENSIVE_CAPABILITIES]
            if operational:
                out.append(
                    Violation(
                        "P4",
                        INVARIANT_TITLES["P4"],
                        f"defensive agent holds operational capability {sorted(operational)}",
                        principal.principal_id,
                    )
                )
        return out

    # P5 -------------------------------------------------------------------
    def _p5_defensive_actions_are_gateway_decisions(self) -> list[Violation]:
        """Containment events must be traceable to a gateway decision or root."""
        out = []
        audit = self.plane.audit
        for event in self.plane.containment.history():
            actor = self.plane.identity.get(event.actor_id) if self.plane.identity.exists(event.actor_id) else None
            if actor is not None and actor.is_root_authority:
                continue
            decisions = audit.search(
                event_type="gateway.decision",
                actor_id=event.actor_id,
                predicate=lambda record, subject=event.subject_id: record.payload.get("decision") == "ALLOW"
                and record.subject_id == subject,
            )
            if not decisions:
                out.append(
                    Violation(
                        "P5",
                        INVARIANT_TITLES["P5"],
                        f"containment {event.event_id} by {event.actor_id} has no allowing gateway decision",
                        event.subject_id,
                    )
                )
        return out

    # P6 -------------------------------------------------------------------
    def _p6_revoked_authority_is_not_effective(self) -> list[Violation]:
        out = []
        authority = self.plane.authority
        for grant in authority.all_grants():
            if not authority.is_revoked(grant.grant_id):
                continue
            still_held = CapabilitySet(
                g.capability for g in authority.grants_for(grant.subject_id)
            ).holds(grant.capability)
            if still_held:
                # Another live grant may legitimately cover the same capability.
                covering = [
                    g.grant_id
                    for g in authority.grants_for(grant.subject_id)
                    if Capability.parse(g.capability).covers(Capability.parse(grant.capability))
                ]
                if not covering:
                    out.append(
                        Violation(
                            "P6",
                            INVARIANT_TITLES["P6"],
                            f"revoked grant {grant.grant_id} still effective",
                            grant.subject_id,
                        )
                    )
        return out

    # P7 -------------------------------------------------------------------
    def _p7_no_allow_without_basis(self) -> list[Violation]:
        """An ALLOW must rest on held authority, or on sandboxed containment."""
        out = []
        for record in self.plane.audit.search(event_type="gateway.decision"):
            payload = record.payload
            if payload.get("decision") != "ALLOW":
                continue
            if payload.get("policy") == "POL-000-DEFAULT-DENY":
                out.append(
                    Violation("P7", INVARIANT_TITLES["P7"], f"default-deny policy produced ALLOW in {payload.get('decision_id')}", record.actor_id)
                )
            evidence = payload.get("evidence", [])
            sandboxed = payload.get("policy") == "POL-001-QUARANTINE-CONFINEMENT"
            if "capability_not_held" in evidence and not sandboxed:
                out.append(
                    Violation(
                        "P7",
                        INVARIANT_TITLES["P7"],
                        f"ALLOW despite capability_not_held in {payload.get('decision_id')}",
                        record.actor_id,
                    )
                )
        return out

    # P8 -------------------------------------------------------------------
    def _p8_tool_calls_match_decisions(self) -> list[Violation]:
        """A tool call with no decision behind it means something bypassed the gateway."""
        accounted = self._allowed_production_tool_decisions()
        invocations = len(self.plane.registry.invocations)
        if invocations != accounted:
            return [
                Violation(
                    "P8",
                    INVARIANT_TITLES["P8"],
                    f"{invocations} production tool calls versus {accounted} allowing decisions "
                    f"(difference {invocations - accounted}) - a call reached the registry outside the gateway",
                )
            ]
        return []

    # -- reporting ---------------------------------------------------------
    def summary(self) -> dict:
        violations = [v for report in self.history for v in report.violations]
        return {
            "reports": len(self.history),
            "decisions_observed": self._decisions,
            "executions_observed": self._executions,
            "violations": [v.as_dict() for v in violations],
            "ok": not violations,
        }
