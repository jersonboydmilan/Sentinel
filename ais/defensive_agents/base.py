"""Defensive agent base class (sections 10 and 11).

A SENTINEL agent is an ordinary principal with an unusual capability set. It
has no privileged code path: every action it takes is an ``ActionRequest``
submitted to the same gateway that governs the agents it watches (P5).

``DECLARED_CAPABILITIES`` is the *only* authority a defensive agent is
provisioned with. Anything else it attempts is denied by the control plane and
recorded as a defender policy violation, which is a first class metric.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..control_plane.gateway import ActionResult
from ..control_plane.plane import ControlPlane
from ..immune_system.immune import ImmuneSystem
from ..observatory.observatory import Observatory


@dataclass
class DefensiveAction:
    action: str
    subject: str | None
    result: ActionResult

    @property
    def allowed(self) -> bool:
        return self.result.allowed


class DefensiveAgent:
    NAME: str = "SENTINEL-BASE"
    DECLARED_CAPABILITIES: tuple[str, ...] = ()
    PURPOSE: str = "defensive"

    def __init__(self, plane: ControlPlane, observatory: Observatory, immune: ImmuneSystem) -> None:
        self.plane = plane
        self.observatory = observatory
        self.immune = immune
        self.principal = plane.register_agent(self.NAME, defensive=True, runtime="sentinel-runtime", model="deterministic")
        for capability in self.DECLARED_CAPABILITIES:
            plane.grant(self.principal.principal_id, capability, reason=f"provision:{self.NAME}")
        self.contract = plane.commission(
            self.principal.principal_id,
            self.PURPOSE,
            self.DECLARED_CAPABILITIES,
            max_tool_calls=10_000,
            max_duration=10_000,
        )
        self.actions: list[DefensiveAction] = []

    # -- gateway access ----------------------------------------------------
    @property
    def agent_id(self) -> str:
        return self.principal.principal_id

    def act(self, action: str, *, subject: str | None = None, payload: dict | None = None) -> DefensiveAction:
        result = self.plane.submit(
            self.agent_id,
            action,
            target_agent=subject,
            task_id=self.contract.contract_id,
            payload=payload or {},
        )
        record = DefensiveAction(action=action, subject=subject, result=result)
        self.actions.append(record)
        return record

    # -- introspection -----------------------------------------------------
    def denied_actions(self) -> list[DefensiveAction]:
        return [a for a in self.actions if not a.allowed]

    def violations(self) -> list[DefensiveAction]:
        """Actions this agent attempted outside its declared defensive authority."""
        declared = set(self.DECLARED_CAPABILITIES)
        return [a for a in self.actions if a.action not in declared]

    def capability_report(self) -> dict:
        return {
            "agent": self.agent_id,
            "declared": list(self.DECLARED_CAPABILITIES),
            "effective": self.plane.authority.effective(self.agent_id).as_strings(),
            "attempted": sorted({a.action for a in self.actions}),
            "denied": len(self.denied_actions()),
        }
