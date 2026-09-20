"""SENTINEL-CONTAIN - restrict, isolate, quarantine, revoke.

Authority: RESTRICT, ISOLATE, QUARANTINE, REVOKE - and nothing else. It cannot
observe on its own initiative, cannot write immune memory, cannot restore, and
cannot touch an operational capability. Each step it executes must carry a
verification reference issued by SENTINEL-AUDIT about *that* subject.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..control_plane.containment import ContainmentAction
from ..immune_system.response import ResponsePlan
from ..immune_system.verification import Verification
from .base import DefensiveAgent, DefensiveAction


@dataclass(frozen=True)
class ContainmentOutcome:
    agent_id: str
    executed: tuple[str, ...]
    refused: tuple[str, ...]
    verification_id: str | None

    def as_dict(self) -> dict:
        return {
            "agent": self.agent_id,
            "executed": list(self.executed),
            "refused": list(self.refused),
            "verification": self.verification_id,
        }


ACTION_TO_CAPABILITY = {
    ContainmentAction.RESTRICT: "agent.restrict",
    ContainmentAction.ISOLATE: "agent.isolate",
    ContainmentAction.QUARANTINE: "agent.quarantine",
    ContainmentAction.REVOKE: "agent.revoke",
}


class SentinelContain(DefensiveAgent):
    NAME = "SENTINEL-CONTAIN"
    DECLARED_CAPABILITIES = ("agent.restrict", "agent.isolate", "agent.quarantine", "agent.revoke")
    PURPOSE = "restrict, isolate, quarantine and revoke compromised agents"

    def execute(self, plan: ResponsePlan, verification: Verification | None) -> ContainmentOutcome:
        executed: list[str] = []
        refused: list[str] = []
        verification_id = verification.verification_id if verification else None

        for step in plan.steps:
            capability = ACTION_TO_CAPABILITY.get(step.action)
            if capability is None:
                # MONITOR belongs to the detector, not to the containment agent.
                refused.append(f"{step.action.value}:not_this_agent")
                continue
            if self._already_in_effect(step.action, plan.agent_id):
                # Containment is idempotent: re-applying it would inflate the
                # audit trail and the containment metrics without changing state.
                refused.append(f"{step.action.value}:already_in_effect")
                continue
            action: DefensiveAction = self.act(
                capability,
                subject=plan.agent_id,
                payload={
                    "reason": f"{plan.classification.threat_class.value}:{step.rationale}",
                    "evidence": list(plan.classification.evidence[:8]),
                    "capabilities": list(step.capabilities),
                    "verification_ref": verification_id,
                    "confidence": plan.classification.confidence,
                },
            )
            if action.allowed:
                executed.append(step.action.value)
            else:
                refused.append(f"{step.action.value}:{action.result.effect.value}")
        return ContainmentOutcome(
            agent_id=plan.agent_id,
            executed=tuple(executed),
            refused=tuple(refused),
            verification_id=verification_id,
        )

    # -- idempotence -------------------------------------------------------
    def _already_in_effect(self, action: ContainmentAction, agent_id: str) -> bool:
        containment = self.plane.containment
        if action is ContainmentAction.QUARANTINE:
            return containment.is_quarantined(agent_id)
        if action is ContainmentAction.ISOLATE:
            return containment.is_isolated(agent_id) or containment.is_quarantined(agent_id)
        if action is ContainmentAction.RESTRICT:
            return bool(self.plane.authority.active_restrictions(agent_id))
        if action is ContainmentAction.REVOKE:
            return not self.plane.authority.granted(agent_id)
        return False
