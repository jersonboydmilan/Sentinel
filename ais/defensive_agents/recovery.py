"""SENTINEL-RECOVERY - restore an agent to an authorized state.

Authority: RESTORE - and only against an external authorization reference
issued by a human operator. Recovery cannot authorize itself, cannot restore
an agent whose authority was revoked (that requires a fresh external grant),
and cannot lift a restriction it imposed on itself.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base import DefensiveAgent


@dataclass(frozen=True)
class RecoveryOutcome:
    agent_id: str
    restored: bool
    reason: str
    restored_capabilities: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "agent": self.agent_id,
            "restored": self.restored,
            "reason": self.reason,
            "capabilities": list(self.restored_capabilities),
        }


class SentinelRecovery(DefensiveAgent):
    NAME = "SENTINEL-RECOVERY"
    DECLARED_CAPABILITIES = ("agent.restore",)
    PURPOSE = "restore agents to an externally authorized configuration"

    def restore(self, agent_id: str, *, authorization_ref: str) -> RecoveryOutcome:
        action = self.act(
            "agent.restore",
            subject=agent_id,
            payload={"authorization_ref": authorization_ref, "reason": "authorized_recovery"},
        )
        if not action.allowed:
            return RecoveryOutcome(agent_id, False, f"denied:{action.result.effect.value}")
        self.immune.authorizations.consume(authorization_ref)
        return RecoveryOutcome(
            agent_id,
            True,
            "restored_under_external_authorization",
            tuple(self.plane.authority.effective(agent_id).as_strings()),
        )
