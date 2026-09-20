"""SENTINEL-DETECT - observe, correlate, flag. Authority: OBSERVE, FLAG.

The detector deliberately cannot restrict, isolate, quarantine or revoke.
Detection does not grant containment authority (P4); the detector's output is a
flag, which is an input to verification, not an action against an agent.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..immune_system.classification import Classification, ThreatClass
from .base import DefensiveAgent


@dataclass(frozen=True)
class Flag:
    agent_id: str
    classification: Classification
    raised_by: str
    at: int
    accepted: bool

    def as_dict(self) -> dict:
        return {
            "agent": self.agent_id,
            "classification": self.classification.threat_class.value,
            "confidence": round(self.classification.confidence, 4),
            "raised_by": self.raised_by,
            "accepted": self.accepted,
            "evidence": list(self.classification.evidence[:8]),
        }


class SentinelDetect(DefensiveAgent):
    NAME = "SENTINEL-DETECT"
    DECLARED_CAPABILITIES = ("agent.observe", "agent.flag", "immune.read")
    PURPOSE = "detect abnormal agent behaviour and raise flags"

    def __init__(self, plane, observatory, immune) -> None:
        super().__init__(plane, observatory, immune)
        self.flags: list[Flag] = []

    def scan(self, agent_ids: list[str] | None = None) -> list[Flag]:
        targets = agent_ids or [
            principal.principal_id
            for principal in self.plane.identity.agents()
            if principal.kind.value == "AGENT"
        ]
        raised: list[Flag] = []
        for agent_id in targets:
            observation = self.act("agent.observe", subject=agent_id, payload={"reason": "routine_scan"})
            if not observation.allowed:
                continue
            classification = self.immune.assess(agent_id)
            if classification.threat_class is ThreatClass.NORMAL:
                continue
            flagged = self.act(
                "agent.flag",
                subject=agent_id,
                payload={
                    "classification": classification.threat_class.value,
                    "confidence": classification.confidence,
                    "evidence": list(classification.evidence[:12]),
                },
            )
            flag = Flag(
                agent_id=agent_id,
                classification=classification,
                raised_by=self.agent_id,
                at=self.plane.clock.now,
                accepted=flagged.allowed,
            )
            self.flags.append(flag)
            raised.append(flag)
        return raised

    def flags_for(self, agent_id: str) -> list[Flag]:
        return [flag for flag in self.flags if flag.agent_id == agent_id]
