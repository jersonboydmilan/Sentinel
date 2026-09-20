"""Response planning.

Translates a classification into an ordered, reversibility-aware plan. The
planner proposes; the control plane disposes. Each step names the defensive
capability required to execute it, so a plan that a defensive agent is not
authorized to carry out simply fails at the gateway rather than silently
escalating.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..control_plane.containment import ContainmentAction, ISOLATION_CAPABILITIES
from .classification import ACTION_CONFIDENCE_GATES, Classification, ThreatClass


@dataclass(frozen=True)
class ResponseStep:
    action: ContainmentAction
    required_capability: str
    min_confidence: float
    reversible: bool
    rationale: str
    capabilities: tuple[str, ...] = ()
    requires_verification: bool = True

    def as_dict(self) -> dict:
        return {
            "action": self.action.value,
            "required_capability": self.required_capability,
            "min_confidence": self.min_confidence,
            "reversible": self.reversible,
            "rationale": self.rationale,
            "capabilities": list(self.capabilities),
        }


@dataclass(frozen=True)
class ResponsePlan:
    agent_id: str
    classification: Classification
    steps: tuple[ResponseStep, ...]

    def as_dict(self) -> dict:
        return {
            "agent": self.agent_id,
            "classification": self.classification.threat_class.value,
            "confidence": round(self.classification.confidence, 4),
            "steps": [step.as_dict() for step in self.steps],
        }


class ResponsePlanner:
    """Graduated response: always the least irreversible action that fits."""

    def plan(self, classification: Classification, *, drift_capabilities: list[str] | None = None) -> ResponsePlan:
        confidence = classification.confidence
        steps: list[ResponseStep] = []
        suspicious = tuple(drift_capabilities or [])

        if classification.threat_class is ThreatClass.NORMAL:
            return ResponsePlan(classification.agent_id, classification, ())

        steps.append(
            ResponseStep(
                ContainmentAction.MONITOR,
                "agent.observe",
                ACTION_CONFIDENCE_GATES[ContainmentAction.MONITOR],
                True,
                "record behaviour without changing authority",
                requires_verification=False,
            )
        )

        if confidence >= ACTION_CONFIDENCE_GATES[ContainmentAction.RESTRICT] and classification.threat_class.severity >= 2:
            steps.append(
                ResponseStep(
                    ContainmentAction.RESTRICT,
                    "agent.restrict",
                    ACTION_CONFIDENCE_GATES[ContainmentAction.RESTRICT],
                    True,
                    "suppress the capabilities implicated in the drift",
                    capabilities=suspicious or ("database.write", "credential.read", "network.egress"),
                )
            )

        if confidence >= ACTION_CONFIDENCE_GATES[ContainmentAction.ISOLATE] and classification.threat_class.severity >= 3:
            steps.append(
                ResponseStep(
                    ContainmentAction.ISOLATE,
                    "agent.isolate",
                    ACTION_CONFIDENCE_GATES[ContainmentAction.ISOLATE],
                    True,
                    "cut external communication and delegation",
                    capabilities=ISOLATION_CAPABILITIES,
                )
            )

        if confidence >= ACTION_CONFIDENCE_GATES[ContainmentAction.QUARANTINE] and classification.threat_class.severity >= 4:
            steps.append(
                ResponseStep(
                    ContainmentAction.QUARANTINE,
                    "agent.quarantine",
                    ACTION_CONFIDENCE_GATES[ContainmentAction.QUARANTINE],
                    True,
                    "move execution into a recorded sandbox for forensic replay",
                )
            )

        if confidence >= ACTION_CONFIDENCE_GATES[ContainmentAction.REVOKE] and classification.threat_class.severity >= 4:
            steps.append(
                ResponseStep(
                    ContainmentAction.REVOKE,
                    "agent.revoke",
                    ACTION_CONFIDENCE_GATES[ContainmentAction.REVOKE],
                    False,
                    "destroy authority after independent verification",
                )
            )

        return ResponsePlan(classification.agent_id, classification, tuple(steps))
