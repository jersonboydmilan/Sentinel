"""Risk engine.

Deterministic, explainable scoring. Every contribution is a named term with a
weight, so a risk score can be reproduced from the audit record alone - a
requirement for the auditor agent, which must be able to independently rebuild
the evidence it is asked to verify.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..common.util import clamp


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        if score >= 0.85:
            return cls.CRITICAL
        if score >= 0.6:
            return cls.HIGH
        if score >= 0.3:
            return cls.MEDIUM
        return cls.LOW


#: Sensitivity of the capability being exercised.
CAPABILITY_SENSITIVITY = {
    "credential.read": 0.9,
    "agent.create": 0.7,
    "agent.delegate": 0.6,
    "database.write": 0.6,
    "network.egress": 0.5,
    "file.write": 0.5,
    "message.send": 0.4,
    "email.read": 0.35,
    "database.read": 0.2,
    "tool.read": 0.1,
    "web.search": 0.1,
}

WEIGHTS = {
    "capability_sensitivity": 0.20,
    "authority_missing": 0.30,
    "contract_violation": 0.20,
    "drift_score": 0.20,
    "anomaly_score": 0.15,
    "immune_match": 0.15,
    "denied_ratio": 0.10,
    "prior_containment": 0.10,
}


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    level: RiskLevel
    terms: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"score": round(self.score, 4), "level": self.level.value, "terms": self.terms}


class RiskEngine:
    def __init__(self, weights: dict | None = None) -> None:
        self._weights = dict(WEIGHTS)
        if weights:
            self._weights.update(weights)

    def assess(self, facts: dict) -> RiskAssessment:
        terms: dict[str, float] = {}
        sensitivity = CAPABILITY_SENSITIVITY.get(str(facts.get("action", "")), 0.3)
        terms["capability_sensitivity"] = sensitivity
        terms["authority_missing"] = 0.0 if facts.get("capability_held") else 1.0
        terms["contract_violation"] = 0.0 if facts.get("contract_in_scope", True) else 1.0
        terms["drift_score"] = float(facts.get("drift_score", 0.0))
        terms["anomaly_score"] = float(facts.get("anomaly_score", 0.0))
        terms["immune_match"] = float(facts.get("immune_match_score", 0.0))
        terms["denied_ratio"] = float(facts.get("denied_ratio", 0.0))
        terms["prior_containment"] = 1.0 if facts.get("previously_contained") else 0.0

        total_weight = sum(self._weights[name] for name in terms)
        score = sum(self._weights[name] * value for name, value in terms.items()) / total_weight
        score = clamp(score)
        weighted = {name: round(self._weights[name] * value, 4) for name, value in terms.items()}
        return RiskAssessment(score=score, level=RiskLevel.from_score(score), terms=weighted)
