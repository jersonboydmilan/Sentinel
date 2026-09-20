"""Threat classification (section 9).

Every classification carries evidence, confidence, source events, affected
resources, the authority involved and a recommended response. Classification is
deterministic: the same audit chain yields the same class and the same
confidence, which is what lets SENTINEL-AUDIT reproduce it independently.

Low confidence can never trigger an irreversible response - that gate lives
both here (``recommended_action``) and in policy (POL-110).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..common.util import clamp
from ..control_plane.containment import ContainmentAction
from ..observatory.anomaly import AnomalyReport
from ..observatory.behavior import BehaviorProfile
from ..observatory.drift import DriftReport
from .signatures import SignatureMatch


class ThreatClass(str, Enum):
    NORMAL = "NORMAL"
    ANOMALOUS = "ANOMALOUS"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    AUTHORITY_DRIFT = "AUTHORITY_DRIFT"
    COMPROMISED = "COMPROMISED"
    CONTAINMENT_BREACH = "CONTAINMENT_BREACH"

    @property
    def severity(self) -> int:
        return {
            ThreatClass.NORMAL: 0,
            ThreatClass.ANOMALOUS: 1,
            ThreatClass.POLICY_VIOLATION: 2,
            ThreatClass.AUTHORITY_DRIFT: 3,
            ThreatClass.COMPROMISED: 4,
            ThreatClass.CONTAINMENT_BREACH: 5,
        }[self]


#: Minimum confidence required before each response may be recommended.
ACTION_CONFIDENCE_GATES = {
    ContainmentAction.MONITOR: 0.0,
    ContainmentAction.RESTRICT: 0.5,
    ContainmentAction.ISOLATE: 0.6,
    ContainmentAction.QUARANTINE: 0.7,
    ContainmentAction.REVOKE: 0.85,
}


@dataclass(frozen=True)
class Classification:
    agent_id: str
    threat_class: ThreatClass
    confidence: float
    evidence: tuple[str, ...]
    source_events: tuple[str, ...]
    affected_resources: tuple[str, ...]
    authority_involved: tuple[str, ...]
    recommended_action: ContainmentAction
    at: int
    memory_matches: tuple[dict, ...] = ()
    rationale: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "agent": self.agent_id,
            "classification": self.threat_class.value,
            "confidence": round(self.confidence, 4),
            "evidence": list(self.evidence),
            "source_events": list(self.source_events),
            "affected_resources": list(self.affected_resources),
            "authority_involved": list(self.authority_involved),
            "recommended_action": self.recommended_action.value,
            "memory_matches": list(self.memory_matches),
            "rationale": list(self.rationale),
        }


class ThreatClassifier:
    def __init__(self, *, policy_violation_threshold: int = 2) -> None:
        self._policy_violation_threshold = policy_violation_threshold

    def classify(
        self,
        agent_id: str,
        *,
        drift: DriftReport,
        anomaly: AnomalyReport,
        profile: BehaviorProfile,
        policy_violations: int,
        quarantined: bool,
        escape_attempts: int,
        source_events: list[str],
        affected_resources: list[str],
        authority_involved: list[str],
        memory_matches: list[SignatureMatch] | None = None,
        memory_prior: float = 0.0,
        collusion_score: float = 0.0,
        collusion_evidence: tuple[str, ...] = (),
        at: int = 0,
    ) -> Classification:
        matches = memory_matches or []
        rationale: list[str] = []
        evidence: list[str] = []
        evidence.extend(drift.evidence())
        evidence.extend(anomaly.evidence())
        if collusion_score:
            evidence.extend(collusion_evidence)

        # --- class selection (ordered, deterministic) ---------------------
        if quarantined and escape_attempts > 0:
            threat = ThreatClass.CONTAINMENT_BREACH
            base = 0.9
            rationale.append(f"quarantined agent attempted {escape_attempts} escape action(s)")
        elif self._compromise_pattern(drift, anomaly):
            threat = ThreatClass.COMPROMISED
            base = 0.6 + 0.3 * drift.score
            rationale.append("multiple drift classes plus credential or escalation behaviour")
        elif drift.drift and drift.score >= 0.5:
            threat = ThreatClass.AUTHORITY_DRIFT
            base = 0.5 + 0.4 * drift.score
            rationale.append(f"authority drift score {round(drift.score, 3)} over {len(drift.components)} component(s)")
        elif policy_violations >= self._policy_violation_threshold:
            threat = ThreatClass.POLICY_VIOLATION
            base = clamp(0.4 + 0.1 * policy_violations)
            rationale.append(f"{policy_violations} denied policy decisions")
        elif collusion_score >= 0.6:
            # Split-capability behaviour: neither agent exceeded its own
            # authority, so this is a relationship finding, not a drift finding.
            threat = ThreatClass.POLICY_VIOLATION if policy_violations else ThreatClass.ANOMALOUS
            base = 0.3 + 0.5 * collusion_score
            rationale.append(f"cross-agent collusion pattern, score {round(collusion_score, 3)}")
        elif anomaly.score >= 0.4:
            threat = ThreatClass.ANOMALOUS
            base = 0.3 + 0.4 * anomaly.score
            rationale.append(f"anomaly score {round(anomaly.score, 3)}")
        else:
            threat = ThreatClass.NORMAL
            base = clamp(1.0 - max(anomaly.score, drift.score))
            rationale.append("no drift and no significant anomaly")

        # --- confidence ---------------------------------------------------
        confidence = clamp(base)
        if threat is not ThreatClass.NORMAL:
            # Independent corroboration raises confidence; memory contributes a
            # strictly bounded prior (section 12: evidence, not guilt).
            corroboration = 0.0
            if drift.drift:
                corroboration += 0.05 * len(drift.components)
            if anomaly.signals:
                corroboration += 0.03 * len(anomaly.signals)
            if profile.denied_ratio >= 0.4:
                corroboration += 0.05
            confidence = clamp(confidence + min(corroboration, 0.2) + memory_prior)
            if matches:
                rationale.append(
                    f"immune memory prior {round(memory_prior, 3)} from {len(matches)} signature match(es)"
                )

        action = self._recommend(threat, confidence)
        return Classification(
            agent_id=agent_id,
            threat_class=threat,
            confidence=confidence,
            evidence=tuple(dict.fromkeys(evidence)),
            source_events=tuple(source_events[-20:]),
            affected_resources=tuple(sorted(set(affected_resources))),
            authority_involved=tuple(sorted(set(authority_involved))),
            recommended_action=action,
            at=at,
            memory_matches=tuple(m.as_dict() for m in matches),
            rationale=tuple(rationale),
        )

    # -- helpers -----------------------------------------------------------
    def _compromise_pattern(self, drift: DriftReport, anomaly: AnomalyReport) -> bool:
        kinds = set(drift.kinds())
        signals = set(anomaly.names())
        severe_drift = {"CREDENTIAL_DRIFT", "ESCALATION_DRIFT", "DELEGATION_DRIFT"} & kinds
        chain = "suspicious_behaviour_chain" in signals
        return bool(severe_drift) and (len(kinds) >= 3 or chain) and drift.score >= 0.7

    def _recommend(self, threat: ThreatClass, confidence: float) -> ContainmentAction:
        desired = {
            ThreatClass.NORMAL: ContainmentAction.MONITOR,
            ThreatClass.ANOMALOUS: ContainmentAction.MONITOR,
            ThreatClass.POLICY_VIOLATION: ContainmentAction.RESTRICT,
            ThreatClass.AUTHORITY_DRIFT: ContainmentAction.RESTRICT,
            ThreatClass.COMPROMISED: ContainmentAction.QUARANTINE,
            ThreatClass.CONTAINMENT_BREACH: ContainmentAction.REVOKE,
        }[threat]
        # Step down until the confidence gate for the action is satisfied.
        ladder = [
            ContainmentAction.REVOKE,
            ContainmentAction.QUARANTINE,
            ContainmentAction.ISOLATE,
            ContainmentAction.RESTRICT,
            ContainmentAction.MONITOR,
        ]
        start = ladder.index(desired)
        for action in ladder[start:]:
            if confidence >= ACTION_CONFIDENCE_GATES[action]:
                return action
        return ContainmentAction.MONITOR
