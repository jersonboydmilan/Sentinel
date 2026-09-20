"""Immune system facade.

Ties classification, immune memory, verification and response planning to the
observatory and the control plane, and contributes the immune facts that policy
depends on (``verification_valid``, ``immune_match_score``, ...).

Like the observatory, the immune system holds no authority of its own: it can
compute a plan, but only a defensive agent with the matching defensive
capability can ask the control plane to execute it.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..control_plane.gateway import ActionRequest
from ..control_plane.plane import ControlPlane
from ..observatory.observatory import Observatory
from .classification import Classification, ThreatClassifier
from .memory import ImmuneMemory
from .response import ResponsePlan, ResponsePlanner
from .verification import AuthorizationLedger, VerificationLedger

ESCAPE_OUTCOMES = {
    "network_blocked",
    "sandbox_write_absorbed",
    "fake_credential_issued",
    "message_contained",
}


class ImmuneSystem:
    def __init__(self, plane: ControlPlane, observatory: Observatory, *, memory_path: str | None = None) -> None:
        self.plane = plane
        self.observatory = observatory
        self.memory = ImmuneMemory(plane.audit, plane.clock, plane.ids, memory_path)
        self.classifier = ThreatClassifier()
        self.planner = ResponsePlanner()
        self.verifications = VerificationLedger(plane.authority, plane.audit, plane.clock, plane.ids)
        self.authorizations = AuthorizationLedger(plane.audit, plane.clock, plane.ids)
        self._classifications: dict[str, Classification] = {}
        plane.gateway.add_fact_provider(self.fact_provider)

    # -- facts -------------------------------------------------------------
    def fact_provider(self, request: ActionRequest, facts: dict) -> dict:
        claimed = request.payload.get("verification_ref")
        subject = request.target_agent or request.principal_id
        verification = self.verifications.validate(claimed, subject)
        authorization_ref = request.payload.get("authorization_ref")
        matches = self.match_agent(subject)
        return {
            "verification_valid": verification is not None,
            "verification_confidence": verification.confidence if verification else 0.0,
            "verification_subject": verification.subject_id if verification else None,
            "external_authorization_valid": self.authorizations.validate(authorization_ref, subject, "restore"),
            "immune_match_score": max([m.score for m in matches], default=0.0),
            "immune_matches": [m.as_dict() for m in matches],
        }

    # -- analysis ----------------------------------------------------------
    def match_agent(self, agent_id: str):
        tokens = self.observatory.behaviour_tokens(agent_id)
        authority = self.plane.authority.granted(agent_id).as_strings()
        delegation = sorted(self.observatory.profile(agent_id).delegation_targets)
        return self.memory.match(tokens=tokens, authority=authority, delegation=delegation)

    def escape_attempts(self, agent_id: str) -> int:
        environment = self.plane.quarantine.environment_for(agent_id)
        if environment is None:
            return 0
        return sum(1 for event in environment.events if event.outcome in ESCAPE_OUTCOMES)

    def assess(self, agent_id: str) -> Classification:
        observatory = self.observatory
        profile = observatory.profile(agent_id)
        drift = observatory.drift_report(agent_id)
        anomaly = observatory.anomaly_report(agent_id)
        events = observatory.telemetry.events(agent_id)
        policy_violations = sum(1 for event in events if not event.allowed)
        matches = self.match_agent(agent_id)
        classification = self.classifier.classify(
            agent_id,
            drift=drift,
            anomaly=anomaly,
            profile=profile,
            policy_violations=policy_violations,
            quarantined=self.plane.containment.is_quarantined(agent_id),
            escape_attempts=self.escape_attempts(agent_id),
            source_events=[event.event_id for event in events],
            affected_resources=sorted(
                set(profile.tool_counts) | set(profile.dataset_counts) | set(profile.endpoint_counts)
            ),
            authority_involved=sorted(profile.capability_counts),
            memory_matches=matches,
            memory_prior=self.memory.prior(matches),
            at=self.plane.clock.now,
        )
        self._classifications[agent_id] = classification
        return classification

    def latest(self, agent_id: str) -> Classification | None:
        return self._classifications.get(agent_id)

    def plan(self, agent_id: str) -> ResponsePlan:
        classification = self._classifications.get(agent_id) or self.assess(agent_id)
        drift = self.observatory.drift_report(agent_id)
        implicated = sorted(
            {
                item.split(":", 1)[1]
                for item in drift.evidence()
                if item.startswith(("attempted_without_grant:", "outside_declared_purpose:", "novel_capability:"))
            }
        )
        return self.planner.plan(classification, drift_capabilities=implicated)
