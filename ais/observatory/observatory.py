"""Behavioural Observatory facade.

Binds telemetry, profiles, graphs, anomaly detection and drift analysis to a
control plane. The observatory holds **no** authority: it registers a fact
provider (read only input to policy) and an observer (read only output from the
gateway). It cannot allow, deny or contain anything - P4 made structural.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..control_plane.gateway import ActionRequest, ActionResult
from ..control_plane.plane import ControlPlane
from .anomaly import AnomalyEngine, AnomalyReport
from .behavior import BehaviorProfile, BehaviorProfiler, DeclaredProfile
from .drift import AuthorityDriftEngine, DriftReport
from .graph import AgentIdentityGraph, BehaviorGraph
from .telemetry import BehaviorEvent, TelemetryBus, event_from_result


@dataclass
class ObservatorySnapshot:
    agents: int
    events: int
    identity_graph: dict
    behaviour_graph: dict


class Observatory:
    def __init__(self, plane: ControlPlane) -> None:
        self.plane = plane
        self.telemetry = TelemetryBus()
        self.profiler = BehaviorProfiler()
        self.anomalies = AnomalyEngine()
        self.identity_graph = AgentIdentityGraph()
        self.behaviour_graph = BehaviorGraph()
        self.drift = AuthorityDriftEngine(plane.authority, plane.contracts, self.profiler, self.anomalies)
        self._last_event_at: dict[str, int] = {}

        plane.gateway.add_observer(self._on_decision)
        plane.gateway.add_fact_provider(self.fact_provider)
        plane.audit.subscribe(self._on_audit)

    # -- ingestion ---------------------------------------------------------
    def _on_decision(self, result: ActionResult) -> None:
        event = event_from_result(result)
        self.telemetry.publish(event)
        profile = self.profiler.observe(event)
        self.behaviour_graph.ingest_event(event)
        self.anomalies.evaluate(event, profile)
        self.drift.evaluate(event.agent_id, at=event.at)
        self._last_event_at[event.agent_id] = event.at

    def _on_audit(self, record) -> None:
        if record.event_type == "authority.granted":
            grant_id = record.payload.get("grant_id")
            for grant in self.plane.authority.all_grants():
                if grant.grant_id == grant_id:
                    self.identity_graph.ingest_grant(grant)
                    break
        elif record.event_type == "delegation.allowed":
            self.identity_graph.ingest_delegation(
                record.actor_id,
                record.subject_id,
                record.payload.get("capabilities", []),
                at=record.timestamp,
            )
        elif record.event_type == "authority.revoked":
            self.identity_graph.add_edge(record.subject_id, "REVOKED_BY", record.actor_id or "control-plane", at=record.timestamp)

    def ingest_principals(self) -> None:
        for principal in self.plane.identity.all_principals():
            self.identity_graph.ingest_principal(principal)

    def declare_profile(self, document: dict) -> BehaviorProfile:
        declared = DeclaredProfile.from_document(document)
        return self.profiler.declare(declared)

    # -- read only facts for the policy engine -----------------------------
    def fact_provider(self, request: ActionRequest, facts: dict) -> dict:
        agent_id = request.principal_id
        profile = self.profiler.profile(agent_id)
        drift = self.drift.latest(agent_id)
        anomaly = self.anomalies.latest(agent_id)
        return {
            "drift_score": drift.score,
            "drift_kinds": list(drift.kinds()),
            "anomaly_score": anomaly.score,
            "anomaly_signals": list(anomaly.names()),
            "denied_ratio": profile.denied_ratio,
            "behaviour_events": profile.events,
            "baseline_locked": profile.baseline_locked,
        }

    # -- queries -----------------------------------------------------------
    def profile(self, agent_id: str) -> BehaviorProfile:
        return self.profiler.profile(agent_id)

    def drift_report(self, agent_id: str) -> DriftReport:
        return self.drift.latest(agent_id)

    def anomaly_report(self, agent_id: str) -> AnomalyReport:
        return self.anomalies.latest(agent_id)

    def behaviour_tokens(self, agent_id: str) -> list[str]:
        return self.telemetry.tokens(agent_id)

    def snapshot(self) -> ObservatorySnapshot:
        return ObservatorySnapshot(
            agents=len(self.profiler.known_agents()),
            events=len(self.telemetry),
            identity_graph=self.identity_graph.summary(),
            behaviour_graph=self.behaviour_graph.summary(),
        )
