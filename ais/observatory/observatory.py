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
from ..common.util import seeded_rng
from .anomaly import AnomalyEngine, AnomalyReport
from .collusion import CollusionAnalyzer, CollusionSignal
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
    """Read-only behavioural observation.

    ``observation_loss`` models partial observability: a fraction of decisions
    never reach the observatory (a dropped telemetry event, an unmonitored
    runtime). It is applied deterministically from a seed so that a noisy run is
    still reproducible. Enforcement is unaffected - the gateway still decides
    every request - which is precisely the point: observation degrades, the
    authority model does not.
    """

    def __init__(self, plane: ControlPlane, *, observation_loss: float = 0.0, seed: str = "observatory") -> None:
        self.plane = plane
        self.observation_loss = observation_loss
        self._rng = seeded_rng(seed)
        self.dropped_events = 0
        self.telemetry = TelemetryBus()
        self.profiler = BehaviorProfiler()
        self.anomalies = AnomalyEngine()
        self.identity_graph = AgentIdentityGraph()
        self.behaviour_graph = BehaviorGraph()
        self.drift = AuthorityDriftEngine(plane.authority, plane.contracts, self.profiler, self.anomalies)
        self.collusion = CollusionAnalyzer(self.telemetry, plane.authority)
        self._last_event_at: dict[str, int] = {}

        plane.gateway.add_observer(self._on_decision)
        plane.gateway.add_fact_provider(self.fact_provider)
        plane.audit.subscribe(self._on_audit)

    # -- ingestion ---------------------------------------------------------
    def _on_decision(self, result: ActionResult) -> None:
        if self.observation_loss and self._rng.random() < self.observation_loss:
            self.dropped_events += 1
            return
        event = event_from_result(result)
        self.telemetry.publish(event)
        profile = self.profiler.observe(event)
        self.behaviour_graph.ingest_event(event)
        self.anomalies.evaluate(event, profile)
        self.drift.evaluate(event.agent_id, at=event.at)
        self.collusion.analyse()
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
        from .collusion import ACQUISITION, EXFILTRATION, TRANSFER

        agent_id = request.principal_id
        profile = self.profiler.profile(agent_id)
        drift = self.drift.latest(agent_id)
        anomaly = self.anomalies.latest(agent_id)
        collusion = self.collusion.for_agent(agent_id)
        chain_capabilities = ACQUISITION | TRANSFER | EXFILTRATION
        return {
            "collusion_score": max((signal.score for signal in collusion), default=0.0),
            "collusion_partners": sorted(
                {s.partner_agent if s.source_agent == agent_id else s.source_agent for s in collusion}
            ),
            "capability_in_collusion_chain": request.action in chain_capabilities,
            "drift_score": drift.score,
            "drift_kinds": list(drift.kinds()),
            "anomaly_score": anomaly.score,
            "anomaly_signals": list(anomaly.names()),
            "denied_ratio": profile.denied_ratio,
            "behaviour_events": profile.events,
            "baseline_locked": profile.baseline_locked,
            "observation_loss": self.observation_loss,
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

    def collusion_signals(self, agent_id: str | None = None) -> list[CollusionSignal]:
        signals = self.collusion.analyse()
        if agent_id is None:
            return signals
        return [signal for signal in signals if signal.involves(agent_id)]

    def snapshot(self) -> ObservatorySnapshot:
        return ObservatorySnapshot(
            agents=len(self.profiler.known_agents()),
            events=len(self.telemetry),
            identity_graph=self.identity_graph.summary(),
            behaviour_graph=self.behaviour_graph.summary(),
        )
