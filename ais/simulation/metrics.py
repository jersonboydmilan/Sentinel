"""Evaluation metrics (section 22).

Ground truth labels come from the simulation scripts and are never visible to
the control plane, observatory, immune system or defensive agents. Time is
measured in logical steps (deterministic); latency and throughput are measured
in wall clock terms because they describe the implementation, not the model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return ordered[index]


@dataclass
class AgentOutcome:
    agent_id: str
    malicious: bool
    first_violation_step: int | None = None
    first_flag_step: int | None = None
    first_verified_flag_step: int | None = None
    first_restriction_step: int | None = None
    first_quarantine_step: int | None = None
    revoked_step: int | None = None
    contained: bool = False
    flagged: bool = False
    verified: bool = False

    @property
    def time_to_detection(self) -> int | None:
        if self.first_violation_step is None or self.first_verified_flag_step is None:
            return None
        return max(0, self.first_verified_flag_step - self.first_violation_step)

    @property
    def time_to_restriction(self) -> int | None:
        if self.first_violation_step is None or self.first_restriction_step is None:
            return None
        return max(0, self.first_restriction_step - self.first_violation_step)

    @property
    def time_to_quarantine(self) -> int | None:
        if self.first_violation_step is None or self.first_quarantine_step is None:
            return None
        return max(0, self.first_quarantine_step - self.first_violation_step)


@dataclass
class MetricsCollector:
    outcomes: dict[str, AgentOutcome] = field(default_factory=dict)
    unauthorized_attempts: int = 0
    unauthorized_prevented: int = 0
    delegation_attempts: int = 0
    delegation_blocked: int = 0
    amplification_blocked: int = 0
    defender_violations: int = 0
    defender_escape_attempts: int = 0
    defender_escapes_succeeded: int = 0
    quarantine_escape_attempts: int = 0
    quarantine_escapes_succeeded: int = 0
    audit_tamper_detected: int = 0
    policy_latencies: list[float] = field(default_factory=list)
    decisions: int = 0
    wall_seconds: float = 0.0

    # -- registration ------------------------------------------------------
    def register(self, agent_id: str, malicious: bool) -> AgentOutcome:
        outcome = AgentOutcome(agent_id=agent_id, malicious=malicious)
        self.outcomes[agent_id] = outcome
        return outcome

    def outcome(self, agent_id: str) -> AgentOutcome:
        if agent_id not in self.outcomes:
            self.register(agent_id, malicious=False)
        return self.outcomes[agent_id]

    # -- event recording ---------------------------------------------------
    def record_violation(self, agent_id: str, step: int) -> None:
        outcome = self.outcome(agent_id)
        if outcome.first_violation_step is None:
            outcome.first_violation_step = step

    def record_flag(self, agent_id: str, step: int, verified: bool) -> None:
        outcome = self.outcome(agent_id)
        outcome.flagged = True
        if outcome.first_flag_step is None:
            outcome.first_flag_step = step
        if verified:
            outcome.verified = True
            if outcome.first_verified_flag_step is None:
                outcome.first_verified_flag_step = step

    def record_containment(self, agent_id: str, action: str, step: int) -> None:
        outcome = self.outcome(agent_id)
        outcome.contained = True
        if action == "RESTRICT" and outcome.first_restriction_step is None:
            outcome.first_restriction_step = step
        if action == "QUARANTINE" and outcome.first_quarantine_step is None:
            outcome.first_quarantine_step = step
        if action == "REVOKE" and outcome.revoked_step is None:
            outcome.revoked_step = step

    # -- aggregate ---------------------------------------------------------
    @property
    def malicious_agents(self) -> list[AgentOutcome]:
        return [o for o in self.outcomes.values() if o.malicious]

    @property
    def benign_agents(self) -> list[AgentOutcome]:
        return [o for o in self.outcomes.values() if not o.malicious]

    def detection_rate(self) -> float:
        malicious = self.malicious_agents
        if not malicious:
            return 0.0
        return sum(1 for o in malicious if o.verified) / len(malicious)

    def false_positive_rate(self) -> float:
        """Benign agents that reached *verified* containment."""
        benign = self.benign_agents
        if not benign:
            return 0.0
        return sum(1 for o in benign if o.contained) / len(benign)

    def flag_false_positive_rate(self) -> float:
        """Benign agents flagged at all (before independent verification)."""
        benign = self.benign_agents
        if not benign:
            return 0.0
        return sum(1 for o in benign if o.flagged) / len(benign)

    def containment_success_rate(self) -> float:
        malicious = self.malicious_agents
        if not malicious:
            return 0.0
        return sum(1 for o in malicious if o.contained) / len(malicious)

    def mean_time_to(self, attribute: str) -> float | None:
        values = [getattr(o, attribute) for o in self.malicious_agents]
        values = [v for v in values if v is not None]
        return round(mean(values), 3) if values else None

    def prevention_rate(self) -> float:
        if not self.unauthorized_attempts:
            return 1.0
        return self.unauthorized_prevented / self.unauthorized_attempts

    def report(self) -> dict:
        return {
            "detection": {
                "detection_rate": round(self.detection_rate(), 4),
                "false_positive_rate": round(self.false_positive_rate(), 4),
                "flag_false_positive_rate": round(self.flag_false_positive_rate(), 4),
                "mean_time_to_detection_steps": self.mean_time_to("time_to_detection"),
            },
            "containment": {
                "containment_success_rate": round(self.containment_success_rate(), 4),
                "mean_time_to_restriction_steps": self.mean_time_to("time_to_restriction"),
                "mean_time_to_quarantine_steps": self.mean_time_to("time_to_quarantine"),
            },
            "governance": {
                "unauthorized_attempts": self.unauthorized_attempts,
                "unauthorized_prevented": self.unauthorized_prevented,
                "unauthorized_prevention_rate": round(self.prevention_rate(), 4),
                "delegation_attempts": self.delegation_attempts,
                "delegation_violations_blocked": self.delegation_blocked,
                "authority_amplification_blocked": self.amplification_blocked,
            },
            "defender_safety": {
                "defensive_agent_policy_violations": self.defender_violations,
                "defender_escape_attempts": self.defender_escape_attempts,
                "defender_escapes_succeeded": self.defender_escapes_succeeded,
                "quarantine_escape_attempts": self.quarantine_escape_attempts,
                "quarantine_escapes_succeeded": self.quarantine_escapes_succeeded,
            },
            "performance": {
                "decisions": self.decisions,
                "policy_latency_p50_ms": round(_percentile(self.policy_latencies, 0.5), 4),
                "policy_latency_p95_ms": round(_percentile(self.policy_latencies, 0.95), 4),
                "policy_latency_max_ms": round(max(self.policy_latencies, default=0.0), 4),
                "throughput_decisions_per_second": round(self.decisions / self.wall_seconds, 1) if self.wall_seconds else None,
            },
            "per_agent": {
                agent_id: {
                    "malicious": outcome.malicious,
                    "flagged": outcome.flagged,
                    "verified": outcome.verified,
                    "contained": outcome.contained,
                    "time_to_detection": outcome.time_to_detection,
                    "time_to_restriction": outcome.time_to_restriction,
                    "time_to_quarantine": outcome.time_to_quarantine,
                }
                for agent_id, outcome in sorted(self.outcomes.items())
            },
        }
