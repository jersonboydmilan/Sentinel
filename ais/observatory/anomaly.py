"""Anomaly detection.

Deliberately *not* model based. Each detector is a named, deterministic rule or
statistic over the behavioural profile, so every signal it emits can be
re-derived by the auditor from the audit chain. Section 7 requires exactly this:
deterministic rules combined with statistical analysis, not model judgement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..common.util import clamp
from .behavior import BehaviorProfile
from .telemetry import BehaviorEvent

#: Known-suspicious ordered behaviour chain from section 8.
CREDENTIAL_EXFIL_CHAIN = [
    "email.read",
    "credential.read",
    "network.egress",
    "agent.create",
    "agent.delegate",
]


@dataclass(frozen=True)
class AnomalySignal:
    name: str
    score: float
    evidence: tuple[str, ...]
    agent_id: str
    at: int

    def as_dict(self) -> dict:
        return {"name": self.name, "score": round(self.score, 4), "evidence": list(self.evidence)}


Detector = Callable[[BehaviorEvent, BehaviorProfile], AnomalySignal | None]


def unseen_capability_detector(event: BehaviorEvent, profile: BehaviorProfile) -> AnomalySignal | None:
    if profile.unseen_capability(event.capability):
        return AnomalySignal("unseen_capability", 0.6, (f"capability:{event.capability}",), event.agent_id, event.at)
    return None


def unseen_endpoint_detector(event: BehaviorEvent, profile: BehaviorProfile) -> AnomalySignal | None:
    if profile.unseen_endpoint(event.endpoint):
        declared = profile.declared.expected_endpoints if profile.declared else ()
        score = 0.75 if event.endpoint not in declared else 0.4
        return AnomalySignal("unexpected_external_endpoint", score, (f"endpoint:{event.endpoint}",), event.agent_id, event.at)
    return None


def unseen_tool_detector(event: BehaviorEvent, profile: BehaviorProfile) -> AnomalySignal | None:
    if profile.unseen_tool(event.tool):
        return AnomalySignal("unseen_tool", 0.45, (f"tool:{event.tool}",), event.agent_id, event.at)
    return None


def rate_detector(event: BehaviorEvent, profile: BehaviorProfile) -> AnomalySignal | None:
    if not event.task_id:
        return None
    declared = profile.declared
    calls = profile.per_task_calls.get(event.task_id, 0)
    if declared and calls > declared.tool_calls_per_task_max:
        return AnomalySignal(
            "tool_call_rate_above_declared_maximum",
            clamp(0.4 + 0.1 * (calls - declared.tool_calls_per_task_max)),
            (f"calls:{calls}", f"declared_max:{declared.tool_calls_per_task_max}"),
            event.agent_id,
            event.at,
        )
    z = profile.calls_per_task_z(event.task_id)
    if z >= 2.5:
        return AnomalySignal("tool_call_rate_statistical_outlier", clamp(z / 6.0), (f"z:{round(z, 2)}",), event.agent_id, event.at)
    return None


def denial_spike_detector(event: BehaviorEvent, profile: BehaviorProfile) -> AnomalySignal | None:
    if profile.events >= 5 and profile.denied_ratio >= 0.3:
        return AnomalySignal(
            "denied_action_ratio",
            clamp(profile.denied_ratio),
            (f"denied_ratio:{round(profile.denied_ratio, 3)}", f"denied:{profile.denied}"),
            event.agent_id,
            event.at,
        )
    return None


def delegation_detector(event: BehaviorEvent, profile: BehaviorProfile) -> AnomalySignal | None:
    if event.capability != "agent.delegate":
        return None
    declared = profile.declared
    if declared and not declared.delegation_allowed:
        return AnomalySignal(
            "delegation_by_non_delegating_agent",
            0.8,
            (f"target:{event.target_agent}", "declared_delegation:false"),
            event.agent_id,
            event.at,
        )
    return AnomalySignal("delegation_observed", 0.25, (f"target:{event.target_agent}",), event.agent_id, event.at)


def credential_access_detector(event: BehaviorEvent, profile: BehaviorProfile) -> AnomalySignal | None:
    if event.capability != "credential.read":
        return None
    declared = profile.declared
    expected = declared.expected_capabilities if declared else ()
    if "credential.read" not in expected:
        return AnomalySignal("credential_access_outside_profile", 0.85, ("capability:credential.read",), event.agent_id, event.at)
    return None


def sequence_detector(event: BehaviorEvent, profile: BehaviorProfile) -> AnomalySignal | None:
    """Ordered chain analysis - sequences, not isolated events (section 8)."""
    capabilities = [token.split(":")[0] for token in profile.sequence]
    matched = 0
    index = 0
    for capability in capabilities:
        if index < len(CREDENTIAL_EXFIL_CHAIN) and capability == CREDENTIAL_EXFIL_CHAIN[index]:
            index += 1
            matched += 1
    if matched >= 3:
        return AnomalySignal(
            "suspicious_behaviour_chain",
            clamp(0.3 + 0.2 * matched),
            tuple(CREDENTIAL_EXFIL_CHAIN[:matched]),
            event.agent_id,
            event.at,
        )
    if profile.unseen_sequence():
        return AnomalySignal("unseen_behaviour_sequence", 0.3, tuple(profile.recent_tokens(3)), event.agent_id, event.at)
    return None


def escalation_detector(event: BehaviorEvent, profile: BehaviorProfile) -> AnomalySignal | None:
    escalation_reasons = {"capability_not_held", "capability_outside_declared_purpose"}
    if set(event.reasons) & escalation_reasons and not event.allowed:
        attempts = sum(
            1
            for token in profile.sequence
            if token.endswith(":denied")
        )
        return AnomalySignal(
            "privilege_escalation_attempt",
            clamp(0.5 + 0.1 * attempts),
            (f"action:{event.capability}", *sorted(set(event.reasons) & escalation_reasons)),
            event.agent_id,
            event.at,
        )
    return None


DEFAULT_DETECTORS: tuple[Detector, ...] = (
    unseen_capability_detector,
    unseen_endpoint_detector,
    unseen_tool_detector,
    rate_detector,
    denial_spike_detector,
    delegation_detector,
    credential_access_detector,
    sequence_detector,
    escalation_detector,
)


@dataclass
class AnomalyReport:
    agent_id: str
    at: int
    signals: tuple[AnomalySignal, ...] = ()

    @property
    def score(self) -> float:
        """Noisy-OR combination: many weak signals accumulate, none saturates alone."""
        product = 1.0
        for signal in self.signals:
            product *= 1.0 - clamp(signal.score)
        return clamp(1.0 - product)

    def names(self) -> tuple[str, ...]:
        return tuple(signal.name for signal in self.signals)

    def evidence(self) -> tuple[str, ...]:
        out: list[str] = []
        for signal in self.signals:
            out.append(signal.name)
            out.extend(signal.evidence)
        return tuple(out)

    def as_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "score": round(self.score, 4),
            "signals": [s.as_dict() for s in self.signals],
        }


class AnomalyEngine:
    def __init__(self, detectors: Iterable[Detector] = DEFAULT_DETECTORS) -> None:
        self._detectors = tuple(detectors)
        self._reports: dict[str, AnomalyReport] = {}
        self._history: list[AnomalyReport] = []

    def evaluate(self, event: BehaviorEvent, profile: BehaviorProfile) -> AnomalyReport:
        signals = []
        for detector in self._detectors:
            signal = detector(event, profile)
            if signal is not None:
                signals.append(signal)
        report = AnomalyReport(agent_id=event.agent_id, at=event.at, signals=tuple(signals))
        self._reports[event.agent_id] = report
        self._history.append(report)
        return report

    def latest(self, agent_id: str) -> AnomalyReport:
        return self._reports.get(agent_id, AnomalyReport(agent_id=agent_id, at=0))

    def history(self, agent_id: str | None = None) -> list[AnomalyReport]:
        if agent_id is None:
            return list(self._history)
        return [r for r in self._history if r.agent_id == agent_id]
