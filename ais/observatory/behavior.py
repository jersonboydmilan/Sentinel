"""Behavioural identity (section 6).

Credentials say *who* an agent claims to be. A behavioural profile says how
that agent has actually acted: which capabilities, in which order, against
which data and endpoints, at what rate, with what error and denial patterns.

Profiles have two sources:

* a **declared** profile, written by the operator (the YAML in section 6), and
* an **observed** baseline, learned over a warm-up window.

Both are kept: a compromised agent that mimics its declared profile while
drifting from its learned one is still visible, and vice versa.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean, pstdev
from typing import Iterable

from ..common.util import ngrams
from .telemetry import BehaviorEvent

WARMUP_EVENTS = 8
SEQUENCE_N = 3


@dataclass
class DeclaredProfile:
    """Operator declared expectations - the ``agent_profile`` YAML of section 6."""

    agent_id: str
    tool_calls_per_task_min: int = 0
    tool_calls_per_task_max: int = 20
    delegation_allowed: bool = False
    database_access: str = "read_only"
    expected_endpoints: tuple[str, ...] = ()
    expected_tools: tuple[str, ...] = ()
    expected_capabilities: tuple[str, ...] = ()
    max_execution_time: int = 10

    @classmethod
    def from_document(cls, document: dict) -> "DeclaredProfile":
        profile = document.get("agent_profile", document)
        normal = profile.get("normal_behavior", {}) or {}
        tool_calls = normal.get("tool_calls_per_task", {}) or {}
        delegation = normal.get("delegation", {}) or {}
        database = normal.get("database", {}) or {}
        external = (normal.get("external_domains", {}) or {}).get("expected", []) or []
        execution = normal.get("execution_time", {}) or {}
        return cls(
            agent_id=profile.get("agent_id", "unknown"),
            tool_calls_per_task_min=int(tool_calls.get("min", 0)),
            tool_calls_per_task_max=int(tool_calls.get("max", 20)),
            delegation_allowed=bool(delegation.get("allowed", False)),
            database_access=str(database.get("access", "read_only")),
            expected_endpoints=tuple(external),
            expected_tools=tuple(normal.get("tools", []) or []),
            expected_capabilities=tuple(normal.get("capabilities", []) or []),
            max_execution_time=int(execution.get("max_minutes", 10)),
        )


@dataclass
class BehaviorProfile:
    agent_id: str
    declared: DeclaredProfile | None = None
    capability_counts: dict[str, int] = field(default_factory=dict)
    tool_counts: dict[str, int] = field(default_factory=dict)
    dataset_counts: dict[str, int] = field(default_factory=dict)
    endpoint_counts: dict[str, int] = field(default_factory=dict)
    delegation_targets: dict[str, int] = field(default_factory=dict)
    sequence: list[str] = field(default_factory=list)
    known_ngrams: set[tuple[str, ...]] = field(default_factory=set)
    per_task_calls: dict[str, int] = field(default_factory=dict)
    task_durations: list[int] = field(default_factory=list)
    task_started: dict[str, int] = field(default_factory=dict)
    denied: int = 0
    allowed: int = 0
    errors: int = 0
    events: int = 0
    baseline_capabilities: set[str] = field(default_factory=set)
    baseline_endpoints: set[str] = field(default_factory=set)
    baseline_tools: set[str] = field(default_factory=set)
    baseline_locked: bool = False
    baseline_calls_per_task: list[int] = field(default_factory=list)

    # -- ingestion ---------------------------------------------------------
    def observe(self, event: BehaviorEvent) -> None:
        self.events += 1
        self.capability_counts[event.capability] = self.capability_counts.get(event.capability, 0) + 1
        if event.tool:
            self.tool_counts[event.tool] = self.tool_counts.get(event.tool, 0) + 1
        if event.dataset:
            self.dataset_counts[event.dataset] = self.dataset_counts.get(event.dataset, 0) + 1
        if event.endpoint:
            self.endpoint_counts[event.endpoint] = self.endpoint_counts.get(event.endpoint, 0) + 1
        if event.target_agent:
            self.delegation_targets[event.target_agent] = self.delegation_targets.get(event.target_agent, 0) + 1
        if event.allowed:
            self.allowed += 1
        else:
            self.denied += 1
        if event.error:
            self.errors += 1
        self.sequence.append(event.token)
        if event.task_id:
            self.per_task_calls[event.task_id] = self.per_task_calls.get(event.task_id, 0) + 1
            self.task_started.setdefault(event.task_id, event.at)
            self.task_durations.append(event.at - self.task_started[event.task_id])

        if not self.baseline_locked:
            self.baseline_capabilities.add(event.capability)
            if event.endpoint:
                self.baseline_endpoints.add(event.endpoint)
            if event.tool:
                self.baseline_tools.add(event.tool)
            self.known_ngrams.update(ngrams(self.sequence, SEQUENCE_N))
            if event.task_id:
                self.baseline_calls_per_task = list(self.per_task_calls.values())
            if self.events >= WARMUP_EVENTS:
                self.baseline_locked = True

    # -- derived statistics ------------------------------------------------
    @property
    def denied_ratio(self) -> float:
        total = self.allowed + self.denied
        return self.denied / total if total else 0.0

    @property
    def mean_calls_per_task(self) -> float:
        values = list(self.per_task_calls.values())
        return mean(values) if values else 0.0

    def calls_per_task_z(self, task_id: str) -> float:
        """Standard score of the current task's call count vs the baseline."""
        baseline = self.baseline_calls_per_task or list(self.per_task_calls.values())
        if len(baseline) < 2:
            return 0.0
        spread = pstdev(baseline)
        if spread == 0:
            return 0.0 if self.per_task_calls.get(task_id, 0) <= max(baseline) else 3.0
        return (self.per_task_calls.get(task_id, 0) - mean(baseline)) / spread

    def unseen_capability(self, capability: str) -> bool:
        return self.baseline_locked and capability not in self.baseline_capabilities

    def unseen_endpoint(self, endpoint: str | None) -> bool:
        return bool(endpoint) and self.baseline_locked and endpoint not in self.baseline_endpoints

    def unseen_tool(self, tool: str | None) -> bool:
        return bool(tool) and self.baseline_locked and tool not in self.baseline_tools

    def unseen_sequence(self) -> bool:
        grams = ngrams(self.sequence, SEQUENCE_N)
        if not grams or not self.baseline_locked:
            return False
        return grams[-1] not in self.known_ngrams

    def recent_tokens(self, window: int = 12) -> list[str]:
        return self.sequence[-window:]

    def snapshot(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "events": self.events,
            "allowed": self.allowed,
            "denied": self.denied,
            "denied_ratio": round(self.denied_ratio, 4),
            "capabilities": sorted(self.capability_counts),
            "endpoints": sorted(self.endpoint_counts),
            "tools": sorted(self.tool_counts),
            "delegation_targets": sorted(self.delegation_targets),
            "baseline_locked": self.baseline_locked,
            "baseline_capabilities": sorted(self.baseline_capabilities),
            "mean_calls_per_task": round(self.mean_calls_per_task, 3),
        }


class BehaviorProfiler:
    def __init__(self) -> None:
        self._profiles: dict[str, BehaviorProfile] = {}

    def declare(self, profile: DeclaredProfile) -> BehaviorProfile:
        existing = self.profile(profile.agent_id)
        existing.declared = profile
        return existing

    def profile(self, agent_id: str) -> BehaviorProfile:
        if agent_id not in self._profiles:
            self._profiles[agent_id] = BehaviorProfile(agent_id=agent_id)
        return self._profiles[agent_id]

    def observe(self, event: BehaviorEvent) -> BehaviorProfile:
        profile = self.profile(event.agent_id)
        profile.observe(event)
        return profile

    def all_profiles(self) -> list[BehaviorProfile]:
        return list(self._profiles.values())

    def known_agents(self) -> list[str]:
        return sorted(self._profiles)
