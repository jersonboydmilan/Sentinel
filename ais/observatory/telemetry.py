"""Telemetry.

The observatory subscribes to gateway decisions. It receives *decisions*, not
tool handles: observation carries no authority (P4). Every event is derived
from an audit record, so anything the observatory claims can be independently
re-derived by the auditor agent from the audit chain alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable


@dataclass(frozen=True)
class BehaviorEvent:
    event_id: str
    at: int
    agent_id: str
    capability: str
    decision: str
    policy_id: str
    task_id: str | None = None
    tool: str | None = None
    dataset: str | None = None
    endpoint: str | None = None
    target_agent: str | None = None
    risk_score: float = 0.0
    reasons: tuple[str, ...] = ()
    error: str | None = None
    audit_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW" and self.error is None

    @property
    def token(self) -> str:
        """Compact behavioural token used for sequence analysis and signatures."""
        return f"{self.capability}:{'ok' if self.allowed else 'denied'}"


class TelemetryBus:
    def __init__(self) -> None:
        self._events: list[BehaviorEvent] = []
        self._subscribers: list[Callable[[BehaviorEvent], None]] = []

    def subscribe(self, callback: Callable[[BehaviorEvent], None]) -> None:
        self._subscribers.append(callback)

    def publish(self, event: BehaviorEvent) -> BehaviorEvent:
        self._events.append(event)
        for subscriber in self._subscribers:
            subscriber(event)
        return event

    def events(self, agent_id: str | None = None, since: int | None = None) -> list[BehaviorEvent]:
        out = self._events
        if agent_id is not None:
            out = [e for e in out if e.agent_id == agent_id]
        if since is not None:
            out = [e for e in out if e.at >= since]
        return list(out)

    def __len__(self) -> int:
        return len(self._events)

    def tokens(self, agent_id: str) -> list[str]:
        return [event.token for event in self.events(agent_id)]


def event_from_result(result) -> BehaviorEvent:
    """Adapt a gateway ``ActionResult`` into a telemetry event."""
    request = result.request
    return BehaviorEvent(
        event_id=result.decision_id,
        at=int(result.facts.get("now", 0)),
        agent_id=request.principal_id,
        capability=request.action,
        decision=result.effect.value,
        policy_id=result.policy_id,
        task_id=request.task_id,
        tool=request.tool,
        dataset=request.dataset,
        endpoint=request.endpoint,
        target_agent=request.target_agent,
        risk_score=result.risk.score if result.risk else 0.0,
        reasons=tuple(result.reasons),
        error=result.error,
        audit_id=result.audit_id,
    )
