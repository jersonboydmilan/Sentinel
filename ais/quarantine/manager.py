"""Quarantine manager.

Owns the lifecycle of isolated execution environments and binds them into the
gateway so that a quarantined agent's requests are transparently routed to the
sandbox registry. The agent is never told which registry it reached - escape
attempts are therefore observable rather than merely blocked.
"""

from __future__ import annotations

from ..common.errors import QuarantineEscape
from ..common.util import IdFactory, LogicalClock
from ..control_plane.audit import AuditService
from .sandbox import QuarantineEnvironment, build_sandbox_registry


class QuarantineManager:
    def __init__(self, audit: AuditService, clock: LogicalClock, ids: IdFactory, gateway=None) -> None:
        self._audit = audit
        self._clock = clock
        self._ids = ids
        self._gateway = gateway
        self._environments: dict[str, QuarantineEnvironment] = {}
        self._by_agent: dict[str, str] = {}

    def bind_gateway(self, gateway) -> None:
        self._gateway = gateway

    # -- lifecycle ---------------------------------------------------------
    def admit(self, agent_id: str, *, reason: str, actor_id: str) -> QuarantineEnvironment:
        if agent_id in self._by_agent:
            return self._environments[self._by_agent[agent_id]]
        environment = QuarantineEnvironment(
            environment_id=self._ids.new("QEN"),
            agent_id=agent_id,
            reason=reason,
            admitted_by=actor_id,
            admitted_at=self._clock.now,
            seed=f"{agent_id}:{self._clock.now}",
            registry=None,  # type: ignore[arg-type]
        )
        environment.registry = build_sandbox_registry(environment)
        self._environments[environment.environment_id] = environment
        self._by_agent[agent_id] = environment.environment_id
        if self._gateway is not None:
            self._gateway.bind_quarantine_registry(agent_id, environment.registry)
        self._audit.append(
            "quarantine.admitted",
            actor_id=actor_id,
            subject_id=agent_id,
            payload={"environment_id": environment.environment_id, "reason": reason, "seed": environment.seed},
        )
        return environment

    def release(self, agent_id: str) -> None:
        environment_id = self._by_agent.pop(agent_id, None)
        if environment_id is None:
            return
        environment = self._environments[environment_id]
        environment.released_at = self._clock.now
        if self._gateway is not None:
            self._gateway.unbind_quarantine_registry(agent_id)
        self._audit.append(
            "quarantine.released",
            actor_id="control-plane",
            subject_id=agent_id,
            payload={
                "environment_id": environment_id,
                "events": len(environment.events),
                "transcript_digest": environment.transcript_digest(),
            },
        )

    # -- queries -----------------------------------------------------------
    def environment_for(self, agent_id: str) -> QuarantineEnvironment | None:
        environment_id = self._by_agent.get(agent_id)
        return self._environments.get(environment_id) if environment_id else None

    def get(self, environment_id: str) -> QuarantineEnvironment:
        try:
            return self._environments[environment_id]
        except KeyError as exc:
            raise QuarantineEscape("unknown quarantine environment", environment_id=environment_id) from exc

    def all_environments(self) -> list[QuarantineEnvironment]:
        return list(self._environments.values())

    def assert_contained(self, agent_id: str, production_registry) -> None:
        """Fails loudly if a quarantined agent ever touched the production registry."""
        environment = self.environment_for(agent_id)
        if environment is None:
            return
        for invocation in production_registry.invocations:
            if invocation.get("agent_id") == agent_id:
                raise QuarantineEscape("quarantined agent reached the production registry", agent_id=agent_id)
