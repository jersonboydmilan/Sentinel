"""Simulated agent ecosystem.

Assembles the full stack - control plane, observatory, immune system, SENTINEL -
around a population of scripted agents, runs it for N logical steps, and
collects metrics. Runs are deterministic: the same population and step count
produce the same audit chain head.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..control_plane.plane import ControlPlane, ControlPlaneConfig
from ..defensive_agents.sentinel import CycleReport, Sentinel
from ..immune_system.immune import ImmuneSystem
from ..observatory.observatory import Observatory
from .agents import Intent, ScriptedAgent, Worker
from .metrics import MetricsCollector


@dataclass
class EcosystemConfig:
    sentinel_interval: int = 4
    #: Agents are commissioned per *task episode*, as in a real deployment:
    #: a fresh TaskContract every ``episode_length`` steps. Behavioural
    #: profiles and drift history persist across episodes; per-task budgets
    #: and rate baselines reset, which is what makes them meaningful.
    episode_length: int = 5
    org_id: str = "org-alpha"
    owner_id: str = "human-operator"
    emergency_key: str = "out-of-band-operator-key"
    memory_path: str | None = None
    policy_dir: str | None = None
    #: Fraction of gateway decisions the observatory never sees (partial
    #: observability). Enforcement is unaffected; only detection degrades.
    observation_loss: float = 0.0
    observation_seed: str = "observatory"
    #: Run SENTINEL-AUDIT-REMOTE in a separate OS process (physical two-party
    #: verification). Adds process spawn and chain-transfer cost.
    remote_verification: bool = False


class Ecosystem:
    def __init__(self, config: EcosystemConfig | None = None) -> None:
        self.config = config or EcosystemConfig()
        plane_config = ControlPlaneConfig(emergency_key=self.config.emergency_key)
        if self.config.policy_dir:
            plane_config.policy_dir = self.config.policy_dir
        self.plane = ControlPlane(plane_config)
        self.observatory = Observatory(
            self.plane,
            observation_loss=self.config.observation_loss,
            seed=self.config.observation_seed,
        )
        self.immune = ImmuneSystem(self.plane, self.observatory, memory_path=self.config.memory_path)
        self.sentinel = Sentinel(
            self.plane,
            self.observatory,
            self.immune,
            remote_verification=self.config.remote_verification,
        )
        self.metrics = MetricsCollector()
        self.agents: dict[str, ScriptedAgent] = {}
        self.contracts: dict[str, str] = {}
        self.cycle_reports: list[CycleReport] = []
        self.step_index = 0
        self._delegated_contracts: set[str] = set()
        self.observatory.ingest_principals()

    # -- population --------------------------------------------------------
    def add_agent(self, agent: ScriptedAgent) -> ScriptedAgent:
        spec = agent.spec
        principal = self.plane.register_agent(
            spec.name,
            owner_id=self.config.owner_id,
            org_id=self.config.org_id,
            defensive=spec.defensive,
        )
        for capability in spec.capabilities:
            self.plane.grant(
                principal.principal_id,
                capability,
                delegable=capability in spec.delegable,
                delegation_depth=2 if capability in spec.delegable else 0,
            )
        contract = self.plane.commission(
            principal.principal_id,
            spec.purpose,
            spec.capabilities,
            allowed_tools=spec.allowed_tools,
            allowed_data=spec.allowed_datasets,
            allowed_endpoints=spec.allowed_endpoints,
            delegation_allowed=spec.delegation_allowed,
            delegable_capabilities=spec.delegable,
            max_tool_calls=spec.max_tool_calls,
            max_duration=10_000,
        )
        self.agents[spec.name] = agent
        self.contracts[spec.name] = contract.contract_id
        self.observatory.declare_profile(agent.profile_document())
        self.observatory.identity_graph.ingest_principal(principal)
        self.metrics.register(spec.name, spec.malicious)
        return agent

    def ensure_worker(self, name: str) -> None:
        if name not in self.agents:
            self.add_agent(Worker(name))

    # -- execution ---------------------------------------------------------
    def submit_intent(self, agent_name: str, intent: Intent):
        spec = self.agents[agent_name].spec
        contained = self.plane.containment.is_quarantined(agent_name)
        holds_authority = self.plane.authority.has(agent_name, intent.action)
        if intent.action not in spec.capabilities:
            # ground truth only - never read by the system under test
            self.metrics.record_violation(agent_name, self.step_index)
        if not holds_authority and not contained:
            self.metrics.unauthorized_attempts += 1
        if intent.action == "agent.delegate":
            self.metrics.delegation_attempts += 1

        result = self.plane.submit(
            agent_name,
            intent.action,
            tool=intent.tool,
            dataset=intent.dataset,
            endpoint=intent.endpoint,
            target_agent=intent.target_agent,
            task_id=self.contracts[agent_name],
            payload=intent.payload,
        )
        self.metrics.decisions += 1
        self.metrics.policy_latencies.append(result.latency_ms)
        if not holds_authority and not contained and not result.allowed:
            self.metrics.unauthorized_prevented += 1
        if intent.action == "agent.delegate" and result.allowed and intent.target_agent in self.agents:
            output = result.output or {}
            self.agents[intent.target_agent].on_delegation(list(output.get("delegated", [])))
            if output.get("sub_contract"):
                # The delegatee now works under its attenuated sub-contract.
                self.contracts[intent.target_agent] = output["sub_contract"]
                self._delegated_contracts.add(intent.target_agent)
        if intent.action == "agent.delegate" and not result.allowed:
            self.metrics.delegation_blocked += 1
            if result.facts.get("delegation_excess"):
                self.metrics.amplification_blocked += 1
                # Ground truth: attempting to delegate authority the agent never
                # held is a violation even though agent.delegate is in its spec.
                self.metrics.record_violation(agent_name, self.step_index)
        return result

    def new_episode(self) -> None:
        """Commission a fresh task contract for every self-directed agent."""
        for name, agent in self.agents.items():
            if name in self._delegated_contracts or not agent.spec.capabilities:
                continue
            spec = agent.spec
            contract = self.plane.commission(
                name,
                spec.purpose,
                spec.capabilities,
                allowed_tools=spec.allowed_tools,
                allowed_data=spec.allowed_datasets,
                allowed_endpoints=spec.allowed_endpoints,
                delegation_allowed=spec.delegation_allowed,
                delegable_capabilities=spec.delegable,
                max_tool_calls=spec.max_tool_calls,
                max_duration=10_000,
            )
            self.contracts[name] = contract.contract_id

    def step(self) -> None:
        self.plane.tick()
        self.step_index += 1
        if self.config.episode_length and (self.step_index - 1) % self.config.episode_length == 0 and self.step_index > 1:
            self.new_episode()
        for name, agent in list(self.agents.items()):
            for intent in agent.act(self.step_index):
                if intent.target_agent and intent.target_agent.startswith("WORKER"):
                    self.ensure_worker(intent.target_agent)
                self.submit_intent(name, intent)
        if self.step_index % self.config.sentinel_interval == 0:
            self.run_sentinel_cycle()

    def run_sentinel_cycle(self) -> CycleReport:
        targets = [name for name in self.agents]
        report = self.sentinel.cycle(targets)
        self.cycle_reports.append(report)
        for flag in report.flags:
            verified = any(
                verification["subject"] == flag.agent_id and verification["verdict"] == "CONFIRMED"
                for verification in report.verifications
            )
            self.metrics.record_flag(flag.agent_id, self.step_index, verified)
        for outcome in report.containment:
            for action in outcome.executed:
                self.metrics.record_containment(outcome.agent_id, action, self.step_index)
        self.metrics.defender_violations = len(self.sentinel.defender_violations())
        self.metrics.defender_holds = len(self.sentinel.defender_holds())
        return report

    def run(self, steps: int) -> MetricsCollector:
        started = time.perf_counter()
        for _ in range(steps):
            self.step()
        self.metrics.wall_seconds += time.perf_counter() - started
        self._finalise_metrics()
        return self.metrics

    def _finalise_metrics(self) -> None:
        # Defender safety: actions any defensive principal attempted outside its
        # own declared capability set, and how many of those the control plane
        # allowed (which must be zero).
        attempts = 0
        succeeded = 0
        for agent in self.sentinel.agents:
            for action in agent.violations():
                attempts += 1
                succeeded += 1 if action.allowed else 0
        for name, agent in self.agents.items():
            if not agent.spec.defensive:
                continue
            for event in self.observatory.telemetry.events(name):
                if event.capability in agent.spec.capabilities:
                    continue
                if event.policy_id == "POL-001-QUARANTINE-CONFINEMENT":
                    # Executed inside the sandbox, not in the real ecosystem:
                    # that is containment working, not an escape.
                    self.metrics.quarantine_escape_attempts += 1
                    continue
                attempts += 1
                succeeded += 1 if event.allowed else 0
        self.metrics.defender_escape_attempts = attempts
        self.metrics.defender_escapes_succeeded = succeeded

        for agent_id in list(self.agents):
            environment = self.plane.quarantine.environment_for(agent_id)
            if environment is not None:
                attempts = self.immune.escape_attempts(agent_id)
                self.metrics.quarantine_escape_attempts += attempts
        self.metrics.audit_tamper_detected = 0 if self.plane.audit.verify().valid else 1

    def close(self) -> None:
        """Release external resources (the out-of-process verifier, if any)."""
        self.sentinel.close()

    def __enter__(self) -> "Ecosystem":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- convenience -------------------------------------------------------
    def state(self) -> dict:
        return {
            "step": self.step_index,
            "agents": sorted(self.agents),
            "audit": self.plane.audit.snapshot(),
            "integrity": self.plane.verify_integrity(),
            "observatory": self.observatory.snapshot().__dict__,
            "signatures": len(self.immune.memory),
            "containment": [event.action.value for event in self.plane.containment.history()],
        }


def default_population() -> list[ScriptedAgent]:
    from .agents import POPULATION

    return [cls() for cls in POPULATION]


def clone_agent(cls, suffix: str) -> ScriptedAgent:
    """Instantiate a scripted agent under a suffixed name, for scale sweeps."""
    from dataclasses import replace

    agent = cls()
    agent.spec = replace(agent.spec, name=f"{agent.spec.name}#{suffix}")
    agent.name = agent.spec.name
    agent.SPEC = agent.spec
    return agent


def build_scaled_ecosystem(copies: int = 1, config: EcosystemConfig | None = None) -> Ecosystem:
    """The standard population replicated ``copies`` times (agent-count sweep)."""
    from .agents import POPULATION

    ecosystem = Ecosystem(config)
    for index in range(copies):
        for cls in POPULATION:
            ecosystem.add_agent(cls() if copies == 1 and index == 0 else clone_agent(cls, str(index + 1)))
    return ecosystem


def build_default_ecosystem(config: EcosystemConfig | None = None) -> Ecosystem:
    ecosystem = Ecosystem(config)
    for agent in default_population():
        ecosystem.add_agent(agent)
    return ecosystem
