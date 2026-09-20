"""Authority Drift Engine (section 7).

Compares five views of one agent:

    Declared Authority   - the TaskContract's purpose and capability set
    Granted Authority    - what the authority service actually issued
    Observed Behaviour   - what the agent attempted, allowed or denied
    Historical Behaviour - the agent's own learned baseline
    TaskContract scope   - tools, data, endpoints and budgets

Drift is not a single boolean. The engine emits typed drift components, each
with its own evidence, and a composite score. Gradual drift (the "research
agent slowly grows an appetite for credentials" case) is caught by the
trend components, not by any single event.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..common.util import clamp
from ..control_plane.authority import AuthorityService
from ..control_plane.capabilities import CapabilitySet
from ..control_plane.contracts import ContractEngine
from .anomaly import AnomalyEngine
from .behavior import BehaviorProfile, BehaviorProfiler


class DriftKind(str, Enum):
    CAPABILITY_DRIFT = "CAPABILITY_DRIFT"          # attempted authority it was never granted
    PURPOSE_DRIFT = "PURPOSE_DRIFT"                # acted outside the declared purpose
    BEHAVIOURAL_DRIFT = "BEHAVIOURAL_DRIFT"        # diverged from its own history
    DELEGATION_DRIFT = "DELEGATION_DRIFT"          # delegation appears where none was declared
    COMMUNICATION_DRIFT = "COMMUNICATION_DRIFT"    # external endpoint expansion
    CREDENTIAL_DRIFT = "CREDENTIAL_DRIFT"          # credential interest appears
    ESCALATION_DRIFT = "ESCALATION_DRIFT"          # repeated privilege escalation attempts


DRIFT_WEIGHTS = {
    DriftKind.CAPABILITY_DRIFT: 0.9,
    DriftKind.PURPOSE_DRIFT: 0.7,
    DriftKind.BEHAVIOURAL_DRIFT: 0.4,
    DriftKind.DELEGATION_DRIFT: 0.8,
    DriftKind.COMMUNICATION_DRIFT: 0.6,
    DriftKind.CREDENTIAL_DRIFT: 0.85,
    DriftKind.ESCALATION_DRIFT: 0.9,
}


@dataclass(frozen=True)
class DriftComponent:
    kind: DriftKind
    magnitude: float
    evidence: tuple[str, ...]

    def weighted(self) -> float:
        return clamp(self.magnitude) * DRIFT_WEIGHTS[self.kind]

    def as_dict(self) -> dict:
        return {"kind": self.kind.value, "magnitude": round(self.magnitude, 3), "evidence": list(self.evidence)}


@dataclass
class DriftReport:
    agent_id: str
    at: int
    components: tuple[DriftComponent, ...] = ()
    declared: tuple[str, ...] = ()
    granted: tuple[str, ...] = ()
    observed: tuple[str, ...] = ()
    historical: tuple[str, ...] = ()

    @property
    def drift(self) -> bool:
        return bool(self.components)

    @property
    def score(self) -> float:
        product = 1.0
        for component in self.components:
            product *= 1.0 - component.weighted()
        return clamp(1.0 - product)

    def kinds(self) -> tuple[str, ...]:
        return tuple(c.kind.value for c in self.components)

    def evidence(self) -> tuple[str, ...]:
        out: list[str] = []
        for component in self.components:
            out.append(component.kind.value.lower())
            out.extend(component.evidence)
        return tuple(out)

    def as_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "drift": self.drift,
            "score": round(self.score, 4),
            "components": [c.as_dict() for c in self.components],
            "comparison": {
                "declared": list(self.declared),
                "granted": list(self.granted),
                "observed": list(self.observed),
                "historical": list(self.historical),
            },
        }


class AuthorityDriftEngine:
    def __init__(
        self,
        authority: AuthorityService,
        contracts: ContractEngine,
        profiler: BehaviorProfiler,
        anomalies: AnomalyEngine,
    ) -> None:
        self._authority = authority
        self._contracts = contracts
        self._profiler = profiler
        self._anomalies = anomalies
        self._reports: dict[str, DriftReport] = {}

    def evaluate(self, agent_id: str, *, at: int = 0) -> DriftReport:
        profile: BehaviorProfile = self._profiler.profile(agent_id)
        contract = self._contracts.active_for(agent_id)
        declared = contract.declared() if contract else CapabilitySet()
        granted = self._authority.granted(agent_id)
        observed = CapabilitySet(
            capability for capability in profile.capability_counts if _representable(capability)
        )
        historical = CapabilitySet(
            capability for capability in profile.baseline_capabilities if _representable(capability)
        )

        components: list[DriftComponent] = []

        # 1. observed capability outside granted authority
        beyond_grant = observed.difference(granted)
        if beyond_grant:
            components.append(
                DriftComponent(
                    DriftKind.CAPABILITY_DRIFT,
                    clamp(len(beyond_grant) / max(len(observed), 1) + 0.3),
                    tuple(f"attempted_without_grant:{c}" for c in beyond_grant.as_strings()),
                )
            )

        # 2. observed capability outside the declared purpose
        if contract is not None:
            beyond_purpose = observed.difference(declared)
            if beyond_purpose:
                components.append(
                    DriftComponent(
                        DriftKind.PURPOSE_DRIFT,
                        clamp(len(beyond_purpose) / max(len(observed), 1) + 0.2),
                        tuple(f"outside_declared_purpose:{c}" for c in beyond_purpose.as_strings()),
                    )
                )

        # 3. divergence from the agent's own history
        if profile.baseline_locked:
            novel = observed.difference(historical)
            if novel:
                components.append(
                    DriftComponent(
                        DriftKind.BEHAVIOURAL_DRIFT,
                        clamp(len(novel) / max(len(historical), 1)),
                        tuple(f"novel_capability:{c}" for c in novel.as_strings()),
                    )
                )

        # 4. delegation that the declared profile or contract does not sanction
        delegation_attempts = profile.capability_counts.get("agent.delegate", 0)
        creation_attempts = profile.capability_counts.get("agent.create", 0)
        declared_delegation = contract.delegation_allowed if contract else False
        if (delegation_attempts or creation_attempts) and not declared_delegation:
            components.append(
                DriftComponent(
                    DriftKind.DELEGATION_DRIFT,
                    clamp(0.5 + 0.1 * (delegation_attempts + creation_attempts)),
                    (
                        f"delegation_attempts:{delegation_attempts}",
                        f"agent_creation_attempts:{creation_attempts}",
                        f"contract_delegation_allowed:{declared_delegation}",
                    ),
                )
            )

        # 5. external communication expansion
        allowed_endpoints = set(contract.allowed_endpoints) if contract else set()
        declared_endpoints = set(profile.declared.expected_endpoints) if profile.declared else set()
        expected = allowed_endpoints | declared_endpoints
        unexpected = sorted(set(profile.endpoint_counts) - expected)
        if unexpected:
            components.append(
                DriftComponent(
                    DriftKind.COMMUNICATION_DRIFT,
                    clamp(0.4 + 0.2 * len(unexpected)),
                    tuple(f"unexpected_endpoint:{e}" for e in unexpected),
                )
            )

        # 6. credential interest that no view sanctions
        if profile.capability_counts.get("credential.read", 0) and not declared.holds("credential.read"):
            components.append(
                DriftComponent(
                    DriftKind.CREDENTIAL_DRIFT,
                    clamp(0.6 + 0.1 * profile.capability_counts["credential.read"]),
                    (f"credential_attempts:{profile.capability_counts['credential.read']}",),
                )
            )

        # 7. sustained escalation pressure
        escalation_signals = [
            report
            for report in self._anomalies.history(agent_id)
            if "privilege_escalation_attempt" in report.names()
        ]
        # Breadth matters: repeatedly retrying one denied capability is a policy
        # violation, whereas probing several distinct capabilities is escalation.
        denied_capabilities = {
            token.split(":")[0] for token in profile.sequence if token.endswith(":denied")
        }
        if len(escalation_signals) >= 2 and len(denied_capabilities) >= 2:
            components.append(
                DriftComponent(
                    DriftKind.ESCALATION_DRIFT,
                    clamp(0.4 + 0.15 * len(escalation_signals)),
                    (
                        f"escalation_events:{len(escalation_signals)}",
                        f"distinct_denied_capabilities:{len(denied_capabilities)}",
                        f"denied_ratio:{round(profile.denied_ratio, 3)}",
                    ),
                )
            )

        report = DriftReport(
            agent_id=agent_id,
            at=at,
            components=tuple(components),
            declared=tuple(declared.as_strings()),
            granted=tuple(granted.as_strings()),
            observed=tuple(observed.as_strings()),
            historical=tuple(historical.as_strings()),
        )
        self._reports[agent_id] = report
        return report

    def latest(self, agent_id: str) -> DriftReport:
        return self._reports.get(agent_id, DriftReport(agent_id=agent_id, at=0))


def _representable(capability: str) -> bool:
    return "." in capability
