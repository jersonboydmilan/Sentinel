"""Delegation engine.

Implements Principle 3 as an executable predicate:

    EffectiveAuthority(B) ⊆ DelegableAuthority(A)

and its transitive closure: authority may not amplify along A → B → C, and a
delegation chain may not contain a cycle. Every rejected delegation is recorded
with the exact excess capability set, which is the evidence the drift engine
later uses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..common.errors import AuthorityAmplification, DelegationError
from ..common.util import IdFactory, LogicalClock
from .audit import AuditService
from .authority import AuthorityService, Grant
from .capabilities import CapabilitySet
from .contracts import ContractEngine
from .identity import IdentityService, Principal

MAX_CHAIN_DEPTH = 3


@dataclass(frozen=True)
class DelegationRequest:
    request_id: str
    delegator_id: str
    delegatee_id: str
    capabilities: tuple[str, ...]
    task_id: str | None
    requested_at: int
    delegable_depth: int = 1


@dataclass(frozen=True)
class DelegationOutcome:
    request: DelegationRequest
    allowed: bool
    reasons: tuple[str, ...] = ()
    grants: tuple[str, ...] = ()
    excess: tuple[str, ...] = ()
    chain: tuple[str, ...] = field(default_factory=tuple)
    sub_contract: str | None = None


class DelegationEngine:
    def __init__(
        self,
        identity: IdentityService,
        authority: AuthorityService,
        contracts: ContractEngine,
        audit: AuditService,
        clock: LogicalClock,
        ids: IdFactory,
        *,
        max_depth: int = MAX_CHAIN_DEPTH,
    ) -> None:
        self._identity = identity
        self._authority = authority
        self._contracts = contracts
        self._audit = audit
        self._clock = clock
        self._ids = ids
        self._max_depth = max_depth
        self._edges: dict[str, set[str]] = {}
        self._history: list[DelegationOutcome] = []

    # -- graph helpers -----------------------------------------------------
    def delegation_edges(self) -> dict[str, set[str]]:
        return {k: set(v) for k, v in self._edges.items()}

    def chain_to(self, agent_id: str, _seen: set[str] | None = None) -> list[str]:
        """Longest ancestor chain ending at ``agent_id``."""
        seen = _seen or set()
        best: list[str] = []
        for parent, children in self._edges.items():
            if agent_id in children and parent not in seen:
                candidate = self.chain_to(parent, seen | {agent_id})
                if len(candidate) > len(best):
                    best = candidate
        return best + [agent_id]

    def depth_of(self, agent_id: str) -> int:
        return max(len(self.chain_to(agent_id)) - 1, 0)

    def _creates_cycle(self, delegator_id: str, delegatee_id: str) -> bool:
        stack = [delegatee_id]
        seen = set()
        while stack:
            current = stack.pop()
            if current == delegator_id:
                return True
            if current in seen:
                continue
            seen.add(current)
            stack.extend(self._edges.get(current, ()))
        return False

    # -- the predicate -----------------------------------------------------
    def evaluate(
        self,
        delegator: Principal,
        delegatee_id: str,
        capabilities: Iterable[str],
        *,
        task_id: str | None = None,
        delegable_depth: int = 0,
    ) -> DelegationOutcome:
        request = DelegationRequest(
            request_id=self._ids.new("DLG"),
            delegator_id=delegator.principal_id,
            delegatee_id=delegatee_id,
            capabilities=tuple(sorted(str(c) for c in capabilities)),
            task_id=task_id,
            requested_at=self._clock.now,
            delegable_depth=delegable_depth,
        )
        reasons: list[str] = []
        requested = CapabilitySet(request.capabilities)
        delegable = self._authority.delegable(delegator.principal_id)

        if not self._identity.exists(delegatee_id):
            reasons.append("unknown_delegatee")
        if not self._authority.has(delegator.principal_id, "agent.delegate"):
            reasons.append("delegator_lacks_agent.delegate")

        contract = self._contracts.active_for(delegator.principal_id)
        if contract is not None:
            contract.verify_integrity()
            if not contract.delegation_allowed:
                reasons.append("contract_forbids_delegation")
            outside_contract = requested.difference(contract.delegable())
            if outside_contract:
                reasons.append("capabilities_outside_contract_delegable_set")

        excess = requested.difference(delegable)
        if excess:
            reasons.append("requested_authority_exceeds_delegable_authority")

        if self._creates_cycle(delegator.principal_id, delegatee_id):
            reasons.append("delegation_cycle")
        if self.depth_of(delegator.principal_id) + 1 > self._max_depth:
            reasons.append("max_delegation_depth_exceeded")

        chain = tuple(self.chain_to(delegator.principal_id) + [delegatee_id])
        outcome = DelegationOutcome(
            request=request,
            allowed=not reasons,
            reasons=tuple(reasons),
            excess=tuple(excess.as_strings()),
            chain=chain,
        )
        self._history.append(outcome)
        return outcome

    # -- execution ---------------------------------------------------------
    def delegate(
        self,
        delegator: Principal,
        delegatee_id: str,
        capabilities: Iterable[str],
        *,
        task_id: str | None = None,
        delegable_depth: int = 0,
    ) -> DelegationOutcome:
        outcome = self.evaluate(
            delegator,
            delegatee_id,
            capabilities,
            task_id=task_id,
            delegable_depth=delegable_depth,
        )
        if not outcome.allowed:
            self._audit.append(
                "delegation.denied",
                actor_id=delegator.principal_id,
                subject_id=delegatee_id,
                task_id=task_id,
                payload={
                    "request_id": outcome.request.request_id,
                    "capabilities": list(outcome.request.capabilities),
                    "excess": list(outcome.excess),
                    "reasons": list(outcome.reasons),
                    "chain": list(outcome.chain),
                },
            )
            if outcome.excess:
                raise AuthorityAmplification(
                    "delegation would amplify authority (P3)",
                    delegator=delegator.principal_id,
                    delegatee=delegatee_id,
                    excess=list(outcome.excess),
                )
            raise DelegationError(
                "delegation denied",
                delegator=delegator.principal_id,
                delegatee=delegatee_id,
                reasons=list(outcome.reasons),
            )

        grants: list[Grant] = []
        for capability in outcome.request.capabilities:
            grants.append(
                self._authority.issue(
                    delegator,
                    delegatee_id,
                    capability,
                    delegable=delegable_depth > 0,
                    delegation_depth=delegable_depth,
                    reason=f"delegated:{outcome.request.request_id}",
                )
            )
        # The delegatee also receives an attenuated sub-contract: authority
        # without declared purpose would leave the delegatee permanently out of
        # scope, which is a contract-level authority gap.
        parent = self._contracts.active_for(delegator.principal_id)
        sub_contract = None
        if parent is not None:
            sub_contract = self._contracts.derive(
                delegator,
                parent,
                delegatee_id,
                outcome.request.capabilities,
                delegation_allowed=delegable_depth > 0,
            )
        self._edges.setdefault(delegator.principal_id, set()).add(delegatee_id)
        recorded = DelegationOutcome(
            request=outcome.request,
            allowed=True,
            reasons=outcome.reasons,
            grants=tuple(g.grant_id for g in grants),
            chain=outcome.chain,
            sub_contract=sub_contract.contract_id if sub_contract else None,
        )
        self._history[-1] = recorded
        self._audit.append(
            "delegation.allowed",
            actor_id=delegator.principal_id,
            subject_id=delegatee_id,
            task_id=task_id,
            payload={
                "request_id": outcome.request.request_id,
                "capabilities": list(outcome.request.capabilities),
                "grants": list(recorded.grants),
                "sub_contract": sub_contract.contract_id if sub_contract else None,
                "chain": list(outcome.chain),
            },
        )
        return recorded

    # -- introspection -----------------------------------------------------
    def history(self, agent_id: str | None = None) -> list[DelegationOutcome]:
        if agent_id is None:
            return list(self._history)
        return [o for o in self._history if agent_id in (o.request.delegator_id, o.request.delegatee_id)]

    def denied_count(self, agent_id: str) -> int:
        return sum(1 for o in self.history(agent_id) if not o.allowed and o.request.delegator_id == agent_id)
