"""TaskContract engine.

A TaskContract is the *declared purpose* half of authority drift detection: it
states what an agent was commissioned to do, with which capabilities, tools,
data and endpoints, and within which budget. Contracts are sealed with a hash
so that in-memory mutation by a compromised agent is detectable.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Iterable

from ..common.errors import ContractError, ContractIntegrityError
from ..common.util import IdFactory, LogicalClock, digest_of
from .audit import AuditService
from .capabilities import CapabilitySet, assert_representable
from .identity import Principal


@dataclass
class TaskContract:
    contract_id: str
    agent_id: str
    purpose: str
    declared_capabilities: tuple[str, ...]
    allowed_tools: tuple[str, ...] = ()
    allowed_data: tuple[str, ...] = ()
    allowed_endpoints: tuple[str, ...] = ()
    delegation_allowed: bool = False
    delegable_capabilities: tuple[str, ...] = ()
    max_tool_calls: int = 20
    max_duration: int = 10
    created_by: str = ""
    created_at: int = 0
    expires_at: int | None = None
    seal: str = ""
    # mutable runtime counters (excluded from the seal)
    tool_calls_used: int = 0
    started_at: int | None = None
    closed: bool = False

    SEALED_FIELDS = (
        "contract_id",
        "agent_id",
        "purpose",
        "declared_capabilities",
        "allowed_tools",
        "allowed_data",
        "allowed_endpoints",
        "delegation_allowed",
        "delegable_capabilities",
        "max_tool_calls",
        "max_duration",
        "created_by",
        "created_at",
        "expires_at",
    )

    def sealed_body(self) -> dict:
        return {name: getattr(self, name) for name in self.SEALED_FIELDS}

    def compute_seal(self) -> str:
        return digest_of(self.sealed_body())

    def verify_integrity(self) -> None:
        if self.compute_seal() != self.seal:
            raise ContractIntegrityError(
                "task contract has been modified after sealing",
                contract_id=self.contract_id,
                agent_id=self.agent_id,
            )

    def declared(self) -> CapabilitySet:
        return CapabilitySet(self.declared_capabilities)

    def delegable(self) -> CapabilitySet:
        return CapabilitySet(self.delegable_capabilities)


@dataclass(frozen=True)
class ContractCheck:
    ok: bool
    reasons: tuple[str, ...] = ()
    scope: str = "in_scope"

    @property
    def failed(self) -> bool:
        return not self.ok


class ContractEngine:
    def __init__(self, audit: AuditService, clock: LogicalClock, ids: IdFactory) -> None:
        self._audit = audit
        self._clock = clock
        self._ids = ids
        self._contracts: dict[str, TaskContract] = {}
        self._by_agent: dict[str, list[str]] = {}

    def create(
        self,
        issuer: Principal,
        agent_id: str,
        purpose: str,
        declared_capabilities: Iterable[str],
        *,
        allowed_tools: Iterable[str] = (),
        allowed_data: Iterable[str] = (),
        allowed_endpoints: Iterable[str] = (),
        delegation_allowed: bool = False,
        delegable_capabilities: Iterable[str] = (),
        max_tool_calls: int = 20,
        max_duration: int = 10,
        expires_at: int | None = None,
    ) -> TaskContract:
        if not (issuer.is_root_authority or issuer.kind.value in {"HUMAN", "ORGANIZATION"}):
            raise ContractError("task contracts are issued externally, not by agents", issuer=issuer.principal_id)
        caps = tuple(sorted(str(assert_representable(c)) for c in declared_capabilities))
        delegable = tuple(sorted(str(assert_representable(c)) for c in delegable_capabilities))
        if not set(delegable).issubset(set(caps)):
            raise ContractError("delegable capabilities must be a subset of declared capabilities")
        contract = TaskContract(
            contract_id=self._ids.new("TC"),
            agent_id=agent_id,
            purpose=purpose,
            declared_capabilities=caps,
            allowed_tools=tuple(sorted(allowed_tools)),
            allowed_data=tuple(sorted(allowed_data)),
            allowed_endpoints=tuple(sorted(allowed_endpoints)),
            delegation_allowed=delegation_allowed,
            delegable_capabilities=delegable,
            max_tool_calls=max_tool_calls,
            max_duration=max_duration,
            created_by=issuer.principal_id,
            created_at=self._clock.now,
            expires_at=expires_at,
        )
        contract.seal = contract.compute_seal()
        self._contracts[contract.contract_id] = contract
        self._by_agent.setdefault(agent_id, []).append(contract.contract_id)
        self._audit.append(
            "contract.created",
            actor_id=issuer.principal_id,
            subject_id=agent_id,
            task_id=contract.contract_id,
            payload={"purpose": purpose, "declared": list(caps), "seal": contract.seal},
        )
        return contract

    def derive(
        self,
        delegator: Principal,
        parent: TaskContract,
        delegatee_id: str,
        capabilities: Iterable[str],
        *,
        delegation_allowed: bool = False,
    ) -> TaskContract:
        """Create an attenuated sub-contract for a delegatee.

        A delegated task inherits a *subset* of its parent's declared purpose,
        tools, data, endpoints and budget. The sub-contract can never widen the
        parent, which is the contract-level mirror of Principle 3.
        """
        parent.verify_integrity()
        if parent.agent_id != delegator.principal_id:
            raise ContractError("only the contract holder may derive a sub-contract", agent=delegator.principal_id)
        caps = tuple(sorted(str(assert_representable(c)) for c in capabilities))
        if not CapabilitySet(caps).issubset(parent.delegable()):
            raise ContractError(
                "sub-contract capabilities exceed the parent's delegable set",
                parent=parent.contract_id,
                requested=list(caps),
                delegable=parent.delegable().as_strings(),
            )
        # A delegatee that may re-delegate needs the act of delegation inside
        # its declared purpose; the *delegable set* still stays attenuated.
        declared = tuple(sorted(set(caps) | ({"agent.delegate"} if delegation_allowed and parent.delegation_allowed else set())))
        contract = TaskContract(
            contract_id=self._ids.new("TC"),
            agent_id=delegatee_id,
            purpose=f"delegated[{parent.contract_id}]: {parent.purpose}",
            declared_capabilities=declared,
            allowed_tools=parent.allowed_tools,
            allowed_data=parent.allowed_data,
            allowed_endpoints=parent.allowed_endpoints,
            delegation_allowed=delegation_allowed and parent.delegation_allowed,
            delegable_capabilities=caps if delegation_allowed else (),
            max_tool_calls=max(1, parent.max_tool_calls // 2),
            max_duration=parent.max_duration,
            created_by=delegator.principal_id,
            created_at=self._clock.now,
            expires_at=parent.expires_at,
        )
        contract.seal = contract.compute_seal()
        self._contracts[contract.contract_id] = contract
        self._by_agent.setdefault(delegatee_id, []).append(contract.contract_id)
        self._audit.append(
            "contract.derived",
            actor_id=delegator.principal_id,
            subject_id=delegatee_id,
            task_id=contract.contract_id,
            payload={"parent": parent.contract_id, "declared": list(caps)},
        )
        return contract

    def get(self, contract_id: str) -> TaskContract:
        try:
            return self._contracts[contract_id]
        except KeyError as exc:
            raise ContractError("unknown task contract", contract_id=contract_id) from exc

    def active_for(self, agent_id: str) -> TaskContract | None:
        for contract_id in reversed(self._by_agent.get(agent_id, [])):
            contract = self._contracts[contract_id]
            if not contract.closed and (contract.expires_at is None or self._clock.now < contract.expires_at):
                return contract
        return None

    def all_for(self, agent_id: str) -> list[TaskContract]:
        return [self._contracts[cid] for cid in self._by_agent.get(agent_id, [])]

    # -- evaluation --------------------------------------------------------
    def check(
        self,
        contract: TaskContract,
        *,
        agent_id: str,
        capability: str,
        tool: str | None = None,
        data: str | None = None,
        endpoint: str | None = None,
    ) -> ContractCheck:
        contract.verify_integrity()
        reasons: list[str] = []
        if contract.agent_id != agent_id:
            reasons.append("contract_agent_mismatch")
        if contract.closed:
            reasons.append("contract_closed")
        if contract.expires_at is not None and self._clock.now >= contract.expires_at:
            reasons.append("contract_expired")
        if not contract.declared().holds(capability):
            reasons.append("capability_outside_declared_purpose")
        if tool and contract.allowed_tools and tool not in contract.allowed_tools:
            reasons.append("tool_outside_contract")
        if data and contract.allowed_data and data not in contract.allowed_data:
            reasons.append("data_outside_contract")
        if endpoint and contract.allowed_endpoints and endpoint not in contract.allowed_endpoints:
            reasons.append("endpoint_outside_contract")
        if contract.tool_calls_used >= contract.max_tool_calls:
            reasons.append("tool_call_budget_exhausted")
        if contract.started_at is not None and self._clock.now - contract.started_at > contract.max_duration:
            reasons.append("duration_budget_exceeded")
        scope = "in_scope" if not reasons else "out_of_scope"
        return ContractCheck(ok=not reasons, reasons=tuple(reasons), scope=scope)

    def consume(self, contract: TaskContract) -> None:
        if contract.started_at is None:
            contract.started_at = self._clock.now
        contract.tool_calls_used += 1

    def close(self, actor: Principal, contract_id: str, reason: str = "completed") -> TaskContract:
        contract = self.get(contract_id)
        contract.closed = True
        self._audit.append(
            "contract.closed",
            actor_id=actor.principal_id,
            subject_id=contract.agent_id,
            task_id=contract_id,
            payload={"reason": reason},
        )
        return contract

    def amend(self, issuer: Principal, contract_id: str, **changes) -> TaskContract:
        """Contracts are amended only by their external issuer, and re-sealed."""
        contract = self.get(contract_id)
        if not (issuer.is_root_authority or issuer.principal_id == contract.created_by):
            raise ContractError("only the external issuer may amend a task contract", issuer=issuer.principal_id)
        updated = replace(contract, **changes)
        updated.seal = updated.compute_seal()
        self._contracts[contract_id] = updated
        self._audit.append(
            "contract.amended",
            actor_id=issuer.principal_id,
            subject_id=contract.agent_id,
            task_id=contract_id,
            payload={"changes": sorted(changes)},
        )
        return updated
