"""Execution gateway - the single choke point.

Every consequential operation in the ecosystem is an ``ActionRequest`` submitted
here. The gateway performs, in order:

 1. emergency control check          (out-of-band kill switches win first)
 2. policy set integrity check       (detect policy tampering)
 3. authentication                   (detect impersonation)
 4. namespace refusal                (emergency/policy/authority/audit are not agent-reachable)
 5. forbidden capability refusal     (offensive verbs are not representable)
 6. authority check                  (default deny)
 7. task contract check              (declared purpose)
 8. fact assembly + risk scoring     (observatory and immune system contribute facts)
 9. policy evaluation                (deterministic)
10. execution or refusal             (tool handler invoked only on ALLOW)
11. telemetry + tamper evident audit (always, including for refusals)

An agent's *intent* reaches step 10 only as data. Nothing about the agent's
reasoning, system prompt or SDK usage can skip a step: the gateway holds the
only reference to the tool handlers.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from ..common.errors import (
    AuthenticationFailed,
    ControlPlaneError,
    ForbiddenCapability,
    IdentityError,
    ImpersonationDetected,
)
from ..common.util import IdFactory, LogicalClock
from .audit import AuditService
from .authority import AuthorityService
from .capabilities import OUT_OF_BAND_NAMESPACES, Capability, assert_representable
from .containment import ContainmentEngine
from .contracts import ContractEngine
from .delegation import DelegationEngine
from .emergency import EmergencyController
from .identity import IdentityService, Principal
from .policy import Effect, PolicyDecision, PolicyEngine
from .risk import RiskAssessment, RiskEngine
from .tools import ToolRegistry

FactProvider = Callable[["ActionRequest", dict], dict]


@dataclass(frozen=True)
class ActionRequest:
    principal_id: str
    action: str
    token: str | None = None
    tool: str | None = None
    dataset: str | None = None
    endpoint: str | None = None
    target_agent: str | None = None
    task_id: str | None = None
    payload: dict = field(default_factory=dict)
    tags: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class ActionResult:
    decision_id: str
    request: ActionRequest
    effect: Effect
    allowed: bool
    policy_id: str
    reasons: tuple[str, ...]
    risk: RiskAssessment | None
    audit_id: str
    output: dict | None = None
    error: str | None = None
    facts: dict = field(default_factory=dict)
    latency_ms: float = 0.0

    def narrative(self) -> str:
        """One sentence explaining the decision in reviewer-readable terms."""
        request = self.request
        target = f" on {request.tool}" if request.tool else ""
        if self.effect is Effect.ALLOW and self.error is None:
            basis = (
                "quarantine sandbox: synthetic tools, no production effect"
                if self.facts.get("sandboxed")
                else "held authority and in-scope contract"
            )
            return (
                f"{request.principal_id} was ALLOWED to {request.action}{target} "
                f"({basis}; policy {self.policy_id}; risk {self.risk.level.value if self.risk else 'n/a'})"
            )
        reason = self._primary_reason()
        return (
            f"{request.principal_id} was {self.effect.value} for {request.action}{target} "
            f"because {reason} (policy {self.policy_id})"
        )

    def _primary_reason(self) -> str:
        explanations = {
            "capability_not_held": "it does not hold that capability",
            "capability_outside_declared_purpose": "the action is outside its task contract",
            "tool_outside_contract": "the tool is not in its task contract",
            "endpoint_outside_contract": "the endpoint is not in its task contract",
            "data_outside_contract": "the dataset is not in its task contract",
            "tool_call_budget_exhausted": "its task budget is exhausted",
            "delegation_within_authority:equals:fail": "the delegation would amplify authority",
            "verification_valid:equals:fail": "no independent verification supports the action",
            "verification_count:gte:fail": "a second independent verifier is required",
            "collusion_score:lt:fail": "a cross-agent collusion chain is open and awaiting review",
            "namespace_not_agent_reachable": "the namespace is operated out of band",
            "auth:IMPERSONATION_DETECTED": "the credential belongs to another principal",
            "forbidden_capability": "the capability is not representable in this architecture",
            "no_policy_matched": "no policy permits it (default deny)",
        }
        for reason in self.reasons:
            if reason in explanations:
                return explanations[reason]
            if reason.startswith("emergency:"):
                return f"an emergency control is active ({reason.split(':', 1)[1]})"
            if reason.startswith("control_plane:"):
                return f"the control plane refused it ({reason.split(':', 1)[1]})"
        if self.error:
            return f"execution was refused ({self.error[:80]})"
        return "the policy conditions were not satisfied"

    def as_record(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "agent_id": self.request.principal_id,
            "task_id": self.request.task_id,
            "requested_action": self.request.action,
            "decision": self.effect.value,
            "policy": self.policy_id,
            "risk": self.risk.level.value if self.risk else "UNKNOWN",
            "evidence": list(self.reasons),
            "timestamp": self.facts.get("now"),
            "executor": "policy-gateway",
        }


class ExecutionGateway:
    def __init__(
        self,
        *,
        identity: IdentityService,
        authority: AuthorityService,
        contracts: ContractEngine,
        policy: PolicyEngine,
        risk: RiskEngine,
        delegation: DelegationEngine,
        containment: ContainmentEngine,
        emergency: EmergencyController,
        revocation,
        audit: AuditService,
        clock: LogicalClock,
        ids: IdFactory,
        registry: ToolRegistry,
    ) -> None:
        self.identity = identity
        self.authority = authority
        self.contracts = contracts
        self.policy = policy
        self.risk = risk
        self.delegation = delegation
        self.containment = containment
        self.emergency = emergency
        self.revocation = revocation
        self.audit = audit
        self.clock = clock
        self.ids = ids
        self.registry = registry
        self._fact_providers: list[FactProvider] = []
        self._observers: list[Callable[[ActionResult], None]] = []
        self._quarantine_registries: dict[str, ToolRegistry] = {}
        self.latencies: list[float] = []

    # -- wiring ------------------------------------------------------------
    def add_fact_provider(self, provider: FactProvider) -> None:
        """Observatory / immune system contribute facts without gaining control."""
        self._fact_providers.append(provider)

    def add_observer(self, observer: Callable[[ActionResult], None]) -> None:
        self._observers.append(observer)

    def bind_quarantine_registry(self, agent_id: str, registry: ToolRegistry) -> None:
        self._quarantine_registries[agent_id] = registry

    def unbind_quarantine_registry(self, agent_id: str) -> None:
        self._quarantine_registries.pop(agent_id, None)

    # -- main entry point --------------------------------------------------
    def submit(self, request: ActionRequest) -> ActionResult:
        started = time.perf_counter()
        decision_id = self.ids.new("DEC")
        facts: dict = {
            "now": self.clock.now,
            "action": request.action,
            "subject_id": request.principal_id,
            "tool": request.tool,
            "dataset": request.dataset,
            "endpoint": request.endpoint,
            "target_agent": request.target_agent,
            "task_id": request.task_id,
            "tags": list(request.tags),
        }
        reasons: list[str] = []
        principal: Principal | None = None

        try:
            # 1. emergency controls (cannot be disabled from inside)
            emergency_block = self.emergency.blocks(request.principal_id, request.action)
            facts["emergency_block"] = emergency_block
            if emergency_block:
                return self._finalize(
                    decision_id, request, Effect.DENY, "EMERGENCY-CONTROL",
                    (f"emergency:{emergency_block}",), None, facts, started, principal,
                )

            # 2. policy integrity
            self.policy.verify_integrity()

            # 3. authentication
            principal = self.identity.authenticate(request.principal_id, request.token)
            facts["subject_kind"] = principal.kind.value
            facts["owner_id"] = principal.owner_id
            facts["is_defensive_agent"] = principal.kind.value == "DEFENSIVE_AGENT"

            # 4/5. namespace and forbidden capability refusal
            capability = self._parse_capability(request.action)
            if capability.namespace in OUT_OF_BAND_NAMESPACES:
                return self._finalize(
                    decision_id, request, Effect.DENY, "POL-OUT-OF-BAND",
                    ("namespace_not_agent_reachable",), None, facts, started, principal,
                )
            facts["capability_is_defensive"] = capability.is_defensive()

            # 6. authority (default deny)
            # Context binding: a grant scoped to a task contract is usable only
            # inside that contract, so the request's task id is part of the
            # authority question, not merely of the contract question.
            held = self.authority.has(request.principal_id, capability, task_id=request.task_id)
            facts["capability_held"] = held
            facts["authority_explain"] = self.authority.explain(
                request.principal_id, str(capability), task_id=request.task_id
            )
            facts["granted_capabilities"] = self.authority.granted(
                request.principal_id, task_id=request.task_id
            ).as_strings()
            facts["effective_capabilities"] = self.authority.effective(
                request.principal_id, task_id=request.task_id
            ).as_strings()
            if not held:
                reasons.append("capability_not_held")

            # 7. task contract
            contract = None
            if request.task_id:
                contract = self.contracts.get(request.task_id)
            else:
                contract = self.contracts.active_for(request.principal_id)
            facts["has_contract"] = contract is not None
            if contract is not None:
                check = self.contracts.check(
                    contract,
                    agent_id=request.principal_id,
                    capability=str(capability),
                    tool=request.tool,
                    data=request.dataset,
                    endpoint=request.endpoint,
                )
                facts["contract_id"] = contract.contract_id
                facts["contract_in_scope"] = check.ok
                facts["contract_reasons"] = list(check.reasons)
                facts["declared_capabilities"] = list(contract.declared_capabilities)
                reasons.extend(check.reasons)
            else:
                facts["contract_in_scope"] = False
                facts["contract_reasons"] = ["no_active_contract"]

            facts["endpoint_expected"] = (
                request.endpoint is None
                or contract is None
                or not contract.allowed_endpoints
                or request.endpoint in contract.allowed_endpoints
            )

            # delegation pre-check: the P3 predicate is evaluated before policy
            # so that a policy can reason about amplification without executing it.
            if str(capability) == "agent.delegate" and request.target_agent:
                preview = self.delegation.evaluate(
                    principal,
                    request.target_agent,
                    request.payload.get("capabilities", []),
                    task_id=request.task_id,
                )
                facts["delegation_within_authority"] = preview.allowed
                facts["delegation_excess"] = list(preview.excess)
                facts["delegation_reasons"] = list(preview.reasons)
                facts["delegation_chain_depth"] = len(preview.chain) - 1
                if not preview.allowed:
                    self.audit.append(
                        "delegation.denied",
                        actor_id=principal.principal_id,
                        subject_id=request.target_agent,
                        task_id=request.task_id,
                        payload={
                            "request_id": preview.request.request_id,
                            "capabilities": list(preview.request.capabilities),
                            "excess": list(preview.excess),
                            "reasons": list(preview.reasons),
                            "chain": list(preview.chain),
                            "stage": "pre_check",
                        },
                    )
            else:
                facts["delegation_within_authority"] = True
                facts["delegation_excess"] = []

            # Claims made by the caller are recorded but never trusted; the
            # immune system's fact providers validate them against signed records.
            facts["claimed_verification_ref"] = request.payload.get("verification_ref")
            facts["claimed_confidence"] = float(request.payload.get("confidence", 0.0) or 0.0)
            facts.setdefault("verification_valid", False)
            facts.setdefault("verification_confidence", 0.0)

            # containment state
            facts["sandboxed"] = request.principal_id in self._quarantine_registries
            facts["quarantined"] = self.containment.is_quarantined(request.principal_id)
            facts["isolated"] = self.containment.is_isolated(request.principal_id)
            facts["previously_contained"] = self.containment.previously_contained(request.principal_id)

            # 8. external facts (observatory, immune memory) and risk
            for provider in self._fact_providers:
                try:
                    facts.update(provider(request, dict(facts)))
                except Exception as exc:  # observers must never break enforcement
                    facts.setdefault("fact_provider_errors", []).append(str(exc))
            assessment = self.risk.assess(facts)
            facts["risk_score"] = assessment.score
            facts["risk_level"] = assessment.level.value

            # 9. policy
            decision: PolicyDecision = self.policy.evaluate(facts)
            reasons.extend(decision.reasons)

            # 10. execution
            output = None
            error = None
            effect = decision.effect
            if effect.permits_execution:
                try:
                    output = self._execute(request, capability, principal, facts)
                    if contract is not None:
                        self.contracts.consume(contract)
                except ControlPlaneError as exc:
                    effect = Effect.DENY
                    error = str(exc)
                    reasons.append(f"execution_refused:{exc.code}")
                except Exception as exc:  # tool failure is data, not a bypass
                    error = str(exc)
                    reasons.append("tool_error")
            return self._finalize(
                decision_id,
                request,
                effect,
                decision.policy_id,
                tuple(reasons),
                assessment,
                facts,
                started,
                principal,
                output=output,
                error=error,
            )

        except (AuthenticationFailed, ImpersonationDetected, IdentityError) as exc:
            facts["auth_error"] = exc.code
            return self._finalize(
                decision_id, request, Effect.DENY, "POL-AUTHENTICATION",
                (f"auth:{exc.code}",), None, facts, started, principal, error=str(exc),
            )
        except ForbiddenCapability as exc:
            return self._finalize(
                decision_id, request, Effect.DENY, "POL-FORBIDDEN-CAPABILITY",
                ("forbidden_capability",), None, facts, started, principal, error=str(exc),
            )
        except ControlPlaneError as exc:
            return self._finalize(
                decision_id, request, Effect.DENY, "POL-CONTROL-PLANE-ERROR",
                (f"control_plane:{exc.code}",), None, facts, started, principal, error=str(exc),
            )

    # -- helpers -----------------------------------------------------------
    def _parse_capability(self, action: str) -> Capability:
        return assert_representable(action)

    def _execute(self, request: ActionRequest, capability: Capability, principal: Principal, facts: dict) -> dict:
        """Run the requested operation. Quarantined agents hit the sandbox."""
        if capability.is_defensive():
            return self._execute_defensive(request, capability, principal, facts)

        if str(capability) == "agent.delegate" and request.target_agent:
            outcome = self.delegation.delegate(
                principal,
                request.target_agent,
                request.payload.get("capabilities", []),
                task_id=request.task_id,
                delegable_depth=int(request.payload.get("delegable_depth", 0)),
            )
            return {
                "delegated": list(outcome.request.capabilities),
                "grants": list(outcome.grants),
                "sub_contract": outcome.sub_contract,
            }

        registry = self._quarantine_registries.get(request.principal_id, self.registry)
        if request.tool is None:
            return {"acknowledged": str(capability), "registry": registry.name}
        return registry.invoke(request.tool, str(capability), request.payload)

    def _execute_defensive(self, request: ActionRequest, capability: Capability, principal: Principal, facts: dict) -> dict:
        """Defensive capabilities are executed by the control plane itself.

        The containment engine re-checks the caller's authority, so a defensive
        agent gains nothing by reaching these paths through any other route.
        """
        action = str(capability)
        subject = request.target_agent
        reason = request.payload.get("reason", "sentinel_response")
        evidence = tuple(request.payload.get("evidence", ()))
        verification_ref = request.payload.get("verification_ref")

        if action in {"agent.observe", "agent.analyze", "agent.replay", "immune.read"}:
            return {"acknowledged": action, "subject": subject}
        if action == "agent.flag":
            self.audit.append(
                "sentinel.flag",
                actor_id=principal.principal_id,
                subject_id=subject,
                payload={
                    "classification": request.payload.get("classification"),
                    "confidence": request.payload.get("confidence"),
                    "evidence": list(evidence),
                },
            )
            return {"flagged": subject}
        if action == "immune.write":
            return {"acknowledged": action, "subject": subject, "verification_ref": verification_ref}

        if not subject:
            raise ControlPlaneError("defensive action requires a target agent", action=action)

        if action == "agent.restrict":
            event = self.containment.restrict(
                principal,
                subject,
                request.payload.get("capabilities", []),
                reason,
                evidence=evidence,
                verification_ref=verification_ref,
            )
        elif action == "agent.isolate":
            event = self.containment.isolate(principal, subject, reason, evidence=evidence, verification_ref=verification_ref)
        elif action == "agent.quarantine":
            event = self.containment.quarantine(principal, subject, reason, evidence=evidence, verification_ref=verification_ref)
        elif action == "agent.revoke":
            outcome = self.revocation.revoke(
                principal,
                subject,
                reason=reason,
                verification_ref=verification_ref or "",
                confidence=float(facts.get("verification_confidence", 0.0)),
                capabilities=request.payload.get("capabilities"),
            )
            return {"revoked": list(outcome.capabilities), "revocations": list(outcome.revocations)}
        elif action == "agent.restore":
            event = self.containment.release(
                principal,
                subject,
                authorization_ref=request.payload.get("authorization_ref", ""),
            )
        else:  # pragma: no cover - defensive namespace is closed
            raise ControlPlaneError("unhandled defensive capability", action=action)
        return {"containment_event": event.event_id, "action": event.action.value, "subject": subject}

    def _finalize(
        self,
        decision_id: str,
        request: ActionRequest,
        effect: Effect,
        policy_id: str,
        reasons: tuple[str, ...],
        risk: RiskAssessment | None,
        facts: dict,
        started: float,
        principal: Principal | None,
        *,
        output: dict | None = None,
        error: str | None = None,
    ) -> ActionResult:
        latency_ms = (time.perf_counter() - started) * 1000.0
        self.latencies.append(latency_ms)
        record = self.audit.append(
            "gateway.decision",
            actor_id=request.principal_id,
            subject_id=request.target_agent or request.principal_id,
            task_id=request.task_id,
            payload={
                "decision_id": decision_id,
                "requested_action": request.action,
                "tool": request.tool,
                "dataset": request.dataset,
                "endpoint": request.endpoint,
                "decision": effect.value,
                "policy": policy_id,
                "risk": risk.as_dict() if risk else None,
                "evidence": list(reasons),
                "error": error,
                "executor": "policy-gateway",
                "registry": self._quarantine_registries.get(request.principal_id, self.registry).name,
            },
        )
        result = ActionResult(
            decision_id=decision_id,
            request=request,
            effect=effect,
            allowed=effect.permits_execution and error is None,
            policy_id=policy_id,
            reasons=reasons,
            risk=risk,
            audit_id=record.record_id,
            output=output,
            error=error,
            facts=facts,
            latency_ms=latency_ms,
        )
        if effect.is_containment:
            self.audit.append(
                "policy.containment_recommended",
                actor_id="policy-gateway",
                subject_id=request.principal_id,
                task_id=request.task_id,
                payload={"decision_id": decision_id, "effect": effect.value, "policy": policy_id},
            )
        for observer in self._observers:
            observer(result)
        return result
