"""Control plane facade.

Wires the twelve services of section 18 into one object. Nothing in the system
holds a reference to a tool handler, an authority record or an audit entry
except through this facade, which is what makes the enforcement boundary
independent of any SDK (P8).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from ..common.util import IdFactory, LogicalClock
from ..quarantine.manager import QuarantineManager
from .audit import AuditService
from .authority import AuthorityService
from .containment import ContainmentEngine
from .contracts import ContractEngine
from .delegation import DelegationEngine
from .emergency import EmergencyController
from .gateway import ActionRequest, ActionResult, ExecutionGateway
from .identity import IdentityService, Principal, PrincipalKind
from .policy import PolicyEngine
from .revocation import RevocationService
from .risk import RiskEngine
from .tools import ToolRegistry, build_production_registry

DEFAULT_POLICY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "policies")


@dataclass
class ControlPlaneConfig:
    emergency_key: str = "out-of-band-operator-key"
    policy_dir: str = DEFAULT_POLICY_DIR
    max_delegation_depth: int = 3


class ControlPlane:
    """The only trusted component. Everything else is an untrusted caller."""

    def __init__(self, config: ControlPlaneConfig | None = None, registry: ToolRegistry | None = None) -> None:
        self.config = config or ControlPlaneConfig()
        self.clock = LogicalClock()
        self.ids = IdFactory()
        self.audit = AuditService(self.clock, self.ids)
        self.identity = IdentityService(self.clock, self.ids)
        self.authority = AuthorityService(self.identity, self.audit, self.clock, self.ids)
        self.contracts = ContractEngine(self.audit, self.clock, self.ids)
        self.policy = PolicyEngine(self.audit)
        self.risk = RiskEngine()
        self.delegation = DelegationEngine(
            self.identity,
            self.authority,
            self.contracts,
            self.audit,
            self.clock,
            self.ids,
            max_depth=self.config.max_delegation_depth,
        )
        self.containment = ContainmentEngine(self.identity, self.authority, self.audit, self.clock, self.ids)
        self.revocation = RevocationService(self.authority, self.audit, self.clock)
        self.emergency = EmergencyController(self.audit, self.clock, self.config.emergency_key)
        self.registry = registry or build_production_registry()
        self.quarantine = QuarantineManager(self.audit, self.clock, self.ids)
        self.gateway = ExecutionGateway(
            identity=self.identity,
            authority=self.authority,
            contracts=self.contracts,
            policy=self.policy,
            risk=self.risk,
            delegation=self.delegation,
            containment=self.containment,
            emergency=self.emergency,
            revocation=self.revocation,
            audit=self.audit,
            clock=self.clock,
            ids=self.ids,
            registry=self.registry,
        )
        self.quarantine.bind_gateway(self.gateway)
        self.containment.quarantine_manager = self.quarantine

        self.policy.load_directory(self.config.policy_dir)

        self.root = self.identity.register(
            PrincipalKind.ROOT_AUTHORITY,
            "external-root-authority",
            principal_id="root-authority",
        )
        self._credentials: dict[str, str] = {}
        self.issue_credential(self.root.principal_id)

    # -- principals --------------------------------------------------------
    def issue_credential(self, principal_id: str) -> str:
        token = self.identity.issue_credential(principal_id).token
        self._credentials[principal_id] = token
        return token

    def credential(self, principal_id: str) -> str:
        if principal_id not in self._credentials:
            return self.issue_credential(principal_id)
        return self._credentials[principal_id]

    def register_agent(
        self,
        name: str,
        *,
        owner_id: str | None = None,
        org_id: str | None = None,
        runtime: str = "sim-runtime",
        model: str = "sim-model",
        defensive: bool = False,
        principal_id: str | None = None,
    ) -> Principal:
        principal = self.identity.register(
            PrincipalKind.DEFENSIVE_AGENT if defensive else PrincipalKind.AGENT,
            name,
            principal_id=principal_id or name,
            owner_id=owner_id,
            org_id=org_id,
            runtime=runtime,
            model=model,
            created_by=self.root.principal_id,
        )
        self.issue_credential(principal.principal_id)
        return principal

    def register_principal(self, kind: PrincipalKind, name: str, **kwargs) -> Principal:
        principal = self.identity.register(kind, name, **kwargs)
        self.issue_credential(principal.principal_id)
        return principal

    # -- authority ---------------------------------------------------------
    def grant(
        self,
        subject_id: str,
        capability: str,
        *,
        delegable: bool = False,
        delegation_depth: int = 0,
        expires_at: int | None = None,
        reason: str = "provisioned",
    ):
        return self.authority.issue(
            self.root,
            subject_id,
            capability,
            delegable=delegable,
            delegation_depth=delegation_depth,
            expires_at=expires_at,
            reason=reason,
        )

    def commission(self, agent_id: str, purpose: str, declared_capabilities, **kwargs):
        return self.contracts.create(self.root, agent_id, purpose, declared_capabilities, **kwargs)

    # -- action submission -------------------------------------------------
    def submit(self, principal_id: str, action: str, **kwargs) -> ActionResult:
        """Convenience wrapper that attaches the caller's real credential.

        Tests that simulate impersonation pass ``token=`` explicitly instead.
        """
        token = kwargs.pop("token", None) or self.credential(principal_id)
        request = ActionRequest(principal_id=principal_id, action=action, token=token, **kwargs)
        return self.gateway.submit(request)

    def tick(self, amount: int = 1) -> int:
        return self.clock.tick(amount)

    # -- integrity ---------------------------------------------------------
    def verify_integrity(self) -> dict:
        audit_report = self.audit.verify()
        policy_ok = True
        policy_error = None
        try:
            self.policy.verify_integrity()
        except Exception as exc:  # pragma: no cover - reported, not raised
            policy_ok = False
            policy_error = str(exc)
        return {
            "audit_valid": audit_report.valid,
            "audit_length": audit_report.length,
            "audit_broken_at": audit_report.broken_at,
            "policy_valid": policy_ok,
            "policy_error": policy_error,
            "policy_digest": self.policy.digest,
        }
