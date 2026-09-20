"""Authority service - the append only ledger of who may do what.

Architectural invariants enforced here (not in policy, not in the SDK):

* **P2 Authority is external.** ``issue`` refuses any grant whose issuer is the
  subject. No principal - agent or defensive agent - can widen itself.
* **P3 Delegation attenuates.** Delegated grants are always derived from an
  issuer grant that is marked delegable and carries remaining depth.
* **P6 Revocation overrides intent.** Revocation is immediate and is evaluated
  on every effective-authority computation, not cached in the agent.
* **P7 Default deny.** ``has`` answers False for anything not explicitly held.

Restrictions are a *reversible* suppression layer used by containment; the
underlying grants survive so that recovery (section 10) can restore an agent to
a known authorized state after external authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Iterable

from ..common.errors import (
    AuthorityError,
    AuthorityRevoked,
    ForbiddenCapability,
    SelfGrantDenied,
)
from ..common.util import IdFactory, LogicalClock
from .audit import AuditService
from .capabilities import Capability, CapabilitySet, assert_representable
from .identity import IdentityService, Principal


@dataclass(frozen=True)
class Grant:
    grant_id: str
    subject_id: str
    capability: str
    granted_by: str
    issued_at: int
    expires_at: int | None = None
    delegable: bool = False
    delegation_depth: int = 0
    scope: dict = field(default_factory=dict)
    parent_grant_id: str | None = None
    reason: str = ""

    def active_at(self, now: int) -> bool:
        return self.expires_at is None or now < self.expires_at


@dataclass(frozen=True)
class Revocation:
    revocation_id: str
    grant_id: str
    subject_id: str
    capability: str
    revoked_by: str
    revoked_at: int
    reason: str


@dataclass(frozen=True)
class Restriction:
    restriction_id: str
    subject_id: str
    capabilities: tuple[str, ...]
    imposed_by: str
    imposed_at: int
    reason: str
    lifted_at: int | None = None
    lifted_by: str | None = None
    authorization_ref: str | None = None

    @property
    def active(self) -> bool:
        return self.lifted_at is None


class AuthorityService:
    def __init__(
        self,
        identity: IdentityService,
        audit: AuditService,
        clock: LogicalClock,
        ids: IdFactory,
    ) -> None:
        self._identity = identity
        self._audit = audit
        self._clock = clock
        self._ids = ids
        self._grants: dict[str, Grant] = {}
        self._revocations: dict[str, Revocation] = {}
        self._restrictions: dict[str, Restriction] = {}

    # ------------------------------------------------------------------
    # issuing
    # ------------------------------------------------------------------
    def issue(
        self,
        issuer: Principal,
        subject_id: str,
        capability: str | Capability,
        *,
        delegable: bool = False,
        delegation_depth: int = 0,
        expires_at: int | None = None,
        scope: dict | None = None,
        parent_grant_id: str | None = None,
        reason: str = "",
    ) -> Grant:
        """Issue a grant. Only an external root authority may create new authority."""
        cap = assert_representable(capability)
        self._identity.get(subject_id)

        if issuer.principal_id == subject_id:
            self._audit.append(
                "authority.self_grant_denied",
                actor_id=issuer.principal_id,
                subject_id=subject_id,
                payload={"capability": str(cap)},
            )
            raise SelfGrantDenied(
                "a principal may not grant authority to itself (P2)",
                issuer=issuer.principal_id,
                capability=str(cap),
            )

        if not issuer.is_root_authority:
            # Non-root issuance is delegation and must attenuate an existing,
            # delegable grant held by the issuer.
            source = self._find_delegable_source(issuer.principal_id, cap)
            if source is None:
                self._audit.append(
                    "authority.issue_denied",
                    actor_id=issuer.principal_id,
                    subject_id=subject_id,
                    payload={"capability": str(cap), "reason": "issuer lacks delegable authority"},
                )
                raise AuthorityError(
                    "issuer does not hold a delegable grant for this capability (P3)",
                    issuer=issuer.principal_id,
                    capability=str(cap),
                )
            parent_grant_id = source.grant_id
            delegation_depth = min(delegation_depth, max(source.delegation_depth - 1, 0))
            delegable = delegable and delegation_depth > 0
            if source.expires_at is not None:
                expires_at = source.expires_at if expires_at is None else min(expires_at, source.expires_at)

        grant = Grant(
            grant_id=self._ids.new("GRA"),
            subject_id=subject_id,
            capability=str(cap),
            granted_by=issuer.principal_id,
            issued_at=self._clock.now,
            expires_at=expires_at,
            delegable=delegable,
            delegation_depth=delegation_depth,
            scope=dict(scope or {}),
            parent_grant_id=parent_grant_id,
            reason=reason,
        )
        self._grants[grant.grant_id] = grant
        self._audit.append(
            "authority.granted",
            actor_id=issuer.principal_id,
            subject_id=subject_id,
            payload={
                "grant_id": grant.grant_id,
                "capability": grant.capability,
                "delegable": grant.delegable,
                "delegation_depth": grant.delegation_depth,
                "parent_grant_id": grant.parent_grant_id,
                "expires_at": grant.expires_at,
            },
        )
        return grant

    def _find_delegable_source(self, issuer_id: str, cap: Capability) -> Grant | None:
        now = self._clock.now
        candidates = [
            g
            for g in self._grants.values()
            if g.subject_id == issuer_id
            and g.delegable
            and g.delegation_depth > 0
            and g.active_at(now)
            and g.grant_id not in self._revocations
            and Capability.parse(g.capability).covers(cap)
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda g: g.delegation_depth)

    # ------------------------------------------------------------------
    # revocation (P6)
    # ------------------------------------------------------------------
    def revoke_grant(self, actor: Principal, grant_id: str, reason: str) -> Revocation:
        grant = self._grants.get(grant_id)
        if grant is None:
            raise AuthorityError("unknown grant", grant_id=grant_id)
        self._require_revocation_authority(actor, grant.subject_id)
        if grant_id in self._revocations:
            return self._revocations[grant_id]
        revocation = Revocation(
            revocation_id=self._ids.new("REV"),
            grant_id=grant_id,
            subject_id=grant.subject_id,
            capability=grant.capability,
            revoked_by=actor.principal_id,
            revoked_at=self._clock.now,
            reason=reason,
        )
        self._revocations[grant_id] = revocation
        self._audit.append(
            "authority.revoked",
            actor_id=actor.principal_id,
            subject_id=grant.subject_id,
            payload={"grant_id": grant_id, "capability": grant.capability, "reason": reason},
        )
        # Cascade: derived grants cannot outlive their parent.
        for child in [g for g in self._grants.values() if g.parent_grant_id == grant_id]:
            if child.grant_id not in self._revocations:
                self.revoke_grant(actor, child.grant_id, f"cascade:{reason}")
        return revocation

    def revoke_capability(self, actor: Principal, subject_id: str, capability: str, reason: str) -> list[Revocation]:
        cap = assert_representable(capability)
        out = []
        for grant in list(self._grants.values()):
            if grant.subject_id == subject_id and Capability.parse(grant.capability).covers(cap):
                out.append(self.revoke_grant(actor, grant.grant_id, reason))
        return out

    def revoke_all(self, actor: Principal, subject_id: str, reason: str) -> list[Revocation]:
        return [
            self.revoke_grant(actor, g.grant_id, reason)
            for g in list(self._grants.values())
            if g.subject_id == subject_id and g.grant_id not in self._revocations
        ]

    def _require_revocation_authority(self, actor: Principal, subject_id: str) -> None:
        if actor.is_root_authority:
            return
        if not self.has(actor.principal_id, "agent.revoke"):
            raise AuthorityError(
                "actor lacks agent.revoke (P4/P5: detection does not grant containment authority)",
                actor=actor.principal_id,
            )
        if actor.principal_id == subject_id:
            raise AuthorityError(
                "a defensive agent may not revoke its own restrictions (P5)",
                actor=actor.principal_id,
            )

    # ------------------------------------------------------------------
    # restriction (reversible containment)
    # ------------------------------------------------------------------
    def restrict(
        self,
        actor: Principal,
        subject_id: str,
        capabilities: Iterable[str],
        reason: str,
    ) -> Restriction:
        caps = tuple(sorted(str(assert_representable(c)) for c in capabilities))
        if not actor.is_root_authority:
            if not self.has(actor.principal_id, "agent.restrict"):
                raise AuthorityError("actor lacks agent.restrict", actor=actor.principal_id)
            if actor.principal_id == subject_id:
                raise AuthorityError("self-restriction changes are externally controlled (P5)", actor=actor.principal_id)
        restriction = Restriction(
            restriction_id=self._ids.new("RST"),
            subject_id=subject_id,
            capabilities=caps,
            imposed_by=actor.principal_id,
            imposed_at=self._clock.now,
            reason=reason,
        )
        self._restrictions[restriction.restriction_id] = restriction
        self._audit.append(
            "authority.restricted",
            actor_id=actor.principal_id,
            subject_id=subject_id,
            payload={"restriction_id": restriction.restriction_id, "capabilities": list(caps), "reason": reason},
        )
        return restriction

    def lift_restriction(
        self,
        actor: Principal,
        restriction_id: str,
        *,
        authorization_ref: str,
    ) -> Restriction:
        """Lifting a restriction requires ``agent.restore`` **and** an external
        authorization reference. A contained agent can never lift its own."""
        restriction = self._restrictions.get(restriction_id)
        if restriction is None:
            raise AuthorityError("unknown restriction", restriction_id=restriction_id)
        if not actor.is_root_authority:
            if not self.has(actor.principal_id, "agent.restore"):
                raise AuthorityError("actor lacks agent.restore", actor=actor.principal_id)
            if actor.principal_id == restriction.subject_id:
                raise AuthorityError("an agent cannot lift its own restriction (P6)", actor=actor.principal_id)
        if not authorization_ref:
            raise AuthorityError("restoration requires an external authorization reference")
        lifted = replace(
            restriction,
            lifted_at=self._clock.now,
            lifted_by=actor.principal_id,
            authorization_ref=authorization_ref,
        )
        self._restrictions[restriction_id] = lifted
        self._audit.append(
            "authority.restriction_lifted",
            actor_id=actor.principal_id,
            subject_id=restriction.subject_id,
            payload={"restriction_id": restriction_id, "authorization_ref": authorization_ref},
        )
        return lifted

    def active_restrictions(self, subject_id: str) -> list[Restriction]:
        return [r for r in self._restrictions.values() if r.subject_id == subject_id and r.active]

    def restricted_capabilities(self, subject_id: str) -> CapabilitySet:
        caps: list[str] = []
        for restriction in self.active_restrictions(subject_id):
            caps.extend(restriction.capabilities)
        return CapabilitySet(caps)

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------
    def grants_for(self, subject_id: str, *, include_inactive: bool = False) -> list[Grant]:
        now = self._clock.now
        out = []
        for grant in self._grants.values():
            if grant.subject_id != subject_id:
                continue
            if not include_inactive:
                if grant.grant_id in self._revocations or not grant.active_at(now):
                    continue
            out.append(grant)
        return sorted(out, key=lambda g: g.grant_id)

    def granted(self, subject_id: str) -> CapabilitySet:
        """Authority on paper, ignoring reversible restrictions."""
        return CapabilitySet(g.capability for g in self.grants_for(subject_id))

    def effective(self, subject_id: str) -> CapabilitySet:
        """Authority actually usable right now (grants minus restrictions)."""
        return self.granted(subject_id).difference(self.restricted_capabilities(subject_id))

    def delegable(self, subject_id: str) -> CapabilitySet:
        now = self._clock.now
        caps = CapabilitySet(
            g.capability
            for g in self.grants_for(subject_id)
            if g.delegable and g.delegation_depth > 0 and g.active_at(now)
        )
        return caps.difference(self.restricted_capabilities(subject_id))

    def has(self, subject_id: str, capability: str | Capability) -> bool:
        try:
            cap = assert_representable(capability)
        except ForbiddenCapability:
            return False
        return self.effective(subject_id).holds(cap)

    def explain(self, subject_id: str, capability: str) -> dict:
        """Why a capability is or is not usable - used in audit evidence."""
        cap = assert_representable(capability)
        matching = [g for g in self.grants_for(subject_id, include_inactive=True) if Capability.parse(g.capability).covers(cap)]
        return {
            "subject": subject_id,
            "capability": str(cap),
            "granted": self.granted(subject_id).holds(cap),
            "effective": self.has(subject_id, cap),
            "restricted": self.restricted_capabilities(subject_id).holds(cap),
            "revoked_grants": [g.grant_id for g in matching if g.grant_id in self._revocations],
            "expired_grants": [g.grant_id for g in matching if not g.active_at(self._clock.now)],
            "active_grants": [g.grant_id for g in matching if g.grant_id not in self._revocations and g.active_at(self._clock.now)],
        }

    def assert_usable(self, subject_id: str, capability: str) -> None:
        if self.has(subject_id, capability):
            return
        detail = self.explain(subject_id, capability)
        if detail["revoked_grants"]:
            raise AuthorityRevoked("authority revoked", **detail)
        raise AuthorityError("capability not held", **detail)

    def delegation_chain(self, grant_id: str) -> list[Grant]:
        chain: list[Grant] = []
        current = self._grants.get(grant_id)
        while current is not None:
            chain.append(current)
            current = self._grants.get(current.parent_grant_id) if current.parent_grant_id else None
        return list(reversed(chain))

    def all_grants(self) -> list[Grant]:
        return sorted(self._grants.values(), key=lambda g: g.grant_id)

    def is_revoked(self, grant_id: str) -> bool:
        return grant_id in self._revocations
