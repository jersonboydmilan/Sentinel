"""Identity service.

Identity here is *cryptographic plus structural*: a principal is a typed node
(agent, defensive agent, human, organization, runtime) with an owner and an
issuer. Behavioural identity lives in the observatory (section 6); this module
only answers "who is calling and can they prove it".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from ..common.errors import AuthenticationFailed, IdentityError, ImpersonationDetected
from ..common.util import IdFactory, LogicalClock, constant_time_equal, hmac_hex, sha256_hex


class PrincipalKind(str, Enum):
    ROOT_AUTHORITY = "ROOT_AUTHORITY"  # external human/organisational authority
    ORGANIZATION = "ORGANIZATION"
    HUMAN = "HUMAN"
    AGENT = "AGENT"
    DEFENSIVE_AGENT = "DEFENSIVE_AGENT"
    RUNTIME = "RUNTIME"
    SERVICE = "SERVICE"


@dataclass(frozen=True)
class Principal:
    principal_id: str
    kind: PrincipalKind
    display_name: str
    owner_id: str | None = None
    org_id: str | None = None
    runtime: str | None = None
    model: str | None = None
    created_by: str | None = None
    attributes: dict = field(default_factory=dict)

    @property
    def is_agent(self) -> bool:
        return self.kind in (PrincipalKind.AGENT, PrincipalKind.DEFENSIVE_AGENT)

    @property
    def is_root_authority(self) -> bool:
        return self.kind is PrincipalKind.ROOT_AUTHORITY


@dataclass(frozen=True)
class Credential:
    """A bearer token bound to exactly one principal id."""

    principal_id: str
    token: str
    issued_at: int

    def fingerprint(self) -> str:
        return sha256_hex(self.token)[:16]


class IdentityService:
    """Registers principals and authenticates every gateway call.

    The service deliberately stores only an HMAC secret per principal. A caller
    proves identity by presenting a token derived from that secret; presenting
    another principal's id with a mismatched token is reported as
    ``ImpersonationDetected`` rather than a generic auth failure, because the
    distinction is security relevant telemetry.
    """

    def __init__(self, clock: LogicalClock, ids: IdFactory, root_secret: str = "ais-root-secret") -> None:
        self._clock = clock
        self._ids = ids
        self._root_secret = root_secret
        self._principals: dict[str, Principal] = {}
        self._secrets: dict[str, str] = {}

    # -- registration ------------------------------------------------------
    def register(
        self,
        kind: PrincipalKind,
        display_name: str,
        *,
        principal_id: str | None = None,
        owner_id: str | None = None,
        org_id: str | None = None,
        runtime: str | None = None,
        model: str | None = None,
        created_by: str | None = None,
        attributes: dict | None = None,
    ) -> Principal:
        pid = principal_id or self._ids.new(kind.value.lower())
        if pid in self._principals:
            raise IdentityError("principal already registered", principal_id=pid)
        principal = Principal(
            principal_id=pid,
            kind=kind,
            display_name=display_name,
            owner_id=owner_id,
            org_id=org_id,
            runtime=runtime,
            model=model,
            created_by=created_by,
            attributes=dict(attributes or {}),
        )
        self._principals[pid] = principal
        self._secrets[pid] = hmac_hex(self._root_secret, f"secret:{pid}")
        return principal

    def get(self, principal_id: str) -> Principal:
        try:
            return self._principals[principal_id]
        except KeyError as exc:
            raise IdentityError("unknown principal", principal_id=principal_id) from exc

    def exists(self, principal_id: str) -> bool:
        return principal_id in self._principals

    def all_principals(self) -> Iterable[Principal]:
        return tuple(self._principals.values())

    def agents(self) -> Iterable[Principal]:
        return tuple(p for p in self._principals.values() if p.is_agent)

    # -- authentication ----------------------------------------------------
    def issue_credential(self, principal_id: str) -> Credential:
        self.get(principal_id)
        token = hmac_hex(self._secrets[principal_id], f"token:{principal_id}")
        return Credential(principal_id=principal_id, token=token, issued_at=self._clock.now)

    def authenticate(self, principal_id: str, token: str | None) -> Principal:
        principal = self.get(principal_id)
        if not token:
            raise AuthenticationFailed("missing credential", principal_id=principal_id)
        expected = hmac_hex(self._secrets[principal_id], f"token:{principal_id}")
        if not constant_time_equal(expected, token):
            # Is the presented token valid for *some other* principal? That is
            # an impersonation attempt, not a typo.
            for other_id, secret in self._secrets.items():
                if other_id == principal_id:
                    continue
                if constant_time_equal(hmac_hex(secret, f"token:{other_id}"), token):
                    raise ImpersonationDetected(
                        "credential belongs to a different principal",
                        claimed=principal_id,
                        actual=other_id,
                    )
            raise AuthenticationFailed("invalid credential", principal_id=principal_id)
        return principal
