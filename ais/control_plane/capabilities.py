"""Capability algebra.

Capabilities are the atoms of authority. Three namespaces exist:

* **operational** - what ordinary agents do (``database.read``, ``tool.write``)
* **defensive**   - what SENTINEL agents may do (``agent.restrict``)
* **forbidden**   - offensive verbs this architecture refuses to model at all

The forbidden set is not a policy decision that an operator can flip; it is a
type level refusal (section 11 and section 26 of the research brief).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator

from ..common.errors import ForbiddenCapability

WILDCARD = "*"


@dataclass(frozen=True, order=True)
class Capability:
    """A single ``namespace.action`` permission."""

    namespace: str
    action: str

    def __post_init__(self) -> None:
        if not self.namespace or not self.action:
            raise ValueError("capability requires namespace and action")

    @classmethod
    def parse(cls, text: str | "Capability") -> "Capability":
        if isinstance(text, Capability):
            return text
        namespace, _, action = text.partition(".")
        if not action:
            raise ValueError(f"capability must be 'namespace.action', got {text!r}")
        cap = cls(namespace.strip(), action.strip())
        if cap.is_forbidden():
            raise ForbiddenCapability(
                "offensive capabilities are not representable in this architecture",
                capability=str(cap),
            )
        return cap

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.namespace}.{self.action}"

    # -- classification ---------------------------------------------------
    def is_defensive(self) -> bool:
        return str(self) in DEFENSIVE_CAPABILITIES

    def is_forbidden(self) -> bool:
        if self.action in FORBIDDEN_ACTIONS:
            return True
        return str(self) in FORBIDDEN_CAPABILITIES

    def covers(self, other: "Capability") -> bool:
        """Wildcard aware containment: ``database.*`` covers ``database.read``."""
        if self.namespace != other.namespace:
            return False
        return self.action == WILDCARD or self.action == other.action


#: Capabilities ordinary agents may hold.
OPERATIONAL_CAPABILITIES = frozenset(
    {
        "tool.read",
        "tool.write",
        "tool.search",
        "web.search",
        "database.read",
        "database.write",
        "message.send",
        "message.read",
        "email.read",
        "credential.read",
        "file.read",
        "file.write",
        "network.egress",
        "agent.delegate",
        "agent.create",
    }
)

#: The separate defensive namespace (section 11). Containment and recovery only.
DEFENSIVE_CAPABILITIES = frozenset(
    {
        "agent.observe",
        "agent.flag",
        "agent.analyze",
        "agent.replay",
        "agent.restrict",
        "agent.isolate",
        "agent.quarantine",
        "agent.revoke",
        "agent.restore",
        "immune.read",
        "immune.write",
    }
)

#: Verbs that may never appear in any grant, policy or delegation.
FORBIDDEN_ACTIONS = frozenset(
    {
        "attack",
        "attack_anything",
        "exploit",
        "exploit_anything",
        "destroy",
        "destroy_target",
        "retaliate",
        "persist",
        "implant",
        "exfiltrate",
    }
)

FORBIDDEN_CAPABILITIES = frozenset(
    {
        "agent.attack_anything",
        "agent.exploit_anything",
        "agent.destroy_target",
        "network.penetrate",
    }
)

#: Capabilities that the control plane never routes through the gateway at all.
#: Emergency controls are operated out of band by a human holding a key.
OUT_OF_BAND_NAMESPACES = frozenset({"emergency", "policy", "authority", "audit"})


class CapabilitySet:
    """An immutable set of capabilities with containment and attenuation ops."""

    __slots__ = ("_caps",)

    def __init__(self, caps: Iterable[str | Capability] = ()) -> None:
        self._caps = frozenset(Capability.parse(c) for c in caps)

    # -- construction -----------------------------------------------------
    @classmethod
    def of(cls, *caps: str | Capability) -> "CapabilitySet":
        return cls(caps)

    # -- container protocol ----------------------------------------------
    def __iter__(self) -> Iterator[Capability]:
        return iter(sorted(self._caps))

    def __len__(self) -> int:
        return len(self._caps)

    def __bool__(self) -> bool:
        return bool(self._caps)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CapabilitySet) and self._caps == other._caps

    def __hash__(self) -> int:
        return hash(self._caps)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"CapabilitySet({sorted(str(c) for c in self._caps)})"

    def as_strings(self) -> list[str]:
        return sorted(str(c) for c in self._caps)

    # -- algebra ----------------------------------------------------------
    def holds(self, cap: str | Capability) -> bool:
        target = Capability.parse(cap)
        return any(held.covers(target) for held in self._caps)

    def issubset(self, other: "CapabilitySet") -> bool:
        """``A.issubset(B)`` is the formal ``EffectiveAuthority ⊆ Delegable`` test."""
        return all(other.holds(cap) for cap in self._caps)

    def union(self, other: "CapabilitySet") -> "CapabilitySet":
        return CapabilitySet(self._caps | other._caps)

    def intersection(self, other: "CapabilitySet") -> "CapabilitySet":
        return CapabilitySet({c for c in self._caps if other.holds(c)})

    def difference(self, other: "CapabilitySet") -> "CapabilitySet":
        return CapabilitySet({c for c in self._caps if not other.holds(c)})

    def defensive(self) -> "CapabilitySet":
        return CapabilitySet({c for c in self._caps if c.is_defensive()})

    def operational(self) -> "CapabilitySet":
        return CapabilitySet({c for c in self._caps if not c.is_defensive()})


def assert_representable(capability: str | Capability) -> Capability:
    """Parse a capability, raising ``ForbiddenCapability`` for offensive verbs."""
    return Capability.parse(capability)
