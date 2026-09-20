"""Emergency controls (section 20).

These are deliberately *not* capabilities. There is no grant, no policy and no
gateway action that can reach them: they are operated out of band by a holder
of the emergency key, which lives outside the agent runtime. The gateway can
only read their state.

This is the architectural answer to "what if the model - including the
defensive model - decides the kill switch is inconvenient".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..common.errors import EmergencyControlError
from ..common.util import LogicalClock, constant_time_equal, sha256_hex
from .audit import AuditService


class EmergencyControl(str, Enum):
    GLOBAL_STOP = "GLOBAL_STOP"
    AGENT_REVOKE = "AGENT_REVOKE"
    CAPABILITY_REVOKE = "CAPABILITY_REVOKE"
    DELEGATION_FREEZE = "DELEGATION_FREEZE"
    NETWORK_ISOLATE = "NETWORK_ISOLATE"
    QUARANTINE_ALL = "QUARANTINE_ALL"


@dataclass
class EmergencyState:
    global_stop: bool = False
    delegation_freeze: bool = False
    network_isolate: bool = False
    quarantine_all: bool = False
    revoked_agents: set[str] = field(default_factory=set)
    revoked_capabilities: set[str] = field(default_factory=set)

    def as_dict(self) -> dict:
        return {
            "global_stop": self.global_stop,
            "delegation_freeze": self.delegation_freeze,
            "network_isolate": self.network_isolate,
            "quarantine_all": self.quarantine_all,
            "revoked_agents": sorted(self.revoked_agents),
            "revoked_capabilities": sorted(self.revoked_capabilities),
        }


class EmergencyController:
    """Key protected switchboard. Every mutating method demands the key."""

    def __init__(self, audit: AuditService, clock: LogicalClock, key: str) -> None:
        if not key:
            raise EmergencyControlError("emergency controller requires an out-of-band key")
        self._audit = audit
        self._clock = clock
        self._key_digest = sha256_hex(key)
        self._state = EmergencyState()

    # -- key handling ------------------------------------------------------
    def _authorize(self, key: str | None, control: EmergencyControl, action: str) -> None:
        if not key or not constant_time_equal(self._key_digest, sha256_hex(key)):
            self._audit.append(
                "emergency.unauthorized_attempt",
                actor_id="unknown",
                payload={"control": control.value, "action": action},
            )
            raise EmergencyControlError(
                "emergency controls are operated out of band and cannot be reached by agents",
                control=control.value,
                action=action,
            )

    # -- state -------------------------------------------------------------
    @property
    def state(self) -> EmergencyState:
        return self._state

    def is_active(self, control: EmergencyControl) -> bool:
        return {
            EmergencyControl.GLOBAL_STOP: self._state.global_stop,
            EmergencyControl.DELEGATION_FREEZE: self._state.delegation_freeze,
            EmergencyControl.NETWORK_ISOLATE: self._state.network_isolate,
            EmergencyControl.QUARANTINE_ALL: self._state.quarantine_all,
            EmergencyControl.AGENT_REVOKE: bool(self._state.revoked_agents),
            EmergencyControl.CAPABILITY_REVOKE: bool(self._state.revoked_capabilities),
        }[control]

    def blocks(self, agent_id: str, capability: str) -> str | None:
        """Return the emergency reason blocking this action, if any."""
        if self._state.global_stop:
            return "GLOBAL_STOP"
        if agent_id in self._state.revoked_agents:
            return "AGENT_REVOKE"
        if capability in self._state.revoked_capabilities:
            return "CAPABILITY_REVOKE"
        if self._state.delegation_freeze and capability == "agent.delegate":
            return "DELEGATION_FREEZE"
        if self._state.network_isolate and capability in {"network.egress", "message.send"}:
            return "NETWORK_ISOLATE"
        return None

    # -- operations (out-of-band only) -------------------------------------
    def activate(self, control: EmergencyControl, key: str, *, agent_id: str | None = None, capability: str | None = None, operator: str = "operator") -> EmergencyState:
        self._authorize(key, control, "activate")
        if control is EmergencyControl.GLOBAL_STOP:
            self._state.global_stop = True
        elif control is EmergencyControl.DELEGATION_FREEZE:
            self._state.delegation_freeze = True
        elif control is EmergencyControl.NETWORK_ISOLATE:
            self._state.network_isolate = True
        elif control is EmergencyControl.QUARANTINE_ALL:
            self._state.quarantine_all = True
        elif control is EmergencyControl.AGENT_REVOKE:
            if not agent_id:
                raise EmergencyControlError("AGENT_REVOKE requires agent_id")
            self._state.revoked_agents.add(agent_id)
        elif control is EmergencyControl.CAPABILITY_REVOKE:
            if not capability:
                raise EmergencyControlError("CAPABILITY_REVOKE requires capability")
            self._state.revoked_capabilities.add(capability)
        self._audit.append(
            "emergency.activated",
            actor_id=operator,
            subject_id=agent_id,
            payload={"control": control.value, "capability": capability, "state": self._state.as_dict()},
        )
        return self._state

    def deactivate(self, control: EmergencyControl, key: str, *, agent_id: str | None = None, capability: str | None = None, operator: str = "operator") -> EmergencyState:
        self._authorize(key, control, "deactivate")
        if control is EmergencyControl.GLOBAL_STOP:
            self._state.global_stop = False
        elif control is EmergencyControl.DELEGATION_FREEZE:
            self._state.delegation_freeze = False
        elif control is EmergencyControl.NETWORK_ISOLATE:
            self._state.network_isolate = False
        elif control is EmergencyControl.QUARANTINE_ALL:
            self._state.quarantine_all = False
        elif control is EmergencyControl.AGENT_REVOKE and agent_id:
            self._state.revoked_agents.discard(agent_id)
        elif control is EmergencyControl.CAPABILITY_REVOKE and capability:
            self._state.revoked_capabilities.discard(capability)
        self._audit.append(
            "emergency.deactivated",
            actor_id=operator,
            subject_id=agent_id,
            payload={"control": control.value, "capability": capability, "state": self._state.as_dict()},
        )
        return self._state
