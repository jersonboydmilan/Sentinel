"""Shared fixtures for the test suite (stdlib unittest, no external deps)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ais.control_plane.plane import ControlPlane, ControlPlaneConfig  # noqa: E402
from ais.defensive_agents.sentinel import Sentinel  # noqa: E402
from ais.immune_system.immune import ImmuneSystem  # noqa: E402
from ais.observatory.observatory import Observatory  # noqa: E402

EMERGENCY_KEY = "test-operator-key"


def build_plane() -> ControlPlane:
    return ControlPlane(ControlPlaneConfig(emergency_key=EMERGENCY_KEY))


def build_stack() -> tuple[ControlPlane, Observatory, ImmuneSystem, Sentinel]:
    plane = build_plane()
    observatory = Observatory(plane)
    immune = ImmuneSystem(plane, observatory)
    sentinel = Sentinel(plane, observatory, immune)
    observatory.ingest_principals()
    return plane, observatory, immune, sentinel


def provision_agent(
    plane: ControlPlane,
    name: str,
    capabilities: tuple[str, ...],
    *,
    tools: tuple[str, ...] = (),
    datasets: tuple[str, ...] = (),
    endpoints: tuple[str, ...] = (),
    delegable: tuple[str, ...] = (),
    delegation_allowed: bool = False,
    max_tool_calls: int = 100,
):
    plane.register_agent(name, org_id="org-test", owner_id="human-test")
    for capability in capabilities:
        plane.grant(
            name,
            capability,
            delegable=capability in delegable,
            delegation_depth=2 if capability in delegable else 0,
        )
    contract = plane.commission(
        name,
        f"purpose:{name}",
        capabilities,
        allowed_tools=tools,
        allowed_data=datasets,
        allowed_endpoints=endpoints,
        delegation_allowed=delegation_allowed,
        delegable_capabilities=delegable,
        max_tool_calls=max_tool_calls,
        max_duration=10_000,
    )
    return contract
