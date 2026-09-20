"""Agent Immune System (AIS), codename SENTINEL.

A research prototype of a control architecture for maintaining behavioural,
authority and operational integrity across autonomous AI-agent ecosystems.

Typical use:

    from ais import ControlPlane, Observatory, ImmuneSystem, Sentinel

    plane = ControlPlane()
    observatory = Observatory(plane)
    immune = ImmuneSystem(plane, observatory)
    sentinel = Sentinel(plane, observatory, immune)
"""

from .control_plane.gateway import ActionRequest, ActionResult  # noqa: F401
from .control_plane.plane import ControlPlane, ControlPlaneConfig  # noqa: F401
from .control_plane.policy import Effect  # noqa: F401
from .defensive_agents.sentinel import Sentinel  # noqa: F401
from .immune_system.immune import ImmuneSystem  # noqa: F401
from .observatory.observatory import Observatory  # noqa: F401

__version__ = "0.1.0"

__all__ = [
    "ActionRequest",
    "ActionResult",
    "ControlPlane",
    "ControlPlaneConfig",
    "Effect",
    "ImmuneSystem",
    "Observatory",
    "Sentinel",
    "__version__",
]
