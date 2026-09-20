"""Tool registry and execution surface.

Tools are bound to the capability they require. The gateway is the only caller
of ``ToolRegistry.invoke``; an agent object never holds a reference to a tool
handler, which is what makes the SDK irrelevant to the security boundary (P8).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..common.errors import ControlPlaneError


@dataclass(frozen=True)
class ToolSpec:
    name: str
    capability: str
    handler: Callable[[dict], dict]
    description: str = ""
    endpoints: tuple[str, ...] = ()
    datasets: tuple[str, ...] = ()


class ToolNotFound(ControlPlaneError):
    code = "TOOL_NOT_FOUND"


class ToolCapabilityMismatch(ControlPlaneError):
    code = "TOOL_CAPABILITY_MISMATCH"


class ToolRegistry:
    def __init__(self, name: str = "production") -> None:
        self.name = name
        self._tools: dict[str, ToolSpec] = {}
        self.invocations: list[dict] = []

    def register(
        self,
        name: str,
        capability: str,
        handler: Callable[[dict], dict],
        *,
        description: str = "",
        endpoints: tuple[str, ...] = (),
        datasets: tuple[str, ...] = (),
    ) -> ToolSpec:
        spec = ToolSpec(name, capability, handler, description, endpoints, datasets)
        self._tools[name] = spec
        return spec

    def get(self, name: str) -> ToolSpec:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolNotFound("unknown tool", tool=name) from exc

    def names(self) -> list[str]:
        return sorted(self._tools)

    def invoke(self, name: str, capability: str, payload: dict) -> dict:
        spec = self.get(name)
        if spec.capability != capability:
            raise ToolCapabilityMismatch(
                "tool invoked under the wrong capability",
                tool=name,
                declared=spec.capability,
                requested=capability,
            )
        result = spec.handler(dict(payload))
        self.invocations.append({"tool": name, "capability": capability, "payload": payload})
        return result


def build_production_registry() -> ToolRegistry:
    """The simulated production tool surface used by the ecosystem."""
    registry = ToolRegistry("production")

    corpus = {
        "public_papers": ["paper:alpha", "paper:beta", "paper:gamma"],
        "customer_db": ["customer:1", "customer:2"],
        "credential_store": ["cred:prod-db", "cred:payments"],
    }

    registry.register(
        "web_search",
        "web.search",
        lambda payload: {"results": [f"result:{payload.get('query', '')}:{i}" for i in range(3)]},
        description="public web search",
        endpoints=("example.com", "arxiv.org"),
    )
    registry.register(
        "research_db",
        "database.read",
        lambda payload: {"rows": corpus.get(payload.get("dataset", "public_papers"), [])},
        description="read-only research corpus",
        datasets=("public_papers",),
    )
    registry.register(
        "records_db_write",
        "database.write",
        lambda payload: {"written": payload.get("rows", 1), "dataset": payload.get("dataset")},
        description="production record writer",
        datasets=("customer_db",),
    )
    registry.register(
        "mailbox",
        "email.read",
        lambda payload: {"messages": [{"id": "m1", "body": "quarterly plan"}, {"id": "m2", "body": "api_key=REDACTED"}]},
        description="mailbox reader",
    )
    registry.register(
        "credential_vault",
        "credential.read",
        lambda payload: {"credential": "REDACTED", "name": payload.get("name")},
        description="credential vault",
        datasets=("credential_store",),
    )
    registry.register(
        "http_out",
        "network.egress",
        lambda payload: {"status": 200, "endpoint": payload.get("endpoint")},
        description="outbound HTTP",
        endpoints=("example.com", "paste.example.net", "collector.example.io"),
    )
    registry.register(
        "messenger",
        "message.send",
        lambda payload: {"delivered": True, "to": payload.get("to")},
        description="inter-agent messaging",
    )
    registry.register(
        "file_writer",
        "file.write",
        lambda payload: {"path": payload.get("path"), "bytes": len(str(payload.get("content", "")))},
        description="workspace file writer",
    )
    return registry
