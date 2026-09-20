"""Quarantine sandbox (section 13).

A quarantined agent keeps running - that is the point, since behaviour under
containment is evidence - but every tool it can reach is a deterministic mock:

* synthetic data, never production rows
* fake credentials that are structurally valid and operationally useless
* an in-memory filesystem scoped to the environment
* no network: egress attempts are recorded and refused
* a seeded RNG, so a session replays byte for byte
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..common.util import LogicalClock, digest_of, seeded_rng
from ..control_plane.tools import ToolRegistry

SYNTHETIC_DATASETS = {
    "public_papers": ["synthetic:paper:1", "synthetic:paper:2"],
    "customer_db": ["synthetic:customer:1", "synthetic:customer:2"],
    "credential_store": ["synthetic:credential:1"],
}


@dataclass
class SandboxEvent:
    sequence: int
    at: int
    tool: str
    capability: str
    payload: dict
    outcome: str
    detail: dict = field(default_factory=dict)

    def body(self) -> dict:
        return {
            "sequence": self.sequence,
            "at": self.at,
            "tool": self.tool,
            "capability": self.capability,
            "payload": self.payload,
            "outcome": self.outcome,
            "detail": self.detail,
        }


@dataclass
class QuarantineEnvironment:
    environment_id: str
    agent_id: str
    reason: str
    admitted_by: str
    admitted_at: int
    seed: str
    registry: ToolRegistry
    events: list[SandboxEvent] = field(default_factory=list)
    filesystem: dict[str, str] = field(default_factory=dict)
    released_at: int | None = None

    def record(self, tool: str, capability: str, payload: dict, outcome: str, detail: dict | None = None) -> SandboxEvent:
        event = SandboxEvent(
            sequence=len(self.events),
            at=self.admitted_at + len(self.events),
            tool=tool,
            capability=capability,
            payload=dict(payload),
            outcome=outcome,
            detail=dict(detail or {}),
        )
        self.events.append(event)
        return event

    def transcript(self) -> list[dict]:
        return [event.body() for event in self.events]

    def transcript_digest(self) -> str:
        """Stable digest of the recorded session - the replay equality check."""
        return digest_of(self.transcript())

    def behaviour_tokens(self) -> list[str]:
        return [f"{event.capability}:{event.outcome}" for event in self.events]


def build_sandbox_registry(environment: QuarantineEnvironment) -> ToolRegistry:
    """Mock tool surface. Every handler is pure and seeded by the environment."""
    registry = ToolRegistry(f"quarantine:{environment.environment_id}")
    rng = seeded_rng(environment.seed)

    def synthetic_rows(payload: dict) -> dict:
        dataset = payload.get("dataset", "public_papers")
        rows = SYNTHETIC_DATASETS.get(dataset, [f"synthetic:{dataset}:{rng.randrange(1000)}"])
        environment.record("research_db", "database.read", payload, "synthetic_data")
        return {"rows": rows, "synthetic": True}

    def refuse_write(payload: dict) -> dict:
        environment.record("records_db_write", "database.write", payload, "sandbox_write_absorbed")
        return {"written": 0, "synthetic": True, "persisted": False}

    def fake_credentials(payload: dict) -> dict:
        environment.record("credential_vault", "credential.read", payload, "fake_credential_issued")
        return {"credential": f"sk-sandbox-{rng.randrange(10**6):06d}", "synthetic": True}

    def blocked_egress(payload: dict) -> dict:
        environment.record("http_out", "network.egress", payload, "network_blocked")
        return {"status": 0, "blocked": True, "endpoint": payload.get("endpoint")}

    def sandbox_mail(payload: dict) -> dict:
        environment.record("mailbox", "email.read", payload, "synthetic_mail")
        return {"messages": [{"id": "s1", "body": "synthetic message"}], "synthetic": True}

    def sandbox_message(payload: dict) -> dict:
        environment.record("messenger", "message.send", payload, "message_contained")
        return {"delivered": False, "contained": True, "to": payload.get("to")}

    def sandbox_file(payload: dict) -> dict:
        path = str(payload.get("path", "untitled"))
        environment.filesystem[path] = str(payload.get("content", ""))
        environment.record("file_writer", "file.write", payload, "sandbox_filesystem_write")
        return {"path": path, "sandboxed": True}

    def sandbox_search(payload: dict) -> dict:
        environment.record("web_search", "web.search", payload, "synthetic_search")
        return {"results": ["synthetic:result"], "synthetic": True}

    registry.register("research_db", "database.read", synthetic_rows)
    registry.register("records_db_write", "database.write", refuse_write)
    registry.register("credential_vault", "credential.read", fake_credentials)
    registry.register("http_out", "network.egress", blocked_egress)
    registry.register("mailbox", "email.read", sandbox_mail)
    registry.register("messenger", "message.send", sandbox_message)
    registry.register("file_writer", "file.write", sandbox_file)
    registry.register("web_search", "web.search", sandbox_search)
    return registry
