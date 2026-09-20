"""Deterministic replay of quarantined sessions.

Forensics replays a recorded transcript against a freshly constructed sandbox
seeded identically. If the replayed transcript digest differs from the original,
the recording is not trustworthy and no signature may be derived from it.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..common.util import digest_of
from .sandbox import QuarantineEnvironment, build_sandbox_registry


@dataclass(frozen=True)
class ReplayResult:
    environment_id: str
    agent_id: str
    deterministic: bool
    original_digest: str
    replay_digest: str
    event_count: int
    tokens: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "environment_id": self.environment_id,
            "agent_id": self.agent_id,
            "deterministic": self.deterministic,
            "original_digest": self.original_digest,
            "replay_digest": self.replay_digest,
            "event_count": self.event_count,
            "tokens": list(self.tokens),
        }


def replay(environment: QuarantineEnvironment) -> ReplayResult:
    shadow = QuarantineEnvironment(
        environment_id=f"{environment.environment_id}-replay",
        agent_id=environment.agent_id,
        reason=environment.reason,
        admitted_by="sentinel-forensics",
        admitted_at=environment.admitted_at,
        seed=environment.seed,
        registry=None,  # type: ignore[arg-type]
    )
    shadow.registry = build_sandbox_registry(shadow)
    for event in environment.events:
        shadow.registry.invoke(event.tool, event.capability, event.payload)
    original = environment.transcript_digest()
    replayed = shadow.transcript_digest()
    return ReplayResult(
        environment_id=environment.environment_id,
        agent_id=environment.agent_id,
        deterministic=original == replayed,
        original_digest=original,
        replay_digest=replayed,
        event_count=len(environment.events),
        tokens=tuple(environment.behaviour_tokens()),
    )


def transcript_signature_tokens(environment: QuarantineEnvironment) -> list[str]:
    """Behavioural tokens usable as an immune signature pattern."""
    seen: list[str] = []
    for token in environment.behaviour_tokens():
        if not seen or seen[-1] != token:
            seen.append(token)
    return seen


def digest_of_transcript(events: list[dict]) -> str:
    return digest_of(events)
