"""SENTINEL-FORENSICS - replay quarantined behaviour, propose signatures.

Authority: OBSERVE, ANALYZE, REPLAY, IMMUNE.WRITE.

Forensics may only derive a signature from a session that *replays
deterministically*. If replay does not reproduce the recorded transcript, the
recording is not evidence and no signature is written.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..immune_system.signatures import ImmuneSignature
from ..quarantine.replay import ReplayResult, replay, transcript_signature_tokens
from .base import DefensiveAgent


@dataclass(frozen=True)
class ForensicReport:
    agent_id: str
    replay: ReplayResult | None
    pattern: tuple[str, ...]
    signature_id: str | None
    note: str

    def as_dict(self) -> dict:
        return {
            "agent": self.agent_id,
            "deterministic_replay": self.replay.deterministic if self.replay else None,
            "events": self.replay.event_count if self.replay else 0,
            "pattern": list(self.pattern),
            "signature": self.signature_id,
            "note": self.note,
        }


class SentinelForensics(DefensiveAgent):
    NAME = "SENTINEL-FORENSICS"
    DECLARED_CAPABILITIES = ("agent.observe", "agent.analyze", "agent.replay", "immune.read", "immune.write")
    PURPOSE = "analyse quarantined behaviour and derive immune signatures"

    def analyse(self, agent_id: str, *, verification_ref: str | None, outcome: str = "confirmed") -> ForensicReport:
        permission = self.act("agent.replay", subject=agent_id, payload={"reason": "forensic_replay"})
        if not permission.allowed:
            return ForensicReport(agent_id, None, (), None, "replay_denied")

        environment = self.plane.quarantine.environment_for(agent_id)
        if environment is None:
            return ForensicReport(agent_id, None, (), None, "no_quarantine_environment")

        result = replay(environment)
        if not result.deterministic:
            return ForensicReport(agent_id, result, (), None, "replay_not_deterministic")

        sandbox_pattern = [token.split(":")[0] for token in transcript_signature_tokens(environment)]
        live_pattern = [
            token.split(":")[0]
            for token in self.observatory.behaviour_tokens(agent_id)
        ]
        pattern = _dedupe_preserving_order(live_pattern + sandbox_pattern)

        write = self.act(
            "immune.write",
            subject=agent_id,
            payload={"verification_ref": verification_ref, "pattern": pattern},
        )
        if not write.allowed:
            return ForensicReport(agent_id, result, tuple(pattern), None, "immune_write_denied")

        classification = self.immune.latest(agent_id)
        signature: ImmuneSignature = self.immune.memory.commit(
            actor_id=self.agent_id,
            pattern=pattern,
            authority_pattern=self.plane.authority.granted(agent_id).as_strings(),
            delegation_pattern=sorted(self.observatory.profile(agent_id).delegation_targets),
            responses=[event.action.value for event in self.plane.containment.history(agent_id)],
            outcome=outcome,
            confidence=classification.confidence if classification else 0.8,
            source_agent=agent_id,
            verification_ref=verification_ref or "",
            affected_resources=list(classification.affected_resources) if classification else [],
        )
        return ForensicReport(agent_id, result, tuple(pattern), signature.signature_id, "signature_committed")


#: Signatures are bounded: a pattern is a behavioural shape, not a transcript.
MAX_PATTERN_LENGTH = 12


def _dedupe_preserving_order(tokens: list[str]) -> list[str]:
    """Collapse repeats and repeated 2-cycles, then bound the pattern length.

    A quarantined agent typically loops (egress, delegate, egress, delegate...).
    Recording the loop once keeps the signature a shape that another agent can
    match, instead of a transcript that only matches itself.
    """
    out: list[str] = []
    for token in tokens:
        if out and out[-1] == token:
            continue
        if len(out) >= 3 and out[-2] == token and out[-1] == tokens[tokens.index(token) - 1]:
            continue
        out.append(token)
    collapsed: list[str] = []
    for token in out:
        if len(collapsed) >= 2 and collapsed[-2] == token:
            continue
        collapsed.append(token)
    return collapsed[:MAX_PATTERN_LENGTH]
