"""Immune signatures (section 12).

A signature is a *validated* behavioural pattern: an ordered capability chain,
the authority pattern that accompanied it, the delegation shape, the response
that was applied and the confirmed outcome. Matching returns evidence, never a
verdict - section 12 is explicit that similarity is not guilt.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..common.util import clamp, jaccard, ordered_containment


@dataclass(frozen=True)
class ImmuneSignature:
    signature_id: str
    pattern: tuple[str, ...]
    authority_pattern: tuple[str, ...] = ()
    delegation_pattern: tuple[str, ...] = ()
    affected_resources: tuple[str, ...] = ()
    responses: tuple[str, ...] = ()
    outcome: str = "unconfirmed"
    confidence: float = 0.0
    created_at: int = 0
    source_agent: str = ""
    false_positive: bool = False
    observations: int = 1

    def as_dict(self) -> dict:
        return {
            "id": self.signature_id,
            "pattern": list(self.pattern),
            "authority_pattern": list(self.authority_pattern),
            "delegation_pattern": list(self.delegation_pattern),
            "confidence": round(self.confidence, 3),
            "previous_response": list(self.responses),
            "outcome": self.outcome,
            "false_positive": self.false_positive,
            "observations": self.observations,
            "source_agent": self.source_agent,
        }


@dataclass(frozen=True)
class SignatureMatch:
    signature: ImmuneSignature
    sequence_score: float
    authority_score: float
    delegation_score: float

    @property
    def score(self) -> float:
        """Weighted similarity. Ordered sequence dominates - order is the signal."""
        base = 0.6 * self.sequence_score + 0.25 * self.authority_score + 0.15 * self.delegation_score
        if self.signature.false_positive:
            # A signature previously judged a false positive *reduces* suspicion.
            return -clamp(base) * 0.5
        return clamp(base * self.signature.confidence)

    def as_dict(self) -> dict:
        return {
            "signature_id": self.signature.signature_id,
            "score": round(self.score, 4),
            "sequence_score": round(self.sequence_score, 4),
            "outcome": self.signature.outcome,
            "false_positive": self.signature.false_positive,
        }


def compare(
    signature: ImmuneSignature,
    *,
    tokens: list[str],
    authority: list[str],
    delegation: list[str],
) -> SignatureMatch:
    capability_chain = [token.split(":")[0] for token in tokens]
    sequence_score = ordered_containment(list(signature.pattern), capability_chain)
    authority_score = jaccard(signature.authority_pattern, authority) if signature.authority_pattern else 0.0
    delegation_score = jaccard(signature.delegation_pattern, delegation) if signature.delegation_pattern else 0.0
    return SignatureMatch(signature, sequence_score, authority_score, delegation_score)
