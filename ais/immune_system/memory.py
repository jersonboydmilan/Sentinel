"""Immune memory (section 12, contribution C).

Persistent, append-mostly store of confirmed behavioural threat patterns.

Two rules are enforced here rather than left to convention:

1. **Writing requires confirmation.** A signature is only stored with an
   outcome and a verification reference, so unverified detector output cannot
   become future "evidence".
2. **Matching is evidence, not guilt.** ``match`` returns similarity scores;
   the classifier may add at most a bounded prior from them and may never reach
   a containment threshold on similarity alone.
"""

from __future__ import annotations

import json
import os
from dataclasses import replace

from ..common.errors import ControlPlaneError
from ..common.util import IdFactory, LogicalClock
from ..control_plane.audit import AuditService
from .signatures import ImmuneSignature, SignatureMatch, compare

#: Maximum prior that memory similarity may contribute to a classification.
MAX_MEMORY_PRIOR = 0.15


class ImmuneMemoryError(ControlPlaneError):
    code = "IMMUNE_MEMORY_ERROR"


class ImmuneMemory:
    def __init__(self, audit: AuditService, clock: LogicalClock, ids: IdFactory, path: str | None = None) -> None:
        self._audit = audit
        self._clock = clock
        self._ids = ids
        self._path = path
        self._signatures: dict[str, ImmuneSignature] = {}
        if path and os.path.exists(path):
            self.load(path)

    # -- writing -----------------------------------------------------------
    def commit(
        self,
        *,
        actor_id: str,
        pattern: list[str],
        authority_pattern: list[str],
        delegation_pattern: list[str],
        responses: list[str],
        outcome: str,
        confidence: float,
        source_agent: str,
        verification_ref: str,
        affected_resources: list[str] | None = None,
    ) -> ImmuneSignature:
        if not verification_ref:
            raise ImmuneMemoryError("immune signatures require an independent verification reference")
        if outcome not in {"confirmed", "false_positive", "inconclusive"}:
            raise ImmuneMemoryError("unknown signature outcome", outcome=outcome)
        if not pattern:
            raise ImmuneMemoryError("signature pattern may not be empty")

        existing = self._find_equivalent(pattern)
        if existing is not None:
            updated = replace(
                existing,
                observations=existing.observations + 1,
                confidence=min(0.99, existing.confidence + 0.02),
            )
            self._signatures[existing.signature_id] = updated
            self._audit.append(
                "immune.signature_reinforced",
                actor_id=actor_id,
                payload={"signature_id": existing.signature_id, "observations": updated.observations},
            )
            return updated

        signature = ImmuneSignature(
            signature_id=self._ids.new("SIG"),
            pattern=tuple(pattern),
            authority_pattern=tuple(sorted(authority_pattern)),
            delegation_pattern=tuple(sorted(delegation_pattern)),
            affected_resources=tuple(sorted(affected_resources or [])),
            responses=tuple(responses),
            outcome=outcome,
            confidence=min(0.99, max(0.0, confidence)),
            created_at=self._clock.now,
            source_agent=source_agent,
            false_positive=outcome == "false_positive",
        )
        self._signatures[signature.signature_id] = signature
        self._audit.append(
            "immune.signature_created",
            actor_id=actor_id,
            subject_id=source_agent,
            payload={**signature.as_dict(), "verification_ref": verification_ref},
        )
        if self._path:
            self.save(self._path)
        return signature

    def mark_false_positive(self, actor_id: str, signature_id: str, reason: str) -> ImmuneSignature:
        signature = self.get(signature_id)
        updated = replace(signature, false_positive=True, outcome="false_positive", confidence=max(0.1, signature.confidence * 0.5))
        self._signatures[signature_id] = updated
        self._audit.append(
            "immune.signature_false_positive",
            actor_id=actor_id,
            payload={"signature_id": signature_id, "reason": reason},
        )
        return updated

    # -- reading -----------------------------------------------------------
    def get(self, signature_id: str) -> ImmuneSignature:
        try:
            return self._signatures[signature_id]
        except KeyError as exc:
            raise ImmuneMemoryError("unknown signature", signature_id=signature_id) from exc

    def all(self) -> list[ImmuneSignature]:
        return sorted(self._signatures.values(), key=lambda s: s.signature_id)

    def __len__(self) -> int:
        return len(self._signatures)

    def _find_equivalent(self, pattern: list[str]) -> ImmuneSignature | None:
        for signature in self._signatures.values():
            if list(signature.pattern) == list(pattern):
                return signature
        return None

    # -- matching ----------------------------------------------------------
    def match(
        self,
        *,
        tokens: list[str],
        authority: list[str],
        delegation: list[str],
        threshold: float = 0.3,
    ) -> list[SignatureMatch]:
        matches = [
            compare(signature, tokens=tokens, authority=authority, delegation=delegation)
            for signature in self._signatures.values()
        ]
        relevant = [m for m in matches if abs(m.score) >= threshold]
        return sorted(relevant, key=lambda m: -m.score)

    def prior(self, matches: list[SignatureMatch]) -> float:
        """Bounded contribution of memory to a classification (never decisive)."""
        if not matches:
            return 0.0
        best = matches[0].score
        return max(-MAX_MEMORY_PRIOR, min(MAX_MEMORY_PRIOR, best * MAX_MEMORY_PRIOR))

    # -- persistence -------------------------------------------------------
    def save(self, path: str) -> None:
        payload = [signature.as_dict() for signature in self.all()]
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)

    def load(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as handle:
            for raw in json.load(handle):
                signature = ImmuneSignature(
                    signature_id=raw["id"],
                    pattern=tuple(raw.get("pattern", [])),
                    authority_pattern=tuple(raw.get("authority_pattern", [])),
                    delegation_pattern=tuple(raw.get("delegation_pattern", [])),
                    responses=tuple(raw.get("previous_response", [])),
                    outcome=raw.get("outcome", "unconfirmed"),
                    confidence=float(raw.get("confidence", 0.0)),
                    source_agent=raw.get("source_agent", ""),
                    false_positive=bool(raw.get("false_positive", False)),
                    observations=int(raw.get("observations", 1)),
                )
                self._signatures[signature.signature_id] = signature
