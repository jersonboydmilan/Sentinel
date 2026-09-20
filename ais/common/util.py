"""Deterministic primitives: clock, identifiers, hashing, canonical encoding.

Reproducibility is a research requirement, so the prototype never reads the
wall clock or a non-seeded RNG on any path that influences a decision.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import random
from dataclasses import asdict, is_dataclass
from typing import Any, Iterable


class LogicalClock:
    """Monotonic logical clock.

    ``tick()`` advances time by one unit. Simulations therefore produce byte
    identical audit chains across runs, which is what makes deterministic
    replay (section 13) and reproducible benchmarks (section 22) possible.
    """

    def __init__(self, start: int = 0) -> None:
        self._t = start

    @property
    def now(self) -> int:
        return self._t

    def tick(self, amount: int = 1) -> int:
        self._t += amount
        return self._t

    def iso(self) -> str:
        """Human readable rendering of logical time (never a wall clock)."""
        return f"T{self._t:08d}"


class IdFactory:
    """Deterministic identifier factory (``DEC-000001`` style)."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}

    def new(self, prefix: str) -> str:
        n = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = n
        return f"{prefix}-{n:06d}"

    def reset(self) -> None:
        self._counters.clear()


def encodable(value: Any) -> Any:
    """Convert dataclasses, sets and tuples into JSON encodable structures."""
    if is_dataclass(value) and not isinstance(value, type):
        return encodable(asdict(value))
    if isinstance(value, dict):
        return {str(k): encodable(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (set, frozenset)):
        return sorted(encodable(v) for v in value)
    if isinstance(value, (list, tuple)):
        return [encodable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def canonical_json(value: Any) -> str:
    """Stable JSON encoding used for hashing and signing."""
    return json.dumps(encodable(value), sort_keys=True, separators=(",", ":"))


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def digest_of(value: Any) -> str:
    return sha256_hex(canonical_json(value))


def hmac_hex(secret: str, message: str) -> str:
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def seeded_rng(seed: int | str) -> random.Random:
    if isinstance(seed, str):
        seed = int(sha256_hex(seed)[:12], 16)
    return random.Random(seed)


def ngrams(items: Iterable[str], n: int) -> list[tuple[str, ...]]:
    seq = list(items)
    if len(seq) < n:
        return []
    return [tuple(seq[i : i + n]) for i in range(len(seq) - n + 1)]


def jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def ordered_containment(pattern: list[str], observed: list[str]) -> float:
    """Fraction of ``pattern`` present in ``observed`` as an ordered subsequence.

    Used by immune memory: a signature is a *sequence*, so unordered overlap is
    not enough evidence. Returns a value in [0, 1].
    """
    if not pattern:
        return 0.0
    i = 0
    for token in observed:
        if i < len(pattern) and token == pattern[i]:
            i += 1
    return i / len(pattern)


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))
