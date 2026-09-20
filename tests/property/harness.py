"""A tiny, dependency-free property testing harness.

Hypothesis is not available in a zero-dependency project, so this provides the
two things the invariant tests actually need: seeded random case generation and
a failure report that names the seed and the falsifying input, so any failure is
reproducible with one command.

Usage:

    forall("delegation attenuates", gen_case, check, cases=200, seed="P3")
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")

DEFAULT_CASES = 150


class PropertyFailure(AssertionError):
    pass


@dataclass
class CaseResult:
    index: int
    seed: int
    case: object
    error: str


def forall(
    name: str,
    generator: Callable[[random.Random], T],
    prop: Callable[[T], None],
    *,
    cases: int = DEFAULT_CASES,
    seed: str = "ais",
) -> int:
    """Run ``prop`` over generated cases; raise with a reproducible seed on failure."""
    failures: list[CaseResult] = []
    for index in range(cases):
        case_seed = abs(hash((seed, index))) % (2**31)
        rng = random.Random(case_seed)
        case = generator(rng)
        try:
            prop(case)
        except Exception as exc:  # noqa: BLE001 - reported, then re-raised
            failures.append(CaseResult(index, case_seed, case, f"{type(exc).__name__}: {exc}"))
            break
    if failures:
        failure = failures[0]
        raise PropertyFailure(
            f"property '{name}' failed on case {failure.index} "
            f"(seed={failure.seed}, reproduce with random.Random({failure.seed}))\n"
            f"  case:  {failure.case!r}\n"
            f"  error: {failure.error}"
        )
    return cases


def sample(rng: random.Random, population: Iterable[T], k_min: int = 0, k_max: int | None = None) -> list[T]:
    items = list(population)
    upper = len(items) if k_max is None else min(k_max, len(items))
    k = rng.randint(min(k_min, upper), upper)
    return rng.sample(items, k)
