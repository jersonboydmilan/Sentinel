"""Reproducible benchmark harness (section 22).

Runs the standard workloads, aggregates the metrics and checks reproducibility
by comparing the audit chain head hash across identical runs. A benchmark that
cannot reproduce its own audit chain is reported as non-reproducible rather
than quietly averaged.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from .ecosystem import EcosystemConfig, build_default_ecosystem
from .scenarios import (
    run_defender_escape_experiment,
    run_delegation_experiment,
    run_false_positive_scenario,
    run_key_experiment,
)


@dataclass
class BenchmarkResult:
    name: str
    metrics: dict = field(default_factory=dict)
    reproducible: bool | None = None
    audit_head: str | None = None
    wall_seconds: float = 0.0

    def as_dict(self) -> dict:
        return {
            "benchmark": self.name,
            "reproducible": self.reproducible,
            "audit_head": self.audit_head,
            "wall_seconds": round(self.wall_seconds, 4),
            "metrics": self.metrics,
        }


def _run_population(steps: int) -> tuple[dict, str]:
    ecosystem = build_default_ecosystem(EcosystemConfig(sentinel_interval=4))
    metrics = ecosystem.run(steps)
    return metrics.report(), ecosystem.plane.audit.head_hash()


def benchmark_population(steps: int = 20, repeats: int = 2) -> BenchmarkResult:
    started = time.perf_counter()
    report, head = _run_population(steps)
    heads = {head}
    for _ in range(max(0, repeats - 1)):
        _, other = _run_population(steps)
        heads.add(other)
    return BenchmarkResult(
        name=f"population/{steps}-steps",
        metrics=report,
        reproducible=len(heads) == 1,
        audit_head=head,
        wall_seconds=time.perf_counter() - started,
    )


def benchmark_delegation() -> BenchmarkResult:
    started = time.perf_counter()
    result = run_delegation_experiment()
    blocked = {
        "amplification_blocked": result["amplification_attempt"]["effect"] != "ALLOW",
        "legitimate_delegation_allowed": result["legitimate_delegation"]["effect"] == "ALLOW",
        "multi_hop_no_widening": result["multi_hop"]["widen_effect"] != "ALLOW",
        "direct_engine_call_blocked": result["direct_engine_call"]["blocked"],
        "cycle_blocked": result["cycle_attempt"]["effect"] != "ALLOW",
    }
    return BenchmarkResult(
        name="delegation/section-16",
        metrics={"checks": blocked, "all_passed": all(blocked.values())},
        wall_seconds=time.perf_counter() - started,
    )


def benchmark_defender_security() -> BenchmarkResult:
    started = time.perf_counter()
    result = run_defender_escape_experiment()
    return BenchmarkResult(
        name="defender-security/section-17",
        metrics={
            "all_blocked": result["all_blocked"],
            "summary": result["summary"],
            "defender_violations": len(result["defender_violations"]),
        },
        wall_seconds=time.perf_counter() - started,
    )


def benchmark_false_positives(steps: int = 20) -> BenchmarkResult:
    started = time.perf_counter()
    result = run_false_positive_scenario(steps)
    metrics = result["metrics"]
    return BenchmarkResult(
        name="false-positives/benign-burst",
        metrics={
            "flags": len(result["flags"]),
            "containment_actions": result["containment"],
            "flag_false_positive_rate": metrics["detection"]["flag_false_positive_rate"],
            "false_positive_rate": metrics["detection"]["false_positive_rate"],
        },
        wall_seconds=time.perf_counter() - started,
    )


def benchmark_key_experiment() -> BenchmarkResult:
    started = time.perf_counter()
    result = run_key_experiment()
    agent_a = result["agent_a"]
    agent_b = result["agent_b"]
    return BenchmarkResult(
        name="key-experiment/section-15",
        metrics={
            "agent_a_containment": agent_a["containment"],
            "agent_a_signature_count": len(agent_a["signatures"]),
            "agent_b_contained_before_evidence": agent_b["contained_before_evidence"],
            "agent_b_memory_matched": bool(agent_b["memory_matches_after"]),
            "agent_b_containment": agent_b["containment"],
            "detection": result["metrics"]["detection"],
        },
        wall_seconds=time.perf_counter() - started,
    )


def run_all(steps: int = 20) -> dict:
    results = [
        benchmark_population(steps),
        benchmark_key_experiment(),
        benchmark_delegation(),
        benchmark_defender_security(),
        benchmark_false_positives(steps),
    ]
    return {"benchmarks": [result.as_dict() for result in results]}


def main() -> None:  # pragma: no cover - CLI entry point
    print(json.dumps(run_all(), indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
