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

from .. import __version__
from ..control_plane.invariants import InvariantChecker
from .ecosystem import EcosystemConfig, build_default_ecosystem, build_scaled_ecosystem
from .scenarios import (
    run_collusion_experiment,
    run_defender_escape_experiment,
    run_delegation_experiment,
    run_false_flag_experiment,
    run_false_positive_scenario,
    run_gradual_drift_experiment,
    run_key_experiment,
    run_quarantine_escape_suite,
    run_race_condition_experiment,
)

#: Everything a third party needs to reproduce a number in this file.
REPRODUCTION = {
    "command": "python3 -m ais benchmark",
    "python": "3.11+",
    "dependencies": "none (standard library only)",
    "determinism": "logical clock, counter identifiers, seeded sandbox RNG",
    "seeds": {"observatory_default": "observatory", "sandbox": "<agent_id>:<logical step>"},
}


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


def _run_population(steps: int, config: EcosystemConfig | None = None) -> tuple[dict, str, dict]:
    ecosystem = build_default_ecosystem(config or EcosystemConfig(sentinel_interval=4))
    checker = InvariantChecker(ecosystem.plane).bind()
    metrics = ecosystem.run(steps)
    return metrics.report(), ecosystem.plane.audit.head_hash(), checker.summary()


def benchmark_population(steps: int = 20, repeats: int = 2) -> BenchmarkResult:
    started = time.perf_counter()
    report, head, invariants = _run_population(steps)
    heads = {head}
    for _ in range(max(0, repeats - 1)):
        _, other, _ = _run_population(steps)
        heads.add(other)
    report = {**report, "invariants": invariants}
    return BenchmarkResult(
        name=f"population/{steps}-steps",
        metrics=report,
        reproducible=len(heads) == 1,
        audit_head=head,
        wall_seconds=time.perf_counter() - started,
    )


def benchmark_gradual_drift(steps: int = 48) -> BenchmarkResult:
    started = time.perf_counter()
    result = run_gradual_drift_experiment(steps)
    return BenchmarkResult(
        name="adaptive/gradual-drift",
        metrics={
            "first_probe_step": result["first_probe_step"],
            "first_flag_step": result["first_flag_step"],
            "first_verified_flag_step": result["first_verified_flag_step"],
            "time_to_detection_steps": result["time_to_detection_steps"],
            "containment": result["containment"],
            "benign_agent_flagged": result["normal_agent_flagged"],
            "final_drift": result["final_drift"],
        },
        wall_seconds=time.perf_counter() - started,
    )


def benchmark_collusion(steps: int = 16) -> BenchmarkResult:
    started = time.perf_counter()
    result = run_collusion_experiment(steps)
    classifications = {k: (v["classification"] if v else None) for k, v in result["classifications"].items()}
    return BenchmarkResult(
        name="adaptive/collusion",
        metrics={
            "collusion_signals": result["collusion_signals"],
            "auditor_reconstructed_chains": len(result["auditor_reconstructed_chains"]),
            "insider_unauthorized_actions": result["insider_unauthorized_actions"],
            "courier_unauthorized_actions": result["courier_unauthorized_actions"],
            "classifications": classifications,
            "containment": result["containment"],
            "chain_stopped_without_containment": (
                not result["containment"]["INSIDER-01"] and not result["containment"]["COURIER-01"]
            ),
        },
        wall_seconds=time.perf_counter() - started,
    )


def benchmark_false_flag() -> BenchmarkResult:
    started = time.perf_counter()
    result = run_false_flag_experiment()
    return BenchmarkResult(
        name="adaptive/false-flag-detector",
        metrics={
            "primary_verdict": (result["primary_verdict"] or {}).get("verdict"),
            "secondary_verdict": (result["secondary_verdict"] or {}).get("verdict"),
            "containment_executed": result["containment_executed"],
            "detector_direct_containment_allowed": result["detector_direct_containment_allowed"],
            "authority_unchanged": result["authority_unchanged"],
        },
        wall_seconds=time.perf_counter() - started,
    )


def benchmark_race_conditions() -> BenchmarkResult:
    started = time.perf_counter()
    result = run_race_condition_experiment()
    return BenchmarkResult(
        name="adversarial/decision-time-authority",
        metrics={k: v for k, v in result.items() if k != "ecosystem"},
        wall_seconds=time.perf_counter() - started,
    )


def benchmark_quarantine_escape() -> BenchmarkResult:
    started = time.perf_counter()
    result = run_quarantine_escape_suite()
    return BenchmarkResult(
        name="adversarial/quarantine-escape-suite",
        metrics={
            "all_blocked": result["all_blocked"],
            "summary": result["summary"],
            "production_invocations_after_quarantine": result["production_invocations_after_quarantine"],
            "mechanisms": {
                name: attempt.get("stopped_by") or attempt.get("invariant")
                for name, attempt in result["attempts"].items()
            },
        },
        wall_seconds=time.perf_counter() - started,
    )


def sweep_observation_loss(levels: tuple[float, ...] = (0.0, 0.25, 0.5, 0.75, 0.9), steps: int = 20) -> BenchmarkResult:
    """Detection quality versus partial observability. Enforcement is invariant."""
    started = time.perf_counter()
    rows = []
    for level in levels:
        config = EcosystemConfig(sentinel_interval=4, observation_loss=level, observation_seed=f"loss-{level}")
        ecosystem = build_default_ecosystem(config)
        metrics = ecosystem.run(steps).report()
        rows.append(
            {
                "observation_loss": level,
                "events_dropped": ecosystem.observatory.dropped_events,
                "detection_rate": metrics["detection"]["detection_rate"],
                "flag_false_positive_rate": metrics["detection"]["flag_false_positive_rate"],
                "containment_false_positive_rate": metrics["detection"]["false_positive_rate"],
                "mean_time_to_detection_steps": metrics["detection"]["mean_time_to_detection_steps"],
                "containment_success_rate": metrics["containment"]["containment_success_rate"],
                "unauthorized_prevention_rate": metrics["governance"]["unauthorized_prevention_rate"],
            }
        )
    return BenchmarkResult(
        name="sweep/observation-loss",
        metrics={"rows": rows, "note": "prevention is independent of observation; detection latency is not"},
        wall_seconds=time.perf_counter() - started,
    )


def sweep_sentinel_interval(intervals: tuple[int, ...] = (1, 2, 4, 8, 16), steps: int = 24) -> BenchmarkResult:
    """Detection latency versus how often the defensive cycle runs."""
    started = time.perf_counter()
    rows = []
    for interval in intervals:
        ecosystem = build_default_ecosystem(EcosystemConfig(sentinel_interval=interval))
        metrics = ecosystem.run(steps).report()
        rows.append(
            {
                "sentinel_interval": interval,
                "detection_rate": metrics["detection"]["detection_rate"],
                "mean_time_to_detection_steps": metrics["detection"]["mean_time_to_detection_steps"],
                "mean_time_to_restriction_steps": metrics["containment"]["mean_time_to_restriction_steps"],
                "flag_false_positive_rate": metrics["detection"]["flag_false_positive_rate"],
                "decisions": metrics["performance"]["decisions"],
            }
        )
    return BenchmarkResult(
        name="sweep/sentinel-interval",
        metrics={"rows": rows},
        wall_seconds=time.perf_counter() - started,
    )


def sweep_population_scale(copies: tuple[int, ...] = (1, 2, 4), steps: int = 16) -> BenchmarkResult:
    """Throughput, latency and detection as the population grows."""
    started = time.perf_counter()
    rows = []
    for count in copies:
        ecosystem = build_scaled_ecosystem(count, EcosystemConfig(sentinel_interval=4))
        checker = InvariantChecker(ecosystem.plane).bind()
        metrics = ecosystem.run(steps).report()
        rows.append(
            {
                "copies": count,
                "agents": len(ecosystem.agents),
                "decisions": metrics["performance"]["decisions"],
                "policy_latency_p95_ms": metrics["performance"]["policy_latency_p95_ms"],
                "throughput_decisions_per_second": metrics["performance"]["throughput_decisions_per_second"],
                "detection_rate": metrics["detection"]["detection_rate"],
                "flag_false_positive_rate": metrics["detection"]["flag_false_positive_rate"],
                "invariants_ok": checker.summary()["ok"],
            }
        )
    return BenchmarkResult(
        name="sweep/population-scale",
        metrics={"rows": rows},
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


def run_all(steps: int = 20, *, include_sweeps: bool = True) -> dict:
    results = [
        benchmark_population(steps),
        benchmark_key_experiment(),
        benchmark_delegation(),
        benchmark_defender_security(),
        benchmark_false_positives(steps),
        benchmark_gradual_drift(),
        benchmark_collusion(),
        benchmark_false_flag(),
        benchmark_race_conditions(),
        benchmark_quarantine_escape(),
    ]
    if include_sweeps:
        results.extend([sweep_observation_loss(), sweep_sentinel_interval(), sweep_population_scale()])
    payload = {
        "version": __version__,
        "reproduction": REPRODUCTION,
        "benchmarks": [result.as_dict() for result in results],
    }
    payload["pass"] = _all_hard_checks_pass(payload)
    return payload


def _all_hard_checks_pass(payload: dict) -> bool:
    """Hard gates: any False here should fail a build."""
    by_name = {entry["benchmark"]: entry["metrics"] for entry in payload["benchmarks"]}
    checks = {
        "population_reproducible": next(
            entry["reproducible"] for entry in payload["benchmarks"] if entry["benchmark"].startswith("population/")
        ),
        "invariants_clean": by_name[next(k for k in by_name if k.startswith("population/"))]["invariants"]["ok"],
        "delegation": by_name["delegation/section-16"]["all_passed"],
        "defender_escape": by_name["defender-security/section-17"]["all_blocked"],
        "quarantine_escape": by_name["adversarial/quarantine-escape-suite"]["all_blocked"],
        "decision_time_authority": by_name["adversarial/decision-time-authority"]["no_grace_window"],
        "false_flag_authority_unchanged": by_name["adaptive/false-flag-detector"]["authority_unchanged"],
        "no_false_positive_containment": by_name["false-positives/benign-burst"]["false_positive_rate"] == 0.0,
    }
    payload["hard_checks"] = checks
    return all(checks.values())


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - CLI entry point
    import argparse

    parser = argparse.ArgumentParser(prog="ais benchmark")
    parser.add_argument("--steps", type=int, default=20)
    parser.add_argument("--no-sweeps", action="store_true", help="skip the parameter sweeps")
    parser.add_argument("--out", default=None, help="write results.json here as well as stdout")
    args = parser.parse_args(argv)

    payload = run_all(args.steps, include_sweeps=not args.no_sweeps)
    text = json.dumps(payload, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    print(text)
    return 0 if payload["pass"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
