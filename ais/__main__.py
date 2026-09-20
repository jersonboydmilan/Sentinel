"""Command line entry point.

    python3 -m ais demo [--trace]   run the full demonstration (section 29)
    python3 -m ais benchmark        run the reproducible benchmark suite
    python3 -m ais experiment <name>
    python3 -m ais trace [--scenario NAME] [--html F] [--json F] [--dot F]

Experiments: key, delegation, defender, false-positives, gradual-drift,
collusion, false-flag, race, quarantine-escape, cross-process,
learning-adversary.
"""

from __future__ import annotations

import json
import sys


def _trace(argv: list[str]) -> int:
    import argparse

    from .observatory.trace import build_trace, to_dot, to_html
    from .simulation import scenarios

    parser = argparse.ArgumentParser(prog="ais trace")
    parser.add_argument("--scenario", default="key", help="key | collusion | gradual-drift | population")
    parser.add_argument("--html", default="trace.html")
    parser.add_argument("--json", default=None)
    parser.add_argument("--dot", default=None)
    parser.add_argument("--steps", type=int, default=20)
    args = parser.parse_args(argv)

    if args.scenario == "population":
        from .simulation.ecosystem import EcosystemConfig, build_default_ecosystem

        ecosystem = build_default_ecosystem(EcosystemConfig(sentinel_interval=4))
        ecosystem.run(args.steps)
    else:
        runners = {
            "key": scenarios.run_key_experiment,
            "collusion": scenarios.run_collusion_experiment,
            "gradual-drift": scenarios.run_gradual_drift_experiment,
            "false-flag": scenarios.run_false_flag_experiment,
            "quarantine-escape": scenarios.run_quarantine_escape_suite,
            "cross-process": scenarios.run_cross_process_verification_experiment,
            "learning-adversary": scenarios.run_learning_adversary_experiment,
        }
        if args.scenario not in runners:
            print(f"unknown scenario: {args.scenario}; choose from {sorted(runners)}", file=sys.stderr)
            return 2
        ecosystem = runners[args.scenario]()["ecosystem"]

    trace = build_trace(ecosystem.plane, ecosystem.observatory, ecosystem.immune)
    with open(args.html, "w", encoding="utf-8") as handle:
        handle.write(
            to_html(
                trace,
                title={
                    "key": "Agent lifecycle trace",
                    "collusion": "Cross-agent collusion trace",
                    "gradual-drift": "Gradual drift trace",
                    "false-flag": "False-flag verification trace",
                    "quarantine-escape": "Quarantine escape trace",
                    "population": "Ecosystem trace",
                }.get(args.scenario, f"SENTINEL trace — {args.scenario}"),
                subtitle=f"scenario: {args.scenario} · {trace['counts']['decisions']} decisions · "
                f"{trace['counts']['audit_records']} audit records",
            )
        )
    written = [args.html]
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(trace, handle, indent=2, default=str)
        written.append(args.json)
    if args.dot:
        with open(args.dot, "w", encoding="utf-8") as handle:
            handle.write(to_dot(ecosystem.observatory.identity_graph))
        written.append(args.dot)
    print(json.dumps({"scenario": args.scenario, "written": written, "counts": trace["counts"]}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv[0] if argv else "demo"

    if command == "demo":
        from examples.complete_simulation import run_demo  # type: ignore

        run_demo.main(trace="--trace" in argv)
        return 0

    if command == "trace":
        return _trace(argv[1:])

    if command == "benchmark":
        from .simulation.benchmark import main as benchmark_main

        return benchmark_main(argv[1:])

    if command == "experiment":
        from .simulation import scenarios

        name = argv[1] if len(argv) > 1 else "key"
        runners = {
            "key": scenarios.run_key_experiment,
            "delegation": scenarios.run_delegation_experiment,
            "defender": scenarios.run_defender_escape_experiment,
            "false-positives": scenarios.run_false_positive_scenario,
            "gradual-drift": scenarios.run_gradual_drift_experiment,
            "collusion": scenarios.run_collusion_experiment,
            "false-flag": scenarios.run_false_flag_experiment,
            "race": scenarios.run_race_condition_experiment,
            "quarantine-escape": scenarios.run_quarantine_escape_suite,
            "cross-process": scenarios.run_cross_process_verification_experiment,
            "learning-adversary": scenarios.run_learning_adversary_experiment,
        }
        if name not in runners:
            print(f"unknown experiment: {name}; choose from {sorted(runners)}", file=sys.stderr)
            return 2
        result = runners[name]()
        printable = {k: v for k, v in result.items() if k not in {"ecosystem", "ecosystems"}}
        print(json.dumps(printable, indent=2, default=str))
        return 0

    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
