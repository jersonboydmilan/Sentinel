"""Command line entry point.

    python3 -m ais demo        run the full demonstration (section 29)
    python3 -m ais benchmark   run the reproducible benchmark suite
    python3 -m ais experiment <key|delegation|defender|false-positives>
"""

from __future__ import annotations

import json
import sys


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv[0] if argv else "demo"

    if command == "demo":
        from examples.complete_simulation import run_demo  # type: ignore

        run_demo.main()
        return 0

    if command == "benchmark":
        from .simulation.benchmark import run_all

        print(json.dumps(run_all(), indent=2))
        return 0

    if command == "experiment":
        from .simulation import scenarios

        name = argv[1] if len(argv) > 1 else "key"
        runners = {
            "key": scenarios.run_key_experiment,
            "delegation": scenarios.run_delegation_experiment,
            "defender": scenarios.run_defender_escape_experiment,
            "false-positives": scenarios.run_false_positive_scenario,
        }
        if name not in runners:
            print(f"unknown experiment: {name}; choose from {sorted(runners)}", file=sys.stderr)
            return 2
        result = runners[name]()
        printable = {k: v for k, v in result.items() if k != "ecosystem"}
        print(json.dumps(printable, indent=2, default=str))
        return 0

    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
