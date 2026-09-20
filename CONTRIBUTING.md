# Contributing

This is a defensive research prototype. Contributions are welcome under the
scope rules below.

## Scope

**In scope:** detection, verification, containment, recovery, governance,
evaluation methodology, adversarial *tests*, simulation agents, documentation.

**Out of scope, and will be rejected:** autonomous attack tooling, malware,
credential theft, exploit delivery, persistence mechanisms, detection evasion
for offensive use, destructive counterattack, or any capability that lets a
defensive agent act beyond containment and recovery. The forbidden capability
set in `ais/control_plane/capabilities.py` is a hard boundary, not a default.

## Engineering rules

1. **No new authority without an invariant.** Any new capability must state
   which of the eight principles constrains it, and add a test proving it.
2. **The control plane is the boundary.** New tools must be reachable only
   through `ExecutionGateway`. A component that can act without a gateway
   decision is a bug.
3. **Determinism.** No wall-clock reads, no unseeded randomness on any path
   that affects a decision. `LogicalClock` and `seeded_rng` exist for this.
   A change that makes `benchmark_population(...).reproducible` false is a
   regression, and the benchmark exits non-zero when it happens.
4. **Evidence over judgement.** Detectors must emit named, reproducible signals.
   Anything the detector claims, the auditor must be able to re-derive from the
   audit chain alone.
5. **No third-party runtime dependencies.** The policy parser, hashing, the
   property-test harness and the test framework are stdlib on purpose: they are
   part of the security boundary. Developer tooling (ruff, black) is configured
   in `pyproject.toml` for those who have it, and is never required to run the
   project.
6. **Honest reporting.** If an experiment shows the defence losing - as the
   learning adversary does - the result gets written down as it is. Several
   design decisions here exist because an earlier claim did not survive its own
   test.

## Working on it

```bash
make test                       # 180 tests: unit, integration, adversarial, delegation, defender, property
make bench                      # every benchmark, writes results.json, non-zero exit if a gate fails
make demo TRACE=1               # narrated run with per-decision explanations
make trace SCENARIO=collusion   # single-file HTML report for review
make invariants                 # P1-P8 over a standard population run
make screenshots                # regenerate docs/assets from real runs
```

New defensive capabilities require a matching test in
`tests/defender_security/`. New enforcement paths require a case in
`tests/adversarial/`. Anything that touches authority, delegation, containment,
verification or policy must name the invariant it protects in the pull request
(the template asks for it).

## Issues

Three templates, and they are not interchangeable:

* **Bug report** - something behaves differently from the code or docs.
* **Broken invariant / falsification** - you have evidence that one of the
  architecture's claims does not hold. This is the most valuable issue you can
  open; the claims and their tests are in
  [docs/claims-map.md](docs/claims-map.md) and
  [docs/evaluation.md §6](docs/evaluation.md).
* **Experiment proposal** - an adversary, scenario or measurement. State the
  falsifying outcome up front.

## Documentation expectations

A change that alters a claim, a metric or a limitation updates the docs in the
same pull request. `docs/claims-map.md` must keep pointing at real code and real
tests; `docs/evaluation.md` must keep stating what the numbers do *not* show.

## Credit

Contributors are listed in [CONTRIBUTORS.md](CONTRIBUTORS.md) by role. Add
yourself in the same pull request as your work. Commit with an email registered
on your GitHub account (or your `@users.noreply.github.com` address) so the work
is attributed to you.

## Commit conventions

One behavioural change per commit. State the invariant the change protects in
the commit message body.
