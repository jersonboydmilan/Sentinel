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
   regression.
4. **Evidence over judgement.** Detectors must emit named, reproducible signals.
   Anything the detector claims, the auditor must be able to re-derive from the
   audit chain alone.
5. **No third-party runtime dependencies.** The policy parser, hashing and test
   framework are stdlib on purpose: they are part of the security boundary.

## Tests

```bash
python3 -m unittest discover -s tests -t . -v
python3 -m ais.simulation.benchmark
```

New defensive capabilities require a matching test in
`tests/defender_security/`. New enforcement paths require a case in
`tests/adversarial/`.

## Commit conventions

One behavioural change per commit. State the invariant the change protects in
the commit message body.
