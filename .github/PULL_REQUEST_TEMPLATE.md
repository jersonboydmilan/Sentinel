## What this changes

<!-- One paragraph. What behaviour is different after this PR? -->

## Which invariant it protects

<!--
Required for anything touching authority, delegation, containment,
verification or policy. Name the principle (P1-P8) or the design position
(two-party verification, bounded memory prior, escalate-don't-contain) and the
test that would fail if the change regressed it.
-->

- Invariant:
- Test:

## Evidence

<!-- Paste the relevant output. Numbers beat adjectives. -->

```text
python3 -m unittest discover -s tests -t .
python3 -m ais benchmark --no-sweeps
```

## Checklist

- [ ] `python3 -m unittest discover -s tests -t .` passes
- [ ] `python3 -m ais benchmark` reports `"pass": true`
- [ ] The run is still deterministic (`benchmarks[0].reproducible == true`)
- [ ] No third-party runtime dependency was added
- [ ] New enforcement paths have an adversarial test; new defensive capability has a `tests/defender_security/` test
- [ ] Docs updated where the change alters a claim, a metric or a limitation
- [ ] `results.json` regenerated if the numbers moved (`python3 -m ais benchmark --out results.json`)

## Scope

- [ ] This change is defensive: it does not add attack tooling, offensive capability, or any way for a defensive agent to exceed containment and recovery
