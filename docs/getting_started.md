# Getting started

Python 3.11+, no dependencies, no network access.

```bash
git clone <repo> && cd agent-immune-system
python3 -m ais demo              # the full demonstration, narrated
python3 -m ais demo --trace      # plus per-decision explanations
```

## 1. Run the demonstration

`python3 -m ais demo` walks through five things in order:

1. one agent's full lifecycle (normal → drift → detection → verification →
   containment → forensic replay → revocation → immune signature → a second
   agent matching that signature);
2. adaptive adversaries: slow drift, split-capability collusion, a compromised
   detector;
3. the delegation experiment (authority cannot amplify);
4. recursive governance: SENTINEL attacking the control plane, the quarantine
   escape suite, and decision-time authority;
5. the false-positive control.

With `--trace` it also prints per-decision narratives:

```text
[ 10] COMPROMISED-01 was DENY for credential.read on credential_vault
      because it does not hold that capability (policy POL-002-…)
```

## 2. Read the numbers

```bash
python3 -m ais benchmark --out results.json
```

Exits non-zero if any hard check fails (reproducibility, invariants, delegation,
defender escape, quarantine escape, decision-time authority, false-flag
containment, false-positive containment). `results.json` carries every metric,
the audit head hash and a `hard_checks` block.

## 3. Look at a run

```bash
python3 -m ais trace --scenario key --html trace.html --json trace.json --dot graph.dot
open trace.html
```

The HTML report is one self-contained file: decision timeline (agent, action,
decision, policy, risk, evidence), the authority timeline, containment events,
drift per agent, and any collusion chains. `graph.dot` renders with
`dot -Tsvg graph.dot -o graph.svg` if Graphviz is installed.

## 4. Add a policy

Policies live in [`policies/`](../policies) as a strict YAML subset
(block mappings and sequences, flow lists/maps, comments — no anchors, no block
scalars; unsupported syntax raises rather than guessing).

```yaml
  - id: POL-200-EXAMPLE
    description: Example - writes to the customer dataset require a fresh contract.
    priority: 55                    # evaluation order is (-priority, id)
    match:                          # request shape
      action: "database.write"
    when:                           # fact gate: does this policy govern the request at all?
      - fact: dataset
        equals: customer_db
    conditions:                     # decide effect vs otherwise
      - fact: capability_held
        equals: true
      - fact: contract_in_scope
        equals: true
      - fact: risk_score
        lt: 0.6
    effect: ALLOW
    otherwise: DENY
```

Available facts are whatever the gateway and the fact providers put in the fact
dictionary: `capability_held`, `contract_in_scope`, `risk_score`, `drift_score`,
`anomaly_score`, `immune_match_score`, `verification_valid`,
`verification_count`, `collusion_score`, `sandboxed`, `quarantined`,
`endpoint_expected`, `delegation_within_authority`, and the request's own
`action`, `tool`, `dataset`, `endpoint`, `subject_kind`. Operators: `equals`,
`not_equals`, `lt`, `lte`, `gt`, `gte`, `in`, `not_in`, `contains`,
`not_contains`, `subset_of`, `matches`.

Two rules worth internalising:

* a **missing fact fails closed** — the condition is false, never skipped;
* **priority matters**: a broad catch-all above a specific evidence requirement
  silently removes that requirement. This has bitten this project once already
  (POL-101 above POL-111 permitted quarantine without verification); the
  defensive policy file carries a comment saying so.

Check your work:

```bash
python3 -c "from ais.control_plane.plane import ControlPlane; cp=ControlPlane(); print(len(cp.policy.policies), cp.policy.digest[:12])"
python3 -m unittest discover -s tests -t .
```

## 5. Write an adversarial scenario

A simulated agent is a deterministic script. Intent is all it produces;
authority is decided elsewhere.

```python
# ais/simulation/agents.py
class MyAdversary(ScriptedAgent):
    SPEC = AgentSpec(
        name="MY-ADVERSARY-01",
        purpose="what it was commissioned to do",
        capabilities=("web.search",),          # what it is granted
        allowed_tools=("web_search",),         # its contract scope
        malicious=True,                        # ground truth, never read by the system
    )

    def script(self, step: int) -> list[Intent]:
        if step < 5:
            return [Intent("web.search", tool="web_search", payload={"query": f"q{step}"})]
        return [Intent("credential.read", tool="credential_vault", payload={"name": "prod"})]
```

Then a scenario that runs it and returns structured evidence:

```python
# ais/simulation/scenarios.py
def run_my_experiment(steps: int = 20) -> dict:
    ecosystem = Ecosystem(EcosystemConfig(sentinel_interval=4))
    ecosystem.add_agent(Normal01())
    ecosystem.add_agent(MyAdversary())
    ecosystem.run(steps)
    return {
        "ecosystem": ecosystem,
        "containment": [e.action.value for e in ecosystem.plane.containment.history("MY-ADVERSARY-01")],
        "metrics": ecosystem.metrics.report(),
    }
```

Add a test asserting what *must* hold (not what happened to happen), register it
in `ais/simulation/benchmark.py` if it should be measured on every run, and add
it to the CLI map in `ais/__main__.py` so `python3 -m ais experiment <name>`
works.

## 6. Interpret the audit chain

Every consequential event is a hash-chained record:

```python
from ais.simulation.ecosystem import build_default_ecosystem
eco = build_default_ecosystem(); eco.run(12)

eco.plane.audit.verify()                         # IntegrityReport(valid=True, ...)
eco.plane.audit.search(actor_id="COMPROMISED-01", event_type="gateway.decision")
eco.plane.audit.correlate("TC-000004")           # one task, causal order
list(eco.plane.audit.replay())                   # decision bodies for forensics
```

Useful event types: `gateway.decision`, `authority.granted`,
`authority.revoked`, `authority.restricted`, `delegation.allowed`,
`delegation.denied`, `contract.created`, `contract.derived`,
`quarantine.admitted`, `verification.recorded`, `containment.*`,
`immune.signature_created`, `invariant.violation`.

A decision record answers "who asked for what, what was decided, under which
policy, with what risk and which evidence". If you need it in prose,
`ActionResult.narrative()` renders one sentence, and the HTML trace renders the
whole run.

## 7. Check the invariants yourself

```python
from ais.control_plane.invariants import InvariantChecker
checker = InvariantChecker(eco.plane).bind()     # runs after every decision
eco.run(10)
print(checker.summary())                          # {'ok': True, 'violations': [], ...}
```

`InvariantChecker(plane, strict=True)` raises on the first violation, which is
what you want inside a test.

## 8. Where to look next

| Question | Document |
|---|---|
| how the pieces fit | [architecture.md](architecture.md) |
| why this is a research contribution | [research-thesis.md](research-thesis.md) |
| what it defends against, and what it does not | [threat-model.md](threat-model.md) |
| how authority is modelled | [authority-model.md](authority-model.md) |
| the delegation predicate | [delegation-model.md](delegation-model.md) |
| the numbers, their limits, and how to falsify the claim | [evaluation.md](evaluation.md) |
| claim → code → test | [claims-map.md](claims-map.md) |
