# Agent Immune System (AIS) — codename SENTINEL

A research prototype of a **control architecture for maintaining behavioural,
authority and operational integrity across autonomous AI-agent ecosystems**.

It is not an AI that attacks other AI. It is the opposite: an architecture that
detects, verifies, contains and recovers from misbehaving agents *without*
handing the defensive agents unrestricted authority.

The research question:

> Can an autonomous AI-agent ecosystem detect and contain compromised agents
> without transferring unrestricted authority to the agents responsible for
> defence?

The prototype answers it constructively: the demo contains a drifting agent end
to end, and the mandatory defender-escape experiment shows every SENTINEL
privilege-escalation attempt denied by the same control plane SENTINEL protects.

---

## Quick start

No third-party dependencies. Python 3.11+.

```bash
python3 examples/complete_simulation/run_demo.py
```

```bash
python3 -m unittest discover -s tests -t . -v
```

```bash
python3 -m ais.simulation.benchmark
```

---

## What is modelled as a first-class security object

| Object | Where |
|---|---|
| agent identity (cryptographic + structural) | `ais/control_plane/identity.py` |
| behavioural identity | `ais/observatory/behavior.py` |
| capability / authority | `ais/control_plane/{capabilities,authority}.py` |
| declared purpose (TaskContract) | `ais/control_plane/contracts.py` |
| delegation chains | `ais/control_plane/delegation.py` |
| inter-agent relationships | `ais/observatory/graph.py` |
| authority drift | `ais/observatory/drift.py` |
| threat classification | `ais/immune_system/classification.py` |
| immune memory | `ais/immune_system/{signatures,memory}.py` |
| containment / revocation | `ais/control_plane/{containment,revocation}.py` |
| quarantine + deterministic replay | `ais/quarantine/` |
| defensive agents | `ais/defensive_agents/` |

## Architectural invariants

| # | Principle | Enforced by |
|---|---|---|
| 1 | Intelligence ≠ authority | gateway evaluates requests, never agent reasoning (`gateway.py`) |
| 2 | Authority is external | `AuthorityService.issue` raises `SelfGrantDenied` for any self-grant |
| 3 | Delegation attenuates | `DelegationEngine.evaluate`: `requested ⊆ delegable`, plus depth and cycle checks, plus attenuated sub-contracts |
| 4 | Detection ≠ offensive authority | SENTINEL-DETECT holds only `agent.observe`, `agent.flag` |
| 5 | Defenders are controlled agents | every defensive action is an `ActionRequest` through the same gateway; POL-100…POL-131 |
| 6 | Revocation overrides intent | revocation evaluated on every effective-authority computation, cascades to derived grants |
| 7 | Default deny | `POL-000-DEFAULT-DENY` when no policy matches |
| 8 | The SDK is not the boundary | tool handlers are reachable only from the gateway; engines re-check authority when called directly |

## Pipeline

```text
AGENT ECOSYSTEM → AGENT IDENTITY GRAPH → BEHAVIORAL OBSERVATORY →
AUTHORITY DRIFT ENGINE → THREAT CLASSIFIER →
{MONITOR | RESTRICT | ISOLATE} → IMMUNE MEMORY → ADAPTIVE POLICY ENGINE
```

Full description: [docs/architecture.md](docs/architecture.md).

## Repository layout

```text
agent-immune-system/
├── README.md, LICENSE, CONTRIBUTING.md
├── docs/            architecture, research thesis, threat model, authority,
│                    delegation, evaluation
├── policies/        machine-readable policy set (YAML subset)
├── ais/
│   ├── common/      deterministic clock, ids, hashing, YAML subset parser
│   ├── control_plane/  identity, capabilities, authority, contracts, policy,
│   │                   risk, delegation, containment, revocation, emergency,
│   │                   audit, tools, gateway, plane
│   ├── observatory/    telemetry, behaviour, graph, anomaly, drift
│   ├── immune_system/  classification, signatures, memory, verification, response
│   ├── defensive_agents/ detector, auditor, containment, forensics, recovery, sentinel
│   ├── quarantine/     sandbox, manager, replay
│   └── simulation/     agents, ecosystem, scenarios, metrics, benchmark
├── tests/           unit, integration, adversarial (20 cases), delegation,
│                    defender_security
└── examples/complete_simulation/run_demo.py
```

Deviation from the brief's directory sketch: hyphenated directory names
(`control-plane/`, `immune-system/`, `defensive-agents/`) are not importable
Python packages, so the equivalent underscore names are used inside `ais/`.
The module-to-section mapping is unchanged.

## Results (reproducible; see `docs/evaluation.md`)

Standard population, 20 logical steps, 10 simulated agents + 5 SENTINEL agents,
213 gateway decisions:

| metric | value |
|---|---|
| detection rate (independently verified) | 1.00 (6/6 malicious) |
| containment false-positive rate | 0.00 (0/4 benign) |
| flag false-positive rate | 0.00 |
| mean time to detection | 2.17 steps |
| unauthorized-action prevention | 18 / 18 |
| authority-amplification attempts blocked | 33 / 33 |
| defensive-agent policy violations | 0 |
| defender escape attempts that succeeded | 0 / 11 |
| section 17 escape paths blocked | 12 / 12 |
| quarantine escapes | 0 / 22 attempts |
| policy latency p50 / p95 | 1.24 / 1.55 ms |
| audit chain verification | intact |
| run-to-run audit head hash | identical (deterministic) |

These numbers describe deterministic scripted adversaries in a simulated
ecosystem. They are evidence about the *architecture's enforcement properties*,
not a claim about detection efficacy against adaptive real-world attackers; see
the limitations section of `docs/evaluation.md`.

## What this project deliberately does not contain

No autonomous hacking agents, malware, credential theft, exploit delivery,
persistence mechanisms, counterattack or network penetration. Offensive verbs
are not even representable: `Capability.parse("agent.attack_anything")` raises
`ForbiddenCapability`. The defensive namespace stops at containment and
recovery.

## License

MIT — see [LICENSE](LICENSE).
