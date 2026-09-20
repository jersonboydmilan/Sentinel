<div align="center">

# Agent Immune System · **SENTINEL**

**A control architecture for behavioural, authority and operational integrity across autonomous AI-agent ecosystems.**

[![CI](https://github.com/jersonboydmilan/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/jersonboydmilan/sentinel/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776ab?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Dependencies: none](https://img.shields.io/badge/dependencies-none-2ea44f)](pyproject.toml)
[![Tests: 180](https://img.shields.io/badge/tests-180-2ea44f)](tests)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Status: research prototype](https://img.shields.io/badge/status-research%20prototype-8957e5)](docs/research-thesis.md)

</div>

> **The research question**
> Can an autonomous AI-agent ecosystem detect and contain compromised agents
> **without transferring unrestricted authority to the agents responsible for defence?**

This is not an AI that attacks other AI. It is the opposite: an architecture
where detection, verification, containment and recovery are separate, bounded
powers — and where the defensive system is governed by the same control plane it
protects.

```bash
git clone https://github.com/jersonboydmilan/sentinel && cd sentinel
python3 -m ais demo --trace      # no dependencies, no network, nothing to install
```

<div align="center">
  <img src="docs/assets/trace-report.png" alt="SENTINEL trace report: containment timeline and authority drift per agent" width="880">
  <br>
  <sub><code>python3 -m ais trace --scenario key --html trace.html</code> — every decision, the policy that made it, and the evidence behind it</sub>
</div>

---

## Contents

- [What it does](#what-it-does)
- [Results](#results)
- [How it works](#how-it-works)
- [The eight invariants](#the-eight-invariants)
- [Adversaries](#adversaries)
- [Commands](#commands)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)
- [What this deliberately is not](#what-this-deliberately-is-not)

---

## What it does

Conventional security protects users, devices, applications and networks. An
agent ecosystem adds objects none of those describe: an agent's **purpose**, its
**authority**, its **behaviour over time**, its **delegation chains**, and its
**relationships with other agents**. SENTINEL treats all of them as first-class
security objects, and puts a single enforcement boundary between agent *intent*
and agent *effect*.

<div align="center">
  <img src="docs/assets/demo-output.png" alt="Demonstration output: an agent drifts, is detected, independently verified, contained and revoked" width="860">
  <br>
  <sub><code>python3 -m ais demo</code> — an agent drifts, is detected, independently verified, contained, replayed and revoked</sub>
</div>

## Results

Standard population, 20 logical steps, 10 simulated agents + 6 SENTINEL agents,
213 gateway decisions, 368 invariant checks — all reproducible with
`python3 -m ais benchmark --out results.json`:

| Metric | Value |
|---|---|
| detection rate (independently verified) | **1.00** (6/6 malicious) |
| containment false-positive rate | **0.00** (0/4 benign) |
| mean time to detection | 2.17 steps |
| unauthorized-action prevention | **18 / 18** |
| authority-amplification attempts blocked | **33 / 33** |
| defensive-agent policy violations | **0** |
| defender escape attempts that succeeded | **0 / 11** |
| section 17 escape paths blocked | **12 / 12** |
| quarantine escapes | **0 / 22 attempts** |
| invariant violations (P1–P8) | **0** |
| policy latency p50 / p95 | 1.33 / 1.61 ms |
| run-to-run audit head hash | identical (deterministic) |

### The result that matters most

<div align="center">
  <img src="docs/assets/learning-adversary.png" alt="Learning adversary comparison: adaptation buys detection latency, not authority" width="720">
</div>

An adversary that **learns from refusals** — never retrying a denied capability,
backing off, diluting its denial ratio — buys **7 steps of detection latency**
and **no authority at all**. Given a long horizon it converges to acting
*inside* its grant, where relationship analysis and escalation take over from
containment. Detection degrades against adaptation; the authority model does
not. That is the designed floor, and [§4.3a of the evaluation](docs/evaluation.md)
is the experiment that tests it rather than asserting it.

## How it works

```text
            AGENT INTENT (untrusted)
                     │
                     ▼
        ┌────────────────────────────┐
        │       CONTROL PLANE        │  emergency controls (out-of-band key)
        │ identity · authority       │  ──▶ state read only
        │ contract · policy · risk   │
        │ delegation · containment   │
        └─────────────┬──────────────┘
                      │ authorized action
                      ▼
            EXECUTION GATEWAY ──▶ production tools | quarantine sandbox
                      │
                      ▼
          hash-chained audit ──▶ observatory ──▶ drift · anomaly · collusion
                      │                                │
                      │                                ▼
                      │                      SENTINEL-DETECT (observe, flag)
                      │                                │
                      └──▶ SENTINEL-AUDIT ×2 + AUDIT-REMOTE (separate process)
                                       │ CONFIRMED verification
                                       ▼
                        SENTINEL-CONTAIN → QUARANTINE → FORENSICS → immune memory
```

Eleven ordered checks run on every request — emergency controls, policy
integrity, authentication, namespace refusal, forbidden-capability refusal,
authority, task contract, facts and risk, policy, execution, audit. The gateway
holds the only reference to the tool handlers, so "call the tool directly" is
not a move an agent has.

## The eight invariants

| # | Principle | Enforced by |
|---|---|---|
| 1 | Intelligence ≠ authority | requests are data; only the gateway holds tool handlers |
| 2 | Authority is external | `SelfGrantDenied` on every self-grant, for every principal |
| 3 | Delegation attenuates | `requested ⊆ delegable`, depth decrement, cycle detection, attenuated sub-contracts |
| 4 | Detection ≠ offensive authority | the detector holds `agent.observe` and `agent.flag`, nothing else |
| 5 | Defenders are controlled agents | every defensive action is a gateway decision; verification can run in a separate process |
| 6 | Revocation overrides intent | evaluated per decision, cascades to derived grants, no grace window |
| 7 | Default deny | `POL-000-DEFAULT-DENY`; a missing fact fails closed |
| 8 | The SDK is not the boundary | engines re-check authority; bypasses are detected by the invariant checker |

All eight are re-checked as **state predicates after every decision** by
`InvariantChecker`, so a violation anywhere is detected and audited rather than
inferred from a passing test.

## Adversaries

| Adversary | Outcome |
|---|---|
| unauthorized tool, data and credential access | denied before execution; 20-case adversarial suite |
| delegation amplification, multi-hop, cycles | 33/33 blocked; authority cannot grow by being passed on |
| prompt injection & tool-output injection | intent changes, authority does not |
| gradual drift over 48 steps | verified detection 6 steps after the first probe; benign agent untouched |
| split-capability collusion | 0 denials per agent — the *relationship* is escalated, no agent loses authority |
| compromised detector fabricating evidence | both auditors INCONCLUSIVE, zero containment, victim authority unchanged |
| **learning adversary** | +7 steps of latency, zero authority, converges to acting inside its grant |
| decision-time races | restriction, expiry and revocation all bite on the next submission |
| SENTINEL attacking the control plane | 12/12 escape paths denied |
| coercing the out-of-process verifier | doctored chain and false head **REJECTED**; outage fails closed |
| 90% telemetry loss | detection 0.83, prevention **1.00**, containment false positives **0.00** |

## Commands

```bash
make demo TRACE=1                     # narrated walkthrough, per-decision explanations
make test                             # 180 tests (unit, integration, adversarial, property, defender)
make bench                            # every benchmark → results.json, non-zero exit if a gate fails
make trace SCENARIO=collusion         # single-file HTML report
make experiment NAME=learning-adversary
make invariants                       # P1–P8 over a standard population run
make screenshots                      # regenerate docs/assets from real runs
```

Everything is deterministic: logical clock, counter identifiers, seeded sandbox
RNG. Two identical runs produce the same audit chain head hash, and the
benchmark refuses to report numbers if they do not.

## Repository layout

```text
ais/
├── common/            deterministic clock, ids, hashing, YAML-subset parser
├── control_plane/     identity, capabilities, authority, contracts, policy, risk,
│                      delegation, containment, revocation, emergency, audit,
│                      tools, gateway, invariants, plane
├── observatory/       telemetry, behaviour, graphs, anomaly, drift, collusion, trace
├── immune_system/     classification, signatures, memory, verification, response
├── defensive_agents/  detector, auditor ×2, remote auditor, containment, forensics, recovery
├── quarantine/        sandbox, manager, deterministic replay
├── verifier/          out-of-process verification: protocol, service, client, reconstruction
└── simulation/        agents, ecosystem, scenarios, metrics, benchmark
docs/                  architecture, thesis, threat model, authority, delegation,
                       evaluation, claims map, getting started, assets
policies/              machine-readable policy set (24 policies, YAML subset)
tests/                 unit · integration · adversarial · delegation · defender_security · property
results.json           committed benchmark output (metrics + audit head hash)
```

Hyphenated directory names from the research brief (`control-plane/`) are not
importable Python packages, so the equivalent underscore names are used inside
`ais/`. The section-to-module mapping is unchanged.

## Documentation

| Document | Contents |
|---|---|
| [getting_started.md](docs/getting_started.md) | run it, add a policy, write a scenario, read the audit chain |
| [architecture.md](docs/architecture.md) | data flow, request path, services, defensive agents, invariants, tracing |
| [research-thesis.md](docs/research-thesis.md) | problem, thesis, five contributions, invariant → metric map |
| [threat-model.md](docs/threat-model.md) | 17 adversaries, mitigations, what is out of scope, residual risks |
| [authority-model.md](docs/authority-model.md) | capabilities, grants, the four authority views, policy evaluation |
| [delegation-model.md](docs/delegation-model.md) | the `⊆` predicate, attenuation, sub-contracts |
| [evaluation.md](docs/evaluation.md) | methodology, results, sweeps, ablations, **16 falsifying experiments**, limitations |
| [claims-map.md](docs/claims-map.md) | every claim → mechanism → code → test → metric |

Start with [claims-map.md](docs/claims-map.md) if you want to check the work
rather than read about it.

## What this deliberately is not

No autonomous hacking agents, malware, credential theft, exploit delivery,
persistence, counterattack or network penetration. Offensive verbs are not even
representable: `Capability.parse("agent.attack_anything")` raises
`ForbiddenCapability`. The defensive namespace stops at containment and
recovery, and [CONTRIBUTING.md](CONTRIBUTING.md) treats that as a hard boundary.

The numbers above describe deterministic adversaries in a closed-world
simulation. They are evidence about an architecture's **enforcement
properties**, not a claim about detection efficacy against real-world attackers
— that distinction, and the assumptions behind it, are stated in
[evaluation §0](docs/evaluation.md).

## Contributing & security

[CONTRIBUTING.md](CONTRIBUTING.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) ·
[SECURITY.md](SECURITY.md) · [CHANGELOG.md](CHANGELOG.md) ·
[CONTRIBUTORS.md](CONTRIBUTORS.md)

Maintained by [@jersonboydmilan](https://github.com/jersonboydmilan).

The most valuable contribution is a **failing test**: the claims and the
experiment that would falsify each one are listed in
[evaluation §6](docs/evaluation.md).

## License

MIT — see [LICENSE](LICENSE). If you use the prototype or its results, see
[CITATION.cff](CITATION.cff).
