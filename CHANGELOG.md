# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [semantic](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-20

### Changed (naming)

* The project presents as **SENTINEL — Authority-Attenuating Immune
  Architecture for AI Agents**. The concept and the package keep their names:
  the Agent Immune System, importable as `ais`.

### Added

* **Learning adversary** (`adaptive/learning-adversary`): an adversary that
  observes the outcome of its own requests, never retries a refused capability,
  backs off after refusals, and falls back to acting inside its grant. Three
  arms (naive, defended, undefended) with a full comparison.
* **Cross-process verification** (`ais/verifier/`): SENTINEL-AUDIT-REMOTE runs
  as a separate OS process that receives only the serialised audit chain and
  returns an HMAC-signed verdict; fails closed on outage, rejects doctored
  chains and mismatched heads.
* **Runtime invariant checker** (`ais/control_plane/invariants.py`): P1–P8
  re-checked as state predicates after every decision; detects gateway bypass.
* **Multi-party attestation**: revocation requires two distinct verifiers.
* **Context-bound grants**: a grant scoped to a task contract is unusable
  elsewhere.
* **Cross-agent collusion analysis** and `POL-060` escalation: relationship
  risk is escalated, not contained.
* **Trace tooling**: JSON timeline, Graphviz DOT, and a single-file HTML report
  with a light, modern UI; `ActionResult.narrative()`.
* **Property-based test harness** (stdlib, reproducible seeds) for the
  authority, delegation and revocation invariants.
* Adaptive adversaries: gradual drift, split-capability collusion, compromised
  detector, decision-time races, quarantine escape suite.
* Benchmark sweeps: observation loss, defensive cycle period, population scale.
* `results.json`, `scripts/make_screenshots.py`, CI gates, and GitHub community
  files.

### Changed

* In-process and out-of-process verification now share one reconstruction
  module, so the two transports cannot drift apart.
* Confidence scoring counts amplification persistence as well as breadth.
* Defender metrics split: acting outside declared authority (a violation)
  versus a containment request held for insufficient evidence (working as
  designed).
* `HOLD` and `ESCALATE` no longer count as agent violations, so escalation
  cannot manufacture the evidence used to justify containment.
* Documentation restructured around claims, falsifiability and limitations.

### Fixed

* Defensive catch-all policy (POL-101) out-prioritising the evidence
  requirement (POL-111), which permitted quarantine without verification.
* Delegatees acting outside their declared purpose because delegation issued
  authority without an attenuated sub-contract.
* Benign long-running agents tripping per-task rate limits, because contracts
  were not episodic.

## [0.1.0] - 2026-09-20

### Added

* Initial prototype: control plane (identity, capabilities, authority,
  contracts, policy, risk, delegation, containment, revocation, emergency
  controls, hash-chained audit, execution gateway), behavioural observatory,
  immune system, five defensive agents, quarantine with deterministic replay,
  simulated ecosystem, metrics and benchmark harness, 114 tests, six documents.
