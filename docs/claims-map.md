# Claims map: research claim → mechanism → code → test → metric

One page. Every row is a claim the project makes, the mechanism that makes it
true, where that mechanism lives, the test that would fail if it stopped being
true, and the number that reports it.

## A. The central claim

> An autonomous agent ecosystem can detect and contain compromised agents
> without transferring unrestricted authority to the agents responsible for
> defence.

| Half of the claim | Evidence |
|---|---|
| *can detect and contain* | `population/20-steps`: detection 1.00 (6/6 verified), containment 1.00, mean TTD 2.17 steps; `adaptive/gradual-drift`: 6-step latency against deliberately slow drift |
| *without transferring unrestricted authority* | `defender-security/section-17`: 12/12 escape paths denied; 0 defensive-agent policy violations; 0/11 defender escape attempts succeeded; property test "defensive agents stay in their namespace" |

## B. Architectural invariants

| # | Invariant | Mechanism | Code | Test | Metric |
|---|---|---|---|---|---|
| P1 | Intelligence ≠ authority | intent arrives as an `ActionRequest`; tool handlers are held only by the gateway | [gateway.py](../ais/control_plane/gateway.py), [tools.py](../ais/control_plane/tools.py) | `test_invariants.py::test_gateway_bypass_is_detected`; adversarial 1, 12, 13 | `invariants.ok`; prevention rate |
| P2 | Authority is external | `issue()` raises `SelfGrantDenied` when issuer == subject, for every principal | [authority.py](../ais/control_plane/authority.py) | property `P2`; `test_defender_escape.py::…cannot_grant_itself…` | defender escapes = 0 |
| P3 | Delegation attenuates | `requested ⊆ delegable`, depth decrement, cycle check, attenuated sub-contract | [delegation.py](../ais/control_plane/delegation.py), [contracts.py](../ais/control_plane/contracts.py) | properties `P3-delegation`, `P3-chain`; `tests/delegation/` | amplification blocked 33/33 |
| P4 | Detection ≠ offensive authority | detector holds `agent.observe`, `agent.flag` only; no offensive verb is representable | [detector.py](../ais/defensive_agents/detector.py), [capabilities.py](../ais/control_plane/capabilities.py) | `test_detector_cannot_contain`; `test_capabilities.py` | defensive violations = 0 |
| P5 | Defenders are controlled agents | every defensive action is a gateway decision; POL-100…POL-131 | [base.py](../ais/defensive_agents/base.py), [policies/10-defensive.yaml](../policies/10-defensive.yaml) | `tests/defender_security/` (21 tests) | section 17: 12/12 |
| P6 | Revocation overrides intent | evaluated per decision; cascades to derived grants; no caching | [authority.py](../ais/control_plane/authority.py) | property `P6`; `adversarial/decision-time-authority` | `no_grace_window: true` |
| P7 | Default deny | `POL-000-DEFAULT-DENY`; a missing fact fails closed | [policy.py](../ais/control_plane/policy.py) | property `P7`; `test_policy_and_audit.py` | prevention 18/18 |
| P8 | SDK is not the boundary | engines re-check authority when called directly; invariant compares tool calls to production-routed ALLOWs | [invariants.py](../ais/control_plane/invariants.py) | `test_gateway_bypass_is_detected`; delegation `direct_engine_call` | `invariants.ok` |

## C. Research contributions

| Contribution | Concrete mechanism | Code | Test | Result it produces |
|---|---|---|---|---|
| **A. Behavioural agent identity** | declared profile + learned baseline; sequences, rates, endpoints, denial patterns | [behavior.py](../ais/observatory/behavior.py) | `test_observatory_and_immune.py` | mimicry yields no authority (adversarial 15) |
| **B. Authority drift** | typed components (capability, purpose, behavioural, delegation, communication, credential, escalation), noisy-OR | [drift.py](../ais/observatory/drift.py) | `ObservatoryTests`, gradual-drift experiment | drift 1.0 across 7 components for AGENT-A; 6-step latency for slow drift |
| **C. Immune memory** | ordered signatures, verification-gated writes, prior bounded at ±0.15, negative score for false positives | [memory.py](../ais/immune_system/memory.py) | `ImmuneMemoryTests`, key experiment | AGENT-B matched 0.99, still not contained until own evidence |
| **D. Defensive authority** | separate namespace, partitioned across 6 agents, offensive verbs unrepresentable | [capabilities.py](../ais/control_plane/capabilities.py), [defensive_agents/](../ais/defensive_agents/) | `tests/defender_security/` | 0 defensive violations across every workload |
| **E. Recursive governance** | defenders governed by the same gateway; two-party attestation for revocation; out-of-process verification; invariant checker over live state | [sentinel.py](../ais/defensive_agents/sentinel.py), [verifier/](../ais/verifier/), [invariants.py](../ais/control_plane/invariants.py) | section 17 experiment, `MultiPartyAttestationTests`, `test_cross_process_verification.py` | 12/12 escape paths denied; single verifier → HOLD; 10/10 cross-process checks |

## D. Design decisions that are themselves claims

| Decision | Claim | Evidence |
|---|---|---|
| Two-party verification (detector ≠ auditor) | accusation must not equal action | false-flag experiment: fabricated flag → INCONCLUSIVE → zero containment; observation-loss sweep: flag FPR 0.50 at 25% loss while containment FPR stays 0.00 |
| Multi-party attestation for revocation | one compromised verifier must not destroy authority | `MultiPartyAttestationTests`: single verifier → HOLD; one verifier repeating itself is still one opinion |
| Cross-process verification | the verifier should *receive* the chain, not share memory with what it audits | `verification/cross-process`: 10/10 checks - agreement across processes, doctored chain and false head REJECTED, forged verdict rejected, outage fails closed |
| Escalate, do not contain, on relationship risk | an agent that stayed inside its grant should not lose authority | collusion experiment: 0 denials per agent, chain stopped by `ESCALATE`, no containment, authority intact |
| Graduated, reversibility-ordered response | irreversible actions need the highest evidence bar | `ACTION_CONFIDENCE_GATES`; POL-110 (two verifiers, ≥0.85) |
| Context-bound grants | authority should be scoped to the task it was issued for | `ContextBoundGrantTests` |
| Deterministic detectors, no model judgement | every claim must be reproducible by an independent verifier | auditor re-derives predicates from the audit chain only |
| Emergency controls outside the capability system | the kill switch must not be a permission | section 17 `emergency_disable`; `POL-OUT-OF-BAND` |

## E. Where the claims stop

| Not claimed | Why | Where stated |
|---|---|---|
| detection efficacy against adaptive attackers | adversaries are scripts | [evaluation §0, §7](evaluation.md) |
| resistance to in-process code execution | the control plane's own process is the trust boundary | [threat-model §5](threat-model.md), quarantine suite row 3 |
| host-level independence of verification | the split is across processes on one host, under one user | [evaluation §1.3, §4.4a](evaluation.md) |
| policy correctness | integrity ≠ correctness | [evaluation §7](evaluation.md) |
| defence against the human root or key holder | trusted by construction | [threat-model §5](threat-model.md) |
