# Threat model

## 1. Assets

| Asset | Why it matters |
|---|---|
| authority records (grants, revocations, restrictions) | the ground truth of what may happen |
| task contracts | the declared purpose that drift is measured against |
| the policy set | the decision function |
| the audit chain | the only evidence base the auditor may trust |
| immune memory | future detection evidence |
| tool handlers and the data behind them | the actual effect surface |
| emergency controls | the last resort |
| defensive agent credentials | keys to the containment pipeline |

## 2. Adversaries

| # | Adversary | Capability assumed |
|---|---|---|
| A1 | Misbehaving agent | authenticated, holds some authority, repeatedly exceeds it |
| A2 | Compromised agent | authenticated, behaviour fully attacker-controlled (prompt injection, poisoned tool output, model compromise) |
| A3 | Escalating agent | probes for capability it was never granted |
| A4 | Delegating agent | tries to widen authority through delegation, including multi-hop and cycles |
| A5 | Propagating agent | spreads capability across a population via delegation |
| A6 | Impersonator | presents another principal's identifier |
| A7 | Compromised defensive agent | holds defensive capability and tries to exceed it (section 17) |
| A8 | Malicious insider tool | returns attacker-controlled output designed to steer an agent |
| A9 | Patient agent (slow drift) | stays mostly in scope, probes rarely, widens gradually over dozens of steps |
| A10 | Colluding pair | two agents, each fully within its own authority, whose *combination* completes an acquire → transfer → exfiltrate chain |
| A11 | Compromised detector | holds `agent.observe`/`agent.flag` and fabricates evidence against an innocent agent |
| A12 | Race-condition agent | submits continuously, hoping a revocation, restriction or expiry leaves a grace window |
| A13 | Partial-observability attacker | operates where telemetry is lossy, so the observatory sees only part of its behaviour |
| A14 | Coercive caller | controls the process that talks to the verifier and supplies a doctored or misdescribed audit chain, hoping for a confirmation |
| A15 | Verdict forger | mints a verification result without the verifier's key, or replays a valid verdict against a different subject or request |
| A16 | Verifier-outage attacker | disables, hangs or crashes the verifier, hoping the system degrades towards permitting containment (or towards permitting anything) |

## 3. Trust boundaries

```text
UNTRUSTED: agent reasoning, prompts, SDK usage, tool *output*, inter-agent messages,
           anything an agent asserts about itself (including claimed verification refs)

TRUSTED:   the control plane process and its services
           (identity, authority, contracts, policy, risk, delegation,
            containment, revocation, audit, emergency)
```

Everything crossing the boundary is data. The gateway's `claimed_*` facts exist
to make that explicit: a caller may *say* it holds a verification; only the
verification ledger can make that true.

## 4. In-scope threats and mitigations

| Threat | Mitigation | Test |
|---|---|---|
| unauthorized tool call | default-deny authority check before execution | adversarial 1 |
| unauthorized data access | capability + contract data scope | adversarial 2 |
| credential access | sensitivity-weighted policy, drift gate | adversarial 3 |
| policy manipulation | root-only mutation + integrity digest re-checked per request | adversarial 4 |
| contract manipulation | sealed hash verified on every check | adversarial 5 |
| capability escalation | `SelfGrantDenied`; external-only issuance | adversarial 6 |
| impersonation | per-principal HMAC credentials; mismatch classified as impersonation | adversarial 7 |
| expired authority | expiry evaluated at decision time | adversarial 8 |
| revoked authority | revocation evaluated per request, cascades to derived grants | adversarial 9 |
| delegation amplification | `requested ⊆ delegable` at gateway *and* engine | adversarial 10, delegation suite |
| multi-hop amplification | depth attenuation, chain closure, cycle detection | adversarial 11 |
| prompt injection | injection changes intent, not authority | adversarial 12 |
| tool-output injection | acting on injected content still requires authority | adversarial 13 |
| inter-agent manipulation | the persuaded agent is bound by its own authority | adversarial 14 |
| behavioural mimicry | authority is not behavioural; mimicry yields no capability | adversarial 15 |
| over-reaction (false positives) | two-party verification, graduated response, bounded memory prior | adversarial 16 |
| defensive privilege escalation | self-grant refusal, operational ban, namespace refusal | adversarial 17, defender suite |
| defender policy bypass | evidence-gated containment policies, forged refs rejected | adversarial 18, defender suite |
| quarantine escape | registry swap at the gateway, synthetic tools, recording | adversarial 19 |
| audit tampering | hash chain verification detects mutation, reorder, truncation | adversarial 20 |
| kill-switch suppression | emergency controls are out-of-band, namespace unreachable | adversarial 20b |
| slow drift (A9) | typed drift components accumulate; escalation drift requires breadth; detection latency measured, not assumed | `adaptive/gradual-drift` (6-step latency, benign agent untouched) |
| split-capability collusion (A10) | relationship analysis over the behaviour graph with capability complementarity; response is ESCALATE, not containment | `adaptive/collusion`; `CollusionTests` |
| fabricated accusation (A11) | a flag is not an action: containment policies require a subject-bound CONFIRMED verification re-derived from the audit chain | `adaptive/false-flag-detector`; `FalseFlagTests` |
| single compromised verifier | revocation requires two *distinct* verifiers (POL-110) | `MultiPartyAttestationTests` |
| decision-time races (A12) | authority is evaluated per request; restrictions, expiry and revocation take effect on the next submission | `adversarial/decision-time-authority` (`no_grace_window`) |
| partial observability (A13) | enforcement depends on authority, not observation; verification absorbs observation noise | `sweep/observation-loss`: prevention 1.00 and containment FPR 0.00 at every loss level |
| gateway bypass (in-process) | not prevented; detected by invariants P1/P8 comparing tool calls to production-routed ALLOWs | `test_gateway_bypass_is_detected`; quarantine suite row 3 |
| over-long authority lifetime | context-bound grants (`scope.task_id`) are usable only inside the issuing contract | `ContextBoundGrantTests` |
| coerced verification (A14) | the verifier process recomputes every record hash and compares the caller's claimed head to the computed head before reading any claim | `verification/cross-process`: `coerced_chain_rejected`, `head_mismatch_rejected`, `empty_chain_refused` |
| forged or replayed verdict (A15) | responses are HMAC-signed with operator key material that never passes through a gateway request; the client also binds request id and nonce | `forged_verdict_rejected`, `unauthenticated_request_refused`, `test_verdict_signed_with_another_key_is_not_accepted` |
| verifier outage (A16) | fail closed: no verdict means POL-110/111/112 stay at HOLD, and the absence is audited | `fails_closed`; `test_outage_records_unavailability_and_blocks_containment` |

## 5. Explicitly out of scope

* **Host and runtime compromise.** If an attacker can edit control-plane memory
  or code, the boundary is gone. The audit chain still makes *some* tampering
  detectable after the fact, which is the honest limit of the claim.
* **Cryptographic hardening for production.** Credentials are HMAC tokens in
  process; there is no key management, rotation, or hardware root of trust.
* **Cross-organisation federation.** Identity is single-domain.
* **Confidentiality of tool data.** AIS governs *whether* an action happens, not
  encryption of what it returns.
* **Model-level attacks.** Jailbreaks and injections are assumed to *succeed* at
  the reasoning layer; the architecture's claim is that success there does not
  translate into authority.
* **Denial of service.** An agent that floods the gateway is contained by rate
  and budget rules in the contract, but resource exhaustion is not modelled.

## 5a. Newly modelled, newly bounded

Three of the additions above change what the architecture claims rather than
merely adding a test:

1. **Relationship threats need a different response class.** Containment is the
   wrong answer when no agent exceeded its authority; `ESCALATE` stops the chain
   and leaves authority intact. This is why HOLD/ESCALATE decisions are excluded
   from the "policy violation" count - otherwise escalation would generate the
   evidence used to justify containment.
2. **The detector is an attack surface, and is treated as one.** A11 is modelled
   explicitly with a detector that fabricates evidence; the answer is structural
   (two-party verification), not a confidence threshold.
3. **Observation is not enforcement.** A13 shows the two degrade independently:
   under 90% telemetry loss detection falls to 0.83 while prevention stays at
   1.00 and containment false positives stay at 0.00.

## 6. Residual risks

1. **Detection is not the guarantee; containment is.** A sufficiently patient
   adversary staying strictly inside its granted authority produces no drift.
   The architecture's guarantee is then reduced to "it can only do what it was
   granted" — which is the point of the authority model, but it is a smaller
   claim than "it will be detected".
2. **Verification can now run out of process, and by default does not.**
   `Sentinel(..., remote_verification=True)` runs SENTINEL-AUDIT-REMOTE as a
   separate OS process that receives only the serialised chain and returns a
   signed verdict, so a compromise of the control-plane process no longer
   implies a compromised verifier. Two residual gaps remain: the default
   configuration is still in-process (the remote verifier costs ~10 ms per
   verification), and both processes run on the same host under the same user,
   so a host-level compromise still defeats the separation. A production
   deployment would run the verifier under a different user or on a different
   machine; the protocol is already the only interface.
3. **Policy is a hand-authored artefact.** A wrong policy is a wrong decision.
   The integrity digest protects against mutation, not against bad authorship.
4. **Ground-truth labels in the simulation are ours.** The measured detection
   rate describes scripted adversaries, and scripted adversaries do not adapt.
5. **Two compromised verifiers defeat multi-party attestation.** The design
   assumes at most one compromised auditor; a colluding pair of verifiers is an
   open experiment (see `evaluation.md` §6).
6. **Collusion detection is pattern-specific.** The analyser finds ordered
   two-party chains inside a window. A three-party chain, or one slower than the
   window, evades it. The response design (escalate rather than contain)
   transfers; the detector does not.
7. **The invariant checker shares the process it monitors.** It detects a
   gateway bypass, but an attacker who can execute code in the control plane can
   also disable the checker. It is a monitoring aid, not a trust anchor.
