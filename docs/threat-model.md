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

## 6. Residual risks

1. **Detection is not the guarantee; containment is.** A sufficiently patient
   adversary staying strictly inside its granted authority produces no drift.
   The architecture's guarantee is then reduced to "it can only do what it was
   granted" — which is the point of the authority model, but it is a smaller
   claim than "it will be detected".
2. **Verification shares an implementation with detection.** SENTINEL-AUDIT
   re-derives evidence from the audit chain, but runs in the same process. A
   process-level compromise defeats the two-party property; a production
   deployment should run it as a separate service with its own credentials.
3. **Policy is a hand-authored artefact.** A wrong policy is a wrong decision.
   The integrity digest protects against mutation, not against bad authorship.
4. **Ground-truth labels in the simulation are ours.** The measured detection
   rate describes scripted adversaries, and scripted adversaries do not adapt.
