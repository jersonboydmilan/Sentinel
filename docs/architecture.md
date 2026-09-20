# Architecture

## 1. Position

AIS is a **control architecture**, not a detector bolted onto an agent
framework. It treats agents, their relationships, their delegation chains, their
tool access, their authority and their behaviour as first-class security
objects, and it places a single enforcement boundary between agent *intent* and
agent *effect*.

```text
                ┌───────────────────┐
                │       AGENT       │
                └─────────┬─────────┘
                          │  untrusted intent
                          ▼
                ┌───────────────────┐
                │   CONTROL PLANE   │
                │  identity         │
                │  authority        │
                │  contract         │
                │  policy           │
                │  risk             │
                │  delegation       │
                └─────────┬─────────┘
                          │  authorized action
                          ▼
                ┌───────────────────┐
                │ EXECUTION GATEWAY │
                └───────────────────┘
```

Nothing above the gateway is trusted: not the system prompt, not the model's
alignment, not the agent's instructions, not the SDK. The gateway holds the only
references to tool handlers (`ais/control_plane/tools.py`), so "call the tool
directly" is not an available move for an agent.

## 2. The analysis pipeline

```text
                         AGENT ECOSYSTEM
                               │
              ┌────────────────┼────────────────┐
           Agent A          Agent B          Agent C
              └────────────────┼────────────────┘
                               ▼
                  ┌────────────────────────┐
                  │   AGENT IDENTITY GRAPH │  observatory/graph.py
                  └────────────┬───────────┘
                               ▼
                  ┌────────────────────────┐
                  │ BEHAVIORAL OBSERVATORY │  observatory/behavior.py
                  └────────────┬───────────┘
                               ▼
                  ┌────────────────────────┐
                  │ AUTHORITY DRIFT ENGINE │  observatory/drift.py
                  └────────────┬───────────┘
                               ▼
                  ┌────────────────────────┐
                  │   THREAT CLASSIFIER    │  immune_system/classification.py
                  └────────────┬───────────┘
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
             MONITOR        RESTRICT       ISOLATE      control_plane/containment.py
                └──────────────┼──────────────┘
                               ▼
                  ┌────────────────────────┐
                  │     IMMUNE MEMORY      │  immune_system/memory.py
                  └────────────┬───────────┘
                               ▼
                  ┌────────────────────────┐
                  │ ADAPTIVE POLICY ENGINE │  control_plane/policy.py + policies/
                  └────────────────────────┘
```

## 3. Request path

`ExecutionGateway.submit` runs eleven ordered steps. The order is itself a
security property: emergency controls win before authentication, authentication
wins before authority, authority wins before policy, and execution happens last.

| # | Step | Failure mode it closes |
|---|---|---|
| 1 | emergency control check | a compromised (or merely confident) system ignoring the kill switch |
| 2 | policy integrity check | in-process policy mutation |
| 3 | authentication | agent impersonation |
| 4 | namespace refusal | agents reaching policy/authority/audit/emergency surfaces |
| 5 | forbidden-capability refusal | offensive verbs entering the model at all |
| 6 | authority check | default-deny violation |
| 7 | task-contract check | acting outside declared purpose; contract tampering |
| 8 | fact assembly + risk | decisions without evidence |
| 9 | policy evaluation | ad-hoc, non-reproducible judgement |
| 10 | execution | tool access without a decision |
| 11 | telemetry + audit | unobservable actions |

Facts are contributed by read-only providers (`Observatory.fact_provider`,
`ImmuneSystem.fact_provider`). Observation therefore *informs* enforcement
without *holding* enforcement authority — Principle 4 as a wiring constraint.

Caller-supplied claims (`verification_ref`, `confidence`) are recorded as
`claimed_*` facts and are never used directly; the immune system validates them
against signed ledger records and produces `verification_valid` /
`verification_confidence`.

## 4. Control plane services (section 18 of the brief)

| Service | Module | Responsibility |
|---|---|---|
| Identity | `identity.py` | principals, credentials, impersonation detection |
| Authority | `authority.py` | grants, expiry, revocation, restrictions |
| Policy | `policy.py` | deterministic decisions over facts |
| TaskContract | `contracts.py` | declared purpose, sealing, sub-contracts |
| Behavior monitor | `observatory/` | telemetry, profiles, graphs |
| Risk | `risk.py` | explainable weighted scoring |
| Delegation | `delegation.py` | the `⊆` predicate, depth, cycles |
| Containment | `containment.py` | monitor/restrict/isolate/quarantine/revoke |
| Revocation | `revocation.py` | irreversible action with an evidence bar |
| Quarantine | `quarantine/` | sandbox, recording, deterministic replay |
| Immune memory | `immune_system/memory.py` | validated signatures |
| Audit | `audit.py` | hash-chained, searchable, replayable ledger |
| Emergency | `emergency.py` | out-of-band kill switches |

## 5. Defensive agents

```text
SENTINEL-DETECT     agent.observe, agent.flag, immune.read
SENTINEL-AUDIT      agent.observe, agent.analyze, immune.read
SENTINEL-CONTAIN    agent.restrict, agent.isolate, agent.quarantine, agent.revoke
SENTINEL-FORENSICS  agent.observe, agent.analyze, agent.replay, immune.read, immune.write
SENTINEL-RECOVERY   agent.restore
```

Each is a separate principal with a separate credential and a separate task
contract. The coordinator (`sentinel.py`) schedules the cycle but holds no
authority itself:

```text
detect → independently verify → plan → contain → (next cycle) forensics → memory
```

The separation is load-bearing. The detector cannot contain; the container
cannot observe; the auditor can neither flag nor contain; forensics cannot
restrict; recovery can only restore, and only against an external authorization
reference. A compromise of any single defensive agent yields a strict subset of
the response pipeline, never the whole of it.

## 6. Why containment decisions are two-party

`SENTINEL-DETECT` produces a classification. `SENTINEL-AUDIT` does **not** read
that classification's evidence strings; it re-derives predicates from the audit
chain (`denied_decisions`, `authority_excess`, `distinct_denied_capabilities`,
`quarantined`, `post_quarantine_attempts`) and asks whether the claimed class is
supported. Only a `CONFIRMED` verification, bound to that subject, unlocks
POL-110/111/112/124. A detector that hallucinates a threat therefore produces
nothing but an audit record.

## 7. Graduated, reversibility-ordered response

```text
MONITOR      (no authority change)        confidence ≥ 0.0
RESTRICT     (reversible suppression)     confidence ≥ 0.5
ISOLATE      (reversible, network+deleg.) confidence ≥ 0.6
QUARANTINE   (reversible, sandboxed)      confidence ≥ 0.7
REVOKE       (irreversible)               confidence ≥ 0.85 + verification
```

`ThreatClassifier._recommend` walks *down* this ladder until the confidence gate
is satisfied, so low confidence can never select an irreversible action. Policy
enforces the same gates independently, so a bug in the planner is not sufficient
to cause an irreversible action.

## 8. Quarantine

A quarantined agent is not stopped; it is re-pointed. The gateway swaps its tool
registry for a sandbox registry (synthetic datasets, fake credentials, absorbed
writes, blocked egress, in-memory filesystem) and records every call. Because
the sandbox is seeded from the environment id, the session replays byte for
byte, which is what makes a forensic signature admissible: a transcript that
does not replay deterministically yields no signature.

## 9. Audit

```text
hash_n = SHA256( canonical(record_n) || hash_{n-1} )
```

Mutation, reordering and truncation are all detectable
(`tests/unit/test_policy_and_audit.py`, `tests/adversarial` case 20). Records are
searchable by actor, subject, task and type, and `replay()` yields decision
bodies for forensic reconstruction.

## 10. Emergency controls

`GLOBAL_STOP`, `AGENT_REVOKE`, `CAPABILITY_REVOKE`, `DELEGATION_FREEZE`,
`NETWORK_ISOLATE`, `QUARANTINE_ALL` are **not capabilities**. There is no grant
that reaches them and no policy that enables them; they are operated by a holder
of an out-of-band key, and the gateway may only *read* their state. The
`emergency.*` namespace is refused at gateway step 4, so no agent — defensive or
otherwise — can address them at all.
