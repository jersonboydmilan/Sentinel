# Research thesis

## Problem

Conventional security protects users, devices, applications, networks and
identities. An ecosystem of autonomous agents introduces objects that none of
those categories describe: an agent's *purpose*, its *authority*, its
*behaviour over time*, its *delegation chains*, and its *relationships with
other agents*. An agent that is fully authenticated, running approved code, on
an approved host, inside the network perimeter, can still be the incident —
because the thing that changed is what it decided to do with the authority it
already had.

Two failure modes follow, and neither is addressed by inspecting model outputs:

1. **Authority drift.** The gap between the purpose an agent was commissioned
   for and the behaviour it actually exhibits widens gradually. No single action
   is conclusive; the trajectory is.
2. **Defender escalation.** The natural response — give the defensive system
   enough authority to stop anything — reproduces the original problem one level
   up. A defensive agent with unrestricted authority is the most valuable target
   in the ecosystem.

## Central question

> Can an autonomous AI-agent ecosystem detect and contain compromised agents
> without transferring unrestricted authority to the agents responsible for
> defence?

## Thesis

Yes, if three separations are made structural rather than procedural:

1. **Reasoning is separated from authorization.** An agent may conclude that an
   action is correct; whether it executes is decided elsewhere, by a component
   the agent cannot address (Principles 1, 2, 8).
2. **Detection is separated from containment, and containment from
   verification.** The component that notices, the component that confirms and
   the component that acts are different principals with disjoint capability
   sets, and the confirming component re-derives evidence from a tamper-evident
   ledger rather than trusting the noticing component (Principles 4, 5).
3. **Authority can only attenuate.** Delegation is a subset operation with depth
   and cycle constraints, and the same constraint applies to the declared purpose
   via attenuated sub-contracts (Principle 3).

## One page: invariant → question → metric

Each architectural invariant answers a specific part of the research question
and is reported by a specific number. Full code/test mapping:
[claims-map.md](claims-map.md).

| Invariant | Part of the question it answers | Reported by |
|---|---|---|
| P1 intelligence ≠ authority | can an agent's *conclusion* become an effect? | prevention rate 18/18; P1 invariant clean over 368 checks |
| P2 authority is external | can any agent widen itself? | `SelfGrantDenied` on every self-grant; defender escapes 0/11 |
| P3 delegation attenuates | can authority grow by being passed around? | amplification blocked 33/33; chain properties `P3-*` |
| P4 detection ≠ offensive authority | does noticing a threat license acting on it? | detector cannot contain (4 denials per attempt); defensive violations 0 |
| P5 defenders are controlled agents | *the* question - is defence itself bounded? | section 17: 12/12 escape paths denied |
| P6 revocation overrides intent | can authority outlive its withdrawal? | `no_grace_window: true` at restriction, expiry and revocation |
| P7 default deny | is anything implicitly permitted? | `POL-000-DEFAULT-DENY`; property `P7` |
| P8 SDK is not the boundary | does convenience tooling become the control? | direct engine call blocked; in-process bypass detected by P1/P8 |

Two further claims are not invariants but design positions, each with its own
number:

| Position | Number |
|---|---|
| accusation must not equal action (two-party verification) | fabricated flag → 0 containment; flag FPR 0.50 at 25% observation loss while containment FPR stays 0.00 |
| relationship risk is answered by escalation, not containment | collusion experiment: 0 denials per agent, chain stopped, authority intact |

## Five proposed concepts

### A. Behavioural agent identity

Identity is credentials **plus** an observable behavioural profile: capability
mix, ordered call sequences, data and endpoint sets, rates, error and denial
patterns, delegation shape. Two profiles are kept per agent — the operator's
*declared* profile and the agent's *learned* baseline — because an attacker who
mimics one still diverges from the other.

*Implementation:* `ais/observatory/behavior.py`.
*Evidence:* adversarial case 15 (behavioural mimicry): mimicry produces no
authority, and the attempt itself produces drift evidence.

### B. Authority drift

Drift is the measurable divergence between five views of one agent: declared
authority, granted authority, observed behaviour, historical behaviour and task
contract. It is decomposed into typed components — capability, purpose,
behavioural, delegation, communication, credential and escalation drift — each
with its own evidence and weight, combined by noisy-OR.

Decomposition matters for the research claim: "drift = 0.83" is not actionable,
whereas "credential drift plus communication drift plus delegation drift, with
this evidence" is both actionable and auditable. Deterministic rules and
statistics are used rather than model judgement, so every drift claim is
reproducible from the audit chain.

*Implementation:* `ais/observatory/drift.py`.

### C. Agent immune memory

Confirmed threats are stored as ordered behavioural signatures with their
authority pattern, delegation shape, applied response and outcome. Two rules
keep memory honest:

* a signature may only be written with an independent verification reference and
  a deterministic replay behind it;
* a match contributes a **bounded prior** (`MAX_MEMORY_PRIOR = 0.15`) and can
  never by itself reach a containment threshold.

Signatures marked false positive contribute *negative* score, so the memory
learns from over-reaction as well as from attacks.

*Implementation:* `ais/immune_system/{signatures,memory}.py`.
*Evidence:* the section 15 experiment — agent B matches agent A's signature at
0.99 yet is classified NORMAL and left uncontained until its own independently
verified evidence exists.

### D. Defensive authority

Defence needs its own capability namespace — `agent.observe`, `agent.flag`,
`agent.analyze`, `agent.replay`, `agent.restrict`, `agent.isolate`,
`agent.quarantine`, `agent.revoke`, `agent.restore`, `immune.read`,
`immune.write` — with no offensive verbs, and it must be *partitioned across
agents* rather than concentrated. Detection authority does not imply containment
authority; containment authority does not imply observation authority.

Offensive capabilities are refused at parse time, not by policy: there is no
configuration in which `agent.attack_anything` becomes representable.

*Implementation:* `ais/control_plane/capabilities.py`, `ais/defensive_agents/`.

### E. Recursive governance

The immune system is itself subject to the immune system. SENTINEL agents are
ordinary principals; their every action is a gateway decision; they cannot grant
themselves or each other authority; they cannot modify policy, edit the audit
chain, lift their own restrictions, or reach the emergency controls; a
quarantined defensive agent is sandboxed exactly like any other agent.

This is the claim the project is least willing to assert rhetorically, so it is
tested adversarially: `tests/defender_security/` plus the mandatory section 17
experiment, twelve escape paths, all denied.

Recursive governance is also *monitored*, not merely designed: an invariant
checker re-evaluates P1-P8 as predicates over live control-plane state after
every decision, and a containment event that cannot be traced back to an
allowing gateway decision is itself a violation. Two further mechanisms harden
the defensive side specifically:

* **multi-party attestation** - revocation requires two distinct confirming
  verifiers, so one compromised auditor yields a HOLD rather than destruction of
  authority;
* **out-of-process verification** - a verifier that runs as its own OS process
  and receives only the serialised audit chain. It recomputes every record hash
  before reading a claim, so a compromised control plane cannot coerce a
  confirmation by handing over a doctored history, and its verdicts are signed
  with key material that never passes through a gateway request;
* **an explicitly modelled compromised detector** - the false-flag experiment
  gives an attacker the detector and shows that a flag without reproducible
  evidence produces nothing at all.

## Falsifiability

Thirteen falsifying observations, each with the test that would report it, are
listed in [evaluation.md §6](evaluation.md). In summary, the thesis fails if any
of these is ever observed:

* a defensive agent obtains authority it was not externally granted;
* containment executes without a subject-bound, independently reproduced
  verification, or revocation executes on a single verifier;
* delegation produces authority the delegator never held;
* a tool call executes with no gateway decision behind it;
* immune memory alone, or a fabricated flag, causes containment;
* authority survives revocation for even one further decision;
* a quarantined agent produces a production effect;
* a benign agent reaches containment;
* an audit mutation goes undetected, or two identical runs disagree on the audit
  head hash.

Three experiments that *could* falsify the thesis are **not yet implemented**
and are stated as open: a learning adversary; two colluding verifiers; and
compromise of the human root or emergency-key holder, who are trusted by
construction. A fourth - physical separation of verification - is now
implemented across processes (`ais/verifier/`), though not yet across hosts or
user accounts.

## Relation to prior framings

This is not "AI cybersecurity" in the sense of applying ML to security
telemetry, and it is not model alignment. It is closer to capability-based
security (Dennis & Van Horn; KeyKOS; seL4's authority reasoning), to
confused-deputy analysis, and to biological immunology's distinction between
recognition, effector function and self-tolerance — with the addition that the
effector arm must itself be bounded, because here the effector is also an
autonomous agent.

## Position

> The desired outcome is not an AI capable of defeating another AI. It is a
> demonstration that an ecosystem of autonomous agents can remain bounded,
> observable, recoverable and governable even when individual agents become
> compromised or act outside their authorized purpose.
