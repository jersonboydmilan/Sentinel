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

## Falsifiability

The thesis is falsified by any of the following, each of which has a test that
would fail loudly:

* a defensive agent obtaining authority it was not externally granted;
* a containment action executing without an independent, subject-bound
  verification;
* delegation producing authority not held by the delegator;
* an agent executing a tool call that received no gateway decision;
* immune memory alone causing containment;
* an audit mutation that verification does not detect;
* a benchmark run whose audit head hash differs between identical runs.

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
