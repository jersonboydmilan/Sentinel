# Delegation model

## 1. The predicate

```text
EffectiveAuthority(B) ⊆ DelegableAuthority(A)
```

Implemented directly as `CapabilitySet.issubset` in
`DelegationEngine.evaluate`. The excess set, when non-empty, *is* the evidence:

```python
excess = requested.difference(delegable)   # -> AuthorityAmplification
```

## 2. Full check sequence

A delegation A → B is allowed only if all hold:

1. B exists as a registered principal;
2. A holds `agent.delegate`;
3. A's task contract permits delegation;
4. the requested capabilities lie inside the contract's delegable set;
5. the requested capabilities lie inside `delegable(A)`;
6. B is not an ancestor of A (no cycle);
7. `depth(A) + 1 ≤ max_depth` (default 3).

Denials are audited at the gateway pre-check with the exact excess set and
reason list, which is how `SENTINEL-AUDIT` can later reproduce amplification
evidence without trusting the detector.

## 3. Attenuation along a chain

Both authority and purpose attenuate:

```text
A: web.search (delegable, depth 2)            contract: delegable {web.search}
        │  delegate(web.search, depth 1)
        ▼
B: web.search (delegable, depth 1)            sub-contract: {web.search, agent.delegate}
        │  delegate(web.search)               (tools/data/endpoints ⊆ A's, budget halved)
        ▼
C: web.search (not delegable, depth 0)        sub-contract: {web.search}
```

Grants carry `parent_grant_id`, so revoking A's grant cascades to B and C. A
delegatee also receives an **attenuated sub-contract** (`ContractEngine.derive`):
its declared purpose, tools, data, endpoints and budget are a subset of the
parent's. Without this, delegated authority would sit permanently outside the
delegatee's declared purpose — an authority gap, and (as the simulation showed
before the fix) a false-positive generator.

## 4. What cannot happen

| Attempt | Result |
|---|---|
| delegate a capability the delegator never held | `AuthorityAmplification`, excess reported |
| delegate beyond the contract's delegable set | `DelegationError: capabilities_outside_contract_delegable_set` |
| delegate without `agent.delegate` | `DelegationError: delegator_lacks_agent.delegate` |
| re-delegate past depth 0 | grant issued non-delegable; further hops denied |
| create a delegation cycle | `DelegationError: delegation_cycle` |
| exceed max chain depth | `DelegationError: max_delegation_depth_exceeded` |
| bypass the gateway by calling the engine directly | same predicate, same exception |
| widen a sub-contract | `ContractError: sub-contract capabilities exceed the parent's delegable set` |

## 5. Section 16 experiment

`ais/simulation/scenarios.py::run_delegation_experiment`, asserted in
`tests/delegation/test_delegation_model.py`:

```text
A(web.search) → B(none):  delegate(database.write)  → DENY, excess=[database.write], B authority = []
A(web.search) → B:        delegate(web.search)      → ALLOW, B authority = [web.search]
B             → C:        delegate(web.search)      → ALLOW, C authority = [web.search]
B             → C:        delegate(database.write)  → DENY
direct engine call, no gateway                      → AuthorityAmplification
B             → A:        delegate(web.search)      → DENY, reason = delegation_cycle
```

## 6. Propagation

`PROPAGATOR-01` in the standard population fans delegations across three
workers, alternating legitimate (`web.search`) and amplifying
(`credential.read`) requests. Across a 20-step run, 33 of 60 delegation attempts
are blocked, all 33 for authority amplification, and no worker ever obtains a
capability the propagator did not hold. The delegation graph
(`AgentIdentityGraph.delegation_chains`) and `Graph.blast_radius` make the
resulting fan-out inspectable as a relationship question rather than an event
question.
