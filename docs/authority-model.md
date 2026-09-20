# Authority model

## 1. Capabilities

A capability is `namespace.action`. Three classes exist:

```text
operational   tool.read  tool.write  database.read  database.write
              message.send  message.read  email.read  credential.read
              file.read  file.write  network.egress  web.search
              agent.delegate  agent.create

defensive     agent.observe  agent.flag  agent.analyze  agent.replay
              agent.restrict  agent.isolate  agent.quarantine
              agent.revoke   agent.restore
              immune.read    immune.write

forbidden     agent.attack_anything  agent.exploit_anything
              agent.destroy_target   network.penetrate
              (plus the verbs attack/exploit/destroy/retaliate/persist/
               implant/exfiltrate in any namespace)
```

Forbidden capabilities are refused by `Capability.parse`, so they cannot appear
in a grant, a policy, a contract or a delegation. This is a type-level refusal,
not a configurable default.

A fourth group is not a capability class at all: the **out-of-band namespaces**
`emergency`, `policy`, `authority`, `audit`. The gateway refuses any request
addressing them (step 4), regardless of who asks.

`CapabilitySet` supports wildcards (`database.*`), containment, union,
intersection and difference. Difference is how restriction is modelled:
`effective = granted − restricted`.

## 2. Grants

```python
Grant(grant_id, subject_id, capability, granted_by, issued_at,
      expires_at, delegable, delegation_depth, scope,
      parent_grant_id, reason)
```

Invariants enforced in `AuthorityService.issue`:

1. **No self-grant.** `issuer == subject` raises `SelfGrantDenied` and is
   audited. This holds for every principal, including root and including
   SENTINEL. (Principle 2)
2. **Non-root issuance is delegation.** A non-root issuer must hold an active,
   unrevoked, delegable grant covering the capability, with remaining depth.
   The new grant's depth is `min(requested, source.depth − 1)`, its expiry is
   `min(requested, source.expiry)`, and it records `parent_grant_id`.
   (Principle 3)
3. **Forbidden capabilities are unrepresentable.** Parsing rejects them.

## 3. The four authority views

| View | Meaning | Method |
|---|---|---|
| declared | what the task contract says the agent is for | `TaskContract.declared()` |
| granted | grants on paper, minus revoked and expired | `AuthorityService.granted()` |
| effective | granted minus active restrictions — what can be used *now* | `AuthorityService.effective()` |
| delegable | effective subset marked delegable with depth > 0 | `AuthorityService.delegable()` |

The drift engine compares declared and granted against *observed* and
*historical* behaviour. Keeping the views distinct is what makes drift a
measurable quantity rather than a judgement call.

## 4. Revocation (Principle 6)

* immediate: evaluated on every `effective()` computation, never cached in the
  agent;
* cascading: derived grants are revoked with their parent;
* authorized: non-root revocation requires `agent.revoke`, and a principal may
  never revoke for itself;
* evidence-gated: `RevocationService` additionally requires a verification
  reference and confidence ≥ 0.85.

```text
authority revoked ⇒ agent intention irrelevant ⇒ execution stops
```

## 5. Restriction versus revocation

| | reversible | destroys grants | evidence bar |
|---|---|---|---|
| RESTRICT | yes | no | verification, confidence ≥ 0.5 |
| ISOLATE | yes | no | verification, confidence ≥ 0.6 |
| QUARANTINE | yes | no | verification, confidence ≥ 0.7 |
| REVOKE | **no** | yes | verification, confidence ≥ 0.85 |

Restrictions suppress capability while leaving the grant intact, which is what
makes recovery possible: `SentinelRecovery` lifts restrictions against an
external `authorization_ref` issued by a human operator, and an agent can never
lift its own.

## 6. Policy evaluation

Policies are declarative documents evaluated in `(-priority, id)` order:

```yaml
- id: POL-017-DATABASE-WRITE
  priority: 60
  match: {action: "database.write"}      # request shape
  when:  []                              # fact gate (optional)
  conditions:                            # decide effect vs otherwise
    - fact: capability_held
      equals: true
    - fact: contract_in_scope
      equals: true
  effect: ALLOW
  otherwise: DENY
```

`match` selects on request shape, `when` on facts, `conditions` decide. The
separation keeps every policy total, so a policy governing quarantined agents
cannot accidentally decide requests from healthy ones. Supported decisions:
`ALLOW`, `DENY`, `RESTRICT`, `HOLD`, `ESCALATE`, `QUARANTINE`, `REVOKE`.
Unmatched requests fall to `POL-000-DEFAULT-DENY` (Principle 7). A missing fact
fails closed.

Policy ordering is itself a tested property: `POL-101` (the defensive catch-all)
sits *below* every specific containment policy precisely so it cannot pre-empt
an evidence requirement — a bug found and fixed by the section 17 experiment.

## 7. Defensive authority (Principle 5)

```text
SENTINEL-DETECT     observe, flag, immune.read
SENTINEL-AUDIT      observe, analyze, immune.read
SENTINEL-CONTAIN    restrict, isolate, quarantine, revoke
SENTINEL-FORENSICS  observe, analyze, replay, immune.read, immune.write
SENTINEL-RECOVERY   restore
```

Constraints, each covered by a test in `tests/defender_security/`:

* `POL-100` denies every operational capability to a defensive principal;
* `POL-101` denies the defensive namespace to non-defensive principals;
* irreversible and containment actions require a subject-bound `CONFIRMED`
  verification, at action-specific confidence gates;
* a defensive agent may not contain itself out of a restriction, verify itself,
  or lift its own restriction;
* a quarantined defensive agent is sandboxed like any other agent.

## 8. Emergency controls

Not capabilities, not policy-reachable, not addressable. Activation and
deactivation require an out-of-band key whose digest is held by the controller;
the gateway may only read state, and does so before authentication. An agent
that discovers the key name, the control names and the method signatures still
cannot call them: the `emergency.*` namespace is refused at gateway step 4.
