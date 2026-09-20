# Security policy

## Scope

This is a **defensive research prototype**, not production software. It is
explicitly not hardened for deployment: credentials are in-process HMAC tokens,
there is no key management, and the control plane trusts its own process.
See [docs/threat-model.md](docs/threat-model.md) §5 for the full list of what is
out of scope.

That said, a finding that breaks one of the architecture's claims is exactly
what this project wants.

## What counts as a vulnerability here

A report is in scope if it shows any of the following, with a reproduction:

| # | Claim broken |
|---|---|
| 1 | a defensive agent obtaining authority it was not externally granted |
| 2 | containment executing without a subject-bound, independently verified finding |
| 3 | revocation executing on a single verifier |
| 4 | delegation yielding authority the delegator never held |
| 5 | a tool call executing with no gateway decision behind it |
| 6 | immune memory or a fabricated flag alone causing containment |
| 7 | authority surviving revocation for a further decision |
| 8 | a quarantined agent producing a production effect |
| 9 | an audit mutation that verification does not detect |
| 10 | the out-of-process verifier confirming a claim its chain does not support |

Each of these maps to a falsification entry in
[docs/evaluation.md §6](docs/evaluation.md) and to a test. The best possible
report is a failing test.

## Out of scope

* in-process code execution inside the control plane (stated as outside the
  modelled boundary; the invariant checker detects it, nothing prevents it)
* compromise of the human root authority or the emergency key holder
* host-level compromise defeating the cross-process verifier split
* denial of service through resource exhaustion
* anything requiring modification of the repository's own source

## Reporting

Open a **private security advisory** through GitHub
("Security" → "Report a vulnerability"), or open a normal issue if the finding
is a research result rather than a live risk — nothing here runs in production,
so most findings are the latter.

Please include: the claim you believe is broken, a minimal reproduction
(ideally a test), the commit, and your Python version.

## Non-goals

This project does not build, and will not accept, offensive tooling: autonomous
attack agents, malware, credential theft, exploit delivery, persistence, or
retaliation. Offensive verbs are refused at parse time in
`ais/control_plane/capabilities.py`, and that is a boundary, not a default.
