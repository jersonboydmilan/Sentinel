# Contributors

This project is a research prototype; credit is recorded by role, not by commit
count. New contributors are added here in the pull request that adds their work.

## Maintainer

| Contributor | GitHub | Role |
|---|---|---|
| Jerson Boyd Milan | [@jersonboydmilan](https://github.com/jersonboydmilan) | Project lead and maintainer — research direction, architecture, control plane, evaluation methodology |

## Areas of ownership

Ownership determines who reviews changes to the enforcement boundary; see
[.github/CODEOWNERS](.github/CODEOWNERS).

| Area | Owner |
|---|---|
| Control plane (`ais/control_plane/`) | [@jersonboydmilan](https://github.com/jersonboydmilan) |
| Out-of-process verification (`ais/verifier/`) | [@jersonboydmilan](https://github.com/jersonboydmilan) |
| Policy set (`policies/`) | [@jersonboydmilan](https://github.com/jersonboydmilan) |
| Defender security tests (`tests/defender_security/`) | [@jersonboydmilan](https://github.com/jersonboydmilan) |

## How to be listed here

Open a pull request that does one of the following, and add yourself to the
table in the same PR:

* **Break a claim.** A failing test that falsifies one of the entries in
  [docs/evaluation.md §6](docs/evaluation.md) is the most valuable contribution
  this project can receive.
* **Add an adversary or experiment.** See the experiment proposal template and
  the open experiments at the end of the evaluation document.
* **Harden an invariant.** Any change to authority, delegation, containment,
  verification or policy must name the invariant it protects and the test that
  would fail without it.
* **Improve the documentation of a limitation.** Making a claim narrower and
  more accurate counts.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the engineering rules and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for how discussion works here.

## Attribution note

Commit authorship is expected to match the contributor's GitHub account, so that
work appears in the contribution graph. If you commit from a local email that is
not registered on your GitHub account, add that email under
*Settings → Emails*, or commit with your `@users.noreply.github.com` address.
