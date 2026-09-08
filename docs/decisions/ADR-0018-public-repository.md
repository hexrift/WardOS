# ADR-0018 — The repository is public: what it carries and what it does not

## Decision
`hexrift/WardOS` is a public repository. Everything in it is written for a reader who
did not build it: the README describes the product and how to run it, `CONTRIBUTING.md`
describes how to build, verify and propose a change, `SECURITY.md` describes how to
report a vulnerability privately, and the ADRs and `docs/` record why things are the way
they are. Material that only the maintainer needs — brand notes, sign-off conventions,
working notes, session tooling — is not committed.

## Context
The repository started as a private design space. Some of what accumulated there was
addressed to its maintainer rather than to a user or a contributor: a README section
explaining the logo's derivation, a license section that still read "to be decided"
next to an Apache-2.0 `LICENSE` file, a security policy written for "Phase 0, no
software yet", and a pull-request template that ended with the maintainer's own
sign-off line, which a contributor would have had to copy or delete.

## Consequences
* The README states the license as Apache-2.0 and points to `CONTRIBUTING.md` and
  `SECURITY.md`; the brand section is gone. The logo stays; a mark needs no explanation.
* `SECURITY.md` names GitHub private vulnerability reporting as the channel, the
  supported versions, and the response expectation.
* `CONTRIBUTING.md` is the contributor's entry point: the verification script that is
  the merge gate, the protected surfaces, the documentation rule, squash merges.
* The pull-request template carries no sign-off; authorship is what git records.
* Maintainer tooling lives outside the tree (`.claude/` is untracked and stays so;
  `.gitignore` keeps agent worktrees out).
* Experiment records keep naming the reference hardware in general terms (a Fedora
  laptop, an AMD desktop); they do not carry personal details.

## Alternatives considered
* **A separate private repository for maintainer notes.** Nothing worth keeping is
  maintainer-only; the notes that mattered became ADRs.
* **Keeping the brand section.** It explained the logo to its designer. A reader sees
  the logo at the top of the README; the TamperWard relationship is stated in the
  design principle.
