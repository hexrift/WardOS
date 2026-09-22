# Developing WardOS under TamperWard

Status: living document; the project's phase is in docs/status.toml and the README.
This describes how the WardOS repository itself is protected while
agents help build it. It is deliberately separate from
[`tamperward-integration.md`](tamperward-integration.md), which is about WardOS *at
runtime* giving TamperWard primitives. Here the relationship is inverted: TamperWard keeps
WardOS's development honest.

```text
WardOS strengthens TamperWard at runtime.
TamperWard keeps WardOS honest during development.
```

If WardOS can eventually say "WardOS was itself developed under TamperWard enforcement,
with the evidence and adversarial tests published", that is a stronger claim than
"designed securely".

## 1. Guard the judge, not the implementation

The agent should be free to modify `ward-daemon`, `ward-agent`, `ward-verifier`, the
installer and everything else that is *candidate code*. What it must not be able to
quietly weaken is the mechanism that decides whether those changes are acceptable.

```text
IMPLEMENTATION      agent may modify
      ↓ judged by
SECURITY TESTS      agent cannot weaken
      ↓ executed by
VERIFICATION        agent cannot redefine
```

Protecting `crates/ward-verifier/**` with TamperWard sounds safer but is the wrong
abstraction: "fix a verifier isolation bug" is a legitimate task that must edit that crate.
What matters is that the agent cannot *simultaneously* change
`crates/ward-verifier/**` **and** `security-tests/verifier-escape/**` **and**
`scripts/verify/verifier.sh` and then declare itself fixed.

## 2. Three layers, three different questions

| Layer | Question | Mechanism | Scope |
| --- | --- | --- | --- |
| TamperWard | "Did the agent weaken the judge?" | `.tamperward.yml`: protected tests, verify config, CI, golden fixtures, hooks; rules; sign-off; pristine re-execution; `run` envelope | Tests, verify scripts, CI workflows, expected outputs, control-plane wiring |
| CODEOWNERS | "Does sensitive implementation need a human?" | `.github/CODEOWNERS` + branch protection requiring owner review | Threat/security docs, `SECURITY.md`, boot/key material, `ward-policy`, `ward-credentials`, `ward-verifier`, installer crypto |
| WardOS Security CI | "Do WardOS's own isolation claims hold?" | QEMU VM boots the real image and runs a hostile agent workload against ST-001..025 | The product's claims, independent of TamperWard |

```text
                     PR candidate
                           │
            ┌──────────────┴──────────────┐
            ▼                             ▼
      TamperWard verify             WardOS Security CI
      (pristine tests,              (QEMU: boot real image,
       protected checks)             hostile agent, ST-*)
            │                             │
            ▼                             ▼
          PASS                          PASS
            └──────────────┬──────────────┘
                           ▼
                     Human review (CODEOWNERS where required)
                           ▼
                         MERGE
```

TamperWard is one control. It is not proof that WardOS is secure. Independent escape
tests, VM boundary tests, malicious-repo tests, verifier-independence tests and,
eventually, external security review are still required.

## 3. Staged enforcement

| Stage | Mode | What is protected | Notes |
| --- | --- | --- | --- |
| Phase 0 (architecture) | **Observe** | Nothing blocks. TamperWard records what agents touch, what shortcuts they try, where policy would need to exist | The `.tamperward.yml` in the repository already lists the intended protected surfaces so observations are meaningful; severities become effective at Phase 1 |
| Phase 1–2 (early implementation) | **Protect critical surfaces** | `docs/threat-model.md`, `docs/security-model.md` (via CODEOWNERS), `security-tests/**`, `integration/tamperward/**`, verify scripts, CI security gates, golden fixtures | Block severities for test deletion/skip, CI tampering, hook tampering, `--no-verify` |
| Phase 3+ (security-sensitive work) | **Full enforcement** | As above, plus `transient-protected-mutation: block` once the watcher is inside the supervised run envelope | An agent must not weaken isolation tests, disable a verifier, alter expected failures, loosen seccomp/Landlock fixtures, or silently broaden privileges |
| Phase 6+ (image builds) | **Self-hosting** | WardOS builds itself under the same guarantees it advertises | Evidence published with releases |

## 4. Repository configuration

### 4.1 `.tamperward.yml`

Committed at the repository root (see the file). Summary of what it protects:

* **tests**: `tests/**`, `security-tests/**`, `crates/**/tests/**`, `integration/**/tests/**`,
  `installer/tests/**`, `runtime/tests/**`
* **config** (how verification is performed, never ordinary source): `scripts/verify/**`,
  `scripts/security-check/**`, `clippy.toml`, `deny.toml`, `rust-toolchain.toml`,
  `.cargo/config.toml`
* **ci**: `.github/workflows/**`
* **snapshots** (rewriting could manufacture a pass): `tests/golden/**`,
  `security-tests/golden/**`, `security-tests/fixtures/expected/**`, `**/*.golden*`
* **hooks** (control-plane wiring): `.tamperward.yml`, `.claude/settings.json`,
  `.github/CODEOWNERS`, `.pre-commit-config.yaml`

Rules: hard failures for test deletion, test content removal, test skip, coverage
lowering, CI tampering, hook tampering, `--no-verify`, transient protected mutation.
Intent-ambiguous signals (assertion weakening, guard removal, snapshot rewrite) start as
`warn`. The ignore list starts empty; adding an ignore requires the same scrutiny as adding
a suppression.

The verify command is `scripts/verify/tamperward.sh` and is deliberately boring: fmt,
clippy with `-D warnings`, the full test suite, then the static security check and the
TamperWard integration check. All of its inputs are declared so pristine verification
restores them from the trusted base.

**Rust caveat.** TamperWard's deepest detector support today is around the
TypeScript/Jest slice; its default protected paths cover Rust layouts, but WardOS does not
claim that `test-skip` comprehensively understands `#[ignore]`, `#[allow(...)]`, clippy
suppressions, `cargo test` filtering, feature-gated exclusion, workspace member removal,
nextest narrowing, or profile weakening. The early protection is therefore the
*combination*: protected test surfaces + protected verify command + pristine
re-execution + `run` envelope + authoritative CI + independent VM escape tests. A
first-class Rust detector pack for TamperWard is a natural later contribution that WardOS
motivates.

### 4.2 CODEOWNERS (human-review-only surfaces)

To be committed as `.github/CODEOWNERS` when the reviewer handles are confirmed:

```text
docs/threat-model.md        @<security-reviewer>
docs/security-model.md      @<security-reviewer>
SECURITY.md                 @<security-reviewer>
image/secure-boot/**        @<security-reviewer>
image/keys/**               @<security-reviewer>
crates/ward-policy/**       @<security-reviewer>
crates/ward-credentials/**  @<security-reviewer>
crates/ward-verifier/**     @<security-reviewer>
installer/crypto/**         @<security-reviewer>
```

An agent may legitimately change these; they may not be merged without a human security
review. Branch protection must require CODEOWNERS review and status checks for both gates
in §2.

### 4.3 Running agents on this repository

For serious implementation sessions:

```bash
TAMPERWARD_TRANSIENT=block npx tamperward run -- claude
```

Local hooks steer, the `run` envelope adjudicates locally, and protected CI/branch rules
are the repository authority.

```text
Claude
  │
  ▼
TamperWard run
  ├── protected tests
  ├── protected verifier
  ├── protected CI
  └── pristine verification
          │
          ▼
       GitHub CI
       ├── TamperWard authoritative gate
       └── WardOS QEMU adversarial suite
                  │
                  ▼
            Human review (CODEOWNERS)
                  │
                  ▼
                merge
```

Once Phase 2 delivers `ward claude`, WardOS development sessions move inside `ward`
itself, with TamperWard in the loop as described in
[`tamperward-integration.md`](tamperward-integration.md): the recursion closes.

### 4.4 Out-of-band sign-off mechanics

`tamperward-verify` (§2, the pristine re-execution job in
[`.github/workflows/tamperward.yml`](../.github/workflows/tamperward.yml)) will fail
whenever a pull request legitimately grows a protected fixture — most commonly
`crates/**/tests/**`'s full-catalogue roundtrip fixtures picking up a new, additive
`WardEvent`/`EventKind` variant. Restoring that fixture to its base-commit state and
re-running against a candidate that already assumes the new variant exists is expected to
fail; `tamperward verify` reports this as a `MASKED FAILURE`, which looks identical in the
check's output to an actual attempt to weaken the suite until a human reads the diff.

This is deliberate, not a gap to route around from inside a pull request: `.tamperward.yml`
requires `signoff.required_for: [block]`, and CI sign-off is explicitly out-of-band (the
local `ledger.jsonl` path only covers `tamperward run` on a workstation) so that a candidate
can never grant itself the sign-off it needs. Concretely:

* **Who** — anyone with *triage* role or higher on this repository. Today that is
  `@hexrift` (see [`.github/CODEOWNERS`](../.github/CODEOWNERS); the same person this
  repository's security-sensitive surfaces already route to). Extending this to additional
  maintainers is a repository-settings change, not a TamperWard or code change.
* **What to check** — read the failing `tamperward-verify` run's diff of the protected
  path(s) named in the failure (e.g. `git diff <base>..<head> -- 'crates/**/tests/**'`).
  Sign off only when every hunk is additive — a new fixture entry, a new assertion, a
  count bumped up to match — never when a line is removed, loosened, or skipped. A single
  removed or weakened line anywhere in the protected diff means this is a real block, not a
  masked failure, and must not be signed off.
* **How** — apply the label `tamperward:allow:verify@<head-sha>`, with `<head-sha>` the
  exact commit the PR is currently at, to the pull request. The gate reads labels from the
  triggering event (`labeled`/`unlabeled` are both in the workflow's `on.pull_request.types`),
  so applying it re-runs the check rather than requiring a new push. The SHA binding means a
  later push invalidates the sign-off and needs a fresh label bound to the new head — this is
  intentional (§ci-tampering's whole point is that a sign-off can't quietly outlive the diff
  it was read against).
* **What it does not clear** — a red *visible* suite, a run that could not execute, or any
  other failing rule. `tamperward:allow:verify@<sha>` clears only a masked failure on the
  `verify` rule for that one SHA; nothing else.

## 5. What the dogfooding loop is expected to surface

* Shortcuts agents actually attempt on a systems codebase (skipping flaky isolation tests,
  loosening seccomp fixtures "temporarily", widening allowlists in golden files).
* Gaps in TamperWard's Rust coverage (input for the detector pack).
* Places where WardOS's own security tests are too weak to be worth protecting.
* Friction that would make a real user disable enforcement, which is product feedback.

Findings are recorded in `security-tests/README.md` (for WardOS) and reported upstream to
TamperWard (for TamperWard), with session evidence attached.
