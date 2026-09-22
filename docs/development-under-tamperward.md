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

* **Who** — anyone with GitHub *triage* repository permission or higher. This is a GitHub
  permission-level fact, checked at
  `Settings → Collaborators and teams`; it is not the same question as who
  [`.github/CODEOWNERS`](../.github/CODEOWNERS) routes review to, and CODEOWNERS entries do
  not by themselves grant or prove label-application authority. Today the only person with
  that permission is `@hexrift`. Extending this to additional maintainers is a
  repository-settings change, not a TamperWard or code change.
* **What to check** — read the failing `tamperward-verify` run's diff of the protected
  path(s) named in the failure (e.g. `git diff <base>..<head> -- 'crates/**/tests/**'`). The
  sign-off criterion is **semantic, not shape-based**: does the protected-surface change
  follow from, and stay proportionate to, the implementation change, without reducing what
  is exercised or how strictly it is checked? A purely additive-looking hunk (new fixture
  entry, new assertion, a count bumped up) is the common, easy case, but additive shape is
  not by itself sufficient — an added `#[ignore]`, a widened allowlist, or a loosened bound
  can also be "additive" while weakening coverage. Conversely, treat *any* deletion,
  skip, guard removal, or assertion weakening in the protected diff as a hold: those need
  the same scrutiny as a suppression, and are grounds to withhold sign-off even if the
  visible suite and the stated intent look reasonable.
* **How, today — a non-authoritative fallback, not a closed control.** Until the mechanism
  in the next paragraph is adopted, apply the label `tamperward:allow:verify@<sha-prefix>`
  to the pull request. **GitHub label names are capped at 50 characters**;
  `tamperward:allow:verify@` alone is 24, leaving 26 for the SHA, so a full 40-character SHA
  (64 characters total) is rejected by GitHub outright — this was hit and confirmed in
  practice against this repository (see #203) before this note was added. `tamperward`'s own
  OOB-signoff matcher (`oobToken` in the CLI) accepts any *prefix* of the head SHA that is at
  least 7 hex characters (`sha.length >= 7 && head.startsWith(sha)`) — it is a prefix match,
  not an equality check against the full object id, so treat the label as authorizing "a
  commit whose id starts with this prefix," not "this exact commit and no other." Use the
  longest prefix the cap allows — `tamperward:allow:verify@` + a 26-character abbreviation
  (`git rev-parse --short=26 <head-sha>`, exactly 50 characters) — rather than a shorter one;
  there is no reason to spend less of the budget than the cap allows. But do not read a
  longer prefix as closing the risk: a naive preimage-search framing (fix the approved head,
  brute-force a colliding successor) would put a 104-bit prefix out of reach, but that is the
  wrong model here. The party this label is meant to constrain can typically influence *both*
  sides of the match — the head that gets reviewed and labeled, and the successor pushed
  afterward — which makes this a **chosen-prefix / birthday-style search**, not a plain
  preimage search: with freedom to vary superficial bits of a candidate on both ends (commit
  timestamps, trailing whitespace, blank lines, other content a reviewer would not weigh),
  the generic cost of finding *some* pair that shares a target prefix scales with the square
  root of the prefix's bit length, roughly 2^52 work for a 104-bit prefix rather than 2^104 —
  the same order of magnitude publicly demonstrated for full chosen-prefix SHA-1 collisions
  (e.g. the 2017 SHAttered attack, since improved on). That is a real, if expensive, budget
  for a well-resourced adversary, not a theoretical one — so the 26-character prefix is a
  meaningfully stronger fallback than the 12-character guidance it replaces, but it is a
  **temporary, non-authoritative compatibility fallback**, not a resolution of the underlying
  gap: it does not by itself close #203, and should not be cited as though it does. The gate
  reads labels from the triggering event (`labeled`/`unlabeled` are both in the workflow's
  `on.pull_request.types`), so applying it re-runs the check rather than requiring a new
  push. The prefix binding means a later push invalidates the sign-off and needs a fresh
  label bound to the new head — intentional (§ci-tampering's whole point is that a sign-off
  can't quietly outlive the diff it was read against) — and is also why the label should be
  removed once the PR it was granted on merges or its head changes, rather than trusted to
  become harmless on its own.
* **How, once available — the actual resolution.** A full-object-id sign-off mechanism that
  fits GitHub's label-length cap without relying on a display-SHA prefix at all (e.g. a
  versioned, hashed token binding the rule, optional file, and the complete head object id)
  closes the gap the paragraph above only narrows. Adopting one is *not* something this
  documentation PR can do from inside this repository: it depends on that mechanism actually
  being released by the `tamperward` project this repo consumes from the npm registry (see
  `.github/workflows/tamperward.yml`'s pinned `tamperward@2.10.3`), which is out of this
  repository's control and outside what this session can independently verify. Once a
  release is confirmed to exist and to do what it claims, adopting it is: bump the pinned
  version in `tamperward.yml`, update this section with its actual label/token format and
  CLI invocation, and replace the fallback above rather than keep it as a second path. Track
  that adoption as its own follow-up rather than assuming it here.
* **What it does not clear** — a red *visible* suite, a run that could not execute, or any
  other failing rule. `tamperward:allow:verify@<sha>` clears only a masked failure on the
  `verify` rule for that one SHA; nothing else.
* **Current limits on this being an authoritative control** — branch protection on `main`
  does not yet require the `tamperward`/`tamperward-verify` checks or Code Owner review, and
  CODEOWNERS does not yet cover `.github/workflows/**`. Until both are true, a pull request
  can in principle edit the workflow that enforces this gate (or bypass the required-check
  list) without a human in the loop; treat the mechanics above as the intended design, not
  yet as a fully closed loop, and tighten the ruleset/CODEOWNERS as a repository-settings
  follow-up.

## 5. What the dogfooding loop is expected to surface

* Shortcuts agents actually attempt on a systems codebase (skipping flaky isolation tests,
  loosening seccomp fixtures "temporarily", widening allowlists in golden files).
* Gaps in TamperWard's Rust coverage (input for the detector pack).
* Places where WardOS's own security tests are too weak to be worth protecting.
* Friction that would make a real user disable enforcement, which is product feedback.

Findings are recorded in `security-tests/README.md` (for WardOS) and reported upstream to
TamperWard (for TamperWard), with session evidence attached.
