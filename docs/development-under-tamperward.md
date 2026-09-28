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

<!-- tamperward-prefix-guidance:reviewed-block:start -->
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

This whole section, from its heading above to the matching
`reviewed-block:end` marker before §5, is pinned by a stored SHA-256 hash in
[`tamperward-signoff-doc.py`](../scripts/security-check/tamperward-signoff-doc.py):
editing anything in it — a word, a sentence, a whole bullet, anywhere in §4.4,
not just the two bullets that discuss the legacy label's abbreviated SHA
`prefix` directly — changes the hash and fails the build until a human
re-reads the new wording and updates the pin in the same pull request, which
is itself a `scripts/security-check/**`-protected, reviewed path. (Issue
#320's review spent three rounds on a regex heuristic for "is this claim
negated", each defeated by a new paraphrase, then found that scoping the
*location* of reviewed content to two bullets by the literal word `prefix`
was itself gameable by a paraphrase that dropped the word — "legacy labels
accept abbreviated head SHAs" has the same meaning without it. Pinning the
whole section this word could have been added to anywhere in, rather than
trying to name every word that could carry that meaning, is what actually
closes it.)

* **How, today — the compact head-bound token (canonical).** Generate one with:

  ```
  npx --yes tamperward@2.33.0 signoff-label --rule verify --head <full-head-sha>
  ```

  (or `--rule check` for a diff-time-gate sign-off, and `--file <path>` when the rule
  is file-scoped), and apply the resulting `tw1:<digest>` label to the pull request.
  This is the mechanism `.github/workflows/tamperward.yml`'s pinned `tamperward@2.33.0`
  actually verifies against: a short, opaque, versioned token that hashes the rule, the
  optional file, and the **complete** head object id — never a truncated display SHA —
  so it fits GitHub's 50-character label-name cap without relying on a prefix at all. It
  is bound to one exact head: an *ordinary* later push (one nobody deliberately crafted)
  no longer matches, and needs a fresh token for the new head, which is what makes a
  routine rebase or merge-from-main behave as intended (§ci-tampering's whole point is
  that a sign-off can't quietly outlive the diff it was read against — see #318's own
  PR thread for a worked example of a sign-off going stale across three separate
  `main`-syncs). Still remove the label itself as soon as the PR it was granted on
  merges, closes, or gets a head that no longer needs it — a label a maintainer forgot
  to remove is a standing authorization, and the removal is the control, not the next
  push.
* **The legacy `tamperward:allow:<rule>@<sha>` label is accepted by the workflow's label
  resolver but does not work against this pin — do not use it.** Earlier guidance here
  described applying `tamperward:allow:verify@<sha-prefix>` (a 26-character abbreviation,
  the longest that fits alongside the `tamperward:allow:verify@` prefix under GitHub's
  50-character label cap) as a fallback, on the mistaken premise that `tamperward`'s
  `oobToken` matcher accepted any prefix of the head SHA that was at least 7 hex
  characters. That premise is wrong for the pinned CLI: under `tamperward@2.33.0`,
  once a full head SHA is supplied — which this repository's workflow always does,
  via `TAMPERWARD_OOB_HEAD` — `oobToken` requires a legacy label's SHA to equal
  that **full** 40-character object id; a prefix is rejected outright, not treated
  as a weaker-but-valid match. Since a legacy label's SHA portion is capped at 26
  characters by the label-name limit, it can *never* equal a full 40-character
  SHA against this workflow's configuration, so this
  path cannot clear a check here at all, however it is applied. This was hit and
  confirmed in practice on PR #318 — a correctly-formed 26-character legacy label was
  applied, `tamperward-verify` still failed the same way, and only re-applying the
  sign-off as a `tw1:` compact token cleared it (see #320 for the full incident). The
  resolver step in `tamperward.yml` still recognizes a `tamperward:allow:` label
  (alongside `tw1:` ones) and passes it through to `TAMPERWARD_OOB_SIGNOFF` — that is
  compatibility for *other* deployments of `tamperward` that may not require a full head
  match, not evidence that the legacy path works here. Prefer the `tw1:` token above in
  every case; if a legacy label is ever proposed as the sign-off, its SHA would need to
  be the literal, complete 40-character head object id to have a chance of matching,
  which cannot fit the label cap — so treat any legacy label seen on a PR here as
  inert, not as a granted sign-off, and reissue a `tw1:` token instead.
* **What it does not clear** — a red *visible* suite, a run that could not execute, or any
  other failing rule. A `tw1:` sign-off clears only a masked failure on the rule (and file,
  where scoped) it was generated for, on that one head SHA; nothing else.
* **Current limits on this being an authoritative control** — branch protection on `main`
  does not yet require the `tamperward`/`tamperward-verify` checks or Code Owner review, and
  CODEOWNERS does not yet cover `.github/workflows/**`. Until both are true, a pull request
  can in principle edit the workflow that enforces this gate (or bypass the required-check
  list) without a human in the loop; treat the mechanics above as the intended design, not
  yet as a fully closed loop, and tighten the ruleset/CODEOWNERS as a repository-settings
  follow-up.
<!-- tamperward-prefix-guidance:reviewed-block:end -->

## 5. What the dogfooding loop is expected to surface

* Shortcuts agents actually attempt on a systems codebase (skipping flaky isolation tests,
  loosening seccomp fixtures "temporarily", widening allowlists in golden files).
* Gaps in TamperWard's Rust coverage (input for the detector pack).
* Places where WardOS's own security tests are too weak to be worth protecting.
* Friction that would make a real user disable enforcement, which is product feedback.

Findings are recorded in `security-tests/README.md` (for WardOS) and reported upstream to
TamperWard (for TamperWard), with session evidence attached.
