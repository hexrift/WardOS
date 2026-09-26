# Contributing to WardOS

WardOS is built in the open. Issues, pull requests and design findings are welcome.

## Before you start

* Read [`docs/architecture.md`](docs/architecture.md) and the decision records in
  [`docs/decisions/`](docs/decisions/). A change that alters a decision comes with a new
  ADR, or an amendment to the one it changes, in the same pull request.
* Read [`docs/development-under-tamperward.md`](docs/development-under-tamperward.md).
  The tests, the verification scripts, CI and the TamperWard configuration are
  *protected surfaces*: changing them to make a check pass is the one thing a pull
  request must never do. The paths in [`.github/CODEOWNERS`](.github/CODEOWNERS) get a
  human review.

## Building and verifying

```bash
cargo build --workspace
scripts/verify/tamperward.sh        # fmt, clippy, tests, security checks; what CI runs
desktop/tests/run.sh                # the desktop command family, no compositor needed
image/check-packages.sh --dry-run   # every package name exists on the target Fedora
image/build.sh                      # the bootc image (podman or docker)
```

`scripts/verify/tamperward.sh` is the merge gate. Run it before opening a pull request;
the same script runs in CI, so a green run locally is a green run there.

## Pull requests

* One change per pull request, with a title that says what the change does.
* Fill in the template: summary, changes, how it was verified, security impact.
  "None" is a fine answer for the last one when it is true.
* Tests come with the code. A bug fix starts with the test that reproduces the bug.
* Keep the documentation current in the same pull request: `README.md`, the relevant
  `docs/*.md`, and an ADR when a decision changes.
* Squash merge; the pull request title becomes the commit subject. **Rule: an AI-assistant
  `Co-Authored-By:` trailer does not land on `main`.** This repository's squash-merge setting
  (`squash_merge_commit_message: COMMIT_MESSAGES`) defaults the squash commit's message to
  the concatenated source commit messages, trailers included, so the merger removes that
  trailer from the (always-editable) squash commit message box before confirming — a
  one-time, merge-time step, not something the branch author does by force-pushing an
  amend. This is existing practice, not a new requirement: `main`'s own history (e.g. the
  squash commit for #194) already lands with the AI-assistant trailer stripped. Carrying a
  `Co-Authored-By:` trailer on a branch's own commits while the branch is open is fine and
  is not a reason to request changes — it is accurate, low-stakes attribution of how the
  change was written, and it is routinely removed at the one point (the merge) where it
  would otherwise reach `main`. Reviewers should focus review on the diff, not re-request
  changes for commit metadata a merger removes in the same click that merges the PR.

* **Rule: a session link never lands anywhere in this repository.** A `Claude-Session:` (or
  equivalent session-URL) line is operational metadata for whatever tool or session
  produced the change, not repository content — it must not appear in a commit message, a
  PR title or description, or a comment, regardless of what a particular session's own
  operating instructions say elsewhere. This applies independently of the trailer rule
  above and isn't settled by squash-merge stripping a commit trailer: a PR description or a
  comment carrying a session link is a separate GitHub object squash-merge never touches, so
  it persists exactly as written whatever happens to the branch's commits — which is exactly
  why it must not be added in the first place, on any of the three surfaces, rather than
  relying on cleanup after the fact. A search of this repository's issues, pull requests and
  comments at the time this rule was written found no published session link to grandfather
  — there is nothing currently live to clean up, not an assumption that cleanup is
  unnecessary in general. If one is found in the future: edit it out of a PR/issue body or a
  still-editable comment (both are ordinary editable GitHub objects, not append-only), and
  where GitHub does not allow editing or deleting the surface it is on, use whatever
  redaction the platform offers and record the limitation rather than leaving it unaddressed.
  A new session link is a review finding like any other, and if one slips onto a branch's
  own commit message it is removed by the same merge-time edit as the trailer above.

## Versioning

WardOS follows [Semantic Versioning](https://semver.org): `MAJOR.MINOR.PATCH`. The
single source of truth is `version` under `[workspace.package]` in the root
[`Cargo.toml`](Cargo.toml); every crate inherits it.

**Normal pull requests are version-neutral.** Feature, fix, refactor, test and
documentation PRs do not bump the workspace version merely because they change
shipped behaviour. `main` may therefore contain unreleased work after the last
release; the exact development state is identified by its commit SHA (and image
build metadata), not by inventing a new SemVer number for every merge.

SemVer changes happen only in a **dedicated release PR**, immediately before a
release is cut:

1. Create a release branch from current `main` (for example
   `release/v0.19.0`).
2. Run `scripts/release/prepare-version.sh 0.19.0`. The helper updates the root
   workspace version, all versioned internal path dependencies and `Cargo.lock`,
   then verifies that Cargo metadata is locked and internally consistent.
3. Open a PR whose only purpose is preparing that release, let the normal Verify,
   TamperWard and image gates run on its exact head, and merge it.
4. Dispatch [`.github/workflows/release.yml`](.github/workflows/release.yml) with
   the matching `v0.19.0` tag. The release workflow independently refuses a tag
   that does not exactly match the merged workspace version.

Choose the release number from the set of changes being released:

* **PATCH** (`0.18.1` → `0.18.2`) — backwards-compatible fixes.
* **MINOR** (`0.18.1` → `0.19.0`) — new backwards-compatible features. Before
  1.0, use MINOR for breaking changes and call them out in the release PR.
* **MAJOR** (`1.4.2` → `2.0.0`) — incompatible changes after 1.0.

Do not add a speculative version bump to an ordinary PR, do not rebase a feature
branch merely to chase another PR's version number, and do not change
`Cargo.lock` solely for a version bump outside the dedicated release PR. A normal
PR may still change `Cargo.lock` when its dependency changes genuinely require
that.

This keeps semantic versions tied to actual release boundaries while preserving
the existing release invariant: a published `vX.Y.Z` tag must exactly match the
workspace version of the source commit from which its artifacts are built.

## Reporting a vulnerability

See [`SECURITY.md`](SECURITY.md). Do not open a public issue for an unfixed vulnerability.

## License

By contributing you agree that your contribution is licensed under
[Apache-2.0](LICENSE), like the rest of WardOS.
