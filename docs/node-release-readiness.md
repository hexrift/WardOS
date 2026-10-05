# ward-node release readiness: what CI proves

Status: living document. It states exactly what the repository's CI proves about the
`ward-node` substrate on every pull request and every push to `main`, what a release
publishes, what CI does not prove, and what to check before tagging a release that
carries node changes. It is the evidence behind the completion gate of
[#332](https://github.com/hexrift/WardOS/issues/332): "the declared Rust toolchain runs
the repository verification gate; every child PR is independently reviewable and green
before merge; a final cross-system acceptance proves bounded execution, recovery,
authorization failure and replay safety."

The workflows named here are protected surfaces (`.github/workflows/**`,
[development-under-tamperward.md](development-under-tamperward.md)); this document
describes them and changes nothing about them.

## 1. What every pull request proves

Every step below is in `.github/workflows/verify.yml`, the merge authority, unless it
names another workflow. All of them run on the declared toolchain (`rust-toolchain.toml`,
which the workflow pins to the same version) on an x86_64 GitHub runner.

| Step | What it runs | What it proves for the node |
| --- | --- | --- |
| **Working isolation** | Installs bubblewrap, enables unprivileged user namespaces, and runs `bwrap --unshare-all … /bin/true`; the job fails if the sandbox cannot be created (#124). | Every bubblewrap-backed node test below ran for real on this runner, not as a skip. |
| **The merge gate** | `scripts/verify/tamperward.sh` with `WARD_REQUIRE_ISOLATION=1`: `cargo metadata --locked` (the lockfile is consistent), `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -D warnings`, `cargo test --workspace --all-targets --all-features`, then `scripts/security-check/static.sh` and `scripts/security-check/tamperward-integration.sh`. | `ward-node-protocol`, `ward-node`, `ward-node-client` and `ward-launch` build warning-free and every one of their tests passes, including the socket, admission, transition-matrix, durability, evidence-log and manifest tests of `ward-node` and the real-node tests of `ward-node-client`, with isolation required (`crates/ward-sandbox/src/ci.rs`: a missing prerequisite is a failure, not a skip). The acceptance cases run here too, in parallel with the rest of the workspace. |
| **Isolation evidence** | `cargo test -p ward-daemon --test e2e` once more, then `scripts/verify/check-isolation-evidence.sh` over its log, after the checker's own self-test. | The daemon's namespace, verifier-corpus and egress regressions each ran exactly once with `ok`; the names and counts go to the step summary. This is the session path's evidence; the node path's is the next row. |
| **Acceptance verdicts** | `scripts/acceptance/node.test.sh`, then `scripts/acceptance/node.sh` with its table appended to the job's step summary (`tee -a "$GITHUB_STEP_SUMMARY"`). | The eight cases of [node-acceptance.md](node-acceptance.md) §2, run one at a time against a real node over its real socket, each with a named `PASS` and its time, and `acceptance: 8 passed, 0 failed`; the job fails when any case fails or none ran. The table is on the run's summary page, under the step "ward-node cross-system acceptance verdicts (#332 slice 9)". This is the completion gate's "final cross-system acceptance", on every pull request. |
| **cargo-deny** (job `deny`) | `cargo deny check advisories licenses sources bans` against `deny.toml`. | No known advisory, no disallowed licence, no unknown registry or git source and no wildcard dependency in the node crates' dependency tree (`ring`, `nix`, `clap`, serde and the workspace crates). |
| **docs links** (job `docs`) | `doc-links.py`, `doc-status.py`, `tamperward-signoff-doc.py`, `protocol-window.test.sh` and `protocol-window.py`. | Every relative link in the node documents resolves; no document claims a project phase of its own; and the protocol window `<!-- protocol-window: 1.0-1.3 -->` in [compatibility.md](compatibility.md) equals `WARD_NODE_PROTOCOL` in `ward-node-protocol`, so a minor cannot be added or retired without the compatibility document saying so in the same change (#275). |
| **ward-bench** (job `benchmark`, measures, never gates) | `ward benchmark --json`, the CI-measurable subset of [performance.md](performance.md) §5, uploaded as an artifact for 90 days. | Nothing specific to the node: its metrics are the session path's (`sandbox_start`, `verifier_spawn`, `snapshot_*`, `observer_event_propagation`, `pause_acknowledgement`). `sandbox_start` and `snapshot_capture_*` measure the same `ward-launch` spawn and `ward-snapshot` capture the node uses, so a regression there is a regression for `start`; no threshold fails the job (#150). |
| **TamperWard gate** (`.github/workflows/tamperward.yml`) | The diff-time protected-surface check over the pull request's commit range, and `tamperward verify`, which re-runs the merge gate in a visible and a pristine copy. | A pull request that deletes, skips or weakens a node test, rewrites a fixture or edits CI is blocked until a human signs off out of band; the gate's own result cannot be manufactured by the change under test. |
| **image** (`.github/workflows/image.yml`, on pull requests that touch `crates/**`) | Builds the bootc image, natively for x86_64 and aarch64, compiling `ward-node` from the checkout (`image/Containerfile`). | `ward-node` builds `--locked` for both architectures the image ships for. It is not started inside the image build. |
| **release scripts** (job `release-scripts`) | `scripts/release/run.sh`: shellcheck and the bash regressions of every release helper. | The tag, version and asset binding of §2 behaves as documented. |

The same `scripts/verify/tamperward.sh` runs locally; a green run there is a green run
in CI (CONTRIBUTING.md). What CI adds is the proof that isolation was required, the
named verdicts and the protected-surface gate.

## 2. What a release publishes

`.github/workflows/release.yml` runs on a `v*` tag or by dispatch with a version. It
refuses a tag that does not equal the workspace version of the source commit
(`scripts/release/check-version.sh`), builds natively per architecture, smokes the
binaries (`check-binary-version.sh` and `--help`), and attaches
`wardos-<version>-<arch>-linux.tar.gz` with its `.sha256` to one GitHub release bound
to that commit (`check-tag-commit.sh`, `check-assets.sh` on a retry). The tarball
carries `ward`, `wardd`, `ward-agent`, `ward-shell`, `wardos-theme-render`,
`install.sh`, `README.md`, `LICENSE` and a copy of `docs/`.

For the node this means:

- **`ward-node` is not in the release tarball**, and neither is `ward-node-adapter`.
  `ward-node` ships in checkout-built images (`image/Containerfile`, #306); both are
  built from source for a deployment ([node-integration-guide.md](node-integration-guide.md)
  §1). Independently versioned node artifacts are
  [#275](https://github.com/hexrift/WardOS/issues/275).
- **The node documents ship in the tarball**, as part of `docs/`, at the revision of the
  release commit.
- **The protocol window of a release is the one in its source commit**
  (compatibility.md §6). The release manifest
  ([release-manifest.md](release-manifest.md)) does not record it.
- **The release run does not re-run the acceptance suite.** The evidence for a release
  commit is the `verify` run on that commit (every push to `main` runs it), not the
  release workflow.

## 3. What CI does not prove

- **Hardware and the shipped kernel.** Everything above runs on a GitHub Ubuntu runner.
  The node is not started on the WardOS image or on reference hardware; the kernel,
  bubblewrap version and user-namespace settings differ. The `desktop-compositor` job
  runs on Fedora 44 for the desktop; nothing comparable exists for the node.
- **aarch64 execution.** The acceptance suite and the workspace tests run on x86_64
  only. The image build compiles `ward-node` for aarch64; the release build smokes only
  the five tarball binaries, which do not include the node.
- **Remote transport, enrolment, rotation.** There is none to test
  ([node-security-limitations.md](node-security-limitations.md) §3.1, #262).
- **Network grants.** The suite proves a network manifest is refused and an offline
  workload has no route off the host; no allowlist exists to prove.
- **Load, capacity, concurrency.** One workload at a time; the registry, pause and
  state-file bounds are unit-tested, not exercised under load (#260).
- **Clock skew.** Envelopes are signed at the node's own clock.
- **Adversarial escape.** The isolation case checks what the sandbox denies an ordinary
  workload; it is not an exploit suite (node-acceptance.md §4).
- **Delegated cgroups.** The runner has none; the node uses none. The signal-only
  freeze is what is tested.
- **The release artifact itself.** The acceptance suite runs against binaries built by
  `cargo test` from the same commit, not against the tarball or the image.
- **TamperWard verdicts.** The suite says what the node did; certification is the
  external control plane's (ADR-0029).

## 4. Before tagging a release with node changes

The release PR of CONTRIBUTING.md ("Versioning") is where these are checked and
recorded in its verification section. None of them is automated by the release
workflow.

1. **The protocol window.** `WARD_NODE_PROTOCOL` and the marker in compatibility.md
   agree (the `docs` job is green on the release commit), and compatibility.md §1 lists
   every minor the release serves. If the window moved since the last release, the
   release PR says so, and compatibility.md §4 tells control planes the upgrade order.
2. **The acceptance table.** The `verify` run on the release commit shows
   `acceptance: 8 passed, 0 failed` in the step summary of "ward-node cross-system
   acceptance verdicts". Link that run from the release PR.
3. **The contract's status line.** node-integration.md §1 names the protocol revision
   and the ADR-0030 steps the release implements, and every "not implemented yet" it
   lists is still true (or the line is updated in the same release PR).
4. **The limitations.** node-security-limitations.md §3 matches what the release ships:
   a limitation closed since the last release is removed, a new one is added, and each
   "no issue yet" still has none or now names its issue.
5. **The documents ship.** `docs/` is copied into the tarball by the release workflow;
   the node documents the tarball carries are therefore the ones on the release commit.
   Nothing to do unless a document was moved.
6. **Build from the tag.** `cargo build --release --locked -p ward-node -p ward-node-client`
   succeeds on the tagged commit on the architectures you deploy to; `ward-node`'s
   `--help` and `ward-node-adapter`'s `--help` print the flags of node-integration.md
   §2.1 and §11.4.
