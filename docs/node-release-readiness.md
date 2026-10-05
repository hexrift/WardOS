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
| **Acceptance verdicts** | `scripts/acceptance/node.test.sh`, then `scripts/acceptance/node.sh` with its table appended to the job's step summary (`tee -a "$GITHUB_STEP_SUMMARY"`). | The sixteen cases of [node-acceptance.md](node-acceptance.md) §2 (the eight of the main suite, the three network allowlist cases of §2.2 and the five result return cases of §2.3), run one at a time against a real node over its real socket, each with a named `PASS` and its time, and `acceptance: 16 passed, 0 failed`; the job fails when any case fails or none ran. The table is on the run's summary page, under the step "ward-node cross-system acceptance verdicts (#332 slice 9)". This is the completion gate's "final cross-system acceptance", on every pull request. After the table, `node.sh` runs `scripts/acceptance/node-js.sh`: the Node.js reference control plane of [node-integration-from-nodejs.md](node-integration-from-nodejs.md) (`examples/node-control-plane`) against a second real node, with the client's own generated key in the node's trust store, under the same `WARD_REQUIRE_ISOLATION=1`, and its eight verdicts (the five of the attempt's lifecycle and three of result return against a node started with `--output-return` and one without; `node-js acceptance <case>: PASS`, then `node-js acceptance: 8 passed, 0 failed`) follow the table; a failed case or a runner without Node.js >= 22 fails the job. The client's own `node --test` suite (the §7.4 vector, ids, the version counter, the adapter framing, the output grant and result verification) is not run by CI at this revision; it needs no node and is run by hand. |
| **cargo-deny** (job `deny`) | `cargo deny check advisories licenses sources bans` against `deny.toml`. | No known advisory, no disallowed licence, no unknown registry or git source and no wildcard dependency in the node crates' dependency tree (`ring`, `nix`, `clap`, serde and the workspace crates). |
| **docs links** (job `docs`) | `doc-links.py`, `doc-status.py`, `tamperward-signoff-doc.py`, `protocol-window.test.sh` and `protocol-window.py`. | Every relative link in the node documents resolves; no document claims a project phase of its own; and the protocol window `<!-- protocol-window: 1.0-1.3 -->` in [compatibility.md](compatibility.md) equals `WARD_NODE_PROTOCOL` in `ward-node-protocol`, so a minor cannot be added or retired without the compatibility document saying so in the same change (#275). |
| **ward-bench** (job `benchmark`, measures, never gates) | `ward benchmark --json`, the CI-measurable subset of [performance.md](performance.md) §5, uploaded as an artifact for 90 days. | Nothing specific to the node: its metrics are the session path's (`sandbox_start`, `verifier_spawn`, `snapshot_*`, `observer_event_propagation`, `pause_acknowledgement`). `sandbox_start` and `snapshot_capture_*` measure the same `ward-launch` spawn and `ward-snapshot` capture the node uses, so a regression there is a regression for `start`; no threshold fails the job (#150). |
| **TamperWard gate** (`.github/workflows/tamperward.yml`) | The diff-time protected-surface check over the pull request's commit range, and `tamperward verify`, which re-runs the merge gate in a visible and a pristine copy. | A pull request that deletes, skips or weakens a node test, rewrites a fixture or edits CI is blocked until a human signs off out of band; the gate's own result cannot be manufactured by the change under test. |
| **image** (`.github/workflows/image.yml`, on pull requests that touch `crates/**`) | Builds the bootc image, natively for x86_64 and aarch64, compiling `ward-node` and `ward-node-adapter` from the checkout (`image/Containerfile`'s builder stage; the release stage, which takes them from the node tarball, needs a published release and is not run on pull requests). | `ward-node` and `ward-node-adapter` build `--locked` for both architectures the image ships for and are in the image's `/usr/bin` (the Containerfile asserts both, and the job runs `ward-node --help`). Neither is started as a service inside the image build. |
| **release scripts** (job `release-scripts`) | `scripts/release/run.sh`: shellcheck and the bash regressions of every release helper. | The tag, version and asset binding of §2 behaves as documented, including the layout of the node tarball (`package.test.sh`), the refusal to publish without it (`check-release-set.test.sh`), the manifest's protocol window, read from compatibility.md's marker and refused when the marker is absent or malformed (`generate-manifest.test.sh`), the offline manifest verifier's verdicts and exit codes against a fake `cosign` — valid, wrong identity, wrong issuer, altered bytes, missing bundle, incomplete set, no cosign (`verify-manifest.test.sh`) — `install.sh`'s states against a fixture release served by a fake `curl`: verified, checksum-only without cosign or a manifest, refused on a wrong identity or an altered tarball (`install.test.sh`) — and the rule that the signature bundle is uploaded on a retry but never byte-compared (`check-assets.test.sh`, `download-published.test.sh`). |

The same `scripts/verify/tamperward.sh` runs locally; a green run there is a green run
in CI (CONTRIBUTING.md). What CI adds is the proof that isolation was required, the
named verdicts and the protected-surface gate.

## 2. What a release publishes

`.github/workflows/release.yml` runs on a `v*` tag or by dispatch with a version. It
refuses a tag that does not equal the workspace version of the source commit
(`scripts/release/check-version.sh`), builds natively per architecture with the
toolchain of `rust-toolchain.toml` and `--locked`, packages two trains per architecture
(`scripts/release/package.sh`), smokes every packaged binary (`check-binary-version.sh`
and `--help`), refuses to publish unless both trains and their checksums are present for
every architecture that built (`check-release-set.sh`), generates the release manifest
from that verified set (`generate-manifest.sh`), signs it keyless under the workflow's
own identity when the run is on the tag (`cosign sign-blob`; ADR-0028, #148), and
attaches everything to one GitHub release bound to that commit (`check-tag-commit.sh`,
`check-assets.sh` on a retry):

| Asset | Carries |
| --- | --- |
| `wardos-<version>-<arch>-linux.tar.gz` and `.sha256` | the runtime: `ward`, `wardd`, `ward-agent`, `ward-shell`, `wardos-theme-render`, `install.sh`, `README.md`, `LICENSE` and a copy of `docs/` |
| `ward-node-<node version>-<arch>-linux.tar.gz` and `.sha256` | the node: `ward-node`, `ward-node-adapter`, `LICENSE` and a copy of `docs/`. The Node.js reference client (`examples/node-control-plane`) is not packaged: a control plane takes it from the repository at the release commit, as [node-integration-from-nodejs.md](node-integration-from-nodejs.md) in the tarball's `docs/` says |
| `wardos-<version>-manifest.json` and `.sha256` | the release manifest ([release-manifest.md](release-manifest.md)): source commit, tag, both trains' versions, every tarball with its component, version, architecture and digest, and the node protocol window |
| `wardos-<version>-manifest.json.sigstore.json` | the manifest's Sigstore signature bundle, made by `release.yml` under its own identity on the release tag; verified offline by `scripts/release/verify-manifest.sh`. Absent on releases before the signing step (v0.4.1 and earlier) and on a run that was not on the tag (release-manifest.md) |

`<version>` is the workspace version without the `v`; `<node version>` is the node
train's own ([compatibility.md](compatibility.md) §6); `<arch>` is the runner's
`uname -m`, `x86_64` or `aarch64`. Each `.sha256` is `sha256sum`'s line for its
tarball (or the manifest), checked with `sha256sum -c` next to it.

For the node this means:

- **`ward-node` and `ward-node-adapter` are release artifacts**, in the node tarball,
  for both architectures. Each prints the node version (`ward-node --version`,
  `ward-node-adapter --version`), which the release checks before uploading, as it
  checks `ward` against the release version. The node version is the literal `version`
  of `crates/ward-node` and `crates/ward-node-client`, set by
  `scripts/release/prepare-version.sh <version> --node <node version>` in the release
  PR; the release refuses to build when it did not move with the node's inputs since
  the previous release, or moved although they did not
  (`scripts/release/node-version.sh`; [compatibility.md](compatibility.md) §6, #275).
  The manifest records it under `components["ward-node"].version`.
- **The node is not part of `install.sh`**, which installs the session layer for one
  user. Installing the node tarball is the operator step of
  [node-integration-guide.md](node-integration-guide.md) §1.
- **The image carries the node whichever way it is built.** `image/Containerfile`'s
  `builder` stage compiles `ward-node` and `ward-node-adapter` from the checkout (#306;
  the images CI publishes on every merge); its `release` stage downloads the node
  tarball beside the runtime tarball, named by the node version (`WARDOS_NODE_VERSION`),
  checks it against a pinned checksum (`WARDOS_NODE_SHA256`,
  `WARDOS_NODE_SHA256_AARCH64`; `image/build.sh` reads all three from the release
  manifest) and installs the same two
  binaries. Both stages end with them in `/usr/bin`, which the host stage asserts. A
  release without a node tarball (every release up to v0.4.1) cannot feed a
  release-source image: the stage refuses rather than ship an image with no node, and
  never falls back to a checkout build on its own (`image/README.md` "Where the binaries
  come from").
- **The node documents ship in both tarballs**, as part of `docs/`, at the revision of
  the release commit.
- **The protocol window of a release is recorded in its manifest.** The manifest's
  `node_protocol_window` is read from the `<!-- protocol-window -->` marker of
  compatibility.md at the release commit, the marker the `docs` job holds equal to
  `WARD_NODE_PROTOCOL` (§1), so the window a release states is the one its node
  serves (compatibility.md §6). A control plane reads it from the release before
  connecting; the generator refuses to produce a manifest when the marker is absent
  or malformed.
- **The release run does not re-run the acceptance suite.** The evidence for a release
  commit is the `verify` run on that commit (every push to `main` runs it), not the
  release workflow.
- **Manifest signed; tarballs checksum-bound to it.** A `.sha256` proves a tarball's
  bytes are the ones CI attached. The signed manifest proves which workflow, on which
  tag of which repository, recorded that tarball's digest — `verify-manifest.sh`
  checks the signature against the pinned identity and then the tarballs beside the
  manifest against its digests (release-manifest.md). The node tarball is trusted
  exactly as far as its digest in the signed manifest: it is not signed itself, and its
  install path — an operator's, not `install.sh`'s — runs the verifier only by hand
  (§3); `install.sh` runs it for the runtime tarball ([install.md](install.md) §1). The
  rest is ADR-0028 and #148.

## 3. What CI does not prove

- **Hardware and the shipped kernel.** Everything above runs on a GitHub Ubuntu runner.
  The node is not started on the WardOS image or on reference hardware; the kernel,
  bubblewrap version and user-namespace settings differ. The `desktop-compositor` job
  runs on Fedora 44 for the desktop; nothing comparable exists for the node.
- **aarch64 execution.** The acceptance suite and the workspace tests run on x86_64
  only. The image build and the release build compile `ward-node` for aarch64; the
  release smokes `--version` and `--help` of the packaged node binaries on an aarch64
  runner, nothing more.
- **Remote transport, enrolment, rotation.** There is none to test
  ([node-security-limitations.md](node-security-limitations.md) §3.1, #262).
- **Network grants beyond the proxy's verdicts.** The suite proves a network manifest is
  refused on a node without `--network-allowlist`, that an offline workload has no route
  off the host, and that an allowlisted attempt's proxy allows exactly the listed hosts,
  refuses the rest, is recorded, and pauses and stops with the attempt
  (node-acceptance.md §2.2). It does not prove a transfer with a real upstream (the
  allowed case accepts the proxy's `200` and `502` alike, and needs only name resolution
  on the runner), an in-sandbox relay for `HTTP_PROXY` clients, or any credential (#267).
- **Result return beyond the declared, bounded result.** The suite proves that a node
  started with `--output-return` returns exactly the stream heads and declared files the
  manifest asked for, marks truncation, matches the digests on the host, refuses an
  escaping path and follows no symlink, and keeps the result across a restart
  (node-acceptance.md §2.3). It does not exercise the 1 MiB and 8 MiB ceilings
  themselves (the unit tests do), a result near the 16 MiB answer bound, or a workspace
  export, which does not exist (node-security-limitations.md §3.2).
- **Load, capacity, concurrency.** One workload at a time; the registry, pause and
  state-file bounds are unit-tested, not exercised under load (#260).
- **Clock skew.** Envelopes are signed at the node's own clock.
- **Adversarial escape.** The isolation case checks what the sandbox denies an ordinary
  workload; it is not an exploit suite (node-acceptance.md §4).
- **Delegated cgroups.** The runner has none; the node uses none. The signal-only
  freeze is what is tested.
- **The release artifact itself.** The acceptance suite runs against binaries built by
  `cargo test` from the same commit, not against the tarballs or the image. Of the
  packaged `ward-node` and `ward-node-adapter` the release checks the version they
  report and that `--help` runs.
- **TamperWard verdicts.** The suite says what the node did; certification is the
  external control plane's (ADR-0029).
- **Verification on the install path.** `verify-manifest.sh` runs in the release job on
  its own fresh signature, by an operator by hand, and inside `install.sh`, which fetches
  it at the release tag and reports ADR-0028 §5's states — `downloaded`,
  `digest-checked`, `provenance-verified`, or `provenance-missing` and
  `verifier-unavailable` for a checksum-only install it never calls verified, refusals
  under the verifier's own exit codes ([install.md](install.md) §1). That covers the
  runtime tarball only: the node tarball is an operator install, the image's release
  stage does not run the verifier, `wardos-update` runs it only on the release manifest
  of the candidate image's version — evidence about that release's tarballs, shown next
  to the image's own `provenance-missing` (desktop.md "Update states") — and the
  tarballs carry no signature of their own. The signing step has run on no published release yet (v0.4.1 is the
  latest), so `install.sh` has installed nothing as `provenance-verified` either; the
  first `v*` tag after it landed exercises both for real, and §4 says what to check then.

## 4. Before tagging a release with node changes

The release PR of CONTRIBUTING.md ("Versioning") is where these are checked and
recorded in its verification section. None of them is automated by the release
workflow.

1. **The protocol window.** `WARD_NODE_PROTOCOL` and the marker in compatibility.md
   agree (the `docs` job is green on the release commit), and compatibility.md §1 lists
   every minor the release serves. If the window moved since the last release, the
   release PR says so, and compatibility.md §4 tells control planes the upgrade order.
   The release workflow then records that marker's window in the published manifest
   (§2); after the release, `jq .node_protocol_window` on
   `wardos-<version>-manifest.json` names the window the release PR announced.
2. **The acceptance table.** The `verify` run on the release commit shows
   `acceptance: 16 passed, 0 failed` in the step summary of "ward-node cross-system
   acceptance verdicts". Link that run from the release PR.
3. **The contract's status line.** node-integration.md §1 names the protocol revision
   and the ADR-0030 steps the release implements, and every "not implemented yet" it
   lists is still true (or the line is updated in the same release PR).
4. **The limitations.** node-security-limitations.md §3 matches what the release ships:
   a limitation closed since the last release is removed, a new one is added, and each
   "no issue yet" still has none or now names its issue.
5. **The documents ship.** `docs/` is copied into both tarballs by the release
   workflow; the node documents they carry are therefore the ones on the release
   commit. Nothing to do unless a document was moved.
6. **The node builds `--locked`.** `cargo build --release --locked -p ward-node -p ward-node-client`
   succeeds on the release PR's head (the release workflow repeats it per architecture
   and refuses to publish without both binaries); `ward-node`'s `--help` and
   `ward-node-adapter`'s `--help` print the flags of node-integration.md §2.1 and
   §11.4, and `--version` of each prints the version the tag will carry.
7. **The manifest signature, after the release.** `gh release download <tag> --pattern
   'wardos-<version>-manifest.json*'`, then `scripts/release/verify-manifest.sh
   wardos-<version>-manifest.json wardos-<version>-manifest.json.sigstore.json --tag
   <tag>` ends with `state=provenance-verified`; record that line in the release PR. A
   release created by a dispatch from a branch has no bundle until `release.yml` runs on
   the tag (release-manifest.md); `cause=provenance-missing` then means that run is
   still owed, not that the release is bad.
