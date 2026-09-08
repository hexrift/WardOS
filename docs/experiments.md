# Highest-Risk Assumptions and Required Experiments

Status: Phase 0. Nothing in this list is "decided" until its experiment has a recorded
result under `experiments/<id>/RESULT.md`. Experiments are throwaway code; they live in
`experiments/`, not in `crates/`.

## 1. Highest-risk architectural assumptions

Ranked by (probability the assumption is wrong) × (cost if wrong).

| Rank | Assumption | If wrong… | Experiment |
| --- | --- | --- | --- |
| 1 | Rootless userns + mount/pid/net ns + seccomp + Landlock is a boundary developers will accept as "the host is outside the agent's authority", given kernel-LPE residual risk | Need microVM tier for the agent, which costs startup latency and complicates device/GPU/nested-container stories | E-01, E-03 |
| 2 | Snapshotting a real worktree can be made fast enough (Btrfs path) that users never disable it | Entry/candidate state model becomes optional → TamperWard trust story weakens | E-02 |
| 3 | Nested rootless Podman inside the sandbox is workable for typical `docker compose` dev stacks | Need a container broker with a restricted API, which is a large component | E-04 |
| 4 | eBPF + fanotify + proxy capture is low-overhead and complete enough for Live mode | Fall back to hooks-only (origin=Agent, forgeable) for most events | E-05 |
| 5 | Sandbox warm start < 150 ms is achievable with crun + prepared layers | Users run agents outside `ward`; the product fails in practice | E-06 |
| 6 | Agents' own model-API credentials can be brokered via gateway/base-URL injection without breaking the agents | The one credential every session needs would sit long-lived in Zone 3 | E-07 |
| 7 | Restricted egress does not break the agents (their endpoints, OAuth, MCP) | Every user flips to `unrestricted` | E-08 |
| 8 | Fedora bootc + Hyprland + Secure Boot (shim) + TPM2 LUKS + rollback works end-to-end on the reference laptops with the *stable* backend, and the sealed/composefs backend is close enough to adopt in Phase 7 | Change base (NixOS/custom) late, which is very expensive | E-09 |
| 9 | A Rust layer-shell UI (iced/GTK4-rs) can hit < 16 ms launcher and < 0.5 % idle | Shell toolkit change | E-10 |
| 10 | Step-through "hard hold" on file writes is possible without unacceptable overhead | Step-through for writes stays best-effort via hooks | E-11 |
| 11 | TamperWard can consume snapshot IDs and Zone 2 verification without redesign | Integration duplicates TamperWard's pristine mechanism | E-12 |

## 2. Experiments

Each has: hypothesis, method, pass criterion, and what changes if it fails.

### E-01 Agent isolation baseline
**Hypothesis.** A `wardd`-built sandbox (ADR-0002/0003) defeats ST-001..004, 011, 013, 014,
015 with a hostile workload that has unlimited time and a full toolchain.
**Method.** Build the sandbox with a hand-written spec + `crun`; run the security-test
workload (shell + Python + C) attempting each escape; also run known public userns/overlay
PoCs that are fixed in the target kernel to confirm the seccomp/Landlock layers give
defence-in-depth.
**Pass.** 0 successes; all attempts produce enforcement-origin events.
**If fail.** Tighten the profile; if unfixable with namespaces, escalate to E-03.

### E-02 Snapshot performance
**Hypothesis.** On Btrfs, entry/candidate capture of a 200k-file, 1 GB worktree stalls the
agent < 100 ms and completes hashing in < 2 s warm; frozen-copy fallback on ext4 stalls
< 3 s.
**Method.** Rust prototype with `cgroup.freeze`, Btrfs subvolume snapshot, parallel BLAKE3
over the ro snapshot; compare with mtime/size-cached incremental hashing.
**Pass.** Numbers above on the reference desktop; ST-008/018 (TOCTOU) pass.
**If fail.** Make Btrfs mandatory for `/work` (loop-mounted Btrfs image for the
portable runtime), or move to incremental-only hashing with a tree cache.

### E-03 Verifier tier: namespaces vs microVM
**Hypothesis.** A Zone 2 verifier in namespaces with a distinct uid satisfies ST-005/006/
019; a libkrun/cloud-hypervisor microVM adds < 400 ms startup and could be the default
when KVM is available.
**Method.** Implement both; run hostile build scripts inside; measure spawn latency and
memory.
**Pass.** Both pass the tests; microVM overhead recorded.
**Decision.** If microVM overhead < 400 ms, default to microVM for the verifier on
hardware with KVM; namespaces otherwise. The agent sandbox stays namespaces-based in 0.1.

### E-04 Nested rootless containers
**Hypothesis.** Rootless Podman in the sandbox (nested userns, native overlayfs in userns,
`/dev/fuse` optional, pasta/slirp not needed because the sandbox netns is already
constrained) runs a Postgres + Redis + Node compose stack.
**Method.** Try three real-world compose files; measure start time; run ST-004/013/014
from *inside* a nested container.
**Pass.** All three stacks run; escapes land inside the outer sandbox at worst.
**If fail.** Design the container broker (Phase 2 scope grows).

### E-05 Event capture overhead and completeness
**Hypothesis.** eBPF exec tracing + fanotify on `/work` + proxy logs cost < 2 % on a
`cargo test` / `npm test` workload and miss no exec or file-modify events.
**Method.** aya or libbpf-rs prototype; compare against `strace -f` ground truth on a
recorded workload; measure with `perf stat`.
**Pass.** < 2 % overhead, 100 % of execs and closes-after-write observed, argv truncation
recorded.
**If fail.** Reduce Live mode to exec + net + hooks; document.

### E-06 Sandbox warm start
**Hypothesis.** With pre-pulled layers and a prepared spec, `ward claude` reaches agent
PID 1 exec in < 150 ms; a frozen-and-thawed persistent sandbox resumes in < 30 ms.
**Method.** Time each step of architecture §4 with tracing; compare crun vs youki; compare
fresh-create vs freezer-resume.
**Pass.** < 150 ms fresh, < 30 ms resume on reference hardware.
**If fail.** Persistent per-project sandboxes become the default and are pre-warmed on
`cd` via a shell hook.

### E-07 Model-API credential brokering
**Hypothesis.** Claude Code (`ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN` gateway mode),
Codex, Gemini CLI and Aider all work with their API host proxied through `ward-proxy` with
the user's real credential injected in Zone 0 and a placeholder in Zone 3.
**Method.** Run each agent's interactive and headless mode through the gateway; exercise
streaming, tool use, OAuth refresh paths (or confirm the OAuth token can be replaced by a
gateway token entirely).
**Pass.** All four work with no long-lived credential file mounted into Zone 3.
**If fail.** Per-agent exception: mount a *sandbox-specific* credential dir
(`CLAUDE_CONFIG_DIR`) containing only a short-lived token minted per session, if the
provider supports it; document the gap.

### E-08 Restricted egress compatibility
**Hypothesis.** The `development` network mode (VCS hosts, registries, model API host,
agent-specific auth hosts) with nonessential-traffic disabled lets each agent operate
without errors.
**Method.** Enumerate each agent's required and optional hosts; run typical sessions in
`development` mode; log every denied host.
**Pass.** No functional breakage; denials are telemetry/update hosts only.

### E-09 Base OS chain on reference hardware
**Hypothesis.** A Fedora bootc image with Hyprland, `ward*`, Secure Boot via Fedora shim,
TPM2-bound LUKS2 (systemd-cryptenroll, PCR 7 + 11 where UKI available), and
`bootc rollback` works on the reference desktop and one reference laptop; the
composefs/sealed backend boots on the same hardware in a test deployment.
**Method.** Build with bootc-image-builder; install; run RT-001/RT-002; break an update
deliberately; suspend/resume; measure boot.
**Pass.** Both RT tests pass on the stable backend; sealed backend result recorded.
**If fail.** Re-open ADR-0001 with data.

### E-10 Shell toolkit latency
**Hypothesis.** A Rust layer-shell bar + launcher (iced with `iced_layershell`, vs
GTK4-rs with `gtk4-layer-shell`) meets < 16 ms launcher visible and < 0.5 % idle CPU.
**Method.** Two minimal prototypes rendering the command centre and the bar; measure with
compositor frame timing.
**Pass.** One candidate meets both; select it.

### E-11 Hard holds for step-through
**Hypothesis.** `fanotify` permission events (`FAN_OPEN_PERM`) on `/work` from Zone 0 can
hold a write for user approval with < 1 ms overhead when not holding.
**Method.** Prototype; test with editors and build tools that write many files.
**Pass.** Holds work; unheld writes unaffected.
**If fail.** Step-through for writes remains hook-based (origin=Agent); FUSE evaluated
later.

### E-12 TamperWard composition
**Hypothesis.** TamperWard's pristine verification can be driven from a WardOS snapshot
ID and executed in Zone 2 with a trusted test bundle, without changing TamperWard's policy
semantics.
**Method.** Walkthrough with the TamperWard spec; prototype adapter; run the demo
scenario in `examples/ward-demo`.
**Pass.** Demo scenario passes end-to-end with the DENIED line originating from
TamperWard and VERIFIED from Zone 2.

## 3. What must be proven before building the distro

Before any Phase 6 (image) work starts, these must have recorded PASS results:
**E-01, E-02, E-05, E-06, E-07, E-08, E-12.** E-03, E-04, E-09, E-10 and E-11 must have
recorded results (pass or documented fallback), because their outcomes shape the image
contents.


## 4. Critical questions and where they are answered

| Question | Answered by |
| --- | --- |
| Can the agent genuinely be prevented from affecting the verifier? | E-01, E-03, ST-005/006/019 |
| Can entry state remain trustworthy even if the agent controls the repository and `.git`? | E-02, ST-008/018, [`snapshots-and-git.md`](snapshots-and-git.md) |
| Can useful temporary credentials be provided without leaking long-lived secrets? | E-07, ST-012/024 |
| Can agents run development containers without host-root-equivalent Docker authority? | E-04, ST-004 |
| Can all this isolation remain nearly invisible to developers? | E-06, E-08, Phase 2 usability review |
| Can project and agent environments start fast enough that users do not bypass them? | E-06, performance CI |
| Can the OS always roll back after a broken upgrade? | E-09, RT-002 |
| Can the project realistically support a sufficiently useful laptop set? | Phase 9 matrix; E-09 on two devices first |
| Does OS integration simplify and strengthen TamperWard rather than duplicate it? | E-12, TamperWard open questions in [`tamperward-integration.md`](tamperward-integration.md) |

## 5. Recorded results (Phase 1)

* **E-01 (isolation baseline) — partial PASS.** The bubblewrap prototype blocks
  ST-001..004, ST-011 and ST-013..015 with a hostile workload (`ward selftest`, 8/8),
  and CI reproduces this on every PR. `ward-agent` adds Landlock + seccomp inside the
  sandbox (verified on the CI runner: empty capability sets, `Seccomp: 2`, denied
  syscalls fail with EPERM, writes outside the rw set fail with EACCES). The full crun
  path still needs a non-nested cgroups-v2 host.
* **E-02 (snapshot performance) — measured.** On a 4 vCPU VM, ext4, kernel 6.18,
  200,000 files / 1 GiB (261,827 entries): cold capture 3.47 s, warm 1.46 s, cached
  incremental after touching 100 files 0.96 s. The warm ext4 hashing budget is met;
  cold misses the < 3 s target by ~0.5 s and CAS ingest is disk-bound. Btrfs
  subvolume snapshot and reflink ingest could not be measured (no Btrfs on the host).
  Full data and the measuring implementation are on branch
  `phase-1/ward-snapshot-full` (`experiments/E-02/RESULT.md`).
* **E-06 (sandbox warm start) — could not measure here.** `crun` cannot manage
  cgroups in the nested CI environment; the spike records `CANNOT-MEASURE-HERE` with
  the exact commands to run on a real cgroups-v2 host
  (`experiments/E-06-warm-start/RESULT.md`).

### Parallel alternative implementations

Some Phase 1 crates were built twice by parallel agents. The merged versions are
canonical; two more thorough alternatives are kept on branches for a later,
deliberate upgrade rather than mid-stream churn:

* `phase-1/ward-snapshot-full` — adds a real cgroup-v2 freezer, reflink ingest,
  ctime-based cache anti-forgery, and the E-02 measurements above (94 tests).
* `phase-1/ward-policy-alt` — adds custom-allowlist intersection, explicit
  unrestricted opt-in, and golden hash fixtures (102 tests).

These also carry documentation corrections (Decision-order and network-spelling
consistency in the policy docs) to fold in with the upgrade.
