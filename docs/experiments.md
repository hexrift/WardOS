# Highest-Risk Assumptions and Required Experiments

Status: living document; the project's phase is in docs/status.toml and the README.
Nothing in this list is "decided" until its experiment has a recorded
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
| 12 | The default policy asks a human rarely enough, and about the right things, that approvals stay decisions rather than reflexes | Habituation: the user approves everything, the approval surface is a formality and the sandbox is the only real control | E-13 |
| 13 | A real task under WardOS costs the developer little over the bare agent and leaves them able to say what the agent could reach, used and changed | Users run agents outside `ward`, or inside it without reading what it shows; the product's legibility claim is unfounded | E-14 |

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

### E-13 Human approval load
**Hypothesis.** None yet: this experiment produces the numbers a hypothesis would need
([ADR-0019](decisions/ADR-0019-authority-freshness-intervention.md) decision 5).
Approval load is a security metric because a prompt the user answers without reading
is not a control, and the published evidence says that is where prompts go: Anthropic
reports that sandboxing cut Claude Code's permission prompts by 84 % and that users
approve about 93 % of what they are asked; usable-security research finds repeated
warnings habituate.
**Metrics.** From the session logs, per session and aggregated over the corpus:
* approvals per agent-hour;
* approve rate and deny rate;
* decision time, from `CapabilityRequested` to `CapabilityDecided`;
* allow-once followed by the same request (the same destination, credential or path
  asked again within the session);
* allow-session rate;
* requests contained by the sandbox (denied by the manifest, never shown to a human);
* requests caused by missing policy (an `ask` that a policy line would have settled);
* switches to unrestricted network;
* launches outside `ward` (the agent run on the same host without a session, from the
  host's shell history and the agents' own logs, where the user provides them).
**Method.** Every `CapabilityRequested` and `CapabilityDecided` record in the log,
with the `NetworkDenied` and `CredentialGranted` records around them, over a corpus of
real sessions: the maintainers' own development sessions first, then volunteered logs.
The corpus is read with `ward replay --json` over each sealed log and the metrics are
derived from the records, never from the observer's counters. The intended tool is
`ward replay --stats`, which would print this list for one log or a directory of logs;
it is not implemented, and the experiment does not wait for it (a script over
`--json` is enough for the first corpus).
**Pass.** No target until the data exists.
**What the result changes.** The profiles of decision `deferred` in ADR-0019 (which
task-shaped network profiles exist, and what each asks); the step-through defaults
(which tools hold by default and which are silent); the approval layout (what the
three blocks show first, and whether allow-once is offered at all for a request the
data says is always followed by the same one).

### E-14 Agent workstation usability
**Hypothesis.** None yet, for the same reason as E-13. The four comprehension
questions at the end are the product's real acceptance test.
**Metrics.** Per task, bare agent against the WardOS default policy:
* task completion;
* time to completion;
* interruptions (every time the developer had to act for the agent to continue);
* prompts shown;
* legitimate work blocked (a denial the developer judged wrong);
* retries by the agent after a denial or a hold;
* time to `✓ VERIFIED`;
* after the task, whether the developer can say, without looking again: what the agent
  could reach, which credentials it used, what it changed, and whether the current
  state is verified.
**Method.** Ten to twenty real tasks from the maintainers' backlog and from
`examples/`, each run twice by the same developer in counterbalanced order: once with
the agent bare on the host, once inside `ward` with the default policy and the desktop
approval surface. Everything is taken from the session log and a stopwatch, except the
four questions, which are asked aloud after each task and scored against the log.
**Pass.** No target until the data exists.
**What the result changes.** The same three things as E-13, from the other side: the
profiles of decision `deferred` (whether a task-shaped profile removes the
interruptions a task showed), the step-through defaults (whether a hold the developer
never needed should be off), and the approval layout (which block the developer read,
by what they could answer afterwards). A task where the bare agent finishes and the
WardOS one does not is a bug report before it is a data point.

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
| Can all this isolation remain nearly invisible to developers? | E-06, E-08, E-14 |
| Does the default policy ask a human rarely enough, and about the right things, that an approval stays a decision? | E-13, E-14 |
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
  `phase-1/ward-snapshot-full` (`experiments/E-02/RESULT.md`). The TOCTOU half of the
  pass criterion (ST-008/018) is now a standing regression: the candidate is captured
  with the session's sandbox frozen (`pause::CaptureFreeze`), proven atomic against a
  concurrently writing agent by `candidate_capture_is_atomic_while_the_agent_writes`
  (see `docs/security-model.md` G5).
* **E-08 (restricted egress) — partial PASS.** From inside the sandbox, via the shim
  relay and the session proxy: `development` mode reaches `registry.npmjs.org` over
  HTTPS (`200`) and denies `10.0.0.1` and `169.254.169.254` (`403`); `localhost_only`
  denies `api.github.com`. Agent-specific host lists (Claude Code OAuth/API hosts) are
  allowlisted in `Development` and remain to be exercised with the real agents (E-07).
* **E-07 (model-API credential brokering) — partial PASS.** Claude Code 2.1.263 ran
  headless inside the session sandbox (`ward claude --dir examples/ward-demo -- -p …`)
  with `ANTHROPIC_API_KEY` held on the host and a placeholder in Zone 3. Its requests
  went placeholder → relay → session proxy → `/anthropic` gateway → TLS to
  `api.anthropic.com`, and the API answered `401 API key is invalid` for the
  deliberately invalid host key: the credential path is complete and the sandbox never
  saw a key. The `SessionStart` hook reported through `ward-agent hook` and was logged
  as a claim. Eleven `NET api.anthropic.com:443` rows are Claude Code's own retries on
  the 401. A full task with a valid key, streaming and tool use, remains to be run.
* **E-12 (TamperWard consumes snapshots and Zone 2 verification) — partial PASS.**
  `ward verify` runs entirely on the primitives §2 of `tamperward-integration.md`
  promises: candidate ids from the CAS, `cat` of pristine bytes for protected paths,
  a disposable verifier whose result lands in the evidence log with the config hash.
  No redesign of the snapshot or event model was needed. Open: the socket protocol
  (§4) so that the decisions are TamperWard's rather than `wardd`'s reading of the
  config, and the semantic rules.
* **E-06 (sandbox warm start, bubblewrap backend) — PASS for the current backend.**
  Release build, 4 vCPU Xeon 2.8 GHz, daemon-backed session on `examples/ward-demo`:
  `ward run -- true` (entry checks, proxy and hook sockets, shim, inotify watcher,
  events through the control socket) median **32 ms** (18–40 ms over 10 runs); bare
  `bwrap … -- true` 6 ms; `ward status` 3 ms. Before this measurement the same command
  took a constant 257 ms: the proxy's Unix acceptor polled its shutdown flag on a
  250 ms sleep and the file watcher slept 40 ms between drains. Both now park in
  `accept`/`poll(2)` and are woken explicitly. The `crun` backend of the original
  E-06 plan is still unmeasured here (below).
* **E-06 (sandbox warm start, crun) — could not measure here.** `crun` cannot manage
  cgroups in the nested CI environment; the spike records `CANNOT-MEASURE-HERE` with
  the exact commands to run on a real cgroups-v2 host
  (`experiments/E-06-warm-start/RESULT.md`).

## 6. Recorded results (Phase 6)

* **E-09 (base OS chain on reference hardware) — first boot, partial.** 2026-09-08,
  a Fedora laptop, QEMU/KVM with OVMF and virtio-gpu, the image built on
  the laptop with `image/build.sh` (podman) from commit 762d193 and written with
  `image/disk.sh --type qcow2 --user wardos` (the `--user` flag was removed later, in
  ADR-0027; disks now ship unprovisioned and create the user at first boot). The disk boots through UEFI to the
  desktop: tty1 autologin into Hyprland 0.56.2 (from the `mineiro/hyprland` COPR on
  Fedora 44), Waybar with the trust bar, foot as the terminal. Findings: Hyprland's
  error bar listed three options removed since the config was written
  (`gestures:workspace_swipe`, `dwindle:pseudotile`, `misc:vfr`), and a parse with the
  real binary then found the rest (`windowrulev2` and the old layer-rule form gone,
  `togglesplit` now a layout message); foot 1.25 deprecated `[colors]`. All fixed in
  #73, and `image/check-hyprland.sh` now parses the tree with the shipped Hyprland on
  every pull request. Also found on the way: a podman build mounts `/run/.containerenv`
  and `/run/secrets` where docker mounts `/run/systemd` (#65). Not yet recorded: the
  Plymouth splash's look, suspend and brightness keys, Wi-Fi on the laptop's own
  hardware, and the time from boot to `✓ VERIFIED` through `wardos-welcome`; those come
  with the next boot of `ghcr.io/hexrift/wardos:latest` and a bare-metal install from
  the v0.2.0 ISO.

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
