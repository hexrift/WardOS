# Performance

Status: living document; the project's phase is in docs/status.toml and the README.
Performance is a release criterion. Every number below is a *budget* to
be confirmed or revised by measurement; no number is published without the
reproducibility record in §4.

## 1. What we optimise

Interaction latency and perceived responsiveness, not benchmark boot time. The order of
priority when budgets conflict:

1. Input-to-pixel latency for the shell (launcher, workspace switch, bar updates).
2. Agent/sandbox warm start (if it is slow, users bypass it, and the security model
   collapses in practice).
3. Observer event latency (if it lags, the user stops trusting it).
4. Terminal and editor startup.
5. Boot, login, resume.
6. Installer.

## 2. Budgets (initial)

| Metric | Budget | Measured how |
| --- | --- | --- |
| Launcher visible | < 16 ms | key event → first frame with content, via compositor timestamp |
| Workspace response | < 8 ms | key event → frame |
| Terminal visible | < 50 ms | key → first prompt frame |
| Bar state update | < 1 frame after event | event ts → frame |
| Observer event propagation | < 25 ms p99, 8 ms median | kernel/proxy ts → subscriber receive |
| Agent sandbox warm start | < 150 ms | `ward claude` exec → agent PID 1 exec (steps 1–9 in architecture §4) |
| Project environment warm resume | < 300 ms | `cd`+`ward status` → READY |
| Entry snapshot stall (Btrfs path) | < 100 ms agent-visible freeze on a 200k-file worktree | freeze → thaw |
| Verification startup | < 500 ms to verifier PID 1 (excluding materialisation of large trees, reported separately) | |
| `ward status` | < 10 ms | wall time |
| Idle shell CPU | < 0.5 % | 60 s average, no agent |
| Idle RAM (desktop ready, no agent) | < 700 MB | after login + 60 s |
| Boot to login | < 4 s on reference NVMe hardware | firmware handoff → greeter |
| Login to desktop ready | < 500 ms | |
| Resume from suspend to unlocked-usable | < 1 s | |
| Install (Phase 8 target) | < 45 s; aspirational < 30 s, with FDE, verification, durability | ISO boot → first reboot into installed system |

## 3. Methodology

* **Fixed reference hardware** (see `hardware/`), fixed firmware version, fixed kernel,
  fixed image digest. Each result records all of these plus filesystem, storage device
  model, CPU, GPU, RAM, thermal state (run after 5-minute idle), power source.
* **Warm vs cold** is always stated. Cold = first run after boot; warm = median of 20
  runs after 3 discarded warm-ups.
* **Timestamps from the kernel or compositor**, not from the process under test, for any
  input-to-pixel metric. Hyprland's frame-timing output or a wlroots presentation-time
  feedback hook is used; a hardware photodiode rig validates the software path once.
* **Percentiles**: report p50 and p99 for latency; mean and stddev for throughput.
* **No benchmark-specific code paths.** If a fast path is added, it is on by default for
  users. Any "benchmark mode" flag is a bug.
* **Noise tolerance in CI**: a regression is flagged when p50 moves > 10 % *and* > 2 ms
  absolute (or > 5 % for anything > 100 ms), across two consecutive runs.

## 4. Reproducibility record (mandatory with any published number)

```yaml
wardos: 0.1.0-tp1 (image sha256:…)
kernel: 6.x.y-…
hardware: Framework 13 AMD (7840U), 32 GB, WD SN850X 1 TB
firmware: 3.05
filesystem: btrfs (zstd:1)
gpu: amdgpu, 780M
power: AC
thermal: idle 5 min before run
runs: 20 (3 warm-up discarded)
tool: ward-bench 0.1.0
```

## 5. Tooling

**Status, as of #150: the CI-measurable subset is real; the hardware/compositor subset
is still planned.** `ward benchmark` (crate `ward-bench`, fixtures under `benchmarks/`)
runs today, against pinned fixtures, and emits versioned JSON plus the human report
below. It does **not** exist as a `ward-bench` binary of its own — it is a `ward-cli`
subcommand backed by the `ward-bench` library crate, since that turned out to be the
shape that needed no daemon and no second binary to install. What it measures, in
process, with no daemon and no `ward` CLI subprocess in the timed path itself:

* **`sandbox_start`** — `Session::run(["/bin/true"])`, the exact code path `ward run --
  true` takes (bubblewrap spawn, proxy/hook sockets, the inotify watch), against the
  budget "Agent sandbox warm start" (§2).
* **`ward_status`** — `SessionMeta::current` plus `render::status_panel`, against
  "`ward status`" (§2). No bubblewrap needed; always measurable.
* **`verifier_spawn`** — `Session::verify()` with a no-op (`true`) verify command over a
  tiny fixture: candidate capture, materialisation and sandbox spawn, without a real
  build/test run. A proxy for "Verification startup" (§2), not an isolated PID1-exec
  timestamp.
* **`snapshot_digest_{cold,warm}`** and **`snapshot_capture_{cold,warm}`** —
  `ward_snapshot::digest_worktree`/`SnapshotStore::capture` over a pinned ~220-file
  fixture (`benchmarks/fixtures/snapshot-digest/`), cold (first run) and warm (median of
  N after discarded warm-ups), mirroring the cold/warm split `docs/experiments.md`'s E-02
  uses. Always measurable; no sandbox involved.

`sandbox_start` and `verifier_spawn` need a working bubblewrap and user namespace; where
that is unavailable (this repository's own nested dev sandbox, some hardened hosts) they
report `status: "unsupported"` with a reason instead of failing the run or being
silently dropped. Every `docs/performance.md` §2 budget this tool does not implement at
all — everything needing Hyprland/Waybar (#84) or the reference rig (#99): launcher,
workspace, terminal and bar latency, observer event propagation (producer-to-subscriber,
not just row-rendering — deferred pending a cheap way to add a live subscriber),
project warm resume, the Btrfs entry-snapshot stall, idle CPU/RAM, boot/login/resume and
install — appears in the report as `status: "not_implemented"` with a reason, never
omitted.

Real sample output (`ward benchmark`, run from the repository root; numbers are from a
4 vCPU CI-shaped VM, not the reference hardware in §4 — a CI run's own environment block
in the JSON is the reproducibility record for these, not the yaml in §4):

```text
metric                         p50       p99       n    status notes
sandbox_start              50.79ms   52.59ms      20  measured warm (budget 150 ms)
ward_status                 0.02ms    0.03ms      20  measured warm (budget 10 ms)
verifier_spawn             24.77ms   26.22ms      20  measured warm (budget 500 ms)
snapshot_digest_cold        2.49ms    2.49ms       1  measured cold
snapshot_digest_warm        1.77ms    1.94ms      20  measured warm
snapshot_capture_cold     112.58ms  112.58ms       1  measured cold
snapshot_capture_warm       3.33ms    3.80ms      20  measured warm
launcher_visible                 —         —       —  not-impl needs a real Hyprland/Waybar compositor session; see #84
…
```

CI (`.github/workflows/verify.yml`, `benchmark` job) runs this subset on every PR and
push to `main` and retains the JSON as a build artifact (90 days) — no pass/fail
regression gate yet: `docs/performance.md` §3's own noise-tolerance rule and #150's
acceptance both say to introduce a gate only after variance is measured across enough
real runs, not before. `--samples`/`--warm-up` default to §3's own 20/3; `--fixtures`
points at a fixtures root other than `benchmarks/fixtures` (rarely needed).

Not yet implemented, and deliberately out of this pass: opt-in replay statistics for
E-13 (`docs/experiments.md`), the E-14 counterbalanced usability study, and any
hardware/compositor measurement (reuse #84 for compositor evidence, #99 for reference
hardware).

## 6. Installer performance plan (Phase 8, after correctness)

Only after the installer is correct and tested for FDE, Secure Boot and rollback:

1. Profile the serial install (where does time go: decompression, write, EFI, key
   generation, initramfs, user setup).
2. Convert stages into a DAG with explicit dependencies; run independent stages
   concurrently (filesystem deployment ‖ EFI ‖ user setup ‖ key generation).
3. Deploy a prebuilt image (bootc install / raw image stream) rather than package-by-package.
4. Evaluate zstd level and parallel decompression, BLAKE3/Merkle verification concurrent
   with writing, sequential write batching, io_uring. Adopt only what measurement justifies.

Omarchy's fastest published installs are ~35 s on the fastest hardware and ~1–2 minutes
typically; those are the reference points, with FDE and verification kept on.

## Measured so far

| Path | Median | Where |
| --- | --- | --- |
| `ward run -- true`, daemon-backed, bubblewrap backend, release build | 32 ms | 4 vCPU Xeon 2.8 GHz, `examples/ward-demo` (E-06 record in [`experiments.md`](experiments.md)) |
| bare `bwrap … -- true` | 6 ms | same host |
| `ward status` | 3 ms | same host |
| Observer event propagation (quiet single file write, inotify → drained) | p50 20 ms, p99 20 ms (60 samples over 30 writes; inotify reports two events per write) | 4 vCPU Xeon 2.1 GHz VM, debug build, `ward-daemon::observe::tests::a_quiet_write_is_drained_within_about_one_poll_tick` |

The warm-start budget is 150 ms; the remaining cost is the sandbox itself, the shim,
the per-launch sockets and the entry checks, not any fixed wait.

The observer row replaces an earlier fixed 250 ms drain interval that had never been
measured against this budget: it made the interval, not `inotify` or the queue, the
dominant term for a quiet write, at up to ~10x the 25 ms p99 target regardless of how
fast the rest of the path was. `DRAIN_INTERVAL` is now tied to the same
`WAIT_POLL` tick (`crates/ward-daemon/src/sandbox.rs`) that already drives the live
drain (`crates/ward-daemon/src/session.rs`), so a quiet observation now waits about
one tick rather than a quarter second. The 20 ms figure is that tick's own floor, not
an inotify or queue cost — reaching the 8 ms median in §2 would mean tightening
`WAIT_POLL` itself, which drives every live-drain tick during a launch and is out of
scope here. Like the other rows in this table, it carries its own reproducibility
record in the "Where" column rather than a full §4 block — the exception §5 already
states for this section until `ward-bench` lands — on a debug build and non-reference
hardware, reproducible via `cargo test -p ward-daemon --lib observe:: -- --nocapture`.

