# Performance

Status: Phase 0. Performance is a release criterion. Every number below is a *budget* to
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

`ward benchmark` (crate `ward-bench`, `benchmarks/`) runs the suite and emits JSON plus
the human table:

```text
Install                  31.8s
Boot                      3.2s
Desktop ready            430ms
Launcher                  11ms
Terminal                  34ms
Agent warm start          91ms
Observer latency           8ms
Idle CPU                  0.4%
Idle RAM                  690MB
```

CI runs the subset that is meaningful in a VM (sandbox start, snapshot, event latency,
`ward status`, verifier spawn) on every PR and stores results as artifacts; the hardware
subset runs on the certification rig per release.

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

The warm-start budget is 150 ms; the remaining cost is the sandbox itself, the shim,
the per-launch sockets and the entry checks, not any fixed wait.

