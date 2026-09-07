# ADR-0009 — Rust for WardOS-owned services; single `wardd` process in 0.1

## Decision
All WardOS-owned long-running, privileged or security-sensitive components (`wardd`,
`ward` CLI, `ward-agent`, proxy, broker, snapshot engine, verifier broker, event bus,
observer, shell) are Rust. Shell scripts are limited to build glue, development helpers
and provisioning prototypes. In 0.1, `wardd` is one process with internal modules;
splitting broker/proxy/snapshot into separate less-privileged processes is a Phase 4+
hardening step, designed for now by keeping module boundaries as crates with typed
interfaces.

## Alternatives
- Go (fast to write, GC pauses, weaker type-level safety for capabilities).
- C for the runtime bits (crun is C; we use it but do not write more C).
- Multi-process privilege separation from day one.

## Advantages
- Memory safety in the privileged daemon; strong newtypes for `SessionId`, `SnapshotId`,
  `ImageDigest`, `Secret<T>`; `deny(warnings)`; excellent eBPF (aya), Landlock,
  seccomp, netlink, Wayland and TUI ecosystems.
- One process in 0.1 keeps latency low (no IPC on the warm path) and the codebase
  reviewable.

## Disadvantages
- Compile times; smaller contributor pool than Go.
- A single privileged process concentrates risk until privilege separation lands.

## Security consequences
- `#![forbid(unsafe_code)]` by default; documented `unsafe` only in sandbox/eBPF crates.
- Agent-originated bytes decoded only through bounded typed decoders.
- Fail-closed by construction: `Decision` has no default; unknown → `Deny`.

## Performance consequences
- Native performance on the warm path; no runtime GC.

## Why selected
Not ideology: the brief's requirements (privileged daemon, capability types, low latency,
no silent fallbacks) are exactly Rust's strengths, and the ecosystem coverage for the
specific kernel interfaces is good. Where an existing C component is best (crun, nftables,
Hyprland) it is used, not rewritten.

## How it will be validated
CI: `clippy -D warnings`, `cargo deny`, `unsafe` audit list; fuzzing of all Zone 3-facing
decoders (`cargo fuzz`) from Phase 1.
