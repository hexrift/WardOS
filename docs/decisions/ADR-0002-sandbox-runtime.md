# ADR-0002 — Agent sandbox runtime: rootless OCI container via crun

## Decision
`wardd` generates an OCI runtime spec per session and executes it with **crun**. The
container is rootless (user namespace with a per-project subuid range), with mount, PID,
network, IPC, UTS and cgroup namespaces, a baseline seccomp profile, empty capability
bounding set, and a composefs/overlay root built from pinned tool-image layers plus the
project environment's writable upper. `ward-agent` is PID 1 (ADR-0003).

## Alternatives
1. **crun from a generated spec** (selected).
2. **Podman as the driver** (`podman run` with flags).
3. **bubblewrap** (as Claude Code's own sandbox uses).
4. **systemd-nspawn**.
5. **Direct syscalls from Rust** (`clone3`, `mount`, `pivot_root`, no OCI runtime).
6. **microVM** (Firecracker / cloud-hypervisor / libkrun) for the agent.
7. **gVisor**.

## Advantages
- crun is the fastest mainstream OCI runtime (C, ~ms startup), understands rootless,
  cgroups v2, seccomp (incl. user notification), and is packaged in Fedora.
- OCI spec keeps `wardd`'s privileged surface declarative and reviewable; image layers
  are shared with the verifier and the portable runtime.
- Nested rootless Podman inside the sandbox is a known configuration.

## Disadvantages
- Landlock is not in the OCI runtime spec, so inner hardening needs `ward-agent`.
- Podman-level features (image pulls, storage) still needed for the CAS; `wardd` uses
  `containers-storage` via the `podman` CLI/library for image management only.
- Direct-syscall approach (5) would be faster still and avoid a C dependency, but
  reimplements a runtime and its CVE history.

## Security consequences
- Kernel-LPE remains the residual risk (threat model §9). Mitigated by seccomp
  (no `bpf`, `keyctl`, `userfaultfd`, `io_uring`, mount family, module/kexec/reboot,
  foreign `ptrace`), no devices, no capabilities, `NoNewPrivs`, Landlock.
- Unprivileged userns must be enabled on the host; WardOS ships it enabled and hardened
  (`kernel.unprivileged_userns_clone=1`, user namespace depth limited to 2 so nested
  Podman works but deeper nesting fails).

## Performance consequences
- Expected fresh start < 60 ms for the runtime portion; total `ward claude` warm path
  < 150 ms (E-06). Persistent, frozen sandboxes resume in the tens of ms.

## Why selected
Podman-as-driver adds a process and parsing layer on the critical path and its CLI is not
a stable API. bubblewrap lacks cgroup integration and OCI image layers. nspawn is
root-oriented. microVMs cost 200–500 ms startup, complicate GPU/device/nested-container
support and are not needed for the agent when the verifier is the asset that needs the
strongest tier (ADR-0004). gVisor's syscall compatibility gaps break toolchains.
Direct syscalls remain a Phase 2+ optimisation if E-06 shows crun on the critical path.

## How it will be validated
E-01 (hostile workload, ST-001..004/011/013/014/015), E-06 (start latency). youki is
benchmarked alongside crun as a Rust alternative; selection by measurement.

## Addendum (Phase 1): bubblewrap dev/nested backend

`crun` cannot manage cgroups inside a nested/CI environment with hybrid (v1+v2)
cgroups, where it exits with `cgroups in hybrid mode not supported`. The Phase 1
prototype therefore also carries a **bubblewrap** backend (`ward-daemon::sandbox`)
that provides the same *filesystem and network* isolation the Phase 1 guarantees
depend on: the worktree is the only writable host path, host home and secrets are
never mounted, and egress is an isolated network namespace (loopback only) unless
policy widens it. `crun` with the generated OCI spec remains the production-host
backend (ADR unchanged); bubblewrap is the portable/nested path and is what
`ward selftest` and the README screenshot run on. This is defence-by-construction
(what is not mounted cannot be reached), not the full seccomp/Landlock defence in
depth the OCI path adds; the two are complementary and both are validated by the
ST-* suite.
