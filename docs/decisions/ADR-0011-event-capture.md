# ADR-0011 — Event capture: kernel-origin facts, agent-origin claims

## Decision
Enforcement-grade events come from Zone 0 mechanisms: **eBPF** tracepoints
(`sched_process_exec/exit`, filtered by session cgroup) for commands; **fanotify** on the
`/work` mount for file modification (and open, optionally, in Live mode); the **proxy
log** and nflog for network; **seccomp user-notification** for a small set of denied
syscalls. Agent hooks (Claude Code `PreToolUse`/`PostToolUse`/`PermissionRequest`, Codex
equivalents) produce `origin=Agent` records used for semantics and step-through UX, never
for enforcement decisions.

## Alternatives
- ptrace/strace of the agent tree.
- Hooks only.
- auditd.
- LD_PRELOAD shims.

## Advantages
- Low overhead, unforgeable by Zone 3, uniform across agents.
- Hooks add intent ("Edit tool on file X") that the kernel cannot see.

## Disadvantages
- eBPF needs `CAP_BPF`/`CAP_PERFMON` in `wardd` and a kernel with BTF; fanotify needs
  `CAP_SYS_ADMIN` in the host mount namespace (both are `wardd` capabilities anyway).
- File *reads* are expensive to capture fully; Live mode shows opens, not reads, and says
  so.

## Security consequences
- The observer can never be fooled into showing a fabricated enforcement fact; forged
  agent claims are visibly labelled (ST-016).

## Performance consequences
E-05 target < 2 % overhead on test-heavy workloads; propagation < 25 ms p99.

## Why selected
ptrace is too slow and fragile; hooks alone are forgeable; auditd is host-global and
noisy; LD_PRELOAD is trivially bypassed.

## How it will be validated
E-05 against `strace -f` ground truth; ST-016.

## Addendum (Phase 1): inotify for file events

The Phase 1 runtime captures file activity with a recursive **inotify** watch of the
worktree for the duration of each command (kernel-origin, no privilege needed), mapping
create / close-write / delete / move / attrib to `FileChangeKind` and emitting
`FileRead` only in Live/StepThrough. fanotify remains the target for mount-wide,
permission-capable capture once `wardd` runs as the privileged `ward` user (it needs
`CAP_SYS_ADMIN`); exec capture is still supervisor-emitted per command until the eBPF
tracepoint path (E-05) lands. The origin semantics are unchanged: these are
enforcement facts, hook records stay claims.
