# ADR-0003 — Inner hardening applied by `ward-agent`

## Decision
`ward-agent`, PID 1 inside the sandbox, applies before exec of the agent: a **Landlock**
ruleset (rw only `/work`, `/env`, `/tmp`, sandbox `$HOME`; ro elsewhere; socket dir
access limited to the control socket), a **final seccomp** filter (tighter than the OCI
profile; user-notification on `connect` to non-proxy addresses and on `ptrace`),
`PR_SET_NO_NEW_PRIVS`, and dropping any remaining capabilities. These are irreversible for
the process tree.

## Alternatives
- OCI-level only (no inner layer).
- LSM policy on the host (SELinux/AppArmor) targeting the container.
- FUSE filesystem for `/work` (policy at the filesystem layer).

## Advantages
- Defence-in-depth against mount-namespace mistakes and future kernel features exposing
  paths; Landlock rules cannot be relaxed by the agent.
- seccomp user-notification gives observation and deny decisions for selected syscalls
  without ptrace overhead.

## Disadvantages
- `ward-agent` runs in Zone 3 and is untrusted after start; it must apply hardening
  *before* any untrusted code runs, and the outer layers must not rely on it.
- Landlock ABI versions vary; feature detection with fail-closed defaults is required.
- seccomp-notify has latency cost on the intercepted syscalls (E-05 measures).

## Security consequences
Strictly additive. If `ward-agent` is subverted before applying rules (impossible by
sequencing: it applies then execs), outer enforcement still holds.

## Performance consequences
< 5 ms at start; per-syscall cost only on intercepted syscalls.

## Why selected
Cheap, irreversible, kernel-enforced, and independent of the OCI runtime's feature set.
Host LSM policy is a possible later addition (SELinux is on in Fedora; a `ward_agent_t`
domain is a Phase 6 candidate) but is not a substitute.

## How it will be validated
ST-001/002/003/013/015/025 pass with the OCI mount layer deliberately weakened in a test
build, proving the inner layer alone blocks host access.
