# ADR-0004 — Verifier isolation: disposable Zone 2 environment

## Decision
Each verification spawns a **fresh** environment: own uid range (distinct from any
agent's), own namespaces, no network by default, root from the verifier image (ro),
pristine and candidate snapshots materialised from the CAS (ro), trusted test bundle from
Zone 1 (ro), a fresh scratch tmpfs, cgroup budget and wall-clock budget. Results flow to
`wardd` over a pipe; the verifier never writes to shared storage. In 0.1 the default is a
namespaces-based environment; E-03 decides whether a libkrun/cloud-hypervisor microVM
becomes the default when KVM is available.

## Alternatives
- Long-lived verifier service with a shared work directory.
- Verifier as a sibling container sharing the agent's worktree read-only via bind mount.
- Always-microVM verifier.
- Verifier on a remote host.

## Advantages
- No shared mutable path with the agent: `/tmp`, Git objects, `node_modules`, venvs,
  package caches, control directories are all distinct by construction.
- Materialising from snapshot IDs makes the evidence claim exact: "these bytes were
  verified".
- Disposable: a hostile build script (T3/T4) cannot persist or affect later runs.

## Disadvantages
- Materialisation cost for large trees (mitigated by CAS reflink copies on Btrfs).
- Dependency installation inside the verifier needs network or a pre-warmed cache;
  default is a policy-declared read-only cache layer built by `ward up` from the *entry*
  snapshot's lockfiles, or explicit allowlisted registries in the verify manifest.

## Security consequences
- Agent cannot see, signal, or share state with the verifier (PID ns, distinct uid, no
  mounts). Verifier cannot reach Zone 0/1/3 or the network.
- Hostile test code runs with the verifier's authority, which is nil beyond its inputs.

## Performance consequences
- Spawn target < 500 ms excluding materialisation; microVM adds 200–400 ms (E-03).
- reflink materialisation is near-O(1) in bytes on Btrfs.

## Why selected
A bind mount of the agent's worktree would be a live view the agent can change during
verification (TOCTOU). A long-lived service accumulates state that hostile code can
poison. Remote verification is an enterprise extension, not a 0.1 requirement.

## How it will be validated
ST-005, 006, 018, 019 with hostile agent and hostile repository; E-03 latency.
