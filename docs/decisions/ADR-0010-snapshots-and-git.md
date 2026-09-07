# ADR-0010 — Frozen state: content-addressed Ward Snapshots independent of `.git`

## Decision
Entry, candidate, accepted and final states are **Ward Snapshots**: BLAKE3-Merkle,
content-addressed captures of the worktree taken by `wardd` under a cgroup freeze (Btrfs
subvolume snapshot when available, frozen copy otherwise), stored in a `ward`-owned CAS
unreachable from Zone 3. `.git` is captured as bytes and never trusted. Details in
[`../snapshots-and-git.md`](../snapshots-and-git.md).

## Alternatives
- Trust `git rev-parse HEAD` + `git status` at session start.
- Use Git's own object store as the CAS (e.g. a `wardd`-owned bare clone with
  `git stash create`-style tree objects).
- Filesystem-level only (Btrfs snapshots without content hashing).

## Advantages
- Independent of agent-controlled metadata; identical trees give identical IDs
  regardless of Git state; untracked/ignored/symlink/submodule semantics are explicit.
- Verifier and TamperWard reason about IDs, not paths.

## Disadvantages
- Hashing cost on large trees (E-02); a second store beside `.git` costs disk (mitigated
  by dedupe and reflinks).
- A Git-object-based CAS would reuse tooling but inherits SHA-1 and Git's model of
  "tracked" files, which is the wrong boundary.

## Security consequences
G5, G9 depend on this. TOCTOU is closed by freezing the whole session cgroup.

## Performance consequences
Btrfs path: O(1) snapshot, hashing off the critical path; frozen-copy path stalls the agent
proportionally to tree size, so Btrfs for `/work` is strongly recommended and is the
default on WardOS.

## Why selected
Trusting `.git` is the vulnerability the brief names. Git-as-CAS is tempting but conflates
collaboration history with trust state. Filesystem-only snapshots have no portable ID.

## How it will be validated
E-02, ST-008, ST-018; property tests on manifest canonicalisation with hostile names.
