# Snapshots and Git

Status: Phase 0. Decision record: [ADR-0010](decisions/ADR-0010-snapshots-and-git.md).

## 1. Why `.git` is not trusted

Inside the sandbox the agent owns the worktree, including `.git`. It can rewrite `HEAD`,
refs, reflogs, objects, hooks, `index`, `info/exclude`, and `config`. Anything that defines
"the state the agent started from" by reading the agent's `.git` after the session starts
is agent-controlled. WardOS therefore introduces a **Ward Snapshot**: an immutable,
content-addressed capture of the worktree taken and stored *outside* Zone 3.

Git remains the developer's tool and the unit of collaboration. Snapshots are the unit of
trust.

## 2. The snapshot object

```text
WARD SNAPSHOT

id:             blake3:9f1c…                (Merkle root of the manifest)
project:        proj_4d2a…                  (stable project id, from .ward/ or path hash)
role:           entry | candidate | accepted | final
session:        sess_01J…
created:        2026-09-07T22:14:03.118Z
captured_by:    wardd 0.1.0 (image digest sha256:…)
capture_mode:   btrfs-snapshot | frozen-copy
git_context:    { head: <sha or null>, branch: <name or detached>, dirty: true }  # informational only
policy:         { include_ignored: false, include_git_dir: true, max_bytes: 2 GiB }

agent-readable:    yes (as the live worktree it was taken from; never the stored copy)
agent-writable:    no
verifier-readable: yes (materialised fresh from CAS)
```

`git_context` is recorded *because it is useful*, and labelled informational because it is
read from an agent-controlled directory at capture time. Nothing in Zone 0/1/2 makes a
trust decision based on it.

## 3. Manifest and ID

The manifest is a canonical, sorted list of entries:

```text
<type> <mode> <size> <content-hash> <path-bytes>
```

* `type`: file, dir, symlink (target hashed, not followed), submodule-worktree (recursed
  as ordinary files; the sub-`.git` is captured like any other directory), and
  unsupported (FIFO/socket/device: recorded by name, content omitted, flagged).
* Paths are raw bytes, NUL-separated in the manifest, sorted bytewise. No normalisation,
  so a repository with tricky names still gets a stable ID.
* Hardlinks are captured as independent files (content-addressed storage dedupes).
* Content hash: BLAKE3 of file bytes. Manifest hash: BLAKE3 of the manifest. This is a
  two-level Merkle structure; it is enough for integrity and is fast. A chunked tree
  (for delta-friendly large files) is an optimisation to be justified by measurement.
* `.git` **is** captured (so the verifier can run `git`-aware tooling and so that history
  rewrites become visible in a candidate diff), but nothing trusts its contents.
* Ignored files are excluded by default (policy `include_ignored: true` to include). Build
  outputs and `node_modules` live in `/env`, which is never snapshotted.

## 4. Capture procedure

```text
1. wardd freezes the session cgroup (cgroup.freeze = 1). This includes nested
   containers because they live under the session cgroup.
2. If /work is a Btrfs subvolume owned by wardd: create a read-only subvolume snapshot
   (atomic, O(1)). Thaw immediately. Hash from the ro snapshot.
   Else: hash and copy from the frozen tree into the CAS, then thaw.
3. Write manifest, compute ID, store under /var/lib/ward/cas/<id>.
4. Emit SnapshotCreated{role, id, entries, bytes, duration} to the event log.
```

Freeze duration budget: Btrfs path < 5 ms; frozen-copy path is proportional to worktree
size and is the reason **[experiment E-02]** measures cold and warm (mtime/size cached)
hashing on a 1 GB / 200k-file repository. Agent-perceived stall must stay < 100 ms on
the Btrfs path for typical repositories.

Symlinks pointing outside `/work` are stored as symlinks and never followed. Path
traversal is impossible during materialisation because materialisation writes relative to
a fresh root and refuses `..` components (rejected at manifest parse).

## 5. Lifecycle

```text
ENTRY SNAPSHOT (ward up / ward claude)
      │
      ▼
AGENT WORKTREE  (rw, agent-owned, mutable, untrusted)
      │
      │  ward verify / TamperWard trigger
      ▼
CANDIDATE SNAPSHOT (frozen capture)
      │
      ▼
TRUSTED VERIFICATION  (verifier materialises ENTRY and CANDIDATE from CAS)
      │
      ├── TamperWard: ACCEPT → ACCEPTED SNAPSHOT (= candidate id, new role record)
      └── TamperWard: REJECT → evidence, agent informed, worktree untouched
      │
      ▼
FINAL SNAPSHOT (ward stop; optional, policy-controlled)
```

WardOS never writes to the agent's worktree on the agent's behalf (no auto-revert). If
TamperWard's model calls for restoring protected files, TamperWard does so through its own
mechanism inside the agent's worktree or at merge time; WardOS supplies the pristine bytes
on request (`ward snapshot cat <id> <path>`), which is trustworthy because they come from
the CAS.

## 6. Git edge cases (explicitly supported by construction)

| Case | Handling |
| --- | --- |
| Detached HEAD | Irrelevant to snapshot; recorded in `git_context` |
| Rewritten HEAD / refs | Shows up as a content change in `.git/` between entry and candidate |
| Staged / unstaged / untracked | All are worktree bytes; all captured |
| Ignored files | Excluded by default; policy switch |
| Submodules | Captured as files; sub-`.git` captured; no recursion into `.git/modules` semantics needed |
| Linked worktrees (`git worktree`) | The worktree's `.git` *file* is captured; the main repository's `.git` dir is outside `/work` and is **not** visible to the agent unless the user mounts it — `ward up` warns and offers to mount the main repo ro |
| Symlinks | Stored as symlinks, never followed |
| Sparse/partial clones | Bytes-on-disk are what is captured; promisor fetches go through the broker like any network access |
| Large files (LFS) | Pointer files captured; actual blobs are in the worktree if checked out |

## 7. Retention

CAS entries are reference-counted by session records. `ward gc` removes unreferenced
content older than the retention window (default 30 days) except `accepted` snapshots
referenced by evidence, which are retained with the evidence.
