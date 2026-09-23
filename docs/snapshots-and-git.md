# Snapshots and Git

Status: living document; the project's phase is in docs/status.toml and the README.
Decision record: [ADR-0010](decisions/ADR-0010-snapshots-and-git.md).

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

`ward snapshot usage` reports CAS and scratch disk usage, read-only (#151 item 1).

`ward snapshot gc` reclaims storage with a conservative mark-and-sweep, never a
time-based retention window and never a reference count derived from a process id or a
file's mtime (#151 items 2–3). A blob, manifest, or meta record is live when it is
reachable from at least one retention root:

* an active session's `entry_snapshot`, for as long as its log is not yet sealed;
* any snapshot an in-flight verification attempt currently names as its candidate;
* any snapshot `TamperWard` has recorded as accepted evidence (`StateAccepted`),
  regardless of whether the session that produced it has since ended;
* any snapshot explicitly marked kept (`ward_snapshot::gc::mark_kept`) — the minimal
  marker user-kept restore backups use today, pending a fuller policy.

Separately, a capture in progress holds a lease over the whole store for its duration,
so a sweep running concurrently with a capture never reclaims a blob or manifest the
capture is still writing, even before anything durably references it. Roots and leases
are both explicit, disk-recorded facts, never inferred from a pid or an mtime. When in
doubt — a lease is ambiguous, a root cannot be fully resolved, or a category cannot be
listed — the sweep keeps the object rather than delete it.

`ward snapshot gc` defaults to printing a plan and deleting nothing; `--apply` performs
it, one object at a time, so an interrupted sweep leaves the store in a valid state and
a re-run recomputes safely from what is left on disk. Startup reconciliation of
abandoned scratch, a low-space preflight, and `doctor`/`status` integration are
follow-up work, not part of this mechanism.
