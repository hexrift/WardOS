//! Storage usage accounting and scratch-ownership reporting (`ward snapshot
//! usage`, #151).
//!
//! This module answers two read-only questions: how big is the state root
//! (broken down by category — shared blobs, manifests, snapshot metadata,
//! session logs), and which leftover `ward-*` scratch directories under the OS
//! temp dir belong to an operation that has definitely finished. It never
//! deletes, renames, or truncates anything; actual reclamation (mark-and-sweep
//! GC, leases, a low-space preflight) is out of scope here — see the crate's
//! CHANGELOG / the pull request that introduced this module for what #151
//! still asks for beyond it.
//!
//! Scratch liveness is deliberately never inferred from a process id or a
//! filesystem timestamp (the issue's own explicit constraint): only from
//! recorded state written by the code that created the scratch — the owner
//! marker [`crate::session::OWNER_MARKER`], whether a daemon currently answers
//! for that session ([`crate::daemon::serving`], a real socket handshake, not a
//! pid-file check), and whether that session's event log has been sealed
//! ([`ward_events::log::head_file_path`]).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ward_snapshot::{CasUsage, CategoryUsage, SnapshotStore};

use crate::daemon;
use crate::error::{Error, Result};
use crate::session::{OWNER_MARKER, session_dir};

/// Storage usage of one `$WARD_STATE_DIR`: the snapshot CAS categories plus
/// session logs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageUsage {
    /// Deduplicated file/symlink content (`cas/blobs`); shared across every
    /// snapshot that references it, so this is the store's real footprint for
    /// content, not the sum of what any one snapshot captured.
    pub blobs: CategoryUsage,
    /// Stored snapshot manifests (`cas/manifests`).
    pub manifests: CategoryUsage,
    /// Stored `(snapshot, role)` metadata records (`cas/meta`).
    pub meta: CategoryUsage,
    /// Every session's own `session.json` and `events.log` (and, once sealed,
    /// its `HEAD` file).
    pub session_logs: CategoryUsage,
}

impl StorageUsage {
    /// The four categories' combined bytes.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.blobs.bytes + self.manifests.bytes + self.meta.bytes + self.session_logs.bytes
    }
}

/// Compute [`StorageUsage`] for `state` (`$WARD_STATE_DIR`). Read-only; walks
/// directory metadata only, never opens or hashes content.
pub fn compute(state: &Path) -> Result<StorageUsage> {
    let store =
        SnapshotStore::open(state.join("cas")).map_err(|e| Error::Snapshot(e.to_string()))?;
    let CasUsage {
        blobs,
        manifests,
        meta,
    } = store.usage().map_err(|e| Error::Snapshot(e.to_string()))?;
    let session_logs = session_logs_usage(state)?;
    Ok(StorageUsage {
        blobs,
        manifests,
        meta,
        session_logs,
    })
}

/// Sum of every session directory's own files (never recursing into a nested
/// directory — a session directory holds no subdirectories today, but this
/// keeps a future one from being silently double-counted or mis-typed).
fn session_logs_usage(state: &Path) -> Result<CategoryUsage> {
    let sessions = state.join("sessions");
    let mut usage = CategoryUsage::default();
    let entries = match std::fs::read_dir(&sessions) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(usage),
        Err(e) => return Err(Error::io(&sessions, e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(&sessions, e))?;
        let file_type = entry.file_type().map_err(|e| Error::io(&sessions, e))?;
        if file_type.is_dir() {
            add_dir_files(&entry.path(), &mut usage)?;
        }
    }
    Ok(usage)
}

/// Add every regular file directly inside `dir` to `usage` (not recursive; a
/// control socket there is a socket, not a file, so `file_type().is_file()`
/// already excludes it without a special case).
fn add_dir_files(dir: &Path, usage: &mut CategoryUsage) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io(dir, e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(dir, e))?;
        // Tolerate a concurrent remover (this session's own cleanup, another
        // `ward` process) taking the entry out from under us; see the matching
        // comment in `ward_snapshot::cas::walk_dir_usage`.
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::io(dir, e)),
        };
        if file_type.is_file() {
            let len = match entry.metadata() {
                Ok(m) => m.len(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(Error::io(dir, e)),
            };
            usage.objects += 1;
            usage.bytes += len;
        }
    }
    Ok(())
}

/// One `ward-*` scratch directory found under the OS temp dir
/// ([`crate::session::run_dir_path`]'s naming), with what the scan could
/// establish about who owns it and whether it is still needed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScratchEntry {
    /// The scratch directory's path.
    pub path: PathBuf,
    /// The full session id recorded in its owner marker, when legible.
    pub owner: Option<String>,
    /// Total bytes found under `path`.
    pub bytes: u64,
    /// What the scan could establish about its liveness.
    pub status: ScratchStatus,
}

/// How a scratch entry's owning operation was classified. See the module docs
/// for why this is never derived from a PID or an mtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScratchStatus {
    /// A daemon currently answers for the owning session: this scratch may be
    /// in active use behind it. Never a candidate for reclamation.
    Active,
    /// The owning session's event log is sealed — `SessionEnded` (or an
    /// equivalent stop) was already recorded and fsynced — so the one `ward`
    /// invocation that created this scratch had, by then, already finished.
    /// Anything still here afterward was never cleaned up: most likely that
    /// process was interrupted (killed, crashed) between finishing its work
    /// and its own `remove_dir_all`.
    Orphaned,
    /// No daemon answers for the owner and its log is not sealed, or ownership
    /// could not be established at all (no marker, or a marker naming a
    /// session with no record on disk). This may be a still-running
    /// foreground command with no daemon behind it; the honest answer is "not
    /// established", so it is never treated as reclaimable.
    Unknown,
}

/// List every `ward-*` scratch directory under the OS temp dir and classify
/// each against `state` (`$WARD_STATE_DIR`). Read-only: sums file sizes and
/// reads each entry's owner marker, never opens, follows, or removes anything
/// else. A directory whose name collides with WardOS's own (`ward-*`) but that
/// something else created is indistinguishable from ours by name alone; its
/// owner marker will simply be absent or unparseable, and it is reported as
/// [`ScratchStatus::Unknown`] rather than guessed at.
pub fn scan_scratch(state: &Path) -> Result<Vec<ScratchEntry>> {
    let temp = std::env::temp_dir();
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&temp) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(Error::io(&temp, e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(&temp, e))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with("ward-") {
            continue;
        }
        // `file_type()` does not follow a symlink, so a `ward-*` name planted as
        // a symlink by another local user (shared, world-writable temp dir) is
        // excluded here rather than traversed into.
        let Ok(file_type) = entry.file_type() else {
            continue; // vanished between readdir and stat; nothing to report
        };
        if !file_type.is_dir() {
            continue;
        }
        let path = entry.path();
        let owner = read_owner_marker(&path);
        let mut bytes = 0u64;
        sum_dir_bytes(&path, &mut bytes)?;
        let status = classify(state, owner.as_deref());
        out.push(ScratchEntry {
            path,
            owner,
            bytes,
            status,
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Generous headroom over the exact text a real owner marker ever contains
/// (`sess_` + a 26-character Crockford ULID body = 31 bytes) plus whatever
/// trailing whitespace/newline a text editor or shell redirect might add.
/// Anything longer is refused outright rather than read to EOF: the marker
/// is untrusted, attacker-controlled input from a shared, world-writable
/// directory, and an unbounded read would let it force arbitrary memory
/// growth.
const MAX_OWNER_MARKER_LEN: usize = 128;

/// The full session id [`crate::session::run_dir`] recorded as this
/// directory's owner, if the marker is present, non-empty, a real regular
/// file — never a symlink, FIFO, socket or device — and no longer than
/// [`MAX_OWNER_MARKER_LEN`]. The OS temp dir is shared and world-writable, so
/// another local user can plant `<ward-*>/.ward-owner` as:
///
/// - a symlink to an arbitrary path (e.g. a victim's private key), which
///   would disclose that target's content verbatim as this entry's reported
///   owner — refused atomically by the `O_NOFOLLOW` open itself, so there is
///   no separate check-then-read window to race;
/// - a FIFO, which a plain blocking open-for-read would wait on forever if
///   nothing has it open for writing, hanging the whole usage scan —
///   refused by opening with `O_NONBLOCK` (so the open itself can never
///   block) and then `fstat`ing the already-open descriptor (not re-stating
///   the path, which would reopen the TOCTOU window) to require a regular
///   file before any read is attempted;
/// - an oversized regular file, which an unbounded read would load into
///   memory in full — refused by capping the read at
///   [`MAX_OWNER_MARKER_LEN`] `+ 1` bytes and rejecting anything that fills
///   that cap, rather than silently truncating and treating a cut-off
///   marker as legitimate.
///
/// Anything that doesn't clear all of the above is treated exactly like a
/// missing marker.
fn read_owner_marker(dir: &Path) -> Option<String> {
    use std::io::Read;

    let marker = dir.join(OWNER_MARKER);
    let fd = nix::fcntl::open(
        &marker,
        nix::fcntl::OFlag::O_RDONLY
            | nix::fcntl::OFlag::O_NOFOLLOW
            | nix::fcntl::OFlag::O_NONBLOCK
            | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .ok()?;
    let file = std::fs::File::from(fd);
    // `fstat`s the descriptor we already hold open, not the path again — the
    // object this checks is exactly the object the read below reads from,
    // with no window for it to have been swapped in between.
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut buf = Vec::new();
    file.take(MAX_OWNER_MARKER_LEN as u64 + 1)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() > MAX_OWNER_MARKER_LEN {
        return None;
    }
    let text = std::str::from_utf8(&buf).ok()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// Sum every regular file's size under `dir`, recursing into subdirectories.
/// Iterative (an explicit worklist, not self-recursion): `dir` is under the
/// shared, world-writable OS temp dir, so another local user can create an
/// arbitrarily deep chain of nested directories there with no filesystem
/// depth limit low enough to stop them; a call-stack recursion over that
/// input is a local stack-overflow DoS reachable by any co-resident user.
fn sum_dir_bytes(dir: &Path, total: &mut u64) -> Result<()> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::io(&dir, e)),
        };
        for entry in entries {
            let entry = entry.map_err(|e| Error::io(&dir, e))?;
            // See the matching comment in `add_dir_files`: an entry can
            // legitimately vanish between being listed and being `stat`ed.
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(Error::io(&dir, e)),
            };
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                match entry.metadata() {
                    Ok(m) => *total += m.len(),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(Error::io(&dir, e)),
                }
            }
        }
    }
    Ok(())
}

/// Classify one scratch entry's owning operation (see [`ScratchStatus`]).
///
/// `owner` is untrusted: it comes verbatim from a marker file inside a
/// shared, world-writable directory, with only `trim()` + non-empty checks
/// applied by [`read_owner_marker`]. Before it reaches a path join
/// ([`session_dir`]) or a socket lookup ([`daemon::serving`]), it must parse
/// as an actual [`ward_events::SessionId`] — the same `sess_<26-char
/// Crockford ULID>` shape [`crate::ids::new_session_id`] generates. Without
/// this, a marker containing e.g. `../../../../etc` would let
/// `session_dir`/`socket_path` resolve outside `sessions/`, turning this
/// read-only report into a path-traversal existence oracle (via
/// `head_file_path(..).exists()`) and letting an attacker who can bind a
/// Unix socket at a path of their choosing spoof `ScratchStatus::Active`.
/// Anything that doesn't parse is `Unknown`, exactly like an absent marker.
fn classify(state: &Path, owner: Option<&str>) -> ScratchStatus {
    let Some(owner) = owner else {
        return ScratchStatus::Unknown;
    };
    if owner.parse::<ward_events::SessionId>().is_err() {
        return ScratchStatus::Unknown;
    }
    if daemon::serving(state, owner) {
        return ScratchStatus::Active;
    }
    let log_path = session_dir(state, owner).join("events.log");
    if ward_events::log::head_file_path(&log_path).exists() {
        ScratchStatus::Orphaned
    } else {
        ScratchStatus::Unknown
    }
}

/// Total bytes of every entry classified [`ScratchStatus::Orphaned`].
#[must_use]
pub fn orphaned_bytes(entries: &[ScratchEntry]) -> u64 {
    entries
        .iter()
        .filter(|e| e.status == ScratchStatus::Orphaned)
        .map(|e| e.bytes)
        .sum()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn compute_reports_zero_on_an_empty_state_root() {
        let state = tempfile::tempdir().unwrap();
        let usage = compute(state.path()).unwrap();
        assert_eq!(usage, StorageUsage::default());
        assert_eq!(usage.total_bytes(), 0);
    }

    #[test]
    fn compute_counts_cas_and_session_log_bytes() {
        let state = tempfile::tempdir().unwrap();
        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let worktree = tempfile::tempdir().unwrap();
        std::fs::write(worktree.path().join("f"), b"some content").unwrap();
        store
            .store_snapshot(
                worktree.path(),
                ward_snapshot::SnapshotRole::Entry,
                ward_snapshot::CaptureOptions::default(),
            )
            .unwrap();

        let dir = session_dir(state.path(), "sess_usage_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("session.json"), b"{}").unwrap();
        std::fs::write(dir.join("events.log"), b"pretend-log-bytes").unwrap();

        let usage = compute(state.path()).unwrap();
        assert!(usage.blobs.objects >= 1, "the captured file was stored");
        assert!(usage.manifests.objects >= 1);
        assert!(usage.meta.objects >= 1);
        assert_eq!(usage.session_logs.objects, 2);
        assert_eq!(
            usage.session_logs.bytes,
            (b"{}".len() + b"pretend-log-bytes".len()) as u64
        );
        assert_eq!(
            usage.total_bytes(),
            usage.blobs.bytes + usage.manifests.bytes + usage.meta.bytes + usage.session_logs.bytes
        );
    }

    #[test]
    fn scan_scratch_ignores_directories_that_are_not_wards() {
        let state = tempfile::tempdir().unwrap();
        let unrelated = std::env::temp_dir().join(format!("not-ward-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&unrelated);
        std::fs::create_dir_all(&unrelated).unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        assert!(
            entries.iter().all(|e| e.path != unrelated),
            "a non-`ward-` prefixed directory must never be reported"
        );

        std::fs::remove_dir_all(&unrelated).unwrap();
    }

    #[test]
    fn a_scratch_dir_with_no_owner_marker_is_unknown() {
        let state = tempfile::tempdir().unwrap();
        let dir =
            std::env::temp_dir().join(format!("ward-usagetest-nomarker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("payload"), vec![b'x'; 10]).unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(entry.owner, None);
        assert_eq!(entry.status, ScratchStatus::Unknown);
        assert_eq!(entry.bytes, 10);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_scratch_dir_owned_by_an_unrecorded_session_is_unknown() {
        let state = tempfile::tempdir().unwrap();
        let dir = std::env::temp_dir().join(format!("ward-usagetest-ghost-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Well-formed (a real `SessionId`'s own textual shape), just never
        // recorded anywhere on disk.
        let owner = ward_events::SessionId::from_u128(0x1234).to_string();
        std::fs::write(dir.join(OWNER_MARKER), &owner).unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(entry.owner.as_deref(), Some(owner.as_str()));
        assert_eq!(
            entry.status,
            ScratchStatus::Unknown,
            "no daemon, no sealed log: this could still be a running foreground command"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_scratch_dir_whose_owner_marker_does_not_parse_as_a_session_id_is_unknown() {
        // A marker that isn't a real `SessionId`'s textual shape must never
        // reach `session_dir`/`daemon::serving`'s path joins — see the doc
        // comment on `classify`. A path-traversal payload is the sharpest
        // instance: if it were joined in unchecked, `session_dir` would
        // resolve outside `sessions/`, turning this read-only report into an
        // existence oracle for an attacker-chosen path.
        let state = tempfile::tempdir().unwrap();
        let dir =
            std::env::temp_dir().join(format!("ward-usagetest-traversal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(OWNER_MARKER), "../../../../etc/passwd").unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(entry.owner.as_deref(), Some("../../../../etc/passwd"));
        assert_eq!(
            entry.status,
            ScratchStatus::Unknown,
            "a marker that isn't a real SessionId's shape must classify as Unknown, \
             never reach a path join"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_scratch_dir_whose_owner_marker_is_a_symlink_is_treated_as_unset() {
        // The OS temp dir is shared and world-writable: another local user
        // can plant `.ward-owner` as a symlink to an arbitrary file (e.g. a
        // victim's private key). Reading through it would disclose that
        // file's content verbatim as this entry's reported owner — see the
        // doc comment on `read_owner_marker`.
        let state = tempfile::tempdir().unwrap();
        let dir =
            std::env::temp_dir().join(format!("ward-usagetest-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let secret = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            secret.path(),
            "sess_should_never_be_disclosed_via_a_symlink",
        )
        .unwrap();
        std::os::unix::fs::symlink(secret.path(), dir.join(OWNER_MARKER)).unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(
            entry.owner, None,
            "a symlinked marker must never be followed or its target disclosed"
        );
        assert_eq!(entry.status, ScratchStatus::Unknown);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_scratch_dir_whose_owner_marker_is_a_fifo_with_no_writer_returns_promptly_as_unset() {
        // A FIFO with no writer open would block a plain `open(O_RDONLY)`
        // forever; this test itself would hang if `read_owner_marker` ever
        // regressed to opening without `O_NONBLOCK`, rather than failing
        // cleanly — which is exactly why the fix opens non-blocking and
        // `fstat`s the descriptor before ever attempting a read.
        let state = tempfile::tempdir().unwrap();
        let dir = std::env::temp_dir().join(format!("ward-usagetest-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        nix::unistd::mkfifo(
            &dir.join(OWNER_MARKER),
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(
            entry.owner, None,
            "a FIFO marker must never be read from, with or without a writer"
        );
        assert_eq!(entry.status, ScratchStatus::Unknown);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_oversized_owner_marker_is_rejected_rather_than_truncated() {
        let state = tempfile::tempdir().unwrap();
        let dir =
            std::env::temp_dir().join(format!("ward-usagetest-oversized-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // One byte over the cap: large enough to prove the read is bounded
        // (not merely large by accident), too small to make the test slow.
        std::fs::write(dir.join(OWNER_MARKER), vec![b'A'; MAX_OWNER_MARKER_LEN + 1]).unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(
            entry.owner, None,
            "a marker over the length cap must be refused outright, never truncated \
             and treated as a legitimate (if garbled) owner"
        );
        assert_eq!(entry.status, ScratchStatus::Unknown);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sum_dir_bytes_handles_a_deeply_nested_tree_without_recursing_on_the_call_stack() {
        // Not a literal stack-overflow reproduction (that would abort the
        // whole test process rather than fail cleanly) — this proves the
        // iterative worklist walk produces the right answer over a tree far
        // deeper than a routine one, which self-recursion could not do
        // without growing the call stack proportionally.
        let mut dir = tempfile::tempdir().unwrap().keep();
        let root = dir.clone();
        // Bounded by PATH_MAX (each level adds "d/" to the absolute path),
        // not by any property of the walk itself — comfortably deeper than
        // any real scratch-directory tree, which is the point.
        for _ in 0..1500 {
            dir.push("d");
            std::fs::create_dir(&dir).unwrap();
        }
        std::fs::write(dir.join("leaf"), vec![b'z'; 7]).unwrap();

        let mut total = 0u64;
        sum_dir_bytes(&root, &mut total).unwrap();
        assert_eq!(total, 7);

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_scratch_dir_whose_owner_session_is_sealed_is_orphaned() {
        let state = tempfile::tempdir().unwrap();
        let owner = ward_events::SessionId::from_u128(0x005e_a1ed).to_string();
        let log_dir = session_dir(state.path(), &owner);
        std::fs::create_dir_all(&log_dir).unwrap();
        let log_path = log_dir.join("events.log");
        std::fs::write(&log_path, b"sealed log contents").unwrap();
        // `LocalLog::seal` writes the chain head to this exact sibling path; a
        // usage scan only ever checks whether it exists (see `classify`), so
        // reproducing just that fact is a faithful, minimal fixture.
        std::fs::write(ward_events::log::head_file_path(&log_path), b"head").unwrap();

        let dir =
            std::env::temp_dir().join(format!("ward-usagetest-sealed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(OWNER_MARKER), owner.as_bytes()).unwrap();
        std::fs::write(dir.join("socket-standin"), vec![b'y'; 5]).unwrap();
        // The marker itself is a real file under `dir` too, so it counts toward
        // the entry's bytes exactly like any other leftover scratch content.
        let expected_bytes = owner.len() as u64 + 5;

        // The real OS temp dir is shared with every other test in this binary
        // (and, in principle, any other WardOS process on the machine), so only
        // this one entry's own numbers are asserted here — `orphaned_bytes`'s
        // summation itself is covered in isolation below.
        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(entry.status, ScratchStatus::Orphaned);
        assert_eq!(entry.bytes, expected_bytes);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn orphaned_bytes_sums_only_the_orphaned_entries() {
        let entries = vec![
            ScratchEntry {
                path: PathBuf::from("/tmp/ward-a"),
                owner: Some("sess_a".to_owned()),
                bytes: 10,
                status: ScratchStatus::Orphaned,
            },
            ScratchEntry {
                path: PathBuf::from("/tmp/ward-b"),
                owner: Some("sess_b".to_owned()),
                bytes: 1000,
                status: ScratchStatus::Active,
            },
            ScratchEntry {
                path: PathBuf::from("/tmp/ward-c"),
                owner: None,
                bytes: 5000,
                status: ScratchStatus::Unknown,
            },
            ScratchEntry {
                path: PathBuf::from("/tmp/ward-d"),
                owner: Some("sess_d".to_owned()),
                bytes: 20,
                status: ScratchStatus::Orphaned,
            },
        ];
        assert_eq!(
            orphaned_bytes(&entries),
            30,
            "only the two Orphaned entries (10 + 20) count; Active and Unknown never do"
        );
    }

    #[test]
    fn a_scratch_dir_whose_owner_session_a_daemon_is_serving_is_active_even_though_unsealed() {
        use crate::control::Response;
        use crate::daemon::bind_socket;

        let state = tempfile::tempdir().unwrap();
        let owner = ward_events::SessionId::from_u128(0x00ac_71fe).to_string();
        let log_dir = session_dir(state.path(), &owner);
        std::fs::create_dir_all(&log_dir).unwrap();
        // Deliberately unsealed: an active session's log has no HEAD file yet.
        // Were `classify` to check the log before the daemon, this would
        // wrongly read as `Orphaned`; the daemon-serving check must win.
        std::fs::write(log_dir.join("events.log"), b"open log, no seal").unwrap();

        let socket = crate::control::SOCKET_NAME;
        let listener = bind_socket(&log_dir.join(socket)).unwrap();
        let server = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                // Answer exactly one `Ping` the way `RemoteSink::connect`'s
                // handshake expects, then let the connection close.
                use std::io::{BufRead, BufReader, Write};
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    let mut resp = serde_json::to_vec(&Response::Ok).unwrap();
                    resp.push(b'\n');
                    let _ = writer.write_all(&resp);
                }
            }
        });

        let dir =
            std::env::temp_dir().join(format!("ward-usagetest-active-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(OWNER_MARKER), owner.as_bytes()).unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(entry.status, ScratchStatus::Active);

        server.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
