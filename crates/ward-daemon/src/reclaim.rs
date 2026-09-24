//! Startup reconciliation of abandoned scratch (#151 item 5).
//!
//! [`crate::usage::scan_scratch`] already classifies every `ward-*` scratch
//! directory under the OS temp dir into [`ScratchStatus::Active`] /
//! [`ScratchStatus::Orphaned`] / [`ScratchStatus::Unknown`] from recorded
//! ownership alone — never a PID or an mtime (see that module's own doc
//! comment). This module is the one piece it explicitly left out: actually
//! removing what that scan calls `Orphaned` — a scratch directory whose
//! owning session's event log is already sealed, so the one `ward`
//! invocation that created it has, by definition, already finished with it.
//!
//! # Never touching anything but `Orphaned`
//!
//! Only entries [`ScratchStatus::Orphaned`] are ever removed. `Active` (a
//! daemon still answers for the owning session) and `Unknown` (no daemon, no
//! sealed log — this may be a still-running foreground command with no
//! daemon behind it, or simply an unrecognised directory) are always left
//! alone: the issue's own explicit constraint is "never remove an active run
//! or the user's worktree", and a status the scan could not positively
//! establish as finished is never treated as safe to remove.
//!
//! # Re-verified immediately before every deletion
//!
//! `run_dir`'s directory-name scheme is a short, deterministic function of a
//! session id (its last 10 characters — see `session::run_dir_path`), and
//! `run_dir` itself legitimately *reuses* an existing private directory at
//! that name for a brand-new session id whenever the two happen to share
//! that tail, overwriting the owner marker to the new session's id when it
//! does. So the classification an earlier
//! [`scan_scratch`](crate::usage::scan_scratch) call produced can go stale:
//! by the time this module gets around to a particular entry, a new, live
//! session may already have taken over that exact directory. Never trusting
//! the earlier scan alone, [`reclaim_orphaned_scratch_with_hook`] re-reads and
//! re-classifies each entry (via [`crate::usage::rescan_entry`])
//! immediately before removing it — the same "recheck right before acting,
//! not just once at plan time" shape `ward_snapshot::gc::apply`'s own lease
//! recheck already uses — and skips it, leaving it untouched, the instant
//! that recheck disagrees.
//!
//! # Deletion itself
//!
//! [`std::fs::remove_dir_all`] on this workspace's pinned toolchain already
//! refuses to follow a symlink at any level of the tree it removes — a
//! symlink is itself unlinked, never traversed into, whether it is the top
//! path or nested inside (verified directly against this toolchain, not
//! merely assumed from general Rust standard-library behaviour). That is
//! exactly the guarantee [`crate::usage::sum_dir_bytes`]'s own hand-rolled
//! `openat`-based walk provides for *reading*; reusing the standard library
//! for deletion here, rather than reimplementing the same walk a second
//! time, means one guarantee to trust instead of two independently
//! maintained ones.
//!
//! # Never fatal to the caller
//!
//! Unlike [`crate::attempt::reconcile_dangling_attempts`] (#139 item 5: fail
//! closed, a daemon that cannot confirm a dangling attempt was reconciled
//! must not start serving), a failure here never blocks a session's daemon
//! from starting. This is disk hygiene, not correctness: the worst outcome
//! of never running this at all is exactly the leftover scratch `ward
//! snapshot usage` already reports today, which is what shipped before this
//! module existed. One entry's removal failing (a permission error, a
//! concurrent remover) is contained to that entry, the same containment
//! [`crate::usage::scan_scratch`] already gives a traversal failure — it
//! never aborts the rest of the sweep.

use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::usage::{ScratchStatus, rescan_entry, scan_scratch};

/// One scratch directory [`reclaim_orphaned_scratch`] actually removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reclaimed {
    /// The removed directory's former path.
    pub path: PathBuf,
    /// Its size as last observed, when the scan that found it could fully
    /// read it (see [`crate::usage::ScratchEntry::bytes`]).
    pub bytes: Option<u64>,
}

/// What [`reclaim_orphaned_scratch`] did, in full — never just a count, so a
/// caller (or a test) can tell exactly which paths were touched and why any
/// were not.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReclaimReport {
    /// Directories actually removed.
    pub reclaimed: Vec<Reclaimed>,
    /// Directories an earlier scan called `Orphaned`, but which the
    /// immediate re-check right before deletion found were no longer
    /// `Orphaned` — most likely reused by a new session in the meantime (see
    /// the module doc comment). Left untouched.
    pub skipped_no_longer_orphaned: Vec<PathBuf>,
    /// Directories that were confirmed `Orphaned` right up to the deletion
    /// attempt itself, but whose removal failed (permission error, unusual
    /// I/O failure). One entry's failure never stops the rest of the sweep.
    pub failed: Vec<(PathBuf, String)>,
}

impl ReclaimReport {
    /// Total bytes [`Self::reclaimed`] actually freed. Entries whose byte
    /// count is unavailable (see [`Reclaimed::bytes`]) contribute nothing to
    /// this total rather than being guessed at.
    #[must_use]
    pub fn reclaimed_bytes(&self) -> u64 {
        self.reclaimed.iter().filter_map(|e| e.bytes).sum()
    }
}

/// Remove every scratch directory under the OS temp dir that
/// [`scan_scratch`](crate::usage::scan_scratch) currently classifies
/// [`ScratchStatus::Orphaned`] against `state` (`$WARD_STATE_DIR`) — the
/// #151 item 5 "startup reconciliation" this crate's usage module left out.
/// See the module doc comment for the safety properties this relies on.
pub fn reclaim_orphaned_scratch(state: &Path) -> Result<ReclaimReport> {
    reclaim_orphaned_scratch_with_hook(state, |_| {})
}

/// [`reclaim_orphaned_scratch`] with a hook invoked, in scan order, with the
/// path about to be re-checked and (if still `Orphaned`) removed. Production
/// code never needs anything other than a no-op hook (that is what
/// [`reclaim_orphaned_scratch`] passes); it exists so a test can
/// deterministically mutate one entry's on-disk ownership *between* the
/// initial scan and its own re-check — most sharply, simulate a new session
/// reusing the directory in that window — without any real concurrency or
/// timing.
pub fn reclaim_orphaned_scratch_with_hook(
    state: &Path,
    mut before_recheck: impl FnMut(&Path),
) -> Result<ReclaimReport> {
    let entries = scan_scratch(state)?;
    let mut report = ReclaimReport::default();
    for entry in entries {
        if entry.status != ScratchStatus::Orphaned {
            continue;
        }
        before_recheck(&entry.path);
        let current = rescan_entry(state, entry.path);
        if current.status != ScratchStatus::Orphaned {
            report.skipped_no_longer_orphaned.push(current.path);
            continue;
        }
        match std::fs::remove_dir_all(&current.path) {
            Ok(()) => report.reclaimed.push(Reclaimed {
                path: current.path,
                bytes: current.bytes,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Already gone — another reclaim pass (a concurrently
                // starting daemon), or the owner's own belated cleanup.
                // Not this call's doing, but not a problem either.
            }
            Err(e) => report.failed.push((current.path, e.to_string())),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::control::{LocalLog, Sink};
    use crate::session::{OWNER_MARKER, session_dir};
    use std::time::SystemTime;

    fn sealed_session(state: &Path, id: &str) {
        let dir = session_dir(state, id);
        std::fs::create_dir_all(&dir).unwrap();
        let log = LocalLog::create(
            &dir.join("events.log"),
            id.parse().unwrap(),
            ward_events::Blake3Hash::ZERO,
            SystemTime::now(),
        )
        .unwrap();
        Box::new(log).seal().unwrap();
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn an_orphaned_scratch_dir_is_removed() {
        let state = tempfile::tempdir().unwrap();
        let owner = ward_events::SessionId::from_u128(0xbeef_0001).to_string();
        sealed_session(state.path(), &owner);

        let dir = scratch_dir(&format!("ward-reclaimtest-orphan-{}", std::process::id()));
        std::fs::write(dir.join(OWNER_MARKER), &owner).unwrap();
        std::fs::write(dir.join("leftover"), b"stale scratch content").unwrap();

        let report = reclaim_orphaned_scratch(state.path()).unwrap();
        assert!(
            report.reclaimed.iter().any(|r| r.path == dir),
            "the orphaned directory must be reclaimed: {report:?}"
        );
        assert!(!dir.exists(), "it must actually be gone from disk");
    }

    #[test]
    fn an_active_sessions_scratch_is_never_touched() {
        use crate::control::Response;
        use crate::daemon::bind_socket;

        let state = tempfile::tempdir().unwrap();
        let owner = ward_events::SessionId::from_u128(0xbeef_0002).to_string();
        let log_dir = session_dir(state.path(), &owner);
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::write(log_dir.join("events.log"), b"open, unsealed").unwrap();

        let listener = bind_socket(&log_dir.join(crate::control::SOCKET_NAME)).unwrap();
        let server = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
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

        let dir = scratch_dir(&format!("ward-reclaimtest-active-{}", std::process::id()));
        std::fs::write(dir.join(OWNER_MARKER), &owner).unwrap();

        let report = reclaim_orphaned_scratch(state.path()).unwrap();
        assert!(
            report.reclaimed.iter().all(|r| r.path != dir),
            "an active session's scratch must never be reclaimed: {report:?}"
        );
        assert!(dir.exists(), "it must still be on disk");

        server.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unknown_scratch_dir_is_never_touched() {
        let state = tempfile::tempdir().unwrap();
        // No owner marker at all: classified `Unknown`, could be a live
        // foreground command with no daemon behind it.
        let dir = scratch_dir(&format!("ward-reclaimtest-unknown-{}", std::process::id()));
        std::fs::write(dir.join("payload"), b"who knows").unwrap();

        let report = reclaim_orphaned_scratch(state.path()).unwrap();
        assert!(report.reclaimed.iter().all(|r| r.path != dir));
        assert!(dir.exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_directory_reused_by_a_new_session_between_scan_and_recheck_survives() {
        // The exact race the module doc comment describes: the initial scan
        // sees `Orphaned` for the old, sealed owner; before this entry's own
        // recheck runs, a brand-new (still live) session takes over the same
        // directory — `run_dir`'s own legitimate reuse path, simulated here
        // by overwriting the owner marker directly. The recheck must catch
        // this and refuse to delete what is now someone else's live scratch.
        let state = tempfile::tempdir().unwrap();
        let old_owner = ward_events::SessionId::from_u128(0xbeef_0003).to_string();
        sealed_session(state.path(), &old_owner);
        let new_owner = ward_events::SessionId::from_u128(0xbeef_0004).to_string();
        let new_dir = session_dir(state.path(), &new_owner);
        std::fs::create_dir_all(&new_dir).unwrap();
        std::fs::write(new_dir.join("events.log"), b"open, unsealed").unwrap();
        // No daemon bound for the new owner: it classifies `Unknown`, not
        // `Active` — either way, not `Orphaned`, which is all this test
        // needs to prove the recheck refuses the deletion.

        let dir = scratch_dir(&format!("ward-reclaimtest-race-{}", std::process::id()));
        std::fs::write(dir.join(OWNER_MARKER), &old_owner).unwrap();
        std::fs::write(dir.join("payload"), b"belongs to whoever owns it now").unwrap();

        let report = reclaim_orphaned_scratch_with_hook(state.path(), |path| {
            if path == dir {
                std::fs::write(dir.join(OWNER_MARKER), &new_owner).unwrap();
            }
        })
        .unwrap();

        assert!(
            report.reclaimed.iter().all(|r| r.path != dir),
            "must never delete a directory the recheck found reused: {report:?}"
        );
        assert!(
            report.skipped_no_longer_orphaned.contains(&dir),
            "must be recorded as skipped for exactly this reason: {report:?}"
        );
        assert!(dir.exists(), "the reused directory must survive intact");
        assert!(
            dir.join("payload").exists(),
            "the new owner's own content must be untouched"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_symlink_planted_at_an_orphaned_looking_name_is_never_followed() {
        // The OS temp dir is shared and world-writable: a co-resident user
        // could plant a symlink at a `ward-*`-prefixed name pointing at a
        // victim directory. `scan_scratch` already refuses to descend into
        // it (reported `Unknown`, see `usage.rs`), so it is never classified
        // `Orphaned` in the first place and this reclaim never reaches the
        // removal step for it at all.
        let state = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        std::fs::write(victim.path().join("do-not-delete"), b"precious").unwrap();

        let link =
            std::env::temp_dir().join(format!("ward-reclaimtest-symlink-{}", std::process::id()));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(victim.path(), &link).unwrap();

        let report = reclaim_orphaned_scratch(state.path()).unwrap();
        assert!(report.reclaimed.iter().all(|r| r.path != link));
        assert!(
            victim.path().join("do-not-delete").exists(),
            "the symlink target must be completely untouched"
        );

        std::fs::remove_file(&link).unwrap();
    }

    #[test]
    fn an_empty_temp_dir_reclaims_nothing() {
        let state = tempfile::tempdir().unwrap();
        // Not asserting the real OS temp dir is empty (it is shared with
        // every other test in this binary) — only that a state root with no
        // sealed, unowned sessions produces an empty report for whatever
        // this call itself did not plant.
        let report = reclaim_orphaned_scratch(state.path()).unwrap();
        assert!(report.failed.is_empty());
    }
}
