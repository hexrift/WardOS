//! Verification-attempt lifecycle plumbing (#139).
//!
//! [`AttemptGuard`] gives every verification attempt a private, durable marker from
//! the moment its [`AttemptId`] is allocated — before any expensive preparation
//! (candidate capture, sandbox launch) begins — so a subscriber sees progress from
//! the very first action, and so the attempt leaves *some* durable trace even if the
//! process is killed before it can write a terminal `WardEvent`.
//! [`reconcile_dangling_attempts`] is what turns a leftover marker into a terminal
//! `VerificationInterrupted` record: called whenever a process (re)takes ownership of
//! a session's log (the daemon's own startup, a client's `Session::open_current`, or
//! the start of a fresh `verify()`), it closes out anything an earlier attempt left
//! dangling before that attempt's marker can be mistaken for a still-running one.
//! [`CancelToken`] is the separate, cooperative cancellation handle for an in-flight
//! `verify()` call.
//!
//! # Why a marker file, not a `Drop` that appends to the log
//!
//! ADR-0015 makes the session daemon the log's only writer; a `ward` client only ever
//! appends through a [`Sink`] (`RemoteSink` over the control socket when a daemon owns
//! the log, `LocalLog` directly otherwise, chosen once when the [`Session`](crate::session::Session)
//! opens). A `Drop` implementation has no reliable way to reach the *right* one of
//! those, and even if it could, opening a second, uncoordinated `LocalLog` on the same
//! file while a daemon might already hold it open would risk two writers on one
//! append-only log — exactly what ADR-0015 exists to rule out. So [`AttemptGuard`]
//! never touches the shared event log at all, from `Drop` or otherwise; it only ever
//! reads and writes its own private marker file, which is safe to do even mid-unwind.
//! The actual terminal-record guarantee comes from [`reconcile_dangling_attempts`],
//! run through the same [`Sink`] the session already writes through.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use ward_events::{AttemptId, Origin, ShortText, SnapshotId, VerifyRequester, WardEvent};

use crate::control::{Sink, unix_ms};
use crate::error::{Error, Result};

/// `<session_dir>/attempts/`: where this session's in-flight attempt markers live.
fn attempts_dir(session_dir: &Path) -> PathBuf {
    session_dir.join("attempts")
}

fn marker_path(session_dir: &Path, attempt: AttemptId) -> PathBuf {
    attempts_dir(session_dir).join(format!("{}.json", attempt.get()))
}

/// The durable record of one in-flight attempt: written by [`AttemptGuard::start`],
/// updated by [`AttemptGuard::bind_candidate`], and read back by
/// [`reconcile_dangling_attempts`] (or, if `Drop` catches it first, annotated with a
/// best-effort `note`). Never touches the shared event log itself — see the module
/// doc comment.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Marker {
    attempt: u64,
    requested_by: VerifyRequester,
    /// The candidate snapshot's `Display` form, once capture has succeeded.
    candidate: Option<String>,
    started_unix_ms: u64,
    /// Set by [`AttemptGuard`]'s `Drop`, best-effort, when it drops still active: a
    /// more specific hint for the reconciled record's `reason` than the generic
    /// text [`reconcile_dangling_attempts`] otherwise falls back to. Never
    /// load-bearing for correctness.
    note: Option<String>,
}

fn write_marker(path: &Path, marker: &Marker) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let bytes =
        serde_json::to_vec(marker).map_err(|e| Error::Events(format!("attempt marker: {e}")))?;
    std::fs::write(path, bytes).map_err(|e| Error::io(path, e))
}

fn read_marker(path: &Path) -> Option<Marker> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The next attempt number for this session: one past the highest
/// `VerificationAttemptStarted { attempt, .. }` record in the log, or 1 for a log with
/// none. Recomputed by scanning the log rather than kept in its own counter file, so
/// it stays correct across process restarts without a separate durability story.
/// A log that cannot be opened (a session not yet started) is treated as having none.
#[must_use]
pub fn next_attempt_id(log_path: &Path) -> AttemptId {
    let Ok(reader) = ward_events::LogReader::open(log_path) else {
        return AttemptId::new(1);
    };
    let max = reader
        .filter_map(std::result::Result::ok)
        .filter_map(|r| match r.event {
            WardEvent::VerificationAttemptStarted { attempt, .. } => Some(attempt.get()),
            _ => None,
        })
        .max();
    AttemptId::new(max.map_or(1, |m| m.saturating_add(1)))
}

/// RAII marker for one verification attempt (#139).
///
/// [`Self::start`] writes the marker the moment an attempt is allocated, before any
/// expensive preparation. [`Self::finish`] removes it once a terminal `WardEvent` for
/// the attempt has been durably appended. If neither a normal `finish()` nor a
/// dedicated interrupted/cancelled append happens — an unexpected early return, a
/// panic, or the process dying outright — the marker survives on disk, and
/// [`reconcile_dangling_attempts`] closes it out the next time anything opens this
/// session's log. A future code path that forgets to finish an attempt therefore
/// cannot reintroduce #139's original bug: at worst it leaves a marker, never a
/// silent, permanent "running".
pub struct AttemptGuard {
    path: PathBuf,
    finished: bool,
}

impl AttemptGuard {
    /// Allocate the marker for a new attempt of `session_dir`.
    pub fn start(
        session_dir: &Path,
        attempt: AttemptId,
        requested_by: VerifyRequester,
    ) -> Result<Self> {
        let path = marker_path(session_dir, attempt);
        write_marker(
            &path,
            &Marker {
                attempt: attempt.get(),
                requested_by,
                candidate: None,
                started_unix_ms: unix_ms(SystemTime::now()),
                note: None,
            },
        )?;
        Ok(Self {
            path,
            finished: false,
        })
    }

    /// Record that capture succeeded and the candidate is now known (#139 item 3:
    /// never invented for a failed capture — this is only ever called once
    /// `verify::prepare` has already returned one). Best-effort: a failure to update
    /// the marker only means a later reconciliation's `VerificationInterrupted` would
    /// carry `candidate: None` instead of the real one, never a wrong one.
    pub fn bind_candidate(&self, candidate: SnapshotId) {
        if let Some(mut marker) = read_marker(&self.path) {
            marker.candidate = Some(candidate.to_string());
            let _ = write_marker(&self.path, &marker);
        }
    }

    /// The attempt reached a terminal record that was durably appended: remove the
    /// marker so no future reconciliation pass mistakes it for dangling.
    pub fn finish(mut self) {
        self.finished = true;
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for AttemptGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Best-effort, and touches only this attempt's own private marker file —
        // never the shared event log (see the module doc comment) — so this is safe
        // to do even mid-unwind.
        if let Some(mut marker) = read_marker(&self.path) {
            marker.note.get_or_insert_with(|| {
                "the process running this attempt exited without recording a terminal \
                 result (an early return, a panic, or the process ending outright)"
                    .to_owned()
            });
            let _ = write_marker(&self.path, &marker);
        }
    }
}

/// Append `VerificationInterrupted` for `attempt` through `sink` and, on success,
/// finish `guard` so it is not reconciled a second time. Used for the *live*
/// preparation-failure path (`Session::verify`), which already has a specific reason
/// and a `Sink` in hand — as distinct from [`reconcile_dangling_attempts`], used when
/// nothing live is left to ask and only the marker's own best-effort note remains.
pub fn finalize_interrupted(
    sink: &mut dyn Sink,
    guard: AttemptGuard,
    attempt: AttemptId,
    candidate: Option<SnapshotId>,
    reason: ShortText,
) -> Result<()> {
    sink.append(
        Origin::Wardd,
        WardEvent::VerificationInterrupted {
            attempt,
            candidate,
            reason,
        },
        SystemTime::now(),
    )?;
    guard.finish();
    Ok(())
}

/// Close out every dangling attempt marker under `session_dir`: each becomes a
/// `VerificationInterrupted` record appended through `sink`, then its marker is
/// removed. Call whenever a process (re)takes ownership of a session's log — the
/// daemon's own startup (#139, the literal ask), a client's `Session::open_current`,
/// or the start of a fresh `verify()` — so a dangling attempt is never left showing
/// "running" for longer than it takes for anything to look at the session again.
/// Markers this pass cannot even parse are removed without an event: a corrupt
/// marker carries no attempt to report on, but must not jam every future
/// reconciliation pass forever either.
///
/// Returns the number of attempts reconciled.
pub fn reconcile_dangling_attempts(sink: &mut dyn Sink, session_dir: &Path) -> Result<usize> {
    let dir = attempts_dir(session_dir);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(Error::io(&dir, e)),
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(std::ffi::OsStr::to_str) == Some("json"))
        .collect();
    // Oldest attempt first: if two ever exist (should not, in the single-attempt-at-a-
    // time model this crate uses today), the log at least records them in allocation
    // order.
    paths.sort();

    let mut reconciled = 0usize;
    for path in paths {
        let Some(marker) = read_marker(&path) else {
            let _ = std::fs::remove_file(&path);
            continue;
        };
        let attempt = AttemptId::new(marker.attempt);
        let candidate = marker.candidate.as_deref().and_then(|s| s.parse().ok());
        let reason = ShortText::new(marker.note.as_deref().unwrap_or(
            "the process serving this session ended before the attempt reached a terminal result",
        ));
        sink.append(
            Origin::Wardd,
            WardEvent::VerificationInterrupted {
                attempt,
                candidate,
                reason,
            },
            SystemTime::now(),
        )?;
        let _ = std::fs::remove_file(&path);
        reconciled += 1;
    }
    if reconciled > 0 {
        sink.sync()?;
    }
    Ok(reconciled)
}

/// A cooperative cancellation handle for one `Session::verify()` call (#139).
///
/// Checked at points between an attempt's steps — never while the verifier
/// subprocess itself is running, which stays bounded by its own existing
/// `verify.budget_secs` timeout as before this change. A cancel requested during
/// that window takes effect at the next checkpoint after the subprocess returns, by
/// which point the attempt may already have reached an ordinary pass/fail/error
/// outcome; that outcome is not retroactively overridden by a late cancel. True
/// preemption of a running verifier subprocess (killing it from another thread the
/// instant a cancel is requested) is not implemented — see the crate's `attempt`
/// module tests and the pull request description for the reasoning.
#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A fresh, not-yet-cancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. Idempotent; safe to call from any thread, including
    /// concurrently with a `verify()` call this token was handed to.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use ward_events::{Blake3Hash, EventRecord, LogReader, SessionId};

    use super::*;
    use crate::control::LocalLog;

    fn fresh_log(dir: &Path) -> LocalLog {
        LocalLog::create(
            &dir.join("events.log"),
            SessionId::from_u128(42),
            Blake3Hash::from_bytes([3; 32]),
            SystemTime::now(),
        )
        .unwrap()
    }

    fn candidate() -> SnapshotId {
        SnapshotId::new(Blake3Hash::from_bytes([0xab; 32]))
    }

    fn read_back(log_path: &Path) -> Vec<EventRecord> {
        LogReader::open(log_path)
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    #[test]
    fn cancel_token_starts_clear_and_is_idempotent() {
        let token = CancelToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
        // A clone shares state: cancelling from one handle is visible on the other,
        // which is the whole point — a caller keeps the handle while `verify()` (on
        // a token it was handed) runs elsewhere.
        let clone = token.clone();
        assert!(clone.is_cancelled());
    }

    #[test]
    fn next_attempt_id_starts_at_one_and_follows_the_highest_started_record() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.log");
        assert_eq!(
            next_attempt_id(&log_path).get(),
            1,
            "a session with no log yet has no attempts"
        );

        let mut log = fresh_log(dir.path());
        log.append(
            Origin::Wardd,
            WardEvent::VerificationAttemptStarted {
                attempt: AttemptId::new(1),
                requested_by: VerifyRequester::User,
            },
            SystemTime::now(),
        )
        .unwrap();
        log.append(
            Origin::Wardd,
            WardEvent::VerificationAttemptStarted {
                attempt: AttemptId::new(2),
                requested_by: VerifyRequester::User,
            },
            SystemTime::now(),
        )
        .unwrap();
        // An unrelated record in between must not confuse the scan.
        log.append(
            Origin::Wardd,
            WardEvent::AgentStateChanged {
                state: ward_events::AgentState::Working,
            },
            SystemTime::now(),
        )
        .unwrap();
        log.sync().unwrap();
        assert_eq!(next_attempt_id(&log_path).get(), 3);
    }

    #[test]
    fn a_marker_left_by_a_finished_attempt_does_not_survive() {
        let dir = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new(1);
        let guard = AttemptGuard::start(dir.path(), attempt, VerifyRequester::User).unwrap();
        assert!(marker_path(dir.path(), attempt).exists());
        guard.bind_candidate(candidate());
        assert!(
            read_marker(&marker_path(dir.path(), attempt))
                .unwrap()
                .candidate
                .is_some()
        );
        guard.finish();
        assert!(!marker_path(dir.path(), attempt).exists());
    }

    /// #139 item 4: an `AttemptGuard` that drops without `finish()` — the same shape
    /// a future buggy code path (an early return that forgot to finalize, or a
    /// panic) would produce — leaves its marker in place with a note, rather than
    /// silently vanishing. `reconcile_dangling_attempts` (below) is what turns that
    /// into a terminal record; this test is only about the guard's own half.
    #[test]
    fn a_guard_dropped_without_finishing_leaves_an_annotated_marker() {
        let dir = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new(1);
        {
            let guard = AttemptGuard::start(dir.path(), attempt, VerifyRequester::User).unwrap();
            guard.bind_candidate(candidate());
            // Dropped here without `finish()` — e.g. an early `?` return.
        }
        let marker = read_marker(&marker_path(dir.path(), attempt))
            .expect("the marker survives an unfinished guard's drop");
        assert_eq!(
            marker.candidate.as_deref(),
            Some(candidate().to_string()).as_deref()
        );
        assert!(
            marker.note.is_some(),
            "drop annotates the marker so reconciliation's reason is specific"
        );
    }

    #[test]
    fn reconcile_turns_a_dangling_marker_into_an_interrupted_record_and_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = fresh_log(dir.path());
        let attempt = AttemptId::new(1);
        log.append(
            Origin::Wardd,
            WardEvent::VerificationAttemptStarted {
                attempt,
                requested_by: VerifyRequester::User,
            },
            SystemTime::now(),
        )
        .unwrap();
        let guard = AttemptGuard::start(dir.path(), attempt, VerifyRequester::User).unwrap();
        guard.bind_candidate(candidate());
        drop(guard); // simulates the process dying mid-attempt: no finish() call.

        let n = reconcile_dangling_attempts(&mut log, dir.path()).unwrap();
        assert_eq!(n, 1);
        assert!(
            !marker_path(dir.path(), attempt).exists(),
            "the marker is removed once reconciled"
        );
        // Reconciling again finds nothing left to do.
        assert_eq!(
            reconcile_dangling_attempts(&mut log, dir.path()).unwrap(),
            0
        );

        log.sync().unwrap();
        let log_path = dir.path().join("events.log");
        let records = read_back(&log_path);
        let last = &records.last().unwrap().event;
        match last {
            WardEvent::VerificationInterrupted {
                attempt: got,
                candidate: got_candidate,
                reason,
            } => {
                assert_eq!(*got, attempt);
                assert_eq!(*got_candidate, Some(candidate()));
                assert!(!reason.as_str().is_empty());
            }
            other => panic!("expected VerificationInterrupted, got {other:?}"),
        }
    }

    #[test]
    fn reconcile_reports_no_candidate_when_the_attempt_never_captured_one() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = fresh_log(dir.path());
        let attempt = AttemptId::new(1);
        // No `bind_candidate`: the attempt died before capture even succeeded (#139
        // item 3 — never invent a digest for a failed capture).
        drop(AttemptGuard::start(dir.path(), attempt, VerifyRequester::User).unwrap());

        reconcile_dangling_attempts(&mut log, dir.path()).unwrap();
        log.sync().unwrap();
        let log_path = dir.path().join("events.log");
        let records = read_back(&log_path);
        match &records.last().unwrap().event {
            WardEvent::VerificationInterrupted { candidate, .. } => {
                assert_eq!(*candidate, None);
            }
            other => panic!("expected VerificationInterrupted, got {other:?}"),
        }
    }

    #[test]
    fn reconcile_removes_an_unparseable_marker_without_jamming_on_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = fresh_log(dir.path());
        let bad = attempts_dir(dir.path()).join("7.json");
        std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
        std::fs::write(&bad, b"not json").unwrap();

        let n = reconcile_dangling_attempts(&mut log, dir.path()).unwrap();
        assert_eq!(n, 0, "an unparseable marker reconciles no event");
        assert!(!bad.exists(), "but it is still cleared out");
    }

    #[test]
    fn reconcile_over_a_session_with_no_attempts_directory_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = fresh_log(dir.path());
        assert_eq!(
            reconcile_dangling_attempts(&mut log, dir.path()).unwrap(),
            0
        );
    }

    #[test]
    fn finalize_interrupted_appends_and_finishes_the_guard() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = fresh_log(dir.path());
        let attempt = AttemptId::new(1);
        let guard = AttemptGuard::start(dir.path(), attempt, VerifyRequester::User).unwrap();
        finalize_interrupted(
            &mut log,
            guard,
            attempt,
            None,
            ShortText::new("verify.prepare failed: no .tamperward/config.yml"),
        )
        .unwrap();
        assert!(!marker_path(dir.path(), attempt).exists());
        log.sync().unwrap();
        let log_path = dir.path().join("events.log");
        match &read_back(&log_path).last().unwrap().event {
            WardEvent::VerificationInterrupted { reason, .. } => {
                assert!(reason.as_str().contains("verify.prepare failed"));
            }
            other => panic!("expected VerificationInterrupted, got {other:?}"),
        }
    }
}
