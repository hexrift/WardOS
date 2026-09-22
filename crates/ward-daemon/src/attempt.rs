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
//!
//! # A marker is not evidence its owner died (review of #208)
//!
//! A marker on disk means only "an attempt was allocated and has not finished yet" —
//! that is equally true of a healthy in-flight verification and of one an earlier,
//! now-dead process abandoned. [`reconcile_dangling_attempts`] therefore never treats
//! a marker's mere existence as dangling: each marker records the pid of the process
//! that wrote it, alongside that pid's own `/proc` start time (so a pid the kernel
//! later hands to an unrelated process is not mistaken for the original owner — see
//! [`owner_is_gone`]). Reconciliation only closes out a marker whose owning process is
//! verifiably gone, or whose marker was written by *this very process* (the only way
//! that can be asked about is a leftover the same process's own earlier `verify()`
//! call abandoned, never a concurrent one). This makes it safe to call
//! `reconcile_dangling_attempts` from every context that (re)takes ownership of a
//! session's log, including an ordinary client's `Session::open_current` — a second
//! `ward` invocation opening the same session can no longer ever interrupt a
//! verification another, still-running process is genuinely carrying out.
//!
//! # Crash-consistent markers
//!
//! A marker is the *only* durable evidence of a dangling attempt, so its own
//! writes and removals are made crash-safe: [`write_marker`] writes to a temp file
//! in the same directory, `fsync`s it, renames it into place, then `fsync`s the
//! directory; [`remove_marker_durably`] removes the file and `fsync`s the directory
//! afterward. A marker [`read_marker`] cannot parse — corrupt or truncated, most
//! likely from a crash mid-write before this scheme landed, or from disk damage —
//! is never silently deleted: [`reconcile_dangling_attempts`] still emits a terminal
//! record for it (its attempt id survives in the file name, which this process
//! controls and never trusts less than the content), then quarantines the original
//! bytes alongside it (`<attempt>.json.corrupt`) rather than destroying the only
//! evidence of what happened. Reconciliation is also terminal-aware: before treating
//! any marker as dangling, it checks whether the log already holds a terminal record
//! for that attempt, so a marker that resurfaces after a crash between a terminal
//! append and that marker's own not-yet-durable removal is retired quietly instead of
//! producing a second, contradictory terminal record.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// `<session_dir>/events.log`, exactly as `Session`/`serve` open it — reconciliation
/// needs read-only access to the log alongside the `Sink` it appends through, to
/// check whether an attempt already has a terminal record (`attempt_already_terminal`)
/// before ever treating its marker as dangling.
fn events_log_path(session_dir: &Path) -> PathBuf {
    session_dir.join("events.log")
}

/// Where a marker that fails to parse is preserved (`reconcile_dangling_attempts`)
/// instead of being silently deleted: alongside the original name so it is easy to
/// find, `.corrupt`-suffixed so it is never picked up as a live marker again (it no
/// longer has the `.json` extension the scan filters on).
fn quarantine_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("marker");
    path.with_file_name(format!("{name}.corrupt"))
}

/// A private temp path in the same directory as `path`, for the write-then-rename
/// [`write_marker`] uses to land an update atomically. Unique per call so a rapid
/// `start` immediately followed by `bind_candidate` (or two attempts racing, which
/// should not happen in the single-attempt-at-a-time model this crate uses today,
/// but costs nothing to make safe anyway) never collide.
fn tmp_marker_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("marker");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.with_file_name(format!(".{name}.{}.{nanos}.tmp", std::process::id()))
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
    /// The pid of the process that wrote this marker (`std::process::id()` at
    /// [`AttemptGuard::start`]). A marker alone is not evidence its owner died — it
    /// is equally present for a healthy in-flight attempt — so reconciliation never
    /// acts on one without first checking this pid (see [`owner_is_gone`]).
    pid: u32,
    /// `pid`'s own `/proc/<pid>/stat` start time, captured alongside it, so a pid
    /// the kernel later reuses for an unrelated process is never mistaken for the
    /// original owner still being alive. `None` when it could not be read (e.g. a
    /// non-Linux or minimal sandbox at the moment of writing) — reconciliation then
    /// treats a live `pid` as still owned, the safer default (see [`owner_is_gone`]).
    owner_started_ticks: Option<u64>,
}

/// `fsync` the regular file at `path` after writing `bytes` to it (truncating any
/// existing content) — the first half of the durable write [`write_marker`] performs
/// as write-temp / fsync / rename / fsync-directory.
fn write_file_durably(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    file.write_all(bytes).map_err(|e| Error::io(path, e))?;
    file.sync_all().map_err(|e| Error::io(path, e))
}

/// `fsync` a directory so a rename or unlink already applied to it survives a crash
/// (POSIX only guarantees a directory entry change is durable once its directory's
/// own fd has been synced, not merely the file that moved).
fn sync_dir(dir: &Path) -> Result<()> {
    let dir_file = std::fs::File::open(dir).map_err(|e| Error::io(dir, e))?;
    dir_file.sync_all().map_err(|e| Error::io(dir, e))
}

/// Write `marker` to `path` crash-consistently: the bytes land in a private temp
/// file in the same directory, are `fsync`'d, then atomically renamed over `path`
/// (a rename is a single directory-entry update — a crash before or after it never
/// leaves a half-written marker at `path` itself), and finally the directory is
/// `fsync`'d so the rename itself survives a crash immediately afterward.
fn write_marker(path: &Path, marker: &Marker) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        Error::Events(format!(
            "{}: attempt marker path has no parent directory",
            path.display()
        ))
    })?;
    std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    let bytes =
        serde_json::to_vec(marker).map_err(|e| Error::Events(format!("attempt marker: {e}")))?;
    let tmp = tmp_marker_path(path);
    write_file_durably(&tmp, &bytes)?;
    std::fs::rename(&tmp, path).map_err(|e| Error::io(path, e))?;
    sync_dir(parent)
}

/// What reading a marker file found: parsed content, benignly gone (a race with
/// whoever last touched it — never itself an error), or present but unreadable —
/// [`reconcile_dangling_attempts`] handles that last case by quarantining rather
/// than deleting, since a corrupt marker is still the only evidence of an attempt.
enum MarkerRead {
    Ok(Marker),
    Gone,
    Corrupt,
}

fn read_marker(path: &Path) -> MarkerRead {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return MarkerRead::Gone,
        Err(_) => return MarkerRead::Corrupt,
    };
    match serde_json::from_slice(&bytes) {
        Ok(marker) => MarkerRead::Ok(marker),
        Err(_) => MarkerRead::Corrupt,
    }
}

/// Remove the marker at `path` and make that removal durable by `fsync`ing its
/// directory afterward. An already-gone marker (removed by a concurrent pass, or by
/// [`AttemptGuard::finish`] racing a reconciliation pass) is not an error.
///
/// Best-effort by design at every call site that does not itself need to fail on a
/// cleanup problem: once a terminal record is durably appended and synced, a marker
/// that fails to be removed is untidy, never incorrect — the next reconciliation
/// pass finds the attempt already terminal (`attempt_already_terminal`) and retires
/// the leftover quietly rather than ever emitting a second terminal record for it.
fn remove_marker_durably(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io(path, e)),
    }
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

/// Preserve an unreadable marker at `path` by renaming it to [`quarantine_path`]
/// instead of deleting it, so the only evidence of whatever attempt it concerned
/// survives for inspection, then `fsync`s the directory so that rename is durable.
fn quarantine_marker(path: &Path) -> Result<()> {
    let target = quarantine_path(path);
    std::fs::rename(path, &target).map_err(|e| Error::io(path, e))?;
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

/// The attempt id encoded in a marker's own file name (`<attempt>.json`) — trusted
/// even when the file's *content* cannot be parsed, since this process controls the
/// naming scheme itself ([`marker_path`]). `None` for anything in the attempts
/// directory that this scheme did not create, which reconciliation then leaves
/// entirely alone.
fn attempt_id_from_filename(path: &Path) -> Option<u64> {
    path.file_stem()?.to_str()?.parse().ok()
}

/// The Linux `/proc/<pid>/stat` "starttime" field (proc(5)): the time `pid` started,
/// in clock ticks since boot. `None` once `pid` no longer exists (or, in a minimal
/// sandbox without `/proc`, always).
fn process_start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name between the parens can itself contain spaces or literal
    // parens; anchor on the *last* ')' the kernel is guaranteed to close it with,
    // exactly as `pause.rs`'s `parent_of` does for the same file. `starttime` is
    // proc(5) field 22 overall; fields 1 (pid) and 2 (the parenthesised comm) are
    // already consumed by that anchor, so it is index 19 of what `split_whitespace`
    // yields afterward.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Whether the process that wrote `marker` can no longer be the one a caller needs
/// to worry about (#139 item 1, the review of #208's finding 1): either it is
/// verifiably dead, or it *is* the process asking right now — which can only mean
/// the [`AttemptGuard`] for this marker already dropped earlier in this very
/// process (that is the only way this function could be reached with the marker
/// still on disk), so it is unconditionally stale, the same-process leftover
/// `Session::verify()`'s own opening reconciliation exists to close out.
///
/// A live pid that is *not* this process is never treated as gone: a marker's mere
/// existence is not evidence its owner died, it is equally present for a healthy
/// in-flight verification, and interrupting that attempt out from under it is
/// exactly the bug this function exists to close. Pid reuse is handled by comparing
/// `/proc`'s own start-time field rather than trusting a live pid alone.
fn owner_is_gone(marker: &Marker) -> bool {
    if marker.pid == std::process::id() {
        return true;
    }
    match process_start_ticks(marker.pid) {
        None => true,
        Some(now_ticks) => marker
            .owner_started_ticks
            .is_some_and(|then_ticks| then_ticks != now_ticks),
    }
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

/// Whether `attempt`'s own record in the log at `log_path` is already followed by a
/// terminal verification record: `Passed`, `Failed`, `Errored` (none of which carry
/// an `AttemptId` of their own — the single-attempt-at-a-time model this crate uses
/// today is what makes "the next one after this attempt's `AttemptStarted`" a safe
/// reading of them), or `Cancelled`/`Interrupted` naming this exact attempt.
/// Defensively, a *later* `AttemptStarted` for a different attempt also counts —
/// this attempt could only still be open if that had not yet begun. A log this
/// process cannot open, or that never even recorded this attempt starting, is not
/// terminal (the safe default: reconciliation still gets a chance to close it out).
///
/// This is what makes [`reconcile_dangling_attempts`] idempotent against a marker
/// that resurfaces after a crash between a terminal append and that marker's own
/// not-yet-durable removal (review of #208, finding 2): such a marker is retired
/// quietly instead of producing a second, contradictory terminal record.
fn attempt_already_terminal(log_path: &Path, attempt: AttemptId) -> bool {
    let Ok(reader) = ward_events::LogReader::open(log_path) else {
        return false;
    };
    let mut seen_start = false;
    for record in reader.filter_map(std::result::Result::ok) {
        match record.event {
            WardEvent::VerificationAttemptStarted { attempt: a, .. } => {
                if a == attempt {
                    seen_start = true;
                } else if seen_start {
                    return true;
                }
            }
            WardEvent::VerificationPassed { .. }
            | WardEvent::VerificationFailed { .. }
            | WardEvent::VerificationErrored { .. }
                if seen_start =>
            {
                return true;
            }
            WardEvent::VerificationCancelled { attempt: a, .. }
            | WardEvent::VerificationInterrupted { attempt: a, .. }
                if seen_start && a == attempt =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
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
        let pid = std::process::id();
        write_marker(
            &path,
            &Marker {
                attempt: attempt.get(),
                requested_by,
                candidate: None,
                started_unix_ms: unix_ms(SystemTime::now()),
                note: None,
                pid,
                owner_started_ticks: process_start_ticks(pid),
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
        if let MarkerRead::Ok(mut marker) = read_marker(&self.path) {
            marker.candidate = Some(candidate.to_string());
            let _ = write_marker(&self.path, &marker);
        }
    }

    /// The attempt reached a terminal record that was durably appended: remove the
    /// marker so no future reconciliation pass mistakes it for dangling.
    ///
    /// Best-effort, deliberately: the terminal record is already durably on the log
    /// by the time every caller reaches this, so a failure to remove the marker
    /// itself is untidy, never a correctness problem — `reconcile_dangling_attempts`
    /// is terminal-aware and idempotent (see [`attempt_already_terminal`]), so a
    /// marker that outlives this call is simply retired, quietly, the next time
    /// anything reconciles this session.
    pub fn finish(mut self) {
        self.finished = true;
        let _ = remove_marker_durably(&self.path);
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
        if let MarkerRead::Ok(mut marker) = read_marker(&self.path) {
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
///
/// A marker is only ever treated as dangling once its owning process is verifiably
/// gone, or it is this very process's own earlier leftover (see [`owner_is_gone`]) —
/// never merely because a marker exists, which is equally true of a healthy
/// in-flight attempt (review of #208, finding 1). Before acting on any marker,
/// reconciliation also checks whether its attempt already has a terminal record in
/// the log ([`attempt_already_terminal`]), so a marker that resurfaces after a crash
/// between a terminal append and its own not-yet-durable removal is retired quietly
/// instead of producing a duplicate, contradictory terminal record (finding 2).
/// Markers this pass cannot even parse are never silently deleted: their attempt id
/// (from the file name, which this process controls) still gets a terminal record
/// when one is not already on the log, and the unreadable original is quarantined
/// alongside it (`<attempt>.json.corrupt`) rather than destroyed.
///
/// Every failure mode here — the directory cannot be listed, the append or its sync
/// fails, or a marker cannot be removed/quarantined once its terminal record (if
/// any) is on the log — is returned, never swallowed (finding 3): every call site
/// propagates it rather than discarding it with `let _ = `.
///
/// Returns the number of attempts for which a `VerificationInterrupted` record was
/// newly appended (never counting one already found terminal, or a live one left
/// alone).
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

    let log_path = events_log_path(session_dir);
    let mut reconciled = 0usize;
    for path in paths {
        match read_marker(&path) {
            // Gone since the directory listing (a concurrent `finish()`, or a
            // concurrent reconciliation pass): nothing left to do, and not an error.
            MarkerRead::Gone => {}
            MarkerRead::Corrupt => {
                // Only this process's own naming scheme puts a `.json` file here; a
                // foreign one (no parseable numeric stem) is left completely alone.
                if let Some(id) = attempt_id_from_filename(&path) {
                    let attempt = AttemptId::new(id);
                    if !attempt_already_terminal(&log_path, attempt) {
                        sink.append(
                            Origin::Wardd,
                            WardEvent::VerificationInterrupted {
                                attempt,
                                candidate: None,
                                reason: ShortText::new(
                                    "this attempt's marker file could not be read (corrupt \
                                     or truncated, most likely a crash mid-write); the \
                                     original was quarantined alongside it for inspection",
                                ),
                            },
                            SystemTime::now(),
                        )?;
                        sink.sync()?;
                        reconciled += 1;
                    }
                    quarantine_marker(&path)?;
                }
            }
            MarkerRead::Ok(marker) => {
                let attempt = AttemptId::new(marker.attempt);
                if attempt_already_terminal(&log_path, attempt) {
                    // A resurrected marker (finding 2): its own attempt already has a
                    // terminal record, most likely because this exact marker's
                    // removal, after an earlier successful reconciliation or a normal
                    // `AttemptGuard::finish`, was not itself durable before a crash.
                    // Retire it without touching the log again.
                    remove_marker_durably(&path)?;
                    continue;
                }
                if !owner_is_gone(&marker) {
                    // A live, different process still owns this attempt (finding 1):
                    // never interrupt a verification on the strength of a marker
                    // file alone.
                    continue;
                }
                let candidate = marker.candidate.as_deref().and_then(|s| s.parse().ok());
                let reason = ShortText::new(marker.note.as_deref().unwrap_or(
                    "the process serving this session ended before the attempt reached a \
                     terminal result",
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
                // Durable before the marker — the only other evidence of this
                // attempt — is removed.
                sink.sync()?;
                remove_marker_durably(&path)?;
                reconciled += 1;
            }
        }
    }
    Ok(reconciled)
}

/// Test-only: write a marker for `attempt` naming `pid` as its owner, exactly as
/// [`AttemptGuard::start`] would for *this* process's own pid — used by
/// `session::tests` to prove `Session::open_current` never interrupts a live
/// attempt another process genuinely owns (review of #208, finding 1), without
/// `session.rs` needing to know this module's on-disk marker schema.
#[cfg(test)]
pub(crate) fn test_marker_owned_by(session_dir: &Path, attempt: AttemptId, pid: u32) -> Result<()> {
    write_marker(
        &marker_path(session_dir, attempt),
        &Marker {
            attempt: attempt.get(),
            requested_by: VerifyRequester::User,
            candidate: None,
            started_unix_ms: unix_ms(SystemTime::now()),
            note: None,
            pid,
            owner_started_ticks: process_start_ticks(pid),
        },
    )
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

    use std::process::{Child, Command, Stdio};

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

    /// A real, independently-alive child process, killed and reaped on drop — used
    /// to stand in for "another process is genuinely still running this attempt"
    /// without any fixed sleep duration to race against (mirrors the pattern
    /// `pause.rs`'s process-tree tests already use).
    struct LiveChild(Child);

    impl LiveChild {
        fn spawn() -> Self {
            Self(
                Command::new("sh")
                    .args(["-c", "while :; do :; done"])
                    .stdout(Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        }

        fn pid(&self) -> u32 {
            self.0.id()
        }
    }

    impl Drop for LiveChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A marker naming `pid` as its owner, with a correctly matching `/proc` start
    /// time when one can be read (a real spawned child always has one on Linux).
    fn marker_owned_by(attempt: AttemptId, pid: u32) -> Marker {
        Marker {
            attempt: attempt.get(),
            requested_by: VerifyRequester::User,
            candidate: None,
            started_unix_ms: unix_ms(SystemTime::now()),
            note: None,
            pid,
            owner_started_ticks: process_start_ticks(pid),
        }
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
        match read_marker(&marker_path(dir.path(), attempt)) {
            MarkerRead::Ok(marker) => assert!(marker.candidate.is_some()),
            _ => panic!("marker must still parse"),
        }
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
        let MarkerRead::Ok(marker) = read_marker(&marker_path(dir.path(), attempt)) else {
            panic!("the marker survives an unfinished guard's drop");
        };
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

    /// Review of #208, finding 1: a marker alone is not evidence its owner died — a
    /// live, *different* process's marker must be left completely alone, exactly as
    /// it would be if a second `ward` command merely opened the same session while a
    /// first one's `verify()` is still genuinely in flight.
    #[test]
    fn reconcile_leaves_a_marker_alone_while_its_owning_process_is_still_alive() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = fresh_log(dir.path());
        let attempt = AttemptId::new(1);
        let owner = LiveChild::spawn();
        let marker = marker_owned_by(attempt, owner.pid());
        write_marker(&marker_path(dir.path(), attempt), &marker).unwrap();

        let n = reconcile_dangling_attempts(&mut log, dir.path()).unwrap();
        assert_eq!(n, 0, "a live owner's attempt is never interrupted");
        assert!(
            marker_path(dir.path(), attempt).exists(),
            "the marker survives untouched"
        );
        log.sync().unwrap();
        assert!(
            read_back(&dir.path().join("events.log")).is_empty(),
            "nothing was appended for a still-owned attempt"
        );
    }

    /// The other half of the same finding: once that owning process actually exits,
    /// the exact same marker *is* reconciled — proving the fix is about the owner's
    /// liveness, not merely refusing to reconcile "second callers" outright.
    #[test]
    fn reconcile_closes_out_the_marker_once_its_owning_process_has_exited() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = fresh_log(dir.path());
        let attempt = AttemptId::new(1);
        let pid = {
            let owner = LiveChild::spawn();
            let pid = owner.pid();
            let marker = marker_owned_by(attempt, pid);
            write_marker(&marker_path(dir.path(), attempt), &marker).unwrap();
            pid
            // `owner` drops here: killed and reaped, so `pid` is genuinely gone by
            // the time reconciliation runs below.
        };
        assert!(
            crate::daemon::wait_until(std::time::Duration::from_secs(2), || {
                process_start_ticks(pid).is_none()
            }),
            "the child pid disappears from /proc once reaped"
        );

        let n = reconcile_dangling_attempts(&mut log, dir.path()).unwrap();
        assert_eq!(n, 1, "the now-dead owner's attempt is reconciled");
        assert!(!marker_path(dir.path(), attempt).exists());
        log.sync().unwrap();
        match &read_back(&dir.path().join("events.log"))
            .last()
            .unwrap()
            .event
        {
            WardEvent::VerificationInterrupted { attempt: got, .. } => {
                assert_eq!(*got, attempt);
            }
            other => panic!("expected VerificationInterrupted, got {other:?}"),
        }
    }

    /// A pid the kernel has since handed to an unrelated process must not be
    /// mistaken for the marker's original owner still being alive: the recorded
    /// `/proc` start time no longer matches, so the marker is reconciled rather than
    /// left dangling forever behind someone else's long-lived process.
    #[test]
    fn reconcile_treats_a_stale_start_time_as_a_reused_pid_not_a_live_owner() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = fresh_log(dir.path());
        let attempt = AttemptId::new(1);
        let owner = LiveChild::spawn();
        let mut marker = marker_owned_by(attempt, owner.pid());
        // Pretend the marker was written by a much earlier process that happened to
        // share this pid; a real start time here would never equal this.
        marker.owner_started_ticks = Some(1);
        write_marker(&marker_path(dir.path(), attempt), &marker).unwrap();

        let n = reconcile_dangling_attempts(&mut log, dir.path()).unwrap();
        assert_eq!(n, 1, "a mismatched start time means the real owner is gone");
    }

    /// Finding 2: a marker `reconcile_dangling_attempts` cannot parse is never
    /// silently deleted — its attempt id (from the file name) still gets a terminal
    /// record, and the unreadable original is quarantined, not destroyed.
    #[test]
    fn reconcile_quarantines_an_unparseable_marker_and_still_emits_a_terminal_record() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = fresh_log(dir.path());
        let bad = attempts_dir(dir.path()).join("7.json");
        std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
        std::fs::write(&bad, b"not json").unwrap();

        let n = reconcile_dangling_attempts(&mut log, dir.path()).unwrap();
        assert_eq!(
            n, 1,
            "the attempt id from the file name still gets a record"
        );
        assert!(
            !bad.exists(),
            "the corrupt original is moved, not left in place"
        );
        assert!(
            bad.with_file_name("7.json.corrupt").exists(),
            "…and preserved for inspection rather than deleted"
        );
        log.sync().unwrap();
        match &read_back(&dir.path().join("events.log"))
            .last()
            .unwrap()
            .event
        {
            WardEvent::VerificationInterrupted {
                attempt, candidate, ..
            } => {
                assert_eq!(attempt.get(), 7);
                assert_eq!(*candidate, None, "a corrupt marker never invents one");
            }
            other => panic!("expected VerificationInterrupted, got {other:?}"),
        }

        // Reconciling again finds nothing left under the `.json` extension the scan
        // filters on: the quarantined file is not picked up a second time.
        assert_eq!(
            reconcile_dangling_attempts(&mut log, dir.path()).unwrap(),
            0
        );
    }

    /// Finding 2, the crash-resurrection case: a marker whose attempt already has a
    /// terminal record in the log — as if an earlier `finish()`/reconciliation
    /// removed it, but a crash right after meant the removal itself never became
    /// durable and the marker resurfaced — must be retired quietly, never turned
    /// into a second, contradictory `VerificationInterrupted`.
    #[test]
    fn reconcile_is_idempotent_against_a_marker_resurrected_after_its_attempt_already_ended() {
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
        log.append(
            Origin::User,
            WardEvent::VerificationCancelled {
                attempt,
                candidate: None,
            },
            SystemTime::now(),
        )
        .unwrap();
        // The marker "resurrects": present on disk even though its attempt already
        // reached a terminal record above (its own removal was not durable before a
        // hypothetical crash right after the cancel).
        let owner = LiveChild::spawn();
        drop(owner); // dead by the time we reconcile, so liveness is not what saves it
        let marker = Marker {
            attempt: attempt.get(),
            requested_by: VerifyRequester::User,
            candidate: None,
            started_unix_ms: unix_ms(SystemTime::now()),
            note: None,
            pid: 999_999, // not this process, and (barring an absurd coincidence) dead
            owner_started_ticks: None,
        };
        write_marker(&marker_path(dir.path(), attempt), &marker).unwrap();

        let n = reconcile_dangling_attempts(&mut log, dir.path()).unwrap();
        assert_eq!(
            n, 0,
            "no new terminal record for an attempt that already has one"
        );
        assert!(
            !marker_path(dir.path(), attempt).exists(),
            "the resurrected marker is still cleaned up"
        );
        log.sync().unwrap();
        let records = read_back(&dir.path().join("events.log"));
        let interrupted = records
            .iter()
            .filter(|r| matches!(r.event, WardEvent::VerificationInterrupted { .. }))
            .count();
        assert_eq!(
            interrupted, 0,
            "the log must never end up with both Cancelled and Interrupted for one attempt"
        );
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

    /// Finding 3: a directory listing failure is surfaced from
    /// `reconcile_dangling_attempts`, never swallowed inside it.
    #[test]
    fn reconcile_surfaces_a_read_dir_failure() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = fresh_log(dir.path());
        // `attempts` exists as a plain file, not a directory: `read_dir` on it fails
        // with a real, privilege-independent error (not-a-directory), regardless of
        // who runs the test.
        std::fs::write(attempts_dir(dir.path()), b"not a directory").unwrap();

        let err = reconcile_dangling_attempts(&mut log, dir.path())
            .expect_err("a non-directory attempts path must not read as \"nothing to do\"");
        assert!(!err.to_string().is_empty());
    }

    /// A [`Sink`] whose `append` and/or `sync` can be made to fail on demand, to
    /// prove `reconcile_dangling_attempts` surfaces both failure kinds rather than
    /// swallowing them (finding 3).
    struct FailingSink {
        inner: LocalLog,
        fail_append: bool,
        fail_sync: bool,
    }

    impl Sink for FailingSink {
        fn append(
            &mut self,
            origin: Origin,
            event: WardEvent,
            at: SystemTime,
        ) -> Result<EventRecord> {
            if self.fail_append {
                return Err(Error::Events("simulated append failure".to_owned()));
            }
            self.inner.append(origin, event, at)
        }

        fn sync(&mut self) -> Result<()> {
            if self.fail_sync {
                return Err(Error::Events("simulated sync failure".to_owned()));
            }
            self.inner.sync()
        }

        fn seal(self: Box<Self>) -> Result<()> {
            Box::new(self.inner).seal()
        }

        fn stop(self: Box<Self>, reason: ward_events::EndReason) -> Result<()> {
            Box::new(self.inner).stop(reason)
        }
    }

    #[test]
    fn reconcile_surfaces_an_append_failure() {
        let dir = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new(1);
        drop(AttemptGuard::start(dir.path(), attempt, VerifyRequester::User).unwrap());
        let mut sink = FailingSink {
            inner: fresh_log(dir.path()),
            fail_append: true,
            fail_sync: false,
        };

        let err = reconcile_dangling_attempts(&mut sink, dir.path())
            .expect_err("an append failure must not be swallowed");
        assert!(err.to_string().contains("simulated append failure"));
        assert!(
            marker_path(dir.path(), attempt).exists(),
            "the marker is left in place when its terminal record could not be appended"
        );
    }

    #[test]
    fn reconcile_surfaces_a_sync_failure() {
        let dir = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new(1);
        drop(AttemptGuard::start(dir.path(), attempt, VerifyRequester::User).unwrap());
        let mut sink = FailingSink {
            inner: fresh_log(dir.path()),
            fail_append: false,
            fail_sync: true,
        };

        let err = reconcile_dangling_attempts(&mut sink, dir.path())
            .expect_err("a sync failure must not be swallowed");
        assert!(err.to_string().contains("simulated sync failure"));
        assert!(
            marker_path(dir.path(), attempt).exists(),
            "the marker is left in place when its terminal record was not durably synced"
        );
    }

    /// Finding 3: a marker that cannot be removed once its terminal record is
    /// durably on the log still surfaces that failure — the append itself is not
    /// undone or hidden, only the cleanup step is left visibly incomplete.
    #[test]
    fn reconcile_surfaces_a_quarantine_failure_after_the_terminal_record_still_lands() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = fresh_log(dir.path());
        let bad = attempts_dir(dir.path()).join("7.json");
        std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
        std::fs::write(&bad, b"not json").unwrap();
        // Pre-occupy the quarantine destination with a directory: renaming a file
        // onto an existing directory fails (EISDIR) regardless of privilege, so this
        // is deterministic whether the suite runs as root or not.
        std::fs::create_dir_all(bad.with_file_name("7.json.corrupt")).unwrap();

        let err = reconcile_dangling_attempts(&mut log, dir.path())
            .expect_err("a quarantine failure must not be swallowed");
        assert!(!err.to_string().is_empty());
        log.sync().unwrap();
        match &read_back(&dir.path().join("events.log"))
            .last()
            .unwrap()
            .event
        {
            WardEvent::VerificationInterrupted { attempt, .. } => assert_eq!(attempt.get(), 7),
            other => panic!(
                "the terminal record must still have been appended before the \
                 cleanup step failed, got {other:?}"
            ),
        }
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
