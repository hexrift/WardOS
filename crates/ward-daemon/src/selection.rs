//! The desktop's session registry (#141): one explicit, shared selection that
//! the bar, the switcher, `wardos-approve` and `wardos-pause` all read instead
//! of each independently recomputing "the newest live session" and risking a
//! different answer from its neighbour whenever a session starts or ends
//! between their two computations.
//!
//! WardOS is single-seat: one desktop, one user, one registry. A [`Selection`]
//! is host state, not session state — it lives directly under the state root,
//! next to `sessions/` and `projects/`, not inside any one session's
//! directory, so it outlives every session it has ever named.
//!
//! This registry is consulted, not obeyed: [`crate::client::desktop_socket`]
//! reads it only as a *fallback* default (after an explicit session id and
//! after the calling directory's own current session), and only when the
//! session it names is still live — an ended selection is replaced, not
//! followed into an error. Nothing that already has a concrete, immutable
//! session id in hand — an approval's `--session`, a pinned "pause this
//! session" — ever consults this file at all, which is what item 6 of #141
//! asks for: changing the selection must never retarget an action already
//! bound to a session.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The desktop's current pick, and how many times it has been set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selection {
    /// The selected session, when one has been chosen — explicitly (the
    /// switcher), or picked automatically the first time some desktop-wide
    /// surface needed one and none had been chosen yet.
    pub session: Option<String>,
    /// Bumped by every [`select`], including one that repeats the same id: a
    /// count of changes, not just the value now. The switcher uses it to tell
    /// "the selection I just read is still current" from "someone else moved
    /// it out from under me" without needing to compare full snapshots.
    pub generation: u64,
}

/// Where the registry lives under `state`.
fn path(state: &Path) -> PathBuf {
    state.join("desktop-selection.json")
}

/// `<state>/desktop-selection.lock`: a sibling of the registry itself, whose
/// only role is something to hold an OS `flock` on — never read or written.
/// [`lock_selection`] is what actually closes the race review 5284361040 of
/// #210 (finding 1) describes: `select_if_unchanged`'s old shape re-read the
/// registry and then wrote it as two separate filesystem operations, so an
/// explicit [`select`] landing in that gap could still be undone by a stale
/// automatic fallback finishing after it. Every write transaction below now
/// holds this lock for its whole read-compare-write critical section, so a
/// concurrent transaction — another thread, or an entirely separate
/// `ward`/`wardd` process — cannot interleave with it at all, not just less
/// often. See `attempt.rs`'s `lock_session_reconciliation` for the same
/// idiom guarding a different registry's read-compare-write section: an OS
/// `flock` on an open file description needs no staleness recovery, since
/// the kernel releases it the instant the holder's last reference closes,
/// including on a crash.
fn lock_path(state: &Path) -> PathBuf {
    state.join("desktop-selection.lock")
}

/// Acquire the exclusive, whole-registry lock for one read-compare-write
/// transaction. Blocks until any other transaction currently inside
/// [`select`], [`select_if_unchanged`] or [`clear`] — another thread, or an
/// entirely separate `ward`/`wardd` process — releases theirs (review
/// 5284361040 of #210, finding 1).
fn lock_selection(state: &Path) -> Result<Flock<File>> {
    let path = lock_path(state);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    // Only this file's *existence* matters — it is never read or written —
    // so an already-present lock file (from an earlier transaction) is
    // opened as-is rather than truncated.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| Error::io(&path, e))?;
    Flock::lock(file, FlockArg::LockExclusive)
        .map_err(|(_, errno)| Error::io(&path, std::io::Error::from(errno)))
}

/// The registry's contents, or the empty selection (`None`, generation 0)
/// when nothing has chosen one yet: a registry that has simply never been
/// written behaves exactly like no selection, not an error, since every
/// reader already has a fallback for "none chosen yet" ([`crate::client::
/// desktop_socket`] picks the newest live session and records it). This
/// degrades a genuine read failure the same way, logging why rather than
/// staying silent about it (#141 finding 2) — every caller of `current`
/// already has its own fallback for "no selection", so aborting whatever
/// asked would only replace one degraded answer with a harder failure it is
/// not equipped to handle; [`read_for_write`] is the read the *write* side
/// uses instead, precisely because it cannot afford that same latitude
/// (review 5284361040 of #210, finding 1).
#[must_use]
pub fn current(state: &Path) -> Selection {
    read_for_write(state).unwrap_or_else(|e| {
        eprintln!(
            "ward: desktop selection at {} unreadable: {e}",
            path(state).display()
        );
        Selection::default()
    })
}

/// The registry's contents for a locked read-compare-write transaction:
/// `Ok(default)` both for "not written yet" and for "written, but not valid
/// JSON" — every writer here goes through [`write_atomic`], so a file that
/// exists, was read, but does not parse can only mean something outside
/// WardOS wrote garbage over it, not a torn write this registry could have
/// produced itself, and is therefore safe to treat as a reset the same way
/// [`current`] does. A real I/O failure (permissions, a full disk, a path
/// that is not even a regular file) is different: `Err`, not folded into
/// generation 0. Called only while holding [`lock_selection`], so together
/// they are what actually closes finding 1's race — folding *this* case into
/// generation 0 the way an ordinary reader may would let a write proceed, or
/// a stale [`select_if_unchanged`] believe nothing has changed, while
/// genuinely unable to tell what is on disk.
fn read_for_write(state: &Path) -> Result<Selection> {
    match std::fs::read(path(state)) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).unwrap_or_default()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Selection::default()),
        Err(e) => Err(Error::io(path(state), e)),
    }
}

/// Record `session` as the desktop's selection and return the new
/// [`Selection`] — its generation always one more than what was there before,
/// even when `session` repeats the value already stored: a switcher
/// re-confirming the same session is still a change it can observe. Holds
/// [`lock_selection`] for its entire read-compare-write transaction, so two
/// concurrent `select` calls can no longer both read the same generation and
/// both win a write (review 5284361040 of #210, finding 1: the previous,
/// unlocked shape had the same lost-update race `select_if_unchanged`'s
/// compare-and-swap did).
pub fn select(state: &Path, session: Option<&str>) -> Result<Selection> {
    let _guard = lock_selection(state)?;
    let next = Selection {
        session: session.map(ToOwned::to_owned),
        generation: read_for_write(state)?.generation + 1,
    };
    write_selection(state, &next)?;
    Ok(next)
}

/// [`select`], but only when the registry's generation is still `expected` —
/// the compare-and-swap [`crate::client::desktop_socket`]'s automatic
/// fallback needs (#141 finding 2): it observes the registry once to decide a
/// fallback is needed, then (picking the newest live session can itself take
/// a while — connecting to every session's socket) writes its pick. A
/// concurrent, explicit `ward session select` landing in that gap must always
/// win, not be undone by the automatic choice arriving after it.
///
/// The whole read-compare-write transaction now runs under [`lock_selection`]
/// (review 5284361040 of #210, finding 1): the previous shape re-read the
/// registry and wrote it as two separate filesystem operations, which only
/// narrowed the race to the gap between them (its own doc comment said so)
/// rather than closing it — a concurrent explicit `select` could still land
/// in exactly that gap and be undone by this function's write landing after
/// it. With the whole transaction under one lock, nothing can write between
/// this function's read and its own write at all, so an explicit selection
/// that lands anywhere around this call either happens entirely before it
/// (and this call sees it, declines, and hands it back unharmed) or entirely
/// after it (and is simply the newer state) — never in between.
pub fn select_if_unchanged(
    state: &Path,
    session: Option<&str>,
    expected: u64,
) -> Result<Selection> {
    select_if_unchanged_locked(state, session, expected, || {})
}

/// [`select_if_unchanged`]'s transaction, with a seam only test code uses: a
/// callback run after the locked read and before the write, so a test can
/// hold the lock open at exactly the point review 5284361040 of #210
/// (finding 1) used to be exploitable, and prove a concurrent transaction
/// really cannot land there any more — not by luck of thread scheduling, but
/// because it blocks on the same lock. Production callers always pass a
/// no-op here; this is the one CAS `select_if_unchanged` runs either way, not
/// a second code path grown just for the test.
fn select_if_unchanged_locked(
    state: &Path,
    session: Option<&str>,
    expected: u64,
    between_read_and_write: impl FnOnce(),
) -> Result<Selection> {
    let _guard = lock_selection(state)?;
    let now = read_for_write(state)?;
    between_read_and_write();
    if now.generation != expected {
        return Ok(now);
    }
    let next = Selection {
        session: session.map(ToOwned::to_owned),
        generation: now.generation + 1,
    };
    write_selection(state, &next)?;
    Ok(next)
}

/// Clear the selection back to "nothing chosen": the next resolution picks
/// one again (and records it), rather than following an id that was cleared
/// on purpose.
pub fn clear(state: &Path) -> Result<Selection> {
    select(state, None)
}

/// Serialise and durably write `next` as the registry's contents.
fn write_selection(state: &Path, next: &Selection) -> Result<()> {
    let file = path(state);
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let bytes = serde_json::to_vec_pretty(next)
        .map_err(|e| Error::Daemon(format!("desktop selection: {e}")))?;
    write_atomic(&file, &bytes)
}

/// Write `bytes` to `path` atomically: a sibling temp file, fsync'd, then
/// renamed over `path` — the same idiom `ward-snapshot`'s content-addressed
/// store (`crates/ward-snapshot/src/cas.rs`, its own private `write_atomic`)
/// already uses for the same problem. An unlocked `fs::write` can be
/// interrupted partway (the process killed, the disk full), and a concurrent
/// reader can then observe a truncated or partial file; a `rename` within one
/// filesystem is atomic, so a reader only ever sees the whole old file or the
/// whole new one, never a mix (#141 finding 2). The rename's directory entry
/// is then `fsync`'d too (review 5284361040 of #210, finding 1: "fsync the
/// parent directory if durability is claimed") — a `rename` is atomic the
/// instant it completes, but on most filesystems that is not yet a promise
/// it survives a crash immediately after until the directory's own inode is
/// synced, the same requirement `attempt.rs`'s `sync_dir` follows for its own
/// atomically-written markers.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| Error::io(&tmp, e))?;
        f.write_all(bytes).map_err(|e| Error::io(&tmp, e))?;
        f.sync_all().map_err(|e| Error::io(&tmp, e))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| Error::io(path, e))?;
    sync_dir(dir)
}

/// `fsync` a directory itself, so a rename or create within it is durable
/// against a crash immediately after — the same pattern `attempt.rs::sync_dir`
/// uses for its own atomically-written markers (review 5284361040 of #210,
/// finding 1).
fn sync_dir(dir: &Path) -> Result<()> {
    let dir_file = std::fs::File::open(dir).map_err(|e| Error::io(dir, e))?;
    dir_file.sync_all().map_err(|e| Error::io(dir, e))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn nothing_written_yet_reads_as_no_selection_at_generation_zero() {
        let state = tempfile::tempdir().unwrap();
        assert_eq!(current(state.path()), Selection::default());
        assert_eq!(current(state.path()).generation, 0);
    }

    #[test]
    fn select_persists_and_bumps_the_generation_on_every_call() {
        let state = tempfile::tempdir().unwrap();
        let first = select(state.path(), Some("sess_a")).unwrap();
        assert_eq!(first.session.as_deref(), Some("sess_a"));
        assert_eq!(first.generation, 1);
        assert_eq!(current(state.path()), first);

        // The same id again still counts as a change: the generation moves.
        let again = select(state.path(), Some("sess_a")).unwrap();
        assert_eq!(again.session.as_deref(), Some("sess_a"));
        assert_eq!(again.generation, 2);

        let switched = select(state.path(), Some("sess_b")).unwrap();
        assert_eq!(switched.session.as_deref(), Some("sess_b"));
        assert_eq!(switched.generation, 3);
        assert_eq!(current(state.path()), switched);
    }

    #[test]
    fn clear_records_no_selection_as_its_own_change() {
        let state = tempfile::tempdir().unwrap();
        select(state.path(), Some("sess_a")).unwrap();
        let cleared = clear(state.path()).unwrap();
        assert_eq!(cleared.session, None);
        assert_eq!(cleared.generation, 2);
        assert_eq!(current(state.path()).session, None);
    }

    #[test]
    fn a_corrupt_registry_reads_as_no_selection_rather_than_failing() {
        let state = tempfile::tempdir().unwrap();
        std::fs::write(path(state.path()), b"not json").unwrap();
        assert_eq!(current(state.path()), Selection::default());
        // Writing still works: a bad file is replaced, not preserved.
        let after = select(state.path(), Some("sess_a")).unwrap();
        assert_eq!(after.generation, 1);
    }

    /// #141 finding 2: `desktop_socket`'s automatic fallback observes the
    /// registry, does slower work (probing every live session's socket for
    /// "newest"), then writes its pick — and a concurrent, *explicit*
    /// `ward session select` landing in that gap must win. `select_if_unchanged`
    /// is the compare-and-swap this needs: handed the generation the fallback
    /// observed before the race, it must write nothing once that generation is
    /// stale, and hand back the winner instead.
    #[test]
    fn select_if_unchanged_never_clobbers_a_newer_concurrent_explicit_select() {
        let state = tempfile::tempdir().unwrap();
        // The fallback's observation: nothing chosen yet, generation 0.
        let observed = current(state.path());
        assert_eq!(observed.generation, 0);

        // The race: an explicit select lands before the fallback writes.
        let explicit = select(state.path(), Some("sess_user_picked")).unwrap();
        assert_eq!(explicit.generation, 1);

        // The fallback, still holding the stale generation 0 it observed
        // before the race, must lose: its write never reaches disk.
        let result =
            select_if_unchanged(state.path(), Some("sess_auto_newest"), observed.generation)
                .unwrap();
        assert_eq!(
            result, explicit,
            "the fallback is handed the winner instead of overwriting it"
        );
        assert_eq!(
            current(state.path()),
            explicit,
            "the concurrent explicit select is untouched by the losing fallback"
        );
    }

    /// The non-race path: when nothing has changed since the caller observed
    /// the registry, `select_if_unchanged` behaves exactly like `select`.
    #[test]
    fn select_if_unchanged_writes_when_nothing_raced_it() {
        let state = tempfile::tempdir().unwrap();
        let observed = current(state.path());
        let result =
            select_if_unchanged(state.path(), Some("sess_auto_newest"), observed.generation)
                .unwrap();
        assert_eq!(result.session.as_deref(), Some("sess_auto_newest"));
        assert_eq!(result.generation, 1);
        assert_eq!(current(state.path()), result);
    }

    /// #141 finding 2: an unlocked `fs::write` can expose a truncated or
    /// partial file to a concurrent reader; the atomic temp-file-plus-rename
    /// write this registry now uses must never let that happen, no matter how
    /// many writers race. Every snapshot a reader takes while several threads
    /// hammer `select` must be either "not written yet" or a whole, parseable
    /// [`Selection`] — never a torn one.
    #[test]
    fn concurrent_writers_never_expose_a_torn_or_partial_file() {
        let state = tempfile::tempdir().unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writers: Vec<_> = (0..2)
            .map(|i| {
                let dir = state.path().to_path_buf();
                let stop = std::sync::Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut n: u32 = 0;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        select(&dir, Some(&format!("sess_{i}_{n}"))).unwrap();
                        n += 1;
                        std::thread::yield_now();
                    }
                })
            })
            .collect();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let mut successful_reads = 0;
        while std::time::Instant::now() < deadline {
            match std::fs::read(path(state.path())) {
                Ok(bytes) => {
                    serde_json::from_slice::<Selection>(&bytes)
                        .unwrap_or_else(|e| panic!("torn read of {bytes:?}: {e}"));
                    successful_reads += 1;
                }
                // Not written yet — fine, just not what this loop is looking for.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => panic!("unexpected read error: {e}"),
            }
        }

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for writer in writers {
            writer.join().unwrap();
        }
        assert!(
            successful_reads > 0,
            "the race window produced no successful read at all; widen it rather than \
             treating that as proof of anything"
        );
    }

    /// Review 5284361040 of #210, finding 1: the old `select_if_unchanged`
    /// re-read the registry and then wrote it as two separate filesystem
    /// operations, so a concurrent, explicit `select` landing in exactly that
    /// gap could still be undone by the fallback's write arriving after it —
    /// its own doc comment said this only narrowed the race. This pauses a
    /// simulated fallback, via the test-only hook, right after its locked
    /// read and before its write — precisely that former gap — while a real
    /// concurrent `select` (the explicit user choice) is spawned and races to
    /// commit. Because the fallback already holds `lock_selection` before the
    /// pause even begins, the explicit call cannot acquire it — and therefore
    /// cannot write — until the fallback's own write has completed and the
    /// lock is released: the gap the old code exposed no longer exists for
    /// anything to land in. The assertion is on the only thing that would
    /// ever matter to a caller: the fallback's write must never be what is on
    /// disk once the explicit selection has also run.
    #[test]
    fn select_if_unchanged_barrier_never_lets_a_paused_fallback_clobber_a_concurrent_explicit_select()
     {
        let state = tempfile::tempdir().unwrap();
        let state_path = state.path().to_path_buf();

        let (paused_tx, paused_rx) = std::sync::mpsc::channel::<()>();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel::<()>();

        // The simulated fallback: observed generation 0 (nothing chosen
        // yet), same as `desktop_socket`'s real fallback would before its
        // slow "newest live session" probe.
        let fallback = std::thread::spawn(move || {
            select_if_unchanged_locked(&state_path, Some("sess_auto_newest"), 0, || {
                // Still holding `lock_selection` here — the read is done,
                // the write has not happened yet. Tell the main thread it is
                // safe to try the explicit select, then wait to be released.
                paused_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
            })
        });

        // Only spawned once the fallback is confirmed to be paused mid-lock,
        // so this genuinely contends for `lock_selection` rather than
        // happening to run before or after it by scheduling luck.
        paused_rx.recv().unwrap();
        let state_path = state.path().to_path_buf();
        let explicit = std::thread::spawn(move || select(&state_path, Some("sess_user_picked")));

        // Let the fallback proceed to its write now that the explicit call
        // is contending for the same lock.
        resume_tx.send(()).unwrap();

        let fallback_result = fallback.join().unwrap().unwrap();
        let explicit_result = explicit.join().unwrap().unwrap();

        assert_eq!(
            fallback_result.session.as_deref(),
            Some("sess_auto_newest"),
            "the fallback still matched its expected generation and wrote"
        );
        assert_eq!(explicit_result.session.as_deref(), Some("sess_user_picked"));
        assert_eq!(
            current(state.path()),
            explicit_result,
            "the fallback's write must never be what is left on disk once the \
             explicit selection has also run — it is serialized strictly after \
             the fallback, never interleaved with it"
        );
    }

    /// Review 5284361040 of #210, finding 1: "Plain `select` has the same
    /// lost-update generation race between concurrent writers" as the
    /// unlocked `select_if_unchanged` did. Many threads calling `select`
    /// concurrently must never let two of them read the same generation and
    /// both write `generation + 1` — every call's bump must actually count,
    /// with none lost to a race. If it does, the final generation would be
    /// less than the number of calls made.
    #[test]
    fn concurrent_selects_never_lose_a_generation_bump_to_a_racing_reader() {
        let state = tempfile::tempdir().unwrap();
        let per_thread: u64 = 50;
        let threads: u64 = 4;
        let writers: Vec<_> = (0..threads)
            .map(|i| {
                let dir = state.path().to_path_buf();
                std::thread::spawn(move || {
                    for n in 0..per_thread {
                        select(&dir, Some(&format!("sess_{i}_{n}"))).unwrap();
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        assert_eq!(
            current(state.path()).generation,
            threads * per_thread,
            "every one of {} concurrent select() calls must bump the generation \
             by exactly one; a lower count means two calls raced on the same read",
            threads * per_thread
        );
    }

    /// Review 5284361040 of #210, finding 1: a real read failure — not
    /// "never written yet", not "written but not valid JSON" — must not be
    /// silently folded into generation 0 by the write side the way `current`
    /// folds it for an ordinary reader. A directory in the registry's place
    /// produces a real `io::Error` (`ENOTDIR`) on read that is not
    /// `NotFound`, so this stands in for a permissions failure or a full disk
    /// without relying on this test running unprivileged.
    #[test]
    fn select_and_select_if_unchanged_surface_a_real_read_failure_instead_of_guessing_generation_zero()
     {
        let state = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(path(state.path())).unwrap();

        let err = select(state.path(), Some("sess_a")).unwrap_err();
        assert!(
            matches!(err, Error::Io { .. }),
            "expected an io error, got {err:?}"
        );
        let err = select_if_unchanged(state.path(), Some("sess_a"), 0).unwrap_err();
        assert!(
            matches!(err, Error::Io { .. }),
            "expected an io error, got {err:?}"
        );

        // `current` is used by callers that already have their own fallback
        // for "no selection" (the doc comment on `current` explains why);
        // it still degrades rather than erroring, since it is the write
        // side's compare-and-swap that cannot afford to guess.
        assert_eq!(current(state.path()), Selection::default());
    }
}
