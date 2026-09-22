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

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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

/// The registry's contents, or the empty selection (`None`, generation 0)
/// when nothing has chosen one yet: a registry that has simply never been
/// written behaves exactly like no selection, not an error, since every
/// reader already has a fallback for "none chosen yet" ([`crate::client::
/// desktop_socket`] picks the newest live session and records it). A file
/// that exists but could not actually be read (permissions, a full disk, …)
/// is a different thing — folding that into generation 0 the same way would
/// let a stale [`select_if_unchanged`] compare-and-swap believe nothing has
/// changed when it cannot tell either way, so that case is surfaced instead
/// of swallowed. A file that exists, was read, but is not valid JSON is still
/// folded into the default: every writer here goes through [`write_atomic`],
/// so that can only mean something outside WardOS wrote garbage over it, not
/// a torn write this registry could have produced itself.
#[must_use]
pub fn current(state: &Path) -> Selection {
    match std::fs::read(path(state)) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Selection::default(),
        Err(e) => {
            // No logging of its own in this crate (ward-cli/ward-shell own
            // stdout and stderr); every caller already has a fallback for
            // "no selection", so this still degrades instead of aborting
            // whatever asked — but it is not silent about why (#141 finding
            // 2: an actionable read error must not be indistinguishable from
            // "nothing chosen yet").
            eprintln!(
                "ward: desktop selection at {} unreadable: {e}",
                path(state).display()
            );
            Selection::default()
        }
    }
}

/// Record `session` as the desktop's selection and return the new
/// [`Selection`] — its generation always one more than what was there before,
/// even when `session` repeats the value already stored: a switcher
/// re-confirming the same session is still a change it can observe.
pub fn select(state: &Path, session: Option<&str>) -> Result<Selection> {
    let next = Selection {
        session: session.map(ToOwned::to_owned),
        generation: current(state).generation + 1,
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
/// win, not be undone by the automatic choice arriving after it. This
/// re-reads the registry right before writing and, when its generation no
/// longer matches `expected`, writes nothing and simply returns the registry
/// as it now stands — the caller's stale decision loses, silently, the same
/// way a losing compare-and-swap always does. (The re-read and the write are
/// still two separate filesystem operations, not one atomic step, so this
/// narrows the race to the gap between them rather than closing it
/// completely; nothing in this registry's callers needs more than that.)
pub fn select_if_unchanged(
    state: &Path,
    session: Option<&str>,
    expected: u64,
) -> Result<Selection> {
    let now = current(state);
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
/// whole new one, never a mix (#141 finding 2).
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
    std::fs::rename(&tmp, path).map_err(|e| Error::io(path, e))
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
}
