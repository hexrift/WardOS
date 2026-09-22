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

use std::path::{Path, PathBuf};

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
/// when nothing has chosen one yet, or the file cannot be read or parsed: a
/// registry a desktop surface cannot read behaves exactly like no selection,
/// not an error, since every reader already has a fallback for "none chosen
/// yet" ([`crate::client::desktop_socket`] picks the newest live session and
/// records it).
#[must_use]
pub fn current(state: &Path) -> Selection {
    std::fs::read(path(state))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
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
    let file = path(state);
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let bytes = serde_json::to_vec_pretty(&next)
        .map_err(|e| Error::Daemon(format!("desktop selection: {e}")))?;
    std::fs::write(&file, bytes).map_err(|e| Error::io(&file, e))?;
    Ok(next)
}

/// Clear the selection back to "nothing chosen": the next resolution picks
/// one again (and records it), rather than following an id that was cleared
/// on purpose.
pub fn clear(state: &Path) -> Result<Selection> {
    select(state, None)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
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
}
