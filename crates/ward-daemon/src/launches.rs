//! Host-owned launch handles (#145 item 2).
//!
//! Every sandbox launch of a session has a stable handle from the moment it
//! is admitted: the sequence number of its own `CommandStarted` record, which
//! the daemon's single writer assigns (unique and monotonic by construction),
//! before any `bwrap` spawns. The daemon records each handle it admits in
//! `sessions/<id>/launches.json` ([`LAUNCHES`]) with the launch's logical pid
//! and when it was admitted, and marks how it ended — a terminal record on
//! the log (`CommandFinished`, `LaunchAborted`), or the connection that
//! started it going away with neither ([`LaunchState::Unknown`], which the
//! log alone cannot say). A daemon restarted on the session therefore knows
//! every launch it ever admitted and how each stands, without replaying the
//! log, and `ward pause --status --json` and `Request::Lifecycle` list the
//! handles still open.
//!
//! The file is bookkeeping beside the log, never a substitute for it: the
//! log's `CommandStarted` is where a handle is minted and its terminal record
//! is what ends it; this record adds the one state the log cannot carry and
//! an index a reader can take in at a glance. Append-only: a record is added
//! when a launch is admitted and its state rewritten when it ends; nothing is
//! removed.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ward_events::Pid;

use crate::error::{Error, Result};
use crate::session::session_dir;

/// File name of the launch register inside `sessions/<id>/`.
pub const LAUNCHES: &str = "launches.json";

/// How one launch stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchState {
    /// Admitted; no terminal record yet.
    Open,
    /// `CommandFinished` landed.
    Finished,
    /// `LaunchAborted` landed: the launch never ran to completion, or a stop
    /// ended it.
    Aborted,
    /// The connection that started it closed before any terminal record: the
    /// client process is gone and nothing will ever finish this launch, but
    /// the daemon cannot say whether its process or its credential route
    /// ended (`Served::disconnect_open_launches`).
    Unknown,
}

impl LaunchState {
    /// The state's name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Finished => "finished",
            Self::Aborted => "aborted",
            Self::Unknown => "unknown",
        }
    }
}

/// One admitted launch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchRecord {
    /// The handle: the launch's `CommandStarted` record's sequence number.
    pub handle: u64,
    /// The logical pid the client gave the launch (not a correlation key, see
    /// `Served::open_launches`; carried so a reader can match the log's rows).
    pub pid: Pid,
    /// When the launch was admitted, milliseconds since the Unix epoch.
    pub admitted_unix_ms: u64,
    /// How it stands.
    pub state: LaunchState,
    /// When it ended, for a launch that has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_unix_ms: Option<u64>,
}

/// Every launch a session admitted, oldest first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Launches {
    /// The records, in admission order.
    #[serde(default)]
    pub launches: Vec<LaunchRecord>,
}

impl Launches {
    /// Record that launch `handle` (pid `pid`) was admitted at `now`.
    pub fn admit(&mut self, handle: u64, pid: Pid, now: u64) {
        if self.launches.iter().any(|l| l.handle == handle) {
            return;
        }
        self.launches.push(LaunchRecord {
            handle,
            pid,
            admitted_unix_ms: now,
            state: LaunchState::Open,
            ended_unix_ms: None,
        });
    }

    /// Record that launch `handle` ended in `state` at `now`; whether it was
    /// open. A launch already ended keeps its first outcome.
    pub fn end(&mut self, handle: u64, state: LaunchState, now: u64) -> bool {
        match self
            .launches
            .iter_mut()
            .find(|l| l.handle == handle && l.state == LaunchState::Open)
        {
            Some(launch) => {
                launch.state = state;
                launch.ended_unix_ms = Some(now);
                true
            }
            None => false,
        }
    }

    /// The launches still open, oldest first.
    pub fn open(&self) -> impl Iterator<Item = &LaunchRecord> {
        self.launches
            .iter()
            .filter(|l| l.state == LaunchState::Open)
    }

    /// How launch `handle` stands, if it was ever admitted.
    #[must_use]
    pub fn state_of(&self, handle: u64) -> Option<LaunchState> {
        self.launches
            .iter()
            .find(|l| l.handle == handle)
            .map(|l| l.state)
    }
}

/// The launch register of `session`.
#[must_use]
pub fn path(state: &Path, session: &str) -> PathBuf {
    session_dir(state, session).join(LAUNCHES)
}

/// The launches `session` admitted, as recorded; none when nothing is
/// recorded. A register that cannot be parsed is an error: a daemon must not
/// serve a session whose launches it cannot name.
pub fn read(state: &Path, session: &str) -> Result<Launches> {
    let path = path(state, session);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Launches::default()),
        Err(e) => return Err(Error::io(&path, e)),
    };
    serde_json::from_slice(&bytes).map_err(|e| {
        Error::Daemon(format!(
            "{}: unreadable launch register: {e}",
            path.display()
        ))
    })
}

/// Record `launches` for `session`: written to a private temp file beside
/// [`path`] and renamed into place, so a reader never sees a partial file.
pub fn write(state: &Path, session: &str, launches: &Launches) -> Result<()> {
    let path = path(state, session);
    let bytes =
        serde_json::to_vec(launches).map_err(|e| Error::Events(format!("launches: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &bytes).map_err(|e| Error::io(&tmp, e))?;
    fs::rename(&tmp, &path).map_err(|e| Error::io(&path, e))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn pid(n: u32) -> Pid {
        Pid::new(n).unwrap()
    }

    #[test]
    fn a_register_admits_once_ends_once_and_lists_what_is_open() {
        let mut launches = Launches::default();
        launches.admit(4, pid(2), 100);
        launches.admit(4, pid(2), 101);
        launches.admit(9, pid(3), 200);
        assert_eq!(launches.launches.len(), 2, "a handle is admitted once");
        assert_eq!(
            launches.open().map(|l| l.handle).collect::<Vec<_>>(),
            [4, 9]
        );
        assert!(launches.end(4, LaunchState::Finished, 300));
        assert!(
            !launches.end(4, LaunchState::Aborted, 301),
            "a launch keeps its first outcome"
        );
        assert_eq!(launches.state_of(4), Some(LaunchState::Finished));
        assert_eq!(launches.launches[0].ended_unix_ms, Some(300));
        assert!(
            !launches.end(77, LaunchState::Unknown, 302),
            "never admitted"
        );
        assert_eq!(launches.state_of(77), None);
        assert_eq!(launches.open().map(|l| l.handle).collect::<Vec<_>>(), [9]);
        assert!(launches.end(9, LaunchState::Unknown, 400));
        assert_eq!(launches.open().count(), 0);
        for state in [
            LaunchState::Open,
            LaunchState::Finished,
            LaunchState::Aborted,
            LaunchState::Unknown,
        ] {
            assert!(!state.as_str().is_empty());
        }
    }

    #[test]
    fn the_register_round_trips_through_its_file_and_is_absent_until_written() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(session_dir(dir.path(), "sess_l")).unwrap();
        assert_eq!(read(dir.path(), "sess_l").unwrap(), Launches::default());
        let mut launches = Launches::default();
        launches.admit(4, pid(2), 100);
        launches.end(4, LaunchState::Aborted, 150);
        launches.admit(6, pid(2), 200);
        write(dir.path(), "sess_l", &launches).unwrap();
        assert_eq!(read(dir.path(), "sess_l").unwrap(), launches);
        let json = std::fs::read_to_string(path(dir.path(), "sess_l")).unwrap();
        assert!(json.contains(r#""state":"aborted""#), "{json}");
        assert!(json.contains(r#""handle":6"#), "{json}");
        assert!(
            !json.contains(r#""ended_unix_ms":null"#),
            "an open launch has no end: {json}"
        );
        std::fs::write(path(dir.path(), "sess_l"), b"{not json").unwrap();
        let err = read(dir.path(), "sess_l").unwrap_err().to_string();
        assert!(err.contains("unreadable launch register"), "{err}");
    }
}
