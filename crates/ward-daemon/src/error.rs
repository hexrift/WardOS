//! Daemon error type.

use std::path::PathBuf;

/// Errors from session setup and execution.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A filesystem operation failed.
    #[error("io error at {path}: {source}")]
    Io {
        /// Path involved.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The project directory was not a usable project.
    #[error("{0}")]
    Project(String),
    /// Policy loading or merge failed.
    #[error("policy: {0}")]
    Policy(String),
    /// Snapshot capture failed.
    #[error("snapshot: {0}")]
    Snapshot(String),
    /// Event log or id construction failed.
    #[error("events: {0}")]
    Events(String),
    /// The sandbox runtime (bubblewrap) failed to launch.
    #[error("sandbox: {0}")]
    Sandbox(String),
    /// The session daemon (`wardd`) could not be started, bound, or reached.
    #[error("daemon: {0}")]
    Daemon(String),
    /// A verification attempt was cancelled before it reached a pass/fail result
    /// (#139): a distinct outcome from every other variant here, so a caller (and
    /// `Session::verify`'s own terminal-record finalisation) can tell "the user
    /// cancelled this" apart from "something went wrong".
    #[error("verification cancelled: {0}")]
    Cancelled(String),
    /// The filesystem backing `<state>/cas` has less free space than
    /// [`crate::space`]'s configured minimum, so an expensive CAS-writing
    /// operation (a worktree capture) was refused before it started rather than
    /// left to fail partway through (#151 item 6). Pure preflight: this is never
    /// produced by, and never itself triggers, any deletion — the previous valid
    /// snapshot and its receipt are untouched either way.
    #[error(
        "not enough free disk space at {path} to start: {} free, {} needed — \
         run `ward snapshot gc` to reclaim reachable-but-unneeded snapshots, or \
         `ward snapshot usage` to see what is using the space",
        crate::render::human_bytes(*available),
        crate::render::human_bytes(*required)
    )]
    LowSpace {
        /// The CAS root whose backing filesystem was checked.
        path: PathBuf,
        /// Free space at check time, in bytes.
        available: u64,
        /// The configured minimum required to proceed, in bytes.
        required: u64,
    },
}

/// Daemon result alias.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
