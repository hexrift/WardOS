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
