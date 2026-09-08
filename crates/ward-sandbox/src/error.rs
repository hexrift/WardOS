//! Error type for sandbox spec generation and the `crun` driver.

use std::path::PathBuf;

/// Errors raised while building specs or driving `crun`.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// An I/O operation failed (writing a bundle, spawning `crun`).
    #[error("io error at {path}: {source}")]
    Io {
        /// Path the operation was targeting.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Serialising the OCI spec to JSON failed.
    #[error("serialize spec: {0}")]
    Serialize(#[from] serde_json::Error),

    /// A `crun` invocation exited non-zero.
    #[error("crun {subcommand} for {id} failed (status {status}): {stderr}")]
    Crun {
        /// The `crun` subcommand that failed (`create`, `start`, ...).
        subcommand: &'static str,
        /// Container id passed to `crun`.
        id: String,
        /// Exit status code, or -1 if terminated by signal.
        status: i32,
        /// Captured standard error.
        stderr: String,
    },
}

/// Convenience alias for fallible sandbox operations.
pub type Result<T> = std::result::Result<T, SandboxError>;
