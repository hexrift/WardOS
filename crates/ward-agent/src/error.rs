//! Error type for the in-sandbox shim.

use std::path::PathBuf;

/// Errors raised while applying inner hardening or supervising the agent.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// Building or enforcing the Landlock ruleset failed.
    #[error("landlock: {0}")]
    Landlock(#[from] landlock::RulesetError),

    /// The kernel offers no Landlock at all and `--allow-no-landlock` was not given.
    #[error("landlock is unavailable on this kernel ({status}); refusing to exec without it")]
    LandlockUnavailable {
        /// What the `landlock` crate reported for the running kernel.
        status: String,
    },

    /// A read-write path does not exist, so the agent would have no writable root.
    #[error("read-write path does not exist: {0}")]
    MissingRwPath(PathBuf),

    /// The seccomp profile could not be converted, compiled or installed.
    #[error("seccomp: {0}")]
    Seccomp(#[from] seccompiler::Error),

    /// The seccomp profile is malformed (e.g. an `Errno` rule with no errno).
    #[error("seccomp profile: {0}")]
    Profile(String),

    /// The compile host architecture has no seccompiler target.
    #[error("unsupported architecture for seccomp: {0}")]
    UnsupportedArch(String),

    /// A raw system call wrapper failed.
    #[error("{context}: {source}")]
    Sys {
        /// What was being attempted.
        context: &'static str,
        /// Underlying errno.
        source: nix::Error,
    },

    /// Reading or clearing a capability set failed.
    #[error("capabilities: {0}")]
    Caps(String),

    /// Spawning the agent process failed.
    #[error("spawn {program}: {source}")]
    Spawn {
        /// The program that could not be started.
        program: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

impl From<seccompiler::BackendError> for AgentError {
    fn from(error: seccompiler::BackendError) -> Self {
        Self::Seccomp(error.into())
    }
}

impl AgentError {
    /// Attach context to a `nix` error.
    pub fn sys(context: &'static str) -> impl FnOnce(nix::Error) -> Self {
        move |source| Self::Sys { context, source }
    }
}

/// Convenience alias for fallible shim operations.
pub type Result<T> = std::result::Result<T, AgentError>;
