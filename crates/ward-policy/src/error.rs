//! Error types for policy parsing, merging, hashing and loading.

use std::path::PathBuf;

/// Errors produced while parsing or validating a policy document, or while hashing
/// policies and manifests.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// The document is not valid YAML or does not match the schema (unknown field,
    /// wrong type, missing required field).
    #[error("policy schema error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// `agent.filesystem.host` may only ever be `deny`.
    #[error("agent.filesystem.host: only `deny` is accepted (got `{0}`)")]
    HostFilesystemNotDeny(String),

    /// `agent.network.deny_private_networks` may only ever be `true`.
    #[error("agent.network.deny_private_networks: must be `true`")]
    PrivateNetworksMustBeDenied,

    /// `agent.network.mode` is required whenever the `network` section is present.
    #[error("agent.network.mode: required when the network section is present")]
    NetworkModeRequired,

    /// A non-empty `agent.network.allow` list is only meaningful with `mode: custom`.
    #[error("agent.network.allow: only valid with `mode: custom` (mode is `{0}`)")]
    AllowRequiresCustomMode(String),

    /// A hostname or host pattern in an allowlist is invalid.
    #[error("invalid hostname `{value}`: {reason}")]
    InvalidHostname {
        /// The offending value.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// A credential service identifier is invalid.
    #[error("invalid service id `{value}`: {reason}")]
    InvalidServiceId {
        /// The offending value.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// A credential scope item is invalid.
    #[error("invalid scope item `{value}`: {reason}")]
    InvalidScopeItem {
        /// The offending value.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// An observer step pattern is not a valid glob.
    #[error("invalid observer.step pattern `{value}`: {reason}")]
    InvalidStepPattern {
        /// The offending value.
        value: String,
        /// Why it was rejected.
        reason: String,
    },

    /// `observer.step` was given without `observer.default: step-through`.
    #[error("observer.step: requires `observer.default: step-through` in the same document")]
    StepRequiresStepThrough,

    /// `observer.step` was given a word other than `all`.
    #[error("observer.step: expected `all` or a list of glob patterns (got `{0}`)")]
    InvalidHoldSet(String),

    /// A resource limit is out of range or unparsable.
    #[error("invalid resource limit `{field}` = `{value}`: {reason}")]
    InvalidResource {
        /// The field name (for example `cpu_weight`).
        field: &'static str,
        /// The offending value.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// A session, project, image or snapshot identifier is malformed.
    #[error("invalid {kind} `{value}`: {reason}")]
    InvalidId {
        /// Which identifier type was being parsed.
        kind: &'static str,
        /// The offending value.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// A value could not be turned into its canonical form for hashing.
    #[error("canonicalisation failed: {0}")]
    Canonical(String),
}

/// Errors produced by [`crate::load_layers`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// An I/O error while reading a policy path.
    #[error("{path}: {source}")]
    Io {
        /// The path being read.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A policy file exceeds [`crate::MAX_POLICY_FILE_BYTES`].
    #[error("{path}: policy file exceeds {limit} bytes")]
    TooLarge {
        /// The path being read.
        path: PathBuf,
        /// The size cap that was exceeded.
        limit: u64,
    },

    /// A policy path is a symbolic link; symlinks are refused.
    #[error("{path}: policy files must not be symbolic links")]
    Symlink {
        /// The offending path.
        path: PathBuf,
    },

    /// A policy path exists but is not a regular file.
    #[error("{path}: policy path is not a regular file")]
    NotRegularFile {
        /// The offending path.
        path: PathBuf,
    },

    /// A policy file failed to parse or validate.
    #[error("{path}: {source}")]
    Policy {
        /// The path being parsed.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: PolicyError,
    },

    /// A file name in the system policy directory is not valid UTF-8 and therefore
    /// cannot be ordered deterministically.
    #[error("{path}: policy file name is not valid UTF-8")]
    NonUtf8FileName {
        /// The offending path.
        path: PathBuf,
    },
}
