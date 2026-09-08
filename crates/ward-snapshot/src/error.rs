//! Error types.

use std::path::PathBuf;

use crate::hash::{ContentHash, SnapshotId};

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Why a relative path was rejected. See [`crate::path::RelPath`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// The path has no bytes at all.
    #[error("path is empty")]
    Empty,
    /// The path starts with `/`.
    #[error("path is absolute")]
    Absolute,
    /// A component between two separators (or a trailing one) is empty.
    #[error("path has an empty component")]
    EmptyComponent,
    /// A component is `.`.
    #[error("path has a `.` component")]
    DotComponent,
    /// A component is `..`.
    #[error("path has a `..` component")]
    DotDotComponent,
    /// The path contains a NUL byte (which would corrupt the NUL-separated manifest).
    #[error("path contains a NUL byte")]
    Nul,
    /// The path is longer than the crate-wide limit.
    #[error("path is too long")]
    TooLong,
}

/// Which capture limit was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// `CapturePolicy::max_bytes`.
    Bytes,
    /// `CapturePolicy::max_entries`.
    Entries,
}

impl std::fmt::Display for Limit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Limit::Bytes => f.write_str("max_bytes"),
            Limit::Entries => f.write_str("max_entries"),
        }
    }
}

/// The crate error type.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An I/O error, annotated with the operation and path involved.
    #[error("{op} {path}: {source}")]
    Io {
        /// What was being attempted (e.g. `open`, `rename`).
        op: &'static str,
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A path did not satisfy the [`crate::path::RelPath`] rules.
    #[error("invalid path {}: {reason}", lossy(path))]
    InvalidPath {
        /// The offending path bytes.
        path: Vec<u8>,
        /// Why it was rejected.
        #[source]
        reason: PathError,
    },

    /// A canonical manifest could not be parsed.
    #[error("manifest entry {index}: {reason}")]
    ManifestParse {
        /// Zero-based index of the entry where parsing failed.
        index: usize,
        /// Human-readable reason.
        reason: String,
    },

    /// Two entries had the same path.
    #[error("duplicate manifest path {}", lossy(path))]
    DuplicatePath {
        /// The duplicated path bytes.
        path: Vec<u8>,
    },

    /// A capture limit was exceeded. Capture never truncates silently.
    #[error("capture exceeded {limit} (limit {value}) at {}", lossy(path))]
    LimitExceeded {
        /// Which limit.
        limit: Limit,
        /// Its configured value.
        value: u64,
        /// The path at which the limit was crossed.
        path: Vec<u8>,
    },

    /// A blob referenced by a manifest is not in the store.
    #[error("missing blob {0}")]
    MissingBlob(ContentHash),

    /// A manifest is not in the store.
    #[error("missing manifest {0}")]
    MissingManifest(SnapshotId),

    /// Stored or ingested content did not hash to the expected value.
    #[error("content hash mismatch for {}: expected {expected}, got {actual}", path.display())]
    HashMismatch {
        /// The file or blob involved.
        path: PathBuf,
        /// Expected hash.
        expected: ContentHash,
        /// Observed hash.
        actual: ContentHash,
    },

    /// A stored manifest did not hash to the id it was stored under.
    #[error("snapshot id mismatch: expected {expected}, got {actual}")]
    IdMismatch {
        /// Expected id.
        expected: SnapshotId,
        /// Observed id.
        actual: SnapshotId,
    },

    /// The materialisation destination exists and is not an empty directory.
    #[error("destination {} is not an empty directory", .0.display())]
    DestinationNotEmpty(PathBuf),

    /// A manifest entry would be created through a symlink recorded earlier in the same
    /// manifest (e.g. `a` is a symlink and `a/b` is a file).
    #[error("refusing to materialise {} through symlink component", lossy(path))]
    PathThroughSymlink {
        /// The offending entry path.
        path: Vec<u8>,
    },

    /// A session identifier is not acceptable as a reference file name.
    #[error("invalid session id {0:?}")]
    InvalidSession(String),

    /// The freezer could not freeze or thaw.
    #[error("freezer: {0}")]
    Freezer(String),

    /// A serialisation error (JSON metadata, cache file).
    #[error("serialisation of {}: {message}", path.display())]
    Serde {
        /// The file involved.
        path: PathBuf,
        /// Human-readable message.
        message: String,
    },

    /// An error reported by the directory walker.
    #[error("walk: {0}")]
    Walk(String),

    /// An entry changed type or vanished between walk and hash (the tree was not
    /// quiescent).
    #[error("tree changed during capture at {}", lossy(path))]
    TreeChanged {
        /// The path involved.
        path: Vec<u8>,
    },
}

impl Error {
    pub(crate) fn io(op: &'static str, path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            op,
            path: path.into(),
            source,
        }
    }
}

/// Render raw path bytes for error messages without ever panicking on non-UTF-8.
pub(crate) fn lossy(bytes: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(bytes))
}
