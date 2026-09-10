//! Error type for snapshot operations.

use std::path::PathBuf;

/// Errors produced while capturing, storing, or materialising snapshots.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SnapshotError {
    /// An I/O operation failed on the given path.
    #[error("i/o error at {path}: {source}")]
    Io {
        /// Path the operation targeted.
        path: PathBuf,
        /// Underlying OS error.
        source: std::io::Error,
    },

    /// A manifest was malformed or violated a canonical-form invariant.
    #[error("invalid manifest: {0}")]
    Manifest(String),

    /// A manifest path contained a `..` component or was otherwise unsafe.
    #[error("unsafe path in manifest: {0}")]
    UnsafePath(String),

    /// A referenced blob, manifest, or metadata record was absent from the CAS.
    #[error("not found in store: {0}")]
    NotFound(String),

    /// The requested path does not exist in the snapshot's manifest.
    #[error("path not in snapshot: {0}")]
    NoSuchEntry(String),

    /// Capture exceeded the configured byte budget.
    #[error("capture exceeded max_bytes budget of {0} bytes")]
    BudgetExceeded(u64),

    /// A stored object's content does not hash to the id it was requested by:
    /// on-disk corruption or tampering. The CAS's core promise is that an id
    /// names exactly its content, so such an object must be refused, not served.
    #[error("integrity: {0}")]
    Integrity(String),
}

/// Convenience alias for results in this crate.
pub type Result<T> = std::result::Result<T, SnapshotError>;

impl SnapshotError {
    /// Build an [`SnapshotError::Io`] tagged with the path it occurred on.
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
