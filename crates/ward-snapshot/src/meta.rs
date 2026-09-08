//! Per-snapshot metadata recorded alongside the manifest.

use serde::{Deserialize, Serialize};

use crate::id::{SnapshotId, SnapshotRole};

/// How the frozen tree was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureMode {
    /// Read-only Btrfs subvolume snapshot (not implemented in this crate).
    BtrfsSnapshot,
    /// Portable path: hash and copy from the frozen tree into the CAS.
    FrozenCopy,
}

/// Git state observed at capture time. Informational only: it is read from the
/// agent-controlled `.git` directory and no trust decision may depend on it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitContext {
    /// Resolved HEAD commit, if it could be read.
    pub head: Option<String>,
    /// Branch name, or `None` when HEAD is detached.
    pub branch: Option<String>,
    /// Whether HEAD was detached.
    pub detached: bool,
}

/// Metadata describing one stored snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMeta {
    /// The snapshot id (Merkle root of the manifest).
    pub id: SnapshotId,
    /// Lifecycle role this record assigns to the id.
    pub role: SnapshotRole,
    /// Number of manifest entries.
    pub entries: u64,
    /// Total stored content bytes.
    pub bytes: u64,
    /// How the tree was captured.
    pub capture_mode: CaptureMode,
    /// Informational git context, if `.git/HEAD` was present.
    pub git_context: Option<GitContext>,
}
