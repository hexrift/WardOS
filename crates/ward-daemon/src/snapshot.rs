//! `ward snapshot …`: the read-only snapshot primitives of
//! `docs/tamperward-integration.md` §2, answered from the session CAS alone.
//!
//! `diff` and `cat` never look at the worktree: two ids name two stored
//! manifests, and the answer is computed from those. Capture (`create`) lives on
//! [`Session::snapshot`](crate::Session::snapshot) so the log records it.

use std::path::Path;

use serde::{Deserialize, Serialize};
use ward_snapshot::{Digest, ManifestDiff, SnapshotId, SnapshotStore};

use crate::error::{Error, Result};

/// Open the session CAS under `state` (`<state>/cas`).
pub fn open_store(state: &Path) -> Result<SnapshotStore> {
    SnapshotStore::open(state.join("cas")).map_err(|e| Error::Snapshot(e.to_string()))
}

/// Parse a snapshot id given as `blake3:<hex>` or bare hex. The store has no
/// prefix lookup, so the full 64-hex-digit id is required.
pub fn parse_id(s: &str) -> Result<SnapshotId> {
    let hex = s.strip_prefix("blake3:").unwrap_or(s);
    Digest::from_hex(hex)
        .map(SnapshotId)
        .map_err(|e| Error::Snapshot(format!("`{s}` is not a full snapshot id ({e})")))
}

/// Manifest-level diff of two stored snapshots, `a` → `b`.
pub fn diff(state: &Path, a: SnapshotId, b: SnapshotId) -> Result<DiffReport> {
    let d = open_store(state)?
        .diff(a, b)
        .map_err(|e| Error::Snapshot(e.to_string()))?;
    Ok(DiffReport::from(&d))
}

/// Pristine bytes of `path` within snapshot `id`.
pub fn cat(state: &Path, id: SnapshotId, path: &Path) -> Result<Vec<u8>> {
    open_store(state)?
        .cat(id, path)
        .map_err(|e| Error::Snapshot(e.to_string()))
}

/// A [`ManifestDiff`] with paths as text, for rendering and JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffReport {
    /// Paths present only in the second snapshot.
    pub added: Vec<String>,
    /// Paths present only in the first snapshot.
    pub removed: Vec<String>,
    /// Paths in both whose type, mode, size, or content differ.
    pub changed: Vec<String>,
}

impl DiffReport {
    /// Whether the two snapshots were identical.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

impl From<&ManifestDiff> for DiffReport {
    fn from(d: &ManifestDiff) -> Self {
        let text = |paths: &[Vec<u8>]| {
            paths
                .iter()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect()
        };
        Self {
            added: text(&d.added),
            removed: text(&d.removed),
            changed: text(&d.changed),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn ids_parse_with_or_without_the_prefix_and_only_in_full() {
        let hex = "ab".repeat(32);
        let a = parse_id(&format!("blake3:{hex}")).unwrap();
        let b = parse_id(&hex).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.to_string(), format!("blake3:{hex}"));
        assert!(parse_id(&hex[..12]).is_err(), "a prefix is not a lookup");
        assert!(parse_id("blake3:zz").is_err());
    }

    #[test]
    fn diff_report_carries_paths_as_text() {
        let d = ManifestDiff {
            added: vec![b"new.txt".to_vec()],
            removed: vec![],
            changed: vec![b"src/lib.rs".to_vec()],
        };
        let r = DiffReport::from(&d);
        assert_eq!(r.added, vec!["new.txt"]);
        assert!(r.removed.is_empty());
        assert_eq!(r.changed, vec!["src/lib.rs"]);
        assert!(!r.is_empty());
        assert!(DiffReport::default().is_empty());
    }
}
