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

/// The worktree as it is now, held against a stored snapshot (#147 item 7: "what did
/// the agent change"). Digested with the capture options a session's entry snapshot and
/// a verification candidate use, so the ids agree byte for byte; nothing is stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorktreeChanges {
    /// The id the worktree would get if captured now, as the log names snapshots; or why
    /// it cannot be digested.
    pub worktree: std::result::Result<ward_events::SnapshotId, String>,
    /// The paths that differ from the stored snapshot; or why that cannot be said (the
    /// worktree cannot be digested, or the snapshot is not in the store).
    pub changes: std::result::Result<DiffReport, String>,
}

/// [`WorktreeChanges`] for `dir` against the stored snapshot `entry` (`blake3:…`).
#[must_use]
pub fn worktree_changes(state: &Path, entry: &str, dir: &Path) -> WorktreeChanges {
    let now = ward_snapshot::digest_manifest(
        dir,
        crate::verify::candidate_options(),
        &mut ward_snapshot::HashCache::new(),
        &mut ward_snapshot::CaptureStats::default(),
    )
    .map_err(|e| format!("the worktree cannot be digested ({e})"));
    let worktree = now
        .as_ref()
        .map(|m| crate::ids::ev_snapshot(m.id()))
        .map_err(Clone::clone);
    let changes = now.and_then(|now| {
        let stored = parse_id(entry)
            .and_then(|id| {
                open_store(state)?
                    .manifest(id)
                    .map_err(|e| Error::Snapshot(e.to_string()))
            })
            .map_err(|e| {
                format!("the entry snapshot {entry} cannot be read from the store ({e})")
            })?;
        Ok(DiffReport::from(&ManifestDiff::between(&stored, &now)))
    });
    WorktreeChanges { worktree, changes }
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
    fn worktree_changes_hold_the_worktree_against_a_stored_snapshot() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("kept.txt"), "k\n").unwrap();
        std::fs::write(dir.path().join("edited.txt"), "before\n").unwrap();
        std::fs::write(dir.path().join("removed.txt"), "r\n").unwrap();
        let entry = open_store(state.path())
            .unwrap()
            .store_snapshot(
                dir.path(),
                ward_snapshot::SnapshotRole::Entry,
                crate::verify::candidate_options(),
            )
            .unwrap()
            .to_string();
        let same = worktree_changes(state.path(), &entry, dir.path());
        assert!(same.changes.unwrap().is_empty());
        assert_eq!(same.worktree.unwrap().to_string(), entry);

        std::fs::write(dir.path().join("edited.txt"), "after\n").unwrap();
        std::fs::remove_file(dir.path().join("removed.txt")).unwrap();
        std::fs::write(dir.path().join("added.txt"), "a\n").unwrap();
        let moved = worktree_changes(state.path(), &entry, dir.path());
        let changes = moved.changes.unwrap();
        assert_eq!(changes.added, ["added.txt"]);
        assert_eq!(changes.changed, ["edited.txt"]);
        assert_eq!(changes.removed, ["removed.txt"]);
        assert_ne!(moved.worktree.unwrap().to_string(), entry);

        let missing = worktree_changes(
            state.path(),
            &format!("blake3:{}", "ab".repeat(32)),
            dir.path(),
        );
        assert!(missing.worktree.is_ok());
        assert!(missing.changes.unwrap_err().contains("cannot be read"));
        let gone = worktree_changes(state.path(), &entry, &dir.path().join("nowhere"));
        assert!(gone.worktree.is_err());
        assert!(gone.changes.unwrap_err().contains("cannot be digested"));
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
