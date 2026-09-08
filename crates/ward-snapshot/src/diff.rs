//! Differences between two manifests, computed from the manifests alone.
//!
//! No file is read; two sorted entry lists are merged. This is what the verifier and
//! `TamperWard` consume to reason about "what changed between entry and candidate".

use crate::manifest::{Entry, Manifest};

/// A pair of entries at the same path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPair {
    /// The entry in the first (older) manifest.
    pub before: Entry,
    /// The entry in the second (newer) manifest.
    pub after: Entry,
}

/// The classified differences between two manifests.
///
/// Every path present in either manifest lands in at most one bucket; unchanged
/// entries are counted in `unchanged`. Classification order for a path present on both
/// sides: type changed → content modified → mode changed → unchanged. A modified file
/// whose mode also changed is reported as `modified` (the mode change is visible in the
/// pair).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManifestDiff {
    /// Present only in `b`.
    pub added: Vec<Entry>,
    /// Present only in `a`.
    pub removed: Vec<Entry>,
    /// Same kind, different content hash (or size, for the same kind).
    pub modified: Vec<EntryPair>,
    /// Same kind and content, different permission bits.
    pub mode_changed: Vec<EntryPair>,
    /// Different kind (e.g. file became symlink or directory).
    pub type_changed: Vec<EntryPair>,
    /// Number of identical entries.
    pub unchanged: usize,
}

impl ManifestDiff {
    /// True if the manifests are identical.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.modified.is_empty()
            && self.mode_changed.is_empty()
            && self.type_changed.is_empty()
    }

    /// Total number of differing paths.
    #[must_use]
    pub fn change_count(&self) -> usize {
        self.added.len()
            + self.removed.len()
            + self.modified.len()
            + self.mode_changed.len()
            + self.type_changed.len()
    }
}

/// Compute the differences from `a` (before) to `b` (after).
#[must_use]
pub fn diff(a: &Manifest, b: &Manifest) -> ManifestDiff {
    let mut out = ManifestDiff::default();
    let mut ia = a.entries().iter().peekable();
    let mut ib = b.entries().iter().peekable();
    loop {
        match (ia.peek(), ib.peek()) {
            (None, None) => break,
            (Some(_), None) => {
                out.removed.extend(ia.by_ref().cloned());
            }
            (None, Some(_)) => {
                out.added.extend(ib.by_ref().cloned());
            }
            (Some(ea), Some(eb)) => match ea.path.cmp(&eb.path) {
                std::cmp::Ordering::Less => {
                    out.removed.push((*ea).clone());
                    ia.next();
                }
                std::cmp::Ordering::Greater => {
                    out.added.push((*eb).clone());
                    ib.next();
                }
                std::cmp::Ordering::Equal => {
                    classify(ea, eb, &mut out);
                    ia.next();
                    ib.next();
                }
            },
        }
    }
    out
}

fn classify(before: &Entry, after: &Entry, out: &mut ManifestDiff) {
    let pair = || EntryPair {
        before: before.clone(),
        after: after.clone(),
    };
    if before.kind != after.kind {
        out.type_changed.push(pair());
    } else if before.hash != after.hash || before.size != after.size {
        out.modified.push(pair());
    } else if before.mode != after.mode {
        out.mode_changed.push(pair());
    } else {
        out.unchanged += 1;
    }
}
