//! `ward-snapshot` — content-addressed Ward Snapshots.
//!
//! A Ward Snapshot is an immutable, content-addressed capture of a worktree,
//! named by the BLAKE3 Merkle root of a canonical manifest and stored in a CAS
//! outside the agent's reach. See `docs/snapshots-and-git.md` and
//! [`ADR-0010`](../decisions/ADR-0010-snapshots-and-git.md).
//!
//! The structure is a two-level Merkle tree: each file (and symlink target) is a
//! BLAKE3 leaf; the manifest listing those leaves hashes to the [`SnapshotId`].
//! Identical trees therefore produce identical ids regardless of capture order,
//! and any changed byte changes the id.
//!
//! # Example
//! ```no_run
//! use ward_snapshot::{SnapshotStore, SnapshotRole, CaptureOptions};
//! # fn main() -> anyhow::Result<()> {
//! let store = SnapshotStore::open("/var/lib/ward/cas")?;
//! let id = store.store_snapshot("/work", SnapshotRole::Entry, CaptureOptions::default())?;
//! let bytes = store.cat(id, std::path::Path::new("README.md"))?;
//! store.materialize(id, "/tmp/verify")?;
//! # let _ = bytes; Ok(())
//! # }
//! ```
//!
//! Only the portable **frozen-copy** capture path is implemented here; a Btrfs
//! subvolume backend can be added behind [`backend::Backend`] with no change to
//! capture, storage, or materialisation.

// These pedantic lints would force `# Errors` sections and `#[must_use]` onto
// nearly every item; we keep doc comments to one line instead.
#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

pub mod backend;
mod capture;
mod cas;
mod error;
mod id;
mod ignore;
mod manifest;
mod materialize;
mod meta;

use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub use capture::{CaptureOptions, CaptureStats, HashCache};
pub use error::{Result, SnapshotError};
pub use id::{Digest, SnapshotId, SnapshotRole};
pub use manifest::{Entry, EntryType, Manifest, ManifestDiff};
pub use meta::{CaptureMode, GitContext, SnapshotMeta};

use backend::{Backend, FrozenCopy};
use cas::Cas;

/// A snapshot store: captures trees into, and serves them from, a CAS.
#[derive(Clone, Debug)]
pub struct SnapshotStore {
    cas: Cas,
}

impl SnapshotStore {
    /// Open (creating if needed) a store backed by a CAS at `cas_root`.
    pub fn open(cas_root: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            cas: Cas::open(cas_root.as_ref())?,
        })
    }

    /// Capture `root_dir` with the given role and store it, returning its id.
    pub fn store_snapshot(
        &self,
        root_dir: impl AsRef<Path>,
        role: SnapshotRole,
        opts: CaptureOptions,
    ) -> Result<SnapshotId> {
        Ok(self.capture(root_dir, role, opts)?.id)
    }

    /// Capture and store `root_dir`, returning full metadata.
    pub fn capture(
        &self,
        root_dir: impl AsRef<Path>,
        role: SnapshotRole,
        opts: CaptureOptions,
    ) -> Result<SnapshotMeta> {
        let mut cache = HashCache::new();
        let mut stats = CaptureStats::default();
        self.capture_with_cache(root_dir, role, opts, &mut cache, &mut stats)
    }

    /// Capture with a caller-owned incremental [`HashCache`], reporting work in
    /// `stats`. Reuse the same cache across captures for the incremental path.
    pub fn capture_with_cache(
        &self,
        root_dir: impl AsRef<Path>,
        role: SnapshotRole,
        opts: CaptureOptions,
        cache: &mut HashCache,
        stats: &mut CaptureStats,
    ) -> Result<SnapshotMeta> {
        let backend = FrozenCopy;
        self.capture_with(&backend, root_dir.as_ref(), role, opts, cache, stats)
    }

    /// Capture using an explicit [`Backend`] (the seam for a future Btrfs path).
    pub fn capture_with(
        &self,
        backend: &dyn Backend,
        root_dir: &Path,
        role: SnapshotRole,
        opts: CaptureOptions,
        cache: &mut HashCache,
        stats: &mut CaptureStats,
    ) -> Result<SnapshotMeta> {
        let cap = capture::capture(&self.cas, backend, root_dir, opts, cache, stats)?;
        let id = self.cas.put_manifest(&cap.manifest)?;
        let meta = SnapshotMeta {
            id,
            role,
            entries: cap.manifest.entries().len() as u64,
            bytes: cap.manifest.content_bytes(),
            capture_mode: cap.mode,
            git_context: cap.git_context,
        };
        self.cas.put_meta(&meta)?;
        Ok(meta)
    }

    /// Load a stored manifest by id.
    pub fn manifest(&self, id: SnapshotId) -> Result<Manifest> {
        self.cas.get_manifest(id)
    }

    /// Load a stored metadata record for one (id, role) pair.
    pub fn meta(&self, id: SnapshotId, role: SnapshotRole) -> Result<SnapshotMeta> {
        self.cas.get_meta(id, role)
    }

    /// Return the content bytes of `path` within snapshot `id`.
    pub fn cat(&self, id: SnapshotId, path: &Path) -> Result<Vec<u8>> {
        let manifest = self.cas.get_manifest(id)?;
        let entry = manifest
            .get(path.as_os_str().as_bytes())
            .ok_or_else(|| SnapshotError::NoSuchEntry(path.display().to_string()))?;
        materialize::read_entry_bytes(&self.cas, entry)
    }

    /// Diff two snapshots by path.
    pub fn diff(&self, a: SnapshotId, b: SnapshotId) -> Result<ManifestDiff> {
        let ma = self.cas.get_manifest(a)?;
        let mb = self.cas.get_manifest(b)?;
        Ok(ManifestDiff::between(&ma, &mb))
    }

    /// Write a fresh tree for snapshot `id` under `dest_dir`, refusing `..` and
    /// writing symlinks as symlinks.
    pub fn materialize(&self, id: SnapshotId, dest_dir: impl AsRef<Path>) -> Result<()> {
        let manifest = self.cas.get_manifest(id)?;
        materialize::materialize(&self.cas, &manifest, dest_dir.as_ref())
    }
}
