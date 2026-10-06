//! Moving a stored snapshot between two stores (#278).
//!
//! A snapshot is its manifest and the blobs it names. [`SnapshotStore::copy_from`] reads
//! each from the source store through the CAS's own integrity checks (a blob or manifest
//! that does not hash to its id is refused, never served) and writes it into this store,
//! so the copy carries exactly the same id or the call fails. [`SnapshotStore::open_existing`]
//! opens a source for reading without creating anything in it.

use crate::SnapshotStore;
use crate::cas::Cas;
use crate::error::{Result, SnapshotError};
use crate::id::{SnapshotId, SnapshotRole};

impl SnapshotStore {
    /// Open the store already at `cas_root` for reading, creating nothing: a missing
    /// root is [`SnapshotError::NotFound`].
    pub fn open_existing(cas_root: impl AsRef<std::path::Path>) -> Result<Self> {
        Ok(Self {
            cas: Cas::open_existing(cas_root.as_ref())?,
        })
    }

    /// Copy snapshot `id` from `source` into this store, with every blob it names and
    /// every metadata record it has, verifying each object against its digest on the
    /// way. Returns the id the copy is stored under, which is always `id`. The manifest is
    /// written last, so a copy that fails leaves no manifest behind, only blobs nothing
    /// names, which a sweep reclaims.
    pub fn copy_from(&self, source: &Self, id: SnapshotId) -> Result<SnapshotId> {
        let manifest = source.cas.get_manifest(id)?;
        for digest in manifest.entries().iter().filter_map(|entry| entry.content) {
            if self.cas.put_blob(&source.cas.get_blob(digest)?)? != digest {
                return Err(SnapshotError::Integrity(format!(
                    "blob {digest} changed while it was copied"
                )));
            }
        }
        let copied = self.cas.put_manifest(&manifest)?;
        if copied != id {
            return Err(SnapshotError::Integrity(format!(
                "manifest {id} was stored as {copied}"
            )));
        }
        for role in SnapshotRole::ALL {
            match source.cas.get_meta(id, role) {
                Ok(meta) => self.cas.put_meta(&meta)?,
                Err(SnapshotError::NotFound(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(copied)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::fs;
    use std::path::Path;

    use super::*;
    use crate::{CaptureOptions, SnapshotStore};

    fn project(dir: &Path) {
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/main.rs"), b"fn main() {}\n").unwrap();
        fs::write(dir.join("README.md"), b"a project\n").unwrap();
        std::os::unix::fs::symlink("README.md", dir.join("link")).unwrap();
    }

    fn files(root: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push((
                        path.strip_prefix(root).unwrap().display().to_string(),
                        fs::read(&path).unwrap(),
                    ));
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn a_copied_snapshot_keeps_its_id_its_content_and_its_metadata() {
        let dir = tempfile::tempdir().unwrap();
        project(&dir.path().join("p"));
        let source = SnapshotStore::open(dir.path().join("a")).unwrap();
        let id = source
            .store_snapshot(
                dir.path().join("p"),
                SnapshotRole::Entry,
                CaptureOptions::default(),
            )
            .unwrap();
        let target = SnapshotStore::open(dir.path().join("b")).unwrap();

        assert_eq!(target.copy_from(&source, id).unwrap(), id);
        assert_eq!(target.manifest(id).unwrap(), source.manifest(id).unwrap());
        assert_eq!(
            target.meta(id, SnapshotRole::Entry).unwrap(),
            source.meta(id, SnapshotRole::Entry).unwrap()
        );
        target.materialize(id, dir.path().join("out")).unwrap();
        assert_eq!(files(&dir.path().join("out")), files(&dir.path().join("p")));
    }

    #[test]
    fn a_corrupt_blob_in_the_source_fails_the_copy_and_never_lands_in_the_target() {
        let dir = tempfile::tempdir().unwrap();
        project(&dir.path().join("p"));
        let source = SnapshotStore::open(dir.path().join("a")).unwrap();
        let id = source
            .store_snapshot(
                dir.path().join("p"),
                SnapshotRole::Entry,
                CaptureOptions::default(),
            )
            .unwrap();
        let digest = crate::Digest::of(b"a project\n").to_hex();
        let blob = dir.path().join("a/blobs").join(&digest[..2]).join(&digest);
        fs::write(&blob, b"tampered\n").unwrap();
        let target = SnapshotStore::open(dir.path().join("b")).unwrap();

        assert!(matches!(
            target.copy_from(&source, id),
            Err(SnapshotError::Integrity(_))
        ));
        assert!(
            target.manifest(id).is_err(),
            "no manifest without its blobs"
        );
        assert!(
            !dir.path()
                .join("b/blobs")
                .join(&digest[..2])
                .join(&digest)
                .exists()
        );
    }

    #[test]
    fn a_snapshot_the_source_does_not_hold_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let source = SnapshotStore::open(dir.path().join("a")).unwrap();
        let target = SnapshotStore::open(dir.path().join("b")).unwrap();
        let id = SnapshotId(crate::Digest::of(b"absent"));
        assert!(matches!(
            target.copy_from(&source, id),
            Err(SnapshotError::NotFound(_))
        ));
    }

    #[test]
    fn opening_an_existing_store_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            SnapshotStore::open_existing(dir.path().join("missing")),
            Err(SnapshotError::NotFound(_))
        ));
        assert!(!dir.path().join("missing").exists());

        fs::create_dir(dir.path().join("bare")).unwrap();
        let bare = SnapshotStore::open_existing(dir.path().join("bare")).unwrap();
        assert!(bare.manifest(SnapshotId(crate::Digest::of(b"x"))).is_err());
        assert_eq!(fs::read_dir(dir.path().join("bare")).unwrap().count(), 0);
    }
}
