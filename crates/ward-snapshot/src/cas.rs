//! The content-addressed store: blobs, manifests, and metadata on disk.
//!
//! Everything is keyed by BLAKE3 hash, so identical bytes are stored once.
//! Writes are atomic (temp file plus rename) which also makes them idempotent.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, SnapshotError};
use crate::id::{Digest, SnapshotId, SnapshotRole};
use crate::manifest::Manifest;
use crate::meta::SnapshotMeta;

/// Object count and byte total of one on-disk CAS category, read straight from
/// the filesystem (no hashing, no parsing): how many files [`Cas::usage`] found
/// under that category's directory and how many bytes they hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryUsage {
    /// Regular files found.
    pub objects: u64,
    /// Their combined size in bytes.
    pub bytes: u64,
}

impl CategoryUsage {
    fn add_file(&mut self, len: u64) {
        self.objects += 1;
        self.bytes += len;
    }
}

/// Disk usage of the three CAS categories (`ward snapshot usage`, #151). Blobs
/// are content-addressed and deduplicated, so their total is the store's real
/// footprint for file content — not the sum of what any one snapshot captured.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasUsage {
    /// `blobs/`: deduplicated file and symlink-target content.
    pub blobs: CategoryUsage,
    /// `manifests/`: one file per stored snapshot manifest.
    pub manifests: CategoryUsage,
    /// `meta/`: one file per stored `(snapshot, role)` metadata record.
    pub meta: CategoryUsage,
}

impl CasUsage {
    /// The three categories' combined bytes.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.blobs.bytes + self.manifests.bytes + self.meta.bytes
    }
}

/// A CAS rooted at a caller-provided directory (e.g. `/var/lib/ward/cas`).
#[derive(Clone, Debug)]
pub struct Cas {
    root: PathBuf,
}

impl Cas {
    /// Open (creating if needed) a CAS at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        for sub in ["blobs", "manifests", "meta"] {
            let dir = root.join(sub);
            fs::create_dir_all(&dir).map_err(|e| SnapshotError::io(&dir, e))?;
        }
        Ok(Self { root })
    }

    fn blob_path(&self, d: Digest) -> PathBuf {
        let hex = d.to_hex();
        self.root.join("blobs").join(&hex[..2]).join(&hex)
    }

    /// Store `bytes`, returning its digest. A blob already present is left as is.
    pub fn put_blob(&self, bytes: &[u8]) -> Result<Digest> {
        let d = Digest::of(bytes);
        let path = self.blob_path(d);
        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| SnapshotError::io(parent, e))?;
            }
            write_atomic(&path, bytes)?;
        }
        Ok(d)
    }

    /// Whether a blob with digest `d` is stored.
    pub fn has_blob(&self, d: Digest) -> bool {
        self.blob_path(d).exists()
    }

    /// Read a blob by digest, verifying its content still hashes to `d`.
    pub fn get_blob(&self, d: Digest) -> Result<Vec<u8>> {
        let path = self.blob_path(d);
        match fs::read(&path) {
            // The id IS the content hash, so a read must re-hash: a corrupted or
            // tampered blob is refused, never served as authentic.
            Ok(b) if Digest::of(&b) == d => Ok(b),
            Ok(_) => Err(SnapshotError::Integrity(format!(
                "blob {d} does not hash to its id"
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(SnapshotError::NotFound(format!("blob {d}")))
            }
            Err(e) => Err(SnapshotError::io(&path, e)),
        }
    }

    fn manifest_path(&self, id: SnapshotId) -> PathBuf {
        self.root.join("manifests").join(id.digest().to_hex())
    }

    /// Store a manifest, returning its id.
    pub fn put_manifest(&self, m: &Manifest) -> Result<SnapshotId> {
        let id = m.id();
        let path = self.manifest_path(id);
        if !path.exists() {
            write_atomic(&path, &m.serialize())?;
        }
        Ok(id)
    }

    /// Load a manifest by id.
    pub fn get_manifest(&self, id: SnapshotId) -> Result<Manifest> {
        let path = self.manifest_path(id);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SnapshotError::NotFound(format!("manifest {id}")));
            }
            Err(e) => return Err(SnapshotError::io(&path, e)),
        };
        let manifest = Manifest::parse(&bytes)?;
        // The manifest is stored under its own id; if the parsed content no longer
        // hashes to the requested id it is corrupt or tampered — refuse it.
        if manifest.id() != id {
            return Err(SnapshotError::Integrity(format!(
                "manifest {id} does not hash to its id"
            )));
        }
        Ok(manifest)
    }

    fn meta_path(&self, id: SnapshotId, role: SnapshotRole) -> PathBuf {
        self.root
            .join("meta")
            .join(format!("{}.{}.json", id.digest().to_hex(), role.as_str()))
    }

    /// Store a metadata record for one (id, role) pair.
    pub fn put_meta(&self, meta: &SnapshotMeta) -> Result<()> {
        let path = self.meta_path(meta.id, meta.role);
        let json = serde_json::to_vec_pretty(meta)
            .map_err(|e| SnapshotError::Manifest(format!("meta serialize: {e}")))?;
        write_atomic(&path, &json)
    }

    /// Load the metadata record for one (id, role) pair.
    pub fn get_meta(&self, id: SnapshotId, role: SnapshotRole) -> Result<SnapshotMeta> {
        let path = self.meta_path(id, role);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SnapshotError::NotFound(format!("meta {id} {role}")));
            }
            Err(e) => return Err(SnapshotError::io(&path, e)),
        };
        serde_json::from_slice(&bytes)
            .map_err(|e| SnapshotError::Manifest(format!("meta parse: {e}")))
    }

    /// Disk usage of `blobs`, `manifests` and `meta`: an object count and a byte
    /// total per category, read from directory metadata alone (#151). This is a
    /// read-only report — it never opens, hashes or deletes anything, and a blob
    /// shared by many snapshots is still counted exactly once.
    ///
    /// A blob or manifest write in progress elsewhere leaves a short-lived
    /// `.tmp-<pid>-<seq>` sibling ([`write_atomic`]) before its rename; a usage
    /// call that races it may count that temp file once, for the duration of
    /// that one write. This is a benign, transient overcount, not a correctness
    /// issue: the temp file holds real bytes on disk either way, and the count
    /// self-corrects on the next call once the rename (or its cleanup) lands.
    pub fn usage(&self) -> Result<CasUsage> {
        Ok(CasUsage {
            blobs: dir_usage(&self.root.join("blobs"))?,
            manifests: dir_usage(&self.root.join("manifests"))?,
            meta: dir_usage(&self.root.join("meta"))?,
        })
    }
}

/// Sum of regular-file sizes under `dir`, recursing into subdirectories (the
/// two-hex-character shards under `blobs/`). A missing `dir` counts as empty
/// rather than an error, so a CAS that has never stored a category reports zero
/// for it instead of failing the whole report. Symlinks are skipped; the CAS
/// itself never writes one.
fn dir_usage(dir: &Path) -> Result<CategoryUsage> {
    let mut usage = CategoryUsage::default();
    walk_dir_usage(dir, &mut usage)?;
    Ok(usage)
}

/// Disk usage of the three CAS categories at `root`, exactly as [`Cas::usage`]
/// reports them, but without ever creating `root` or any category directory
/// under it — unlike [`Cas::open`], whose whole point is to create them.
/// `dir_usage`/`walk_dir_usage` already treat a missing directory as empty, so
/// a state root that has never stored anything reports all zeros here without
/// this call leaving any trace on disk. For a caller that only wants to
/// report on a CAS, never to write to one — `ward snapshot usage` (#151) — so
/// the report stays what its own contract promises: read-only.
pub fn usage_at(root: impl AsRef<Path>) -> Result<CasUsage> {
    let root = root.as_ref();
    Ok(CasUsage {
        blobs: dir_usage(&root.join("blobs"))?,
        manifests: dir_usage(&root.join("manifests"))?,
        meta: dir_usage(&root.join("meta"))?,
    })
}

fn walk_dir_usage(dir: &Path, usage: &mut CategoryUsage) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(SnapshotError::io(dir, e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| SnapshotError::io(dir, e))?;
        // An entry this `read_dir` just listed can still vanish before it is
        // `stat`ed — a concurrent capture or (once #151's follow-up GC lands) a
        // reclaim can legitimately remove it between the two calls. A read-only
        // report tolerates that as "gone, so nothing to count", not a hard
        // error; anything other than `NotFound` still fails the report.
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(SnapshotError::io(dir, e)),
        };
        if file_type.is_dir() {
            walk_dir_usage(&entry.path(), usage)?;
        } else if file_type.is_file() {
            let len = match entry.metadata() {
                Ok(m) => m.len(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(SnapshotError::io(dir, e)),
            };
            usage.add_file(len);
        }
    }
    Ok(())
}

/// Write `bytes` to `path` atomically via a sibling temp file and rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    {
        let mut f = fs::File::create(&tmp).map_err(|e| SnapshotError::io(&tmp, e))?;
        f.write_all(bytes).map_err(|e| SnapshotError::io(&tmp, e))?;
        f.sync_all().map_err(|e| SnapshotError::io(&tmp, e))?;
    }
    fs::rename(&tmp, path).map_err(|e| SnapshotError::io(path, e))
}

#[cfg(test)]
mod integrity_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::manifest::{Entry, EntryType};

    #[test]
    fn a_corrupted_blob_is_refused_not_served() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path()).unwrap();
        let d = cas.put_blob(b"hello").unwrap();
        assert_eq!(cas.get_blob(d).unwrap(), b"hello");
        // Tamper with the stored bytes so they no longer hash to their id.
        fs::write(cas.blob_path(d), b"HELLO").unwrap();
        assert!(
            matches!(cas.get_blob(d), Err(SnapshotError::Integrity(_))),
            "a blob that does not hash to its id must be refused, not served"
        );
    }

    #[test]
    fn a_manifest_that_does_not_hash_to_its_id_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path()).unwrap();
        let empty = Manifest::from_entries(Vec::new()).unwrap();
        let id = cas.put_manifest(&empty).unwrap();
        assert!(cas.get_manifest(id).is_ok());
        // Overwrite the stored manifest with a different but well-formed manifest:
        // it parses fine, but its content no longer hashes to `id`.
        let other = Manifest::from_entries(vec![Entry {
            path: b"a".to_vec(),
            kind: EntryType::Dir,
            mode: 0o755,
            size: 0,
            content: None,
        }])
        .unwrap();
        assert_ne!(other.id(), id);
        fs::write(cas.manifest_path(id), other.serialize()).unwrap();
        assert!(
            matches!(cas.get_manifest(id), Err(SnapshotError::Integrity(_))),
            "a manifest that does not hash to its requested id must be refused"
        );
    }
}

#[cfg(test)]
mod usage_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::manifest::{Entry, EntryType};

    #[test]
    fn an_empty_cas_reports_zero_everywhere() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path()).unwrap();
        let usage = cas.usage().unwrap();
        assert_eq!(usage, CasUsage::default());
        assert_eq!(usage.total_bytes(), 0);
    }

    #[test]
    fn a_shared_blob_is_counted_once_not_once_per_referrer() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path()).unwrap();
        // The same bytes stored twice (as two different manifests might reference
        // it) must land on disk, and be counted, exactly once — that is the whole
        // point of content addressing.
        let d1 = cas.put_blob(b"shared content").unwrap();
        let d2 = cas.put_blob(b"shared content").unwrap();
        assert_eq!(d1, d2);
        let usage = cas.usage().unwrap();
        assert_eq!(usage.blobs.objects, 1);
        assert_eq!(usage.blobs.bytes, b"shared content".len() as u64);
    }

    #[test]
    fn each_category_counts_only_its_own_directory() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path()).unwrap();
        cas.put_blob(b"one blob, 8 bytes").unwrap();
        let manifest = Manifest::from_entries(vec![Entry {
            path: b"a".to_vec(),
            kind: EntryType::Dir,
            mode: 0o755,
            size: 0,
            content: None,
        }])
        .unwrap();
        let id = cas.put_manifest(&manifest).unwrap();
        cas.put_meta(&SnapshotMeta {
            id,
            role: SnapshotRole::Entry,
            entries: 1,
            bytes: 0,
            capture_mode: crate::meta::CaptureMode::FrozenCopy,
            git_context: None,
        })
        .unwrap();

        let usage = cas.usage().unwrap();
        assert_eq!(usage.blobs.objects, 1);
        assert_eq!(usage.manifests.objects, 1);
        assert_eq!(usage.meta.objects, 1);
        assert!(usage.manifests.bytes > 0);
        assert!(usage.meta.bytes > 0);
        assert_eq!(
            usage.total_bytes(),
            usage.blobs.bytes + usage.manifests.bytes + usage.meta.bytes
        );
    }

    #[test]
    fn a_cas_that_has_never_written_one_category_reports_zero_for_it_not_an_error() {
        // `Cas::open` creates all three directories, so this also covers the case
        // of a category directory being absent entirely (a store from before this
        // feature, or a category never used).
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path()).unwrap();
        std::fs::remove_dir_all(dir.path().join("meta")).unwrap();
        let usage = cas.usage().unwrap();
        assert_eq!(usage.meta, CategoryUsage::default());
    }
}
