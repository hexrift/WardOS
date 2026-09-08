//! The content-addressed store: blobs, manifests, and metadata on disk.
//!
//! Everything is keyed by BLAKE3 hash, so identical bytes are stored once.
//! Writes are atomic (temp file plus rename) which also makes them idempotent.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::error::{Result, SnapshotError};
use crate::id::{Digest, SnapshotId, SnapshotRole};
use crate::manifest::Manifest;
use crate::meta::SnapshotMeta;

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

    /// Read a blob by digest.
    pub fn get_blob(&self, d: Digest) -> Result<Vec<u8>> {
        let path = self.blob_path(d);
        match fs::read(&path) {
            Ok(b) => Ok(b),
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
        Manifest::parse(&bytes)
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
