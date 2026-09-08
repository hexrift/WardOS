//! Incremental re-hashing cache keyed by file identity and timestamps.
//!
//! # What it is
//!
//! A [`TreeCache`] remembers, for each file path captured last time, the file's
//! `(dev, ino, size, mtime, ctime)` and its content hash. On the next capture a file whose
//! identity and timestamps are unchanged reuses the stored hash instead of being read.
//! For a 200k-file tree this turns a full read into a `stat` pass.
//!
//! # What it is not
//!
//! The cache is an **optimisation only**. Its soundness rests on filesystem metadata:
//!
//! * `mtime` and `size` are attacker-controlled: an agent can edit a file and restore
//!   both with `utimensat(2)`. That alone would be fatal, which is why the key also
//!   includes `ctime`, which unprivileged processes cannot set (any write, `chmod`,
//!   rename or `utimensat` bumps it).
//! * `ctime` is still only as fine as the kernel's inode timestamp granularity. An edit
//!   that lands in the *same timestamp tick* as the previous capture's observation and
//!   leaves the size unchanged is invisible to the cache. Multigrain timestamps (Linux
//!   6.13+) make this window nanoseconds wide; coarse-grained kernels have a jiffy
//!   (1–10 ms) window. Inode-number reuse after delete+recreate is covered by `ctime`
//!   as well.
//! * A `wardd` that runs as root while the agent can `settimeofday` (it cannot inside
//!   the sandbox) would lose the `ctime` guarantee.
//!
//! **Rule for `wardd`:** use the cache to make *candidate* captures fast between
//! verifications, but never let a cached hash be the only evidence for an `accepted`
//! snapshot. When the cache's own file is stored, it must live in Zone 0 storage the
//! agent cannot write; a corrupted cache file simply fails to load (and is ignored).
//! The tests in `tests/cache.rs` pin both the detection guarantees and the documented
//! limitation.

use std::collections::HashMap;
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::hash::ContentHash;
use crate::path::RelPath;

/// Format version of the on-disk cache file.
const CACHE_VERSION: u32 = 1;

/// The identity of a file at one instant, as far as `stat(2)` can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileIdentity {
    /// Device number.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
    /// Length in bytes.
    pub size: u64,
    /// Modification time, seconds.
    pub mtime: i64,
    /// Modification time, nanoseconds part.
    pub mtime_nsec: i64,
    /// Inode change time, seconds.
    pub ctime: i64,
    /// Inode change time, nanoseconds part.
    pub ctime_nsec: i64,
}

impl FileIdentity {
    /// Extract the identity from metadata.
    #[must_use]
    pub fn from_metadata(m: &Metadata) -> Self {
        FileIdentity {
            dev: m.dev(),
            ino: m.ino(),
            size: m.len(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_nsec: m.ctime_nsec(),
        }
    }
}

/// One cached record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheRecord {
    /// The identity observed when the hash was computed.
    pub identity: FileIdentity,
    /// The content hash computed at that time.
    pub hash: ContentHash,
}

#[derive(Serialize, Deserialize)]
struct CacheFile {
    version: u32,
    records: Vec<(Vec<u8>, CacheRecord)>,
}

/// The cache. See the module documentation for the trust rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeCache {
    records: HashMap<Vec<u8>, CacheRecord>,
}

impl TreeCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        TreeCache::default()
    }

    /// Number of records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True if there are no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Return the cached hash if `identity` matches the record for `path` exactly.
    #[must_use]
    pub fn lookup(&self, path: &RelPath, identity: &FileIdentity) -> Option<ContentHash> {
        let rec = self.records.get(path.as_bytes())?;
        (rec.identity == *identity).then_some(rec.hash)
    }

    /// Get the raw record for `path`.
    #[must_use]
    pub fn get(&self, path: &RelPath) -> Option<&CacheRecord> {
        self.records.get(path.as_bytes())
    }

    /// Insert or replace a record.
    pub fn insert(&mut self, path: RelPath, identity: FileIdentity, hash: ContentHash) {
        self.records
            .insert(path.into_bytes(), CacheRecord { identity, hash });
    }

    /// Replace the whole content (used by capture to drop records for vanished files).
    pub fn replace(&mut self, records: HashMap<Vec<u8>, CacheRecord>) {
        self.records = records;
    }

    /// Remove every record.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// Load from a file written by [`TreeCache::save`].
    ///
    /// # Errors
    /// I/O errors, or [`Error::Serde`] if the file is corrupt or of another version.
    /// Callers should treat a load error as "no cache" rather than as fatal.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|e| Error::io("read", path, e))?;
        let file: CacheFile = postcard::from_bytes(&bytes).map_err(|e| Error::Serde {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        if file.version != CACHE_VERSION {
            return Err(Error::Serde {
                path: path.to_path_buf(),
                message: format!("unsupported cache version {}", file.version),
            });
        }
        Ok(TreeCache {
            records: file.records.into_iter().collect(),
        })
    }

    /// Save atomically (temp file + rename) to `path`.
    ///
    /// # Errors
    /// I/O or serialisation errors.
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut records: Vec<(Vec<u8>, CacheRecord)> =
            self.records.iter().map(|(k, v)| (k.clone(), *v)).collect();
        records.sort_by(|a, b| a.0.cmp(&b.0));
        let file = CacheFile {
            version: CACHE_VERSION,
            records,
        };
        let bytes = postcard::to_allocvec(&file).map_err(|e| Error::Serde {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp =
            tempfile::NamedTempFile::new_in(dir).map_err(|e| Error::io("mkstemp", dir, e))?;
        std::io::Write::write_all(&mut tmp, &bytes)
            .map_err(|e| Error::io("write", tmp.path(), e))?;
        tmp.as_file()
            .sync_all()
            .map_err(|e| Error::io("fsync", tmp.path(), e))?;
        tmp.persist(path)
            .map_err(|e| Error::io("rename", path, e.error))?;
        Ok(())
    }
}
