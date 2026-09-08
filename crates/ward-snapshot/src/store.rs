//! The content-addressed store (CAS).
//!
//! Layout under the store directory:
//!
//! ```text
//! blobs/<hex[0..2]>/<hex>      file content, named by BLAKE3, mode 0444
//! manifests/<hex>              canonical manifest bytes, named by snapshot id
//! meta/<hex>.json              SnapshotMeta for that id (optional)
//! refs/<session>               newline-separated snapshot ids referenced by a session
//! tmp/                         staging area for atomic writes (same filesystem)
//! ```
//!
//! Every blob and manifest is written to `tmp/`, fsynced, and renamed into place, so a
//! crash never leaves a partially written object under its final name. Ingest uses
//! reflink (`FICLONE`) when the worktree and the store share a reflink-capable
//! filesystem (Btrfs, XFS with reflink, bcachefs) and falls back to a plain copy. A
//! reflinked blob shares extents with the agent's file but is copy-on-write: the agent's
//! later writes never reach the blob.
//!
//! Retention is by session references (`docs/snapshots-and-git.md` §7): [`Store::gc`]
//! keeps everything reachable from `refs/` and removes unreferenced objects older than
//! the retention window. Evidence-retained `accepted` snapshots are expressed as
//! references held by the evidence's own session record.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use rayon::prelude::*;

use crate::error::{Error, Result};
use crate::hash::{ContentHash, SnapshotId};
use crate::manifest::{EntryKind, Manifest};
use crate::meta::SnapshotMeta;

/// Options for [`Store::ingest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestOptions {
    /// Try `FICLONE` before copying. Default `true`.
    pub use_reflink: bool,
    /// Re-hash every newly written blob and fail on mismatch with the manifest. Costs a
    /// second read of new content; useful when the tree might not have been quiescent.
    /// Default `false` (capture ran on a frozen tree, so the manifest hash is
    /// authoritative).
    pub verify: bool,
    /// `fsync` every staged blob before renaming it into place. Default `true`.
    ///
    /// With `false`, blobs are renamed without a per-file `fsync` and the caller must
    /// call [`Store::sync`] once afterwards to make the batch durable. On the
    /// frozen-copy path this moves the (large) `fsync` cost out of the agent-visible
    /// stall: copy while frozen, thaw, then `sync`. Until `sync` returns, a crash can
    /// leave a blob under its final name with incomplete content; [`Store::get_manifest`]
    /// still verifies manifests, and [`Store::verify_blob`] verifies a blob on demand.
    pub fsync_each: bool,
}

impl Default for IngestOptions {
    fn default() -> Self {
        IngestOptions {
            use_reflink: true,
            verify: false,
            fsync_each: true,
        }
    }
}

/// What [`Store::ingest`] did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IngestReport {
    /// Regular-file entries in the manifest.
    pub files: u64,
    /// Blobs newly written.
    pub blobs_written: u64,
    /// Blobs that already existed (deduplicated).
    pub blobs_existing: u64,
    /// Bytes of newly written blobs (logical size, even when reflinked).
    pub bytes_written: u64,
    /// Newly written blobs that were reflinked.
    pub reflinked: u64,
    /// Newly written blobs that were copied byte-by-byte.
    pub copied: u64,
    /// Wall time.
    pub duration: Duration,
}

/// What [`Store::gc`] did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GcReport {
    /// Manifests kept because they are referenced or too young.
    pub manifests_kept: u64,
    /// Manifests removed.
    pub manifests_removed: u64,
    /// Blobs kept.
    pub blobs_kept: u64,
    /// Blobs removed.
    pub blobs_removed: u64,
    /// Logical bytes of removed blobs.
    pub bytes_freed: u64,
}

/// A content-addressed store rooted at a directory.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl Store {
    /// Open (creating if necessary) the store at `dir`.
    ///
    /// # Errors
    /// I/O errors creating the layout.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let root = dir.into();
        for sub in ["blobs", "manifests", "meta", "refs", "tmp"] {
            let p = root.join(sub);
            fs::create_dir_all(&p).map_err(|e| Error::io("mkdir", &p, e))?;
        }
        // Pre-create the 256 shard directories so ingest never has to `mkdir` on the hot
        // path (a `create_dir_all` per blob costs a stat and, on a cold shard, a journal
        // transaction).
        for shard in 0..=0xffu8 {
            let p = root.join("blobs").join(format!("{shard:02x}"));
            match fs::create_dir(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(Error::io("mkdir", &p, e)),
            }
        }
        Ok(Store { root })
    }

    /// The store directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where a blob lives (whether or not it exists).
    #[must_use]
    pub fn blob_path(&self, hash: &ContentHash) -> PathBuf {
        let hex = hash.to_hex();
        self.root.join("blobs").join(&hex[..2]).join(hex)
    }

    /// Where a manifest lives (whether or not it exists).
    #[must_use]
    pub fn manifest_path(&self, id: &SnapshotId) -> PathBuf {
        self.root.join("manifests").join(id.to_hex())
    }

    fn meta_path(&self, id: &SnapshotId) -> PathBuf {
        self.root.join("meta").join(format!("{}.json", id.to_hex()))
    }

    /// True if the blob exists.
    #[must_use]
    pub fn has_blob(&self, hash: &ContentHash) -> bool {
        self.blob_path(hash).is_file()
    }

    /// True if the manifest exists.
    #[must_use]
    pub fn has_manifest(&self, id: &SnapshotId) -> bool {
        self.manifest_path(id).is_file()
    }

    fn tmp_path(&self) -> PathBuf {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.root
            .join("tmp")
            .join(format!("{}-{n}", std::process::id()))
    }

    /// Open a blob for reading.
    ///
    /// # Errors
    /// [`Error::MissingBlob`] if absent; I/O errors otherwise.
    pub fn open_blob(&self, hash: &ContentHash) -> Result<File> {
        let p = self.blob_path(hash);
        File::open(&p).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::MissingBlob(*hash)
            } else {
                Error::io("open", &p, e)
            }
        })
    }

    /// Read a whole blob.
    ///
    /// # Errors
    /// See [`Store::open_blob`].
    pub fn read_blob(&self, hash: &ContentHash) -> Result<Vec<u8>> {
        let mut f = self.open_blob(hash)?;
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut buf)
            .map_err(|e| Error::io("read", self.blob_path(hash), e))?;
        Ok(buf)
    }

    /// Store an in-memory blob. Returns its hash and whether it was newly written.
    ///
    /// # Errors
    /// I/O errors.
    pub fn put_blob_bytes(&self, bytes: &[u8]) -> Result<(ContentHash, bool)> {
        let hash = ContentHash::of(bytes);
        let dest = self.blob_path(&hash);
        if dest.is_file() {
            return Ok((hash, false));
        }
        let tmp = self.tmp_path();
        {
            let mut f = File::create(&tmp).map_err(|e| Error::io("create", &tmp, e))?;
            f.write_all(bytes)
                .map_err(|e| Error::io("write", &tmp, e))?;
            f.sync_all().map_err(|e| Error::io("fsync", &tmp, e))?;
        }
        let written = self.commit_blob(&tmp, &dest, true)?;
        Ok((hash, written))
    }

    /// Store the regular file at `src` as a blob.
    ///
    /// `expected` is the hash the caller already computed (from a capture of a
    /// quiescent tree); with `opts.verify` the staged copy is re-hashed and must match.
    /// Without `expected` the staged copy is always hashed to learn its name.
    ///
    /// Returns the hash, whether a new blob was written, and whether the write was a
    /// reflink.
    ///
    /// # Errors
    /// [`Error::HashMismatch`] on a verify failure; I/O errors.
    pub fn put_blob_from_path(
        &self,
        src: &Path,
        expected: Option<ContentHash>,
        opts: IngestOptions,
    ) -> Result<(ContentHash, bool, bool)> {
        if let Some(h) = expected
            && self.has_blob(&h)
        {
            return Ok((h, false, false));
        }
        let tmp = self.tmp_path();
        let reflinked = stage_copy(src, &tmp, opts.use_reflink)?;
        let staged = TmpGuard(&tmp);
        let hash = if expected.is_none() || opts.verify {
            let (actual, _) = ContentHash::of_file(&tmp)?;
            if let Some(exp) = expected
                && exp != actual
            {
                return Err(Error::HashMismatch {
                    path: src.to_path_buf(),
                    expected: exp,
                    actual,
                });
            }
            actual
        } else {
            expected.unwrap_or(ContentHash::NONE)
        };
        let dest = self.blob_path(&hash);
        if dest.is_file() {
            return Ok((hash, false, false));
        }
        if opts.fsync_each {
            let file = File::open(&tmp).map_err(|e| Error::io("open", &tmp, e))?;
            file.sync_all().map_err(|e| Error::io("fsync", &tmp, e))?;
        }
        let written = self.commit_blob(&tmp, &dest, opts.fsync_each)?;
        staged.disarm();
        Ok((hash, written, written && reflinked))
    }

    /// Set read-only permissions and rename `tmp` into `dest`, fsyncing the shard
    /// directory when `durable`. Returns `false` if another writer won the race (the
    /// tmp file is removed).
    fn commit_blob(&self, tmp: &Path, dest: &Path, durable: bool) -> Result<bool> {
        fs::set_permissions(tmp, fs::Permissions::from_mode(0o444))
            .map_err(|e| Error::io("chmod", tmp, e))?;
        let parent = dest.parent().unwrap_or(&self.root);
        if dest.is_file() {
            let _ = fs::remove_file(tmp);
            return Ok(false);
        }
        fs::rename(tmp, dest).map_err(|e| Error::io("rename", dest, e))?;
        if durable {
            sync_dir(parent);
        }
        Ok(true)
    }

    /// Copy every regular file of `manifest` from the worktree at `root` into the store,
    /// and store each symlink's target bytes as a blob under the symlink's hash.
    ///
    /// Directories and unsupported entries carry no blob. Blobs already present are
    /// skipped without reading the source. Files are ingested in parallel.
    ///
    /// # Errors
    /// I/O errors; [`Error::HashMismatch`] when a symlink target no longer matches the
    /// manifest, or when `opts.verify` is set and a file's content no longer matches.
    pub fn ingest(
        &self,
        root: &Path,
        manifest: &Manifest,
        opts: IngestOptions,
    ) -> Result<IngestReport> {
        let t0 = Instant::now();
        for e in manifest
            .entries()
            .iter()
            .filter(|e| e.kind == EntryKind::Symlink)
        {
            use std::os::unix::ffi::OsStrExt;
            let src = root.join(e.path.as_path());
            let target = fs::read_link(&src).map_err(|err| Error::io("readlink", &src, err))?;
            let bytes = target.as_os_str().as_bytes();
            let actual = ContentHash::of(bytes);
            if actual != e.hash {
                return Err(Error::HashMismatch {
                    path: src,
                    expected: e.hash,
                    actual,
                });
            }
            self.put_blob_bytes(bytes)?;
        }
        let files: Vec<_> = manifest
            .entries()
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .collect();
        let mut seen: HashSet<ContentHash> = HashSet::with_capacity(files.len());
        // Deduplicate within the manifest so identical files are staged once.
        let unique: Vec<_> = files.iter().filter(|e| seen.insert(e.hash)).collect();
        let outcomes: Vec<(bool, bool, u64)> = unique
            .par_iter()
            .map(|e| {
                let src = root.join(e.path.as_path());
                let (_, written, reflinked) = self.put_blob_from_path(&src, Some(e.hash), opts)?;
                Ok((written, reflinked, e.size))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut report = IngestReport {
            files: files.len() as u64,
            ..IngestReport::default()
        };
        for (written, reflinked, size) in outcomes {
            if written {
                report.blobs_written += 1;
                report.bytes_written += size;
                if reflinked {
                    report.reflinked += 1;
                } else {
                    report.copied += 1;
                }
            } else {
                report.blobs_existing += 1;
            }
        }
        report.duration = t0.elapsed();
        Ok(report)
    }

    /// Store a manifest under its id. Idempotent.
    ///
    /// # Errors
    /// I/O errors.
    pub fn put_manifest(&self, manifest: &Manifest) -> Result<SnapshotId> {
        let bytes = manifest.to_canonical_bytes();
        let id = SnapshotId::of_manifest_bytes(&bytes);
        let dest = self.manifest_path(&id);
        if dest.is_file() {
            return Ok(id);
        }
        self.write_atomic(&dest, &bytes)?;
        Ok(id)
    }

    /// Load and verify a manifest.
    ///
    /// # Errors
    /// [`Error::MissingManifest`]; [`Error::IdMismatch`] if the stored bytes do not hash
    /// to `id`; parse errors for corrupt content.
    pub fn get_manifest(&self, id: &SnapshotId) -> Result<Manifest> {
        let p = self.manifest_path(id);
        let bytes = fs::read(&p).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::MissingManifest(*id)
            } else {
                Error::io("read", &p, e)
            }
        })?;
        let actual = SnapshotId::of_manifest_bytes(&bytes);
        if actual != *id {
            return Err(Error::IdMismatch {
                expected: *id,
                actual,
            });
        }
        Manifest::parse(&bytes)
    }

    /// Store metadata for a snapshot (overwrites; the role of an id can change from
    /// candidate to accepted).
    ///
    /// # Errors
    /// I/O or serialisation errors.
    pub fn put_meta(&self, meta: &SnapshotMeta) -> Result<()> {
        let dest = self.meta_path(&meta.id);
        let bytes = serde_json::to_vec_pretty(meta).map_err(|e| Error::Serde {
            path: dest.clone(),
            message: e.to_string(),
        })?;
        self.write_atomic(&dest, &bytes)
    }

    /// Load metadata for a snapshot.
    ///
    /// # Errors
    /// [`Error::MissingManifest`] if there is no metadata; I/O or parse errors.
    pub fn get_meta(&self, id: &SnapshotId) -> Result<SnapshotMeta> {
        let p = self.meta_path(id);
        let bytes = fs::read(&p).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::MissingManifest(*id)
            } else {
                Error::io("read", &p, e)
            }
        })?;
        serde_json::from_slice(&bytes).map_err(|e| Error::Serde {
            path: p,
            message: e.to_string(),
        })
    }

    /// Record that `session` references `id`.
    ///
    /// # Errors
    /// [`Error::InvalidSession`] for a session id that is not a safe file name; I/O
    /// errors.
    pub fn add_reference(&self, session: &str, id: &SnapshotId) -> Result<()> {
        let p = self.refs_path(session)?;
        let mut ids = read_refs_file(&p)?;
        if ids.insert(*id) {
            let mut text = String::with_capacity(ids.len() * 65);
            for i in &ids {
                text.push_str(&i.to_hex());
                text.push('\n');
            }
            self.write_atomic(&p, text.as_bytes())?;
        }
        Ok(())
    }

    /// Drop every reference held by `session`.
    ///
    /// # Errors
    /// [`Error::InvalidSession`]; I/O errors.
    pub fn remove_session(&self, session: &str) -> Result<()> {
        let p = self.refs_path(session)?;
        match fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::io("unlink", &p, e)),
        }
    }

    /// All references, by session.
    ///
    /// # Errors
    /// I/O errors.
    pub fn references(&self) -> Result<BTreeMap<String, BTreeSet<SnapshotId>>> {
        let dir = self.root.join("refs");
        let mut out = BTreeMap::new();
        for entry in fs::read_dir(&dir).map_err(|e| Error::io("readdir", &dir, e))? {
            let entry = entry.map_err(|e| Error::io("readdir", &dir, e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let ids = read_refs_file(&entry.path())?;
            out.insert(name, ids);
        }
        Ok(out)
    }

    fn refs_path(&self, session: &str) -> Result<PathBuf> {
        let ok = !session.is_empty()
            && session.len() <= 200
            && !session.starts_with('.')
            && session
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.');
        if !ok {
            return Err(Error::InvalidSession(session.to_owned()));
        }
        Ok(self.root.join("refs").join(session))
    }

    /// Remove unreferenced manifests and blobs whose file is older than `retention`.
    ///
    /// Reachability: every id in every `refs/` file, plus every blob named by a kept
    /// manifest (referenced *or* younger than the retention window, so a snapshot being
    /// written concurrently is never torn). Manifests that fail to parse are kept and
    /// counted as kept.
    ///
    /// # Errors
    /// I/O errors.
    pub fn gc(&self, retention: Duration) -> Result<GcReport> {
        let cutoff = SystemTime::now()
            .checked_sub(retention)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let referenced: BTreeSet<SnapshotId> = self.references()?.into_values().flatten().collect();
        let mut report = GcReport::default();
        let mut live_blobs: HashSet<ContentHash> = HashSet::new();

        let mdir = self.root.join("manifests");
        for entry in fs::read_dir(&mdir).map_err(|e| Error::io("readdir", &mdir, e))? {
            let entry = entry.map_err(|e| Error::io("readdir", &mdir, e))?;
            let path = entry.path();
            let Ok(id) = entry.file_name().to_string_lossy().parse::<SnapshotId>() else {
                continue;
            };
            let young = is_younger_than(&path, cutoff);
            if referenced.contains(&id) || young {
                report.manifests_kept += 1;
                if let Ok(m) = self.get_manifest(&id) {
                    live_blobs.extend(
                        m.entries()
                            .iter()
                            .filter(|e| e.kind == EntryKind::File)
                            .map(|e| e.hash),
                    );
                }
            } else {
                fs::remove_file(&path).map_err(|e| Error::io("unlink", &path, e))?;
                let _ = fs::remove_file(self.meta_path(&id));
                report.manifests_removed += 1;
            }
        }

        let bdir = self.root.join("blobs");
        for shard in fs::read_dir(&bdir).map_err(|e| Error::io("readdir", &bdir, e))? {
            let shard = shard.map_err(|e| Error::io("readdir", &bdir, e))?.path();
            if !shard.is_dir() {
                continue;
            }
            for entry in fs::read_dir(&shard).map_err(|e| Error::io("readdir", &shard, e))? {
                let entry = entry.map_err(|e| Error::io("readdir", &shard, e))?;
                let path = entry.path();
                let Ok(hash) = entry.file_name().to_string_lossy().parse::<ContentHash>() else {
                    continue;
                };
                if live_blobs.contains(&hash) || is_younger_than(&path, cutoff) {
                    report.blobs_kept += 1;
                } else {
                    let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    fs::remove_file(&path).map_err(|e| Error::io("unlink", &path, e))?;
                    report.blobs_removed += 1;
                    report.bytes_freed += size;
                }
            }
        }

        let tdir = self.root.join("tmp");
        for entry in fs::read_dir(&tdir)
            .map_err(|e| Error::io("readdir", &tdir, e))?
            .flatten()
        {
            let path = entry.path();
            if !is_younger_than(&path, cutoff) {
                let _ = fs::remove_file(&path);
            }
        }
        Ok(report)
    }

    /// Flush the whole filesystem holding the store (`syncfs(2)`), making every blob
    /// ingested with `fsync_each = false` durable.
    ///
    /// # Errors
    /// I/O errors.
    pub fn sync(&self) -> Result<()> {
        let dir = File::open(&self.root).map_err(|e| Error::io("open", &self.root, e))?;
        rustix::fs::syncfs(&dir).map_err(|e| Error::io("syncfs", &self.root, e.into()))
    }

    /// Re-hash a stored blob and compare with its name.
    ///
    /// # Errors
    /// [`Error::MissingBlob`], [`Error::HashMismatch`], I/O errors.
    pub fn verify_blob(&self, hash: &ContentHash) -> Result<()> {
        let p = self.blob_path(hash);
        if !p.is_file() {
            return Err(Error::MissingBlob(*hash));
        }
        let (actual, _) = ContentHash::of_file(&p)?;
        if actual != *hash {
            return Err(Error::HashMismatch {
                path: p,
                expected: *hash,
                actual,
            });
        }
        Ok(())
    }

    /// Bytes on disk used by blobs (sum of `st_blocks * 512`) and their logical size.
    ///
    /// # Errors
    /// I/O errors.
    pub fn blob_disk_usage(&self) -> Result<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        let bdir = self.root.join("blobs");
        let (mut allocated, mut logical) = (0u64, 0u64);
        for shard in fs::read_dir(&bdir)
            .map_err(|e| Error::io("readdir", &bdir, e))?
            .flatten()
        {
            let shard = shard.path();
            if !shard.is_dir() {
                continue;
            }
            for entry in fs::read_dir(&shard)
                .map_err(|e| Error::io("readdir", &shard, e))?
                .flatten()
            {
                if let Ok(m) = entry.metadata() {
                    allocated += m.blocks() * 512;
                    logical += m.len();
                }
            }
        }
        Ok((allocated, logical))
    }

    /// Write `bytes` to `dest` via a fsynced temp file and rename.
    fn write_atomic(&self, dest: &Path, bytes: &[u8]) -> Result<()> {
        let tmp = self.tmp_path();
        {
            let mut f = File::create(&tmp).map_err(|e| Error::io("create", &tmp, e))?;
            f.write_all(bytes)
                .map_err(|e| Error::io("write", &tmp, e))?;
            f.sync_all().map_err(|e| Error::io("fsync", &tmp, e))?;
        }
        let parent = dest.parent().unwrap_or(&self.root);
        fs::rename(&tmp, dest).map_err(|e| Error::io("rename", dest, e))?;
        sync_dir(parent);
        Ok(())
    }
}

fn read_refs_file(p: &Path) -> Result<BTreeSet<SnapshotId>> {
    let text = match fs::read_to_string(p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(e) => return Err(Error::io("read", p, e)),
    };
    let mut ids = BTreeSet::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        ids.insert(line.parse::<SnapshotId>()?);
    }
    Ok(ids)
}

/// Removes the staged temp file on drop unless disarmed.
struct TmpGuard<'a>(&'a Path);

impl TmpGuard<'_> {
    fn disarm(self) {
        std::mem::forget(self);
    }
}

impl Drop for TmpGuard<'_> {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0);
    }
}

/// Stage `src` at `tmp`; returns whether the staging was a reflink.
fn stage_copy(src: &Path, tmp: &Path, use_reflink: bool) -> Result<bool> {
    if use_reflink {
        match reflink_copy::reflink_or_copy(src, tmp) {
            Ok(None) => Ok(true),
            Ok(Some(_)) => Ok(false),
            Err(e) => Err(Error::io("reflink_or_copy", src, e)),
        }
    } else {
        fs::copy(src, tmp).map_err(|e| Error::io("copy", src, e))?;
        Ok(false)
    }
}

fn is_younger_than(path: &Path, cutoff: SystemTime) -> bool {
    fs::symlink_metadata(path)
        .and_then(|m| m.modified())
        .map(|mtime| mtime > cutoff)
        .unwrap_or(true)
}

/// Best-effort directory fsync (durability of the rename).
fn sync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}
