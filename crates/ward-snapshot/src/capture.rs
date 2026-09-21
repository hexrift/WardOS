//! Deterministic capture of a directory tree into a manifest and CAS blobs.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::backend::Backend;
use crate::cas::Cas;
use crate::error::{Result, SnapshotError};
use crate::id::Digest;
use crate::ignore::Rules;
use crate::manifest::{Entry, EntryType, Manifest};
use crate::meta::{CaptureMode, GitContext};

const DEFAULT_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Policy governing what a capture includes.
#[derive(Clone, Copy, Debug)]
pub struct CaptureOptions {
    /// Include files excluded by `.gitignore` (default: false).
    pub include_ignored: bool,
    /// Capture the `.git` directory as ordinary files (default: true).
    pub include_git_dir: bool,
    /// Reuse cached `(path, mtime, size) -> hash` results (default: false).
    pub incremental: bool,
    /// Abort if total captured content exceeds this many bytes.
    pub max_bytes: u64,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            include_ignored: false,
            include_git_dir: true,
            incremental: false,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

/// A cache of file content hashes keyed by path, mtime, and size, letting an
/// incremental capture skip re-reading and re-hashing unchanged files.
#[derive(Clone, Debug, Default)]
pub struct HashCache {
    map: HashMap<PathBuf, (SystemTime, u64, Digest)>,
}

impl HashCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of cached files.
    pub fn len(&self) -> usize {
        self.map.len()
    }
    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    /// Forget all cached hashes.
    pub fn clear(&mut self) {
        self.map.clear();
    }
}

/// Counts describing the work a capture did (useful for tests and telemetry).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureStats {
    /// Regular files encountered.
    pub files_total: u64,
    /// Files whose bytes were read and hashed.
    pub files_hashed: u64,
    /// Files served from the incremental cache without re-hashing.
    pub files_cached: u64,
    /// Bytes actually read and hashed.
    pub bytes_hashed: u64,
}

/// Result of walking a tree: the manifest plus how it was captured.
pub(crate) struct Capture {
    pub manifest: Manifest,
    pub mode: CaptureMode,
    pub git_context: Option<GitContext>,
}

pub(crate) fn capture(
    cas: &Cas,
    backend: &dyn Backend,
    source: &Path,
    opts: CaptureOptions,
    cache: &mut HashCache,
    stats: &mut CaptureStats,
) -> Result<Capture> {
    walk(Some(cas), backend, source, opts, cache, stats)
}

/// The same walk as [`capture`] with nothing stored: every leaf is hashed in
/// memory, so the manifest (and its id) is exactly what a capture would
/// produce. This is what lets a shell compare a worktree against a verified
/// candidate by content without owning a CAS (ADR-0019 decision 1).
pub(crate) fn digest(
    backend: &dyn Backend,
    source: &Path,
    opts: CaptureOptions,
    cache: &mut HashCache,
    stats: &mut CaptureStats,
) -> Result<Capture> {
    walk(None, backend, source, opts, cache, stats)
}

fn walk(
    cas: Option<&Cas>,
    backend: &dyn Backend,
    source: &Path,
    opts: CaptureOptions,
    cache: &mut HashCache,
    stats: &mut CaptureStats,
) -> Result<Capture> {
    let frozen = backend.freeze(source)?;
    let root = frozen.root();
    let mut walker = Walker {
        cas,
        opts,
        cache,
        stats,
        entries: Vec::new(),
        total_bytes: 0,
    };
    let mut rules = Rules::default();
    walker.walk_dir(root, b"", &mut rules)?;
    let manifest = Manifest::from_entries(walker.entries)?;
    Ok(Capture {
        manifest,
        mode: backend.mode(),
        git_context: read_git_context(root),
    })
}

struct Walker<'a> {
    /// Where leaves go; `None` digests without storing.
    cas: Option<&'a Cas>,
    opts: CaptureOptions,
    cache: &'a mut HashCache,
    stats: &'a mut CaptureStats,
    entries: Vec<Entry>,
    total_bytes: u64,
}

impl Walker<'_> {
    fn walk_dir(&mut self, abs: &Path, rel: &[u8], rules: &mut Rules) -> Result<()> {
        let added = if self.opts.include_ignored {
            0
        } else {
            match fs::read(abs.join(".gitignore")) {
                Ok(body) => rules.push_file(&body, rel),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
                Err(e) => return Err(SnapshotError::io(abs.join(".gitignore"), e)),
            }
        };

        let mut names = read_dir_names(abs)?;
        names.sort();
        for name in names {
            self.visit(abs, rel, &name, rules)?;
        }

        rules.truncate_by(added);
        Ok(())
    }

    fn visit(
        &mut self,
        dir_abs: &Path,
        dir_rel: &[u8],
        name: &[u8],
        rules: &mut Rules,
    ) -> Result<()> {
        let abs = dir_abs.join(Path::new(std::ffi::OsStr::from_bytes(name)));
        let rel = join_rel(dir_rel, name);
        let is_git = name == b".git";
        if is_git && !self.opts.include_git_dir {
            return Ok(());
        }

        let meta = fs::symlink_metadata(&abs).map_err(|e| SnapshotError::io(&abs, e))?;
        let ft = meta.file_type();

        if !is_git && !self.opts.include_ignored && rules.is_ignored(&rel, ft.is_dir()) {
            return Ok(());
        }
        let mode = meta.mode() & 0o7777;

        if ft.is_symlink() {
            let target = fs::read_link(&abs).map_err(|e| SnapshotError::io(&abs, e))?;
            let bytes = target.as_os_str().as_bytes();
            let digest = self.store(bytes)?;
            self.push(
                rel,
                EntryType::Symlink,
                mode,
                bytes.len() as u64,
                Some(digest),
            );
        } else if ft.is_dir() {
            // A subdirectory that itself contains a `.git` is a submodule worktree;
            // its contents are still recursed as ordinary files.
            let kind = if abs.join(".git").symlink_metadata().is_ok() {
                EntryType::SubmoduleWorktree
            } else {
                EntryType::Dir
            };
            self.push(rel.clone(), kind, mode, 0, None);
            self.walk_dir(&abs, &rel, rules)?;
        } else if ft.is_file() {
            self.stats.files_total += 1;
            let size = meta.len();
            // Check the budget against the file's *claimed* size before reading
            // any of its bytes: this is a cheap early reject for a file whose
            // metadata already declares it over budget (issue #160). It is not
            // sufficient on its own, though: the tree is agent-controlled, so the
            // file can grow or be replaced between this `symlink_metadata` and the
            // read that follows (a TOCTOU). The authoritative bound therefore lives
            // in `hash_file`, which reads at most `remaining + 1` bytes and rejects
            // overflow before hashing or storing anything — capping peak allocation
            // regardless of what `metadata().len()` claimed here.
            let prospective_total = self.total_bytes.saturating_add(size);
            if prospective_total > self.opts.max_bytes {
                return Err(SnapshotError::BudgetExceeded(self.opts.max_bytes));
            }
            // Account by the bytes *actually* read within budget, not the metadata
            // size, so a file that shrank or grew between metadata and read is
            // counted by what was truly buffered.
            let (digest, read_len) = self.hash_file(&abs, &meta)?;
            self.total_bytes = self.total_bytes.saturating_add(read_len);
            self.push(rel, EntryType::File, mode, size, Some(digest));
        } else if ft.is_fifo() || ft.is_socket() || ft.is_block_device() || ft.is_char_device() {
            self.push(rel, EntryType::Unsupported, mode, 0, None);
        }
        Ok(())
    }

    /// Hash (and, when there is a CAS, store) one regular file, returning its
    /// digest and the number of content bytes actually read. Every read here is
    /// bounded by the remaining budget via [`Walker::read_within_budget`], so an
    /// over-budget file is rejected before any blob is stored.
    fn hash_file(&mut self, abs: &Path, meta: &fs::Metadata) -> Result<(Digest, u64)> {
        if self.opts.incremental {
            let mtime = meta.modified().map_err(|e| SnapshotError::io(abs, e))?;
            let size = meta.len();
            if let Some(&(mt, sz, d)) = self.cache.map.get(abs)
                && mt == mtime
                && sz == size
            {
                // The cache may have been warmed by a digest-only walk, or by
                // a capture into another CAS: a hit says what the bytes hash
                // to, not that this store holds them.
                if let Some(cas) = self.cas
                    && !cas.has_blob(d)
                {
                    // CAS-backfill read: still agent-controlled input, so bound it
                    // against the remaining budget just like a fresh read.
                    let bytes = self.read_within_budget(abs)?;
                    cas.put_blob(&bytes)?;
                }
                self.stats.files_cached += 1;
                // The metadata matched the cache, so the content length is `size`.
                return Ok((d, size));
            }
            let bytes = self.read_within_budget(abs)?;
            let n = bytes.len() as u64;
            let d = self.store(&bytes)?;
            self.cache.map.insert(abs.to_path_buf(), (mtime, size, d));
            self.stats.files_hashed += 1;
            self.stats.bytes_hashed += n;
            Ok((d, n))
        } else {
            let bytes = self.read_within_budget(abs)?;
            let n = bytes.len() as u64;
            let d = self.store(&bytes)?;
            self.stats.files_hashed += 1;
            self.stats.bytes_hashed += n;
            Ok((d, n))
        }
    }

    /// Read a candidate file's bytes while enforcing the remaining byte budget on
    /// the read itself. Opens the file once and reads at most `remaining + 1`
    /// bytes; if that sentinel byte is reached the file is over budget and
    /// [`SnapshotError::BudgetExceeded`] is returned before any hashing or store,
    /// so peak allocation is capped at `remaining + 1` no matter what the earlier
    /// `metadata().len()` claimed. A result of `<= remaining` bytes is the whole
    /// file (the cap was not hit), hashed and stored as-is.
    fn read_within_budget(&self, abs: &Path) -> Result<Vec<u8>> {
        let file = fs::File::open(abs).map_err(|e| SnapshotError::io(abs, e))?;
        let remaining = self.opts.max_bytes.saturating_sub(self.total_bytes);
        read_capped(file, remaining, self.opts.max_bytes, abs)
    }

    /// The digest of one leaf, stored when there is a CAS to store it in.
    fn store(&self, bytes: &[u8]) -> Result<Digest> {
        match self.cas {
            Some(cas) => cas.put_blob(bytes),
            None => Ok(Digest::of(bytes)),
        }
    }

    fn push(
        &mut self,
        path: Vec<u8>,
        kind: EntryType,
        mode: u32,
        size: u64,
        content: Option<Digest>,
    ) {
        self.entries.push(Entry {
            path,
            kind,
            mode,
            size,
            content,
        });
    }
}

/// Read from `reader` into a `Vec`, buffering at most `remaining + 1` bytes.
///
/// This is the authoritative byte-budget bound. It is deliberately independent
/// of any prior `metadata().len()`: an agent-controlled file can grow or be
/// replaced after its metadata was observed, so only bounding the read itself
/// caps allocation. At most `remaining + 1` bytes are ever buffered; if the
/// `+ 1` sentinel byte is present the source held more than `remaining` bytes
/// and [`SnapshotError::BudgetExceeded`] is returned (with the configured
/// `max_bytes`) before the bytes are handed back for hashing or storage.
/// Otherwise the returned `Vec` is the complete content (the cap was not hit).
///
/// `path` is used only to tag any I/O error with its source file.
fn read_capped(reader: impl Read, remaining: u64, max_bytes: u64, path: &Path) -> Result<Vec<u8>> {
    // Cap the reader at one byte past the budget: reaching that extra byte is
    // proof of overflow, while a shorter read is a complete, in-budget file.
    let cap = remaining.saturating_add(1);
    let mut buf = Vec::new();
    reader
        .take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| SnapshotError::io(path, e))?;
    if buf.len() as u64 > remaining {
        return Err(SnapshotError::BudgetExceeded(max_bytes));
    }
    Ok(buf)
}

fn read_dir_names(dir: &Path) -> Result<Vec<Vec<u8>>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| SnapshotError::io(dir, e))? {
        let entry = entry.map_err(|e| SnapshotError::io(dir, e))?;
        names.push(entry.file_name().as_bytes().to_vec());
    }
    Ok(names)
}

fn join_rel(dir_rel: &[u8], name: &[u8]) -> Vec<u8> {
    if dir_rel.is_empty() {
        name.to_vec()
    } else {
        let mut p = Vec::with_capacity(dir_rel.len() + 1 + name.len());
        p.extend_from_slice(dir_rel);
        p.push(b'/');
        p.extend_from_slice(name);
        p
    }
}

fn read_git_context(root: &Path) -> Option<GitContext> {
    let head = fs::read_to_string(root.join(".git").join("HEAD")).ok()?;
    let head = head.trim();
    if let Some(reference) = head.strip_prefix("ref: ") {
        // `.git/HEAD` lives inside the captured (agent-controlled) worktree, so its
        // `ref:` target is untrusted input. A real symref is a relative `refs/...`
        // path; anything else — an absolute path, a `..` escape, a NUL — must not be
        // followed, or a crafted HEAD would make the host wardd read an arbitrary file
        // (e.g. `ref: /etc/shadow`) and embed its contents in the snapshot metadata.
        let safe = reference.starts_with("refs/")
            && crate::manifest::validate_path(reference.as_bytes()).is_ok();
        let branch = if safe {
            reference.rsplit('/').next().map(str::to_string)
        } else {
            None
        };
        let sha = if safe {
            fs::read_to_string(root.join(".git").join(reference))
                .ok()
                .map(|s| s.trim().to_string())
        } else {
            None
        };
        Some(GitContext {
            head: sha,
            branch,
            detached: false,
        })
    } else {
        Some(GitContext {
            head: Some(head.to_string()),
            branch: None,
            detached: true,
        })
    }
}

#[cfg(test)]
mod git_context_tests {
    #![allow(clippy::unwrap_used)]
    use super::read_git_context;
    use std::fs;

    fn worktree_with_head(head: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let git = dir.path().join(".git");
        fs::create_dir_all(&git).unwrap();
        fs::write(git.join("HEAD"), head).unwrap();
        dir
    }

    #[test]
    fn follows_a_legitimate_symref() {
        let dir = worktree_with_head("ref: refs/heads/main\n");
        fs::create_dir_all(dir.path().join(".git/refs/heads")).unwrap();
        fs::write(dir.path().join(".git/refs/heads/main"), "abc123\n").unwrap();
        let ctx = read_git_context(dir.path()).unwrap();
        assert_eq!(ctx.head.as_deref(), Some("abc123"));
        assert_eq!(ctx.branch.as_deref(), Some("main"));
        assert!(!ctx.detached);
    }

    #[test]
    fn refuses_an_absolute_ref_target() {
        // A crafted HEAD must not make wardd read a host file outside the worktree.
        let dir = worktree_with_head("ref: /etc/hostname\n");
        let ctx = read_git_context(dir.path()).unwrap();
        assert_eq!(
            ctx.head, None,
            "an absolute ref target was followed off the tree"
        );
        assert_eq!(ctx.branch, None);
    }

    #[test]
    fn refuses_a_traversal_ref_target() {
        let dir = worktree_with_head("ref: ../../../../etc/hostname\n");
        let ctx = read_git_context(dir.path()).unwrap();
        assert_eq!(ctx.head, None, "a `..` ref target escaped the worktree");
        assert_eq!(ctx.branch, None);
    }

    #[test]
    fn refuses_a_ref_outside_refs() {
        // Even a relative, traversal-free target is not followed unless it is a refs/ path.
        let dir = worktree_with_head("ref: config\n");
        fs::write(dir.path().join(".git/config"), "[core]\n").unwrap();
        let ctx = read_git_context(dir.path()).unwrap();
        assert_eq!(ctx.head, None, "a non-refs/ ref target was followed");
    }

    #[test]
    fn detached_head_is_recorded_verbatim() {
        let dir = worktree_with_head("0123456789abcdef0123456789abcdef01234567\n");
        let ctx = read_git_context(dir.path()).unwrap();
        assert_eq!(
            ctx.head.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert!(ctx.detached);
    }
}

#[cfg(test)]
mod bounded_read_tests {
    #![allow(clippy::unwrap_used)]
    use super::read_capped;
    use crate::error::SnapshotError;
    use std::io;
    use std::path::Path;

    /// The read is bounded by `remaining + 1`, not by any metadata length. A
    /// reader that yields bytes without end — standing in for a file that grew
    /// or was swapped for a larger one after its (stale) metadata was observed —
    /// is rejected as over budget without buffering the whole stream.
    ///
    /// This is the regression for the TOCTOU that the metadata-only pre-check
    /// could not close: the old path did an unbounded `fs::read`, which on this
    /// endless source would never return (exhausting host memory). The bounded
    /// read returning `BudgetExceeded` instead — and, because the error is
    /// returned before any bytes are handed back, storing no blob — is the fix.
    #[test]
    fn a_source_longer_than_metadata_claimed_is_rejected_by_the_read_itself() {
        // `io::repeat` yields its byte forever; reaching `read_capped`'s return at
        // all proves the read is capped independently of the source's true length.
        let grown = io::repeat(b'x');
        let err = read_capped(grown, 1024, 1024, Path::new("grew-after-metadata")).unwrap_err();
        assert!(
            matches!(err, SnapshotError::BudgetExceeded(1024)),
            "an over-budget read must be rejected before its bytes are returned for storage, \
             got {err:?}"
        );
    }

    /// A source of exactly `remaining` bytes is in budget: the `+ 1` sentinel is
    /// never reached, so the complete content is returned verbatim for hashing
    /// and storage — the digest of an in-budget file is unchanged by the bound.
    #[test]
    fn a_source_exactly_at_the_budget_is_returned_whole() {
        let content = vec![b'a'; 1024];
        let bytes = read_capped(content.as_slice(), 1024, 1024, Path::new("fits")).unwrap();
        assert_eq!(
            bytes, content,
            "an at-budget file must be read back in full"
        );
    }

    /// One byte past the remaining budget trips the sentinel and is rejected,
    /// even though only `remaining + 1` bytes were ever buffered.
    #[test]
    fn one_byte_over_the_budget_trips_the_sentinel() {
        let content = vec![b'a'; 1025];
        let err = read_capped(content.as_slice(), 1024, 1024, Path::new("over")).unwrap_err();
        assert!(
            matches!(err, SnapshotError::BudgetExceeded(1024)),
            "got {err:?}"
        );
    }

    /// With no budget left, even a single readable byte is over budget.
    #[test]
    fn a_nonempty_source_with_no_remaining_budget_is_rejected() {
        let err = read_capped([0u8].as_slice(), 0, 4096, Path::new("no-room")).unwrap_err();
        assert!(
            matches!(err, SnapshotError::BudgetExceeded(4096)),
            "got {err:?}"
        );
    }
}
