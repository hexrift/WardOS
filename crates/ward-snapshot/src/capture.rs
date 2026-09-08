//! Deterministic capture of a directory tree into a manifest and CAS blobs.

use std::collections::HashMap;
use std::fs;
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
    cas: &'a Cas,
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
            let digest = self.cas.put_blob(bytes)?;
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
            let digest = self.hash_file(&abs, &meta)?;
            self.total_bytes += size;
            if self.total_bytes > self.opts.max_bytes {
                return Err(SnapshotError::BudgetExceeded(self.opts.max_bytes));
            }
            self.push(rel, EntryType::File, mode, size, Some(digest));
        } else if ft.is_fifo() || ft.is_socket() || ft.is_block_device() || ft.is_char_device() {
            self.push(rel, EntryType::Unsupported, mode, 0, None);
        }
        Ok(())
    }

    fn hash_file(&mut self, abs: &Path, meta: &fs::Metadata) -> Result<Digest> {
        if self.opts.incremental {
            let mtime = meta.modified().map_err(|e| SnapshotError::io(abs, e))?;
            let size = meta.len();
            if let Some(&(mt, sz, d)) = self.cache.map.get(abs)
                && mt == mtime
                && sz == size
            {
                self.stats.files_cached += 1;
                return Ok(d);
            }
            let bytes = fs::read(abs).map_err(|e| SnapshotError::io(abs, e))?;
            let d = self.cas.put_blob(&bytes)?;
            self.cache.map.insert(abs.to_path_buf(), (mtime, size, d));
            self.stats.files_hashed += 1;
            self.stats.bytes_hashed += bytes.len() as u64;
            Ok(d)
        } else {
            let bytes = fs::read(abs).map_err(|e| SnapshotError::io(abs, e))?;
            let d = self.cas.put_blob(&bytes)?;
            self.stats.files_hashed += 1;
            self.stats.bytes_hashed += bytes.len() as u64;
            Ok(d)
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
        let branch = reference.rsplit('/').next().map(str::to_string);
        let sha = fs::read_to_string(root.join(".git").join(reference))
            .ok()
            .map(|s| s.trim().to_string());
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
