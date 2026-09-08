//! The frozen-copy capture engine: worktree → [`Manifest`].
//!
//! ```text
//!  walk (parallel, one filesystem, symlinks not followed, limits enforced)
//!    │   .gitignore honoured via the `ignore` crate unless include_ignored
//!    │   .git/ walked separately with `walkdir` when include_git_dir (never ignored)
//!    ▼
//!  hash (rayon; BLAKE3; TreeCache lookups by (dev, ino, size, mtime, ctime))
//!    ▼
//!  Manifest::from_entries (bytewise sort, duplicate check)
//! ```
//!
//! The engine assumes the tree is **quiescent**. [`Capture::run`] does not freeze
//! anything; [`capture_with_freezer`] wraps a run in a [`Freezer`] so `wardd` can freeze
//! the session cgroup around it. On the Btrfs path `wardd` snapshots the subvolume, thaws
//! immediately, and runs [`Capture::run`] on the read-only snapshot with a
//! [`NoopFreezer`](crate::freezer::NoopFreezer).

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::cache::{CacheRecord, FileIdentity, TreeCache};
use crate::error::{Error, Limit, Result};
use crate::freezer::Freezer;
use crate::hash::ContentHash;
use crate::manifest::{Entry, EntryKind, MODE_MASK, Manifest};
use crate::path::RelPath;

/// Capture policy (`docs/snapshots-and-git.md` §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturePolicy {
    /// Include files matched by `.gitignore` / `.git/info/exclude`. Default `false`.
    pub include_ignored: bool,
    /// Include the `.git` directory (or file). Default `true`. When set, `.git` is
    /// captured even if an ignore rule matches it.
    pub include_git_dir: bool,
    /// Abort with [`Error::LimitExceeded`] once the sum of regular-file sizes exceeds
    /// this. Default 2 GiB.
    pub max_bytes: u64,
    /// Abort with [`Error::LimitExceeded`] once more than this many entries are seen.
    /// Default 1,000,000.
    pub max_entries: u64,
}

impl Default for CapturePolicy {
    fn default() -> Self {
        CapturePolicy {
            include_ignored: false,
            include_git_dir: true,
            max_bytes: 2 * 1024 * 1024 * 1024,
            max_entries: 1_000_000,
        }
    }
}

/// Counters and timings from one capture.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CaptureStats {
    /// Total entries in the manifest.
    pub entries: u64,
    /// Regular files.
    pub files: u64,
    /// Directories.
    pub dirs: u64,
    /// Symlinks.
    pub symlinks: u64,
    /// FIFOs, sockets, devices (recorded by name only).
    pub unsupported: u64,
    /// Sum of regular-file sizes in the manifest.
    pub bytes_total: u64,
    /// Bytes actually read and hashed (excludes cache hits).
    pub bytes_hashed: u64,
    /// Files whose hash came from the cache.
    pub cache_hits: u64,
    /// Files that had to be hashed.
    pub cache_misses: u64,
    /// Entries skipped because they live on another filesystem (bind mounts inside the
    /// tree). Never silent: `wardd` decides whether to fail the capture.
    pub skipped_foreign_fs: Vec<RelPath>,
    /// Time spent walking (stat, ignore matching).
    pub walk_duration: Duration,
    /// Time spent hashing.
    pub hash_duration: Duration,
    /// Time between `freeze()` returning and `thaw()` being called, when a freezer was
    /// used (the agent-visible stall on the frozen-copy path).
    pub frozen_for: Option<Duration>,
}

/// One item found by the walk, before hashing.
struct WalkItem {
    path: RelPath,
    abs: PathBuf,
    kind: EntryKind,
    mode: u32,
    identity: FileIdentity,
    symlink_target: Option<Vec<u8>>,
}

/// The capture engine. Stateless; see the module docs.
#[derive(Debug, Clone, Copy, Default)]
pub struct Capture;

impl Capture {
    /// Capture `root` into a manifest, assuming the tree is quiescent.
    ///
    /// `cache`, when given, is consulted for every regular file and then replaced with
    /// records for exactly the files seen in this capture.
    ///
    /// # Errors
    /// [`Error::LimitExceeded`] when the policy limits are crossed (nothing is
    /// truncated); [`Error::Io`]/[`Error::Walk`] for unreadable entries; other variants
    /// for a tree that changed underneath the capture.
    pub fn run(
        root: &Path,
        policy: &CapturePolicy,
        cache: Option<&mut TreeCache>,
    ) -> Result<Manifest> {
        Self::run_with_stats(root, policy, cache).map(|(m, _)| m)
    }

    /// Like [`Capture::run`], also returning [`CaptureStats`].
    ///
    /// # Errors
    /// See [`Capture::run`].
    pub fn run_with_stats(
        root: &Path,
        policy: &CapturePolicy,
        cache: Option<&mut TreeCache>,
    ) -> Result<(Manifest, CaptureStats)> {
        let mut stats = CaptureStats::default();
        let t0 = Instant::now();
        let items = walk(root, policy, &mut stats)?;
        stats.walk_duration = t0.elapsed();

        let t1 = Instant::now();
        let read_cache: Option<&TreeCache> = cache.as_deref();
        let hits = AtomicU64::new(0);
        let misses = AtomicU64::new(0);
        let hashed = AtomicU64::new(0);
        let results: Vec<(Entry, Option<CacheRecord>)> = items
            .par_iter()
            .map(|item| hash_item(item, read_cache, &hits, &misses, &hashed))
            .collect::<Result<Vec<_>>>()?;
        stats.hash_duration = t1.elapsed();
        stats.cache_hits = hits.into_inner();
        stats.cache_misses = misses.into_inner();
        stats.bytes_hashed = hashed.into_inner();

        if let Some(cache) = cache {
            let records = results
                .iter()
                .filter_map(|(e, rec)| rec.map(|r| (e.path.as_bytes().to_vec(), r)))
                .collect();
            cache.replace(records);
        }

        let entries: Vec<Entry> = results.into_iter().map(|(e, _)| e).collect();
        for e in &entries {
            match e.kind {
                EntryKind::File => {
                    stats.files += 1;
                    stats.bytes_total += e.size;
                }
                EntryKind::Dir => stats.dirs += 1,
                EntryKind::Symlink => stats.symlinks += 1,
                EntryKind::Unsupported => stats.unsupported += 1,
            }
        }
        stats.entries = entries.len() as u64;
        let manifest = Manifest::from_entries(entries)?;
        Ok((manifest, stats))
    }
}

/// Freeze, capture, thaw. The thaw always runs once the freeze succeeded, even when the
/// capture fails; a thaw failure is reported only if the capture itself succeeded.
///
/// # Errors
/// The freezer's error if freezing fails (no capture is attempted); otherwise as
/// [`Capture::run`].
pub fn capture_with_freezer(
    root: &Path,
    policy: &CapturePolicy,
    cache: Option<&mut TreeCache>,
    freezer: &dyn Freezer,
) -> Result<(Manifest, CaptureStats)> {
    freezer.freeze()?;
    let frozen_at = Instant::now();
    let outcome = Capture::run_with_stats(root, policy, cache);
    let frozen_for = frozen_at.elapsed();
    let thawed = freezer.thaw();
    let (manifest, mut stats) = outcome?;
    thawed?;
    stats.frozen_for = Some(frozen_for);
    Ok((manifest, stats))
}

fn hash_item(
    item: &WalkItem,
    cache: Option<&TreeCache>,
    hits: &AtomicU64,
    misses: &AtomicU64,
    hashed: &AtomicU64,
) -> Result<(Entry, Option<CacheRecord>)> {
    match item.kind {
        EntryKind::Dir => Ok((Entry::dir(item.path.clone(), item.mode), None)),
        EntryKind::Unsupported => Ok((Entry::unsupported(item.path.clone(), item.mode), None)),
        EntryKind::Symlink => {
            let target = item.symlink_target.as_deref().unwrap_or_default();
            Ok((Entry::symlink(item.path.clone(), target), None))
        }
        EntryKind::File => {
            if let Some(hash) = cache.and_then(|c| c.lookup(&item.path, &item.identity)) {
                hits.fetch_add(1, Ordering::Relaxed);
                let entry = Entry::file(item.path.clone(), item.mode, item.identity.size, hash);
                return Ok((
                    entry,
                    Some(CacheRecord {
                        identity: item.identity,
                        hash,
                    }),
                ));
            }
            misses.fetch_add(1, Ordering::Relaxed);
            let (hash, size) = ContentHash::of_file(&item.abs)?;
            hashed.fetch_add(size, Ordering::Relaxed);
            let mut identity = item.identity;
            identity.size = size;
            let entry = Entry::file(item.path.clone(), item.mode, size, hash);
            Ok((entry, Some(CacheRecord { identity, hash })))
        }
    }
}

/// Shared state of one walk: the main tree is walked by the `ignore` crate's parallel
/// walker (one thread per core), the `.git` subtree by `walkdir`; both feed `push`.
struct Walker<'a> {
    root: &'a Path,
    root_dev: u64,
    policy: &'a CapturePolicy,
    entries: AtomicU64,
    bytes: AtomicU64,
    items: Mutex<Vec<WalkItem>>,
    foreign: Mutex<Vec<RelPath>>,
    error: Mutex<Option<Error>>,
}

fn walk(root: &Path, policy: &CapturePolicy, stats: &mut CaptureStats) -> Result<Vec<WalkItem>> {
    let root_meta = std::fs::symlink_metadata(root).map_err(|e| Error::io("stat", root, e))?;
    if !root_meta.is_dir() {
        return Err(Error::io(
            "stat",
            root,
            std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "capture root is not a directory",
            ),
        ));
    }
    let walker = Walker {
        root,
        root_dev: root_meta.dev(),
        policy,
        entries: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
        items: Mutex::new(Vec::new()),
        foreign: Mutex::new(Vec::new()),
        error: Mutex::new(None),
    };
    walker.walk_main()?;
    if policy.include_git_dir && !policy.include_ignored {
        walker.walk_git_dir()?;
    }
    let Walker { items, foreign, .. } = walker;
    stats.skipped_foreign_fs = foreign.into_inner().unwrap_or_default();
    Ok(items.into_inner().unwrap_or_default())
}

impl Walker<'_> {
    /// Walk the root in parallel. With `include_ignored` the ignore rules are switched
    /// off; otherwise nested `.gitignore` and `.git/info/exclude` are honoured (`.ignore`
    /// files, global and parent ignores are not, for reproducibility across hosts). The
    /// top-level `.git` is skipped unless it is to be captured *without* ignore rules,
    /// which `walk_git_dir` does separately.
    fn walk_main(&self) -> Result<()> {
        let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
        let use_ignore = !self.policy.include_ignored;
        let skip_git = use_ignore || !self.policy.include_git_dir;
        let mut builder = ignore::WalkBuilder::new(self.root);
        builder
            .follow_links(false)
            .same_file_system(true)
            .hidden(false)
            .parents(false)
            .ignore(false)
            .git_global(false)
            .git_ignore(use_ignore)
            .git_exclude(use_ignore)
            .require_git(false)
            .threads(threads)
            .filter_entry(move |e| !(skip_git && is_root_git(e.depth(), e.file_name())));
        builder.build_parallel().run(|| {
            Box::new(|entry| match entry {
                Ok(entry) if entry.depth() == 0 => ignore::WalkState::Continue,
                Ok(entry) => {
                    let meta = match std::fs::symlink_metadata(entry.path()) {
                        Ok(m) => m,
                        Err(e) => return self.fail(Error::io("stat", entry.path(), e)),
                    };
                    match self.push(entry.path(), &meta) {
                        Ok(()) => ignore::WalkState::Continue,
                        Err(e) => self.fail(e),
                    }
                }
                Err(e) => self.fail(Error::Walk(e.to_string())),
            })
        });
        self.take_error()
    }

    /// Capture `<root>/.git` (directory or linked-worktree file) with `walkdir`, no
    /// ignore rules applied.
    fn walk_git_dir(&self) -> Result<()> {
        let git = self.root.join(".git");
        let Ok(git_meta) = std::fs::symlink_metadata(&git) else {
            return Ok(());
        };
        if !git_meta.is_dir() {
            return self.push(&git, &git_meta);
        }
        let walker = walkdir::WalkDir::new(&git)
            .follow_links(false)
            .same_file_system(true);
        for entry in walker {
            let entry = entry.map_err(|e| Error::Walk(e.to_string()))?;
            let meta = entry.metadata().map_err(|e| Error::Walk(e.to_string()))?;
            self.push(entry.path(), &meta)?;
        }
        Ok(())
    }

    fn fail(&self, e: Error) -> ignore::WalkState {
        if let Ok(mut slot) = self.error.lock()
            && slot.is_none()
        {
            *slot = Some(e);
        }
        ignore::WalkState::Quit
    }

    fn take_error(&self) -> Result<()> {
        match self.error.lock() {
            Ok(mut slot) => slot.take().map_or(Ok(()), Err),
            Err(_) => Err(Error::Walk("walker state poisoned".into())),
        }
    }

    fn account(&self, item: &WalkItem) -> Result<()> {
        let entries = self.entries.fetch_add(1, Ordering::Relaxed) + 1;
        if entries > self.policy.max_entries {
            return Err(Error::LimitExceeded {
                limit: Limit::Entries,
                value: self.policy.max_entries,
                path: item.path.as_bytes().to_vec(),
            });
        }
        if item.kind == EntryKind::File {
            let bytes = self
                .bytes
                .fetch_add(item.identity.size, Ordering::Relaxed)
                .saturating_add(item.identity.size);
            if bytes > self.policy.max_bytes {
                return Err(Error::LimitExceeded {
                    limit: Limit::Bytes,
                    value: self.policy.max_bytes,
                    path: item.path.as_bytes().to_vec(),
                });
            }
        }
        Ok(())
    }

    fn push(&self, abs: &Path, meta: &std::fs::Metadata) -> Result<()> {
        let rel = abs.strip_prefix(self.root).map_err(|_| {
            Error::Walk(format!(
                "{} is not under {}",
                abs.display(),
                self.root.display()
            ))
        })?;
        let path = RelPath::from_path(rel)?;
        if meta.dev() != self.root_dev {
            if let Ok(mut foreign) = self.foreign.lock() {
                foreign.push(path);
            }
            return Ok(());
        }
        let ft = meta.file_type();
        let kind = if ft.is_symlink() {
            EntryKind::Symlink
        } else if ft.is_dir() {
            EntryKind::Dir
        } else if ft.is_file() {
            EntryKind::File
        } else {
            EntryKind::Unsupported
        };
        let symlink_target = if kind == EntryKind::Symlink {
            use std::os::unix::ffi::OsStrExt;
            let target = std::fs::read_link(abs).map_err(|e| Error::io("readlink", abs, e))?;
            Some(target.as_os_str().as_bytes().to_vec())
        } else {
            None
        };
        let item = WalkItem {
            path,
            abs: abs.to_path_buf(),
            kind,
            mode: meta.mode() & MODE_MASK,
            identity: FileIdentity::from_metadata(meta),
            symlink_target,
        };
        self.account(&item)?;
        if let Ok(mut items) = self.items.lock() {
            items.push(item);
        }
        Ok(())
    }
}

fn is_root_git(depth: usize, name: &std::ffi::OsStr) -> bool {
    depth == 1 && name == ".git"
}
