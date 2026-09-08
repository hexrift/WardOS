//! Live filesystem capture for a running command.
//!
//! Phase 1's production capture source is `fanotify` from Zone 0 (see
//! `docs/event-model.md` §4); in the in-process dev runtime the daemon uses an
//! inotify recursive watch of the worktree instead. The worktree is bind-mounted
//! into the sandbox's `/work`, so the same inodes are watched from the host and
//! writes made inside the sandbox are observed here.
//!
//! A background thread drains the inotify queue for the lifetime of one command,
//! translating each event into a [`FileChangeKind`] (or a read), debouncing so a
//! single editor save does not produce dozens of rows, and adding watches for new
//! directories as they appear. If inotify cannot be initialised the caller falls
//! back to a before/after directory scan.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use nix::errno::Errno;
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};

use ward_events::FileChangeKind;

/// Which capture source produced a run's file events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureMode {
    /// Live inotify watch of the worktree.
    Inotify,
    /// Before/after directory scan fallback.
    Scan,
}

impl CaptureMode {
    /// A short human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            CaptureMode::Inotify => "inotify",
            CaptureMode::Scan => "scan",
        }
    }
}

/// One observed filesystem access, relative to the worktree root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Captured {
    /// A modification (create, write, delete, rename, chmod).
    Modified {
        /// When it was observed.
        at: SystemTime,
        /// Path relative to the worktree root.
        rel: String,
        /// The kind of change.
        kind: FileChangeKind,
    },
    /// A read (open/access), captured only in Live/StepThrough observer modes.
    Read {
        /// When it was observed.
        at: SystemTime,
        /// Path relative to the worktree root.
        rel: String,
    },
}

impl Captured {
    /// When the access was observed.
    #[must_use]
    pub fn at(&self) -> SystemTime {
        match self {
            Self::Modified { at, .. } | Self::Read { at, .. } => *at,
        }
    }
}

/// Directory names never descended into or reported.
const SKIP: [&str; 3] = [".git", "target", "node_modules"];
/// How often the watcher thread wakes to drain the queue.
const POLL: Duration = Duration::from_millis(40);
/// Debounce window: repeats of the same (path, kind) within it are dropped.
const DEBOUNCE: Duration = Duration::from_millis(300);

/// A running inotify watch over one worktree.
pub struct Watcher {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<Vec<Captured>>,
}

impl Watcher {
    /// Start watching `worktree`. `watch_reads` adds `IN_ACCESS`/`IN_OPEN` so read
    /// accesses are captured (Live/StepThrough); leave it false in Quiet mode.
    ///
    /// # Errors
    /// [`Errno`] if the inotify instance cannot be created or the root cannot be
    /// watched; the caller should fall back to a directory scan.
    pub fn start(worktree: &Path, watch_reads: bool) -> Result<Self, Errno> {
        let inotify = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)?;
        let mut flags = AddWatchFlags::IN_CREATE
            | AddWatchFlags::IN_CLOSE_WRITE
            | AddWatchFlags::IN_DELETE
            | AddWatchFlags::IN_DELETE_SELF
            | AddWatchFlags::IN_MOVED_FROM
            | AddWatchFlags::IN_MOVED_TO
            | AddWatchFlags::IN_MOVE_SELF
            | AddWatchFlags::IN_ATTRIB
            | AddWatchFlags::IN_DONT_FOLLOW;
        if watch_reads {
            flags |= AddWatchFlags::IN_ACCESS | AddWatchFlags::IN_OPEN;
        }

        let root = worktree.to_path_buf();
        let mut wds: HashMap<WatchDescriptor, PathBuf> = HashMap::new();
        add_watch_recursive(&inotify, flags, &root, &mut wds)?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let handle =
            std::thread::spawn(move || watch_loop(&inotify, flags, &root, &mut wds, &stop_thread));
        Ok(Self { stop, handle })
    }

    /// Stop watching and return the captured events in observed order.
    #[must_use]
    pub fn finish(self) -> Vec<Captured> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().unwrap_or_default()
    }
}

/// The watcher thread body: drain until told to stop, then drain any tail.
fn watch_loop(
    inotify: &Inotify,
    flags: AddWatchFlags,
    root: &Path,
    wds: &mut HashMap<WatchDescriptor, PathBuf>,
    stop: &AtomicBool,
) -> Vec<Captured> {
    let started = Instant::now();
    let mut debouncer = Debouncer::new(DEBOUNCE);
    let mut out = Vec::new();
    loop {
        let drained = drain(inotify, flags, root, wds, &mut debouncer, started, &mut out);
        if stop.load(Ordering::Relaxed) {
            // One final pass catches events queued just before the command exited.
            if !drained {
                break;
            }
        } else if !drained {
            std::thread::sleep(POLL);
        }
    }
    out
}

/// Read and translate one batch of events. Returns whether any were read.
fn drain(
    inotify: &Inotify,
    flags: AddWatchFlags,
    root: &Path,
    wds: &mut HashMap<WatchDescriptor, PathBuf>,
    debouncer: &mut Debouncer,
    started: Instant,
    out: &mut Vec<Captured>,
) -> bool {
    // EAGAIN = queue empty (nonblocking); any other error just means nothing to
    // report this pass, so treat every error as "no events".
    let Ok(events) = inotify.read_events() else {
        return false;
    };
    if events.is_empty() {
        return false;
    }
    let now = started.elapsed();
    let at = SystemTime::now();
    for ev in events {
        let Some(dir) = wds.get(&ev.wd).cloned() else {
            continue;
        };
        let Some(name) = ev.name.as_deref() else {
            continue;
        };
        if SKIP.contains(&&*name.to_string_lossy()) {
            continue;
        }
        let full = dir.join(name);
        let is_dir = ev.mask.contains(AddWatchFlags::IN_ISDIR);
        if is_dir && ev.mask.contains(AddWatchFlags::IN_CREATE) {
            let _ = add_watch_recursive(inotify, flags, &full, wds);
        }
        let Some(rel) = relative(root, &full) else {
            continue;
        };
        if let Some(captured) = translate(ev.mask, rel, debouncer, now, at) {
            out.push(captured);
        }
    }
    true
}

/// Map an inotify mask to a captured event, applying debounce.
fn translate(
    mask: AddWatchFlags,
    rel: String,
    debouncer: &mut Debouncer,
    now: Duration,
    at: SystemTime,
) -> Option<Captured> {
    if let Some(kind) = change_kind(mask) {
        if debouncer.allow(&rel, Some(kind), now) {
            return Some(Captured::Modified { at, rel, kind });
        }
        return None;
    }
    if mask.intersects(AddWatchFlags::IN_ACCESS | AddWatchFlags::IN_OPEN)
        && debouncer.allow(&rel, None, now)
    {
        return Some(Captured::Read { at, rel });
    }
    None
}

/// Pure mask → [`FileChangeKind`] mapping (modifications only; `None` for reads).
#[must_use]
pub fn change_kind(mask: AddWatchFlags) -> Option<FileChangeKind> {
    if mask.contains(AddWatchFlags::IN_CREATE) {
        return Some(FileChangeKind::Create);
    }
    if mask.contains(AddWatchFlags::IN_CLOSE_WRITE) {
        return Some(FileChangeKind::Write);
    }
    if mask.intersects(AddWatchFlags::IN_DELETE | AddWatchFlags::IN_DELETE_SELF) {
        return Some(FileChangeKind::Delete);
    }
    if mask.intersects(
        AddWatchFlags::IN_MOVED_FROM | AddWatchFlags::IN_MOVED_TO | AddWatchFlags::IN_MOVE_SELF,
    ) {
        return Some(FileChangeKind::Rename);
    }
    if mask.contains(AddWatchFlags::IN_ATTRIB) {
        return Some(FileChangeKind::Chmod);
    }
    None
}

/// Add a watch for `dir` and, recursively, its non-skipped subdirectories.
fn add_watch_recursive(
    inotify: &Inotify,
    flags: AddWatchFlags,
    dir: &Path,
    wds: &mut HashMap<WatchDescriptor, PathBuf>,
) -> Result<(), Errno> {
    let wd = inotify.add_watch(dir, flags)?;
    wds.insert(wd, dir.to_path_buf());
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if SKIP.contains(&&*name.to_string_lossy()) {
                continue;
            }
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                let _ = add_watch_recursive(inotify, flags, &entry.path(), wds);
            }
        }
    }
    Ok(())
}

/// The worktree-relative path of `full`, or `None` if it escapes the root.
fn relative(root: &Path, full: &Path) -> Option<String> {
    let rel = full.strip_prefix(root).ok()?;
    let text = rel.to_string_lossy().into_owned();
    if text.is_empty() { None } else { Some(text) }
}

/// Suppresses repeats of the same (path, kind) within a time window. A `None`
/// kind marks a read access.
struct Debouncer {
    window: Duration,
    last: HashMap<(String, Option<FileChangeKind>), Duration>,
}

impl Debouncer {
    fn new(window: Duration) -> Self {
        Self {
            window,
            last: HashMap::new(),
        }
    }

    /// Whether an event should be emitted now, recording it if so.
    fn allow(&mut self, rel: &str, kind: Option<FileChangeKind>, now: Duration) -> bool {
        let key = (rel.to_owned(), kind);
        match self.last.get(&key) {
            Some(&prev) if now.saturating_sub(prev) < self.window => false,
            _ => {
                self.last.insert(key, now);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_masks_to_change_kinds() {
        assert_eq!(
            change_kind(AddWatchFlags::IN_CREATE),
            Some(FileChangeKind::Create)
        );
        assert_eq!(
            change_kind(AddWatchFlags::IN_CLOSE_WRITE),
            Some(FileChangeKind::Write)
        );
        assert_eq!(
            change_kind(AddWatchFlags::IN_DELETE),
            Some(FileChangeKind::Delete)
        );
        assert_eq!(
            change_kind(AddWatchFlags::IN_MOVED_TO),
            Some(FileChangeKind::Rename)
        );
        assert_eq!(
            change_kind(AddWatchFlags::IN_MOVED_FROM),
            Some(FileChangeKind::Rename)
        );
        assert_eq!(
            change_kind(AddWatchFlags::IN_ATTRIB),
            Some(FileChangeKind::Chmod)
        );
        // Pure read masks are not modifications.
        assert_eq!(change_kind(AddWatchFlags::IN_OPEN), None);
        assert_eq!(change_kind(AddWatchFlags::IN_ACCESS), None);
    }

    #[test]
    fn create_wins_over_close_write_in_one_mask() {
        let mask = AddWatchFlags::IN_CREATE | AddWatchFlags::IN_CLOSE_WRITE;
        assert_eq!(change_kind(mask), Some(FileChangeKind::Create));
    }

    #[test]
    fn debounce_collapses_repeats_but_allows_after_window() {
        let mut d = Debouncer::new(Duration::from_millis(300));
        let k = Some(FileChangeKind::Write);
        assert!(d.allow("a.txt", k, Duration::from_millis(0)));
        // Same path+kind inside the window: dropped.
        assert!(!d.allow("a.txt", k, Duration::from_millis(100)));
        assert!(!d.allow("a.txt", k, Duration::from_millis(299)));
        // After the window: allowed again.
        assert!(d.allow("a.txt", k, Duration::from_millis(400)));
    }

    #[test]
    fn debounce_distinguishes_path_and_kind() {
        let mut d = Debouncer::new(Duration::from_millis(300));
        let now = Duration::from_millis(0);
        assert!(d.allow("a.txt", Some(FileChangeKind::Create), now));
        // Different kind on the same path is a distinct key.
        assert!(d.allow("a.txt", Some(FileChangeKind::Write), now));
        // Different path is a distinct key.
        assert!(d.allow("b.txt", Some(FileChangeKind::Write), now));
        // A read on a.txt is distinct from any modification.
        assert!(d.allow("a.txt", None, now));
    }

    #[test]
    fn translate_gates_reads_and_debounces() {
        let mut d = Debouncer::new(Duration::from_millis(300));
        let now = Duration::from_millis(0);
        let at = SystemTime::now();
        let read = translate(AddWatchFlags::IN_OPEN, "r.txt".into(), &mut d, now, at);
        assert_eq!(
            read,
            Some(Captured::Read {
                at,
                rel: "r.txt".into()
            })
        );
        // Repeat read inside window is dropped.
        assert_eq!(
            translate(AddWatchFlags::IN_ACCESS, "r.txt".into(), &mut d, now, at),
            None
        );
    }
}
