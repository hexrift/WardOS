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
//!
//! What that thread observes is handed straight to a bounded queue
//! ([`crate::observe::Bounded`]) rather than accumulated until the command exits, so
//! the session can append file observations to the log *while* the agent is still
//! working (#137). The thread never touches the log itself; the session's single
//! writer drains the queue.

use std::collections::HashMap;
use std::io::Write as _;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};

use ward_events::FileChangeKind;

use crate::observe::{Bounded, DEFAULT_CAPACITY, Drained};

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
/// Upper bound on one park in `poll(2)`; the wake pipe ends it early.
const POLL_CAP_MS: u16 = 500;
/// Debounce window: repeats of the same (path, kind) within it are dropped.
const DEBOUNCE: Duration = Duration::from_millis(300);

/// What a finished [`Watcher`] observed *since the last drain*: a watch drained
/// live while the command ran hands over only its tail here, while the verdict
/// fields describe the whole run.
pub struct WatchOutcome {
    /// Captured accesses still queued when the watch stopped, in observed order.
    pub captured: Vec<Captured>,
    /// Whether at least one directory under the worktree could not be (or could
    /// not be re-) registered — a create/move-in raced the watch, a nested
    /// directory disappeared before it could be added, or a permission denied
    /// it. That subtree's future changes are not guaranteed to be captured.
    pub degraded: bool,
    /// Accesses the watch had to refuse since the last drain because its queue was
    /// full; the caller turns these into an explicit overflow marker.
    pub dropped: u64,
}

/// Registered watch descriptors, plus whether registering one of them has
/// ever failed (bundled together so the functions that thread both through
/// the watch loop stay under the lint's argument-count limit).
#[derive(Default)]
struct WatchState {
    wds: HashMap<WatchDescriptor, PathBuf>,
    degraded: bool,
}

/// A running inotify watch over one worktree.
pub struct Watcher {
    stop: Arc<AtomicBool>,
    wake: UnixStream,
    handle: JoinHandle<bool>,
    queue: Arc<Bounded<Captured>>,
}

impl Watcher {
    /// Start watching `worktree`. `watch_reads` adds `IN_ACCESS`/`IN_OPEN` so read
    /// accesses are captured (Live/StepThrough); leave it false in Quiet mode.
    ///
    /// # Errors
    /// [`Errno`] if the inotify instance cannot be created or the root cannot be
    /// watched; the caller should fall back to a directory scan. A nested
    /// directory that cannot be watched does not fail this call: it is instead
    /// reported through [`WatchOutcome::degraded`] once the watch finishes.
    pub fn start(worktree: &Path, watch_reads: bool) -> Result<Self, Errno> {
        Self::start_bounded(worktree, watch_reads, DEFAULT_CAPACITY)
    }

    /// [`Watcher::start`] with an explicit bound on how many observations the watch
    /// may hold between drains. Past it, further observations are refused and
    /// counted into [`WatchOutcome::dropped`] rather than growing the queue without
    /// limit or vanishing unrecorded.
    ///
    /// # Errors
    /// As [`Watcher::start`].
    pub fn start_bounded(
        worktree: &Path,
        watch_reads: bool,
        capacity: usize,
    ) -> Result<Self, Errno> {
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
        let mut state = WatchState::default();
        add_watch_recursive(&inotify, flags, &root, &mut state)?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let (wake, wake_rx) =
            UnixStream::pair().map_err(|e| Errno::from_raw(e.raw_os_error().unwrap_or(0)))?;
        let queue = Arc::new(Bounded::new(capacity));
        let queue_thread = Arc::clone(&queue);
        let handle = std::thread::spawn(move || {
            watch_loop(
                &inotify,
                flags,
                &root,
                state,
                &stop_thread,
                &wake_rx,
                &queue_thread,
            )
        });
        Ok(Self {
            stop,
            wake,
            handle,
            queue,
        })
    }

    /// Everything observed since the last drain, with the count of accesses the
    /// queue had to refuse. Safe to call while the watch is running: this is how
    /// the session streams file observations to the log during a command.
    #[must_use]
    pub fn drain(&self) -> Drained<Captured> {
        self.queue.drain()
    }

    /// How many observations are waiting to be drained.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queue.queued()
    }

    /// Stop watching and return the tail: whatever is still queued, plus the
    /// verdict on the run as a whole.
    #[must_use]
    pub fn finish(mut self) -> WatchOutcome {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.wake.write_all(&[1]);
        let joined = self.handle.join();
        outcome_from_join(joined, self.queue.drain())
    }
}

/// Turn a joined watcher-thread result and its final drain into the outcome to
/// report. A thread that panicked proved nothing about the rest of the tree, so it
/// is reported degraded — never as a healthy run, which `unwrap_or_default` would
/// silently produce — while whatever it had already queued is still handed over
/// rather than thrown away with it.
fn outcome_from_join(joined: std::thread::Result<bool>, tail: Drained<Captured>) -> WatchOutcome {
    WatchOutcome {
        captured: tail.items,
        degraded: joined.unwrap_or(true),
        dropped: tail.dropped,
    }
}

/// The watcher thread body: drain until told to stop, then drain any tail.
/// Between drains it parks in `poll(2)` on the inotify descriptor and the wake
/// pipe, so events and the stop request are both seen at once. Each translated
/// access goes straight into `out`, the bounded queue the session drains while the
/// command is still running; the thread never appends to the log itself. Returns
/// whether the watch lost coverage of any part of the worktree.
fn watch_loop(
    inotify: &Inotify,
    flags: AddWatchFlags,
    root: &Path,
    mut state: WatchState,
    stop: &AtomicBool,
    wake: &UnixStream,
    out: &Bounded<Captured>,
) -> bool {
    let started = Instant::now();
    let mut debouncer = Debouncer::new(DEBOUNCE);
    loop {
        let drained = drain(
            inotify,
            flags,
            root,
            &mut state,
            &mut debouncer,
            started,
            out,
        );
        if stop.load(Ordering::Relaxed) {
            // One final pass catches events queued just before the command exited.
            if !drained {
                break;
            }
        } else if !drained {
            let mut fds = [
                PollFd::new(inotify.as_fd(), PollFlags::POLLIN),
                PollFd::new(wake.as_fd(), PollFlags::POLLIN),
            ];
            if poll(&mut fds, PollTimeout::from(POLL_CAP_MS)).is_err() {
                std::thread::sleep(Duration::from_millis(u64::from(POLL_CAP_MS)));
            }
        }
    }
    state.degraded
}

/// Read and translate one batch of events. Returns whether any were read.
fn drain(
    inotify: &Inotify,
    flags: AddWatchFlags,
    root: &Path,
    state: &mut WatchState,
    debouncer: &mut Debouncer,
    started: Instant,
    out: &Bounded<Captured>,
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
        let Some(dir) = state.wds.get(&ev.wd).cloned() else {
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
        // A directory can become part of the tree either by being created in
        // place or by being moved in from elsewhere; either way its own subtree
        // needs the same recursive registration or its future changes are
        // silently uncaptured.
        let entered = ev
            .mask
            .intersects(AddWatchFlags::IN_CREATE | AddWatchFlags::IN_MOVED_TO);
        if is_dir && entered && add_watch_recursive(inotify, flags, &full, state).is_err() {
            state.degraded = true;
        }
        let Some(rel) = relative(root, &full) else {
            continue;
        };
        if let Some(captured) = translate(ev.mask, rel, debouncer, now, at) {
            // A refusal is counted inside the queue and surfaced by the next
            // drain as an explicit marker; it is never silently lost.
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
/// `dir` itself failing to register is returned to the caller (the top-level
/// call fails the whole watch this way); every other way this can fail to see
/// the whole subtree — `dir` itself cannot be listed, an entry fails mid
/// iteration, a child's type cannot be determined, or a child directory fails
/// to register — sets `state.degraded` and continues with whatever siblings
/// remain, so one unwatchable or unreadable child does not stop the rest from
/// being registered. [`std::fs::read_dir`] documents both of the first two
/// failure modes: <https://doc.rust-lang.org/std/fs/fn.read_dir.html>.
fn add_watch_recursive(
    inotify: &Inotify,
    flags: AddWatchFlags,
    dir: &Path,
    state: &mut WatchState,
) -> Result<(), Errno> {
    let wd = inotify.add_watch(dir, flags)?;
    state.wds.insert(wd, dir.to_path_buf());
    let Ok(entries) = std::fs::read_dir(dir) else {
        state.degraded = true;
        return Ok(());
    };
    for entry in entries {
        let Ok(entry) = entry else {
            state.degraded = true;
            continue;
        };
        let name = entry.file_name();
        if SKIP.contains(&&*name.to_string_lossy()) {
            continue;
        }
        match entry.file_type() {
            Ok(t) if t.is_dir() => {
                if add_watch_recursive(inotify, flags, &entry.path(), state).is_err() {
                    state.degraded = true;
                }
            }
            Ok(_) => {}
            Err(_) => state.degraded = true,
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
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
    fn vanished_directory_failure_is_recorded_not_discarded() {
        let root = tempfile::tempdir().expect("tempdir");
        // A path that never existed always fails `inotify_add_watch` with ENOENT,
        // deterministically and without needing root or a permission trick. This
        // is exactly what `drain` calls into when a directory it just saw
        // `IN_CREATE`/`IN_MOVED_TO` for has already vanished (a fast create+
        // delete, or a second move) by the time it tries to watch it.
        let missing = root.path().join("never-created");
        let inotify =
            Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).expect("inotify init");
        let flags = AddWatchFlags::IN_CREATE | AddWatchFlags::IN_CLOSE_WRITE;
        let mut state = WatchState::default();
        let result = add_watch_recursive(&inotify, flags, &missing, &mut state);
        assert!(result.is_err(), "watching a vanished directory must fail");
        assert!(state.wds.is_empty());
        // `add_watch_recursive`'s own return only reports its own directory; it
        // is the caller (`Watcher::start`'s initial walk, `drain`'s create/move
        // handling) that turns that `Err` into `degraded = true` — exercised by
        // `drain`/`add_watch_recursive`'s `.is_err()` checks, not by this helper
        // itself, so `degraded` is untouched here.
        assert!(!state.degraded);
    }

    #[test]
    fn read_dir_failure_on_a_registered_directory_is_recorded_degraded() {
        // `dir` is a regular *file*, not a directory. `inotify_add_watch` does
        // not require a directory, so the watch on it succeeds — but
        // `std::fs::read_dir` then fails deterministically with ENOTDIR. This
        // is the same shape of failure as a directory that becomes unreadable
        // after it was registered (permission change, filesystem error): the
        // watch itself is fine, but its contents cannot be enumerated.
        let root = tempfile::tempdir().expect("tempdir");
        let file = root.path().join("not-a-directory");
        std::fs::write(&file, b"x").expect("write file");
        let inotify =
            Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).expect("inotify init");
        let flags = AddWatchFlags::IN_CREATE | AddWatchFlags::IN_CLOSE_WRITE;
        let mut state = WatchState::default();

        let result = add_watch_recursive(&inotify, flags, &file, &mut state);

        assert!(
            result.is_ok(),
            "the watch on the file itself still succeeds"
        );
        assert!(
            !state.wds.is_empty(),
            "the file's own watch must still be registered"
        );
        assert!(
            state.degraded,
            "a registered directory whose contents cannot be listed must be reported degraded, not silently treated as fully covered"
        );
    }

    #[test]
    fn a_panicked_watch_thread_is_reported_degraded_not_healthy() {
        let joined = std::thread::spawn(|| -> bool { panic!("simulated watcher crash") }).join();
        assert!(joined.is_err());

        let outcome = outcome_from_join(joined, Drained::default());

        assert!(
            outcome.degraded,
            "a watcher thread that panicked must never be reported as a healthy, empty run"
        );
        assert!(outcome.captured.is_empty());
    }

    /// A watcher thread that panicked still had a queue, and whatever it managed
    /// to put there before dying is real evidence. Reporting the run degraded must
    /// not also throw that away.
    #[test]
    fn a_panicked_watch_thread_still_hands_over_what_it_had_queued() {
        let joined = std::thread::spawn(|| -> bool { panic!("simulated watcher crash") }).join();
        let tail = Drained {
            items: vec![Captured::Modified {
                at: SystemTime::now(),
                rel: "queued-before-the-crash.txt".to_owned(),
                kind: FileChangeKind::Write,
            }],
            dropped: 3,
        };

        let outcome = outcome_from_join(joined, tail);

        assert!(outcome.degraded);
        assert_eq!(outcome.captured.len(), 1);
        assert_eq!(outcome.dropped, 3);
    }

    #[test]
    fn drain_marks_degraded_when_a_moved_in_directory_vanishes_before_it_is_registered() {
        let root = tempfile::tempdir().expect("tempdir");
        let inotify =
            Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).expect("inotify init");
        let flags = AddWatchFlags::IN_CREATE
            | AddWatchFlags::IN_CLOSE_WRITE
            | AddWatchFlags::IN_DELETE
            | AddWatchFlags::IN_MOVED_TO
            | AddWatchFlags::IN_DONT_FOLLOW;
        let mut state = WatchState::default();
        add_watch_recursive(&inotify, flags, root.path(), &mut state).expect("watch root");

        // Move a directory in, then remove it again before `drain` (called
        // directly here, so there is no background thread to race) gets a
        // chance to see the move and register it. By the time `rename` and
        // `remove_dir` return, the kernel has already queued both inotify
        // events on the root watch, so this is deterministic: no sleep, no
        // thread, no window for the watcher to win the race.
        let outside = tempfile::tempdir().expect("tempdir");
        let src = outside.path().join("gone");
        std::fs::create_dir_all(&src).expect("mkdir");
        let dest = root.path().join("gone");
        std::fs::rename(&src, &dest).expect("move dir in");
        std::fs::remove_dir(&dest).expect("remove before drain can watch it");

        let mut debouncer = Debouncer::new(DEBOUNCE);
        let out = Bounded::default();
        let drained = drain(
            &inotify,
            flags,
            root.path(),
            &mut state,
            &mut debouncer,
            Instant::now(),
            &out,
        );

        assert!(drained, "the queued move/delete events must be read");
        assert!(
            state.degraded,
            "a moved-in directory that vanished before drain could register it must be reported degraded"
        );
    }

    #[test]
    fn moved_in_directory_is_watched() {
        let outside = tempfile::tempdir().expect("tempdir");
        let worktree = tempfile::tempdir().expect("tempdir");
        let moved_subdir = outside.path().join("moved");
        std::fs::create_dir_all(&moved_subdir).expect("mkdir");

        let watcher = Watcher::start(worktree.path(), false).expect("watcher start");

        // Move a whole directory tree into the watched worktree.
        let dest = worktree.path().join("moved");
        std::fs::rename(&moved_subdir, &dest).expect("move dir into worktree");
        // Give the watcher thread time to see the move and register the new
        // subtree *before* writing into it — otherwise the write could land
        // before the recursive watch does, which would make this a test of
        // scheduling luck rather than of the moved-in-directory fix.
        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(dest.join("inside.txt"), b"hello").expect("write inside moved dir");
        std::thread::sleep(Duration::from_millis(300));

        let outcome = watcher.finish();
        assert!(
            outcome.captured.iter().any(|c| matches!(
                c,
                Captured::Modified { rel, .. } if rel == "moved/inside.txt"
            )),
            "a write inside a moved-in directory must be captured: {:?}",
            outcome.captured
        );
    }

    /// #137: the watch hands observations over *while* it runs. A write must be
    /// drainable before `finish` is ever called — that is what lets the session
    /// put file activity on the log during a long command instead of only after
    /// it. If `drain` went back to returning nothing until the watch stopped,
    /// this would time out.
    #[test]
    fn a_write_is_drainable_before_the_watch_is_finished() {
        let worktree = tempfile::tempdir().expect("tempdir");
        let watcher = Watcher::start(worktree.path(), false).expect("watcher start");

        std::fs::write(worktree.path().join("live.txt"), b"hello").expect("write");

        let mut seen = Vec::new();
        let live = crate::daemon::wait_until(Duration::from_secs(5), || {
            seen.extend(watcher.drain().items);
            seen.iter()
                .any(|c| matches!(c, Captured::Modified { rel, .. } if rel == "live.txt"))
        });
        assert!(live, "the write must be drainable mid-run, got {seen:?}");

        // And the tail drain does not hand the same observation over a second
        // time: what a live drain took is gone from the queue.
        let outcome = watcher.finish();
        assert!(
            !outcome
                .captured
                .iter()
                .any(|c| matches!(c, Captured::Modified { rel, kind, .. }
                    if rel == "live.txt" && *kind == FileChangeKind::Create)),
            "a live-drained observation must not be handed over again: {:?}",
            outcome.captured
        );
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
