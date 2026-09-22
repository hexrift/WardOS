//! Live observation streaming for one command (#137).
//!
//! The file watch ([`crate::watch`]), the egress proxy's decision recorder
//! ([`crate::egress`]) and the hook broker ([`crate::hooks`]) all run on their own
//! threads while the agent's command runs. Each hands what it sees to the session
//! through a **bounded** queue; the session drains those queues *while the command
//! is still running* and appends what it takes through the same single writer every
//! other record goes through ([`crate::control::Sink`]). Nothing here opens a second
//! writer: producers never touch the log, and the one thread that owns the sink is
//! the one that drains them.
//!
//! Three properties the queues are built for:
//!
//! * **Enforcement is never coupled to ingestion.** [`Bounded::push`] takes a lock,
//!   compares one length and returns. It never blocks on the log, on disk, or on a
//!   UI consumer, so a proxy thread keeps deciding allow/deny in real time however
//!   far behind the drain has fallen (`docs/security-model.md` G14).
//! * **Overflow is recorded, never silent.** A push into a full queue is *refused*
//!   (the queue is never rewritten behind an already-accepted observation) and
//!   counted; the next drain turns the count into an explicit
//!   [`WardEvent::ObservationsDropped`] marker, appended right after the batch it
//!   accompanies.
//! * **Order is preserved across drains.** Each queue is FIFO, and the drain visits
//!   its sources in a fixed order, so no drain can reorder observations relative to
//!   an earlier one. Every observation keeps its own observation time, which is what
//!   the record is stamped with — ingestion time is only when it reached the log.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use ward_events::{ObserverSource, Origin, ProcessRef, SandboxPath, SandboxRoot, WardEvent};

use crate::egress::Egress;
use crate::hooks::Hooks;
use crate::watch::{Captured, WatchOutcome, Watcher};

/// How many observations one source may hold between drains before further ones
/// are refused and counted.
///
/// Sized so a burst no live drain interval can absorb — a `git checkout` of a large
/// tree, a build that rewrites thousands of files — is still carried whole, while a
/// genuinely unbounded producer cannot grow the daemon's memory without limit.
pub const DEFAULT_CAPACITY: usize = 4096;

/// The longest an observation waits in a queue before the drain takes it.
pub const DRAIN_INTERVAL: Duration = Duration::from_millis(250);

/// The drain also runs early once this many observations are queued, so a burst is
/// ingested as a batch instead of waiting out [`DRAIN_INTERVAL`] and risking the
/// bound. Whichever comes first wins.
pub const DRAIN_BATCH: usize = 256;

/// One observation, ready to append: when its source saw it, which trusted source
/// that was, and the record it becomes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// Observation time, as the source recorded it — never the time it reached the log.
    pub at: SystemTime,
    /// Origin the record carries.
    pub origin: Origin,
    /// The record itself.
    pub event: WardEvent,
}

impl Observation {
    /// An observation of `event` made by `origin` at `at`.
    #[must_use]
    pub fn new(at: SystemTime, origin: Origin, event: WardEvent) -> Self {
        Self { at, origin, event }
    }
}

/// What one [`Bounded::drain`] took: the observations, in the order they were
/// offered, and how many were refused since the previous drain.
#[derive(Debug)]
pub struct Drained<T> {
    /// Observations taken, oldest first.
    pub items: Vec<T>,
    /// Observations refused because the queue was full since the last drain.
    pub dropped: u64,
}

impl<T> Default for Drained<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            dropped: 0,
        }
    }
}

/// A bounded FIFO hand-off queue between one observer's thread and the session's
/// single log writer.
///
/// Full means *refused*, not "make room": an observation already accepted is never
/// evicted to admit a newer one, so what the log receives is always a contiguous,
/// correctly ordered prefix of what the source offered between two drains, followed
/// by a marker for the rest.
#[derive(Debug)]
pub struct Bounded<T> {
    items: Mutex<VecDeque<T>>,
    dropped: AtomicU64,
    capacity: usize,
}

impl<T> Bounded<T> {
    /// A queue holding at most `capacity` observations (at least one).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            items: Mutex::new(VecDeque::new()),
            dropped: AtomicU64::new(0),
            capacity: capacity.max(1),
        }
    }

    /// The bound this queue was built with.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Offer one observation. Returns whether it was accepted; a refusal is counted
    /// and surfaced by the next [`drain`](Self::drain), never silently discarded.
    ///
    /// A poisoned lock — a producer that panicked mid-push — counts as a refusal for
    /// the same reason: the observation is gone, and the log must say so.
    pub fn push(&self, item: T) -> bool {
        let Ok(mut items) = self.items.lock() else {
            self.dropped.fetch_add(1, Ordering::SeqCst);
            return false;
        };
        if items.len() >= self.capacity {
            drop(items);
            self.dropped.fetch_add(1, Ordering::SeqCst);
            return false;
        }
        items.push_back(item);
        true
    }

    /// How many observations are waiting right now.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.items.lock().map_or(0, |items| items.len())
    }

    /// Take everything queued, plus the number refused since the previous drain.
    pub fn drain(&self) -> Drained<T> {
        let items = self
            .items
            .lock()
            .map(|mut items| items.drain(..).collect())
            .unwrap_or_default();
        Drained {
            items,
            dropped: self.dropped.swap(0, Ordering::SeqCst),
        }
    }
}

impl<T> Default for Bounded<T> {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

/// The marker that accounts for `dropped` observations `source` could not hand over.
#[must_use]
pub fn overflow_marker(source: ObserverSource, dropped: u64, capacity: usize) -> Observation {
    Observation::new(
        SystemTime::now(),
        // Wardd, not the observed source: this is the daemon's own statement that
        // its ingestion queue overflowed, and it has to be an enforcement fact —
        // an agent-origin claim could not be trusted to say the record is incomplete.
        Origin::Wardd,
        WardEvent::ObservationsDropped {
            source,
            dropped,
            capacity: capacity as u64,
        },
    )
}

/// One captured filesystem access as a log-ready observation, or `None` when the
/// path cannot be represented as a sandbox path (the same paths the batch drain
/// skipped before this was live).
#[must_use]
pub fn file_observation(captured: &Captured, by: &ProcessRef) -> Option<Observation> {
    match captured {
        Captured::Modified { at, rel, kind } => Some(Observation::new(
            *at,
            Origin::Kernel,
            WardEvent::FileModified {
                path: SandboxPath::new(SandboxRoot::Work, rel).ok()?,
                by: by.clone(),
                kind: *kind,
            },
        )),
        Captured::Read { at, rel } => Some(Observation::new(
            *at,
            Origin::Kernel,
            WardEvent::FileRead {
                path: SandboxPath::new(SandboxRoot::Work, rel).ok()?,
                by: by.clone(),
            },
        )),
    }
}

/// A batch of captured filesystem accesses as observations, followed by the
/// overflow marker when the watch had to refuse any.
#[must_use]
pub fn file_batch(
    captured: &[Captured],
    by: &ProcessRef,
    dropped: u64,
    capacity: usize,
) -> Vec<Observation> {
    let mut out: Vec<Observation> = captured
        .iter()
        .filter_map(|c| file_observation(c, by))
        .collect();
    if dropped > 0 {
        out.push(overflow_marker(
            ObserverSource::Filesystem,
            dropped,
            capacity,
        ));
    }
    out
}

/// Decides when the next live drain is due: every [`DRAIN_INTERVAL`], or as soon as
/// [`DRAIN_BATCH`] observations are queued, whichever comes first.
#[derive(Debug)]
pub struct DrainClock {
    last: Instant,
    interval: Duration,
    batch: usize,
}

impl DrainClock {
    /// A clock with the default interval and batch size.
    #[must_use]
    pub fn new() -> Self {
        Self::with(DRAIN_INTERVAL, DRAIN_BATCH)
    }

    /// A clock with an explicit interval and batch size.
    #[must_use]
    pub fn with(interval: Duration, batch: usize) -> Self {
        Self {
            last: Instant::now(),
            interval,
            batch,
        }
    }

    /// Whether a drain is due now, given how many observations are waiting. Returns
    /// true at most once per interval unless the batch size forces an early drain,
    /// and restarts the interval when it does.
    pub fn due(&mut self, queued: usize) -> bool {
        let due = queued >= self.batch || self.last.elapsed() >= self.interval;
        if due {
            self.last = Instant::now();
        }
        due
    }
}

impl Default for DrainClock {
    fn default() -> Self {
        Self::new()
    }
}

/// What the producers still held when the command ended.
pub struct Finished {
    /// The proxy's and the hook broker's remaining observations, with their
    /// overflow markers, in source order.
    pub tail: Vec<Observation>,
    /// The live watch's outcome, when one ran: its own remaining observations,
    /// whether coverage degraded, and how many it had to refuse.
    pub watch: Option<WatchOutcome>,
    /// The capacity each queue was given, for the overflow markers.
    pub capacity: usize,
}

/// The live producers of one launch, owned together so they are always stopped.
///
/// Every producer added to an `Observers` is shut down when the value drops,
/// whatever path the caller leaves the scope by — a sandbox that failed to prepare,
/// a child that failed to spawn, an error on the way to `CommandFinished`. Before
/// this existed, an early `?` between `Watcher::start` and `Watcher::finish` left
/// the watch thread spinning for the life of the process and threw away everything
/// the proxy and the hook broker had already recorded.
///
/// The drop is a safety net for the threads and the run directory only; the caller
/// still calls [`finish`](Self::finish) exactly once to flush the tail, because a
/// `Drop` cannot reach the session's sink.
pub struct Observers {
    watcher: Option<Watcher>,
    egress: Option<Egress>,
    hooks: Option<Hooks>,
    run_dir: Option<PathBuf>,
    capacity: usize,
}

impl Observers {
    /// An empty set over `run_dir`, which is removed when the observers shut down.
    #[must_use]
    pub fn new(run_dir: PathBuf) -> Self {
        Self {
            watcher: None,
            egress: None,
            hooks: None,
            run_dir: Some(run_dir),
            capacity: DEFAULT_CAPACITY,
        }
    }

    /// Start the live file watch over `worktree`, returning whether it started.
    /// A watch that cannot be started is not an error: the caller falls back to a
    /// before/after directory scan, which has no live observations to stream.
    pub fn start_watch(&mut self, worktree: &Path, watch_reads: bool) -> bool {
        self.watcher = Watcher::start_bounded(worktree, watch_reads, self.capacity).ok();
        self.watcher.is_some()
    }

    /// Adopt a started egress proxy.
    pub fn set_egress(&mut self, egress: Egress) {
        self.egress = Some(egress);
    }

    /// Adopt a started hook broker.
    pub fn set_hooks(&mut self, hooks: Hooks) {
        self.hooks = Some(hooks);
    }

    /// The bound each queue was built with.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The egress socket to bind into the sandbox, when a proxy is running.
    #[must_use]
    pub fn egress_socket(&self) -> Option<&Path> {
        self.egress.as_ref().map(Egress::socket)
    }

    /// The hook socket to bind into the sandbox, when a broker is running.
    #[must_use]
    pub fn hook_socket(&self) -> Option<&Path> {
        self.hooks.as_ref().map(Hooks::socket)
    }

    /// How many observations are waiting across every source.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.watcher.as_ref().map_or(0, Watcher::queued)
            + self.egress.as_ref().map_or(0, Egress::queued)
            + self.hooks.as_ref().map_or(0, Hooks::queued)
    }

    /// Take everything the producers have buffered so far, in a fixed source order
    /// (files, then network, then agent claims) so repeated drains never reorder
    /// observations relative to each other.
    ///
    /// Safe to call as often as the caller likes while the command runs; each call
    /// takes only what has arrived since the last one.
    #[must_use]
    pub fn drain(&self, by: &ProcessRef) -> Vec<Observation> {
        let mut out = Vec::new();
        if let Some(watcher) = &self.watcher {
            let drained = watcher.drain();
            out.extend(file_batch(
                &drained.items,
                by,
                drained.dropped,
                self.capacity,
            ));
        }
        if let Some(egress) = &self.egress {
            out.extend(egress.drain_observations(by));
        }
        if let Some(hooks) = &self.hooks {
            out.extend(
                hooks
                    .drain_events()
                    .into_iter()
                    .map(|(at, event)| Observation::new(at, Origin::Agent, event)),
            );
        }
        out
    }

    /// Stop every producer and return what they still held. Call exactly once: the
    /// producers are gone afterwards, so a second call returns nothing and cannot
    /// append a record twice.
    #[must_use]
    pub fn finish(&mut self, by: &ProcessRef) -> Finished {
        // The watch is drained through its own `finish`, which stops the thread and
        // makes a last pass over the inotify queue before handing its tail back.
        let watch = self.watcher.take().map(Watcher::finish);
        let mut tail = Vec::new();
        if let Some(egress) = &self.egress {
            tail.extend(egress.drain_observations(by));
        }
        if let Some(hooks) = &self.hooks {
            tail.extend(
                hooks
                    .drain_events()
                    .into_iter()
                    .map(|(at, event)| Observation::new(at, Origin::Agent, event)),
            );
        }
        self.shutdown();
        Finished {
            tail,
            watch,
            capacity: self.capacity,
        }
    }

    /// Stop whatever is still running and remove the run directory. Idempotent.
    fn shutdown(&mut self) {
        if let Some(watcher) = self.watcher.take() {
            drop(watcher.finish());
        }
        if let Some(egress) = self.egress.take() {
            egress.stop();
        }
        if let Some(hooks) = self.hooks.take() {
            hooks.stop();
        }
        if let Some(dir) = self.run_dir.take() {
            drop(std::fs::remove_dir_all(&dir));
        }
    }
}

impl Drop for Observers {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use ward_events::{FileChangeKind, Pid};

    fn by() -> ProcessRef {
        ProcessRef {
            pid: Pid::new(7).unwrap(),
            comm: None,
        }
    }

    #[test]
    fn a_full_queue_refuses_and_counts_instead_of_losing_silently() {
        let q = Bounded::new(2);
        assert!(q.push(1));
        assert!(q.push(2));
        // Full: the third and fourth are refused, and the two already accepted
        // stay exactly as they were — no eviction, no reordering.
        assert!(!q.push(3));
        assert!(!q.push(4));
        assert_eq!(q.queued(), 2);

        let drained = q.drain();
        assert_eq!(drained.items, vec![1, 2]);
        assert_eq!(drained.dropped, 2, "refusals must be counted, not lost");

        // The counter is per-drain: a second drain of a quiet queue reports none.
        assert!(q.drain().items.is_empty());
        assert_eq!(q.drain().dropped, 0);

        // Draining makes room again.
        assert!(q.push(5));
        assert_eq!(q.drain().items, vec![5]);
    }

    #[test]
    fn a_tiny_queue_turns_its_overflow_into_one_explicit_marker() {
        let q = Bounded::new(1);
        let at = SystemTime::now();
        for rel in ["a.txt", "b.txt", "c.txt"] {
            q.push(Captured::Modified {
                at,
                rel: rel.to_owned(),
                kind: FileChangeKind::Write,
            });
        }
        let drained = q.drain();
        let batch = file_batch(&drained.items, &by(), drained.dropped, q.capacity());

        assert_eq!(batch.len(), 2, "one observation and one marker: {batch:?}");
        assert!(matches!(
            &batch[0].event,
            WardEvent::FileModified { path, .. } if path.to_string().contains("a.txt")
        ));
        assert_eq!(
            batch[1].event,
            WardEvent::ObservationsDropped {
                source: ObserverSource::Filesystem,
                dropped: 2,
                capacity: 1,
            },
            "the two refused writes must be accounted for explicitly"
        );
        // The marker is the daemon's own fact, so it must be an enforcement fact.
        assert_eq!(batch[1].origin, Origin::Wardd);
        assert!(batch[1].origin.is_enforcement_fact());
    }

    #[test]
    fn a_batch_with_no_overflow_carries_no_marker() {
        let q: Bounded<Captured> = Bounded::new(8);
        q.push(Captured::Read {
            at: SystemTime::now(),
            rel: "r.txt".to_owned(),
        });
        let drained = q.drain();
        let batch = file_batch(&drained.items, &by(), drained.dropped, q.capacity());
        assert_eq!(batch.len(), 1);
        assert!(matches!(batch[0].event, WardEvent::FileRead { .. }));
    }

    #[test]
    fn the_queue_keeps_offer_order_across_repeated_drains() {
        let q = Bounded::new(4);
        for i in 0..3 {
            assert!(q.push(i));
        }
        assert_eq!(q.drain().items, vec![0, 1, 2]);
        for i in 3..6 {
            assert!(q.push(i));
        }
        // The second drain continues where the first stopped: no observation is
        // ever handed to the log out of the order its source offered it in.
        assert_eq!(q.drain().items, vec![3, 4, 5]);
    }

    #[test]
    fn the_drain_clock_fires_on_the_batch_before_the_interval() {
        let mut clock = DrainClock::with(Duration::from_secs(3600), 4);
        assert!(!clock.due(0), "an empty queue inside the interval can wait");
        assert!(!clock.due(3));
        assert!(clock.due(4), "a full batch drains without waiting it out");
        // Firing restarts the interval, so the next drain needs another batch.
        assert!(!clock.due(3));
    }

    #[test]
    fn the_drain_clock_fires_on_the_interval_with_nothing_queued() {
        let mut clock = DrainClock::with(Duration::from_millis(0), usize::MAX);
        assert!(clock.due(0));
    }

    #[test]
    fn dropping_observers_removes_the_run_directory() {
        let dir = tempfile::tempdir().unwrap();
        let run_dir = dir.path().join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        {
            let _obs = Observers::new(run_dir.clone());
        }
        assert!(
            !run_dir.exists(),
            "leaving the scope must clean the run directory up"
        );
    }

    #[test]
    fn dropping_observers_stops_a_started_watch() {
        let worktree = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut obs = Observers::new(dir.path().join("run"));
        if !obs.start_watch(worktree.path(), false) {
            // No inotify on this host; the scan fallback has no thread to leak.
            return;
        }
        // The drop must join the watch thread rather than leave it spinning; if it
        // did not, this test would hang here rather than return.
        drop(obs);
    }

    #[test]
    fn finish_hands_the_tail_over_once_and_nothing_afterwards() {
        let worktree = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut obs = Observers::new(dir.path().join("run"));
        if !obs.start_watch(worktree.path(), false) {
            return;
        }
        std::fs::write(worktree.path().join("note.txt"), b"hi").unwrap();
        let first = obs.finish(&by());
        assert!(first.watch.is_some());
        // Everything is stopped: a second finish can only be empty, so no record
        // this command already appended can be appended twice.
        let second = obs.finish(&by());
        assert!(second.tail.is_empty());
        assert!(second.watch.is_none());
    }
}
