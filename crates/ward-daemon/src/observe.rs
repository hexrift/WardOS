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
//!   counted *under the same lock*; the next drain takes the observations and the
//!   refusals together and turns the count into an explicit
//!   [`WardEvent::ObservationsDropped`] marker, appended right after the batch it
//!   accompanies. Because the two are one atomic epoch, a refusal can never be
//!   split across two markers, attached to a batch it did not accompany, or lost to
//!   a drain that reset the count between the refusal and its being recorded. Every
//!   bounded source has its own [`ObserverSource`], the hook broker included, so no
//!   gap is reported as something an observer mode may hide.
//! * **Order is preserved across drains.** Each queue is FIFO, and the drain visits
//!   its sources in a fixed order, so no drain can reorder observations relative to
//!   an earlier one. Every observation keeps its own observation time, which is what
//!   the record is stamped with — ingestion time is only when it reached the log.
//! * **The last drain is a cutover, not a race.** [`Observers::finish`] quiesces
//!   each producer — stops it accepting new work and waits, for a bounded time, for
//!   what it already had in flight — *before* draining that producer for the last
//!   time, so a decision or claim completed across the cutover is flushed rather
//!   than discarded with the producer. A producer still busy when the bound runs out
//!   is counted and marked like any other gap. Giving up is itself a single atomic
//!   step ([`Bounded::seal`]) taken under the queue's own lock, the same lock a
//!   producer must take to hand its observation over, so each in-flight producer is
//!   classified exactly once — accepted into the final batch, or counted in the gap
//!   marker, never both. The egress proxy and the hook broker close their cutovers
//!   with that one primitive rather than each sampling a count of their own.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
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

/// The longest the terminal flush waits for one producer to go quiet before it
/// drains that producer for the last time.
///
/// The wait is what makes the final drain a *cutover* rather than a race: the
/// producer is first stopped from accepting new work, then given this long to
/// finish what it already had in flight, and only then drained. It is bounded
/// because a handler wedged on something that never returns must not be able to
/// wedge the daemon's shutdown with it; a producer still busy when it runs out is
/// a real gap in the record, and is counted and marked exactly as an overflow is.
///
/// It applies to each producer separately, so the flush is bounded by this times
/// the number of producers, not by anything a producer can choose. In practice
/// nothing waits at all: the child is gone by the time the flush runs, so the
/// proxy's connections and the broker's handlers have already finished.
pub const QUIESCE_TIMEOUT: Duration = Duration::from_secs(2);

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
///
/// The queued observations and the count of refusals live behind **one** lock, so
/// each `push` and each `drain` is a single atomic epoch: a refusal is either
/// wholly inside the batch the next drain takes or wholly inside the one after,
/// never split between them, attached to a batch it did not accompany, or lost
/// because a drain reset the count after the refusal decided but before it was
/// recorded. That is what lets the marker's documented contract — "immediately
/// follows and bounds the batch it accompanies" — actually hold.
///
/// # The terminal cutover
///
/// The same lock also holds the producers still **in flight** and whether the
/// queue has been **sealed**, which is what makes the terminal cutover a single
/// decision rather than two racing ones. A producer that can be tracked joins the
/// in-flight set with [`enter`](Self::enter) and leaves it by
/// [`commit`](Self::commit)ting its observation — leaving and offering in *one*
/// lock acquisition — or by [`leave`](Self::leave) when it has nothing to offer.
/// [`seal`](Self::seal) closes the cutover: in one acquisition it flips `sealed`
/// and counts whatever is still in flight as a gap.
///
/// So for every producer exactly one of two things happens, decided by whichever
/// of the two reaches the lock first and never precomputed from a sampled count:
///
/// * it commits before the seal — its observation is in the batch the final drain
///   takes, and the seal no longer sees it in flight, so nothing counts it; or
/// * the seal gets there first — the producer is counted once, there and then,
///   and its later `commit` finds the queue sealed and adds nothing, because the
///   loss it would report has already been reported for it.
///
/// A producer that was never in the in-flight set is not counted by the seal, so
/// its own late [`push`](Self::push) is refused and counted at that point instead.
/// Either way an observation is accepted into the final batch or counted in the
/// gap marker, exactly once, never both.
#[derive(Debug)]
pub struct Bounded<T> {
    queue: Mutex<Queue<T>>,
    /// Woken when the last in-flight producer leaves the set.
    idle: Condvar,
    capacity: usize,
}

/// The one piece of state a [`Bounded`] guards: the observations and the refusals
/// that belong to the same drain epoch, the producers still in flight, and whether
/// the terminal cutover has sealed.
#[derive(Debug)]
struct Queue<T> {
    items: VecDeque<T>,
    dropped: u64,
    in_flight: usize,
    sealed: bool,
}

impl<T> Bounded<T> {
    /// A queue holding at most `capacity` observations (at least one).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(Queue {
                items: VecDeque::new(),
                dropped: 0,
                in_flight: 0,
                sealed: false,
            }),
            idle: Condvar::new(),
            capacity: capacity.max(1),
        }
    }

    /// The bound this queue was built with.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The guarded state. A producer that panicked mid-push poisons the lock but
    /// cannot corrupt what it guards — a `VecDeque` and a counter — and dropping the
    /// queue on the floor would lose observations already accepted, so the guard is
    /// recovered and the queue keeps working.
    fn locked(&self) -> MutexGuard<'_, Queue<T>> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Offer one observation from a producer that is **not** tracked in the
    /// in-flight set. Returns whether it was accepted; a refusal is counted under
    /// the same lock that saw the queue full — or saw it sealed — so the next
    /// [`drain`](Self::drain) that takes the batch takes the refusal with it.
    ///
    /// An offer made after the cutover [`seal`](Self::seal)ed is refused and
    /// counted here: the seal counted the producers it could see in flight, and
    /// this one was not among them, so this is the only place its loss is
    /// reported.
    pub fn push(&self, item: T) -> bool {
        let mut queue = self.locked();
        if queue.sealed || queue.items.len() >= self.capacity {
            queue.dropped = queue.dropped.saturating_add(1);
            return false;
        }
        queue.items.push_back(item);
        true
    }

    /// Join the in-flight set, unless `max` producers are already in it or the
    /// cutover has sealed. Returns whether the slot was taken; a caller refused
    /// here has produced nothing the seal will account for, so it reports its own
    /// loss with [`record_dropped`](Self::record_dropped).
    pub fn enter(&self, max: usize) -> bool {
        let mut queue = self.locked();
        if queue.sealed || queue.in_flight >= max {
            return false;
        }
        queue.in_flight += 1;
        true
    }

    /// Leave the in-flight set with nothing to offer — a producer that reached no
    /// observation at all. If the cutover has already sealed, this producer was
    /// counted as a gap there; that is deliberate, and it is what "a producer that
    /// could not be quiesced is itself recorded as a gap" means.
    pub fn leave(&self) {
        let mut queue = self.locked();
        self.depart(&mut queue);
    }

    /// Leave the in-flight set **and** offer this producer's observation, in one
    /// lock acquisition. Returns whether the observation was accepted.
    ///
    /// Doing both under one lock is what makes the cutover exact: the observation
    /// cannot land in the batch after a [`seal`](Self::seal) has already written
    /// this producer off, and the seal cannot write it off after the observation
    /// has been accepted. A sealed queue refuses the observation and counts
    /// *nothing* — the seal counted this producer already, and counting it twice
    /// is what turned one loss into a false gap beside its own observation.
    pub fn commit(&self, item: T) -> bool {
        let mut queue = self.locked();
        self.depart(&mut queue);
        if queue.sealed {
            return false;
        }
        if queue.items.len() >= self.capacity {
            queue.dropped = queue.dropped.saturating_add(1);
            return false;
        }
        queue.items.push_back(item);
        true
    }

    /// Drop one producer from the in-flight set, waking [`wait_idle`](Self::wait_idle)
    /// when it was the last.
    fn depart(&self, queue: &mut Queue<T>) {
        queue.in_flight = queue.in_flight.saturating_sub(1);
        if queue.in_flight == 0 {
            self.idle.notify_all();
        }
    }

    /// Wait up to `timeout` for the in-flight set to empty. Bounded on purpose: a
    /// producer that will not finish must not be able to hold the cutover — and
    /// with it the daemon's shutdown — open.
    ///
    /// This is only the wait. Nothing is decided here and no count is sampled, so
    /// a producer that finishes between the wait ending and the [`seal`](Self::seal)
    /// is simply a producer the seal sees has already left.
    pub fn wait_idle(&self, timeout: Duration) {
        let queue = self.locked();
        drop(
            self.idle
                .wait_timeout_while(queue, timeout, |queue| queue.in_flight > 0)
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// Close the cutover and count whatever is still in flight as a gap, in one
    /// lock acquisition. Returns how many producers that was.
    ///
    /// Reading the final in-flight count and committing to it happen together, so
    /// there is no interval in which a producer can both hand its observation to
    /// the batch and be written off as lost. After this the queue accepts nothing
    /// more: a producer counted here adds nothing when it finally
    /// [`commit`](Self::commit)s, and an untracked [`push`](Self::push) is refused
    /// and counted for itself.
    pub fn seal(&self) -> usize {
        let mut queue = self.locked();
        queue.sealed = true;
        let remaining = queue.in_flight;
        queue.dropped = queue.dropped.saturating_add(remaining as u64);
        remaining
    }

    /// Count `n` observations as refused without offering them: what a producer
    /// reports when it lost them before the queue ever saw them (a connection
    /// turned away at a handler cap). Surfaced by the next drain exactly as an
    /// overflow is.
    ///
    /// Never used to account for the terminal cutover — that is [`seal`](Self::seal)'s
    /// job, and doing it from a separately sampled count is exactly how the same
    /// producer came to be counted as lost *and* have its observation accepted.
    pub fn record_dropped(&self, n: u64) {
        let mut queue = self.locked();
        queue.dropped = queue.dropped.saturating_add(n);
    }

    /// How many observations are waiting right now.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.locked().items.len()
    }

    /// Take everything queued, plus the number refused since the previous drain.
    /// Both come out of one lock acquisition, so a concurrent producer cannot slip
    /// a refusal between the items and the count.
    pub fn drain(&self) -> Drained<T> {
        let mut queue = self.locked();
        Drained {
            items: queue.items.drain(..).collect(),
            dropped: std::mem::take(&mut queue.dropped),
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
            out.extend(hooks.drain_observations());
        }
        out
    }

    /// Stop every producer and return what they still held. Call exactly once: the
    /// producers are gone afterwards, so a second call returns nothing and cannot
    /// append a record twice.
    ///
    /// Each producer is **quiesced before its own final drain**, never after. A
    /// producer is first stopped from accepting new work and then waited on — for at
    /// most [`QUIESCE_TIMEOUT`] — until the work it already had in flight has
    /// finished and reached its queue; only then is that queue drained for the last
    /// time. Draining a producer that is still live would race the drain against a
    /// legitimate decision or claim and discard whatever lost, with no later drain
    /// and no marker to say so.
    ///
    /// The wait is bounded, so a wedged handler cannot hold shutdown open; a
    /// producer that is still busy when it runs out is reported the same way an
    /// overflow is — counted into that source's refusals, so the drain below turns
    /// it into an explicit [`WardEvent::ObservationsDropped`] marker. Counting it is
    /// the same lock acquisition that closes the queue to further work
    /// ([`Bounded::seal`]), so a producer that finishes in the instant the wait ran
    /// out is on exactly one side of the cutover: its observation is in the batch
    /// drained below, or it is in the marker, never in both.
    #[must_use]
    pub fn finish(&mut self, by: &ProcessRef) -> Finished {
        self.finish_within(by, QUIESCE_TIMEOUT)
    }

    /// [`finish`](Self::finish) with the quiesce wait given explicitly, so the
    /// regression for a producer that cannot be quiesced does not have to wait out
    /// the production bound.
    #[must_use]
    pub fn finish_within(&mut self, by: &ProcessRef, quiesce: Duration) -> Finished {
        // The watch is drained through its own `finish`, which stops the thread and
        // *joins* it — so the inotify loop has made its last pass and can no longer
        // push — before handing the queue's tail back.
        let watch = self.watcher.take().map(Watcher::finish);
        let mut tail = Vec::new();
        if let Some(egress) = self.egress.take() {
            // Stop accepting, let the connections already being served finish
            // recording their decisions, then take the queue.
            egress.quiesce(quiesce);
            tail.extend(egress.drain_observations(by));
            egress.stop();
        }
        if let Some(hooks) = self.hooks.take() {
            // `Hooks::stop` deliberately leaves in-flight handlers running, and each
            // of them still holds the claim buffer; quiescing joins the accept thread
            // *and* waits for those handlers, so a claim decided across the cutover
            // is in the buffer this drain empties instead of being appended to a
            // buffer nothing will ever look at again.
            hooks.quiesce(quiesce);
            tail.extend(hooks.drain_observations());
            hooks.stop();
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
    use std::io::{BufRead, BufReader, Write as _};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Barrier};
    use ward_events::{ClaimKind, FileChangeKind, Pid};
    use ward_policy::{ObserverMode, StepPolicy};

    use crate::hooks::{Holder, HookDecision, HookResponse, Hooks};

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

    /// A refusal and the batch it belongs to are one epoch, even under a drain
    /// running concurrently with the producer that is being refused.
    ///
    /// With a bound of one, a push is refused *only* while an observation is
    /// queued, and only a drain ever removes that observation — so every drain that
    /// reports a refusal must also hand over the observation the refusal collided
    /// with. A drain reporting `dropped > 0` with nothing taken is proof that the
    /// count was moved across a drain boundary: the refusal decided in one epoch and
    /// was recorded in the next. That is the same misattribution that loses the
    /// *final* refusal outright when the drain it slipped past is the terminal one.
    ///
    /// No sleeps: the two threads rendezvous on a barrier and then run flat out, and
    /// the assertion is an invariant that holds for every interleaving rather than a
    /// timing expectation.
    #[test]
    fn a_refusal_is_never_counted_into_a_drain_that_did_not_take_the_batch() {
        const ROUNDS: u64 = 20_000;
        let q = Arc::new(Bounded::new(1));
        let start = Arc::new(Barrier::new(2));

        let producer = {
            let (q, start) = (Arc::clone(&q), Arc::clone(&start));
            std::thread::spawn(move || {
                start.wait();
                for i in 0..ROUNDS {
                    // One of the two is refused whenever the drain has not been
                    // through since the last round.
                    q.push(i);
                    q.push(i);
                }
            })
        };

        start.wait();
        let (mut taken, mut refused) = (0u64, 0u64);
        let mut check = |drained: Drained<u64>| {
            assert!(
                drained.dropped == 0 || !drained.items.is_empty(),
                "a refusal was counted into a drain that took nothing: the queue was \
                 full when the push was refused, and only a drain empties it, so this \
                 refusal belongs to an earlier batch"
            );
            assert!(
                drained.items.len() <= 1,
                "the bound is one: {:?}",
                drained.items
            );
            taken += drained.items.len() as u64;
            refused += drained.dropped;
        };
        while !producer.is_finished() {
            check(q.drain());
        }
        producer.join().unwrap();
        check(q.drain());

        assert_eq!(
            taken + refused,
            2 * ROUNDS,
            "every offered observation is either taken or counted as refused, exactly once"
        );
    }

    /// The drain and the reset of the refusal count are one step relative to
    /// concurrent producers: across several producers hammering a queue while a
    /// drainer empties it, every offer is accounted for exactly once — never lost
    /// between the two, never counted twice — and no drain takes a refusal whose
    /// batch it did not also take.
    #[test]
    fn draining_and_resetting_the_refusal_count_are_atomic_against_pushes() {
        const PRODUCERS: usize = 4;
        const EACH: u64 = 5_000;
        let q = Arc::new(Bounded::new(2));
        let start = Arc::new(Barrier::new(PRODUCERS + 1));

        let producers: Vec<_> = (0..PRODUCERS)
            .map(|_| {
                let (q, start) = (Arc::clone(&q), Arc::clone(&start));
                std::thread::spawn(move || {
                    start.wait();
                    for i in 0..EACH {
                        q.push(i);
                    }
                })
            })
            .collect();

        start.wait();
        let (mut taken, mut refused) = (0u64, 0u64);
        let check = |drained: &Drained<u64>| {
            assert!(drained.items.len() <= q.capacity());
            assert!(
                drained.dropped == 0 || !drained.items.is_empty(),
                "the queue was full when these {} refusals happened, and only a drain \
                 empties it — so the batch they belong to was taken by an earlier drain \
                 and this count has been moved out of its epoch",
                drained.dropped
            );
        };
        loop {
            let drained = q.drain();
            check(&drained);
            taken += drained.items.len() as u64;
            refused += drained.dropped;
            if producers.iter().all(std::thread::JoinHandle::is_finished) {
                break;
            }
        }
        for p in producers {
            p.join().unwrap();
        }
        let drained = q.drain();
        check(&drained);
        taken += drained.items.len() as u64;
        refused += drained.dropped;

        assert_eq!(
            taken + refused,
            PRODUCERS as u64 * EACH,
            "an offer must be in exactly one drain epoch, as an item or as a refusal"
        );
    }

    /// The terminal cutover is **one** decision about each in-flight producer, made
    /// under the queue's own lock.
    ///
    /// A producer still in flight when the seal happens is counted there and then,
    /// and the commit it finally makes adds nothing: not to the batch, and not to
    /// the count a second time. That is the whole difference from sampling "how many
    /// are still live", releasing the lock and recording a refusal afterwards — in
    /// that interval the producer could hand its observation over *and* be written
    /// off as lost, which is one observation accounted for twice.
    #[test]
    fn a_producer_sealed_out_of_the_cutover_is_counted_once_and_never_twice() {
        let q = Bounded::new(8);
        assert!(q.enter(4), "the producer is in flight");
        assert_eq!(
            q.seal(),
            1,
            "the seal gives up on it, and counts it doing so"
        );
        assert!(
            !q.commit(1),
            "the sealed queue takes nothing more: this loss is already reported"
        );

        let drained = q.drain();
        assert!(
            drained.items.is_empty(),
            "the observation must not also be in the batch: {:?}",
            drained.items
        );
        assert_eq!(
            drained.dropped, 1,
            "exactly one offer, exactly one account of it"
        );
    }

    /// The symmetric boundary: a producer that commits before the seal is in the
    /// final batch, and the seal — which reads the in-flight set itself rather than
    /// a count sampled earlier — no longer sees it, so nothing marks it as a gap.
    #[test]
    fn a_producer_that_commits_before_the_seal_is_accepted_and_not_counted() {
        let q = Bounded::new(8);
        assert!(q.enter(4));
        assert!(q.commit(1), "it made the cutover");
        assert_eq!(q.seal(), 0, "nothing is left in flight to give up on");

        let drained = q.drain();
        assert_eq!(drained.items, vec![1]);
        assert_eq!(
            drained.dropped, 0,
            "a producer that made the cutover is not a gap"
        );
    }

    /// A producer that never joined the in-flight set cannot have been counted by
    /// the seal, so its own late offer is what reports the loss — once.
    #[test]
    fn an_untracked_offer_after_the_seal_is_refused_and_counted_for_itself() {
        let q = Bounded::new(8);
        assert!(q.push(1));
        assert_eq!(q.seal(), 0);
        assert!(!q.push(2), "a sealed queue accepts nothing more");

        let drained = q.drain();
        assert_eq!(drained.items, vec![1]);
        assert_eq!(drained.dropped, 1);
    }

    /// Every producer racing the seal is classified exactly once.
    ///
    /// Each producer joins the in-flight set, rendezvouses with the sealing thread
    /// on a barrier, and then commits flat out while the seal happens. Whichever of
    /// the two reaches the queue's lock first decides that producer's fate, so this
    /// is an invariant over every interleaving rather than a timing expectation: no
    /// sleeps, and nothing depends on who wins. What it rules out is the interval
    /// the old shape had — a producer both accepted into the batch and counted in
    /// the marker, or (with the count sampled before the last commit) neither.
    #[test]
    fn every_producer_racing_the_seal_is_accounted_for_exactly_once() {
        const ROUNDS: usize = 50;
        const PRODUCERS: usize = 8;

        for _ in 0..ROUNDS {
            let q = Arc::new(Bounded::new(PRODUCERS));
            let start = Arc::new(Barrier::new(PRODUCERS + 1));
            let producers: Vec<_> = (0..PRODUCERS)
                .map(|i| {
                    let (q, start) = (Arc::clone(&q), Arc::clone(&start));
                    std::thread::spawn(move || {
                        assert!(q.enter(PRODUCERS));
                        start.wait();
                        q.commit(i)
                    })
                })
                .collect();

            start.wait();
            let charged = q.seal() as u64;
            let accepted = producers
                .into_iter()
                .map(|p| p.join().unwrap())
                .filter(|committed| *committed)
                .count() as u64;
            let drained = q.drain();

            assert_eq!(
                drained.items.len() as u64,
                accepted,
                "the batch holds exactly the producers that were told they committed"
            );
            assert_eq!(
                drained.dropped, charged,
                "the only refusals are the producers the seal gave up on"
            );
            assert_eq!(
                accepted + drained.dropped,
                PRODUCERS as u64,
                "every producer is in the batch or in the marker, exactly once"
            );
        }
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

    /// A hook handler that rendezvouses with the test and then never finishes until
    /// the test says so: a producer that cannot be quiesced inside the bound.
    struct WedgedHolder {
        entered: Arc<Barrier>,
        released: Arc<Barrier>,
    }

    impl Holder for WedgedHolder {
        fn hold(&self, _tool: &str, _summary: &str, _reason: &str) -> Option<HookResponse> {
            self.entered.wait();
            self.released.wait();
            Some(HookResponse {
                decision: HookDecision::Allow,
                reason: "approval: allowed once".to_owned(),
            })
        }
    }

    /// A hook handler that rendezvouses with the test and then keeps working for a
    /// known, bounded time: an in-flight producer that is still holding the claim
    /// buffer exactly when the terminal flush begins, and finishes across it.
    struct SlowHolder {
        entered: Arc<Barrier>,
        work: Duration,
    }

    impl Holder for SlowHolder {
        fn hold(&self, _tool: &str, _summary: &str, _reason: &str) -> Option<HookResponse> {
            // The test releases this the instant before it calls `finish`, so the
            // handler is provably in flight at the cutover.
            self.entered.wait();
            // Still working when `finish` starts. This is the producer's own
            // duration, not a synchronisation guess: the assertion below does not
            // depend on how long it is, only that quiescing waits for it.
            std::thread::sleep(self.work);
            Some(HookResponse {
                decision: HookDecision::Allow,
                reason: "approval: allowed once".to_owned(),
            })
        }
    }

    /// #137: the terminal flush must quiesce each producer *before* draining it.
    ///
    /// A hook handler is in flight — blocked in its holder — when `finish` is
    /// called, and completes while the flush is running. `Hooks::stop` deliberately
    /// never waits for handlers, so if the final drain runs before the producer is
    /// quiesced, this claim is appended to a buffer nothing will ever drain again:
    /// silently lost, with no gap marker, against the guarantee. Quiescing first
    /// makes the drain a cutover, and the claim lands in the tail.
    #[test]
    fn a_hook_claim_completed_across_the_cutover_is_still_flushed() {
        let dir = tempfile::tempdir().unwrap();
        let run_dir = dir.path().join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let mut obs = Observers::new(run_dir.clone());

        let entered = Arc::new(Barrier::new(2));
        let holder: Arc<dyn Holder> = Arc::new(SlowHolder {
            entered: Arc::clone(&entered),
            work: Duration::from_millis(300),
        });
        let hooks = Hooks::start_with(
            &run_dir,
            ObserverMode::StepThrough(StepPolicy {
                pause_before_writes: true,
                pause_before_network: false,
            }),
            Vec::new(),
            Some(holder),
        )
        .unwrap();
        let socket = hooks.socket().to_path_buf();
        obs.set_hooks(hooks);

        let asking = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&socket).unwrap();
            stream
                .write_all(
                    b"{\"hook\":\"PreToolUse\",\"tool\":\"Write\",\"summary\":\"/work/src/lib.rs\"}\n",
                )
                .unwrap();
            let mut reply = String::new();
            BufReader::new(&stream).read_line(&mut reply).unwrap();
            reply
        });

        // The handler is inside the holder: its claim is not recorded yet, and it is
        // about to be, right as the flush cuts over.
        entered.wait();
        let finished = obs.finish(&by());

        assert!(
            finished.tail.iter().any(|o| matches!(
                (&o.origin, &o.event),
                (
                    Origin::Agent,
                    WardEvent::AgentClaim {
                        kind: ClaimKind::ToolUse,
                        payload,
                    }
                ) if payload.content() == "PreToolUse Write /work/src/lib.rs → allow"
            )),
            "an in-flight claim that completed across the cutover must be flushed, not \
             discarded with the producer: {:?}",
            finished.tail.iter().map(|o| &o.event).collect::<Vec<_>>()
        );
        // Nothing was refused: the producer was quiesced, not given up on.
        assert!(
            !finished
                .tail
                .iter()
                .any(|o| matches!(o.event, WardEvent::ObservationsDropped { .. })),
            "a quiesced producer is not a gap: {:?}",
            finished.tail.iter().map(|o| &o.event).collect::<Vec<_>>()
        );
        // And the agent still got its answer.
        let reply: HookResponse = serde_json::from_str(&asking.join().unwrap()).unwrap();
        assert_eq!(reply.decision, HookDecision::Allow);
    }

    /// The quiesce wait is bounded, and running out of it is a *recorded* gap.
    ///
    /// A handler that will not finish cannot hold the daemon's shutdown open — but
    /// the claim it is still holding will now never be drained, so the flush says so
    /// with the same explicit marker an overflow produces, in the same place.
    #[test]
    fn a_producer_that_cannot_be_quiesced_is_marked_as_a_gap_not_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let run_dir = dir.path().join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let mut obs = Observers::new(run_dir.clone());

        let entered = Arc::new(Barrier::new(2));
        // Two barrier parties on the far side: the handler waits there until the
        // test releases it, which it only does after the flush has given up on it.
        let released = Arc::new(Barrier::new(2));
        let holder: Arc<dyn Holder> = Arc::new(WedgedHolder {
            entered: Arc::clone(&entered),
            released: Arc::clone(&released),
        });
        let hooks = Hooks::start_with(
            &run_dir,
            ObserverMode::StepThrough(StepPolicy {
                pause_before_writes: true,
                pause_before_network: false,
            }),
            Vec::new(),
            Some(holder),
        )
        .unwrap();
        let socket = hooks.socket().to_path_buf();
        obs.set_hooks(hooks);

        let asking = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&socket).unwrap();
            stream
                .write_all(
                    b"{\"hook\":\"PreToolUse\",\"tool\":\"Write\",\"summary\":\"/work/src/lib.rs\"}\n",
                )
                .unwrap();
            let mut reply = String::new();
            drop(BufReader::new(&stream).read_line(&mut reply));
            reply
        });

        entered.wait();
        let started = Instant::now();
        let finished = obs.finish_within(&by(), Duration::from_millis(100));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the wait is bounded: a wedged handler must not hold shutdown open, took {:?}",
            started.elapsed()
        );
        assert!(
            finished.tail.iter().any(|o| matches!(
                (&o.origin, &o.event),
                (
                    Origin::Wardd,
                    WardEvent::ObservationsDropped {
                        source: ObserverSource::Hook,
                        dropped: 1,
                        ..
                    }
                )
            )),
            "a producer that could not be quiesced is an incomplete capture and must be \
             recorded like any other gap: {:?}",
            finished.tail.iter().map(|o| &o.event).collect::<Vec<_>>()
        );

        released.wait();
        drop(asking.join());
    }

    /// #137: the boundary the quiesce timeout creates is itself atomic — a claim
    /// that lands *after* the cutover gave up is counted once, and is not in the
    /// terminal batch beside the marker that counts it.
    ///
    /// This is the tighter case the cutover regressions above do not reach. One
    /// covers a handler that finishes comfortably inside the wait (accepted, no
    /// marker); the other a handler that never finishes at all (marker, no claim).
    /// Neither covers a handler that finishes in the instant the wait ran out,
    /// which is where the classification used to be made twice: `quiesce` sampled
    /// "one handler still live", released the live-count lock, and *then* recorded
    /// a refusal, while the handler — racing in that interval — pushed its real
    /// claim into the same buffer. The terminal batch carried both the
    /// `AgentClaim` and an `ObservationsDropped { dropped: 1 }` for it: a false gap
    /// in a record documented to account for every observation exactly once.
    ///
    /// The ordering here is a barrier, not a sleep, so the race is decided rather
    /// than sampled. The handler is parked inside its holder; `quiesce` is given a
    /// zero wait, so the seal provably happens while that handler is still in
    /// flight; only then is the handler released, and joining the asking client
    /// proves its claim was recorded before the terminal drain below.
    #[test]
    fn a_hook_claim_that_lands_after_the_seal_is_counted_once_not_twice() {
        let dir = tempfile::tempdir().unwrap();
        let run_dir = dir.path().join("run");
        std::fs::create_dir_all(&run_dir).unwrap();

        let entered = Arc::new(Barrier::new(2));
        let released = Arc::new(Barrier::new(2));
        let holder: Arc<dyn Holder> = Arc::new(WedgedHolder {
            entered: Arc::clone(&entered),
            released: Arc::clone(&released),
        });
        let hooks = Hooks::start_with(
            &run_dir,
            ObserverMode::StepThrough(StepPolicy {
                pause_before_writes: true,
                pause_before_network: false,
            }),
            Vec::new(),
            Some(holder),
        )
        .unwrap();
        let socket = hooks.socket().to_path_buf();

        let asking = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&socket).unwrap();
            stream
                .write_all(
                    b"{\"hook\":\"PreToolUse\",\"tool\":\"Write\",\"summary\":\"/work/src/lib.rs\"}\n",
                )
                .unwrap();
            let mut reply = String::new();
            drop(BufReader::new(&stream).read_line(&mut reply));
            reply
        });

        // The handler is inside the holder: in flight, with nothing recorded yet.
        entered.wait();
        // A zero wait, so the seal is taken with that handler still in flight —
        // the exact instant the classification has to be made exactly once.
        assert_eq!(
            hooks.quiesce(Duration::ZERO),
            1,
            "the cutover gave up on the handler that was still in flight"
        );
        // Only now does the handler finish and try to record its claim, before the
        // terminal drain — the window the sampled-count shape lost.
        released.wait();
        drop(asking.join());

        let tail = hooks.drain_observations();
        hooks.stop();

        let claims = tail
            .iter()
            .filter(|o| matches!(o.event, WardEvent::AgentClaim { .. }))
            .count();
        let dropped: u64 = tail
            .iter()
            .filter_map(|o| match o.event {
                WardEvent::ObservationsDropped {
                    source: ObserverSource::Hook,
                    dropped,
                    ..
                } => Some(dropped),
                _ => None,
            })
            .sum();

        assert_eq!(
            claims,
            0,
            "the claim missed the cutover, so it must not be in the terminal batch \
             alongside the marker that accounts for it: {:?}",
            tail.iter().map(|o| &o.event).collect::<Vec<_>>()
        );
        assert_eq!(
            claims as u64 + dropped,
            1,
            "one offered claim, accounted for exactly once — never both accepted and \
             counted as dropped, never neither: {:?}",
            tail.iter().map(|o| &o.event).collect::<Vec<_>>()
        );
        assert_eq!(dropped, 1, "and the gap is reported exactly once");
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
