//! Session egress: the proxy on a Unix socket that is the sandbox's only way out
//! (ADR-0014), plus a recorder that turns its decisions into log events.
//!
//! The proxy lives in the `ward` process that launched the sandbox, not in the
//! daemon, so a pause (ADR-0019 §3) reaches it through a file: the egress
//! watches the session's pause marker ([`Egress::watch_marker`]) and flips the
//! proxy's paused flag as the marker comes and goes.
//!
//! The recorder is deliberately the cheapest thing a proxy thread can do with a
//! decision: one lock, one length comparison, one push into a bounded queue
//! ([`crate::observe::Bounded`]) the session drains while the command runs (#137).
//! Enforcement never waits on ingestion — a proxy thread keeps deciding allow/deny
//! in real time however far behind the log writer or a UI consumer has fallen — and
//! a decision the queue has no room for is counted and surfaced as an explicit
//! [`ward_events::WardEvent::ObservationsDropped`] marker, never dropped in silence.
//!
//! The recorder also tracks the verdicts that have not been made *yet*: the proxy
//! announces each accepted connection before it serves it and retires it at its
//! verdict ([`ward_proxy::Observer::deciding`]), so the connection sits in the
//! queue's in-flight set for exactly the window in which a decision may still be
//! produced and not yet recorded — never for the life of a relay, which has long
//! since decided. [`Egress::quiesce`] can then charge whatever is left in that set
//! as a gap in the same lock acquisition that closes the queue, so the session's
//! one terminal drain takes every gap with it.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use ward_events::{
    DeniedDst, DenyReason, HostName, ObserverSource, Origin, ProcessRef, RuleRef, WardEvent,
};
use ward_policy::NetworkCapability;
use ward_proxy::{
    Config, Decision, GatewayRoute, Handle, Host, Observer, Proxy, Request, Resolver,
    SystemResolver,
};

use crate::error::{Error, Result};
use crate::observe::{Bounded, DEFAULT_CAPACITY, Drained, Observation, overflow_marker};

/// A recorded proxy decision, kept until the session drains it into the log.
#[derive(Clone, Debug)]
pub struct Recorded {
    /// When the proxy decided.
    pub at: SystemTime,
    /// Destination host or literal.
    pub host: Host,
    /// Destination port.
    pub port: u16,
    /// Whether the proxy allowed it.
    pub allowed: bool,
    /// The proxy's reason string.
    pub reason: String,
}

/// Collects decisions from the proxy threads into a bounded queue.
#[derive(Default)]
pub struct Recorder(Bounded<Recorded>);

impl Recorder {
    /// A recorder holding at most `capacity` decisions between drains.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Bounded::new(capacity))
    }

    /// Take everything recorded so far, with the number of decisions the queue had
    /// to refuse since the last drain.
    pub fn drain_bounded(&self) -> Drained<Recorded> {
        self.0.drain()
    }

    /// Take everything recorded so far.
    pub fn drain(&self) -> Vec<Recorded> {
        self.0.drain().items
    }

    /// Close the terminal cutover, counting every connection whose verdict has not
    /// reached the queue yet as a gap — in the one lock acquisition that also shuts
    /// the queue.
    ///
    /// Returns how many connections that was. They are the ones the proxy announced
    /// with [`Observer::deciding`] and has not yet retired, which is *not* the same
    /// set as the connections it still has open: a tunnel that is still relaying
    /// recorded its decision when it was allowed and left the set there and then.
    /// Counting open connections here instead is what produced the false gaps.
    ///
    /// Because the proxy announces a connection on its acceptor thread, and
    /// `Handle::shutdown` — which [`Egress::quiesce`] runs first — is mutually
    /// exclusive with that announcement, no connection can join the set after the
    /// shutdown returns, whether or not the acceptor thread has stopped. So what the
    /// seal sees really is everything that may still be decided, and charging it
    /// here, synchronously, is what puts the gap in the batch the caller's one
    /// terminal drain is about to take. A late verdict that arrives after this adds
    /// nothing: its loss has already been reported for it.
    pub fn seal(&self) -> usize {
        self.0.seal()
    }

    /// How many decisions are waiting to be drained.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.0.queued()
    }

    /// The bound this recorder was built with.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    /// The record one verdict becomes, stamped with the time the proxy decided.
    fn recorded(req: &Request, decision: Decision, reason: &str) -> Recorded {
        Recorded {
            at: SystemTime::now(),
            host: req.target.host.clone(),
            port: req.target.port,
            allowed: matches!(decision, Decision::Allow),
            reason: reason.to_owned(),
        }
    }
}

impl Observer for Recorder {
    /// Called on a proxy thread, in the path of a live decision, for a connection
    /// the recorder is *not* tracking — which, since [`Recorder::deciding`] takes
    /// every connection it is offered, happens only after the cutover sealed. The
    /// queue refuses the record and counts it, so the loss is still accounted for.
    fn decision(&self, req: &Request, decision: Decision, reason: &str) {
        self.0.push(Self::recorded(req, decision, reason));
    }

    /// One accepted connection joins the set of verdicts still to come, so the
    /// terminal [`seal`](Recorder::seal) can charge it as a gap if it does not reach
    /// one in time. Called on the proxy's acceptor thread, and mutually exclusive
    /// with `Handle::shutdown` — so once the caller's quiesce has shut the proxy
    /// down, this set only shrinks.
    ///
    /// There is no cap of the recorder's own: the proxy already bounds how many
    /// connections it serves at once, and a second cap here could only refuse a
    /// connection whose verdict it would then have to account for separately.
    /// Refused only once the cutover has sealed, and then the verdict accounts for
    /// itself through [`decision`](Observer::decision).
    fn deciding(&self) -> bool {
        self.0.enter(usize::MAX)
    }

    /// The verdict for a connection this recorder is tracking. It must never block
    /// on the log, on disk or on a UI consumer, so it does no more than leave the
    /// set and offer the record to the bounded queue — one lock, one length
    /// comparison — and the decision the proxy just made stands either way.
    ///
    /// Leaving and offering are the *same* lock acquisition, which is what makes
    /// the cutover exact: this verdict cannot land in the batch after the seal has
    /// already charged this connection as a gap, and the seal cannot charge it
    /// after the verdict has been accepted.
    fn decided(&self, req: &Request, decision: Decision, reason: &str) {
        self.0.commit(Self::recorded(req, decision, reason));
    }

    /// A connection that reached no verdict at all — an unparsable head, a request
    /// that is not a proxy request, a pause that landed while the head was in
    /// flight. Nothing was decided, so nothing is recorded; it simply stops being a
    /// verdict the cutover has to wait for.
    fn undecided(&self) {
        self.0.leave();
    }
}

/// Recorded decisions as log-ready observations, with the overflow marker when the
/// recorder had to refuse any. Entries whose host or reason cannot be represented
/// are skipped (the proxy already validated them).
#[must_use]
pub fn observations(
    drained: &Drained<Recorded>,
    by: &ProcessRef,
    capacity: usize,
) -> Vec<Observation> {
    let mut out: Vec<Observation> = drained
        .items
        .iter()
        .filter_map(|r| Some(Observation::new(r.at, Origin::Proxy, to_event(r, by)?)))
        .collect();
    if drained.dropped > 0 {
        out.push(overflow_marker(
            ObserverSource::Network,
            drained.dropped,
            capacity,
        ));
    }
    out
}

/// How often the marker is looked at. The sandbox is frozen before the marker
/// is written, so this lag is not a window anything inside can use.
const MARKER_POLL: Duration = Duration::from_millis(50);

/// A running session proxy bound to a Unix socket.
pub struct Egress {
    handle: Arc<Handle>,
    socket: PathBuf,
    recorder: Arc<Recorder>,
    watcher: Option<(Arc<AtomicBool>, JoinHandle<()>)>,
}

impl Egress {
    /// Start the proxy for `network` with the given gateway routes, listening at
    /// `dir/proxy.sock`.
    pub fn start(
        dir: &Path,
        network: &NetworkCapability,
        routes: Vec<GatewayRoute>,
    ) -> Result<Self> {
        Self::start_with(dir, network, routes, Arc::new(SystemResolver))
    }

    /// [`Egress::start`] with the resolver the proxy uses for every hostname.
    /// Sessions resolve through the system; `ward selftest` injects answers to
    /// stage DNS rebinding against the real proxy (ST-028).
    pub fn start_with(
        dir: &Path,
        network: &NetworkCapability,
        routes: Vec<GatewayRoute>,
        resolver: Arc<dyn Resolver>,
    ) -> Result<Self> {
        Self::start_bounded(dir, network, routes, resolver, DEFAULT_CAPACITY)
    }

    /// [`Egress::start_with`] with an explicit bound on how many decisions the
    /// recorder may hold between drains. Past it, decisions are counted and
    /// surfaced as an overflow marker rather than growing without limit — and the
    /// proxy keeps deciding either way.
    pub fn start_bounded(
        dir: &Path,
        network: &NetworkCapability,
        routes: Vec<GatewayRoute>,
        resolver: Arc<dyn Resolver>,
        capacity: usize,
    ) -> Result<Self> {
        let socket = dir.join("proxy.sock");
        let recorder = Arc::new(Recorder::with_capacity(capacity));
        let observer: Arc<dyn Observer> = recorder.clone();
        let config = routes
            .into_iter()
            .fold(Config::new(network.clone()), Config::gateway)
            .resolver(resolver)
            .listen_unix(&socket);
        let handle = Proxy::spawn(config, observer)
            .map_err(|e| Error::Sandbox(format!("egress proxy: {e}")))?;
        Ok(Self {
            handle: Arc::new(handle),
            socket,
            recorder,
            watcher: None,
        })
    }

    /// Pause the proxy while `marker` exists and resume it when it is gone,
    /// checked every [`MARKER_POLL`] until the egress stops. A marker already
    /// there starts the proxy paused.
    pub fn watch_marker(&mut self, marker: PathBuf) {
        let handle = Arc::clone(&self.handle);
        handle.set_paused(marker.exists());
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Acquire) {
                std::thread::sleep(MARKER_POLL);
                let paused = marker.exists();
                if paused != handle.paused() {
                    handle.set_paused(paused);
                }
            }
        });
        self.watcher = Some((stop, thread));
    }

    /// Whether the proxy is refusing traffic as paused.
    #[must_use]
    pub fn paused(&self) -> bool {
        self.handle.paused()
    }

    /// Host path of the socket to bind into the sandbox.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Decisions made since the last drain, as recorded (the self-test reads
    /// the proxy's own account of what it allowed and refused).
    pub fn drain_decisions(&self) -> Vec<Recorded> {
        self.recorder.drain()
    }

    /// Decisions made since the last drain, as log-ready observations keeping their
    /// decision time, followed by an overflow marker when the recorder had to
    /// refuse any. Safe to call repeatedly while the command runs.
    pub fn drain_observations(&self, by: &ProcessRef) -> Vec<Observation> {
        observations(&self.recorder.drain_bounded(), by, self.recorder.capacity())
    }

    /// How many decisions are waiting to be drained.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.recorder.queued()
    }

    /// Stop the proxy and wait, for at most `timeout`, until every connection it
    /// was still serving has finished — so a decision made across the cutover is in
    /// the recorder before the caller's final [`drain_observations`](Self::drain_observations),
    /// rather than being recorded into a queue nothing will drain again. The wait is
    /// bounded on purpose: a relay that will not wind down must not be able to hold
    /// the daemon's shutdown open.
    ///
    /// When the wait runs out the cutover is **sealed** ([`Recorder::seal`]) rather
    /// than guessed at, and the seal charges the connections whose verdicts have
    /// not reached the recorder yet — the set the proxy maintains through
    /// [`Observer::deciding`]/[`Observer::decided`], which a connection joins
    /// before it is served and leaves at its verdict, not at the end of its relay.
    /// Charging it is one acquisition of the recorder's own lock, the lock a proxy
    /// thread must take to record a decision, so a straggling connection either got
    /// its decision into the batch the caller is about to drain or is counted, then
    /// and there, as the gap it is. Nothing is counted from a sampled connection
    /// count, which is what let the same decision appear in the final batch *and*
    /// in an `ObservationsDropped` marker beside it: a connection still being
    /// served has, by then, already recorded the decision it was served for.
    ///
    /// The three steps are in this order for a reason. `shutdown` closes the proxy's
    /// announcement gate, so after it no connection can join the set at all — the
    /// acceptor may still be parked in `accept`, and a connection may still arrive,
    /// but neither can be announced any more, so neither is served; the wait then
    /// gives the ones already in it their bounded chance to decide; and the seal
    /// charges whatever is left **before this returns**. That is what makes the
    /// caller's single terminal [`drain_observations`](Self::drain_observations)
    /// enough: every gap has been counted by the time the drain runs, so none is
    /// left for a drain that never happens.
    ///
    /// Returns how many connections were still in flight when the wait ran out,
    /// which is a report on the proxy, not an accounting of the record.
    pub fn quiesce(&self, timeout: Duration) -> usize {
        // Stops accepting and asks every relay to wind down; idempotent, so the
        // later `stop` is still safe. Its returning is what closes the set of
        // connections that may still be decided — unconditionally, without relying
        // on the wake connection that gets the acceptor out of `accept`.
        self.handle.shutdown();
        // An open connection is a superset of an undecided one, so this waits out
        // the relays too; the seal below is what distinguishes the two.
        crate::daemon::wait_until(timeout, || self.handle.active_connections() == 0);
        self.recorder.seal();
        self.handle.active_connections()
    }

    /// Stop the proxy and remove the socket.
    pub fn stop(self) {
        if let Some((stop, thread)) = self.watcher {
            stop.store(true, Ordering::Release);
            let _ = thread.join();
        }
        self.handle.shutdown();
    }
}

fn to_event(r: &Recorded, by: &ProcessRef) -> Option<WardEvent> {
    let event = match (&r.host, r.allowed) {
        (Host::Name(name), true) => WardEvent::NetworkRequested {
            host: HostName::new(name).ok()?,
            port: r.port,
            decision: ward_events::Decision::Allow,
            rule: RuleRef::new(&r.reason)
                .or_else(|_| RuleRef::new("proxy"))
                .ok()?,
            by: by.clone(),
        },
        (Host::Name(name), false) => WardEvent::NetworkDenied {
            dst: DeniedDst::Host {
                host: HostName::new(name).ok()?,
                port: r.port,
            },
            reason: deny_reason(&r.reason),
        },
        (Host::Ip(addr), _) => WardEvent::NetworkDenied {
            dst: DeniedDst::Ip {
                addr: *addr,
                port: r.port,
            },
            reason: deny_reason(&r.reason),
        },
    };
    Some(event)
}

fn deny_reason(reason: &str) -> DenyReason {
    let r = reason.to_ascii_lowercase();
    if r.contains("offline") {
        DenyReason::Offline
    } else if r.contains("private") || r.contains("loopback") || r.contains("metadata") {
        DenyReason::PrivateRange
    } else {
        DenyReason::NotAllowlisted
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::net::IpAddr;
    use ward_events::Pid;

    use crate::observe::Observers;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn by() -> ProcessRef {
        ProcessRef {
            pid: Pid::new(7).unwrap(),
            comm: None,
        }
    }

    #[test]
    fn allowed_name_becomes_network_requested() {
        let r = Recorded {
            at: SystemTime::now(),
            host: Host::Name("api.github.com".into()),
            port: 443,
            allowed: true,
            reason: "allowlisted".into(),
        };
        assert!(matches!(
            to_event(&r, &by()),
            Some(WardEvent::NetworkRequested { port: 443, .. })
        ));
    }

    #[test]
    fn denied_private_ip_maps_to_private_range() {
        let r = Recorded {
            at: SystemTime::now(),
            host: Host::Ip(ip("10.0.0.1")),
            port: 80,
            allowed: false,
            reason: "private range".into(),
        };
        match to_event(&r, &by()) {
            Some(WardEvent::NetworkDenied {
                dst: DeniedDst::Ip { port: 80, .. },
                reason,
            }) => {
                assert_eq!(reason, DenyReason::PrivateRange);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// The marker file drives the proxy's paused flag both ways.
    #[test]
    fn the_marker_pauses_and_resumes_the_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("paused");
        let mut egress =
            Egress::start(dir.path(), &NetworkCapability::Offline, Vec::new()).unwrap();
        egress.watch_marker(marker.clone());
        assert!(!egress.paused());
        std::fs::write(&marker, "why\n").unwrap();
        assert!(crate::daemon::wait_until(Duration::from_secs(2), || egress.paused()));
        std::fs::remove_file(&marker).unwrap();
        assert!(crate::daemon::wait_until(Duration::from_secs(2), || {
            !egress.paused()
        }));
        egress.stop();
        assert!(!dir.path().join("proxy.sock").exists());
    }

    fn req(host: &str) -> Request {
        Request {
            method: ward_proxy::Method::Connect,
            target: ward_proxy::Target {
                host: Host::Name(host.into()),
                port: 1,
            },
        }
    }

    /// One HTTP request straight at the proxy's Unix socket; the reply is whatever
    /// the policy decided, and the decision is recorded either way.
    fn ask_proxy(socket: &Path, host: &str) -> String {
        use std::io::{Read as _, Write as _};
        let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
        stream
            .write_all(
                format!("GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
        let mut reply = String::new();
        drop(stream.read_to_string(&mut reply));
        reply
    }

    /// #137: the terminal flush quiesces the proxy *before* it drains the recorder,
    /// so a decision cannot be accepted into a queue that will never be drained
    /// again. After quiescing, nothing can reach the proxy at all, and everything it
    /// decided is still there for the drain that follows.
    #[test]
    fn quiescing_stops_the_proxy_before_its_decisions_are_drained() {
        let dir = tempfile::tempdir().unwrap();
        let egress = Egress::start(dir.path(), &NetworkCapability::Offline, Vec::new()).unwrap();
        let reply = ask_proxy(egress.socket(), "example.com");
        assert!(!reply.is_empty(), "the proxy answered the request");

        // Quiesce first: stop accepting and wait for the connections still being
        // served, so the drain below is a cutover rather than a race.
        assert_eq!(
            egress.quiesce(Duration::from_secs(5)),
            0,
            "no connection was left in flight"
        );
        let obs = egress.drain_observations(&by());
        assert!(
            obs.iter()
                .any(|o| matches!(o.event, WardEvent::NetworkDenied { .. })),
            "the decision made before the cutover must still be flushed: {obs:?}"
        );
        assert!(
            !obs.iter()
                .any(|o| matches!(o.event, WardEvent::ObservationsDropped { .. })),
            "a proxy that quiesced cleanly is not a gap: {obs:?}"
        );
        // Quiesced means quiesced: nothing can be decided after the drain.
        assert!(
            std::os::unix::net::UnixStream::connect(egress.socket()).is_err(),
            "the proxy socket must be gone once the proxy has been quiesced"
        );
        egress.stop();
    }

    /// A resolver that parks the connection it is asked about until the test
    /// releases it. Resolution happens after the proxy has started serving the
    /// request and before it reports its verdict, so this is a proxy thread
    /// provably in flight with its decision not yet recorded.
    struct BlockedResolver {
        entered: Arc<std::sync::Barrier>,
        released: Arc<std::sync::Barrier>,
    }

    impl Resolver for BlockedResolver {
        fn resolve(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
            self.entered.wait();
            self.released.wait();
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no such host",
            ))
        }
    }

    /// #137: the egress cutover is sealed, not sampled — a decision that lands
    /// after the bounded wait ran out is counted once, and is not in the terminal
    /// batch beside the marker that counts it.
    ///
    /// The previous shape read `active_connections()` after the wait and handed
    /// that number to the recorder as refusals. Two things were wrong with it, and
    /// both show up here: the count was taken outside the recorder's lock, so a
    /// straggler could record its decision in the interval and be accounted for
    /// twice; and a connection is still counted as active long after it has
    /// recorded its decision, so the number was not a count of lost decisions at
    /// all.
    ///
    /// The ordering is a barrier, not a sleep. The proxy is parked in the resolver,
    /// so `quiesce` with a zero wait provably seals while that decision is still in
    /// flight; only then is the proxy released, and joining the client proves the
    /// decision was recorded before the terminal drain below.
    #[test]
    fn a_proxy_decision_that_lands_after_the_seal_is_counted_once_not_twice() {
        let dir = tempfile::tempdir().unwrap();
        let entered = Arc::new(std::sync::Barrier::new(2));
        let released = Arc::new(std::sync::Barrier::new(2));
        let resolver: Arc<dyn Resolver> = Arc::new(BlockedResolver {
            entered: Arc::clone(&entered),
            released: Arc::clone(&released),
        });
        let allowed =
            NetworkCapability::Custom(["parked.example".to_owned()].into_iter().collect());
        let egress = Egress::start_with(dir.path(), &allowed, Vec::new(), resolver).unwrap();
        let socket = egress.socket().to_path_buf();
        let asking = std::thread::spawn(move || ask_proxy(&socket, "parked.example"));

        // The proxy is serving the request and has not decided yet.
        entered.wait();
        // A zero wait, so the seal is taken with that decision still in flight.
        egress.quiesce(Duration::ZERO);
        // Only now does the proxy reach its verdict and try to record it, before
        // the terminal drain — the window the sampled-count shape lost.
        released.wait();
        drop(asking.join());

        let obs = egress.drain_observations(&by());
        egress.stop();

        let decisions = obs
            .iter()
            .filter(|o| {
                matches!(
                    o.event,
                    WardEvent::NetworkDenied { .. } | WardEvent::NetworkRequested { .. }
                )
            })
            .count();
        let dropped: u64 = obs
            .iter()
            .filter_map(|o| match o.event {
                WardEvent::ObservationsDropped {
                    source: ObserverSource::Network,
                    dropped,
                    ..
                } => Some(dropped),
                _ => None,
            })
            .sum();

        assert_eq!(
            decisions, 0,
            "the decision missed the cutover, so it must not be in the terminal batch \
             alongside the marker that accounts for it: {obs:?}"
        );
        assert_eq!(
            decisions as u64 + dropped,
            1,
            "one decision, accounted for exactly once — never both recorded and \
             counted as dropped, never neither: {obs:?}"
        );
        assert_eq!(dropped, 1, "and the gap is reported exactly once");
    }

    /// Count the decisions and the network-gap total in one batch.
    fn tally(obs: &[Observation]) -> (usize, u64) {
        let decisions = obs
            .iter()
            .filter(|o| {
                matches!(
                    o.event,
                    WardEvent::NetworkDenied { .. } | WardEvent::NetworkRequested { .. }
                )
            })
            .count();
        let dropped = obs
            .iter()
            .filter_map(|o| match o.event {
                WardEvent::ObservationsDropped {
                    source: ObserverSource::Network,
                    dropped,
                    ..
                } => Some(dropped),
                _ => None,
            })
            .sum();
        (decisions, dropped)
    }

    /// #137: the gap has to be in the batch the terminal drain **already took**.
    ///
    /// This is the production ordering, which the regression above does not reach.
    /// There the blocked decision is released and joined *before* the drain, so the
    /// refusal it records on arrival is still in the queue when the drain runs. The
    /// session does not do that: [`crate::observe::Observers::finish_within`]
    /// quiesces and then drains, immediately, with no join in between and no second
    /// drain afterwards. A straggler that counts *itself* on arrival therefore
    /// counts into a `dropped` total nothing will ever emit — the gap is real and
    /// the record is silent about it, which is exactly what G14 forbids.
    ///
    /// So: seal with the decision provably in flight, take the terminal batch, and
    /// only then let the decision happen. The already-returned batch must carry the
    /// one gap. A count that only appears afterwards is a count nobody reads.
    #[test]
    fn a_decision_still_in_flight_at_the_seal_is_a_gap_in_the_batch_the_drain_already_took() {
        let dir = tempfile::tempdir().unwrap();
        let entered = Arc::new(std::sync::Barrier::new(2));
        let released = Arc::new(std::sync::Barrier::new(2));
        let resolver: Arc<dyn Resolver> = Arc::new(BlockedResolver {
            entered: Arc::clone(&entered),
            released: Arc::clone(&released),
        });
        let allowed =
            NetworkCapability::Custom(["parked.example".to_owned()].into_iter().collect());
        let egress = Egress::start_with(dir.path(), &allowed, Vec::new(), resolver).unwrap();
        let socket = egress.socket().to_path_buf();
        let asking = std::thread::spawn(move || ask_proxy(&socket, "parked.example"));

        // The proxy is serving the request and has not decided yet.
        entered.wait();
        // A zero wait, so the seal is taken with that decision still in flight.
        egress.quiesce(Duration::ZERO);
        // The one terminal drain, in the place the session performs it: straight
        // after the quiesce, with the straggler still parked.
        let terminal = egress.drain_observations(&by());
        // Only now does the proxy reach its verdict — too late, by construction.
        released.wait();
        drop(asking.join());

        let (decisions, dropped) = tally(&terminal);
        assert_eq!(
            decisions, 0,
            "the decision missed the cutover, so it cannot be in the terminal batch: \
             {terminal:?}"
        );
        assert_eq!(
            dropped, 1,
            "the batch the drain already returned must carry the gap: a count raised \
             after it is a count no drain will ever emit: {terminal:?}"
        );

        // And the straggler adds nothing of its own afterwards — neither the
        // decision nor a second count of the same loss.
        let after = egress.drain_observations(&by());
        egress.stop();
        assert!(
            after.is_empty(),
            "the loss was accounted for in the terminal batch; nothing may be left \
             over for a drain that never happens: {after:?}"
        );
    }

    /// The same, one level up: through the session's real terminal path.
    ///
    /// [`crate::observe::Observers::finish_within`] is what production calls, and
    /// the sequencing under test is its own — quiesce, then the single drain, with
    /// nothing joining the proxy in between. The tail it returns is the last thing
    /// the log ever receives for this command, so the gap has to be in it.
    #[test]
    fn the_terminal_flush_returns_the_network_gap_for_a_decision_it_gave_up_on() {
        let dir = tempfile::tempdir().unwrap();
        let run_dir = dir.path().join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let entered = Arc::new(std::sync::Barrier::new(2));
        let released = Arc::new(std::sync::Barrier::new(2));
        let resolver: Arc<dyn Resolver> = Arc::new(BlockedResolver {
            entered: Arc::clone(&entered),
            released: Arc::clone(&released),
        });
        let allowed =
            NetworkCapability::Custom(["parked.example".to_owned()].into_iter().collect());
        let egress = Egress::start_with(&run_dir, &allowed, Vec::new(), resolver).unwrap();
        let socket = egress.socket().to_path_buf();
        let mut obs = Observers::new(run_dir.clone());
        obs.set_egress(egress);
        let asking = std::thread::spawn(move || ask_proxy(&socket, "parked.example"));

        entered.wait();
        // The real terminal path, with the bound collapsed so the test does not
        // have to wait it out. It quiesces, drains once and is done.
        let finished = obs.finish_within(&by(), Duration::ZERO);
        // The straggler only now reaches its verdict — after the tail was returned.
        released.wait();
        drop(asking.join());

        let (decisions, dropped) = tally(&finished.tail);
        assert_eq!(
            decisions,
            0,
            "the decision missed the cutover: {:?}",
            finished.tail.iter().map(|o| &o.event).collect::<Vec<_>>()
        );
        assert_eq!(
            dropped,
            1,
            "the tail the session appends is the last record of this command, so a \
             decision the cutover gave up on must be marked in it: {:?}",
            finished.tail.iter().map(|o| &o.event).collect::<Vec<_>>()
        );
        // The marker is the daemon's own statement, which no observer mode may hide.
        assert!(
            finished
                .tail
                .iter()
                .any(|o| o.origin == Origin::Wardd && o.origin.is_enforcement_fact())
        );
    }

    /// Parks the proxy's acceptor at the exact point the announcement is made, and
    /// lets the test decide when it may proceed.
    ///
    /// `deciding` is the announcement: it is the call through which an accepted
    /// connection joins the recorder's outstanding set, and the accept loop makes it
    /// after its last look at the shutdown flag. Blocking the first one therefore
    /// holds the acceptor still in precisely the window a shutdown must not be able
    /// to slip through — past the flag check, not yet in the set. Everything else is
    /// the real [`Recorder`]'s.
    struct ParkedAnnouncement {
        inner: Arc<Recorder>,
        entered: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
        parked: AtomicBool,
    }

    impl Observer for ParkedAnnouncement {
        fn decision(&self, req: &Request, decision: Decision, reason: &str) {
            self.inner.decision(req, decision, reason);
        }

        fn deciding(&self) -> bool {
            if !self.parked.swap(true, Ordering::AcqRel) {
                self.entered.wait();
                self.release.wait();
            }
            self.inner.deciding()
        }

        fn decided(&self, req: &Request, decision: Decision, reason: &str) {
            self.inner.decided(req, decision, reason);
        }

        fn undecided(&self) {
            self.inner.undecided();
        }
    }

    /// #137, round 5: the cutover may not depend on the proxy's wake connection.
    ///
    /// `Handle::shutdown` used to join its acceptor only when the synthetic
    /// connection it makes to wake that acceptor out of `accept` succeeded, and to
    /// leave the thread running when it did not. The seal, though, relies on the
    /// stronger statement — *after `shutdown` returns, nothing more can join the
    /// outstanding-decision set* — and a wake that cannot land (the Unix socket file
    /// is gone) left an acceptor free to announce a connection after the seal had
    /// already decided there was nothing left to account for. Its verdict then
    /// arrived untracked, was refused by the sealed queue, and raised a `dropped`
    /// count in an epoch no drain would ever emit: a genuine gap, silently.
    ///
    /// The five steps of that interleaving, forced here rather than waited for:
    /// the acceptor is parked at its announcement (1); the socket file is unlinked
    /// so the wake provably fails (2); `quiesce` and the session's single terminal
    /// drain run (3); only then is the acceptor released and its verdict produced
    /// (4, 5). The batch the drain already returned has to account for that verdict
    /// exactly once — not zero times, which is the silent loss, and not twice.
    #[test]
    fn a_connection_announced_while_the_wake_fails_is_accounted_for_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("proxy.sock");
        let recorder = Arc::new(Recorder::with_capacity(8));
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let observer: Arc<dyn Observer> = Arc::new(ParkedAnnouncement {
            inner: Arc::clone(&recorder),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            parked: AtomicBool::new(false),
        });
        let config = Config::new(NetworkCapability::Offline).listen_unix(&socket);
        let handle = Proxy::spawn(config, observer).unwrap();
        let egress = Egress {
            handle: Arc::new(handle),
            socket: socket.clone(),
            recorder,
            watcher: None,
        };

        let asking = {
            let socket = socket.clone();
            std::thread::spawn(move || ask_proxy(&socket, "example.com"))
        };

        // (1) The acceptor has accepted, has looked at the shutdown flag, and has
        // not yet joined the outstanding-decision set.
        entered.wait();
        // (2) The socket file goes, so the wake connection `shutdown` makes cannot
        // reach the acceptor. Nothing about the cutover may depend on it.
        std::fs::remove_file(&socket).unwrap();

        let drained = Arc::new(AtomicBool::new(false));
        let releaser = {
            let (release, drained) = (Arc::clone(&release), Arc::clone(&drained));
            std::thread::spawn(move || {
                // Without the gate, `quiesce` never waits for the parked
                // announcement: the terminal drain is taken immediately and this
                // returns at once, which is the interleaving under test. With it,
                // `quiesce` cannot complete until the release below, so this waits
                // the bound out and then lets the acceptor through.
                crate::daemon::wait_until(Duration::from_millis(250), || {
                    drained.load(Ordering::Acquire)
                });
                release.wait();
            })
        };

        // (3) The terminal sequence, exactly as the session runs it: quiesce, then
        // the one drain, with nothing joining the proxy in between.
        egress.quiesce(Duration::ZERO);
        let terminal = egress.drain_observations(&by());
        drained.store(true, Ordering::Release);

        // (4, 5) Only now is the acceptor released, so the verdict is produced
        // strictly after the batch above was returned.
        releaser.join().unwrap();
        drop(asking.join());

        let (decisions, dropped) = tally(&terminal);
        assert_eq!(
            decisions as u64 + dropped,
            1,
            "the connection was accepted, so its one verdict has to be accounted for \
             in the batch the terminal drain already took — a wake connection that \
             could not land must not be able to turn it into a silent gap: {terminal:?}"
        );
        assert_eq!(
            decisions, 0,
            "the verdict came after the cutover, so it cannot be in the batch: \
             {terminal:?}"
        );
        assert_eq!(
            dropped, 1,
            "and the gap is reported exactly once: {terminal:?}"
        );

        // Nothing is left over for a drain that never happens, and nothing counted
        // the same loss a second time when the verdict finally arrived.
        let after = egress.drain_observations(&by());
        egress.stop();
        assert!(after.is_empty(), "{after:?}");
    }

    /// The set the seal charges is "not decided yet", never "still connected".
    ///
    /// A connection that has been allowed goes on relaying — a large response body,
    /// a long-lived tunnel — for as long as it likes, and none of that is a decision
    /// still to be made: it was recorded when the connection was allowed. Charging
    /// open connections is what produced false gaps beside their own decisions.
    #[test]
    fn a_connection_leaves_the_pending_set_at_its_verdict_not_at_the_end_of_its_relay() {
        let rec = Recorder::with_capacity(4);
        assert!(
            rec.deciding(),
            "the connection is announced before it is served"
        );
        rec.decided(&req("still-relaying.io"), Decision::Allow, "allowlisted");
        // The relay may run for minutes from here; the verdict is already recorded.
        assert_eq!(rec.seal(), 0, "there is no verdict left to wait for");

        let drained = rec.drain_bounded();
        assert_eq!(drained.items.len(), 1);
        assert_eq!(drained.dropped, 0, "a decided connection is not a gap");
    }

    /// A connection that reaches no verdict is not a lost observation either: it
    /// leaves the set with nothing to record, so the cutover has nothing to charge.
    #[test]
    fn a_connection_that_never_decides_is_retired_without_a_gap() {
        let rec = Recorder::with_capacity(4);
        assert!(rec.deciding());
        rec.undecided();
        assert_eq!(rec.seal(), 0);
        assert_eq!(rec.drain_bounded().dropped, 0);
    }

    /// A verdict for a connection the seal already charged adds nothing — not the
    /// decision, and not a second count of the same loss.
    #[test]
    fn a_verdict_charged_by_the_seal_is_not_counted_again_when_it_arrives() {
        let rec = Recorder::with_capacity(4);
        assert!(rec.deciding());
        assert_eq!(
            rec.seal(),
            1,
            "the seal gives up on the undecided connection"
        );
        rec.decided(&req("too-late.io"), Decision::Deny, "offline");

        let drained = rec.drain_bounded();
        assert!(drained.items.is_empty(), "{:?}", drained.items);
        assert_eq!(drained.dropped, 1, "one loss, one account of it");
    }

    #[test]
    fn recorder_drains_once() {
        let rec = Recorder::default();
        let before = SystemTime::now();
        rec.decision(&req("x.io"), Decision::Deny, "offline");
        let drained = rec.drain();
        assert_eq!(drained.len(), 1);
        assert!(
            drained[0].at >= before,
            "decision time is captured, not drained"
        );
        assert!(rec.drain().is_empty());
    }

    /// #137: a recorder whose queue is full must never quietly lose a security
    /// decision. It refuses the record, counts it, and the next drain turns the
    /// count into one explicit marker beside the decisions it did keep.
    #[test]
    fn a_full_recorder_records_an_overflow_marker_instead_of_losing_decisions() {
        let rec = Recorder::with_capacity(2);
        rec.decision(&req("kept-one.io"), Decision::Allow, "allowlisted");
        rec.decision(&req("kept-two.io"), Decision::Deny, "offline");
        // Past the bound: refused, counted, never silently gone.
        rec.decision(&req("overflow-one.io"), Decision::Deny, "offline");
        rec.decision(&req("overflow-two.io"), Decision::Deny, "offline");

        let drained = rec.drain_bounded();
        assert_eq!(drained.dropped, 2);
        let obs = observations(&drained, &by(), rec.capacity());

        assert_eq!(obs.len(), 3, "two decisions and one marker: {obs:?}");
        assert!(matches!(obs[0].event, WardEvent::NetworkRequested { .. }));
        assert!(matches!(obs[1].event, WardEvent::NetworkDenied { .. }));
        assert_eq!(
            obs[2].event,
            WardEvent::ObservationsDropped {
                source: ObserverSource::Network,
                dropped: 2,
                capacity: 2,
            }
        );
        // The marker comes after the batch it accompanies, so the incomplete
        // window is bounded by the records either side of it.
        assert_eq!(obs[2].origin, Origin::Wardd);
    }

    /// The bound is on ingestion only: a recorder that is refusing records still
    /// returns from `decision` immediately, so the proxy thread that called it
    /// carries on making decisions in real time.
    #[test]
    fn a_full_recorder_still_accepts_decisions_without_failing_the_proxy() {
        let rec = Recorder::with_capacity(1);
        for _ in 0..1_000 {
            rec.decision(&req("busy.io"), Decision::Deny, "offline");
        }
        let drained = rec.drain_bounded();
        assert_eq!(drained.items.len(), 1);
        assert_eq!(drained.dropped, 999);
        // And the queue is usable again straight after a drain.
        rec.decision(&req("after.io"), Decision::Allow, "allowlisted");
        assert_eq!(rec.drain_bounded().items.len(), 1);
    }
}
