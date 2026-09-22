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
}

impl Observer for Recorder {
    /// Called on a proxy thread, in the path of a live decision. It must never
    /// block on the log, on disk or on a UI consumer, so it does no more than
    /// offer the record to the bounded queue: a full queue counts the refusal and
    /// returns immediately, and the decision the proxy just made stands either way.
    fn decision(&self, req: &Request, decision: Decision, reason: &str) {
        self.0.push(Recorded {
            at: SystemTime::now(),
            host: req.target.host.clone(),
            port: req.target.port,
            allowed: matches!(decision, Decision::Allow),
            reason: reason.to_owned(),
        });
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
