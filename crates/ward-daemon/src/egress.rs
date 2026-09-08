//! Session egress: the proxy on a Unix socket that is the sandbox's only way out
//! (ADR-0014), plus a recorder that turns its decisions into log events.
//!
//! The proxy lives in the `ward` process that launched the sandbox, not in the
//! daemon, so a pause (ADR-0019 §3) reaches it through a file: the egress
//! watches the session's pause marker ([`Egress::watch_marker`]) and flips the
//! proxy's paused flag as the marker comes and goes.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use ward_events::{DeniedDst, DenyReason, HostName, ProcessRef, RuleRef, WardEvent};
use ward_policy::NetworkCapability;
use ward_proxy::{
    Config, Decision, GatewayRoute, Handle, Host, Observer, Proxy, Request, Resolver,
    SystemResolver,
};

use crate::error::{Error, Result};

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

/// Collects decisions from the proxy threads.
#[derive(Default)]
pub struct Recorder(Mutex<Vec<Recorded>>);

impl Recorder {
    /// Take everything recorded so far.
    pub fn drain(&self) -> Vec<Recorded> {
        self.0
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default()
    }
}

impl Observer for Recorder {
    fn decision(&self, req: &Request, decision: Decision, reason: &str) {
        if let Ok(mut v) = self.0.lock() {
            v.push(Recorded {
                at: SystemTime::now(),
                host: req.target.host.clone(),
                port: req.target.port,
                allowed: matches!(decision, Decision::Allow),
                reason: reason.to_owned(),
            });
        }
    }
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
        let socket = dir.join("proxy.sock");
        let recorder = Arc::new(Recorder::default());
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

    /// Decisions made since the last drain, as log events with their decision time.
    /// Entries whose host or reason cannot be represented are skipped (the proxy
    /// already validated them).
    pub fn drain_events(&self, by: &ProcessRef) -> Vec<(SystemTime, WardEvent)> {
        self.recorder
            .drain()
            .iter()
            .filter_map(|r| Some((r.at, to_event(r, by)?)))
            .collect()
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

    #[test]
    fn recorder_drains_once() {
        let rec = Recorder::default();
        let req = Request {
            method: ward_proxy::Method::Connect,
            target: ward_proxy::Target {
                host: Host::Name("x.io".into()),
                port: 1,
            },
        };
        let before = SystemTime::now();
        rec.decision(&req, Decision::Deny, "offline");
        let drained = rec.drain();
        assert_eq!(drained.len(), 1);
        assert!(
            drained[0].at >= before,
            "decision time is captured, not drained"
        );
        assert!(rec.drain().is_empty());
    }
}
