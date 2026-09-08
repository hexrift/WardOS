//! Session egress: the proxy on a Unix socket that is the sandbox's only way out
//! (ADR-0014), plus a recorder that turns its decisions into log events.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ward_events::{DeniedDst, DenyReason, HostName, ProcessRef, RuleRef, WardEvent};
use ward_policy::NetworkCapability;
use ward_proxy::{Config, Decision, Handle, Host, Observer, Proxy, Request};

use crate::error::{Error, Result};

/// A recorded proxy decision, kept until the session drains it into the log.
#[derive(Clone, Debug)]
pub struct Recorded {
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
                host: req.target.host.clone(),
                port: req.target.port,
                allowed: matches!(decision, Decision::Allow),
                reason: reason.to_owned(),
            });
        }
    }
}

/// A running session proxy bound to a Unix socket.
pub struct Egress {
    handle: Handle,
    socket: PathBuf,
    recorder: Arc<Recorder>,
}

impl Egress {
    /// Start the proxy for `network`, listening at `dir/proxy.sock`.
    pub fn start(dir: &Path, network: &NetworkCapability) -> Result<Self> {
        let socket = dir.join("proxy.sock");
        let recorder = Arc::new(Recorder::default());
        let observer: Arc<dyn Observer> = recorder.clone();
        let handle = Proxy::spawn(Config::new(network.clone()).listen_unix(&socket), observer)
            .map_err(|e| Error::Sandbox(format!("egress proxy: {e}")))?;
        Ok(Self {
            handle,
            socket,
            recorder,
        })
    }

    /// Host path of the socket to bind into the sandbox.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Decisions made since the last drain, as log events. Entries whose host or
    /// reason cannot be represented are skipped (the proxy already validated them).
    pub fn drain_events(&self, by: &ProcessRef) -> Vec<WardEvent> {
        self.recorder
            .drain()
            .iter()
            .filter_map(|r| to_event(r, by))
            .collect()
    }

    /// Stop the proxy and remove the socket.
    pub fn stop(self) {
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
        rec.decision(&req, Decision::Deny, "offline");
        assert_eq!(rec.drain().len(), 1);
        assert!(rec.drain().is_empty());
    }
}
