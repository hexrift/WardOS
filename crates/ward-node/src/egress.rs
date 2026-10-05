//! Per-attempt egress for admitted workloads whose manifest names `network.custom` (#332).
//!
//! A node that enforces a network allowlist ([`crate::execution::NodeExecution::with_network_allowlist`])
//! honours a `{"network":{"custom":[…]}}` manifest by running the attempt behind its own
//! `ward-proxy` instance ([`AttemptEgress`]): the same proxy, policy and structural denies
//! the per-session runtime applies (ADR-0014). The proxy runs in the node process, on
//! threads that live exactly as long as the attempt, listening on a Unix socket in the
//! attempt's private egress directory `<task-root>/<task>/<attempt>.egress/` — beside the
//! workspace, never inside it, like the evidence directory. The sandbox binds that socket
//! at [`ward_launch::PROXY_SOCKET`] and names it in [`PROXY_SOCKET_ENV`]; its network
//! namespace still holds only loopback, so the proxy is the one path out.
//!
//! The policy is exactly the manifest's host patterns as a
//! [`NetworkCapability::Custom`] allowlist. Private, link-local, loopback, multicast and
//! reserved ranges and the cloud metadata endpoint are refused in every mode, IP literals
//! are refused, every resolved address is checked and connections go only to a checked
//! address ([`ward_proxy::policy`]). No credential is injected (#267).
//!
//! The proxy reports every verdict to a [`DecisionRecorder`], a bounded queue the attempt's
//! reaper drains between waits; the registry, the attempt's single evidence writer
//! (ADR-0030 §3), appends each verdict as a `NetworkRequested` or `NetworkDenied` record
//! with origin `node`. Enforcement never waits on the record: a verdict the queue has no
//! room for is counted and surfaced as one `ObservationsDropped` marker before the attempt's
//! end record ([`overflow_marker`]), never lost in silence. Request bodies and payloads are
//! never recorded, only the destination and the reason.
//!
//! A Unix socket path is at most 108 bytes and a task root may be deep, so the listener is
//! bound through a held descriptor of the egress directory (`/proc/self/fd/<n>/proxy.sock`)
//! while the sandbox is handed the real path, which bind mounts do not limit.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use thiserror::Error;
use ward_events::{
    DeniedDst, DenyReason, HostName, ObserverSource, ProcessRef, RuleRef, WardEvent,
};
use ward_node_protocol::{HostAllowlist, TaskBinding};
use ward_proxy::{
    Config, Decision, Handle, Host, NetworkCapability, Observer, Proxy, Request, Resolver,
    SystemResolver,
};

use crate::evidence::private_dir;

/// Suffix of an attempt's egress directory, beside its workspace.
pub const EGRESS_SUFFIX: &str = ".egress";

/// File name of the proxy socket inside an attempt's egress directory.
pub const PROXY_SOCKET_FILE: &str = "proxy.sock";

/// The environment variable naming the proxy socket inside the sandbox.
pub const PROXY_SOCKET_ENV: &str = "WARD_PROXY_SOCKET";

/// Verdicts the recorder holds between drains; past it, verdicts are counted as dropped.
pub const DECISION_QUEUE_CAPACITY: usize = 256;

/// How long the attempt's end waits for the proxy's open connections to reach a verdict
/// before the remainder is counted as a gap.
pub const DEFAULT_QUIESCE: Duration = Duration::from_secs(2);

const QUIESCE_POLL: Duration = Duration::from_millis(10);

/// Why an attempt's egress proxy could not start.
#[derive(Debug, Error)]
pub enum EgressError {
    /// The egress directory could not be created or inspected.
    #[error("egress directory I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The egress directory is not a private directory.
    #[error("egress directory is not a private directory")]
    InsecurePath,
    /// The proxy could not bind its socket or start accepting.
    #[error("egress proxy could not start: {0}")]
    Proxy(#[from] ward_proxy::Error),
}

/// The egress directory of `binding` under the task root `root`:
/// `<root>/<task>/<attempt>.egress`.
#[must_use]
pub fn egress_dir(root: &Path, binding: TaskBinding) -> PathBuf {
    root.join(binding.task().to_string())
        .join(format!("{}{EGRESS_SUFFIX}", binding.attempt()))
}

/// The egress directory beside the attempt workspace `workspace`.
#[must_use]
pub fn egress_dir_beside(workspace: &Path) -> Option<PathBuf> {
    let attempt = workspace.file_name()?.to_str()?;
    Some(workspace.with_file_name(format!("{attempt}{EGRESS_SUFFIX}")))
}

/// One verdict the proxy reached, as recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkDecision {
    /// When the proxy decided.
    pub at: SystemTime,
    /// The destination host or literal.
    pub host: Host,
    /// The destination port.
    pub port: u16,
    /// Whether the proxy allowed it.
    pub allowed: bool,
    /// The proxy's allowlist-free reason.
    pub reason: String,
}

impl NetworkDecision {
    fn of(req: &Request, decision: Decision, reason: &str) -> Self {
        Self {
            at: SystemTime::now(),
            host: req.target.host.clone(),
            port: req.target.port,
            allowed: matches!(decision, Decision::Allow),
            reason: reason.to_owned(),
        }
    }

    /// The evidence record of this verdict, made by the workload process `by`; `None` when
    /// the host or reason cannot be represented.
    #[must_use]
    pub fn event(&self, by: &ProcessRef) -> Option<WardEvent> {
        let event = match (&self.host, self.allowed) {
            (Host::Name(name), true) => WardEvent::NetworkRequested {
                host: HostName::new(name).ok()?,
                port: self.port,
                decision: ward_events::Decision::Allow,
                rule: RuleRef::new(&self.reason)
                    .or_else(|_| RuleRef::new("proxy"))
                    .ok()?,
                by: by.clone(),
            },
            (Host::Name(name), false) => WardEvent::NetworkDenied {
                dst: DeniedDst::Host {
                    host: HostName::new(name).ok()?,
                    port: self.port,
                },
                reason: deny_reason(&self.reason),
            },
            (Host::Ip(addr), _) => WardEvent::NetworkDenied {
                dst: DeniedDst::Ip {
                    addr: *addr,
                    port: self.port,
                },
                reason: deny_reason(&self.reason),
            },
        };
        Some(event)
    }
}

fn deny_reason(reason: &str) -> DenyReason {
    let reason = reason.to_ascii_lowercase();
    if reason.contains("offline") {
        DenyReason::Offline
    } else if reason.contains("private")
        || reason.contains("loopback")
        || reason.contains("metadata")
        || reason.contains("link-local")
        || reason.contains("unique-local")
    {
        DenyReason::PrivateRange
    } else {
        DenyReason::NotAllowlisted
    }
}

/// The marker recorded when `dropped` verdicts of an attempt could not be recorded under
/// the bound `capacity`.
#[must_use]
pub fn overflow_marker(dropped: u64, capacity: usize) -> WardEvent {
    WardEvent::ObservationsDropped {
        source: ObserverSource::Network,
        dropped,
        capacity: u64::try_from(capacity).unwrap_or(u64::MAX),
    }
}

/// What one drain of the recorder returns.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Drained {
    /// The verdicts recorded since the last drain, oldest first.
    pub decisions: Vec<NetworkDecision>,
    /// Verdicts the recorder had to refuse since the last drain.
    pub dropped: u64,
}

impl Drained {
    /// Whether there is nothing to record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty() && self.dropped == 0
    }
}

#[derive(Debug, Default)]
struct RecorderState {
    decisions: Vec<NetworkDecision>,
    dropped: u64,
    in_flight: usize,
    sealed: bool,
}

/// Collects the proxy's verdicts into a bounded queue, and tracks the connections whose
/// verdict is still to come so a seal can charge them as a gap.
#[derive(Debug)]
pub struct DecisionRecorder {
    state: Mutex<RecorderState>,
    capacity: usize,
}

impl DecisionRecorder {
    /// A recorder holding at most `capacity` verdicts between drains.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            state: Mutex::new(RecorderState::default()),
            capacity: capacity.max(1),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RecorderState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Take every verdict recorded so far, with the count the queue had to refuse.
    pub fn drain(&self) -> Drained {
        let mut state = self.lock();
        Drained {
            decisions: std::mem::take(&mut state.decisions),
            dropped: std::mem::take(&mut state.dropped),
        }
    }

    /// Close the recorder: every connection announced and not yet decided is charged as a
    /// gap now, and nothing announced later is tracked. Returns how many were charged.
    pub fn seal(&self) -> usize {
        let mut state = self.lock();
        let pending = std::mem::take(&mut state.in_flight);
        state.dropped += u64::try_from(pending).unwrap_or(u64::MAX);
        state.sealed = true;
        pending
    }

    /// How many verdicts are waiting to be drained.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.lock().decisions.len()
    }
}

impl Observer for DecisionRecorder {
    fn decision(&self, _req: &Request, _decision: Decision, _reason: &str) {
        self.lock().dropped += 1;
    }

    fn deciding(&self) -> bool {
        let mut state = self.lock();
        if state.sealed {
            return false;
        }
        state.in_flight += 1;
        true
    }

    fn decided(&self, req: &Request, decision: Decision, reason: &str) {
        let mut state = self.lock();
        if state.sealed {
            return;
        }
        state.in_flight = state.in_flight.saturating_sub(1);
        if state.decisions.len() >= self.capacity {
            state.dropped += 1;
        } else {
            state
                .decisions
                .push(NetworkDecision::of(req, decision, reason));
        }
    }

    fn undecided(&self) {
        let mut state = self.lock();
        if !state.sealed {
            state.in_flight = state.in_flight.saturating_sub(1);
        }
    }
}

/// One attempt's running egress proxy. Dropping it shuts the proxy down and unlinks its
/// socket.
pub struct AttemptEgress {
    handle: Handle,
    recorder: Arc<DecisionRecorder>,
    socket: PathBuf,
    _dir: File,
}

impl fmt::Debug for AttemptEgress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttemptEgress")
            .field("socket", &self.socket)
            .field("paused", &self.paused())
            .finish_non_exhaustive()
    }
}

impl AttemptEgress {
    /// Start the proxy for `allowlist` in the egress directory `dir` (created mode 0700,
    /// refused when it is not a private directory), resolving names through the system.
    ///
    /// # Errors
    ///
    /// Returns [`EgressError`] when the directory cannot be prepared or the proxy cannot
    /// bind its socket; nothing is left listening then.
    pub fn start(dir: &Path, allowlist: &HostAllowlist) -> Result<Self, EgressError> {
        Self::start_with(dir, allowlist, Arc::new(SystemResolver))
    }

    /// [`Self::start`] with the resolver the proxy uses for every name.
    ///
    /// # Errors
    ///
    /// As [`Self::start`].
    pub fn start_with(
        dir: &Path,
        allowlist: &HostAllowlist,
        resolver: Arc<dyn Resolver>,
    ) -> Result<Self, EgressError> {
        private_dir(dir).map_err(|error| match error {
            crate::evidence::EvidenceError::Io(error) => EgressError::Io(error),
            _ => EgressError::InsecurePath,
        })?;
        let held = File::open(dir)?;
        let bind = PathBuf::from(format!(
            "/proc/self/fd/{}/{PROXY_SOCKET_FILE}",
            held.as_raw_fd()
        ));
        let hosts: BTreeSet<String> = allowlist.patterns().iter().cloned().collect();
        let recorder = Arc::new(DecisionRecorder::with_capacity(DECISION_QUEUE_CAPACITY));
        let observer: Arc<dyn Observer> = recorder.clone();
        let config = Config::new(NetworkCapability::Custom(hosts))
            .resolver(resolver)
            .listen_unix(bind);
        let handle = Proxy::spawn(config, observer)?;
        Ok(Self {
            handle,
            recorder,
            socket: dir.join(PROXY_SOCKET_FILE),
            _dir: held,
        })
    }

    /// Host path of the socket the sandbox binds at [`ward_launch::PROXY_SOCKET`].
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Refuse every new connection and every request not yet resolved with `503 paused
    /// by ward` while `paused`, and hold established relays (ADR-0019 §3).
    pub fn set_paused(&self, paused: bool) {
        self.handle.set_paused(paused);
    }

    /// Whether the proxy is refusing traffic as paused.
    #[must_use]
    pub fn paused(&self) -> bool {
        self.handle.paused()
    }

    /// Connections the proxy is serving right now.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.handle.active_connections()
    }

    /// The verdicts recorded since the last drain, with the count the recorder refused.
    pub fn drain(&self) -> Drained {
        self.recorder.drain()
    }

    /// Stop accepting, wait at most `timeout` for the connections still being served to
    /// end, then seal the recorder so any verdict still outstanding is charged as a gap
    /// before the caller's final [`drain`](Self::drain). Returns how many connections were
    /// still open when the wait ran out.
    pub fn quiesce(&self, timeout: Duration) -> usize {
        self.handle.shutdown();
        let deadline = Instant::now() + timeout;
        while self.handle.active_connections() > 0 && Instant::now() < deadline {
            std::thread::sleep(QUIESCE_POLL);
        }
        self.recorder.seal();
        self.handle.active_connections()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::{Read, Write};
    use std::net::IpAddr;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::UnixStream;

    use ward_events::Pid;
    use ward_proxy::StaticResolver;

    use super::*;

    fn allowlist() -> HostAllowlist {
        HostAllowlist::new(vec![
            "allowed.example".to_owned(),
            "*.wild.example".to_owned(),
        ])
        .unwrap()
    }

    fn by() -> ProcessRef {
        ProcessRef {
            pid: Pid::new(7).unwrap(),
            comm: None,
        }
    }

    fn start(dir: &Path) -> AttemptEgress {
        let resolver = StaticResolver::new()
            .with("allowed.example", [IpAddr::from([8, 8, 8, 8])])
            .with("a.wild.example", [IpAddr::from([8, 8, 4, 4])])
            .with("denied.example", [IpAddr::from([9, 9, 9, 9])])
            .with("rebind.wild.example", [IpAddr::from([10, 0, 0, 7])]);
        AttemptEgress::start_with(dir, &allowlist(), Arc::new(resolver)).unwrap()
    }

    fn connect(egress: &AttemptEgress) -> UnixStream {
        let dir = File::open(egress.socket().parent().unwrap()).unwrap();
        let stream = UnixStream::connect(format!(
            "/proc/self/fd/{}/{PROXY_SOCKET_FILE}",
            dir.as_raw_fd()
        ))
        .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
    }

    fn ask(egress: &AttemptEgress, target: &str) -> String {
        let mut stream = connect(egress);
        stream
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
            head.push(byte[0]);
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    fn drained_events(egress: &AttemptEgress) -> Vec<WardEvent> {
        egress
            .drain()
            .decisions
            .iter()
            .map(|decision| decision.event(&by()).unwrap())
            .collect()
    }

    #[test]
    fn the_socket_is_private_and_sits_in_a_private_directory_beside_the_workspace() {
        let root = tempfile::tempdir().unwrap();
        let binding = crate::test_support::lifecycle_binding();
        let workspace = root
            .path()
            .join(binding.task().to_string())
            .join(binding.attempt().to_string());
        let dir = egress_dir(root.path(), binding);
        assert_eq!(egress_dir_beside(&workspace).unwrap(), dir);
        assert_eq!(dir.parent(), workspace.parent());
        std::fs::create_dir_all(dir.parent().unwrap()).unwrap();

        let egress = start(&dir);
        assert_eq!(egress.socket(), dir.join(PROXY_SOCKET_FILE));
        let mode = |path: &Path| {
            std::fs::symlink_metadata(path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(egress.socket()), 0o600);
        assert!(
            std::fs::symlink_metadata(egress.socket())
                .unwrap()
                .file_type()
                .is_socket()
        );
        drop(egress);
        assert!(!dir.join(PROXY_SOCKET_FILE).exists());
    }

    #[test]
    fn a_non_private_directory_refuses_to_start() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("open.egress");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            AttemptEgress::start(&dir, &allowlist()),
            Err(EgressError::InsecurePath)
        ));
        let file = root.path().join("file.egress");
        std::fs::write(&file, b"x").unwrap();
        assert!(matches!(
            AttemptEgress::start(&file, &allowlist()),
            Err(EgressError::InsecurePath | EgressError::Io(_))
        ));
    }

    #[test]
    fn exactly_the_allowlist_passes_and_every_structural_deny_holds() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("x.egress");
        let egress = start(&dir);

        let allowed =
            |head: String| head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.1 502");
        assert!(allowed(ask(&egress, "allowed.example:443")));
        assert!(allowed(ask(&egress, "a.wild.example:443")));
        assert!(ask(&egress, "denied.example:443").starts_with("HTTP/1.1 403"));
        assert!(ask(&egress, "wild.example:443").starts_with("HTTP/1.1 403"));
        assert!(ask(&egress, "rebind.wild.example:443").starts_with("HTTP/1.1 403"));
        assert!(ask(&egress, "10.0.0.1:80").starts_with("HTTP/1.1 403"));
        assert!(ask(&egress, "127.0.0.1:80").starts_with("HTTP/1.1 403"));
        assert!(ask(&egress, "169.254.169.254:80").starts_with("HTTP/1.1 403"));
        assert!(ask(&egress, "8.8.8.8:53").starts_with("HTTP/1.1 403"));

        let events = drained_events(&egress);
        assert_eq!(events.len(), 9, "{events:?}");
        let allowed = |event: &WardEvent, name: &str| {
            matches!(event, WardEvent::NetworkRequested { host, port: 443, decision: ward_events::Decision::Allow, by: who, .. }
                if host.as_str() == name && *who == by())
        };
        assert!(allowed(&events[0], "allowed.example"), "{:?}", events[0]);
        assert!(allowed(&events[1], "a.wild.example"), "{:?}", events[1]);
        let denied = |event: &WardEvent, want: DenyReason| matches!(event, WardEvent::NetworkDenied { reason, .. } if *reason == want);
        assert!(
            denied(&events[2], DenyReason::NotAllowlisted),
            "{:?}",
            events[2]
        );
        assert!(
            denied(&events[3], DenyReason::NotAllowlisted),
            "{:?}",
            events[3]
        );
        assert!(
            denied(&events[4], DenyReason::PrivateRange),
            "{:?}",
            events[4]
        );
        assert!(
            matches!(&events[5], WardEvent::NetworkDenied { dst: DeniedDst::Ip { addr, port: 80 }, reason: DenyReason::NotAllowlisted } if *addr == IpAddr::from([10, 0, 0, 1])),
            "{:?}",
            events[5]
        );
        assert!(
            denied(&events[6], DenyReason::NotAllowlisted),
            "{:?}",
            events[6]
        );
        assert!(
            denied(&events[7], DenyReason::NotAllowlisted),
            "{:?}",
            events[7]
        );
        assert!(
            denied(&events[8], DenyReason::NotAllowlisted),
            "{:?}",
            events[8]
        );
        assert!(egress.drain().is_empty());
    }

    #[test]
    fn a_paused_proxy_refuses_without_deciding_and_resumes() {
        let root = tempfile::tempdir().unwrap();
        let egress = start(&root.path().join("p.egress"));
        egress.set_paused(true);
        assert!(egress.paused());
        let head = ask(&egress, "allowed.example:443");
        assert!(head.starts_with("HTTP/1.1 503"), "{head}");
        assert!(egress.drain().is_empty());
        egress.set_paused(false);
        assert!(ask(&egress, "denied.example:443").starts_with("HTTP/1.1 403"));
        assert_eq!(egress.drain().decisions.len(), 1);
    }

    #[test]
    fn quiescing_unlinks_the_socket_and_keeps_every_verdict_made_before_it() {
        let root = tempfile::tempdir().unwrap();
        let egress = start(&root.path().join("q.egress"));
        assert!(ask(&egress, "denied.example:443").starts_with("HTTP/1.1 403"));
        assert_eq!(egress.quiesce(Duration::from_secs(5)), 0);
        assert!(!egress.socket().exists());
        let drained = egress.drain();
        assert_eq!(drained.decisions.len(), 1);
        assert_eq!(drained.dropped, 0);
    }

    #[test]
    fn the_recorder_counts_what_it_cannot_hold_and_what_a_seal_leaves_undecided() {
        let recorder = DecisionRecorder::with_capacity(2);
        let req = Request {
            method: ward_proxy::Method::Connect,
            target: ward_proxy::Target {
                host: Host::Name("denied.example".into()),
                port: 443,
            },
        };
        for _ in 0..3 {
            assert!(recorder.deciding());
            recorder.decided(&req, Decision::Deny, "host is not on the session allowlist");
        }
        assert!(recorder.deciding());
        recorder.undecided();
        assert!(recorder.deciding());
        assert_eq!(recorder.queued(), 2);
        assert_eq!(recorder.seal(), 1);
        assert!(!recorder.deciding());
        recorder.decision(&req, Decision::Deny, "late");
        recorder.decided(&req, Decision::Deny, "charged already");
        let drained = recorder.drain();
        assert_eq!(drained.decisions.len(), 2);
        assert_eq!(drained.dropped, 3);
        assert!(recorder.drain().is_empty());
        assert_eq!(
            overflow_marker(3, 512),
            WardEvent::ObservationsDropped {
                source: ObserverSource::Network,
                dropped: 3,
                capacity: 512,
            }
        );
    }

    #[test]
    fn deny_reasons_map_to_the_event_catalogue() {
        assert_eq!(
            deny_reason("session network mode is offline"),
            DenyReason::Offline
        );
        assert_eq!(
            deny_reason("destination is a private range"),
            DenyReason::PrivateRange
        );
        assert_eq!(
            deny_reason("destination is a loopback"),
            DenyReason::PrivateRange
        );
        assert_eq!(
            deny_reason("destination is a cloud metadata endpoint"),
            DenyReason::PrivateRange
        );
        assert_eq!(
            deny_reason("destination is a link-local range"),
            DenyReason::PrivateRange
        );
        assert_eq!(
            deny_reason("host did not resolve"),
            DenyReason::NotAllowlisted
        );
        let unrepresentable = NetworkDecision {
            at: SystemTime::now(),
            host: Host::Name("bad host".into()),
            port: 1,
            allowed: true,
            reason: String::new(),
        };
        assert_eq!(unrepresentable.event(&by()), None);
    }
}
