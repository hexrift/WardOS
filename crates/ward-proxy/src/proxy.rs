//! The listener, connection threads and byte relay.
//!
//! One acceptor thread hands each connection to its own thread, bounded by
//! [`Config::max_connections`]; a tunnel uses a second thread for the return
//! direction. Everything is blocking std I/O with timeouts, so shutdown is a
//! flag the relay loops poll rather than a cancellation token.

use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ward_policy::NetworkCapability;

use crate::error::Error;
use crate::http::{self, Method, Parsed};
use crate::observer::{Decision, Observer};
use crate::policy::{Pinned, Policy};
use crate::resolve::{Resolver, SystemResolver};

/// How often a relay loop wakes to check for shutdown or idleness.
const POLL: Duration = Duration::from_millis(250);
/// Relay buffer size.
const RELAY_BUF: usize = 16 * 1024;

/// Proxy configuration. Build with [`Config::new`] and the setters.
#[derive(Clone)]
pub struct Config {
    listen: SocketAddr,
    capability: NetworkCapability,
    resolver: Arc<dyn Resolver>,
    max_connections: usize,
    request_timeout: Duration,
    connect_timeout: Duration,
    idle_timeout: Duration,
    allow_loopback: bool,
}

impl Config {
    /// Defaults: listen on `127.0.0.1:0`, system resolver, 64 connections,
    /// 15 s to send a request head, 10 s to connect upstream, 5 min idle.
    pub fn new(capability: NetworkCapability) -> Self {
        Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            capability,
            resolver: Arc::new(SystemResolver),
            max_connections: 64,
            request_timeout: Duration::from_secs(15),
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            allow_loopback: false,
        }
    }

    /// Address to listen on. Port `0` picks a free port; see [`Handle::local_addr`].
    #[must_use]
    pub fn listen(mut self, addr: SocketAddr) -> Self {
        self.listen = addr;
        self
    }

    /// Resolver used for every hostname lookup.
    #[must_use]
    pub fn resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Upper bound on concurrently served connections; excess gets `503`.
    #[must_use]
    pub fn max_connections(mut self, n: usize) -> Self {
        self.max_connections = n.max(1);
        self
    }

    /// How long a client may take to send its request head.
    #[must_use]
    pub fn request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = d;
        self
    }

    /// Upstream TCP connect timeout, per pinned address.
    #[must_use]
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = d;
        self
    }

    /// A tunnel with no bytes in either direction for this long is closed.
    #[must_use]
    pub fn idle_timeout(mut self, d: Duration) -> Self {
        self.idle_timeout = d;
        self
    }

    /// Permit loopback destinations in any mode. Test builds only: lets an
    /// integration test run its upstream on `127.0.0.1`.
    #[cfg(feature = "test-loopback")]
    #[must_use]
    pub fn allow_loopback(mut self, allow: bool) -> Self {
        self.allow_loopback = allow;
        self
    }

    fn policy(&self) -> Policy {
        let policy = Policy::new(self.capability.clone());
        #[cfg(feature = "test-loopback")]
        let policy = policy.allow_loopback(self.allow_loopback);
        policy
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("listen", &self.listen)
            .field("capability", &self.capability)
            .field("max_connections", &self.max_connections)
            .field("request_timeout", &self.request_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field("allow_loopback", &self.allow_loopback)
            .finish_non_exhaustive()
    }
}

/// State shared between the acceptor and every connection thread.
struct Shared {
    policy: Policy,
    resolver: Arc<dyn Resolver>,
    observer: Arc<dyn Observer>,
    max_connections: usize,
    request_timeout: Duration,
    connect_timeout: Duration,
    idle_timeout: Duration,
    active: AtomicUsize,
    shutdown: AtomicBool,
}

impl Shared {
    fn shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }
}

/// The proxy entry point.
#[derive(Debug, Clone, Copy)]
pub struct Proxy;

impl Proxy {
    /// Bind the listener and start accepting. Returns once the socket is
    /// bound, so [`Handle::local_addr`] is immediately usable.
    pub fn spawn(config: Config, observer: Arc<dyn Observer>) -> Result<Handle, Error> {
        let listener = TcpListener::bind(config.listen).map_err(|source| Error::Bind {
            addr: config.listen,
            source,
        })?;
        let local_addr = listener.local_addr().map_err(|source| Error::Bind {
            addr: config.listen,
            source,
        })?;
        let policy = config.policy();
        let shared = Arc::new(Shared {
            policy,
            resolver: config.resolver,
            observer,
            max_connections: config.max_connections,
            request_timeout: config.request_timeout,
            connect_timeout: config.connect_timeout,
            idle_timeout: config.idle_timeout,
            active: AtomicUsize::new(0),
            shutdown: AtomicBool::new(false),
        });
        let acceptor = {
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name("ward-proxy-accept".into())
                .spawn(move || accept_loop(&listener, &shared))
                .map_err(Error::Spawn)?
        };
        Ok(Handle {
            local_addr,
            shared,
            acceptor: Mutex::new(Some(acceptor)),
        })
    }
}

/// A running proxy. Dropping it shuts the listener down.
pub struct Handle {
    local_addr: SocketAddr,
    shared: Arc<Shared>,
    acceptor: Mutex<Option<JoinHandle<()>>>,
}

impl Handle {
    /// The bound listening address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Connections currently being served.
    pub fn active_connections(&self) -> usize {
        self.shared.active.load(Ordering::Acquire)
    }

    /// Stop accepting, ask every relay to wind down, and join the acceptor.
    /// Idempotent.
    pub fn shutdown(&self) {
        self.shared.shutdown.store(true, Ordering::Release);
        let acceptor = self
            .acceptor
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(acceptor) = acceptor {
            // Wake the blocking `accept` so it observes the flag.
            let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_secs(1));
            let _ = acceptor.join();
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handle")
            .field("local_addr", &self.local_addr)
            .field("active", &self.active_connections())
            .finish_non_exhaustive()
    }
}

/// Decrements the active-connection count when dropped.
struct Slot(Arc<Shared>);

impl Slot {
    fn acquire(shared: &Arc<Shared>) -> Option<Self> {
        let mut current = shared.active.load(Ordering::Acquire);
        loop {
            if current >= shared.max_connections {
                return None;
            }
            match shared.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self(Arc::clone(shared))),
                Err(seen) => current = seen,
            }
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn accept_loop(listener: &TcpListener, shared: &Arc<Shared>) {
    for incoming in listener.incoming() {
        if shared.shutting_down() {
            break;
        }
        let Ok(mut client) = incoming else { continue };
        let Some(slot) = Slot::acquire(shared) else {
            respond(&mut client, 503, "Service Unavailable", "proxy at capacity");
            continue;
        };
        let shared = Arc::clone(shared);
        let spawned = thread::Builder::new()
            .name("ward-proxy-conn".into())
            .spawn(move || {
                let _slot = slot;
                serve(client, &shared);
            });
        // On spawn failure the closure — and with it the stream and slot — is
        // dropped, which closes the connection and frees the slot.
        drop(spawned);
    }
}

/// Serve exactly one request on `client`.
fn serve(mut client: TcpStream, shared: &Arc<Shared>) {
    let _ = client.set_read_timeout(Some(shared.request_timeout));
    let _ = client.set_nodelay(true);
    let head = match http::read_head(&mut client) {
        Ok(Ok(head)) => head,
        Ok(Err(e)) => return respond(&mut client, 400, "Bad Request", &e.to_string()),
        Err(_) => return,
    };
    let parsed = match http::parse(&head.bytes) {
        Ok(parsed) => parsed,
        Err(e) => return respond(&mut client, 400, "Bad Request", &e.to_string()),
    };
    let req = &parsed.request;
    let pinned = match shared
        .policy
        .evaluate(shared.resolver.as_ref(), &req.target)
    {
        Ok(pinned) => pinned,
        Err(denial) => {
            shared
                .observer
                .decision(req, Decision::Deny, &denial.to_string());
            return respond(
                &mut client,
                403,
                "Forbidden",
                "destination not permitted by session policy",
            );
        }
    };
    shared.observer.decision(
        req,
        Decision::Allow,
        &format!("pinned {}", pinned_list(&pinned)),
    );
    let Some(mut upstream) = connect_pinned(&pinned, shared.connect_timeout) else {
        return respond(
            &mut client,
            502,
            "Bad Gateway",
            "upstream connection failed",
        );
    };
    let _ = upstream.set_nodelay(true);
    let prelude = match &req.method {
        Method::Connect => {
            let ok = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
            if ok.is_err() {
                return;
            }
            head.remainder
        }
        Method::Forward { .. } => forward_prelude(&parsed, &head.remainder),
    };
    if upstream.write_all(&prelude).is_err() {
        return;
    }
    relay(client, upstream, shared);
}

fn forward_prelude(parsed: &Parsed, body: &[u8]) -> Vec<u8> {
    let mut prelude = http::origin_head(parsed);
    prelude.extend_from_slice(body);
    prelude
}

fn pinned_list(pinned: &Pinned) -> String {
    pinned
        .addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Connect to the first reachable pinned address. The hostname is never
/// consulted here — only addresses that already passed the policy check.
fn connect_pinned(pinned: &Pinned, timeout: Duration) -> Option<TcpStream> {
    pinned
        .addrs
        .iter()
        .find_map(|ip| TcpStream::connect_timeout(&SocketAddr::new(*ip, pinned.port), timeout).ok())
}

/// Write a short plain-text response, then let the client finish before closing
/// so it can read the status instead of a reset.
fn respond(client: &mut TcpStream, status: u16, reason: &str, body: &str) {
    let body = format!("{body}\n");
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    if client.write_all(head.as_bytes()).is_ok() && client.write_all(body.as_bytes()).is_ok() {
        let _ = client.shutdown(Shutdown::Write);
        let _ = client.set_read_timeout(Some(Duration::from_millis(500)));
        let mut sink = [0u8; 1024];
        for _ in 0..8 {
            match client.read(&mut sink) {
                Ok(n) if n > 0 => {}
                _ => break,
            }
        }
    }
}

/// Last time either direction moved bytes.
struct Liveness(Mutex<Instant>);

impl Liveness {
    fn touch(&self) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    fn idle(&self) -> Duration {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .elapsed()
    }
}

/// Copy bytes both ways until either side closes, the tunnel idles out, or
/// the proxy shuts down.
fn relay(client: TcpStream, upstream: TcpStream, shared: &Arc<Shared>) {
    let (Ok(client_rx), Ok(upstream_rx)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let live = Arc::new(Liveness(Mutex::new(Instant::now())));
    let back = {
        let (live, shared) = (Arc::clone(&live), Arc::clone(shared));
        thread::Builder::new()
            .name("ward-proxy-relay".into())
            .spawn(move || pump(upstream_rx, client, &live, &shared))
    };
    pump(client_rx, upstream, &live, shared);
    if let Ok(back) = back {
        let _ = back.join();
    }
}

fn pump(mut src: TcpStream, mut dst: TcpStream, live: &Liveness, shared: &Shared) {
    let _ = src.set_read_timeout(Some(POLL));
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                live.touch();
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if shared.shutting_down() || live.idle() > shared.idle_timeout {
                    break;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let _ = dst.shutdown(Shutdown::Write);
}

/// Convenience for callers that only need `io::Error` semantics.
impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Bind { source, .. } | Error::Spawn(source) => source,
        }
    }
}
