//! The listener, connection threads and byte relay.
//!
//! One acceptor thread hands each connection to its own thread, bounded by
//! [`Config::max_connections`]; a tunnel uses a second thread for the return
//! direction. Everything is blocking std I/O with timeouts, so shutdown is a
//! flag the relay loops poll rather than a cancellation token.
//!
//! Clients arrive over TCP or over a Unix-domain socket
//! ([`Config::listen_unix`]) — the latter is what a sandbox with its own
//! network namespace is handed, bind-mounted in. Both transports share one
//! connection handler through the private [`Conn`] trait; upstream
//! connections are always TCP to pinned addresses.
//!
//! A request that matches a [`GatewayRoute`] takes a third path: the head is
//! rewritten with the credential injected, the body is forwarded by its
//! framing, and the response is streamed back byte-for-byte as it arrives
//! (so SSE from a model API is never buffered) — see [`serve_gateway`].

use std::fmt;
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ward_policy::NetworkCapability;

use crate::error::Error;
use crate::gateway::{GatewayRoute, Upstream};
use crate::http::{self, ChunkTracker, Framing, Method, Parsed};
use crate::observer::{Decision, Observer};
use crate::policy::{Pinned, Policy};
use crate::resolve::{Resolver, SystemResolver};

/// How often a relay loop wakes to check for shutdown or idleness.
const POLL: Duration = Duration::from_millis(250);
/// Relay buffer size.
const RELAY_BUF: usize = 16 * 1024;

/// Where clients are accepted from. Also records what was actually bound.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Listen {
    /// A TCP listener; port `0` requests a free port.
    Tcp(SocketAddr),
    /// A Unix-domain socket at this path, mode `0600`, unlinked on shutdown.
    Unix(PathBuf),
}

/// Proxy configuration. Build with [`Config::new`] and the setters.
#[derive(Clone)]
pub struct Config {
    listen: Listen,
    capability: NetworkCapability,
    resolver: Arc<dyn Resolver>,
    max_connections: usize,
    request_timeout: Duration,
    connect_timeout: Duration,
    idle_timeout: Duration,
    allow_loopback: bool,
    gateways: Vec<GatewayRoute>,
}

impl Config {
    /// Defaults: listen on `127.0.0.1:0`, system resolver, 64 connections,
    /// 15 s to send a request head, 10 s to connect upstream, 5 min idle,
    /// no gateway routes.
    pub fn new(capability: NetworkCapability) -> Self {
        Self {
            listen: Listen::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            capability,
            resolver: Arc::new(SystemResolver),
            max_connections: 64,
            request_timeout: Duration::from_secs(15),
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            allow_loopback: false,
            gateways: Vec::new(),
        }
    }

    /// Add a gateway route (repeatable). Routes are tried in the order added;
    /// the first whose prefix matches a forward request's path wins. The
    /// route's upstream still has to pass the session policy.
    #[must_use]
    pub fn gateway(mut self, route: GatewayRoute) -> Self {
        self.gateways.push(route);
        self
    }

    /// TCP address to listen on (the default transport). Port `0` picks a
    /// free port; see [`Handle::local_addr`]. Replaces any [`Self::listen_unix`].
    #[must_use]
    pub fn listen(mut self, addr: SocketAddr) -> Self {
        self.listen = Listen::Tcp(addr);
        self
    }

    /// Listen on a Unix-domain socket at `path` instead of TCP, so the daemon
    /// can bind-mount the socket into a sandbox whose network namespace cannot
    /// reach the host loopback. The parent directory must exist; a stale
    /// socket file there is replaced, any other file is an error. The socket
    /// is created mode `0600` and unlinked by [`Handle::shutdown`].
    #[must_use]
    pub fn listen_unix(mut self, path: impl Into<PathBuf>) -> Self {
        self.listen = Listen::Unix(path.into());
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
            .field("gateways", &self.gateways)
            .finish_non_exhaustive()
    }
}

/// State shared between the acceptor and every connection thread.
struct Shared {
    policy: Policy,
    resolver: Arc<dyn Resolver>,
    observer: Arc<dyn Observer>,
    gateways: Vec<GatewayRoute>,
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
    /// bound, so [`Handle::local_addr`] / [`Handle::unix_path`] are
    /// immediately usable.
    pub fn spawn(config: Config, observer: Arc<dyn Observer>) -> Result<Handle, Error> {
        let policy = config.policy();
        let shared = Arc::new(Shared {
            policy,
            resolver: config.resolver,
            observer,
            gateways: config.gateways,
            max_connections: config.max_connections,
            request_timeout: config.request_timeout,
            connect_timeout: config.connect_timeout,
            idle_timeout: config.idle_timeout,
            active: AtomicUsize::new(0),
            shutdown: AtomicBool::new(false),
        });
        let (bound, acceptor) = match config.listen {
            Listen::Tcp(addr) => {
                let bind_err = |source| Error::Bind { addr, source };
                let listener = TcpListener::bind(addr).map_err(bind_err)?;
                let local = listener.local_addr().map_err(bind_err)?;
                (Listen::Tcp(local), spawn_acceptor(listener, &shared)?)
            }
            Listen::Unix(path) => {
                let listener = bind_unix(&path)?;
                let acceptor = spawn_acceptor(listener, &shared);
                if acceptor.is_err() {
                    let _ = fs::remove_file(&path);
                }
                (Listen::Unix(path), acceptor?)
            }
        };
        Ok(Handle {
            bound,
            shared,
            acceptor: Mutex::new(Some(acceptor)),
        })
    }
}

fn spawn_acceptor<L: Acceptor>(listener: L, shared: &Arc<Shared>) -> Result<JoinHandle<()>, Error> {
    let shared = Arc::clone(shared);
    thread::Builder::new()
        .name("ward-proxy-accept".into())
        .spawn(move || accept_loop(&listener, &shared))
        .map_err(Error::Spawn)
}

/// Create the Unix listening socket: replace a stale socket file, bind, and
/// restrict the node to `0600`. The listener is left non-blocking so the
/// accept loop can poll the shutdown flag instead of parking in `accept`.
fn bind_unix(path: &Path) -> Result<UnixListener, Error> {
    let err = |source| Error::BindUnix {
        path: path.to_path_buf(),
        source,
    };
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(path).map_err(err)?,
        Ok(_) => {
            return Err(err(io::Error::new(
                ErrorKind::AlreadyExists,
                "path exists and is not a socket",
            )));
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(err(e)),
    }
    // A missing parent surfaces here as `NotFound`; nothing is created.
    let listener = UnixListener::bind(path).map_err(err)?;
    let secured = fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .and_then(|()| listener.set_nonblocking(true));
    if let Err(e) = secured {
        let _ = fs::remove_file(path);
        return Err(err(e));
    }
    Ok(listener)
}

/// A running proxy. Dropping it shuts the listener down.
pub struct Handle {
    bound: Listen,
    shared: Arc<Shared>,
    acceptor: Mutex<Option<JoinHandle<()>>>,
}

impl Handle {
    /// The bound TCP listening address; `None` for a Unix-socket listener.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        match &self.bound {
            Listen::Tcp(addr) => Some(*addr),
            Listen::Unix(_) => None,
        }
    }

    /// The Unix-socket path being listened on; `None` for a TCP listener.
    pub fn unix_path(&self) -> Option<&Path> {
        match &self.bound {
            Listen::Unix(path) => Some(path),
            Listen::Tcp(_) => None,
        }
    }

    /// Connections currently being served.
    pub fn active_connections(&self) -> usize {
        self.shared.active.load(Ordering::Acquire)
    }

    /// Stop accepting, ask every relay to wind down, join the acceptor and
    /// (for a Unix listener) unlink the socket file. Idempotent.
    pub fn shutdown(&self) {
        self.shared.shutdown.store(true, Ordering::Release);
        let acceptor = self
            .acceptor
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(acceptor) = acceptor else { return };
        // Wake the acceptor so it observes the flag now. The TCP listener
        // blocks in `accept`, so this is required; the Unix listener is
        // non-blocking and polls the flag anyway, so a failed connect (say
        // the file was removed behind our back) still cannot hang the join.
        match &self.bound {
            Listen::Tcp(addr) => {
                let _ = TcpStream::connect_timeout(addr, Duration::from_secs(1));
            }
            Listen::Unix(path) => {
                let _ = UnixStream::connect(path);
            }
        }
        let _ = acceptor.join();
        if let Listen::Unix(path) = &self.bound {
            let _ = fs::remove_file(path);
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
            .field("listen", &self.bound)
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

/// A client-side transport. What [`serve`] needs from a stream beyond
/// `Read + Write`, implemented for both `TcpStream` and `UnixStream` so the
/// two share one parsing, policy, relay and timeout path.
trait Conn: Read + Write + Send + Sized + 'static {
    fn try_clone(&self) -> io::Result<Self>;
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
}

impl Conn for TcpStream {
    fn try_clone(&self) -> io::Result<Self> {
        Self::try_clone(self)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        Self::set_read_timeout(self, timeout)
    }
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        Self::shutdown(self, how)
    }
}

impl Conn for UnixStream {
    fn try_clone(&self) -> io::Result<Self> {
        Self::try_clone(self)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        Self::set_read_timeout(self, timeout)
    }
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        Self::shutdown(self, how)
    }
}

/// A listening socket yielding [`Conn`]s. `WouldBlock` from `accept` means
/// "nothing yet" and makes [`accept_loop`] poll the shutdown flag.
trait Acceptor: Send + 'static {
    type Conn: Conn;
    fn accept(&self) -> io::Result<Self::Conn>;
}

impl Acceptor for TcpListener {
    type Conn = TcpStream;
    fn accept(&self) -> io::Result<TcpStream> {
        let (stream, _) = Self::accept(self)?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }
}

impl Acceptor for UnixListener {
    type Conn = UnixStream;
    fn accept(&self) -> io::Result<UnixStream> {
        let (stream, _) = Self::accept(self)?;
        // The listener is non-blocking; the connection must not be, or the
        // per-connection read timeouts would never apply.
        stream.set_nonblocking(false)?;
        Ok(stream)
    }
}

fn accept_loop<L: Acceptor>(listener: &L, shared: &Arc<Shared>) {
    loop {
        if shared.shutting_down() {
            break;
        }
        let mut client = match listener.accept() {
            Ok(client) => client,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(POLL);
                continue;
            }
            Err(_) => continue,
        };
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
fn serve<C: Conn>(mut client: C, shared: &Arc<Shared>) {
    let _ = client.set_read_timeout(Some(shared.request_timeout));
    let head = match http::read_head(&mut client) {
        Ok(Ok(head)) => head,
        Ok(Err(e)) => return respond(&mut client, 400, "Bad Request", &e.to_string()),
        Err(_) => return,
    };
    let parsed = match http::parse(&head.bytes) {
        Ok(parsed) => parsed,
        Err(e) => return respond(&mut client, 400, "Bad Request", &e.to_string()),
    };
    // A gateway route replaces the destination; an origin-form request that
    // matches none is not a proxy request at all.
    let gateway = shared.gateways.iter().find(|g| g.matches(&parsed));
    if gateway.is_none() && parsed.origin_form {
        return respond(
            &mut client,
            400,
            "Bad Request",
            "proxy requires an absolute http:// URI",
        );
    }
    let framing = match gateway.map(|_| http::body_framing(&parsed)) {
        Some(Ok(framing)) => framing,
        Some(Err(e)) => return respond(&mut client, 400, "Bad Request", &e.to_string()),
        None => Framing::None,
    };
    let req = &gateway.map_or_else(|| parsed.request.clone(), |g| g.request(&parsed));
    let resolver = shared.resolver.as_ref();
    let pinned = match gateway.map_or_else(
        || shared.policy.evaluate(resolver, &req.target),
        |_| shared.policy.evaluate_gateway(resolver, &req.target),
    ) {
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
    let reason = gateway.map_or_else(
        || format!("pinned {}", pinned_list(&pinned)),
        |g| format!("gateway {}", g.prefix()),
    );
    shared.observer.decision(req, Decision::Allow, &reason);
    let Some(mut upstream) = connect_pinned(&pinned, shared.connect_timeout) else {
        return respond(
            &mut client,
            502,
            "Bad Gateway",
            "upstream connection failed",
        );
    };
    let _ = upstream.set_nodelay(true);
    if let Some(route) = gateway {
        return serve_gateway(
            client,
            upstream,
            route,
            &parsed,
            framing,
            &head.remainder,
            shared,
        );
    }
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

/// One gateway exchange: TLS to the pinned address, the rewritten head with
/// the credential injected, the request body by its framing, then the
/// response streamed back until the upstream closes. `first` is whatever the
/// client sent after its head.
fn serve_gateway<C: Conn>(
    mut client: C,
    tcp: TcpStream,
    route: &GatewayRoute,
    parsed: &Parsed,
    framing: Framing,
    first: &[u8],
    shared: &Shared,
) {
    let Ok(mut upstream) = route.connect(tcp, shared.connect_timeout) else {
        return respond(
            &mut client,
            502,
            "Bad Gateway",
            "upstream TLS handshake failed",
        );
    };
    let head = match route.rewrite_head(parsed) {
        Ok(head) => head,
        Err(reason) => return respond(&mut client, 502, "Bad Gateway", reason),
    };
    let sent = upstream.write_all(&head).and_then(|()| upstream.flush());
    drop(head);
    if sent.is_err() {
        return;
    }
    let expects_continue = parsed.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("expect") && h.value.eq_ignore_ascii_case("100-continue")
    });
    if expects_continue && client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").is_err() {
        return;
    }
    let live = Liveness(Mutex::new(Instant::now()));
    let _ = client.set_read_timeout(Some(POLL));
    if send_body(&mut client, &mut upstream, framing, first, &live, shared).is_err() {
        return;
    }
    let _ = upstream.socket().set_read_timeout(Some(POLL));
    let _ = copy_stream(&mut upstream, &mut client, &live, shared);
    let _ = client.shutdown(Shutdown::Write);
}

/// Forward the request body: `first` (already read) followed by the client
/// stream, delimited by `framing`.
fn send_body<C: Conn>(
    client: &mut C,
    upstream: &mut Upstream,
    framing: Framing,
    first: &[u8],
    live: &Liveness,
    shared: &Shared,
) -> io::Result<()> {
    let source = first.chain(client);
    match framing {
        Framing::None => Ok(()),
        Framing::Length(n) => {
            let mut limited = source.take(n as u64);
            copy_stream(&mut limited, upstream, live, shared)?;
            if limited.limit() == 0 {
                Ok(())
            } else {
                Err(io::Error::from(ErrorKind::UnexpectedEof))
            }
        }
        Framing::Chunked => {
            let mut body = ChunkedBody {
                inner: source,
                tracker: ChunkTracker::new(),
            };
            copy_stream(&mut body, upstream, live, shared)
        }
    }
}

/// A reader that ends at the terminating chunk of a chunked body while
/// passing the framing bytes through untouched.
struct ChunkedBody<R> {
    inner: R,
    tracker: ChunkTracker,
}

impl<R: Read> Read for ChunkedBody<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.tracker.done() {
            return Ok(0);
        }
        let n = self.inner.read(buf)?;
        if n == 0 {
            return Err(io::Error::from(ErrorKind::UnexpectedEof));
        }
        // Bytes past the end of the body (a pipelined request) are dropped.
        self.tracker
            .feed(&buf[..n])
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
    }
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
fn respond<C: Conn>(client: &mut C, status: u16, reason: &str, body: &str) {
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
fn relay<C: Conn>(client: C, upstream: TcpStream, shared: &Arc<Shared>) {
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

fn pump<S: Conn, D: Conn>(mut src: S, mut dst: D, live: &Liveness, shared: &Shared) {
    let _ = src.set_read_timeout(Some(POLL));
    let _ = copy_stream(&mut src, &mut dst, live, shared);
    let _ = dst.shutdown(Shutdown::Write);
}

/// Copy `src` to `dst` as bytes arrive until `src` reaches EOF. `src` must
/// have a read timeout of [`POLL`]: each timeout is a chance to notice
/// shutdown or an idle tunnel, both of which end the copy with `TimedOut`.
fn copy_stream<S: Read + ?Sized, D: Write + ?Sized>(
    src: &mut S,
    dst: &mut D,
    live: &Liveness,
    shared: &Shared,
) -> io::Result<()> {
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        match src.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                live.touch();
                dst.write_all(&buf[..n])?;
                dst.flush()?;
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if shared.shutting_down() || live.idle() > shared.idle_timeout {
                    return Err(io::Error::from(ErrorKind::TimedOut));
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            // A TLS peer that closes without `close_notify` is still EOF.
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

/// Convenience for callers that only need `io::Error` semantics.
impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Bind { source, .. } | Error::BindUnix { source, .. } | Error::Spawn(source) => {
                source
            }
            Error::InvalidGateway { .. } => Self::new(ErrorKind::InvalidInput, e),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::observer::NullObserver;

    fn socket_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("wp-unit-{tag}-{}.sock", std::process::id()))
    }

    fn spawn_unix(path: &Path) -> Result<Handle, Error> {
        let config = Config::new(NetworkCapability::Offline).listen_unix(path);
        Proxy::spawn(config, Arc::new(NullObserver))
    }

    #[test]
    fn listen_defaults_to_tcp_and_the_setters_switch_transport() {
        let config = Config::new(NetworkCapability::Offline);
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        assert_eq!(config.listen, Listen::Tcp(loopback));
        let config = config.listen_unix("/run/ward/proxy.sock");
        assert_eq!(
            config.listen,
            Listen::Unix(PathBuf::from("/run/ward/proxy.sock"))
        );
        assert!(format!("{config:?}").contains("proxy.sock"));
        let tcp: SocketAddr = "127.0.0.1:3128".parse().unwrap();
        assert_eq!(config.listen(tcp).listen, Listen::Tcp(tcp));
    }

    #[test]
    fn unix_socket_is_private_and_unlinked_on_shutdown() {
        let path = socket_path("mode");
        let handle = spawn_unix(&path).unwrap();
        assert_eq!(handle.local_addr(), None);
        assert_eq!(handle.unix_path(), Some(path.as_path()));
        let meta = fs::metadata(&path).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert!(format!("{handle:?}").contains("Unix"));
        handle.shutdown();
        assert!(!path.exists());
        handle.shutdown();
    }

    #[test]
    fn stale_socket_is_replaced_but_other_files_are_not() {
        let path = socket_path("stale");
        // Dropping a listener leaves its socket node behind.
        drop(UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        drop(spawn_unix(&path).unwrap());
        assert!(!path.exists());

        fs::write(&path, b"not a socket").unwrap();
        let err = spawn_unix(&path).unwrap_err();
        assert!(matches!(err, Error::BindUnix { .. }), "{err}");
        assert_eq!(fs::read(&path).unwrap(), b"not a socket");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn missing_parent_directory_is_refused() {
        let path = socket_path("missing").join("nested").join("proxy.sock");
        let err = spawn_unix(&path).unwrap_err();
        assert!(matches!(err, Error::BindUnix { ref path, .. } if path.ends_with("proxy.sock")));
        assert_eq!(io::Error::from(err).kind(), ErrorKind::NotFound);
    }
}
