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
//!
//! A proxy can be **paused** ([`Handle::set_paused`], ADR-0019 §3): a new
//! connection is answered `503 paused by ward` before any of it is read, a
//! request already read is refused the same way before it is resolved or its
//! credential is injected, and the relays of established tunnels stop moving
//! bytes until the proxy is resumed. Bytes already handed to a socket are not
//! recalled; that is the boundary the security model states.

use std::collections::{HashMap, HashSet};
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
use crate::http::{self, ChunkTracker, Framing, Method, Parsed, Request};
use crate::observer::{Decision, Observer};
use crate::policy::{Pinned, Policy};
use crate::resolve::{Resolver, SystemResolver};

/// How often a relay loop wakes to check for shutdown or idleness.
/// Relay buffer size.
/// Read timeout on relayed sockets so a relay thread re-checks the shutdown flag.
const POLL: Duration = Duration::from_millis(250);
const RELAY_BUF: usize = 16 * 1024;
/// The body of every refusal while the proxy is paused.
pub const PAUSED_BODY: &str = "paused by ward";

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
    /// The gate that makes "stop accepting" and "announce one accepted
    /// connection" mutually exclusive; see [`Shared::close`] and
    /// [`Shared::announce`].
    announcing: Mutex<()>,
    paused: AtomicBool,
    /// Credential ids this proxy has been told to stop honoring (#245), and
    /// how many connections were already relaying with each at the moment it
    /// was revoked — decremented as they finish, never recalled (bytes
    /// already handed to a socket are not, per `docs/security-model.md`).
    /// One lock over both so a revoke and an in-flight count change can
    /// never interleave torn.
    revoked: Mutex<Revocation>,
}

/// See [`Shared::revoked`].
#[derive(Default)]
struct Revocation {
    ids: HashSet<u64>,
    in_flight: HashMap<u64, usize>,
}

impl Shared {
    fn shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    fn paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    /// Has credential `id` been revoked (#245)? Checked before a gateway
    /// request's scope, so a revoked credential is refused for the same
    /// reason it has no scope left at all: there is no authority to check.
    fn credential_revoked(&self, id: u64) -> bool {
        self.revoked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .ids
            .contains(&id)
    }

    /// One more connection is now relaying with credential `id` injected.
    fn enter_credential(&self, id: u64) {
        *self
            .revoked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .in_flight
            .entry(id)
            .or_insert(0) += 1;
    }

    /// That connection's relay ended.
    fn leave_credential(&self, id: u64) {
        let mut rev = self.revoked.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = rev.in_flight.get_mut(&id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                rev.in_flight.remove(&id);
            }
        }
    }

    /// Stop accepting — atomically with respect to announcing a connection.
    ///
    /// Raising the flag on its own is not enough for the invariant
    /// [`Handle::shutdown`] owes an observer. The acceptor reads the flag and then
    /// announces, and between those two steps it can be descheduled for arbitrarily
    /// long; a flag raised in that window is read too late, and the connection joins
    /// the observer's outstanding set after the observer was told nothing more could.
    /// Nothing else closed that window: the synthetic wake connection is a *latency*
    /// device, not a correctness one, and it does not even reach the acceptor once
    /// the socket file is gone.
    ///
    /// Raising it under the same gate the announcement holds leaves exactly two
    /// orders, and both are safe. Either the announcement got the gate first, in
    /// which case it has completed — the connection is in the observer's outstanding
    /// set — before this call can return; or this call got the gate first, in which
    /// case the announcement re-reads the flag under the gate, sees it set, and is
    /// abandoned with the connection it would have announced. There is no longer any
    /// interval in which the acceptor is past its last shutdown check and has not yet
    /// announced.
    ///
    /// The wait this can impose is bounded by the [`Observer`] contract, not by the
    /// network: the gate is held across one [`Observer::deciding`] call and nothing
    /// else — no I/O, no connection being served, no relay — and that call is
    /// required to be cheap and non-blocking.
    fn close(&self) {
        let _gate = self
            .announcing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.shutdown.store(true, Ordering::Release);
    }

    /// Announce one accepted connection to the observer, unless [`Shared::close`]
    /// got to the gate first — in which case this connection is not announced and
    /// not served, because its verdict would be one no observer is still listening
    /// for.
    fn announce(&self) -> Option<Pending> {
        let _gate = self
            .announcing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.shutting_down() {
            return None;
        }
        Some(Pending::take(&self.observer))
    }
}

/// `503 paused by ward`: the one answer a paused proxy gives.
fn refuse_paused<C: Conn>(client: &mut C) {
    respond(client, 503, "Service Unavailable", PAUSED_BODY);
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
            announcing: Mutex::new(()),
            paused: AtomicBool::new(false),
            revoked: Mutex::new(Revocation::default()),
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
/// restrict the node to `0600`. The listener blocks in `accept`; shutdown wakes
/// it with one connect, exactly like the TCP listener.
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
    if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
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

    /// Pause or resume the proxy (ADR-0019 §3). Paused, every new connection
    /// and every request not yet resolved is answered `503 paused by ward`, no
    /// credential is injected, and established relays hold their bytes.
    pub fn set_paused(&self, paused: bool) {
        self.shared.paused.store(paused, Ordering::Release);
    }

    /// Whether the proxy is paused.
    pub fn paused(&self) -> bool {
        self.shared.paused()
    }

    /// Does this proxy hold a gateway route carrying grant `id` (#245)? The
    /// seam a caller applying a revoke instruction uses to tell whether
    /// *this* launch's proxy is the one that must act on it — a session's
    /// other, concurrent launches may hold routes of their own, tagged with
    /// different ids, and must not be disturbed by this one's revoke.
    pub fn has_credential_route(&self, id: u64) -> bool {
        self.shared
            .gateways
            .iter()
            .any(|g| g.credential_id() == Some(id))
    }

    /// Stop honoring credential `id` for any request not already relaying
    /// (#245): from this call on, a route carrying it answers `403` instead
    /// of injecting it. Returns how many connections were already relaying
    /// with it injected at the instant of revocation — the module doc's
    /// stated boundary is that bytes already handed to a socket are not
    /// recalled, so those connections are not stopped, only ever reported
    /// honestly instead of the revoke being silently treated as though
    /// nothing was still using the credential. `None` when this proxy holds
    /// no route for `id` at all, which the caller must not read as "nothing
    /// to withdraw" for the grant as a whole — only the daemon, which knows
    /// every launch of the session, can say that.
    pub fn revoke_credential(&self, id: u64) -> Option<usize> {
        if !self.has_credential_route(id) {
            return None;
        }
        let mut rev = self
            .shared
            .revoked
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        rev.ids.insert(id);
        Some(rev.in_flight.get(&id).copied().unwrap_or(0))
    }

    /// Stop accepting, ask every relay to wind down, join the acceptor when it can
    /// be woken, and (for a Unix listener) unlink the socket file. Idempotent.
    ///
    /// **When this returns, no further connection can be announced** to the
    /// observer through [`Observer::deciding`]. That is the invariant an observer
    /// accounting for gaps seals on: whatever it still has outstanding when
    /// `shutdown` has returned is exactly what may still be decided, and it can
    /// charge the rest as a gap without a later connection sneaking into the set
    /// behind it.
    ///
    /// The guarantee is [`Shared::close`]'s, taken before anything below runs, and
    /// it holds unconditionally. The wake connection and the join are latency, not
    /// correctness: the wake gets the acceptor out of a blocking `accept` promptly
    /// when it lands, but it needs the listening socket to still be reachable — a
    /// Unix socket file unlinked behind us is not — so neither it nor the join it
    /// enables can be what the invariant rests on. An acceptor that could not be
    /// woken is left parked in `accept`; it holds nothing but the listener, it can
    /// no longer announce anything, and it ends with the process.
    pub fn shutdown(&self) {
        // Atomic against the acceptor's announcement, so there is no window in
        // which a connection is announced after this has been observed.
        self.shared.close();
        let acceptor = self
            .acceptor
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(acceptor) = acceptor else { return };
        // Wake the acceptor so it observes the flag now: both listeners block
        // in `accept`.
        let woken = match &self.bound {
            Listen::Tcp(addr) => TcpStream::connect_timeout(addr, Duration::from_secs(1)).is_ok(),
            Listen::Unix(path) => UnixStream::connect(path).is_ok(),
        };
        if woken {
            let _ = acceptor.join();
        }
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

/// Leaves a gateway route's in-flight count decremented when dropped (#245):
/// the same shape as [`Slot`], but keyed by credential id rather than by
/// connection, and held only across a gateway exchange whose route carries
/// one. What [`Shared::credential_revoked`] and [`Handle::revoke_credential`]
/// account against.
struct CredentialSlot(Arc<Shared>, u64);

impl CredentialSlot {
    fn acquire(shared: &Arc<Shared>, id: u64) -> Self {
        shared.enter_credential(id);
        Self(Arc::clone(shared), id)
    }
}

impl Drop for CredentialSlot {
    fn drop(&mut self) {
        self.0.leave_credential(self.1);
    }
}

/// One accepted connection's outstanding verdict.
///
/// Taken on the acceptor thread before the connection is served and retired
/// exactly once — by [`report`](Pending::report) when the connection reached a
/// verdict, and by the drop otherwise, whatever path serving it left by
/// (an unparsable head, a paused proxy, a thread that could not be spawned, an
/// unwind).
///
/// It is deliberately **not** the connection's lifetime: it ends at the verdict,
/// so a tunnel that goes on relaying for minutes after being allowed is not an
/// outstanding decision. An observer accounting for gaps needs "not decided
/// yet", not "still connected" — reading the latter for the former reports a
/// connection whose decision is already recorded as if it had been lost.
struct Pending {
    observer: Arc<dyn Observer>,
    /// Whether the observer asked to be told how this one ends.
    tracked: bool,
    /// Whether the verdict has been reported, so the drop does not retire it twice.
    reported: bool,
}

impl Pending {
    /// Announce one accepted connection to `observer`.
    fn take(observer: &Arc<dyn Observer>) -> Self {
        Self {
            observer: Arc::clone(observer),
            tracked: observer.deciding(),
            reported: false,
        }
    }

    /// Report this connection's one verdict and retire it.
    fn report(&mut self, req: &Request, decision: Decision, reason: &str) {
        self.reported = true;
        if self.tracked {
            self.observer.decided(req, decision, reason);
        } else {
            self.observer.decision(req, decision, reason);
        }
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if self.tracked && !self.reported {
            self.observer.undecided();
        }
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
        Ok(stream)
    }
}

fn accept_loop<L: Acceptor>(listener: &L, shared: &Arc<Shared>) {
    loop {
        if shared.shutting_down() {
            break;
        }
        let Ok(mut client) = listener.accept() else {
            continue;
        };
        // The shutdown flag is set before the connect that wakes this loop out of
        // `accept`, so a connection that arrives with it already set is either that
        // wake or a client that missed the close by a hair. Neither is served: the
        // wake is not a request at all, and serving one here would announce a
        // verdict that will never come to an observer that is winding down.
        if shared.shutting_down() {
            continue;
        }
        if shared.paused() {
            refuse_paused(&mut client);
            continue;
        }
        let Some(slot) = Slot::acquire(shared) else {
            respond(&mut client, 503, "Service Unavailable", "proxy at capacity");
            continue;
        };
        // Announced here, on the acceptor thread rather than on the connection
        // thread, and under the gate `Handle::shutdown` closes: an observer that has
        // seen `shutdown` return knows no further connection can be announced, so
        // what it still has outstanding is exactly what may still be decided. The
        // check above is only a fast path — this is the one that decides, and it
        // cannot be overtaken by a shutdown, whatever the acceptor was descheduled
        // for in between.
        let Some(pending) = shared.announce() else {
            // The shutdown won the gate. Nothing was announced, so there is no
            // verdict owed for this connection; the slot and the stream go back.
            drop(slot);
            continue;
        };
        let shared = Arc::clone(shared);
        let spawned = thread::Builder::new()
            .name("ward-proxy-conn".into())
            .spawn(move || {
                let _slot = slot;
                serve(client, &shared, pending);
            });
        // On spawn failure the closure — and with it the stream, the slot and the
        // outstanding verdict — is dropped, which closes the connection, frees the
        // slot and retires the connection as undecided.
        drop(spawned);
    }
}

/// Why a gateway request must be refused before it is resolved, connected to
/// or has its credential read — the observer's reason, and the body text —
/// or `None` when it may proceed: a revoked credential (#245) is checked
/// first, since there is no authority left for anything to be in or out of
/// scope of; a request outside the route's scope is checked next, exactly as
/// it always was.
fn gateway_refusal(
    route: &GatewayRoute,
    req: &Request,
    shared: &Shared,
) -> Option<(String, &'static str)> {
    if let Some(id) = route.credential_id()
        && shared.credential_revoked(id)
    {
        return Some((
            format!("gateway {}: credential revoked", route.prefix()),
            "credential revoked",
        ));
    }
    if let Method::Forward { verb, path } = &req.method
        && let Err(denial) = route.permits(verb, path)
    {
        return Some((
            format!("gateway {}: {denial}", route.prefix()),
            "request outside credential scope",
        ));
    }
    None
}

/// Serve exactly one request on `client`.
///
/// `pending` is this connection's outstanding verdict: every return below either
/// reports one through it or drops it, which retires the connection as undecided.
fn serve<C: Conn>(mut client: C, shared: &Arc<Shared>, mut pending: Pending) {
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
    // A pause that landed while the head was in flight: nothing is resolved,
    // connected or injected for it.
    if shared.paused() {
        return refuse_paused(&mut client);
    }
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
    // A revoked credential (#245) or one outside its route's scope: neither
    // is resolved, connected to or ever gets its secret read. Checked before
    // anything else so a refused request never reaches the upstream.
    if let Some(route) = gateway
        && let Some((reason, body)) = gateway_refusal(route, req, shared)
    {
        pending.report(req, Decision::Deny, &reason);
        return respond(&mut client, 403, "Forbidden", body);
    }
    let resolver = shared.resolver.as_ref();
    let pinned = match gateway.map_or_else(
        || shared.policy.evaluate(resolver, &req.target),
        |_| shared.policy.evaluate_gateway(resolver, &req.target),
    ) {
        Ok(pinned) => pinned,
        Err(denial) => {
            pending.report(req, Decision::Deny, &denial.to_string());
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
    pending.report(req, Decision::Allow, &reason);
    // The verdict is in, so this connection is no longer outstanding: everything
    // below is the relay, which may run for as long as the tunnel lives without
    // that ever being a decision still to be made.
    drop(pending);
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
        // Held across the whole exchange, however long it relays for (an SSE
        // stream can run for minutes): what a revoke landing mid-exchange
        // reports as still in flight (#245) is this, not `active_connections`,
        // which tracks a connection regardless of whether it ever carried a
        // credential at all.
        let _credential = route
            .credential_id()
            .map(|id| CredentialSlot::acquire(shared, id));
        serve_gateway(
            client,
            upstream,
            route,
            &parsed,
            framing,
            &head.remainder,
            shared,
        );
        return;
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
    // The last check before the credential leaves the host. A revoke that
    // landed while DNS resolution/TCP connect/TLS handshake were still in
    // flight — a window `CredentialSlot::acquire` (taken only after the TCP
    // connect succeeds, in `serve`) does not yet cover — must still stop the
    // credential from being injected, exactly as `gateway_refusal`'s earlier
    // check does for a revoke that lands before any of that starts.
    if shared.paused() {
        return refuse_paused(&mut client);
    }
    if let Some(id) = route.credential_id()
        && shared.credential_revoked(id)
    {
        return respond(&mut client, 403, "Forbidden", "credential revoked");
    }
    let head = match route.rewrite_head(parsed, framing) {
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
        // Paused: hold the bytes where they are (the kernel's buffers fill and
        // TCP flow control does the rest) until resume or shutdown.
        if shared.paused() {
            if shared.shutting_down() {
                return Err(io::Error::from(ErrorKind::TimedOut));
            }
            thread::sleep(POLL);
            continue;
        }
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

    /// ADR-0019 §3: while paused the proxy answers every new connection with
    /// `503 paused by ward` before reading a byte of it, and takes requests
    /// again the moment it is resumed.
    #[test]
    fn a_paused_proxy_refuses_new_requests_and_resumes_cleanly() {
        let path = socket_path("paused");
        let handle = spawn_unix(&path).unwrap();
        assert!(!handle.paused());
        let ask = |path: &Path| {
            let mut s = UnixStream::connect(path).unwrap();
            s.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                .unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out
        };
        handle.set_paused(true);
        assert!(handle.paused());
        let out = ask(&path);
        assert!(
            out.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
            "{out}"
        );
        assert!(out.ends_with("\r\n\r\npaused by ward\n"), "{out}");
        handle.set_paused(false);
        let out = ask(&path);
        assert!(out.starts_with("HTTP/1.1 403 "), "offline denies: {out}");
        handle.shutdown();
    }

    #[test]
    fn missing_parent_directory_is_refused() {
        let path = socket_path("missing").join("nested").join("proxy.sock");
        let err = spawn_unix(&path).unwrap_err();
        assert!(matches!(err, Error::BindUnix { ref path, .. } if path.ends_with("proxy.sock")));
        assert_eq!(io::Error::from(err).kind(), ErrorKind::NotFound);
    }
}
