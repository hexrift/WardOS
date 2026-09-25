//! `wardd serve`: the per-session daemon of ADR-0015.
//!
//! One process owns a session's chain and [`LogWriter`](ward_events::LogWriter)
//! and listens on `sessions/<id>/control.sock`. Every connection is served on its
//! own thread; requests are applied one at a time under a mutex around the
//! [`LocalLog`], so the chain has exactly one writer. A [`Request::Subscribe`]
//! turns its connection into a stream: the records already in the log from
//! `from_seq` (read back with [`LogReader`]), then every record appended after
//! that, in order, until the client hangs up or the log is sealed. The switch
//! from replay to live happens under the same mutex as appends, so a subscriber
//! sees no gap and no duplicate at the boundary.
//!
//! When a request seals the log ([`Request::Seal`] or [`Request::Stop`]) the daemon
//! stops accepting, finishes in-flight responses, unlinks the socket and the pid
//! file, and returns; the binary exits 0.
//!
//! [`Request::Pause`] and [`Request::Resume`] are the host's intervention
//! (ADR-0019 §3, [`crate::pause`]): one operation under the mutex that freezes
//! the sandboxes, writes the marker the proxies refuse on, holds the approvals
//! and appends the record; a `Stop` from paused kills the frozen tree first, so
//! nothing is left stopped forever, and the workspace is kept as it is. Freezing
//! a sandbox by signal (no delegated cgroup freezer available) is asynchronous —
//! `SIGSTOP` is delivered by the kernel, not observed to land — so `Request::Pause`
//! waits up to [`pause::FREEZE_SETTLE`] to confirm every process actually stopped
//! before answering; on success this is invisible, on failure the marker and held
//! approvals still stand (the safest state) but the response and the log both say
//! plainly that the freeze was not confirmed (#145 items 3-4).
//!
//! `ward up` starts the daemon with [`spawn`] and `ward status` asks [`serving`];
//! every other command adopts the socket through
//! [`Session::open_current`](crate::session::Session::open_current).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ward_events::{EventRecord, LogReader, Origin, Pid, RevokeReason, ServiceId, ShortText, WardEvent};

use crate::approvals::{self, Approval, Approvals, Deriver, Outcome};
use crate::control::{self, LocalLog, RemoteSink, Request, Response, SOCKET_NAME};
use crate::error::{Error, Result};
use crate::pause::{self, Frozen};
use crate::revoke;
use crate::session::{SessionMeta, protected_paths, session_dir};

/// File name of the daemon's pid file inside `sessions/<id>/`.
pub const PID_NAME: &str = "wardd.pid";
/// How long `ward up` waits for a spawned daemon to answer.
pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(2);
/// Name of the daemon binary.
pub const BINARY: &str = "wardd";
/// Longest socket path Linux accepts (`sun_path` is 108 bytes with the NUL).
pub const MAX_SOCKET_PATH: usize = 107;

/// Largest control-socket request line accepted. The protocol's requests are
/// small JSON objects; a client that streams bytes without a newline would
/// otherwise grow the read buffer without bound (an out-of-memory / abort
/// vector from a same-user client). 1 MiB is far above any real request.
pub const MAX_REQUEST_BYTES: u64 = 1 << 20;

/// A request line hit the [`MAX_REQUEST_BYTES`] cap without a terminating
/// newline — a truncated, oversized line that must be rejected, not parsed.
pub(crate) fn request_too_large(line: &str) -> bool {
    line.len() as u64 >= MAX_REQUEST_BYTES && !line.ends_with('\n')
}

/// The control socket of `session` under `state`.
#[must_use]
pub fn socket_path(state: &Path, session: &str) -> PathBuf {
    session_dir(state, session).join(SOCKET_NAME)
}

/// The pid file of `session`'s daemon under `state`.
#[must_use]
pub fn pid_path(state: &Path, session: &str) -> PathBuf {
    session_dir(state, session).join(PID_NAME)
}

/// Whether a daemon answers a `Ping` on `session`'s control socket.
#[must_use]
pub fn serving(state: &Path, session: &str) -> bool {
    RemoteSink::connect(&socket_path(state, session)).is_some()
}

/// Every session under `state` whose daemon answers, newest first: the pool a
/// desktop-wide surface (the bar, the switcher, `wardos-approve --watch`
/// multiplexing every live session's approvals, #141) draws from when it is
/// not asking about one particular project. Sessions whose record cannot be
/// read are skipped. Ties (equal `started_unix_ms`) keep directory-listing
/// order rather than being resorted, so which one counts "newest" among them
/// is at least stable within one process.
pub fn live_sessions(state: &Path) -> Result<Vec<SessionMeta>> {
    let sessions = state.join("sessions");
    let entries = match std::fs::read_dir(&sessions) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(&sessions, e)),
    };
    let mut live = Vec::new();
    for entry in entries.flatten() {
        let id = entry.file_name().to_string_lossy().into_owned();
        let Ok(meta) = SessionMeta::load(state, &id) else {
            continue;
        };
        if serving(state, &id) {
            live.push(meta);
        }
    }
    live.sort_by(|a, b| b.started_unix_ms.cmp(&a.started_unix_ms));
    Ok(live)
}

/// The newest session under `state` whose daemon answers: the desktop's
/// session when it is asked from somewhere that is not a project (the bar,
/// the approval listener), before #141's shared selection narrowed most of
/// those callers to [`live_sessions`] instead. Sessions whose record cannot be
/// read are skipped.
pub fn newest_live(state: &Path) -> Result<Option<SessionMeta>> {
    Ok(live_sessions(state)?.into_iter().next())
}

/// Serve `session`'s log on its control socket until a request seals it.
///
/// Reads `session.json` for the start time, resumes the chain from the log,
/// binds the socket (mode 0600, replacing a stale file nothing answers on),
/// writes `wardd.pid`, and serves connections concurrently. Returns once the log
/// is sealed and the socket and pid file are gone.
pub fn serve(state: &Path, session: &str) -> Result<()> {
    let meta = SessionMeta::load(state, session)?;
    let dir = session_dir(state, session);
    let log_path = dir.join("events.log");
    let started = UNIX_EPOCH + Duration::from_millis(meta.started_unix_ms);
    let mut log = LocalLog::open(&log_path, started)?;
    // #139 item 5, the literal ask: a daemon starting up is taking ownership of a
    // log a previous process (an earlier `wardd`, or a daemonless `ward` command)
    // may have left mid-verification-attempt — most often because that process
    // died or was killed. Reconcile any such dangling attempt into
    // `VerificationInterrupted` before serving a single connection, so a
    // subscriber never sees the eternal "running" spinner this issue is about,
    // even across a daemon restart. Fail closed (review of #208, finding 3): a
    // daemon that could not confirm a dangling attempt was actually closed out
    // must not start serving the session as though it had been — a client asking
    // for `Describe`/`Subscribe` right after would otherwise see whatever
    // half-reconciled state this left behind with nothing to say it is suspect.
    crate::attempt::reconcile_dangling_attempts(&mut log, &dir)?;
    let description = serde_json::to_value(meta.describe())
        .map_err(|e| Error::Daemon(format!("describe {session}: {e}")))?;
    // What an approval's authority is derived from: the manifest, the
    // repository a `current_repository` credential scope means, and the paths
    // TamperWard protects, all fixed at the session's start. The repository
    // is `meta.origin_repo`, resolved once when the session started and never
    // re-read from the live worktree (issue #196) — see
    // `github::resolve_origin_repo`.
    let deriver = Deriver::new(
        meta.manifest.clone(),
        meta.origin_repo.clone(),
        protected_paths(state, &meta.entry_snapshot),
    );

    let socket = dir.join(SOCKET_NAME);
    let listener = bind_socket(&socket)?;
    let bound_inode = std::fs::metadata(&socket).map(|m| m.ino()).ok();
    let pid_file = dir.join(PID_NAME);
    std::fs::write(&pid_file, format!("{}\n", std::process::id()))
        .map_err(|e| Error::io(&pid_file, e))?;

    // #151 item 5: a daemon starting up is also a good, cheap moment to sweep
    // whatever scratch other, already-finished sessions left behind — most
    // often because their own process was killed between finishing its work
    // and its normal cleanup. Unlike the dangling-attempt reconciliation
    // above, this is disk hygiene, not correctness, so it runs in its own
    // background thread rather than on this session's startup path: this
    // session's control socket is already bound by this point and can start
    // answering connections immediately, regardless of how large a sweep of
    // accumulated orphaned scratch elsewhere turns out to be. A failure (or
    // simply finding nothing to do) is silently discarded either way — see
    // `crate::reclaim`'s own module doc comment for the full safety argument
    // (never touching anything but a re-verified `Orphaned` entry).
    {
        let state = state.to_path_buf();
        std::thread::spawn(move || {
            let _ = crate::reclaim::reclaim_orphaned_scratch(&state);
        });
    }

    let served = Arc::new(Mutex::new(Served::new(
        log,
        log_path,
        description,
        deriver,
        state.to_path_buf(),
        session.to_owned(),
    )));
    let finished = Arc::new(AtomicBool::new(false));
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    let mut next_peer: u64 = 0;
    for stream in listener.incoming() {
        if finished.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = stream else {
            continue;
        };
        workers.retain(|w| !w.is_finished());
        let peer = next_peer;
        next_peer = next_peer.wrapping_add(1);
        if let Ok(clone) = stream.try_clone() {
            lock(&served).peers.push((peer, clone));
        }
        let served = Arc::clone(&served);
        let finished = Arc::clone(&finished);
        let socket = socket.clone();
        workers.push(std::thread::spawn(move || {
            let sealed = serve_stream(stream, &served, peer);
            {
                let mut served = lock(&served);
                served.peers.retain(|(id, _)| *id != peer);
                // The connection is gone: any launch it started that never
                // got a terminal record now never will (see `open_launches`'
                // doc comment). A no-op when `peer` has no open launches —
                // the common case.
                served.disconnect_open_launches(peer);
            }
            if sealed {
                finished.store(true, Ordering::SeqCst);
                // Wake the acceptor so it sees `finished`; the connection itself is
                // dropped unanswered.
                drop(UnixStream::connect(&socket));
            }
        }));
    }
    drop(listener);
    // Only remove what this process bound: a successor that replaced a stale
    // socket file owns the path now.
    if std::fs::metadata(&socket).map(|m| m.ino()).ok() == bound_inode {
        let _ = std::fs::remove_file(&socket);
    }
    let _ = std::fs::remove_file(&pid_file);
    // Idle connections are blocked reading their next request; end those reads
    // while letting a response still being written complete.
    for (_, peer) in lock(&served).peers.drain(..) {
        let _ = peer.shutdown(Shutdown::Read);
    }
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

/// Bind the control socket at `path` with mode 0600.
///
/// A socket file left behind by an earlier daemon (nothing answers a `Ping` on
/// it) is removed first; one that answers belongs to a running daemon and is an
/// error.
pub fn bind_socket(path: &Path) -> Result<UnixListener> {
    check_socket_path(path)?;
    if path.exists() {
        if RemoteSink::connect(path).is_some() {
            return Err(Error::Daemon(format!(
                "{}: another wardd is serving this session",
                path.display()
            )));
        }
        std::fs::remove_file(path).map_err(|e| Error::io(path, e))?;
    }
    let listener = UnixListener::bind(path).map_err(|e| Error::io(path, e))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::io(path, e))?;
    Ok(listener)
}

/// A socket path longer than [`MAX_SOCKET_PATH`] cannot be bound or connected
/// to; say so instead of timing out on a daemon that could never answer.
fn check_socket_path(path: &Path) -> Result<()> {
    let len = path.as_os_str().len();
    if len > MAX_SOCKET_PATH {
        return Err(Error::Daemon(format!(
            "{}: control socket path is {len} bytes, more than the {MAX_SOCKET_PATH} a Unix \
             socket allows; use a shorter WARD_STATE_DIR",
            path.display()
        )));
    }
    Ok(())
}

/// Locate the daemon binary: beside the running executable, else on `PATH`.
#[must_use]
pub fn find_binary() -> Option<PathBuf> {
    let beside = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    find_in(beside.as_deref(), std::env::var_os("PATH").as_deref())
}

/// [`find_binary`] over an explicit directory and `PATH` value.
fn find_in(beside: Option<&Path>, path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    beside
        .map(|dir| dir.join(BINARY))
        .filter(|p| p.is_file())
        .or_else(|| {
            path.and_then(|path| {
                std::env::split_paths(path)
                    .map(|dir| dir.join(BINARY))
                    .find(|p| p.is_file())
            })
        })
}

/// Start `wardd serve` for `session` as a detached process (its own process
/// group, no stdio) and wait up to [`STARTUP_TIMEOUT`] for its socket to answer.
///
/// Returns the socket path when the daemon answers, `Ok(None)` when no `wardd`
/// binary is found, and [`Error::Daemon`] when it was started but did not answer
/// in time.
pub fn spawn(state: &Path, session: &str) -> Result<Option<PathBuf>> {
    let Some(binary) = find_binary() else {
        return Ok(None);
    };
    let socket = socket_path(state, session);
    check_socket_path(&socket)?;
    let mut command = Command::new(&binary);
    command
        .arg("serve")
        .arg("--state")
        .arg(state)
        .arg("--session")
        .arg(session)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    // The child is not waited for: it outlives this command by design.
    let _child = command.spawn().map_err(|e| Error::io(&binary, e))?;
    if wait_until(STARTUP_TIMEOUT, || RemoteSink::connect(&socket).is_some()) {
        Ok(Some(socket))
    } else {
        Err(Error::Daemon(format!(
            "{} did not answer on {} within {:?}",
            binary.display(),
            socket.display(),
            STARTUP_TIMEOUT
        )))
    }
}

/// Wait up to `timeout` for `session`'s socket to disappear (the daemon exited).
pub fn wait_stopped(state: &Path, session: &str, timeout: Duration) -> bool {
    let socket = socket_path(state, session);
    wait_until(timeout, || !socket.exists())
}

/// Poll `ready` every 20 ms until it holds or `timeout` passes.
pub fn wait_until(timeout: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if ready() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// What a subscriber's channel carries.
enum Delivery {
    /// A record appended after the subscription started.
    Record(Box<EventRecord>),
    /// The log was sealed or the client hung up; nothing more follows.
    End,
}

/// A subscription as handed to the streaming thread.
struct Subscription {
    /// Records already in the log from `from_seq`.
    replay: Vec<EventRecord>,
    /// The live channel and a sender for the hang-up watcher; `None` when the log
    /// is already sealed and the replay is everything.
    live: Option<(Receiver<Delivery>, Sender<Delivery>)>,
}

/// A pause in force: what was frozen, since when, and what holds it.
struct Paused {
    frozen: Frozen,
    since: Instant,
    hold: Hold,
}

/// What a [`Paused`] is holding the session for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hold {
    /// `ward pause`: released by `ward resume`.
    Pause,
    /// A stop that has begun and not completed: a `HoldForStop` waiting for its
    /// `Stop` (PR #253 review finding 3), or a `Stop` that was refused because
    /// it could not confirm termination (finding 5) — whose held processes may
    /// already have taken an irreversible `SIGKILL`. Never released by `ward
    /// resume`; only a stop (or a log-only `Seal`) ends it.
    Stop,
}

/// What [`Served::pause`] produced: the one terminal record the pause attempt
/// appended — `SessionPaused` when the freeze confirmed settled within
/// [`pause::FREEZE_SETTLE`], `SessionPauseUnsettled` otherwise (the `SIGSTOP`
/// fallback path only; the cgroup freezer is synchronous and always confirms) —
/// and, mirroring that same record, `Some(pending)` on the unsettled path.
/// PR #207 review finding 1: the settle outcome is decided *before* either record
/// is appended, so the two are mutually exclusive, never "`SessionPaused` now,
/// qualified later" — a caller that only sees the RPC response (not a log
/// subscriber) still learns the same single truth the log itself now records
/// (#145 item 4).
#[derive(Debug)]
struct PauseOutcome {
    record: Box<EventRecord>,
    unsettled: Option<u32>,
}

/// The daemon's shared state: the log, the session facts, the subscribers, the
/// open connections, the approvals it holds, what it derives their authority
/// from, and the pause in force.
struct Served {
    log: Option<LocalLog>,
    log_path: PathBuf,
    description: serde_json::Value,
    subscribers: Vec<Sender<Delivery>>,
    peers: Vec<(u64, UnixStream)>,
    approvals: Arc<Approvals>,
    deriver: Deriver,
    state: PathBuf,
    session: String,
    paused: Option<Paused>,
    /// Launches (`CommandStarted`) seen so far whose terminal record
    /// (`CommandFinished` or `LaunchAborted`) has not landed yet: the id of
    /// the connection whose request appended the `CommandStarted` (see
    /// [`serve`]; never reused across connections for the life of this
    /// daemon), paired with a per-launch key minted from that
    /// `CommandStarted` record's own sequence number (unique and monotonic
    /// by construction — the log already assigns it).
    ///
    /// A `CredentialGranted` is attributed to *the request's own connection's*
    /// open launch, and a terminal record retires only that same connection's
    /// launch — never merely "whichever launch anywhere started most
    /// recently", and never keyed by the client-supplied `Pid` on
    /// `CommandStarted`/`CommandFinished`. That `Pid` is not a safe
    /// correlation key here: every freshly opened `Session` allocates its
    /// logical pids from the same small range starting at 2
    /// (`Session::alloc_pid`), so two genuinely concurrent launches — two
    /// `ward` client processes talking to this same daemon session — can and
    /// do choose the identical `Pid`. Keying attribution and retirement by
    /// connection instead means that collision cannot merge their credentials
    /// or let one launch's end retire the other's grant (PR #197 review,
    /// finding 2).
    ///
    /// An entry here is removed by that launch's own terminal record —
    /// `CommandFinished`, or a `LaunchAborted` raised from inside
    /// `Session::launch` itself for an ordinary Rust error — or, when the
    /// control connection is severed before either ever arrives (the client
    /// process is killed, crashes, or the socket is otherwise cut
    /// mid-launch), by [`Served::disconnect_open_launches`] once `serve`
    /// notices the connection is gone. `wardd` has no handle onto the
    /// client-side sandbox/egress proxy (`Egress::start` runs inside the
    /// client's own `Session::run_launch`, not the daemon), so a bare
    /// connection close cannot establish that the process or its credential
    /// route has actually ended — reporting the grant retired on EOF alone
    /// would be an unsupported claim in that direction (the mistake
    /// `f5d5c19` made and `0198c95` reverted). Nor is leaving it reporting as
    /// a plain, still-open `Lifetime::Launch` honest: that just as wrongly
    /// claims the launch is still confirmed running. So
    /// `disconnect_open_launches` takes the entry out of this map — nothing
    /// will ever produce a terminal record for it now — and calls
    /// [`Approvals::mark_launch_unknown`] on its key instead, so
    /// `Approvals::grants` reports the credential it scoped as
    /// [`crate::approvals::Lifetime::LaunchUnknown`] from then on: visible,
    /// neither confirmed running nor confirmed safe (#140, PR #197 review
    /// round 3). #140 stays open for a host-owned teardown capability that
    /// could make EOF trustworthy enough to retire the grant outright.
    open_launches: Vec<(u64, u64, Pid)>,
    /// The agent state the log last recorded (`AgentStateChanged`), so a stop
    /// records `Finished` itself — once, and only after termination is
    /// confirmed (PR #253 review finding 5) — unless a client that predates
    /// that (0.18, which appended `Finished` before asking to stop) already has.
    last_agent_state: Option<ward_events::AgentState>,
}

impl Served {
    fn new(
        log: LocalLog,
        log_path: PathBuf,
        description: serde_json::Value,
        deriver: Deriver,
        state: PathBuf,
        session: String,
    ) -> Self {
        Self {
            log: Some(log),
            log_path,
            description,
            subscribers: Vec::new(),
            peers: Vec::new(),
            approvals: Arc::new(Approvals::new()),
            deriver,
            state,
            session,
            paused: None,
            open_launches: Vec::new(),
            last_agent_state: None,
        }
    }

    /// A connection id used for requests that do not come from a real client
    /// connection dispatched by [`serve`] (`Self::append`, and the daemon's
    /// own tests): see [`Self::handle_conn`]'s doc comment.
    const INTERNAL_CONN: u64 = u64::MAX;

    /// [`Self::handle_conn`] for a caller with no real client connection to
    /// attribute the request to.
    fn handle(&mut self, request: Request) -> (Response, bool) {
        self.handle_conn(Self::INTERNAL_CONN, request)
    }

    /// Apply one request received over connection `conn` (see [`serve`]: an id
    /// unique for the life of this daemon, never reused). Appended records are
    /// fanned out to every subscriber; a subscriber whose channel is gone is
    /// dropped. Returns the response and whether the log is now sealed.
    ///
    /// `conn` is not part of the wire protocol; it is only how this process
    /// attributes a `CredentialGranted` and retires a launch's grants without
    /// trusting the client-supplied `Pid` on `CommandStarted`/`CommandFinished`
    /// for correlation (PR #197 review, finding 2 — see `open_launches`' doc
    /// comment for why that `Pid` is not safe to key by). A caller with no real
    /// client connection to attribute a request to goes through [`Self::handle`],
    /// which uses a fixed id: none of those callers ever have more than one
    /// launch open at a time, so a shared id is exactly as unambiguous there as
    /// a real per-connection one would be.
    fn handle_conn(&mut self, conn: u64, request: Request) -> (Response, bool) {
        match request {
            Request::Describe => (Response::Description(self.description.clone()), false),
            Request::Subscribe { .. } => (
                Response::Error("subscribe is served on its own connection".into()),
                false,
            ),
            Request::Hold { .. } => (
                Response::Error("hold is served on its own connection".into()),
                false,
            ),
            Request::Approve { id, decision } => (
                self.approvals
                    .answer(id, decision)
                    .map_or_else(|e| Response::Error(refusal(e)), |()| Response::Ok),
                false,
            ),
            Request::Pending => (Response::Pending(self.approvals.pending()), false),
            Request::Approvals => (Response::Approvals(self.approvals.approvals()), false),
            Request::Grants => (Response::Grants(self.approvals.grants()), false),
            // Can block on the owning proxy's acknowledgement (#245): served
            // on its own connection, exactly like `Hold`, so this never holds
            // the whole daemon's lock across that wait.
            Request::Revoke { .. } => (
                Response::Error("revoke is served on its own connection".into()),
                false,
            ),
            Request::Pause { reason } => (
                self.pause(&reason).map_or_else(
                    |e| Response::Error(refusal(e)),
                    |outcome| Response::Paused {
                        record: outcome.record,
                        unsettled: outcome.unsettled,
                    },
                ),
                false,
            ),
            Request::Resume => (
                self.resume()
                    .map_or_else(|e| Response::Error(refusal(e)), Response::Record),
                false,
            ),
            Request::Capabilities => (
                Response::Capabilities {
                    features: vec![
                        control::FEATURE_STOP_TERMINATES.into(),
                        control::FEATURE_STOP_HOLD.into(),
                    ],
                },
                false,
            ),
            Request::HoldForStop { reason } => (
                self.hold_for_stop(&reason).map_or_else(
                    |e| Response::Error(refusal(e)),
                    |unsettled| Response::HeldForStop { unsettled },
                ),
                false,
            ),
            // A stop ends the session's workloads before anything is sealed
            // (#145 item 5), from running or from paused.
            Request::Stop { reason } => self.stop(conn, reason, pause::terminate),
            // Log-only closure from paused: the frozen tree is killed rather
            // than left stopped for ever; the worktree is not touched.
            Request::Seal if self.paused.is_some() => {
                if let Some(paused) = self.paused.take() {
                    pause::kill_frozen(&paused.frozen);
                    let _ = pause::clear_marker(&self.state, &self.session);
                }
                self.handle_conn(conn, Request::Seal)
            }
            // Give every approval still open a terminal record before anything
            // that follows can seal the log (#146): once sealed, no record can
            // follow it, so this must happen first, not from inside
            // `handle_appendable`'s `done` handling below.
            Request::Seal => {
                self.close_pending_approvals();
                self.handle_appendable(conn, Request::Seal)
            }
            other => self.handle_appendable(conn, other),
        }
    }

    /// Every request `handle_conn` does not answer itself: appended to the log,
    /// fanned out to subscribers, and watched for the records that feed the
    /// grants list — a credential the launch grants (recorded as temporary
    /// authority) and a launch beginning or ending (`#140`). A
    /// `CredentialGranted` is attributed to `conn`'s own open launch, and a
    /// launch's terminal record (`CommandFinished` or `LaunchAborted`) retires
    /// only that same connection's launch — never a launch on another
    /// connection, even one whose client-chosen `Pid` happens to collide.
    fn handle_appendable(&mut self, conn: u64, other: Request) -> (Response, bool) {
        let credential = match &other {
            Request::Append {
                event: WardEvent::CredentialGranted { service, scope, .. },
                ..
            } => Some((
                service.as_str().to_owned(),
                scope.subject.as_str().to_owned(),
                scope
                    .permissions
                    .iter()
                    .map(|p| p.as_str().to_owned())
                    .collect::<Vec<_>>(),
                self.open_launches
                    .iter()
                    .rev()
                    .find(|(c, _, _)| *c == conn)
                    .map(|(_, key, _)| *key),
            )),
            _ => None,
        };
        let launch_started = match &other {
            Request::Append {
                event: WardEvent::CommandStarted { pid, .. },
                ..
            } => Some(*pid),
            _ => None,
        };
        let launch_finished = match &other {
            Request::Append {
                event: WardEvent::CommandFinished { pid, .. } | WardEvent::LaunchAborted { pid, .. },
                ..
            } => Some(*pid),
            _ => None,
        };
        let agent_state = match &other {
            Request::Append {
                event: WardEvent::AgentStateChanged { state },
                ..
            } => Some(*state),
            _ => None,
        };
        let subscribers = &mut self.subscribers;
        let (response, done) = control::handle_with(&mut self.log, other, |record| {
            subscribers.retain(|s| s.send(Delivery::Record(Box::new(record.clone()))).is_ok());
        });
        // Set only for a `CredentialGranted` append, once it lands: the
        // client learns this same id back through `Response::Granted` (#245)
        // so the `GatewayRoute` it built for this exact grant can be tagged
        // with it (`GatewayRoute::revocable`) — the one thing that lets a
        // later `ward session revoke` reach that route in a different
        // process at all.
        let mut grant_id = None;
        if let Response::Record(record) = &response {
            if agent_state.is_some() {
                self.last_agent_state = agent_state;
            }
            if let Some((service, subject, permissions, launch_key)) = credential {
                // The subject is the route's upstream, `host:port`.
                let host = subject
                    .rsplit_once(':')
                    .map_or(subject.as_str(), |(h, _)| h);
                grant_id = Some(self.approvals.record_credential(
                    &service,
                    host,
                    permissions,
                    launch_key,
                    control::unix_ms(SystemTime::now()),
                ));
            }
            if let Some(pid) = launch_started {
                // Keep the logical pid so a confirmed stop can terminalize any
                // still-open launch before sealing the log.
                self.open_launches.push((conn, record.seq, pid));
            }
            if let Some(pid) = launch_finished
                && let Some(pos) = self
                    .open_launches
                    .iter()
                    .rposition(|(c, _, p)| *c == conn && *p == pid)
            {
                let (_, key, _) = self.open_launches.remove(pos);
                // The route this launch's credentials were scoped to is torn
                // down with it: they are no longer active authority, whether
                // the launch ran to completion, failed, was killed over
                // budget, or never got off the ground at all (`LaunchAborted`,
                // PR #197 review finding 1).
                self.approvals.retire_launch(key);
            }
        }
        if done {
            for s in self.subscribers.drain(..) {
                let _ = s.send(Delivery::End);
            }
            // Any approval still open at this point was already given its
            // terminal record and released by `close_pending_approvals`
            // before this request was allowed to reach here and seal the log
            // (#146) — nothing left to do for approvals here.
        }
        let response = match (response, grant_id) {
            (Response::Record(record), Some(grant_id)) => Response::Granted { record, grant_id },
            (response, _) => response,
        };
        (response, done)
    }

    /// Close out every launch still open on `conn` once that connection's
    /// worker thread has returned (`serve`, right after removing it from
    /// `peers`): the client process was killed, crashed, or the control
    /// socket was otherwise severed before a terminal record ever landed for
    /// it (see `open_launches`' doc comment).
    ///
    /// `RemoteSink` is one connection, one request at a time, over a Unix
    /// domain socket local to this host, so there is no transient-network
    /// case where the peer comes back and finishes the launch on a
    /// *different* connection later — a connection that has ended can never
    /// supply this launch's real terminal record. This does not retire the
    /// grant (that would claim the route is confirmed to have ended, which a
    /// bare disconnect cannot support) and does not leave it reporting as a
    /// plain, still-open `Launch` either (which would just as wrongly claim
    /// it is still confirmed running): it takes the entry out of
    /// `open_launches` — nothing will ever finish it now — and marks its key
    /// unknown in `Approvals`, so `grants` reports the credential from here
    /// on as `Lifetime::LaunchUnknown` (#140, PR #197 review round 3).
    ///
    /// A no-op when `conn` has no open launches (the common case: most
    /// connections never start one, or already finished it cleanly before
    /// closing). Closes out every one of `conn`'s open launches, not just
    /// one, since nothing about the protocol forbids a connection starting
    /// more than one launch before closing.
    /// Terminalize every launch still open when Stop has confirmed that the
    /// session's workloads are gone. This runs before SessionEnded/seal, so the
    /// log never closes with an unmatched CommandStarted and launch-scoped
    /// credentials retire through the same per-connection path as a client
    /// supplied terminal record.
    fn abort_open_launches_for_stop(&mut self) -> Result<()> {
        let launches = self.open_launches.clone();
        for (conn, _, pid) in launches {
            let request = Request::Append {
                origin: Origin::Wardd,
                event: WardEvent::LaunchAborted {
                    pid,
                    reason: ShortText::new("terminated by ward stop"),
                },
                at_unix_ms: control::unix_ms(SystemTime::now()),
            };
            match self.handle_conn(conn, request).0 {
                Response::Record(_) => {}
                Response::Error(e) => return Err(Error::Daemon(e)),
                other => {
                    return Err(Error::Daemon(format!(
                        "unexpected response while terminalizing launch {pid}: {other:?}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn disconnect_open_launches(&mut self, conn: u64) {
        let mut keys = Vec::new();
        self.open_launches.retain(|&(c, key, _)| {
            if c == conn {
                keys.push(key);
                false
            } else {
                true
            }
        });
        for key in keys {
            self.approvals.mark_launch_unknown(key);
        }
    }

    /// Give every approval still held a terminal `CapabilityDecided` record
    /// — its real answer if it had one, `Outcome::Closed`
    /// (`DecisionSource::SessionEnded`) if it did not — while the log can
    /// still take one. Called from [`Self::handle_conn`] right before a
    /// `Stop` or `Seal` request is allowed to reach [`Self::handle_appendable`]
    /// and seal the log.
    ///
    /// Before #146 the daemon released these approvals (waking every
    /// `Request::Hold` connection waiting on one, so the agent still got its
    /// `deny`) but appended nothing for them, because by the time `close`
    /// ran the log had already sealed. #146 fixed the genuinely-still-open
    /// case by appending here, but left an approval that was already
    /// answered — just not yet collected by its own `Request::Hold`
    /// connection — for that connection to record later through the
    /// ordinary path in [`hold`]. The review of #218 (finding 1) found that
    /// handoff itself raced this same Stop/Seal: nothing made "the hold
    /// connection notices and appends" and "the log seals" mutually
    /// exclusive, so an answered-but-uncollected approval could still reach
    /// the seal with no terminal record at all. `Approvals::close` now
    /// drains and returns *every* held entry with its real outcome --
    /// answered or not — so this appends the true record for that case too,
    /// here, before the seal; [`hold`] checks `Approvals::take_recorded` to
    /// know not to append a second one once its own `wait` collects the
    /// same entry.
    fn close_pending_approvals(&mut self) {
        for (approval, outcome) in self.approvals.close() {
            let event = approvals::decided_event(&approval.tool, &approval.summary, outcome);
            // Best-effort: a request line arriving after some earlier failure
            // already sealed the log (a pathological double-seal) leaves this
            // a no-op rather than a panic; the approval was released either
            // way and the agent already got its answer from `Approvals::wait`.
            let _ = self.append(event);
        }
    }

    /// Append one `wardd`-origin record now, fanned out like any other.
    fn append(&mut self, event: WardEvent) -> Result<EventRecord> {
        let request = Request::Append {
            origin: Origin::Wardd,
            event,
            at_unix_ms: control::unix_ms(SystemTime::now()),
        };
        match self.handle(request).0 {
            // A `CredentialGranted` append also answers with the grant id
            // (#245) — this internal helper's callers have no route to tag
            // with it, so only the record itself is of interest here.
            Response::Record(record) | Response::Granted { record, .. } => Ok(*record),
            Response::Error(e) => Err(Error::Daemon(e)),
            other => Err(Error::Daemon(format!("unexpected response {other:?}"))),
        }
    }

    /// Register a question: the `CapabilityRequested` record is appended and
    /// its seq becomes the approval's id, in one step under the mutex so a
    /// subscriber that sees the record can already answer it. A standing
    /// `allow-session` answers it at once. The approval's authority is derived
    /// here, from the manifest and the credentials granted so far, and its
    /// decision clock of `timeout` is armed in the same step (#146 item 4),
    /// so the same subscriber already sees how long it has to answer.
    fn hold(
        &mut self,
        tool: &str,
        summary: &str,
        reason: &str,
        timeout: Duration,
    ) -> Result<(u64, Option<Outcome>)> {
        let record = self.append(approvals::requested_event(tool, summary, reason))?;
        if self.approvals.remembered(tool, summary) {
            return Ok((record.seq, Some(Outcome::Remembered)));
        }
        let authority = self
            .deriver
            .derive(tool, summary, reason, &self.approvals.credentials());
        self.approvals.register_with_timeout(
            Approval::new(
                record.seq,
                tool,
                summary,
                authority,
                control::unix_ms(SystemTime::now()),
            ),
            timeout,
        )?;
        Ok((record.seq, None))
    }

    /// Pause the session (ADR-0019 §3), in this order: freeze the sandbox
    /// processes, write the marker every proxy of the session refuses on (new
    /// connections, new requests, credential injection), hold the approvals,
    /// decide whether the freeze actually settled, and append exactly one
    /// terminal record for it — `SessionPaused` when confirmed,
    /// `SessionPauseUnsettled` otherwise. The processes are frozen first so
    /// nothing can use the gap before the proxy notices the marker. Any failure
    /// before the terminal record is (successfully) recorded undoes what was
    /// done, so the session is either paused whole or not at all — see
    /// [`Self::pause_with`] for the one exception (a *log-only* failure once the
    /// freeze is already known unsettled).
    ///
    /// Always uses [`pause::settle_outcome`]; see [`Self::pause_with`] for why
    /// this is split out.
    fn pause(&mut self, reason: &str) -> Result<PauseOutcome> {
        self.pause_with(reason, pause::settle_outcome)
    }

    /// [`Self::pause`], with the settle check injectable: real callers always pass
    /// [`pause::settle_outcome`], which waits up to [`pause::FREEZE_SETTLE`] against
    /// real `/proc` state; a test passes a closure that answers at once, so the
    /// unsettled path (and the `pending` count it reports) is exercised
    /// deterministically, with no real un-stoppable process and no real wait —
    /// `SIGSTOP` cannot be caught, blocked or ignored by user space, so there is no
    /// way to make a *real* process resist it for a test to race against.
    ///
    /// `settle` runs after the marker and the held approvals are already in place,
    /// but — PR #207 review finding 1 — strictly *before* either terminal record is
    /// appended: the outcome decides which single record gets published, so no
    /// subscriber, CLI caller, or later log reader can ever see a confirmed
    /// `SessionPaused` that a moment later turns out to have been unsettled all
    /// along. Whether or not the freeze is confirmed changes only which record is
    /// appended, never whether the pause itself proceeds — #145 item 4's "preserve
    /// the safest achievable state" applies regardless of the answer.
    fn pause_with(
        &mut self,
        reason: &str,
        settle: impl FnOnce(&Frozen) -> Option<u32>,
    ) -> Result<PauseOutcome> {
        self.pause_with_appending(reason, settle, Self::append)
    }

    /// [`Self::pause_with`], with the terminal append itself also injectable: real
    /// callers always pass [`Self::append`]; a test passes a closure that fails
    /// deterministically. This is what lets PR #207 review finding 2 — a log-only
    /// failure on the terminal append must be surfaced, never silently discarded,
    /// and must never roll back the marker/approvals/frozen tree once the freeze is
    /// already known unsettled — be exercised without needing a real, reproducible
    /// disk failure (storage exhaustion) to trigger it, the same reason `settle`
    /// above is injectable rather than driven by a real timed wait.
    fn pause_with_appending(
        &mut self,
        reason: &str,
        settle: impl FnOnce(&Frozen) -> Option<u32>,
        mut append: impl FnMut(&mut Self, WardEvent) -> Result<EventRecord>,
    ) -> Result<PauseOutcome> {
        if self.log.is_none() {
            return Err(Error::Daemon("log is sealed".into()));
        }
        if self.paused.is_some() {
            return Err(Error::Daemon("already paused".into()));
        }
        let reason = pause::reason_text(reason);
        // #234: the same lock `CaptureFreeze::acquire`/`Drop` take, held across the
        // freeze and the marker write so a capture's own marker check or thaw can
        // never straddle this pause taking hold.
        let _lock = pause::lock_pause_freeze(&session_dir(&self.state, &self.session))?;
        let frozen = pause::freeze(&self.session);
        if let Err(e) = pause::write_marker(&self.state, &self.session, &reason) {
            pause::thaw(&frozen);
            return Err(e);
        }
        self.approvals.set_paused(true);
        // The marker and the held approvals already stand — the safest state #145
        // item 4 asks for — before the settle check even runs, and stay that way
        // regardless of its answer or of whether the terminal record below makes it
        // onto the log.
        let unsettled = settle(&frozen);
        let record = match unsettled {
            None => match append(
                self,
                WardEvent::SessionPaused {
                    method: frozen.method,
                    reason: ShortText::new(&reason),
                },
            ) {
                Ok(record) => record,
                Err(e) => {
                    // Byte-for-byte the same rollback this append has always had:
                    // without a durable `SessionPaused` record, the log never
                    // agrees the session was paused at all, so nothing else about
                    // it should stand either.
                    self.approvals.set_paused(false);
                    let _ = pause::clear_marker(&self.state, &self.session);
                    pause::thaw(&frozen);
                    return Err(e);
                }
            },
            Some(pending) => match append(
                self,
                WardEvent::SessionPauseUnsettled {
                    method: frozen.method,
                    reason: ShortText::new(&reason),
                    pending,
                },
            ) {
                Ok(record) => record,
                Err(e) => {
                    // PR #207 review finding 2: unlike the settled branch above, an
                    // unsettled pause's marker/approvals/frozen tree are never
                    // rolled back for a failure of *this* append — they are already
                    // the safest achievable state, independent of whether the log
                    // can also say so, and a real, correct freeze must not be undone
                    // over a log-only failure (e.g. storage exhaustion). `self.paused`
                    // is still recorded (unlike the early-return above) so `ward
                    // resume` remains able to release the freeze even though the log
                    // does not, yet or ever, agree the pause happened. What must not
                    // happen is silently discarding the failure the way `let _ =
                    // self.append(...)` used to: the caller has to learn the durable
                    // history may not actually contain the unsettled record it is
                    // about to be told happened, exactly the fold
                    // `Session::verify_prepared` already does for its own terminal-
                    // append failure (#194).
                    self.paused = Some(Paused {
                        frozen,
                        since: Instant::now(),
                        hold: Hold::Pause,
                    });
                    return Err(Error::Daemon(format!(
                        "the freeze for session {} could not be confirmed settled \
                         ({pending} process(es) still pending), and the record of \
                         that could not be written to the log ({e}); the marker is \
                         held and approvals stay frozen regardless, but the log may \
                         not reflect the unsettled pause",
                        self.session
                    )));
                }
            },
        };
        self.paused = Some(Paused {
            frozen,
            since: Instant::now(),
            hold: Hold::Pause,
        });
        Ok(PauseOutcome {
            record: Box::new(record),
            unsettled,
        })
    }

    /// Reverse [`Self::pause`]: release the approvals, open the proxy, thaw
    /// the processes, append `SessionResumed`.
    ///
    /// Refused while the session is held for a stop ([`Hold::Stop`]), and once
    /// a stop of it has begun at all (the on-disk stop marker, which outlives
    /// a daemon restart): a `HoldForStop` must stay in force until its stop
    /// (PR #253 review finding 3), and a refused stop's remaining processes
    /// have already been sent `SIGKILL` — releasing them as though they were an
    /// ordinary pause would present a half-killed session as resumable
    /// execution (finding 5). A stop is retried with `ward stop`.
    fn resume(&mut self) -> Result<Box<EventRecord>> {
        let Some(paused) = self.paused.as_ref() else {
            return Err(Error::Daemon("not paused".into()));
        };
        if paused.hold == Hold::Stop || pause::stop_begun(&self.state, &self.session) {
            return Err(Error::Daemon(format!(
                "a stop of session {} has begun and not completed: its sandboxed processes \
                 are held for that stop (some may already have been killed), so `ward \
                 resume` cannot release them. Run `ward stop` to finish it",
                self.session
            )));
        }
        // #234: the same lock `pause`/`CaptureFreeze` take, so a capture's own
        // marker check or thaw can never straddle this resume's marker clear and
        // thaw.
        let _lock = pause::lock_pause_freeze(&session_dir(&self.state, &self.session))?;
        // Clear the on-disk pause marker FIRST. The session proxies read it to refuse
        // egress, so it is the load-bearing part of a resume: if it fails we must leave
        // the session fully paused (marker present, approvals held, processes frozen)
        // and return the error, not half-resume into a state where the proxy still
        // refuses traffic while the daemon believes it is running (which a later
        // Resume would reject as "not paused"). Nothing is mutated before this succeeds.
        pause::clear_marker(&self.state, &self.session)?;
        self.approvals.set_paused(false);
        pause::thaw(&paused.frozen);
        let paused_for = paused.since.elapsed();
        self.paused = None;
        let record = self.append(WardEvent::SessionResumed { paused_for })?;
        Ok(Box::new(record))
    }

    /// `Request::HoldForStop` (PR #253 review finding 3): make the session
    /// quiescent for the stop that follows, as a daemon-owned hold nothing but
    /// that stop (or a log-only `Seal`) can end. Always uses
    /// [`pause::freeze_confirmed`] / [`pause::stabilize`]; see
    /// [`Self::hold_for_stop_with`].
    fn hold_for_stop(&mut self, reason: &str) -> Result<Option<u32>> {
        self.hold_for_stop_with(reason, pause::freeze_confirmed, pause::stabilize)
    }

    /// [`Self::hold_for_stop`], with the freeze injectable (a test needs an
    /// unsettled outcome no real process can produce on demand).
    ///
    /// Under [`pause::lock_pause_freeze`], in this order: the stop marker is
    /// written, so no launch is admitted from here on
    /// ([`pause::admit_launch`]); then the daemon's *own* view decides what is
    /// frozen — never the pause marker on disk, which a daemon restarted since
    /// it was written does not hold anything for. A pause already in force is
    /// taken over (its freeze re-confirmed stable, since it may have been
    /// unsettled) without a new record; otherwise the sandboxes are frozen now,
    /// the marker is written, the approvals are held and `SessionPaused` (or
    /// `SessionPauseUnsettled`) is appended, exactly as `ward pause` records
    /// one. Either way the result is a [`Hold::Stop`], which `Resume` refuses.
    /// Returns `Some(pending)` when the freeze could not be confirmed stable in
    /// time — the hold still stands, and a caller that needs quiescence (a
    /// restore) must not proceed on it.
    fn hold_for_stop_with(
        &mut self,
        reason: &str,
        freeze: impl FnOnce(&str) -> (Frozen, bool),
        restabilize: impl FnOnce(&str, Frozen) -> (Frozen, bool),
    ) -> Result<Option<u32>> {
        if self.log.is_none() {
            return Err(Error::Daemon("log is sealed".into()));
        }
        let _lock = pause::lock_pause_freeze(&session_dir(&self.state, &self.session))?;
        pause::write_stop_marker(&self.state, &self.session)?;
        if let Some(paused) = self.paused.take() {
            let (frozen, stable) = restabilize(&self.session, paused.frozen);
            let unsettled = if stable {
                None
            } else {
                Some(pause::unsettled_count(&frozen, false).unwrap_or(0))
            };
            // The pause's marker normally stands already; a hold must not
            // depend on that.
            let marker = if pause::marker_path(&self.state, &self.session).exists() {
                Ok(())
            } else {
                pause::write_marker(&self.state, &self.session, &pause::reason_text(reason))
            };
            self.approvals.set_paused(true);
            self.paused = Some(Paused {
                frozen,
                since: paused.since,
                hold: Hold::Stop,
            });
            marker?;
            return Ok(unsettled);
        }
        let reason = pause::reason_text(reason);
        let (frozen, stable) = freeze(&self.session);
        if let Err(e) = pause::write_marker(&self.state, &self.session, &reason) {
            // Nothing is held: let the tree run rather than leave it frozen
            // with no marker saying so. The stop marker stays — the session
            // is ending — so no launch is admitted either way.
            pause::thaw(&frozen);
            return Err(e);
        }
        self.approvals.set_paused(true);
        let unsettled = if stable {
            None
        } else {
            Some(pause::unsettled_count(&frozen, false).unwrap_or(0))
        };
        let method = frozen.method;
        self.paused = Some(Paused {
            frozen,
            since: Instant::now(),
            hold: Hold::Stop,
        });
        let event = match unsettled {
            None => WardEvent::SessionPaused {
                method,
                reason: ShortText::new(&reason),
            },
            Some(pending) => WardEvent::SessionPauseUnsettled {
                method,
                reason: ShortText::new(&reason),
                pending,
            },
        };
        // The hold is never undone for a log-only failure: it is the safest
        // state, and the stop that follows ends it.
        self.append(event).map_err(|e| {
            Error::Daemon(format!(
                "session {} is held for its stop, but the record of that could not be \
                 written ({e}); nothing was restored. Run `ward stop` to finish the stop",
                self.session
            ))
        })?;
        Ok(unsettled)
    }

    /// `Request::Stop` (#145 item 5): stop is termination of the session's
    /// workloads followed by evidence sealing, not log-only closure (that is
    /// `Request::Seal`). In order: the stop marker is written under the session
    /// lock, so no launch is admitted from here on (PR #253 review finding 2);
    /// every sandboxed process of the session is frozen (or already is, from a
    /// pause or a stop hold), the freeze confirmed stable, killed and confirmed
    /// gone (`terminate`, always [`pause::terminate`] outside tests); when
    /// there was anything to end, `WorkloadsTerminated` records it; only then
    /// is `AgentStateChanged { Finished }` appended (finding 5: never before
    /// termination is confirmed), every approval still open gets its terminal
    /// record (#146), and `SessionEnded` and the seal follow. The answer's
    /// `ended` is `Some(n)`: the positive acknowledgement a client requires
    /// (finding 1).
    ///
    /// When termination cannot be confirmed within [`pause::STOP_SETTLE`], the
    /// stop is refused rather than reported as done (#145 item 4): the log is
    /// not sealed, `Finished` is not recorded, and the session is held for the
    /// stop ([`Hold::Stop`]) — the marker written so every proxy refuses, the
    /// approvals held, the processes still present kept as the hold's freeze.
    /// `WorkloadsTerminated { pending }` records the partial outcome. That is
    /// an incomplete stop, not a pause: `ward resume` refuses it, and a later
    /// `ward stop` retries from there.
    ///
    /// `terminate` is injectable for the same reason [`Self::pause_with`]'s
    /// `settle` is: a real process that survives `SIGKILL` for the length of the
    /// bound (uninterruptible sleep) cannot be produced on demand by a test.
    fn stop(
        &mut self,
        conn: u64,
        reason: ward_events::EndReason,
        terminate: impl FnOnce(&str, Option<Frozen>) -> pause::Termination,
    ) -> (Response, bool) {
        // A log already sealed has nothing to stop; `handle_appendable` answers
        // that exactly as it always has.
        if self.log.is_none() {
            return self.handle_appendable(conn, Request::Stop { reason });
        }
        let ended = match self.end_workloads(terminate) {
            Ok(n) => n,
            Err(e) => return (Response::Error(refusal(e)), false),
        };
        if let Err(e) = self.abort_open_launches_for_stop() {
            return (
                Response::Error(format!(
                    "stop ended every sandboxed process of session {} ({ended}), but an open                      launch could not be terminalized ({e}); the log is not sealed. Run `ward stop` again",
                    self.session
                )),
                false,
            );
        }
        if self.last_agent_state != Some(ward_events::AgentState::Finished)
            && let Err(e) = self.append(WardEvent::AgentStateChanged {
                state: ward_events::AgentState::Finished,
            })
        {
            return (
                Response::Error(format!(
                    "stop ended every sandboxed process of session {} ({ended}), but the \
                     agent's finished state could not be recorded ({e}); the log is not \
                     sealed. Run `ward stop` again",
                    self.session
                )),
                false,
            );
        }
        self.close_pending_approvals();
        match self.handle_appendable(conn, Request::Stop { reason }) {
            (Response::Sealed { head, .. }, done) => (
                Response::Sealed {
                    head,
                    ended: Some(ended),
                },
                done,
            ),
            other => other,
        }
    }

    /// The termination half of [`Self::stop`]: returns how many processes ended,
    /// or the refusal once the session has been put in its held-for-stop state.
    fn end_workloads(
        &mut self,
        terminate: impl FnOnce(&str, Option<Frozen>) -> pause::Termination,
    ) -> Result<u32> {
        // #234: the lock `pause`/`resume`/`CaptureFreeze` take, and — PR #253
        // review finding 2 — the one `pause::admit_launch` takes around every
        // sandbox spawn, held from the stop marker through the scan, the kill
        // and the confirmation. Failure is fail-closed: without this lock Ward
        // cannot prove another already-admitted launch will not spawn after the scan.
        let _lock = pause::lock_pause_freeze(&session_dir(&self.state, &self.session)).map_err(
            |e| {
                Error::Daemon(format!(
                    "stop could not take the lifecycle lock for session {} ({e}); nothing was                      terminated and the log is not sealed",
                    self.session
                ))
            },
        )?;
        pause::write_stop_marker(&self.state, &self.session).map_err(|e| {
            Error::Daemon(format!(
                "stop could not record that session {} is stopping ({e}), so it could not \
                 keep new launches out; nothing was terminated and the log is not sealed",
                self.session
            ))
        })?;
        let held = self.paused.take();
        let since = held.as_ref().map(|p| p.since);
        let outcome = terminate(&self.session, held.map(|p| p.frozen));
        let ended = outcome.ended;
        let pending = outcome.pending();
        let barrier_confirmed = outcome.barrier_confirmed;
        let Some(remaining) = outcome.remaining else {
            // Everything the stop found is gone: nothing is left for the marker
            // to hold back. (Idempotent when there never was a marker.)
            let _ = pause::clear_marker(&self.state, &self.session);
            if ended > 0 {
                self.append(WardEvent::WorkloadsTerminated { ended, pending: 0 })
                    .map_err(|e| {
                        Error::Daemon(format!(
                            "stop ended {ended} sandboxed process(es) of session {}, but \
                             the record of that could not be written ({e}); the log is not \
                             sealed",
                            self.session
                        ))
                    })?;
            }
            return Ok(ended);
        };
        // Not confirmed: hold the session for the stop over whatever is still
        // there — an incomplete stop, not a pause.
        let marker = pause::write_marker(
            &self.state,
            &self.session,
            &pause::stop_hold_reason(pending),
        )
        .err();
        self.approvals.set_paused(true);
        self.paused = Some(Paused {
            frozen: remaining,
            since: since.unwrap_or_else(Instant::now),
            hold: Hold::Stop,
        });
        // A zero-pending result with an unconfirmed membership barrier is not a
        // confirmed STOP. Keep the log unsealed and avoid emitting the event
        // whose pending=0 rendering would claim otherwise.
        let logged = if barrier_confirmed {
            self.append(WardEvent::WorkloadsTerminated { ended, pending }).err()
        } else {
            None
        };
        let detail = if barrier_confirmed {
            "the stop is incomplete and the session is held for it (proxy closed, \
             approvals held, no new launch admitted; `ward resume` cannot release it). \
             Run `ward stop` again to retry"
        } else {
            "the pre-termination fork barrier was not confirmed, so Ward cannot prove the \
             session is quiescent even though no known pid remains. The session is held \
             for the stop; `ward resume` cannot release it. Run `ward stop` again to retry"
        };
        Err(Error::Daemon(pause::stop_refusal(
            &self.session,
            ended,
            pending,
            detail,
            marker.as_ref(),
            logged.as_ref(),
        )))
    }

    /// Start a subscription from `from_seq`: everything in the log so far, and a
    /// channel for what comes next. Called under the mutex so no append falls
    /// between the two.
    fn subscribe(&mut self, from_seq: u64) -> Result<Subscription> {
        let replay = LogReader::open(&self.log_path)
            .map_err(|e| Error::Events(e.to_string()))?
            .map_while(std::result::Result::ok)
            .filter(|r| r.seq >= from_seq)
            .collect();
        let live = self.log.as_ref().map(|_| {
            let (tx, rx) = channel();
            let watcher = tx.clone();
            self.subscribers.push(tx);
            (rx, watcher)
        });
        Ok(Subscription { replay, live })
    }
}

fn lock(served: &Mutex<Served>) -> MutexGuard<'_, Served> {
    served.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The text of a refusal on the wire: the daemon's own errors without their
/// `daemon: ` prefix, since the client adds it back when it reports them.
fn refusal(e: Error) -> String {
    match e {
        Error::Daemon(message) => message,
        other => other.to_string(),
    }
}

fn write_line(writer: &mut UnixStream, response: &Response) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(response).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    writer.write_all(&bytes)
}

/// Serve one connection until the client hangs up, subscribes, or seals the
/// log. Returns whether it sealed.
///
/// `conn` is this connection's id (see `serve`): passed to [`Served::handle_conn`]
/// so a `CommandStarted`/`CredentialGranted`/`CommandFinished` this connection
/// appends is attributed to and retired with this connection's own launch, never
/// another connection's (PR #197 review, finding 2).
fn serve_stream(stream: UnixStream, served: &Arc<Mutex<Served>>, conn: u64) -> bool {
    let Ok(mut writer) = stream.try_clone() else {
        return false;
    };
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        // Bound each request line so a newline-less stream cannot grow `line`
        // without limit; a Take yields at most MAX_REQUEST_BYTES per read.
        match (&mut reader).take(MAX_REQUEST_BYTES).read_line(&mut line) {
            Ok(0) | Err(_) => return false,
            Ok(_) => {}
        }
        if request_too_large(&line) {
            let _ = write_line(&mut writer, &Response::Error("request too large".into()));
            return false;
        }
        let (response, done) = match serde_json::from_str::<Request>(&line) {
            Ok(Request::Subscribe { from_seq }) => {
                stream_subscription(reader, writer, served, from_seq);
                return false;
            }
            Ok(Request::Hold {
                tool,
                summary,
                reason,
                timeout_secs,
            }) => (hold(served, &tool, &summary, &reason, timeout_secs), false),
            Ok(Request::Revoke { id }) => (revoke(served, id), false),
            Ok(request) => lock(served).handle_conn(conn, request),
            Err(e) => (Response::Error(format!("bad request: {e}")), false),
        };
        if write_line(&mut writer, &response).is_err() || done {
            return done;
        }
    }
}

/// Hold one `ask` (ADR-0016): record the request, wait for the user's answer
/// or the timeout with the mutex released, record the decision, and answer.
fn hold(
    served: &Arc<Mutex<Served>>,
    tool: &str,
    summary: &str,
    reason: &str,
    timeout_secs: u64,
) -> Response {
    let timeout = Duration::from_secs(timeout_secs);
    let (id, approvals, remembered) = {
        let mut s = lock(served);
        match s.hold(tool, summary, reason, timeout) {
            Ok((id, remembered)) => (id, Arc::clone(&s.approvals), remembered),
            Err(e) => return Response::Error(refusal(e)),
        }
    };
    let outcome = remembered.unwrap_or_else(|| approvals.wait(id, timeout));
    // `Approvals::take_recorded` is true exactly when a concurrent `close`
    // (`Served::close_pending_approvals`, running for a `Stop`/`Seal` on
    // another connection) already claimed this id itself and appended its
    // terminal record before the log could seal — whether that record was
    // `Outcome::Closed` (#146), this same real answer collected straight out
    // of `held` a moment too late to record it here (review of #218, finding
    // 1), or this same real answer collected by `wait` above but not yet
    // appended when `close` ran (finding 2). Appending again here would
    // duplicate that record, so this skips it; every other outcome still
    // records here, same as before #146.
    //
    // The check and the append it guards must happen under one acquisition
    // of `Served`'s lock, not two: `close_pending_approvals` needs that same
    // lock for its own claim-then-append-then-seal, entirely inside one
    // acquisition of its own. Checking `take_recorded` before taking this
    // lock (as this used to) leaves a gap between "decide to append" and
    // "actually append" during which a concurrent Stop/Seal can find nothing
    // left in `held` for `wait` to have collected, conclude there is nothing
    // to do, and seal the log before this call ever gets back here to append
    // — dropping the record entirely even though `wait` already returned the
    // real outcome above (finding 2). Taking the lock first, and holding it
    // across both the check and the append, makes this call's
    // check-then-append and `close_pending_approvals`'s own
    // claim-then-append-then-seal mutually exclusive: whichever of the two
    // reaches this lock first is the one that appends `id`'s real terminal
    // record, and the other one's own check then correctly finds it already
    // done.
    let mut s = lock(served);
    if !s.approvals.take_recorded(id) {
        let event = approvals::decided_event(tool, summary, outcome);
        let _ = s.append(event);
    }
    drop(s);
    let response = outcome.response();
    Response::Decision {
        id,
        decision: response.decision,
        reason: response.reason,
    }
}

/// Revoke grant `id` (`ward session revoke <id>`, #245, closing the gap #243
/// left open in #140 items 4-5): mark it revoking with the mutex released
/// before any wait — exactly like [`hold`]'s own wait — so a `ward session
/// grants` or `ward session approve` on another connection is never blocked
/// behind this one's proxy round trip.
fn revoke(served: &Arc<Mutex<Served>>, id: u64) -> Response {
    revoke_bounded(served, id, revoke::ACK_TIMEOUT)
}

/// [`revoke`] with an explicit wait bound: the seam the daemon's own tests
/// use to exercise an unconfirmed revoke without spending
/// [`revoke::ACK_TIMEOUT`] on it.
fn revoke_bounded(served: &Arc<Mutex<Served>>, id: u64, ack_timeout: Duration) -> Response {
    revoke_bounded_inner(served, id, ack_timeout, || {})
}

/// [`revoke_bounded`] with a hook run, still holding `served`'s lock,
/// between the leader publishing its outcome and the same call's
/// `finish_revoke` transition — the seam a test uses to pause exactly there
/// and prove a concurrent revoke of the same id cannot make progress during
/// that window (#248 review). A no-op in production ([`revoke_bounded`]).
#[cfg(test)]
fn revoke_bounded_with_hook(
    served: &Arc<Mutex<Served>>,
    id: u64,
    ack_timeout: Duration,
    after_publish_before_finish: impl FnOnce(),
) -> Response {
    revoke_bounded_inner(served, id, ack_timeout, after_publish_before_finish)
}

fn revoke_bounded_inner(
    served: &Arc<Mutex<Served>>,
    id: u64,
    ack_timeout: Duration,
    after_publish_before_finish: impl FnOnce(),
) -> Response {
    // The credential lookup and the leader/joiner decision for its
    // proxy-facing wait happen as one atomic step (#248 review):
    // `begin_revoke_wait` and the wait-slot claim used to be two separate
    // `served` lock acquisitions, which left a window where a connection's
    // credential check could see the grant still `Revoking`, but by the
    // time it went to claim the wait slot, another connection had already
    // finished revoking it (grant gone, slot gone) — and this connection
    // would then create a fresh slot and lead an independent second wait
    // for an id whose revoke had already concluded.
    let begin = lock(served).approvals.begin_revoke_wait(id);
    match begin {
        None => Response::Error(format!("revoke: grant {id} not found")),
        // An `allow-session` answer has no proxy route to wait on: it was
        // already removed by `begin_revoke_wait` itself.
        Some(approvals::RevokeStart::Approval) => {
            Response::Revoked(approvals::RevokeOutcome::Withdrawn)
        }
        Some(approvals::RevokeStart::Credential {
            service,
            slot,
            leader,
        }) => {
            let (state, session) = {
                let s = lock(served);
                (s.state.clone(), s.session.clone())
            };
            // Only the leader — the first connection to reach this id's
            // wait — ever touches `crate::revoke`'s marker file. A racing
            // connection for the same id joins the leader's shared slot
            // instead (#248 review): both independently writing, waiting on
            // and clearing the same marker let whichever one observed
            // `CONFIRMED` first delete it out from under the other, which
            // then timed out and reported `Unconfirmed` for an operation
            // that had already succeeded.
            let outcome = if leader {
                if let Err(e) = revoke::request(&state, &session, id) {
                    // The marker itself could not even be written (disk
                    // full, a vanished state dir): nothing can possibly
                    // acknowledge a request that was never made. Reported
                    // the same honest way as a wait that simply ran out —
                    // the grant stays, flagged, rather than either silently
                    // succeeding or handing back a bare, undifferentiated
                    // error #245's acceptance criteria rule out.
                    let _ = e;
                    approvals::RevokeOutcome::Unconfirmed
                } else {
                    let ack = revoke::wait_for_ack(&state, &session, id, ack_timeout);
                    revoke::clear(&state, &session, id);
                    match ack.as_deref() {
                        Some(revoke::CONFIRMED) => approvals::RevokeOutcome::Withdrawn,
                        // A marker body that is neither `CONFIRMED` nor a
                        // well-formed in-flight count (a torn write, a
                        // future format from a version-skewed egress) must
                        // fail toward the least confident outcome, not the
                        // most: treating unparsed text as a clean
                        // `Withdrawn` would report a revoke as fully
                        // enforced on data this daemon cannot actually
                        // read, exactly the "silently succeeded" shape this
                        // whole three-way outcome exists to rule out.
                        Some(text) => revoke::parse_in_flight(text).map_or(
                            approvals::RevokeOutcome::Unconfirmed,
                            approvals::RevokeOutcome::WithdrawnInFlight,
                        ),
                        None => approvals::RevokeOutcome::Unconfirmed,
                    }
                }
            } else {
                approvals::Approvals::join_revoke_wait(&slot, ack_timeout)
            };
            // Publishing the leader's outcome (which removes `id`'s shared
            // slot) and the Revoking→terminal `finish_revoke` transition it
            // implies must happen as one step with respect to `served`'s
            // lock, held continuously across both (#248 review): releasing
            // it in between would let a brand new connection's
            // `begin_revoke_wait` find the grant still `Revoking` and join a
            // slot this call is about to remove, or — worse, since that
            // check and claim are themselves one atomic step now — run
            // entirely between this call's publish and its own
            // `finish_revoke`, finding the grant already gone from a revoke
            // it never joined.
            let mut s = lock(served);
            if leader {
                s.approvals.publish_revoke_wait(id, &slot, outcome.clone());
            }
            after_publish_before_finish();
            let performed = s.approvals.finish_revoke(id, &outcome);
            // Only the connection whose `finish_revoke` actually performed
            // the Revoking→terminal transition records the audit event: two
            // connections racing a revoke of the same id both reach this
            // point with the same outcome (see `finish_revoke`'s doc
            // comment), and without this guard both would append a
            // `CredentialRevoked` record for one logical revoke.
            if performed && !matches!(outcome, approvals::RevokeOutcome::Unconfirmed) {
                match ServiceId::new(&service) {
                    Ok(service) => {
                        let _ = s.append(WardEvent::CredentialRevoked {
                            service,
                            reason: RevokeReason::UserRevoked,
                        });
                    }
                    Err(e) => return Response::Error(e.to_string()),
                }
            }
            drop(s);
            Response::Revoked(outcome)
        }
    }
}

/// Stream records from `from_seq`: the replay, then live records until the
/// client hangs up or the log is sealed.
fn stream_subscription(
    reader: BufReader<UnixStream>,
    mut writer: UnixStream,
    served: &Arc<Mutex<Served>>,
    from_seq: u64,
) {
    let subscription = match lock(served).subscribe(from_seq) {
        Ok(s) => s,
        Err(e) => {
            let _ = write_line(&mut writer, &Response::Error(e.to_string()));
            return;
        }
    };
    let mut next_seq = from_seq;
    for record in subscription.replay {
        next_seq = record.seq + 1;
        if write_line(&mut writer, &Response::Record(Box::new(record))).is_err() {
            return;
        }
    }
    // A replay-only subscription (the log was already sealed when `subscribe`
    // ran) has nothing live to mark a boundary against: the connection
    // closing right behind the last record already says "that was everything,
    // unambiguously and immediately" — sending a marker here would only give
    // a client one more line to read before learning the same thing.
    let Some((live, hangup)) = subscription.live else {
        return;
    };
    // The replay set was fixed atomically under the same mutex as every
    // append, in `Served::subscribe` above, so this marker is an exact
    // boundary, not a guess: everything before it is the replay this live
    // subscription started with, everything after is live (#138 item 1). A
    // client that waits for this instead of a silence timeout gets its first
    // render, or its initial pending-approval listing, as soon as the
    // backlog it asked for is actually delivered — regardless of how much
    // live traffic follows right behind it.
    if write_line(&mut writer, &Response::CaughtUp { next_seq }).is_err() {
        return;
    }
    // A subscriber sends nothing more, so its next read completing is its
    // disconnect: end the stream then.
    let watcher = std::thread::spawn(move || {
        let mut reader = reader;
        let mut ignored = String::new();
        while matches!(reader.read_line(&mut ignored), Ok(n) if n > 0) {
            ignored.clear();
        }
        let _ = hangup.send(Delivery::End);
    });
    for delivery in live {
        match delivery {
            Delivery::Record(record) => {
                if write_line(&mut writer, &Response::Record(record)).is_err() {
                    break;
                }
            }
            Delivery::End => break,
        }
    }
    let _ = writer.shutdown(Shutdown::Both);
    let _ = watcher.join();
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use ward_events::{
        AgentState, Blake3Hash, DetailText, EndReason, Origin, PolicySubject, RuleRef, SessionId,
        WardEvent,
    };
    use ward_policy::{Policy, merge};

    #[test]
    fn oversized_request_line_is_rejected() {
        // A complete line (ends in newline) under the cap is fine, however long.
        assert!(!request_too_large("{\"x\":1}\n"));
        assert!(!request_too_large(""));
        // A line at/over the cap with no terminating newline is a truncated,
        // unbounded stream and must be rejected rather than parsed.
        let cap = usize::try_from(MAX_REQUEST_BYTES).unwrap();
        let huge = "x".repeat(cap);
        assert!(request_too_large(&huge));
        // At the cap but properly terminated is still accepted.
        let mut capped = "x".repeat(cap - 1);
        capped.push('\n');
        assert!(!request_too_large(&capped));
    }

    fn working() -> WardEvent {
        WardEvent::AgentStateChanged {
            state: AgentState::Working,
        }
    }

    fn append(seq_hint: u64) -> Request {
        Request::Append {
            origin: Origin::Wardd,
            event: working(),
            at_unix_ms: seq_hint,
        }
    }

    fn denied() -> WardEvent {
        WardEvent::PolicyDenied {
            subject: PolicySubject::ProtectedTests,
            rule: RuleRef::new("tests").unwrap(),
            detail: DetailText::new("tests/x.rs"),
        }
    }

    fn fresh_served(dir: &Path) -> Served {
        fresh_served_as(dir, "sess_9")
    }

    /// [`fresh_served`] for a named session: tests that run real processes
    /// under a session's run directory need an id no other test shares.
    fn fresh_served_as(dir: &Path, session: &str) -> Served {
        let log_path = dir.join("events.log");
        let log = LocalLog::create(
            &log_path,
            SessionId::from_u128(9),
            Blake3Hash::from_bytes([2; 32]),
            SystemTime::now(),
        )
        .unwrap();
        let deriver = Deriver::new(
            ward_policy::default_manifest(),
            Some("hexrift/WardOS".into()),
            vec!["tests/security_expiry.rs".into()],
        );
        std::fs::create_dir_all(session_dir(dir, session)).unwrap();
        Served::new(
            log,
            log_path,
            serde_json::json!({ "session": session }),
            deriver,
            dir.to_path_buf(),
            session.to_owned(),
        )
    }

    /// The kinds of every record in `served`'s log, by name, in order.
    fn kinds_of(served: &mut Served) -> Vec<String> {
        served
            .subscribe(0)
            .unwrap()
            .replay
            .iter()
            .map(|r| format!("{:?}", r.event.kind()))
            .collect()
    }

    /// #145 item 5, end to end in the daemon against real processes: `ward
    /// stop` on a *running* session (never paused) ends every process of its
    /// sandbox and confirms it gone before sealing, records how many, and
    /// answers with the count. Before this, `Request::Stop` sealed the log and
    /// left the agent running unobserved. `Finished` lands only after the
    /// confirmed termination (PR #253 review finding 5).
    #[test]
    fn stop_ends_a_running_sandbox_before_sealing() {
        let dir = tempfile::tempdir().unwrap();
        let mut sandbox = pause::FakeSandbox::spawn("sess_stoprun");
        let mut served = fresh_served_as(dir.path(), &sandbox.session);
        let (response, done) = served.handle(Request::Stop {
            reason: EndReason::UserStop,
        });
        let Response::Sealed {
            ended: Some(ended), ..
        } = response
        else {
            panic!("{response:?}");
        };
        assert!(done, "the log is sealed");
        assert!(ended >= 2, "the shell and its child: {ended}");
        assert!(sandbox.was_killed(), "the sandbox root died of SIGKILL");
        assert!(pause::sandbox_pids(Path::new("/proc"), &sandbox.session).is_empty());
        let replay = LogReader::open(&served.log_path)
            .unwrap()
            .map_while(std::result::Result::ok)
            .collect::<Vec<_>>();
        let kinds: Vec<_> = replay
            .iter()
            .map(|r| format!("{:?}", r.event.kind()))
            .collect();
        assert_eq!(
            kinds,
            ["WorkloadsTerminated", "AgentStateChanged", "SessionEnded"],
            "{kinds:?}"
        );
        assert!(matches!(
            replay[0].event,
            WardEvent::WorkloadsTerminated { ended: e, pending: 0 } if e == ended
        ));
        assert_eq!(replay[0].origin, Origin::Wardd);
        assert!(!pause::marker_path(dir.path(), &sandbox.session).exists());
    }

    /// The explicit other operation (#145 item 5): `Request::Seal` is log-only
    /// closure and does not touch a running sandbox — and its answer carries no
    /// termination acknowledgement (`ended: None`), so no client can mistake it
    /// for a stop.
    #[test]
    fn seal_is_log_only_closure_and_leaves_a_running_sandbox_alone() {
        let dir = tempfile::tempdir().unwrap();
        let mut sandbox = pause::FakeSandbox::spawn("sess_sealrun");
        let mut served = fresh_served_as(dir.path(), &sandbox.session);
        let (response, done) = served.handle(Request::Seal);
        assert!(
            matches!(response, Response::Sealed { ended: None, .. }),
            "{response:?}"
        );
        assert!(done);
        std::thread::sleep(Duration::from_millis(100));
        assert!(sandbox.running(), "a seal does not end the workloads");
    }

    /// PR #253 review finding 1, daemon side: the daemon names the features a
    /// 0.19 client checks for before it sends `Stop` or `HoldForStop`.
    #[test]
    fn capabilities_name_confirmed_stop_and_the_stop_hold() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let (Response::Capabilities { features }, false) = served.handle(Request::Capabilities)
        else {
            panic!("capabilities");
        };
        assert!(
            features
                .iter()
                .any(|f| f == control::FEATURE_STOP_TERMINATES)
        );
        assert!(features.iter().any(|f| f == control::FEATURE_STOP_HOLD));
        assert!(kinds_of(&mut served).is_empty(), "nothing is recorded");
    }

    /// A pause's freeze is what a stop from paused terminates: the held
    /// `Frozen` is handed to `terminate` (not re-frozen from scratch), and a
    /// confirmed termination clears the marker and seals.
    #[test]
    fn stop_from_paused_terminates_the_pauses_own_freeze() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let held = Frozen {
            method: ward_events::PauseMethod::Sigstop,
            pids: vec![41, 42],
            cgroup: None,
        };
        served.paused = Some(Paused {
            frozen: held.clone(),
            since: Instant::now(),
            hold: Hold::Pause,
        });
        pause::write_marker(dir.path(), "sess_9", "looks wrong").unwrap();
        let mut given = None;
        let (response, done) = served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |s, f| {
            assert_eq!(s, "sess_9");
            given = f;
            pause::Termination::confirmed(2)
        });
        assert_eq!(given, Some(held), "the pause's freeze, as held");
        assert!(
            matches!(response, Response::Sealed { ended: Some(2), .. }),
            "{response:?}"
        );
        assert!(done);
        assert!(served.paused.is_none());
        assert!(!pause::marker_path(dir.path(), "sess_9").exists());
    }

    /// #145 items 4-5: a stop that cannot confirm every process ended is
    /// refused, never reported as done — the log stays unsealed, the session is
    /// held for the stop over exactly what is left (marker written, approvals
    /// held), and `WorkloadsTerminated { pending }` records the partial outcome.
    /// A retry hands the held remainder back to `terminate` and, once that is
    /// confirmed, seals. Deterministic: `terminate` is injected.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_stop_that_cannot_confirm_termination_is_refused_and_held_paused_until_a_retry() {
        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let marker = pause::marker_path(dir.path(), "sess_9");
        // A question is open when the stop is attempted.
        let holding = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || hold(&served, "Write", "/work/a.rs", "r", 30))
        };
        assert!(wait_until(Duration::from_secs(2), || {
            !lock(&served).approvals.pending().is_empty()
        }));
        let stuck = Frozen {
            method: ward_events::PauseMethod::Sigstop,
            pids: vec![77],
            cgroup: None,
        };
        let (response, done) = {
            let stuck = stuck.clone();
            lock(&served).stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, held| {
                assert_eq!(held, None, "nothing was paused");
                pause::Termination {
                    ended: 3,
                    remaining: Some(stuck),
                    barrier_confirmed: true,
                }
            })
        };
        let Response::Error(message) = response else {
            panic!("{response:?}");
        };
        assert!(!done, "not sealed");
        assert!(message.contains("3 ended, 1 still present"), "{message}");
        assert!(message.contains("held for it"), "{message}");
        assert!(message.contains("not sealed"), "{message}");
        {
            let mut served = lock(&served);
            assert!(served.log.is_some(), "the log is still open");
            let paused = served.paused.as_ref().unwrap();
            assert_eq!(paused.frozen, stuck, "held over exactly what is left");
            assert_eq!(paused.hold, Hold::Stop, "an incomplete stop, not a pause");
            assert!(served.approvals.paused(), "approvals held");
            assert_eq!(
                served.approvals.pending().len(),
                1,
                "the open question is held, not closed out"
            );
            let kinds = kinds_of(&mut served);
            assert_eq!(
                kinds.last().map(String::as_str),
                Some("WorkloadsTerminated")
            );
            assert!(!kinds.iter().any(|k| k == "SessionEnded"), "{kinds:?}");
            let last = served.subscribe(0).unwrap().replay.pop().unwrap();
            assert!(matches!(
                last.event,
                WardEvent::WorkloadsTerminated {
                    ended: 3,
                    pending: 1
                }
            ));
        }
        assert!(
            std::fs::read_to_string(&marker)
                .unwrap()
                .starts_with("ward stop: 1 process(es) not confirmed ended"),
            "the proxy refuses while held"
        );
        // Still a session: a pause is refused as already in force (it is),
        // and it is the retry that ends it.
        assert!(matches!(
            lock(&served).handle(Request::Pause { reason: String::new() }).0,
            Response::Error(e) if e == "already paused"
        ));

        let (response, done) =
            lock(&served).stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, held| {
                assert_eq!(held, Some(stuck), "the retry gets the held remainder");
                pause::Termination::confirmed(1)
            });
        assert!(
            matches!(response, Response::Sealed { ended: Some(1), .. }),
            "{response:?}"
        );
        assert!(done);
        assert!(!marker.exists());
        assert!(matches!(
            holding.join().unwrap(),
            Response::Decision { decision: crate::hooks::HookDecision::Deny, reason, .. }
                if reason == "approval: session ended"
        ));
        let kinds: Vec<_> = LogReader::open(&lock(&served).log_path)
            .unwrap()
            .map_while(std::result::Result::ok)
            .map(|r| format!("{:?}", r.event.kind()))
            .collect();
        let tail = &kinds[kinds.len() - 4..];
        assert_eq!(
            tail,
            [
                "WorkloadsTerminated",
                "AgentStateChanged",
                "CapabilityDecided",
                "SessionEnded"
            ],
            "{kinds:?}"
        );
    }

    /// The agent states the log recorded, in order.
    fn agent_states(served: &mut Served) -> Vec<AgentState> {
        served
            .subscribe(0)
            .unwrap()
            .replay
            .iter()
            .filter_map(|r| match r.event {
                WardEvent::AgentStateChanged { state } => Some(state),
                _ => None,
            })
            .collect()
    }

    /// PR #253 review finding 5, the actual event sequence: `Working` → a
    /// refused `Stop` → `Resume` → retry. The refused stop records no
    /// `Finished` (nothing was confirmed); the `Resume` is refused — the held
    /// process already took `SIGKILL`, so this is an incomplete stop, not a
    /// resumable pause — and changes nothing; the retry, once confirmed,
    /// records `Finished` exactly once, after the termination and before
    /// `SessionEnded`.
    #[test]
    fn working_then_a_refused_stop_then_resume_is_refused_and_only_the_retry_finishes() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        assert!(matches!(served.handle(append(0)).0, Response::Record(_)));
        let stuck = Frozen {
            method: ward_events::PauseMethod::Sigstop,
            pids: vec![999_999],
            cgroup: None,
        };
        let (response, done) = {
            let stuck = stuck.clone();
            served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, _| {
                pause::Termination {
                    ended: 2,
                    remaining: Some(stuck),
                    barrier_confirmed: true,
                }
            })
        };
        assert!(matches!(response, Response::Error(_)), "{response:?}");
        assert!(!done);
        assert_eq!(
            agent_states(&mut served),
            [AgentState::Working],
            "no Finished yet"
        );
        let before = kinds_of(&mut served);
        assert_eq!(before, ["AgentStateChanged", "WorkloadsTerminated"]);

        let (response, _) = served.handle(Request::Resume);
        let Response::Error(message) = response else {
            panic!("{response:?}");
        };
        assert!(message.contains("cannot release"), "{message}");
        assert_eq!(
            kinds_of(&mut served),
            before,
            "the refused resume records nothing"
        );
        assert_eq!(served.paused.as_ref().map(|p| p.hold), Some(Hold::Stop));
        assert!(served.approvals.paused());
        assert!(pause::marker_path(dir.path(), "sess_9").exists());

        let (response, done) =
            served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, held| {
                assert_eq!(held, Some(stuck), "the retry gets the held remainder");
                pause::Termination::confirmed(1)
            });
        assert!(
            matches!(response, Response::Sealed { ended: Some(1), .. }),
            "{response:?}"
        );
        assert!(done);
        assert_eq!(
            agent_states(&mut served),
            [AgentState::Working, AgentState::Finished]
        );
        assert_eq!(
            kinds_of(&mut served),
            [
                "AgentStateChanged",
                "WorkloadsTerminated",
                "WorkloadsTerminated",
                "AgentStateChanged",
                "SessionEnded"
            ]
        );
    }

    /// A 0.18 client appends `Finished` itself before it asks to stop; the
    /// daemon must not record a second one.
    #[test]
    fn a_client_that_already_recorded_finished_gets_no_second_one() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let finished = Request::Append {
            origin: Origin::Wardd,
            event: WardEvent::AgentStateChanged {
                state: AgentState::Finished,
            },
            at_unix_ms: 0,
        };
        assert!(matches!(served.handle(finished).0, Response::Record(_)));
        let (response, done) = served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, _| {
            pause::Termination::nothing()
        });
        assert!(
            matches!(response, Response::Sealed { ended: Some(0), .. }),
            "{response:?}"
        );
        assert!(done);
        assert_eq!(agent_states(&mut served), [AgentState::Finished]);
    }

    /// PR #253 review finding 2, deterministic barrier: a launch that has been
    /// admitted (`pause::admit_launch` holds the session lock across its
    /// `bwrap` spawn) and a stop that arrives meanwhile are serialized — the
    /// stop cannot scan until the spawn has returned, so what it scans includes
    /// the new sandbox. The order is recorded by both sides; without the shared
    /// lock the stop would scan first (the launch waits 150 ms before
    /// "spawning").
    #[test]
    fn a_launch_admitted_before_a_stop_spawns_before_the_stops_scan() {
        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let order = Arc::new(Mutex::new(Vec::new()));
        let admitted = pause::admit_launch(dir.path(), "sess_9").expect("admitted");
        let stopping = {
            let (served, order) = (Arc::clone(&served), Arc::clone(&order));
            std::thread::spawn(move || {
                lock(&served).stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, _| {
                    order.lock().unwrap().push("scanned");
                    pause::Termination::confirmed(1)
                })
            })
        };
        std::thread::sleep(Duration::from_millis(150));
        order.lock().unwrap().push("spawned");
        drop(admitted);
        let (response, done) = stopping.join().unwrap();
        assert!(
            matches!(response, Response::Sealed { ended: Some(1), .. }),
            "{response:?}"
        );
        assert!(done);
        assert_eq!(*order.lock().unwrap(), ["spawned", "scanned"]);
    }

    /// PR #253 review finding 2, the reviewer's exact ordering: a launch passes
    /// the early check, stalls, the stop runs (scans nothing, seals), and the
    /// launch then reaches its spawn. The spawn's own admission — under the
    /// session lock, after the stop marker — refuses it, so nothing is
    /// spawned: the error is the admission refusal, never bubblewrap's own
    /// (`bwrap` is not needed for this test to be meaningful). Deterministic:
    /// the launch's admission is held on a channel until the stop has sealed.
    #[test]
    fn a_launch_that_stalls_past_a_stop_is_refused_before_it_spawns() {
        let dir = tempfile::tempdir().unwrap();
        let worktree = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let (past_check, stalled) = std::sync::mpsc::channel::<()>();
        let (stopped, release) = std::sync::mpsc::channel::<()>();
        let state = dir.path().to_path_buf();
        let launching = std::thread::spawn(move || {
            let launch = crate::sandbox::Launch::new(worktree.path(), vec!["/bin/true".into()]);
            let mut admit = || {
                past_check.send(()).unwrap();
                release.recv().unwrap();
                pause::admit_launch(&state, "sess_9").map(|g| Box::new(g) as Box<dyn std::any::Any>)
            };
            launch.run_admitted(&mut admit, &mut || {}).map(|_| ())
        });
        stalled.recv().unwrap();
        let (response, done) = served.handle(Request::Stop {
            reason: EndReason::UserStop,
        });
        assert!(
            matches!(response, Response::Sealed { ended: Some(0), .. }),
            "{response:?}"
        );
        assert!(done);
        stopped.send(()).unwrap();
        let err = launching.join().unwrap().unwrap_err().to_string();
        assert!(err.contains(pause::STOPPED_REFUSAL), "{err}");
        assert!(!err.contains("bwrap"), "nothing was spawned: {err}");
        assert!(pause::admit_launch(dir.path(), "sess_9").is_err());
    }

    /// Launch admission and pause share the lock too: a paused session admits
    /// no spawn, and a resumed one does again.
    #[test]
    fn a_paused_session_admits_no_launch_until_resumed() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        assert!(matches!(
            served
                .handle(Request::Pause {
                    reason: String::new()
                })
                .0,
            Response::Paused { .. }
        ));
        let err = pause::admit_launch(dir.path(), "sess_9")
            .unwrap_err()
            .to_string();
        assert!(err.contains(pause::PAUSED_REFUSAL), "{err}");
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Record(_)
        ));
        drop(pause::admit_launch(dir.path(), "sess_9").expect("admitted again"));
    }

    /// PR #253 review finding 3, stale marker / restarted daemon: a pause
    /// marker on disk that this daemon did not write (its predecessor died
    /// while paused, or thawed without clearing it) holds nothing. A
    /// `HoldForStop` must not trust it: it freezes the running sandbox itself,
    /// records `SessionPaused`, and the stop then ends that tree.
    #[test]
    fn hold_for_stop_freezes_for_itself_even_with_a_stale_marker_from_before_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut sandbox = pause::FakeSandbox::spawn("sess_stale");
        let mut served = fresh_served_as(dir.path(), &sandbox.session);
        pause::write_marker(dir.path(), &sandbox.session, "left by a dead wardd").unwrap();
        assert!(served.paused.is_none(), "this daemon holds nothing");
        assert!(!sandbox.stopped(), "the sandbox runs, marker or not");

        let (response, _) = served.handle(Request::HoldForStop {
            reason: "ward stop --restore-entry".into(),
        });
        assert!(
            matches!(response, Response::HeldForStop { unsettled: None }),
            "{response:?}"
        );
        let paused = served.paused.as_ref().unwrap();
        assert!(
            sandbox.frozen_by(&paused.frozen),
            "frozen by the hold itself"
        );
        assert_eq!(paused.hold, Hold::Stop);
        assert!(paused.frozen.pids.contains(&sandbox.root()));
        assert!(pause::stop_begun(dir.path(), &sandbox.session));
        assert_eq!(kinds_of(&mut served), ["SessionPaused"]);

        let (response, done) = served.handle(Request::Stop {
            reason: EndReason::UserStop,
        });
        assert!(done, "{response:?}");
        assert!(sandbox.was_killed());
    }

    /// PR #253 review finding 3, concurrent Resume and launch: once held for a
    /// stop, the session cannot be released by another client's `Resume`, no
    /// launch is admitted, and a second `Pause` changes nothing — only the stop
    /// ends the hold.
    #[test]
    fn a_stop_hold_cannot_be_released_by_resume_or_bypassed_by_a_launch() {
        let dir = tempfile::tempdir().unwrap();
        let mut sandbox = pause::FakeSandbox::spawn("sess_hold");
        let mut served = fresh_served_as(dir.path(), &sandbox.session);
        assert!(matches!(
            served
                .handle(Request::HoldForStop {
                    reason: String::new()
                })
                .0,
            Response::HeldForStop { unsettled: None }
        ));
        let (response, _) = served.handle(Request::Resume);
        assert!(
            matches!(&response, Response::Error(e) if e.contains("cannot release")),
            "{response:?}"
        );
        let frozen = served.paused.as_ref().unwrap().frozen.clone();
        assert!(
            sandbox.frozen_by(&frozen),
            "still frozen after the refused resume"
        );
        assert!(served.approvals.paused());
        let err = pause::admit_launch(dir.path(), &sandbox.session)
            .unwrap_err()
            .to_string();
        assert!(err.contains(pause::STOPPED_REFUSAL), "{err}");
        assert!(matches!(
            served.handle(Request::Pause { reason: String::new() }).0,
            Response::Error(e) if e == "already paused"
        ));
        // A capture freeze (the restore's own) holds nothing and thaws nothing.
        let capture = pause::CaptureFreeze::acquire(dir.path(), &sandbox.session);
        assert_eq!(capture.method(), None);
        drop(capture);
        assert!(sandbox.frozen_by(&frozen), "the capture thawed nothing");

        let (response, done) = served.handle(Request::Stop {
            reason: EndReason::UserStop,
        });
        assert!(
            matches!(response, Response::Sealed { ended: Some(n), .. } if n >= 2),
            "{response:?}"
        );
        assert!(done);
        assert!(sandbox.was_killed());
    }

    /// A `HoldForStop` on a session the user has already paused takes that
    /// pause over (no second record) and makes it unreleasable.
    #[test]
    fn hold_for_stop_takes_over_a_pause_in_force() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        assert!(matches!(
            served
                .handle(Request::Pause {
                    reason: "mine".into()
                })
                .0,
            Response::Paused { .. }
        ));
        assert!(matches!(
            served
                .handle(Request::HoldForStop {
                    reason: String::new()
                })
                .0,
            Response::HeldForStop { unsettled: None }
        ));
        assert_eq!(served.paused.as_ref().map(|p| p.hold), Some(Hold::Stop));
        assert_eq!(kinds_of(&mut served), ["SessionPaused"]);
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Error(_)
        ));
    }

    /// A hold whose freeze cannot be confirmed stable says so — the restore
    /// that asked for it must not proceed — and still stands, recorded as
    /// unsettled. Deterministic: the freeze is injected, holding a pid that is
    /// really running (this test process) so the recount finds it pending.
    #[test]
    fn an_unconfirmed_stop_hold_is_reported_and_still_held() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let unsettled = served
            .hold_for_stop_with(
                "r",
                |_| {
                    (
                        Frozen {
                            method: ward_events::PauseMethod::Sigstop,
                            pids: vec![std::process::id()],
                            cgroup: None,
                        },
                        false,
                    )
                },
                |_, f| (f, true),
            )
            .unwrap();
        assert_eq!(unsettled, Some(1));
        assert_eq!(served.paused.as_ref().map(|p| p.hold), Some(Hold::Stop));
        assert_eq!(kinds_of(&mut served), ["SessionPauseUnsettled"]);
        // Never signal this test process: forget the injected freeze.
        served.paused = None;
    }

    /// ADR-0019 §3 in the daemon: a pause writes the marker, holds the
    /// approvals and records itself; a second pause is refused; resume undoes
    /// it and records; a stop from paused seals with the marker gone.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn pause_holds_approvals_writes_the_marker_and_records_until_resume_or_stop() {
        use crate::approvals::ApprovalDecision;
        use ward_events::PauseMethod;

        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let marker = pause::marker_path(dir.path(), "sess_9");
        let sub = lock(&served).subscribe(0).unwrap();
        let (rx, _hangup) = sub.live.unwrap();

        // A question is open when the pause lands.
        let holding = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || hold(&served, "Write", "/work/a.rs", "r", 1))
        };
        assert!(wait_until(Duration::from_secs(2), || {
            !lock(&served).approvals.pending().is_empty()
        }));

        let (record, unsettled) = match lock(&served)
            .handle(Request::Pause {
                reason: " looks wrong ".into(),
            })
            .0
        {
            Response::Paused { record, unsettled } => (*record, unsettled),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            unsettled, None,
            "no real sandbox process runs in this test; an empty pid set settles trivially"
        );
        assert_eq!(record.origin, Origin::Wardd);
        assert!(matches!(
            &record.event,
            WardEvent::SessionPaused { method, reason }
                if matches!(method, PauseMethod::Sigstop | PauseMethod::CgroupFreezer)
                    && reason.as_str() == "looks wrong"
        ));
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "looks wrong\n",
            "the proxies' marker"
        );
        assert!(lock(&served).approvals.paused());
        assert!(matches!(
            lock(&served).handle(Request::Pause { reason: String::new() }).0,
            Response::Error(e) if e == "already paused"
        ));
        // The daemon says so (#146 item 4): the question's countdown is
        // held, and does not move while the pause lasts.
        let countdown = |served: &Arc<Mutex<Served>>| match lock(served).handle(Request::Pending).0
        {
            Response::Pending(p) => p[0].countdown.expect("an armed clock"),
            other => panic!("{other:?}"),
        };
        let before = countdown(&served);
        assert!(before.held, "{before:?}");
        assert_eq!(before.timeout_ms, 1000);
        assert!(before.remaining_ms <= 1000, "{before:?}");
        // The open question stays open past its own timeout, and cannot be
        // answered while paused.
        std::thread::sleep(Duration::from_millis(1200));
        assert!(!holding.is_finished(), "held in turn");
        assert_eq!(countdown(&served), before, "the clock stands still");
        assert!(matches!(
            lock(&served).handle(Request::Approve { id: 0, decision: ApprovalDecision::Allow }).0,
            Response::Error(e) if e.contains("paused by ward")
        ));

        let record = match lock(&served).handle(Request::Resume).0 {
            Response::Record(r) => *r,
            other => panic!("{other:?}"),
        };
        assert!(matches!(
            &record.event,
            WardEvent::SessionResumed { paused_for } if *paused_for >= Duration::from_millis(1000)
        ));
        assert!(!marker.exists(), "the marker is gone");
        assert!(!lock(&served).approvals.paused());
        // Resumed, the countdown runs on from where it stood — the question
        // may already have timed out by the time this looks, never refilled.
        if let Response::Pending(p) = lock(&served).handle(Request::Pending).0
            && let Some(after) = p.first().and_then(|a| a.countdown)
        {
            assert!(!after.held, "{after:?}");
            assert!(after.remaining_ms <= before.remaining_ms, "{after:?}");
        }
        assert!(matches!(
            lock(&served).handle(Request::Resume).0,
            Response::Error(e) if e == "not paused"
        ));
        // Resumed, the clock runs: the question times out on its own.
        assert!(matches!(
            holding.join().unwrap(),
            Response::Decision { reason, .. } if reason == "approval: timed out"
        ));

        // Paused again, then stopped: the log seals, the marker is gone.
        assert!(matches!(
            lock(&served)
                .handle(Request::Pause {
                    reason: String::new()
                })
                .0,
            Response::Paused {
                unsettled: None,
                ..
            }
        ));
        assert!(marker.exists());
        let (response, done) = lock(&served).handle(Request::Stop {
            reason: EndReason::UserStop,
        });
        assert!(done, "{response:?}");
        assert!(!marker.exists());
        let (live, ended) = drain(&rx);
        let kinds: Vec<_> = live
            .iter()
            .map(|r| format!("{:?}", r.event.kind()))
            .collect();
        assert_eq!(
            kinds,
            [
                "CapabilityRequested",
                "SessionPaused",
                "SessionResumed",
                "CapabilityDecided",
                "SessionPaused",
                // The daemon's own `Finished`, once the stop's termination is
                // confirmed (PR #253 review finding 5).
                "AgentStateChanged",
                "SessionEnded"
            ]
        );
        assert!(ended);
        assert!(matches!(
            lock(&served).handle(Request::Pause { reason: String::new() }).0,
            Response::Error(e) if e == "log is sealed"
        ));
    }

    /// #145 items 3-4, PR #207 review finding 1: when the freeze cannot be
    /// confirmed settled within the bound, the pause still proceeds — the marker
    /// is written and the approvals are still held (the safest achievable
    /// state) — but the outcome is visibly different from a clean pause: the RPC
    /// response carries `unsettled`, and the log carries `SessionPauseUnsettled`
    /// *instead of* `SessionPaused`, never both and never the confirmed variant
    /// first — the settle check now runs before either is appended, so no
    /// subscriber can ever see a `SessionPaused` that later turns out to have
    /// been unsettled. `pause_with` injects the settle check because `SIGSTOP`
    /// cannot be resisted by a real process for a test to race against (see
    /// `Served::pause_with`'s own doc comment).
    #[test]
    fn an_unsettled_freeze_still_pauses_but_is_never_reported_as_a_clean_success() {
        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let marker = pause::marker_path(dir.path(), "sess_9");
        let sub = lock(&served).subscribe(0).unwrap();
        let (rx, _hangup) = sub.live.unwrap();

        let outcome = lock(&served)
            .pause_with("looks wrong", |_frozen| Some(3))
            .unwrap();
        assert_eq!(
            outcome.unsettled,
            Some(3),
            "the injected settle check's answer is reported back, unchanged"
        );
        assert!(
            matches!(
                &outcome.record.event,
                WardEvent::SessionPauseUnsettled { reason, pending: 3, .. }
                    if reason.as_str() == "looks wrong"
            ),
            "{:?}",
            outcome.record.event
        );
        // The safest achievable state: preserved exactly as it would be for a
        // confirmed pause, regardless of the settle outcome.
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "looks wrong\n",
            "the proxies' marker is written either way"
        );
        assert!(lock(&served).approvals.paused());
        assert!(
            lock(&served).paused.is_some(),
            "the freeze is still recorded as held"
        );

        // A second pause is still refused, same as after a confirmed one: an
        // unsettled pause is a pause, not a no-op.
        assert!(matches!(
            lock(&served).handle(Request::Pause { reason: String::new() }).0,
            Response::Error(e) if e == "already paused"
        ));

        let (live, _ended) = drain(&rx);
        let kinds: Vec<_> = live
            .iter()
            .map(|r| format!("{:?}", r.event.kind()))
            .collect();
        assert_eq!(
            kinds,
            ["SessionPauseUnsettled"],
            "the single terminal record for an unsettled pause — never a \
             `SessionPaused` record that a qualifier only later corrects"
        );

        // A settled freeze reports `SessionPaused` and nothing else: today's
        // behaviour is unchanged when the daemon can confirm the freeze.
        lock(&served)
            .resume()
            .expect("resume the unsettled pause so a second pause can be tried");
        let settled = lock(&served).pause_with("", |_frozen| None).unwrap();
        assert_eq!(settled.unsettled, None);
        assert!(matches!(
            &settled.record.event,
            WardEvent::SessionPaused { .. }
        ));
    }

    /// PR #207 review finding 2: an append failure on the unsettled path's
    /// terminal record must never be silently discarded (the old `let _ =
    /// self.append(...)`) — the caller learns the log may not actually contain
    /// the `SessionPauseUnsettled` it is about to be told happened, while the
    /// marker, held approvals and frozen tree all stand exactly as they would
    /// for a successfully-logged unsettled pause (a log-only failure must never
    /// undo a real, correct freeze), and `ward resume` still works afterwards.
    /// The failure is made reproducible the same way `settle` already is
    /// injected above: `pause_with_appending`'s `append` closure always fails,
    /// deterministically, with no real disk exhaustion needed.
    #[test]
    fn an_unsettled_pauses_append_failure_is_surfaced_not_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let marker = pause::marker_path(dir.path(), "sess_9");

        let err = served
            .pause_with_appending(
                "looks wrong",
                |_frozen| Some(3),
                |_served, _event| {
                    Err(Error::Daemon(
                        "simulated log failure (storage exhaustion)".into(),
                    ))
                },
            )
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("could not be confirmed settled") && msg.contains("3 process"),
            "{msg}"
        );
        assert!(
            msg.contains("simulated log failure"),
            "the underlying append failure is folded in, not discarded: {msg}"
        );

        // The safest achievable state stands regardless of the log-only failure:
        // the marker is on disk, the approvals are held, and the freeze is still
        // recorded as held — none of it is rolled back for a failure this far in.
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "looks wrong\n",
            "the marker is written before the settle check even runs"
        );
        assert!(served.approvals.paused(), "the approvals stay held");
        assert!(
            served.paused.is_some(),
            "the freeze is still recorded as held, even though the log does not \
             (yet, or ever) agree the pause happened"
        );

        // Unlike the old silently-discarded qualifier append, this failure never
        // leaves the session stuck: `ward resume` still releases the real freeze.
        let resumed = served
            .resume()
            .expect("resume still works after the log-only failure");
        assert!(matches!(&resumed.event, WardEvent::SessionResumed { .. }));
        assert!(
            !marker.exists(),
            "resume clears the marker despite the earlier failure"
        );
    }

    fn seqs(records: &[EventRecord]) -> Vec<u64> {
        records.iter().map(|r| r.seq).collect()
    }

    fn drain(rx: &Receiver<Delivery>) -> (Vec<EventRecord>, bool) {
        let mut records = Vec::new();
        let mut ended = false;
        while let Ok(delivery) = rx.try_recv() {
            match delivery {
                Delivery::Record(r) => records.push(*r),
                Delivery::End => ended = true,
            }
        }
        (records, ended)
    }

    #[test]
    fn broadcast_replays_then_streams_live_without_gaps() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        for i in 0..3 {
            assert!(matches!(served.handle(append(i)).0, Response::Record(_)));
        }
        let sub = served.subscribe(1).unwrap();
        assert_eq!(seqs(&sub.replay), [1, 2]);
        let (rx, _hangup) = sub.live.unwrap();
        let dropped = served.subscribe(0).unwrap();
        assert_eq!(seqs(&dropped.replay), [0, 1, 2]);
        drop(dropped.live);
        assert_eq!(served.subscribers.len(), 2);

        served.handle(append(3));
        served.handle(Request::Evidence { event: denied() });
        let (live, ended) = drain(&rx);
        assert_eq!(seqs(&live), [3, 4], "live records follow the replay");
        assert_eq!(live[1].origin, Origin::TamperWard);
        assert!(!ended);
        assert_eq!(
            served.subscribers.len(),
            1,
            "a subscriber whose channel is closed is dropped"
        );

        let (response, done) = served.handle(Request::Stop {
            reason: EndReason::UserStop,
        });
        assert!(done);
        // The daemon's own `Finished` (PR #253 review finding 5: recorded once
        // termination is confirmed, not by the client beforehand), then the end.
        assert!(
            matches!(response, Response::Sealed { head, ended: Some(0) } if head.next_seq == 7)
        );
        let (tail, ended) = drain(&rx);
        assert_eq!(seqs(&tail), [5, 6]);
        assert!(matches!(
            tail[0].event,
            WardEvent::AgentStateChanged {
                state: AgentState::Finished
            }
        ));
        assert!(matches!(tail[1].event, WardEvent::SessionEnded { .. }));
        assert!(ended, "sealing ends every subscription");
        assert!(served.subscribers.is_empty());

        // After the seal a subscription is the replay alone.
        let after = served.subscribe(4).unwrap();
        assert_eq!(seqs(&after.replay), [4, 5, 6]);
        assert!(after.live.is_none());
        assert!(matches!(
            served.handle(Request::Ping),
            (Response::Error(_), true)
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_held_approval_is_recorded_listed_answered_and_recorded_again() {
        use crate::approvals::ApprovalDecision;
        use crate::hooks::HookDecision;
        use ward_events::{CapabilityKind, Decision, DecisionSource, GrantScope};

        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let sub = lock(&served).subscribe(0).unwrap();
        let (rx, _hangup) = sub.live.unwrap();

        // Nothing pending, nothing to answer.
        assert!(matches!(
            lock(&served).handle(Request::Pending).0,
            Response::Pending(p) if p.is_empty()
        ));
        assert!(matches!(
            lock(&served).handle(Request::Approve { id: 0, decision: ApprovalDecision::Allow }).0,
            Response::Error(e) if e == "approval 0: not pending"
        ));

        // A hold blocks its thread until the answer arrives.
        let holding = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || {
                hold(
                    &served,
                    "Write",
                    "/work/src/lib.rs",
                    "step-through: pause before writes",
                    5,
                )
            })
        };
        assert!(wait_until(Duration::from_secs(2), || {
            !lock(&served).approvals.pending().is_empty()
        }));
        let pending = match lock(&served).handle(Request::Pending).0 {
            Response::Pending(p) => p,
            other => panic!("{other:?}"),
        };
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, 0, "the seq of the request record");
        assert_eq!(pending[0].tool, "Write");
        assert_eq!(
            pending[0].claim, "Write /work/src/lib.rs",
            "the agent's words"
        );
        assert_eq!(pending[0].authority.destination, "/work/src/lib.rs");
        assert_eq!(pending[0].authority.method, "write");
        // Its decision clock is the hold's own `timeout_secs`, armed as it
        // was registered and running (#146 item 4).
        let countdown = pending[0].countdown.expect("armed at registration");
        assert_eq!(countdown.timeout_ms, 5000);
        assert!(!countdown.held);
        assert!(countdown.remaining_ms <= 5000, "{countdown:?}");
        assert_eq!(
            pending[0].authority.rule,
            "step-through: pause before writes"
        );
        let (live, _) = drain(&rx);
        assert_eq!(seqs(&live), [0], "the subscriber saw the request");
        assert!(matches!(
            &live[0].event,
            WardEvent::CapabilityRequested { cap, reason }
                if cap.kind == CapabilityKind::FileWrite
                    && cap.target.as_str() == "Write /work/src/lib.rs"
                    && reason.as_ref().unwrap().as_str() == "step-through: pause before writes"
        ));
        assert!(!holding.is_finished());

        assert!(matches!(
            lock(&served)
                .handle(Request::Approve {
                    id: 0,
                    decision: ApprovalDecision::AllowSession
                })
                .0,
            Response::Ok
        ));
        assert!(matches!(
            holding.join().unwrap(),
            Response::Decision { id: 0, decision: HookDecision::Allow, reason }
                if reason == "approval: allowed for the session"
        ));
        let (live, _) = drain(&rx);
        assert_eq!(seqs(&live), [1]);
        assert!(matches!(
            &live[0].event,
            WardEvent::CapabilityDecided {
                decision: Decision::Allow,
                by: DecisionSource::User,
                grant: Some(GrantScope::Session),
                ..
            }
        ));

        // The same question again is answered from memory, and still recorded.
        let response = hold(
            &served,
            "Write",
            "/work/src/lib.rs",
            "step-through: pause before writes",
            5,
        );
        assert!(matches!(
            response,
            Response::Decision {
                id: 2,
                decision: HookDecision::Allow,
                ..
            }
        ));
        let (live, _) = drain(&rx);
        assert_eq!(seqs(&live), [2, 3]);

        // A short timeout denies, by the timeout.
        let response = hold(&served, "WebFetch", "api.github.com", "network", 0);
        assert!(matches!(
            response,
            Response::Decision { id: 4, decision: HookDecision::Deny, reason }
                if reason == "approval: timed out"
        ));
        let (live, _) = drain(&rx);
        assert!(matches!(
            &live[1].event,
            WardEvent::CapabilityDecided {
                decision: Decision::Deny,
                by: DecisionSource::Timeout,
                grant: None,
                ..
            }
        ));

        // Sealing releases an open question as denied and — since #146 —
        // gives it its own terminal record before `SessionEnded` seals the
        // log, rather than dropping it with no record at all.
        let holding = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || hold(&served, "Write", "/work/x.rs", "r", 5))
        };
        assert!(wait_until(Duration::from_secs(2), || {
            !lock(&served).approvals.pending().is_empty()
        }));
        drain(&rx); // this hold's own CapabilityRequested; not what this section checks
        let (response, done) = lock(&served).handle(Request::Stop {
            reason: EndReason::UserStop,
        });
        assert!(done, "{response:?}");
        assert!(matches!(
            holding.join().unwrap(),
            Response::Decision { decision: HookDecision::Deny, reason, .. }
                if reason == "approval: session ended"
        ));
        let (live, ended) = drain(&rx);
        let kinds: Vec<_> = live
            .iter()
            .map(|r| format!("{:?}", r.event.kind()))
            .collect();
        // `AgentStateChanged` is the daemon's own `Finished`, recorded once the
        // stop's termination is confirmed (PR #253 review finding 5).
        assert_eq!(
            kinds,
            ["AgentStateChanged", "CapabilityDecided", "SessionEnded"],
            "the still-open question's terminal record precedes the seal, not just the hook's own answer"
        );
        assert!(matches!(
            &live[1].event,
            WardEvent::CapabilityDecided {
                cap,
                decision: Decision::Deny,
                by: DecisionSource::SessionEnded,
                grant: None,
            } if cap.target.as_str() == "Write /work/x.rs"
        ));
        assert!(ended);
        assert!(matches!(
            hold(&served, "Write", "/work/y.rs", "r", 5),
            Response::Error(e) if e == "log is sealed"
        ));
    }

    /// Review of PR #218, finding 1: an approval already answered, but not
    /// yet collected by its own `Request::Hold` connection, must still get
    /// exactly one real terminal record, appended before `SessionEnded` --
    /// even when `Stop`/`Seal` runs in between the answer landing and that
    /// connection collecting it.
    ///
    /// Forces the exact interleaving deterministically with an `mpsc`
    /// channel (this module's own convention — see `wait_until` elsewhere
    /// in this file — never a `sleep`), rather than hoping to win a real
    /// race against `wait`'s own condvar wakeup: `Approve` and `Stop` are
    /// both driven to completion, in that order, strictly before the
    /// collecting thread is ever released to call `wait` at all. Since
    /// `Approvals::wait` returns immediately (without blocking) once its id
    /// is no longer in `held`, calling it only after `close` has already
    /// drained that id exercises precisely the same code path a genuinely
    /// preempted, still-blocked `wait` call would hit on waking — with no
    /// dependency on OS thread-scheduling timing either way.
    #[test]
    fn an_answer_that_lands_just_before_stop_still_gets_exactly_one_real_record() {
        use crate::approvals::ApprovalDecision;
        use ward_events::{Decision, DecisionSource, GrantScope};

        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let sub = lock(&served).subscribe(0).unwrap();
        let (rx, _hangup) = sub.live.unwrap();

        // Register the question — what `Request::Hold` does before it
        // blocks in `wait` — synchronously, so the test controls exactly
        // when the collecting side is allowed to run. With a real decision
        // time: `hold` arms the question's clock with it (#146 item 4), and
        // an answer to a question whose clock has already run out is
        // refused (review of #225, finding 1), so a zero-length one would
        // make the `Approve` below fail instead of racing `Stop`.
        let id = match lock(&served).hold("Write", "/work/race.rs", "r", Duration::from_secs(60)) {
            Ok((id, None)) => id,
            other => panic!("{other:?}"),
        };
        assert_eq!(lock(&served).approvals.pending().len(), 1);
        drain(&rx); // this hold's own CapabilityRequested; not what this test checks
        // Right after registering: pending, not decided.
        let view = lock(&served).approvals.approvals();
        assert_eq!(view.len(), 1, "{view:?}");
        assert_eq!(view[0].approval.id, id);
        assert_eq!(view[0].outcome, None);

        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let collector = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || {
                // Blocks here until the main thread has driven Approve and
                // Stop to completion below — this is the connection that
                // registered the hold, finally reacquiring the lock to
                // collect its answer, exactly as `Request::Hold`'s own
                // connection would once its own thread was scheduled again.
                release_rx.recv().unwrap();
                // Released before calling `wait`, exactly like the real
                // `hold` free function: `wait` only ever needs `Approvals`'
                // own lock, never `Served`'s.
                let approvals = Arc::clone(&lock(&served).approvals);
                approvals.wait(id, Duration::ZERO)
            })
        };

        // Approve lands first...
        assert!(matches!(
            lock(&served)
                .handle(Request::Approve {
                    id,
                    decision: ApprovalDecision::Allow
                })
                .0,
            Response::Ok
        ));
        // ...and the question is still visible — as pending, since nothing
        // has turned the answer into a terminal record yet — never
        // vanished from the view (review of #218, finding 1's second half).
        let view = lock(&served).approvals.approvals();
        assert_eq!(view.len(), 1, "{view:?}");
        assert_eq!(view[0].outcome, None, "answered but not yet collected");

        // ...then Stop/Seal runs, before the hold connection ever
        // reacquires the lock to notice its answer.
        let (response, done) = lock(&served).handle(Request::Stop {
            reason: EndReason::UserStop,
        });
        assert!(done, "{response:?}");

        // The listing already carries the real answer, the moment Stop's
        // own `close_pending_approvals` drained it — decided, not pending,
        // and not a fabricated session-ended.
        let view = lock(&served).approvals.approvals();
        assert_eq!(
            view.iter().find(|r| r.approval.id == id).unwrap().outcome,
            Some(Outcome::Answered(ApprovalDecision::Allow))
        );

        // The log already carries this approval's real answer, not a
        // fabricated session-ended, and it precedes the seal — exactly
        // one `CapabilityDecided` for it, never zero.
        let (live, ended) = drain(&rx);
        let kinds: Vec<_> = live
            .iter()
            .map(|r| format!("{:?}", r.event.kind()))
            .collect();
        // (`AgentStateChanged`: the daemon's `Finished`, PR #253 finding 5.)
        assert_eq!(
            kinds,
            ["AgentStateChanged", "CapabilityDecided", "SessionEnded"],
            "{live:?}"
        );
        assert!(matches!(
            &live[1].event,
            WardEvent::CapabilityDecided {
                decision: Decision::Allow,
                by: DecisionSource::User,
                grant: Some(GrantScope::Once),
                ..
            }
        ));
        assert!(ended);

        // Only now let the collecting connection proceed: it still gets the
        // real answer, not `Outcome::Closed`.
        release_tx.send(()).unwrap();
        assert_eq!(
            collector.join().unwrap(),
            Outcome::Answered(ApprovalDecision::Allow),
            "the hold connection still receives the real answer, not a \
             fabricated session-ended"
        );

        // `hold`'s own check, exercised directly here: `take_recorded`
        // says `close` already appended this id's terminal record, so the
        // collecting connection must not append a second one — and, sure
        // enough, the subscriber saw nothing more.
        assert!(
            lock(&served).approvals.take_recorded(id),
            "close already recorded id {id}'s terminal record"
        );
        assert!(
            !lock(&served).approvals.take_recorded(id),
            "consulted once: a second check finds nothing left to take"
        );
        let (live, _) = drain(&rx);
        assert!(
            live.is_empty(),
            "no second record for the same approval: {live:?}"
        );
    }

    /// Re-review of PR #218, finding 2: an approval whose own `wait` call
    /// already settled it — removed it from `held`, recorded its real
    /// outcome in `history` — but whose terminal record has not yet been
    /// appended (its collecting connection has not yet won back the
    /// `Served` lock to do so), must still get exactly one real terminal
    /// record, appended before `SessionEnded`, even when `Stop`/`Seal` runs
    /// in that exact gap.
    ///
    /// This is a different interleaving from
    /// `an_answer_that_lands_just_before_stop_still_gets_exactly_one_real_record`
    /// above, which forces `close` to win the race to a still-`held` entry
    /// (releasing the collector to call `wait` only *after* Stop has already
    /// run, so `wait` finds nothing in `held` and falls back to `close`'s own
    /// `handoff`). Here `wait` itself is what settles the entry — deterministically
    /// driven to completion, with the id already recorded in `history` and
    /// removed from `held`, strictly *before* `Stop`/`Seal` ever runs —
    /// and only the collecting connection's own belated check-and-append
    /// (what `hold` does once it wins back the `Served` lock) is held back,
    /// with an `mpsc` channel, until after `Stop`/`Seal` has completed. Before
    /// the fix for finding 2, `close` had nothing in `held` to look at for
    /// this id and nothing else to consult either, so it concluded there was
    /// nothing to do and sealed the log with no terminal record for an
    /// approval that, in truth, `wait` had already decided.
    #[test]
    fn an_answer_settled_by_wait_just_before_stop_still_gets_exactly_one_real_record() {
        use crate::approvals::ApprovalDecision;
        use ward_events::{Decision, DecisionSource, GrantScope};

        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let sub = lock(&served).subscribe(0).unwrap();
        let (rx, _hangup) = sub.live.unwrap();

        // A real decision time, for the same reason as the test above: the
        // `Approve` below must land on a question whose clock is still running.
        let id = match lock(&served).hold("Write", "/work/race2.rs", "r", Duration::from_secs(60)) {
            Ok((id, None)) => id,
            other => panic!("{other:?}"),
        };
        drain(&rx); // this hold's own CapabilityRequested; not what this test checks

        assert!(matches!(
            lock(&served)
                .handle(Request::Approve {
                    id,
                    decision: ApprovalDecision::Allow
                })
                .0,
            Response::Ok
        ));

        let (settled_tx, settled_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let collector = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || {
                // `wait` only ever needs `Approvals`' own lock: it settles
                // the outcome and removes the entry from `held` right here
                // — before Stop ever runs — exactly the "wait before
                // terminal append" window (review of #218, finding 2). The
                // real outcome is already decided at this point; only its
                // terminal-record append is still outstanding.
                let approvals = Arc::clone(&lock(&served).approvals);
                let outcome = approvals.wait(id, Duration::ZERO);
                settled_tx.send(()).unwrap();
                // Blocks here — exactly like the free `hold` function's own
                // gap between `wait` returning and it reacquiring
                // `Served`'s lock — until the main thread has driven
                // Stop/Seal to completion below.
                release_rx.recv().unwrap();
                let mut s = lock(&served);
                if !s.approvals.take_recorded(id) {
                    let event = crate::approvals::decided_event("Write", "/work/race2.rs", outcome);
                    let _ = s.append(event);
                }
                outcome
            })
        };

        settled_rx.recv().unwrap();
        // `wait` already recorded the real answer in `history` the moment
        // it settled, before Stop ever ran.
        let view = lock(&served).approvals.approvals();
        assert_eq!(
            view.iter().find(|r| r.approval.id == id).unwrap().outcome,
            Some(Outcome::Answered(ApprovalDecision::Allow))
        );

        // Stop/Seal runs to completion here, entirely before the collecting
        // connection ever reacquires `Served`'s lock.
        let (response, done) = lock(&served).handle(Request::Stop {
            reason: EndReason::UserStop,
        });
        assert!(done, "{response:?}");

        // The real record already landed, before the seal — `close`
        // claimed it out of `Approvals`' `unclaimed` bookkeeping, even
        // though `wait`, not `close`, is what actually settled this
        // outcome. Exactly one `CapabilityDecided`, never zero.
        let (live, ended) = drain(&rx);
        let kinds: Vec<_> = live
            .iter()
            .map(|r| format!("{:?}", r.event.kind()))
            .collect();
        // (`AgentStateChanged`: the daemon's `Finished`, PR #253 finding 5.)
        assert_eq!(
            kinds,
            ["AgentStateChanged", "CapabilityDecided", "SessionEnded"],
            "{live:?}"
        );
        assert!(matches!(
            &live[1].event,
            WardEvent::CapabilityDecided {
                decision: Decision::Allow,
                by: DecisionSource::User,
                grant: Some(GrantScope::Once),
                ..
            }
        ));
        assert!(ended);

        // Only now let the collecting connection try its own belated
        // append: it must find the record already claimed, and append
        // nothing more.
        release_tx.send(()).unwrap();
        assert_eq!(
            collector.join().unwrap(),
            Outcome::Answered(ApprovalDecision::Allow),
            "the collecting connection still receives the real answer"
        );
        let (live, _) = drain(&rx);
        assert!(
            live.is_empty(),
            "no second record for the same approval: {live:?}"
        );
    }

    /// The timeout half of the same finding 2: `Approvals::wait`'s timeout
    /// branch settles an id (removes it from `held`, records `TimedOut` in
    /// `history`) through the exact same not-yet-appended gap as the
    /// answered branch above, so it is exposed to the identical race. Same
    /// structure as
    /// `an_answer_settled_by_wait_just_before_stop_still_gets_exactly_one_real_record`,
    /// with no `Approve` at all and `wait` given a zero timeout so it settles
    /// as `TimedOut` on its very first check rather than actually blocking.
    #[test]
    fn a_timeout_settled_by_wait_just_before_stop_still_gets_exactly_one_real_record() {
        use ward_events::{Decision, DecisionSource};

        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let sub = lock(&served).subscribe(0).unwrap();
        let (rx, _hangup) = sub.live.unwrap();

        let id = match lock(&served).hold("Write", "/work/race3.rs", "r", Duration::ZERO) {
            Ok((id, None)) => id,
            other => panic!("{other:?}"),
        };
        drain(&rx);

        let (settled_tx, settled_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let collector = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || {
                let approvals = Arc::clone(&lock(&served).approvals);
                let outcome = approvals.wait(id, Duration::ZERO);
                settled_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                let mut s = lock(&served);
                if !s.approvals.take_recorded(id) {
                    let event = crate::approvals::decided_event("Write", "/work/race3.rs", outcome);
                    let _ = s.append(event);
                }
                outcome
            })
        };

        settled_rx.recv().unwrap();
        let view = lock(&served).approvals.approvals();
        assert_eq!(
            view.iter().find(|r| r.approval.id == id).unwrap().outcome,
            Some(Outcome::TimedOut)
        );

        let (response, done) = lock(&served).handle(Request::Stop {
            reason: EndReason::UserStop,
        });
        assert!(done, "{response:?}");

        let (live, ended) = drain(&rx);
        let kinds: Vec<_> = live
            .iter()
            .map(|r| format!("{:?}", r.event.kind()))
            .collect();
        // (`AgentStateChanged`: the daemon's `Finished`, PR #253 finding 5.)
        assert_eq!(
            kinds,
            ["AgentStateChanged", "CapabilityDecided", "SessionEnded"],
            "{live:?}"
        );
        assert!(matches!(
            &live[1].event,
            WardEvent::CapabilityDecided {
                decision: Decision::Deny,
                by: DecisionSource::Timeout,
                grant: None,
                ..
            }
        ));
        assert!(ended);

        release_tx.send(()).unwrap();
        assert_eq!(collector.join().unwrap(), Outcome::TimedOut);
        let (live, _) = drain(&rx);
        assert!(
            live.is_empty(),
            "no second record for the same approval: {live:?}"
        );
    }

    /// `ward session approvals` (#146 item 1): unlike `Pending`, it still
    /// shows a request once it has been decided, so missing or dismissing
    /// whatever first announced it does not lose it from view for the rest
    /// of the session.
    #[test]
    fn request_approvals_lists_pending_and_decided_oldest_asked_first() {
        use crate::approvals::{ApprovalDecision, Outcome};

        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        assert!(matches!(
            lock(&served).handle(Request::Approvals).0,
            Response::Approvals(a) if a.is_empty()
        ));

        // Asked first, answered.
        let answered = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || hold(&served, "Write", "/work/a.rs", "r", 5))
        };
        assert!(wait_until(Duration::from_secs(2), || {
            !lock(&served).approvals.pending().is_empty()
        }));
        lock(&served).handle(Request::Approve {
            id: 0,
            decision: ApprovalDecision::Deny,
        });
        answered.join().unwrap();

        // Asked second, still open.
        let pending = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || hold(&served, "Write", "/work/b.rs", "r", 5))
        };
        assert!(wait_until(Duration::from_secs(2), || {
            !lock(&served).approvals.pending().is_empty()
        }));

        let records = match lock(&served).handle(Request::Approvals).0 {
            Response::Approvals(records) => records,
            other => panic!("{other:?}"),
        };
        assert_eq!(records.len(), 2, "{records:?}");
        assert_eq!(records[0].approval.id, 0, "decided, but asked first");
        assert_eq!(
            records[0].outcome,
            Some(Outcome::Answered(ApprovalDecision::Deny))
        );
        assert!(records[0].decided_at_unix_ms.is_some());
        // id 1 is the first question's own `CapabilityDecided` record (the
        // log's seq counter is shared across every event, not per-approval).
        assert_eq!(records[1].approval.id, 2, "still open");
        assert_eq!(records[1].outcome, None);
        assert!(records[1].decided_at_unix_ms.is_none());

        // Sealing decides the still-open one too, and it joins the same view.
        lock(&served).handle(Request::Stop {
            reason: EndReason::UserStop,
        });
        pending.join().unwrap();
        let records = match lock(&served).handle(Request::Approvals).0 {
            Response::Approvals(records) => records,
            other => panic!("{other:?}"),
        };
        assert_eq!(records[1].approval.id, 2);
        assert_eq!(records[1].outcome, Some(Outcome::Closed));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_granted_credential_is_temporary_authority_the_daemon_lists_and_derives_from() {
        use crate::approvals::{GrantKind, Lifetime};
        use crate::hooks::HookDecision;
        use ward_events::{CredentialDelivery, NameText, Scope, ServiceId, ShortText};

        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        assert!(matches!(
            lock(&served).handle(Request::Grants).0,
            Response::Grants(g) if g.is_empty()
        ));
        // Before any grant, a fetch to GitHub shows the rule and that nothing
        // was granted.
        let holding = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || {
                hold(
                    &served,
                    "WebFetch",
                    "https://api.github.com/repos/hexrift/WardOS/issues/1",
                    "step-through: pause before network",
                    5,
                )
            })
        };
        assert!(wait_until(Duration::from_secs(2), || {
            !lock(&served).approvals.pending().is_empty()
        }));
        let pending = lock(&served).approvals.pending();
        assert_eq!(
            pending[0].authority.credential,
            "GitHub · contents:read, issues:read · not granted (--grant github)"
        );
        assert_eq!(pending[0].authority.network, "reachable · restricted (dev)");
        lock(&served).handle(Request::Approve {
            id: 0,
            decision: crate::approvals::ApprovalDecision::AllowSession,
        });
        assert!(matches!(
            holding.join().unwrap(),
            Response::Decision {
                decision: HookDecision::Allow,
                ..
            }
        ));

        // The launch grants GitHub: two routes, one credential.
        for host in ["github.com", "api.github.com"] {
            let granted = WardEvent::CredentialGranted {
                service: ServiceId::new("github").unwrap(),
                scope: Scope {
                    subject: ShortText::new(&format!("{host}:443")),
                    permissions: vec![NameText::new("contents:read"), NameText::new("issues:read")],
                },
                expires: Duration::from_secs(60),
                delivery: CredentialDelivery::ProxyInjected,
            };
            assert!(matches!(
                lock(&served).append(granted),
                Ok(record) if record.seq >= 2
            ));
        }
        let grants = match lock(&served).handle(Request::Grants).0 {
            Response::Grants(g) => g,
            other => panic!("{other:?}"),
        };
        assert_eq!(grants.len(), 2, "{grants:?}");
        assert_eq!(grants[0].kind, GrantKind::Approval);
        assert_eq!(grants[0].label, "WebFetch api.github.com");
        assert_eq!(grants[0].lifetime, Lifetime::Session);
        assert_eq!(grants[1].kind, GrantKind::Credential);
        assert_eq!(grants[1].label, "GitHub");
        assert_eq!(
            grants[1].scope,
            "contents:read, issues:read · github.com, api.github.com"
        );
        assert_eq!(grants[1].lifetime, Lifetime::Launch);

        // A fresh question to the same service now shows the injected credential.
        let holding = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || {
                hold(
                    &served,
                    "WebFetch",
                    "https://github.com/hexrift/WardOS",
                    "r",
                    5,
                )
            })
        };
        assert!(wait_until(Duration::from_secs(2), || {
            !lock(&served).approvals.pending().is_empty()
        }));
        let pending = lock(&served).approvals.pending();
        assert_eq!(
            pending[0].authority.credential,
            "GitHub · contents:read, issues:read"
        );
        assert_eq!(
            pending[0].authority.repository.as_deref(),
            Some("hexrift/WardOS")
        );
        lock(&served).handle(Request::Approve {
            id: pending[0].id,
            decision: crate::approvals::ApprovalDecision::Deny,
        });
        assert!(matches!(
            holding.join().unwrap(),
            Response::Decision {
                decision: HookDecision::Deny,
                ..
            }
        ));
        assert_eq!(
            lock(&served).approvals.grants().len(),
            2,
            "a denial grants nothing"
        );
    }

    /// A credential's grant id in a fresh `Served`, with a `CredentialGranted`
    /// already on the log (#245's test fixture, shared by the revoke tests
    /// below).
    fn granted_credential(served: &Arc<Mutex<Served>>) -> u64 {
        use ward_events::{CredentialDelivery, NameText, Scope, ServiceId};
        let granted = WardEvent::CredentialGranted {
            service: ServiceId::new("github").unwrap(),
            scope: Scope {
                subject: ShortText::new("github.com:443"),
                permissions: vec![NameText::new("contents:read")],
            },
            expires: Duration::from_secs(60),
            delivery: CredentialDelivery::ProxyInjected,
        };
        assert!(lock(served).append(granted).is_ok());
        match lock(served).handle(Request::Grants).0 {
            Response::Grants(g) if g.len() == 1 => g[0].id,
            other => panic!("{other:?}"),
        }
    }

    /// This session's `state`/`session` fields, the two things a test needs
    /// to reach into the same proxy-facing marker directory `daemon::revoke`
    /// itself writes to and polls (#245).
    fn state_and_session(served: &Arc<Mutex<Served>>) -> (PathBuf, String) {
        let s = lock(served);
        (s.state.clone(), s.session.clone())
    }

    #[test]
    fn revoking_a_credential_grant_waits_for_the_marker_then_removes_it_and_records_credential_revoked()
     {
        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let id = granted_credential(&served);

        // Simulate the owning egress: by the time `daemon::revoke` writes
        // the marker (`revoke::request`, a no-op once the file exists), a
        // proxy that already confirmed leaves this content in place for the
        // wait to find immediately.
        let (state, session) = state_and_session(&served);
        std::fs::create_dir_all(revoke::dir_path(&state, &session)).unwrap();
        std::fs::write(revoke::marker_path(&state, &session, id), revoke::CONFIRMED).unwrap();

        assert_eq!(
            revoke_bounded(&served, id, Duration::from_millis(500)),
            Response::Revoked(approvals::RevokeOutcome::Withdrawn)
        );
        assert!(
            !revoke::marker_path(&state, &session, id).exists(),
            "the marker is cleared once its outcome is read"
        );

        let grants = match lock(&served).handle(Request::Grants).0 {
            Response::Grants(g) => g,
            other => panic!("{other:?}"),
        };
        assert!(
            grants.is_empty(),
            "revoked grant no longer listed: {grants:?}"
        );

        let replay = lock(&served).subscribe(0).unwrap().replay;
        assert!(
            matches!(
                replay.last().map(|r| &r.event),
                Some(WardEvent::CredentialRevoked { service, reason })
                    if service.as_str() == "github" && *reason == RevokeReason::UserRevoked
            ),
            "{replay:?}"
        );

        // Already revoked: the same id is refused, not silently accepted again.
        assert!(matches!(
            revoke_bounded(&served, id, Duration::from_millis(50)),
            Response::Error(e) if e.contains("not found")
        ));
        // Never minted: same refusal shape.
        assert!(matches!(
            revoke_bounded(&served, 999_999, Duration::from_millis(50)),
            Response::Error(e) if e.contains("not found")
        ));
    }

    #[test]
    fn revoke_reports_withdrawn_in_flight_and_still_removes_the_grant() {
        // #245's honest partial-failure shape: a proxy that confirmed but
        // still has a connection relaying with the credential is not a
        // failure — the authority is withdrawn either way — but it is a
        // distinct, named outcome, never silently folded into a bare
        // `Withdrawn`.
        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let id = granted_credential(&served);

        let (state, session) = state_and_session(&served);
        std::fs::create_dir_all(revoke::dir_path(&state, &session)).unwrap();
        std::fs::write(
            revoke::marker_path(&state, &session, id),
            revoke::in_flight_text(3),
        )
        .unwrap();

        assert_eq!(
            revoke_bounded(&served, id, Duration::from_millis(500)),
            Response::Revoked(approvals::RevokeOutcome::WithdrawnInFlight(3))
        );
        assert!(matches!(
            lock(&served).handle(Request::Grants).0,
            Response::Grants(g) if g.is_empty()
        ));
    }

    #[test]
    fn revoke_reports_unconfirmed_and_keeps_the_grant_when_nothing_acknowledges() {
        // The other honest outcome #245 asks for: a proxy that is
        // unreachable (or simply has not polled yet) must never be reported
        // as though the revoke succeeded.
        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let id = granted_credential(&served);

        let response = revoke_bounded(&served, id, Duration::from_millis(80));
        assert_eq!(
            response,
            Response::Revoked(approvals::RevokeOutcome::Unconfirmed)
        );

        let grants = match lock(&served).handle(Request::Grants).0 {
            Response::Grants(g) => g,
            other => panic!("{other:?}"),
        };
        assert_eq!(grants.len(), 1, "never silently dropped: {grants:?}");
        assert_eq!(grants[0].revoke_state, approvals::RevokeState::Unconfirmed);

        // No `CredentialRevoked` for a revoke nothing ever confirmed: the
        // audit trail must not claim an enforcement fact that never happened.
        let replay = lock(&served).subscribe(0).unwrap().replay;
        assert!(
            !replay
                .iter()
                .any(|r| matches!(r.event, WardEvent::CredentialRevoked { .. })),
            "{replay:?}"
        );
    }

    #[test]
    fn revoke_reports_unconfirmed_when_the_marker_holds_unparseable_text() {
        // A review of #248 found this had the failure direction backwards: a
        // marker body that is neither `CONFIRMED` nor a well-formed
        // in-flight count (a torn write, a future format from a
        // version-skewed egress) must fail toward the least confident
        // outcome, `Unconfirmed`, not toward the most confident one,
        // `Withdrawn` — the opposite of every other honest-failure case this
        // module documents.
        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let id = granted_credential(&served);
        let (state, session) = state_and_session(&served);

        std::fs::create_dir_all(revoke::dir_path(&state, &session)).unwrap();
        std::fs::write(revoke::marker_path(&state, &session, id), "garbage").unwrap();

        assert_eq!(
            revoke_bounded(&served, id, Duration::from_millis(500)),
            Response::Revoked(approvals::RevokeOutcome::Unconfirmed)
        );

        let grants = match lock(&served).handle(Request::Grants).0 {
            Response::Grants(g) => g,
            other => panic!("{other:?}"),
        };
        assert_eq!(grants.len(), 1, "never silently dropped: {grants:?}");
        assert_eq!(grants[0].revoke_state, approvals::RevokeState::Unconfirmed);

        let replay = lock(&served).subscribe(0).unwrap().replay;
        assert!(
            !replay
                .iter()
                .any(|r| matches!(r.event, WardEvent::CredentialRevoked { .. })),
            "an outcome nothing confirmed must never be recorded as one that did: {replay:?}"
        );
    }

    #[test]
    fn ward_session_grants_shows_revoking_while_a_revoke_waits_for_acknowledgement() {
        // #245 item 5: the intermediate state must be visible through the
        // exact surface a user reads, `ward session grants`, for the whole
        // window between the revoke starting and its acknowledgement — not
        // only in `Approvals`' own internal state.
        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let id = granted_credential(&served);
        let (state, session) = state_and_session(&served);

        let waiting = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || revoke_bounded(&served, id, Duration::from_secs(2)))
        };

        assert!(
            wait_until(Duration::from_secs(2), || {
                matches!(
                    lock(&served).handle(Request::Grants).0,
                    Response::Grants(g)
                        if g.first().is_some_and(|g| g.revoke_state == approvals::RevokeState::Revoking)
                )
            }),
            "revoking must be visible in `ward session grants` while the wait is pending"
        );

        // The owning proxy answers, mid-wait.
        std::fs::create_dir_all(revoke::dir_path(&state, &session)).unwrap();
        std::fs::write(revoke::marker_path(&state, &session, id), revoke::CONFIRMED).unwrap();
        assert_eq!(
            waiting.join().unwrap(),
            Response::Revoked(approvals::RevokeOutcome::Withdrawn)
        );
        assert!(matches!(
            lock(&served).handle(Request::Grants).0,
            Response::Grants(g) if g.is_empty()
        ));
    }

    #[test]
    fn revoke_never_holds_the_daemon_lock_across_its_wait() {
        // The whole point of serving `Revoke` on its own connection, exactly
        // like `Hold` (#245): a `ward session grants` on another connection
        // must not be blocked behind this one's proxy round trip.
        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let id = granted_credential(&served);
        let (state, session) = state_and_session(&served);

        let waiting = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || revoke_bounded(&served, id, Duration::from_secs(2)))
        };
        // If `revoke_bounded` held the lock across its wait, this would never
        // observe `revoking` and would instead time out at 2 s; bounded well
        // under that so a regression fails loudly instead of just being slow.
        assert!(
            wait_until(Duration::from_millis(500), || {
                matches!(
                    lock(&served).handle(Request::Grants).0,
                    Response::Grants(g)
                        if g.first().is_some_and(|g| g.revoke_state == approvals::RevokeState::Revoking)
                )
            }),
            "a concurrent `ward session grants` must see `revoking`, not block behind the wait"
        );

        std::fs::create_dir_all(revoke::dir_path(&state, &session)).unwrap();
        std::fs::write(revoke::marker_path(&state, &session, id), revoke::CONFIRMED).unwrap();
        drop(waiting.join());
    }

    #[test]
    fn revoke_bounded_only_records_credential_revoked_once_the_racing_caller_it_deferred_to_reports_it()
     {
        // #248's review: `begin_revoke` is a harmless no-op on a credential
        // already `Revoking`, so two connections racing `Request::Revoke`
        // for the same id both reach this point with the same confirmed
        // outcome. Before `finish_revoke` reported which caller actually
        // performed the Revoking→terminal transition, both would append
        // `CredentialRevoked` for one logical revoke. This drives the same
        // `performed` guard `revoke_bounded` uses, standing in for the
        // second racer directly rather than depending on real thread
        // scheduling to land both callers inside the same window.
        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let id = granted_credential(&served);
        let (state, session) = state_and_session(&served);

        std::fs::create_dir_all(revoke::dir_path(&state, &session)).unwrap();
        std::fs::write(revoke::marker_path(&state, &session, id), revoke::CONFIRMED).unwrap();

        assert_eq!(
            revoke_bounded(&served, id, Duration::from_millis(500)),
            Response::Revoked(approvals::RevokeOutcome::Withdrawn)
        );

        // The second racer: `begin_revoke` already ran for it too (a
        // harmless no-op, per its own doc comment) before the first racer's
        // `finish_revoke` won the race, so it reaches `finish_revoke` with
        // the same outcome and must not record a second audit event.
        let performed = lock(&served)
            .approvals
            .finish_revoke(id, &approvals::RevokeOutcome::Withdrawn);
        assert!(!performed, "the grant is already gone");

        let replay = lock(&served).subscribe(0).unwrap().replay;
        let revoked_events = replay
            .iter()
            .filter(|r| matches!(r.event, WardEvent::CredentialRevoked { .. }))
            .count();
        assert_eq!(
            revoked_events, 1,
            "one logical revoke must record exactly one audit event: {replay:?}"
        );
    }

    #[test]
    fn two_concurrent_revokes_of_the_same_id_agree_on_the_outcome_and_record_one_event() {
        // #248's review: before `approvals::begin_revoke_wait`/
        // `join_revoke_wait` existed, real connections racing
        // `revoke_bounded` for the same id each independently waited on and
        // cleared `crate::revoke`'s marker file — whichever observed the
        // confirmed ack first deleted the marker before another's poll
        // could read it, so the loser timed out and reported `Unconfirmed`
        // for an operation that had already succeeded. This drives several
        // real racing callers (not a simulated second racer) end to end;
        // more than two, since `begin_revoke_wait`'s own atomicity (the
        // credential check and the leader/joiner decision as one step under
        // one lock — a later review round's finding) is what keeps every
        // one of them consistent regardless of how many race in, not just
        // a specific pair.
        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let id = granted_credential(&served);
        let (state, session) = state_and_session(&served);

        let racers: Vec<_> = (0..5)
            .map(|_| {
                let served = Arc::clone(&served);
                std::thread::spawn(move || revoke_bounded(&served, id, Duration::from_secs(2)))
            })
            .collect();

        // Whichever of the racers wins leadership is the one that writes
        // the marker (every other one only ever joins its shared slot, and
        // never touches the marker file at all).
        assert!(
            wait_until(Duration::from_secs(2), || revoke::marker_path(
                &state, &session, id
            )
            .exists()),
            "the leading racer's revoke::request must have written the marker"
        );
        std::fs::write(revoke::marker_path(&state, &session, id), revoke::CONFIRMED).unwrap();

        let outcomes: Vec<_> = racers.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(
            outcomes
                .iter()
                .all(|r| *r == Response::Revoked(approvals::RevokeOutcome::Withdrawn)),
            "every racer must agree on the same confirmed outcome: {outcomes:?}"
        );

        let replay = lock(&served).subscribe(0).unwrap().replay;
        let revoked_events = replay
            .iter()
            .filter(|r| matches!(r.event, WardEvent::CredentialRevoked { .. }))
            .count();
        assert_eq!(
            revoked_events, 1,
            "one logical revoke must record exactly one audit event: {replay:?}"
        );
    }

    #[test]
    fn a_concurrent_revoke_cannot_start_a_second_marker_wait_between_publish_and_the_terminal_transition()
     {
        // #248's review: publishing the leader's outcome (which removes the
        // id's shared slot) and the Revoking→terminal `finish_revoke`
        // transition it implies must happen as one step with respect to
        // `served`'s lock — otherwise a brand new connection's
        // `begin_revoke` could find the grant still `Revoking` while
        // `claim_revoke_wait` finds no slot left to join, and start an
        // independent second marker wait for what is actually the same,
        // already-settled logical revoke. This pauses the leader in
        // exactly that window (via `revoke_bounded_with_hook`, a test-only
        // seam) and proves a concurrent revoke of the same id cannot make
        // any progress until the leader has fully finished.
        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let id = granted_credential(&served);
        let (state, session) = state_and_session(&served);
        std::fs::create_dir_all(revoke::dir_path(&state, &session)).unwrap();
        std::fs::write(revoke::marker_path(&state, &session, id), revoke::CONFIRMED).unwrap();

        let (reached_hook_tx, reached_hook_rx) = std::sync::mpsc::channel::<()>();
        let (release_hook_tx, release_hook_rx) = std::sync::mpsc::channel::<()>();
        let leader = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || {
                revoke_bounded_with_hook(&served, id, Duration::from_secs(2), move || {
                    reached_hook_tx.send(()).unwrap();
                    release_hook_rx.recv().unwrap();
                })
            })
        };

        reached_hook_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();

        // A brand new connection racing a revoke of the same id right now
        // must not be able to make any progress: `served`'s lock is still
        // held by the leader, paused in the hook, so this blocks on it
        // rather than becoming a second leader with a marker wait of its
        // own.
        let late = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || revoke_bounded(&served, id, Duration::from_secs(2)))
        };
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            !late.is_finished(),
            "a concurrent revoke must block on the daemon lock during this window, not race ahead"
        );

        release_hook_tx.send(()).unwrap();
        let leader_outcome = leader.join().unwrap();
        let late_outcome = late.join().unwrap();

        assert_eq!(
            leader_outcome,
            Response::Revoked(approvals::RevokeOutcome::Withdrawn)
        );
        // By the time the late caller's own `begin_revoke` finally runs,
        // the grant is already gone (the leader finished the transition
        // while holding the lock the late caller was blocked on) — honestly
        // refused, never a second, independent marker wait for an
        // already-settled revoke.
        assert!(
            matches!(&late_outcome, Response::Error(e) if e.contains("not found")),
            "{late_outcome:?}"
        );

        assert!(matches!(
            lock(&served).handle(Request::Grants).0,
            Response::Grants(g) if g.is_empty()
        ));
        let replay = lock(&served).subscribe(0).unwrap().replay;
        let revoked_events = replay
            .iter()
            .filter(|r| matches!(r.event, WardEvent::CredentialRevoked { .. }))
            .count();
        assert_eq!(
            revoked_events, 1,
            "one logical revoke must record exactly one audit event: {replay:?}"
        );
    }

    #[test]
    fn a_launch_scoped_credential_is_retired_when_the_launch_that_granted_it_ends() {
        use ward_events::{
            BoundedArgv, CredentialDelivery, ExitStatus, NameText, Pid, SandboxPath, SandboxRoot,
            Scope, ServiceId,
        };

        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));

        let pid = Pid::new(2).unwrap();
        let started = WardEvent::CommandStarted {
            pid,
            parent: Pid::new(1).unwrap(),
            argv: BoundedArgv::from_bytes([b"git".as_slice(), b"push".as_slice()]),
            cwd: SandboxPath::new(SandboxRoot::Work, ".").unwrap(),
            exe_digest: None,
        };
        assert!(lock(&served).append(started).is_ok());

        let granted = WardEvent::CredentialGranted {
            service: ServiceId::new("github").unwrap(),
            scope: Scope {
                subject: ShortText::new("github.com:443"),
                permissions: vec![NameText::new("contents:read")],
            },
            expires: Duration::from_secs(60),
            delivery: CredentialDelivery::ProxyInjected,
        };
        assert!(lock(&served).append(granted).is_ok());

        assert_eq!(
            lock(&served).approvals.grants().len(),
            1,
            "the launch's credential is a grant while it runs"
        );

        let finished = WardEvent::CommandFinished {
            pid,
            exit: ExitStatus::Exited { code: 0 },
            duration: Duration::from_secs(1),
        };
        assert!(lock(&served).append(finished).is_ok());

        // The launch that was granted the credential has ended: the
        // authority view must not keep showing it as active (issue #140).
        let grants = lock(&served).approvals.grants();
        assert!(
            grants.is_empty(),
            "a launch-scoped grant must not outlive the launch it was scoped to: {grants:?}"
        );
    }

    /// PR #197 review, finding 2: two genuinely concurrent launches — two
    /// separate `ward` client connections against the same daemon session —
    /// must never share or cross-retire each other's grants, even when both
    /// happen to choose the identical client-side `Pid` (every freshly opened
    /// `Session` allocates its logical pids from the same small range
    /// starting at 2, so this is not a contrived collision). Correlation here
    /// is by connection, not by that `Pid`.
    #[test]
    fn concurrent_launches_on_different_connections_neither_share_nor_retire_each_others_grants() {
        use ward_events::{
            BoundedArgv, CredentialDelivery, ExitStatus, NameText, Pid, SandboxPath, SandboxRoot,
            Scope, ServiceId,
        };

        const CONN_A: u64 = 1;
        const CONN_B: u64 = 2;

        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());

        // Both launches allocate the same client-visible pid: exactly the
        // collision two independently opened `Session`s can produce.
        let collided_pid = Pid::new(2).unwrap();
        let started = |argv: &'static [u8]| WardEvent::CommandStarted {
            pid: collided_pid,
            parent: Pid::new(1).unwrap(),
            argv: BoundedArgv::from_bytes([argv]),
            cwd: SandboxPath::new(SandboxRoot::Work, ".").unwrap(),
            exe_digest: None,
        };
        let granted = |host: &str| WardEvent::CredentialGranted {
            service: ServiceId::new("github").unwrap(),
            scope: Scope {
                subject: ShortText::new(&format!("{host}:443")),
                permissions: vec![NameText::new("contents:read")],
            },
            expires: Duration::from_secs(60),
            delivery: CredentialDelivery::ProxyInjected,
        };
        let finished = || WardEvent::CommandFinished {
            pid: collided_pid,
            exit: ExitStatus::Exited { code: 0 },
            duration: Duration::from_secs(1),
        };
        let append = |served: &mut Served, conn: u64, event: WardEvent| {
            let request = Request::Append {
                origin: Origin::Kernel,
                event,
                at_unix_ms: control::unix_ms(SystemTime::now()),
            };
            assert!(matches!(
                served.handle_conn(conn, request).0,
                Response::Record(_) | Response::Granted { .. }
            ));
        };

        // A starts, B starts while A is still open (both pid 2), A is granted
        // a credential.
        append(&mut served, CONN_A, started(b"a"));
        append(&mut served, CONN_B, started(b"b"));
        append(&mut served, CONN_A, granted("a.example.com"));
        assert_eq!(
            served.approvals.grants().len(),
            1,
            "A's own credential, attributed to A despite B's identical pid being open too"
        );

        // B finishes first: A's still-open launch and its grant must survive.
        append(&mut served, CONN_B, finished());
        assert_eq!(
            served.approvals.grants().len(),
            1,
            "B finishing must not retire A's credential just because they share a pid"
        );

        // B is granted its own credential after finishing is a no-op path in
        // practice, but the interesting case is A's grant surviving B's
        // finish; now end A and its own grant must retire.
        append(&mut served, CONN_A, finished());
        assert!(
            served.approvals.grants().is_empty(),
            "A's own finish retires A's own credential: {:?}",
            served.approvals.grants()
        );
    }

    #[test]
    fn the_newest_served_session_is_the_desktops_session() {
        let state = tempfile::tempdir().unwrap();
        assert_eq!(newest_live(state.path()).unwrap(), None, "no sessions yet");
        let meta = |id: &str, started: u64| SessionMeta {
            id: id.to_owned(),
            project: PathBuf::from("/tmp/demo"),
            project_id: "proj_unit".to_owned(),
            entry_snapshot: "blake3:abc".to_owned(),
            origin_repo: None,
            manifest: merge(
                &Policy::default(),
                &Policy::default(),
                &Policy::default(),
                ward_policy::SessionId(id.to_owned()),
                ward_policy::ProjectId("proj_unit".to_owned()),
            ),
            started_unix_ms: started,
            agent: None,
        };
        for (id, started) in [("sess_old", 1), ("sess_new", 3), ("sess_mid", 2)] {
            let dir = session_dir(state.path(), id);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("session.json"),
                serde_json::to_vec(&meta(id, started)).unwrap(),
            )
            .unwrap();
        }
        std::fs::create_dir_all(session_dir(state.path(), "sess_broken")).unwrap();
        std::fs::write(
            session_dir(state.path(), "sess_broken").join("session.json"),
            b"{",
        )
        .unwrap();
        assert_eq!(
            newest_live(state.path()).unwrap(),
            None,
            "sessions on disk, none served"
        );
        // Serve the middle one: it is the live one, whatever started later.
        let mut log = Some(fresh_served(state.path()).log.take().unwrap());
        let listener = bind_socket(&socket_path(state.path(), "sess_mid")).unwrap();
        let server = std::thread::spawn(move || {
            // Two pings: the probe in `newest_live`, and the caller's own connect.
            for _ in 0..2 {
                if let Ok((stream, _)) = listener.accept() {
                    control::serve_connection(stream, &mut log);
                }
            }
        });
        let live = newest_live(state.path()).unwrap().unwrap();
        assert_eq!(live.id, "sess_mid");
        assert!(RemoteSink::connect(&socket_path(state.path(), "sess_mid")).is_some());
        server.join().unwrap();
    }

    #[test]
    fn describe_is_answered_from_the_session_record() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        match served.handle(Request::Describe) {
            (Response::Description(v), false) => assert_eq!(v["session"], "sess_9"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            served.handle(Request::Subscribe { from_seq: 0 }).0,
            Response::Error(_)
        ));
    }

    #[test]
    fn stale_socket_is_replaced_and_a_live_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SOCKET_NAME);
        // A socket file nothing listens on any more.
        drop(UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        let listener = bind_socket(&path).expect("stale socket is replaced");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // The same path with a daemon answering on it.
        let mut log = Some(fresh_served(dir.path()).log.take().unwrap());
        let server = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                control::serve_connection(stream, &mut log);
            }
        });
        let err = bind_socket(&path).expect_err("a live socket is refused");
        assert!(err.to_string().contains("another wardd"), "{err}");
        assert!(path.exists(), "the live socket is left alone");
        server.join().unwrap();
    }

    #[test]
    fn an_overlong_socket_path_is_refused_up_front() {
        let dir = tempfile::tempdir().unwrap();
        let long = dir
            .path()
            .join("x".repeat(MAX_SOCKET_PATH))
            .join(SOCKET_NAME);
        let err = bind_socket(&long).expect_err("too long to bind");
        assert!(err.to_string().contains("WARD_STATE_DIR"), "{err}");
        assert!(check_socket_path(&dir.path().join(SOCKET_NAME)).is_ok());
    }

    #[test]
    fn find_binary_prefers_beside_then_path() {
        let beside = tempfile::tempdir().unwrap();
        let on_path = tempfile::tempdir().unwrap();
        let empty = tempfile::tempdir().unwrap();
        std::fs::write(beside.path().join(BINARY), "#!/bin/sh\n").unwrap();
        std::fs::write(on_path.path().join(BINARY), "#!/bin/sh\n").unwrap();
        let path = std::env::join_paths([empty.path(), on_path.path()]).unwrap();
        assert_eq!(
            find_in(Some(beside.path()), Some(&path)),
            Some(beside.path().join(BINARY))
        );
        assert_eq!(
            find_in(Some(empty.path()), Some(&path)),
            Some(on_path.path().join(BINARY))
        );
        assert_eq!(find_in(Some(empty.path()), None), None);
        assert_eq!(find_in(None, Some(empty.path().as_os_str())), None);
    }

    /// The whole daemon over its socket, without a sandbox: describe, append from
    /// two clients, a subscriber that sees everything in order, stop, and a clean
    /// exit that removes the socket and pid file.
    #[test]
    fn serve_answers_over_the_socket_and_exits_on_stop() {
        let state = tempfile::tempdir().unwrap();
        let id = "sess_daemon_unit";
        let dir = session_dir(state.path(), id);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = merge(
            &Policy::default(),
            &Policy::default(),
            &Policy::default(),
            ward_policy::SessionId(id.to_owned()),
            ward_policy::ProjectId("proj_unit".to_owned()),
        );
        let meta = SessionMeta {
            id: id.to_owned(),
            project: PathBuf::from("/tmp/demo"),
            project_id: "proj_unit".to_owned(),
            entry_snapshot: "blake3:abc".to_owned(),
            origin_repo: None,
            manifest,
            started_unix_ms: control::unix_ms(SystemTime::now()),
            agent: None,
        };
        std::fs::write(
            dir.join("session.json"),
            serde_json::to_vec_pretty(&meta).unwrap(),
        )
        .unwrap();
        let log_path = dir.join("events.log");
        {
            let mut log = LocalLog::create(
                &log_path,
                SessionId::from_u128(11),
                Blake3Hash::from_bytes([3; 32]),
                SystemTime::now(),
            )
            .unwrap();
            control::Sink::append(&mut log, Origin::Wardd, working(), SystemTime::now()).unwrap();
        }

        let (state_path, session) = (state.path().to_path_buf(), id.to_owned());
        let daemon = std::thread::spawn(move || serve(&state_path, &session));
        let socket = socket_path(state.path(), id);
        assert!(wait_until(STARTUP_TIMEOUT, || serving(state.path(), id)));
        assert_eq!(
            std::fs::read_to_string(pid_path(state.path(), id))
                .unwrap()
                .trim(),
            std::process::id().to_string()
        );

        let mut a = RemoteSink::connect(&socket).unwrap();
        match a.call(&Request::Describe).unwrap() {
            Response::Description(v) => {
                assert_eq!(v, serde_json::to_value(meta.describe()).unwrap());
            }
            other => panic!("{other:?}"),
        }
        let mut subscriber = RemoteSink::connect(&socket).unwrap();
        let first = subscriber
            .call(&Request::Subscribe { from_seq: 0 })
            .unwrap();
        assert!(
            matches!(&first, Response::Record(r) if r.seq == 0),
            "{first:?}"
        );

        let mut b = RemoteSink::connect(&socket).unwrap();
        assert!(matches!(a.call(&append(1)).unwrap(), Response::Record(r) if r.seq == 1));
        assert!(matches!(
            b.call(&Request::Evidence { event: denied() }).unwrap(),
            Response::Record(r) if r.seq == 2
        ));
        assert!(matches!(
            b.call(&Request::Stop {
                reason: EndReason::UserStop
            })
            .unwrap(),
            // `Finished` (the daemon's, after termination) and `SessionEnded`.
            Response::Sealed { head, ended: Some(0) } if head.next_seq == 5
        ));
        daemon
            .join()
            .unwrap()
            .expect("serve returns Ok after the seal");
        assert!(!socket.exists(), "the socket is unlinked");
        assert!(
            !pid_path(state.path(), id).exists(),
            "the pid file is removed"
        );

        // The subscriber got every live record in order, then the stream closed.
        // The replay-complete marker (#138 item 1) lands right behind the
        // replay it started with — before any live record — and is skipped,
        // not counted.
        let mut seen = vec![0];
        loop {
            match subscriber.read_response() {
                Ok(Response::Record(r)) => seen.push(r.seq),
                Ok(Response::CaughtUp { next_seq }) => assert_eq!(next_seq, 1),
                _ => break,
            }
        }
        assert_eq!(seen, [0, 1, 2, 3, 4]);
        let head = LogReader::open(&log_path).unwrap().verify_all().unwrap();
        assert_eq!(head.next_seq, 5);
        assert!(
            RemoteSink::connect(&socket).is_none(),
            "nothing answers after exit"
        );
    }

    /// #139 item 5, the literal ask: a session left mid-verification-attempt by
    /// whatever had been running it before — a crashed `wardd`, or a daemonless
    /// `ward verify` that was killed — must not still read as "running" once a
    /// fresh daemon takes the log over. `serve`'s own startup reconciles it before
    /// a single connection is served.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn serve_reconciles_a_dangling_verification_attempt_at_startup() {
        let state = tempfile::tempdir().unwrap();
        let id = "sess_daemon_reconcile";
        let dir = session_dir(state.path(), id);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = merge(
            &Policy::default(),
            &Policy::default(),
            &Policy::default(),
            ward_policy::SessionId(id.to_owned()),
            ward_policy::ProjectId("proj_unit".to_owned()),
        );
        let meta = SessionMeta {
            id: id.to_owned(),
            project: PathBuf::from("/tmp/demo"),
            project_id: "proj_unit".to_owned(),
            entry_snapshot: "blake3:abc".to_owned(),
            origin_repo: None,
            manifest,
            started_unix_ms: control::unix_ms(SystemTime::now()),
            agent: None,
        };
        std::fs::write(
            dir.join("session.json"),
            serde_json::to_vec_pretty(&meta).unwrap(),
        )
        .unwrap();
        let log_path = dir.join("events.log");
        let attempt = ward_events::AttemptId::new(1);
        {
            let mut log = LocalLog::create(
                &log_path,
                SessionId::from_u128(21),
                Blake3Hash::from_bytes([4; 32]),
                SystemTime::now(),
            )
            .unwrap();
            control::Sink::append(
                &mut log,
                Origin::Wardd,
                WardEvent::VerificationAttemptStarted {
                    attempt,
                    requested_by: ward_events::VerifyRequester::User,
                },
                SystemTime::now(),
            )
            .unwrap();
        }
        // The marker a real attempt's `AttemptGuard` would have left, as if the
        // process running it died right here — never `finish()`ed.
        let marker = dir.join("attempts").join("1.json");
        drop(
            crate::attempt::AttemptGuard::start(&dir, attempt, ward_events::VerifyRequester::User)
                .unwrap(),
        );
        assert!(marker.exists(), "the guard leaves its marker behind");

        let (state_path, session) = (state.path().to_path_buf(), id.to_owned());
        let daemon = std::thread::spawn(move || serve(&state_path, &session));
        assert!(wait_until(STARTUP_TIMEOUT, || serving(state.path(), id)));

        let socket = socket_path(state.path(), id);
        let mut client = RemoteSink::connect(&socket).unwrap();
        assert!(matches!(
            client
                .call(&Request::Stop {
                    reason: EndReason::UserStop,
                })
                .unwrap(),
            Response::Sealed { .. }
        ));
        daemon
            .join()
            .unwrap()
            .expect("serve returns Ok after the seal");

        assert!(
            !marker.exists(),
            "the marker is consumed by the daemon's own startup reconciliation"
        );
        let records: Vec<_> = LogReader::open(&log_path)
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let kinds: Vec<&str> = records
            .iter()
            .filter_map(|r| match &r.event {
                WardEvent::VerificationAttemptStarted { .. } => Some("AttemptStarted"),
                WardEvent::VerificationInterrupted { .. } => Some("Interrupted"),
                _ => None,
            })
            .collect();
        assert_eq!(
            kinds,
            vec!["AttemptStarted", "Interrupted"],
            "the dangling attempt is reconciled before any client could have \
             connected and asked for it"
        );
        match &records[1].event {
            WardEvent::VerificationInterrupted {
                attempt: got,
                candidate,
                reason,
            } => {
                assert_eq!(*got, attempt);
                assert_eq!(*candidate, None, "capture never even started");
                assert!(!reason.as_str().is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    /// #140, PR #197 review round 3: a connection that closes without ever
    /// appending a terminal record for the launch it started must not vanish
    /// from the grants list (the old silent-drop bug this doc comment on
    /// `open_launches` used to describe), must not keep reporting as a
    /// plain, still-open `Lifetime::Launch` (a false "still confirmed
    /// running" claim), and must not be retired either -- the false
    /// "confirmed safe" claim `f5d5c19` made and `0198c95` reverted for. It
    /// must report `Lifetime::LaunchUnknown`. Drives the exact reproduction
    /// the reverted commit's own test used -- append `CommandStarted` and a
    /// launch-scoped `CredentialGranted` over one real connection, drop that
    /// connection without ever sending a terminal record -- and adds a
    /// second, ordinary launch on its own connection that finishes cleanly,
    /// to confirm normal launches are completely unaffected by another
    /// connection's disconnect.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_connection_that_closes_without_a_terminal_record_reports_its_grant_as_launch_unknown() {
        use ward_events::{
            BoundedArgv, CredentialDelivery, ExitStatus, NameText, Pid, SandboxPath, SandboxRoot,
            Scope, ServiceId,
        };

        let state = tempfile::tempdir().unwrap();
        let id = "sess_disconnect_unit";
        let dir = session_dir(state.path(), id);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = merge(
            &Policy::default(),
            &Policy::default(),
            &Policy::default(),
            ward_policy::SessionId(id.to_owned()),
            ward_policy::ProjectId("proj_disconnect".to_owned()),
        );
        let meta = SessionMeta {
            id: id.to_owned(),
            project: PathBuf::from("/tmp/demo"),
            project_id: "proj_disconnect".to_owned(),
            entry_snapshot: "blake3:abc".to_owned(),
            origin_repo: None,
            manifest,
            started_unix_ms: control::unix_ms(SystemTime::now()),
            agent: None,
        };
        std::fs::write(
            dir.join("session.json"),
            serde_json::to_vec_pretty(&meta).unwrap(),
        )
        .unwrap();
        let log_path = dir.join("events.log");
        {
            let mut log = LocalLog::create(
                &log_path,
                SessionId::from_u128(12),
                Blake3Hash::from_bytes([4; 32]),
                SystemTime::now(),
            )
            .unwrap();
            control::Sink::append(&mut log, Origin::Wardd, working(), SystemTime::now()).unwrap();
        }

        let (state_path, session) = (state.path().to_path_buf(), id.to_owned());
        let daemon = std::thread::spawn(move || serve(&state_path, &session));
        let socket = socket_path(state.path(), id);
        assert!(wait_until(STARTUP_TIMEOUT, || serving(state.path(), id)));

        let started = |pid: Pid, argv: &'static [u8]| WardEvent::CommandStarted {
            pid,
            parent: Pid::new(1).unwrap(),
            argv: BoundedArgv::from_bytes([argv]),
            cwd: SandboxPath::new(SandboxRoot::Work, ".").unwrap(),
            exe_digest: None,
        };
        let granted = |service: &'static str, host: &str| WardEvent::CredentialGranted {
            service: ServiceId::new(service).unwrap(),
            scope: Scope {
                subject: ShortText::new(&format!("{host}:443")),
                permissions: vec![NameText::new("contents:read")],
            },
            expires: Duration::from_secs(60),
            delivery: CredentialDelivery::ProxyInjected,
        };
        let append = |sink: &mut RemoteSink, event: WardEvent| {
            assert!(matches!(
                sink.call(&Request::Append {
                    origin: Origin::Kernel,
                    event,
                    at_unix_ms: control::unix_ms(SystemTime::now()),
                })
                .unwrap(),
                Response::Record(_) | Response::Granted { .. }
            ));
        };

        let disconnected_pid = Pid::new(2).unwrap();
        {
            // Connection A: starts a launch and is granted a launch-scoped
            // credential, then closes (drops) without ever finishing it.
            let mut a = RemoteSink::connect(&socket).unwrap();
            append(&mut a, started(disconnected_pid, b"true"));
            append(&mut a, granted("github", "api.github.com"));
            // `a` drops here: the connection closes with no terminal record
            // ever sent for the launch it started.
        }

        // A second, separate launch on its own connection that DOES finish
        // normally: it must be entirely unaffected by A's disconnect.
        let finished_pid = Pid::new(3).unwrap();
        let mut c = RemoteSink::connect(&socket).unwrap();
        append(&mut c, started(finished_pid, b"false"));
        append(&mut c, granted("npm", "registry.npmjs.org"));
        append(
            &mut c,
            WardEvent::CommandFinished {
                pid: finished_pid,
                exit: ExitStatus::Exited { code: 0 },
                duration: Duration::from_secs(1),
            },
        );

        // Give the daemon's per-connection worker thread a bounded window to
        // notice A's close and run its cleanup before asserting on it: once
        // C's clean finish has already retired its own credential, only A's
        // should remain.
        let socket_for_wait = socket.clone();
        assert!(wait_until(Duration::from_secs(5), || {
            let Some(mut probe) = RemoteSink::connect(&socket_for_wait) else {
                return false;
            };
            matches!(
                probe.call(&Request::Grants),
                Ok(Response::Grants(g)) if g.len() == 1
            )
        }));

        // Over a third, unrelated connection: A's grant must still be listed
        // -- never silently dropped, the old bug -- but as `LaunchUnknown`,
        // never plain `Launch` (which would falsely claim it is still
        // confirmed running) and never gone (which would falsely claim it
        // was confirmed retired, the claim `f5d5c19` made and was reverted
        // for). C's grant, having ended cleanly on its own connection, is
        // gone exactly as before.
        let mut b = RemoteSink::connect(&socket).unwrap();
        match b.call(&Request::Grants).unwrap() {
            Response::Grants(grants) => {
                assert_eq!(
                    grants.len(),
                    1,
                    "only the disconnected launch's grant remains: {grants:?}"
                );
                assert_eq!(grants[0].label, "GitHub");
                assert_eq!(
                    grants[0].lifetime,
                    crate::approvals::Lifetime::LaunchUnknown,
                    "a connection that closed without a terminal record must report \
                     outcome-unknown, not confirmed running and not confirmed retired: \
                     {grants:?}"
                );
            }
            other => panic!("{other:?}"),
        }

        // The log itself is never fabricated a terminal record it cannot
        // vouch for: the disconnected launch is left at its bare
        // `CommandStarted`, while the one that finished normally shows its
        // real `CommandFinished`.
        let records: Vec<_> = LogReader::open(&log_path)
            .unwrap()
            .map(std::result::Result::unwrap)
            .collect();
        let last_for = |pid: Pid| {
            records.iter().rev().find_map(|r| match &r.event {
                WardEvent::CommandStarted { pid: p, .. }
                | WardEvent::CommandFinished { pid: p, .. }
                | WardEvent::LaunchAborted { pid: p, .. }
                    if *p == pid =>
                {
                    Some(&r.event)
                }
                _ => None,
            })
        };
        assert!(
            matches!(
                last_for(disconnected_pid),
                Some(WardEvent::CommandStarted { .. })
            ),
            "the disconnected launch is left at its CommandStarted, never a fabricated \
             terminal record: {:?}",
            last_for(disconnected_pid)
        );
        assert!(
            matches!(
                last_for(finished_pid),
                Some(WardEvent::CommandFinished { .. })
            ),
            "the launch that finished normally is unaffected: {:?}",
            last_for(finished_pid)
        );

        b.call(&Request::Stop {
            reason: EndReason::UserStop,
        })
        .unwrap();
        daemon.join().unwrap().unwrap();
    }
}
