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

use ward_events::{
    EventRecord, LogReader, Origin, PauseMethod, Pid, RevokeReason, ServiceId, ShortText, WardEvent,
};

use crate::acks::{self, Acknowledgement, Acknowledger, Phase};
use crate::approvals::{self, Approval, Approvals, Deriver, Outcome};
use crate::control::{
    self, LocalLog, OnProgress, Progress, RemoteSink, Request, Response, SOCKET_NAME,
};
use crate::error::{Error, Result};
use crate::launches::{self, LaunchState, Launches};
use crate::pause::{self, Frozen, Lifecycle, LifecycleReport, Operation};
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
/// writes `wardd.pid`, reconciles the lifecycle a previous process left
/// behind (#145 item 7, [`Served::reconcile_lifecycle_with`]: an interrupted
/// pause or stop is finished before a single connection is served, failing
/// closed like the attempt reconciliation; a stop finished this way seals the
/// log, clears the project's current pointer and returns at once, exactly as
/// if the stop had been asked over the socket), and serves connections
/// concurrently. Returns once the log is sealed and the socket and pid file
/// are gone.
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

    let mut served = Served::new(
        log,
        log_path,
        description,
        deriver,
        state.to_path_buf(),
        session.to_owned(),
    );
    let sealed = match served.reconcile_lifecycle() {
        Ok(sealed) => sealed,
        Err(e) => {
            release_socket(&socket, bound_inode, &pid_file);
            return Err(e);
        }
    };
    if sealed {
        release_socket(&socket, bound_inode, &pid_file);
        return crate::session::clear_current(state, &meta.project_id, session);
    }
    let lane = Arc::clone(&served.lane);
    let served = Arc::new(Mutex::new(served));
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
        let lane = Arc::clone(&lane);
        let finished = Arc::clone(&finished);
        let socket = socket.clone();
        workers.push(std::thread::spawn(move || {
            let sealed = serve_stream(stream, &served, &lane, peer);
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
    release_socket(&socket, bound_inode, &pid_file);
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

/// Remove the socket this process bound (only that one: a successor that
/// replaced a stale socket file owns the path now) and its pid file.
fn release_socket(socket: &Path, bound_inode: Option<u64>, pid_file: &Path) {
    if std::fs::metadata(socket).map(|m| m.ino()).ok() == bound_inode {
        let _ = std::fs::remove_file(socket);
    }
    let _ = std::fs::remove_file(pid_file);
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

/// A live subscription's channel and the sender its hang-up watcher ends it
/// with ([`Served::begin_subscription`]).
type LiveChannel = (Receiver<Delivery>, Sender<Delivery>);

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
    live: Option<LiveChannel>,
}

/// A pause in force: what was frozen, since when, and who holds it.
struct Paused {
    frozen: Frozen,
    since: Instant,
    /// Who holds the session (#145 item 6), mirrored durably in
    /// [`pause::HELD_BY`]: `ward resume` releases only the user's layer, a
    /// capture's hold is released by its [`Request::ReleaseCapture`] (or by
    /// reconciliation once the capturer is gone), and a stop's — a
    /// `HoldForStop` waiting for its `Stop` (PR #253 review finding 3), or a
    /// `Stop` refused because it could not confirm termination (finding 5),
    /// whose held processes may already have taken an irreversible `SIGKILL`
    /// — only by a stop (or a log-only `Seal`). The freeze is thawed and the
    /// marker cleared only when no owner remains.
    holders: pause::Holders,
    /// Processes a stop already ended and confirmed gone but has not recorded
    /// yet, because a component did not confirm the hold before
    /// `WorkloadsTerminated` could be appended (#145 item 3): carried into the
    /// retry's record, so the count on the log is the whole stop's.
    ended: u32,
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
    unconfirmed: Option<String>,
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
    /// Confirms each component of a hold (#145 item 3): the real registrations
    /// and approvals ([`acks::Live`]) outside tests.
    acks: Box<dyn Acknowledger>,
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
    /// The lifecycle this daemon last published (#145 item 1), read by
    /// `Request::Lifecycle` on its own lane — never behind the daemon's
    /// mutex, so a status request answers `pausing` *while* a pause waits on
    /// a component rather than after it ([`serve_stream`]). Rewritten under
    /// the mutex at every transition ([`Self::publish`]).
    lane: Arc<Mutex<LifecycleReport>>,
    /// Every launch this session admitted and how each stands (#145 item 2),
    /// mirrored durably in [`launches::LAUNCHES`].
    launches: Launches,
    /// Where a lifecycle operation reports each component as it confirms
    /// (#145 item 8): installed by the connection that asked for progress for
    /// the length of its request, `None` otherwise.
    progress: Option<OnProgress>,
    /// What the hold in force (`paused`) could not confirm (#145 item 1): the
    /// pending processes, the component that did not acknowledge, or what a
    /// stop could not confirm ended — `None` for a confirmed hold. Set
    /// wherever `paused` is, beside it; decides whether the lifecycle reads
    /// `Paused`/`Stopping` or `Incomplete`.
    held_unconfirmed: Option<String>,
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
            acks: Box::new(acks::Live::new()),
            open_launches: Vec::new(),
            last_agent_state: None,
            lane: Arc::new(Mutex::new(LifecycleReport::of(Lifecycle::Running))),
            launches: Launches::default(),
            progress: None,
            held_unconfirmed: None,
        }
    }

    /// The session's lifecycle from this daemon's own state (#145 item 1):
    /// `Stopped` once the log is sealed; while a hold is in force, `Incomplete`
    /// when it could not be confirmed, else `Stopping` for a stop's hold and
    /// `Paused` for the user's or a capture's; `Stopping` when a stop has
    /// begun (the stop marker) and nothing is held in memory — a stop that
    /// could not take its hold, which only a retry goes on from; `Running`
    /// otherwise. The transient states are what [`Self::enter`] publishes
    /// while an operation runs; between operations the daemon is never in one.
    fn lifecycle(&self) -> Lifecycle {
        if self.log.is_none() {
            return Lifecycle::Stopped;
        }
        // The stop marker outlives a daemon restart and makes any hold a
        // stop's, as `resume` has always read it.
        let stop_begun = pause::stop_begun(&self.state, &self.session);
        match &self.paused {
            Some(_) if self.held_unconfirmed.is_some() => Lifecycle::Incomplete,
            Some(paused) if paused.holders.stop || stop_begun => Lifecycle::Stopping,
            Some(_) => Lifecycle::Paused,
            None if stop_begun => Lifecycle::Stopping,
            None => Lifecycle::Running,
        }
    }

    /// What the lifecycle lane reports: the state, what is uncertain about it,
    /// the owners, and the handles still open.
    fn report(&self) -> LifecycleReport {
        LifecycleReport {
            state: self.lifecycle(),
            detail: self
                .paused
                .as_ref()
                .and_then(|_| self.held_unconfirmed.clone()),
            op: None,
            held_by: self
                .paused
                .as_ref()
                .map(|p| p.holders.owners())
                .unwrap_or_default(),
            open_launches: self.open_launches.iter().map(|(_, key, _)| *key).collect(),
        }
    }

    /// Publish the lifecycle the daemon is in now ([`Self::report`]) to the
    /// lane `Request::Lifecycle` reads.
    fn publish(&self) {
        *lock(&self.lane) = self.report();
    }

    /// Begin `op` (#145 item 1): decide, in the one transition table
    /// ([`pause::transition`]), whether the session's state admits it — the
    /// refusal names the state — and publish the transient state the session
    /// is in while it runs, so a `Request::Lifecycle` meanwhile reads
    /// `pausing`, `resuming` or `stopping`. Captures whose process is gone are
    /// forgotten first, as they hold nothing. The operation's end republishes
    /// the settled state ([`Self::publish`]).
    fn enter(&mut self, op: Operation) -> Result<Lifecycle> {
        if let Some(paused) = self.paused.as_mut() {
            paused.holders.prune_dead(Path::new("/proc"));
        }
        let holders = self
            .paused
            .as_ref()
            .map(|p| p.holders.clone())
            .unwrap_or_default();
        let entered = pause::transition(&self.session, self.lifecycle(), &holders, op)?;
        let mut report = self.report();
        report.state = entered;
        *lock(&self.lane) = report;
        Ok(entered)
    }

    /// Report one component's progress to the connection that asked for it
    /// (#145 item 8); nothing when none did.
    fn report_progress(&mut self, component: &str, confirmed: bool, detail: impl Into<String>) {
        if let Some(on_progress) = self.progress.as_mut() {
            on_progress(&Progress {
                component: component.to_owned(),
                confirmed,
                detail: detail.into(),
            });
        }
    }

    /// The progress line for a freeze: how many were frozen, by what, and
    /// whether it settled.
    fn report_freeze(&mut self, frozen: &Frozen, unsettled: Option<u32>) {
        let method = match frozen.method {
            PauseMethod::CgroupFreezer => "cgroup freezer",
            PauseMethod::Sigstop => "sigstop",
        };
        let detail = match unsettled {
            None => format!("{} frozen ({method}), settled", frozen.pids.len()),
            Some(pending) => format!(
                "{} frozen ({method}), {pending} not confirmed stopped within {}s",
                frozen.pids.len(),
                pause::FREEZE_SETTLE.as_secs()
            ),
        };
        self.report_progress(Progress::PROCESSES, unsettled.is_none(), detail);
    }

    /// The progress line for one component's acknowledgement.
    fn report_ack(&mut self, ack: &Acknowledgement, phase: Phase) {
        let detail = match (&ack.outcome, phase) {
            (acks::Outcome::Acknowledged, Phase::Held) => "acknowledged".to_owned(),
            (acks::Outcome::Acknowledged, Phase::Released) => "released".to_owned(),
            (acks::Outcome::TimedOut { after }, _) => {
                format!("no acknowledgement within {}s", after.as_secs())
            }
            (acks::Outcome::Error(reason), _) => reason.clone(),
        };
        self.report_progress(ack.component.as_str(), ack.confirmed(), detail);
    }

    /// Ask every component to confirm `phase` (#145 item 3), in hold order for
    /// [`Phase::Held`] and release order for [`Phase::Released`]. The daemon
    /// has already acted — marker written or cleared, approvals held or
    /// released — when this asks; each answer is a bounded read-back.
    fn confirm_components(&mut self, phase: Phase) -> Vec<Acknowledgement> {
        let order: Vec<acks::Component> = match phase {
            Phase::Held => acks::Component::HOLD_ORDER.to_vec(),
            Phase::Released => acks::Component::release_order().collect(),
        };
        order
            .into_iter()
            .map(|component| self.confirm_one(component, phase))
            .collect()
    }

    /// One component's confirmation of `phase`: a single step of a release.
    fn confirm_one(&mut self, component: acks::Component, phase: Phase) -> Acknowledgement {
        let site = acks::Site {
            state: &self.state,
            session: &self.session,
            approvals: &self.approvals,
        };
        let ack = Acknowledgement {
            component,
            outcome: self.acks.confirm(component, phase, &site),
        };
        self.report_ack(&ack, phase);
        ack
    }

    /// The one terminal record of a hold: `SessionPaused` only when the freeze
    /// settled (`unsettled` is `None`) and every component confirmed;
    /// `SessionPauseUnsettled` otherwise, its `pending` the freeze's count (zero
    /// when only a component is unconfirmed) and its `reason` naming the first
    /// unconfirmed component ([`acks::unconfirmed_reason`]).
    fn hold_record(
        method: PauseMethod,
        reason: &str,
        unsettled: Option<u32>,
        unconfirmed: Option<&Acknowledgement>,
    ) -> WardEvent {
        match (unsettled, unconfirmed) {
            (None, None) => WardEvent::SessionPaused {
                method,
                reason: ShortText::new(reason),
            },
            (pending, ack) => WardEvent::SessionPauseUnsettled {
                method,
                reason: ShortText::new(&ack.map_or_else(
                    || reason.to_owned(),
                    |a| acks::unconfirmed_reason(reason, a),
                )),
                pending: pending.unwrap_or(0),
            },
        }
    }

    /// What a hold could not confirm, in the words the log's own record
    /// yields back ([`acks::unsettled_detail`]) — so the lifecycle the daemon
    /// serves and the one a reader derives from the records agree: the
    /// component that did not acknowledge, else the processes not confirmed
    /// stopped; `None` for a confirmed hold.
    fn hold_uncertainty(
        unsettled: Option<u32>,
        unconfirmed: Option<&Acknowledgement>,
    ) -> Option<String> {
        match (unsettled, unconfirmed) {
            (_, Some(ack)) => Some(ack.text()),
            (Some(pending), None) => Some(format!("{pending} process(es) not confirmed stopped")),
            (None, None) => None,
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
            Request::GrantHistory => (
                Response::GrantHistory(self.approvals.grant_history()),
                false,
            ),
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
                        unconfirmed: outcome.unconfirmed,
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
                        control::FEATURE_CAPTURE_HOLD.into(),
                        control::FEATURE_LIFECYCLE.into(),
                    ],
                },
                false,
            ),
            // Served on its own lane by `serve_stream`, never behind this
            // mutex; answered here too for a caller that holds it already.
            Request::Lifecycle => (Response::Lifecycle(self.report()), false),
            // Per-connection, decided in `serve_stream`; a caller with no
            // connection has nothing to report to.
            Request::ReportProgress => (Response::Ok, false),
            Request::HoldForCapture {
                reason,
                pid,
                started,
            } => (
                self.hold_for_capture(&reason, (pid, started)).map_or_else(
                    |e| Response::Error(refusal(e)),
                    |op| Response::HeldForCapture { op },
                ),
                false,
            ),
            Request::ReleaseCapture { op } => (
                self.release_capture(&op).map_or_else(
                    |e| Response::Error(refusal(e)),
                    |record| record.map_or(Response::Ok, |r| Response::Record(Box::new(r))),
                ),
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
                    let _ = pause::clear_held_by(&self.state, &self.session);
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
                origin,
                at_unix_ms,
                event:
                    WardEvent::CredentialGranted {
                        service,
                        scope,
                        expires,
                        ..
                    },
            } => Some((
                *origin,
                *at_unix_ms,
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
                *expires,
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
                event: WardEvent::CommandFinished { pid, .. },
                ..
            } => Some((*pid, LaunchState::Finished)),
            Request::Append {
                event: WardEvent::LaunchAborted { pid, .. },
                ..
            } => Some((*pid, LaunchState::Aborted)),
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
            if let Some(credential) = credential {
                grant_id = Some(self.record_credential_grant(record, credential));
            }
            if let Some(pid) = launch_started {
                // Keep the logical pid so a confirmed stop can terminalize any
                // still-open launch before sealing the log. The record's seq
                // is the launch's stable, host-owned handle (#145 item 2),
                // registered durably from this moment.
                self.open_launches.push((conn, record.seq, pid));
                self.register_launch(record.seq, pid);
                self.publish();
            }
            if let Some((pid, state)) = launch_finished
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
                self.end_launch(key, state);
                self.publish();
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

    /// Records the daemon-side bookkeeping for a `CredentialGranted` append
    /// that `record` (just appended by [`Self::handle_appendable`]) carries:
    /// the live `Approvals` grant, and, when this grant could be attributed
    /// to a tracked launch, its own trailing `CredentialGrantedLaunch`
    /// attribution record (PR #318 review round 3 — see
    /// `WardEvent::CredentialGrantedLaunch`'s own doc comment for why this is
    /// a second record rather than a field on `CredentialGranted` itself).
    /// `credential` is `(origin, at_unix_ms, service, subject, permissions,
    /// launch_key, expires)`, exactly as [`Self::handle_appendable`] read it
    /// off the original `Request::Append` before that request was consumed.
    /// Returns the grant id the client learns back through
    /// `Response::Granted` (#245).
    ///
    /// Called from inside the same `handle_appendable` call that just
    /// appended `record`, so still under the one lock that call already
    /// holds (`Arc<Mutex<Served>>`, taken once per request in `serve_stream`
    /// — see `lock`/`serve_stream`): no other connection's request can land a
    /// record between the grant and this attribution.
    fn record_credential_grant(
        &mut self,
        record: &EventRecord,
        credential: (
            Origin,
            u64,
            String,
            String,
            Vec<String>,
            Option<u64>,
            Duration,
        ),
    ) -> u64 {
        let (origin, at_unix_ms, service, subject, permissions, launch_key, expires) = credential;
        // The subject is the route's upstream, `host:port`.
        let host = subject
            .rsplit_once(':')
            .map_or(subject.as_str(), |(h, _)| h);
        // Read from the record this very append just committed rather than
        // taking a second, independent `SystemTime::now()` (PR #318 review,
        // finding 3): `LocalLog::append` (`control.rs`) now always stamps
        // `ts_wall` with the daemon's own `SystemTime::now()` at the moment
        // of append, so this and the persisted/replayed `EventRecord.ts_wall`
        // the shell/desktop panel projection reads (`ward-shell-core::authority`)
        // are the exact same instant, not two clock reads that a delayed
        // append could pull apart. The fallback is defensive only —
        // unreachable in practice post-fix, since every `Sink::append` path
        // now populates `ts_wall` — so a `None` here (an older log format, or
        // a `Sink` implementation this daemon does not control) still
        // produces a sane bound instead of panicking or nonsense-dating the
        // grant.
        let granted_at_unix_ms = record
            .ts_wall
            .map_or_else(|| control::unix_ms(SystemTime::now()), control::unix_ms);
        // The instant this credential's own recorded lifetime runs out
        // (#140): `granted_at_unix_ms` plus the event's own `expires`,
        // saturating rather than overflowing on a pathological huge duration
        // — a credential that could never expire on its own maths is exactly
        // the same as one this cannot compute a bound for at all.
        let expires_at_unix_ms = u64::try_from(expires.as_millis())
            .ok()
            .map(|ms| granted_at_unix_ms.saturating_add(ms));
        let grant_id = self.approvals.record_credential_with_expiry(
            &service,
            host,
            permissions,
            launch_key,
            granted_at_unix_ms,
            expires_at_unix_ms,
        );
        // Attribute this grant to its own launch on the wire, as a second,
        // immediately-following record. Only emitted when this grant could be
        // attributed to a tracked launch at all; when it could not
        // (`launch_key` is `None`), no attribution record follows, exactly as
        // a grant with no known launch identity looked before this variant
        // existed.
        if let Some(launch_seq) = launch_key {
            let subscribers = &mut self.subscribers;
            let attributed = control::handle_with(
                &mut self.log,
                Request::Append {
                    origin,
                    event: WardEvent::CredentialGrantedLaunch { launch_seq },
                    at_unix_ms,
                },
                |record| {
                    subscribers
                        .retain(|s| s.send(Delivery::Record(Box::new(record.clone()))).is_ok());
                },
            );
            debug_assert!(
                matches!(attributed.0, Response::Record(_)),
                "the log was just appended to successfully under the same lock; \
                 a second append on the same session cannot fail here: {:?}",
                attributed.0
            );
        }
        grant_id
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
            self.end_launch(key, LaunchState::Unknown);
        }
        self.publish();
    }

    /// Register launch `handle` as admitted (#145 item 2) and write the
    /// register. The log already carries the launch's `CommandStarted`; the
    /// register is the index beside it, so a failure to write it is untidy,
    /// never incorrect, and is not allowed to fail the append it follows.
    fn register_launch(&mut self, handle: u64, pid: Pid) {
        self.launches
            .admit(handle, pid, control::unix_ms(SystemTime::now()));
        let _ = launches::write(&self.state, &self.session, &self.launches);
    }

    /// Record how launch `handle` ended in the register (#145 item 2).
    fn end_launch(&mut self, handle: u64, state: LaunchState) {
        if self
            .launches
            .end(handle, state, control::unix_ms(SystemTime::now()))
        {
            let _ = launches::write(&self.state, &self.session, &self.launches);
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

    /// Pause the session (ADR-0019 §3), in this order: record the pause's
    /// intent ([`Self::record_intent`]), freeze the sandbox processes, write
    /// the marker every proxy of the session refuses on (new connections, new
    /// requests, credential injection), hold the approvals, decide whether the
    /// freeze actually settled, and append exactly one terminal record for it
    /// — `SessionPaused` when confirmed, `SessionPauseUnsettled` otherwise —
    /// after which the intent is cleared. The processes are frozen first so
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
        append: impl FnMut(&mut Self, WardEvent) -> Result<EventRecord>,
    ) -> Result<PauseOutcome> {
        // #145 item 1: admitted (or refused, naming the state) by the one
        // transition table; `pausing` is published while this runs.
        self.enter(Operation::Pause)?;
        let outcome = self.pause_entered(reason, settle, append);
        self.publish();
        outcome
    }

    /// [`Self::pause_with_appending`] once the transition is admitted.
    fn pause_entered(
        &mut self,
        reason: &str,
        settle: impl FnOnce(&Frozen) -> Option<u32>,
        mut append: impl FnMut(&mut Self, WardEvent) -> Result<EventRecord>,
    ) -> Result<PauseOutcome> {
        let reason = pause::reason_text(reason);
        self.record_intent(pause::Verb::Pause {
            reason: reason.clone(),
        })?;
        // #234: the same lock `CaptureFreeze::acquire`/`Drop` take, held across the
        // freeze and the marker write so a capture's own marker check or thaw can
        // never straddle this pause taking hold.
        let _lock = pause::lock_pause_freeze(&session_dir(&self.state, &self.session))?;
        let layered = self.paused.take();
        let layered_unconfirmed = self.held_unconfirmed.take();
        let (frozen, since, before, ended) = match layered {
            Some(paused) => (paused.frozen, paused.since, paused.holders, paused.ended),
            None => (
                pause::freeze(&self.session),
                Instant::now(),
                pause::Holders::default(),
                0,
            ),
        };
        let fresh = before.is_empty();
        let mut holders = before.clone();
        holders.user = true;
        let marked = pause::write_marker(&self.state, &self.session, &reason)
            .and_then(|()| pause::write_held_by(&self.state, &self.session, &holders));
        if let Err(e) = marked {
            self.take_back_user_layer(fresh, frozen, since, before, ended, layered_unconfirmed);
            let _ = pause::clear_intent(&self.state, &self.session);
            return Err(e);
        }
        self.approvals.set_paused(true);
        // The marker and the held approvals already stand — the safest state #145
        // item 4 asks for — before the settle check or any component is asked,
        // and stay that way regardless of the answers or of whether the terminal
        // record below makes it onto the log. The freeze is confirmed first,
        // then each component in hold order, each reported as it answers
        // (#145 item 8).
        let unsettled = settle(&frozen);
        self.report_freeze(&frozen, unsettled);
        let acks = self.confirm_components(Phase::Held);
        let unconfirmed = acks::first_unconfirmed(&acks).cloned();
        let event = Self::hold_record(frozen.method, &reason, unsettled, unconfirmed.as_ref());
        let confirmed = matches!(event, WardEvent::SessionPaused { .. });
        let uncertain = Self::hold_uncertainty(unsettled, unconfirmed.as_ref());
        let record = match append(self, event) {
            Ok(record) => record,
            Err(e) if confirmed => {
                // Byte-for-byte the same rollback this append has always had:
                // without a durable `SessionPaused` record, the log never
                // agrees the session was paused at all, so nothing else about
                // it should stand either.
                self.take_back_user_layer(fresh, frozen, since, before, ended, layered_unconfirmed);
                let _ = pause::clear_intent(&self.state, &self.session);
                return Err(e);
            }
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
                self.held_unconfirmed = uncertain;
                self.paused = Some(Paused {
                    frozen,
                    since,
                    holders,
                    ended,
                });
                return Err(Error::Daemon(format!(
                    "the pause of session {} could not be confirmed settled ({}), and \
                     the record of that could not be written to the log ({e}); the \
                     marker is held and approvals stay frozen regardless, but the log \
                     may not reflect the unsettled pause",
                    self.session,
                    pause::uncertainty(unsettled, unconfirmed.as_ref())
                )));
            }
        };
        let _ = pause::clear_intent(&self.state, &self.session);
        self.held_unconfirmed = uncertain;
        self.paused = Some(Paused {
            frozen,
            since,
            holders,
            ended,
        });
        Ok(PauseOutcome {
            record: Box::new(record),
            unsettled,
            unconfirmed: unconfirmed.map(|a| a.text()),
        })
    }

    /// Undo a user's pause that did not complete: when it was the only hold
    /// (`fresh`), everything it did; when it was layered over a capture's hold,
    /// only its own layer — the marker is rewritten with the capture's reason,
    /// the owners restored, nothing thawed and the approvals kept held.
    fn take_back_user_layer(
        &mut self,
        fresh: bool,
        frozen: Frozen,
        since: Instant,
        before: pause::Holders,
        ended: u32,
        unconfirmed: Option<String>,
    ) {
        if fresh {
            self.approvals.set_paused(false);
            let _ = pause::clear_marker(&self.state, &self.session);
            let _ = pause::clear_held_by(&self.state, &self.session);
            pause::thaw(&frozen);
            return;
        }
        if let Some(reason) = before.captures.first().map(|c| c.reason.clone()) {
            let _ = pause::write_marker(&self.state, &self.session, &reason);
        }
        let _ = pause::write_held_by(&self.state, &self.session, &before);
        self.held_unconfirmed = unconfirmed;
        self.paused = Some(Paused {
            frozen,
            since,
            holders: before,
            ended,
        });
    }

    /// Record durably that `verb` has begun for this session (#145 item 7):
    /// see [`pause::INTENT`]. Called before any process is signalled, so a
    /// daemon restarted after a crash anywhere after it finishes the operation
    /// ([`Self::reconcile_lifecycle`]). The intent is cleared, best effort,
    /// once the operation's terminal record is durable: a removal that fails
    /// is untidy, never incorrect, since a restart then finds the log already
    /// carrying the outcome and adopts it without a second record.
    fn record_intent(&self, verb: pause::Verb) -> Result<()> {
        let intent = pause::Intent::begin(verb)?;
        lock(&self.lane).op = Some(intent.op.clone());
        pause::write_intent(&self.state, &self.session, &intent)
    }

    /// Reverse [`Self::pause`] in the reverse of the order it held (#145 item
    /// 3): release the credentials and the approvals, clear the marker the
    /// proxies read, confirm each release before the next
    /// ([`Self::confirm_one`]), thaw the processes last, append
    /// `SessionResumed` ([`Self::release_hold`]). A release that is not
    /// confirmed is taken back — the marker rewritten with the pause's
    /// reason, the approvals held again, nothing thawed — and the resume is
    /// refused naming the component, so the session is never half-resumed
    /// with a proxy still refusing traffic while the daemon believes it runs.
    ///
    /// Releases only the user's layer (#145 item 6): a hold a capture also
    /// owns stays — marker, held approvals, freeze — and the record answered
    /// is the `SessionPaused` that says what still holds; a hold only
    /// captures own is refused, since no user pause is there to release. A
    /// capture whose process is gone owns nothing any more, so a hold left
    /// only to such captures is released outright: reconciliation after its
    /// owners are gone, not a user pause being lifted.
    ///
    /// Refused while the session is held for a stop, and once a stop of it
    /// has begun at all (the on-disk stop marker, which outlives a daemon
    /// restart): a `HoldForStop` must stay in force until its stop (PR #253
    /// review finding 3), and a refused stop's remaining processes have
    /// already been sent `SIGKILL` — releasing them as though they were an
    /// ordinary pause would present a half-killed session as resumable
    /// execution (finding 5). A stop is retried with `ward stop`.
    fn resume(&mut self) -> Result<Box<EventRecord>> {
        // #145 item 1: admitted (or refused, naming the state — `not paused`,
        // the stop that has begun, the capture that holds it) by the one
        // transition table; `resuming` is published while this runs.
        self.enter(Operation::Resume)?;
        let released = self.resume_entered();
        self.publish();
        released
    }

    /// [`Self::resume`] once the transition is admitted: the hold is the
    /// user's (perhaps with captures under it).
    fn resume_entered(&mut self) -> Result<Box<EventRecord>> {
        // #234: the same lock `pause`/`CaptureFreeze` take, so a capture's own
        // marker check or thaw can never straddle this resume's marker clear and
        // thaw.
        let _lock = pause::lock_pause_freeze(&session_dir(&self.state, &self.session))?;
        let Some(mut paused) = self.paused.take() else {
            return Err(Error::Daemon("not paused".into()));
        };
        // The resume's intent (#145 items 1 and 7): durable before anything
        // is released, so a daemon restarted after a death between the
        // marker's clearing and the thaw finishes the release.
        if let Err(e) = self.record_intent(pause::Verb::Resume) {
            self.paused = Some(paused);
            return Err(e);
        }
        if let Some(capture) = paused.holders.captures.first().cloned() {
            paused.holders.user = false;
            let relabelled = pause::write_held_by(&self.state, &self.session, &paused.holders)
                .and_then(|()| pause::write_marker(&self.state, &self.session, &capture.reason));
            if let Err(e) = relabelled {
                paused.holders.user = true;
                self.paused = Some(paused);
                let _ = pause::clear_intent(&self.state, &self.session);
                return Err(e);
            }
            let method = paused.frozen.method;
            self.paused = Some(paused);
            let record = self.append(Self::hold_record(method, &capture.reason, None, None))?;
            let _ = pause::clear_intent(&self.state, &self.session);
            return Ok(Box::new(record));
        }
        let released = self.release_hold(paused);
        // The hold either released (recorded) or stands again: the resume has
        // its outcome either way.
        let _ = pause::clear_intent(&self.state, &self.session);
        released.map(Box::new)
    }

    /// End a hold no owner keeps any more, in the reverse of the order it was
    /// taken (#145 item 3): release the credentials and the approvals, clear
    /// the marker, confirm each before the next, thaw last, and append
    /// `SessionResumed`. A release a component does not confirm is taken
    /// back — `paused` restored as given, marker rewritten, approvals held —
    /// and refused naming the component. Called under
    /// [`pause::lock_pause_freeze`].
    fn release_hold(&mut self, paused: Paused) -> Result<EventRecord> {
        let marker = pause::marker_path(&self.state, &self.session);
        let marker_reason =
            pause::reason_text(&std::fs::read_to_string(&marker).unwrap_or_default());
        self.approvals.set_paused(false);
        for component in acks::Component::release_order() {
            if component == acks::Component::Proxy
                && let Err(e) = pause::clear_marker(&self.state, &self.session)
            {
                self.approvals.set_paused(true);
                self.paused = Some(paused);
                return Err(e);
            }
            let ack = self.confirm_one(component, Phase::Released);
            if ack.confirmed() {
                continue;
            }
            self.approvals.set_paused(true);
            self.paused = Some(paused);
            let rewritten = (component == acks::Component::Proxy)
                .then(|| pause::write_marker(&self.state, &self.session, &marker_reason).err())
                .flatten();
            return Err(Error::Daemon(format!(
                "resume of session {} is refused: {} did not confirm its release, so the \
                 session stays paused (marker held, approvals held, processes frozen){}. \
                 Run `ward resume` again",
                self.session,
                ack.text(),
                rewritten.map_or_else(String::new, |e| format!(
                    "; the marker could not be rewritten ({e}), so the proxies may have \
                     released"
                ))
            )));
        }
        let _ = pause::clear_held_by(&self.state, &self.session);
        pause::thaw(&paused.frozen);
        self.report_progress(
            Progress::PROCESSES,
            true,
            format!("{} thawed", paused.frozen.pids.len()),
        );
        let paused_for = paused.since.elapsed();
        self.append(WardEvent::SessionResumed { paused_for })
    }

    /// `Request::HoldForCapture` (#145 item 6): hold the session for a
    /// snapshot capture from confirmed quiescence. Always uses
    /// [`pause::freeze_for_capture`] / [`pause::stabilize`]; see
    /// [`Self::hold_for_capture_with`].
    fn hold_for_capture(&mut self, reason: &str, by: (u32, String)) -> Result<Option<String>> {
        self.hold_for_capture_with(reason, by, pause::freeze_for_capture, pause::stabilize)
    }

    /// [`Self::hold_for_capture`], with the freeze injectable (a test needs an
    /// unsettled outcome no real process can produce on demand).
    ///
    /// Under [`pause::lock_pause_freeze`]: a hold already in force (the user's,
    /// a stop's, another capture's) is reused — its freeze confirmed stable
    /// again, every component asked again — and this capture is added to its
    /// owners, with no record of its own: the session's hold is recorded
    /// already, and the capture must never take it over. Otherwise the
    /// capture's intent is recorded, the sandboxes are frozen, the marker
    /// written, the approvals held, the owners written, every component asked,
    /// and — only when the freeze settled and every component acknowledged —
    /// `SessionPaused` is appended with the capture's reason and the intent
    /// cleared. A session with nothing running is held by nothing (`Ok(None)`).
    ///
    /// When quiescence cannot be confirmed the capture is refused
    /// ([`pause::capture_refusal`]) with nothing recorded: a fresh hold is
    /// undone whole, a reused one loses only this capture. Nothing may be
    /// captured from a state that would record `SessionPauseUnsettled`.
    fn hold_for_capture_with(
        &mut self,
        reason: &str,
        by: (u32, String),
        freeze: impl FnOnce(&str) -> (Frozen, bool),
        restabilize: impl FnOnce(&str, Frozen) -> (Frozen, bool),
    ) -> Result<Option<String>> {
        self.enter(Operation::HoldForCapture)?;
        let held = self.hold_for_capture_entered(reason, by, freeze, restabilize);
        self.publish();
        held
    }

    /// [`Self::hold_for_capture_with`] once the transition is admitted.
    fn hold_for_capture_entered(
        &mut self,
        reason: &str,
        by: (u32, String),
        freeze: impl FnOnce(&str) -> (Frozen, bool),
        restabilize: impl FnOnce(&str, Frozen) -> (Frozen, bool),
    ) -> Result<Option<String>> {
        let _lock = pause::lock_pause_freeze(&session_dir(&self.state, &self.session))?;
        let op = crate::ids::new_operation_id()?;
        let capturer = pause::Capturer {
            op: op.clone(),
            pid: by.0,
            started: by.1,
            reason: reason.to_owned(),
        };
        if let Some(paused) = self.paused.take() {
            let (frozen, stable) = restabilize(&self.session, paused.frozen);
            let unsettled = if stable {
                None
            } else {
                Some(pause::unsettled_count(&frozen, false).unwrap_or(0))
            };
            let before = paused.holders.clone();
            let mut holders = before.clone();
            holders.add_capture(capturer);
            self.paused = Some(Paused {
                frozen,
                since: paused.since,
                holders,
                ended: paused.ended,
            });
            let acks = self.confirm_components(Phase::Held);
            let unconfirmed = acks::first_unconfirmed(&acks);
            if unsettled.is_some() || unconfirmed.is_some() {
                if let Some(p) = self.paused.as_mut() {
                    p.holders = before;
                }
                return Err(pause::capture_refusal(
                    &self.session,
                    unsettled,
                    unconfirmed,
                ));
            }
            if let Some(p) = self.paused.as_ref()
                && let Err(e) = pause::write_held_by(&self.state, &self.session, &p.holders)
            {
                if let Some(p) = self.paused.as_mut() {
                    p.holders = before;
                }
                return Err(e);
            }
            return Ok(Some(op));
        }
        self.record_intent(pause::Verb::Capture {
            reason: reason.to_owned(),
            capturer: capturer.clone(),
        })?;
        let (frozen, stable) = freeze(&self.session);
        if frozen.pids.is_empty() {
            let _ = pause::clear_intent(&self.state, &self.session);
            return Ok(None);
        }
        let holders = pause::Holders::for_capture(capturer);
        let take_back = |this: &mut Self, frozen: &Frozen| {
            this.approvals.set_paused(false);
            let _ = pause::clear_held_by(&this.state, &this.session);
            let _ = pause::clear_marker(&this.state, &this.session);
            pause::thaw(frozen);
            let _ = pause::clear_intent(&this.state, &this.session);
        };
        let marked = pause::write_marker(&self.state, &self.session, reason)
            .and_then(|()| pause::write_held_by(&self.state, &self.session, &holders));
        if let Err(e) = marked {
            take_back(self, &frozen);
            return Err(e);
        }
        self.approvals.set_paused(true);
        let acks = self.confirm_components(Phase::Held);
        let unconfirmed = acks::first_unconfirmed(&acks);
        let unsettled = if stable {
            None
        } else {
            Some(pause::unsettled_count(&frozen, false).unwrap_or(0))
        };
        if unsettled.is_some() || unconfirmed.is_some() {
            let refusal = pause::capture_refusal(&self.session, unsettled, unconfirmed);
            take_back(self, &frozen);
            return Err(refusal);
        }
        if let Err(e) = self.append(Self::hold_record(frozen.method, reason, None, None)) {
            take_back(self, &frozen);
            return Err(e);
        }
        let _ = pause::clear_intent(&self.state, &self.session);
        self.held_unconfirmed = None;
        self.paused = Some(Paused {
            frozen,
            since: Instant::now(),
            holders,
            ended: 0,
        });
        Ok(Some(op))
    }

    /// `Request::ReleaseCapture` (#145 item 6): the capture of operation `op`
    /// lets go of the session. Other owners keep the hold as it is (`Ok(None)`,
    /// nothing recorded); the last owner's release ends it
    /// ([`Self::release_hold`]) and the `SessionResumed` is returned. A hold
    /// `op` does not own — released already, or ended by a stop — is nothing
    /// to release.
    fn release_capture(&mut self, op: &str) -> Result<Option<EventRecord>> {
        let released = self.release_capture_entered(op);
        self.publish();
        released
    }

    /// [`Self::release_capture`]; idempotent, so it needs no transition.
    fn release_capture_entered(&mut self, op: &str) -> Result<Option<EventRecord>> {
        if !self
            .paused
            .as_ref()
            .is_some_and(|p| p.holders.captures.iter().any(|c| c.op == op))
        {
            return Ok(None);
        }
        let _lock = pause::lock_pause_freeze(&session_dir(&self.state, &self.session))?;
        let Some(paused) = self.paused.take() else {
            return Ok(None);
        };
        let mut remaining = paused.holders.clone();
        remaining.remove_capture(op);
        remaining.prune_dead(Path::new("/proc"));
        if remaining.is_empty() {
            return self.release_hold(paused).map(Some);
        }
        let written = pause::write_held_by(&self.state, &self.session, &remaining);
        self.paused = Some(Paused {
            holders: remaining,
            ..paused
        });
        written.map(|()| None)
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
    /// Under [`pause::lock_pause_freeze`], in this order: the hold's intent is
    /// recorded (as a pause: that is what a restart finishes, as a hold for
    /// the stop once the stop marker exists), the stop marker is
    /// written, so no launch is admitted from here on
    /// ([`pause::admit_launch`]); then the daemon's *own* view decides what is
    /// frozen — never the pause marker on disk, which a daemon restarted since
    /// it was written does not hold anything for. A pause already in force is
    /// taken over (its freeze re-confirmed stable, since it may have been
    /// unsettled) without a new record; otherwise the sandboxes are frozen now,
    /// the marker is written, the approvals are held and `SessionPaused` (or
    /// `SessionPauseUnsettled`) is appended, exactly as `ward pause` records
    /// one. Either way the result is a stop's hold ([`pause::Holders::stop`]), which `Resume` refuses.
    /// Returns `Some(pending)` when the freeze could not be confirmed stable in
    /// time — the hold still stands, and a caller that needs quiescence (a
    /// restore) must not proceed on it.
    fn hold_for_stop_with(
        &mut self,
        reason: &str,
        freeze: impl FnOnce(&str) -> (Frozen, bool),
        restabilize: impl FnOnce(&str, Frozen) -> (Frozen, bool),
    ) -> Result<Option<u32>> {
        self.enter(Operation::HoldForStop)?;
        let held = self.hold_for_stop_entered(reason, freeze, restabilize);
        self.publish();
        held
    }

    /// [`Self::hold_for_stop_with`] once the transition is admitted.
    fn hold_for_stop_entered(
        &mut self,
        reason: &str,
        freeze: impl FnOnce(&str) -> (Frozen, bool),
        restabilize: impl FnOnce(&str, Frozen) -> (Frozen, bool),
    ) -> Result<Option<u32>> {
        let _lock = pause::lock_pause_freeze(&session_dir(&self.state, &self.session))?;
        self.record_intent(pause::Verb::Pause {
            reason: pause::reason_text(reason),
        })?;
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
            let mut holders = paused.holders;
            holders.stop = true;
            let owners = pause::write_held_by(&self.state, &self.session, &holders);
            self.report_freeze(&frozen, unsettled);
            self.held_unconfirmed = Self::hold_uncertainty(unsettled, None);
            self.paused = Some(Paused {
                frozen,
                since: paused.since,
                holders,
                ended: paused.ended,
            });
            marker?;
            owners?;
            let _ = pause::clear_intent(&self.state, &self.session);
            let acks = self.confirm_components(Phase::Held);
            if let Some(ack) = acks::first_unconfirmed(&acks) {
                self.held_unconfirmed = Self::hold_uncertainty(unsettled, Some(ack));
                return Err(self.hold_unconfirmed(ack));
            }
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
        let holders = pause::Holders::for_stop();
        let owners = pause::write_held_by(&self.state, &self.session, &holders);
        self.report_freeze(&frozen, unsettled);
        self.held_unconfirmed = Self::hold_uncertainty(unsettled, None);
        self.paused = Some(Paused {
            frozen,
            since: Instant::now(),
            holders,
            ended: 0,
        });
        owners?;
        let acks = self.confirm_components(Phase::Held);
        let unconfirmed = acks::first_unconfirmed(&acks).cloned();
        if unconfirmed.is_some() {
            self.held_unconfirmed = Self::hold_uncertainty(unsettled, unconfirmed.as_ref());
        }
        let event = Self::hold_record(method, &reason, unsettled, unconfirmed.as_ref());
        // The hold is never undone for a log-only failure: it is the safest
        // state, and the stop that follows ends it.
        self.append(event).map_err(|e| {
            Error::Daemon(format!(
                "session {} is held for its stop, but the record of that could not be \
                 written ({e}); nothing was restored. Run `ward stop` to finish the stop",
                self.session
            ))
        })?;
        let _ = pause::clear_intent(&self.state, &self.session);
        match unconfirmed {
            Some(ack) => Err(self.hold_unconfirmed(&ack)),
            None => Ok(unsettled),
        }
    }

    /// The refusal a hold for a stop answers with when a component did not
    /// confirm it: the hold stands, and nothing may rely on it as quiescence.
    fn hold_unconfirmed(&self, ack: &Acknowledgement) -> Error {
        Error::Daemon(format!(
            "session {} is held for its stop, but {} did not confirm the hold; nothing \
             was restored. Run `ward stop --restore-entry` again, or `ward stop`",
            self.session,
            ack.text()
        ))
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
    /// stop ([`pause::Holders::stop`]) — the marker written so every proxy refuses, the
    /// approvals held, the processes still present kept as the hold's freeze.
    /// `WorkloadsTerminated { pending }` records the partial outcome. That is
    /// an incomplete stop, not a pause: `ward resume` refuses it, and a later
    /// `ward stop` retries from there.
    ///
    /// The stop's intent ([`Self::record_intent`]) is durable before the
    /// lifecycle lock is even taken, and cleared once the log is sealed (or,
    /// in [`Self::end_workloads`], once the refused stop's hold is recorded).
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
        // #145 item 1: a stop is admitted from running, from paused and as the
        // retry of an incomplete one; `stopping` is published while it runs.
        if let Err(e) = self.enter(Operation::Stop) {
            return (Response::Error(refusal(e)), false);
        }
        let stopped = self.stop_entered(conn, reason, terminate);
        self.publish();
        stopped
    }

    /// [`Self::stop`] once the transition is admitted.
    fn stop_entered(
        &mut self,
        conn: u64,
        reason: ward_events::EndReason,
        terminate: impl FnOnce(&str, Option<Frozen>) -> pause::Termination,
    ) -> (Response, bool) {
        if let Err(e) = self.record_intent(pause::Verb::Stop { reason }) {
            return (
                Response::Error(format!(
                    "stop could not record its intent for session {} ({}); nothing was \
                     terminated and the log is not sealed",
                    self.session,
                    refusal(e)
                )),
                false,
            );
        }
        let ended = match self.end_workloads(terminate) {
            Ok(n) => n,
            Err(e) => return (Response::Error(refusal(e)), false),
        };
        if let Err(e) = self.abort_open_launches_for_stop() {
            return (
                Response::Error(format!(
                    "stop ended every sandboxed process of session {} ({ended}), but an open launch could not be terminalized ({e}); the log is not sealed. Run `ward stop` again",
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
            (Response::Sealed { head, .. }, done) => {
                let _ = pause::clear_intent(&self.state, &self.session);
                (
                    Response::Sealed {
                        head,
                        ended: Some(ended),
                    },
                    done,
                )
            }
            other => other,
        }
    }

    /// The termination half of [`Self::stop`]: returns how many processes ended,
    /// or the refusal once the session has been put in its held-for-stop state.
    /// The marker is written (if a pause's does not stand already) and the
    /// approvals held before anything is killed, so every proxy refuses during
    /// the kill and can acknowledge that it does; once every process is
    /// confirmed gone, every component must confirm the hold (#145 item 3,
    /// [`Self::confirm_components`]) before `WorkloadsTerminated` is appended —
    /// a stop is not confirmed by process termination alone — and one that does
    /// not refuses the stop ([`Self::hold_for_unconfirmed_stop`]).
    /// That hold and its `WorkloadsTerminated` record are the attempt's durable
    /// outcome, so the stop's intent is cleared with them: a restart adopts the
    /// hold rather than terminating again on its own, and the user's retry does
    /// that. A hold whose record could not be written keeps the intent, so a
    /// restart records it.
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
        let retrying_incomplete_stop = held.as_ref().is_some_and(|p| p.holders.stop);
        let carried = held.as_ref().map_or(0, |p| p.ended);
        if !pause::marker_path(&self.state, &self.session).exists() {
            pause::write_marker(&self.state, &self.session, pause::STOP_REASON).map_err(|e| {
                Error::Daemon(format!(
                    "stop could not close session {}'s proxies ({e}); nothing was terminated \
                     and the log is not sealed",
                    self.session
                ))
            })?;
        }
        self.approvals.set_paused(true);
        let outcome = terminate(&self.session, held.map(|p| p.frozen));
        let ended = outcome.ended.saturating_add(carried);
        let pending = outcome.pending();
        let barrier_confirmed = outcome.barrier_confirmed;
        self.report_progress(
            Progress::PROCESSES,
            outcome.remaining.is_none(),
            format!(
                "{ended} ended, {pending} pending, barrier {}",
                if barrier_confirmed {
                    "confirmed"
                } else {
                    "not confirmed"
                }
            ),
        );
        let Some(remaining) = outcome.remaining else {
            let acks = self.confirm_components(Phase::Held);
            if let Some(ack) = acks::first_unconfirmed(&acks) {
                return Err(self.hold_for_unconfirmed_stop(ack, outcome.method, since, ended));
            }
            // Nothing is left for the marker to hold back. (Idempotent when
            // there never was a marker.)
            let _ = pause::clear_marker(&self.state, &self.session);
            let _ = pause::clear_held_by(&self.state, &self.session);
            if ended > 0 || retrying_incomplete_stop {
                self.append(WardEvent::WorkloadsTerminated {
                    ended,
                    pending: 0,
                    barrier_confirmed: true,
                })
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
        Err(self.hold_for_incomplete_stop(remaining, since, ended, barrier_confirmed))
    }

    /// The refused half of [`Self::end_workloads`]: termination was not
    /// confirmed, so the session is held for the stop over whatever is still
    /// there (`remaining`) — an incomplete stop, not a pause — and
    /// `WorkloadsTerminated { pending, barrier_confirmed }` records it durably.
    fn hold_for_incomplete_stop(
        &mut self,
        remaining: Frozen,
        since: Option<Instant>,
        ended: u32,
        barrier_confirmed: bool,
    ) -> Error {
        let pending = u32::try_from(remaining.pids.len()).unwrap_or(u32::MAX);
        let marker = pause::write_marker(
            &self.state,
            &self.session,
            &pause::stop_hold_reason(pending),
        )
        .err();
        let _ = pause::write_held_by(&self.state, &self.session, &pause::Holders::for_stop());
        self.held_unconfirmed = Some(if pending > 0 {
            format!("{pending} process(es) not confirmed ended")
        } else {
            "membership barrier unconfirmed".to_owned()
        });
        self.paused = Some(Paused {
            frozen: remaining,
            since: since.unwrap_or_else(Instant::now),
            holders: pause::Holders::for_stop(),
            ended: 0,
        });
        // Persist the incomplete result even when no currently-known PID remains:
        // barrier uncertainty is itself evidence. Replay/restart must still know
        // this stop was refused and keep showing STOP?, not fall back to the
        // pre-stop agent state simply because `pending == 0`.
        let logged = self
            .append(WardEvent::WorkloadsTerminated {
                ended,
                pending,
                barrier_confirmed,
            })
            .err();
        if logged.is_none() {
            let _ = pause::clear_intent(&self.state, &self.session);
        }
        let detail = if barrier_confirmed {
            "the stop is incomplete and the session is held for it (proxy closed, \
             approvals held, no new launch admitted; `ward resume` cannot release it). \
             Run `ward stop` again to retry"
        } else {
            "the pre-termination fork barrier was not confirmed, so Ward cannot prove the \
             session is quiescent even though no known pid remains. The session is held \
             for the stop; `ward resume` cannot release it. Run `ward stop` again to retry"
        };
        Error::Daemon(pause::stop_refusal(
            &self.session,
            ended,
            pending,
            detail,
            marker.as_ref(),
            logged.as_ref(),
        ))
    }

    /// A stop whose processes are all confirmed gone but whose hold a component
    /// did not confirm (#145 item 3): the session is held for the stop over
    /// nothing — stop marker, pause marker naming the component, approvals
    /// held — `SessionPauseUnsettled` records the hold and what is uncertain
    /// about it, the `ended` count is carried into the retry's
    /// `WorkloadsTerminated` (none is appended now: the stop is not confirmed),
    /// and the refusal names the component. A hold whose record could not be
    /// written keeps the intent, so a restart records it.
    fn hold_for_unconfirmed_stop(
        &mut self,
        ack: &Acknowledgement,
        method: PauseMethod,
        since: Option<Instant>,
        ended: u32,
    ) -> Error {
        use std::fmt::Write as _;
        let reason = acks::unconfirmed_reason(pause::STOP_REASON, ack);
        let marker = pause::write_marker(&self.state, &self.session, &reason).err();
        let _ = pause::write_held_by(&self.state, &self.session, &pause::Holders::for_stop());
        self.paused = Some(Paused {
            frozen: Frozen {
                method,
                pids: Vec::new(),
                cgroup: None,
            },
            since: since.unwrap_or_else(Instant::now),
            holders: pause::Holders::for_stop(),
            ended,
        });
        self.held_unconfirmed = Some(ack.text());
        let logged = self
            .append(Self::hold_record(
                method,
                pause::STOP_REASON,
                None,
                Some(ack),
            ))
            .err();
        if logged.is_none() {
            let _ = pause::clear_intent(&self.state, &self.session);
        }
        let mut message = format!(
            "stop ended every sandboxed process of session {} ({ended}), but {} did not \
             confirm the hold, so the stop is not confirmed: the log is not sealed and the \
             session is held for the stop (proxy closed, approvals held, no new launch \
             admitted; `ward resume` cannot release it). Run `ward stop` again to retry",
            self.session,
            ack.text()
        );
        if let Some(e) = marker {
            let _ = write!(message, "; the pause marker could not be written ({e})");
        }
        if let Some(e) = logged {
            let _ = write!(message, "; the record of this could not be written ({e})");
        }
        Error::Daemon(message)
    }

    /// Reconcile the lifecycle a previous process of this session left behind
    /// (#145 item 7), before a single connection is served. Always uses the
    /// real freeze and termination; see [`Self::reconcile_lifecycle_with`].
    fn reconcile_lifecycle(&mut self) -> Result<bool> {
        self.reconcile_lifecycle_with(pause::freeze_confirmed, pause::terminate)
    }

    /// [`Self::reconcile_lifecycle`] with the freeze and the termination
    /// injectable, for the same reason [`Self::pause_with`]'s `settle` and
    /// [`Self::stop`]'s `terminate` are.
    ///
    /// First the log is read back: the agent state it last recorded, the
    /// launches it still has open, and whether it says the session is held
    /// (`SessionPaused`/`SessionPauseUnsettled`, or an incomplete
    /// `WorkloadsTerminated`, with no `SessionResumed` after). Then, in order
    /// of what is on disk:
    ///
    /// * A stop intent ([`pause::INTENT`]): the stop is finished exactly as a
    ///   client's retry would finish it — a hold the marker says is in force
    ///   is rebuilt first, from what `/proc` shows now, so the stop retries
    ///   over it — and the answer is whether that sealed the log. Returns an
    ///   error, and leaves the intent, when the stop reached neither of its
    ///   durable outcomes (sealed, or held with `WorkloadsTerminated`
    ///   recorded): a daemon that cannot finish the session's last operation
    ///   does not serve it as though it had.
    /// * A pause intent: the pause is finished — the trees frozen (again, for
    ///   anything already stopped), the marker written if it is not, the
    ///   approvals held, and exactly one terminal record appended unless the
    ///   log already carries it. It is recorded as unsettled whenever the
    ///   freeze cannot be confirmed: never a confirmed `SessionPaused` that
    ///   was not observed.
    /// * A capture intent (#145 item 6): the hold's taking was interrupted,
    ///   so that capture cannot complete; it is forgotten, and the hold is
    ///   released unless another owner remains.
    /// * No intent but a marker: a hold that completed before the previous
    ///   process died. Its owners are read back ([`pause::HELD_BY`]; a marker
    ///   with none recorded is the user's), a capture whose process is gone
    ///   is forgotten, and what remains is adopted the same way, so `resume`
    ///   and `stop` work on it; a hold the log already records gets no
    ///   second record. The stop marker makes it a stop's. A hold no owner
    ///   remains for is released ([`Self::release_orphaned_hold`]).
    fn reconcile_lifecycle_with(
        &mut self,
        freeze: impl FnOnce(&str) -> (Frozen, bool),
        terminate: impl FnOnce(&str, Option<Frozen>) -> pause::Termination,
    ) -> Result<bool> {
        let outcome = self.reconcile_entered(freeze, terminate);
        self.publish();
        outcome
    }

    /// [`Self::reconcile_lifecycle_with`]'s body; the lifecycle it leaves is
    /// published whatever it returns.
    fn reconcile_entered(
        &mut self,
        freeze: impl FnOnce(&str) -> (Frozen, bool),
        terminate: impl FnOnce(&str, Option<Frozen>) -> pause::Termination,
    ) -> Result<bool> {
        let tail = read_log_tail(&self.log_path)?;
        self.last_agent_state = tail.last_agent_state;
        // The launch register (#145 item 2): every handle this session ever
        // admitted. A launch the log still has open but the register says
        // the connection abandoned (`Unknown`) is not reopened as though it
        // were still confirmed running; everything else the log says is open
        // is open.
        self.read_launch_register(tail.open_launches)?;
        let marker = pause::marker_path(&self.state, &self.session);
        match pause::read_intent(&self.state, &self.session)? {
            Some(pause::Intent {
                verb: pause::Verb::Stop { reason },
                ..
            }) => self.finish_stop(reason, tail.unconfirmed.as_deref(), freeze, terminate),
            Some(pause::Intent {
                verb: pause::Verb::Pause { reason },
                started_unix_ms,
                ..
            }) => {
                let mut holders = self.recorded_holders()?;
                holders.user = true;
                self.adopt_hold(
                    &pause::reason_text(&reason),
                    instant_at(started_unix_ms),
                    tail.held,
                    tail.unconfirmed.as_deref(),
                    holders,
                    freeze,
                )?;
                pause::clear_intent(&self.state, &self.session)?;
                Ok(false)
            }
            // A resume died between its first release and its record (#145
            // item 1): finished as the resume would have finished — every
            // component confirmed released, the tree thawed, `SessionResumed`
            // appended if the log still says held. A release a component does
            // not confirm leaves the session held as the user's, for the next
            // `ward resume` to retry; nothing is left frozen with no marker.
            Some(pause::Intent {
                verb: pause::Verb::Resume,
                started_unix_ms,
                ..
            }) => {
                let since = if marker.exists() {
                    marker_facts(&marker).1
                } else {
                    instant_at(started_unix_ms)
                };
                self.finish_resume(since, tail.held, freeze)?;
                pause::clear_intent(&self.state, &self.session)?;
                Ok(false)
            }
            Some(pause::Intent {
                verb: pause::Verb::Capture { capturer, .. },
                started_unix_ms,
                ..
            }) => {
                let mut holders = self.recorded_holders()?;
                holders.remove_capture(&capturer.op);
                let (reason, since) = if marker.exists() {
                    marker_facts(&marker)
                } else {
                    (capturer.reason, instant_at(started_unix_ms))
                };
                if holders.is_empty() {
                    self.release_orphaned_hold(since, tail.held, freeze)?;
                } else {
                    self.adopt_hold(
                        &reason,
                        since,
                        tail.held,
                        tail.unconfirmed.as_deref(),
                        holders,
                        freeze,
                    )?;
                }
                pause::clear_intent(&self.state, &self.session)?;
                Ok(false)
            }
            None if marker.exists() => {
                let (reason, since) = marker_facts(&marker);
                let holders = self.recorded_holders()?;
                if holders.is_empty() {
                    self.release_orphaned_hold(since, tail.held, freeze)?;
                } else {
                    self.adopt_hold(
                        &reason,
                        since,
                        tail.held,
                        tail.unconfirmed.as_deref(),
                        holders,
                        freeze,
                    )?;
                }
                Ok(false)
            }
            None => Ok(false),
        }
    }

    /// Read the launch register back (#145 item 2) and merge it with the
    /// launches the log still has open (`open`): a launch the register says
    /// its connection abandoned (`Unknown`) is not reopened as though it were
    /// still confirmed running, and a launch the log opened under a daemon
    /// that predates the register is registered now.
    fn read_launch_register(&mut self, open: Vec<(u64, Pid)>) -> Result<()> {
        self.launches = launches::read(&self.state, &self.session)?;
        self.open_launches = open
            .into_iter()
            .filter(|(seq, _)| self.launches.state_of(*seq) != Some(LaunchState::Unknown))
            .map(|(seq, pid)| (Self::INTERNAL_CONN, seq, pid))
            .collect();
        for &(_, seq, pid) in &self.open_launches {
            if self.launches.state_of(seq).is_none() {
                self.launches
                    .admit(seq, pid, control::unix_ms(SystemTime::now()));
                let _ = launches::write(&self.state, &self.session, &self.launches);
            }
        }
        Ok(())
    }

    /// Finish a stop a previous process began (#145 item 7): a hold the marker
    /// says is in force is rebuilt first, from what `/proc` shows now, so the
    /// stop retries over it; then the stop runs exactly as a client's retry
    /// would. Returns whether that sealed the log, or an error — the intent
    /// left in place — when the stop reached neither of its durable outcomes.
    fn finish_stop(
        &mut self,
        reason: ward_events::EndReason,
        logged_uncertainty: Option<&str>,
        freeze: impl FnOnce(&str) -> (Frozen, bool),
        terminate: impl FnOnce(&str, Option<Frozen>) -> pause::Termination,
    ) -> Result<bool> {
        let marker = pause::marker_path(&self.state, &self.session);
        if marker.exists() {
            let (reason, since) = marker_facts(&marker);
            let mut holders = self.recorded_holders()?;
            holders.stop = true;
            self.adopt_hold(&reason, since, true, logged_uncertainty, holders, freeze)?;
        }
        let (response, sealed) = self.stop(Self::INTERNAL_CONN, reason, terminate);
        if pause::intent_path(&self.state, &self.session).exists() {
            let outcome = match response {
                Response::Error(e) => e,
                other => format!("unexpected response {other:?}"),
            };
            return Err(Error::Daemon(format!(
                "the stop of session {} that a previous process began could not be finished: \
                 {outcome}",
                self.session
            )));
        }
        Ok(sealed)
    }

    /// Who the previous process recorded as holding the session
    /// ([`pause::HELD_BY`]), less every capture whose process is gone; a
    /// marker with no owners recorded is the user's, and the stop marker
    /// makes any hold a stop's.
    fn recorded_holders(&self) -> Result<pause::Holders> {
        let mut holders = pause::read_held_by(&self.state, &self.session)?.unwrap_or_else(|| {
            if pause::marker_path(&self.state, &self.session).exists() {
                pause::Holders::for_user()
            } else {
                pause::Holders::default()
            }
        });
        holders.prune_dead(Path::new("/proc"));
        if pause::stop_begun(&self.state, &self.session) {
            holders.stop = true;
        }
        Ok(holders)
    }

    /// Put the session's sandboxes under this daemon's own hold, from what
    /// `/proc` shows now: `freeze` finds and freezes every process (one already
    /// stopped stays so) and says whether that confirmed stable. The marker is
    /// written with `reason` if it is not there, the owners (`holders`)
    /// written, the approvals are held, the components asked to confirm again
    /// (#145 item 3), and — unless `recorded` says the log already carries it
    /// and every component confirmed — exactly one terminal record is
    /// appended: `SessionPaused` when confirmed, `SessionPauseUnsettled`
    /// naming the pending count or the unconfirmed component otherwise.
    fn adopt_hold(
        &mut self,
        reason: &str,
        since: Instant,
        recorded: bool,
        logged_uncertainty: Option<&str>,
        holders: pause::Holders,
        freeze: impl FnOnce(&str) -> (Frozen, bool),
    ) -> Result<()> {
        let _lock = pause::lock_pause_freeze(&session_dir(&self.state, &self.session))?;
        let (frozen, stable) = freeze(&self.session);
        if !pause::marker_path(&self.state, &self.session).exists() {
            pause::write_marker(&self.state, &self.session, reason)?;
        }
        pause::write_held_by(&self.state, &self.session, &holders)?;
        self.approvals.set_paused(true);
        let unsettled = pause::unsettled_count(&frozen, stable);
        let acks = self.confirm_components(Phase::Held);
        let unconfirmed = acks::first_unconfirmed(&acks);
        if !recorded || unconfirmed.is_some() {
            self.append(Self::hold_record(
                frozen.method,
                reason,
                unsettled,
                unconfirmed,
            ))?;
        }
        // What this hold cannot confirm (#145 item 1): what the daemon found
        // now, or — when it found everything confirmed — what the log's own
        // last hold record still says is uncertain, so the lifecycle never
        // reads `paused` while the log reads unsettled.
        self.held_unconfirmed = Self::hold_uncertainty(unsettled, unconfirmed)
            .or_else(|| logged_uncertainty.map(str::to_owned));
        self.paused = Some(Paused {
            frozen,
            since,
            holders,
            ended: 0,
        });
        Ok(())
    }

    /// Finish a resume a previous process began (#145 item 1): what `/proc`
    /// shows of the session is taken as the user's hold — approvals held, the
    /// marker rewritten if it is gone — and released through the same
    /// confirmed release a resume performs ([`Self::release_hold`]),
    /// appending `SessionResumed` only when the log still says held. A
    /// release a component does not confirm leaves the session held as the
    /// user's, which the next `ward resume` retries.
    fn finish_resume(
        &mut self,
        since: Instant,
        recorded: bool,
        freeze: impl FnOnce(&str) -> (Frozen, bool),
    ) -> Result<()> {
        let _lock = pause::lock_pause_freeze(&session_dir(&self.state, &self.session))?;
        let (frozen, _) = freeze(&self.session);
        let paused = Paused {
            frozen,
            since,
            holders: pause::Holders::for_user(),
            ended: 0,
        };
        self.held_unconfirmed = None;
        if !recorded {
            // The log already says resumed: only the tree (and whatever the
            // dying resume left) is to be let go.
            self.approvals.set_paused(false);
            let _ = pause::clear_marker(&self.state, &self.session);
            let _ = pause::clear_held_by(&self.state, &self.session);
            pause::thaw(&paused.frozen);
            return Ok(());
        }
        if !pause::marker_path(&self.state, &self.session).exists() {
            pause::write_marker(&self.state, &self.session, pause::DEFAULT_REASON)?;
        }
        pause::write_held_by(&self.state, &self.session, &paused.holders)?;
        self.approvals.set_paused(true);
        match self.release_hold(paused) {
            Ok(_) | Err(Error::Daemon(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Release a hold no owner remains for (#145 item 6): a capture's whose
    /// process is gone, so the capture cannot complete and nothing else could
    /// ever release it. What `/proc` shows frozen is thawed through the same
    /// confirmed release a resume performs ([`Self::release_hold`]), and
    /// `SessionResumed` is appended when the log says the session is held. A
    /// release a component does not confirm leaves the hold standing with no
    /// owner, which the next `ward resume` releases the same way.
    fn release_orphaned_hold(
        &mut self,
        since: Instant,
        recorded: bool,
        freeze: impl FnOnce(&str) -> (Frozen, bool),
    ) -> Result<()> {
        let _lock = pause::lock_pause_freeze(&session_dir(&self.state, &self.session))?;
        let (frozen, _) = freeze(&self.session);
        let paused = Paused {
            frozen,
            since,
            holders: pause::Holders::default(),
            ended: 0,
        };
        self.held_unconfirmed = None;
        if !recorded {
            self.approvals.set_paused(false);
            let _ = pause::clear_marker(&self.state, &self.session);
            let _ = pause::clear_held_by(&self.state, &self.session);
            pause::thaw(&paused.frozen);
            return Ok(());
        }
        self.approvals.set_paused(true);
        match self.release_hold(paused) {
            Ok(_) | Err(Error::Daemon(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Start a subscription from `from_seq`: everything in the log so far, and a
    /// channel for what comes next. Called under the mutex so no append falls
    /// between the two. What [`stream_subscription`] does in two steps, for
    /// the daemon's own tests.
    #[cfg(test)]
    fn subscribe(&mut self, from_seq: u64) -> Result<Subscription> {
        let (boundary, live) = self.begin_subscription();
        let replay = read_replay(&self.log_path, from_seq, boundary)?;
        Ok(Subscription { replay, live })
    }

    /// Fix a subscription's boundary (#145 item 8): the sequence the next
    /// record appended will get, and the live channel registered in the same
    /// step, so every record before the boundary is in the log already and
    /// every record from it on arrives through the channel — no gap, no
    /// duplicate. Only this runs under the daemon's mutex; the replay itself
    /// ([`read_replay`], as long as the log is) is read outside it, so a
    /// subscriber replaying a long log never delays a pause or a stop waiting
    /// on the mutex behind it. A sealed log has no live half: the boundary is
    /// then the whole log.
    fn begin_subscription(&mut self) -> (u64, Option<LiveChannel>) {
        match self.log.as_ref() {
            Some(log) => {
                let boundary = log.next_seq();
                let (tx, rx) = channel();
                let watcher = tx.clone();
                self.subscribers.push(tx);
                (boundary, Some((rx, watcher)))
            }
            None => (u64::MAX, None),
        }
    }
}

/// The records of `log_path` with `from_seq <= seq < boundary`
/// ([`Served::begin_subscription`]). Every record below the boundary was
/// written whole before the boundary was fixed (the log writer writes each
/// frame through to the file under the mutex), so a read after the mutex is
/// released sees all of them; a frame still being written belongs to a record
/// at or past the boundary, which the live channel delivers.
fn read_replay(log_path: &Path, from_seq: u64, boundary: u64) -> Result<Vec<EventRecord>> {
    Ok(LogReader::open(log_path)
        .map_err(|e| Error::Events(e.to_string()))?
        .map_while(std::result::Result::ok)
        .filter(|r| r.seq >= from_seq && r.seq < boundary)
        .collect())
}

/// What a daemon restarted on a session reads back from its log before it
/// serves ([`Served::reconcile_lifecycle_with`]).
struct LogTail {
    /// The log says the session is held: its last hold record is a
    /// `SessionPaused`/`SessionPauseUnsettled` or an incomplete
    /// `WorkloadsTerminated`, with no `SessionResumed` or confirmed
    /// `WorkloadsTerminated` after it.
    held: bool,
    /// The last `AgentStateChanged`.
    last_agent_state: Option<ward_events::AgentState>,
    /// Every `CommandStarted` (its seq and pid) without a `CommandFinished` or
    /// `LaunchAborted` for the same pid after it.
    open_launches: Vec<(u64, Pid)>,
    /// What the log's last hold record could not confirm
    /// ([`acks::unsettled_detail`]), while `held`.
    unconfirmed: Option<String>,
}

fn read_log_tail(log_path: &Path) -> Result<LogTail> {
    let mut tail = LogTail {
        held: false,
        last_agent_state: None,
        open_launches: Vec::new(),
        unconfirmed: None,
    };
    for record in LogReader::open(log_path)
        .map_err(|e| Error::Events(e.to_string()))?
        .map_while(std::result::Result::ok)
    {
        match record.event {
            WardEvent::AgentStateChanged { state } => tail.last_agent_state = Some(state),
            WardEvent::SessionPaused { .. } => {
                tail.held = true;
                tail.unconfirmed = None;
            }
            WardEvent::SessionPauseUnsettled {
                ref reason,
                pending,
                ..
            } => {
                tail.held = true;
                tail.unconfirmed = Some(acks::unsettled_detail(reason.as_str(), pending));
            }
            WardEvent::SessionResumed { .. } => {
                tail.held = false;
                tail.unconfirmed = None;
            }
            WardEvent::WorkloadsTerminated {
                pending,
                barrier_confirmed,
                ..
            } => {
                tail.held = pending > 0 || !barrier_confirmed;
                tail.unconfirmed = if pending > 0 {
                    Some(format!("{pending} process(es) not confirmed ended"))
                } else if !barrier_confirmed {
                    Some("membership barrier unconfirmed".to_owned())
                } else {
                    None
                };
            }
            WardEvent::CommandStarted { pid, .. } => tail.open_launches.push((record.seq, pid)),
            WardEvent::CommandFinished { pid, .. } | WardEvent::LaunchAborted { pid, .. } => {
                if let Some(pos) = tail.open_launches.iter().rposition(|(_, p)| *p == pid) {
                    tail.open_launches.remove(pos);
                }
            }
            _ => {}
        }
    }
    Ok(tail)
}

/// What an on-disk pause marker says: its text as the hold's reason (the
/// default when it is empty or unreadable), and when it was written.
fn marker_facts(marker: &Path) -> (String, Instant) {
    let reason = std::fs::read_to_string(marker).map_or_else(
        |_| pause::DEFAULT_REASON.to_owned(),
        |text| pause::reason_text(&text),
    );
    let since = std::fs::metadata(marker)
        .and_then(|m| m.modified())
        .map_or_else(|_| Instant::now(), |at| instant_at(control::unix_ms(at)));
    (reason, since)
}

/// The monotonic instant `unix_ms` ago from now, or now when that is not
/// representable.
fn instant_at(unix_ms: u64) -> Instant {
    let elapsed = control::unix_ms(SystemTime::now()).saturating_sub(unix_ms);
    Instant::now()
        .checked_sub(Duration::from_millis(elapsed))
        .unwrap_or_else(Instant::now)
}

fn lock<T>(shared: &Mutex<T>) -> MutexGuard<'_, T> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
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
fn serve_stream(
    stream: UnixStream,
    served: &Arc<Mutex<Served>>,
    lifecycle: &Arc<Mutex<LifecycleReport>>,
    conn: u64,
) -> bool {
    let Ok(mut writer) = stream.try_clone() else {
        return false;
    };
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    // #145 item 8: whether this connection asked for per-component progress.
    let mut progress = false;
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
            // The status lane (#145 item 1): answered from what the daemon
            // last published, never behind its mutex, so a pause waiting on a
            // component's acknowledgement answers `pausing` meanwhile.
            Ok(Request::Lifecycle) => (Response::Lifecycle(lock(lifecycle).clone()), false),
            Ok(Request::ReportProgress) => {
                progress = true;
                (Response::Ok, false)
            }
            Ok(
                request @ (Request::Pause { .. }
                | Request::Resume
                | Request::Stop { .. }
                | Request::HoldForStop { .. }),
            ) if progress => {
                let Ok(mut reporter) = writer.try_clone() else {
                    return false;
                };
                let mut s = lock(served);
                s.progress = Some(Box::new(move |p: &Progress| {
                    let _ = write_line(&mut reporter, &Response::Progress(p.clone()));
                }));
                let answered = s.handle_conn(conn, request);
                s.progress = None;
                answered
            }
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
    writer: UnixStream,
    served: &Arc<Mutex<Served>>,
    from_seq: u64,
) {
    stream_subscription_with(reader, writer, served, from_seq, read_replay);
}

/// [`stream_subscription`] with the replay read injectable: the seam a test
/// uses to hold a replay mid-read and prove a pause is not waiting behind it
/// (#145 item 8). The boundary and the live channel are fixed under the
/// mutex ([`Served::begin_subscription`]); the replay is read with it
/// released.
fn stream_subscription_with(
    reader: BufReader<UnixStream>,
    mut writer: UnixStream,
    served: &Arc<Mutex<Served>>,
    from_seq: u64,
    read_replay: impl FnOnce(&Path, u64, u64) -> Result<Vec<EventRecord>>,
) {
    let (log_path, boundary, live) = {
        let mut s = lock(served);
        let (boundary, live) = s.begin_subscription();
        (s.log_path.clone(), boundary, live)
    };
    let subscription = match read_replay(&log_path, from_seq, boundary) {
        Ok(replay) => Subscription { replay, live },
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
            WardEvent::WorkloadsTerminated {
                ended: e,
                pending: 0,
                barrier_confirmed: true
            } if e == ended
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
            ended: 0,
            frozen: held.clone(),
            since: Instant::now(),
            holders: pause::Holders::for_user(),
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
                    method: ward_events::PauseMethod::Sigstop,
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
            assert_eq!(
                paused.holders.owners(),
                [pause::Owner::Stop],
                "an incomplete stop, not a pause"
            );
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
                    pending: 1,
                    barrier_confirmed: true
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

    /// A failed membership/fork barrier is an incomplete stop even when every
    /// currently-known PID is already gone. The uncertainty itself is durable:
    /// replay sees `barrier_confirmed: false`, the session stays held and
    /// unsealed, and a later confirmed retry writes the clearing
    /// `WorkloadsTerminated` record before sealing.
    #[test]
    fn an_unconfirmed_stop_barrier_with_zero_known_pids_is_durable_until_retry() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let empty_hold = Frozen {
            method: ward_events::PauseMethod::Sigstop,
            pids: Vec::new(),
            cgroup: None,
        };
        let (response, done) =
            served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, held| {
                assert!(held.is_none());
                pause::Termination {
                    ended: 2,
                    remaining: Some(empty_hold.clone()),
                    barrier_confirmed: false,
                    method: ward_events::PauseMethod::Sigstop,
                }
            });
        let Response::Error(message) = response else {
            panic!("{response:?}");
        };
        assert!(!done);
        assert!(
            message.contains("fork barrier was not confirmed"),
            "{message}"
        );
        assert!(served.log.is_some());
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::Stop])
        );
        assert!(pause::marker_path(dir.path(), "sess_9").exists());

        let replay = served.subscribe(0).unwrap().replay;
        let incomplete = replay.last().expect("incomplete stop record");
        assert!(matches!(
            incomplete.event,
            WardEvent::WorkloadsTerminated {
                ended: 2,
                pending: 0,
                barrier_confirmed: false
            }
        ));

        let (response, done) =
            served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, held| {
                assert_eq!(held, Some(empty_hold));
                pause::Termination::confirmed(0)
            });
        assert!(matches!(response, Response::Sealed { ended: Some(0), .. }));
        assert!(done);
        let records: Vec<_> = LogReader::open(&served.log_path)
            .unwrap()
            .map_while(std::result::Result::ok)
            .collect();
        let terminated: Vec<_> = records
            .iter()
            .filter_map(|r| match r.event {
                WardEvent::WorkloadsTerminated {
                    ended,
                    pending,
                    barrier_confirmed,
                } => Some((ended, pending, barrier_confirmed)),
                _ => None,
            })
            .collect();
        assert_eq!(terminated, [(2, 0, false), (0, 0, true)]);
        assert!(matches!(
            records.last().map(|r| &r.event),
            Some(WardEvent::SessionEnded { .. })
        ));
    }

    /// `served`'s session as a daemon restarted on the same session directory
    /// sees it: the log resumed from disk, nothing held in memory.
    fn restarted_served(dir: &Path, session: &str) -> Served {
        let log_path = dir.join("events.log");
        let log = LocalLog::open(&log_path, SystemTime::now()).unwrap();
        let deriver = Deriver::new(
            ward_policy::default_manifest(),
            Some("hexrift/WardOS".into()),
            vec!["tests/security_expiry.rs".into()],
        );
        Served::new(
            log,
            log_path,
            serde_json::json!({ "session": session }),
            deriver,
            dir.to_path_buf(),
            session.to_owned(),
        )
    }

    /// A session whose previous process recorded the agent `Working` and then
    /// died: the log a restart resumes from.
    fn started_log(dir: &Path) {
        let mut served = fresh_served(dir);
        assert!(matches!(served.handle(append(0)).0, Response::Record(_)));
    }

    fn no_sandbox(_: &str) -> (Frozen, bool) {
        (
            Frozen {
                method: ward_events::PauseMethod::Sigstop,
                pids: Vec::new(),
                cgroup: None,
            },
            true,
        )
    }

    fn never_freezes(_: &str) -> (Frozen, bool) {
        panic!("a stop reconciliation freezes nothing itself")
    }

    fn never_terminates(_: &str, _: Option<Frozen>) -> pause::Termination {
        panic!("a pause reconciliation terminates nothing")
    }

    fn stuck(pid: u32) -> Frozen {
        Frozen {
            method: ward_events::PauseMethod::Sigstop,
            pids: vec![pid],
            cgroup: None,
        }
    }

    fn pause_intent(reason: &str) -> pause::Intent {
        pause::Intent::begin(pause::Verb::Pause {
            reason: reason.to_owned(),
        })
        .unwrap()
    }

    fn stop_intent() -> pause::Intent {
        pause::Intent::begin(pause::Verb::Stop {
            reason: EndReason::UserStop,
        })
        .unwrap()
    }

    /// #145 item 7: a pause's intent is durable before any process is
    /// signalled — the settle check, which runs after the freeze, finds it on
    /// disk naming the operation — and gone once the pause's record is.
    #[test]
    fn a_pause_records_its_intent_before_the_freeze_and_clears_it_with_its_record() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let outcome = served
            .pause_with("ops asked", |_| {
                let intent = pause::read_intent(dir.path(), "sess_9")
                    .unwrap()
                    .expect("the intent is on disk before the freeze is judged");
                assert_eq!(
                    intent.verb,
                    pause::Verb::Pause {
                        reason: "ops asked".into()
                    }
                );
                assert_eq!(intent.op.len(), 32, "{intent:?}");
                assert!(intent.started_unix_ms > 0);
                None
            })
            .unwrap();
        assert!(matches!(
            outcome.record.event,
            WardEvent::SessionPaused { .. }
        ));
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Record(_)
        ));
    }

    /// A stop's intent is durable before termination begins and gone once the
    /// log is sealed.
    #[test]
    fn a_stop_records_its_intent_before_terminating_and_clears_it_at_the_seal() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let (response, done) = served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, _| {
            let intent = pause::read_intent(dir.path(), "sess_9")
                .unwrap()
                .expect("the intent is on disk before anything is killed");
            assert_eq!(
                intent.verb,
                pause::Verb::Stop {
                    reason: EndReason::UserStop
                }
            );
            pause::Termination::confirmed(2)
        });
        assert!(matches!(response, Response::Sealed { ended: Some(2), .. }));
        assert!(done);
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
    }

    /// A refused stop has reached its durable outcome (`WorkloadsTerminated {
    /// pending }`, the hold): its intent is cleared, so a restart adopts the
    /// hold instead of terminating again on its own.
    #[test]
    fn a_refused_stop_clears_its_intent_once_the_hold_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let (response, done) = served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, _| {
            assert!(pause::intent_path(dir.path(), "sess_9").exists());
            pause::Termination {
                ended: 1,
                remaining: Some(stuck(77)),
                barrier_confirmed: true,
                method: ward_events::PauseMethod::Sigstop,
            }
        });
        assert!(matches!(response, Response::Error(_)), "{response:?}");
        assert!(!done);
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::Stop])
        );
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
    }

    /// Restart during a pause, before the freeze was sent: the intent alone is
    /// on disk. The restarted daemon finishes the pause — freezes, writes the
    /// marker with the intended reason, holds the approvals, records exactly
    /// one `SessionPaused` — and the retry and the resume behave as after an
    /// uninterrupted pause.
    #[test]
    fn a_restart_during_a_pause_before_the_freeze_finishes_the_pause() {
        let dir = tempfile::tempdir().unwrap();
        started_log(dir.path());
        pause::write_intent(dir.path(), "sess_9", &pause_intent("ops asked")).unwrap();

        let mut served = restarted_served(dir.path(), "sess_9");
        let sealed = served
            .reconcile_lifecycle_with(no_sandbox, never_terminates)
            .unwrap();
        assert!(!sealed);
        assert_eq!(
            std::fs::read_to_string(pause::marker_path(dir.path(), "sess_9")).unwrap(),
            "ops asked\n"
        );
        assert!(served.approvals.paused());
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::User])
        );
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
        let replay = served.subscribe(0).unwrap().replay;
        assert!(matches!(
            &replay.last().unwrap().event,
            WardEvent::SessionPaused { reason, .. } if reason.as_str() == "ops asked"
        ));
        assert_eq!(
            kinds_of(&mut served),
            ["AgentStateChanged", "SessionPaused"]
        );
        assert!(matches!(
            served.handle(Request::Pause { reason: String::new() }).0,
            Response::Error(e) if e == "already paused"
        ));
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Record(_)
        ));
        assert!(!pause::marker_path(dir.path(), "sess_9").exists());
        assert_eq!(
            kinds_of(&mut served),
            ["AgentStateChanged", "SessionPaused", "SessionResumed"]
        );
    }

    /// Restart during a pause after the freeze was sent (the marker is already
    /// there) and with a process the restarted daemon cannot confirm stopped:
    /// the pause is recorded as unsettled, naming what is pending — never as a
    /// confirmed `SessionPaused` — and exactly once.
    #[test]
    fn a_restart_during_a_pause_after_the_freeze_records_what_it_cannot_confirm() {
        let dir = tempfile::tempdir().unwrap();
        started_log(dir.path());
        pause::write_intent(dir.path(), "sess_9", &pause_intent("")).unwrap();
        pause::write_marker(dir.path(), "sess_9", pause::DEFAULT_REASON).unwrap();

        let mut served = restarted_served(dir.path(), "sess_9");
        let sealed = served
            .reconcile_lifecycle_with(|_| (stuck(77), false), never_terminates)
            .unwrap();
        assert!(!sealed);
        assert_eq!(
            kinds_of(&mut served),
            ["AgentStateChanged", "SessionPauseUnsettled"]
        );
        let replay = served.subscribe(0).unwrap().replay;
        assert!(matches!(
            &replay[1].event,
            WardEvent::SessionPauseUnsettled { pending: 1, reason, .. }
                if reason.as_str() == pause::DEFAULT_REASON
        ));
        let paused = served.paused.as_ref().unwrap();
        assert_eq!(paused.frozen, stuck(77), "held over what was found");
        assert_eq!(paused.holders.owners(), [pause::Owner::User]);
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
    }

    /// Restart during a stop before the kill (and before the stop marker): the
    /// restarted daemon finishes the stop — terminates, records the real
    /// counts, terminalizes the launch the log still had open, records
    /// `Finished`, `SessionEnded`, seals — and leaves no intent behind.
    #[test]
    fn a_restart_during_a_stop_before_the_kill_finishes_the_stop() {
        use ward_events::{BoundedArgv, Pid, SandboxPath, SandboxRoot};
        let dir = tempfile::tempdir().unwrap();
        {
            let mut served = fresh_served(dir.path());
            assert!(matches!(served.handle(append(0)).0, Response::Record(_)));
            served
                .append(WardEvent::CommandStarted {
                    pid: Pid::new(2).unwrap(),
                    parent: Pid::new(1).unwrap(),
                    argv: BoundedArgv::from_bytes([b"agent".as_slice()]),
                    cwd: SandboxPath::new(SandboxRoot::Work, ".").unwrap(),
                    exe_digest: None,
                })
                .unwrap();
        }
        pause::write_intent(dir.path(), "sess_9", &stop_intent()).unwrap();

        let mut served = restarted_served(dir.path(), "sess_9");
        let sealed = served
            .reconcile_lifecycle_with(never_freezes, |_, held| {
                assert_eq!(held, None);
                pause::Termination::confirmed(2)
            })
            .unwrap();
        assert!(sealed);
        assert!(served.log.is_none());
        assert!(pause::stop_begun(dir.path(), "sess_9"));
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
        let records: Vec<_> = LogReader::open(&served.log_path)
            .unwrap()
            .map_while(std::result::Result::ok)
            .collect();
        let kinds: Vec<String> = records
            .iter()
            .map(|r| format!("{:?}", r.event.kind()))
            .collect();
        assert_eq!(
            kinds,
            [
                "AgentStateChanged",
                "CommandStarted",
                "WorkloadsTerminated",
                "LaunchAborted",
                "AgentStateChanged",
                "SessionEnded"
            ]
        );
        assert!(matches!(
            records[2].event,
            WardEvent::WorkloadsTerminated {
                ended: 2,
                pending: 0,
                barrier_confirmed: true
            }
        ));
        assert!(matches!(
            records[4].event,
            WardEvent::AgentStateChanged {
                state: AgentState::Finished
            }
        ));
        assert!(matches!(
            records[5].event,
            WardEvent::SessionEnded {
                reason: EndReason::UserStop,
                ..
            }
        ));
    }

    /// Restart after the stop's `WorkloadsTerminated` and `Finished` landed but
    /// before the seal: nothing is terminated or recorded twice; only the
    /// `SessionEnded` and the seal are still owed.
    #[test]
    fn a_restart_after_the_termination_record_but_before_the_seal_only_seals() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut served = fresh_served(dir.path());
            assert!(matches!(served.handle(append(0)).0, Response::Record(_)));
            served
                .append(WardEvent::WorkloadsTerminated {
                    ended: 2,
                    pending: 0,
                    barrier_confirmed: true,
                })
                .unwrap();
            served
                .append(WardEvent::AgentStateChanged {
                    state: AgentState::Finished,
                })
                .unwrap();
        }
        pause::write_stop_marker(dir.path(), "sess_9").unwrap();
        pause::write_intent(dir.path(), "sess_9", &stop_intent()).unwrap();

        let mut served = restarted_served(dir.path(), "sess_9");
        let sealed = served
            .reconcile_lifecycle_with(never_freezes, |_, held| {
                assert_eq!(held, None);
                pause::Termination::nothing()
            })
            .unwrap();
        assert!(sealed);
        let kinds: Vec<String> = LogReader::open(&served.log_path)
            .unwrap()
            .map_while(std::result::Result::ok)
            .map(|r| format!("{:?}", r.event.kind()))
            .collect();
        assert_eq!(
            kinds,
            [
                "AgentStateChanged",
                "WorkloadsTerminated",
                "AgentStateChanged",
                "SessionEnded"
            ]
        );
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
    }

    /// Reconciliation that cannot finish the stop leaves the session held for
    /// it, exactly as a refused stop does: the uncertainty is recorded, the log
    /// stays open, `resume` is refused, and the client's retry — which observes
    /// the reconciled state rather than acting from scratch — finishes it.
    #[test]
    fn a_restart_whose_stop_cannot_confirm_termination_holds_the_session_until_a_retry() {
        let dir = tempfile::tempdir().unwrap();
        started_log(dir.path());
        pause::write_intent(dir.path(), "sess_9", &stop_intent()).unwrap();

        let mut served = restarted_served(dir.path(), "sess_9");
        let sealed = served
            .reconcile_lifecycle_with(never_freezes, |_, _| pause::Termination {
                ended: 1,
                remaining: Some(stuck(77)),
                barrier_confirmed: true,
                method: ward_events::PauseMethod::Sigstop,
            })
            .unwrap();
        assert!(!sealed);
        assert!(served.log.is_some());
        let paused = served.paused.as_ref().unwrap();
        assert_eq!(paused.holders.owners(), [pause::Owner::Stop]);
        assert_eq!(paused.frozen, stuck(77));
        assert!(served.approvals.paused());
        assert!(
            std::fs::read_to_string(pause::marker_path(dir.path(), "sess_9"))
                .unwrap()
                .starts_with("ward stop: 1 process(es) not confirmed ended")
        );
        assert_eq!(
            kinds_of(&mut served),
            ["AgentStateChanged", "WorkloadsTerminated"]
        );
        assert!(matches!(
            served.subscribe(0).unwrap().replay[1].event,
            WardEvent::WorkloadsTerminated {
                ended: 1,
                pending: 1,
                barrier_confirmed: true
            }
        ));
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Error(e) if e.contains("has begun and not completed")
        ));

        let (response, done) =
            served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, held| {
                assert_eq!(held, Some(stuck(77)));
                pause::Termination::confirmed(1)
            });
        assert!(matches!(response, Response::Sealed { ended: Some(1), .. }));
        assert!(done);
        let kinds: Vec<String> = LogReader::open(&served.log_path)
            .unwrap()
            .map_while(std::result::Result::ok)
            .map(|r| format!("{:?}", r.event.kind()))
            .collect();
        assert_eq!(
            kinds,
            [
                "AgentStateChanged",
                "WorkloadsTerminated",
                "WorkloadsTerminated",
                "AgentStateChanged",
                "SessionEnded"
            ]
        );
    }

    /// Restart after a completed pause: the log already says paused, the
    /// marker stands, no intent is left. The restarted daemon takes the hold
    /// over from what it observes, records nothing new, and `resume` works —
    /// where before it answered "not paused" and nothing ever thawed the tree.
    #[test]
    fn a_restart_after_a_completed_pause_adopts_the_hold_without_a_second_record() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut served = fresh_served(dir.path());
            assert!(matches!(served.handle(append(0)).0, Response::Record(_)));
            served.pause_with("ops asked", |_| None).unwrap();
        }
        assert!(pause::marker_path(dir.path(), "sess_9").exists());

        let mut served = restarted_served(dir.path(), "sess_9");
        let sealed = served
            .reconcile_lifecycle_with(no_sandbox, never_terminates)
            .unwrap();
        assert!(!sealed);
        assert_eq!(
            kinds_of(&mut served),
            ["AgentStateChanged", "SessionPaused"]
        );
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::User])
        );
        assert!(served.approvals.paused());
        assert_eq!(served.last_agent_state, Some(AgentState::Working));
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Record(_)
        ));
        assert!(!pause::marker_path(dir.path(), "sess_9").exists());
        assert!(!served.approvals.paused());
    }

    /// Restart after a refused stop: the hold is adopted as a hold for the stop
    /// (the stop marker says one began), nothing is recorded again, `resume`
    /// stays refused and `stop` retries over what is held.
    #[test]
    fn a_restart_after_a_refused_stop_adopts_the_hold_for_the_stop() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut served = fresh_served(dir.path());
            let (response, _) = served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, _| {
                pause::Termination {
                    ended: 1,
                    remaining: Some(stuck(77)),
                    barrier_confirmed: true,
                    method: ward_events::PauseMethod::Sigstop,
                }
            });
            assert!(matches!(response, Response::Error(_)));
        }

        let mut served = restarted_served(dir.path(), "sess_9");
        let sealed = served
            .reconcile_lifecycle_with(|_| (stuck(77), false), never_terminates)
            .unwrap();
        assert!(!sealed);
        assert_eq!(kinds_of(&mut served), ["WorkloadsTerminated"]);
        let paused = served.paused.as_ref().unwrap();
        assert_eq!(paused.holders.owners(), [pause::Owner::Stop]);
        assert_eq!(paused.frozen, stuck(77));
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Error(e) if e.contains("has begun and not completed")
        ));
        let (response, done) =
            served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, held| {
                assert_eq!(held, Some(stuck(77)));
                pause::Termination::confirmed(1)
            });
        assert!(matches!(response, Response::Sealed { ended: Some(1), .. }));
        assert!(done);
    }

    /// A session with nothing begun and nothing held reconciles to nothing:
    /// no record, no hold, no marker.
    #[test]
    fn a_restart_with_nothing_in_flight_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut served = fresh_served(dir.path());
            assert!(matches!(served.handle(append(0)).0, Response::Record(_)));
        }
        let mut served = restarted_served(dir.path(), "sess_9");
        assert!(
            !served
                .reconcile_lifecycle_with(never_freezes, never_terminates)
                .unwrap()
        );
        assert!(served.paused.is_none());
        assert!(!served.approvals.paused());
        assert_eq!(kinds_of(&mut served), ["AgentStateChanged"]);
        assert_eq!(served.last_agent_state, Some(AgentState::Working));
    }

    /// An intent the daemon cannot read names an operation it cannot finish:
    /// it refuses to serve rather than serve a session in an unknown state.
    #[test]
    fn an_unreadable_intent_refuses_to_serve() {
        let dir = tempfile::tempdir().unwrap();
        started_log(dir.path());
        std::fs::write(pause::intent_path(dir.path(), "sess_9"), b"{not json").unwrap();
        let mut served = restarted_served(dir.path(), "sess_9");
        let err = served
            .reconcile_lifecycle_with(never_freezes, never_terminates)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unreadable lifecycle intent"), "{err}");
        assert!(served.paused.is_none());
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
                    method: ward_events::PauseMethod::Sigstop,
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
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::Stop])
        );
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

    /// Stop fails closed before changing state when the lifecycle/admission
    /// lock itself cannot be acquired. A directory at the lock-file path makes
    /// `OpenOptions::open` fail deterministically; the injected terminator must
    /// never run and no stop marker may be published.
    #[test]
    fn stop_refuses_before_termination_when_the_lifecycle_lock_cannot_be_acquired() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let lock_path = session_dir(dir.path(), "sess_9").join(".pause-freeze.lock");
        std::fs::create_dir(&lock_path).unwrap();

        let (response, done) = served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, _| {
            panic!("termination must not run without the lifecycle lock")
        });
        let Response::Error(message) = response else {
            panic!("{response:?}");
        };
        assert!(!done);
        assert!(message.contains("lifecycle lock"), "{message}");
        assert!(served.log.is_some(), "the log remains open");
        assert!(!pause::stop_marker_path(dir.path(), "sess_9").exists());
        assert!(kinds_of(&mut served).is_empty(), "nothing was recorded");
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
        assert_eq!(paused.holders.owners(), [pause::Owner::Stop]);
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
    /// pause over (no second record) and makes it unreleasable: the stop joins
    /// the owners, and a stop's hold is not `ward resume`'s to release.
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
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::User, pause::Owner::Stop])
        );
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
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::Stop])
        );
        assert_eq!(kinds_of(&mut served), ["SessionPauseUnsettled"]);
        // Never signal this test process: forget the injected freeze.
        served.paused = None;
    }

    /// Barrier uncertainty is not normalized away merely because the immediate
    /// recount has zero known PIDs. HoldForStop must report `Some(0)`, record an
    /// unsettled hold, and therefore make the restore client refuse to write the
    /// worktree until a later retry confirms the barrier.
    #[test]
    fn an_unconfirmed_stop_hold_with_zero_known_pids_is_still_unsettled() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let unsettled = served
            .hold_for_stop_with(
                "ward stop --restore-entry",
                |_| {
                    (
                        Frozen {
                            method: ward_events::PauseMethod::Sigstop,
                            pids: Vec::new(),
                            cgroup: None,
                        },
                        false,
                    )
                },
                |_, f| (f, true),
            )
            .unwrap();
        assert_eq!(unsettled, Some(0));
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::Stop])
        );
        let replay = served.subscribe(0).unwrap().replay;
        assert!(matches!(
            replay.last().map(|r| &r.event),
            Some(WardEvent::SessionPauseUnsettled { pending: 0, .. })
        ));
        // The injected empty freeze is safe to forget; the stop marker/record
        // are what this test is proving.
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
            Response::Paused {
                record, unsettled, ..
            } => (*record, unsettled),
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

    /// PR #318 review, finding 3: `Credential::granted_at_unix_ms` (and so
    /// its `expires_at_unix_ms`) must come from the same instant this
    /// append's own `EventRecord.ts_wall` is persisted with — the exact
    /// value `ward-shell-core::authority`'s panel projection reads back —
    /// not from a second, independent `SystemTime::now()` read in
    /// `Served::handle_appendable`. A delayed append (a client-supplied
    /// `at_unix_ms` far in the past — a slow send, a busy socket) must not
    /// be able to pull those two apart: both must still land at the
    /// daemon's own real append-time clock, not the stale client capture
    /// time.
    #[test]
    fn a_delayed_appends_stale_capture_time_does_not_skew_the_grants_own_deadline() {
        use ward_events::{CredentialDelivery, NameText, Scope, ServiceId};

        let dir = tempfile::tempdir().unwrap();
        let served = Arc::new(Mutex::new(fresh_served(dir.path())));
        let granted = WardEvent::CredentialGranted {
            service: ServiceId::new("github").unwrap(),
            scope: Scope {
                subject: ShortText::new("github.com:443"),
                permissions: vec![NameText::new("contents:read")],
            },
            expires: Duration::from_secs(60),
            delivery: CredentialDelivery::ProxyInjected,
        };
        let before = control::unix_ms(SystemTime::now());
        // A capture time from decades before this append actually reaches
        // the daemon: exactly the "delayed append" the review's finding 3
        // describes, deliberately exaggerated so a bug that leaks this
        // stale value into either clock read is unmistakable.
        let (response, _) = lock(&served).handle(Request::Append {
            origin: Origin::Wardd,
            event: granted,
            at_unix_ms: 0,
        });
        let after = control::unix_ms(SystemTime::now());
        let record = match response {
            Response::Granted { record, .. } => record,
            other => panic!("{other:?}"),
        };

        // The persisted record's own wall clock is the daemon's real
        // append-time instant, not the stale client-supplied capture time.
        let ts_wall_ms = record
            .ts_wall
            .map(control::unix_ms)
            .expect("ts_wall is now always populated on append");
        assert!(
            (before..=after).contains(&ts_wall_ms),
            "ts_wall {ts_wall_ms} must fall within [{before}, {after}], not near 0"
        );

        // The daemon's own in-memory grant shares that exact same instant —
        // read back from the record, not a second independent clock call.
        let grants = match lock(&served).handle(Request::Grants).0 {
            Response::Grants(g) => g,
            other => panic!("{other:?}"),
        };
        assert_eq!(grants.len(), 1, "{grants:?}");
        assert_eq!(
            grants[0].granted_at_unix_ms, ts_wall_ms,
            "the daemon's own Credential and the persisted record must agree \
             on the exact instant the credential was granted"
        );
        assert!((before..=after).contains(&grants[0].granted_at_unix_ms));
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

    /// PR #318 review round 3: a `CredentialGranted` this daemon can
    /// attribute to a tracked launch is always immediately followed, in the
    /// persisted log itself, by its own `WardEvent::CredentialGrantedLaunch`
    /// record carrying that launch's own `CommandStarted` record's `seq` —
    /// so a reader with no `conn` to key by (the shell/desktop panel's
    /// `Authority` projection, replaying one session's own ordered records)
    /// can still tell two routes of one launch apart from a later,
    /// independent one, without `CredentialGranted` itself ever carrying
    /// that identity (round 2's shape, reverted: a field on an existing
    /// variant would have changed the hash of every `CredentialGranted`
    /// record persisted before it existed). Two routes of the same launch
    /// must share it even when their own appends land at genuinely distinct
    /// wall-clock instants (a real `sleep` between them here, not an
    /// artificial identical-instant shortcut); a later, independent launch
    /// granting the same service and permissions again must get a different
    /// one.
    #[test]
    fn credential_granted_is_followed_by_its_own_launch_attribution_record() {
        use ward_events::{
            BoundedArgv, CredentialDelivery, ExitStatus, NameText, Pid, SandboxPath, SandboxRoot,
            Scope, ServiceId,
        };

        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());

        let pid = Pid::new(2).unwrap();
        let started = || WardEvent::CommandStarted {
            pid,
            parent: Pid::new(1).unwrap(),
            argv: BoundedArgv::from_bytes([b"a".as_slice()]),
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
            pid,
            exit: ExitStatus::Exited { code: 0 },
            duration: Duration::from_secs(1),
        };

        let started_record = served.append(started()).unwrap();

        // Two routes of the *same* launch, appended with a real, deliberate
        // delay between them -- genuinely distinct wall-clock instants, not
        // an identical one.
        let route_a = served.append(granted("github.com")).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let route_b = served.append(granted("api.github.com")).unwrap();

        assert_ne!(
            route_a.ts_wall, route_b.ts_wall,
            "the two routes really were appended at different instants"
        );

        served.append(finished()).unwrap();

        // A later, independent launch granting the same service and
        // permissions again must get a different launch_seq.
        let started_again = served.append(started()).unwrap();
        let route_c = served.append(granted("github.com")).unwrap();
        served.append(finished()).unwrap();

        // Read the whole persisted log back rather than trusting
        // `served.append`'s own return value, which only ever answers with
        // the record the client's own request appended, never the second,
        // daemon-internal one that follows it.
        let all = served.subscribe(0).unwrap().replay;
        let launch_seq_after = |granted_seq: u64| -> u64 {
            let attribution = all
                .iter()
                .find(|r| r.seq == granted_seq + 1)
                .unwrap_or_else(|| panic!("no record follows CredentialGranted seq {granted_seq}"));
            match attribution.event {
                WardEvent::CredentialGrantedLaunch { launch_seq } => launch_seq,
                ref other => panic!(
                    "expected CredentialGrantedLaunch right after seq {granted_seq}, got {other:?}"
                ),
            }
        };

        assert_eq!(
            launch_seq_after(route_a.seq),
            started_record.seq,
            "stamped from this launch's own CommandStarted record"
        );
        assert_eq!(
            launch_seq_after(route_a.seq),
            launch_seq_after(route_b.seq),
            "two routes of one launch share one launch_seq even at genuinely \
             distinct wall-clock instants"
        );
        assert_eq!(launch_seq_after(route_c.seq), started_again.seq);
        assert_ne!(
            launch_seq_after(route_c.seq),
            launch_seq_after(route_a.seq),
            "a later independent launch does not inherit the first launch's \
             own launch_seq"
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

    /// A stand-in for the components (#145 item 3): every confirmation is
    /// recorded in the order asked, and the one `(component, phase)` named in
    /// `refuse` answers `outcome` instead of acknowledging.
    #[derive(Clone)]
    struct Scripted {
        refuse: Arc<Mutex<Option<(acks::Component, acks::Phase, acks::Outcome)>>>,
        calls: Arc<Mutex<Vec<(acks::Component, acks::Phase)>>>,
    }

    impl Scripted {
        fn install(served: &mut Served) -> Self {
            let scripted = Self {
                refuse: Arc::new(Mutex::new(None)),
                calls: Arc::new(Mutex::new(Vec::new())),
            };
            served.acks = Box::new(scripted.clone());
            scripted
        }

        fn refuse(&self, component: acks::Component, phase: acks::Phase, outcome: acks::Outcome) {
            *self.refuse.lock().unwrap() = Some((component, phase, outcome));
        }

        fn relent(&self) {
            *self.refuse.lock().unwrap() = None;
        }

        fn calls(&self) -> Vec<(acks::Component, acks::Phase)> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }
    }

    impl acks::Acknowledger for Scripted {
        fn confirm(
            &mut self,
            component: acks::Component,
            phase: acks::Phase,
            _: &acks::Site<'_>,
        ) -> acks::Outcome {
            self.calls.lock().unwrap().push((component, phase));
            match &*self.refuse.lock().unwrap() {
                Some((c, p, outcome)) if *c == component && *p == phase => outcome.clone(),
                _ => acks::Outcome::Acknowledged,
            }
        }
    }

    fn proxy_timeout() -> acks::Outcome {
        acks::Outcome::TimedOut {
            after: Duration::from_secs(2),
        }
    }

    const PROXY_UNCONFIRMED: &str = "egress proxy (no acknowledgement within 2s)";

    /// #145 item 3: the freeze settles but the proxy never acknowledges. The
    /// pause holds everything it would have held, is recorded as unsettled
    /// naming the proxy with `pending: 0`, and the response says so; the
    /// components were asked in hold order after the marker and the approvals
    /// were already in place.
    #[test]
    fn a_pause_whose_proxy_does_not_acknowledge_is_unsettled_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let scripted = Scripted::install(&mut served);
        scripted.refuse(acks::Component::Proxy, acks::Phase::Held, proxy_timeout());
        let marker = pause::marker_path(dir.path(), "sess_9");

        let outcome = served.pause_with("looks wrong", |_| None).unwrap();
        assert_eq!(outcome.unsettled, None, "the freeze itself settled");
        assert_eq!(outcome.unconfirmed.as_deref(), Some(PROXY_UNCONFIRMED));
        assert!(
            matches!(
                &outcome.record.event,
                WardEvent::SessionPauseUnsettled { reason, pending: 0, .. }
                    if reason.as_str() == format!("looks wrong - unconfirmed: {PROXY_UNCONFIRMED}")
            ),
            "{:?}",
            outcome.record.event
        );
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "looks wrong\n");
        assert!(served.approvals.paused());
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::User])
        );
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
        assert_eq!(
            scripted.calls(),
            [
                (acks::Component::Proxy, acks::Phase::Held),
                (acks::Component::Approvals, acks::Phase::Held),
                (acks::Component::Credentials, acks::Phase::Held),
            ],
            "every component is asked, in hold order, even after the first refusal"
        );
        assert_eq!(kinds_of(&mut served), ["SessionPauseUnsettled"]);
        assert!(matches!(
            served.handle(Request::Pause { reason: String::new() }).0,
            Response::Error(e) if e == "already paused"
        ));
    }

    /// #145 item 3: the approvals answer with an error (the hold did not take).
    /// The record names them; the freeze's own pending count, when there is
    /// one, is kept beside the component.
    #[test]
    fn a_pause_whose_approvals_do_not_confirm_is_unsettled_naming_them() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let scripted = Scripted::install(&mut served);
        scripted.refuse(
            acks::Component::Approvals,
            acks::Phase::Held,
            acks::Outcome::Error("hold not applied".into()),
        );
        let outcome = served.pause_with("", |_| Some(2)).unwrap();
        assert_eq!(outcome.unsettled, Some(2));
        assert_eq!(
            outcome.unconfirmed.as_deref(),
            Some("approvals (hold not applied)")
        );
        assert!(matches!(
            &outcome.record.event,
            WardEvent::SessionPauseUnsettled { reason, pending: 2, .. }
                if reason.as_str() == "ward pause - unconfirmed: approvals (hold not applied)"
        ));
        assert_eq!(
            acks::unconfirmed_detail(&served.log_path)
                .unwrap()
                .as_deref(),
            Some("approvals (hold not applied)")
        );

        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let scripted = Scripted::install(&mut served);
        scripted.refuse(acks::Component::Proxy, acks::Phase::Held, proxy_timeout());
        let err = served
            .pause_with_appending(
                "looks wrong",
                |_| Some(1),
                |_, _| Err(Error::Daemon("simulated log failure".into())),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("1 process(es) still pending"), "{err}");
        assert!(
            err.contains(&format!("{PROXY_UNCONFIRMED} unconfirmed")),
            "{err}"
        );
        assert!(served.paused.is_some());
    }

    /// #145 item 3: a resume releases in the reverse of the hold order —
    /// credentials, approvals, then the proxy once the marker is gone — and
    /// confirms each before the next.
    #[test]
    fn resume_releases_the_components_in_reverse_order_and_confirms_each() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let scripted = Scripted::install(&mut served);
        served.pause_with("", |_| None).unwrap();
        scripted.calls();
        let record = served.resume().unwrap();
        assert!(matches!(record.event, WardEvent::SessionResumed { .. }));
        assert_eq!(
            scripted.calls(),
            [
                (acks::Component::Credentials, acks::Phase::Released),
                (acks::Component::Approvals, acks::Phase::Released),
                (acks::Component::Proxy, acks::Phase::Released),
            ]
        );
        assert!(!pause::marker_path(dir.path(), "sess_9").exists());
        assert!(!served.approvals.paused());
        assert!(served.paused.is_none());
    }

    /// #145 item 3: a release the proxy does not confirm is taken back — the
    /// marker rewritten with the pause's reason, the approvals held again,
    /// nothing thawed, no record — and the resume is refused naming it; the
    /// next resume, confirmed, releases.
    #[test]
    fn a_resume_whose_proxy_does_not_confirm_release_keeps_the_session_paused() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let scripted = Scripted::install(&mut served);
        served.pause_with("looks wrong", |_| None).unwrap();
        let marker = pause::marker_path(dir.path(), "sess_9");
        scripted.refuse(
            acks::Component::Proxy,
            acks::Phase::Released,
            proxy_timeout(),
        );

        let err = served.resume().unwrap_err().to_string();
        assert!(err.contains("resume of session sess_9 is refused"), "{err}");
        assert!(err.contains(PROXY_UNCONFIRMED), "{err}");
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "looks wrong\n",
            "the marker is back"
        );
        assert!(served.approvals.paused(), "the approvals are held again");
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::User])
        );
        assert_eq!(kinds_of(&mut served), ["SessionPaused"], "nothing recorded");

        scripted.refuse(
            acks::Component::Approvals,
            acks::Phase::Released,
            acks::Outcome::Error("hold not released".into()),
        );
        let err = served.resume().unwrap_err().to_string();
        assert!(err.contains("approvals (hold not released)"), "{err}");
        assert!(marker.exists(), "the marker was never cleared");
        assert!(served.approvals.paused());

        scripted.relent();
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Record(_)
        ));
        assert!(!marker.exists());
        assert!(!served.approvals.paused());
        assert_eq!(kinds_of(&mut served), ["SessionPaused", "SessionResumed"]);
    }

    /// #145 item 3: a stop whose processes are all confirmed gone but whose
    /// proxy does not acknowledge the hold is refused, never sealed:
    /// `WorkloadsTerminated` is not appended, the session is held for the stop
    /// over nothing with `SessionPauseUnsettled` naming the proxy, `resume`
    /// refuses it, and the retry — once the proxy confirms — records the whole
    /// stop's ended count and seals.
    #[test]
    fn a_stop_waits_for_every_component_before_recording_termination() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        assert!(matches!(served.handle(append(0)).0, Response::Record(_)));
        let scripted = Scripted::install(&mut served);
        scripted.refuse(acks::Component::Proxy, acks::Phase::Held, proxy_timeout());
        let marker = pause::marker_path(dir.path(), "sess_9");

        let (response, done) =
            served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, held| {
                assert_eq!(held, None);
                assert!(
                    marker.exists(),
                    "the marker closes the proxies before anything is killed"
                );
                pause::Termination::confirmed(3)
            });
        let Response::Error(message) = response else {
            panic!("{response:?}");
        };
        assert!(!done);
        assert!(message.contains("(3)"), "{message}");
        assert!(message.contains(PROXY_UNCONFIRMED), "{message}");
        assert!(message.contains("not sealed"), "{message}");
        assert!(served.log.is_some());
        assert_eq!(
            kinds_of(&mut served),
            ["AgentStateChanged", "SessionPauseUnsettled"],
            "no WorkloadsTerminated before the components confirm"
        );
        let last = served.subscribe(0).unwrap().replay.pop().unwrap();
        assert!(matches!(
            &last.event,
            WardEvent::SessionPauseUnsettled { reason, pending: 0, .. }
                if reason.as_str() == format!("ward stop - unconfirmed: {PROXY_UNCONFIRMED}")
        ));
        let held = served.paused.as_ref().unwrap();
        assert_eq!(held.holders.owners(), [pause::Owner::Stop]);
        assert_eq!(held.ended, 3, "carried into the retry");
        assert!(held.frozen.pids.is_empty());
        assert!(served.approvals.paused());
        assert!(pause::stop_begun(dir.path(), "sess_9"));
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
        assert!(
            std::fs::read_to_string(&marker)
                .unwrap()
                .starts_with("ward stop - unconfirmed: egress proxy"),
            "the marker names what holds the session"
        );
        assert_eq!(
            scripted.calls(),
            [
                (acks::Component::Proxy, acks::Phase::Held),
                (acks::Component::Approvals, acks::Phase::Held),
                (acks::Component::Credentials, acks::Phase::Held),
            ]
        );
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Error(e) if e.contains("has begun and not completed")
        ));

        scripted.relent();
        let (response, done) =
            served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, held| {
                assert_eq!(held.map(|f| f.pids), Some(Vec::new()));
                pause::Termination::nothing()
            });
        assert!(
            matches!(response, Response::Sealed { ended: Some(3), .. }),
            "{response:?}"
        );
        assert!(done);
        assert!(!marker.exists());
        let records: Vec<_> = LogReader::open(&served.log_path)
            .unwrap()
            .map_while(std::result::Result::ok)
            .collect();
        let kinds: Vec<String> = records
            .iter()
            .map(|r| format!("{:?}", r.event.kind()))
            .collect();
        assert_eq!(
            kinds,
            [
                "AgentStateChanged",
                "SessionPauseUnsettled",
                "WorkloadsTerminated",
                "AgentStateChanged",
                "SessionEnded"
            ]
        );
        assert!(matches!(
            records[2].event,
            WardEvent::WorkloadsTerminated {
                ended: 3,
                pending: 0,
                barrier_confirmed: true
            }
        ));
    }

    /// #145 item 3: a hold for a stop whose component does not confirm is
    /// refused — nothing may be restored over it — but the hold stands and its
    /// record names the component; the stop then finishes it once confirmed.
    #[test]
    fn a_hold_for_stop_whose_component_does_not_confirm_is_refused_but_stands() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let scripted = Scripted::install(&mut served);
        scripted.refuse(
            acks::Component::Credentials,
            acks::Phase::Held,
            acks::Outcome::Error("1 grant(s) still active".into()),
        );
        let err = served
            .hold_for_stop_with("ward stop --restore-entry", no_sandbox, |_, f| (f, true))
            .unwrap_err()
            .to_string();
        assert!(err.contains("nothing was restored"), "{err}");
        assert!(
            err.contains("credentials (1 grant(s) still active)"),
            "{err}"
        );
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::Stop])
        );
        assert!(served.approvals.paused());
        let last = served.subscribe(0).unwrap().replay.pop().unwrap();
        assert!(matches!(
            &last.event,
            WardEvent::SessionPauseUnsettled { reason, pending: 0, .. }
                if reason.as_str()
                    == "ward stop --restore-entry - unconfirmed: credentials (1 grant(s) still active)"
        ));

        let err = served
            .hold_for_stop_with("ward stop --restore-entry", no_sandbox, |_, f| (f, true))
            .unwrap_err()
            .to_string();
        assert!(err.contains("credentials"), "{err}");
        assert_eq!(
            kinds_of(&mut served),
            ["SessionPauseUnsettled"],
            "no second record"
        );

        scripted.relent();
        assert_eq!(
            served
                .hold_for_stop_with("ward stop --restore-entry", no_sandbox, |_, f| (f, true))
                .unwrap(),
            None
        );
        let (response, done) = served.handle(Request::Stop {
            reason: EndReason::UserStop,
        });
        assert!(done, "{response:?}");
    }

    /// #145 item 3 meets item 7: a restarted daemon finishing an interrupted
    /// pause collects the acknowledgements again, so a proxy that does not
    /// answer makes the reconciled record unsettled naming it, never a
    /// confirmed `SessionPaused`; and a completed pause the log records as
    /// confirmed, whose proxy the restarted daemon cannot confirm, gets the
    /// one record that says so.
    #[test]
    fn reconciliation_re_collects_the_acknowledgements() {
        let dir = tempfile::tempdir().unwrap();
        started_log(dir.path());
        pause::write_intent(dir.path(), "sess_9", &pause_intent("ops asked")).unwrap();
        let mut served = restarted_served(dir.path(), "sess_9");
        let scripted = Scripted::install(&mut served);
        scripted.refuse(acks::Component::Proxy, acks::Phase::Held, proxy_timeout());
        assert!(
            !served
                .reconcile_lifecycle_with(no_sandbox, never_terminates)
                .unwrap()
        );
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
        assert_eq!(
            kinds_of(&mut served),
            ["AgentStateChanged", "SessionPauseUnsettled"]
        );
        let last = served.subscribe(0).unwrap().replay.pop().unwrap();
        assert!(matches!(
            &last.event,
            WardEvent::SessionPauseUnsettled { reason, pending: 0, .. }
                if reason.as_str() == format!("ops asked - unconfirmed: {PROXY_UNCONFIRMED}")
        ));
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::User])
        );
        assert_eq!(
            std::fs::read_to_string(pause::marker_path(dir.path(), "sess_9")).unwrap(),
            "ops asked\n"
        );

        let dir = tempfile::tempdir().unwrap();
        {
            let mut served = fresh_served(dir.path());
            assert!(matches!(served.handle(append(0)).0, Response::Record(_)));
            served.pause_with("ops asked", |_| None).unwrap();
        }
        let mut served = restarted_served(dir.path(), "sess_9");
        let scripted = Scripted::install(&mut served);
        scripted.refuse(acks::Component::Proxy, acks::Phase::Held, proxy_timeout());
        assert!(
            !served
                .reconcile_lifecycle_with(no_sandbox, never_terminates)
                .unwrap()
        );
        assert_eq!(
            kinds_of(&mut served),
            [
                "AgentStateChanged",
                "SessionPaused",
                "SessionPauseUnsettled"
            ],
            "the log's confirmed hold is qualified by what this daemon cannot confirm"
        );
    }

    const CAPTURE_REASON: &str = "ward capture: test";

    fn this_process() -> (u32, String) {
        (std::process::id(), pause::own_start_time())
    }

    fn dead_capturer(op: &str) -> pause::Capturer {
        pause::Capturer {
            op: op.to_owned(),
            pid: 999_999,
            started: "0".to_owned(),
            reason: CAPTURE_REASON.to_owned(),
        }
    }

    /// A freeze holding this test process, confirmed stable: thawing it sends a
    /// `SIGCONT` to a process that is not stopped, which does nothing.
    fn own_process(_: &str) -> (Frozen, bool) {
        (
            Frozen {
                method: ward_events::PauseMethod::Sigstop,
                pids: vec![std::process::id()],
                cgroup: None,
            },
            true,
        )
    }

    fn unsettled_own_process(_: &str) -> (Frozen, bool) {
        let (frozen, _) = own_process("");
        (frozen, false)
    }

    fn restabilized(_: &str, frozen: Frozen) -> (Frozen, bool) {
        (frozen, true)
    }

    fn held_by(dir: &Path) -> Option<pause::Holders> {
        pause::read_held_by(dir, "sess_9").unwrap()
    }

    /// #145 item 6, against a real tree: a capture's hold freezes the sandbox,
    /// writes the marker, holds the approvals, collects every acknowledgement
    /// in hold order and records `SessionPaused` with the capture's reason;
    /// its release thaws, clears and records `SessionResumed`.
    #[test]
    fn a_capture_hold_proceeds_from_a_settled_and_acknowledged_freeze() {
        let dir = tempfile::tempdir().unwrap();
        let mut sandbox = pause::FakeSandbox::spawn("sess_cap");
        let mut served = fresh_served_as(dir.path(), &sandbox.session);
        let scripted = Scripted::install(&mut served);
        let marker = pause::marker_path(dir.path(), &sandbox.session);

        let op = served
            .hold_for_capture(CAPTURE_REASON, this_process())
            .unwrap()
            .expect("something ran, so something is held");
        let paused = served.paused.as_ref().unwrap();
        assert!(sandbox.frozen_by(&paused.frozen));
        assert_eq!(paused.holders.owners(), [pause::Owner::Capture]);
        assert_eq!(paused.holders.captures[0].op, op);
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            format!("{CAPTURE_REASON}\n")
        );
        assert!(served.approvals.paused());
        assert_eq!(
            pause::read_held_by(dir.path(), &sandbox.session)
                .unwrap()
                .map(|h| h.owners()),
            Some(vec![pause::Owner::Capture])
        );
        assert!(!pause::intent_path(dir.path(), &sandbox.session).exists());
        assert_eq!(
            scripted.calls(),
            [
                (acks::Component::Proxy, acks::Phase::Held),
                (acks::Component::Approvals, acks::Phase::Held),
                (acks::Component::Credentials, acks::Phase::Held),
            ]
        );
        assert_eq!(kinds_of(&mut served), ["SessionPaused"]);
        let last = served.subscribe(0).unwrap().replay.pop().unwrap();
        assert!(matches!(
            &last.event,
            WardEvent::SessionPaused { reason, .. } if reason.as_str() == CAPTURE_REASON
        ));

        let record = served
            .release_capture(&op)
            .unwrap()
            .expect("the last owner's release is recorded");
        assert!(matches!(record.event, WardEvent::SessionResumed { .. }));
        assert!(served.paused.is_none());
        assert!(!served.approvals.paused());
        assert!(!marker.exists());
        assert_eq!(
            pause::read_held_by(dir.path(), &sandbox.session).unwrap(),
            None
        );
        assert!(
            crate::daemon::wait_until(Duration::from_secs(2), || !sandbox.stopped()),
            "the tree runs again"
        );
        assert!(sandbox.running());
        assert_eq!(kinds_of(&mut served), ["SessionPaused", "SessionResumed"]);
        assert_eq!(
            served.release_capture(&op).unwrap(),
            None,
            "a second release of the same operation is nothing"
        );
    }

    /// #145 item 6: a capture is refused — nothing held, nothing recorded, and
    /// only what the capture itself took released — when a component does not
    /// acknowledge the hold, naming it, or when the freeze is not confirmed
    /// settled, naming the pending count.
    #[test]
    fn a_capture_from_an_unconfirmed_freeze_is_refused_with_nothing_held_or_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let scripted = Scripted::install(&mut served);
        scripted.refuse(acks::Component::Proxy, acks::Phase::Held, proxy_timeout());
        let marker = pause::marker_path(dir.path(), "sess_9");

        let err = served
            .hold_for_capture_with(CAPTURE_REASON, this_process(), own_process, restabilized)
            .unwrap_err()
            .to_string();
        assert!(err.contains("nothing was captured"), "{err}");
        assert!(err.contains(PROXY_UNCONFIRMED), "{err}");
        assert!(served.paused.is_none());
        assert!(!served.approvals.paused());
        assert!(!marker.exists());
        assert_eq!(held_by(dir.path()), None);
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
        assert!(kinds_of(&mut served).is_empty(), "nothing recorded");

        scripted.relent();
        let err = served
            .hold_for_capture_with(
                CAPTURE_REASON,
                this_process(),
                unsettled_own_process,
                restabilized,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("nothing was captured"), "{err}");
        assert!(err.contains("1 process(es) still pending"), "{err}");
        assert!(served.paused.is_none());
        assert!(!marker.exists());
        assert!(kinds_of(&mut served).is_empty());
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Error(e) if e == "not paused"
        ));
    }

    /// #145 item 6: a capture over a user's pause reuses that quiescence but
    /// must still confirm it; one that cannot is refused and leaves the user's
    /// pause — marker, record, owners — untouched.
    #[test]
    fn a_capture_over_a_user_pause_that_cannot_be_reconfirmed_is_refused_leaving_the_pause() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let scripted = Scripted::install(&mut served);
        served.pause_with("mine", |_| None).unwrap();
        scripted.calls();
        scripted.refuse(acks::Component::Proxy, acks::Phase::Held, proxy_timeout());

        let err = served
            .hold_for_capture_with(CAPTURE_REASON, this_process(), never_freezes, restabilized)
            .unwrap_err()
            .to_string();
        assert!(err.contains(PROXY_UNCONFIRMED), "{err}");
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::User])
        );
        assert_eq!(
            held_by(dir.path()).map(|h| h.owners()),
            Some(vec![pause::Owner::User])
        );
        assert_eq!(
            std::fs::read_to_string(pause::marker_path(dir.path(), "sess_9")).unwrap(),
            "mine\n"
        );
        assert!(served.approvals.paused());
        assert_eq!(kinds_of(&mut served), ["SessionPaused"]);
    }

    /// #145 item 6: `ward resume` releases a user's pause, not a capture's hold.
    #[test]
    fn resume_refuses_a_hold_owned_only_by_a_capture() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        Scripted::install(&mut served);
        let op = served
            .hold_for_capture_with(CAPTURE_REASON, this_process(), own_process, restabilized)
            .unwrap()
            .unwrap();
        let marker = pause::marker_path(dir.path(), "sess_9");

        let (response, _) = served.handle(Request::Resume);
        assert!(
            matches!(&response, Response::Error(e)
                if e.contains(&format!("held for capture by operation {op}")) && e.contains("not a user pause")),
            "{response:?}"
        );
        assert!(marker.exists());
        assert!(served.approvals.paused());
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::Capture])
        );
        assert_eq!(kinds_of(&mut served), ["SessionPaused"], "nothing recorded");

        assert!(matches!(
            served.handle(Request::ReleaseCapture { op }).0,
            Response::Record(r) if matches!(r.event, WardEvent::SessionResumed { .. })
        ));
        assert!(served.paused.is_none());
        assert!(!marker.exists());
    }

    /// #145 item 6: a user pause layered over a capture is released by `ward
    /// resume` alone — the marker, the held approvals and the freeze stay for
    /// the capture, and the record says what still holds — and the capture's
    /// release then ends the hold.
    #[test]
    fn resume_releases_only_the_users_layer_over_a_capture() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let scripted = Scripted::install(&mut served);
        let op = served
            .hold_for_capture_with(CAPTURE_REASON, this_process(), own_process, restabilized)
            .unwrap()
            .unwrap();
        let marker = pause::marker_path(dir.path(), "sess_9");
        scripted.calls();

        let outcome = served.pause_with("mine", |_| None).unwrap();
        assert!(matches!(
            &outcome.record.event,
            WardEvent::SessionPaused { reason, .. } if reason.as_str() == "mine"
        ));
        assert_eq!(outcome.unsettled, None);
        assert_eq!(outcome.unconfirmed, None);
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::User, pause::Owner::Capture])
        );
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "mine\n");
        assert_eq!(
            held_by(dir.path()).map(|h| h.owners()),
            Some(vec![pause::Owner::User, pause::Owner::Capture])
        );
        assert_eq!(
            scripted.calls(),
            [
                (acks::Component::Proxy, acks::Phase::Held),
                (acks::Component::Approvals, acks::Phase::Held),
                (acks::Component::Credentials, acks::Phase::Held),
            ],
            "the user's pause confirms the hold again"
        );
        assert!(matches!(
            served.handle(Request::Pause { reason: String::new() }).0,
            Response::Error(e) if e == "already paused"
        ));

        let record = served.resume().unwrap();
        assert!(
            matches!(
                &record.event,
                WardEvent::SessionPaused { reason, .. } if reason.as_str() == CAPTURE_REASON
            ),
            "{:?}",
            record.event
        );
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::Capture])
        );
        assert!(served.approvals.paused(), "held for the capture");
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            format!("{CAPTURE_REASON}\n"),
            "the marker names what holds the session now"
        );
        assert_eq!(
            held_by(dir.path()).map(|h| h.owners()),
            Some(vec![pause::Owner::Capture])
        );
        assert!(scripted.calls().is_empty(), "nothing was released");
        assert_eq!(
            kinds_of(&mut served),
            ["SessionPaused", "SessionPaused", "SessionPaused"]
        );

        let record = served.release_capture(&op).unwrap().unwrap();
        assert!(matches!(record.event, WardEvent::SessionResumed { .. }));
        assert!(served.paused.is_none());
        assert!(!marker.exists());
        assert_eq!(
            scripted.calls(),
            [
                (acks::Component::Credentials, acks::Phase::Released),
                (acks::Component::Approvals, acks::Phase::Released),
                (acks::Component::Proxy, acks::Phase::Released),
            ]
        );
    }

    /// #145 item 6: a capture taken while the user holds the session takes no
    /// record and no ownership of the pause; its release leaves the user's
    /// pause exactly as it was.
    #[test]
    fn a_captures_release_leaves_the_users_pause_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let scripted = Scripted::install(&mut served);
        served.pause_with("mine", |_| None).unwrap();
        scripted.calls();
        let marker = pause::marker_path(dir.path(), "sess_9");

        let op = served
            .hold_for_capture_with(CAPTURE_REASON, this_process(), never_freezes, restabilized)
            .unwrap()
            .unwrap();
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::User, pause::Owner::Capture])
        );
        assert_eq!(
            scripted.calls(),
            [
                (acks::Component::Proxy, acks::Phase::Held),
                (acks::Component::Approvals, acks::Phase::Held),
                (acks::Component::Credentials, acks::Phase::Held),
            ],
            "the capture confirms the quiescence it reuses"
        );
        assert_eq!(kinds_of(&mut served), ["SessionPaused"], "no second record");
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "mine\n");

        assert_eq!(served.release_capture(&op).unwrap(), None);
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::User])
        );
        assert_eq!(
            held_by(dir.path()).map(|h| h.owners()),
            Some(vec![pause::Owner::User])
        );
        assert!(marker.exists());
        assert!(served.approvals.paused());
        assert!(scripted.calls().is_empty(), "nothing released");
        assert_eq!(kinds_of(&mut served), ["SessionPaused"]);

        let record = served.resume().unwrap();
        assert!(matches!(record.event, WardEvent::SessionResumed { .. }));
        assert!(served.paused.is_none());
    }

    /// A stop takes over whatever holds the session: a capture's hold included.
    #[test]
    fn a_stop_hold_takes_over_a_captures_hold() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        Scripted::install(&mut served);
        let op = served
            .hold_for_capture_with(CAPTURE_REASON, this_process(), own_process, restabilized)
            .unwrap()
            .unwrap();
        assert_eq!(
            served
                .hold_for_stop_with("ward stop --restore-entry", never_freezes, restabilized)
                .unwrap(),
            None
        );
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::Capture, pause::Owner::Stop])
        );
        assert_eq!(kinds_of(&mut served), ["SessionPaused"]);
        assert_eq!(served.release_capture(&op).unwrap(), None);
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::Stop])
        );
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Error(e) if e.contains("has begun and not completed")
        ));
        let (response, done) =
            served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, held| {
                assert_eq!(
                    held.map(|f| f.pids),
                    Some(vec![std::process::id()]),
                    "the stop ends exactly what the hold kept"
                );
                pause::Termination::confirmed(1)
            });
        assert!(done, "{response:?}");
        assert!(matches!(response, Response::Sealed { ended: Some(1), .. }));
    }

    /// #145 item 6 meets item 7: a restarted daemon releases a hold whose only
    /// owner is a capture whose process is gone (the capture cannot complete),
    /// recording the release; one the user also holds is adopted as the
    /// user's, the dead capture forgotten; a capture whose hold-taking was
    /// interrupted is released whether or not it got as far as the marker.
    #[test]
    fn reconciliation_releases_an_orphaned_capture_hold_but_not_a_user_hold() {
        let capture_paused = || WardEvent::SessionPaused {
            method: ward_events::PauseMethod::Sigstop,
            reason: ward_events::ShortText::new(CAPTURE_REASON),
        };

        let dir = tempfile::tempdir().unwrap();
        {
            let mut served = fresh_served(dir.path());
            assert!(matches!(served.handle(append(0)).0, Response::Record(_)));
            served.append(capture_paused()).unwrap();
        }
        pause::write_marker(dir.path(), "sess_9", CAPTURE_REASON).unwrap();
        pause::write_held_by(
            dir.path(),
            "sess_9",
            &pause::Holders::for_capture(dead_capturer("op_dead")),
        )
        .unwrap();
        let mut served = restarted_served(dir.path(), "sess_9");
        let scripted = Scripted::install(&mut served);
        assert!(
            !served
                .reconcile_lifecycle_with(no_sandbox, never_terminates)
                .unwrap()
        );
        assert!(served.paused.is_none());
        assert!(!served.approvals.paused());
        assert!(!pause::marker_path(dir.path(), "sess_9").exists());
        assert_eq!(held_by(dir.path()), None);
        assert_eq!(
            kinds_of(&mut served),
            ["AgentStateChanged", "SessionPaused", "SessionResumed"]
        );
        assert_eq!(
            scripted.calls(),
            [
                (acks::Component::Credentials, acks::Phase::Released),
                (acks::Component::Approvals, acks::Phase::Released),
                (acks::Component::Proxy, acks::Phase::Released),
            ]
        );

        let dir = tempfile::tempdir().unwrap();
        {
            let mut served = fresh_served(dir.path());
            assert!(matches!(served.handle(append(0)).0, Response::Record(_)));
            served.pause_with("mine", |_| None).unwrap();
        }
        let mut holders = pause::Holders::for_user();
        holders.add_capture(dead_capturer("op_dead"));
        pause::write_held_by(dir.path(), "sess_9", &holders).unwrap();
        let mut served = restarted_served(dir.path(), "sess_9");
        Scripted::install(&mut served);
        assert!(
            !served
                .reconcile_lifecycle_with(no_sandbox, never_terminates)
                .unwrap()
        );
        assert_eq!(
            served.paused.as_ref().map(|p| p.holders.owners()),
            Some(vec![pause::Owner::User])
        );
        assert_eq!(
            held_by(dir.path()).map(|h| h.owners()),
            Some(vec![pause::Owner::User])
        );
        assert!(pause::marker_path(dir.path(), "sess_9").exists());
        assert_eq!(
            kinds_of(&mut served),
            ["AgentStateChanged", "SessionPaused"]
        );
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Record(r) if matches!(r.event, WardEvent::SessionResumed { .. })
        ));

        let dir = tempfile::tempdir().unwrap();
        started_log(dir.path());
        pause::write_intent(
            dir.path(),
            "sess_9",
            &pause::Intent::begin(pause::Verb::Capture {
                reason: CAPTURE_REASON.to_owned(),
                capturer: dead_capturer("op_cut"),
            })
            .unwrap(),
        )
        .unwrap();
        let mut served = restarted_served(dir.path(), "sess_9");
        Scripted::install(&mut served);
        assert!(
            !served
                .reconcile_lifecycle_with(no_sandbox, never_terminates)
                .unwrap()
        );
        assert!(served.paused.is_none());
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
        assert_eq!(
            kinds_of(&mut served),
            ["AgentStateChanged"],
            "a hold that never got to its record releases without one"
        );
    }

    /// `ward resume` on a hold whose only owner is a capture whose process is
    /// gone releases it: reconciliation after the owner is gone, not a user
    /// pause being released.
    #[test]
    fn resume_releases_a_capture_hold_whose_capturer_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        Scripted::install(&mut served);
        served
            .hold_for_capture_with(CAPTURE_REASON, this_process(), own_process, restabilized)
            .unwrap()
            .unwrap();
        if let Some(paused) = served.paused.as_mut() {
            paused.holders.captures[0].pid = 999_999;
            paused.holders.captures[0].started = "0".to_owned();
        }
        let record = served.resume().unwrap();
        assert!(matches!(record.event, WardEvent::SessionResumed { .. }));
        assert!(served.paused.is_none());
        assert!(!pause::marker_path(dir.path(), "sess_9").exists());
    }

    fn command_started(pid: u32) -> WardEvent {
        use ward_events::{BoundedArgv, Pid, SandboxPath, SandboxRoot};
        WardEvent::CommandStarted {
            pid: Pid::new(pid).unwrap(),
            parent: Pid::new(1).unwrap(),
            argv: BoundedArgv::from_bytes([b"agent".as_slice()]),
            cwd: SandboxPath::new(SandboxRoot::Work, ".").unwrap(),
            exe_digest: None,
        }
    }

    fn command_finished(pid: u32) -> WardEvent {
        WardEvent::CommandFinished {
            pid: ward_events::Pid::new(pid).unwrap(),
            exit: ward_events::ExitStatus::Exited { code: 0 },
            duration: Duration::from_millis(5),
        }
    }

    fn appended(event: WardEvent) -> Request {
        Request::Append {
            origin: Origin::Kernel,
            event,
            at_unix_ms: 1,
        }
    }

    fn lane_of(served: &Served) -> LifecycleReport {
        lock(&served.lane).clone()
    }

    /// #145 item 1: the lifecycle is explicit and every request outside its
    /// state is refused naming the state — in the words existing clients read
    /// where those already existed (`already paused`, `not paused`, `log is
    /// sealed`, the stop that has begun), and naming the state otherwise.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn the_lifecycle_is_explicit_and_requests_outside_their_state_are_refused_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        assert_eq!(served.lifecycle(), Lifecycle::Running);
        assert_eq!(lane_of(&served), LifecycleReport::of(Lifecycle::Running));
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Error(e) if e == "not paused"
        ));

        assert!(matches!(
            served
                .handle(Request::Pause {
                    reason: "looks wrong".into()
                })
                .0,
            Response::Paused {
                unsettled: None,
                unconfirmed: None,
                ..
            }
        ));
        assert_eq!(served.lifecycle(), Lifecycle::Paused);
        let lane = lane_of(&served);
        assert_eq!(lane.state, Lifecycle::Paused);
        assert_eq!(lane.held_by, [pause::Owner::User]);
        assert_eq!(lane.detail, None);
        assert!(matches!(
            served.handle(Request::Pause { reason: String::new() }).0,
            Response::Error(e) if e == "already paused"
        ));
        assert!(
            pause::admit_launch(dir.path(), "sess_9")
                .unwrap_err()
                .to_string()
                .contains(pause::PAUSED_REFUSAL)
        );
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Record(_)
        ));
        assert_eq!(served.lifecycle(), Lifecycle::Running);
        assert_eq!(lane_of(&served).state, Lifecycle::Running);
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());

        // A stop has begun (its marker) and nothing is held in memory: a
        // retry goes on; a pause, a resume and a capture are refused naming it.
        pause::write_stop_marker(dir.path(), "sess_9").unwrap();
        assert_eq!(served.lifecycle(), Lifecycle::Stopping);
        // The marker makes even a user's hold a stop's, as `resume` always read it.
        served.paused = Some(Paused {
            frozen: no_sandbox("").0,
            since: Instant::now(),
            holders: pause::Holders::for_user(),
            ended: 0,
        });
        assert_eq!(served.lifecycle(), Lifecycle::Stopping);
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Error(e) if e.contains("has begun and not completed")
        ));
        served.paused = None;
        let (response, _) = served.handle(Request::Pause {
            reason: String::new(),
        });
        assert!(
            matches!(&response, Response::Error(e) if e.contains("session sess_9 is stopping")),
            "{response:?}"
        );
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Error(e) if e.contains("has begun and not completed")
        ));
        let (response, _) = served.handle(Request::HoldForCapture {
            reason: pause::capture_reason("x"),
            pid: std::process::id(),
            started: pause::own_start_time(),
        });
        assert!(
            matches!(&response, Response::Error(e) if e.contains("is stopping")),
            "{response:?}"
        );
        assert!(matches!(
            served
                .handle(Request::Pause {
                    reason: String::new()
                })
                .0,
            Response::Error(_)
        ));
        let (response, done) = served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, _| {
            pause::Termination::confirmed(0)
        });
        assert!(matches!(response, Response::Sealed { ended: Some(0), .. }));
        assert!(done);
        assert_eq!(served.lifecycle(), Lifecycle::Stopped);
        assert_eq!(lane_of(&served).state, Lifecycle::Stopped);
        for request in [
            Request::Pause {
                reason: String::new(),
            },
            Request::Resume,
            Request::HoldForStop {
                reason: String::new(),
            },
            Request::HoldForCapture {
                reason: String::new(),
                pid: 1,
                started: String::new(),
            },
        ] {
            let (response, _) = served.handle(request.clone());
            assert!(
                matches!(&response, Response::Error(e) if e == "log is sealed"),
                "{request:?}: {response:?}"
            );
        }
    }

    /// #145 item 1: a hold that could not be confirmed is `Incomplete` — in
    /// memory, on the lane and on disk alike, naming what is uncertain — never
    /// `Paused` or `Stopping`; the retry that confirms it moves on.
    #[test]
    fn an_unconfirmed_hold_is_incomplete_everywhere_until_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let scripted = Scripted::install(&mut served);
        // An unsettled freeze.
        let outcome = served.pause_with("looks wrong", |_| Some(1)).unwrap();
        assert_eq!(outcome.unsettled, Some(1));
        assert_eq!(served.lifecycle(), Lifecycle::Incomplete);
        let lane = lane_of(&served);
        assert_eq!(lane.state, Lifecycle::Incomplete);
        assert_eq!(
            lane.detail.as_deref(),
            Some("1 process(es) not confirmed stopped")
        );
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Record(_)
        ));
        assert_eq!(served.lifecycle(), Lifecycle::Running);

        // A component that does not acknowledge.
        scripted.refuse(acks::Component::Proxy, acks::Phase::Held, proxy_timeout());
        let outcome = served.pause_with("again", |_| None).unwrap();
        assert_eq!(outcome.unconfirmed.as_deref(), Some(PROXY_UNCONFIRMED));
        assert_eq!(served.lifecycle(), Lifecycle::Incomplete);
        assert_eq!(lane_of(&served).detail.as_deref(), Some(PROXY_UNCONFIRMED));
        scripted.relent();
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Record(_)
        ));

        // A stop that cannot confirm termination: incomplete, held for the
        // stop, and the retry that confirms it ends the session.
        let (response, done) = served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, _| {
            pause::Termination {
                ended: 1,
                remaining: Some(stuck(77)),
                barrier_confirmed: true,
                method: ward_events::PauseMethod::Sigstop,
            }
        });
        assert!(matches!(response, Response::Error(_)));
        assert!(!done);
        assert_eq!(served.lifecycle(), Lifecycle::Incomplete);
        let lane = lane_of(&served);
        assert_eq!(lane.held_by, [pause::Owner::Stop]);
        assert_eq!(
            lane.detail.as_deref(),
            Some("1 process(es) not confirmed ended")
        );
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Error(e) if e.contains("has begun and not completed")
        ));
        let (response, done) = served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, _| {
            pause::Termination::confirmed(1)
        });
        assert!(matches!(response, Response::Sealed { ended: Some(1), .. }));
        assert!(done);
        assert_eq!(lane_of(&served).state, Lifecycle::Stopped);
    }

    /// A stand-in component that does not answer until told to: what a pause
    /// waiting on the egress proxy looks like from the lane.
    struct Blocking {
        until: Receiver<()>,
    }

    impl acks::Acknowledger for Blocking {
        fn confirm(
            &mut self,
            component: acks::Component,
            phase: acks::Phase,
            _: &acks::Site<'_>,
        ) -> acks::Outcome {
            if component == acks::Component::Proxy && phase == acks::Phase::Held {
                self.until.recv().unwrap();
            }
            acks::Outcome::Acknowledged
        }
    }

    /// #145 item 1: while a pause holds the daemon's mutex waiting on a
    /// component, the lane already reads `pausing` with the operation named —
    /// what `Request::Lifecycle` answers from, without the mutex.
    #[test]
    fn the_lane_reads_pausing_while_a_pause_waits_on_a_component() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let (release, until) = channel();
        served.acks = Box::new(Blocking { until });
        let lane = Arc::clone(&served.lane);
        let served = Arc::new(Mutex::new(served));
        let pausing = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || {
                lock(&served).handle(Request::Pause {
                    reason: "looks wrong".into(),
                })
            })
        };
        assert!(
            wait_until(Duration::from_secs(2), || {
                lock(&lane).state == Lifecycle::Pausing
            }),
            "{:?}",
            lock(&lane)
        );
        let in_flight = lock(&lane).clone();
        assert!(in_flight.op.is_some(), "{in_flight:?}");
        assert!(
            served.try_lock().is_err(),
            "the pause holds the daemon's mutex meanwhile"
        );
        assert_eq!(
            pause::lifecycle_on_disk(dir.path(), "sess_9")
                .unwrap()
                .state,
            Lifecycle::Pausing
        );
        release.send(()).unwrap();
        assert!(matches!(pausing.join().unwrap().0, Response::Paused { .. }));
        assert_eq!(lock(&lane).state, Lifecycle::Paused);
        assert_eq!(lock(&lane).op, None);
    }

    /// #145 item 1: a resume records its intent before it releases anything,
    /// a refused resume clears it with the hold standing, and a restart
    /// mid-resume finishes the release — appending `SessionResumed` when the
    /// log still says held, nothing when it already says resumed — so no tree
    /// is left frozen with no marker saying so.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_resume_records_its_intent_and_a_restart_mid_resume_finishes_the_release() {
        /// A component that reads the intent file back when asked to confirm
        /// its release, and refuses.
        struct Observing {
            seen: Arc<Mutex<Option<pause::Intent>>>,
            state: PathBuf,
        }
        impl acks::Acknowledger for Observing {
            fn confirm(
                &mut self,
                _: acks::Component,
                _: acks::Phase,
                _: &acks::Site<'_>,
            ) -> acks::Outcome {
                *self.seen.lock().unwrap() = pause::read_intent(&self.state, "sess_9").unwrap();
                acks::Outcome::Error("not yet".into())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        let scripted = Scripted::install(&mut served);
        assert!(matches!(
            served
                .handle(Request::Pause {
                    reason: String::new()
                })
                .0,
            Response::Paused { .. }
        ));
        // The intent is on disk while the components are asked to release.
        let seen = Arc::new(Mutex::new(None));
        served.acks = Box::new(Observing {
            seen: Arc::clone(&seen),
            state: dir.path().to_path_buf(),
        });
        let (response, _) = served.handle(Request::Resume);
        assert!(matches!(response, Response::Error(e) if e.contains("not yet")));
        assert!(
            matches!(
                &*seen.lock().unwrap(),
                Some(pause::Intent {
                    verb: pause::Verb::Resume,
                    ..
                })
            ),
            "{:?}",
            seen.lock().unwrap()
        );
        assert!(
            !pause::intent_path(dir.path(), "sess_9").exists(),
            "a refused resume has its outcome: the hold stands"
        );
        assert_eq!(served.lifecycle(), Lifecycle::Paused);
        served.acks = Box::new(scripted);
        assert!(matches!(
            served.handle(Request::Resume).0,
            Response::Record(_)
        ));
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());

        // A resume that died after clearing the marker, before the thaw and
        // the record: the log says held, nothing on disk does.
        assert!(matches!(
            served
                .handle(Request::Pause {
                    reason: "again".into()
                })
                .0,
            Response::Paused { .. }
        ));
        drop(served);
        pause::write_intent(
            dir.path(),
            "sess_9",
            &pause::Intent::begin(pause::Verb::Resume).unwrap(),
        )
        .unwrap();
        pause::clear_marker(dir.path(), "sess_9").unwrap();
        pause::clear_held_by(dir.path(), "sess_9").unwrap();
        assert_eq!(
            pause::lifecycle_on_disk(dir.path(), "sess_9")
                .unwrap()
                .state,
            Lifecycle::Resuming
        );
        let mut served = restarted_served(dir.path(), "sess_9");
        let sealed = served
            .reconcile_lifecycle_with(no_sandbox, never_terminates)
            .unwrap();
        assert!(!sealed);
        assert!(served.paused.is_none());
        assert!(!served.approvals.paused());
        assert!(!pause::marker_path(dir.path(), "sess_9").exists());
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
        assert_eq!(served.lifecycle(), Lifecycle::Running);
        assert_eq!(lane_of(&served).state, Lifecycle::Running);
        assert_eq!(
            kinds_of(&mut served),
            [
                "SessionPaused",
                "SessionResumed",
                "SessionPaused",
                "SessionResumed"
            ]
        );

        // A resume that died after its record, before clearing its intent:
        // nothing to append, the intent is cleared.
        drop(served);
        pause::write_intent(
            dir.path(),
            "sess_9",
            &pause::Intent::begin(pause::Verb::Resume).unwrap(),
        )
        .unwrap();
        let mut served = restarted_served(dir.path(), "sess_9");
        assert!(
            !served
                .reconcile_lifecycle_with(no_sandbox, never_terminates)
                .unwrap()
        );
        assert_eq!(kinds_of(&mut served).len(), 4, "no second SessionResumed");
        assert!(!pause::intent_path(dir.path(), "sess_9").exists());
        assert_eq!(served.lifecycle(), Lifecycle::Running);
    }

    /// #145 item 2: every launch has a stable handle from its admission — the
    /// seq of its `CommandStarted` — recorded in the session's register with
    /// how it ended, and a restarted daemon reads the register back: a launch
    /// whose connection went away is not reopened as though it still ran.
    #[test]
    fn launch_handles_are_registered_from_admission_and_read_back_on_restart() {
        let dir = tempfile::tempdir().unwrap();
        let register = || launches::read(dir.path(), "sess_9").unwrap();
        let first = {
            let mut served = fresh_served(dir.path());
            let Response::Record(started) = served.handle(appended(command_started(2))).0 else {
                panic!("appended");
            };
            let first = started.seq;
            assert_eq!(
                register().open().map(|l| l.handle).collect::<Vec<_>>(),
                [first]
            );
            assert_eq!(lane_of(&served).open_launches, [first]);
            assert!(matches!(
                served.handle(appended(command_finished(2))).0,
                Response::Record(_)
            ));
            assert_eq!(register().state_of(first), Some(LaunchState::Finished));
            assert!(lane_of(&served).open_launches.is_empty());

            // A launch on a connection that then goes away.
            let Response::Record(started) = served.handle_conn(7, appended(command_started(2))).0
            else {
                panic!("appended");
            };
            let abandoned = started.seq;
            served.disconnect_open_launches(7);
            assert_eq!(register().state_of(abandoned), Some(LaunchState::Unknown));
            assert!(served.open_launches.is_empty());

            // A launch still open when the daemon dies.
            let Response::Record(started) = served.handle_conn(8, appended(command_started(3))).0
            else {
                panic!("appended");
            };
            assert_eq!(
                register().open().map(|l| l.handle).collect::<Vec<_>>(),
                [started.seq]
            );
            started.seq
        };
        let open = first;

        let mut served = restarted_served(dir.path(), "sess_9");
        assert!(
            !served
                .reconcile_lifecycle_with(no_sandbox, never_terminates)
                .unwrap()
        );
        assert_eq!(
            served
                .open_launches
                .iter()
                .map(|(_, key, _)| *key)
                .collect::<Vec<_>>(),
            [open],
            "the abandoned launch is not reopened"
        );
        assert_eq!(served.launches.launches.len(), 3);
        assert_eq!(lane_of(&served).open_launches, [open]);
        assert_eq!(
            pause::lifecycle_on_disk(dir.path(), "sess_9")
                .unwrap()
                .open_launches,
            [open]
        );
        // The stop terminalizes the open launch and the register says so.
        let (response, done) = served.stop(Served::INTERNAL_CONN, EndReason::UserStop, |_, _| {
            pause::Termination::confirmed(0)
        });
        assert!(matches!(response, Response::Sealed { .. }), "{response:?}");
        assert!(done);
        assert_eq!(register().state_of(open), Some(LaunchState::Aborted));
        assert_eq!(register().open().count(), 0);
    }

    /// #145 item 8: a pause is not blocked behind a subscriber's replay. The
    /// replay's boundary is fixed under the mutex and the log is read with it
    /// released, so a pause landing while a replay is still being read
    /// completes at once — and the subscriber still sees every record before
    /// the boundary, the marker, and the pause's record live after it.
    #[test]
    fn a_pause_is_not_blocked_behind_a_subscribers_replay() {
        let dir = tempfile::tempdir().unwrap();
        let mut served = fresh_served(dir.path());
        for i in 0..5 {
            assert!(matches!(served.handle(append(i)).0, Response::Record(_)));
        }
        let served = Arc::new(Mutex::new(served));
        let (reading, started) = channel::<()>();
        let (release, held) = channel::<()>();
        let (daemon_end, client_end) = UnixStream::pair().unwrap();
        let streaming = {
            let served = Arc::clone(&served);
            let writer = daemon_end.try_clone().unwrap();
            std::thread::spawn(move || {
                stream_subscription_with(
                    BufReader::new(daemon_end),
                    writer,
                    &served,
                    0,
                    |path, from, boundary| {
                        reading.send(()).unwrap();
                        held.recv().unwrap();
                        read_replay(path, from, boundary)
                    },
                );
            })
        };
        started.recv().unwrap();
        let asked = Instant::now();
        let (response, _) = lock(&served).handle(Request::Pause {
            reason: "mid-replay".into(),
        });
        assert!(matches!(response, Response::Paused { .. }), "{response:?}");
        assert!(
            asked.elapsed() < Duration::from_secs(1),
            "the pause did not wait for the replay: {:?}",
            asked.elapsed()
        );
        release.send(()).unwrap();
        let mut reader = BufReader::new(client_end.try_clone().unwrap());
        let mut next = || {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            serde_json::from_str::<Response>(&line).unwrap()
        };
        for seq in 0..5 {
            assert!(matches!(next(), Response::Record(r) if r.seq == seq));
        }
        assert!(matches!(next(), Response::CaughtUp { next_seq: 5 }));
        assert!(matches!(
            next(),
            Response::Record(r) if r.seq == 5 && matches!(r.event, WardEvent::SessionPaused { .. })
        ));
        drop(client_end);
        drop(reader);
        streaming.join().unwrap();
    }
}
