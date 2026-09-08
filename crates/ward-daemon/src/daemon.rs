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
//! `ward up` starts the daemon with [`spawn`] and `ward status` asks [`serving`];
//! every other command adopts the socket through
//! [`Session::open_current`](crate::session::Session::open_current).

use std::io::{BufRead, BufReader, Write};
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

use ward_events::{EventRecord, LogReader, Origin, WardEvent};

use crate::approvals::{self, Approval, Approvals, Outcome};
use crate::control::{self, LocalLog, RemoteSink, Request, Response, SOCKET_NAME};
use crate::error::{Error, Result};
use crate::session::{SessionMeta, session_dir};

/// File name of the daemon's pid file inside `sessions/<id>/`.
pub const PID_NAME: &str = "wardd.pid";
/// How long `ward up` waits for a spawned daemon to answer.
pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(2);
/// Name of the daemon binary.
pub const BINARY: &str = "wardd";
/// Longest socket path Linux accepts (`sun_path` is 108 bytes with the NUL).
pub const MAX_SOCKET_PATH: usize = 107;

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

/// The newest session under `state` whose daemon answers: the desktop's
/// session when it is asked from somewhere that is not a project (the bar,
/// the approval listener). Sessions whose record cannot be read are skipped.
pub fn newest_live(state: &Path) -> Result<Option<SessionMeta>> {
    let sessions = state.join("sessions");
    let entries = match std::fs::read_dir(&sessions) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io(&sessions, e)),
    };
    let mut newest: Option<SessionMeta> = None;
    for entry in entries.flatten() {
        let id = entry.file_name().to_string_lossy().into_owned();
        let Ok(meta) = SessionMeta::load(state, &id) else {
            continue;
        };
        if newest
            .as_ref()
            .is_some_and(|n| n.started_unix_ms >= meta.started_unix_ms)
            || !serving(state, &id)
        {
            continue;
        }
        newest = Some(meta);
    }
    Ok(newest)
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
    let log = LocalLog::open(&log_path, started)?;
    let description = serde_json::to_value(meta.describe())
        .map_err(|e| Error::Daemon(format!("describe {session}: {e}")))?;

    let socket = dir.join(SOCKET_NAME);
    let listener = bind_socket(&socket)?;
    let bound_inode = std::fs::metadata(&socket).map(|m| m.ino()).ok();
    let pid_file = dir.join(PID_NAME);
    std::fs::write(&pid_file, format!("{}\n", std::process::id()))
        .map_err(|e| Error::io(&pid_file, e))?;

    let served = Arc::new(Mutex::new(Served::new(log, log_path, description)));
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
            let sealed = serve_stream(stream, &served);
            lock(&served).peers.retain(|(id, _)| *id != peer);
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

/// The daemon's shared state: the log, the session facts, the subscribers, the
/// open connections, and the approvals it holds.
struct Served {
    log: Option<LocalLog>,
    log_path: PathBuf,
    description: serde_json::Value,
    subscribers: Vec<Sender<Delivery>>,
    peers: Vec<(u64, UnixStream)>,
    approvals: Arc<Approvals>,
}

impl Served {
    fn new(log: LocalLog, log_path: PathBuf, description: serde_json::Value) -> Self {
        Self {
            log: Some(log),
            log_path,
            description,
            subscribers: Vec::new(),
            peers: Vec::new(),
            approvals: Arc::new(Approvals::new()),
        }
    }

    /// Apply one request. Appended records are fanned out to every subscriber;
    /// a subscriber whose channel is gone is dropped. Returns the response and
    /// whether the log is now sealed.
    fn handle(&mut self, request: Request) -> (Response, bool) {
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
            other => {
                let subscribers = &mut self.subscribers;
                let (response, done) = control::handle_with(&mut self.log, other, |record| {
                    subscribers
                        .retain(|s| s.send(Delivery::Record(Box::new(record.clone()))).is_ok());
                });
                if done {
                    for s in self.subscribers.drain(..) {
                        let _ = s.send(Delivery::End);
                    }
                    // A question still open when the log seals is released as
                    // denied; no record of it can follow the seal.
                    self.approvals.close();
                }
                (response, done)
            }
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
            Response::Record(record) => Ok(*record),
            Response::Error(e) => Err(Error::Daemon(e)),
            other => Err(Error::Daemon(format!("unexpected response {other:?}"))),
        }
    }

    /// Register a question: the `CapabilityRequested` record is appended and
    /// its seq becomes the approval's id, in one step under the mutex so a
    /// subscriber that sees the record can already answer it. A standing
    /// `allow-session` answers it at once.
    fn hold(&mut self, tool: &str, summary: &str, reason: &str) -> Result<(u64, Option<Outcome>)> {
        let record = self.append(approvals::requested_event(tool, summary, reason))?;
        if self.approvals.remembered(tool, summary) {
            return Ok((record.seq, Some(Outcome::Remembered)));
        }
        self.approvals.register(Approval {
            id: record.seq,
            tool: tool.to_owned(),
            summary: summary.to_owned(),
            reason: reason.to_owned(),
            requested_at_unix_ms: control::unix_ms(SystemTime::now()),
        })?;
        Ok((record.seq, None))
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
fn serve_stream(stream: UnixStream, served: &Arc<Mutex<Served>>) -> bool {
    let Ok(mut writer) = stream.try_clone() else {
        return false;
    };
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return false,
            Ok(_) => {}
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
            Ok(request) => lock(served).handle(request),
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
    let (id, approvals, remembered) = {
        let mut s = lock(served);
        match s.hold(tool, summary, reason) {
            Ok((id, remembered)) => (id, Arc::clone(&s.approvals), remembered),
            Err(e) => return Response::Error(refusal(e)),
        }
    };
    let outcome =
        remembered.unwrap_or_else(|| approvals.wait(id, Duration::from_secs(timeout_secs)));
    if let Some(event) = approvals::decided_event(tool, summary, outcome) {
        // The log may have sealed meanwhile; the agent still gets its answer.
        let _ = lock(served).append(event);
    }
    let response = outcome.response();
    Response::Decision {
        id,
        decision: response.decision,
        reason: response.reason,
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
    for record in subscription.replay {
        if write_line(&mut writer, &Response::Record(Box::new(record))).is_err() {
            return;
        }
    }
    let Some((live, hangup)) = subscription.live else {
        return;
    };
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
        let log_path = dir.join("events.log");
        let log = LocalLog::create(
            &log_path,
            SessionId::from_u128(9),
            Blake3Hash::from_bytes([2; 32]),
            SystemTime::now(),
        )
        .unwrap();
        Served::new(log, log_path, serde_json::json!({"session": "sess_9"}))
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
        assert!(matches!(response, Response::Sealed { head } if head.next_seq == 6));
        let (tail, ended) = drain(&rx);
        assert_eq!(seqs(&tail), [5]);
        assert!(matches!(tail[0].event, WardEvent::SessionEnded { .. }));
        assert!(ended, "sealing ends every subscription");
        assert!(served.subscribers.is_empty());

        // After the seal a subscription is the replay alone.
        let after = served.subscribe(4).unwrap();
        assert_eq!(seqs(&after.replay), [4, 5]);
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

        // Sealing releases an open question as denied and records nothing more.
        let holding = {
            let served = Arc::clone(&served);
            std::thread::spawn(move || hold(&served, "Write", "/work/x.rs", "r", 5))
        };
        assert!(wait_until(Duration::from_secs(2), || {
            !lock(&served).approvals.pending().is_empty()
        }));
        let (response, done) = lock(&served).handle(Request::Stop {
            reason: EndReason::UserStop,
        });
        assert!(done, "{response:?}");
        assert!(matches!(
            holding.join().unwrap(),
            Response::Decision { decision: HookDecision::Deny, reason, .. }
                if reason == "approval: session ended"
        ));
        assert!(matches!(
            hold(&served, "Write", "/work/y.rs", "r", 5),
            Response::Error(e) if e == "log is sealed"
        ));
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
            Response::Sealed { head } if head.next_seq == 4
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
        let mut seen = vec![0];
        while let Ok(Response::Record(r)) = subscriber.read_response() {
            seen.push(r.seq);
        }
        assert_eq!(seen, [0, 1, 2, 3]);
        let head = LogReader::open(&log_path).unwrap().verify_all().unwrap();
        assert_eq!(head.next_seq, 4);
        assert!(
            RemoteSink::connect(&socket).is_none(),
            "nothing answers after exit"
        );
    }
}
