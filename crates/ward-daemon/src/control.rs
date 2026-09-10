//! The session control protocol (ADR-0015): one JSON object per line over the
//! session's Unix socket. `wardd` is the only process that appends to the log;
//! `ward` commands and TamperWard are its clients.
//!
//! [`Sink`] is what a [`Session`](crate::session::Session) writes events through:
//! [`LocalLog`] owns the chain and log directly (no daemon), [`RemoteSink`] sends
//! [`Request::Append`] to a daemon. [`serve_connection`] is the daemon side for the
//! requests a sink needs; the daemon binary adds the rest.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use ward_events::{
    Chain, ChainHead, EndReason, EventRecord, FsyncPolicy, LogWriter, Origin, SessionId, Timestamp,
    WardEvent,
};

use crate::approvals::{Approval, ApprovalDecision, Grant};
use crate::error::{Error, Result};
use crate::hooks::HookDecision;

/// File name of the control socket inside `sessions/<id>/`.
pub const SOCKET_NAME: &str = "control.sock";
/// Client read timeout.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// What a client asks the daemon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "req", rename_all = "snake_case")]
pub enum Request {
    /// Append an event observed by a `ward` command at `at_unix_ms`.
    Append {
        /// Origin the command is entitled to (never `TamperWard`).
        origin: Origin,
        /// The event.
        event: WardEvent,
        /// Capture time, milliseconds since the Unix epoch.
        at_unix_ms: u64,
    },
    /// Append a `TamperWard`-origin evidence record (evidence kinds only).
    Evidence {
        /// The record.
        event: WardEvent,
    },
    /// Flush the log to disk.
    Sync,
    /// Seal the log; the daemon exits afterwards.
    Seal,
    /// End the session on the caller's behalf: `SessionEnded` then seal.
    Stop {
        /// Why.
        reason: EndReason,
    },
    /// The session's immutable facts.
    Describe,
    /// Stream records from `from_seq` until the client disconnects.
    Subscribe {
        /// First sequence number to deliver.
        from_seq: u64,
    },
    /// Liveness.
    Ping,
    /// Hold an `ask` from the hook adapter until the user answers it or
    /// `timeout_secs` pass (ADR-0016): the daemon records the request, lists it
    /// as pending, and answers this connection once with the decision.
    Hold {
        /// The tool the agent wants to use.
        tool: String,
        /// Its target, sanitised.
        summary: String,
        /// Why the hook asks.
        reason: String,
        /// How long to wait before denying.
        timeout_secs: u64,
    },
    /// Answer a pending approval.
    Approve {
        /// The approval's id: the seq of its `CapabilityRequested` record.
        id: u64,
        /// `allow`, `allow-session` or `deny`.
        decision: ApprovalDecision,
    },
    /// The approvals waiting for an answer.
    Pending,
    /// The temporary authority the session holds (ADR-0019): every
    /// `allow-session` answer and every credential the proxy injects.
    Grants,
    /// Pause the session as one operation (ADR-0019 §3): freeze its sandbox
    /// processes, close the proxy to new traffic, suspend credential
    /// injection, hold the approvals, and record `SessionPaused`.
    Pause {
        /// Why, in the user's words (may be empty).
        reason: String,
    },
    /// Reverse a `Pause` and record `SessionResumed`.
    Resume,
}

/// What the daemon answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resp", content = "body", rename_all = "snake_case")]
pub enum Response {
    /// The appended (or streamed) record.
    Record(Box<EventRecord>),
    /// Nothing to return.
    Ok,
    /// The sealed head.
    Sealed {
        /// Chain head after sealing.
        head: ChainHead,
    },
    /// The session description as JSON.
    Description(serde_json::Value),
    /// The request failed; the log is unchanged.
    Error(String),
    /// A held approval was released: what the hook tells the agent.
    Decision {
        /// The approval's id.
        id: u64,
        /// Allow or deny.
        decision: HookDecision,
        /// Why (`approval: timed out`).
        reason: String,
    },
    /// The open approvals, oldest first.
    Pending(Vec<Approval>),
    /// The session's temporary grants, oldest first.
    Grants(Vec<Grant>),
}

/// Where a session's events go.
pub trait Sink: Send {
    /// Append `event` observed at `at`.
    fn append(&mut self, origin: Origin, event: WardEvent, at: SystemTime) -> Result<EventRecord>;
    /// Flush to disk.
    fn sync(&mut self) -> Result<()>;
    /// Seal the log.
    fn seal(self: Box<Self>) -> Result<()>;
    /// End the session: append `SessionEnded { reason }` and seal.
    fn stop(self: Box<Self>, reason: EndReason) -> Result<()>;
}

/// The chain and log in this process (no daemon).
pub struct LocalLog {
    chain: Chain,
    log: LogWriter,
    started: SystemTime,
}

impl LocalLog {
    /// Create a fresh log for `session` whose genesis is `manifest_hash`.
    pub fn create(
        path: &Path,
        session: SessionId,
        manifest_hash: ward_events::Blake3Hash,
        started: SystemTime,
    ) -> Result<Self> {
        let chain = Chain::genesis(session, manifest_hash);
        let log = LogWriter::create(path, chain.head(), FsyncPolicy::DEFAULT)
            .map_err(|e| Error::Events(e.to_string()))?;
        Ok(Self {
            chain,
            log,
            started,
        })
    }

    /// Reopen an existing log and resume its chain.
    pub fn open(path: &Path, started: SystemTime) -> Result<Self> {
        let log = LogWriter::open(path, FsyncPolicy::DEFAULT)
            .map_err(|e| Error::Events(e.to_string()))?;
        let chain = Chain::resume(log.head());
        Ok(Self {
            chain,
            log,
            started,
        })
    }

    /// Sequence number the next record will get.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.chain.head().next_seq
    }

    /// Seal and return the head (the daemon reports it to the client).
    pub fn seal_head(self) -> Result<ChainHead> {
        self.log.seal().map_err(|e| Error::Events(e.to_string()))
    }
}

impl Sink for LocalLog {
    fn append(&mut self, origin: Origin, event: WardEvent, at: SystemTime) -> Result<EventRecord> {
        let record = self
            .chain
            .append(origin, event, ts_at(self.started, at))
            .map_err(|e| Error::Events(e.to_string()))?;
        self.log
            .append(&record)
            .map_err(|e| Error::Events(e.to_string()))?;
        Ok(record)
    }

    fn sync(&mut self) -> Result<()> {
        self.log.sync().map_err(|e| Error::Events(e.to_string()))
    }

    fn seal(self: Box<Self>) -> Result<()> {
        self.seal_head().map(drop)
    }

    fn stop(mut self: Box<Self>, reason: EndReason) -> Result<()> {
        self.append(Origin::Wardd, session_ended(reason), SystemTime::now())?;
        self.seal()
    }
}

/// The record every stop path appends before sealing.
fn session_ended(reason: EndReason) -> WardEvent {
    WardEvent::SessionEnded {
        reason,
        final_snapshot: None,
    }
}

/// What a bounded read ([`RemoteSink::next_within`]) yields.
#[derive(Debug)]
pub enum Next {
    /// A response line.
    Response(Response),
    /// The daemon hung up.
    Closed,
    /// Nothing arrived within the wait.
    Quiet,
}

fn parse_response(line: &str) -> Result<Response> {
    serde_json::from_str(line).map_err(|e| Error::Events(format!("control response: {e}")))
}

/// A client of a running daemon: one connection, one request at a time.
pub struct RemoteSink {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl RemoteSink {
    /// Connect to the socket; `None` when nothing is listening there.
    pub fn connect(socket: &Path) -> Option<Self> {
        let stream = UnixStream::connect(socket).ok()?;
        stream.set_read_timeout(Some(TIMEOUT)).ok()?;
        let writer = stream.try_clone().ok()?;
        let mut sink = Self {
            reader: BufReader::new(stream),
            writer,
        };
        matches!(sink.call(&Request::Ping).ok()?, Response::Ok).then_some(sink)
    }

    /// Send one request and read its first response line.
    pub fn call(&mut self, request: &Request) -> Result<Response> {
        self.send(request)?;
        self.read_response()
    }

    /// Send one request without waiting for its response (a subscriber reads the
    /// stream with [`Self::next_response`]).
    pub fn send(&mut self, request: &Request) -> Result<()> {
        let mut line = serde_json::to_vec(request).map_err(|e| Error::Events(e.to_string()))?;
        line.push(b'\n');
        self.writer
            .write_all(&line)
            .map_err(|e| Error::Sandbox(format!("control socket: {e}")))
    }

    /// Read the next response line (a subscription yields many).
    pub fn read_response(&mut self) -> Result<Response> {
        self.next_response()?
            .ok_or_else(|| Error::Sandbox("control socket closed".into()))
    }

    /// Read the next response line, or `None` once the daemon has hung up (a
    /// subscription ends this way when the log is sealed).
    pub fn next_response(&mut self) -> Result<Option<Response>> {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .map_err(|e| Error::Sandbox(format!("control socket: {e}")))?;
        if n == 0 {
            return Ok(None);
        }
        parse_response(&line).map(Some)
    }

    /// Read the next response line, waiting at most `wait` for it: [`Next::Quiet`]
    /// when the daemon is up but has nothing to say yet, [`Next::Closed`] once it
    /// has hung up. Leaves the read timeout at `wait`. The daemon writes each
    /// response as one `write` of a short line, so a wait that ends mid-line is not
    /// expected; if it did, that line would be lost.
    pub fn next_within(&mut self, wait: Duration) -> Result<Next> {
        self.set_read_timeout(Some(wait))?;
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Ok(Next::Closed),
            Ok(_) => parse_response(&line).map(Next::Response),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(Next::Quiet)
            }
            Err(e) => Err(Error::Sandbox(format!("control socket: {e}"))),
        }
    }

    /// Change the read timeout (`None` waits forever; a subscriber uses this so a
    /// quiet session does not look like a dead daemon).
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.reader
            .get_ref()
            .set_read_timeout(timeout)
            .map_err(|e| Error::Sandbox(format!("control socket: {e}")))
    }
}

impl Sink for RemoteSink {
    fn append(&mut self, origin: Origin, event: WardEvent, at: SystemTime) -> Result<EventRecord> {
        match self.call(&Request::Append {
            origin,
            event,
            at_unix_ms: unix_ms(at),
        })? {
            Response::Record(record) => Ok(*record),
            Response::Error(e) => Err(Error::Events(format!("daemon refused append: {e}"))),
            other => Err(Error::Events(format!("unexpected response {other:?}"))),
        }
    }

    fn sync(&mut self) -> Result<()> {
        expect_ok(self.call(&Request::Sync)?)
    }

    fn seal(mut self: Box<Self>) -> Result<()> {
        expect_sealed(self.call(&Request::Seal)?)
    }

    fn stop(mut self: Box<Self>, reason: EndReason) -> Result<()> {
        expect_sealed(self.call(&Request::Stop { reason })?)
    }
}

fn expect_sealed(response: Response) -> Result<()> {
    match response {
        Response::Sealed { .. } => Ok(()),
        Response::Error(e) => Err(Error::Events(format!("daemon refused seal: {e}"))),
        other => Err(Error::Events(format!("unexpected response {other:?}"))),
    }
}

fn expect_ok(response: Response) -> Result<()> {
    match response {
        Response::Ok => Ok(()),
        Response::Error(e) => Err(Error::Events(e)),
        other => Err(Error::Events(format!("unexpected response {other:?}"))),
    }
}

/// Whether `event` may be appended with `origin = TamperWard` through `Evidence`.
#[must_use]
pub fn is_evidence(event: &WardEvent) -> bool {
    matches!(
        event,
        WardEvent::PolicyDecision { .. }
            | WardEvent::PolicyDenied { .. }
            | WardEvent::TamperDetected { .. }
            | WardEvent::StateAccepted { .. }
    )
}

/// Handle one request against `log`. Returns the response to write, and whether
/// the log was sealed (the caller stops serving afterwards).
pub fn handle(log: &mut Option<LocalLog>, request: Request) -> (Response, bool) {
    handle_with(log, request, |_| {})
}

/// [`handle`] with `appended` called for every record the request appends to the
/// log, including the `SessionEnded` a [`Request::Stop`] writes before sealing;
/// the daemon fans those out to subscribers.
pub fn handle_with(
    log: &mut Option<LocalLog>,
    request: Request,
    mut appended: impl FnMut(&EventRecord),
) -> (Response, bool) {
    let Some(local) = log.as_mut() else {
        return (Response::Error("log is sealed".into()), true);
    };
    let mut append = |origin: Origin, event: WardEvent, at: SystemTime| {
        let record = local.append(origin, event, at)?;
        appended(&record);
        Ok(record)
    };
    let as_response = |r: Result<EventRecord>| match r {
        Ok(record) => Response::Record(Box::new(record)),
        Err(e) => Response::Error(e.to_string()),
    };
    match request {
        Request::Ping => (Response::Ok, false),
        Request::Append {
            origin,
            event,
            at_unix_ms,
        } if origin != Origin::TamperWard => (
            as_response(append(
                origin,
                event,
                UNIX_EPOCH + Duration::from_millis(at_unix_ms),
            )),
            false,
        ),
        Request::Append { .. } => (
            Response::Error("TamperWard origin needs an evidence request".into()),
            false,
        ),
        Request::Evidence { event } if is_evidence(&event) => (
            as_response(append(Origin::TamperWard, event, SystemTime::now())),
            false,
        ),
        Request::Evidence { .. } => (Response::Error("not an evidence kind".into()), false),
        Request::Sync => (
            local
                .sync()
                .map_or_else(|e| Response::Error(e.to_string()), |()| Response::Ok),
            false,
        ),
        Request::Seal => seal(log),
        Request::Stop { reason } => {
            match append(Origin::Wardd, session_ended(reason), SystemTime::now()) {
                Ok(_) => seal(log),
                Err(e) => (Response::Error(e.to_string()), false),
            }
        }
        Request::Describe
        | Request::Subscribe { .. }
        | Request::Hold { .. }
        | Request::Approve { .. }
        | Request::Pending
        | Request::Grants
        | Request::Pause { .. }
        | Request::Resume => (
            Response::Error("not served on this connection".into()),
            false,
        ),
    }
}

fn seal(log: &mut Option<LocalLog>) -> (Response, bool) {
    match log.take().map(LocalLog::seal_head) {
        Some(Ok(head)) => (Response::Sealed { head }, true),
        Some(Err(e)) => (Response::Error(e.to_string()), true),
        None => (Response::Error("log is sealed".into()), true),
    }
}

/// Serve one client connection to completion (the client hangs up or seals).
pub fn serve_connection(stream: UnixStream, log: &mut Option<LocalLog>) {
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        // Cap each request line: a newline-less stream would otherwise grow the
        // buffer without bound (an OOM vector from a same-user client).
        match (&mut reader)
            .take(crate::daemon::MAX_REQUEST_BYTES)
            .read_line(&mut line)
        {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if crate::daemon::request_too_large(&line) {
            let _ = write_response(&mut writer, &Response::Error("request too large".into()));
            return;
        }
        let (response, done) = match serde_json::from_str::<Request>(&line) {
            Ok(request) => handle(log, request),
            Err(e) => (Response::Error(format!("bad request: {e}")), false),
        };
        if write_response(&mut writer, &response).is_err() || done {
            return;
        }
    }
}

/// Write one JSON response line to the client.
fn write_response(writer: &mut UnixStream, response: &Response) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(response).unwrap_or_default();
    bytes.push(b'\n');
    writer.write_all(&bytes)
}

/// Monotonic session time of `at`; anything before the session started is 0.
#[must_use]
pub fn ts_at(started: SystemTime, at: SystemTime) -> Timestamp {
    Timestamp::mono(at.duration_since(started).unwrap_or_default())
}

/// Milliseconds since the Unix epoch, saturating.
#[must_use]
pub fn unix_ms(t: SystemTime) -> u64 {
    u64::try_from(t.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::os::unix::net::UnixListener;
    use ward_events::{AgentState, Blake3Hash, DetailText, LogReader, PolicySubject, RuleRef};

    fn session() -> SessionId {
        SessionId::from_u128(7)
    }

    fn fresh(dir: &Path) -> LocalLog {
        LocalLog::create(
            &dir.join("events.log"),
            session(),
            Blake3Hash::from_bytes([1; 32]),
            SystemTime::now(),
        )
        .unwrap()
    }

    fn working() -> WardEvent {
        WardEvent::AgentStateChanged {
            state: AgentState::Working,
        }
    }

    fn denied() -> WardEvent {
        WardEvent::PolicyDenied {
            subject: PolicySubject::ProtectedTests,
            rule: RuleRef::new("tests").unwrap(),
            detail: DetailText::new("tests/x.rs"),
        }
    }

    #[test]
    fn ts_at_keeps_capture_time_and_clamps_before_start() {
        let started = SystemTime::now();
        assert_eq!(
            ts_at(started, started + Duration::from_secs(5)).mono,
            Duration::from_secs(5)
        );
        assert_eq!(
            ts_at(started, started - Duration::from_secs(1)).mono,
            Duration::ZERO
        );
    }

    #[test]
    fn requests_and_responses_round_trip_as_json_lines() {
        let req = Request::Append {
            origin: Origin::Kernel,
            event: working(),
            at_unix_ms: 5,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.starts_with(r#"{"req":"append""#), "{json}");
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), req);
        let resp = Response::Error("x".into());
        assert_eq!(
            serde_json::from_str::<Response>(&serde_json::to_string(&resp).unwrap()).unwrap(),
            resp
        );
    }

    #[test]
    fn approval_requests_and_responses_round_trip_with_their_words() {
        let hold = Request::Hold {
            tool: "Write".into(),
            summary: "/work/src/lib.rs".into(),
            reason: "step-through: pause before writes".into(),
            timeout_secs: 60,
        };
        let json = serde_json::to_string(&hold).unwrap();
        assert!(
            json.starts_with(r#"{"req":"hold","tool":"Write""#),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), hold);
        let approve = Request::Approve {
            id: 7,
            decision: ApprovalDecision::AllowSession,
        };
        let json = serde_json::to_string(&approve).unwrap();
        assert_eq!(
            json,
            r#"{"req":"approve","id":7,"decision":"allow-session"}"#
        );
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), approve);
        assert_eq!(
            serde_json::to_string(&Request::Pending).unwrap(),
            r#"{"req":"pending"}"#
        );
        let decision = Response::Decision {
            id: 7,
            decision: HookDecision::Deny,
            reason: "approval: timed out".into(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        assert_eq!(
            json,
            r#"{"resp":"decision","body":{"id":7,"decision":"deny","reason":"approval: timed out"}}"#
        );
        assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), decision);
        let pending = Response::Pending(vec![Approval::new(
            7,
            "Write",
            "/work/src/lib.rs",
            crate::approvals::Authority::none("r", "/work/src/lib.rs"),
            5,
        )]);
        let json = serde_json::to_string(&pending).unwrap();
        assert!(json.contains(r#""requested_at_unix_ms":5"#), "{json}");
        assert!(
            json.contains(r#""claim":"Write /work/src/lib.rs""#),
            "the agent's words travel as the claim: {json}"
        );
        assert!(
            json.contains(r#""authority":{"rule":"r","destination":"/work/src/lib.rs","network":"none","method":"none","credential":"none","repository":null,"lifetime":null}"#),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), pending);
        assert_eq!(
            serde_json::to_string(&Request::Grants).unwrap(),
            r#"{"req":"grants"}"#
        );
        let grants = Response::Grants(vec![Grant {
            kind: crate::approvals::GrantKind::Credential,
            label: "GitHub".into(),
            scope: "contents:read · github.com".into(),
            lifetime: crate::approvals::Lifetime::Launch,
            granted_at_unix_ms: 9,
        }]);
        let json = serde_json::to_string(&grants).unwrap();
        assert_eq!(
            json,
            r#"{"resp":"grants","body":[{"kind":"credential","label":"GitHub","scope":"contents:read · github.com","lifetime":"launch","granted_at_unix_ms":9}]}"#
        );
        assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), grants);
        // Pause and resume are the daemon's; they round-trip as their words.
        let pause = Request::Pause {
            reason: "looks wrong".into(),
        };
        assert_eq!(
            serde_json::to_string(&pause).unwrap(),
            r#"{"req":"pause","reason":"looks wrong"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::Resume).unwrap(),
            r#"{"req":"resume"}"#
        );
        // A plain log connection does not hold or answer approvals, list grants, or pause.
        let dir = tempfile::tempdir().unwrap();
        let mut log = Some(fresh(dir.path()));
        for request in [
            hold,
            approve,
            Request::Pending,
            Request::Grants,
            pause,
            Request::Resume,
        ] {
            assert!(matches!(
                handle(&mut log, request).0,
                Response::Error(e) if e == "not served on this connection"
            ));
        }
    }

    #[test]
    fn handle_enforces_origins_and_seals_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = Some(fresh(dir.path()));
        let forged = Request::Append {
            origin: Origin::TamperWard,
            event: working(),
            at_unix_ms: 0,
        };
        assert!(matches!(handle(&mut log, forged).0, Response::Error(_)));
        let not_evidence = Request::Evidence { event: working() };
        assert!(matches!(
            handle(&mut log, not_evidence).0,
            Response::Error(_)
        ));
        let (r, done) = handle(&mut log, Request::Evidence { event: denied() });
        assert!(!done);
        match r {
            Response::Record(rec) => assert_eq!(rec.origin, Origin::TamperWard),
            other => panic!("{other:?}"),
        }
        let (r, done) = handle(
            &mut log,
            Request::Stop {
                reason: EndReason::UserStop,
            },
        );
        assert!(done);
        assert!(matches!(r, Response::Sealed { head } if head.next_seq == 2));
        assert!(matches!(
            handle(&mut log, Request::Ping).0,
            Response::Error(_)
        ));
    }

    #[test]
    fn remote_sink_appends_through_a_served_connection() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        let mut log = Some(fresh(dir.path()));
        let log_path = dir.path().join("events.log");
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_connection(stream, &mut log);
            log.is_none()
        });

        let mut sink: Box<dyn Sink> = Box::new(RemoteSink::connect(&socket).expect("daemon"));
        let at = SystemTime::now() + Duration::from_secs(3);
        let rec = sink.append(Origin::Wardd, working(), at).unwrap();
        assert_eq!(rec.seq, 0);
        assert!(
            rec.ts_mono >= Duration::from_secs(2),
            "capture time is kept"
        );
        sink.sync().unwrap();
        sink.seal().unwrap();
        assert!(server.join().unwrap(), "seal drops the log");

        let records: Vec<_> = LogReader::open(&log_path)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert_eq!(records.len(), 1);
        assert!(
            RemoteSink::connect(&socket).is_none(),
            "nothing listens after seal"
        );
    }
}
