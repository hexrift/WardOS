//! The session control protocol (ADR-0015): one JSON object per line over the
//! session's Unix socket. `wardd` is the only process that appends to the log;
//! `ward` commands and TamperWard are its clients.
//!
//! [`Sink`] is what a [`Session`](crate::session::Session) writes events through:
//! [`LocalLog`] owns the chain and log directly (no daemon), [`RemoteSink`] sends
//! [`Request::Append`] to a daemon. [`serve_connection`] is the daemon side for the
//! requests a sink needs; the daemon binary adds the rest.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use ward_events::{
    Chain, ChainHead, EndReason, EventRecord, FsyncPolicy, LogWriter, Origin, SessionId, Timestamp,
    WardEvent,
};

use crate::error::{Error, Result};

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
}

/// Where a session's events go.
pub trait Sink: Send {
    /// Append `event` observed at `at`.
    fn append(&mut self, origin: Origin, event: WardEvent, at: SystemTime) -> Result<EventRecord>;
    /// Flush to disk.
    fn sync(&mut self) -> Result<()>;
    /// Seal the log.
    fn seal(self: Box<Self>) -> Result<()>;
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
        serde_json::from_str(&line)
            .map(Some)
            .map_err(|e| Error::Events(format!("control response: {e}")))
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
        match self.call(&Request::Seal)? {
            Response::Sealed { .. } => Ok(()),
            Response::Error(e) => Err(Error::Events(format!("daemon refused seal: {e}"))),
            other => Err(Error::Events(format!("unexpected response {other:?}"))),
        }
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
    let Some(local) = log.as_mut() else {
        return (Response::Error("log is sealed".into()), true);
    };
    let appended = |r: Result<EventRecord>| match r {
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
            appended(local.append(
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
            appended(local.append(Origin::TamperWard, event, SystemTime::now())),
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
            let ended = local.append(
                Origin::Wardd,
                WardEvent::SessionEnded {
                    reason,
                    final_snapshot: None,
                },
                SystemTime::now(),
            );
            match ended {
                Ok(_) => seal(log),
                Err(e) => (Response::Error(e.to_string()), false),
            }
        }
        Request::Describe | Request::Subscribe { .. } => (
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
    for line in BufReader::new(stream)
        .lines()
        .map_while(std::result::Result::ok)
    {
        let (response, done) = match serde_json::from_str::<Request>(&line) {
            Ok(request) => handle(log, request),
            Err(e) => (Response::Error(format!("bad request: {e}")), false),
        };
        let Ok(mut bytes) = serde_json::to_vec(&response) else {
            return;
        };
        bytes.push(b'\n');
        if writer.write_all(&bytes).is_err() || done {
            return;
        }
    }
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
