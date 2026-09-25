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

use crate::approvals::{Approval, ApprovalDecision, ApprovalRecord, Grant};
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
    /// Seal the log; the daemon exits afterwards. Log-only closure: a sandbox of
    /// the session that is still running is not touched (a paused one's frozen
    /// tree is killed rather than left stopped for ever). Ending the session's
    /// workloads is [`Request::Stop`].
    Seal,
    /// End the session on the caller's behalf (#145 item 5): write the stop
    /// marker (no launch is admitted from here on), terminate every sandboxed
    /// process of the session and confirm it is gone (`pause::terminate`,
    /// recorded as `WorkloadsTerminated` when there was anything to end), record
    /// the agent `Finished` (unless the client already did), give every open
    /// approval its terminal record, then `SessionEnded` and seal; answered
    /// `Sealed { ended: Some(n) }`. Refused, with the log left unsealed and the
    /// session held for the stop, when termination could not be confirmed.
    ///
    /// A daemon that predates this (0.18) also accepts `Stop`, but only seals:
    /// a client checks [`FEATURE_STOP_TERMINATES`] first
    /// ([`RemoteSink::require`]) and never sends it otherwise.
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
    /// Every approval this session has asked, pending or decided, within the
    /// daemon's bounded history (`ward session approvals`, #146 item 1): the
    /// authoritative account a client can still read after missing or
    /// dismissing whatever first announced a request.
    Approvals,
    /// The temporary authority the session holds (ADR-0019): every
    /// `allow-session` answer and every credential the proxy injects.
    Grants,
    /// Remove one grant from live authority, by the id [`Response::Grants`]
    /// listed it under (#140 items 4-6, #245: host-confirmed for a
    /// credential). An `allow-session` answer is forgotten immediately, so
    /// the same tool on the same target asks again — it has no proxy route
    /// to wait on. A credential grant is instead marked `revoking`
    /// (surfaced in `Response::Grants` while this is in flight) while the
    /// daemon instructs the owning proxy to withdraw the route and waits for
    /// its acknowledgement (`crate::revoke`), bounded by
    /// `crate::revoke::ACK_TIMEOUT`; see [`Response::Revoked`] for the
    /// possible outcomes. Refused when `id` names no live grant. Served on
    /// its own connection (like [`Request::Hold`]), since the wait can take
    /// up to that bound.
    Revoke {
        /// The grant's id, as `ward session grants` lists it.
        id: u64,
    },
    /// Pause the session as one operation (ADR-0019 §3): freeze its sandbox
    /// processes, close the proxy to new traffic, suspend credential
    /// injection, hold the approvals, and record `SessionPaused`.
    Pause {
        /// Why, in the user's words (may be empty).
        reason: String,
    },
    /// Reverse a `Pause` and record `SessionResumed`. Refused while the session
    /// is held for a stop ([`Request::HoldForStop`], or a refused
    /// [`Request::Stop`]): only a stop (or a log-only `Seal`) ends that hold.
    Resume,
    /// Which protocol features this daemon implements (PR #253 review finding
    /// 1): answered with [`Response::Capabilities`]. A daemon that predates the
    /// request rejects it as a bad request, which a client reads as "none" —
    /// so a client that needs a feature ([`FEATURE_STOP_TERMINATES`],
    /// [`FEATURE_STOP_HOLD`]) fails closed instead of trusting an older
    /// daemon's different semantics for a request of the same name.
    Capabilities,
    /// Make the session quiescent for a stop and keep it so until that stop
    /// (`ward stop --restore-entry`, PR #253 review finding 3): the daemon
    /// freezes the sandboxes itself — never trusting an on-disk marker a
    /// restarted daemon did not write — or takes over a pause already in
    /// force, writes the marker and the stop marker (no launch is admitted
    /// from here on), holds the approvals, and records `SessionPaused` if it
    /// was not paused. The hold cannot be released by `Resume`; the stop that
    /// follows terminates exactly what it holds.
    HoldForStop {
        /// Why (recorded on the `SessionPaused` a fresh hold appends).
        reason: String,
    },
}

/// [`Request::Capabilities`] feature: `Request::Stop` terminates the session's
/// sandboxed workloads and confirms them gone before it seals, and says so in
/// [`Response::Sealed`]'s `ended` (#145 item 5).
pub const FEATURE_STOP_TERMINATES: &str = "stop-terminates-workloads";
/// [`Request::Capabilities`] feature: [`Request::HoldForStop`] is served.
pub const FEATURE_STOP_HOLD: &str = "stop-hold";

/// What the daemon answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resp", content = "body", rename_all = "snake_case")]
pub enum Response {
    /// The appended (or streamed) record.
    Record(Box<EventRecord>),
    /// A `Pause` request answered: the `SessionPaused` record, and — only when the
    /// freeze could not be confirmed settled within `pause::FREEZE_SETTLE` (the
    /// `SIGSTOP` fallback path; the cgroup freezer is synchronous) — how many
    /// processes had not yet confirmed stopped. A `Response::Record` on the same
    /// request would read identically whether or not the freeze was confirmed,
    /// which is exactly the unqualified-success shape #145 item 4 asks not to show.
    Paused {
        /// The `SessionPaused` record.
        record: Box<EventRecord>,
        /// `Some(pending)` when the freeze could not be confirmed within the bound;
        /// `None` on a clean, confirmed pause (today's only outcome for the cgroup
        /// freezer, and the common case for the signal path).
        unsettled: Option<u32>,
    },
    /// Nothing to return.
    Ok,
    /// The sealed head.
    Sealed {
        /// Chain head after sealing.
        head: ChainHead,
        /// For a `Stop`: the daemon's positive acknowledgement that it
        /// terminated the session's sandboxed processes and confirmed them gone
        /// before sealing, and how many there were (`Some(0)` when nothing ran;
        /// #145 item 5). `None` — absent on the wire — for a `Seal`, and for
        /// any daemon that predates confirmed stop: a client must never read
        /// its absence as "zero ended" (PR #253 review finding 1).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ended: Option<u32>,
    },
    /// A [`Request::Capabilities`] answer: the features this daemon serves.
    Capabilities {
        /// Feature names ([`FEATURE_STOP_TERMINATES`], [`FEATURE_STOP_HOLD`]).
        features: Vec<String>,
    },
    /// A [`Request::HoldForStop`] answered: the session is held for its stop.
    HeldForStop {
        /// `Some(pending)` when the freeze could not be confirmed stable
        /// within `pause::FREEZE_SETTLE` (the hold still stands); `None` when
        /// every process is confirmed stopped and none can fork.
        unsettled: Option<u32>,
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
    /// A `Subscribe` stream's replay-complete marker (#138 item 1): every
    /// record up to (not including) `next_seq` has now been sent on this
    /// connection. Sent exactly once per subscription, right after the last
    /// replay record (or immediately, if the replay set was empty) and
    /// before any live record — the boundary the daemon itself fixed
    /// atomically when the subscription began, alongside the mutex that
    /// serializes every append (`daemon::Served::subscribe`). A client waits
    /// for this instead of a silence timeout, so continuous live traffic
    /// can no longer delay it indefinitely.
    CaughtUp {
        /// The sequence the next record delivered on this connection — replay
        /// or live — will have.
        next_seq: u64,
    },
    /// The open approvals, oldest first.
    Pending(Vec<Approval>),
    /// Every approval `Request::Approvals` asked for, oldest requested first.
    Approvals(Vec<ApprovalRecord>),
    /// The session's temporary grants, oldest first.
    Grants(Vec<Grant>),
    /// A `CredentialGranted` append answered (#245): the record, and the
    /// grant id `crate::approvals::Approvals::record_credential` minted (or
    /// already had) for it. The one client that appended it uses this id to
    /// tag its own `GatewayRoute` (`GatewayRoute::revocable`) so a later
    /// `ward session revoke` can reach that exact route. Every other append
    /// still answers with a plain [`Response::Record`].
    Granted {
        /// The `CredentialGranted` record.
        record: Box<EventRecord>,
        /// The grant id.
        grant_id: u64,
    },
    /// `Request::Revoke` answered (#245): what actually happened to the
    /// grant, not merely that the authority projection changed.
    Revoked(crate::approvals::RevokeOutcome),
}

/// Where a session's events go.
pub trait Sink: Send {
    /// Append `event` observed at `at`.
    fn append(&mut self, origin: Origin, event: WardEvent, at: SystemTime) -> Result<EventRecord>;
    /// Flush to disk.
    fn sync(&mut self) -> Result<()>;
    /// Seal the log.
    fn seal(self: Box<Self>) -> Result<()>;
    /// End the session: append `SessionEnded { reason }` and seal. Returns how
    /// many sandboxed processes the other end terminated first (#145 item 5):
    /// always 0 from a sink that does not end workloads itself (see
    /// [`ends_workloads`](Self::ends_workloads)). [`RemoteSink`] fails closed
    /// unless its daemon both advertises and acknowledges the termination.
    fn stop(self: Box<Self>, reason: EndReason) -> Result<u32>;
    /// Whether [`stop`](Self::stop) itself terminates the session's sandboxed
    /// workloads before sealing: true for [`RemoteSink`], whose daemon does it as
    /// part of `Request::Stop` (and holds the pause state it needs); false
    /// otherwise, where [`Session::stop`](crate::session::Session::stop) does it
    /// in-process first.
    fn ends_workloads(&self) -> bool {
        false
    }
    /// [`append`](Self::append) a `CredentialGranted` event, also returning
    /// the grant id the daemon recorded it under, when there is a daemon to
    /// mint one (#245): the caller (`Session::launch`) tags the
    /// `GatewayRoute` it built for this exact grant with that id
    /// (`GatewayRoute::revocable`), the one thing that lets a later `ward
    /// session revoke <id>` reach this route in what is, from the daemon's
    /// point of view, a different process entirely.
    ///
    /// The default falls back to plain [`append`](Self::append) and answers
    /// `None`: [`LocalLog`] has no `Approvals` to mint an id from at all (no
    /// daemon is running, so `ward session revoke` could never reach this
    /// process either), and every other event this trait ever appends has no
    /// grant id to report, so only [`RemoteSink`] needs to override this.
    fn append_credential(
        &mut self,
        origin: Origin,
        event: WardEvent,
        at: SystemTime,
    ) -> Result<(EventRecord, Option<u64>)> {
        self.append(origin, event, at).map(|record| (record, None))
    }

    /// Re-read this sink's view of the chain from durable storage, discarding any
    /// cached head that may now be behind what is actually on disk (review 5283028228
    /// of #208, finding 4, `crate::attempt::reconcile_dangling_attempts`): a
    /// [`LocalLog`] caches its `Chain` in memory from the moment it is opened, so two
    /// independently-opened `LocalLog`s on the same session log can each believe they
    /// own the true head even after one of them has appended — exactly the divergence
    /// that would duplicate a sequence number or break the hash-predecessor chain if
    /// left unchecked. [`RemoteSink`] never caches any chain state locally (every
    /// append is computed by the daemon's own single, already-serialized `Chain`), so
    /// it has nothing to refresh and keeps this default no-op.
    fn resync(&mut self) -> Result<()> {
        Ok(())
    }
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

    fn stop(mut self: Box<Self>, reason: EndReason) -> Result<u32> {
        self.append(Origin::Wardd, session_ended(reason), SystemTime::now())?;
        self.seal().map(|()| 0)
    }

    fn resync(&mut self) -> Result<()> {
        let path = self.log.path().to_path_buf();
        // A log with nothing appended to it yet has nothing on disk that could have
        // diverged from this sink's own in-memory genesis-only head — and
        // `LogWriter::open` cannot even bootstrap a chain head from zero records (it
        // is only ever taken from the first record's own `prev`), so this is the one
        // case reopening is skipped rather than attempted. Only one caller can ever
        // win `LocalLog::create`'s own `create_new`, so a file still empty here means
        // no rival has appended anything either.
        let empty = std::fs::metadata(&path)
            .map(|m| m.len() == 0)
            .unwrap_or(false);
        if empty {
            return Ok(());
        }
        // Otherwise reopen in place: re-reads and re-verifies the whole log to recover
        // the true current head, exactly as `Self::open` does — the same cost this
        // session already pays every time a fresh `ward` command opens it, just paid
        // again here so a pass that started with a stale view never appends against it
        // (finding 4).
        *self = Self::open(&path, self.started)?;
        Ok(())
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

    /// A duplicate file descriptor of this sink's underlying socket, sharing
    /// the same kernel connection [`Self::next_response`]/[`Self::next_within`]
    /// read from (review 5284703397 of #210, finding 2): `UnixStream::shutdown`
    /// acts on the socket itself, not on any one fd referencing it, so calling
    /// it on this clone from another thread unblocks a read pending on
    /// *this* sink right now — including one with no read timeout set at all
    /// — with an immediate `Ok(0)`/EOF, the same shape a blocked read already
    /// gets when the daemon on the other end hangs up on its own.
    /// [`follow_pending_all`](crate::client::follow_pending_all) uses this to
    /// give its watcher threads a way to be told "stop" that a quiet,
    /// unbounded `next_response` actually observes.
    pub fn try_clone_socket(&self) -> Result<UnixStream> {
        self.writer
            .try_clone()
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

    fn append_credential(
        &mut self,
        origin: Origin,
        event: WardEvent,
        at: SystemTime,
    ) -> Result<(EventRecord, Option<u64>)> {
        match self.call(&Request::Append {
            origin,
            event,
            at_unix_ms: unix_ms(at),
        })? {
            Response::Granted { record, grant_id } => Ok((*record, Some(grant_id))),
            // A daemon that never learned about this credential grant (an
            // older `wardd`, or an event `handle_appendable` did not
            // recognise as a `CredentialGranted`) still appended it: no id
            // to tag the route with, but the record itself is real.
            Response::Record(record) => Ok((*record, None)),
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

    /// PR #253 review finding 1: `Request::Stop` exists on older daemons too,
    /// where it only appends `SessionEnded` and seals. So the daemon is asked
    /// first ([`RemoteSink::require`]) whether its stop terminates the
    /// workloads, and nothing is sent unless it says so; and the answer must
    /// then positively acknowledge the termination (`Sealed { ended: Some }`).
    fn stop(mut self: Box<Self>, reason: EndReason) -> Result<u32> {
        self.require(FEATURE_STOP_TERMINATES, "nothing was sealed")?;
        match self.call(&Request::Stop { reason })? {
            Response::Sealed {
                ended: Some(ended), ..
            } => Ok(ended),
            Response::Sealed { ended: None, .. } => Err(Error::Daemon(
                "the session daemon sealed the log without confirming the session's \
                 sandboxed processes were terminated; a sandbox of it may still be running"
                    .into(),
            )),
            // The daemon's own words: a refused stop says exactly what it could
            // not confirm and what state it left the session in.
            Response::Error(e) => Err(Error::Daemon(e)),
            other => Err(Error::Events(format!("unexpected response {other:?}"))),
        }
    }

    fn ends_workloads(&self) -> bool {
        true
    }
}

impl RemoteSink {
    /// The features the daemon on the other end serves ([`Request::Capabilities`]).
    /// A daemon that predates the request answers it with an error (it cannot
    /// parse it) and serves none of them; that is `Ok(vec![])`, not a failure.
    pub fn capabilities(&mut self) -> Result<Vec<String>> {
        match self.call(&Request::Capabilities)? {
            Response::Capabilities { features } => Ok(features),
            Response::Error(_) => Ok(Vec::new()),
            other => Err(Error::Events(format!("unexpected response {other:?}"))),
        }
    }

    /// Fail closed unless the daemon serves `feature` (PR #253 review finding
    /// 1). `nothing_done` finishes the refusal: what the caller did not do
    /// because of it.
    pub fn require(&mut self, feature: &str, nothing_done: &str) -> Result<()> {
        if self.capabilities()?.iter().any(|f| f == feature) {
            return Ok(());
        }
        Err(Error::Daemon(format!(
            "the session daemon does not serve `{feature}` (it predates this ward), so it \
             cannot confirm the session's sandboxed processes are terminated; {nothing_done}. \
             End that daemon (its pid is in the session's `{}`) and run the command again: \
             with no daemon serving, ward terminates the workloads itself",
            crate::daemon::PID_NAME
        )))
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
        | Request::Approvals
        | Request::Grants
        | Request::Revoke { .. }
        | Request::Pause { .. }
        | Request::Resume
        // A plain log connection neither terminates workloads on `Stop` nor
        // holds one: it serves no feature, exactly like an older daemon.
        | Request::Capabilities
        | Request::HoldForStop { .. } => (
            Response::Error("not served on this connection".into()),
            false,
        ),
    }
}

fn seal(log: &mut Option<LocalLog>) -> (Response, bool) {
    match log.take().map(LocalLog::seal_head) {
        Some(Ok(head)) => (Response::Sealed { head, ended: None }, true),
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
    #[allow(clippy::too_many_lines)]
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
            serde_json::to_string(&Request::Approvals).unwrap(),
            r#"{"req":"approvals"}"#
        );
        let approvals = Response::Approvals(vec![
            crate::approvals::ApprovalRecord {
                approval: Approval::new(
                    7,
                    "Write",
                    "/work/src/lib.rs",
                    crate::approvals::Authority::none("r", "/work/src/lib.rs"),
                    5,
                ),
                outcome: None,
                decided_at_unix_ms: None,
            },
            crate::approvals::ApprovalRecord {
                approval: Approval::new(
                    8,
                    "WebFetch",
                    "example.org",
                    crate::approvals::Authority::none("r", "example.org"),
                    6,
                ),
                outcome: Some(crate::approvals::Outcome::TimedOut),
                decided_at_unix_ms: Some(66),
            },
        ]);
        let json = serde_json::to_string(&approvals).unwrap();
        assert!(json.contains(r#""outcome":null"#), "{json}");
        assert!(json.contains(r#""outcome":"timed-out""#), "{json}");
        assert!(json.contains(r#""decided_at_unix_ms":66"#), "{json}");
        assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), approvals);
        assert_eq!(
            serde_json::to_string(&Request::Grants).unwrap(),
            r#"{"req":"grants"}"#
        );
        let base_grant = Grant {
            id: 3,
            kind: crate::approvals::GrantKind::Credential,
            label: "GitHub".into(),
            scope: "contents:read · github.com".into(),
            lifetime: crate::approvals::Lifetime::Launch,
            granted_at_unix_ms: 9,
            revoke_state: crate::approvals::RevokeState::Active,
        };
        let grants = Response::Grants(vec![base_grant.clone()]);
        let json = serde_json::to_string(&grants).unwrap();
        assert_eq!(
            json,
            r#"{"resp":"grants","body":[{"id":3,"kind":"credential","label":"GitHub","scope":"contents:read · github.com","lifetime":"launch","granted_at_unix_ms":9,"revoke_state":"active"}]}"#
        );
        assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), grants);
        // A grant listed while its revoke is still pending, or came back
        // unconfirmed (#245): both round-trip, and `Grant::line` names the
        // state so a plain-text list shows it too.
        let revoking = Grant {
            revoke_state: crate::approvals::RevokeState::Revoking,
            ..base_grant.clone()
        };
        assert!(
            revoking.line().ends_with("   revoking"),
            "{}",
            revoking.line()
        );
        let unconfirmed = Grant {
            revoke_state: crate::approvals::RevokeState::Unconfirmed,
            ..base_grant
        };
        assert!(
            unconfirmed.line().ends_with("   revoke unconfirmed"),
            "{}",
            unconfirmed.line()
        );
        let json = serde_json::to_string(&Response::Grants(vec![revoking.clone()])).unwrap();
        assert!(json.contains(r#""revoke_state":"revoking""#), "{json}");
        assert_eq!(
            serde_json::from_str::<Response>(&json).unwrap(),
            Response::Grants(vec![revoking])
        );

        let revoke = Request::Revoke { id: 3 };
        assert_eq!(
            serde_json::to_string(&revoke).unwrap(),
            r#"{"req":"revoke","id":3}"#
        );
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"req":"revoke","id":3}"#).unwrap(),
            revoke
        );
        // `Request::Revoke`'s answer names what actually happened (#245), not
        // merely that the authority projection changed; all three outcomes
        // round-trip.
        for outcome in [
            crate::approvals::RevokeOutcome::Withdrawn,
            crate::approvals::RevokeOutcome::WithdrawnInFlight(2),
            crate::approvals::RevokeOutcome::Unconfirmed,
        ] {
            let revoked = Response::Revoked(outcome);
            let json = serde_json::to_string(&revoked).unwrap();
            assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), revoked);
        }
        assert_eq!(
            serde_json::to_string(&Response::Revoked(
                crate::approvals::RevokeOutcome::WithdrawnInFlight(2)
            ))
            .unwrap(),
            r#"{"resp":"revoked","body":{"withdrawn-in-flight":2}}"#
        );
        // A `CredentialGranted` append answers with the grant id it minted
        // (#245), distinct from every other append's plain `Response::Record`.
        let record_dir = tempfile::tempdir().unwrap();
        let record = fresh(record_dir.path())
            .append(Origin::Wardd, working(), SystemTime::now())
            .unwrap();
        let granted = Response::Granted {
            record: Box::new(record),
            grant_id: 42,
        };
        let json = serde_json::to_string(&granted).unwrap();
        assert!(json.contains(r#""grant_id":42"#), "{json}");
        assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), granted);
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
        // A plain log connection does not hold or answer approvals, list or revoke grants, or pause.
        let dir = tempfile::tempdir().unwrap();
        let mut log = Some(fresh(dir.path()));
        for request in [
            hold,
            approve,
            Request::Pending,
            Request::Approvals,
            Request::Grants,
            revoke,
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
        assert!(matches!(r, Response::Sealed { head, ended: None } if head.next_seq == 2));
        assert!(matches!(
            handle(&mut log, Request::Ping).0,
            Response::Error(_)
        ));
    }

    /// The request tags a 0.18 daemon could parse: anything else it answered
    /// with serde's own `bad request: unknown variant …`.
    const V018_REQUESTS: &[&str] = &[
        "append",
        "evidence",
        "sync",
        "seal",
        "stop",
        "describe",
        "subscribe",
        "ping",
        "hold",
        "approve",
        "pending",
        "approvals",
        "grants",
        "pause",
        "resume",
    ];

    /// A stand-in for a 0.18 `wardd` on one connection: it parses only the
    /// requests 0.18 knew, and serves them with 0.18's semantics — its `Stop`
    /// appends `SessionEnded` and seals without touching any workload, and its
    /// `Sealed` carries no `ended` (the wire shape `control::handle` still
    /// produces for a plain log connection). `ack_capabilities` makes it lie
    /// that it serves [`FEATURE_STOP_TERMINATES`], to check the response-side
    /// acknowledgement on its own. Returns every request tag it received and
    /// whether its log ended sealed.
    fn serve_v018(
        stream: UnixStream,
        mut log: Option<LocalLog>,
        ack_capabilities: bool,
    ) -> (Vec<String>, bool) {
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        let mut seen = Vec::new();
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            let tag = serde_json::from_str::<serde_json::Value>(&line).unwrap()["req"]
                .as_str()
                .unwrap()
                .to_owned();
            seen.push(tag.clone());
            let (response, done) = if tag == "capabilities" && ack_capabilities {
                (
                    Response::Capabilities {
                        features: vec![FEATURE_STOP_TERMINATES.into()],
                    },
                    false,
                )
            } else if V018_REQUESTS.contains(&tag.as_str()) {
                handle(&mut log, serde_json::from_str(&line).unwrap())
            } else {
                (
                    Response::Error(format!("bad request: unknown variant `{tag}`")),
                    false,
                )
            };
            write_response(&mut writer, &response).unwrap();
            line.clear();
            if done {
                break;
            }
        }
        (seen, log.is_none())
    }

    /// PR #253 review finding 1, old daemon / new client: `Request::Stop`
    /// exists on 0.18 too, where it only seals. A 0.19 client attached to a
    /// still-running 0.18 daemon must not send it and report success with
    /// `ended = 0`: it asks for the capability first, gets the old daemon's
    /// "unknown variant", and refuses — with nothing sent that could seal the
    /// log beside a live sandbox.
    #[test]
    fn a_new_client_refuses_to_stop_through_a_daemon_that_predates_confirmed_stop() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        let log = Some(fresh(dir.path()));
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_v018(stream, log, false)
        });
        let sink: Box<dyn Sink> = Box::new(RemoteSink::connect(&socket).expect("daemon"));
        assert!(sink.ends_workloads());
        let err = sink.stop(EndReason::UserStop).unwrap_err().to_string();
        assert!(
            err.contains("does not serve `stop-terminates-workloads`"),
            "{err}"
        );
        assert!(err.contains("nothing was sealed"), "{err}");
        let (seen, sealed) = server.join().unwrap();
        assert_eq!(seen, ["ping", "capabilities"], "no `stop` was ever sent");
        assert!(!sealed, "the old daemon's log is still open");
    }

    /// The response-side half of finding 1: even a daemon that claims the
    /// capability must positively acknowledge the termination in its answer.
    /// A `Sealed` without `ended` (0.18's shape) is never read as "0 ended".
    #[test]
    fn a_seal_without_a_termination_acknowledgement_is_not_a_successful_stop() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        let log = Some(fresh(dir.path()));
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_v018(stream, log, true)
        });
        let sink: Box<dyn Sink> = Box::new(RemoteSink::connect(&socket).expect("daemon"));
        let err = sink.stop(EndReason::UserStop).unwrap_err().to_string();
        assert!(err.contains("without confirming"), "{err}");
        let (seen, sealed) = server.join().unwrap();
        assert_eq!(seen, ["ping", "capabilities", "stop"]);
        assert!(sealed);
        // On the wire: 0.18's `Sealed` has no `ended`, and parses as `None`.
        let head =
            serde_json::to_value(Chain::genesis(session(), Blake3Hash::from_bytes([1; 32])).head())
                .unwrap();
        let old = serde_json::json!({ "resp": "sealed", "body": { "head": head } }).to_string();
        assert!(matches!(
            serde_json::from_str::<Response>(&old).unwrap(),
            Response::Sealed { ended: None, .. }
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
