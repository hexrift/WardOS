//! `ward` as a client of a running daemon (ADR-0015): the evidence producer and
//! the observer's subscription, both over the session's control socket.
//!
//! [`append_evidence`] is `ward evidence append`: a `TamperWard`-origin record
//! appended on TamperWard's behalf (`tamperward-integration.md` §2). [`watch`] is
//! `ward watch`: [`Request::Subscribe`] and one observer row per record until the
//! daemon closes the stream, which it does when the log is sealed. [`describe`]
//! is `ward session describe` over the socket, and [`catch_up`] the bounded
//! subscription a shell surface uses to draw its first frame. None of them
//! touches the log: with no daemon they fail with [`NO_DAEMON`] instead of
//! falling back to a local writer, because a producer that opened the log itself
//! would fork the chain the daemon owns.

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ward_events::{EventKind, EventRecord, WardEvent};

use crate::approvals::{Approval, ApprovalDecision, ApprovalRecord, Grant};
use crate::control::{Next, RemoteSink, Request, Response, SOCKET_NAME, is_evidence};
use crate::describe::SessionDescription;
use crate::error::{Error, Result};
use crate::render;
use crate::session::{SessionMeta, session_dir};

/// The message printed when the current session has no daemon listening.
pub const NO_DAEMON: &str = "no daemon is serving this session (run ward up)";

/// The kinds `ward evidence append` accepts, in the order of the catalogue.
pub const EVIDENCE_KINDS: [EventKind; 4] = [
    EventKind::PolicyDecision,
    EventKind::PolicyDenied,
    EventKind::TamperDetected,
    EventKind::StateAccepted,
];

/// The control socket of `project_dir`'s current session, whether or not a daemon
/// listens on it.
pub fn socket_path(project_dir: &Path, state: &Path) -> Result<PathBuf> {
    let meta = SessionMeta::current(project_dir, state)?.ok_or_else(|| {
        Error::Project(format!(
            "no session for {}; run `ward up {0}` to start one",
            project_dir.display()
        ))
    })?;
    Ok(session_dir(state, &meta.id).join(SOCKET_NAME))
}

/// The control socket the desktop means (ADR-0016, #141): `session`'s when one
/// is named — an id a caller already has in hand (an approval's own
/// `--session`, a switcher's pinned target) is used exactly as given and
/// never checked against [`selection`](crate::selection) or "newest", so
/// selection changes elsewhere can never retarget it; else `project_dir`'s
/// current session when it has one, since a human running `ward` inside a
/// project always means that project's session; else the desktop's shared
/// selection, kept if its daemon still answers — the session every other
/// desktop-wide surface (the bar, the switcher, `wardos-approve`,
/// `wardos-pause` with no session pinned) just asked about, so they agree
/// with each other instead of each independently recomputing "newest" and
/// risking a different answer; else the newest session a daemon serves,
/// adopted and recorded as the new shared selection so the *next* ask agrees
/// with this one. [`Error::Project`] when there is none of those.
pub fn desktop_socket(project_dir: &Path, state: &Path, session: Option<&str>) -> Result<PathBuf> {
    if let Some(id) = session {
        return Ok(session_dir(state, id).join(SOCKET_NAME));
    }
    if let Some(meta) = SessionMeta::current(project_dir, state).ok().flatten() {
        return Ok(session_dir(state, &meta.id).join(SOCKET_NAME));
    }
    // The generation observed here is the compare-and-swap's baseline
    // (#141 finding 2): `newest_live` below probes every live session's
    // socket, which takes long enough for a concurrent, explicit
    // `ward session select` to land before this function's own automatic
    // pick is written — and that explicit choice must win.
    let observed = crate::selection::current(state);
    if let Some(id) = &observed.session
        && crate::daemon::serving(state, id)
    {
        return Ok(session_dir(state, id).join(SOCKET_NAME));
    }
    match crate::daemon::newest_live(state)? {
        Some(meta) => {
            // Best-effort, and race-safe: a registry we cannot write still
            // lets this one call through with the session it found (the next
            // call just looks again), and a registry a concurrent explicit
            // select already moved since `observed` is left alone rather
            // than overwritten with this automatic pick.
            let _ =
                crate::selection::select_if_unchanged(state, Some(&meta.id), observed.generation);
            Ok(session_dir(state, &meta.id).join(SOCKET_NAME))
        }
        None => Err(Error::Project(format!(
            "no session for {} and no live session anywhere; run `ward up` to start one",
            project_dir.display()
        ))),
    }
}

/// Connect to the daemon on `socket`; [`NO_DAEMON`] when nothing answers there.
pub fn connect(socket: &Path) -> Result<RemoteSink> {
    RemoteSink::connect(socket).ok_or_else(|| Error::Project(NO_DAEMON.to_owned()))
}

/// `ward pause`: the daemon pauses the session as one operation (ADR-0019 §3)
/// and answers with the `SessionPaused` record.
pub fn pause(sink: &mut RemoteSink, reason: &str) -> Result<EventRecord> {
    expect_record(sink.call(&Request::Pause {
        reason: reason.to_owned(),
    })?)
}

/// `ward resume`: the daemon reverses the pause and answers with the
/// `SessionResumed` record.
pub fn resume(sink: &mut RemoteSink) -> Result<EventRecord> {
    expect_record(sink.call(&Request::Resume)?)
}

/// One session's outcome from [`pause_all`].
#[derive(Debug)]
pub struct SessionPauseResult {
    /// The session's id.
    pub session: String,
    /// The `SessionPaused` record, or why this session could not be paused
    /// (already paused, or gone between listing and asking).
    pub outcome: Result<EventRecord>,
}

/// `ward pause --all` (#141 item 5): "Pause all sessions", distinct from
/// pausing the one selected session. Every session live when this is called
/// is paused as its own operation, on its own connection, and reported on its
/// own line — one session refusing (or having ended in the meantime) does not
/// stop the rest from being paused, and does not stop being reported.
pub fn pause_all(state: &Path, reason: &str) -> Result<Vec<SessionPauseResult>> {
    let live = crate::daemon::live_sessions(state)?;
    let mut results = Vec::with_capacity(live.len());
    for meta in live {
        let socket = session_dir(state, &meta.id).join(SOCKET_NAME);
        let outcome = connect(&socket).and_then(|mut sink| pause(&mut sink, reason));
        results.push(SessionPauseResult {
            session: meta.id,
            outcome,
        });
    }
    Ok(results)
}

/// One session's pending approvals from [`pending_all`], or why they could not
/// be listed.
#[derive(Debug)]
pub struct SessionPendingResult {
    /// The session's id.
    pub session: String,
    /// Its description and what it holds pending, or the connect/describe/
    /// pending failure that stopped this session from being inspected at all.
    pub outcome: Result<(SessionDescription, Vec<Approval>)>,
}

/// `ward session pending --all` (without `--follow`): every live session's
/// approvals, one connection each, on its own line — mirroring [`pause_all`]'s
/// shape. A session whose connect, describe or pending call fails is reported
/// with that failure rather than silently dropped (#141 finding 5): before
/// this, a session skipped here was indistinguishable from one reachable and
/// genuinely empty, so a caller could print "no pending approvals" without
/// having actually inspected every listed live session.
pub fn pending_all(state: &Path) -> Result<Vec<SessionPendingResult>> {
    let live = crate::daemon::live_sessions(state)?;
    let mut results = Vec::with_capacity(live.len());
    for meta in live {
        let socket = session_dir(state, &meta.id).join(SOCKET_NAME);
        let outcome = connect(&socket).and_then(|mut sink| {
            let description = describe(&mut sink)?;
            let approvals = pending(&mut sink)?;
            Ok((description, approvals))
        });
        results.push(SessionPendingResult {
            session: meta.id,
            outcome,
        });
    }
    Ok(results)
}

fn expect_record(response: Response) -> Result<EventRecord> {
    match response {
        Response::Record(record) => Ok(*record),
        Response::Error(e) => Err(Error::Project(e)),
        other => Err(Error::Project(format!("unexpected response {other:?}"))),
    }
}

/// Parse one `WardEvent` from its serde JSON and check it is an evidence kind,
/// with the same rule the daemon applies ([`is_evidence`]), so a refused record
/// never reaches the socket.
///
/// `detail` may be given as a bare string; it is lifted to the `DetailText`
/// object (`{"text": …, "truncated": false}`) before parsing.
pub fn parse_evidence(json: &str) -> Result<WardEvent> {
    let mut value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| Error::Events(format!("evidence JSON: {e}")))?;
    lift_detail(&mut value);
    // Some fields borrow from the input, so parse text, not a `Value`.
    let text = serde_json::to_string(&value).map_err(|e| Error::Events(e.to_string()))?;
    let event: WardEvent =
        serde_json::from_str(&text).map_err(|e| Error::Events(format!("evidence JSON: {e}")))?;
    if is_evidence(&event) {
        Ok(event)
    } else {
        let allowed: Vec<String> = EVIDENCE_KINDS.iter().map(ToString::to_string).collect();
        Err(Error::Events(format!(
            "{} is not an evidence kind (one of {})",
            event.kind(),
            allowed.join(", ")
        )))
    }
}

/// `{"Kind": {"detail": "text"}}` → `{"Kind": {"detail": {"text": "text", …}}}`.
fn lift_detail(value: &mut serde_json::Value) {
    let Some(variants) = value.as_object_mut() else {
        return;
    };
    for body in variants.values_mut() {
        let Some(fields) = body.as_object_mut() else {
            continue;
        };
        if let Some(text) = fields.get("detail").and_then(serde_json::Value::as_str) {
            let text = text.to_owned();
            fields.insert(
                "detail".to_owned(),
                serde_json::json!({ "text": text, "truncated": false, "original_hash": null }),
            );
        }
    }
}

/// Append `event` with `origin = TamperWard` through the daemon.
pub fn append_evidence(sink: &mut RemoteSink, event: WardEvent) -> Result<EventRecord> {
    match sink.call(&Request::Evidence { event })? {
        Response::Record(record) => Ok(*record),
        Response::Error(e) => Err(Error::Events(format!("daemon refused evidence: {e}"))),
        other => Err(Error::Events(format!("unexpected response {other:?}"))),
    }
}

/// The session's immutable facts from the daemon (`ward session describe` over
/// the socket): the same [`SessionDescription`] the daemon answers TamperWard.
pub fn describe(sink: &mut RemoteSink) -> Result<SessionDescription> {
    match sink.call(&Request::Describe)? {
        Response::Description(value) => serde_json::from_value(value)
            .map_err(|e| Error::Events(format!("session description: {e}"))),
        Response::Error(e) => Err(Error::Events(format!("daemon refused describe: {e}"))),
        other => Err(Error::Events(format!("unexpected response {other:?}"))),
    }
}

/// The approvals the daemon holds (`ward session pending`), oldest first.
pub fn pending(sink: &mut RemoteSink) -> Result<Vec<Approval>> {
    match sink.call(&Request::Pending)? {
        Response::Pending(approvals) => Ok(approvals),
        Response::Error(e) => Err(Error::Daemon(format!("daemon refused pending: {e}"))),
        other => Err(Error::Events(format!("unexpected response {other:?}"))),
    }
}

/// Every approval the session has asked, pending or decided, oldest asked
/// first (`ward session approvals`, #146 item 1): the daemon's own
/// authoritative account, still readable after a client missed or dismissed
/// whatever first announced a request.
pub fn approvals(sink: &mut RemoteSink) -> Result<Vec<ApprovalRecord>> {
    match sink.call(&Request::Approvals)? {
        Response::Approvals(records) => Ok(records),
        Response::Error(e) => Err(Error::Daemon(format!("daemon refused approvals: {e}"))),
        other => Err(Error::Events(format!("unexpected response {other:?}"))),
    }
}

/// The temporary grants the session holds (`ward session grants`), oldest
/// first: `allow-session` answers and the credentials the proxy injects.
pub fn grants(sink: &mut RemoteSink) -> Result<Vec<Grant>> {
    match sink.call(&Request::Grants)? {
        Response::Grants(grants) => Ok(grants),
        Response::Error(e) => Err(Error::Daemon(format!("daemon refused grants: {e}"))),
        other => Err(Error::Events(format!("unexpected response {other:?}"))),
    }
}

/// Answer a held approval (`ward session approve <id> <decision>`).
pub fn approve(sink: &mut RemoteSink, id: u64, decision: ApprovalDecision) -> Result<()> {
    match sink.call(&Request::Approve { id, decision })? {
        Response::Ok => Ok(()),
        Response::Error(e) => Err(Error::Daemon(e)),
        other => Err(Error::Events(format!("unexpected response {other:?}"))),
    }
}

/// `ward session pending --follow`: hand `emit` every approval as it becomes
/// pending, until the daemon closes the stream. The backlog is skipped with
/// [`catch_up`]'s rule (`idle` of silence), then what is pending now is
/// emitted, then each live `CapabilityRequested` record prompts a fresh
/// listing so an approval is emitted once, with its id and reason, and an
/// approval already answered by then is not emitted at all.
///
/// This call itself is never cancelled from inside this process — `ward
/// session pending --follow` (its only direct caller) runs until the daemon
/// closes the stream or SIGINT ends the process outright, neither of which
/// needs a cooperative signal. [`follow_pending_all`]'s watcher threads need
/// exactly that, though (review 5284703397 of #210, finding 2), so they call
/// [`follow_pending_cancellable`] instead, below, which this delegates to
/// with a [`Cancel`] nothing ever arms.
pub fn follow_pending(
    socket: &Path,
    idle: Duration,
    emit: impl FnMut(Approval),
) -> Result<WatchEnd> {
    follow_pending_cancellable(socket, idle, emit, &Cancel::default())
}

/// [`follow_pending`]'s actual implementation, plus `cancel`: armed with this
/// call's own live subscriber connection as soon as it is made, so
/// [`join_watchers`] can unblock this specific call's read — including the
/// unbounded one below, once a session has gone quiet after its backlog —
/// from another thread (review 5284703397 of #210, finding 2). See
/// [`Cancel`]'s own doc comment for why that shutdown needs no special
/// handling anywhere in this read loop: it surfaces exactly like the daemon
/// hanging up on its own.
fn follow_pending_cancellable(
    socket: &Path,
    idle: Duration,
    mut emit: impl FnMut(Approval),
    cancel: &Cancel,
) -> Result<WatchEnd> {
    let mut subscriber = connect(socket)?;
    cancel.arm(&subscriber);
    subscriber.send(&Request::Subscribe { from_seq: 0 })?;
    let mut records = 0;
    let mut emitted = Vec::new();
    let list = |emitted: &mut Vec<u64>, emit: &mut dyn FnMut(Approval)| -> Result<()> {
        let mut sink = connect(socket)?;
        for approval in pending(&mut sink)? {
            if !emitted.contains(&approval.id) {
                emitted.push(approval.id);
                emit(approval);
            }
        }
        Ok(())
    };
    // The backlog: read until the stream goes quiet, or ends.
    loop {
        match subscriber.next_within(idle)? {
            Next::Quiet => break,
            Next::Closed => return Ok(WatchEnd::Closed { records }),
            Next::Response(response) => {
                if let Some(end) = step(Some(response), &mut records, &mut |_| {})? {
                    return Ok(end);
                }
            }
        }
    }
    list(&mut emitted, &mut emit)?;
    subscriber.set_read_timeout(None)?;
    loop {
        let response = subscriber.next_response()?;
        let asked = matches!(
            &response,
            Some(Response::Record(rec)) if matches!(rec.event, WardEvent::CapabilityRequested { .. })
        );
        if let Some(end) = step(response, &mut records, &mut |_| {})? {
            return Ok(end);
        }
        if asked {
            list(&mut emitted, &mut emit)?;
        }
    }
}

/// A handle [`join_watchers`] uses to unblock one [`follow_pending_cancellable`]
/// watcher's in-progress blocking read from another thread (review
/// 5284703397 of #210, finding 2): the unbounded `next_response` a watcher
/// sits in once its session has gone quiet after its backlog is exactly the
/// healthy, expected shape for a live, quiet session — a `TcpStream`/
/// `UnixStream`-style `shutdown()` called on a clone of its socket from the
/// *outside*, rather than retrofitting a poll-a-flag loop into that read, is
/// what closes it without touching that normal-operation behaviour at all:
/// nothing in the read loop needs to change to become cancellable, and a
/// live, quiet watcher that is never cancelled reads exactly as before,
/// blocked indefinitely until its daemon actually has something to say.
/// Shutting down the socket a blocking read is waiting on makes that read
/// return `Ok(0)` (EOF) immediately, which [`step`] already treats the same
/// as the daemon hanging up on its own (`WatchEnd::Closed`) — so a cancelled
/// watcher ends exactly like a session whose daemon closed the stream
/// itself, with no separate cancelled/error branch needed anywhere in
/// [`follow_pending_cancellable`]'s loop.
///
/// [`Self::cancel`] is sticky rather than a one-shot "shut this socket down
/// right now": a watcher thread is spawned before this handle's owner can
/// possibly know whether it will ever need cancelling, so `cancel()` can
/// race `arm()` — a `live_sessions` failure landing before a brand new
/// watcher has even finished its `describe`/`connect` must still stop that
/// watcher once it does get as far as arming this handle, not lose the
/// signal because nothing was listening yet. Recording `Cancelled` as
/// permanent state, and having `arm` itself shut down immediately when it
/// finds that state already set, closes that race in either order: whichever
/// of `arm`/`cancel` runs first, the socket ends up shut down.
#[derive(Clone, Default)]
struct Cancel(Arc<Mutex<CancelState>>);

/// [`Cancel`]'s inner state.
#[derive(Default)]
enum CancelState {
    /// Not yet armed, not cancelled.
    #[default]
    Idle,
    /// Armed with the socket a blocked read is (or will be) waiting on.
    Armed(UnixStream),
    /// [`Cancel::cancel`] ran before, or races, [`Cancel::arm`]: permanent,
    /// so an `arm` that has not happened yet still takes effect immediately
    /// once it does.
    Cancelled,
}

impl Cancel {
    /// Record `sink`'s socket as the one [`Self::cancel`] shuts down. Called
    /// once, right after [`follow_pending_cancellable`] makes its one
    /// long-lived subscriber connection — the short-lived connections `list`
    /// opens for `Pending` are not what this needs to interrupt, since a
    /// `Pending` call is already bounded by [`TIMEOUT`](crate::control::TIMEOUT),
    /// not unbounded the way the subscriber's post-backlog read is. If
    /// `cancel()` already ran (this watcher was told to stop before it even
    /// got this far), the newly-connected socket is shut down immediately
    /// instead of being left live and un-signalled.
    fn arm(&self, sink: &RemoteSink) {
        let Ok(stream) = sink.try_clone_socket() else {
            return;
        };
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        if matches!(*state, CancelState::Cancelled) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        } else {
            *state = CancelState::Armed(stream);
        }
    }

    /// Unblock whatever this handle's armed socket is doing right now, and
    /// remember that this watcher has been told to stop even if it is not
    /// armed yet — a not-yet-connected watcher's own next connection attempt
    /// is still governed by the ordinary, bounded connect timeout regardless
    /// (this is not what bounds that), but once it does reach [`Self::arm`]
    /// that call now shuts it straight down instead of leaving it live.
    fn cancel(&self) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        if let CancelState::Armed(stream) = &*state {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        *state = CancelState::Cancelled;
    }
}

/// One approval as [`follow_pending_all`] reports it: which live session it
/// belongs to, so a multiplexed view (or a notification) can name it
/// prominently instead of leaving the session implicit the way a single-session
/// follow can.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionApproval {
    /// The session's id.
    pub session: String,
    /// Its project id, from `session describe`.
    pub project: String,
    /// The agent's product name, when recorded.
    pub agent: Option<String>,
    /// The approval itself.
    pub approval: Approval,
}

/// How often [`follow_pending_all`] re-checks `live_sessions` for a session
/// that started after it began watching: the granularity that is reasonable
/// for an approval-notification path (a human waiting on a live agent), and
/// the longest this ever goes without noticing a new session even while every
/// session it already knows about stays perfectly quiet.
pub const REDISCOVER: Duration = Duration::from_secs(30);

/// How one of [`follow_pending_all`]'s watcher threads ended, as reported
/// through its `done_tx`.
enum WatcherEnd {
    /// It got as far as `describe` succeeding (whether or not `follow_pending`
    /// itself then ran into trouble): a normal end, retried on the usual
    /// `rediscover` cadence with no extra delay.
    Ended(Result<()>),
    /// Its very first `describe` failed: this session answered `Ping` (or
    /// `live_sessions` would never have named it) but is not actually
    /// reachable. Kept apart from [`Self::Ended`] so [`follow_pending_all`]
    /// can back a session like this off instead of respawning it immediately
    /// (review 5284361040 of #210, finding 2).
    Unreachable(Error),
}

/// `ward session pending --all --follow` (#141 items 4 and 6): every live
/// session's approvals, multiplexed, independently of which one the desktop
/// has selected — an approval in a second session must never be invisible
/// just because the bar is showing the first.
///
/// One [`follow_pending`] watcher per live session, spawned as it is found:
/// once for every session live when this call began, then again for any
/// session `live_sessions` reports that was not already being watched, every
/// time a watcher finishes or [`REDISCOVER`] passes, whichever comes first —
/// so a session that starts after watching began is never invisible for
/// longer than one [`REDISCOVER`] interval, no matter how long every session
/// watched so far stays live (#141 finding 1: the previous shape joined one
/// thread per *original* session and could not return, or notice anything
/// new, until every one of them ended). A watcher that ends — whether the
/// session sealed, or its `describe` failed and it never got to follow at all
/// — is dropped from the watched set, so a session that comes back (or a
/// transient `describe` failure) is retried at the next rediscovery instead
/// of staying silently forgotten (#141 finding 5).
///
/// Every watcher's [`JoinHandle`] is tracked, not just its session id (review
/// 5284361040 of #210, finding 2): on *every* exit path — the ordinary one
/// below, or an early return on a `live_sessions` failure — every handle
/// still outstanding is joined before this actually returns, so a caller's
/// next call can never overlap with a straggler thread from this one still
/// holding the shared `emit`. A watcher's own blocking read stays genuinely
/// unbounded once its session has gone quiet after its backlog (`idle` only
/// bounds the backlog phase itself) — that is the whole point of it, so a
/// live session can go quiet for a long time without `follow_pending`
/// spuriously giving up on it — which means joining it on an ordinary,
/// healthy exit can take as long as that session's own daemon does to next
/// speak or close the stream. On the early-return path, that is not
/// acceptable: a `live_sessions` failure has nothing to do with any one
/// watched session's health, and a daemon that is alive, connected and
/// genuinely silent must not make this call wait on it indefinitely (review
/// 5284703397 of #210, finding 2, correcting the previous round's own
/// reasoning here — it read the `rediscover`-scale wait on the *ordinary*
/// path as already covering this case, but the ordinary path only ever waits
/// on `done_rx`, never on a `JoinHandle::join` directly the way this early
/// return does). Every watched thread now carries a [`Cancel`] handle
/// alongside its `JoinHandle`, and [`join_watchers`] signals every one of
/// them *before* joining on this path, so a watcher genuinely blocked in
/// that unbounded read is unblocked first — bounding this early return by
/// how long a `shutdown()` and a woken thread's own cleanup take, not by
/// anything the far end ever does.
///
/// A session that is `Ping`-live but whose `describe` never succeeds is
/// backed off, not respawned the instant it is the only session watched: the
/// previous shape emptied `watched` and immediately rediscovered, which for a
/// persistently unreachable session was a tight reconnect loop that also
/// never reported the failure anywhere (finding 2). Every describe failure is
/// now both logged and folded into this call's own returned error, and the
/// session is not retried again until [`REDISCOVER`]-scale time has passed
/// (see `backoff` below) — the same cadence a quiet, healthy session is
/// already rechecked on, just applied to one that keeps failing instead of
/// one that keeps succeeding quietly.
///
/// This returns once nothing is being watched, nothing is under a cooldown
/// either, and one more look at `live_sessions` still finds nothing live at
/// all to pick up.
pub fn follow_pending_all(
    state: &Path,
    idle: Duration,
    rediscover: Duration,
    emit: impl FnMut(SessionApproval) + Send + 'static,
) -> Result<()> {
    let emit: Emit = Arc::new(Mutex::new(emit));
    // Each watcher thread reports its own end (session id, outcome) here
    // instead of being `join`ed in a batch, so this can react to whichever
    // happens first: a watcher finishing, or `rediscover` passing with none
    // finishing — never blocked on one without a bound from the other. The
    // `JoinHandle`s themselves live in `watched` below, so a thread reporting
    // here is not yet the same as it actually having returned.
    let (done_tx, done_rx) = mpsc::channel::<(String, WatcherEnd)>();
    // Per session id: when its watcher last ended in `WatcherEnd::Unreachable`
    // — read, never written, by `spawn_new_watchers` to skip respawning it
    // too soon (review 5284361040 of #210, finding 2).
    let mut backoff: HashMap<String, Instant> = HashMap::new();
    let mut watched: HashMap<String, Watched> = HashMap::new();

    let mut anything_live = match spawn_new_watchers(
        state,
        idle,
        rediscover,
        &emit,
        &done_tx,
        &mut watched,
        &mut backoff,
    ) {
        Ok(any_live) => any_live,
        Err(e) => {
            join_watchers(watched);
            return Err(e);
        }
    };
    let mut first_err = None;
    loop {
        if watched.is_empty() && !anything_live {
            break;
        }
        let rediscover_now = match done_rx.recv_timeout(rediscover) {
            Ok((session, end)) => {
                record_watcher_end(
                    session,
                    end,
                    rediscover,
                    &mut watched,
                    &mut backoff,
                    &mut first_err,
                );
                // One more look right away when that was the last watcher: a
                // session that started in the instant this one ended must not
                // lose out just because it lost the race with this check.
                watched.is_empty()
            }
            // Nothing finished within `rediscover`: every session watched so
            // far is still quietly live (or, when `watched` is empty and
            // `anything_live` is true, everything live is under a backoff
            // cooldown with no thread running yet) — either way, this is
            // exactly when to look again.
            Err(RecvTimeoutError::Timeout) => true,
            // Cannot happen while `watched` is non-empty: every watcher holds
            // its own clone of `done_tx`, and so does this scope. Treated as
            // "nothing left to wait for" rather than panicking.
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if rediscover_now {
            anything_live = match spawn_new_watchers(
                state,
                idle,
                rediscover,
                &emit,
                &done_tx,
                &mut watched,
                &mut backoff,
            ) {
                Ok(any_live) => any_live,
                Err(e) => {
                    join_watchers(watched);
                    return Err(e);
                }
            };
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// [`follow_pending_all`]'s shared `emit`, boxed as a trait object so the
/// helper functions below can take it as an ordinary parameter instead of
/// each needing to be generic over `follow_pending_all`'s own `impl FnMut`.
type Emit = Arc<Mutex<dyn FnMut(SessionApproval) + Send>>;

/// One watcher thread [`follow_pending_all`] is tracking: its handle to
/// `join`, and the [`Cancel`] that [`join_watchers`] uses to unblock its
/// in-progress blocking read from outside on the early-return path (review
/// 5284703397 of #210, finding 2).
struct Watched {
    handle: JoinHandle<()>,
    cancel: Cancel,
}

/// [`follow_pending_all`]'s `discover`: list what `live_sessions` reports
/// live, and spawn a watcher thread for anything not already in `watched` and
/// not still under a `backoff` cooldown (review 5284361040 of #210,
/// finding 2). Returns whether `live_sessions` found anything live at all,
/// spawned or not — [`follow_pending_all`] uses that, not `watched` alone, to
/// decide whether it is really done: everything live can be backed off with
/// `watched` empty, and that must keep this waiting, not end it.
#[allow(clippy::too_many_arguments)]
fn spawn_new_watchers(
    state: &Path,
    idle: Duration,
    rediscover: Duration,
    emit: &Emit,
    done_tx: &mpsc::Sender<(String, WatcherEnd)>,
    watched: &mut HashMap<String, Watched>,
    backoff: &mut HashMap<String, Instant>,
) -> Result<bool> {
    let live = crate::daemon::live_sessions(state)?;
    let mut any_live = false;
    for meta in live {
        any_live = true;
        if watched.contains_key(&meta.id) {
            continue;
        }
        if backoff
            .get(&meta.id)
            .is_some_and(|last| last.elapsed() < rediscover)
        {
            continue;
        }
        backoff.remove(&meta.id);
        let socket = session_dir(state, &meta.id).join(SOCKET_NAME);
        let session_id = meta.id.clone();
        let emit = Arc::clone(emit);
        let done_tx = done_tx.clone();
        let cancel = Cancel::default();
        let cancel_for_thread = cancel.clone();
        let handle = std::thread::spawn(move || {
            let end = match connect(&socket).and_then(|mut sink| describe(&mut sink)) {
                Ok(d) => {
                    let (project, agent) = (d.project, d.agent.map(|a| a.name));
                    let result = follow_pending_cancellable(
                        &socket,
                        idle,
                        |approval| {
                            if let Ok(mut emit) = emit.lock() {
                                emit(SessionApproval {
                                    session: session_id.clone(),
                                    project: project.clone(),
                                    agent: agent.clone(),
                                    approval,
                                });
                            }
                        },
                        &cancel_for_thread,
                    )
                    .map(|_| ());
                    WatcherEnd::Ended(result)
                }
                // Gone, or never reachable, before we could ask it anything:
                // this is what `WatcherEnd::Unreachable` backs off, rather
                // than being retried immediately.
                Err(e) => WatcherEnd::Unreachable(e),
            };
            let _ = done_tx.send((session_id, end));
        });
        watched.insert(meta.id.clone(), Watched { handle, cancel });
    }
    Ok(any_live)
}

/// Fold one watcher's end into [`follow_pending_all`]'s bookkeeping: join its
/// handle (it already sent on `done_tx`, so this does not block indefinitely
/// waiting for a thread that has not finished), record any error as this
/// call's `first_err`, and, for an unreachable session, log it and start its
/// backoff cooldown (review 5284361040 of #210, finding 2).
fn record_watcher_end(
    session: String,
    end: WatcherEnd,
    rediscover: Duration,
    watched: &mut HashMap<String, Watched>,
    backoff: &mut HashMap<String, Instant>,
    first_err: &mut Option<Error>,
) {
    if let Some(watched) = watched.remove(&session) {
        let _ = watched.handle.join();
    }
    match end {
        WatcherEnd::Ended(Ok(())) => {}
        WatcherEnd::Ended(Err(e)) => {
            first_err.get_or_insert(e);
        }
        WatcherEnd::Unreachable(e) => {
            // Visible here even though it is not fatal to this call as a
            // whole (finding 2: "the failure is never reported anywhere"
            // before this) — mirrors how `pending_all`'s non-follow path
            // (finding 5) reports an unreachable session instead of hiding
            // it.
            eprintln!(
                "ward: session {session} is live but not reachable, retrying in \
                 at most {rediscover:?}: {e}"
            );
            backoff.insert(session, Instant::now());
            first_err.get_or_insert(e);
        }
    }
}

/// Join every watcher thread still tracked in `watched`, discarding their
/// results (a caller returning early already has the error it is about to
/// propagate): the cleanup every exit path of [`follow_pending_all`] runs
/// before actually returning, so no watcher is ever left running — and still
/// holding the shared `emit` — after the function that owns it has returned
/// (review 5284361040 of #210, finding 2).
///
/// Every watcher is [`Cancel::cancel`]'d *before* any of them is joined
/// (review 5284703397 of #210, finding 2): a watcher genuinely alive,
/// connected, and quiet is sitting in `follow_pending_cancellable`'s
/// unbounded post-backlog read precisely because that is the correct,
/// intended behaviour for a healthy session — nothing about it will ever
/// make that read return on its own within any bound this function could
/// wait for. Signalling every watcher first, rather than cancelling and
/// joining one at a time, means no watcher waits on another's socket
/// shutdown before its own is even signalled; joining is then just waiting
/// for threads that have all already been told to stop.
fn join_watchers(watched: HashMap<String, Watched>) {
    for watched in watched.values() {
        watched.cancel.cancel();
    }
    for (_, watched) in watched {
        let _ = watched.handle.join();
    }
}

/// What `ward watch` prints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WatchOptions {
    /// First sequence number to deliver (records already in the log come first).
    pub from_seq: u64,
    /// Also print the kinds the compact observer view hides, as a dim kind name.
    pub all: bool,
}

/// How a watch ended. Ctrl-C is not an outcome: SIGINT terminates the process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchEnd {
    /// The daemon closed the stream: the log is sealed (or the daemon is gone).
    Closed {
        /// Records received.
        records: u64,
    },
    /// The daemon reported the seal explicitly before closing.
    Sealed {
        /// Records received.
        records: u64,
    },
    /// The stream is still open but nothing more arrived within [`catch_up`]'s
    /// wait: the log is caught up with, the session is live.
    Quiet {
        /// Records received.
        records: u64,
    },
}

impl WatchEnd {
    /// Records received before the stream ended.
    #[must_use]
    pub const fn records(&self) -> u64 {
        match self {
            Self::Closed { records } | Self::Sealed { records } | Self::Quiet { records } => {
                *records
            }
        }
    }
}

/// The observer row for `rec`: [`render::observer_row`], or with `all` the dim
/// [`render::kind_row`] for the kinds the compact view hides.
#[must_use]
pub fn row(rec: &EventRecord, all: bool) -> Option<String> {
    render::observer_row(rec).or_else(|| all.then(|| render::kind_row(rec)))
}

/// Subscribe from `opts.from_seq` and hand `emit` one row per record as it
/// arrives, until the daemon ends the stream.
pub fn watch(
    sink: RemoteSink,
    opts: WatchOptions,
    mut emit: impl FnMut(String),
) -> Result<WatchEnd> {
    watch_records(sink, opts.from_seq, |rec| {
        if let Some(line) = row(&rec, opts.all) {
            emit(line);
        }
    })
}

/// Subscribe from `from_seq` and hand `emit` every record as it arrives, until
/// the daemon ends the stream. The TUI consumes records, not rows: its counters
/// and its `--all` filter are derived from the record itself.
pub fn watch_records(
    mut sink: RemoteSink,
    from_seq: u64,
    mut emit: impl FnMut(EventRecord),
) -> Result<WatchEnd> {
    // A quiet session is not a dead daemon: wait as long as the stream is open.
    sink.set_read_timeout(None)?;
    sink.send(&Request::Subscribe { from_seq })?;
    let mut records = 0;
    loop {
        if let Some(end) = step(sink.next_response()?, &mut records, &mut emit)? {
            return Ok(end);
        }
    }
}

/// [`watch_records`] with a clock: `emit` gets `Some(record)` as each arrives
/// and `None` whenever `tick` passes with nothing from the daemon, until the
/// stream ends. The shell's bar re-reads the worktree on both, since an edit
/// made outside the sandbox is a change the stream never reports (ADR-0019).
pub fn watch_records_ticking(
    mut sink: RemoteSink,
    from_seq: u64,
    tick: Duration,
    mut emit: impl FnMut(Option<EventRecord>),
) -> Result<WatchEnd> {
    sink.send(&Request::Subscribe { from_seq })?;
    let mut records = 0;
    loop {
        let response = match sink.next_within(tick)? {
            Next::Quiet => {
                emit(None);
                continue;
            }
            Next::Closed => None,
            Next::Response(response) => Some(response),
        };
        if let Some(end) = step(response, &mut records, &mut |rec| emit(Some(rec)))? {
            return Ok(end);
        }
    }
}

/// Subscribe from `from_seq` and hand `emit` the records the daemon has now:
/// returns [`WatchEnd::Quiet`] once nothing more has arrived for `idle`, or the
/// end of the stream if that comes first. A shell surface draws its first frame
/// from this and then follows with [`watch_records`] on a fresh connection.
pub fn catch_up(
    mut sink: RemoteSink,
    from_seq: u64,
    idle: Duration,
    mut emit: impl FnMut(EventRecord),
) -> Result<WatchEnd> {
    sink.send(&Request::Subscribe { from_seq })?;
    let mut records = 0;
    loop {
        let response = match sink.next_within(idle)? {
            Next::Quiet => return Ok(WatchEnd::Quiet { records }),
            Next::Closed => None,
            Next::Response(response) => Some(response),
        };
        if let Some(end) = step(response, &mut records, &mut emit)? {
            return Ok(end);
        }
    }
}

/// One step of a subscription: count and emit a record, or report how the
/// stream ended (`None` is the daemon hanging up).
fn step(
    response: Option<Response>,
    records: &mut u64,
    emit: &mut impl FnMut(EventRecord),
) -> Result<Option<WatchEnd>> {
    match response {
        Some(Response::Record(rec)) => {
            *records += 1;
            emit(*rec);
            Ok(None)
        }
        Some(Response::Ok) => Ok(None),
        Some(Response::Sealed { .. }) => Ok(Some(WatchEnd::Sealed { records: *records })),
        Some(Response::Error(e)) => Err(Error::Events(format!("daemon refused subscribe: {e}"))),
        Some(other) => Err(Error::Events(format!("unexpected response {other:?}"))),
        None => Ok(Some(WatchEnd::Closed { records: *records })),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::thread::JoinHandle;
    use std::time::Duration;
    use tempfile::TempDir;
    use ward_events::{
        Acceptor, AgentState, Blake3Hash, Chain, DetailText, Origin, PolicySubject, RuleRef,
        SessionId, SnapshotId, Timestamp,
    };

    const DENIED: &str = r#"{"PolicyDenied":{"subject":"ProtectedTests","rule":"protected-tests","detail":{"text":"tests/verify.rs","truncated":false}}}"#;
    const TAMPER: &str =
        r#"{"TamperDetected":{"subject":"VerifyConfig","detail":".tamperward/config.yml"}}"#;
    const ACCEPTED: &str = r#"{"StateAccepted":{"snapshot":"abababababababababababababababababababababababababababababababab","by":"TamperWard"}}"#;
    const DECISION: &str = r#"{"PolicyDecision":{"subject":"Session","decision":"Allow","rule":"session-open","detail":"ok"}}"#;

    fn plain(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn denied() -> WardEvent {
        WardEvent::PolicyDenied {
            subject: PolicySubject::ProtectedTests,
            rule: RuleRef::new("protected-tests").unwrap(),
            detail: DetailText::new("tests/verify.rs"),
        }
    }

    fn tamper() -> WardEvent {
        WardEvent::TamperDetected {
            subject: PolicySubject::VerifyConfig,
            detail: DetailText::new(".tamperward/config.yml"),
        }
    }

    fn accepted() -> WardEvent {
        WardEvent::StateAccepted {
            snapshot: SnapshotId::new(Blake3Hash::from_bytes([0xab; 32])),
            by: Acceptor::TamperWard,
        }
    }

    fn working() -> WardEvent {
        WardEvent::AgentStateChanged {
            state: AgentState::Working,
        }
    }

    /// A chain of synthetic records, one per event, one second apart.
    fn records(events: &[(Origin, WardEvent)]) -> (Chain, Vec<EventRecord>) {
        let mut chain = Chain::genesis(SessionId::from_u128(7), Blake3Hash::from_bytes([1; 32]));
        let records = events
            .iter()
            .enumerate()
            .map(|(i, (origin, event))| {
                chain
                    .append(
                        *origin,
                        event.clone(),
                        Timestamp::mono(Duration::from_secs(i as u64)),
                    )
                    .unwrap()
            })
            .collect();
        (chain, records)
    }

    /// A daemon stand-in serving one connection: `Ping` → `Ok`; `Subscribe` streams
    /// `log` from `from_seq` and closes; `Evidence` appends to `chain` and answers
    /// `Record` (or `refuse`). Returns the requests it saw.
    fn fake_daemon(
        chain: Chain,
        log: Vec<EventRecord>,
        refuse: Option<&'static str>,
    ) -> (TempDir, PathBuf, JoinHandle<Vec<Request>>) {
        fake_daemon_holding(chain, log, refuse, None)
    }

    /// [`fake_daemon`], but after streaming a subscription it keeps the
    /// connection open for `hold` (a live session with nothing new to say)
    /// before closing. `Describe` answers [`description`] as JSON.
    fn fake_daemon_holding(
        mut chain: Chain,
        log: Vec<EventRecord>,
        refuse: Option<&'static str>,
        hold: Option<Duration>,
    ) -> (TempDir, PathBuf, JoinHandle<Vec<Request>>) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut seen = Vec::new();
            let reply = |writer: &mut std::os::unix::net::UnixStream, r: &Response| {
                let mut b = serde_json::to_vec(r).unwrap();
                b.push(b'\n');
                writer.write_all(&b).unwrap();
            };
            for line in BufReader::new(stream)
                .lines()
                .map_while(std::result::Result::ok)
            {
                let request: Request = serde_json::from_str(&line).unwrap();
                seen.push(request.clone());
                match request {
                    Request::Ping | Request::Approve { id: 4, .. } => {
                        reply(&mut writer, &Response::Ok);
                    }
                    Request::Describe => reply(
                        &mut writer,
                        &Response::Description(serde_json::to_value(description()).unwrap()),
                    ),
                    Request::Subscribe { from_seq } => {
                        if let Some(e) = refuse {
                            reply(&mut writer, &Response::Error(e.into()));
                        }
                        for rec in log.iter().filter(|r| r.seq >= from_seq) {
                            reply(&mut writer, &Response::Record(Box::new(rec.clone())));
                        }
                        if let Some(hold) = hold {
                            std::thread::sleep(hold);
                        }
                        break;
                    }
                    Request::Pending => reply(
                        &mut writer,
                        &Response::Pending(vec![Approval::new(
                            4,
                            "Write",
                            "/work/a.rs",
                            crate::approvals::Authority::none("r", "/work/a.rs"),
                            0,
                        )]),
                    ),
                    Request::Approvals => reply(
                        &mut writer,
                        &Response::Approvals(vec![crate::approvals::ApprovalRecord {
                            approval: Approval::new(
                                4,
                                "Write",
                                "/work/a.rs",
                                crate::approvals::Authority::none("r", "/work/a.rs"),
                                0,
                            ),
                            outcome: None,
                            decided_at_unix_ms: None,
                        }]),
                    ),
                    Request::Grants => reply(
                        &mut writer,
                        &Response::Grants(vec![Grant {
                            kind: crate::approvals::GrantKind::Approval,
                            label: "Write /work/a.rs".into(),
                            scope: "write".into(),
                            lifetime: crate::approvals::Lifetime::Session,
                            granted_at_unix_ms: 1,
                        }]),
                    ),
                    Request::Approve { id, .. } => reply(
                        &mut writer,
                        &Response::Error(format!("approval {id}: not pending")),
                    ),
                    Request::Evidence { event } => {
                        let response = match refuse {
                            Some(e) => Response::Error(e.into()),
                            None => Response::Record(Box::new(
                                chain
                                    .append(
                                        Origin::TamperWard,
                                        event,
                                        Timestamp::mono(Duration::from_secs(9)),
                                    )
                                    .unwrap(),
                            )),
                        };
                        reply(&mut writer, &response);
                    }
                    other => panic!("unexpected request {other:?}"),
                }
            }
            seen
        });
        (dir, socket, server)
    }

    /// The description the fake daemon answers.
    fn description() -> SessionDescription {
        let manifest = ward_policy::merge(
            &ward_policy::Policy::default(),
            &ward_policy::Policy::default(),
            &ward_policy::Policy::default(),
            ward_policy::SessionId("sess_fake".to_owned()),
            ward_policy::ProjectId("proj_fake".to_owned()),
        );
        SessionDescription {
            session: "sess_fake".to_owned(),
            project: "proj_fake".to_owned(),
            worktree: PathBuf::from("/home/dev/payments-api"),
            started_unix_ms: 1_700_000_000_000,
            agent: None,
            entry_snapshot: format!("blake3:{}", "ab".repeat(32)),
            policy_hash: manifest.policy_hash.to_hex(),
            manifest,
        }
    }

    #[test]
    fn describe_returns_the_daemons_description() {
        let (chain, log) = records(&[]);
        let (_dir, socket, server) = fake_daemon(chain, log, None);
        let mut sink = connect(&socket).unwrap();
        let d = describe(&mut sink).unwrap();
        assert_eq!(d, description());
        assert_eq!(d.worktree, PathBuf::from("/home/dev/payments-api"));
        drop(sink);
        assert_eq!(
            server.join().unwrap(),
            vec![Request::Ping, Request::Describe]
        );
    }

    #[test]
    fn catch_up_returns_quiet_on_a_live_session_and_closed_on_a_sealed_one() {
        let events = [(Origin::TamperWard, denied()), (Origin::Wardd, working())];
        // Live: the daemon streams the backlog and then says nothing for a while.
        let (chain, log) = records(&events);
        let (_dir, socket, _) =
            fake_daemon_holding(chain, log, None, Some(Duration::from_millis(400)));
        let sink = connect(&socket).unwrap();
        let mut seen = Vec::new();
        let end = catch_up(sink, 0, Duration::from_millis(50), |rec| seen.push(rec)).unwrap();
        assert_eq!(end, WatchEnd::Quiet { records: 2 });
        assert_eq!(end.records(), 2);
        assert_eq!(seen[0].event, denied());
        assert_eq!(seen[1].event, working());

        // Sealed: the daemon hangs up right after the backlog.
        let (chain, log) = records(&events);
        let (_dir, socket, _) = fake_daemon(chain, log, None);
        let sink = connect(&socket).unwrap();
        let end = catch_up(sink, 1, Duration::from_secs(5), |_| {}).unwrap();
        assert_eq!(end, WatchEnd::Closed { records: 1 });

        // A refusal is the same error as for a watch.
        let (chain, log) = records(&[]);
        let (_dir, socket, _) = fake_daemon(chain, log, Some("log is sealed"));
        let sink = connect(&socket).unwrap();
        let err = catch_up(sink, 0, Duration::from_secs(5), |_| {}).unwrap_err();
        assert_eq!(
            err.to_string(),
            "events: daemon refused subscribe: log is sealed"
        );
    }

    #[test]
    fn parse_evidence_accepts_each_evidence_kind() {
        assert_eq!(parse_evidence(DENIED).unwrap(), denied());
        assert_eq!(parse_evidence(TAMPER).unwrap(), tamper());
        assert_eq!(parse_evidence(ACCEPTED).unwrap(), accepted());
        assert!(matches!(
            parse_evidence(DECISION).unwrap(),
            WardEvent::PolicyDecision {
                decision: ward_events::Decision::Allow,
                ..
            }
        ));
    }

    #[test]
    fn parse_evidence_lifts_a_bare_detail_string() {
        let long = r#"{"TamperDetected":{"subject":"VerifyConfig","detail":{"text":".tamperward/config.yml","truncated":false,"original_hash":null}}}"#;
        assert_eq!(
            parse_evidence(TAMPER).unwrap(),
            parse_evidence(long).unwrap()
        );
    }

    #[test]
    fn parse_evidence_refuses_non_evidence_kinds_client_side() {
        let json = serde_json::to_string(&working()).unwrap();
        let err = parse_evidence(&json).unwrap_err().to_string();
        assert!(
            err.contains("agent_state_changed is not an evidence kind"),
            "{err}"
        );
        assert!(err.contains("policy_decision, policy_denied, tamper_detected, state_accepted"));
        let ended = serde_json::to_string(&WardEvent::SessionEnded {
            reason: ward_events::EndReason::UserStop,
            final_snapshot: None,
        })
        .unwrap();
        assert!(parse_evidence(&ended).is_err());
        // The client-side rule is the daemon's rule.
        for json in [DENIED, TAMPER, ACCEPTED, DECISION] {
            assert!(is_evidence(&parse_evidence(json).unwrap()));
        }
    }

    #[test]
    fn parse_evidence_reports_malformed_json_and_unknown_variants() {
        let err = parse_evidence("{not json").unwrap_err().to_string();
        assert!(err.starts_with("events: evidence JSON:"), "{err}");
        let err = parse_evidence(r#"{"Bogus":{}}"#).unwrap_err().to_string();
        assert!(err.contains("evidence JSON"), "{err}");
        let err = parse_evidence(r#"{"PolicyDenied":{"subject":"ProtectedTests"}}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing field"), "{err}");
    }

    #[test]
    fn row_hides_quiet_kinds_unless_all() {
        let (_, recs) = records(&[(Origin::Wardd, working()), (Origin::TamperWard, denied())]);
        assert_eq!(row(&recs[0], false), None);
        assert_eq!(
            plain(&row(&recs[0], true).unwrap()),
            "00:00  agent_state_changed"
        );
        assert_eq!(
            plain(&row(&recs[1], false).unwrap()),
            "00:01  DENIED protected tests · rule protected-tests · tests/verify.rs"
        );
    }

    #[test]
    fn connect_reports_no_daemon_and_socket_path_needs_a_session() {
        let dir = tempfile::tempdir().unwrap();
        let err = connect(&dir.path().join(SOCKET_NAME))
            .err()
            .expect("nothing listens");
        assert_eq!(err.to_string(), NO_DAEMON);
        let state = dir.path().join("state");
        let err = socket_path(dir.path(), &state).unwrap_err().to_string();
        assert!(err.starts_with("no session for "), "{err}");
        // The desktop's socket: a named session needs no lookup; otherwise a
        // project without a session falls back to a live one, and says so when
        // there is none.
        assert_eq!(
            desktop_socket(dir.path(), &state, Some("sess_x")).unwrap(),
            state.join("sessions/sess_x").join(SOCKET_NAME)
        );
        let err = desktop_socket(dir.path(), &state, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no live session anywhere"), "{err}");
    }

    #[test]
    fn pending_and_approve_go_through_the_daemon() {
        let (chain, log) = records(&[]);
        let (_dir, socket, server) = fake_daemon(chain, log, None);
        let mut sink = connect(&socket).unwrap();
        let listed = pending(&mut sink).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, 4);
        assert_eq!(listed[0].tool, "Write");
        approve(&mut sink, 4, ApprovalDecision::Allow).unwrap();
        let err = approve(&mut sink, 5, ApprovalDecision::Deny).unwrap_err();
        assert_eq!(err.to_string(), "daemon: approval 5: not pending");
        let held = grants(&mut sink).unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].label, "Write /work/a.rs");
        assert_eq!(held[0].lifetime, crate::approvals::Lifetime::Session);
        let records = approvals(&mut sink).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].approval.id, 4);
        assert_eq!(records[0].outcome, None);
        drop(sink);
        let seen = server.join().unwrap();
        assert_eq!(seen[1], Request::Pending);
        assert_eq!(
            seen[2],
            Request::Approve {
                id: 4,
                decision: ApprovalDecision::Allow
            }
        );
        assert_eq!(seen[4], Request::Grants);
        assert_eq!(seen[5], Request::Approvals);
    }

    #[test]
    fn follow_pending_emits_what_is_pending_after_the_backlog_then_on_each_request() {
        // A daemon whose subscription streams a backlog, goes quiet, then sends
        // a `CapabilityRequested` record; `Pending` answers one approval, the
        // same one each time, so it is emitted once.
        let asked = crate::approvals::requested_event("Write", "/work/a.rs", "r");
        let (_, backlog) = records(&[(Origin::Wardd, working()), (Origin::Wardd, asked.clone())]);
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let mut pending_calls = 0;
            // The subscription has been streamed and closed; the listings that
            // follow are what the test counts.
            let mut done = false;
            // Connections: the subscriber, then one per `Pending` listing.
            for stream in listener.incoming().flatten() {
                let mut writer = stream.try_clone().unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                let reply = |writer: &mut std::os::unix::net::UnixStream, r: &Response| {
                    let mut b = serde_json::to_vec(r).unwrap();
                    b.push(b'\n');
                    writer.write_all(&b).unwrap();
                };
                while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                    match serde_json::from_str::<Request>(&line).unwrap() {
                        Request::Ping => reply(&mut writer, &Response::Ok),
                        Request::Pending => {
                            pending_calls += 1;
                            reply(
                                &mut writer,
                                &Response::Pending(vec![Approval::new(
                                    1,
                                    "Write",
                                    "/work/a.rs",
                                    crate::approvals::Authority::none("r", "/work/a.rs"),
                                    0,
                                )]),
                            );
                        }
                        Request::Subscribe { .. } => {
                            for rec in &backlog {
                                reply(&mut writer, &Response::Record(Box::new(rec.clone())));
                            }
                            std::thread::sleep(Duration::from_millis(300));
                            let (_, fresh) = records(&[(Origin::Wardd, asked.clone())]);
                            reply(&mut writer, &Response::Record(Box::new(fresh[0].clone())));
                            std::thread::sleep(Duration::from_millis(100));
                            done = true;
                            break;
                        }
                        other => panic!("{other:?}"),
                    }
                    line.clear();
                }
                if done && pending_calls >= 2 {
                    break;
                }
            }
            pending_calls
        });
        let mut seen = Vec::new();
        let end = follow_pending(&socket, Duration::from_millis(50), |a| seen.push(a)).unwrap();
        assert_eq!(end, WatchEnd::Closed { records: 3 });
        assert_eq!(seen.len(), 1, "listed twice, emitted once");
        assert_eq!(seen[0].id, 1);
        assert_eq!(server.join().unwrap(), 2);
    }

    #[test]
    fn watch_yields_the_rows_in_order_and_ends_when_the_stream_closes() {
        let (chain, log) = records(&[
            (Origin::TamperWard, denied()),
            (Origin::TamperWard, tamper()),
            (Origin::TamperWard, accepted()),
        ]);
        let (_dir, socket, server) = fake_daemon(chain, log, None);
        let sink = connect(&socket).expect("fake daemon answers ping");
        let mut rows = Vec::new();
        let end = watch(sink, WatchOptions::default(), |r| rows.push(plain(&r))).unwrap();
        assert_eq!(end, WatchEnd::Closed { records: 3 });
        assert_eq!(end.records(), 3);
        assert_eq!(
            rows,
            vec![
                "00:00  DENIED protected tests · rule protected-tests · tests/verify.rs",
                "00:01  TAMPER verify config · .tamperward/config.yml",
                "00:02  ACCEPT snapshot abababababab",
            ]
        );
        let seen = server.join().unwrap();
        assert_eq!(
            seen,
            vec![Request::Ping, Request::Subscribe { from_seq: 0 }],
            "one ping, one subscribe, nothing appended"
        );
    }

    #[test]
    fn watch_honours_from_seq_and_all() {
        let events = [
            (Origin::TamperWard, denied()),
            (Origin::Wardd, working()),
            (Origin::TamperWard, accepted()),
        ];
        let (chain, log) = records(&events);
        let (_dir, socket, _) = fake_daemon(chain, log, None);
        let sink = connect(&socket).unwrap();
        let mut rows = Vec::new();
        let opts = WatchOptions {
            from_seq: 1,
            all: false,
        };
        let end = watch(sink, opts, |r| rows.push(plain(&r))).unwrap();
        assert_eq!(end.records(), 2, "seq 0 is not delivered");
        assert_eq!(rows, vec!["00:02  ACCEPT snapshot abababababab"]);

        let (chain, log) = records(&events);
        let (_dir, socket, _) = fake_daemon(chain, log, None);
        let sink = connect(&socket).unwrap();
        let mut rows = Vec::new();
        let opts = WatchOptions {
            from_seq: 1,
            all: true,
        };
        watch(sink, opts, |r| rows.push(plain(&r))).unwrap();
        assert_eq!(
            rows,
            vec![
                "00:01  agent_state_changed",
                "00:02  ACCEPT snapshot abababababab"
            ]
        );
    }

    #[test]
    fn watch_records_delivers_every_record_including_hidden_kinds() {
        let (chain, log) = records(&[
            (Origin::TamperWard, denied()),
            (Origin::Wardd, working()),
            (Origin::TamperWard, accepted()),
        ]);
        let (_dir, socket, _) = fake_daemon(chain, log, None);
        let sink = connect(&socket).unwrap();
        let mut seen = Vec::new();
        let end = watch_records(sink, 1, |rec| seen.push(rec)).unwrap();
        assert_eq!(end, WatchEnd::Closed { records: 2 });
        assert_eq!(seen.len(), 2, "records, not rows: the hidden kind arrives");
        assert_eq!(seen[0].seq, 1);
        assert_eq!(seen[0].event, working());
        assert_eq!(seen[1].event, accepted());
    }

    #[test]
    fn watch_surfaces_the_daemons_refusal() {
        let (chain, log) = records(&[]);
        let (_dir, socket, _) = fake_daemon(chain, log, Some("log is sealed"));
        let sink = connect(&socket).unwrap();
        let err = watch(sink, WatchOptions::default(), |_| {}).unwrap_err();
        assert_eq!(
            err.to_string(),
            "events: daemon refused subscribe: log is sealed"
        );
    }

    #[test]
    fn evidence_is_appended_through_the_daemon_with_tamperward_origin() {
        let (chain, log) = records(&[(Origin::Wardd, working())]);
        let (_dir, socket, server) = fake_daemon(chain, log, None);
        let mut sink = connect(&socket).unwrap();
        let rec = append_evidence(&mut sink, parse_evidence(TAMPER).unwrap()).unwrap();
        assert_eq!(rec.seq, 1);
        assert_eq!(rec.origin, Origin::TamperWard);
        assert_eq!(rec.event, tamper());
        assert_eq!(
            plain(&row(&rec, false).unwrap()),
            "00:09  TAMPER verify config · .tamperward/config.yml"
        );
        drop(sink);
        let seen = server.join().unwrap();
        assert_eq!(seen[1], Request::Evidence { event: tamper() });
    }

    #[test]
    fn evidence_refused_by_the_daemon_is_an_error() {
        let (chain, log) = records(&[]);
        let (_dir, socket, _) = fake_daemon(chain, log, Some("not an evidence kind"));
        let mut sink = connect(&socket).unwrap();
        let err = append_evidence(&mut sink, denied()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "events: daemon refused evidence: not an evidence kind"
        );
    }

    // -- #141: the shared selection `desktop_socket` falls back to, and the
    // multiplexed operations (`pause_all`, `follow_pending_all`) that act on
    // every live session at once. All three need a stand-in that, unlike
    // `fake_daemon` above, answers more than one connection: the `serving()`
    // probe `desktop_socket`/`live_sessions` makes is its own connection,
    // separate from whatever the caller does next.

    /// A session under `state` with a real control socket that answers as many
    /// connections as asked, one thread each: `Ping`, `Describe`, `Pending`
    /// (`pending`, unconditionally), and `Pause` (`pause_outcome`, when given —
    /// otherwise refused). `Subscribe` never streams anything; it holds the
    /// connection for `hold` (longer than a caller's `idle`, so a
    /// `follow_pending` reaches `Quiet` and lists what is pending) and then
    /// closes it, so a follower reaches its own end without this stand-in ever
    /// having to track subscribers explicitly. Once a `Subscribe` has held and
    /// closed, this session is done for good — every connection after that is
    /// dropped unanswered, the same as a real `wardd` that has sealed its log
    /// and unlinked its socket, so `serving`/`live_sessions` correctly stop
    /// counting it (needed for `follow_pending_all`'s rediscovery, #141
    /// finding 1: without this, a stand-in that keeps accepting connections
    /// forever would look live forever, and get re-watched forever).
    fn spawn_pool_session(
        state: &Path,
        id: &str,
        started_unix_ms: u64,
        pending: Vec<Approval>,
        pause_outcome: Option<std::result::Result<EventRecord, String>>,
        hold: Duration,
    ) {
        let meta = SessionMeta {
            id: id.to_owned(),
            project: PathBuf::from("/tmp/demo"),
            project_id: format!("proj_{id}"),
            entry_snapshot: "blake3:abc".to_owned(),
            origin_repo: None,
            manifest: ward_policy::merge(
                &ward_policy::Policy::default(),
                &ward_policy::Policy::default(),
                &ward_policy::Policy::default(),
                ward_policy::SessionId(id.to_owned()),
                ward_policy::ProjectId(format!("proj_{id}")),
            ),
            started_unix_ms,
            agent: None,
        };
        let dir = session_dir(state, id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("session.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
        let description = meta.describe();
        let listener = UnixListener::bind(dir.join(SOCKET_NAME)).unwrap();
        let ended = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                if ended.load(std::sync::atomic::Ordering::Acquire) {
                    // Sealed: behave like nothing is listening any more.
                    continue;
                }
                let description = description.clone();
                let pending = pending.clone();
                let pause_outcome = pause_outcome.clone();
                let ended = std::sync::Arc::clone(&ended);
                std::thread::spawn(move || {
                    let mut writer = stream.try_clone().unwrap();
                    let reply = |writer: &mut std::os::unix::net::UnixStream, r: &Response| {
                        let mut b = serde_json::to_vec(r).unwrap();
                        b.push(b'\n');
                        let _ = writer.write_all(&b);
                    };
                    for line in BufReader::new(stream)
                        .lines()
                        .map_while(std::result::Result::ok)
                    {
                        let Ok(request) = serde_json::from_str::<Request>(&line) else {
                            continue;
                        };
                        match request {
                            Request::Ping => reply(&mut writer, &Response::Ok),
                            Request::Describe => reply(
                                &mut writer,
                                &Response::Description(serde_json::to_value(&description).unwrap()),
                            ),
                            Request::Pending => {
                                reply(&mut writer, &Response::Pending(pending.clone()));
                            }
                            Request::Subscribe { .. } => {
                                std::thread::sleep(hold);
                                ended.store(true, std::sync::atomic::Ordering::Release);
                                break;
                            }
                            Request::Pause { .. } => match &pause_outcome {
                                Some(Ok(rec)) => {
                                    reply(&mut writer, &Response::Record(Box::new(rec.clone())));
                                }
                                Some(Err(e)) => reply(&mut writer, &Response::Error(e.clone())),
                                None => reply(
                                    &mut writer,
                                    &Response::Error("pause not configured".into()),
                                ),
                            },
                            other => panic!("unexpected request {other:?}"),
                        }
                    }
                });
            }
        });
    }

    /// A `SessionPaused` record, for `pause_all`'s ok outcome.
    fn paused_record() -> EventRecord {
        let mut chain = Chain::genesis(SessionId::from_u128(9), Blake3Hash::from_bytes([3; 32]));
        chain
            .append(
                Origin::Wardd,
                WardEvent::SessionPaused {
                    method: ward_events::PauseMethod::Sigstop,
                    reason: ward_events::ShortText::new("because"),
                },
                Timestamp::mono(Duration::from_secs(0)),
            )
            .unwrap()
    }

    #[test]
    fn desktop_socket_shares_a_registry_backed_selection_across_calls() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap(); // no session of its own
        spawn_pool_session(
            state.path(),
            "sess_a",
            1,
            vec![],
            None,
            Duration::from_millis(50),
        );
        spawn_pool_session(
            state.path(),
            "sess_b",
            2,
            vec![],
            None,
            Duration::from_millis(50),
        );

        // Nothing selected yet: the newest live session is picked and recorded.
        let first = desktop_socket(project.path(), state.path(), None).unwrap();
        assert_eq!(first, session_dir(state.path(), "sess_b").join(SOCKET_NAME));
        assert_eq!(
            crate::selection::current(state.path()).session.as_deref(),
            Some("sess_b")
        );

        // A third, newer session starts; the bar, the switcher and
        // `wardos-pause` still agree on the one already selected instead of
        // each silently jumping to "whatever is newest now".
        spawn_pool_session(
            state.path(),
            "sess_c",
            3,
            vec![],
            None,
            Duration::from_millis(50),
        );
        let second = desktop_socket(project.path(), state.path(), None).unwrap();
        assert_eq!(
            second, first,
            "the shared selection does not drift on its own"
        );

        // An id given explicitly always wins, and never touches the registry:
        // this is the immutable binding item 2 of #141 asks for.
        let explicit = desktop_socket(project.path(), state.path(), Some("sess_c")).unwrap();
        assert_eq!(
            explicit,
            session_dir(state.path(), "sess_c").join(SOCKET_NAME)
        );
        assert_eq!(
            crate::selection::current(state.path()).session.as_deref(),
            Some("sess_b"),
            "an explicit session id never consults or changes the registry"
        );
    }

    #[test]
    fn desktop_socket_replaces_a_selection_whose_session_is_no_longer_live() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        // A stale selection: recorded once, nothing serves it any more.
        crate::selection::select(state.path(), Some("sess_gone")).unwrap();
        spawn_pool_session(
            state.path(),
            "sess_live",
            5,
            vec![],
            None,
            Duration::from_millis(50),
        );
        let socket = desktop_socket(project.path(), state.path(), None).unwrap();
        assert_eq!(
            socket,
            session_dir(state.path(), "sess_live").join(SOCKET_NAME)
        );
        assert_eq!(
            crate::selection::current(state.path()).session.as_deref(),
            Some("sess_live"),
            "an ended selection is replaced, not followed into an error"
        );
    }

    #[test]
    fn pause_all_reports_a_per_session_outcome_ok_or_error() {
        let state = tempfile::tempdir().unwrap();
        spawn_pool_session(
            state.path(),
            "sess_a",
            1,
            vec![],
            Some(Ok(paused_record())),
            Duration::from_millis(50),
        );
        spawn_pool_session(
            state.path(),
            "sess_b",
            2,
            vec![],
            Some(Err("already paused".to_owned())),
            Duration::from_millis(50),
        );
        let mut results = pause_all(state.path(), "because").unwrap();
        results.sort_by(|a, b| a.session.cmp(&b.session));
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].session, "sess_a");
        assert!(results[0].outcome.is_ok(), "{:?}", results[0].outcome);
        assert_eq!(results[1].session, "sess_b");
        assert_eq!(
            results[1].outcome.as_ref().unwrap_err().to_string(),
            "already paused",
            "one session refusing does not stop the rest being paused or reported"
        );
    }

    #[test]
    fn follow_pending_all_multiplexes_every_live_sessions_approvals() {
        let state = tempfile::tempdir().unwrap();
        let a = Approval::new(
            1,
            "Write",
            "/work/a.rs",
            crate::approvals::Authority::none("r", "/work/a.rs"),
            0,
        );
        let b = Approval::new(
            2,
            "Write",
            "/work/b.rs",
            crate::approvals::Authority::none("r", "/work/b.rs"),
            0,
        );
        spawn_pool_session(
            state.path(),
            "sess_a",
            1,
            vec![a],
            None,
            Duration::from_millis(80),
        );
        spawn_pool_session(
            state.path(),
            "sess_b",
            2,
            vec![b],
            None,
            Duration::from_millis(80),
        );
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let collected = std::sync::Arc::clone(&seen);
        follow_pending_all(
            state.path(),
            Duration::from_millis(30),
            Duration::from_millis(30),
            move |sa| {
                collected.lock().unwrap().push(sa);
            },
        )
        .unwrap();
        let mut seen = seen.lock().unwrap().clone();
        seen.sort_by(|x: &SessionApproval, y| x.session.cmp(&y.session));
        assert_eq!(seen.len(), 2, "one approval named per live session");
        assert_eq!(seen[0].session, "sess_a");
        assert_eq!(seen[0].project, "proj_sess_a");
        assert_eq!(seen[0].approval.id, 1);
        assert_eq!(seen[1].session, "sess_b");
        assert_eq!(seen[1].approval.id, 2);
    }

    /// #141 finding 1: a session started well after `follow_pending_all` began
    /// watching must still be discovered — bounded by `rediscover`, not by
    /// waiting for the session that was already live to end. `sess_a` is held
    /// open far longer than the bound this test asserts, so a regression back
    /// to "one thread per original session, joined at the end" would leave
    /// `sess_b`'s approval unobserved until `sess_a`'s 600ms hold elapses,
    /// which the 400ms deadline below catches.
    #[test]
    fn follow_pending_all_discovers_a_session_started_after_watching_began() {
        let state = tempfile::tempdir().unwrap();
        let a = Approval::new(
            1,
            "Write",
            "/work/a.rs",
            crate::approvals::Authority::none("r", "/work/a.rs"),
            0,
        );
        spawn_pool_session(
            state.path(),
            "sess_a",
            1,
            vec![a],
            None,
            Duration::from_millis(600),
        );
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let collected = std::sync::Arc::clone(&seen);
        let state_path = state.path().to_path_buf();
        let watcher = std::thread::spawn(move || {
            follow_pending_all(
                &state_path,
                Duration::from_millis(30),
                Duration::from_millis(50),
                move |sa| {
                    collected.lock().unwrap().push(sa);
                },
            )
        });

        // sess_b starts only once the watch above is already running.
        std::thread::sleep(Duration::from_millis(100));
        let b = Approval::new(
            2,
            "Write",
            "/work/b.rs",
            crate::approvals::Authority::none("r", "/work/b.rs"),
            0,
        );
        spawn_pool_session(
            state.path(),
            "sess_b",
            2,
            vec![b],
            None,
            Duration::from_millis(100),
        );

        let deadline = std::time::Instant::now() + Duration::from_millis(400);
        loop {
            if seen
                .lock()
                .unwrap()
                .iter()
                .any(|sa: &SessionApproval| sa.session == "sess_b")
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "sess_b's approval was never observed within the rediscovery bound"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // sess_a is still being watched (600ms hold): proof this did not wait
        // for it to end before picking sess_b up.
        watcher.join().unwrap().unwrap();
    }

    #[test]
    fn pending_all_reports_a_per_session_outcome_and_never_hides_an_unreachable_one() {
        let state = tempfile::tempdir().unwrap();
        let a = Approval::new(
            1,
            "Write",
            "/work/a.rs",
            crate::approvals::Authority::none("r", "/work/a.rs"),
            0,
        );
        spawn_pool_session(
            state.path(),
            "sess_a",
            1,
            vec![a],
            None,
            Duration::from_millis(50),
        );
        // A "live" session (its socket exists and answers `Ping`, so
        // `live_sessions` lists it) whose `Describe` refuses: the failure a
        // connect/describe/pending skip must surface instead of silently
        // dropping (#141 finding 5).
        let dir = session_dir(state.path(), "sess_broken");
        std::fs::create_dir_all(&dir).unwrap();
        let meta = SessionMeta {
            id: "sess_broken".to_owned(),
            project: PathBuf::from("/tmp/demo"),
            project_id: "proj_sess_broken".to_owned(),
            entry_snapshot: "blake3:abc".to_owned(),
            origin_repo: None,
            manifest: ward_policy::merge(
                &ward_policy::Policy::default(),
                &ward_policy::Policy::default(),
                &ward_policy::Policy::default(),
                ward_policy::SessionId("sess_broken".to_owned()),
                ward_policy::ProjectId("proj_sess_broken".to_owned()),
            ),
            started_unix_ms: 2,
            agent: None,
        };
        std::fs::write(dir.join("session.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
        let listener = UnixListener::bind(dir.join(SOCKET_NAME)).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut writer = stream.try_clone().unwrap();
                    for line in BufReader::new(stream)
                        .lines()
                        .map_while(std::result::Result::ok)
                    {
                        let request: Request = serde_json::from_str(&line).unwrap();
                        let reply = match request {
                            Request::Ping => Response::Ok,
                            Request::Describe => Response::Error("not ready".into()),
                            other => panic!("unexpected request {other:?}"),
                        };
                        let mut b = serde_json::to_vec(&reply).unwrap();
                        b.push(b'\n');
                        let _ = writer.write_all(&b);
                    }
                });
            }
        });

        let mut results = pending_all(state.path()).unwrap();
        results.sort_by(|a, b| a.session.cmp(&b.session));
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].session, "sess_a");
        let (description, pending) = results[0].outcome.as_ref().unwrap();
        assert_eq!(description.session, "sess_a");
        assert_eq!(pending.len(), 1);
        assert_eq!(results[1].session, "sess_broken");
        assert_eq!(
            results[1].outcome.as_ref().unwrap_err().to_string(),
            "events: daemon refused describe: not ready",
            "an unreachable session is reported, never indistinguishable from \
             one reachable with nothing pending"
        );
    }

    /// A session that answers `Ping` (so `live_sessions` reports it as live)
    /// but whose `Describe` always refuses, counting every attempt in
    /// `attempts`. Stops accepting connections entirely once `alive_for` has
    /// elapsed — the same "once sealed, stay sealed" idea `spawn_pool_session`
    /// uses, so `live_sessions` eventually and correctly stops counting this
    /// session too, letting a `follow_pending_all` watching only this one
    /// terminate on its own once it is done being live, instead of the test
    /// having to cut it off externally.
    fn spawn_describe_broken_session(
        state: &Path,
        id: &str,
        attempts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        alive_for: Duration,
    ) {
        let meta = SessionMeta {
            id: id.to_owned(),
            project: PathBuf::from("/tmp/demo"),
            project_id: format!("proj_{id}"),
            entry_snapshot: "blake3:abc".to_owned(),
            origin_repo: None,
            manifest: ward_policy::merge(
                &ward_policy::Policy::default(),
                &ward_policy::Policy::default(),
                &ward_policy::Policy::default(),
                ward_policy::SessionId(id.to_owned()),
                ward_policy::ProjectId(format!("proj_{id}")),
            ),
            started_unix_ms: 1,
            agent: None,
        };
        let dir = session_dir(state, id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("session.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
        let listener = UnixListener::bind(dir.join(SOCKET_NAME)).unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + alive_for;
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let attempts = std::sync::Arc::clone(&attempts);
                        std::thread::spawn(move || {
                            let mut writer = stream.try_clone().unwrap();
                            for line in BufReader::new(stream)
                                .lines()
                                .map_while(std::result::Result::ok)
                            {
                                let Ok(request) = serde_json::from_str::<Request>(&line) else {
                                    continue;
                                };
                                let reply = match request {
                                    Request::Ping => Response::Ok,
                                    Request::Describe => {
                                        attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                        Response::Error("not ready".into())
                                    }
                                    other => panic!("unexpected request {other:?}"),
                                };
                                let mut b = serde_json::to_vec(&reply).unwrap();
                                b.push(b'\n');
                                let _ = writer.write_all(&b);
                            }
                        });
                    }
                    // Nothing pending: a short, bounded wait before checking
                    // the deadline again rather than busy-spinning the CPU —
                    // this governs only how promptly the stand-in notices a
                    // new connection, never what the test asserts on.
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
            // Past `alive_for`: stop accepting so `serving`/`live_sessions`
            // correctly see this session as gone, the same as a real `wardd`
            // that has exited.
            drop(listener);
        });
    }

    /// A daemon for exactly one connection sequence: `Ping` → `Ok`,
    /// `Describe` → [`description`], `Pending` → `approvals`, and
    /// `Subscribe` → send nothing and hold the connection open, silent,
    /// *forever* — never closing it, never timing anything out on its own.
    /// Unlike [`spawn_pool_session`]'s `hold`
    /// (a fixed sleep after which it closes), this is what review 5284703397
    /// of #210, finding 2 says the previous test never actually exercised: a
    /// genuinely live, connected, healthy session that simply has nothing to
    /// say, indistinguishable from a daemon still faithfully serving a
    /// long-running agent. Every connection is handled on its own thread, so
    /// `live_sessions`' own repeated `serving()` probes (one per rediscovery
    /// interval, for as long as this call keeps watching) are answered
    /// independently of the one held-open `Subscribe` connection.
    fn spawn_quiet_forever_session(state: &Path, id: &str, approvals: Vec<Approval>) {
        let meta = SessionMeta {
            id: id.to_owned(),
            project: PathBuf::from("/tmp/demo"),
            project_id: format!("proj_{id}"),
            entry_snapshot: "blake3:abc".to_owned(),
            origin_repo: None,
            manifest: ward_policy::merge(
                &ward_policy::Policy::default(),
                &ward_policy::Policy::default(),
                &ward_policy::Policy::default(),
                ward_policy::SessionId(id.to_owned()),
                ward_policy::ProjectId(format!("proj_{id}")),
            ),
            started_unix_ms: 1,
            agent: None,
        };
        let dir = session_dir(state, id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("session.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
        let description = meta.describe();
        let listener = UnixListener::bind(dir.join(SOCKET_NAME)).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let description = description.clone();
                let approvals = approvals.clone();
                std::thread::spawn(move || {
                    let mut writer = stream.try_clone().unwrap();
                    let reply = |writer: &mut std::os::unix::net::UnixStream, r: &Response| {
                        let mut b = serde_json::to_vec(r).unwrap();
                        b.push(b'\n');
                        let _ = writer.write_all(&b);
                    };
                    for line in BufReader::new(stream)
                        .lines()
                        .map_while(std::result::Result::ok)
                    {
                        let Ok(request) = serde_json::from_str::<Request>(&line) else {
                            continue;
                        };
                        match request {
                            Request::Ping => reply(&mut writer, &Response::Ok),
                            Request::Describe => reply(
                                &mut writer,
                                &Response::Description(serde_json::to_value(&description).unwrap()),
                            ),
                            Request::Pending => {
                                reply(&mut writer, &Response::Pending(approvals.clone()));
                            }
                            Request::Subscribe { .. } => {
                                // Genuinely silent and never closed: nothing
                                // in this test process ever writes to or
                                // shuts this connection down from the daemon
                                // side. If `follow_pending_all`'s own
                                // cancellation does not unblock the watcher
                                // reading it, nothing here ever will.
                                std::thread::sleep(Duration::from_secs(3600));
                                break;
                            }
                            other => panic!("unexpected request {other:?}"),
                        }
                    }
                });
            }
        });
    }

    /// Review 5284703397 of #210, finding 2 — replacing this test's previous
    /// shape: the old version used [`spawn_pool_session_signaling`] with a
    /// short `hold` after which the fake daemon closed the `Subscribe`
    /// connection on its own, and asserted `follow_pending_all` returned only
    /// once that closure happened — which proves "this call eventually
    /// notices a stream closing", not "this call bounds its own cleanup for
    /// a watcher that is still genuinely alive and silent", the exact gap the
    /// review called out. `sess_a` here never closes its `Subscribe`
    /// connection and never sends anything on it — indistinguishable from a
    /// real daemon quietly serving a live agent — so the *only* way
    /// `follow_pending_all` can return once `live_sessions` starts failing is
    /// by actively unblocking that watcher's read itself, not by waiting for
    /// the far end to do it.
    #[test]
    fn follow_pending_all_bounds_cleanup_for_a_genuinely_quiet_live_watcher() {
        let state = tempfile::tempdir().unwrap();
        let approval = Approval::new(
            1,
            "Write",
            "/work/a.rs",
            crate::approvals::Authority::none("r", "/work/a.rs"),
            0,
        );
        spawn_quiet_forever_session(state.path(), "sess_a", vec![approval]);

        // Signalled from inside `emit` itself, not from the fake daemon's
        // side of the `Pending` exchange: the daemon has already answered by
        // the time it would send such a signal, but `follow_pending`'s own
        // client-side processing of that answer (matching ids, calling
        // `emit`) still has to happen afterwards — signalling from the
        // daemon would race the assertion below against that client-side
        // work instead of actually waiting for it.
        let (emitted_tx, emitted_rx) = mpsc::channel();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let collected = std::sync::Arc::clone(&seen);
        let state_path = state.path().to_path_buf();
        let started = std::time::Instant::now();
        let handle = std::thread::spawn(move || {
            follow_pending_all(
                &state_path,
                Duration::from_millis(20),
                Duration::from_millis(20),
                move |sa| {
                    collected.lock().unwrap().push(sa);
                    let _ = emitted_tx.send(());
                },
            )
        });

        // `sess_a`'s watcher has, by now, connected its `Subscribe` stream,
        // gone through the backlog (`Next::Quiet` after 20ms of silence —
        // there is no backlog at all here), listed what is pending once (the
        // one approval configured above, emitted here), and settled into its
        // unbounded post-backlog read: genuinely blocked, exactly the
        // scenario finding 2 is about, not merely "about to connect".
        emitted_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("sess_a's watcher emits what is pending after its backlog");
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "the one approval was emitted"
        );

        // A discovery failure distinct from "nothing live": the sessions
        // directory itself becomes unreadable as a directory (`ENOTDIR`), so
        // the next `live_sessions` call — driven by the 20ms rediscover
        // timeout — errors instead of just finding nothing new. `sess_a`'s
        // own already-open `Subscribe` connection is unaffected by its
        // directory entry being removed out from under it.
        std::fs::remove_dir_all(state.path().join("sessions")).unwrap();
        std::fs::write(state.path().join("sessions"), b"not a directory").unwrap();

        // Generous but finite, and nowhere near `sess_a`'s 3600s `Subscribe`
        // hold: without cancellation, `join_watchers` would block on this
        // watcher's `next_response()` until that hold elapsed — over an hour
        // — so this bound alone already tells the two apart.
        let result = handle.join().expect("follow_pending_all does not panic");
        let elapsed = started.elapsed();
        assert!(
            result.is_err(),
            "the corrupted sessions directory must surface as an error"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "returned in {elapsed:?}: a genuinely quiet, healthy watcher must be \
             unblocked and joined within a bound, not waited on indefinitely"
        );

        // `handle.join()` above only returns once every watcher thread —
        // including `sess_a`'s — has actually finished, not merely been
        // abandoned: `join_watchers` cannot return early while a `JoinHandle`
        // it holds is still running. That is already proof the watcher
        // thread stopped calling `emit`; this is the belt-and-suspenders
        // check that nothing slipped through anyway.
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "no further approval was emitted once follow_pending_all returned"
        );
    }

    /// Review 5284361040 of #210, finding 2: a session that answers `Ping`
    /// (so `live_sessions` keeps reporting it as live) but whose `Describe`
    /// always refuses must not be retried in a tight reconnect loop — the
    /// previous shape dropped it from `watched` on every failure, found
    /// `watched` empty, and immediately rediscovered with nothing slowing it
    /// down. `sess_broken` here stops answering `Ping` at all after
    /// `alive_for`, so `follow_pending_all` eventually sees nothing live and
    /// returns on its own, letting this assert on the attempts made during
    /// the bounded window it really was live: with backoff, that count is
    /// bounded by roughly `alive_for / rediscover`, not by how fast a
    /// reconnect loop can spin.
    #[test]
    fn follow_pending_all_backs_off_a_ping_live_describe_failing_session() {
        let state = tempfile::tempdir().unwrap();
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let alive_for = Duration::from_millis(200);
        spawn_describe_broken_session(
            state.path(),
            "sess_broken",
            std::sync::Arc::clone(&attempts),
            alive_for,
        );

        let state_path = state.path().to_path_buf();
        let rediscover = Duration::from_millis(30);
        let handle = std::thread::spawn(move || {
            follow_pending_all(&state_path, Duration::from_millis(20), rediscover, |_| {})
        });
        let result = handle.join().expect("follow_pending_all does not panic");

        let seen = attempts.load(std::sync::atomic::Ordering::SeqCst);
        assert!(seen >= 1, "the broken session was never even tried");
        // A tight reconnect loop would attempt this hundreds or thousands of
        // times over `alive_for`; bounded backoff keeps it to roughly one
        // attempt per `rediscover` interval.
        let generous_bound = (alive_for.as_millis() / rediscover.as_millis()) as usize + 5;
        assert!(
            seen <= generous_bound,
            "{seen} describe attempts in {alive_for:?} at a {rediscover:?} cooldown \
             looks like a tight reconnect loop, not bounded backoff"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("not ready"),
            "a persistent describe failure must be visible in the result, not \
             silently retried forever: {err}"
        );
    }
}
