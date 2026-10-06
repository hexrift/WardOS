//! The per-attempt action channel (#404, ADR-0031; #332 stage 3).
//!
//! A node started with `--action-channel` ([`crate::execution::NodeExecution::with_action_channel`])
//! honours a manifest's `actions` grant by giving the attempt its own channel
//! ([`AttemptActions`]): a Unix socket the node listens on, in the attempt's private
//! directory `<task-root>/<task>/<attempt>.actions/` (mode 0700) — beside the workspace,
//! never inside it, like the evidence and egress directories. The sandbox binds that socket
//! at [`ward_launch::ACTION_SOCKET`] and names it in [`ACTION_SOCKET_ENV`].
//!
//! The workload writes one JSON request per line (`{"id","kind","summary","detail"}`,
//! [`ward_node_protocol::ActionRequest`]) and reads one reply line per answered request
//! (`{"id","decision","note"?}`, [`ward_node_protocol::ActionReply`]) on the connection it
//! asked on. Each line is read bounded at [`MAX_ACTION_LINE_BYTES`]. A line that is
//! oversized, malformed, a node-protocol or control-protocol request (anything that parses
//! as an object with a `request`, `req` or `response` member: a lifecycle request or a
//! `hello`), of a kind the grant does not name, a repeated id, or past the grant's
//! `max_pending` or `max_total` is answered with nothing: the node queues a
//! `NodeActionRefused` record and closes that connection. At [`MAX_ACTION_REFUSALS`]
//! refusals the channel closes for the rest of the attempt. At most
//! [`MAX_ACTION_CONNECTIONS`] connections are served at once; a further one is closed
//! unread.
//!
//! The registry ([`crate::task`]), the attempt's single evidence writer, records for the
//! channel: the channel's own threads only queue records, and every method here that takes
//! a `record` callback appends the queue first, in order, under the registry's lock. A
//! request becomes visible to the control plane, and answerable, only once its
//! `NodeActionRequested` record is appended; a request whose record cannot be appended is
//! answered `cancelled` and never listed. An answer from the control plane is appended
//! before the workload is told; a request nobody answers within the grant's `wait_secs` is
//! answered `expired`, recorded first. While the attempt is paused the wait clocks stop, so
//! a pending request stays pending; [`AttemptActions::finish`] answers every pending
//! request `cancelled` when the attempt ends, before its end record, and closes the
//! channel. A request whose connection closes before it is answered is withdrawn: answered
//! `cancelled`. Records carry sizes and `BLAKE3-256` digests, never a summary, detail or
//! note.
//!
//! Replies are written without blocking: a workload that does not read its socket loses
//! the reply (the connection is shut down), never the node's progress. The channel grants
//! nothing by itself: an approval of a workload's request is a statement the node records
//! and relays.
//!
//! A channel started with a manifest's `hold` ([`AttemptActions::start_held`], #415,
//! ADR-0035) also holds the capabilities it names: [`AttemptActions::hold`] is what the
//! attempt's egress proxy asks about every request it would let through. The first request
//! touching a held capability opens one `approval` request for it, the node's own, under
//! [`ward_node_protocol::hold_request_id`] and listed with the capability; the capability
//! is refused until that request is answered `approved`, recorded, and any other answer
//! keeps it refused for the attempt. The node's requests count against neither the
//! workload's `max_pending` nor its `max_total`, and their ids are reserved.
//!
//! A Unix socket path is at most 108 bytes and a task root may be deep, so the listener is
//! bound through a held descriptor of the directory (`/proc/self/fd/<n>/actions.sock`)
//! while the sandbox is handed the real path, as for the egress proxy.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nix::sys::socket::{MsgFlags, Shutdown as SocketShutdown, send, shutdown};
use thiserror::Error;
use ward_events::{Blake3Hash, NodeActionDecision, NodeActionKind, NodeActionRefusal, WardEvent};
use ward_node_protocol::{
    ActionDecision, ActionError, ActionGrant, ActionId, ActionKind, ActionNote,
    ActionRejectionReason, ActionReply, ActionRequest, HeldCapability, HoldGrant,
    MAX_ACTION_LINE_BYTES, OperationId, PendingAction, TaskBinding, hold_request_id,
};
use ward_proxy::{Held, Hold, Host, Target};

use crate::evidence::private_dir;

/// Suffix of an attempt's action-channel directory, beside its workspace.
pub const ACTIONS_SUFFIX: &str = ".actions";

/// File name of the channel socket inside an attempt's action-channel directory.
pub const ACTION_SOCKET_FILE: &str = "actions.sock";

/// The environment variable naming the channel socket inside the sandbox.
pub const ACTION_SOCKET_ENV: &str = "WARD_ACTION_SOCKET";

/// Connections one channel serves at once; a further one is closed unread.
pub const MAX_ACTION_CONNECTIONS: usize = 8;

/// Refused lines after which the channel closes for the rest of the attempt, so a hostile
/// workload cannot grow its evidence log without bound.
pub const MAX_ACTION_REFUSALS: u32 = 16;

const ACCEPT_RETRY: Duration = Duration::from_millis(10);

/// Why an attempt's action channel could not start.
#[derive(Debug, Error)]
pub enum ActionChannelError {
    /// The directory or the socket could not be created.
    #[error("action channel I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The directory is not a private directory.
    #[error("action channel directory is not a private directory")]
    InsecurePath,
}

/// The action-channel directory of `binding` under the task root `root`:
/// `<root>/<task>/<attempt>.actions`.
#[must_use]
pub fn actions_dir(root: &Path, binding: TaskBinding) -> PathBuf {
    root.join(binding.task().to_string())
        .join(format!("{}{ACTIONS_SUFFIX}", binding.attempt()))
}

/// The action-channel directory beside the attempt workspace `workspace`.
#[must_use]
pub fn actions_dir_beside(workspace: &Path) -> Option<PathBuf> {
    let attempt = workspace.file_name()?.to_str()?;
    Some(workspace.with_file_name(format!("{attempt}{ACTIONS_SUFFIX}")))
}

/// The evidence spelling of a request kind.
#[must_use]
pub const fn action_kind(kind: ActionKind) -> NodeActionKind {
    match kind {
        ActionKind::Approval => NodeActionKind::Approval,
        ActionKind::Decision => NodeActionKind::Decision,
    }
}

/// The evidence spelling of a decision.
#[must_use]
pub const fn action_decision(decision: ActionDecision) -> NodeActionDecision {
    match decision {
        ActionDecision::Approved => NodeActionDecision::Approved,
        ActionDecision::Denied => NodeActionDecision::Denied,
        ActionDecision::Expired => NodeActionDecision::Expired,
        ActionDecision::Cancelled => NodeActionDecision::Cancelled,
    }
}

/// Classify one channel line, newline removed: the request it carries, or why it is
/// refused.
///
/// # Errors
///
/// Returns the [`NodeActionRefusal`] the line earns.
pub fn classify(line: &[u8]) -> Result<ActionRequest, NodeActionRefusal> {
    if line.len() > MAX_ACTION_LINE_BYTES {
        return Err(NodeActionRefusal::Oversized);
    }
    let text = std::str::from_utf8(line).map_err(|_| NodeActionRefusal::Malformed)?;
    let value = serde_json::from_str::<serde_json::Value>(text)
        .map_err(|_| NodeActionRefusal::Malformed)?;
    if let Some(object) = value.as_object()
        && ["request", "req", "response"]
            .iter()
            .any(|key| object.contains_key(*key))
    {
        return Err(NodeActionRefusal::ControlRequest);
    }
    ActionRequest::decode(text).map_err(|error| match error {
        ActionError::TooLong => NodeActionRefusal::Oversized,
        ActionError::InvalidGrant | ActionError::Malformed | ActionError::InvalidDecision => {
            NodeActionRefusal::Malformed
        }
    })
}

fn requested_event(action: u32, request: &ActionRequest) -> WardEvent {
    WardEvent::NodeActionRequested {
        action,
        kind: action_kind(request.kind()),
        summary_bytes: request.summary().len() as u64,
        summary: Blake3Hash::hash(request.summary().as_bytes()),
        detail_bytes: request.detail().len() as u64,
        detail: Blake3Hash::hash(request.detail().as_bytes()),
    }
}

fn answered_event(
    action: u32,
    decision: ActionDecision,
    operation: Option<OperationId>,
    note: Option<&ActionNote>,
) -> WardEvent {
    WardEvent::NodeActionAnswered {
        action,
        decision: action_decision(decision),
        operation: operation.map(OperationId::get),
        note_bytes: note.map_or(0, |note| note.as_str().len() as u64),
        note: note.map(|note| Blake3Hash::hash(note.as_str().as_bytes())),
    }
}

#[derive(Debug)]
struct Pending {
    request: ActionRequest,
    /// The workload's connection it was asked on; `None` for a request the node opened for
    /// a held capability.
    conn: Option<u64>,
    deadline: Instant,
    recorded: bool,
    hold: Option<HeldCapability>,
}

/// One held capability and the request the node opened for it, once it has.
#[derive(Debug)]
struct HoldSlot {
    held: HeldCapability,
    action: Option<u32>,
}

impl HoldSlot {
    fn covers(&self, host: Option<&str>, service: Option<&str>) -> bool {
        match &self.held {
            HeldCapability::Host(pattern) => {
                host.is_some_and(|host| ward_proxy::hosts::matches(pattern, host))
            }
            HeldCapability::Service(name) => service == Some(name.as_str()),
        }
    }
}

type AnswerKey = (u32, ActionDecision, Option<ActionNote>);

#[derive(Debug, Default)]
struct State {
    next_action: u32,
    sent: u32,
    ids: HashSet<ActionId>,
    pending: BTreeMap<u32, Pending>,
    answered: HashMap<u32, ActionDecision>,
    answer_ops: BTreeMap<OperationId, AnswerKey>,
    queue: Vec<WardEvent>,
    connections: HashMap<u64, UnixStream>,
    next_conn: u64,
    refusals: u32,
    paused_since: Option<Instant>,
    closed: bool,
    holds: Vec<HoldSlot>,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    grant: ActionGrant,
    listener: UnixListener,
    socket: PathBuf,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn register(&self, conn: u64, request: ActionRequest) -> Result<(), Option<NodeActionRefusal>> {
        let mut state = self.lock();
        if state.closed {
            return Err(None);
        }
        if !self.grant.allows(request.kind()) {
            return Err(Some(NodeActionRefusal::KindNotGranted));
        }
        if state.ids.contains(request.id()) {
            return Err(Some(NodeActionRefusal::DuplicateId));
        }
        let waiting = state
            .pending
            .values()
            .filter(|pending| pending.conn.is_some())
            .count();
        if u32::try_from(waiting).unwrap_or(u32::MAX) >= self.grant.max_pending() {
            return Err(Some(NodeActionRefusal::TooManyPending));
        }
        if state.sent >= self.grant.max_total() {
            return Err(Some(NodeActionRefusal::TooManyRequests));
        }
        state.next_action += 1;
        state.sent += 1;
        let action = state.next_action;
        let started = state.paused_since.unwrap_or_else(Instant::now);
        let deadline = started + Duration::from_secs(u64::from(self.grant.wait_secs()));
        state.ids.insert(request.id().clone());
        state.queue.push(requested_event(action, &request));
        state.pending.insert(
            action,
            Pending {
                request,
                conn: Some(conn),
                deadline,
                recorded: false,
                hold: None,
            },
        );
        Ok(())
    }

    /// What the attempt's proxy is told about a request for `host` (on the credential route
    /// of `service`, if any): every held capability it touches is opened on first use, and
    /// it passes only once each of them was approved, recorded.
    fn held(&self, host: Option<&str>, service: Option<&str>, now: Instant) -> Option<Held> {
        let mut state = self.lock();
        let covering: Vec<usize> = state
            .holds
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.covers(host, service))
            .map(|(index, _)| index)
            .collect();
        let refusals: Vec<Held> = covering
            .into_iter()
            .filter_map(|index| self.hold_state(&mut state, index, now))
            .collect();
        refusals.into_iter().next()
    }

    /// The refusal the held capability at `index` earns now, opening its request first if
    /// nothing has; `None` once it was approved.
    fn hold_state(&self, state: &mut State, index: usize, now: Instant) -> Option<Held> {
        let opened = match state.holds[index].action {
            Some(action) => Some(action),
            None if state.closed => None,
            None => self.open(state, index, now),
        };
        let Some(action) = opened else {
            return Some(Held {
                reason: "hold:cancelled".to_owned(),
                body: "approval cancelled",
            });
        };
        let (state_name, body) = match state.answered.get(&action) {
            Some(ActionDecision::Approved) => return None,
            Some(ActionDecision::Denied) => ("denied", "approval denied"),
            Some(ActionDecision::Expired) => ("expired", "approval expired"),
            Some(ActionDecision::Cancelled) => ("cancelled", "approval cancelled"),
            None => ("held", "held for approval"),
        };
        Some(Held {
            reason: format!("hold:{state_name}:{action}"),
            body,
        })
    }

    /// Open the approval request for the held capability at `index`, queued for the record.
    fn open(&self, state: &mut State, index: usize, now: Instant) -> Option<u32> {
        let held = state.holds[index].held.clone();
        let request = ActionRequest::new(
            hold_request_id(index),
            ActionKind::Approval,
            held.summary(),
            held.detail(),
        )
        .ok()?;
        state.next_action += 1;
        let action = state.next_action;
        let started = state.paused_since.unwrap_or(now);
        state.queue.push(requested_event(action, &request));
        state.pending.insert(
            action,
            Pending {
                request,
                conn: None,
                deadline: started + Duration::from_secs(u64::from(self.grant.wait_secs())),
                recorded: false,
                hold: Some(held),
            },
        );
        state.holds[index].action = Some(action);
        Some(action)
    }

    fn refuse(&self, reason: NodeActionRefusal, bytes: usize) {
        let mut state = self.lock();
        if state.closed {
            return;
        }
        state.refusals += 1;
        state.queue.push(WardEvent::NodeActionRefused {
            reason,
            bytes: bytes as u64,
        });
        if state.refusals >= MAX_ACTION_REFUSALS {
            self.close(&mut state);
        }
    }

    /// The workload's connection `conn` ended: withdraw its pending requests.
    fn withdraw(&self, conn: u64) {
        let mut state = self.lock();
        let withdrawn: Vec<u32> = state
            .pending
            .iter()
            .filter(|(_, pending)| pending.conn == Some(conn))
            .map(|(action, _)| *action)
            .collect();
        for action in withdrawn {
            state.pending.remove(&action);
            state.answered.insert(action, ActionDecision::Cancelled);
            state.queue.push(answered_event(
                action,
                ActionDecision::Cancelled,
                None,
                None,
            ));
        }
        if let Some(stream) = state.connections.remove(&conn) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    /// Close the channel: every pending request is answered `cancelled` (queued for the
    /// record), every connection is shut down, the listener stops and the socket goes.
    fn close(&self, state: &mut State) {
        if state.closed {
            return;
        }
        let pending = std::mem::take(&mut state.pending);
        for (action, entry) in pending {
            state.answered.insert(action, ActionDecision::Cancelled);
            state.queue.push(answered_event(
                action,
                ActionDecision::Cancelled,
                None,
                None,
            ));
            reply(state, &entry, ActionDecision::Cancelled, None);
        }
        self.shut(state);
    }

    fn shut(&self, state: &mut State) {
        state.closed = true;
        for (_, stream) in state.connections.drain() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        // A shut-down listening socket wakes a blocked accept with an error.
        let _ = shutdown(self.listener.as_raw_fd(), SocketShutdown::Both);
        let _ = std::fs::remove_file(&self.socket);
    }

    /// Append every queued record through `record`, in order, and act on what could not
    /// be: a request whose record failed is answered `cancelled`, unrecorded and unlisted.
    fn flush(state: &mut State, record: &mut dyn FnMut(WardEvent) -> bool) {
        for event in std::mem::take(&mut state.queue) {
            let requested = match &event {
                WardEvent::NodeActionRequested { action, .. } => Some(*action),
                _ => None,
            };
            let recorded = record(event);
            let Some(action) = requested else {
                continue;
            };
            if recorded {
                if let Some(pending) = state.pending.get_mut(&action) {
                    pending.recorded = true;
                }
            } else if let Some(pending) = state.pending.remove(&action) {
                state.answered.insert(action, ActionDecision::Cancelled);
                reply(state, &pending, ActionDecision::Cancelled, None);
            }
        }
    }

    /// Answer `expired` every recorded request whose wait ran out by `now`, recording it
    /// first; nothing expires while the attempt is paused.
    fn expire(state: &mut State, now: Instant, record: &mut dyn FnMut(WardEvent) -> bool) {
        if state.paused_since.is_some() {
            return;
        }
        let due: Vec<u32> = state
            .pending
            .iter()
            .filter(|(_, pending)| pending.recorded && pending.deadline <= now)
            .map(|(action, _)| *action)
            .collect();
        for action in due {
            let _ = record(answered_event(action, ActionDecision::Expired, None, None));
            if let Some(pending) = state.pending.remove(&action) {
                state.answered.insert(action, ActionDecision::Expired);
                reply(state, &pending, ActionDecision::Expired, None);
            }
        }
    }
}

/// Write the reply to `pending`'s request on its connection without blocking; a reply that
/// does not fit whole shuts the connection down, so the workload never reads half of one.
fn reply(state: &mut State, pending: &Pending, decision: ActionDecision, note: Option<ActionNote>) {
    let Some(conn) = pending.conn else {
        return;
    };
    let Some(stream) = state.connections.get(&conn) else {
        return;
    };
    let reply = ActionReply::new(pending.request.id().clone(), decision, note);
    let Ok(mut line) = serde_json::to_vec(&reply) else {
        return;
    };
    line.push(b'\n');
    let sent = send(
        stream.as_raw_fd(),
        &line,
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
    );
    if sent.ok() != Some(line.len()) {
        let _ = stream.shutdown(std::net::Shutdown::Both);
        state.connections.remove(&conn);
    }
}

/// One attempt's action channel. Dropping it closes the channel and removes its socket.
pub struct AttemptActions {
    shared: Arc<Shared>,
    accept: Mutex<Option<JoinHandle<()>>>,
    _dir: File,
}

impl std::fmt::Debug for AttemptActions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttemptActions")
            .field("socket", &self.shared.socket)
            .field("grant", &self.shared.grant)
            .finish_non_exhaustive()
    }
}

impl AttemptActions {
    /// Start the channel for `grant` in the directory `dir` (created mode 0700, refused
    /// when it is not a private directory).
    ///
    /// # Errors
    ///
    /// Returns [`ActionChannelError`] when the directory cannot be prepared or the socket
    /// cannot be bound; nothing is left listening then.
    pub fn start(dir: &Path, grant: ActionGrant) -> Result<Self, ActionChannelError> {
        Self::start_held(dir, grant, None)
    }

    /// [`Self::start`], also holding the capabilities of `hold` (#415, ADR-0035): their
    /// request ids are the node's, and [`Self::hold`] is what the attempt's proxy asks.
    ///
    /// # Errors
    ///
    /// As [`Self::start`].
    pub fn start_held(
        dir: &Path,
        grant: ActionGrant,
        holding: Option<&HoldGrant>,
    ) -> Result<Self, ActionChannelError> {
        private_dir(dir).map_err(|error| match error {
            crate::evidence::EvidenceError::Io(error) => ActionChannelError::Io(error),
            _ => ActionChannelError::InsecurePath,
        })?;
        let held = File::open(dir)?;
        let bind = PathBuf::from(format!(
            "/proc/self/fd/{}/{ACTION_SOCKET_FILE}",
            held.as_raw_fd()
        ));
        let socket = dir.join(ACTION_SOCKET_FILE);
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&bind)?;
        let holds: Vec<HoldSlot> = holding
            .map(HoldGrant::held)
            .unwrap_or_default()
            .into_iter()
            .map(|held| HoldSlot { held, action: None })
            .collect();
        let state = State {
            ids: (0..holds.len()).map(hold_request_id).collect(),
            holds,
            ..State::default()
        };
        let shared = Arc::new(Shared {
            state: Mutex::new(state),
            grant,
            listener: listener.try_clone()?,
            socket,
        });
        let accepting = Arc::clone(&shared);
        let accept = std::thread::Builder::new()
            .name("ward-node-actions".to_owned())
            .spawn(move || accept_loop(&accepting, &listener))?;
        Ok(Self {
            shared,
            accept: Mutex::new(Some(accept)),
            _dir: held,
        })
    }

    /// Host path of the socket the sandbox binds at [`ward_launch::ACTION_SOCKET`].
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.shared.socket
    }

    /// The grant the channel enforces.
    #[must_use]
    pub fn grant(&self) -> &ActionGrant {
        &self.shared.grant
    }

    /// The hold the attempt's egress proxy asks about every request it would let through
    /// ([`ward_proxy::Hold`]): a request touching a held capability opens its approval
    /// request on first use and is refused until that request is answered `approved`,
    /// recorded; one the hold does not name passes.
    #[must_use]
    pub fn hold(&self) -> Arc<dyn Hold> {
        Arc::new(ActionHold {
            shared: Arc::clone(&self.shared),
        })
    }

    /// Whether the registry has something to do: records queued, or a recorded request
    /// whose wait ran out by `now`. Takes only the channel's own lock.
    #[must_use]
    pub fn due(&self, now: Instant) -> bool {
        let state = self.shared.lock();
        !state.queue.is_empty()
            || (state.paused_since.is_none()
                && state
                    .pending
                    .values()
                    .any(|pending| pending.recorded && pending.deadline <= now))
    }

    /// Append the queued records through `record` and answer `expired` what ran out by
    /// `now`.
    pub fn tend(&self, now: Instant, record: &mut dyn FnMut(WardEvent) -> bool) {
        let mut state = self.shared.lock();
        Shared::flush(&mut state, record);
        Shared::expire(&mut state, now, record);
    }

    /// [`Self::tend`], then the recorded pending requests, oldest first, with the time each
    /// has left as of `now` (frozen while the attempt is paused).
    pub fn list(
        &self,
        now: Instant,
        record: &mut dyn FnMut(WardEvent) -> bool,
    ) -> Vec<PendingAction> {
        let mut state = self.shared.lock();
        Shared::flush(&mut state, record);
        Shared::expire(&mut state, now, record);
        let clock = state.paused_since.unwrap_or(now);
        state
            .pending
            .iter()
            .filter(|(_, pending)| pending.recorded)
            .filter_map(|(action, pending)| {
                let left = pending.deadline.saturating_duration_since(clock);
                let listed = PendingAction::new(
                    *action,
                    pending.request.clone(),
                    u64::try_from(left.as_millis()).unwrap_or(u64::MAX),
                )
                .ok()?;
                Some(match &pending.hold {
                    Some(held) => listed.with_hold(held.clone()),
                    None => listed,
                })
            })
            .collect()
    }

    /// The recorded result of replaying the `answer` `operation_id`: `Ok` with the decision
    /// for the same answer, `stale_operation` for a different one, `None` for an id never
    /// applied.
    #[must_use]
    pub fn replay(
        &self,
        operation_id: OperationId,
        action: u32,
        decision: ActionDecision,
        note: Option<&ActionNote>,
    ) -> Option<Result<ActionDecision, ActionRejectionReason>> {
        let state = self.shared.lock();
        let (applied, applied_decision, applied_note) = state.answer_ops.get(&operation_id)?;
        Some(
            if *applied == action && *applied_decision == decision && applied_note.as_ref() == note
            {
                Ok(decision)
            } else {
                Err(ActionRejectionReason::StaleOperation)
            },
        )
    }

    /// Answer the pending request `action` with `decision` under `operation_id`: append
    /// the record through `record`, then tell the workload. A replay of the same answer is
    /// accepted again without acting.
    ///
    /// # Errors
    ///
    /// `stale_operation` when `operation_id` already applied a different answer,
    /// `already_answered` for a request answered before (by the control plane or the
    /// node), `unknown_request` for a number the attempt never recorded, and
    /// `resource_unavailable` when the record cannot be appended (the request stays
    /// pending).
    pub fn answer(
        &self,
        now: Instant,
        operation_id: OperationId,
        action: u32,
        decision: ActionDecision,
        note: Option<ActionNote>,
        record: &mut dyn FnMut(WardEvent) -> bool,
    ) -> Result<ActionDecision, ActionRejectionReason> {
        if let Some(replayed) = self.replay(operation_id, action, decision, note.as_ref()) {
            return replayed;
        }
        let mut state = self.shared.lock();
        Shared::flush(&mut state, record);
        Shared::expire(&mut state, now, record);
        if !state
            .pending
            .get(&action)
            .is_some_and(|pending| pending.recorded)
        {
            return Err(if state.answered.contains_key(&action) {
                ActionRejectionReason::AlreadyAnswered
            } else {
                ActionRejectionReason::UnknownRequest
            });
        }
        if !record(answered_event(
            action,
            decision,
            Some(operation_id),
            note.as_ref(),
        )) {
            return Err(ActionRejectionReason::ResourceUnavailable);
        }
        if let Some(pending) = state.pending.remove(&action) {
            reply(&mut state, &pending, decision, note.clone());
        }
        state.answered.insert(action, decision);
        state
            .answer_ops
            .insert(operation_id, (action, decision, note));
        Ok(decision)
    }

    /// Stop or restart the wait clocks: while paused nothing expires, and on resume every
    /// pending deadline moves by the time spent paused.
    pub fn set_paused(&self, paused: bool, now: Instant) {
        let mut state = self.shared.lock();
        match (paused, state.paused_since) {
            (true, None) => state.paused_since = Some(now),
            (false, Some(since)) => {
                let held = now.saturating_duration_since(since);
                for pending in state.pending.values_mut() {
                    pending.deadline += held;
                }
                state.paused_since = None;
            }
            _ => {}
        }
    }

    /// The attempt ended: append the queued records, answer every pending request
    /// `cancelled` (recorded first) and close the channel. Idempotent.
    pub fn finish(&self, record: &mut dyn FnMut(WardEvent) -> bool) {
        let mut state = self.shared.lock();
        Shared::flush(&mut state, record);
        let pending = std::mem::take(&mut state.pending);
        for (action, entry) in pending {
            let _ = record(answered_event(
                action,
                ActionDecision::Cancelled,
                None,
                None,
            ));
            state.answered.insert(action, ActionDecision::Cancelled);
            reply(&mut state, &entry, ActionDecision::Cancelled, None);
        }
        if !state.closed {
            self.shared.shut(&mut state);
        }
        Shared::flush(&mut state, record);
    }

    /// Whether the channel has closed: the attempt ended, or the workload exhausted its
    /// refusals.
    #[must_use]
    pub fn closed(&self) -> bool {
        self.shared.lock().closed
    }

    #[cfg(test)]
    fn connections(&self) -> usize {
        self.shared.lock().connections.len()
    }
}

impl Drop for AttemptActions {
    fn drop(&mut self) {
        {
            let mut state = self.shared.lock();
            if !state.closed {
                self.shared.shut(&mut state);
            }
        }
        if let Some(accept) = self
            .accept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = accept.join();
        }
    }
}

/// What an attempt's egress proxy asks about the requests it would let through.
#[derive(Debug)]
struct ActionHold {
    shared: Arc<Shared>,
}

impl Hold for ActionHold {
    fn held(&self, target: &Target, route: Option<&str>) -> Option<Held> {
        let host = match &target.host {
            Host::Name(name) => Some(name.as_str()),
            Host::Ip(_) => None,
        };
        let service = route.and_then(|prefix| prefix.strip_prefix('/'));
        self.shared.held(host, service, Instant::now())
    }
}

fn accept_loop(shared: &Arc<Shared>, listener: &UnixListener) {
    loop {
        let accepted = listener.accept();
        let mut state = shared.lock();
        if state.closed {
            return;
        }
        let Ok((stream, _)) = accepted else {
            drop(state);
            std::thread::sleep(ACCEPT_RETRY);
            continue;
        };
        if state.connections.len() >= MAX_ACTION_CONNECTIONS {
            continue;
        }
        let Ok(writer) = stream.try_clone() else {
            continue;
        };
        let conn = state.next_conn;
        state.next_conn += 1;
        state.connections.insert(conn, writer);
        drop(state);
        let serving = Arc::clone(shared);
        let spawned = std::thread::Builder::new()
            .name("ward-node-action".to_owned())
            .spawn(move || serve_connection(&serving, conn, stream));
        if spawned.is_err() {
            shared.withdraw(conn);
        }
    }
}

fn serve_connection(shared: &Shared, conn: u64, stream: UnixStream) {
    let mut reader = BufReader::new(stream);
    let limit = u64::try_from(MAX_ACTION_LINE_BYTES + 2).unwrap_or(u64::MAX);
    loop {
        let mut line = Vec::new();
        match reader.by_ref().take(limit).read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let read = line.len();
        if line.last() != Some(&b'\n') {
            let reason = if read > MAX_ACTION_LINE_BYTES {
                NodeActionRefusal::Oversized
            } else {
                NodeActionRefusal::Malformed
            };
            shared.refuse(reason, read);
            break;
        }
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let refused = match classify(&line) {
            Ok(request) => shared.register(conn, request).err(),
            Err(reason) => Some(Some(reason)),
        };
        match refused {
            None => {}
            Some(Some(reason)) => {
                shared.refuse(reason, read);
                break;
            }
            Some(None) => break,
        }
    }
    shared.withdraw(conn);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::Write;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    use ward_events::{ExecutionAttemptId, LeaseId, TaskId};

    use super::*;

    fn grant(max_pending: u32, max_total: u32, wait_secs: u32) -> ActionGrant {
        ActionGrant::new(
            vec![ActionKind::Approval],
            max_pending,
            max_total,
            wait_secs,
        )
        .unwrap()
    }

    fn op(value: u64) -> OperationId {
        OperationId::new(value).unwrap()
    }

    fn line(id: &str) -> String {
        format!(r#"{{"id":"{id}","kind":"approval","summary":"deploy {id}","detail":"the plan"}}"#)
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        actions: AttemptActions,
        records: Arc<Mutex<Vec<WardEvent>>>,
    }

    impl Fixture {
        fn new(grant: ActionGrant) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let actions = AttemptActions::start(&dir.path().join("a.actions"), grant).unwrap();
            Self {
                _dir: dir,
                actions,
                records: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn recorder(&self) -> impl FnMut(WardEvent) -> bool + use<> {
            let records = Arc::clone(&self.records);
            move |event| {
                records.lock().unwrap().push(event);
                true
            }
        }

        fn connect(&self) -> (UnixStream, BufReader<UnixStream>) {
            let stream = UnixStream::connect(self.actions.socket()).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let reader = BufReader::new(stream.try_clone().unwrap());
            (stream, reader)
        }

        /// Tend until `count` requests are listed.
        fn listed(&self, count: usize) -> Vec<PendingAction> {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let listed = self.actions.list(Instant::now(), &mut self.recorder());
                if listed.len() == count {
                    return listed;
                }
                assert!(
                    Instant::now() < deadline,
                    "never listed {count}: {listed:?}"
                );
                std::thread::yield_now();
            }
        }

        fn records(&self) -> Vec<WardEvent> {
            self.records.lock().unwrap().clone()
        }

        /// Tend until a record matching `wanted` was appended.
        fn recorded(&self, wanted: impl Fn(&WardEvent) -> bool) {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !self.records().iter().any(&wanted) {
                assert!(
                    Instant::now() < deadline,
                    "never recorded: {:?}",
                    self.records()
                );
                self.actions.tend(Instant::now(), &mut self.recorder());
                std::thread::yield_now();
            }
        }
    }

    fn reply(reader: &mut BufReader<UnixStream>) -> ActionReply {
        let mut text = String::new();
        reader.read_line(&mut text).unwrap();
        ActionReply::decode(text.trim_end()).unwrap()
    }

    fn closed(reader: &mut BufReader<UnixStream>) -> bool {
        let mut rest = Vec::new();
        reader
            .read_to_end(&mut rest)
            .map(|_| rest.is_empty())
            .unwrap_or(true)
    }

    #[test]
    fn the_socket_lives_in_a_private_directory_beside_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let binding = TaskBinding::new(
            TaskId::from_u128(1),
            ExecutionAttemptId::from_u128(2),
            LeaseId::from_u128(3),
        );
        let workspace = dir
            .path()
            .join(binding.task().to_string())
            .join(binding.attempt().to_string());
        assert_eq!(
            actions_dir_beside(&workspace).unwrap(),
            actions_dir(dir.path(), binding)
        );
        assert_eq!(actions_dir_beside(Path::new("/")), None);
        std::fs::create_dir_all(workspace.parent().unwrap()).unwrap();
        let actions =
            AttemptActions::start(&actions_dir(dir.path(), binding), grant(1, 1, 1)).unwrap();
        let metadata = std::fs::metadata(actions_dir(dir.path(), binding)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert!(
            std::fs::symlink_metadata(actions.socket())
                .unwrap()
                .file_type()
                .is_socket()
        );
        assert_eq!(actions.grant(), &grant(1, 1, 1));
        assert!(!actions.closed());
        let socket = actions.socket().to_path_buf();
        drop(actions);
        assert!(!socket.exists(), "dropping the channel removes its socket");
        assert!(UnixStream::connect(&socket).is_err());

        let open = dir.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            AttemptActions::start(&open, grant(1, 1, 1)),
            Err(ActionChannelError::InsecurePath)
        ));
        let file = dir.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(AttemptActions::start(&file.join("x"), grant(1, 1, 1)).is_err());
    }

    #[test]
    fn lines_are_classified_and_control_requests_are_refused() {
        assert!(classify(line("a").as_bytes()).is_ok());
        for (bytes, reason) in [
            (b"not json".to_vec(), NodeActionRefusal::Malformed),
            (vec![0xff, 0xfe], NodeActionRefusal::Malformed),
            (
                br#"{"request":"hello","protocol":{"major":1,"min_minor":3,"max_minor":3}}"#
                    .to_vec(),
                NodeActionRefusal::ControlRequest,
            ),
            (
                br#"{"request":"stop","protocol":{"major":1,"minor":3},"operation_id":1}"#.to_vec(),
                NodeActionRefusal::ControlRequest,
            ),
            (
                br#"{"req":"approve","id":1}"#.to_vec(),
                NodeActionRefusal::ControlRequest,
            ),
            (
                br#"{"response":"accepted"}"#.to_vec(),
                NodeActionRefusal::ControlRequest,
            ),
            (
                br#"{"id":"a","kind":"credential","summary":"s","detail":""}"#.to_vec(),
                NodeActionRefusal::Malformed,
            ),
            (
                format!(
                    r#"{{"id":"a","kind":"approval","summary":"s","detail":"{}"}}"#,
                    "d".repeat(ward_node_protocol::MAX_ACTION_DETAIL_BYTES + 1)
                )
                .into_bytes(),
                NodeActionRefusal::Oversized,
            ),
            (
                vec![b'x'; MAX_ACTION_LINE_BYTES + 1],
                NodeActionRefusal::Oversized,
            ),
        ] {
            assert_eq!(classify(&bytes).unwrap_err(), reason);
        }
        assert_eq!(action_kind(ActionKind::Decision), NodeActionKind::Decision);
        assert_eq!(
            action_decision(ActionDecision::Denied),
            NodeActionDecision::Denied
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_request_is_recorded_before_it_is_listed_and_an_answer_before_it_is_delivered() {
        let fixture = Fixture::new(grant(2, 4, 30));
        let (mut stream, mut reader) = fixture.connect();
        writeln!(stream, "{}", line("deploy-1")).unwrap();
        let listed = fixture.listed(1);
        assert_eq!(listed[0].action(), 1);
        assert_eq!(listed[0].id().as_str(), "deploy-1");
        assert!(listed[0].expires_in_ms() <= 30_000);
        assert!(matches!(
            fixture.records()[0],
            WardEvent::NodeActionRequested {
                action: 1,
                kind: NodeActionKind::Approval,
                summary_bytes: 15,
                detail_bytes: 8,
                ..
            }
        ));
        let WardEvent::NodeActionRequested {
            summary, detail, ..
        } = fixture.records()[0]
        else {
            unreachable!()
        };
        assert_eq!(summary, Blake3Hash::hash(b"deploy deploy-1"));
        assert_eq!(detail, Blake3Hash::hash(b"the plan"));

        let note = ActionNote::new("go").unwrap();
        assert_eq!(
            fixture.actions.answer(
                Instant::now(),
                op(7),
                1,
                ActionDecision::Approved,
                Some(note.clone()),
                &mut fixture.recorder()
            ),
            Ok(ActionDecision::Approved)
        );
        let got = reply(&mut reader);
        assert_eq!(got.id().as_str(), "deploy-1");
        assert_eq!(got.decision(), ActionDecision::Approved);
        assert_eq!(got.note(), Some(&note));
        assert_eq!(
            fixture.records()[1],
            WardEvent::NodeActionAnswered {
                action: 1,
                decision: NodeActionDecision::Approved,
                operation: Some(7),
                note_bytes: 2,
                note: Some(Blake3Hash::hash(b"go")),
            }
        );
        // A replay is accepted again without acting; anything else is refused.
        assert_eq!(
            fixture.actions.answer(
                Instant::now(),
                op(7),
                1,
                ActionDecision::Approved,
                Some(note.clone()),
                &mut fixture.recorder()
            ),
            Ok(ActionDecision::Approved)
        );
        assert_eq!(
            fixture.actions.answer(
                Instant::now(),
                op(7),
                1,
                ActionDecision::Denied,
                None,
                &mut fixture.recorder()
            ),
            Err(ActionRejectionReason::StaleOperation)
        );
        assert_eq!(
            fixture.actions.answer(
                Instant::now(),
                op(8),
                1,
                ActionDecision::Denied,
                None,
                &mut fixture.recorder()
            ),
            Err(ActionRejectionReason::AlreadyAnswered)
        );
        assert_eq!(
            fixture.actions.answer(
                Instant::now(),
                op(9),
                5,
                ActionDecision::Denied,
                None,
                &mut fixture.recorder()
            ),
            Err(ActionRejectionReason::UnknownRequest)
        );
        assert_eq!(fixture.records().len(), 2, "refusals append nothing");
        assert!(
            fixture
                .actions
                .list(Instant::now(), &mut fixture.recorder())
                .is_empty()
        );
    }

    #[test]
    fn an_answer_that_cannot_be_recorded_is_refused_and_the_request_stays_pending() {
        let fixture = Fixture::new(grant(1, 1, 30));
        let (mut stream, _reader) = fixture.connect();
        writeln!(stream, "{}", line("a")).unwrap();
        fixture.listed(1);
        assert_eq!(
            fixture.actions.answer(
                Instant::now(),
                op(1),
                1,
                ActionDecision::Approved,
                None,
                &mut |_| false
            ),
            Err(ActionRejectionReason::ResourceUnavailable)
        );
        assert_eq!(fixture.listed(1)[0].action(), 1);
        assert_eq!(
            fixture
                .actions
                .replay(op(1), 1, ActionDecision::Approved, None),
            None
        );
    }

    #[test]
    fn a_request_whose_record_fails_is_cancelled_and_never_listed() {
        let fixture = Fixture::new(grant(1, 2, 30));
        let (mut stream, mut reader) = fixture.connect();
        writeln!(stream, "{}", line("a")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !fixture.actions.due(Instant::now()) {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(
            fixture
                .actions
                .list(Instant::now(), &mut |_| false)
                .is_empty()
        );
        assert_eq!(reply(&mut reader).decision(), ActionDecision::Cancelled);
        assert_eq!(
            fixture.actions.answer(
                Instant::now(),
                op(1),
                1,
                ActionDecision::Approved,
                None,
                &mut fixture.recorder()
            ),
            Err(ActionRejectionReason::AlreadyAnswered)
        );
    }

    #[test]
    fn an_unanswered_request_expires_after_its_wait_and_a_pause_stops_the_clock() {
        let fixture = Fixture::new(grant(2, 4, 30));
        let (mut stream, mut reader) = fixture.connect();
        writeln!(stream, "{}", line("slow")).unwrap();
        fixture.listed(1);
        let now = Instant::now();
        fixture.actions.set_paused(true, now);
        fixture.actions.set_paused(true, now);
        let later = now + Duration::from_secs(60);
        assert!(!fixture.actions.due(later), "nothing expires while paused");
        fixture.actions.tend(later, &mut fixture.recorder());
        let listed = fixture.actions.list(later, &mut fixture.recorder());
        assert_eq!(listed.len(), 1, "a paused request stays pending");
        assert!(listed[0].expires_in_ms() > 25_000);
        fixture.actions.set_paused(false, later);
        fixture.actions.set_paused(false, later);
        assert!(!fixture.actions.due(later + Duration::from_secs(20)));
        let expired = later + Duration::from_secs(31);
        assert!(fixture.actions.due(expired));
        fixture.actions.tend(expired, &mut fixture.recorder());
        assert_eq!(reply(&mut reader).decision(), ActionDecision::Expired);
        assert_eq!(
            fixture.records().last(),
            Some(&WardEvent::NodeActionAnswered {
                action: 1,
                decision: NodeActionDecision::Expired,
                operation: None,
                note_bytes: 0,
                note: None,
            })
        );
        assert_eq!(
            fixture.actions.answer(
                expired,
                op(1),
                1,
                ActionDecision::Approved,
                None,
                &mut fixture.recorder()
            ),
            Err(ActionRejectionReason::AlreadyAnswered)
        );
    }

    #[test]
    fn finishing_cancels_what_is_pending_records_it_and_closes_the_channel() {
        let fixture = Fixture::new(grant(2, 4, 30));
        let (mut stream, mut reader) = fixture.connect();
        writeln!(stream, "{}", line("a")).unwrap();
        writeln!(stream, "{}", line("b")).unwrap();
        fixture.listed(2);
        fixture.actions.finish(&mut fixture.recorder());
        fixture.actions.finish(&mut fixture.recorder());
        let first = reply(&mut reader);
        let second = reply(&mut reader);
        assert_eq!(
            (first.decision(), second.decision()),
            (ActionDecision::Cancelled, ActionDecision::Cancelled)
        );
        assert!(closed(&mut reader));
        assert!(fixture.actions.closed());
        assert!(!fixture.actions.socket().exists());
        let cancelled = fixture
            .records()
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    WardEvent::NodeActionAnswered {
                        decision: NodeActionDecision::Cancelled,
                        operation: None,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(cancelled, 2);
        assert_eq!(
            fixture.actions.answer(
                Instant::now(),
                op(1),
                1,
                ActionDecision::Approved,
                None,
                &mut fixture.recorder()
            ),
            Err(ActionRejectionReason::AlreadyAnswered)
        );
    }

    #[test]
    fn a_closed_connection_withdraws_its_requests() {
        let fixture = Fixture::new(grant(2, 4, 30));
        let (mut stream, reader) = fixture.connect();
        writeln!(stream, "{}", line("gone")).unwrap();
        fixture.listed(1);
        drop(stream);
        drop(reader);
        fixture.recorded(|event| {
            matches!(
                event,
                WardEvent::NodeActionAnswered {
                    action: 1,
                    decision: NodeActionDecision::Cancelled,
                    ..
                }
            )
        });
        assert!(
            fixture
                .actions
                .list(Instant::now(), &mut fixture.recorder())
                .is_empty()
        );
    }

    #[test]
    fn hostile_and_out_of_grant_lines_get_nothing_and_are_recorded() {
        let fixture = Fixture::new(ActionGrant::new(vec![ActionKind::Approval], 1, 2, 30).unwrap());
        let cases: [(String, NodeActionRefusal); 5] = [
            ("not json".to_owned(), NodeActionRefusal::Malformed),
            (
                r#"{"request":"hello","protocol":{"major":1,"min_minor":3,"max_minor":3}}"#
                    .to_owned(),
                NodeActionRefusal::ControlRequest,
            ),
            (
                r#"{"id":"d","kind":"decision","summary":"s","detail":""}"#.to_owned(),
                NodeActionRefusal::KindNotGranted,
            ),
            (
                "x".repeat(MAX_ACTION_LINE_BYTES + 10),
                NodeActionRefusal::Oversized,
            ),
            ("{\"id\":\"half".to_owned(), NodeActionRefusal::Malformed),
        ];
        for (index, (text, reason)) in cases.iter().enumerate() {
            let (mut stream, mut reader) = fixture.connect();
            if index + 1 == cases.len() {
                stream.write_all(text.as_bytes()).unwrap();
                stream.shutdown(std::net::Shutdown::Write).unwrap();
            } else {
                let _ = writeln!(stream, "{text}");
            }
            assert!(closed(&mut reader), "{reason:?} gets nothing");
            fixture.recorded(|event| {
                matches!(event, WardEvent::NodeActionRefused { reason: got, .. } if got == reason)
            });
        }
        // Within the grant: one pending at a time, two in all, ids once.
        let (mut first, _first_reader) = fixture.connect();
        writeln!(first, "{}", line("one")).unwrap();
        fixture.listed(1);
        let (mut second, mut second_reader) = fixture.connect();
        writeln!(second, "{}", line("two")).unwrap();
        assert!(closed(&mut second_reader));
        fixture.recorded(|event| {
            matches!(
                event,
                WardEvent::NodeActionRefused {
                    reason: NodeActionRefusal::TooManyPending,
                    ..
                }
            )
        });
        fixture
            .actions
            .answer(
                Instant::now(),
                op(1),
                1,
                ActionDecision::Denied,
                None,
                &mut fixture.recorder(),
            )
            .unwrap();
        writeln!(first, "{}", line("one")).unwrap();
        fixture.recorded(|event| {
            matches!(
                event,
                WardEvent::NodeActionRefused {
                    reason: NodeActionRefusal::DuplicateId,
                    ..
                }
            )
        });
        let (mut third, _third_reader) = fixture.connect();
        writeln!(third, "{}", line("three")).unwrap();
        fixture.listed(1);
        fixture
            .actions
            .answer(
                Instant::now(),
                op(2),
                2,
                ActionDecision::Approved,
                None,
                &mut fixture.recorder(),
            )
            .unwrap();
        let (mut fourth, mut fourth_reader) = fixture.connect();
        writeln!(fourth, "{}", line("four")).unwrap();
        assert!(closed(&mut fourth_reader));
        fixture.recorded(|event| {
            matches!(
                event,
                WardEvent::NodeActionRefused {
                    reason: NodeActionRefusal::TooManyRequests,
                    ..
                }
            )
        });
        let requested = fixture
            .records()
            .iter()
            .filter(|event| matches!(event, WardEvent::NodeActionRequested { .. }))
            .count();
        assert_eq!(requested, 2);
    }

    #[test]
    fn the_channel_closes_after_its_refusal_bound() {
        let fixture = Fixture::new(grant(2, 4, 30));
        let (mut keeper, mut keeper_reader) = fixture.connect();
        writeln!(keeper, "{}", line("kept")).unwrap();
        fixture.listed(1);
        for _ in 0..MAX_ACTION_REFUSALS {
            let (mut stream, mut reader) = fixture.connect();
            let _ = writeln!(stream, "garbage");
            assert!(closed(&mut reader));
        }
        assert!(fixture.actions.closed());
        assert_eq!(
            reply(&mut keeper_reader).decision(),
            ActionDecision::Cancelled
        );
        fixture
            .actions
            .tend(Instant::now(), &mut fixture.recorder());
        let refused = fixture
            .records()
            .iter()
            .filter(|event| matches!(event, WardEvent::NodeActionRefused { .. }))
            .count();
        assert_eq!(refused, usize::try_from(MAX_ACTION_REFUSALS).unwrap());
        assert!(fixture.records().iter().any(|event| matches!(
            event,
            WardEvent::NodeActionAnswered {
                action: 1,
                decision: NodeActionDecision::Cancelled,
                ..
            }
        )));
        assert!(UnixStream::connect(fixture.actions.socket()).is_err());
    }

    #[test]
    fn connections_past_the_bound_are_closed_unread() {
        let fixture = Fixture::new(grant(1, 1, 30));
        let held: Vec<_> = (0..MAX_ACTION_CONNECTIONS)
            .map(|_| fixture.connect())
            .collect();
        let deadline = Instant::now() + Duration::from_secs(10);
        while fixture.actions.connections() < MAX_ACTION_CONNECTIONS {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        let (mut extra, mut extra_reader) = fixture.connect();
        let _ = writeln!(extra, "{}", line("extra"));
        assert!(closed(&mut extra_reader));
        fixture
            .actions
            .tend(Instant::now(), &mut fixture.recorder());
        assert!(
            fixture.records().is_empty(),
            "a connection past the bound is not recorded"
        );
        drop(held);
        while fixture.actions.connections() > 0 {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        let (mut stream, _reader) = fixture.connect();
        writeln!(stream, "{}", line("later")).unwrap();
        assert_eq!(fixture.listed(1)[0].id().as_str(), "later");
    }

    fn hold_grant(hosts: &[&str], services: &[&str]) -> HoldGrant {
        HoldGrant::new(
            hosts.iter().map(|host| (*host).to_owned()).collect(),
            services
                .iter()
                .map(|service| (*service).to_owned())
                .collect(),
        )
        .unwrap()
    }

    fn holding(grant: ActionGrant, hold: &HoldGrant) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let actions =
            AttemptActions::start_held(&dir.path().join("a.actions"), grant, Some(hold)).unwrap();
        Fixture {
            _dir: dir,
            actions,
            records: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn target(host: &str) -> Target {
        Target {
            host: Host::Name(host.to_owned()),
            port: 443,
        }
    }

    /// What the attempt's proxy is told about a request for `host` (on `route`, if any).
    fn asked(hold: &dyn Hold, host: &str, route: Option<&str>) -> Option<(String, &'static str)> {
        hold.held(&target(host), route)
            .map(|held| (held.reason, held.body))
    }

    #[allow(clippy::unnecessary_wraps)] // compared with what the hold answers
    fn held(action: u32) -> Option<(String, &'static str)> {
        Some((format!("hold:held:{action}"), "held for approval"))
    }

    fn answer(fixture: &Fixture, operation: u64, action: u32, decision: ActionDecision) {
        assert_eq!(
            fixture.actions.answer(
                Instant::now(),
                op(operation),
                action,
                decision,
                None,
                &mut fixture.recorder()
            ),
            Ok(decision)
        );
    }

    #[test]
    fn a_held_capability_opens_one_request_on_first_use_recorded_before_it_is_listed() {
        let fixture = holding(
            grant(1, 1, 30),
            &hold_grant(&["deploy.example.com", "*.wild.example"], &["artifacts"]),
        );
        let hold = fixture.actions.hold();
        assert_eq!(asked(hold.as_ref(), "other.example", None), None);
        assert_eq!(
            asked(hold.as_ref(), "artifacts.example", Some("/other")),
            None
        );
        assert!(
            fixture
                .actions
                .list(Instant::now(), &mut fixture.recorder())
                .is_empty()
        );
        assert!(fixture.records().is_empty(), "nothing held, nothing opened");

        assert_eq!(asked(hold.as_ref(), "deploy.example.com", None), held(1));
        assert!(fixture.records().is_empty(), "queued, not yet recorded");
        let listed = fixture.listed(1);
        assert_eq!(listed[0].action(), 1);
        assert_eq!(listed[0].id().as_str(), "hold:1");
        assert_eq!(listed[0].kind(), ActionKind::Approval);
        assert_eq!(listed[0].summary(), "network deploy.example.com");
        assert_eq!(
            listed[0].hold(),
            Some(&HeldCapability::Host("deploy.example.com".to_owned()))
        );
        assert!(matches!(
            fixture.records()[0],
            WardEvent::NodeActionRequested {
                action: 1,
                kind: NodeActionKind::Approval,
                ..
            }
        ));
        let WardEvent::NodeActionRequested { summary, .. } = fixture.records()[0] else {
            unreachable!()
        };
        assert_eq!(summary, Blake3Hash::hash(b"network deploy.example.com"));

        // The same capability again, in any case, opens nothing more.
        assert_eq!(asked(hold.as_ref(), "deploy.example.com", None), held(1));
        assert_eq!(asked(hold.as_ref(), "DEPLOY.example.com", None), held(1));
        assert_eq!(fixture.listed(1).len(), 1);
        assert_eq!(fixture.records().len(), 1);

        assert_eq!(asked(hold.as_ref(), "x.wild.example", None), held(2));
        assert_eq!(asked(hold.as_ref(), "wild.example", None), None);
        assert_eq!(
            asked(hold.as_ref(), "127.0.0.1", Some("/artifacts")),
            held(3)
        );
        let listed = fixture.listed(3);
        assert_eq!(listed[2].id().as_str(), "hold:3");
        assert_eq!(listed[2].summary(), "credential artifacts");
        assert_eq!(
            listed[2].hold(),
            Some(&HeldCapability::Service("artifacts".to_owned()))
        );
        let ip = Target {
            host: Host::Ip(std::net::IpAddr::from([10, 0, 0, 1])),
            port: 443,
        };
        assert!(hold.held(&ip, None).is_none());
    }

    #[test]
    fn an_approval_releases_only_the_capability_its_request_was_opened_for_once_recorded() {
        let fixture = holding(
            grant(2, 4, 30),
            &hold_grant(&["deploy.example.com", "artifacts.example"], &["artifacts"]),
        );
        let hold = fixture.actions.hold();
        assert_eq!(asked(hold.as_ref(), "deploy.example.com", None), held(1));
        assert_eq!(asked(hold.as_ref(), "artifacts.example", None), held(2));
        fixture.listed(2);

        // The workload's own approval request, worded like the node's, releases nothing.
        let (mut stream, mut reader) = fixture.connect();
        writeln!(
            stream,
            r#"{{"id":"mine","kind":"approval","summary":"network deploy.example.com","detail":""}}"#
        )
        .unwrap();
        let listed = fixture.listed(3);
        assert_eq!(listed[2].hold(), None);
        answer(&fixture, 10, 3, ActionDecision::Approved);
        assert_eq!(reply(&mut reader).decision(), ActionDecision::Approved);
        assert_eq!(asked(hold.as_ref(), "deploy.example.com", None), held(1));

        // An answer that cannot be recorded releases nothing.
        assert_eq!(
            fixture.actions.answer(
                Instant::now(),
                op(11),
                2,
                ActionDecision::Approved,
                None,
                &mut |_| false
            ),
            Err(ActionRejectionReason::ResourceUnavailable)
        );
        assert_eq!(asked(hold.as_ref(), "artifacts.example", None), held(2));

        // Approving request 2 releases its host only, and the route to it is still held
        // by its service.
        answer(&fixture, 12, 2, ActionDecision::Approved);
        assert_eq!(asked(hold.as_ref(), "artifacts.example", None), None);
        assert_eq!(asked(hold.as_ref(), "deploy.example.com", None), held(1));
        assert_eq!(
            asked(hold.as_ref(), "artifacts.example", Some("/artifacts")),
            held(4)
        );
        assert_eq!(
            fixture
                .listed(2)
                .iter()
                .map(PendingAction::action)
                .collect::<Vec<_>>(),
            [1, 4]
        );

        // A replay applies nothing new; the same operation id for another request is stale
        // and releases nothing.
        answer(&fixture, 12, 2, ActionDecision::Approved);
        assert_eq!(
            fixture.actions.answer(
                Instant::now(),
                op(12),
                1,
                ActionDecision::Approved,
                None,
                &mut fixture.recorder()
            ),
            Err(ActionRejectionReason::StaleOperation)
        );
        assert_eq!(asked(hold.as_ref(), "deploy.example.com", None), held(1));
        assert_eq!(
            fixture.actions.answer(
                Instant::now(),
                op(13),
                9,
                ActionDecision::Approved,
                None,
                &mut fixture.recorder()
            ),
            Err(ActionRejectionReason::UnknownRequest)
        );
        assert_eq!(asked(hold.as_ref(), "deploy.example.com", None), held(1));
        let approvals = fixture
            .records()
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    WardEvent::NodeActionAnswered {
                        decision: NodeActionDecision::Approved,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(approvals, 2);
    }

    #[test]
    fn a_denied_expired_or_cancelled_hold_stays_refused_by_name() {
        let fixture = holding(
            grant(1, 1, 30),
            &hold_grant(&["a.example", "b.example", "c.example", "d.example"], &[]),
        );
        let hold = fixture.actions.hold();
        for host in ["a.example", "b.example"] {
            assert!(asked(hold.as_ref(), host, None).is_some());
        }
        fixture.listed(2);

        answer(&fixture, 1, 1, ActionDecision::Denied);
        let denied = Some(("hold:denied:1".to_owned(), "approval denied"));
        assert_eq!(asked(hold.as_ref(), "a.example", None), denied);
        assert_eq!(asked(hold.as_ref(), "a.example", None), denied);

        let expired = Instant::now() + Duration::from_secs(31);
        fixture.actions.tend(expired, &mut fixture.recorder());
        assert_eq!(
            asked(hold.as_ref(), "b.example", None),
            Some(("hold:expired:2".to_owned(), "approval expired"))
        );
        assert!(
            fixture
                .actions
                .list(expired, &mut fixture.recorder())
                .is_empty()
        );

        assert_eq!(asked(hold.as_ref(), "c.example", None), held(3));
        fixture.listed(1);
        fixture.actions.finish(&mut fixture.recorder());
        assert_eq!(
            asked(hold.as_ref(), "a.example", None),
            denied,
            "a denial stays a denial"
        );
        assert_eq!(
            asked(hold.as_ref(), "d.example", None),
            Some(("hold:cancelled".to_owned(), "approval cancelled")),
            "a closed channel opens nothing"
        );
        let answered: Vec<(u32, NodeActionDecision)> = fixture
            .records()
            .iter()
            .filter_map(|event| match event {
                WardEvent::NodeActionAnswered {
                    action, decision, ..
                } => Some((*action, *decision)),
                _ => None,
            })
            .collect();
        assert_eq!(
            answered,
            vec![
                (1, NodeActionDecision::Denied),
                (2, NodeActionDecision::Expired),
                (3, NodeActionDecision::Cancelled),
            ]
        );
        assert_eq!(
            asked(hold.as_ref(), "c.example", None),
            Some(("hold:cancelled:3".to_owned(), "approval cancelled"))
        );
        assert_eq!(
            fixture.actions.answer(
                Instant::now(),
                op(5),
                3,
                ActionDecision::Approved,
                None,
                &mut fixture.recorder()
            ),
            Err(ActionRejectionReason::AlreadyAnswered)
        );
        assert_eq!(
            asked(hold.as_ref(), "c.example", None),
            Some(("hold:cancelled:3".to_owned(), "approval cancelled"))
        );
    }

    #[test]
    fn a_hold_whose_request_cannot_be_recorded_is_cancelled_and_never_listed() {
        let fixture = holding(grant(1, 1, 30), &hold_grant(&["a.example"], &[]));
        let hold = fixture.actions.hold();
        assert_eq!(asked(hold.as_ref(), "a.example", None), held(1));
        assert!(
            fixture
                .actions
                .list(Instant::now(), &mut |_| false)
                .is_empty()
        );
        assert_eq!(
            asked(hold.as_ref(), "a.example", None),
            Some(("hold:cancelled:1".to_owned(), "approval cancelled"))
        );
    }

    #[test]
    fn a_pause_keeps_a_hold_held_and_stops_its_clock() {
        let fixture = holding(grant(1, 1, 30), &hold_grant(&["a.example"], &[]));
        let hold = fixture.actions.hold();
        assert_eq!(asked(hold.as_ref(), "a.example", None), held(1));
        fixture.listed(1);
        let now = Instant::now();
        fixture.actions.set_paused(true, now);
        let later = now + Duration::from_secs(120);
        fixture.actions.tend(later, &mut fixture.recorder());
        assert_eq!(
            fixture.actions.list(later, &mut fixture.recorder()).len(),
            1
        );
        assert_eq!(asked(hold.as_ref(), "a.example", None), held(1));
        fixture.actions.set_paused(false, later);
        answer(&fixture, 1, 1, ActionDecision::Approved);
        assert_eq!(asked(hold.as_ref(), "a.example", None), None);
    }

    #[test]
    fn the_node_reserves_its_hold_ids_and_holds_take_none_of_the_workloads_slots() {
        let fixture = holding(
            grant(1, 1, 30),
            &hold_grant(&["a.example", "b.example"], &[]),
        );
        let hold = fixture.actions.hold();
        let (mut stream, mut reader) = fixture.connect();
        writeln!(stream, "{}", line("hold:2")).unwrap();
        assert!(
            closed(&mut reader),
            "a workload request under a hold id gets nothing"
        );
        fixture.recorded(|event| {
            matches!(
                event,
                WardEvent::NodeActionRefused {
                    reason: NodeActionRefusal::DuplicateId,
                    ..
                }
            )
        });
        assert_eq!(asked(hold.as_ref(), "a.example", None), held(1));
        assert_eq!(asked(hold.as_ref(), "b.example", None), held(2));
        let (mut stream, _reader) = fixture.connect();
        writeln!(stream, "{}", line("mine")).unwrap();
        let listed = fixture.listed(3);
        assert_eq!(listed[2].id().as_str(), "mine");
        assert_eq!(listed[2].action(), 3);
    }

    #[test]
    fn a_request_touching_two_held_capabilities_opens_both_at_once() {
        let fixture = holding(
            grant(1, 1, 30),
            &hold_grant(&["artifacts.example"], &["artifacts"]),
        );
        let hold = fixture.actions.hold();
        assert_eq!(
            asked(hold.as_ref(), "artifacts.example", Some("/artifacts")),
            held(1)
        );
        let listed = fixture.listed(2);
        assert_eq!(
            listed
                .iter()
                .map(|entry| entry.id().as_str())
                .collect::<Vec<_>>(),
            ["hold:1", "hold:2"]
        );
        answer(&fixture, 1, 1, ActionDecision::Approved);
        assert_eq!(
            asked(hold.as_ref(), "artifacts.example", Some("/artifacts")),
            held(2)
        );
        assert_eq!(asked(hold.as_ref(), "artifacts.example", None), None);
        answer(&fixture, 2, 2, ActionDecision::Approved);
        assert_eq!(
            asked(hold.as_ref(), "artifacts.example", Some("/artifacts")),
            None
        );
    }
}
