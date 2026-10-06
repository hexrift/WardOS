//! The action channel (#404, ADR-0031; #332 stage 3): a workload in an admitted attempt asks
//! the control plane a bounded question through a socket the node owns, relays and records,
//! and the control plane reads and answers it over the node protocol.
//!
//! Three grammars live here, all additive within protocol 1.3:
//!
//! * the manifest's optional `actions` grant ([`ActionGrant`]): which request kinds the
//!   workload may send, how many may wait at once and in all, and how long each waits; and
//!   the capability document's `actions` section ([`ActionCapabilities`]), present only on
//!   a node whose operator enabled the channel;
//! * the channel itself, JSON lines on the per-attempt socket: one [`ActionRequest`] per
//!   line from the workload (`{"id","kind","summary","detail"}`), one [`ActionReply`] per
//!   answered request back to it (`{"id","decision","note"?}`);
//! * the control plane's two requests: the read-only `actions` listing of the attempt's
//!   pending requests and the mutating `answer` ([`TaskActionsRequest`]), answered by a
//!   [`TaskActionsResponse`].
//!
//! The channel grants nothing by itself: an approval is a statement the node records in
//! the attempt's evidence log and relays to the workload, not a capability the node
//! enforces. Every bound below is a byte count of the UTF-8 text.

use std::fmt::{Display, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    OperationId, ProtocolVersion, TaskBinding, TaskLifecycleContext, TaskLifecycleError,
    TaskLifecycleState, supports_task_admission,
};

/// Maximum bytes of a workload-chosen request id.
pub const MAX_ACTION_ID_BYTES: usize = 64;

/// Maximum bytes of a request's summary.
pub const MAX_ACTION_SUMMARY_BYTES: usize = 512;

/// Maximum bytes of a request's detail.
pub const MAX_ACTION_DETAIL_BYTES: usize = 16 * 1024;

/// Maximum bytes of the note a control plane may attach to an answer.
pub const MAX_ACTION_NOTE_BYTES: usize = 512;

/// Maximum bytes of one request line on the channel, newline excluded: room for a summary
/// and a detail at their bounds even when every byte is JSON-escaped.
pub const MAX_ACTION_LINE_BYTES: usize = 128 * 1024;

/// Ceiling on `max_pending`: a grant asking for more is refused `unsupported_grant`.
pub const MAX_ACTION_PENDING: u32 = 8;

/// Ceiling on `max_total`: a grant asking for more is refused `unsupported_grant`.
pub const MAX_ACTION_TOTAL: u32 = 64;

/// Ceiling on `wait_secs`: a grant asking for more is refused `unsupported_grant`.
pub const MAX_ACTION_WAIT_SECS: u32 = 3600;

/// Upper bound on one `actions` response line: [`MAX_ACTION_PENDING`] requests at their
/// bounds, escaped, with room for the metadata.
pub const MAX_ACTIONS_RESPONSE_BYTES: usize = 1024 * 1024;

/// Why an action grant, request, reply or listing is outside its grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionError {
    /// The grant names no kind or a kind twice, or a bound is zero, or `max_pending`
    /// exceeds `max_total`.
    InvalidGrant,
    /// The text is not one object of the grammar: unknown or missing fields, an unknown
    /// kind, an id outside `[A-Za-z0-9._:-]{1,64}`, an empty summary.
    Malformed,
    /// A summary, detail or note is longer than its bound.
    TooLong,
    /// A control plane may answer only `approved` or `denied`; `expired` and `cancelled`
    /// are the node's.
    InvalidDecision,
}

impl Display for ActionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGrant => "action grant is invalid",
            Self::Malformed => "action message is malformed",
            Self::TooLong => "action text exceeds its bound",
            Self::InvalidDecision => "a control plane answers approved or denied only",
        })
    }
}

impl std::error::Error for ActionError {}

/// What a workload asks for. A closed set: a kind outside it fails decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Permission to do what the summary says.
    Approval,
    /// A yes-or-no choice the control plane makes for the workload.
    Decision,
}

impl ActionKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 2] = [Self::Approval, Self::Decision];

    /// Stable lowercase name, as the wire spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Decision => "decision",
        }
    }
}

/// How a request ended, as the workload and the control plane see it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionDecision {
    /// The control plane approved it.
    Approved,
    /// The control plane denied it.
    Denied,
    /// Nobody answered within the grant's `wait_secs`; the node answered.
    Expired,
    /// The attempt ended, the node restarted, the channel closed or the workload withdrew
    /// the request before it was answered; the node answered.
    Cancelled,
}

impl ActionDecision {
    /// Whether a control plane may give this answer: `approved` and `denied` only.
    #[must_use]
    pub const fn answerable(self) -> bool {
        matches!(self, Self::Approved | Self::Denied)
    }

    /// Stable lowercase name, as the wire spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

/// The `actions` grant of a capability manifest: what the workload may ask through its
/// channel, and the bounds the node holds it to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActionGrant {
    kinds: Vec<ActionKind>,
    max_pending: u32,
    max_total: u32,
    wait_secs: u32,
}

impl ActionGrant {
    /// A grant of `kinds`, at most `max_pending` requests waiting at once and `max_total`
    /// in the attempt's lifetime, each answered `expired` after `wait_secs`.
    ///
    /// # Errors
    ///
    /// Returns [`ActionError::InvalidGrant`] for no kind or a repeated one, a zero bound,
    /// or `max_pending` above `max_total`.
    pub fn new(
        kinds: Vec<ActionKind>,
        max_pending: u32,
        max_total: u32,
        wait_secs: u32,
    ) -> Result<Self, ActionError> {
        let repeated = kinds
            .iter()
            .enumerate()
            .any(|(index, kind)| kinds[..index].contains(kind));
        if kinds.is_empty()
            || repeated
            || max_pending == 0
            || max_total == 0
            || wait_secs == 0
            || max_pending > max_total
        {
            return Err(ActionError::InvalidGrant);
        }
        Ok(Self {
            kinds,
            max_pending,
            max_total,
            wait_secs,
        })
    }

    /// The kinds the workload may send, in the order given.
    #[must_use]
    pub fn kinds(&self) -> &[ActionKind] {
        &self.kinds
    }

    /// Whether `kind` is granted.
    #[must_use]
    pub fn allows(&self, kind: ActionKind) -> bool {
        self.kinds.contains(&kind)
    }

    /// Requests that may wait for an answer at once.
    #[must_use]
    pub const fn max_pending(&self) -> u32 {
        self.max_pending
    }

    /// Requests the workload may send in the attempt's lifetime.
    #[must_use]
    pub const fn max_total(&self) -> u32 {
        self.max_total
    }

    /// Seconds a request waits for an answer before the node answers `expired`.
    #[must_use]
    pub const fn wait_secs(&self) -> u32 {
        self.wait_secs
    }

    /// Whether a node whose ceilings are [`MAX_ACTION_PENDING`], [`MAX_ACTION_TOTAL`] and
    /// [`MAX_ACTION_WAIT_SECS`] can honour this grant.
    #[must_use]
    pub const fn within_ceilings(&self) -> bool {
        self.max_pending <= MAX_ACTION_PENDING
            && self.max_total <= MAX_ACTION_TOTAL
            && self.wait_secs <= MAX_ACTION_WAIT_SECS
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActionGrantWire {
    kinds: Vec<ActionKind>,
    max_pending: u32,
    max_total: u32,
    wait_secs: u32,
}

impl TryFrom<ActionGrantWire> for ActionGrant {
    type Error = ActionError;

    fn try_from(wire: ActionGrantWire) -> Result<Self, ActionError> {
        Self::new(wire.kinds, wire.max_pending, wire.max_total, wire.wait_secs)
    }
}

/// What a node offers through the action channel (the `actions` section of the capability
/// document): the kinds it relays and its ceilings. Absent from the document when no kind
/// is offered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCapabilities {
    /// The node relays `approval` requests.
    pub approval: bool,
    /// The node relays `decision` requests.
    pub decision: bool,
    /// The highest `max_pending` the node honours.
    pub max_pending: u32,
    /// The highest `max_total` the node honours.
    pub max_total: u32,
    /// The highest `wait_secs` the node honours.
    pub max_wait_secs: u32,
}

impl ActionCapabilities {
    /// No channel.
    pub const NONE: Self = Self {
        approval: false,
        decision: false,
        max_pending: 0,
        max_total: 0,
        max_wait_secs: 0,
    };

    /// Every kind, at this revision's ceilings.
    pub const CEILINGS: Self = Self {
        approval: true,
        decision: true,
        max_pending: MAX_ACTION_PENDING,
        max_total: MAX_ACTION_TOTAL,
        max_wait_secs: MAX_ACTION_WAIT_SECS,
    };

    /// Whether any kind is offered.
    #[must_use]
    pub const fn any(self) -> bool {
        self.approval || self.decision
    }
}

/// A workload-chosen request id: 1 to [`MAX_ACTION_ID_BYTES`] bytes of
/// `A-Z a-z 0-9 . _ : -`, unique within the attempt.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ActionId(String);

impl ActionId {
    /// Validate an id.
    ///
    /// # Errors
    ///
    /// Returns [`ActionError::Malformed`] outside the grammar.
    pub fn new(id: impl Into<String>) -> Result<Self, ActionError> {
        let id = id.into();
        let allowed =
            |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-');
        if id.is_empty() || id.len() > MAX_ACTION_ID_BYTES || !id.bytes().all(allowed) {
            return Err(ActionError::Malformed);
        }
        Ok(Self(id))
    }

    /// The id as the workload sent it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ActionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// The note a control plane attaches to an answer: at most [`MAX_ACTION_NOTE_BYTES`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ActionNote(String);

impl ActionNote {
    /// Validate a note.
    ///
    /// # Errors
    ///
    /// Returns [`ActionError::TooLong`] past the bound.
    pub fn new(note: impl Into<String>) -> Result<Self, ActionError> {
        let note = note.into();
        if note.len() > MAX_ACTION_NOTE_BYTES {
            return Err(ActionError::TooLong);
        }
        Ok(Self(note))
    }

    /// The note.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ActionNote {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

fn check_text(summary: &str, detail: &str) -> Result<(), ActionError> {
    if summary.len() > MAX_ACTION_SUMMARY_BYTES || detail.len() > MAX_ACTION_DETAIL_BYTES {
        return Err(ActionError::TooLong);
    }
    if summary.is_empty() {
        return Err(ActionError::Malformed);
    }
    Ok(())
}

/// One request line a workload writes on its channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActionRequest {
    id: ActionId,
    kind: ActionKind,
    summary: String,
    detail: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionRequestWire {
    id: ActionId,
    kind: ActionKind,
    summary: String,
    detail: String,
}

impl ActionRequest {
    /// A request of `kind` under `id`, with a non-empty `summary` of at most
    /// [`MAX_ACTION_SUMMARY_BYTES`] and a `detail` of at most [`MAX_ACTION_DETAIL_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`ActionError::TooLong`] past a bound and [`ActionError::Malformed`] for an
    /// empty summary.
    pub fn new(
        id: ActionId,
        kind: ActionKind,
        summary: impl Into<String>,
        detail: impl Into<String>,
    ) -> Result<Self, ActionError> {
        let (summary, detail) = (summary.into(), detail.into());
        check_text(&summary, &detail)?;
        Ok(Self {
            id,
            kind,
            summary,
            detail,
        })
    }

    /// Strictly decode one channel line (without its newline).
    ///
    /// # Errors
    ///
    /// Returns [`ActionError::TooLong`] for a summary or detail past its bound and
    /// [`ActionError::Malformed`] for anything else outside the grammar.
    pub fn decode(line: &str) -> Result<Self, ActionError> {
        let wire =
            serde_json::from_str::<ActionRequestWire>(line).map_err(|_| ActionError::Malformed)?;
        Self::new(wire.id, wire.kind, wire.summary, wire.detail)
    }

    /// The workload's id.
    #[must_use]
    pub const fn id(&self) -> &ActionId {
        &self.id
    }

    /// The kind.
    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        self.kind
    }

    /// The summary.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// The detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// The line a workload receives on its channel when a request is answered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActionReply {
    id: ActionId,
    decision: ActionDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<ActionNote>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionReplyWire {
    id: ActionId,
    decision: ActionDecision,
    #[serde(default, deserialize_with = "deserialize_present_string")]
    note: Option<String>,
}

fn deserialize_present_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

fn deserialize_present_note<'de, D>(deserializer: D) -> Result<Option<ActionNote>, D::Error>
where
    D: Deserializer<'de>,
{
    ActionNote::deserialize(deserializer).map(Some)
}

impl ActionReply {
    /// The answer `decision` to the request `id`, with the control plane's `note`.
    #[must_use]
    pub const fn new(id: ActionId, decision: ActionDecision, note: Option<ActionNote>) -> Self {
        Self { id, decision, note }
    }

    /// Strictly decode one reply line (without its newline).
    ///
    /// # Errors
    ///
    /// Returns [`ActionError::Malformed`] or [`ActionError::TooLong`] outside the grammar.
    pub fn decode(line: &str) -> Result<Self, ActionError> {
        let wire =
            serde_json::from_str::<ActionReplyWire>(line).map_err(|_| ActionError::Malformed)?;
        let note = wire.note.map(ActionNote::new).transpose()?;
        Ok(Self::new(wire.id, wire.decision, note))
    }

    /// The request's id.
    #[must_use]
    pub const fn id(&self) -> &ActionId {
        &self.id
    }

    /// The decision.
    #[must_use]
    pub const fn decision(&self) -> ActionDecision {
        self.decision
    }

    /// The control plane's note, if it gave one.
    #[must_use]
    pub const fn note(&self) -> Option<&ActionNote> {
        self.note.as_ref()
    }
}

/// One request waiting for an answer, as the `actions` listing shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PendingAction {
    action: u32,
    id: ActionId,
    kind: ActionKind,
    summary: String,
    detail: String,
    expires_in_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingActionWire {
    action: u32,
    id: ActionId,
    kind: ActionKind,
    summary: String,
    detail: String,
    expires_in_ms: u64,
}

impl PendingAction {
    /// The node's request number `action` (from 1) for `request`, answered `expired` in
    /// `expires_in_ms` unless answered before.
    ///
    /// # Errors
    ///
    /// Returns [`ActionError::Malformed`] for request number 0.
    pub fn new(
        action: u32,
        request: ActionRequest,
        expires_in_ms: u64,
    ) -> Result<Self, ActionError> {
        if action == 0 {
            return Err(ActionError::Malformed);
        }
        Ok(Self {
            action,
            id: request.id,
            kind: request.kind,
            summary: request.summary,
            detail: request.detail,
            expires_in_ms,
        })
    }

    /// The node's request number: what `answer` names.
    #[must_use]
    pub const fn action(&self) -> u32 {
        self.action
    }

    /// The workload's id.
    #[must_use]
    pub const fn id(&self) -> &ActionId {
        &self.id
    }

    /// The kind.
    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        self.kind
    }

    /// The summary.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// The detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Milliseconds until the node answers `expired`, as of the listing.
    #[must_use]
    pub const fn expires_in_ms(&self) -> u64 {
        self.expires_in_ms
    }
}

impl<'de> Deserialize<'de> for PendingAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PendingActionWire::deserialize(deserializer)?;
        let request = ActionRequest::new(wire.id, wire.kind, wire.summary, wire.detail)
            .map_err(D::Error::custom)?;
        Self::new(wire.action, request, wire.expires_in_ms).map_err(D::Error::custom)
    }
}

/// Why an `actions` or `answer` request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRejectionReason {
    /// The task is not known to the node.
    TaskNotFound,
    /// The binding names another execution attempt.
    AttemptMismatch,
    /// The binding names another lease.
    LeaseMismatch,
    /// `answer` to an attempt that is not running or paused.
    InvalidState,
    /// The node does not offer the channel, or the protocol predates it.
    UnsupportedOperation,
    /// The answer could not be recorded in the evidence log; nothing changed.
    ResourceUnavailable,
    /// The operation id was already applied to a different answer.
    StaleOperation,
    /// No request with that number was ever recorded for the attempt.
    UnknownRequest,
    /// The request was already answered: by the control plane, or `expired` or
    /// `cancelled` by the node.
    AlreadyAnswered,
}

/// The control plane's requests on the action channel. Protocol 1.3 and later; built and
/// decoded through [`TaskLifecycleContext`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum TaskActionsRequest {
    /// Read-only: list the attempt's pending requests.
    Actions {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// The task/attempt/lease this request applies to.
        binding: TaskBinding,
    },
    /// Answer one pending request. Mutating, with an idempotency id.
    Answer {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// Idempotency identity of this answer.
        operation_id: OperationId,
        /// The task/attempt/lease this request applies to.
        binding: TaskBinding,
        /// The node's request number, from the listing.
        action: u32,
        /// `approved` or `denied`.
        decision: ActionDecision,
        /// A note relayed to the workload.
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<ActionNote>,
    },
}

#[derive(Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
enum TaskActionsRequestWire {
    Actions {
        protocol: ProtocolVersion,
        binding: TaskBinding,
    },
    Answer {
        protocol: ProtocolVersion,
        operation_id: OperationId,
        binding: TaskBinding,
        action: u32,
        decision: ActionDecision,
        #[serde(default, deserialize_with = "deserialize_present_note")]
        note: Option<ActionNote>,
    },
}

/// The answer to `actions` or `answer`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskActionsResponse {
    /// The attempt's pending requests, oldest first, with its state.
    Actions {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// The task/attempt/lease this response applies to.
        binding: TaskBinding,
        /// The task's current state.
        state: TaskLifecycleState,
        /// The requests waiting for an answer; empty unless the attempt runs or is paused.
        pending: Vec<PendingAction>,
    },
    /// The answer was recorded and relayed (or, on a replay, had been).
    Answered {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// The `answer`'s operation id.
        operation_id: OperationId,
        /// The task/attempt/lease this response applies to.
        binding: TaskBinding,
        /// The request answered.
        action: u32,
        /// The decision recorded.
        decision: ActionDecision,
    },
    /// The request was refused; `operation_id` is `null` for `actions`.
    Rejected {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// The `answer`'s operation id; `None` for `actions`.
        operation_id: Option<OperationId>,
        /// The task/attempt/lease this response applies to.
        binding: TaskBinding,
        /// Why.
        reason: ActionRejectionReason,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case", deny_unknown_fields)]
enum TaskActionsResponseWire {
    Actions {
        protocol: ProtocolVersion,
        binding: TaskBinding,
        state: TaskLifecycleState,
        pending: Vec<PendingAction>,
    },
    Answered {
        protocol: ProtocolVersion,
        operation_id: OperationId,
        binding: TaskBinding,
        action: u32,
        decision: ActionDecision,
    },
    Rejected {
        protocol: ProtocolVersion,
        operation_id: Option<OperationId>,
        binding: TaskBinding,
        reason: ActionRejectionReason,
    },
}

impl Serialize for TaskActionsResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let wire = match self.clone() {
            Self::Actions {
                protocol,
                binding,
                state,
                pending,
            } => TaskActionsResponseWire::Actions {
                protocol,
                binding,
                state,
                pending,
            },
            Self::Answered {
                protocol,
                operation_id,
                binding,
                action,
                decision,
            } => TaskActionsResponseWire::Answered {
                protocol,
                operation_id,
                binding,
                action,
                decision,
            },
            Self::Rejected {
                protocol,
                operation_id,
                binding,
                reason,
            } => TaskActionsResponseWire::Rejected {
                protocol,
                operation_id,
                binding,
                reason,
            },
        };
        wire.serialize(serializer)
    }
}

/// Whether `pending` is a listing a node can send: at most [`MAX_ACTION_PENDING`] requests,
/// each number and id once.
fn valid_listing(pending: &[PendingAction]) -> bool {
    u32::try_from(pending.len()).is_ok_and(|len| len <= MAX_ACTION_PENDING)
        && pending.iter().enumerate().all(|(index, entry)| {
            pending[..index]
                .iter()
                .all(|other| other.action != entry.action && other.id != entry.id)
        })
}

impl TaskLifecycleContext {
    /// Build the read-only [`TaskActionsRequest::Actions`] bound to this context's protocol.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleError::UnsupportedByProtocol`] before protocol 1.3.
    pub const fn actions(
        self,
        binding: TaskBinding,
    ) -> Result<TaskActionsRequest, TaskLifecycleError> {
        if !supports_task_admission(self.protocol()) {
            return Err(TaskLifecycleError::UnsupportedByProtocol);
        }
        Ok(TaskActionsRequest::Actions {
            protocol: self.protocol(),
            binding,
        })
    }

    /// Build a [`TaskActionsRequest::Answer`] bound to this context's protocol.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleError::UnsupportedByProtocol`] before protocol 1.3, and
    /// [`TaskLifecycleError::MalformedMessage`] for request number 0 or a decision a
    /// control plane may not give.
    pub fn answer(
        self,
        operation_id: OperationId,
        binding: TaskBinding,
        action: u32,
        decision: ActionDecision,
        note: Option<ActionNote>,
    ) -> Result<TaskActionsRequest, TaskLifecycleError> {
        if !supports_task_admission(self.protocol()) {
            return Err(TaskLifecycleError::UnsupportedByProtocol);
        }
        if action == 0 || !decision.answerable() {
            return Err(TaskLifecycleError::MalformedMessage);
        }
        Ok(TaskActionsRequest::Answer {
            protocol: self.protocol(),
            operation_id,
            binding,
            action,
            decision,
            note,
        })
    }

    /// Decode a wire-format `actions` or `answer` request bound to this context's exact
    /// protocol.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleError::MalformedMessage`] if `json` is not one of them, an
    /// answer names request 0 or a decision a control plane may not give, or the context
    /// predates 1.3, and [`TaskLifecycleError::ProtocolMismatch`] if it names another
    /// protocol version.
    pub fn decode_actions_request(
        self,
        json: &str,
    ) -> Result<TaskActionsRequest, TaskLifecycleError> {
        if !supports_task_admission(self.protocol()) {
            return Err(TaskLifecycleError::MalformedMessage);
        }
        let wire = serde_json::from_str::<TaskActionsRequestWire>(json)
            .map_err(|_| TaskLifecycleError::MalformedMessage)?;
        let (protocol, request) = match wire {
            TaskActionsRequestWire::Actions { protocol, binding } => {
                (protocol, TaskActionsRequest::Actions { protocol, binding })
            }
            TaskActionsRequestWire::Answer {
                protocol,
                operation_id,
                binding,
                action,
                decision,
                note,
            } => {
                if action == 0 || !decision.answerable() {
                    return Err(TaskLifecycleError::MalformedMessage);
                }
                (
                    protocol,
                    TaskActionsRequest::Answer {
                        protocol,
                        operation_id,
                        binding,
                        action,
                        decision,
                        note,
                    },
                )
            }
        };
        if protocol != self.protocol() {
            return Err(TaskLifecycleError::ProtocolMismatch);
        }
        Ok(request)
    }

    /// Build a [`TaskActionsResponse::Actions`] bound to this context's protocol.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleError::UnsupportedByProtocol`] before protocol 1.3, and
    /// [`TaskLifecycleError::MalformedMessage`] for more than [`MAX_ACTION_PENDING`]
    /// requests or a repeated number or id.
    pub fn actions_listed(
        self,
        binding: TaskBinding,
        state: TaskLifecycleState,
        pending: Vec<PendingAction>,
    ) -> Result<TaskActionsResponse, TaskLifecycleError> {
        if !supports_task_admission(self.protocol()) {
            return Err(TaskLifecycleError::UnsupportedByProtocol);
        }
        if !valid_listing(&pending) {
            return Err(TaskLifecycleError::MalformedMessage);
        }
        Ok(TaskActionsResponse::Actions {
            protocol: self.protocol(),
            binding,
            state,
            pending,
        })
    }

    /// Build a [`TaskActionsResponse::Answered`] bound to this context's protocol.
    #[must_use]
    pub const fn answered(
        self,
        operation_id: OperationId,
        binding: TaskBinding,
        action: u32,
        decision: ActionDecision,
    ) -> TaskActionsResponse {
        TaskActionsResponse::Answered {
            protocol: self.protocol(),
            operation_id,
            binding,
            action,
            decision,
        }
    }

    /// Build a [`TaskActionsResponse::Rejected`] bound to this context's protocol.
    #[must_use]
    pub const fn actions_rejected(
        self,
        operation_id: Option<OperationId>,
        binding: TaskBinding,
        reason: ActionRejectionReason,
    ) -> TaskActionsResponse {
        TaskActionsResponse::Rejected {
            protocol: self.protocol(),
            operation_id,
            binding,
            reason,
        }
    }

    /// Decode a wire-format `actions` or `answer` response bound to this context's exact
    /// protocol.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleError::MalformedMessage`] if `json` does not decode, lists
    /// more than [`MAX_ACTION_PENDING`] requests or one twice, answers with a decision a
    /// control plane may not give, or the context predates 1.3, and
    /// [`TaskLifecycleError::ProtocolMismatch`] if it names another protocol version.
    pub fn decode_actions_response(
        self,
        json: &str,
    ) -> Result<TaskActionsResponse, TaskLifecycleError> {
        if !supports_task_admission(self.protocol()) {
            return Err(TaskLifecycleError::MalformedMessage);
        }
        let wire = serde_json::from_str::<TaskActionsResponseWire>(json)
            .map_err(|_| TaskLifecycleError::MalformedMessage)?;
        let response = match wire {
            TaskActionsResponseWire::Actions {
                protocol,
                binding,
                state,
                pending,
            } => {
                if !valid_listing(&pending) {
                    return Err(TaskLifecycleError::MalformedMessage);
                }
                TaskActionsResponse::Actions {
                    protocol,
                    binding,
                    state,
                    pending,
                }
            }
            TaskActionsResponseWire::Answered {
                protocol,
                operation_id,
                binding,
                action,
                decision,
            } => {
                if action == 0 || !decision.answerable() {
                    return Err(TaskLifecycleError::MalformedMessage);
                }
                TaskActionsResponse::Answered {
                    protocol,
                    operation_id,
                    binding,
                    action,
                    decision,
                }
            }
            TaskActionsResponseWire::Rejected {
                protocol,
                operation_id,
                binding,
                reason,
            } => TaskActionsResponse::Rejected {
                protocol,
                operation_id,
                binding,
                reason,
            },
        };
        let protocol = match response {
            TaskActionsResponse::Actions { protocol, .. }
            | TaskActionsResponse::Answered { protocol, .. }
            | TaskActionsResponse::Rejected { protocol, .. } => protocol,
        };
        if protocol != self.protocol() {
            return Err(TaskLifecycleError::ProtocolMismatch);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use ward_events::{ExecutionAttemptId, LeaseId, TaskId};

    use super::*;
    use crate::{
        CapabilityManifest, CapabilityManifestBytes, NetworkGrant, TaskAdmissionError,
        TaskLifecycleRejectionReason,
    };

    fn binding() -> TaskBinding {
        TaskBinding::new(
            TaskId::from_u128(7),
            ExecutionAttemptId::from_u128(8),
            LeaseId::from_u128(9),
        )
    }

    fn one_three() -> TaskLifecycleContext {
        TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
    }

    fn one_two() -> TaskLifecycleContext {
        TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap()
    }

    fn op(value: u64) -> OperationId {
        OperationId::new(value).unwrap()
    }

    const BINDING_JSON: &str = r#""binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}"#;

    fn request(id: &str) -> ActionRequest {
        ActionRequest::new(
            ActionId::new(id).unwrap(),
            ActionKind::Approval,
            "deploy to staging",
            "plan: 3 services",
        )
        .unwrap()
    }

    #[test]
    fn grants_are_bounded_and_free_of_repeats() {
        let grant = ActionGrant::new(vec![ActionKind::Approval], 2, 4, 30).unwrap();
        assert_eq!(grant.kinds(), [ActionKind::Approval]);
        assert!(grant.allows(ActionKind::Approval));
        assert!(!grant.allows(ActionKind::Decision));
        assert_eq!(
            (grant.max_pending(), grant.max_total(), grant.wait_secs()),
            (2, 4, 30)
        );
        assert!(grant.within_ceilings());
        for (kinds, pending, total, wait) in [
            (vec![], 1, 1, 1),
            (vec![ActionKind::Approval, ActionKind::Approval], 1, 1, 1),
            (vec![ActionKind::Approval], 0, 1, 1),
            (vec![ActionKind::Approval], 1, 0, 1),
            (vec![ActionKind::Approval], 1, 1, 0),
            (vec![ActionKind::Approval], 3, 2, 1),
        ] {
            assert_eq!(
                ActionGrant::new(kinds.clone(), pending, total, wait),
                Err(ActionError::InvalidGrant),
                "{kinds:?} {pending} {total} {wait}"
            );
        }
        for over in [
            ActionGrant::new(vec![ActionKind::Approval], MAX_ACTION_PENDING + 1, 99, 1),
            ActionGrant::new(vec![ActionKind::Approval], 1, MAX_ACTION_TOTAL + 1, 1),
            ActionGrant::new(vec![ActionKind::Approval], 1, 1, MAX_ACTION_WAIT_SECS + 1),
        ] {
            assert!(!over.unwrap().within_ceilings());
        }
        let ceiling = ActionGrant::new(
            ActionKind::ALL.to_vec(),
            MAX_ACTION_PENDING,
            MAX_ACTION_TOTAL,
            MAX_ACTION_WAIT_SECS,
        )
        .unwrap();
        assert!(ceiling.within_ceilings());
        assert_eq!(
            ActionKind::ALL.map(ActionKind::as_str),
            ["approval", "decision"]
        );
    }

    #[test]
    fn a_manifest_may_carry_an_actions_grant_and_keeps_its_bytes_without_one() {
        let plain = CapabilityManifestBytes::new(br#"{"network":"offline"}"#.to_vec()).unwrap();
        assert_eq!(plain.manifest().actions(), None);
        let bytes = br#"{"network":"offline","actions":{"kinds":["approval","decision"],"max_pending":2,"max_total":4,"wait_secs":30}}"#;
        let granted = CapabilityManifestBytes::new(bytes.to_vec()).unwrap();
        let grant = granted.manifest().actions().unwrap();
        assert_eq!(grant.kinds(), [ActionKind::Approval, ActionKind::Decision]);
        let built = CapabilityManifest::new(NetworkGrant::Offline).with_actions(grant.clone());
        assert_eq!(&built, granted.manifest());
        assert_eq!(
            CapabilityManifestBytes::encode(&built).unwrap().bytes(),
            bytes
        );
    }

    #[test]
    fn an_actions_grant_outside_the_grammar_fails_manifest_decoding() {
        for bad in [
            r#"{"network":"offline","actions":{"kinds":[],"max_pending":1,"max_total":1,"wait_secs":1}}"#,
            r#"{"network":"offline","actions":{"kinds":["approval","approval"],"max_pending":1,"max_total":1,"wait_secs":1}}"#,
            r#"{"network":"offline","actions":{"kinds":["approval"],"max_pending":2,"max_total":1,"wait_secs":1}}"#,
            r#"{"network":"offline","actions":{"kinds":["approval"],"max_pending":1,"max_total":1,"wait_secs":0}}"#,
        ] {
            assert_eq!(
                CapabilityManifest::decode_json(bad.as_bytes()),
                Err(TaskAdmissionError::MalformedActionGrant(
                    ActionError::InvalidGrant
                )),
                "{bad}"
            );
        }
        for bad in [
            r#"{"network":"offline","actions":{"kinds":["credential"],"max_pending":1,"max_total":1,"wait_secs":1}}"#,
            r#"{"network":"offline","actions":{"kinds":["approval"],"max_pending":1,"max_total":1}}"#,
            r#"{"network":"offline","actions":{"kinds":["approval"],"max_pending":1,"max_total":1,"wait_secs":1,"extra":1}}"#,
            r#"{"network":"offline","actions":null}"#,
            r#"{"network":"offline","actions":{"kinds":["approval"],"max_pending":-1,"max_total":1,"wait_secs":1}}"#,
        ] {
            assert_eq!(
                CapabilityManifest::decode_json(bad.as_bytes()),
                Err(TaskAdmissionError::MalformedManifest),
                "{bad}"
            );
        }
        assert_eq!(
            TaskAdmissionError::MalformedActionGrant(ActionError::InvalidGrant).to_string(),
            "capability manifest actions grant is invalid"
        );
    }

    #[test]
    fn ids_notes_and_texts_are_bounded() {
        assert!(ActionId::new("a").is_ok());
        assert!(ActionId::new("deploy-1.step_2:x").is_ok());
        assert!(ActionId::new("x".repeat(MAX_ACTION_ID_BYTES)).is_ok());
        for bad in [
            String::new(),
            "x".repeat(MAX_ACTION_ID_BYTES + 1),
            "a b".to_owned(),
            "a/b".to_owned(),
            "é".to_owned(),
            "a\n".to_owned(),
        ] {
            assert_eq!(
                ActionId::new(bad.clone()),
                Err(ActionError::Malformed),
                "{bad}"
            );
        }
        assert_eq!(ActionId::new("abc").unwrap().as_str(), "abc");
        assert!(ActionNote::new("").is_ok());
        assert_eq!(
            ActionNote::new("n".repeat(MAX_ACTION_NOTE_BYTES))
                .unwrap()
                .as_str()
                .len(),
            MAX_ACTION_NOTE_BYTES
        );
        assert_eq!(
            ActionNote::new("n".repeat(MAX_ACTION_NOTE_BYTES + 1)),
            Err(ActionError::TooLong)
        );
        let id = ActionId::new("a").unwrap();
        assert!(
            ActionRequest::new(
                id.clone(),
                ActionKind::Decision,
                "s".repeat(MAX_ACTION_SUMMARY_BYTES),
                "d".repeat(MAX_ACTION_DETAIL_BYTES)
            )
            .is_ok()
        );
        assert_eq!(
            ActionRequest::new(
                id.clone(),
                ActionKind::Approval,
                "s".repeat(MAX_ACTION_SUMMARY_BYTES + 1),
                ""
            ),
            Err(ActionError::TooLong)
        );
        assert_eq!(
            ActionRequest::new(
                id.clone(),
                ActionKind::Approval,
                "s",
                "d".repeat(MAX_ACTION_DETAIL_BYTES + 1)
            ),
            Err(ActionError::TooLong)
        );
        assert_eq!(
            ActionRequest::new(id, ActionKind::Approval, "", ""),
            Err(ActionError::Malformed)
        );
        for error in [
            ActionError::InvalidGrant,
            ActionError::Malformed,
            ActionError::TooLong,
            ActionError::InvalidDecision,
        ] {
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn channel_requests_and_replies_have_a_strict_line_grammar() {
        let line = r#"{"id":"deploy-1","kind":"approval","summary":"deploy to staging","detail":"plan: 3 services"}"#;
        let decoded = ActionRequest::decode(line).unwrap();
        assert_eq!(decoded, request("deploy-1"));
        assert_eq!(serde_json::to_string(&decoded).unwrap(), line);
        assert_eq!(decoded.id().as_str(), "deploy-1");
        assert_eq!(decoded.kind(), ActionKind::Approval);
        assert_eq!(decoded.summary(), "deploy to staging");
        assert_eq!(decoded.detail(), "plan: 3 services");
        for bad in [
            "",
            "not json",
            r#"{"id":"a","kind":"approval","summary":"s"}"#,
            r#"{"id":"a","kind":"approval","summary":"s","detail":"","extra":1}"#,
            r#"{"id":"a","kind":"credential","summary":"s","detail":""}"#,
            r#"{"id":"a b","kind":"approval","summary":"s","detail":""}"#,
            r#"{"id":"a","kind":"approval","summary":"","detail":""}"#,
            r#"[{"id":"a","kind":"approval","summary":"s","detail":""}]"#,
            r#"{"request":"hello","protocol":{"major":1,"min_minor":3,"max_minor":3}}"#,
        ] {
            assert_eq!(
                ActionRequest::decode(bad),
                Err(ActionError::Malformed),
                "{bad}"
            );
        }
        let long = format!(
            r#"{{"id":"a","kind":"approval","summary":"s","detail":"{}"}}"#,
            "d".repeat(MAX_ACTION_DETAIL_BYTES + 1)
        );
        assert_eq!(ActionRequest::decode(&long), Err(ActionError::TooLong));

        let reply = ActionReply::new(
            ActionId::new("deploy-1").unwrap(),
            ActionDecision::Approved,
            Some(ActionNote::new("go ahead").unwrap()),
        );
        let json = serde_json::to_string(&reply).unwrap();
        assert_eq!(
            json,
            r#"{"id":"deploy-1","decision":"approved","note":"go ahead"}"#
        );
        assert_eq!(ActionReply::decode(&json).unwrap(), reply);
        assert_eq!(reply.id().as_str(), "deploy-1");
        assert_eq!(reply.decision(), ActionDecision::Approved);
        assert_eq!(reply.note().unwrap().as_str(), "go ahead");
        for decision in [
            ActionDecision::Denied,
            ActionDecision::Expired,
            ActionDecision::Cancelled,
        ] {
            let bare = ActionReply::new(ActionId::new("x").unwrap(), decision, None);
            let json = serde_json::to_string(&bare).unwrap();
            assert_eq!(
                json,
                format!(r#"{{"id":"x","decision":"{}"}}"#, decision.as_str())
            );
            assert_eq!(ActionReply::decode(&json).unwrap(), bare);
        }
        assert!(!ActionDecision::Expired.answerable());
        assert!(!ActionDecision::Cancelled.answerable());
        assert!(ActionDecision::Approved.answerable());
        assert!(ActionDecision::Denied.answerable());
        assert_eq!(
            ActionReply::decode(r#"{"id":"x","decision":"maybe"}"#),
            Err(ActionError::Malformed)
        );
        assert_eq!(
            ActionReply::decode(r#"{"id":"x","decision":"approved","note":null}"#),
            Err(ActionError::Malformed)
        );
        assert_eq!(
            ActionReply::decode(&format!(
                r#"{{"id":"x","decision":"approved","note":"{}"}}"#,
                "n".repeat(MAX_ACTION_NOTE_BYTES + 1)
            )),
            Err(ActionError::TooLong)
        );
    }

    #[test]
    fn actions_requests_are_one_three_features_with_a_stable_wire() {
        let listing = one_three().actions(binding()).unwrap();
        let json = serde_json::to_string(&listing).unwrap();
        assert_eq!(
            json,
            format!(r#"{{"request":"actions","protocol":{{"major":1,"minor":3}},{BINDING_JSON}}}"#)
        );
        assert_eq!(one_three().decode_actions_request(&json).unwrap(), listing);

        let answer = one_three()
            .answer(
                op(5),
                binding(),
                1,
                ActionDecision::Approved,
                Some(ActionNote::new("ok").unwrap()),
            )
            .unwrap();
        let answer_json = serde_json::to_string(&answer).unwrap();
        assert_eq!(
            answer_json,
            format!(
                r#"{{"request":"answer","protocol":{{"major":1,"minor":3}},"operation_id":5,{BINDING_JSON},"action":1,"decision":"approved","note":"ok"}}"#
            )
        );
        assert_eq!(
            one_three().decode_actions_request(&answer_json).unwrap(),
            answer
        );
        let bare = one_three()
            .answer(op(6), binding(), 2, ActionDecision::Denied, None)
            .unwrap();
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("note"), "{bare_json}");
        assert_eq!(
            one_three().decode_actions_request(&bare_json).unwrap(),
            bare
        );

        assert_eq!(
            one_two().actions(binding()),
            Err(TaskLifecycleError::UnsupportedByProtocol)
        );
        assert_eq!(
            one_two().answer(op(5), binding(), 1, ActionDecision::Approved, None),
            Err(TaskLifecycleError::UnsupportedByProtocol)
        );
        for (action, decision) in [
            (0, ActionDecision::Approved),
            (1, ActionDecision::Expired),
            (1, ActionDecision::Cancelled),
        ] {
            assert_eq!(
                one_three().answer(op(5), binding(), action, decision, None),
                Err(TaskLifecycleError::MalformedMessage)
            );
        }
        assert_eq!(
            one_two().decode_actions_request(&json),
            Err(TaskLifecycleError::MalformedMessage)
        );
        assert_eq!(
            one_three().decode_actions_request(&json.replace(r#""minor":3"#, r#""minor":2"#)),
            Err(TaskLifecycleError::ProtocolMismatch)
        );
        assert_eq!(
            one_three()
                .decode_actions_request(&answer_json.replace(r#""minor":3"#, r#""minor":2"#)),
            Err(TaskLifecycleError::ProtocolMismatch)
        );
        for bad in [
            json.replace("actions", "result"),
            json.replace("}}", r#"},"from_seq":1}"#),
            answer_json.replace(r#""action":1"#, r#""action":0"#),
            answer_json.replace("approved", "expired"),
            answer_json.replace("approved", "cancelled"),
            answer_json.replace(r#","note":"ok""#, r#","note":null"#),
            answer_json.replace(r#""operation_id":5,"#, ""),
            answer_json.replace(r#""ok""#, &format!("\"{}\"", "n".repeat(513))),
        ] {
            assert_eq!(
                one_three().decode_actions_request(&bad),
                Err(TaskLifecycleError::MalformedMessage),
                "{bad}"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn actions_responses_have_a_stable_wire_and_decode_strictly() {
        let pending = vec![
            PendingAction::new(1, request("deploy-1"), 29_000).unwrap(),
            PendingAction::new(
                2,
                ActionRequest::new(
                    ActionId::new("pick").unwrap(),
                    ActionKind::Decision,
                    "use the cache?",
                    "",
                )
                .unwrap(),
                30_000,
            )
            .unwrap(),
        ];
        assert_eq!(pending[0].action(), 1);
        assert_eq!(pending[0].id().as_str(), "deploy-1");
        assert_eq!(pending[0].kind(), ActionKind::Approval);
        assert_eq!(pending[0].summary(), "deploy to staging");
        assert_eq!(pending[0].detail(), "plan: 3 services");
        assert_eq!(pending[0].expires_in_ms(), 29_000);
        assert_eq!(
            PendingAction::new(0, request("x"), 1),
            Err(ActionError::Malformed)
        );
        let listed = one_three()
            .actions_listed(binding(), TaskLifecycleState::Running, pending.clone())
            .unwrap();
        let json = serde_json::to_string(&listed).unwrap();
        assert_eq!(
            json,
            format!(
                r#"{{"response":"actions","protocol":{{"major":1,"minor":3}},{BINDING_JSON},"state":"running","pending":[{{"action":1,"id":"deploy-1","kind":"approval","summary":"deploy to staging","detail":"plan: 3 services","expires_in_ms":29000}},{{"action":2,"id":"pick","kind":"decision","summary":"use the cache?","detail":"","expires_in_ms":30000}}]}}"#
            )
        );
        assert_eq!(one_three().decode_actions_response(&json).unwrap(), listed);
        assert_eq!(
            one_two().actions_listed(binding(), TaskLifecycleState::Running, Vec::new()),
            Err(TaskLifecycleError::UnsupportedByProtocol)
        );
        let repeated = vec![pending[0].clone(), pending[0].clone()];
        assert_eq!(
            one_three().actions_listed(binding(), TaskLifecycleState::Running, repeated),
            Err(TaskLifecycleError::MalformedMessage)
        );
        let too_many: Vec<PendingAction> = (1..=MAX_ACTION_PENDING + 1)
            .map(|action| PendingAction::new(action, request(&format!("r{action}")), 1).unwrap())
            .collect();
        assert_eq!(
            one_three().actions_listed(binding(), TaskLifecycleState::Running, too_many.clone()),
            Err(TaskLifecycleError::MalformedMessage)
        );
        let too_many_json = serde_json::to_string(&TaskActionsResponse::Actions {
            protocol: ProtocolVersion::new(1, 3),
            binding: binding(),
            state: TaskLifecycleState::Running,
            pending: too_many,
        })
        .unwrap();
        assert_eq!(
            one_three().decode_actions_response(&too_many_json),
            Err(TaskLifecycleError::MalformedMessage)
        );
        for bad in [
            json.replace(r#""action":2"#, r#""action":1"#),
            json.replace(r#""action":2"#, r#""action":0"#),
            json.replace(r#""id":"pick""#, r#""id":"deploy-1""#),
            json.replace(r#""summary":"use the cache?""#, r#""summary":"""#),
            json.replace(r#","expires_in_ms":30000"#, ""),
        ] {
            assert_eq!(
                one_three().decode_actions_response(&bad),
                Err(TaskLifecycleError::MalformedMessage),
                "{bad}"
            );
        }

        let answered = one_three().answered(op(5), binding(), 1, ActionDecision::Denied);
        let answered_json = serde_json::to_string(&answered).unwrap();
        assert_eq!(
            answered_json,
            format!(
                r#"{{"response":"answered","protocol":{{"major":1,"minor":3}},"operation_id":5,{BINDING_JSON},"action":1,"decision":"denied"}}"#
            )
        );
        assert_eq!(
            one_three().decode_actions_response(&answered_json).unwrap(),
            answered
        );
        for bad in [
            answered_json.replace("denied", "expired"),
            answered_json.replace(r#""action":1"#, r#""action":0"#),
        ] {
            assert_eq!(
                one_three().decode_actions_response(&bad),
                Err(TaskLifecycleError::MalformedMessage),
                "{bad}"
            );
        }

        for (operation_id, reason, spelled) in [
            (
                None,
                ActionRejectionReason::UnsupportedOperation,
                "unsupported_operation",
            ),
            (
                Some(op(5)),
                ActionRejectionReason::UnknownRequest,
                "unknown_request",
            ),
            (
                Some(op(5)),
                ActionRejectionReason::AlreadyAnswered,
                "already_answered",
            ),
            (
                Some(op(5)),
                ActionRejectionReason::StaleOperation,
                "stale_operation",
            ),
        ] {
            let rejected = one_three().actions_rejected(operation_id, binding(), reason);
            let json = serde_json::to_string(&rejected).unwrap();
            let id = operation_id.map_or_else(|| "null".to_owned(), |id| id.get().to_string());
            assert_eq!(
                json,
                format!(
                    r#"{{"response":"rejected","protocol":{{"major":1,"minor":3}},"operation_id":{id},{BINDING_JSON},"reason":"{spelled}"}}"#
                )
            );
            assert_eq!(
                one_three().decode_actions_response(&json).unwrap(),
                rejected
            );
        }
        assert_eq!(
            one_two().decode_actions_response(&answered_json),
            Err(TaskLifecycleError::MalformedMessage)
        );
        assert_eq!(
            one_three()
                .decode_actions_response(&answered_json.replace(r#""minor":3"#, r#""minor":2"#)),
            Err(TaskLifecycleError::ProtocolMismatch)
        );
        // A lifecycle decoder never takes a listing for an inspection, and vice versa.
        assert_eq!(
            one_three().decode_response(&json),
            Err(TaskLifecycleError::MalformedMessage)
        );
        let inspected =
            serde_json::to_string(&one_three().inspected(binding(), TaskLifecycleState::Running))
                .unwrap();
        assert_eq!(
            one_three().decode_actions_response(&inspected),
            Err(TaskLifecycleError::MalformedMessage)
        );
        let lifecycle_rejection = serde_json::to_string(&one_three().rejected(
            Some(op(5)),
            binding(),
            TaskLifecycleRejectionReason::InvalidState,
        ))
        .unwrap();
        assert!(matches!(
            one_three().decode_actions_response(&lifecycle_rejection),
            Ok(TaskActionsResponse::Rejected {
                reason: ActionRejectionReason::InvalidState,
                ..
            })
        ));
    }

    #[test]
    fn action_capabilities_say_what_the_node_offers() {
        assert!(!ActionCapabilities::NONE.any());
        assert_eq!(ActionCapabilities::default(), ActionCapabilities::NONE);
        assert!(ActionCapabilities::CEILINGS.any());
        assert_eq!(
            serde_json::to_string(&ActionCapabilities::CEILINGS).unwrap(),
            r#"{"approval":true,"decision":true,"max_pending":8,"max_total":64,"max_wait_secs":3600}"#
        );
    }
}
