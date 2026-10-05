//! The fail-closed attempt driver an external control plane needs (node-integration.md
//! §6, §9, §10): `create` → `admit` → `start` → poll `inspect` → read the receipt → `seal`.
//!
//! Every mutating verb uses an operation id from a caller-supplied [`OperationIds`], so a
//! control plane that restarts replays the same run with the same ids and the same signed
//! envelope and gets the same answers: the node answers each replayed id with the task's
//! current state and acts on nothing (§6.3), the workload is never run twice, and the
//! replayed `seal` is accepted again. Cancellation ([`CancelToken`]) and a workload still
//! running past its budget plus a grace end in `revoke`, never `stop`: the authority is
//! withdrawn durably and nothing under that lease can be started again (§10).
//!
//! A connection the node closed without an answer, or that timed out, leaves the verb's
//! effect unknown. The driver recovers exactly as §10 prescribes, once: it inspects, then
//! replays the same request with the same operation id. A second failure, or any other
//! transport failure, ends the run with [`AttemptOutcome::Unknown`] and a
//! `transport_error`; the driver never retries beyond that, never re-admits with a new
//! envelope and never starts a second attempt (ADR-0030 §6). The caller replays the run
//! with the same ids once the node is reachable again.

use std::fmt::Display;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use ward_events::log::{head_file_path, parse_head};
use ward_events::{Blake3Hash, LogReader, NodeAttemptEnd, WardEvent};
use ward_node_protocol::{
    OperationId, TaskAdmissionEnvelope, TaskAdmissionError, TaskBinding, TaskExecutionOutcome,
    TaskLifecycleRejectionReason, TaskLifecycleState,
};

use crate::client::{Applied, Client, ClientError, Inspection, Verb};
use crate::issuer::{IssuerKey, IssuerKeyError, SignedEnvelope};
use crate::transport::{Transport, TransportError};

/// The evidence log of an attempt under `task_root` (§6.5):
/// `<task-root>/<task>/<attempt>.evidence/events.log`.
#[must_use]
pub fn evidence_log_path(task_root: &Path, binding: TaskBinding) -> PathBuf {
    task_root
        .join(binding.task().to_string())
        .join(format!("{}.evidence", binding.attempt()))
        .join("events.log")
}

/// Why an [`OperationIds`] scheme could not be formed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum OperationIdsError {
    /// An operation id was zero.
    #[error("operation ids start at 1")]
    Zero,
    /// The scheme does not fit below 2^64.
    #[error("operation ids overflow")]
    Overflow,
}

/// The operation ids one attempt uses, one per verb (§6.3 keeps ids per verb).
///
/// The default scheme is `create` 1, `admit` 2, `start` 3, `stop` 4, `revoke` 5, `seal`
/// 6, with `pause`/`resume` counting up from 7; [`OperationIds::starting_at`] shifts the
/// whole scheme, and every id can be set explicitly. On the wire a scheme is either
/// `{"start_at": N}` or every field spelled out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct OperationIds {
    /// The `create` operation id.
    pub create: OperationId,
    /// The `admit` operation id.
    pub admit: OperationId,
    /// The `start` operation id.
    pub start: OperationId,
    /// The `stop` operation id (the driver never stops; it revokes).
    pub stop: OperationId,
    /// The `revoke` operation id.
    pub revoke: OperationId,
    /// The `seal` operation id.
    pub seal: OperationId,
    /// The first id for `pause` and `resume`, counting up.
    pub first_intervention: OperationId,
}

impl OperationIds {
    /// The default scheme shifted so that `create` is `first`.
    ///
    /// # Errors
    ///
    /// Returns [`OperationIdsError::Zero`] for 0 and [`OperationIdsError::Overflow`] when
    /// the scheme does not fit.
    pub fn starting_at(first: u64) -> Result<Self, OperationIdsError> {
        let id = |offset: u64| {
            first
                .checked_add(offset)
                .ok_or(OperationIdsError::Overflow)
                .and_then(|value| OperationId::new(value).map_err(|_| OperationIdsError::Zero))
        };
        Ok(Self {
            create: id(0)?,
            admit: id(1)?,
            start: id(2)?,
            stop: id(3)?,
            revoke: id(4)?,
            seal: id(5)?,
            first_intervention: id(6)?,
        })
    }
}

impl Default for OperationIds {
    fn default() -> Self {
        let id = |value: u64| OperationId::from(NonZeroU64::new(value).unwrap_or(NonZeroU64::MIN));
        Self {
            create: id(1),
            admit: id(2),
            start: id(3),
            stop: id(4),
            revoke: id(5),
            seal: id(6),
            first_intervention: id(7),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OperationIdsWire {
    StartAt {
        start_at: u64,
    },
    Explicit {
        create: OperationId,
        admit: OperationId,
        start: OperationId,
        stop: OperationId,
        revoke: OperationId,
        seal: OperationId,
        first_intervention: OperationId,
    },
}

impl<'de> Deserialize<'de> for OperationIds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match OperationIdsWire::deserialize(deserializer)? {
            OperationIdsWire::StartAt { start_at } => {
                Self::starting_at(start_at).map_err(D::Error::custom)
            }
            OperationIdsWire::Explicit {
                create,
                admit,
                start,
                stop,
                revoke,
                seal,
                first_intervention,
            } => Ok(Self {
                create,
                admit,
                start,
                stop,
                revoke,
                seal,
                first_intervention,
            }),
        }
    }
}

/// A cancellation the caller raises when its own lease or deadline is withdrawn.
#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// Request cancellation: the driver revokes the attempt at its next step.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// How the driver polls and how long it waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunConfig {
    /// The first interval between two `inspect`s; it doubles after each poll.
    pub poll_interval: Duration,
    /// The longest interval between two `inspect`s.
    pub max_poll_interval: Duration,
    /// How long past the workload's budget the driver waits before it revokes.
    pub grace: Duration,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(250),
            max_poll_interval: Duration::from_secs(2),
            grace: Duration::from_secs(60),
        }
    }
}

/// One attempt to run: the signed envelope, what the driver reads out of it, and where the
/// node keeps the attempt's evidence if the caller can read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptRequest {
    /// The binding the envelope is bound to.
    pub binding: TaskBinding,
    /// The signed envelope, sent byte for byte.
    pub envelope: SignedEnvelope,
    /// The envelope's wall-clock budget.
    pub budget: Duration,
    /// The node's `--task-root`, when the caller runs as the node's uid and may read the
    /// evidence log there.
    pub task_root: Option<PathBuf>,
}

impl AttemptRequest {
    /// Sign `envelope` with `issuer`.
    ///
    /// # Errors
    ///
    /// Returns [`IssuerKeyError::Envelope`] when the envelope does not fit the wire.
    pub fn sign(
        envelope: &TaskAdmissionEnvelope,
        issuer: &IssuerKey,
        task_root: Option<PathBuf>,
    ) -> Result<Self, IssuerKeyError> {
        Ok(Self {
            binding: envelope.binding(),
            envelope: issuer.sign(envelope)?,
            budget: Duration::from_millis(envelope.workload().wall_clock_budget_ms()),
            task_root,
        })
    }

    /// Use an envelope signed elsewhere, reading the binding and budget from its bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`TaskAdmissionError`] when the bytes are not one valid envelope.
    pub fn pre_signed(
        envelope: SignedEnvelope,
        task_root: Option<PathBuf>,
    ) -> Result<Self, TaskAdmissionError> {
        let decoded = envelope.envelope_json.decode()?;
        Ok(Self {
            binding: decoded.binding(),
            budget: Duration::from_millis(decoded.workload().wall_clock_budget_ms()),
            envelope,
            task_root,
        })
    }
}

/// What the driver observed, in order, while running an attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AttemptEvent {
    /// A mutating verb was accepted; `state` is the task's state after it.
    State {
        /// The verb.
        verb: Verb,
        /// Its operation id.
        operation_id: OperationId,
        /// The task's state.
        state: TaskLifecycleState,
    },
    /// The node refused a verb and changed nothing.
    Rejected {
        /// The verb.
        verb: Verb,
        /// Its operation id, `None` for `inspect`.
        operation_id: Option<OperationId>,
        /// The typed refusal.
        reason: TaskLifecycleRejectionReason,
    },
    /// The envelope was admitted; these exact bytes and proof replay it.
    Admitted {
        /// The signed bytes, as sent.
        envelope_json: ward_node_protocol::AdmissionEnvelopeJson,
        /// The proof over them.
        proof: ward_node_protocol::IssuerProof,
    },
    /// A verb got no answer; the driver inspects and replays it once (§10).
    Recovering {
        /// The verb.
        verb: Verb,
        /// Its operation id.
        operation_id: OperationId,
    },
    /// The attempt ended; its receipt outcome, if the node reports one (§9).
    Receipt {
        /// The ended state.
        state: TaskLifecycleState,
        /// The receipt outcome.
        outcome: Option<TaskExecutionOutcome>,
    },
    /// Where the node keeps the attempt's evidence log (§6.5).
    Evidence {
        /// The log path.
        path: PathBuf,
    },
}

/// The result of a run, mapped for a control plane that must fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOutcome {
    /// The receipt says `completed`.
    Completed,
    /// The receipt says `failed`.
    Failed,
    /// No trustworthy receipt: the node reported `unknown`, the transport failed, or the
    /// attempt never ended. Treat as failed.
    Unknown,
    /// The node refused `create`, `admit`, `start` or `inspect`; nothing ran.
    Refused {
        /// The refused verb.
        verb: Verb,
        /// The typed refusal.
        reason: TaskLifecycleRejectionReason,
    },
}

/// One mutating verb the run sent and what the node answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedOperation {
    /// The verb.
    pub verb: Verb,
    /// Its operation id; replay the run with the same ids to get the same answers.
    pub operation_id: OperationId,
    /// The task's state when the verb was accepted.
    pub state: Option<TaskLifecycleState>,
    /// The refusal when the verb was rejected.
    pub reason: Option<TaskLifecycleRejectionReason>,
}

/// Everything a control plane needs to record about one run.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptReport {
    /// The binding that ran.
    pub binding: TaskBinding,
    /// The task's last observed state.
    pub final_state: Option<TaskLifecycleState>,
    /// The outcome, mapped for a caller that fails closed.
    pub outcome: AttemptOutcome,
    /// `false` exactly when `outcome` is `unknown`: map it to failed.
    pub outcome_certain: bool,
    /// The node's receipt outcome, as inspected (§9).
    pub receipt: Option<TaskExecutionOutcome>,
    /// What ended the attempt, read from its evidence log when it is readable.
    pub cause: Option<NodeAttemptEnd>,
    /// Whether the node confirmed `seal`.
    pub sealed: bool,
    /// Whether the run was cancelled and revoked.
    pub cancelled: bool,
    /// Whether the workload outlived its budget plus the grace and was revoked.
    pub deadline_exceeded: bool,
    /// The evidence log path, when the task root is known.
    pub evidence_log: Option<PathBuf>,
    /// The sealed log's head hash, when the log is sealed and readable.
    pub evidence_head: Option<Blake3Hash>,
    /// Every mutating verb sent, with its id and answer.
    pub operations: Vec<AppliedOperation>,
    /// The transport failure that ended the run, if one did.
    pub transport_error: Option<String>,
}

/// Drives attempts over one connected client.
#[derive(Debug)]
pub struct Driver<'a, T: Transport> {
    client: &'a Client<T>,
    config: RunConfig,
}

impl<'a, T: Transport> Driver<'a, T> {
    /// A driver over `client`.
    pub const fn new(client: &'a Client<T>, config: RunConfig) -> Self {
        Self { client, config }
    }

    /// Run one attempt to its end and seal it; see the module documentation.
    ///
    /// `observe` receives every [`AttemptEvent`] as it happens. Replaying a run with the
    /// same `request` and `ids` never acts twice.
    pub fn run_attempt(
        &self,
        request: &AttemptRequest,
        ids: &OperationIds,
        cancel: &CancelToken,
        observe: &mut dyn FnMut(&AttemptEvent),
    ) -> AttemptReport {
        let mut run = Run {
            client: self.client,
            config: self.config,
            request,
            ids,
            cancel,
            observe,
            report: AttemptReport {
                binding: request.binding,
                final_state: None,
                outcome: AttemptOutcome::Unknown,
                outcome_certain: false,
                receipt: None,
                cause: None,
                sealed: false,
                cancelled: false,
                deadline_exceeded: false,
                evidence_log: None,
                evidence_head: None,
                operations: Vec::new(),
                transport_error: None,
            },
            refused: None,
        };
        let _ = run.execute();
        run.finish()
    }
}

struct Halt;

const fn ended(state: TaskLifecycleState) -> bool {
    matches!(
        state,
        TaskLifecycleState::Exited
            | TaskLifecycleState::Stopped
            | TaskLifecycleState::Revoked
            | TaskLifecycleState::Sealed
    )
}

struct Run<'r, T: Transport> {
    client: &'r Client<T>,
    config: RunConfig,
    request: &'r AttemptRequest,
    ids: &'r OperationIds,
    cancel: &'r CancelToken,
    observe: &'r mut dyn FnMut(&AttemptEvent),
    report: AttemptReport,
    refused: Option<(Verb, TaskLifecycleRejectionReason)>,
}

impl<T: Transport> Run<'_, T> {
    fn execute(&mut self) -> Result<(), Halt> {
        let request = self.request;
        let binding = request.binding;
        let mut state = self.required(Verb::Create, self.ids.create, |client, op| {
            client.create(binding, op)
        })?;
        state = self
            .required(Verb::Admit, self.ids.admit, |client, op| {
                client.admit(binding, op, &request.envelope)
            })?
            .or(state);
        (self.observe)(&AttemptEvent::Admitted {
            envelope_json: request.envelope.envelope_json.clone(),
            proof: request.envelope.proof,
        });

        let mut receipt = None;
        if !state.is_some_and(ended) {
            if self.cancel.is_cancelled() {
                self.report.cancelled = true;
                state = self.revoke()?.or(state);
            } else {
                state = self
                    .required(Verb::Start, self.ids.start, |client, op| {
                        client.start(binding, op)
                    })?
                    .or(state);
            }
        }
        if !state.is_some_and(ended) {
            receipt = self.poll()?;
        }
        let (state, outcome) = match receipt {
            Some(receipt) => receipt,
            None => self.inspect()?,
        };
        self.report.final_state = Some(state);
        if !ended(state) {
            return Ok(());
        }
        self.report.receipt = outcome;
        (self.observe)(&AttemptEvent::Receipt { state, outcome });
        match self.apply(Verb::Seal, self.ids.seal, |client, op| {
            client.seal(binding, op)
        })? {
            Applied::Accepted { state } => {
                self.report.sealed = state == TaskLifecycleState::Sealed;
                self.report.final_state = Some(state);
            }
            Applied::Rejected { .. } => {}
        }
        Ok(())
    }

    fn poll(&mut self) -> Result<Option<Receipt>, Halt> {
        let deadline =
            Instant::now().checked_add(self.request.budget.saturating_add(self.config.grace));
        let mut interval = self.config.poll_interval;
        loop {
            if self.cancel.is_cancelled() {
                self.report.cancelled = true;
                self.revoke()?;
                return Ok(None);
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                self.report.deadline_exceeded = true;
                self.revoke()?;
                return Ok(None);
            }
            let (state, outcome) = self.inspect()?;
            self.report.final_state = Some(state);
            if ended(state) {
                return Ok(Some((state, outcome)));
            }
            std::thread::sleep(interval);
            interval = interval
                .saturating_mul(2)
                .min(self.config.max_poll_interval);
        }
    }

    fn revoke(&mut self) -> Result<Option<TaskLifecycleState>, Halt> {
        let binding = self.request.binding;
        match self.apply(Verb::Revoke, self.ids.revoke, |client, op| {
            client.revoke(binding, op)
        })? {
            Applied::Accepted { state } => {
                self.report.final_state = Some(state);
                Ok(Some(state))
            }
            Applied::Rejected { .. } => Ok(None),
        }
    }

    fn required(
        &mut self,
        verb: Verb,
        operation: OperationId,
        call: impl Fn(&Client<T>, OperationId) -> Result<Applied, ClientError>,
    ) -> Result<Option<TaskLifecycleState>, Halt> {
        match self.apply(verb, operation, call)? {
            Applied::Accepted { state } => {
                self.report.final_state = Some(state);
                Ok(Some(state))
            }
            Applied::Rejected { reason } => {
                self.refused = Some((verb, reason));
                Err(Halt)
            }
        }
    }

    fn apply(
        &mut self,
        verb: Verb,
        operation: OperationId,
        call: impl Fn(&Client<T>, OperationId) -> Result<Applied, ClientError>,
    ) -> Result<Applied, Halt> {
        self.report.operations.push(AppliedOperation {
            verb,
            operation_id: operation,
            state: None,
            reason: None,
        });
        let applied = match call(self.client, operation) {
            Ok(applied) => applied,
            Err(error) if recoverable(&error) => {
                (self.observe)(&AttemptEvent::Recovering {
                    verb,
                    operation_id: operation,
                });
                let (state, _) = self.inspect()?;
                self.report.final_state = Some(state);
                call(self.client, operation).map_err(|error| self.halt(&error))?
            }
            Err(error) => return Err(self.halt(&error)),
        };
        if let Some(recorded) = self.report.operations.last_mut() {
            match applied {
                Applied::Accepted { state } => recorded.state = Some(state),
                Applied::Rejected { reason } => recorded.reason = Some(reason),
            }
        }
        (self.observe)(&match applied {
            Applied::Accepted { state } => AttemptEvent::State {
                verb,
                operation_id: operation,
                state,
            },
            Applied::Rejected { reason } => AttemptEvent::Rejected {
                verb,
                operation_id: Some(operation),
                reason,
            },
        });
        Ok(applied)
    }

    fn inspect(&mut self) -> Result<Receipt, Halt> {
        let binding = self.request.binding;
        let inspection = match self.client.inspect(binding) {
            Ok(inspection) => inspection,
            Err(error) if recoverable(&error) => self
                .client
                .inspect(binding)
                .map_err(|error| self.halt(&error))?,
            Err(error) => return Err(self.halt(&error)),
        };
        match inspection {
            Inspection::Inspected { state, outcome } => Ok((state, outcome)),
            Inspection::Rejected { reason } => {
                (self.observe)(&AttemptEvent::Rejected {
                    verb: Verb::Inspect,
                    operation_id: None,
                    reason,
                });
                self.refused = Some((Verb::Inspect, reason));
                Err(Halt)
            }
        }
    }

    fn halt(&mut self, error: &impl Display) -> Halt {
        self.report.transport_error = Some(error.to_string());
        Halt
    }

    fn finish(mut self) -> AttemptReport {
        if let Some(task_root) = &self.request.task_root {
            let path = evidence_log_path(task_root, self.request.binding);
            (self.observe)(&AttemptEvent::Evidence { path: path.clone() });
            self.report.cause = cause(&path);
            if self.report.sealed {
                self.report.evidence_head = sealed_head(&path);
            }
            self.report.evidence_log = Some(path);
        }
        self.report.outcome = if self.report.transport_error.is_some() {
            AttemptOutcome::Unknown
        } else if let Some((verb, reason)) = self.refused {
            AttemptOutcome::Refused { verb, reason }
        } else {
            match self.report.receipt {
                Some(TaskExecutionOutcome::Completed) => AttemptOutcome::Completed,
                Some(TaskExecutionOutcome::Failed) => AttemptOutcome::Failed,
                Some(TaskExecutionOutcome::Unknown) | None => AttemptOutcome::Unknown,
            }
        };
        self.report.outcome_certain = self.report.outcome != AttemptOutcome::Unknown;
        self.report
    }
}

type Receipt = (TaskLifecycleState, Option<TaskExecutionOutcome>);

const fn recoverable(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::NoResponse { .. } | ClientError::Transport(TransportError::TimedOut)
    )
}

fn cause(log: &Path) -> Option<NodeAttemptEnd> {
    let reader = LogReader::open(log).ok()?;
    reader
        .filter_map(Result::ok)
        .filter_map(|record| match record.event {
            WardEvent::NodeAttemptEnded { end, .. } => Some(end),
            _ => None,
        })
        .last()
}

fn sealed_head(log: &Path) -> Option<Blake3Hash> {
    let head = std::fs::read_to_string(head_file_path(log)).ok()?;
    let parsed = parse_head(&head).ok()?;
    let verified = LogReader::open(log).ok()?.verify_all().ok()?;
    (verified == parsed).then_some(parsed.hash)
}
