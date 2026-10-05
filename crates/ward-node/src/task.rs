//! Node-owned task registry for the task lifecycle protocol (#321, #324, #332).
//!
//! This slice binds [`TaskLifecycleRequest`]s to node-owned state. It implements:
//!
//! * `create` registers a task under its immutable [`TaskBinding`] in the
//!   [`TaskLifecycleState::Created`] state. `Created` means "the node has admitted this
//!   task identity into its registry", nothing more: no process, sandbox, credential or
//!   network authority exists for it. The protocol's `create` carries no workload
//!   description, so there is nothing to execute yet; the workload arrives with
//!   `admit`, and execution belongs to `start`. A `create` for a known task under a new
//!   execution attempt starts that attempt in `Created` only once the current attempt is
//!   finished (`exited`, `stopped`, `revoked` or `sealed`); it replaces the finished
//!   attempt, whose state and receipt are then no longer inspectable (ADR-0030 §6: a retry
//!   is a new attempt with a new envelope, and the durable per-task admission version
//!   keeps rising across attempts). While the current attempt is not finished, a new
//!   attempt is refused [`TaskLifecycleRejectionReason::AttemptMismatch`]. The replaced
//!   attempt id is first recorded durably in the node state
//!   ([`crate::state::NodeState::retire_attempt`]); if that cannot be recorded (an I/O
//!   failure, or the store at its bound) the new attempt is refused
//!   [`TaskLifecycleRejectionReason::ResourceUnavailable`] and nothing changes. A `create`
//!   naming a retired attempt is refused [`TaskLifecycleRejectionReason::StaleOperation`]
//!   whatever the registry holds, also after a restart or an eviction, so a replaced
//!   attempt is never registered, admitted or run again.
//! * `inspect` reports the state the registry actually holds for that binding. At
//!   protocol 1.3 an `exited`, `stopped`, `revoked` or `sealed` task also reports its
//!   receipt outcome; a 1.2 connection, which cannot represent `exited`, reads an exited
//!   task as `stopped` (its workload is gone) and never sees an outcome.
//! * `admit` (protocol 1.3) moves a `Created` task with the exact binding to
//!   [`TaskLifecycleState::Ready`] once [`NodeAdmission`] has verified its signed
//!   envelope and durably recorded its version (ADR-0030 §2). The registry keeps the
//!   admitted envelope and its trusted authority ([`AdmittedTask`]). Replaying the same
//!   operation with the same envelope and proof returns the same `Ready` result; any
//!   refusal leaves the task `Created`. A registry built without admission refuses
//!   `admit` as unsupported.
//! * `start` (protocol 1.3, a registry built [`TaskRegistry::with_execution`]) moves a
//!   `Ready` task to [`TaskLifecycleState::Running`] (ADR-0030 §3). It rechecks at the
//!   node clock that the admitted envelope and lease are unexpired and unrevoked, allocates
//!   and materialises the attempt's workspace ([`crate::workspace`]), and spawns the
//!   envelope's argv through the node's [`crate::execution::TaskLauncher`] on a node-owned
//!   reaper thread. `Running` is reported only once the launcher confirmed a spawn and its
//!   host pid is recorded. A clean pre-spawn failure refuses with no state change (the
//!   workspace is removed); an ambiguous launch is recorded `exited` with an `unknown`
//!   receipt and is never re-run (ADR-0030 §6).
//! * `stop` (protocol 1.3, with execution) moves a `Running` or `Paused` task to
//!   [`TaskLifecycleState::Stopped`] once its reaper has killed and reaped the workload,
//!   and a `Ready` task to `Stopped` without spawning anything. Stopping or revoking a
//!   `Paused` task continues its tree before the kill, so from then on the task reads
//!   `Running` until the reaper records its end; while that kill is pending, `pause` and
//!   `resume` are refused `invalid_state`.
//! * `pause` (protocol 1.3, with execution) moves a `Running` task to
//!   [`TaskLifecycleState::Paused`] only once the attempt's
//!   [`crate::execution::WorkloadFreezer`] confirmed its whole process tree stopped. A freeze
//!   that cannot be confirmed is continued back and refused
//!   [`TaskLifecycleRejectionReason::ResourceUnavailable`] with the task still `Running`.
//!   `resume` moves a `Paused` task back to `Running` once the thaw is confirmed, and is
//!   refused `resource_unavailable` with the task still `Paused` otherwise. The reaper keeps
//!   watching a paused workload and the budget clock keeps running: a paused workload can
//!   be stopped, revoked, or killed at its budget. An attempt applies at most
//!   [`MAX_ATTEMPT_PAUSES`] pauses; a further `pause` is refused `resource_unavailable`.
//! * `revoke` (protocol 1.3, with execution) moves a `Ready`, `Running` or `Paused` task to
//!   [`TaskLifecycleState::Revoked`]. It first records the revocation of the binding's lease
//!   at the node clock in the durable revocation store, so after a restart too no later
//!   `admit` or `start` under that lease, or under a lease delegated from it, is accepted
//!   (`lease_revoked`); a failure to record it refuses `resource_unavailable` with nothing
//!   changed. It then stops a live workload (requesting the kill, and continuing a paused
//!   tree) and waits for the reap. The receipt is `failed`, or what the reaper observed if
//!   the workload had already ended on its own; if the reap is not confirmed within the
//!   stop timeout the task is still `revoked` (its authority is gone) with an `unknown`
//!   receipt, and the reaper keeps killing.
//! * `seal` (protocol 1.3, with execution) moves an `exited`, `stopped` or `revoked` task
//!   to the terminal [`TaskLifecycleState::Sealed`]; the receipt is kept.
//!
//! The reaper waits on the workload promptly and, when it ends, moves the task
//! `Running → Exited` (or `Paused → Exited`) under the registry lock with a
//! [`TaskExecutionReceipt`]: exit 0 within budget is `completed`; a non-zero exit, a signal
//! or a kill at the budget is `failed`; a lost child is `unknown`. A stop that races a
//! natural exit ends in exactly one terminal state: the reaper decides, so a workload that
//! had already exited on its own is `exited` (and the stop is answered `invalid_state`),
//! otherwise it is `stopped`. A stopped attempt's receipt is `failed`, because the node
//! knows the attempt did not complete and that its workload is gone (a `ready` task never
//! ran at all); it is `unknown` only when the reap could not be confirmed. A stop whose
//! reap is not confirmed within the stop timeout is refused `resource_unavailable` and may
//! be replayed.
//!
//! Every transition is decided and applied under the registry lock; `stop` and `revoke`
//! release it only while the reaper kills and reaps, and the reaper records the outcome
//! under the lock, so a client that disconnects mid-request never leaves a half-applied
//! transition: the request is served to completion and its replay returns the result.
//!
//! Every operation id an attempt applied is kept, per verb, for the attempt's lifetime, and
//! a replay never acts twice. One rule covers all eight mutating verbs: replaying the
//! latest operation of its verb that took effect on the attempt is accepted with the
//! task's current state, however far the task has moved on since (`sealed`, for example);
//! replaying one that a later operation of the same verb superseded (only `pause` and
//! `resume` can take effect more than once) is refused
//! [`TaskLifecycleRejectionReason::StaleOperation`]. Any other operation that the task's
//! state does not allow is `invalid_state` with nothing changed.
//!
//! `stream` is answered with an explicit
//! [`TaskLifecycleRejectionReason::UnsupportedOperation`] and never changes a task's state,
//! as are `start`, `stop`, `pause`, `resume`, `revoke` and `seal` without execution or
//! below protocol 1.3. The node does not accept a transition it cannot carry out, and it
//! never reports one as applied.
//!
//! The registry is bounded by its capacity. A `sealed` task does not count against the
//! capacity: when a new task needs room, the task sealed longest ago is evicted, its record
//! removed first (its durable admission version and any revocation stay in the node
//! state); with no sealed task to evict, a full registry refuses a new `create` with
//! [`TaskLifecycleRejectionReason::ResourceUnavailable`] rather than growing without limit.
//! An attempt's workspace outlives a restart, so the same attempt is never started twice.
//! Dropping the registry stops and reaps every live workload; a node process that dies
//! outright takes its sandboxes with it (`--die-with-parent`).
//!
//! A registry that admits is durable: every task has a record ([`crate::records`]), and
//! every transition is written to it before the in-memory view changes and before the
//! verb is answered. A write that fails refuses the verb
//! [`TaskLifecycleRejectionReason::ResourceUnavailable`] with nothing changed; `pause` and
//! `resume` undo their freeze or thaw first. `start` records a launch intent before it
//! spawns and the spawned host process once the spawn is confirmed; a spawn whose record
//! cannot be written is killed and recorded `exited` with an `unknown` receipt. The reaper
//! records how an attempt ended whether or not the record can be written; a record it
//! could not write still reads as executing. A restarted node rebuilds the registry from
//! the records, and records every recovered change, before it serves:
//!
//! * a `created` task is `created`. A `ready` task is `created` again and forgets its
//!   admission: the node never starts on an admission it did not verify itself since it
//!   started, and the admission version is durable, so the task is admitted again only
//!   under a higher version;
//! * an attempt recorded launching, `running` or `paused` (a pending `stop` or `revoke`
//!   included) may have had effects: it becomes `exited` with an `unknown` receipt, any
//!   survivor of its recorded workload process is killed, and it is never run again
//!   (ADR-0030 §6);
//! * an `exited`, `stopped`, `revoked` or `sealed` task keeps its state and receipt.
//!
//! The applied operation ids survive with their task, so a replay after a restart is
//! answered as before and never acts: replaying the `start` of an attempt recovered as
//! `exited` answers `exited` and spawns nothing.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::sync::{Arc, Condvar, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use thiserror::Error;
use ward_events::{Blake3Hash, TaskId};
use ward_node_protocol::{
    AdmissionEnvelopeJson, IssuerProof, OperationId, TaskAdmissionEnvelope, TaskBinding,
    TaskExecutionOutcome, TaskExecutionReceipt, TaskLifecycleContext, TaskLifecycleRejectionReason,
    TaskLifecycleRequest, TaskLifecycleResponse, TaskLifecycleState, TaskReceiptContext,
    supports_task_admission,
};

use crate::admission::TrustedTaskAdmission;
use crate::admit::{NodeAdmission, VerifiedAdmission};
use crate::execution::{
    LaunchRequest, NodeExecution, SandboxLauncher, SpawnError, StopSignal, TaskLauncher,
    WorkloadExit, WorkloadFreezer, WorkloadProcess,
};
use crate::records::{
    AdmitRecord, RECORD_FORMAT, RecordedState, SealRecord, TaskRecord, TaskRecordError, TaskStore,
};
use crate::workspace::{WorkspaceError, discard};

/// Default upper bound on tasks one node registry holds.
pub const MAX_NODE_TASKS: usize = 1024;

/// Upper bound on `pause` operations one execution attempt applies. Every applied
/// operation id of an attempt is kept for the attempt's lifetime (one each for `create`,
/// `admit`, `start`, `stop`, `revoke` and `seal`, and every `pause` and `resume`, of which
/// there are never more than pauses), so a replay is always recognised; once this bound is
/// reached a new `pause` is refused [`TaskLifecycleRejectionReason::ResourceUnavailable`]
/// rather than forgetting an id.
pub const MAX_ATTEMPT_PAUSES: usize = 128;

/// The shared task registry is unavailable: an earlier panic poisoned its lock.
#[derive(Clone, Copy, Debug, Error)]
#[error("ward-node task registry is unavailable")]
pub struct TaskRegistryUnavailable;

type Reason = TaskLifecycleRejectionReason;
type State = TaskLifecycleState;
type SharedRegistry = Arc<Mutex<TaskRegistry>>;

#[derive(Clone, Debug)]
struct NodeTask {
    binding: TaskBinding,
    state: TaskLifecycleState,
    created_by: OperationId,
    admit: Option<AdmitRecord>,
    admitted: Option<AdmittedTask>,
    started_by: Option<OperationId>,
    workspace: Option<PathBuf>,
    attempt: Option<Attempt>,
    stopped_by: Option<OperationId>,
    paused_by: Vec<OperationId>,
    resumed_by: Vec<OperationId>,
    revoked_by: Option<OperationId>,
    sealed: Option<SealRecord>,
    receipt: Option<TaskExecutionReceipt>,
}

/// A spawned (or ambiguously spawned) attempt and the handles its reaper shares.
#[derive(Clone, Debug)]
struct Attempt {
    pid: Option<u32>,
    process: Option<WorkloadProcess>,
    freezer: Option<Arc<dyn WorkloadFreezer>>,
    stop: StopSignal,
    stop_requested_by: Option<OperationId>,
    revoke_requested_by: Option<OperationId>,
    reaped: Arc<Reaped>,
}

/// Set by an attempt's reaper once the attempt's terminal state is recorded.
#[derive(Debug, Default)]
struct Reaped {
    done: Mutex<bool>,
    changed: Condvar,
}

impl Reaped {
    fn set(&self) {
        let mut done = self.done.lock().unwrap_or_else(PoisonError::into_inner);
        *done = true;
        self.changed.notify_all();
    }

    fn is_set(&self) -> bool {
        *self.done.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait(&self, timeout: Duration) -> bool {
        let deadline = Instant::now().checked_add(timeout);
        let mut done = self.done.lock().unwrap_or_else(PoisonError::into_inner);
        while !*done {
            let remaining = deadline
                .and_then(|deadline| deadline.checked_duration_since(Instant::now()))
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                return false;
            }
            done = self
                .changed
                .wait_timeout(done, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }
}

/// The admission a `Ready` task was admitted under, kept for `start`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedTask {
    operation_id: OperationId,
    envelope_json: AdmissionEnvelopeJson,
    proof: IssuerProof,
    verified: VerifiedAdmission,
}

impl AdmittedTask {
    /// The `admit` operation that admitted the task.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// The exact envelope bytes the issuer signed.
    #[must_use]
    pub const fn envelope_json(&self) -> &AdmissionEnvelopeJson {
        &self.envelope_json
    }

    /// The issuer proof that verified over [`Self::envelope_json`].
    #[must_use]
    pub const fn proof(&self) -> IssuerProof {
        self.proof
    }

    /// The decoded, verified envelope.
    #[must_use]
    pub const fn envelope(&self) -> &TaskAdmissionEnvelope {
        self.verified.envelope()
    }

    /// The trusted authority the envelope carried; revalidate it before use.
    #[must_use]
    pub const fn authority(&self) -> &TrustedTaskAdmission {
        self.verified.authority()
    }
}

/// Bounded registry of node-owned tasks keyed by task identity, durable when it admits.
#[derive(Debug)]
pub struct TaskRegistry {
    tasks: HashMap<TaskId, NodeTask>,
    capacity: usize,
    admission: Option<NodeAdmission>,
    execution: Option<NodeExecution>,
    store: Option<TaskStore>,
    seals: u64,
    retired: Vec<Attempt>,
}

/// Where a registry's task records go: nowhere for a registry without admission.
#[derive(Clone, Copy)]
struct Journal<'a>(Option<&'a TaskStore>);

impl Journal<'_> {
    fn write(self, record: &TaskRecord) -> Result<(), Reason> {
        self.0.map_or(Ok(()), |store| {
            store.write(record).map_err(|_| Reason::ResourceUnavailable)
        })
    }

    fn remove(self, task: TaskId) -> Result<(), Reason> {
        self.0.map_or(Ok(()), |store| {
            store.remove(task).map_err(|_| Reason::ResourceUnavailable)
        })
    }
}

impl Default for TaskRegistry {
    fn default() -> Self {
        Self::with_capacity(MAX_NODE_TASKS)
    }
}

/// What `stop` or `revoke` does once it has looked at the task under the registry lock.
enum ReapStep {
    Answer(TaskLifecycleResponse),
    AwaitReap(Arc<Reaped>, Duration),
}

impl TaskRegistry {
    /// An empty, in-memory registry that holds at most `capacity` tasks.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            tasks: HashMap::new(),
            capacity,
            admission: None,
            execution: None,
            store: None,
            seals: 0,
            retired: Vec::new(),
        }
    }

    /// The registry of at most `capacity` tasks recorded under the node state directory,
    /// as recovered after a restart (see the module docs). Every survivor of an attempt
    /// that may have been executing is ended through `survivors`, and every recovered
    /// change is recorded before the registry is returned.
    fn recover(
        capacity: usize,
        admission: NodeAdmission,
        execution: Option<NodeExecution>,
    ) -> Result<Self, TaskRecordError> {
        let store = TaskStore::open(admission.state().dir())?;
        let survivors: Arc<dyn TaskLauncher> = execution
            .as_ref()
            .map_or_else(|| Arc::new(SandboxLauncher), NodeExecution::launcher);
        let mut tasks = HashMap::new();
        let mut seals = 0;
        for record in store.load(capacity)? {
            let (task, changed) = NodeTask::recovered(record, survivors.as_ref());
            if changed {
                store.write(&task.record())?;
            }
            if let Some(sealed) = task.sealed {
                seals = seals.max(sealed.order.saturating_add(1));
            }
            tasks.insert(task.binding.task(), task);
        }
        Ok(Self {
            tasks,
            capacity,
            admission: Some(admission),
            execution,
            store: Some(store),
            seals,
            retired: Vec::new(),
        })
    }

    /// The registry of at most `capacity` tasks that admits through `admission`, recovered
    /// from its task records.
    ///
    /// # Errors
    ///
    /// Returns [`TaskRecordError`] when the task records cannot be read, are invalid or
    /// more than `capacity`, or a recovered change cannot be recorded.
    pub fn with_admission(
        capacity: usize,
        admission: NodeAdmission,
    ) -> Result<Self, TaskRecordError> {
        Self::recover(capacity, admission, None)
    }

    /// The registry of at most `capacity` tasks that admits through `admission` and
    /// starts, pauses, resumes, stops, revokes and seals admitted tasks through `execution`
    /// (protocol 1.3), recovered from its task records.
    ///
    /// # Errors
    ///
    /// Returns [`TaskRecordError`] when the task records cannot be read, are invalid or
    /// more than `capacity`, or a recovered change cannot be recorded.
    pub fn with_execution(
        capacity: usize,
        admission: NodeAdmission,
        execution: NodeExecution,
    ) -> Result<Self, TaskRecordError> {
        Self::recover(capacity, admission, Some(execution))
    }

    /// Whether this registry executes admitted tasks.
    #[must_use]
    pub const fn executes(&self) -> bool {
        self.execution.is_some()
    }

    /// The admission configuration, if this registry admits tasks.
    #[must_use]
    pub const fn admission(&self) -> Option<&NodeAdmission> {
        self.admission.as_ref()
    }

    /// The admission configuration, for recording durable revocations.
    pub const fn admission_mut(&mut self) -> Option<&mut NodeAdmission> {
        self.admission.as_mut()
    }

    /// The admission held by the task `binding` names, if it was admitted under exactly
    /// that binding since this registry was built.
    #[must_use]
    pub fn admitted(&self, binding: TaskBinding) -> Option<&AdmittedTask> {
        self.task(binding).and_then(|task| task.admitted.as_ref())
    }

    /// The recorded host pid of the attempt `binding` names, while it is running.
    #[must_use]
    pub fn running_pid(&self, binding: TaskBinding) -> Option<u32> {
        self.task(binding)
            .filter(|task| task.state == TaskLifecycleState::Running)
            .and_then(|task| task.attempt.as_ref())
            .and_then(|attempt| attempt.pid)
    }

    /// The execution receipt of the attempt `binding` names, once it has ended.
    #[must_use]
    pub fn receipt(&self, binding: TaskBinding) -> Option<TaskExecutionReceipt> {
        self.task(binding).and_then(|task| task.receipt)
    }

    /// Number of tasks the registry currently holds, sealed ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Whether the registry holds no tasks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    fn task(&self, binding: TaskBinding) -> Option<&NodeTask> {
        self.tasks
            .get(&binding.task())
            .filter(|task| task.binding == binding)
    }

    /// Serve one decoded lifecycle request against the shared registry.
    ///
    /// `start`, `stop` and `revoke` are served here, because the reaper of a started
    /// attempt needs the shared registry to record how it ended; every other verb is
    /// [`Self::handle`]. The registry lock is never held while a workload runs: `start`
    /// returns once the spawn is confirmed, and `stop` and `revoke` release the lock while
    /// the reaper kills and reaps. `pause` and `resume` hold it for at most the freezer's
    /// settle bound.
    ///
    /// # Errors
    ///
    /// Returns [`TaskRegistryUnavailable`] if the registry lock is poisoned.
    pub fn serve(
        registry: &SharedRegistry,
        context: TaskLifecycleContext,
        request: TaskLifecycleRequest,
    ) -> Result<TaskLifecycleResponse, TaskRegistryUnavailable> {
        let lock = || registry.lock().map_err(|_| TaskRegistryUnavailable);
        match request {
            TaskLifecycleRequest::Start {
                operation_id,
                binding,
                ..
            } => Ok(lock()?.start(registry, context, operation_id, binding)),
            TaskLifecycleRequest::Stop {
                operation_id,
                binding,
                ..
            } => {
                let step = lock()?.begin_stop(context, operation_id, binding);
                let (reaped, timeout) = match step {
                    ReapStep::Answer(response) => return Ok(response),
                    ReapStep::AwaitReap(reaped, timeout) => (reaped, timeout),
                };
                reaped.wait(timeout);
                Ok(lock()?.finish_stop(context, operation_id, binding))
            }
            TaskLifecycleRequest::Revoke {
                operation_id,
                binding,
                ..
            } => {
                let step = lock()?.begin_revoke(context, operation_id, binding);
                let (reaped, timeout) = match step {
                    ReapStep::Answer(response) => return Ok(response),
                    ReapStep::AwaitReap(reaped, timeout) => (reaped, timeout),
                };
                reaped.wait(timeout);
                Ok(lock()?.finish_revoke(context, operation_id, binding))
            }
            other => Ok(lock()?.handle(context, other)),
        }
    }

    /// Apply one decoded lifecycle request and build its response under `context`.
    ///
    /// The request must already have been decoded through `context` (which proves it
    /// names the negotiated protocol). `start`, `stop` and `revoke` need the shared
    /// registry and are served only through [`Self::serve`]; here they are refused as
    /// unsupported.
    #[allow(clippy::needless_pass_by_value)]
    pub fn handle(
        &mut self,
        context: TaskLifecycleContext,
        request: TaskLifecycleRequest,
    ) -> TaskLifecycleResponse {
        let answer = |operation_id, binding, result: Result<State, Reason>| match result {
            Ok(state) => context.accepted(operation_id, binding, visible(context, state)),
            Err(reason) => context.rejected(Some(operation_id), binding, reason),
        };
        match request {
            TaskLifecycleRequest::Create {
                operation_id,
                binding,
                ..
            } => self.create(context, operation_id, binding),
            TaskLifecycleRequest::Inspect { binding, .. } => self.inspect(context, binding),
            TaskLifecycleRequest::Admit {
                operation_id,
                binding,
                envelope_json,
                proof,
                ..
            } => answer(
                operation_id,
                binding,
                self.admit(operation_id, binding, envelope_json, proof),
            ),
            TaskLifecycleRequest::Pause {
                operation_id,
                binding,
                ..
            } => answer(
                operation_id,
                binding,
                self.pause(context, operation_id, binding),
            ),
            TaskLifecycleRequest::Resume {
                operation_id,
                binding,
                ..
            } => answer(
                operation_id,
                binding,
                self.resume(context, operation_id, binding),
            ),
            TaskLifecycleRequest::Seal {
                operation_id,
                binding,
                ..
            } => answer(
                operation_id,
                binding,
                self.seal(context, operation_id, binding),
            ),
            TaskLifecycleRequest::Start {
                operation_id,
                binding,
                ..
            }
            | TaskLifecycleRequest::Stop {
                operation_id,
                binding,
                ..
            }
            | TaskLifecycleRequest::Revoke {
                operation_id,
                binding,
                ..
            } => context.rejected(
                Some(operation_id),
                binding,
                TaskLifecycleRejectionReason::UnsupportedOperation,
            ),
            TaskLifecycleRequest::Stream { binding, .. } => context.rejected(
                None,
                binding,
                TaskLifecycleRejectionReason::UnsupportedOperation,
            ),
        }
    }

    fn create(
        &mut self,
        context: TaskLifecycleContext,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> TaskLifecycleResponse {
        let refuse = |reason| context.rejected(Some(operation_id), binding, reason);
        if self.admission.as_ref().is_some_and(|admission| {
            admission
                .state()
                .is_retired_attempt(binding.task(), binding.attempt())
        }) {
            return refuse(Reason::StaleOperation);
        }
        if let Some(task) = self.tasks.get(&binding.task()) {
            match task.matches(binding) {
                Ok(()) if task.created_by == operation_id => {
                    return context.accepted(
                        operation_id,
                        task.binding,
                        visible(context, task.state),
                    );
                }
                Ok(()) => return refuse(Reason::InvalidState),
                Err(Reason::AttemptMismatch) if finished(task.state) => {
                    let current = task.binding;
                    let Some(admission) = self.admission.as_mut() else {
                        return refuse(Reason::ResourceUnavailable);
                    };
                    if admission
                        .state_mut()
                        .retire_attempt(current.task(), current.attempt())
                        .is_err()
                    {
                        return refuse(Reason::ResourceUnavailable);
                    }
                    let task = NodeTask::new(binding, operation_id);
                    if let Err(reason) = Journal(self.store.as_ref()).write(&task.record()) {
                        return refuse(reason);
                    }
                    if let Some(replaced) = self.tasks.insert(binding.task(), task) {
                        self.retire(replaced);
                    }
                    return context.accepted(operation_id, binding, TaskLifecycleState::Created);
                }
                Err(reason) => return refuse(reason),
            }
        }

        if self.tasks.len() >= self.capacity && !self.evict_oldest_sealed() {
            return context.rejected(
                Some(operation_id),
                binding,
                TaskLifecycleRejectionReason::ResourceUnavailable,
            );
        }

        let task = NodeTask::new(binding, operation_id);
        if let Err(reason) = Journal(self.store.as_ref()).write(&task.record()) {
            return refuse(reason);
        }
        self.tasks.insert(binding.task(), task);
        context.accepted(operation_id, binding, TaskLifecycleState::Created)
    }

    /// Make room by forgetting the task sealed longest ago, its record first; false if
    /// none is sealed or its record cannot be removed.
    fn evict_oldest_sealed(&mut self) -> bool {
        let Some(oldest) = self
            .tasks
            .iter()
            .filter_map(|(id, task)| task.sealed.map(|sealed| (sealed.order, *id)))
            .min()
            .map(|(_, id)| id)
        else {
            return false;
        };
        if Journal(self.store.as_ref()).remove(oldest).is_err() {
            return false;
        }
        if let Some(evicted) = self.tasks.remove(&oldest) {
            self.retire(evicted);
        }
        true
    }

    /// Keep a forgotten task's attempt until its reaper is done, so dropping the registry
    /// still waits for it.
    fn retire(&mut self, task: NodeTask) {
        self.retired.retain(|attempt| !attempt.reaped.is_set());
        if let Some(attempt) = task.attempt
            && !attempt.reaped.is_set()
        {
            self.retired.push(attempt);
        }
    }

    fn admit(
        &mut self,
        operation_id: OperationId,
        binding: TaskBinding,
        envelope_json: AdmissionEnvelopeJson,
        proof: IssuerProof,
    ) -> Result<TaskLifecycleState, TaskLifecycleRejectionReason> {
        let journal = Journal(self.store.as_ref());
        let Some(admission) = self.admission.as_mut() else {
            return Err(TaskLifecycleRejectionReason::UnsupportedOperation);
        };
        let Some(task) = self.tasks.get_mut(&binding.task()) else {
            return Err(TaskLifecycleRejectionReason::TaskNotFound);
        };
        task.matches(binding)?;
        let envelope = Blake3Hash::hash(envelope_json.as_bytes());
        if task.admit.as_ref().is_some_and(|admit| {
            admit.operation_id == operation_id && admit.envelope == envelope && admit.proof == proof
        }) {
            return Ok(task.state);
        }
        if task.state != TaskLifecycleState::Created {
            return Err(TaskLifecycleRejectionReason::InvalidState);
        }

        let verified = admission.verify(binding, &envelope_json, &proof)?;
        let mut ready = task.clone();
        ready.state = TaskLifecycleState::Ready;
        ready.admit = Some(AdmitRecord {
            operation_id,
            envelope,
            proof,
            session: verified.envelope().session(),
        });
        journal.write(&ready.record())?;
        if let Err(reason) = admission.commit(&verified) {
            let _ = journal.write(&task.record());
            return Err(reason);
        }
        ready.admitted = Some(AdmittedTask {
            operation_id,
            envelope_json,
            proof,
            verified,
        });
        *task = ready;
        Ok(task.state)
    }

    fn inspect(
        &self,
        context: TaskLifecycleContext,
        binding: TaskBinding,
    ) -> TaskLifecycleResponse {
        let Some(task) = self.tasks.get(&binding.task()) else {
            return context.rejected(None, binding, TaskLifecycleRejectionReason::TaskNotFound);
        };
        if let Err(reason) = task.matches(binding) {
            return context.rejected(None, binding, reason);
        }
        task.receipt
            .and_then(|receipt| {
                context
                    .inspected_with_outcome(task.binding, task.state, receipt.outcome())
                    .ok()
            })
            .unwrap_or_else(|| context.inspected(task.binding, visible(context, task.state)))
    }

    /// The task `binding` names and where its record goes, for a verb only an executing
    /// node serves at 1.3.
    fn executing_task(
        &mut self,
        context: TaskLifecycleContext,
        binding: TaskBinding,
    ) -> Result<(&mut NodeTask, Journal<'_>), Reason> {
        if self.execution.is_none()
            || self.admission.is_none()
            || !supports_task_admission(context.protocol())
        {
            return Err(Reason::UnsupportedOperation);
        }
        let task = self
            .tasks
            .get_mut(&binding.task())
            .ok_or(Reason::TaskNotFound)?;
        task.matches(binding)?;
        Ok((task, Journal(self.store.as_ref())))
    }

    fn pause(
        &mut self,
        context: TaskLifecycleContext,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> Result<State, Reason> {
        let (task, journal) = self.executing_task(context, binding)?;
        if let Some(replay) = replay(&task.paused_by, operation_id, task.state) {
            return replay;
        }
        if task.state != State::Running {
            return Err(Reason::InvalidState);
        }
        if task.paused_by.len() >= MAX_ATTEMPT_PAUSES {
            return Err(Reason::ResourceUnavailable);
        }
        let freezer = task.freezer().ok_or(Reason::InvalidState)?;
        freezer.freeze().map_err(|_| Reason::ResourceUnavailable)?;
        if let Err(reason) = task.commit(journal, |task| {
            task.state = State::Paused;
            task.paused_by.push(operation_id);
        }) {
            let _ = freezer.thaw();
            return Err(reason);
        }
        Ok(task.state)
    }

    fn resume(
        &mut self,
        context: TaskLifecycleContext,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> Result<State, Reason> {
        let (task, journal) = self.executing_task(context, binding)?;
        if let Some(replay) = replay(&task.resumed_by, operation_id, task.state) {
            return replay;
        }
        if task.state != State::Paused {
            return Err(Reason::InvalidState);
        }
        let freezer = task.freezer().ok_or(Reason::InvalidState)?;
        freezer.thaw().map_err(|_| Reason::ResourceUnavailable)?;
        if let Err(reason) = task.commit(journal, |task| {
            task.state = State::Running;
            task.resumed_by.push(operation_id);
        }) {
            let _ = freezer.freeze();
            return Err(reason);
        }
        Ok(task.state)
    }

    fn seal(
        &mut self,
        context: TaskLifecycleContext,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> Result<State, Reason> {
        let order = self.seals;
        let (task, journal) = self.executing_task(context, binding)?;
        if task.sealed.is_some_and(|sealed| sealed.by == operation_id) {
            return Ok(task.state);
        }
        if !matches!(task.state, State::Exited | State::Stopped | State::Revoked) {
            return Err(Reason::InvalidState);
        }
        task.commit(journal, |task| {
            task.state = State::Sealed;
            task.sealed = Some(SealRecord {
                by: operation_id,
                order,
            });
        })?;
        self.seals = order.saturating_add(1);
        Ok(State::Sealed)
    }

    fn start(
        &mut self,
        registry: &SharedRegistry,
        context: TaskLifecycleContext,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> TaskLifecycleResponse {
        match self.prepare_start(context, operation_id, binding) {
            Ok(Prepared::Replay(state)) => context.accepted(operation_id, binding, state),
            Ok(Prepared::Launch(request, launcher, timeout)) => {
                match self.launch(registry, operation_id, binding, request, &launcher, timeout) {
                    Ok(state) => context.accepted(operation_id, binding, state),
                    Err(reason) => context.rejected(Some(operation_id), binding, reason),
                }
            }
            Err(reason) => context.rejected(Some(operation_id), binding, reason),
        }
    }

    fn prepare_start(
        &self,
        context: TaskLifecycleContext,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> Result<Prepared, Reason> {
        let (Some(execution), Some(admission)) = (&self.execution, &self.admission) else {
            return Err(Reason::UnsupportedOperation);
        };
        if !supports_task_admission(context.protocol()) {
            return Err(Reason::UnsupportedOperation);
        }
        let task = self
            .tasks
            .get(&binding.task())
            .ok_or(Reason::TaskNotFound)?;
        task.matches(binding)?;
        if task.started_by == Some(operation_id) {
            return Ok(Prepared::Replay(task.state));
        }
        let Some(admitted) = task
            .admitted
            .as_ref()
            .filter(|_| task.state == TaskLifecycleState::Ready)
        else {
            return Err(Reason::InvalidState);
        };
        admission.revalidate(&admitted.verified)?;

        let workload = admitted.envelope().workload();
        let workspace = execution
            .task_root()
            .materialise(binding, execution.snapshots(), workload.snapshot())
            .map_err(|error| match error {
                WorkspaceError::SnapshotUnavailable
                | WorkspaceError::AttemptExists
                | WorkspaceError::Io(_) => Reason::ResourceUnavailable,
            })?;
        Ok(Prepared::Launch(
            LaunchRequest::new(
                workspace,
                workload.argv().args().to_vec(),
                Duration::from_millis(workload.wall_clock_budget_ms()),
            ),
            execution.launcher(),
            execution.spawn_timeout(),
        ))
    }

    /// Record the launch intent, spawn, and record how the spawn went. A spawn whose
    /// `running` record cannot be written is killed and recorded `exited` with an `unknown`
    /// receipt, as is a clean refusal whose launch intent cannot be withdrawn: the durable
    /// intent already makes the attempt ambiguous.
    fn launch(
        &mut self,
        registry: &SharedRegistry,
        operation_id: OperationId,
        binding: TaskBinding,
        request: LaunchRequest,
        launcher: &Arc<dyn TaskLauncher>,
        spawn_timeout: Duration,
    ) -> Result<TaskLifecycleState, Reason> {
        let journal = Journal(self.store.as_ref());
        let workspace = request.workspace().to_path_buf();
        let Some(task) = self.tasks.get_mut(&binding.task()) else {
            discard(&workspace);
            return Err(Reason::TaskNotFound);
        };
        if let Err(reason) = journal.write(&task.launching(operation_id, &workspace)) {
            discard(&workspace);
            return Err(reason);
        }
        let stop = StopSignal::default();
        let done = Arc::new(Reaped::default());
        let (spawned_tx, spawned_rx) = sync_channel(1);
        let reaper = Reaper {
            registry: Arc::downgrade(registry),
            binding,
            stop: stop.clone(),
            reaped: Arc::clone(&done),
        };
        let launcher = Arc::clone(launcher);
        let thread = std::thread::Builder::new()
            .name("ward-node-reaper".to_owned())
            .spawn(move || {
                let workload = match launcher.launch(&request) {
                    Ok(workload) => workload,
                    Err(error) => {
                        let _ = spawned_tx.send(Err(error));
                        reaper.reaped.set();
                        return;
                    }
                };
                if spawned_tx
                    .send(Ok((workload.pid(), workload.process(), workload.freezer())))
                    .is_err()
                {
                    drop(workload);
                    reaper.reaped.set();
                    return;
                }
                let exit = workload.wait(&reaper.stop);
                reaper.record(exit);
            });

        let spawned = match thread {
            Err(_) => Err(SpawnError::Refused),
            Ok(_) => match spawned_rx.recv_timeout(spawn_timeout) {
                Ok(spawned) => spawned,
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    Err(SpawnError::Ambiguous)
                }
            },
        };
        let spawned = match spawned {
            Ok(spawned) => Some(spawned),
            Err(SpawnError::Refused) => {
                discard(&workspace);
                if journal.write(&task.record()).is_ok() {
                    return Err(Reason::ResourceUnavailable);
                }
                None
            }
            Err(SpawnError::Ambiguous) => None,
        };
        let running = spawned.is_some();
        let (pid, process, freezer) = spawned
            .map_or((None, None, None), |(pid, process, freezer)| {
                (Some(pid), process, Some(freezer))
            });
        task.started_by = Some(operation_id);
        task.workspace = Some(workspace);
        task.attempt = Some(Attempt {
            pid,
            process,
            freezer,
            stop: stop.clone(),
            stop_requested_by: None,
            revoke_requested_by: None,
            reaped: done,
        });
        if running {
            task.state = TaskLifecycleState::Running;
        } else {
            stop.request();
            task.finish(TaskLifecycleState::Exited, TaskExecutionOutcome::Unknown);
        }
        if journal.write(&task.record()).is_err() && running {
            stop.request();
            task.finish(TaskLifecycleState::Exited, TaskExecutionOutcome::Unknown);
        }
        Ok(task.state)
    }

    fn begin_stop(
        &mut self,
        context: TaskLifecycleContext,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> ReapStep {
        let refuse =
            |reason| ReapStep::Answer(context.rejected(Some(operation_id), binding, reason));
        let stop_timeout = self
            .execution
            .as_ref()
            .map_or(Duration::ZERO, NodeExecution::stop_timeout);
        let (task, journal) = match self.executing_task(context, binding) {
            Ok(found) => found,
            Err(reason) => return refuse(reason),
        };
        if task.stopped_by == Some(operation_id) {
            return ReapStep::Answer(context.accepted(operation_id, binding, task.state));
        }
        match task.state {
            TaskLifecycleState::Ready => match task.commit(journal, |task| {
                task.stopped_by = Some(operation_id);
                task.finish(TaskLifecycleState::Stopped, TaskExecutionOutcome::Failed);
            }) {
                Ok(()) => ReapStep::Answer(context.accepted(operation_id, binding, task.state)),
                Err(reason) => refuse(reason),
            },
            TaskLifecycleState::Running | TaskLifecycleState::Paused => match task.end_attempt() {
                Some(attempt) => {
                    attempt.stop_requested_by.get_or_insert(operation_id);
                    ReapStep::AwaitReap(Arc::clone(&attempt.reaped), stop_timeout)
                }
                None => refuse(Reason::InvalidState),
            },
            _ => refuse(Reason::InvalidState),
        }
    }

    fn finish_stop(
        &self,
        context: TaskLifecycleContext,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> TaskLifecycleResponse {
        let reason = match self.task(binding) {
            Some(task) if task.stopped_by == Some(operation_id) => {
                return context.accepted(operation_id, binding, task.state);
            }
            Some(task) if live(task.state) => Reason::ResourceUnavailable,
            Some(_) | None => Reason::InvalidState,
        };
        context.rejected(Some(operation_id), binding, reason)
    }

    fn begin_revoke(
        &mut self,
        context: TaskLifecycleContext,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> ReapStep {
        let refuse =
            |reason| ReapStep::Answer(context.rejected(Some(operation_id), binding, reason));
        let stop_timeout = self
            .execution
            .as_ref()
            .map_or(Duration::ZERO, NodeExecution::stop_timeout);
        let task = match self.executing_task(context, binding) {
            Ok((task, _)) => task,
            Err(reason) => return refuse(reason),
        };
        if task.revoked_by == Some(operation_id) {
            return ReapStep::Answer(context.accepted(operation_id, binding, task.state));
        }
        if !matches!(task.state, State::Ready | State::Running | State::Paused) {
            return refuse(Reason::InvalidState);
        }
        let Some(admission) = self.admission.as_mut() else {
            return refuse(Reason::UnsupportedOperation);
        };
        if let Err(reason) = admission.revoke(binding.lease()) {
            return refuse(reason);
        }
        let journal = Journal(self.store.as_ref());
        let Some(task) = self.tasks.get_mut(&binding.task()) else {
            return refuse(Reason::TaskNotFound);
        };
        if live(task.state)
            && let Some(attempt) = task.end_attempt()
        {
            attempt.revoke_requested_by.get_or_insert(operation_id);
            return ReapStep::AwaitReap(Arc::clone(&attempt.reaped), stop_timeout);
        }
        match task.commit(journal, |task| {
            task.revoked_by = Some(operation_id);
            task.finish(State::Revoked, TaskExecutionOutcome::Failed);
        }) {
            Ok(()) => ReapStep::Answer(context.accepted(operation_id, binding, task.state)),
            Err(reason) => refuse(reason),
        }
    }

    fn finish_revoke(
        &mut self,
        context: TaskLifecycleContext,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> TaskLifecycleResponse {
        let journal = Journal(self.store.as_ref());
        let Some(task) = self
            .tasks
            .get_mut(&binding.task())
            .filter(|task| task.binding == binding)
        else {
            return context.rejected(Some(operation_id), binding, Reason::InvalidState);
        };
        if task.revoked_by == Some(operation_id) {
            return context.accepted(operation_id, binding, task.state);
        }
        let requested = task
            .attempt
            .as_ref()
            .is_some_and(|attempt| attempt.revoke_requested_by == Some(operation_id));
        if live(task.state) && requested {
            return match task.commit(journal, |task| {
                task.revoked_by = Some(operation_id);
                task.finish(State::Revoked, TaskExecutionOutcome::Unknown);
            }) {
                Ok(()) => context.accepted(operation_id, binding, task.state),
                Err(reason) => context.rejected(Some(operation_id), binding, reason),
            };
        }
        context.rejected(Some(operation_id), binding, Reason::InvalidState)
    }

    /// Record how a live attempt ended. The reaper has observed the end, so the in-memory
    /// state changes whether or not its record can be written; a record that cannot be
    /// written still reads as executing and recovers as `exited` with an `unknown` receipt.
    fn record_exit(&mut self, binding: TaskBinding, reaped: &Arc<Reaped>, exit: WorkloadExit) {
        let journal = Journal(self.store.as_ref());
        let Some(task) = self
            .tasks
            .get_mut(&binding.task())
            .filter(|task| task.binding == binding && live(task.state))
        else {
            return;
        };
        if task.finish_attempt(exit, reaped) {
            let _ = journal.write(&task.record());
        }
    }
}

impl Drop for TaskRegistry {
    fn drop(&mut self) {
        let Some(execution) = &self.execution else {
            return;
        };
        let timeout = execution.stop_timeout();
        let unreaped: Vec<Arc<Reaped>> = self
            .tasks
            .values()
            .filter_map(|task| task.attempt.as_ref())
            .chain(self.retired.iter())
            .filter(|attempt| !attempt.reaped.is_set())
            .map(|attempt| {
                attempt.stop.request();
                Arc::clone(&attempt.reaped)
            })
            .collect();
        for reaped in unreaped {
            reaped.wait(timeout);
        }
    }
}

/// A `start` that passed every check, ready to launch, or the replay of the one that did.
enum Prepared {
    Replay(TaskLifecycleState),
    Launch(LaunchRequest, Arc<dyn TaskLauncher>, Duration),
}

/// What an attempt's reaper thread needs to record how the attempt ended.
struct Reaper {
    registry: Weak<Mutex<TaskRegistry>>,
    binding: TaskBinding,
    stop: StopSignal,
    reaped: Arc<Reaped>,
}

impl Reaper {
    fn record(self, exit: WorkloadExit) {
        if let Some(registry) = self.registry.upgrade() {
            if let Ok(mut registry) = registry.lock() {
                registry.record_exit(self.binding, &self.reaped, exit);
            }
            self.reaped.set();
            drop(registry);
        } else {
            self.reaped.set();
        }
    }
}

/// The state a connection at `context` can represent: below 1.3 an exited task reads as
/// stopped, since its workload is gone either way.
const fn visible(context: TaskLifecycleContext, state: TaskLifecycleState) -> TaskLifecycleState {
    match state {
        TaskLifecycleState::Exited if !supports_task_admission(context.protocol()) => {
            TaskLifecycleState::Stopped
        }
        state => state,
    }
}

/// Whether a task in `state` has a workload its reaper still watches.
const fn live(state: TaskLifecycleState) -> bool {
    matches!(
        state,
        TaskLifecycleState::Running | TaskLifecycleState::Paused
    )
}

/// Whether a task in `state` is done executing, so a new attempt may replace it.
const fn finished(state: TaskLifecycleState) -> bool {
    matches!(
        state,
        TaskLifecycleState::Exited
            | TaskLifecycleState::Stopped
            | TaskLifecycleState::Revoked
            | TaskLifecycleState::Sealed
    )
}

/// The recorded result of replaying `operation_id` against the ids `applied` for one verb
/// (oldest first): the task's current state for the latest, `stale_operation` for one a
/// later operation of the verb superseded, and `None` for an id never applied.
fn replay(
    applied: &[OperationId],
    operation_id: OperationId,
    state: TaskLifecycleState,
) -> Option<Result<TaskLifecycleState, TaskLifecycleRejectionReason>> {
    let position = applied.iter().rposition(|id| *id == operation_id)?;
    Some(if position + 1 == applied.len() {
        Ok(state)
    } else {
        Err(TaskLifecycleRejectionReason::StaleOperation)
    })
}

impl NodeTask {
    const fn new(binding: TaskBinding, created_by: OperationId) -> Self {
        Self {
            binding,
            state: TaskLifecycleState::Created,
            created_by,
            admit: None,
            admitted: None,
            started_by: None,
            workspace: None,
            attempt: None,
            stopped_by: None,
            paused_by: Vec::new(),
            resumed_by: Vec::new(),
            revoked_by: None,
            sealed: None,
            receipt: None,
        }
    }

    /// The task a record describes, as a restarted node holds it, and whether that differs
    /// from the record. A `ready` task is `created` again and forgets its admission. An
    /// attempt that was launching, `running` or `paused` (a stop or revoke pending
    /// included) may have had effects: it is `exited` with an `unknown` receipt and never
    /// runs again. Any survivor of a recorded workload process is ended through
    /// `survivors` first. Every other task keeps its state, receipt and applied operations.
    fn recovered(record: TaskRecord, survivors: &dyn TaskLauncher) -> (Self, bool) {
        if let Some(process) = &record.process {
            survivors.end_survivor(process);
        }
        let mut task = Self {
            binding: record.binding,
            state: TaskLifecycleState::Created,
            created_by: record.created_by,
            admit: record.admitted,
            admitted: None,
            started_by: record.started_by,
            workspace: record.workspace,
            attempt: None,
            stopped_by: record.stopped_by,
            paused_by: record.paused_by,
            resumed_by: record.resumed_by,
            revoked_by: record.revoked_by,
            sealed: record.sealed,
            receipt: None,
        };
        let mut changed = record.process.is_some();
        match record.state {
            RecordedState::Created => {}
            RecordedState::Ready => {
                task.admit = None;
                changed = true;
            }
            RecordedState::Launching | RecordedState::Running | RecordedState::Paused => {
                task.finish(State::Exited, TaskExecutionOutcome::Unknown);
                changed = true;
            }
            RecordedState::Stopped => task.ended(State::Stopped, record.outcome),
            RecordedState::Exited => task.ended(State::Exited, record.outcome),
            RecordedState::Revoked => task.ended(State::Revoked, record.outcome),
            RecordedState::Sealed => task.ended(State::Sealed, record.outcome),
        }
        (task, changed)
    }

    /// This task's durable record.
    fn record(&self) -> TaskRecord {
        TaskRecord {
            format: RECORD_FORMAT,
            binding: self.binding,
            state: self.state.into(),
            created_by: self.created_by,
            admitted: self.admit.clone(),
            started_by: self.started_by,
            stopped_by: self.stopped_by,
            paused_by: self.paused_by.clone(),
            resumed_by: self.resumed_by.clone(),
            revoked_by: self.revoked_by,
            sealed: self.sealed,
            outcome: self.receipt.map(TaskExecutionReceipt::outcome),
            workspace: self.workspace.clone(),
            process: self
                .attempt
                .as_ref()
                .and_then(|attempt| attempt.process.clone()),
        }
    }

    /// The record of this `ready` task's launch intent: `operation_id` is starting it over
    /// `workspace`, and nothing is confirmed spawned yet.
    fn launching(&self, operation_id: OperationId, workspace: &Path) -> TaskRecord {
        TaskRecord {
            state: RecordedState::Launching,
            started_by: Some(operation_id),
            workspace: Some(workspace.to_path_buf()),
            ..self.record()
        }
    }

    /// Apply `change` once the changed task's record is durably written; on a failed write
    /// nothing changes.
    fn commit(
        &mut self,
        journal: Journal<'_>,
        change: impl FnOnce(&mut Self),
    ) -> Result<(), Reason> {
        let mut changed = self.clone();
        change(&mut changed);
        journal.write(&changed.record())?;
        *self = changed;
        Ok(())
    }

    /// The freezer of this task's live workload, unless its kill is pending.
    fn freezer(&self) -> Option<Arc<dyn WorkloadFreezer>> {
        self.attempt
            .as_ref()
            .filter(|attempt| !attempt.stop.is_requested())
            .and_then(|attempt| attempt.freezer.clone())
    }

    /// Record how this attempt's workload ended, as its reaper observed it; false if
    /// `reaped` belongs to another attempt.
    fn finish_attempt(&mut self, exit: WorkloadExit, reaped: &Arc<Reaped>) -> bool {
        let Some(attempt) = self
            .attempt
            .as_mut()
            .filter(|attempt| Arc::ptr_eq(&attempt.reaped, reaped))
        else {
            return false;
        };
        let stop_requested = attempt.stop.is_requested();
        let stop_requested_by = attempt.stop_requested_by;
        let revoke_requested_by = attempt.revoke_requested_by;
        if exit != WorkloadExit::Lost {
            attempt.process = None;
        }
        if let Some(revoked_by) = revoke_requested_by {
            let outcome = match exit {
                WorkloadExit::Lost => TaskExecutionOutcome::Unknown,
                WorkloadExit::Exited { code: Some(0) } => TaskExecutionOutcome::Completed,
                WorkloadExit::Stopped
                | WorkloadExit::BudgetExceeded
                | WorkloadExit::Exited { .. } => TaskExecutionOutcome::Failed,
            };
            self.revoked_by = Some(revoked_by);
            self.finish(State::Revoked, outcome);
            return true;
        }
        let (state, outcome) = match exit {
            WorkloadExit::Stopped => (TaskLifecycleState::Stopped, TaskExecutionOutcome::Failed),
            WorkloadExit::Lost if stop_requested => {
                (TaskLifecycleState::Stopped, TaskExecutionOutcome::Unknown)
            }
            WorkloadExit::Lost => (TaskLifecycleState::Exited, TaskExecutionOutcome::Unknown),
            WorkloadExit::Exited { code: Some(0) } => {
                (TaskLifecycleState::Exited, TaskExecutionOutcome::Completed)
            }
            WorkloadExit::BudgetExceeded | WorkloadExit::Exited { .. } => {
                (TaskLifecycleState::Exited, TaskExecutionOutcome::Failed)
            }
        };
        if state == TaskLifecycleState::Stopped {
            self.stopped_by = stop_requested_by;
        }
        self.finish(state, outcome);
        true
    }

    fn matches(&self, binding: TaskBinding) -> Result<(), TaskLifecycleRejectionReason> {
        if self.binding.attempt() != binding.attempt() {
            return Err(TaskLifecycleRejectionReason::AttemptMismatch);
        }
        if self.binding.lease() != binding.lease() {
            return Err(TaskLifecycleRejectionReason::LeaseMismatch);
        }
        Ok(())
    }

    /// Ask the reaper to kill and reap the live workload, continuing a paused tree first so
    /// nothing the kill misses is left stopped. `SIGKILL` ends a stopped process anyway, so
    /// a thaw that cannot be confirmed does not hold the kill back. A paused task reads
    /// `Running` from here on: its tree has been continued and is being killed, and while
    /// the kill is pending neither `pause` nor `resume` is accepted.
    fn end_attempt(&mut self) -> Option<&mut Attempt> {
        let attempt = self.attempt.as_mut()?;
        attempt.stop.request();
        if self.state == TaskLifecycleState::Paused {
            if let Some(freezer) = &attempt.freezer {
                let _ = freezer.thaw();
            }
            self.state = TaskLifecycleState::Running;
        }
        Some(attempt)
    }

    fn finish(&mut self, state: TaskLifecycleState, outcome: TaskExecutionOutcome) {
        self.ended(state, Some(outcome));
    }

    fn ended(&mut self, state: TaskLifecycleState, outcome: Option<TaskExecutionOutcome>) {
        self.state = state;
        self.receipt = outcome.and_then(|outcome| {
            self.admit
                .as_ref()
                .map(|admit| TaskReceiptContext::new(self.binding, admit.session).receipt(outcome))
        });
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use ward_events::{ExecutionAttemptId, LeaseId, TaskId};
    use ward_node_protocol::{ProtocolVersion, TaskLifecycleRejectionReason as Reason};

    use super::*;

    fn context() -> TaskLifecycleContext {
        TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap()
    }

    fn binding(task: u128, attempt: u128, lease: u128) -> TaskBinding {
        TaskBinding::new(
            TaskId::from_u128(task),
            ExecutionAttemptId::from_u128(attempt),
            LeaseId::from_u128(lease),
        )
    }

    fn op(value: u64) -> OperationId {
        OperationId::new(value).unwrap()
    }

    #[test]
    fn create_registers_a_created_task_that_inspect_reports() {
        let ctx = context();
        let mut registry = TaskRegistry::default();
        let task = binding(1, 2, 3);

        assert_eq!(
            registry.handle(ctx, ctx.create(op(10), task)),
            ctx.accepted(op(10), task, TaskLifecycleState::Created)
        );
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.handle(ctx, ctx.inspect(task)),
            ctx.inspected(task, TaskLifecycleState::Created)
        );
    }

    #[test]
    fn inspect_of_an_unknown_task_is_task_not_found() {
        let ctx = context();
        let mut registry = TaskRegistry::default();
        let task = binding(1, 2, 3);

        assert_eq!(
            registry.handle(ctx, ctx.inspect(task)),
            ctx.rejected(None, task, Reason::TaskNotFound)
        );
        assert!(registry.is_empty());
    }

    #[test]
    fn replaying_the_same_create_is_idempotent() {
        let ctx = context();
        let mut registry = TaskRegistry::default();
        let task = binding(1, 2, 3);

        let first = registry.handle(ctx, ctx.create(op(10), task));
        let replay = registry.handle(ctx, ctx.create(op(10), task));
        assert_eq!(first, replay);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn a_second_create_under_a_different_operation_is_invalid_state() {
        let ctx = context();
        let mut registry = TaskRegistry::default();
        let task = binding(1, 2, 3);

        registry.handle(ctx, ctx.create(op(10), task));
        assert_eq!(
            registry.handle(ctx, ctx.create(op(11), task)),
            ctx.rejected(Some(op(11)), task, Reason::InvalidState)
        );
    }

    #[test]
    fn create_and_inspect_reject_a_mismatched_attempt_or_lease() {
        let ctx = context();
        let mut registry = TaskRegistry::default();
        let task = binding(1, 2, 3);
        registry.handle(ctx, ctx.create(op(10), task));

        let other_attempt = binding(1, 99, 3);
        let other_lease = binding(1, 2, 99);

        assert_eq!(
            registry.handle(ctx, ctx.create(op(10), other_attempt)),
            ctx.rejected(Some(op(10)), other_attempt, Reason::AttemptMismatch)
        );
        assert_eq!(
            registry.handle(ctx, ctx.create(op(10), other_lease)),
            ctx.rejected(Some(op(10)), other_lease, Reason::LeaseMismatch)
        );
        assert_eq!(
            registry.handle(ctx, ctx.inspect(other_attempt)),
            ctx.rejected(None, other_attempt, Reason::AttemptMismatch)
        );
        assert_eq!(
            registry.handle(ctx, ctx.inspect(other_lease)),
            ctx.rejected(None, other_lease, Reason::LeaseMismatch)
        );
        assert_eq!(
            registry.handle(ctx, ctx.inspect(task)),
            ctx.inspected(task, TaskLifecycleState::Created)
        );
    }

    #[test]
    fn unimplemented_verbs_are_refused_and_never_change_state() {
        let ctx = context();
        let mut registry = TaskRegistry::default();
        let task = binding(1, 2, 3);
        registry.handle(ctx, ctx.create(op(10), task));

        for (request, operation_id) in [
            (ctx.start(op(11), task), Some(op(11))),
            (ctx.pause(op(12), task), Some(op(12))),
            (ctx.resume(op(13), task), Some(op(13))),
            (ctx.stop(op(14), task), Some(op(14))),
            (ctx.revoke(op(15), task), Some(op(15))),
            (ctx.seal(op(16), task), Some(op(16))),
            (ctx.stream(task, 0), None),
        ] {
            assert_eq!(
                registry.handle(ctx, request.clone()),
                ctx.rejected(operation_id, task, Reason::UnsupportedOperation),
                "{request:?} must be refused, not reported as applied"
            );
            assert_eq!(
                registry.handle(ctx, ctx.inspect(task)),
                ctx.inspected(task, TaskLifecycleState::Created)
            );
        }
    }

    #[test]
    fn admit_is_refused_as_unsupported_and_never_changes_state() {
        let ctx = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let mut registry = TaskRegistry::default();
        let task = binding(1, 2, 3);
        let unknown = binding(4, 5, 6);

        assert_eq!(
            registry.handle(ctx, crate::test_support::admit(ctx, op(9), unknown)),
            ctx.rejected(Some(op(9)), unknown, Reason::UnsupportedOperation)
        );
        assert!(registry.is_empty());

        registry.handle(ctx, ctx.create(op(10), task));
        for operation in [op(11), op(10)] {
            assert_eq!(
                registry.handle(ctx, crate::test_support::admit(ctx, operation, task)),
                ctx.rejected(Some(operation), task, Reason::UnsupportedOperation)
            );
            assert_eq!(
                registry.handle(ctx, ctx.inspect(task)),
                ctx.inspected(task, TaskLifecycleState::Created)
            );
        }
        assert_eq!(registry.len(), 1);
    }

    mod admit {
        #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

        use std::path::PathBuf;

        use ward_authority::revocation::{AuthorityRevocation, RevocationReason};
        use ward_authority::{
            AuthorityLease, DelegationInput, EmptyAuthorityPolicy, LeaseVersion,
            UntrustedAuthorityLease,
        };
        use ward_events::{AgentId, DelegationId, ExecutionAttemptId, LeaseId, NodeId, TaskId};
        use ward_node_protocol::{
            AdmissionEnvelopeJson, AdmissionVersion, IssuerProof, IssuerSignature, OperationId,
            ProtocolVersion, TaskAdmissionAuthority, TaskAdmissionEnvelope,
            TaskAdmissionEnvelopeInput, TaskBinding, TaskLifecycleContext,
            TaskLifecycleRejectionReason as Reason, TaskLifecycleRequest, TaskLifecycleState,
        };

        use crate::admit::NodeAdmission;
        use crate::issuer::TrustedIssuers;
        use crate::state::NodeState;
        use crate::task::{MAX_NODE_TASKS, TaskRegistry};
        use crate::test_support::{
            FixedClock, NODE, NOW, envelope_input, issuer_keypair, lifecycle_binding,
            node_admission, other_keypair, root_lease, sign, signed_admit,
        };

        struct Node {
            _dir: tempfile::TempDir,
            state_dir: PathBuf,
            clock: FixedClock,
            registry: TaskRegistry,
        }

        impl Node {
            fn new() -> Self {
                let dir = tempfile::tempdir().unwrap();
                let state_dir = dir.path().join("state");
                let clock = FixedClock::at(NOW);
                let registry = TaskRegistry::with_admission(
                    MAX_NODE_TASKS,
                    node_admission(&state_dir, &clock),
                )
                .unwrap();
                Self {
                    _dir: dir,
                    state_dir,
                    clock,
                    registry,
                }
            }

            fn restart(self) -> Self {
                let Self {
                    _dir: dir,
                    state_dir,
                    clock,
                    registry,
                } = self;
                drop(registry);
                let registry = TaskRegistry::with_admission(
                    MAX_NODE_TASKS,
                    node_admission(&state_dir, &clock),
                )
                .unwrap();
                Self {
                    _dir: dir,
                    state_dir,
                    clock,
                    registry,
                }
            }

            fn create(&mut self, binding: TaskBinding) {
                assert_eq!(
                    self.registry.handle(ctx(), ctx().create(op(10), binding)),
                    ctx().accepted(op(10), binding, TaskLifecycleState::Created)
                );
            }

            fn state(&self) -> &NodeState {
                self.registry.admission().unwrap().state()
            }

            fn revoke(&mut self, lease: LeaseId, at: u64) {
                self.registry
                    .admission_mut()
                    .unwrap()
                    .state_mut()
                    .record_revocation(AuthorityRevocation::new(
                        lease,
                        at,
                        RevocationReason::Operator,
                    ))
                    .unwrap();
            }

            #[track_caller]
            fn assert_refused(&mut self, request: TaskLifecycleRequest, reason: Reason) {
                let TaskLifecycleRequest::Admit {
                    operation_id,
                    binding,
                    ..
                } = request.clone()
                else {
                    panic!("not an admit request");
                };
                let recorded = self.state().last_admitted_version(binding.task());
                assert_eq!(
                    self.registry.handle(ctx(), request),
                    ctx().rejected(Some(operation_id), binding, reason)
                );
                self.assert_untouched(lifecycle_binding());
                assert_eq!(
                    self.state().last_admitted_version(binding.task()),
                    recorded,
                    "a refused admit must not change the durable version"
                );
            }

            #[track_caller]
            fn assert_untouched(&mut self, binding: TaskBinding) {
                assert_eq!(
                    self.registry.handle(ctx(), ctx().inspect(binding)),
                    ctx().inspected(binding, TaskLifecycleState::Created),
                    "a refused admit must leave the task created"
                );
                assert!(self.registry.admitted(binding).is_none());
            }
        }

        fn ctx() -> TaskLifecycleContext {
            TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
        }

        fn op(value: u64) -> OperationId {
            OperationId::new(value).unwrap()
        }

        fn envelope(change: impl FnOnce(&mut TaskAdmissionEnvelopeInput)) -> TaskAdmissionEnvelope {
            let mut input = envelope_input(lifecycle_binding());
            change(&mut input);
            TaskAdmissionEnvelope::new(input).unwrap()
        }

        fn admit(envelope: &TaskAdmissionEnvelope) -> TaskLifecycleRequest {
            signed_admit(ctx(), op(20), lifecycle_binding(), envelope)
        }

        fn raw_admit(json: &str, proof: IssuerProof) -> TaskLifecycleRequest {
            ctx()
                .admit(
                    op(20),
                    lifecycle_binding(),
                    AdmissionEnvelopeJson::new(json.to_owned()).unwrap(),
                    proof,
                )
                .unwrap()
        }

        fn authority(
            lease: &AuthorityLease,
            lineage: &[&AuthorityLease],
        ) -> TaskAdmissionAuthority {
            TaskAdmissionAuthority::new(
                UntrustedAuthorityLease::from(lease),
                lineage
                    .iter()
                    .map(|lease| UntrustedAuthorityLease::from(*lease))
                    .collect(),
            )
            .unwrap()
        }

        fn delegated() -> (AuthorityLease, AuthorityLease) {
            let binding = lifecycle_binding();
            let parent = root_lease(
                TaskBinding::new(binding.task(), binding.attempt(), LeaseId::from_u128(20)),
                1_000,
                9_000,
            );
            let child = parent
                .delegate(
                    DelegationInput {
                        id: binding.lease(),
                        delegation_id: DelegationId::from_u128(22),
                        subject: AgentId::from_u128(3),
                        task: binding.task(),
                        grants: parent.grants().clone(),
                        issued_at_unix_ms: 1_500,
                        expires_at_unix_ms: 8_500,
                        version: LeaseVersion::new(2).unwrap(),
                    },
                    2_000,
                    EmptyAuthorityPolicy::Reject,
                )
                .unwrap();
            (parent, child)
        }

        #[test]
        fn admit_moves_a_created_task_to_ready_and_keeps_the_envelope() {
            let mut node = Node::new();
            let binding = lifecycle_binding();
            node.create(binding);
            let envelope = envelope(|_| {});

            assert_eq!(
                node.registry.handle(ctx(), admit(&envelope)),
                ctx().accepted(op(20), binding, TaskLifecycleState::Ready)
            );
            assert_eq!(
                node.registry.handle(ctx(), ctx().inspect(binding)),
                ctx().inspected(binding, TaskLifecycleState::Ready)
            );
            let admitted = node.registry.admitted(binding).unwrap();
            assert_eq!(admitted.operation_id(), op(20));
            assert_eq!(admitted.envelope(), &envelope);
            assert_eq!(
                admitted.envelope_json(),
                &AdmissionEnvelopeJson::encode(&envelope).unwrap()
            );
            assert_eq!(admitted.authority().identity().binding(), binding);
            assert_eq!(admitted.authority().identity().node(), NODE);
            assert_eq!(
                admitted.authority().identity().agent(),
                AgentId::from_u128(3)
            );
            assert_eq!(
                node.state().last_admitted_version(binding.task()),
                Some(AdmissionVersion::new(1).unwrap())
            );
        }

        #[test]
        fn replaying_the_same_admit_is_idempotent_and_any_other_admit_is_invalid_state() {
            let mut node = Node::new();
            let binding = lifecycle_binding();
            node.create(binding);
            let first = admit(&envelope(|_| {}));
            let accepted = node.registry.handle(ctx(), first.clone());
            assert_eq!(
                accepted,
                ctx().accepted(op(20), binding, TaskLifecycleState::Ready)
            );

            node.clock.set(8_500);
            assert_eq!(node.registry.handle(ctx(), first), accepted);

            node.clock.set(NOW);
            let newer = envelope(|input| input.version = AdmissionVersion::new(2).unwrap());
            for request in [
                signed_admit(ctx(), op(21), binding, &envelope(|_| {})),
                signed_admit(ctx(), op(20), binding, &newer),
                signed_admit(ctx(), op(21), binding, &newer),
            ] {
                let TaskLifecycleRequest::Admit { operation_id, .. } = request else {
                    panic!("admit");
                };
                assert_eq!(
                    node.registry.handle(ctx(), request),
                    ctx().rejected(Some(operation_id), binding, Reason::InvalidState)
                );
            }
            assert_eq!(
                node.registry.admitted(binding).unwrap().operation_id(),
                op(20)
            );
            assert_eq!(
                node.state().last_admitted_version(binding.task()),
                Some(AdmissionVersion::new(1).unwrap())
            );
        }

        #[test]
        fn admit_needs_an_existing_created_task_with_the_exact_binding() {
            let mut node = Node::new();
            let binding = lifecycle_binding();
            let envelope = envelope(|_| {});

            assert_eq!(
                node.registry.handle(ctx(), admit(&envelope)),
                ctx().rejected(Some(op(20)), binding, Reason::TaskNotFound)
            );
            assert!(node.registry.is_empty());
            assert_eq!(node.state().last_admitted_version(binding.task()), None);

            node.create(binding);
            for (other, reason) in [
                (
                    TaskBinding::new(
                        binding.task(),
                        ExecutionAttemptId::from_u128(99),
                        binding.lease(),
                    ),
                    Reason::AttemptMismatch,
                ),
                (
                    TaskBinding::new(binding.task(), binding.attempt(), LeaseId::from_u128(99)),
                    Reason::LeaseMismatch,
                ),
            ] {
                let request = signed_admit(ctx(), op(20), other, &envelope);
                assert_eq!(
                    node.registry.handle(ctx(), request),
                    ctx().rejected(Some(op(20)), other, reason)
                );
                node.assert_untouched(binding);
                assert_eq!(node.state().last_admitted_version(binding.task()), None);
            }
        }

        #[test]
        fn no_trusted_issuer_means_every_admit_is_authority_denied() {
            let dir = tempfile::tempdir().unwrap();
            let clock = FixedClock::at(NOW);
            let mut registry = TaskRegistry::with_admission(
                MAX_NODE_TASKS,
                NodeAdmission::new(
                    TrustedIssuers::empty(),
                    NodeState::open(&dir.path().join("state"), NODE).unwrap(),
                    Box::new(clock),
                ),
            )
            .unwrap();
            let binding = lifecycle_binding();
            registry.handle(ctx(), ctx().create(op(10), binding));

            assert_eq!(
                registry.handle(ctx(), admit(&envelope(|_| {}))),
                ctx().rejected(Some(op(20)), binding, Reason::AuthorityDenied)
            );
            assert_eq!(
                registry.handle(ctx(), ctx().inspect(binding)),
                ctx().inspected(binding, TaskLifecycleState::Created)
            );
        }

        #[test]
        fn an_untrusted_or_forged_issuer_proof_is_authority_denied() {
            let mut node = Node::new();
            node.create(lifecycle_binding());
            let json = AdmissionEnvelopeJson::encode(&envelope(|_| {})).unwrap();
            let trusted = sign(&json, &issuer_keypair());
            let untrusted = sign(&json, &other_keypair());
            let forged = IssuerProof::new(trusted.issuer_key_id(), untrusted.signature());
            let zeroed = IssuerProof::new(
                trusted.issuer_key_id(),
                IssuerSignature::from_bytes([0; 64]),
            );

            for proof in [untrusted, forged, zeroed] {
                let request = ctx()
                    .admit(op(20), lifecycle_binding(), json.clone(), proof)
                    .unwrap();
                node.assert_refused(request, Reason::AuthorityDenied);
            }
        }

        #[test]
        fn the_signature_must_cover_exactly_the_envelope_bytes() {
            let mut node = Node::new();
            node.create(lifecycle_binding());
            let json = AdmissionEnvelopeJson::encode(&envelope(|_| {})).unwrap();
            let proof = sign(&json, &issuer_keypair());
            let text = std::str::from_utf8(json.as_bytes()).unwrap();

            for altered in [
                format!("{text} "),
                format!(" {text}"),
                text.replacen(r#""version":1"#, r#""version": 1"#, 1),
                text.replacen(r#""version":1"#, r#""version":2"#, 1),
            ] {
                assert_ne!(altered, text);
                node.assert_refused(raw_admit(&altered, proof), Reason::AuthorityDenied);
            }
        }

        #[test]
        fn the_signature_is_checked_before_the_envelope_is_decoded_or_judged() {
            let mut node = Node::new();
            node.create(lifecycle_binding());

            let signed_garbage = AdmissionEnvelopeJson::new("{not an envelope".to_owned()).unwrap();
            let proof = sign(&signed_garbage, &issuer_keypair());
            node.assert_refused(
                raw_admit("{not an envelope", proof),
                Reason::AuthorityDenied,
            );

            let mut unknown_field: serde_json::Value = serde_json::from_slice(
                AdmissionEnvelopeJson::encode(&envelope(|_| {}))
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
            unknown_field["extra"] = serde_json::json!(true);
            let unknown_field = serde_json::to_string(&unknown_field).unwrap();
            let proof = sign(
                &AdmissionEnvelopeJson::new(unknown_field.clone()).unwrap(),
                &issuer_keypair(),
            );
            node.assert_refused(raw_admit(&unknown_field, proof), Reason::AuthorityDenied);

            for envelope in [
                envelope(|input| input.expires_at_unix_ms = 3_000),
                envelope(|input| {
                    input.binding = TaskBinding::new(
                        input.binding.task(),
                        ExecutionAttemptId::from_u128(99),
                        input.binding.lease(),
                    );
                }),
            ] {
                let json = AdmissionEnvelopeJson::encode(&envelope).unwrap();
                let request = ctx()
                    .admit(
                        op(20),
                        lifecycle_binding(),
                        json.clone(),
                        sign(&json, &other_keypair()),
                    )
                    .unwrap();
                node.assert_refused(request, Reason::AuthorityDenied);
            }
        }

        #[test]
        fn the_decoded_binding_must_equal_the_request_binding() {
            let mut node = Node::new();
            let binding = lifecycle_binding();
            node.create(binding);

            for (decoded, reason) in [
                (
                    TaskBinding::new(
                        binding.task(),
                        ExecutionAttemptId::from_u128(99),
                        binding.lease(),
                    ),
                    Reason::AttemptMismatch,
                ),
                (
                    TaskBinding::new(binding.task(), binding.attempt(), LeaseId::from_u128(99)),
                    Reason::LeaseMismatch,
                ),
                (
                    TaskBinding::new(TaskId::from_u128(99), binding.attempt(), binding.lease()),
                    Reason::AuthorityDenied,
                ),
            ] {
                node.assert_refused(admit(&envelope(|input| input.binding = decoded)), reason);
            }
        }

        #[test]
        fn the_envelope_must_be_addressed_to_this_node() {
            let mut node = Node::new();
            node.create(lifecycle_binding());
            node.assert_refused(
                admit(&envelope(|input| input.node = NodeId::from_u128(99))),
                Reason::AuthorityDenied,
            );
        }

        #[test]
        fn the_envelope_must_be_current_at_the_node_clock() {
            let mut node = Node::new();
            let binding = lifecycle_binding();
            node.create(binding);
            let envelope = envelope(|_| {});

            node.clock.set(1_999);
            node.assert_refused(admit(&envelope), Reason::AuthorityDenied);
            for expired in [8_000, 8_001, u64::MAX] {
                node.clock.set(expired);
                node.assert_refused(admit(&envelope), Reason::LeaseExpired);
            }

            node.clock.set(2_000);
            assert_eq!(
                node.registry.handle(ctx(), admit(&envelope)),
                ctx().accepted(op(20), binding, TaskLifecycleState::Ready)
            );
        }

        #[test]
        fn an_expired_or_not_yet_valid_lease_is_refused() {
            let mut node = Node::new();
            node.create(lifecycle_binding());
            let short = root_lease(lifecycle_binding(), 1_000, 4_000);
            node.assert_refused(
                admit(&envelope(|input| input.authority = authority(&short, &[]))),
                Reason::LeaseExpired,
            );

            let future = root_lease(lifecycle_binding(), 6_000, 9_000);
            node.assert_refused(
                admit(&envelope(|input| input.authority = authority(&future, &[]))),
                Reason::AuthorityDenied,
            );
        }

        #[test]
        fn stale_versions_are_refused_across_a_restart() {
            let mut node = Node::new();
            let binding = lifecycle_binding();
            node.create(binding);
            let second = envelope(|input| input.version = AdmissionVersion::new(2).unwrap());
            assert_eq!(
                node.registry.handle(ctx(), admit(&second)),
                ctx().accepted(op(20), binding, TaskLifecycleState::Ready)
            );

            let mut node = node.restart();
            node.assert_untouched(binding);
            node.create(binding);
            for version in [1, 2] {
                node.assert_refused(
                    admit(&envelope(|input| {
                        input.version = AdmissionVersion::new(version).unwrap();
                    })),
                    Reason::StaleOperation,
                );
            }
            assert_eq!(
                node.state().last_admitted_version(binding.task()),
                Some(AdmissionVersion::new(2).unwrap())
            );

            let third = envelope(|input| input.version = AdmissionVersion::new(3).unwrap());
            assert_eq!(
                node.registry.handle(ctx(), admit(&third)),
                ctx().accepted(op(20), binding, TaskLifecycleState::Ready)
            );
        }

        #[test]
        fn the_lease_must_cover_the_binding_and_the_agent() {
            let mut node = Node::new();
            let binding = lifecycle_binding();
            node.create(binding);

            let other_lease = root_lease(
                TaskBinding::new(binding.task(), binding.attempt(), LeaseId::from_u128(99)),
                1_000,
                9_000,
            );
            let other_task = root_lease(
                TaskBinding::new(TaskId::from_u128(99), binding.attempt(), binding.lease()),
                1_000,
                9_000,
            );
            for (envelope, reason) in [
                (
                    envelope(|input| input.agent = AgentId::from_u128(99)),
                    Reason::AuthorityDenied,
                ),
                (
                    envelope(|input| input.authority = authority(&other_task, &[])),
                    Reason::AuthorityDenied,
                ),
                (
                    envelope(|input| input.authority = authority(&other_lease, &[])),
                    Reason::LeaseMismatch,
                ),
            ] {
                node.assert_refused(admit(&envelope), reason);
            }
        }

        #[test]
        fn a_delegated_lease_needs_its_complete_lineage() {
            let mut node = Node::new();
            let binding = lifecycle_binding();
            node.create(binding);
            let (parent, child) = delegated();

            node.assert_refused(
                admit(&envelope(|input| input.authority = authority(&child, &[]))),
                Reason::AuthorityDenied,
            );
            node.assert_refused(
                admit(&envelope(|input| {
                    input.authority = authority(&parent, &[&parent]);
                })),
                Reason::AuthorityDenied,
            );

            assert_eq!(
                node.registry.handle(
                    ctx(),
                    admit(&envelope(
                        |input| input.authority = authority(&child, &[&parent])
                    ))
                ),
                ctx().accepted(op(20), binding, TaskLifecycleState::Ready)
            );
        }

        #[test]
        fn a_durably_revoked_lease_or_ancestor_is_lease_revoked_after_restart() {
            let mut node = Node::new();
            let binding = lifecycle_binding();
            node.create(binding);
            node.revoke(binding.lease(), 3_000);
            node.assert_refused(admit(&envelope(|_| {})), Reason::LeaseRevoked);

            let mut node = node.restart();
            node.create(binding);
            node.assert_refused(admit(&envelope(|_| {})), Reason::LeaseRevoked);

            let mut node = Node::new();
            node.create(binding);
            let (parent, child) = delegated();
            node.revoke(parent.id(), 3_000);
            let mut node = node.restart();
            node.create(binding);
            node.assert_refused(
                admit(&envelope(|input| {
                    input.authority = authority(&child, &[&parent]);
                })),
                Reason::LeaseRevoked,
            );
        }

        #[test]
        fn a_ready_task_recovers_as_created_and_is_admitted_again_only_with_a_higher_version() {
            let mut node = Node::new();
            let binding = lifecycle_binding();
            node.create(binding);
            let first = admit(&envelope(|_| {}));
            assert_eq!(
                node.registry.handle(ctx(), first.clone()),
                ctx().accepted(op(20), binding, TaskLifecycleState::Ready)
            );

            let mut node = node.restart();
            node.assert_untouched(binding);
            node.create(binding);
            node.assert_refused(first, Reason::StaleOperation);
            let second = envelope(|input| input.version = AdmissionVersion::new(2).unwrap());
            assert_eq!(
                node.registry.handle(ctx(), admit(&second)),
                ctx().accepted(op(20), binding, TaskLifecycleState::Ready)
            );
        }

        #[test]
        fn a_created_task_survives_a_restart_and_its_create_replays() {
            let mut node = Node::new();
            let binding = lifecycle_binding();
            node.create(binding);
            let mut node = node.restart();
            assert_eq!(node.registry.len(), 1);
            node.assert_untouched(binding);
            node.create(binding);
            assert_eq!(
                node.registry.handle(ctx(), ctx().create(op(11), binding)),
                ctx().rejected(Some(op(11)), binding, Reason::InvalidState)
            );
        }

        #[test]
        fn a_malformed_task_record_fails_the_registry_closed() {
            let mut node = Node::new();
            node.create(lifecycle_binding());
            let record = node
                .state_dir
                .join(crate::records::TASKS_DIR)
                .join(format!("{}.json", lifecycle_binding().task()));
            std::fs::write(&record, b"{not json").unwrap();
            assert!(matches!(
                TaskRegistry::with_admission(
                    MAX_NODE_TASKS,
                    node_admission(&node.state_dir, &node.clock)
                ),
                Err(crate::records::TaskRecordError::InvalidRecord(_))
            ));
        }

        #[test]
        fn a_failed_durable_version_write_refuses_and_leaves_the_task_created() {
            let mut node = Node::new();
            node.create(lifecycle_binding());
            std::fs::create_dir_all(
                node.state_dir
                    .join(crate::state::ADMISSION_VERSIONS_FILE)
                    .join("blocker"),
            )
            .unwrap();
            node.assert_refused(admit(&envelope(|_| {})), Reason::ResourceUnavailable);
        }
    }

    mod execution {
        #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        use ward_authority::revocation::{AuthorityRevocation, RevocationReason};
        use ward_events::{ExecutionAttemptId, SessionId, SnapshotId};
        use ward_node_protocol::{
            OperationId, ProtocolVersion, TaskAdmissionEnvelope, TaskBinding,
            TaskExecutionOutcome as Outcome, TaskLifecycleContext,
            TaskLifecycleRejectionReason as Reason, TaskLifecycleRequest, TaskLifecycleResponse,
            TaskLifecycleState as State, TaskReceiptContext, WorkloadArgv,
        };

        use crate::execution::{NodeExecution, WorkloadExit};
        use crate::task::{MAX_ATTEMPT_PAUSES, MAX_NODE_TASKS, TaskRegistry};
        use crate::test_support::{
            FAKE_PID, FakeFreeze, FakeLauncher, FakeSpawn, FakeStop, FixedClock, NOW,
            envelope_input, eventually, fake_process, fill_revocations, lifecycle_binding,
            node_admission, signed_admit,
        };
        use crate::workspace::{TaskRoot, import_snapshot, open_snapshot_store};

        struct Node {
            _dir: tempfile::TempDir,
            root: PathBuf,
            clock: FixedClock,
            launcher: FakeLauncher,
            tasks: Arc<Mutex<TaskRegistry>>,
            snapshot: SnapshotId,
        }

        impl Node {
            fn new() -> Self {
                Self::with_stop_timeout(Duration::from_secs(10))
            }

            fn with_stop_timeout(stop_timeout: Duration) -> Self {
                Self::build(tempfile::tempdir().unwrap(), MAX_NODE_TASKS, stop_timeout)
            }

            fn with_capacity(capacity: usize) -> Self {
                Self::build(
                    tempfile::tempdir().unwrap(),
                    capacity,
                    Duration::from_secs(10),
                )
            }

            fn build(dir: tempfile::TempDir, capacity: usize, stop_timeout: Duration) -> Self {
                let state = dir.path().join("state");
                let clock = FixedClock::at(NOW);
                let admission = node_admission(&state, &clock);
                let project = dir.path().join("project");
                std::fs::create_dir_all(&project).unwrap();
                std::fs::write(project.join("hello.txt"), b"hello").unwrap();
                let snapshots = open_snapshot_store(&state).unwrap();
                let snapshot = import_snapshot(&snapshots, &project).unwrap();
                let root = dir.path().join("tasks");
                let launcher = FakeLauncher::new();
                let execution = NodeExecution::new(
                    TaskRoot::open(&root).unwrap(),
                    snapshots,
                    Arc::new(launcher.clone()),
                )
                .with_stop_timeout(stop_timeout);
                let tasks = Arc::new(Mutex::new(
                    TaskRegistry::with_execution(capacity, admission, execution).unwrap(),
                ));
                Self {
                    _dir: dir,
                    root,
                    clock,
                    launcher,
                    tasks,
                    snapshot,
                }
            }

            /// Drop the registry, as a node restart does, and serve again over the same
            /// state directory and task root.
            fn restart(self) -> Self {
                let Self {
                    _dir: dir, tasks, ..
                } = self;
                drop(tasks);
                Self::build(dir, MAX_NODE_TASKS, Duration::from_secs(10))
            }

            fn serve(&self, request: TaskLifecycleRequest) -> TaskLifecycleResponse {
                TaskRegistry::serve(&self.tasks, ctx(), request).unwrap()
            }

            fn envelope(&self) -> TaskAdmissionEnvelope {
                let mut input = envelope_input(lifecycle_binding());
                input.workload = ward_node_protocol::TaskWorkload::new(
                    WorkloadArgv::new(vec![
                        "sh".to_owned(),
                        "-c".to_owned(),
                        "echo ok > out.txt".to_owned(),
                    ])
                    .unwrap(),
                    input.workload.capability_manifest().clone(),
                    self.snapshot,
                    45_000,
                )
                .unwrap();
                TaskAdmissionEnvelope::new(input).unwrap()
            }

            fn ready(&self) {
                self.ready_with(&self.envelope());
            }

            fn ready_with(&self, envelope: &TaskAdmissionEnvelope) {
                let binding = lifecycle_binding();
                assert_eq!(
                    self.serve(ctx().create(op(10), binding)),
                    ctx().accepted(op(10), binding, State::Created)
                );
                assert_eq!(
                    self.serve(signed_admit(ctx(), op(20), binding, envelope)),
                    ctx().accepted(op(20), binding, State::Ready)
                );
            }

            fn running(&self) {
                self.ready();
                assert_eq!(
                    self.serve(ctx().start(op(30), lifecycle_binding())),
                    ctx().accepted(op(30), lifecycle_binding(), State::Running)
                );
            }

            fn state(&self) -> State {
                match self.serve(ctx().inspect(lifecycle_binding())) {
                    TaskLifecycleResponse::Inspected { state, .. } => state,
                    other => panic!("inspect failed: {other:?}"),
                }
            }

            fn wait_for(&self, state: State) {
                eventually(|| self.state() == state);
            }

            fn workspace(&self) -> PathBuf {
                let binding = lifecycle_binding();
                self.root
                    .join(binding.task().to_string())
                    .join(binding.attempt().to_string())
            }

            #[track_caller]
            fn assert_finished(&self, state: State, outcome: Outcome) {
                let binding = lifecycle_binding();
                assert_eq!(
                    self.serve(ctx().inspect(binding)),
                    ctx()
                        .inspected_with_outcome(binding, state, outcome)
                        .unwrap()
                );
                let receipt = self.tasks.lock().unwrap().receipt(binding).unwrap();
                assert_eq!(
                    receipt,
                    TaskReceiptContext::new(binding, SessionId::from_u128(5)).receipt(outcome)
                );
                assert_eq!(self.tasks.lock().unwrap().running_pid(binding), None);
            }
        }

        fn ctx() -> TaskLifecycleContext {
            TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
        }

        fn op(value: u64) -> OperationId {
            OperationId::new(value).unwrap()
        }

        fn mode(path: &std::path::Path) -> u32 {
            std::fs::symlink_metadata(path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        }

        #[test]
        fn start_runs_the_admitted_workload_in_a_node_allocated_workspace() {
            let node = Node::new();
            node.running();
            let binding = lifecycle_binding();

            let launches = node.launcher.launches();
            assert_eq!(launches.len(), 1);
            assert_eq!(launches[0].workspace(), node.workspace());
            assert_eq!(launches[0].argv(), node.envelope().workload().argv().args());
            assert_eq!(launches[0].budget(), Duration::from_millis(45_000));
            assert_eq!(
                std::fs::read(node.workspace().join("hello.txt")).unwrap(),
                b"hello"
            );
            assert_eq!(mode(&node.workspace()), 0o700);
            assert_eq!(mode(node.workspace().parent().unwrap()), 0o700);
            assert_eq!(
                node.tasks.lock().unwrap().running_pid(binding),
                Some(FAKE_PID)
            );
            assert_eq!(
                node.serve(ctx().inspect(binding)),
                ctx().inspected(binding, State::Running)
            );
            assert!(node.tasks.lock().unwrap().receipt(binding).is_none());
            eventually(|| node.launcher.waiting() == 1);
        }

        #[test]
        fn replaying_start_is_idempotent_and_never_launches_twice() {
            let node = Node::new();
            node.running();
            let binding = lifecycle_binding();
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().accepted(op(30), binding, State::Running)
            );
            assert_eq!(
                node.serve(ctx().start(op(31), binding)),
                ctx().rejected(Some(op(31)), binding, Reason::InvalidState)
            );
            assert_eq!(node.launcher.launches().len(), 1);
        }

        #[test]
        fn start_needs_an_admitted_ready_task_with_the_exact_binding() {
            let node = Node::new();
            let binding = lifecycle_binding();
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().rejected(Some(op(30)), binding, Reason::TaskNotFound)
            );
            node.serve(ctx().create(op(10), binding));
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().rejected(Some(op(30)), binding, Reason::InvalidState)
            );
            let other = TaskBinding::new(
                binding.task(),
                ExecutionAttemptId::from_u128(99),
                binding.lease(),
            );
            assert_eq!(
                node.serve(ctx().start(op(30), other)),
                ctx().rejected(Some(op(30)), other, Reason::AttemptMismatch)
            );
            assert_eq!(node.state(), State::Created);
            assert!(node.launcher.launches().is_empty());
            assert!(!node.workspace().exists());
        }

        #[test]
        fn start_rechecks_expiry_and_revocation_with_nothing_spawned() {
            let binding = lifecycle_binding();

            let node = Node::new();
            node.ready();
            node.clock.set(8_000);
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().rejected(Some(op(30)), binding, Reason::LeaseExpired)
            );
            assert_eq!(node.state(), State::Ready);

            let node = Node::new();
            node.ready();
            node.tasks
                .lock()
                .unwrap()
                .admission_mut()
                .unwrap()
                .state_mut()
                .record_revocation(AuthorityRevocation::new(
                    binding.lease(),
                    4_000,
                    RevocationReason::Operator,
                ))
                .unwrap();
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().rejected(Some(op(30)), binding, Reason::LeaseRevoked)
            );
            assert_eq!(node.state(), State::Ready);
            assert!(node.launcher.launches().is_empty());
            assert!(!node.workspace().exists());
        }

        #[test]
        fn a_snapshot_missing_from_the_node_store_refuses_start_with_nothing_spawned() {
            let node = Node::new();
            node.ready_with(
                &TaskAdmissionEnvelope::new(envelope_input(lifecycle_binding())).unwrap(),
            );
            let binding = lifecycle_binding();
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().rejected(Some(op(30)), binding, Reason::ResourceUnavailable)
            );
            assert_eq!(node.state(), State::Ready);
            assert!(node.launcher.launches().is_empty());
            assert_eq!(std::fs::read_dir(&node.root).unwrap().count(), 0);
        }

        #[test]
        fn a_clean_spawn_failure_refuses_with_no_state_change() {
            let node = Node::new();
            node.ready();
            let binding = lifecycle_binding();
            node.launcher.set_spawn(FakeSpawn::Refuse);
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().rejected(Some(op(30)), binding, Reason::ResourceUnavailable)
            );
            assert_eq!(node.state(), State::Ready);
            assert!(!node.workspace().exists());
            assert!(node.tasks.lock().unwrap().receipt(binding).is_none());

            node.launcher.set_spawn(FakeSpawn::Spawn);
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().accepted(op(30), binding, State::Running)
            );
            assert_eq!(node.launcher.launches().len(), 2);
        }

        #[test]
        fn an_ambiguous_launch_is_exited_unknown_and_never_rerun() {
            let node = Node::new();
            node.ready();
            let binding = lifecycle_binding();
            node.launcher.set_spawn(FakeSpawn::Ambiguous);
            let first = node.serve(ctx().start(op(30), binding));
            assert_eq!(first, ctx().accepted(op(30), binding, State::Exited));
            node.assert_finished(State::Exited, Outcome::Unknown);

            node.launcher.set_spawn(FakeSpawn::Spawn);
            assert_eq!(node.serve(ctx().start(op(30), binding)), first);
            assert_eq!(
                node.serve(ctx().start(op(31), binding)),
                ctx().rejected(Some(op(31)), binding, Reason::InvalidState)
            );
            assert_eq!(node.launcher.launches().len(), 1);
        }

        #[test]
        fn the_reaper_records_exited_with_the_receipt_outcome() {
            for (exit, outcome) in [
                (WorkloadExit::Exited { code: Some(0) }, Outcome::Completed),
                (WorkloadExit::Exited { code: Some(3) }, Outcome::Failed),
                (WorkloadExit::Exited { code: None }, Outcome::Failed),
                (WorkloadExit::BudgetExceeded, Outcome::Failed),
                (WorkloadExit::Lost, Outcome::Unknown),
            ] {
                let node = Node::new();
                node.running();
                node.launcher.exit(exit);
                node.wait_for(State::Exited);
                node.assert_finished(State::Exited, outcome);
                assert_eq!(
                    node.serve(ctx().start(op(30), lifecycle_binding())),
                    ctx().accepted(op(30), lifecycle_binding(), State::Exited),
                    "{exit:?}"
                );
            }
        }

        #[test]
        fn stop_kills_and_reaps_a_running_task_before_answering_stopped() {
            let node = Node::new();
            node.running();
            let binding = lifecycle_binding();
            eventually(|| node.launcher.waiting() == 1);

            let stopped = node.serve(ctx().stop(op(40), binding));
            assert_eq!(stopped, ctx().accepted(op(40), binding, State::Stopped));
            assert_eq!(node.launcher.stopped(), 1);
            assert_eq!(node.launcher.reaped(), 1);
            node.assert_finished(State::Stopped, Outcome::Failed);

            assert_eq!(node.serve(ctx().stop(op(40), binding)), stopped);
            for (request, operation) in [
                (ctx().stop(op(41), binding), op(41)),
                (ctx().start(op(42), binding), op(42)),
            ] {
                assert_eq!(
                    node.serve(request),
                    ctx().rejected(Some(operation), binding, Reason::InvalidState)
                );
            }
            assert_eq!(node.state(), State::Stopped);
        }

        #[test]
        fn stop_of_a_ready_task_stops_it_without_spawning() {
            let node = Node::new();
            node.ready();
            let binding = lifecycle_binding();
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().accepted(op(40), binding, State::Stopped)
            );
            node.assert_finished(State::Stopped, Outcome::Failed);
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().rejected(Some(op(30)), binding, Reason::InvalidState)
            );
            assert!(node.launcher.launches().is_empty());
            assert!(!node.workspace().exists());
        }

        #[test]
        fn stop_needs_an_admitted_task() {
            let node = Node::new();
            let binding = lifecycle_binding();
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().rejected(Some(op(40)), binding, Reason::TaskNotFound)
            );
            node.serve(ctx().create(op(10), binding));
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().rejected(Some(op(40)), binding, Reason::InvalidState)
            );
            assert_eq!(node.state(), State::Created);
        }

        #[test]
        fn a_stop_after_the_reaper_recorded_the_exit_is_invalid_state() {
            let node = Node::new();
            node.running();
            let binding = lifecycle_binding();
            node.launcher.exit(WorkloadExit::Exited { code: Some(0) });
            node.wait_for(State::Exited);
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().rejected(Some(op(40)), binding, Reason::InvalidState)
            );
            node.assert_finished(State::Exited, Outcome::Completed);
        }

        #[test]
        fn a_stop_that_lands_after_a_natural_exit_leaves_the_task_exited() {
            let node = Node::new();
            node.running();
            let binding = lifecycle_binding();
            eventually(|| node.launcher.waiting() == 1);
            node.launcher
                .set_on_stop(FakeStop::ExitedFirst(WorkloadExit::Exited {
                    code: Some(0),
                }));
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().rejected(Some(op(40)), binding, Reason::InvalidState)
            );
            node.assert_finished(State::Exited, Outcome::Completed);
            assert_eq!(node.launcher.stopped(), 0);
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().rejected(Some(op(40)), binding, Reason::InvalidState)
            );
        }

        #[test]
        fn a_stop_racing_a_natural_exit_ends_in_exactly_one_terminal_state() {
            for round in 0..40 {
                let node = Node::new();
                node.running();
                let binding = lifecycle_binding();
                eventually(|| node.launcher.waiting() == 1);
                let launcher = node.launcher.clone();
                let exiter = std::thread::spawn(move || {
                    if round % 2 == 0 {
                        std::thread::yield_now();
                    }
                    launcher.exit(WorkloadExit::Exited { code: Some(0) });
                });
                let response = node.serve(ctx().stop(op(40), binding));
                exiter.join().unwrap();
                node.launcher.set_on_stop(FakeStop::Honour);
                eventually(|| node.state() != State::Running);
                eventually(|| node.launcher.reaped() == 1);

                if response == ctx().accepted(op(40), binding, State::Stopped) {
                    node.assert_finished(State::Stopped, Outcome::Failed);
                    assert_eq!(node.launcher.stopped(), 1);
                } else {
                    assert_eq!(
                        response,
                        ctx().rejected(Some(op(40)), binding, Reason::InvalidState)
                    );
                    node.assert_finished(State::Exited, Outcome::Completed);
                    assert_eq!(node.launcher.stopped(), 0);
                }
                assert_eq!(node.serve(ctx().stop(op(40), binding)), response);
            }
        }

        #[test]
        fn a_stop_that_cannot_confirm_the_reap_is_refused_and_can_be_replayed() {
            let node = Node::with_stop_timeout(Duration::from_millis(50));
            node.running();
            let binding = lifecycle_binding();
            eventually(|| node.launcher.waiting() == 1);
            node.launcher.set_on_stop(FakeStop::Ignore);
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().rejected(Some(op(40)), binding, Reason::ResourceUnavailable)
            );
            assert_eq!(node.state(), State::Running);

            node.launcher.set_on_stop(FakeStop::Honour);
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().accepted(op(40), binding, State::Stopped)
            );
            node.assert_finished(State::Stopped, Outcome::Failed);
        }

        #[test]
        fn serving_stays_responsive_while_a_workload_runs() {
            let node = Node::new();
            node.running();
            let started = std::time::Instant::now();
            for _ in 0..20 {
                assert_eq!(node.state(), State::Running);
            }
            assert!(started.elapsed() < Duration::from_secs(2));
            assert_eq!(node.launcher.reaped(), 0);
        }

        #[test]
        fn start_and_stop_are_one_three_verbs() {
            let node = Node::new();
            node.ready();
            let one_two = TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap();
            let binding = lifecycle_binding();
            for (request, operation) in [
                (one_two.start(op(30), binding), op(30)),
                (one_two.stop(op(40), binding), op(40)),
            ] {
                assert_eq!(
                    TaskRegistry::serve(&node.tasks, one_two, request).unwrap(),
                    one_two.rejected(Some(operation), binding, Reason::UnsupportedOperation)
                );
            }
            assert_eq!(node.state(), State::Ready);
            assert!(node.launcher.launches().is_empty());
        }

        #[test]
        fn a_one_two_client_reads_a_finished_task_as_stopped_without_an_outcome() {
            let node = Node::new();
            node.running();
            node.launcher.exit(WorkloadExit::Exited { code: Some(0) });
            node.wait_for(State::Exited);
            let one_two = TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap();
            let binding = lifecycle_binding();
            for (request, expected) in [
                (
                    one_two.inspect(binding),
                    one_two.inspected(binding, State::Stopped),
                ),
                (
                    one_two.create(op(10), binding),
                    one_two.accepted(op(10), binding, State::Stopped),
                ),
            ] {
                let response = TaskRegistry::serve(&node.tasks, one_two, request).unwrap();
                assert_eq!(response, expected);
                assert!(serde_json::to_string(&response).is_ok());
            }
        }

        #[test]
        fn dropping_the_registry_stops_and_reaps_its_running_workloads() {
            let node = Node::new();
            node.running();
            eventually(|| node.launcher.waiting() == 1);
            let launcher = node.launcher.clone();
            drop(node);
            assert_eq!(launcher.stopped(), 1);
            assert_eq!(launcher.reaped(), 1);
            assert_eq!(launcher.waiting(), 0);
        }

        impl Node {
            fn envelope_for(&self, binding: TaskBinding, version: u64) -> TaskAdmissionEnvelope {
                let mut input = envelope_input(binding);
                input.workload = self.envelope().workload().clone();
                input.version = ward_node_protocol::AdmissionVersion::new(version).unwrap();
                TaskAdmissionEnvelope::new(input).unwrap()
            }

            fn paused(&self) {
                self.running();
                eventually(|| self.launcher.waiting() == 1);
                assert_eq!(
                    self.serve(ctx().pause(op(50), lifecycle_binding())),
                    ctx().accepted(op(50), lifecycle_binding(), State::Paused)
                );
            }

            fn exited(&self) {
                self.running();
                self.launcher.exit(WorkloadExit::Exited { code: Some(0) });
                self.wait_for(State::Exited);
            }

            fn drive(&self, state: State) {
                let binding = lifecycle_binding();
                match state {
                    State::Created => {
                        self.serve(ctx().create(op(10), binding));
                    }
                    State::Ready => self.ready(),
                    State::Running => self.running(),
                    State::Paused => self.paused(),
                    State::Stopped => {
                        self.running();
                        eventually(|| self.launcher.waiting() == 1);
                        self.serve(ctx().stop(op(40), binding));
                    }
                    State::Exited => self.exited(),
                    State::Revoked => {
                        self.running();
                        eventually(|| self.launcher.waiting() == 1);
                        self.serve(ctx().revoke(op(60), binding));
                    }
                    State::Sealed => {
                        self.exited();
                        self.serve(ctx().seal(op(70), binding));
                    }
                }
                assert_eq!(self.state(), state, "driving to {state:?}");
            }

            fn revoked_lease(&self) -> bool {
                self.tasks
                    .lock()
                    .unwrap()
                    .admission()
                    .unwrap()
                    .state()
                    .revocation(lifecycle_binding().lease())
                    .is_some()
            }

            fn effects(&self) -> (usize, usize, usize, usize, bool) {
                (
                    self.launcher.launches().len(),
                    self.launcher.freezes(),
                    self.launcher.thaws(),
                    self.launcher.stopped(),
                    self.revoked_lease(),
                )
            }

            fn outcome(&self) -> Option<Outcome> {
                self.tasks
                    .lock()
                    .unwrap()
                    .receipt(lifecycle_binding())
                    .map(ward_node_protocol::TaskExecutionReceipt::outcome)
            }
        }

        const ALL_STATES: [State; 8] = [
            State::Created,
            State::Ready,
            State::Running,
            State::Paused,
            State::Stopped,
            State::Exited,
            State::Revoked,
            State::Sealed,
        ];

        #[derive(Clone, Copy, Debug)]
        enum Verb {
            Create,
            Admit,
            Start,
            Pause,
            Resume,
            Stop,
            Revoke,
            Seal,
            Inspect,
            Stream,
        }

        /// The one accepted transition of `verb` from `state`, or its exact refusal.
        fn transition(state: State, verb: Verb) -> Result<State, Reason> {
            match (verb, state) {
                (Verb::Inspect, state) => Ok(state),
                (Verb::Stream, _) => Err(Reason::UnsupportedOperation),
                (Verb::Admit, State::Created) => Ok(State::Ready),
                (Verb::Start, State::Ready) | (Verb::Resume, State::Paused) => Ok(State::Running),
                (Verb::Pause, State::Running) => Ok(State::Paused),
                (Verb::Stop, State::Ready | State::Running | State::Paused) => Ok(State::Stopped),
                (Verb::Revoke, State::Ready | State::Running | State::Paused) => Ok(State::Revoked),
                (Verb::Seal, State::Stopped | State::Exited | State::Revoked) => Ok(State::Sealed),
                _ => Err(Reason::InvalidState),
            }
        }

        #[test]
        fn every_verb_in_every_state_is_one_exact_transition_or_an_exact_refusal() {
            let binding = lifecycle_binding();
            for state in ALL_STATES {
                for (index, verb) in [
                    Verb::Create,
                    Verb::Admit,
                    Verb::Start,
                    Verb::Pause,
                    Verb::Resume,
                    Verb::Stop,
                    Verb::Revoke,
                    Verb::Seal,
                    Verb::Inspect,
                    Verb::Stream,
                ]
                .into_iter()
                .enumerate()
                {
                    let node = Node::new();
                    node.drive(state);
                    if matches!(state, State::Running | State::Paused) {
                        eventually(|| node.launcher.waiting() == 1);
                    }
                    let operation = op(100 + u64::try_from(index).unwrap());
                    let request = match verb {
                        Verb::Create => ctx().create(operation, binding),
                        Verb::Admit => signed_admit(ctx(), operation, binding, &node.envelope()),
                        Verb::Start => ctx().start(operation, binding),
                        Verb::Pause => ctx().pause(operation, binding),
                        Verb::Resume => ctx().resume(operation, binding),
                        Verb::Stop => ctx().stop(operation, binding),
                        Verb::Revoke => ctx().revoke(operation, binding),
                        Verb::Seal => ctx().seal(operation, binding),
                        Verb::Inspect => ctx().inspect(binding),
                        Verb::Stream => ctx().stream(binding, 0),
                    };
                    let before = node.effects();
                    let response = node.serve(request);
                    let case = format!("{verb:?} from {state:?}");
                    match (verb, transition(state, verb)) {
                        (Verb::Inspect, Ok(unchanged)) => {
                            assert!(
                                matches!(
                                    response,
                                    TaskLifecycleResponse::Inspected { state, .. } if state == unchanged
                                ),
                                "{case}: {response:?}"
                            );
                            assert_eq!(node.effects(), before, "{case}");
                        }
                        (_, Ok(next)) => {
                            assert_eq!(
                                response,
                                ctx().accepted(operation, binding, next),
                                "{case}"
                            );
                            assert_eq!(node.state(), next, "{case}");
                        }
                        (Verb::Stream, Err(reason)) => {
                            assert_eq!(response, ctx().rejected(None, binding, reason), "{case}");
                            assert_eq!(node.state(), state, "{case}");
                            assert_eq!(node.effects(), before, "{case}");
                        }
                        (_, Err(reason)) => {
                            assert_eq!(
                                response,
                                ctx().rejected(Some(operation), binding, reason),
                                "{case}"
                            );
                            assert_eq!(node.state(), state, "{case}: a refusal changes nothing");
                            assert_eq!(node.effects(), before, "{case}: a refusal has no effect");
                        }
                    }
                }
            }
        }

        #[test]
        fn pause_freezes_the_workload_and_resume_thaws_it_while_the_reaper_keeps_watching() {
            let node = Node::new();
            node.paused();
            let binding = lifecycle_binding();
            assert!(node.launcher.frozen());
            assert_eq!(node.launcher.freezes(), 1);
            assert_eq!(
                node.serve(ctx().inspect(binding)),
                ctx().inspected(binding, State::Paused)
            );
            assert!(node.outcome().is_none());

            assert_eq!(
                node.serve(ctx().resume(op(55), binding)),
                ctx().accepted(op(55), binding, State::Running)
            );
            assert!(!node.launcher.frozen());
            assert_eq!(node.launcher.thaws(), 1);

            node.launcher.exit(WorkloadExit::Exited { code: Some(0) });
            node.wait_for(State::Exited);
            node.assert_finished(State::Exited, Outcome::Completed);
        }

        #[test]
        fn an_unconfirmed_freeze_is_refused_and_the_task_keeps_running() {
            let node = Node::new();
            node.running();
            let binding = lifecycle_binding();
            node.launcher.set_on_freeze(FakeFreeze::Unconfirmed);
            assert_eq!(
                node.serve(ctx().pause(op(50), binding)),
                ctx().rejected(Some(op(50)), binding, Reason::ResourceUnavailable)
            );
            assert_eq!(node.state(), State::Running);
            assert!(!node.launcher.frozen());

            node.launcher.set_on_freeze(FakeFreeze::Confirm);
            assert_eq!(
                node.serve(ctx().pause(op(50), binding)),
                ctx().accepted(op(50), binding, State::Paused)
            );
        }

        #[test]
        fn an_unconfirmed_thaw_is_refused_and_the_task_stays_paused() {
            let node = Node::new();
            node.paused();
            let binding = lifecycle_binding();
            node.launcher.set_on_thaw(FakeFreeze::Unconfirmed);
            assert_eq!(
                node.serve(ctx().resume(op(55), binding)),
                ctx().rejected(Some(op(55)), binding, Reason::ResourceUnavailable)
            );
            assert_eq!(node.state(), State::Paused);

            node.launcher.set_on_thaw(FakeFreeze::Confirm);
            assert_eq!(
                node.serve(ctx().resume(op(55), binding)),
                ctx().accepted(op(55), binding, State::Running)
            );
        }

        #[test]
        fn a_paused_task_can_be_stopped_and_is_reaped() {
            let node = Node::new();
            node.paused();
            let binding = lifecycle_binding();
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().accepted(op(40), binding, State::Stopped)
            );
            assert_eq!(node.launcher.stopped(), 1);
            assert_eq!(node.launcher.reaped(), 1);
            assert!(!node.launcher.frozen(), "thawed before the kill");
            node.assert_finished(State::Stopped, Outcome::Failed);
        }

        #[test]
        fn the_budget_keeps_running_while_paused() {
            let node = Node::new();
            node.paused();
            node.launcher.exit(WorkloadExit::BudgetExceeded);
            node.wait_for(State::Exited);
            node.assert_finished(State::Exited, Outcome::Failed);
        }

        #[test]
        fn revoke_records_the_revocation_durably_then_kills_and_reaps_the_workload() {
            let node = Node::new();
            node.running();
            eventually(|| node.launcher.waiting() == 1);
            let binding = lifecycle_binding();
            assert_eq!(
                node.serve(ctx().revoke(op(60), binding)),
                ctx().accepted(op(60), binding, State::Revoked)
            );
            let fact = node
                .tasks
                .lock()
                .unwrap()
                .admission()
                .unwrap()
                .state()
                .revocation(binding.lease())
                .unwrap();
            assert_eq!(fact.revoked_at_unix_ms(), NOW);
            assert_eq!(node.launcher.stopped(), 1);
            assert_eq!(node.launcher.reaped(), 1);
            assert_eq!(node.outcome(), Some(Outcome::Failed));
            assert_eq!(
                node.serve(ctx().inspect(binding)),
                ctx()
                    .inspected_with_outcome(binding, State::Revoked, Outcome::Failed)
                    .unwrap()
            );
            assert_eq!(node.tasks.lock().unwrap().running_pid(binding), None);
        }

        #[test]
        fn a_revoked_lease_refuses_a_new_attempt_even_after_a_restart() {
            let node = Node::new();
            node.running();
            eventually(|| node.launcher.waiting() == 1);
            let binding = lifecycle_binding();
            node.serve(ctx().revoke(op(60), binding));

            let node = node.restart();
            let retry = TaskBinding::new(
                binding.task(),
                ExecutionAttemptId::from_u128(99),
                binding.lease(),
            );
            assert_eq!(
                node.serve(ctx().create(op(80), retry)),
                ctx().accepted(op(80), retry, State::Created)
            );
            assert_eq!(
                node.serve(signed_admit(
                    ctx(),
                    op(81),
                    retry,
                    &node.envelope_for(retry, 2)
                )),
                ctx().rejected(Some(op(81)), retry, Reason::LeaseRevoked)
            );
            assert_eq!(
                node.serve(ctx().inspect(retry)),
                ctx().inspected(retry, State::Created)
            );
        }

        #[test]
        fn revoke_of_a_paused_task_thaws_kills_and_reaps_it() {
            let node = Node::new();
            node.paused();
            let binding = lifecycle_binding();
            assert_eq!(
                node.serve(ctx().revoke(op(60), binding)),
                ctx().accepted(op(60), binding, State::Revoked)
            );
            assert!(!node.launcher.frozen());
            assert_eq!(node.launcher.stopped(), 1);
            assert_eq!(node.outcome(), Some(Outcome::Failed));
            assert!(node.revoked_lease());
        }

        #[test]
        fn revoke_of_a_ready_task_spawns_nothing() {
            let node = Node::new();
            node.ready();
            let binding = lifecycle_binding();
            assert_eq!(
                node.serve(ctx().revoke(op(60), binding)),
                ctx().accepted(op(60), binding, State::Revoked)
            );
            assert!(node.revoked_lease());
            assert_eq!(node.outcome(), Some(Outcome::Failed));
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().rejected(Some(op(30)), binding, Reason::InvalidState)
            );
            assert!(node.launcher.launches().is_empty());
            assert!(!node.workspace().exists());
        }

        #[test]
        fn a_revoke_whose_reap_cannot_be_confirmed_is_revoked_with_an_unknown_receipt() {
            let node = Node::with_stop_timeout(Duration::from_millis(50));
            node.running();
            eventually(|| node.launcher.waiting() == 1);
            node.launcher.set_on_stop(FakeStop::Ignore);
            let binding = lifecycle_binding();
            assert_eq!(
                node.serve(ctx().revoke(op(60), binding)),
                ctx().accepted(op(60), binding, State::Revoked)
            );
            assert_eq!(node.outcome(), Some(Outcome::Unknown));

            node.launcher.set_on_stop(FakeStop::Honour);
            eventually(|| node.launcher.reaped() == 1);
            assert_eq!(node.state(), State::Revoked);
            assert_eq!(node.outcome(), Some(Outcome::Unknown));
        }

        #[test]
        fn a_revoke_that_cannot_be_recorded_durably_is_refused_and_changes_nothing() {
            let node = Node::new();
            node.running();
            eventually(|| node.launcher.waiting() == 1);
            let state_dir = node.root.parent().unwrap().join("state");
            std::fs::create_dir_all(
                state_dir
                    .join(crate::state::REVOCATIONS_FILE)
                    .join("blocker"),
            )
            .unwrap();
            let binding = lifecycle_binding();
            assert_eq!(
                node.serve(ctx().revoke(op(60), binding)),
                ctx().rejected(Some(op(60)), binding, Reason::ResourceUnavailable)
            );
            assert_eq!(node.state(), State::Running);
            assert_eq!(node.launcher.stopped(), 0);
            assert!(!node.revoked_lease());
        }

        #[test]
        fn seal_makes_a_finished_task_terminal() {
            for finished in [State::Stopped, State::Exited, State::Revoked] {
                let node = Node::new();
                node.drive(finished);
                let binding = lifecycle_binding();
                let outcome = node.outcome();
                assert_eq!(
                    node.serve(ctx().seal(op(70), binding)),
                    ctx().accepted(op(70), binding, State::Sealed),
                    "{finished:?}"
                );
                assert_eq!(
                    node.serve(ctx().inspect(binding)),
                    ctx()
                        .inspected_with_outcome(binding, State::Sealed, outcome.unwrap())
                        .unwrap()
                );
                assert_eq!(node.outcome(), outcome, "the receipt survives the seal");
            }
        }

        #[test]
        fn replaying_a_verb_returns_its_result_and_a_new_operation_on_a_terminal_task_is_refused() {
            let binding = lifecycle_binding();
            let node = Node::new();
            node.paused();
            let paused = ctx().accepted(op(50), binding, State::Paused);
            assert_eq!(node.serve(ctx().pause(op(50), binding)), paused);
            assert_eq!(node.launcher.freezes(), 1, "a replay never freezes again");
            let resumed = node.serve(ctx().resume(op(55), binding));
            assert_eq!(resumed, ctx().accepted(op(55), binding, State::Running));
            assert_eq!(node.serve(ctx().resume(op(55), binding)), resumed);
            assert_eq!(node.launcher.thaws(), 1, "a replay never thaws again");

            let revoked = node.serve(ctx().revoke(op(60), binding));
            assert_eq!(revoked, ctx().accepted(op(60), binding, State::Revoked));
            assert_eq!(node.serve(ctx().revoke(op(60), binding)), revoked);
            let sealed = node.serve(ctx().seal(op(70), binding));
            assert_eq!(sealed, ctx().accepted(op(70), binding, State::Sealed));
            assert_eq!(node.serve(ctx().seal(op(70), binding)), sealed);
            assert_eq!(
                node.serve(ctx().revoke(op(60), binding)),
                ctx().accepted(op(60), binding, State::Sealed)
            );

            for (request, operation) in [
                (ctx().pause(op(51), binding), op(51)),
                (ctx().resume(op(56), binding), op(56)),
                (ctx().revoke(op(61), binding), op(61)),
                (ctx().seal(op(71), binding), op(71)),
                (ctx().stop(op(41), binding), op(41)),
            ] {
                assert_eq!(
                    node.serve(request),
                    ctx().rejected(Some(operation), binding, Reason::InvalidState)
                );
            }
            assert_eq!(node.state(), State::Sealed);
            assert_eq!(node.launcher.stopped(), 1);
        }

        #[test]
        fn a_superseded_pause_or_resume_is_stale_and_never_acts_again() {
            let binding = lifecycle_binding();
            let node = Node::new();
            node.paused();
            for (request, operation, state) in [
                (ctx().resume(op(55), binding), op(55), State::Running),
                (ctx().pause(op(56), binding), op(56), State::Paused),
                (ctx().resume(op(57), binding), op(57), State::Running),
            ] {
                assert_eq!(
                    node.serve(request),
                    ctx().accepted(operation, binding, state)
                );
            }
            assert_eq!((node.launcher.freezes(), node.launcher.thaws()), (2, 2));

            for (request, operation) in [
                (ctx().pause(op(50), binding), op(50)),
                (ctx().resume(op(55), binding), op(55)),
            ] {
                assert_eq!(
                    node.serve(request),
                    ctx().rejected(Some(operation), binding, Reason::StaleOperation),
                    "a superseded operation is refused, never re-applied"
                );
            }
            assert_eq!(node.state(), State::Running);
            assert_eq!((node.launcher.freezes(), node.launcher.thaws()), (2, 2));

            assert_eq!(
                node.serve(ctx().pause(op(56), binding)),
                ctx().accepted(op(56), binding, State::Running)
            );
            assert_eq!(
                node.serve(ctx().resume(op(57), binding)),
                ctx().accepted(op(57), binding, State::Running)
            );
            assert_eq!((node.launcher.freezes(), node.launcher.thaws()), (2, 2));
        }

        #[test]
        fn every_applied_operation_replays_as_the_current_state_after_the_task_moved_on() {
            let binding = lifecycle_binding();
            let node = Node::new();
            node.paused();
            assert_eq!(
                node.serve(ctx().resume(op(55), binding)),
                ctx().accepted(op(55), binding, State::Running)
            );
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().accepted(op(40), binding, State::Stopped)
            );
            assert_eq!(
                node.serve(ctx().seal(op(70), binding)),
                ctx().accepted(op(70), binding, State::Sealed)
            );
            let effects = node.effects();
            for (request, operation) in [
                (ctx().create(op(10), binding), op(10)),
                (
                    signed_admit(ctx(), op(20), binding, &node.envelope()),
                    op(20),
                ),
                (ctx().start(op(30), binding), op(30)),
                (ctx().pause(op(50), binding), op(50)),
                (ctx().resume(op(55), binding), op(55)),
                (ctx().stop(op(40), binding), op(40)),
                (ctx().seal(op(70), binding), op(70)),
            ] {
                assert_eq!(
                    node.serve(request.clone()),
                    ctx().accepted(operation, binding, State::Sealed),
                    "{request:?}"
                );
            }
            assert_eq!(node.effects(), effects, "a replay never acts");
        }

        #[test]
        fn a_replaced_attempt_can_never_be_registered_again() {
            let binding = lifecycle_binding();
            let retry = TaskBinding::new(
                binding.task(),
                ExecutionAttemptId::from_u128(99),
                binding.lease(),
            );
            let node = Node::with_capacity(1);
            node.ready();
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().accepted(op(40), binding, State::Stopped)
            );
            assert_eq!(
                node.serve(ctx().create(op(80), retry)),
                ctx().accepted(op(80), retry, State::Created)
            );
            assert_eq!(
                node.serve(ctx().create(op(90), binding)),
                ctx().rejected(Some(op(90)), binding, Reason::StaleOperation),
                "while the new attempt is not finished"
            );
            assert_eq!(
                node.serve(signed_admit(
                    ctx(),
                    op(81),
                    retry,
                    &node.envelope_for(retry, 2)
                )),
                ctx().accepted(op(81), retry, State::Ready)
            );
            assert_eq!(
                node.serve(ctx().stop(op(82), retry)),
                ctx().accepted(op(82), retry, State::Stopped)
            );
            for operation in [op(10), op(90)] {
                assert_eq!(
                    node.serve(ctx().create(operation, binding)),
                    ctx().rejected(Some(operation), binding, Reason::StaleOperation),
                    "once the new attempt is finished"
                );
            }
            assert_eq!(
                node.serve(ctx().inspect(retry)),
                ctx()
                    .inspected_with_outcome(retry, State::Stopped, Outcome::Failed)
                    .unwrap()
            );

            let node = node.restart();
            assert_eq!(
                node.serve(ctx().create(op(90), binding)),
                ctx().rejected(Some(op(90)), binding, Reason::StaleOperation),
                "after a restart"
            );
            assert_eq!(
                node.serve(ctx().inspect(binding)),
                ctx().rejected(None, binding, Reason::AttemptMismatch)
            );
            assert_eq!(
                node.serve(ctx().inspect(retry)),
                ctx()
                    .inspected_with_outcome(retry, State::Stopped, Outcome::Failed)
                    .unwrap()
            );

            let Node {
                _dir: dir, tasks, ..
            } = node;
            drop(tasks);
            let node = Node::build(dir, 1, Duration::from_secs(10));
            assert_eq!(
                node.serve(ctx().seal(op(94), retry)),
                ctx().accepted(op(94), retry, State::Sealed)
            );
            let other = other_task(5);
            assert_eq!(
                node.serve(ctx().create(op(95), other)),
                ctx().accepted(op(95), other, State::Created)
            );
            assert_eq!(
                node.serve(ctx().inspect(retry)),
                ctx().rejected(None, retry, Reason::TaskNotFound),
                "evicted"
            );
            assert_eq!(
                node.serve(ctx().create(op(96), binding)),
                ctx().rejected(Some(op(96)), binding, Reason::StaleOperation),
                "after eviction"
            );
            assert!(node.launcher.launches().is_empty());
        }

        #[test]
        fn pauses_beyond_the_per_attempt_bound_are_refused_and_no_applied_id_is_forgotten() {
            let binding = lifecycle_binding();
            let node = Node::new();
            node.running();
            let pause = |index: usize| op(1_000 + u64::try_from(index).unwrap());
            let resume = |index: usize| op(5_000 + u64::try_from(index).unwrap());
            for index in 0..MAX_ATTEMPT_PAUSES {
                assert_eq!(
                    node.serve(ctx().pause(pause(index), binding)),
                    ctx().accepted(pause(index), binding, State::Paused)
                );
                assert_eq!(
                    node.serve(ctx().resume(resume(index), binding)),
                    ctx().accepted(resume(index), binding, State::Running)
                );
            }
            let effects = node.effects();
            let next = pause(MAX_ATTEMPT_PAUSES);
            assert_eq!(
                node.serve(ctx().pause(next, binding)),
                ctx().rejected(Some(next), binding, Reason::ResourceUnavailable)
            );
            for index in [0, MAX_ATTEMPT_PAUSES - 2] {
                for (request, operation) in [
                    (ctx().pause(pause(index), binding), pause(index)),
                    (ctx().resume(resume(index), binding), resume(index)),
                ] {
                    assert_eq!(
                        node.serve(request),
                        ctx().rejected(Some(operation), binding, Reason::StaleOperation)
                    );
                }
            }
            let last = MAX_ATTEMPT_PAUSES - 1;
            assert_eq!(
                node.serve(ctx().pause(pause(last), binding)),
                ctx().accepted(pause(last), binding, State::Running)
            );
            assert_eq!(
                node.effects(),
                effects,
                "nothing was frozen or thawed again"
            );
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().accepted(op(40), binding, State::Stopped),
                "stop is never held back by the bound"
            );
        }

        #[test]
        fn a_new_attempt_that_cannot_be_retired_durably_is_refused_and_changes_nothing() {
            let binding = lifecycle_binding();
            let retry = TaskBinding::new(
                binding.task(),
                ExecutionAttemptId::from_u128(99),
                binding.lease(),
            );
            let node = Node::new();
            node.drive(State::Exited);
            std::fs::create_dir_all(
                node.root
                    .parent()
                    .unwrap()
                    .join("state")
                    .join(crate::state::RETIRED_ATTEMPTS_FILE)
                    .join("blocker"),
            )
            .unwrap();
            assert_eq!(
                node.serve(ctx().create(op(80), retry)),
                ctx().rejected(Some(op(80)), retry, Reason::ResourceUnavailable)
            );
            node.assert_finished(State::Exited, Outcome::Completed);
            assert_eq!(
                node.serve(ctx().inspect(retry)),
                ctx().rejected(None, retry, Reason::AttemptMismatch)
            );
        }

        #[test]
        fn a_revoke_that_would_overflow_the_revocation_store_is_refused_and_changes_nothing() {
            let binding = lifecycle_binding();
            let node = Node::new();
            fill_revocations(&node.root.parent().unwrap().join("state"));
            let node = node.restart();
            node.running();
            eventually(|| node.launcher.waiting() == 1);
            assert_eq!(
                node.serve(ctx().revoke(op(60), binding)),
                ctx().rejected(Some(op(60)), binding, Reason::ResourceUnavailable)
            );
            assert_eq!(node.state(), State::Running);
            assert_eq!(node.launcher.stopped(), 0);
            assert!(!node.revoked_lease());
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().accepted(op(40), binding, State::Stopped)
            );
            let node = node.restart();
            assert_eq!(
                node.serve(ctx().inspect(binding)),
                ctx()
                    .inspected_with_outcome(binding, State::Stopped, Outcome::Failed)
                    .unwrap(),
                "the node still starts on the full store"
            );
        }

        #[test]
        fn revoked_and_sealed_tasks_report_their_receipt_outcome() {
            let binding = lifecycle_binding();
            let node = Node::new();
            node.drive(State::Revoked);
            assert_eq!(
                node.serve(ctx().inspect(binding)),
                ctx()
                    .inspected_with_outcome(binding, State::Revoked, Outcome::Failed)
                    .unwrap()
            );
            node.serve(ctx().seal(op(70), binding));
            assert_eq!(
                node.serve(ctx().inspect(binding)),
                ctx()
                    .inspected_with_outcome(binding, State::Sealed, Outcome::Failed)
                    .unwrap()
            );

            let node = Node::new();
            node.drive(State::Sealed);
            assert_eq!(
                node.serve(ctx().inspect(binding)),
                ctx()
                    .inspected_with_outcome(binding, State::Sealed, Outcome::Completed)
                    .unwrap()
            );
        }

        #[test]
        fn a_paused_task_whose_stop_times_out_reads_running_and_refuses_resume_and_pause() {
            let binding = lifecycle_binding();
            let node = Node::with_stop_timeout(Duration::from_millis(50));
            node.paused();
            node.launcher.set_on_stop(FakeStop::Ignore);
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().rejected(Some(op(40)), binding, Reason::ResourceUnavailable)
            );
            assert!(
                !node.launcher.frozen(),
                "the tree was continued for the kill"
            );
            assert_eq!(
                node.serve(ctx().inspect(binding)),
                ctx().inspected(binding, State::Running),
                "a continued tree that is being killed is not paused"
            );
            for (request, operation) in [
                (ctx().resume(op(55), binding), op(55)),
                (ctx().pause(op(56), binding), op(56)),
            ] {
                assert_eq!(
                    node.serve(request),
                    ctx().rejected(Some(operation), binding, Reason::InvalidState)
                );
            }
            assert_eq!((node.launcher.freezes(), node.launcher.thaws()), (1, 1));
            assert_eq!(node.state(), State::Running);

            node.launcher.set_on_stop(FakeStop::Honour);
            node.wait_for(State::Stopped);
            assert_eq!(
                node.serve(ctx().stop(op(40), binding)),
                ctx().accepted(op(40), binding, State::Stopped)
            );
            node.assert_finished(State::Stopped, Outcome::Failed);
        }

        #[test]
        fn pause_resume_revoke_and_seal_are_one_three_verbs_of_an_executing_node() {
            let node = Node::new();
            node.running();
            let one_two = TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap();
            let binding = lifecycle_binding();
            for (request, operation) in [
                (one_two.pause(op(50), binding), op(50)),
                (one_two.resume(op(55), binding), op(55)),
                (one_two.revoke(op(60), binding), op(60)),
                (one_two.seal(op(70), binding), op(70)),
            ] {
                assert_eq!(
                    TaskRegistry::serve(&node.tasks, one_two, request).unwrap(),
                    one_two.rejected(Some(operation), binding, Reason::UnsupportedOperation)
                );
            }
            assert_eq!(node.state(), State::Running);
            assert_eq!(node.launcher.freezes(), 0);
            assert!(!node.revoked_lease());

            let dir = tempfile::tempdir().unwrap();
            let clock = FixedClock::at(NOW);
            let tasks = Arc::new(Mutex::new(
                TaskRegistry::with_admission(
                    MAX_NODE_TASKS,
                    node_admission(&dir.path().join("state"), &clock),
                )
                .unwrap(),
            ));
            TaskRegistry::serve(&tasks, ctx(), ctx().create(op(10), binding)).unwrap();
            let envelope = TaskAdmissionEnvelope::new(envelope_input(binding)).unwrap();
            TaskRegistry::serve(
                &tasks,
                ctx(),
                signed_admit(ctx(), op(20), binding, &envelope),
            )
            .unwrap();
            for (request, operation) in [
                (ctx().pause(op(50), binding), op(50)),
                (ctx().resume(op(55), binding), op(55)),
                (ctx().revoke(op(60), binding), op(60)),
                (ctx().seal(op(70), binding), op(70)),
            ] {
                assert_eq!(
                    TaskRegistry::serve(&tasks, ctx(), request).unwrap(),
                    ctx().rejected(Some(operation), binding, Reason::UnsupportedOperation)
                );
            }
            assert!(
                tasks
                    .lock()
                    .unwrap()
                    .admission()
                    .unwrap()
                    .state()
                    .revocation(binding.lease())
                    .is_none()
            );
        }

        #[test]
        fn a_new_attempt_replaces_a_terminal_attempt_of_the_same_task() {
            let binding = lifecycle_binding();
            for finished in [State::Stopped, State::Exited, State::Revoked, State::Sealed] {
                let node = Node::new();
                node.drive(finished);
                let lease = if finished == State::Revoked {
                    ward_events::LeaseId::from_u128(10)
                } else {
                    binding.lease()
                };
                let retry =
                    TaskBinding::new(binding.task(), ExecutionAttemptId::from_u128(99), lease);
                assert_eq!(
                    node.serve(ctx().create(op(80), retry)),
                    ctx().accepted(op(80), retry, State::Created),
                    "{finished:?}"
                );
                assert_eq!(
                    node.serve(ctx().create(op(80), retry)),
                    ctx().accepted(op(80), retry, State::Created)
                );
                assert_eq!(
                    node.serve(ctx().inspect(binding)),
                    ctx().rejected(None, binding, Reason::AttemptMismatch)
                );
                assert_eq!(
                    node.serve(signed_admit(
                        ctx(),
                        op(81),
                        retry,
                        &node.envelope_for(retry, 1)
                    )),
                    ctx().rejected(Some(op(81)), retry, Reason::StaleOperation),
                    "versions stay strictly increasing per task across attempts"
                );
                assert_eq!(
                    node.serve(signed_admit(
                        ctx(),
                        op(81),
                        retry,
                        &node.envelope_for(retry, 2)
                    )),
                    ctx().accepted(op(81), retry, State::Ready)
                );
                assert_eq!(
                    node.serve(ctx().start(op(82), retry)),
                    ctx().accepted(op(82), retry, State::Running)
                );
                let launches = node.launcher.launches();
                let last = launches.last().unwrap();
                assert_eq!(
                    last.workspace(),
                    node.root
                        .join(binding.task().to_string())
                        .join(retry.attempt().to_string())
                );
            }
        }

        #[test]
        fn a_new_attempt_is_refused_while_the_current_attempt_is_not_terminal() {
            let binding = lifecycle_binding();
            let retry = TaskBinding::new(
                binding.task(),
                ExecutionAttemptId::from_u128(99),
                binding.lease(),
            );
            for current in [State::Created, State::Ready, State::Running, State::Paused] {
                let node = Node::new();
                node.drive(current);
                let before = node.effects();
                assert_eq!(
                    node.serve(ctx().create(op(80), retry)),
                    ctx().rejected(Some(op(80)), retry, Reason::AttemptMismatch),
                    "{current:?}"
                );
                assert_eq!(node.state(), current);
                assert_eq!(node.effects(), before);
            }
        }

        fn other_task(task: u128) -> TaskBinding {
            TaskBinding::new(
                ward_events::TaskId::from_u128(task),
                ExecutionAttemptId::from_u128(8),
                ward_events::LeaseId::from_u128(9),
            )
        }

        fn finish_and_seal(node: &Node, binding: TaskBinding, base: u64) {
            assert_eq!(
                node.serve(ctx().create(op(base), binding)),
                ctx().accepted(op(base), binding, State::Created)
            );
            assert_eq!(
                node.serve(signed_admit(
                    ctx(),
                    op(base + 1),
                    binding,
                    &node.envelope_for(binding, 1)
                )),
                ctx().accepted(op(base + 1), binding, State::Ready)
            );
            node.serve(ctx().stop(op(base + 2), binding));
            assert_eq!(
                node.serve(ctx().seal(op(base + 3), binding)),
                ctx().accepted(op(base + 3), binding, State::Sealed)
            );
        }

        #[test]
        fn sealed_tasks_do_not_count_against_capacity_and_the_oldest_is_evicted_first() {
            let node = Node::with_capacity(2);
            let (first, second, third, fourth) =
                (other_task(1), other_task(2), other_task(3), other_task(4));
            finish_and_seal(&node, first, 10);
            finish_and_seal(&node, second, 20);
            assert_eq!(
                node.serve(ctx().create(op(30), third)),
                ctx().accepted(op(30), third, State::Created)
            );
            assert_eq!(
                node.serve(ctx().inspect(first)),
                ctx().rejected(None, first, Reason::TaskNotFound),
                "the oldest sealed task is evicted first"
            );
            assert_eq!(
                node.serve(ctx().inspect(second)),
                ctx()
                    .inspected_with_outcome(second, State::Sealed, Outcome::Failed)
                    .unwrap()
            );
            assert_eq!(
                node.serve(ctx().create(op(40), fourth)),
                ctx().accepted(op(40), fourth, State::Created)
            );
            assert_eq!(
                node.serve(ctx().inspect(second)),
                ctx().rejected(None, second, Reason::TaskNotFound)
            );
            assert_eq!(
                node.serve(ctx().create(op(50), first)),
                ctx().rejected(Some(op(50)), first, Reason::ResourceUnavailable),
                "unsealed tasks still count"
            );
            assert_eq!(node.tasks.lock().unwrap().len(), 2);
        }

        #[test]
        fn an_evicted_task_keeps_its_durable_admission_version() {
            let node = Node::with_capacity(1);
            let (first, second) = (other_task(1), other_task(2));
            finish_and_seal(&node, first, 10);
            assert_eq!(
                node.serve(ctx().create(op(20), second)),
                ctx().accepted(op(20), second, State::Created)
            );
            assert_eq!(
                node.serve(ctx().create(op(30), first)),
                ctx().rejected(Some(op(30)), first, Reason::ResourceUnavailable)
            );

            let node = Node::with_capacity(1);
            finish_and_seal(&node, first, 10);
            finish_and_seal(&node, second, 20);
            assert_eq!(
                node.serve(ctx().create(op(30), first)),
                ctx().accepted(op(30), first, State::Created)
            );
            assert_eq!(
                node.serve(signed_admit(
                    ctx(),
                    op(31),
                    first,
                    &node.envelope_for(first, 1)
                )),
                ctx().rejected(Some(op(31)), first, Reason::StaleOperation)
            );
        }

        impl Node {
            fn state_dir(&self) -> PathBuf {
                self.root.parent().unwrap().join("state")
            }

            fn record_path(&self, binding: TaskBinding) -> PathBuf {
                self.state_dir()
                    .join(crate::records::TASKS_DIR)
                    .join(format!("{}.json", binding.task()))
            }

            fn record_blocker(&self) -> PathBuf {
                self.state_dir()
                    .join(crate::records::TASKS_DIR)
                    .join(format!(".{}.json.tmp", lifecycle_binding().task()))
                    .join("blocker")
            }

            fn block_records(&self) {
                std::fs::create_dir_all(self.record_blocker()).unwrap();
            }

            fn unblock_records(&self) {
                std::fs::remove_dir_all(self.record_blocker().parent().unwrap()).unwrap();
            }
        }

        #[test]
        fn a_running_or_paused_attempt_recovers_as_exited_unknown_and_never_runs_again() {
            let binding = lifecycle_binding();
            for executing in [State::Running, State::Paused] {
                let node = Node::new();
                node.drive(executing);
                eventually(|| node.launcher.waiting() == 1);

                let node = node.restart();
                node.assert_finished(State::Exited, Outcome::Unknown);
                assert_eq!(
                    node.launcher.survivors(),
                    vec![fake_process()],
                    "{executing:?}: the survivor is ended by its recorded identity"
                );
                assert_eq!(
                    node.serve(ctx().start(op(30), binding)),
                    ctx().accepted(op(30), binding, State::Exited),
                    "{executing:?}"
                );
                assert_eq!(
                    node.serve(ctx().start(op(31), binding)),
                    ctx().rejected(Some(op(31)), binding, Reason::InvalidState)
                );
                assert!(node.launcher.launches().is_empty(), "{executing:?}");

                let node = node.restart();
                node.assert_finished(State::Exited, Outcome::Unknown);
                assert!(node.launcher.survivors().is_empty());
                assert!(node.launcher.launches().is_empty());
            }
        }

        #[test]
        fn a_recorded_launch_intent_recovers_as_exited_unknown_without_a_spawn() {
            let binding = lifecycle_binding();
            let node = Node::new();
            node.ready();
            let store = crate::records::TaskStore::open(&node.state_dir()).unwrap();
            let mut record = store.load(MAX_NODE_TASKS).unwrap().remove(0);
            record.state = crate::records::RecordedState::Launching;
            record.started_by = Some(op(30));
            record.workspace = Some(node.workspace());
            store.write(&record).unwrap();

            let node = node.restart();
            node.assert_finished(State::Exited, Outcome::Unknown);
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().accepted(op(30), binding, State::Exited)
            );
            assert!(node.launcher.launches().is_empty());
            assert!(node.launcher.survivors().is_empty());
        }

        #[test]
        fn a_spawn_whose_running_record_cannot_be_written_is_killed_and_ambiguous() {
            let binding = lifecycle_binding();
            let node = Node::new();
            node.ready();
            node.launcher.block_on_launch(node.record_blocker());
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().accepted(op(30), binding, State::Exited)
            );
            node.assert_finished(State::Exited, Outcome::Unknown);
            eventually(|| node.launcher.stopped() == 1);
            node.unblock_records();

            let node = node.restart();
            node.assert_finished(State::Exited, Outcome::Unknown);
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().accepted(op(30), binding, State::Exited)
            );
            assert!(node.launcher.launches().is_empty());
        }

        #[test]
        fn ended_attempts_keep_their_state_receipt_and_replays_across_a_restart() {
            let binding = lifecycle_binding();
            for (ended, verb) in [
                (State::Stopped, ctx().stop(op(40), binding)),
                (State::Exited, ctx().start(op(30), binding)),
                (State::Revoked, ctx().revoke(op(60), binding)),
                (State::Sealed, ctx().seal(op(70), binding)),
            ] {
                let node = Node::new();
                node.drive(ended);
                let outcome = node.outcome().unwrap();

                let node = node.restart();
                node.assert_finished(ended, outcome);
                assert_eq!(
                    node.serve(verb.clone()),
                    match verb {
                        TaskLifecycleRequest::Stop { operation_id, .. }
                        | TaskLifecycleRequest::Start { operation_id, .. }
                        | TaskLifecycleRequest::Revoke { operation_id, .. }
                        | TaskLifecycleRequest::Seal { operation_id, .. } =>
                            ctx().accepted(operation_id, binding, ended),
                        other => panic!("unexpected {other:?}"),
                    },
                    "{ended:?}"
                );
                assert!(node.launcher.survivors().is_empty(), "{ended:?}");
                assert_eq!(node.effects(), (0, 0, 0, 0, ended == State::Revoked));
            }
        }

        #[test]
        fn every_applied_operation_replays_exactly_after_a_restart_and_never_acts() {
            let binding = lifecycle_binding();
            let node = Node::new();
            node.paused();
            for (request, operation, state) in [
                (ctx().resume(op(55), binding), op(55), State::Running),
                (ctx().pause(op(56), binding), op(56), State::Paused),
                (ctx().resume(op(57), binding), op(57), State::Running),
                (ctx().stop(op(40), binding), op(40), State::Stopped),
                (ctx().seal(op(70), binding), op(70), State::Sealed),
            ] {
                assert_eq!(
                    node.serve(request),
                    ctx().accepted(operation, binding, state)
                );
            }

            let node = node.restart();
            for (request, operation) in [
                (ctx().create(op(10), binding), op(10)),
                (
                    signed_admit(ctx(), op(20), binding, &node.envelope()),
                    op(20),
                ),
                (ctx().start(op(30), binding), op(30)),
                (ctx().pause(op(56), binding), op(56)),
                (ctx().resume(op(57), binding), op(57)),
                (ctx().stop(op(40), binding), op(40)),
                (ctx().seal(op(70), binding), op(70)),
            ] {
                assert_eq!(
                    node.serve(request.clone()),
                    ctx().accepted(operation, binding, State::Sealed),
                    "{request:?}"
                );
            }
            for (request, operation) in [
                (ctx().pause(op(50), binding), op(50)),
                (ctx().resume(op(55), binding), op(55)),
            ] {
                assert_eq!(
                    node.serve(request),
                    ctx().rejected(Some(operation), binding, Reason::StaleOperation)
                );
            }
            assert_eq!(node.effects(), (0, 0, 0, 0, false), "a replay never acts");
        }

        #[test]
        fn a_revocation_recorded_before_a_restart_still_refuses_the_recovered_task() {
            let binding = lifecycle_binding();
            let node = Node::new();
            node.ready();
            node.tasks
                .lock()
                .unwrap()
                .admission_mut()
                .unwrap()
                .state_mut()
                .record_revocation(AuthorityRevocation::new(
                    binding.lease(),
                    4_000,
                    RevocationReason::Operator,
                ))
                .unwrap();

            let node = node.restart();
            assert_eq!(node.state(), State::Created);
            assert_eq!(
                node.serve(signed_admit(
                    ctx(),
                    op(21),
                    binding,
                    &node.envelope_for(binding, 2)
                )),
                ctx().rejected(Some(op(21)), binding, Reason::LeaseRevoked)
            );
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().rejected(Some(op(30)), binding, Reason::InvalidState)
            );
            assert!(node.launcher.launches().is_empty());
        }

        #[test]
        fn a_failed_record_write_refuses_the_verb_and_changes_nothing() {
            let binding = lifecycle_binding();
            let node = Node::new();
            node.block_records();
            assert_eq!(
                node.serve(ctx().create(op(10), binding)),
                ctx().rejected(Some(op(10)), binding, Reason::ResourceUnavailable)
            );
            assert_eq!(
                node.serve(ctx().inspect(binding)),
                ctx().rejected(None, binding, Reason::TaskNotFound)
            );
            node.unblock_records();
            assert_eq!(
                node.serve(ctx().create(op(10), binding)),
                ctx().accepted(op(10), binding, State::Created)
            );

            node.block_records();
            assert_eq!(
                node.serve(signed_admit(ctx(), op(20), binding, &node.envelope())),
                ctx().rejected(Some(op(20)), binding, Reason::ResourceUnavailable)
            );
            assert_eq!(node.state(), State::Created);
            assert_eq!(
                node.tasks
                    .lock()
                    .unwrap()
                    .admission()
                    .unwrap()
                    .state()
                    .last_admitted_version(binding.task()),
                None,
                "a refused admit consumes no version"
            );
            node.unblock_records();
            assert_eq!(
                node.serve(signed_admit(ctx(), op(20), binding, &node.envelope())),
                ctx().accepted(op(20), binding, State::Ready)
            );

            node.block_records();
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().rejected(Some(op(30)), binding, Reason::ResourceUnavailable)
            );
            assert_eq!(node.state(), State::Ready);
            assert!(node.launcher.launches().is_empty());
            assert!(!node.workspace().exists());
            node.unblock_records();
            assert_eq!(
                node.serve(ctx().start(op(30), binding)),
                ctx().accepted(op(30), binding, State::Running)
            );
            eventually(|| node.launcher.waiting() == 1);

            node.block_records();
            assert_eq!(
                node.serve(ctx().pause(op(50), binding)),
                ctx().rejected(Some(op(50)), binding, Reason::ResourceUnavailable)
            );
            assert_eq!(node.state(), State::Running);
            assert!(!node.launcher.frozen(), "the freeze was continued back");
            node.unblock_records();

            node.launcher.exit(WorkloadExit::Exited { code: Some(0) });
            node.wait_for(State::Exited);
            node.block_records();
            assert_eq!(
                node.serve(ctx().seal(op(70), binding)),
                ctx().rejected(Some(op(70)), binding, Reason::ResourceUnavailable)
            );
            node.assert_finished(State::Exited, Outcome::Completed);
            node.unblock_records();
            assert_eq!(
                node.serve(ctx().seal(op(70), binding)),
                ctx().accepted(op(70), binding, State::Sealed)
            );
        }

        #[test]
        fn a_ready_task_whose_stop_or_revoke_cannot_be_recorded_stays_ready() {
            let binding = lifecycle_binding();
            for request in [ctx().stop(op(40), binding), ctx().revoke(op(60), binding)] {
                let node = Node::new();
                node.ready();
                node.block_records();
                let (TaskLifecycleRequest::Stop { operation_id, .. }
                | TaskLifecycleRequest::Revoke { operation_id, .. }) = request
                else {
                    panic!("stop or revoke");
                };
                assert_eq!(
                    node.serve(request.clone()),
                    ctx().rejected(Some(operation_id), binding, Reason::ResourceUnavailable),
                    "{request:?}"
                );
                assert_eq!(node.state(), State::Ready);
                assert!(node.outcome().is_none());
            }
        }

        #[test]
        fn eviction_removes_the_record_so_a_restart_does_not_bring_the_task_back() {
            let node = Node::with_capacity(1);
            let (first, second) = (other_task(1), other_task(2));
            finish_and_seal(&node, first, 10);
            assert!(node.record_path(first).exists());
            assert_eq!(
                node.serve(ctx().create(op(20), second)),
                ctx().accepted(op(20), second, State::Created)
            );
            assert!(!node.record_path(first).exists());

            let node = node.restart();
            assert_eq!(
                node.serve(ctx().inspect(first)),
                ctx().rejected(None, first, Reason::TaskNotFound)
            );
            assert_eq!(
                node.serve(ctx().inspect(second)),
                ctx().inspected(second, State::Created)
            );
        }

        #[test]
        fn a_registry_without_execution_refuses_start_and_stop() {
            let dir = tempfile::tempdir().unwrap();
            let clock = FixedClock::at(NOW);
            let tasks = Arc::new(Mutex::new(
                TaskRegistry::with_admission(
                    MAX_NODE_TASKS,
                    node_admission(&dir.path().join("state"), &clock),
                )
                .unwrap(),
            ));
            let binding = lifecycle_binding();
            TaskRegistry::serve(&tasks, ctx(), ctx().create(op(10), binding)).unwrap();
            let envelope = TaskAdmissionEnvelope::new(envelope_input(binding)).unwrap();
            TaskRegistry::serve(
                &tasks,
                ctx(),
                signed_admit(ctx(), op(20), binding, &envelope),
            )
            .unwrap();
            for (request, operation) in [
                (ctx().start(op(30), binding), op(30)),
                (ctx().stop(op(40), binding), op(40)),
            ] {
                assert_eq!(
                    TaskRegistry::serve(&tasks, ctx(), request).unwrap(),
                    ctx().rejected(Some(operation), binding, Reason::UnsupportedOperation)
                );
            }
            assert!(!tasks.lock().unwrap().executes());
        }
    }

    #[test]
    fn a_full_registry_refuses_new_tasks_but_still_replays_existing_ones() {
        let ctx = context();
        let mut registry = TaskRegistry::with_capacity(1);
        let first = binding(1, 2, 3);
        let second = binding(4, 5, 6);

        registry.handle(ctx, ctx.create(op(10), first));
        assert_eq!(
            registry.handle(ctx, ctx.create(op(11), second)),
            ctx.rejected(Some(op(11)), second, Reason::ResourceUnavailable)
        );
        assert_eq!(
            registry.handle(ctx, ctx.inspect(second)),
            ctx.rejected(None, second, Reason::TaskNotFound)
        );
        assert_eq!(
            registry.handle(ctx, ctx.create(op(10), first)),
            ctx.accepted(op(10), first, TaskLifecycleState::Created)
        );
        assert_eq!(registry.len(), 1);
    }
}
