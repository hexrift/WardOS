//! Node-owned task registry for the task lifecycle protocol (#321).
//!
//! This slice binds [`TaskLifecycleRequest`]s to node-owned state. It implements five
//! verbs:
//!
//! * `create` registers a task under its immutable [`TaskBinding`] in the
//!   [`TaskLifecycleState::Created`] state. `Created` means "the node has admitted this
//!   task identity into its registry", nothing more: no process, sandbox, credential or
//!   network authority exists for it. The protocol's `create` carries no workload
//!   description, so there is nothing to execute yet; the workload arrives with
//!   `admit`, and execution belongs to `start`.
//! * `inspect` reports the state the registry actually holds for that binding. At
//!   protocol 1.3 an `exited` or `stopped` task also reports its receipt outcome; a 1.2
//!   connection, which cannot represent `exited`, reads an exited task as `stopped` (its
//!   workload is gone) and never sees an outcome.
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
//! * `stop` (protocol 1.3, with execution) moves a `Running` task to
//!   [`TaskLifecycleState::Stopped`] once its reaper has killed and reaped the workload,
//!   and a `Ready` task to `Stopped` without spawning anything.
//!
//! The reaper waits on the workload promptly and, when it ends, moves the task
//! `Running → Exited` under the registry lock with a [`TaskExecutionReceipt`]: exit 0
//! within budget is `completed`; a non-zero exit, a signal or a kill at the budget is
//! `failed`; a lost child is `unknown`. A stop that races a natural exit ends in exactly one
//! terminal state: the reaper decides, so a workload that had already exited on its own is
//! `exited` (and the stop is answered `invalid_state`), otherwise it is `stopped`. A
//! stopped attempt's receipt is `failed`, because the node knows the attempt did not
//! complete and that its workload is gone (a `ready` task never ran at all); it is
//! `unknown` only when the reap could not be confirmed. A stop whose reap is not confirmed
//! within the stop timeout is refused `resource_unavailable` and may be replayed.
//! Replaying the `start` or `stop` that took effect is accepted with the task's current
//! state; any other `start` or `stop` of a task past `ready` is `invalid_state`.
//!
//! `pause`, `resume`, `revoke`, `seal` and `stream` are answered with an explicit
//! [`TaskLifecycleRejectionReason::UnsupportedOperation`] and never change a task's state,
//! as are `start` and `stop` without execution or below protocol 1.3. The node does not
//! accept a transition it cannot carry out, and it never reports one as applied.
//!
//! The registry is in memory and bounded by its capacity: a node restart forgets every
//! task, including a running attempt (durable recovery is #332 slice 7), and a full
//! registry refuses a new `create` with
//! [`TaskLifecycleRejectionReason::ResourceUnavailable`] rather than growing without
//! limit. An attempt's workspace outlives a restart, so the same attempt is never started
//! twice. Dropping the registry stops and reaps every running workload; a node process
//! that dies outright takes its sandboxes with it (`--die-with-parent`).

use std::collections::HashMap;
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::sync::{Arc, Condvar, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use thiserror::Error;
use ward_events::TaskId;
use ward_node_protocol::{
    AdmissionEnvelopeJson, IssuerProof, OperationId, TaskAdmissionEnvelope, TaskBinding,
    TaskExecutionOutcome, TaskExecutionReceipt, TaskLifecycleContext, TaskLifecycleRejectionReason,
    TaskLifecycleRequest, TaskLifecycleResponse, TaskLifecycleState, TaskReceiptContext,
    supports_task_admission,
};

use crate::admission::TrustedTaskAdmission;
use crate::admit::{NodeAdmission, VerifiedAdmission};
use crate::execution::{
    LaunchRequest, NodeExecution, SpawnError, StopSignal, TaskLauncher, WorkloadExit,
};
use crate::workspace::{WorkspaceError, discard};

/// Default upper bound on tasks one node registry holds.
pub const MAX_NODE_TASKS: usize = 1024;

/// The shared task registry is unavailable: an earlier panic poisoned its lock.
#[derive(Clone, Copy, Debug, Error)]
#[error("ward-node task registry is unavailable")]
pub struct TaskRegistryUnavailable;

type Reason = TaskLifecycleRejectionReason;
type SharedRegistry = Arc<Mutex<TaskRegistry>>;

#[derive(Debug)]
struct NodeTask {
    binding: TaskBinding,
    state: TaskLifecycleState,
    created_by: OperationId,
    admitted: Option<AdmittedTask>,
    started_by: Option<OperationId>,
    attempt: Option<Attempt>,
    stopped_by: Option<OperationId>,
    receipt: Option<TaskExecutionReceipt>,
}

/// A spawned (or ambiguously spawned) attempt and the handles its reaper shares.
#[derive(Debug)]
struct Attempt {
    pid: Option<u32>,
    stop: StopSignal,
    stop_requested_by: Option<OperationId>,
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

/// In-memory, bounded registry of node-owned tasks keyed by task identity.
#[derive(Debug)]
pub struct TaskRegistry {
    tasks: HashMap<TaskId, NodeTask>,
    capacity: usize,
    admission: Option<NodeAdmission>,
    execution: Option<NodeExecution>,
}

impl Default for TaskRegistry {
    fn default() -> Self {
        Self::with_capacity(MAX_NODE_TASKS)
    }
}

/// What `stop` does once it has looked at the task under the registry lock.
enum StopStep {
    Answer(TaskLifecycleResponse),
    AwaitReap(Arc<Reaped>, Duration),
}

impl TaskRegistry {
    /// An empty registry that holds at most `capacity` tasks.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            tasks: HashMap::new(),
            capacity,
            admission: None,
            execution: None,
        }
    }

    /// An empty registry of at most `capacity` tasks that admits through `admission`.
    #[must_use]
    pub fn with_admission(capacity: usize, admission: NodeAdmission) -> Self {
        Self {
            tasks: HashMap::new(),
            capacity,
            admission: Some(admission),
            execution: None,
        }
    }

    /// An empty registry of at most `capacity` tasks that admits through `admission` and
    /// starts and stops admitted tasks through `execution` (protocol 1.3).
    #[must_use]
    pub fn with_execution(
        capacity: usize,
        admission: NodeAdmission,
        execution: NodeExecution,
    ) -> Self {
        Self {
            tasks: HashMap::new(),
            capacity,
            admission: Some(admission),
            execution: Some(execution),
        }
    }

    /// Whether this registry starts and stops admitted tasks.
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

    /// The admission held by the task `binding` names, if it is admitted under exactly
    /// that binding.
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

    /// Number of tasks the registry currently holds.
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
    /// `start` and `stop` are served here, because the reaper of a started attempt needs
    /// the shared registry to record how it ended; every other verb is [`Self::handle`].
    /// The registry lock is never held while a workload runs: `start` returns once the
    /// spawn is confirmed, and `stop` releases the lock while the reaper kills and reaps.
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
                    StopStep::Answer(response) => return Ok(response),
                    StopStep::AwaitReap(reaped, timeout) => (reaped, timeout),
                };
                reaped.wait(timeout);
                Ok(lock()?.finish_stop(context, operation_id, binding))
            }
            other => Ok(lock()?.handle(context, other)),
        }
    }

    /// Apply one decoded lifecycle request and build its response under `context`.
    ///
    /// The request must already have been decoded through `context` (which proves it
    /// names the negotiated protocol). `start` and `stop` need the shared registry and are
    /// served only through [`Self::serve`]; here they are refused as unsupported.
    #[allow(clippy::needless_pass_by_value)]
    pub fn handle(
        &mut self,
        context: TaskLifecycleContext,
        request: TaskLifecycleRequest,
    ) -> TaskLifecycleResponse {
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
            } => match self.admit(operation_id, binding, envelope_json, proof) {
                Ok(state) => context.accepted(operation_id, binding, visible(context, state)),
                Err(reason) => context.rejected(Some(operation_id), binding, reason),
            },
            TaskLifecycleRequest::Start {
                operation_id,
                binding,
                ..
            }
            | TaskLifecycleRequest::Pause {
                operation_id,
                binding,
                ..
            }
            | TaskLifecycleRequest::Resume {
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
            }
            | TaskLifecycleRequest::Seal {
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
        if let Some(task) = self.tasks.get(&binding.task()) {
            if let Err(reason) = task.matches(binding) {
                return context.rejected(Some(operation_id), binding, reason);
            }
            if task.created_by != operation_id {
                return context.rejected(
                    Some(operation_id),
                    binding,
                    TaskLifecycleRejectionReason::InvalidState,
                );
            }
            // Idempotent replay of the very create that registered this task.
            return context.accepted(operation_id, task.binding, visible(context, task.state));
        }

        if self.tasks.len() >= self.capacity {
            return context.rejected(
                Some(operation_id),
                binding,
                TaskLifecycleRejectionReason::ResourceUnavailable,
            );
        }

        self.tasks.insert(
            binding.task(),
            NodeTask {
                binding,
                state: TaskLifecycleState::Created,
                created_by: operation_id,
                admitted: None,
                started_by: None,
                attempt: None,
                stopped_by: None,
                receipt: None,
            },
        );
        context.accepted(operation_id, binding, TaskLifecycleState::Created)
    }

    fn admit(
        &mut self,
        operation_id: OperationId,
        binding: TaskBinding,
        envelope_json: AdmissionEnvelopeJson,
        proof: IssuerProof,
    ) -> Result<TaskLifecycleState, TaskLifecycleRejectionReason> {
        let Some(admission) = self.admission.as_mut() else {
            return Err(TaskLifecycleRejectionReason::UnsupportedOperation);
        };
        let Some(task) = self.tasks.get_mut(&binding.task()) else {
            return Err(TaskLifecycleRejectionReason::TaskNotFound);
        };
        task.matches(binding)?;
        if let Some(admitted) = &task.admitted
            && admitted.operation_id == operation_id
            && admitted.envelope_json == envelope_json
            && admitted.proof == proof
        {
            return Ok(task.state);
        }
        if task.state != TaskLifecycleState::Created {
            return Err(TaskLifecycleRejectionReason::InvalidState);
        }

        let verified = admission.verify(binding, &envelope_json, &proof)?;
        admission.commit(&verified)?;
        task.state = TaskLifecycleState::Ready;
        task.admitted = Some(AdmittedTask {
            operation_id,
            envelope_json,
            proof,
            verified,
        });
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
                match self.launch(registry, binding, request, &launcher, timeout) {
                    Ok(state) => {
                        if let Some(task) = self.tasks.get_mut(&binding.task()) {
                            task.started_by = Some(operation_id);
                        }
                        context.accepted(operation_id, binding, state)
                    }
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

    fn launch(
        &mut self,
        registry: &SharedRegistry,
        binding: TaskBinding,
        request: LaunchRequest,
        launcher: &Arc<dyn TaskLauncher>,
        spawn_timeout: Duration,
    ) -> Result<TaskLifecycleState, Reason> {
        let stop = StopSignal::default();
        let done = Arc::new(Reaped::default());
        let (spawned_tx, spawned_rx) = sync_channel(1);
        let workspace = request.workspace().to_path_buf();
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
                if spawned_tx.send(Ok(workload.pid())).is_err() {
                    drop(workload);
                    reaper.reaped.set();
                    return;
                }
                let exit = workload.wait(&reaper.stop);
                reaper.record(exit);
            });
        if thread.is_err() {
            discard(&workspace);
            return Err(Reason::ResourceUnavailable);
        }

        let spawned = match spawned_rx.recv_timeout(spawn_timeout) {
            Ok(Ok(pid)) => Some(pid),
            Ok(Err(SpawnError::Refused)) => {
                discard(&workspace);
                return Err(Reason::ResourceUnavailable);
            }
            Ok(Err(SpawnError::Ambiguous))
            | Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => None,
        };
        let task = self
            .tasks
            .get_mut(&binding.task())
            .ok_or(Reason::TaskNotFound)?;
        if spawned.is_none() {
            stop.request();
        }
        task.attempt = Some(Attempt {
            pid: spawned,
            stop,
            stop_requested_by: None,
            reaped: done,
        });
        if spawned.is_some() {
            task.state = TaskLifecycleState::Running;
        } else {
            task.finish(TaskLifecycleState::Exited, TaskExecutionOutcome::Unknown);
        }
        Ok(task.state)
    }

    fn begin_stop(
        &mut self,
        context: TaskLifecycleContext,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> StopStep {
        let refuse =
            |reason| StopStep::Answer(context.rejected(Some(operation_id), binding, reason));
        let Some(execution) = &self.execution else {
            return refuse(Reason::UnsupportedOperation);
        };
        if !supports_task_admission(context.protocol()) {
            return refuse(Reason::UnsupportedOperation);
        }
        let stop_timeout = execution.stop_timeout();
        let Some(task) = self.tasks.get_mut(&binding.task()) else {
            return refuse(Reason::TaskNotFound);
        };
        if let Err(reason) = task.matches(binding) {
            return refuse(reason);
        }
        match task.state {
            TaskLifecycleState::Stopped if task.stopped_by == Some(operation_id) => {
                StopStep::Answer(context.accepted(operation_id, binding, task.state))
            }
            TaskLifecycleState::Ready => {
                task.stopped_by = Some(operation_id);
                task.finish(TaskLifecycleState::Stopped, TaskExecutionOutcome::Failed);
                StopStep::Answer(context.accepted(operation_id, binding, task.state))
            }
            TaskLifecycleState::Running => match task.attempt.as_mut() {
                Some(attempt) => {
                    attempt.stop_requested_by.get_or_insert(operation_id);
                    attempt.stop.request();
                    StopStep::AwaitReap(Arc::clone(&attempt.reaped), stop_timeout)
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
            Some(task)
                if task.state == TaskLifecycleState::Stopped
                    && task.stopped_by == Some(operation_id) =>
            {
                return context.accepted(operation_id, binding, task.state);
            }
            Some(task) if task.state == TaskLifecycleState::Running => Reason::ResourceUnavailable,
            Some(_) | None => Reason::InvalidState,
        };
        context.rejected(Some(operation_id), binding, reason)
    }

    fn record_exit(&mut self, binding: TaskBinding, reaped: &Arc<Reaped>, exit: WorkloadExit) {
        let Some(task) = self
            .tasks
            .get_mut(&binding.task())
            .filter(|task| task.binding == binding && task.state == TaskLifecycleState::Running)
        else {
            return;
        };
        let Some(attempt) = task
            .attempt
            .as_ref()
            .filter(|attempt| Arc::ptr_eq(&attempt.reaped, reaped))
        else {
            return;
        };
        let stop_requested = attempt.stop.is_requested();
        let stop_requested_by = attempt.stop_requested_by;
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
            task.stopped_by = stop_requested_by;
        }
        task.finish(state, outcome);
    }
}

impl Drop for TaskRegistry {
    fn drop(&mut self) {
        let Some(execution) = &self.execution else {
            return;
        };
        let timeout = execution.stop_timeout();
        let running: Vec<Arc<Reaped>> = self
            .tasks
            .values()
            .filter(|task| task.state == TaskLifecycleState::Running)
            .filter_map(|task| task.attempt.as_ref())
            .map(|attempt| {
                attempt.stop.request();
                Arc::clone(&attempt.reaped)
            })
            .collect();
        for reaped in running {
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

impl NodeTask {
    fn matches(&self, binding: TaskBinding) -> Result<(), TaskLifecycleRejectionReason> {
        if self.binding.attempt() != binding.attempt() {
            return Err(TaskLifecycleRejectionReason::AttemptMismatch);
        }
        if self.binding.lease() != binding.lease() {
            return Err(TaskLifecycleRejectionReason::LeaseMismatch);
        }
        Ok(())
    }

    fn finish(&mut self, state: TaskLifecycleState, outcome: TaskExecutionOutcome) {
        self.state = state;
        if let Some(admitted) = &self.admitted {
            self.receipt = Some(
                TaskReceiptContext::new(self.binding, admitted.envelope().session())
                    .receipt(outcome),
            );
        }
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
                );
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
                );
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
            );
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
            assert!(node.registry.is_empty());
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
        use crate::task::{MAX_NODE_TASKS, TaskRegistry};
        use crate::test_support::{
            FAKE_PID, FakeLauncher, FakeSpawn, FakeStop, FixedClock, NOW, envelope_input,
            eventually, lifecycle_binding, node_admission, signed_admit,
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
                let dir = tempfile::tempdir().unwrap();
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
                let tasks = Arc::new(Mutex::new(TaskRegistry::with_execution(
                    MAX_NODE_TASKS,
                    admission,
                    execution,
                )));
                Self {
                    _dir: dir,
                    root,
                    clock,
                    launcher,
                    tasks,
                    snapshot,
                }
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

        #[test]
        fn a_registry_without_execution_refuses_start_and_stop() {
            let dir = tempfile::tempdir().unwrap();
            let clock = FixedClock::at(NOW);
            let tasks = Arc::new(Mutex::new(TaskRegistry::with_admission(
                MAX_NODE_TASKS,
                node_admission(&dir.path().join("state"), &clock),
            )));
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
