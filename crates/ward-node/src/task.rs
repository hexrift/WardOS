//! Node-owned task registry for the task lifecycle protocol (#321).
//!
//! This slice binds [`TaskLifecycleRequest`]s to node-owned state. It implements three
//! verbs:
//!
//! * `create` registers a task under its immutable [`TaskBinding`] in the
//!   [`TaskLifecycleState::Created`] state. `Created` means "the node has admitted this
//!   task identity into its registry", nothing more: no process, sandbox, credential or
//!   network authority exists for it. The protocol's `create` carries no workload
//!   description, so there is nothing to execute yet; the workload arrives with
//!   `admit`, and execution belongs to `start`.
//! * `inspect` reports the state the registry actually holds for that binding.
//! * `admit` (protocol 1.3) moves a `Created` task with the exact binding to
//!   [`TaskLifecycleState::Ready`] once [`NodeAdmission`] has verified its signed
//!   envelope and durably recorded its version (ADR-0030 §2). The registry keeps the
//!   admitted envelope and its trusted authority ([`AdmittedTask`]). Replaying the same
//!   operation with the same envelope and proof returns the same `Ready` result; any
//!   refusal leaves the task `Created`. A registry built without admission refuses
//!   `admit` as unsupported. Nothing executes: `Ready` holds no process or sandbox.
//!
//! Every other verb (`start`, `pause`, `resume`, `stop`, `revoke`, `seal`, `stream`) is
//! answered with an explicit [`TaskLifecycleRejectionReason::UnsupportedOperation`] and
//! never changes a task's state. The node does not accept a transition it cannot carry
//! out, and it never reports one as applied.
//!
//! The registry is in memory and bounded by its capacity: a node restart forgets every
//! task (restart recovery is a later #258 slice), and a full registry refuses a new
//! `create` with [`TaskLifecycleRejectionReason::ResourceUnavailable`] rather than
//! growing without limit.
//!
//! The lease id in a binding is recorded and matched exactly. `create` exercises no
//! authority; `admit` binds the lease only through the verified envelope, and the verbs
//! that would use it (`start`, `revoke`) are the ones this slice refuses.

use std::collections::HashMap;

use ward_events::TaskId;
use ward_node_protocol::{
    AdmissionEnvelopeJson, IssuerProof, OperationId, TaskAdmissionEnvelope, TaskBinding,
    TaskLifecycleContext, TaskLifecycleRejectionReason, TaskLifecycleRequest,
    TaskLifecycleResponse, TaskLifecycleState,
};

use crate::admission::TrustedTaskAdmission;
use crate::admit::{NodeAdmission, VerifiedAdmission};

/// Default upper bound on tasks one node registry holds.
pub const MAX_NODE_TASKS: usize = 1024;

#[derive(Clone, Debug)]
struct NodeTask {
    binding: TaskBinding,
    state: TaskLifecycleState,
    created_by: OperationId,
    admitted: Option<AdmittedTask>,
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
}

impl Default for TaskRegistry {
    fn default() -> Self {
        Self::with_capacity(MAX_NODE_TASKS)
    }
}

impl TaskRegistry {
    /// An empty registry that holds at most `capacity` tasks.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            tasks: HashMap::new(),
            capacity,
            admission: None,
        }
    }

    /// An empty registry of at most `capacity` tasks that admits through `admission`.
    #[must_use]
    pub fn with_admission(capacity: usize, admission: NodeAdmission) -> Self {
        Self {
            tasks: HashMap::new(),
            capacity,
            admission: Some(admission),
        }
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
        self.tasks
            .get(&binding.task())
            .filter(|task| task.binding == binding)
            .and_then(|task| task.admitted.as_ref())
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

    /// Apply one decoded lifecycle request and build its response under `context`.
    ///
    /// The request must already have been decoded through `context` (which proves it
    /// names the negotiated protocol).
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
                Ok(state) => context.accepted(operation_id, binding, state),
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
            return context.accepted(operation_id, task.binding, task.state);
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
        match task.matches(binding) {
            Ok(()) => context.inspected(task.binding, task.state),
            Err(reason) => context.rejected(None, binding, reason),
        }
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
