//! Node-owned task registry for the task lifecycle protocol (#321).
//!
//! This is the first slice binding [`TaskLifecycleRequest`]s to node-owned state. It
//! implements exactly two verbs:
//!
//! * `create` registers a task under its immutable [`TaskBinding`] in the
//!   [`TaskLifecycleState::Created`] state. `Created` means "the node has admitted this
//!   task identity into its registry", nothing more: no process, sandbox, credential or
//!   network authority exists for it. The protocol's `create` carries no workload
//!   description, so there is nothing to execute yet; the workload and the execution
//!   binding belong to `start`.
//! * `inspect` reports the state the registry actually holds for that binding.
//!
//! Every other verb (`admit`, `start`, `pause`, `resume`, `stop`, `revoke`, `seal`,
//! `stream`) is answered with an explicit
//! [`TaskLifecycleRejectionReason::UnsupportedOperation`] and never changes a task's
//! state. `admit` (protocol 1.3) stays refused until the node verifies the issuer proof
//! and the durable version and revocation stores exist (ADR-0030). The node does not accept a transition it cannot carry
//! out, and it never reports one as applied.
//!
//! The registry is in memory and bounded by its capacity: a node restart forgets every
//! task (restart recovery is a later #258 slice), and a full registry refuses a new
//! `create` with [`TaskLifecycleRejectionReason::ResourceUnavailable`] rather than
//! growing without limit.
//!
//! The lease id in a binding is recorded and matched exactly, but it is not yet checked
//! against an authority lease store: `create` exercises no authority, and the verbs that
//! would (`start`, `revoke`) are the ones this slice refuses.

use std::collections::HashMap;

use ward_events::TaskId;
use ward_node_protocol::{
    OperationId, TaskBinding, TaskLifecycleContext, TaskLifecycleRejectionReason,
    TaskLifecycleRequest, TaskLifecycleResponse, TaskLifecycleState,
};

/// Default upper bound on tasks one node registry holds.
pub const MAX_NODE_TASKS: usize = 1024;

#[derive(Clone, Copy, Debug)]
struct NodeTask {
    binding: TaskBinding,
    state: TaskLifecycleState,
    created_by: OperationId,
}

/// In-memory, bounded registry of node-owned tasks keyed by task identity.
#[derive(Debug)]
pub struct TaskRegistry {
    tasks: HashMap<TaskId, NodeTask>,
    capacity: usize,
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
        }
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
                ..
            }
            | TaskLifecycleRequest::Start {
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

        let task = NodeTask {
            binding,
            state: TaskLifecycleState::Created,
            created_by: operation_id,
        };
        self.tasks.insert(binding.task(), task);
        context.accepted(operation_id, task.binding, task.state)
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
