//! Trusted task-lease checks for a future node-owned admission path.

use thiserror::Error;
use ward_authority::AuthorityLease;
use ward_authority::revocation::{AuthorityRevocations, LeaseLineage};
use ward_events::AgentId;
use ward_node_protocol::TaskBinding;

/// Why a trusted lease does not cover the requested task binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum TaskAuthorityError {
    /// The lease belongs to another task.
    #[error("authority lease task does not match the task binding")]
    TaskMismatch,
    /// The binding names another lease.
    #[error("authority lease identity does not match the task binding")]
    LeaseMismatch,
    /// The lease belongs to another agent.
    #[error("authority lease subject does not match the expected agent")]
    AgentMismatch,
    /// The lease is inactive, revoked, conflicted, or has the wrong lineage.
    #[error("task authority is unavailable")]
    AuthorityUnavailable,
}

/// Check that trusted, currently usable authority covers a task and agent.
/// This does not authenticate lease delivery or admit execution. The node must
/// bind the execution attempt separately; it is not part of an authority lease.
///
/// # Errors
///
/// Rejects identity substitution or unavailable authority.
pub fn validate_trusted_task_authority(
    binding: TaskBinding,
    expected_agent: AgentId,
    lease: &AuthorityLease,
    lineage: &LeaseLineage,
    revocations: &AuthorityRevocations,
    now_unix_ms: u64,
) -> Result<(), TaskAuthorityError> {
    if lease.task() != binding.task() {
        return Err(TaskAuthorityError::TaskMismatch);
    }
    if lease.id() != binding.lease() {
        return Err(TaskAuthorityError::LeaseMismatch);
    }
    if lease.subject() != expected_agent {
        return Err(TaskAuthorityError::AgentMismatch);
    }
    if !revocations.is_usable_with_lineage(lease, lineage, now_unix_ms) {
        return Err(TaskAuthorityError::AuthorityUnavailable);
    }
    Ok(())
}
