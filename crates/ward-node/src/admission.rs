//! Trusted task-lease checks and node-local admission identity.

use thiserror::Error;
use ward_authority::AuthorityLease;
use ward_authority::revocation::{AuthorityRevocations, LeaseLineage};
use ward_events::{AgentId, NodeId, SessionId};
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

/// Immutable typed identity for one node-local task admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskAdmissionIdentity {
    binding: TaskBinding,
    agent: AgentId,
    node: NodeId,
    session: SessionId,
}

impl TaskAdmissionIdentity {
    /// Bind one task attempt and lease to its agent, node audience and Ward session.
    #[must_use]
    pub const fn new(
        binding: TaskBinding,
        agent: AgentId,
        node: NodeId,
        session: SessionId,
    ) -> Self {
        Self {
            binding,
            agent,
            node,
            session,
        }
    }

    /// Exact task / execution-attempt / authority-lease binding.
    #[must_use]
    pub const fn binding(self) -> TaskBinding {
        self.binding
    }

    /// Agent whose authority applies to this admission.
    #[must_use]
    pub const fn agent(self) -> AgentId {
        self.agent
    }

    /// Node audience this admission is local to.
    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }

    /// Ward session this admission is local to.
    #[must_use]
    pub const fn session(self) -> SessionId {
        self.session
    }
}

/// Node-local admission whose already-trusted authority passed the current checks.
///
/// This value is not an authenticated wire envelope and does not make authority
/// permanently usable. Its constructor accepts only an [`AuthorityLease`] and
/// [`LeaseLineage`] the caller has already established as trusted, binds them to one
/// [`TaskAdmissionIdentity`], and checks current revocation/lifetime state.
///
/// A later execution boundary must call [`Self::revalidate`] immediately before using
/// the authority. That catches expiry or revocation that happened after this value was
/// constructed. No lifecycle transition is implied by holding this value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedTaskAdmission {
    identity: TaskAdmissionIdentity,
    lease: AuthorityLease,
    lineage: LeaseLineage,
}

impl TrustedTaskAdmission {
    /// Bind already-trusted authority to one exact node execution identity.
    ///
    /// # Errors
    ///
    /// Returns [`TaskAuthorityError`] when the lease does not match the task/agent or
    /// is not currently usable under its validated lineage and local revocation state.
    pub fn new(
        identity: TaskAdmissionIdentity,
        lease: AuthorityLease,
        lineage: LeaseLineage,
        revocations: &AuthorityRevocations,
        now_unix_ms: u64,
    ) -> Result<Self, TaskAuthorityError> {
        validate_trusted_task_authority(
            identity.binding,
            identity.agent,
            &lease,
            &lineage,
            revocations,
            now_unix_ms,
        )?;

        Ok(Self {
            identity,
            lease,
            lineage,
        })
    }

    /// Exact typed execution identity bound by this admission.
    #[must_use]
    pub const fn identity(&self) -> TaskAdmissionIdentity {
        self.identity
    }

    /// The trusted lease this admission was bound under.
    #[must_use]
    pub const fn lease(&self) -> &AuthorityLease {
        &self.lease
    }

    /// Re-check the retained trusted authority against current time and revocations.
    ///
    /// A successful construction is deliberately not a permanent authorization:
    /// callers must use this immediately before a later authority-exercising transition.
    ///
    /// # Errors
    ///
    /// Returns [`TaskAuthorityError`] if retained authority is no longer usable.
    pub fn revalidate(
        &self,
        revocations: &AuthorityRevocations,
        now_unix_ms: u64,
    ) -> Result<(), TaskAuthorityError> {
        validate_trusted_task_authority(
            self.identity.binding,
            self.identity.agent,
            &self.lease,
            &self.lineage,
            revocations,
            now_unix_ms,
        )
    }
}

/// Check that trusted, currently usable authority covers a task and agent.
///
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
