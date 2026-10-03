//! Node-local trusted task admission contract.

#![allow(clippy::unwrap_used)]

use ward_authority::revocation::{
    AuthorityRevocation, AuthorityRevocations, LeaseLineage, RevocationReason,
};
use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef,
};
use ward_events::{
    AgentId, DelegationId, ExecutionAttemptId, LeaseId, NodeId, PrincipalId, SessionId, TaskId,
};
use ward_node::admission::{TaskAuthorityError, TrustedTaskAdmission};
use ward_node_protocol::TaskBinding;

fn lease() -> AuthorityLease {
    AuthorityLease::root(
        AuthorityLeaseInput {
            id: LeaseId::from_u128(2),
            delegation_id: DelegationId::from_u128(20),
            issuer: PrincipalId::from_u128(30),
            subject: AgentId::from_u128(3),
            task: TaskId::from_u128(1),
            grants: GrantSet::new([CapabilityGrant::new(
                CapabilityName::new("repo.read").unwrap(),
                ResourceRef::new("repo:hexrift/WardOS").unwrap(),
                true,
            )])
            .unwrap(),
            issued_at_unix_ms: 100,
            expires_at_unix_ms: 900,
            version: LeaseVersion::new(1).unwrap(),
        },
        500,
        EmptyAuthorityPolicy::Reject,
    )
    .unwrap()
}

fn binding(task: u128, attempt: u128, lease: u128) -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(task),
        ExecutionAttemptId::from_u128(attempt),
        LeaseId::from_u128(lease),
    )
}

#[test]
fn admission_preserves_the_exact_execution_identity() {
    let lease = lease();
    let lineage = LeaseLineage::for_lease(&lease, []).unwrap();
    let revocations = AuthorityRevocations::new();
    let binding = binding(1, 40, 2);
    let agent = AgentId::from_u128(3);
    let node = NodeId::from_u128(4);
    let session = SessionId::from_u128(5);

    let admission = TrustedTaskAdmission::new(
        binding,
        agent,
        node,
        session,
        lease,
        lineage,
        &revocations,
        500,
    )
    .unwrap();

    assert_eq!(admission.binding(), binding);
    assert_eq!(admission.agent(), agent);
    assert_eq!(admission.node(), node);
    assert_eq!(admission.session(), session);
}

#[test]
fn admission_reuses_the_existing_fail_closed_authority_predicate() {
    let revocations = AuthorityRevocations::new();

    for (binding, agent, expected) in [
        (
            binding(9, 40, 2),
            AgentId::from_u128(3),
            TaskAuthorityError::TaskMismatch,
        ),
        (
            binding(1, 40, 9),
            AgentId::from_u128(3),
            TaskAuthorityError::LeaseMismatch,
        ),
        (
            binding(1, 40, 2),
            AgentId::from_u128(9),
            TaskAuthorityError::AgentMismatch,
        ),
    ] {
        let lease = lease();
        let lineage = LeaseLineage::for_lease(&lease, []).unwrap();

        assert_eq!(
            TrustedTaskAdmission::new(
                binding,
                agent,
                NodeId::from_u128(4),
                SessionId::from_u128(5),
                lease,
                lineage,
                &revocations,
                500,
            ),
            Err(expected)
        );
    }
}

#[test]
fn admitted_authority_is_revalidated_for_expiry_and_later_revocation() {
    let lease = lease();
    let lineage = LeaseLineage::for_lease(&lease, []).unwrap();
    let mut revocations = AuthorityRevocations::new();

    let admission = TrustedTaskAdmission::new(
        binding(1, 40, 2),
        AgentId::from_u128(3),
        NodeId::from_u128(4),
        SessionId::from_u128(5),
        lease,
        lineage,
        &revocations,
        500,
    )
    .unwrap();

    assert_eq!(admission.revalidate(&revocations, 500), Ok(()));
    assert_eq!(
        admission.revalidate(&revocations, 900),
        Err(TaskAuthorityError::AuthorityUnavailable)
    );

    revocations
        .record(AuthorityRevocation::new(
            LeaseId::from_u128(2),
            550,
            RevocationReason::Operator,
        ))
        .unwrap();
    assert_eq!(
        admission.revalidate(&revocations, 600),
        Err(TaskAuthorityError::AuthorityUnavailable)
    );
}
