use ward_authority::revocation::{
    AuthorityRevocation, AuthorityRevocations, LeaseLineage, RevocationReason,
};
use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, DelegationInput,
    EmptyAuthorityPolicy, GrantSet, LeaseVersion, ResourceRef,
};
use ward_events::{AgentId, DelegationId, ExecutionAttemptId, LeaseId, PrincipalId, TaskId};
use ward_node::admission::{TaskAuthorityError, validate_trusted_task_authority};
use ward_node_protocol::TaskBinding;

fn root(task: u128, lease: u128, agent: u128) -> AuthorityLease {
    AuthorityLease::root(
        AuthorityLeaseInput {
            id: LeaseId::from_u128(lease),
            delegation_id: DelegationId::from_u128(20),
            issuer: PrincipalId::from_u128(30),
            subject: AgentId::from_u128(agent),
            task: TaskId::from_u128(task),
            grants: GrantSet::new([CapabilityGrant::new(
                CapabilityName::new("repo.read").unwrap(),
                ResourceRef::new("repo:example").unwrap(),
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

fn binding(task: u128, lease: u128) -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(task),
        ExecutionAttemptId::from_u128(40),
        LeaseId::from_u128(lease),
    )
}

#[test]
fn exact_trusted_root_and_delegated_lease_are_usable() {
    let root = root(1, 2, 3);
    let root_lineage = LeaseLineage::for_lease(&root, []).unwrap();
    let revocations = AuthorityRevocations::new();
    assert_eq!(
        validate_trusted_task_authority(
            binding(1, 2),
            AgentId::from_u128(3),
            &root,
            &root_lineage,
            &revocations,
            500,
        ),
        Ok(())
    );

    let child = root
        .delegate(
            DelegationInput {
                id: LeaseId::from_u128(4),
                delegation_id: DelegationId::from_u128(5),
                subject: AgentId::from_u128(6),
                task: root.task(),
                grants: root.grants().clone(),
                issued_at_unix_ms: 200,
                expires_at_unix_ms: 800,
                version: LeaseVersion::new(2).unwrap(),
            },
            500,
            EmptyAuthorityPolicy::Reject,
        )
        .unwrap();
    let lineage = LeaseLineage::for_lease(&child, [&root]).unwrap();
    assert_eq!(
        validate_trusted_task_authority(
            binding(1, 4),
            AgentId::from_u128(6),
            &child,
            &lineage,
            &revocations,
            500,
        ),
        Ok(())
    );
}

#[test]
fn task_lease_agent_and_lineage_substitution_fail_closed() {
    let lease = root(1, 2, 3);
    let lineage = LeaseLineage::for_lease(&lease, []).unwrap();
    let other_lineage = LeaseLineage::for_lease(&root(9, 8, 3), []).unwrap();
    let revocations = AuthorityRevocations::new();

    for (binding, agent, lineage, expected) in [
        (
            binding(9, 2),
            AgentId::from_u128(3),
            &lineage,
            TaskAuthorityError::TaskMismatch,
        ),
        (
            binding(1, 8),
            AgentId::from_u128(3),
            &lineage,
            TaskAuthorityError::LeaseMismatch,
        ),
        (
            binding(1, 2),
            AgentId::from_u128(9),
            &lineage,
            TaskAuthorityError::AgentMismatch,
        ),
        (
            binding(1, 2),
            AgentId::from_u128(3),
            &other_lineage,
            TaskAuthorityError::AuthorityUnavailable,
        ),
    ] {
        assert_eq!(
            validate_trusted_task_authority(binding, agent, &lease, lineage, &revocations, 500),
            Err(expected)
        );
    }
}

#[test]
fn inactive_revoked_and_conflicted_authority_fail_closed() {
    let lease = root(1, 2, 3);
    let lineage = LeaseLineage::for_lease(&lease, []).unwrap();
    let mut revocations = AuthorityRevocations::new();
    for now in [99, 900] {
        assert_eq!(
            validate_trusted_task_authority(
                binding(1, 2),
                lease.subject(),
                &lease,
                &lineage,
                &revocations,
                now
            ),
            Err(TaskAuthorityError::AuthorityUnavailable)
        );
    }

    revocations
        .record(AuthorityRevocation::new(
            lease.id(),
            400,
            RevocationReason::Operator,
        ))
        .unwrap();
    assert_eq!(
        validate_trusted_task_authority(
            binding(1, 2),
            lease.subject(),
            &lease,
            &lineage,
            &revocations,
            500
        ),
        Err(TaskAuthorityError::AuthorityUnavailable)
    );

    let parent = root(7, 8, 9);
    let child = parent
        .delegate(
            DelegationInput {
                id: LeaseId::from_u128(10),
                delegation_id: DelegationId::from_u128(11),
                subject: AgentId::from_u128(12),
                task: parent.task(),
                grants: parent.grants().clone(),
                issued_at_unix_ms: 200,
                expires_at_unix_ms: 800,
                version: LeaseVersion::new(2).unwrap(),
            },
            500,
            EmptyAuthorityPolicy::Reject,
        )
        .unwrap();
    let child_lineage = LeaseLineage::for_lease(&child, [&parent]).unwrap();
    revocations
        .record(AuthorityRevocation::new(
            parent.id(),
            400,
            RevocationReason::Operator,
        ))
        .unwrap();
    assert_eq!(
        validate_trusted_task_authority(
            binding(7, 10),
            child.subject(),
            &child,
            &child_lineage,
            &revocations,
            500
        ),
        Err(TaskAuthorityError::AuthorityUnavailable)
    );

    let mut conflict = AuthorityRevocations::new();
    conflict
        .record(AuthorityRevocation::new(
            parent.id(),
            700,
            RevocationReason::Operator,
        ))
        .unwrap();
    assert!(
        conflict
            .record(AuthorityRevocation::new(
                parent.id(),
                700,
                RevocationReason::Policy
            ))
            .is_err()
    );
    assert_eq!(
        validate_trusted_task_authority(
            binding(7, 10),
            child.subject(),
            &child,
            &child_lineage,
            &conflict,
            500
        ),
        Err(TaskAuthorityError::AuthorityUnavailable)
    );
}
