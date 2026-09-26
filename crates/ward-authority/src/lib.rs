//! Task-bound delegated authority leases.
//!
//! Authority is explicit data. Process lifetime, model identity and provider metadata do
//! not grant capabilities.

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use ward_events::{AgentId, DelegationId, LeaseId, PrincipalId, TaskId};

    fn root() -> AuthorityLease {
        AuthorityLease::root(AuthorityLeaseInput {
            id: LeaseId::from_u128(1),
            delegation_id: DelegationId::from_u128(1),
            issuer: PrincipalId::from_u128(1),
            subject: AgentId::from_u128(1),
            task: TaskId::from_u128(1),
            grants: GrantSet::new([
                CapabilityGrant::new(
                    CapabilityName::new("repo.read").unwrap(),
                    ResourceRef::new("repo:hexrift/WardOS").unwrap(),
                    true,
                ),
                CapabilityGrant::new(
                    CapabilityName::new("network.fetch").unwrap(),
                    ResourceRef::new("host:api.github.com").unwrap(),
                    false,
                ),
            ])
            .unwrap(),
            issued_at_unix_ms: 100,
            expires_at_unix_ms: 1_000,
            version: LeaseVersion::new(1).unwrap(),
        })
        .unwrap()
    }

    #[test]
    fn lease_lifetime_is_bounded_and_active_only_inside_interval() {
        let lease = root();

        assert!(!lease.is_active_at(99));
        assert!(lease.is_active_at(100));
        assert!(lease.is_active_at(999));
        assert!(!lease.is_active_at(1_000));

        let mut input = lease.to_input();
        input.expires_at_unix_ms = input.issued_at_unix_ms;
        assert_eq!(
            AuthorityLease::root(input),
            Err(AuthorityLeaseError::InvalidLifetime)
        );
    }

    #[test]
    fn child_delegation_can_only_contract_delegable_authority() {
        let parent = root();
        let child_grants = GrantSet::new([CapabilityGrant::new(
            CapabilityName::new("repo.read").unwrap(),
            ResourceRef::new("repo:hexrift/WardOS").unwrap(),
            false,
        )])
        .unwrap();

        let child = parent
            .delegate(DelegationInput {
                id: LeaseId::from_u128(2),
                delegation_id: DelegationId::from_u128(2),
                subject: AgentId::from_u128(2),
                task: parent.task(),
                grants: child_grants,
                issued_at_unix_ms: 200,
                expires_at_unix_ms: 900,
                version: LeaseVersion::new(2).unwrap(),
            })
            .unwrap();

        assert_eq!(child.parent_lease_id(), Some(parent.id()));
        assert_eq!(child.delegated_by(), Some(parent.subject()));
        assert_eq!(child.issuer(), parent.issuer());
        assert_eq!(child.task(), parent.task());
    }

    #[test]
    fn widening_non_delegable_or_cross_task_delegation_fails_closed() {
        let parent = root();

        let cases = [
            (
                GrantSet::new([CapabilityGrant::new(
                    CapabilityName::new("repo.write").unwrap(),
                    ResourceRef::new("repo:hexrift/WardOS").unwrap(),
                    false,
                )])
                .unwrap(),
                parent.task(),
                AuthorityLeaseError::AuthorityWidening,
            ),
            (
                GrantSet::new([CapabilityGrant::new(
                    CapabilityName::new("network.fetch").unwrap(),
                    ResourceRef::new("host:api.github.com").unwrap(),
                    false,
                )])
                .unwrap(),
                parent.task(),
                AuthorityLeaseError::GrantNotDelegable,
            ),
            (
                GrantSet::new([]).unwrap(),
                TaskId::from_u128(99),
                AuthorityLeaseError::TaskMismatch,
            ),
        ];

        for (grants, task, expected) in cases {
            assert_eq!(
                parent.delegate(DelegationInput {
                    id: LeaseId::from_u128(2),
                    delegation_id: DelegationId::from_u128(2),
                    subject: AgentId::from_u128(2),
                    task,
                    grants,
                    issued_at_unix_ms: 200,
                    expires_at_unix_ms: 900,
                    version: LeaseVersion::new(2).unwrap(),
                }),
                Err(expected)
            );
        }
    }

    #[test]
    fn child_lifetime_and_version_must_contract_parent() {
        let parent = root();
        let grants = GrantSet::new([]).unwrap();

        for (issued, expires, version, expected) in [
            (99, 900, 2, AuthorityLeaseError::LifetimeOutsideParent),
            (200, 1_001, 2, AuthorityLeaseError::LifetimeOutsideParent),
            (200, 900, 1, AuthorityLeaseError::NonIncreasingVersion),
        ] {
            assert_eq!(
                parent.delegate(DelegationInput {
                    id: LeaseId::from_u128(2),
                    delegation_id: DelegationId::from_u128(2),
                    subject: AgentId::from_u128(2),
                    task: parent.task(),
                    grants: grants.clone(),
                    issued_at_unix_ms: issued,
                    expires_at_unix_ms: expires,
                    version: LeaseVersion::new(version).unwrap(),
                }),
                Err(expected)
            );
        }
    }

    #[test]
    fn grants_are_bounded_canonical_and_unambiguous() {
        assert!(CapabilityName::new("repo.read").is_ok());
        assert!(CapabilityName::new("Repo Read").is_err());
        assert!(ResourceRef::new("repo:hexrift/WardOS").is_ok());
        assert!(ResourceRef::new("has space").is_err());

        let grant = CapabilityGrant::new(
            CapabilityName::new("repo.read").unwrap(),
            ResourceRef::new("repo:hexrift/WardOS").unwrap(),
            true,
        );
        assert_eq!(
            GrantSet::new([grant.clone(), grant]),
            Err(GrantSetError::DuplicateGrant)
        );
    }

    #[test]
    fn authority_envelope_has_stable_complete_json() {
        let lease = root();
        let json = serde_json::to_string(&lease).unwrap();

        assert_eq!(
            json,
            r#"{"id":"lease_00000000000000000000000001","delegation_id":"deleg_00000000000000000000000001","issuer":"prn_00000000000000000000000001","subject":"agent_00000000000000000000000001","task":"task_00000000000000000000000001","parent_lease_id":null,"delegated_by":null,"grants":[{"capability":"network.fetch","resource":"host:api.github.com","delegable":false},{"capability":"repo.read","resource":"repo:hexrift/WardOS","delegable":true}],"issued_at_unix_ms":100,"expires_at_unix_ms":1000,"version":1}"#
        );
        assert_eq!(serde_json::from_str::<AuthorityLease>(&json).unwrap(), lease);

        let mut value = serde_json::from_str::<serde_json::Value>(&json).unwrap();
        value["provider"] = serde_json::Value::String("model".into());
        assert!(serde_json::from_value::<AuthorityLease>(value).is_err());
    }
}
