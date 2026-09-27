//! Monotonic authority revocation semantics.
//!
//! Revocation is an explicit trusted fact. Process lifetime, provider state and control-plane
//! reachability do not create or remove revocation.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use thiserror::Error;
use ward_events::LeaseId;

use crate::AuthorityLease;

/// Stable reason attached to a trusted revocation fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// An authorised operator withdrew the lease.
    Operator,
    /// Policy withdrew the lease.
    Policy,
    /// An ancestor delegation was withdrawn.
    DelegationRevoked,
    /// Security response withdrew the lease.
    Security,
}

/// One trusted, immutable revocation fact.
///
/// This type is intentionally not deserializable from arbitrary wire data. Remote
/// authenticity and signed revocation delivery belong to later transport slices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AuthorityRevocation {
    lease_id: LeaseId,
    revoked_at_unix_ms: u64,
    reason: RevocationReason,
}

impl AuthorityRevocation {
    /// Construct a trusted revocation fact.
    #[must_use]
    pub const fn new(
        lease_id: LeaseId,
        revoked_at_unix_ms: u64,
        reason: RevocationReason,
    ) -> Self {
        Self {
            lease_id,
            revoked_at_unix_ms,
            reason,
        }
    }

    /// Revoked lease identity.
    #[must_use]
    pub const fn lease_id(self) -> LeaseId {
        self.lease_id
    }

    /// Inclusive effective instant in Unix milliseconds.
    #[must_use]
    pub const fn revoked_at_unix_ms(self) -> u64 {
        self.revoked_at_unix_ms
    }

    /// Stable revocation reason.
    #[must_use]
    pub const fn reason(self) -> RevocationReason {
        self.reason
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RevocationState {
    Known(AuthorityRevocation),
    Conflict,
}

/// Trusted lineage context for evaluating inherited revocation.
///
/// Ancestors are ordered nearest-parent first. The lineage is not deserializable: a trusted
/// application/control-plane component must build it from known delegation state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseLineage {
    lease_id: LeaseId,
    ancestors: Vec<LeaseId>,
}

impl LeaseLineage {
    /// Construct lineage for one trusted lease.
    ///
    /// # Errors
    ///
    /// Rejects a missing/wrong direct parent, ancestors on a root lease, the current lease
    /// appearing among its own ancestors, or duplicate ancestor IDs.
    pub fn for_lease(
        lease: &AuthorityLease,
        ancestors: impl IntoIterator<Item = LeaseId>,
    ) -> Result<Self, LeaseLineageError> {
        let ancestors: Vec<_> = ancestors.into_iter().collect();

        match lease.parent_lease_id() {
            None if !ancestors.is_empty() => {
                return Err(LeaseLineageError::UnexpectedAncestorsForRoot);
            }
            Some(parent) if ancestors.first().copied() != Some(parent) => {
                return Err(LeaseLineageError::DirectParentMismatch);
            }
            None | Some(_) => {}
        }

        let mut seen = BTreeSet::new();
        for ancestor in &ancestors {
            if *ancestor == lease.id() {
                return Err(LeaseLineageError::CurrentLeaseInAncestors);
            }
            if !seen.insert(*ancestor) {
                return Err(LeaseLineageError::DuplicateAncestor);
            }
        }

        Ok(Self {
            lease_id: lease.id(),
            ancestors,
        })
    }

    /// Lease identity this lineage belongs to.
    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    /// Ancestors ordered nearest-parent first.
    #[must_use]
    pub fn ancestors(&self) -> &[LeaseId] {
        &self.ancestors
    }
}

/// Invalid trusted lineage context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum LeaseLineageError {
    /// A root lease cannot have ancestors.
    #[error("root authority lease cannot have ancestors")]
    UnexpectedAncestorsForRoot,
    /// The first ancestor must be the lease's recorded parent.
    #[error("authority lineage direct parent does not match lease")]
    DirectParentMismatch,
    /// A lease cannot appear in its own ancestor set.
    #[error("authority lineage contains the current lease")]
    CurrentLeaseInAncestors,
    /// Ancestor identities must be unique.
    #[error("authority lineage contains a duplicate ancestor")]
    DuplicateAncestor,
}

/// Monotonic in-memory reference set of known lease revocations.
///
/// There is deliberately no remove/unrevoke operation.
#[derive(Clone, Debug, Default)]
pub struct AuthorityRevocations {
    by_lease: BTreeMap<LeaseId, RevocationState>,
}

impl AuthorityRevocations {
    /// Create an empty revocation set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            by_lease: BTreeMap::new(),
        }
    }

    /// Record one trusted revocation fact.
    ///
    /// Replaying the exact same fact is idempotent. A different fact for the same lease
    /// irreversibly marks that lease conflicted and therefore unusable.
    ///
    /// # Errors
    ///
    /// Returns a conflict error when the same lease already has a different fact or
    /// has previously entered the conflicted state.
    pub fn record(
        &mut self,
        revocation: AuthorityRevocation,
    ) -> Result<(), AuthorityRevocationError> {
        match self.by_lease.get(&revocation.lease_id).copied() {
            None => {
                self.by_lease
                    .insert(revocation.lease_id, RevocationState::Known(revocation));
                Ok(())
            }
            Some(RevocationState::Known(existing)) if existing == revocation => Ok(()),
            Some(RevocationState::Known(_)) | Some(RevocationState::Conflict) => {
                self.by_lease
                    .insert(revocation.lease_id, RevocationState::Conflict);
                Err(AuthorityRevocationError::RevocationConflict)
            }
        }
    }

    /// Whether one lease is usable at an instant under locally known revocation facts.
    ///
    /// Expiry and direct revocation independently deny authority. A conflicted revocation
    /// record also denies authority immediately.
    #[must_use]
    pub fn is_usable(&self, lease: &AuthorityLease, now_unix_ms: u64) -> bool {
        lease.is_active_at(now_unix_ms) && self.id_is_unrevoked(lease.id(), now_unix_ms)
    }

    /// Whether one lease is usable after applying direct and inherited revocation.
    ///
    /// The trusted lineage must belong to this lease. Any effective/conflicted ancestor
    /// revocation denies the child even when the child itself remains active and unrevoked.
    #[must_use]
    pub fn is_usable_with_lineage(
        &self,
        lease: &AuthorityLease,
        lineage: &LeaseLineage,
        now_unix_ms: u64,
    ) -> bool {
        if lineage.lease_id != lease.id() || !self.is_usable(lease, now_unix_ms) {
            return false;
        }

        lineage
            .ancestors
            .iter()
            .all(|ancestor| self.id_is_unrevoked(*ancestor, now_unix_ms))
    }

    /// Whether this lease has an explicit revocation conflict.
    #[must_use]
    pub fn is_conflicted(&self, lease_id: LeaseId) -> bool {
        matches!(
            self.by_lease.get(&lease_id),
            Some(RevocationState::Conflict)
        )
    }

    fn id_is_unrevoked(&self, lease_id: LeaseId, now_unix_ms: u64) -> bool {
        match self.by_lease.get(&lease_id) {
            None => true,
            Some(RevocationState::Known(revocation)) => {
                now_unix_ms < revocation.revoked_at_unix_ms
            }
            Some(RevocationState::Conflict) => false,
        }
    }
}

/// Revocation state update failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum AuthorityRevocationError {
    /// Two distinct facts claim to revoke the same lease.
    #[error("conflicting revocation facts for one authority lease")]
    RevocationConflict,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::{
        AuthorityLeaseInput, DelegationInput, EmptyAuthorityPolicy, GrantSet, LeaseVersion,
    };
    use ward_events::{AgentId, DelegationId, PrincipalId, TaskId};

    fn root(id: u128) -> AuthorityLease {
        AuthorityLease::root(
            AuthorityLeaseInput {
                id: LeaseId::from_u128(id),
                delegation_id: DelegationId::from_u128(id + 100),
                issuer: PrincipalId::from_u128(9),
                subject: AgentId::from_u128(id + 200),
                task: TaskId::from_u128(11),
                grants: GrantSet::new([]).unwrap(),
                issued_at_unix_ms: 100,
                expires_at_unix_ms: 1_000,
                version: LeaseVersion::new(1).unwrap(),
            },
            500,
            EmptyAuthorityPolicy::Allow,
        )
        .unwrap()
    }

    fn child(parent: &AuthorityLease) -> AuthorityLease {
        parent
            .delegate(
                DelegationInput {
                    id: LeaseId::from_u128(2),
                    delegation_id: DelegationId::from_u128(102),
                    subject: AgentId::from_u128(202),
                    task: parent.task(),
                    grants: GrantSet::new([]).unwrap(),
                    issued_at_unix_ms: 200,
                    expires_at_unix_ms: 900,
                    version: LeaseVersion::new(2).unwrap(),
                },
                500,
                EmptyAuthorityPolicy::Allow,
            )
            .unwrap()
    }

    #[test]
    fn active_unrevoked_lease_is_usable_and_expiry_denies_independently() {
        let revocations = AuthorityRevocations::new();
        let lease = root(7);

        assert!(revocations.is_usable(&lease, 100));
        assert!(revocations.is_usable(&lease, 999));
        assert!(!revocations.is_usable(&lease, 1_000));
    }

    #[test]
    fn revocation_becomes_effective_at_its_instant() {
        let lease = root(7);
        let mut revocations = AuthorityRevocations::new();
        revocations
            .record(AuthorityRevocation::new(
                lease.id(),
                500,
                RevocationReason::Policy,
            ))
            .unwrap();

        assert!(revocations.is_usable(&lease, 499));
        assert!(!revocations.is_usable(&lease, 500));
        assert!(!revocations.is_usable(&lease, 999));
    }

    #[test]
    fn exact_duplicate_is_idempotent_and_there_is_no_unrevoke_path() {
        let lease = root(7);
        let revocation =
            AuthorityRevocation::new(lease.id(), 500, RevocationReason::Operator);
        let mut revocations = AuthorityRevocations::new();

        assert_eq!(revocations.record(revocation), Ok(()));
        assert_eq!(revocations.record(revocation), Ok(()));
        assert!(!revocations.is_conflicted(lease.id()));
        assert!(!revocations.is_usable(&lease, 500));
        assert!(!revocations.is_usable(&lease, 900));
    }

    #[test]
    fn conflicting_fact_irreversibly_fails_closed() {
        let lease = root(7);
        let first = AuthorityRevocation::new(lease.id(), 900, RevocationReason::Operator);
        let conflict = AuthorityRevocation::new(lease.id(), 700, RevocationReason::Security);
        let mut revocations = AuthorityRevocations::new();

        revocations.record(first).unwrap();
        assert!(revocations.is_usable(&lease, 600));

        assert_eq!(
            revocations.record(conflict),
            Err(AuthorityRevocationError::RevocationConflict)
        );
        assert!(revocations.is_conflicted(lease.id()));
        assert!(!revocations.is_usable(&lease, 600));
        assert_eq!(
            revocations.record(first),
            Err(AuthorityRevocationError::RevocationConflict)
        );
    }

    #[test]
    fn ancestor_revocation_denies_an_otherwise_active_child() {
        let parent = root(1);
        let child = child(&parent);
        let lineage = LeaseLineage::for_lease(&child, [parent.id()]).unwrap();
        let mut revocations = AuthorityRevocations::new();

        revocations
            .record(AuthorityRevocation::new(
                parent.id(),
                600,
                RevocationReason::DelegationRevoked,
            ))
            .unwrap();

        assert!(revocations.is_usable(&child, 599));
        assert!(revocations.is_usable_with_lineage(&child, &lineage, 599));
        assert!(revocations.is_usable(&child, 600));
        assert!(!revocations.is_usable_with_lineage(&child, &lineage, 600));
    }

    #[test]
    fn lineage_rejects_missing_wrong_duplicate_or_self_ancestors() {
        let parent = root(1);
        let child = child(&parent);

        assert_eq!(
            LeaseLineage::for_lease(&child, []),
            Err(LeaseLineageError::DirectParentMismatch)
        );
        assert_eq!(
            LeaseLineage::for_lease(&child, [LeaseId::from_u128(99)]),
            Err(LeaseLineageError::DirectParentMismatch)
        );
        assert_eq!(
            LeaseLineage::for_lease(&child, [parent.id(), parent.id()]),
            Err(LeaseLineageError::DuplicateAncestor)
        );
        assert_eq!(
            LeaseLineage::for_lease(&child, [parent.id(), child.id()]),
            Err(LeaseLineageError::CurrentLeaseInAncestors)
        );
        assert_eq!(
            LeaseLineage::for_lease(&parent, [child.id()]),
            Err(LeaseLineageError::UnexpectedAncestorsForRoot)
        );
    }

    #[test]
    fn lineage_context_cannot_be_reused_for_another_lease() {
        let parent = root(1);
        let child = child(&parent);
        let other = root(20);
        let lineage = LeaseLineage::for_lease(&child, [parent.id()]).unwrap();
        let revocations = AuthorityRevocations::new();

        assert!(!revocations.is_usable_with_lineage(&other, &lineage, 500));
    }

    #[test]
    fn revocation_fact_has_stable_json_without_wire_trust_conversion() {
        let fact = AuthorityRevocation::new(
            LeaseId::from_u128(7),
            500,
            RevocationReason::DelegationRevoked,
        );

        assert_eq!(
            serde_json::to_string(&fact).unwrap(),
            r#"{"lease_id":"lease_00000000000000000000000007","revoked_at_unix_ms":500,"reason":"delegation_revoked"}"#
        );
    }
}
