//! Monotonic authority revocation semantics.

use std::collections::BTreeMap;

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

/// Monotonic in-memory reference set of known lease revocations.
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
    /// Returns RevocationConflict when the same lease already has a different fact or
    /// is already conflicted.
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

    /// Whether a lease may be used at one instant under all locally known revocation facts.
    ///
    /// Expiry and revocation independently deny authority. A conflicted revocation record
    /// also denies authority immediately.
    #[must_use]
    pub fn is_usable(&self, lease: &AuthorityLease, now_unix_ms: u64) -> bool {
        if !lease.is_active_at(now_unix_ms) {
            return false;
        }

        match self.by_lease.get(&lease.id()) {
            None => true,
            Some(RevocationState::Known(revocation)) => {
                now_unix_ms < revocation.revoked_at_unix_ms
            }
            Some(RevocationState::Conflict) => false,
        }
    }

    /// Whether this lease has an explicit revocation conflict.
    #[must_use]
    pub fn is_conflicted(&self, lease_id: LeaseId) -> bool {
        matches!(
            self.by_lease.get(&lease_id),
            Some(RevocationState::Conflict)
        )
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
        AuthorityLeaseInput, GrantSet, LeaseVersion,
    };
    use ward_events::{AgentId, DelegationId, PrincipalId, TaskId};

    fn lease() -> AuthorityLease {
        AuthorityLease::root(AuthorityLeaseInput {
            id: LeaseId::from_u128(7),
            delegation_id: DelegationId::from_u128(8),
            issuer: PrincipalId::from_u128(9),
            subject: AgentId::from_u128(10),
            task: TaskId::from_u128(11),
            grants: GrantSet::new([]).unwrap(),
            issued_at_unix_ms: 100,
            expires_at_unix_ms: 1_000,
            version: LeaseVersion::new(1).unwrap(),
        })
        .unwrap()
    }

    #[test]
    fn active_unrevoked_lease_is_usable_and_expiry_denies_independently() {
        let revocations = AuthorityRevocations::new();
        let lease = lease();

        assert!(revocations.is_usable(&lease, 100));
        assert!(revocations.is_usable(&lease, 999));
        assert!(!revocations.is_usable(&lease, 1_000));
    }

    #[test]
    fn revocation_becomes_effective_at_its_instant() {
        let lease = lease();
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
    fn exact_duplicate_is_idempotent() {
        let lease = lease();
        let revocation =
            AuthorityRevocation::new(lease.id(), 500, RevocationReason::Operator);
        let mut revocations = AuthorityRevocations::new();

        assert_eq!(revocations.record(revocation), Ok(()));
        assert_eq!(revocations.record(revocation), Ok(()));
        assert!(!revocations.is_conflicted(lease.id()));
        assert!(!revocations.is_usable(&lease, 500));
    }

    #[test]
    fn conflicting_fact_irreversibly_fails_closed() {
        let lease = lease();
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
