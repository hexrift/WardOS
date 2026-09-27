//! Task-bound delegated authority leases.
//!
//! Authority is explicit data. Process lifetime, model identity and provider metadata do
//! not grant capabilities.

#![forbid(unsafe_code)]

pub mod revocation;

use std::num::NonZeroU64;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use ward_events::{AgentId, DelegationId, LeaseId, PrincipalId, TaskId};

/// Maximum bytes in a capability name.
const MAX_CAPABILITY_BYTES: usize = 64;
/// Maximum bytes in a resource reference.
const MAX_RESOURCE_BYTES: usize = 256;

/// A bounded capability name such as repo.read.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CapabilityName(String);

impl CapabilityName {
    /// Construct a validated capability name.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, or non-canonical names.
    pub fn new(value: &str) -> Result<Self, AuthorityTextError> {
        if value.is_empty()
            || value.len() > MAX_CAPABILITY_BYTES
            || !value
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(AuthorityTextError);
        }

        Ok(Self(value.to_owned()))
    }

    /// Canonical capability text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CapabilityName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(&value).map_err(D::Error::custom)
    }
}

/// A bounded exact resource reference.
///
/// This first authority slice intentionally does not invent a resource hierarchy:
/// contraction is exact capability/resource set inclusion.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ResourceRef(String);

impl ResourceRef {
    /// Construct a validated resource reference.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, whitespace-containing or control text.
    pub fn new(value: &str) -> Result<Self, AuthorityTextError> {
        if value.is_empty()
            || value.len() > MAX_RESOURCE_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| !byte.is_ascii_graphic())
        {
            return Err(AuthorityTextError);
        }

        Ok(Self(value.to_owned()))
    }

    /// Exact resource text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ResourceRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(&value).map_err(D::Error::custom)
    }
}

/// Invalid bounded authority text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("authority text is invalid")]
pub struct AuthorityTextError;

/// One exact capability/resource grant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrant {
    capability: CapabilityName,
    resource: ResourceRef,
    delegable: bool,
}

impl CapabilityGrant {
    /// Construct one exact grant.
    #[must_use]
    pub const fn new(capability: CapabilityName, resource: ResourceRef, delegable: bool) -> Self {
        Self {
            capability,
            resource,
            delegable,
        }
    }

    /// Capability name.
    #[must_use]
    pub fn capability(&self) -> &CapabilityName {
        &self.capability
    }

    /// Exact resource reference.
    #[must_use]
    pub fn resource(&self) -> &ResourceRef {
        &self.resource
    }

    /// Whether a child lease may receive this grant.
    #[must_use]
    pub const fn delegable(&self) -> bool {
        self.delegable
    }

    fn same_scope(&self, other: &Self) -> bool {
        self.capability == other.capability && self.resource == other.resource
    }
}

/// Canonical exact grant set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct GrantSet(Vec<CapabilityGrant>);

impl GrantSet {
    /// Construct a canonical grant set.
    ///
    /// # Errors
    ///
    /// Rejects two entries for the same capability/resource scope.
    pub fn new(grants: impl IntoIterator<Item = CapabilityGrant>) -> Result<Self, GrantSetError> {
        let mut values: Vec<_> = grants.into_iter().collect();
        values.sort_unstable();

        if values.windows(2).any(|pair| pair[0].same_scope(&pair[1])) {
            return Err(GrantSetError::DuplicateGrant);
        }

        Ok(Self(values))
    }

    /// Canonical grant slice.
    #[must_use]
    pub fn as_slice(&self) -> &[CapabilityGrant] {
        &self.0
    }

    /// Whether this set grants no authority.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for GrantSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = Vec::<CapabilityGrant>::deserialize(deserializer)?;
        let canonical = Self::new(wire.iter().cloned()).map_err(D::Error::custom)?;
        if canonical.0 != wire {
            return Err(D::Error::custom(GrantSetError::NonCanonicalOrder));
        }
        Ok(canonical)
    }
}

/// Invalid grant set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum GrantSetError {
    /// Two grants name the same exact capability/resource scope.
    #[error("duplicate capability/resource grant")]
    DuplicateGrant,
    /// Wire grants were not already encoded in canonical order.
    #[error("grant set is not in canonical order")]
    NonCanonicalOrder,
}

/// Monotonic authority version within one delegation lineage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LeaseVersion(NonZeroU64);

impl LeaseVersion {
    /// Construct a non-zero lease version.
    ///
    /// # Errors
    ///
    /// Returns an error for zero.
    pub fn new(value: u64) -> Result<Self, LeaseVersionError> {
        NonZeroU64::new(value).map(Self).ok_or(LeaseVersionError)
    }

    /// Raw version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl Serialize for LeaseVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.get())
    }
}

impl<'de> Deserialize<'de> for LeaseVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Invalid zero lease version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("lease version must be non-zero")]
pub struct LeaseVersionError;

/// Input for a root authority lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityLeaseInput {
    /// Lease identity.
    pub id: LeaseId,
    /// Delegation lineage identity.
    pub delegation_id: DelegationId,
    /// Root issuing principal.
    pub issuer: PrincipalId,
    /// Agent receiving authority.
    pub subject: AgentId,
    /// Task this authority is bound to.
    pub task: TaskId,
    /// Exact capability/resource grants.
    pub grants: GrantSet,
    /// Inclusive start in Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Exclusive expiry in Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Monotonic lineage version.
    pub version: LeaseVersion,
}

/// Input for one child delegation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationInput {
    /// Child lease identity.
    pub id: LeaseId,
    /// Child delegation identity.
    pub delegation_id: DelegationId,
    /// Child agent receiving authority.
    pub subject: AgentId,
    /// Task, which must remain identical to the parent in this slice.
    pub task: TaskId,
    /// Contracted grants.
    pub grants: GrantSet,
    /// Inclusive start in Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Exclusive expiry in Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Version strictly greater than the parent.
    pub version: LeaseVersion,
}

/// Explicit caller policy for constructing an authority lease with no grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmptyAuthorityPolicy {
    /// Empty authority is rejected.
    Reject,
    /// Empty authority is intentionally accepted.
    Allow,
}

/// One task-bound authority lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuthorityLease {
    id: LeaseId,
    delegation_id: DelegationId,
    issuer: PrincipalId,
    subject: AgentId,
    task: TaskId,
    parent_lease_id: Option<LeaseId>,
    delegated_by: Option<AgentId>,
    grants: GrantSet,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    version: LeaseVersion,
}

impl AuthorityLease {
    /// Construct a root lease that is active at the supplied instant.
    ///
    /// # Errors
    ///
    /// Rejects an invalid/inactive lifetime or accidental empty authority.
    pub fn root(
        input: AuthorityLeaseInput,
        now_unix_ms: u64,
        empty_policy: EmptyAuthorityPolicy,
    ) -> Result<Self, AuthorityLeaseError> {
        validate_lifetime(input.issued_at_unix_ms, input.expires_at_unix_ms)?;
        validate_active_interval(
            input.issued_at_unix_ms,
            input.expires_at_unix_ms,
            now_unix_ms,
        )?;
        validate_empty_policy(&input.grants, empty_policy)?;

        Ok(Self {
            id: input.id,
            delegation_id: input.delegation_id,
            issuer: input.issuer,
            subject: input.subject,
            task: input.task,
            parent_lease_id: None,
            delegated_by: None,
            grants: input.grants,
            issued_at_unix_ms: input.issued_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
            version: input.version,
        })
    }

    /// Delegate an active same-task subset of this lease.
    ///
    /// # Errors
    ///
    /// Rejects inactive authority, lease-ID reuse, task substitution, widened or
    /// non-delegable grants, lifetime widening, accidental empty authority and
    /// non-increasing versions.
    pub fn delegate(
        &self,
        input: DelegationInput,
        now_unix_ms: u64,
        empty_policy: EmptyAuthorityPolicy,
    ) -> Result<Self, AuthorityLeaseError> {
        validate_active_interval(self.issued_at_unix_ms, self.expires_at_unix_ms, now_unix_ms)?;
        validate_lifetime(input.issued_at_unix_ms, input.expires_at_unix_ms)?;

        if input.id == self.id {
            return Err(AuthorityLeaseError::LeaseIdReuse);
        }
        if input.delegation_id == self.delegation_id {
            return Err(AuthorityLeaseError::DelegationIdReuse);
        }
        if input.task != self.task {
            return Err(AuthorityLeaseError::TaskMismatch);
        }
        if input.issued_at_unix_ms < self.issued_at_unix_ms
            || input.expires_at_unix_ms > self.expires_at_unix_ms
        {
            return Err(AuthorityLeaseError::LifetimeOutsideParent);
        }
        validate_active_interval(
            input.issued_at_unix_ms,
            input.expires_at_unix_ms,
            now_unix_ms,
        )?;
        if input.version <= self.version {
            return Err(AuthorityLeaseError::NonIncreasingVersion);
        }
        validate_empty_policy(&input.grants, empty_policy)?;

        for child in input.grants.as_slice() {
            let Some(parent) = self
                .grants
                .as_slice()
                .iter()
                .find(|grant| grant.same_scope(child))
            else {
                return Err(AuthorityLeaseError::AuthorityWidening);
            };
            if !parent.delegable {
                return Err(AuthorityLeaseError::GrantNotDelegable);
            }
        }

        Ok(Self {
            id: input.id,
            delegation_id: input.delegation_id,
            issuer: self.issuer,
            subject: input.subject,
            task: self.task,
            parent_lease_id: Some(self.id),
            delegated_by: Some(self.subject),
            grants: input.grants,
            issued_at_unix_ms: input.issued_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
            version: input.version,
        })
    }

    /// Whether the lease is active at the supplied Unix-millisecond instant.
    #[must_use]
    pub const fn is_active_at(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.issued_at_unix_ms && now_unix_ms < self.expires_at_unix_ms
    }

    /// Lease identity.
    #[must_use]
    pub const fn id(&self) -> LeaseId {
        self.id
    }

    /// Delegation identity.
    #[must_use]
    pub const fn delegation_id(&self) -> DelegationId {
        self.delegation_id
    }

    /// Root issuing principal.
    #[must_use]
    pub const fn issuer(&self) -> PrincipalId {
        self.issuer
    }

    /// Agent holding this lease.
    #[must_use]
    pub const fn subject(&self) -> AgentId {
        self.subject
    }

    /// Bound task.
    #[must_use]
    pub const fn task(&self) -> TaskId {
        self.task
    }

    /// Parent lease for delegated authority.
    #[must_use]
    pub const fn parent_lease_id(&self) -> Option<LeaseId> {
        self.parent_lease_id
    }

    /// Agent that delegated the parent authority.
    #[must_use]
    pub const fn delegated_by(&self) -> Option<AgentId> {
        self.delegated_by
    }

    /// Exact grants.
    #[must_use]
    pub fn grants(&self) -> &GrantSet {
        &self.grants
    }

    /// Inclusive validity start.
    #[must_use]
    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.issued_at_unix_ms
    }

    /// Exclusive validity end.
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// Monotonic lineage version.
    #[must_use]
    pub const fn version(&self) -> LeaseVersion {
        self.version
    }

    /// Validate an untrusted child envelope against this trusted parent lease.
    ///
    /// # Errors
    ///
    /// Requires exact parent/delegator/issuer lineage and then applies every delegation
    /// contraction rule enforced by delegate.
    pub fn validate_delegated(
        &self,
        wire: UntrustedAuthorityLease,
        expected: DelegationBinding,
        now_unix_ms: u64,
        empty_policy: EmptyAuthorityPolicy,
    ) -> Result<Self, AuthorityLeaseError> {
        if wire.parent_lease_id != Some(self.id)
            || wire.delegated_by != Some(self.subject)
            || wire.issuer != self.issuer
        {
            return Err(AuthorityLeaseError::LineageMismatch);
        }
        if wire.id != expected.lease_id
            || wire.delegation_id != expected.delegation_id
            || wire.subject != expected.subject
            || wire.task != expected.task
            || wire.version != expected.version
        {
            return Err(AuthorityLeaseError::DelegationBindingMismatch);
        }

        self.delegate(
            DelegationInput {
                id: wire.id,
                delegation_id: wire.delegation_id,
                subject: wire.subject,
                task: wire.task,
                grants: wire.grants,
                issued_at_unix_ms: wire.issued_at_unix_ms,
                expires_at_unix_ms: wire.expires_at_unix_ms,
                version: wire.version,
            },
            now_unix_ms,
            empty_policy,
        )
    }

    /// Reconstruct root input for deterministic validation tests and adapters.
    #[must_use]
    pub fn to_input(&self) -> AuthorityLeaseInput {
        AuthorityLeaseInput {
            id: self.id,
            delegation_id: self.delegation_id,
            issuer: self.issuer,
            subject: self.subject,
            task: self.task,
            grants: self.grants.clone(),
            issued_at_unix_ms: self.issued_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            version: self.version,
        }
    }
}

/// Trusted child identity binding supplied by the application/control plane.
///
/// This value is deliberately not deserializable from the authority envelope itself.
/// It gives delegated-wire validation an independent expected lease, delegation,
/// subject and task identity so untrusted bytes cannot substitute those identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegationBinding {
    /// Expected child lease identity.
    pub lease_id: LeaseId,
    /// Expected delegation identity.
    pub delegation_id: DelegationId,
    /// Expected child agent identity.
    pub subject: AgentId,
    /// Expected task identity.
    pub task: TaskId,
    /// Expected monotonic lease version.
    pub version: LeaseVersion,
}

/// Untrusted serialized authority envelope.
///
/// Deserializing this value grants nothing. There is deliberately no promotion path
/// from wire data to root authority in this slice. A delegated envelope must pass
/// `AuthorityLease::validate_delegated` with its trusted parent. Root authority is
/// constructed only from non-deserializable trusted `AuthorityLeaseInput`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UntrustedAuthorityLease {
    id: LeaseId,
    delegation_id: DelegationId,
    issuer: PrincipalId,
    subject: AgentId,
    task: TaskId,
    parent_lease_id: Option<LeaseId>,
    delegated_by: Option<AgentId>,
    grants: GrantSet,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    version: LeaseVersion,
}

fn validate_lifetime(issued_at: u64, expires_at: u64) -> Result<(), AuthorityLeaseError> {
    if expires_at <= issued_at {
        return Err(AuthorityLeaseError::InvalidLifetime);
    }
    Ok(())
}

fn validate_active_interval(
    issued_at: u64,
    expires_at: u64,
    now: u64,
) -> Result<(), AuthorityLeaseError> {
    if now < issued_at {
        return Err(AuthorityLeaseError::NotYetValid);
    }
    if now >= expires_at {
        return Err(AuthorityLeaseError::Expired);
    }
    Ok(())
}

fn validate_empty_policy(
    grants: &GrantSet,
    policy: EmptyAuthorityPolicy,
) -> Result<(), AuthorityLeaseError> {
    if grants.is_empty() && policy == EmptyAuthorityPolicy::Reject {
        return Err(AuthorityLeaseError::EmptyAuthorityNotAllowed);
    }
    Ok(())
}

/// Invalid authority lease or delegation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum AuthorityLeaseError {
    /// Expiry is not strictly after issue time.
    #[error("authority lease lifetime is invalid")]
    InvalidLifetime,
    /// Lease has not reached its issue time.
    #[error("authority lease is not yet valid")]
    NotYetValid,
    /// Lease has reached or passed its expiry.
    #[error("authority lease is expired")]
    Expired,
    /// Child attempted to reuse its parent's lease identity.
    #[error("child authority lease id must differ from parent lease id")]
    LeaseIdReuse,
    /// Child attempted to reuse its parent's delegation identity.
    #[error("child delegation id must differ from parent delegation id")]
    DelegationIdReuse,
    /// Empty authority was not explicitly allowed by the caller.
    #[error("empty authority requires explicit caller opt-in")]
    EmptyAuthorityNotAllowed,
    /// Child delegation changed the task identity.
    #[error("child authority must remain bound to the parent task")]
    TaskMismatch,
    /// Child lifetime extends outside the parent lifetime.
    #[error("child authority lifetime exceeds parent authority")]
    LifetimeOutsideParent,
    /// Child version did not advance.
    #[error("child authority version must increase")]
    NonIncreasingVersion,
    /// Child requested a capability/resource absent from the parent.
    #[error("child authority widens the parent grant set")]
    AuthorityWidening,
    /// Parent grant exists but is not delegable.
    #[error("parent grant is not delegable")]
    GrantNotDelegable,
    /// Child wire does not identify the supplied trusted parent/delegator/issuer.
    #[error("delegated authority lineage does not match the trusted parent")]
    LineageMismatch,
    /// Child wire does not match the independently trusted child identity binding.
    #[error("delegated authority identity does not match the expected child binding")]
    DelegationBindingMismatch,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use ward_events::{AgentId, DelegationId, LeaseId, PrincipalId, TaskId};

    fn root() -> AuthorityLease {
        AuthorityLease::root(
            AuthorityLeaseInput {
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
            },
            500,
            EmptyAuthorityPolicy::Reject,
        )
        .unwrap()
    }

    fn binding_for(lease: &AuthorityLease) -> DelegationBinding {
        DelegationBinding {
            lease_id: lease.id(),
            delegation_id: lease.delegation_id(),
            subject: lease.subject(),
            task: lease.task(),
            version: lease.version(),
        }
    }

    fn decode_wire(value: &serde_json::Value) -> UntrustedAuthorityLease {
        let encoded = serde_json::to_string(value).unwrap();
        serde_json::from_str(&encoded).unwrap()
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
            AuthorityLease::root(input, 500, EmptyAuthorityPolicy::Reject),
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
            .delegate(
                DelegationInput {
                    id: LeaseId::from_u128(2),
                    delegation_id: DelegationId::from_u128(2),
                    subject: AgentId::from_u128(2),
                    task: parent.task(),
                    grants: child_grants,
                    issued_at_unix_ms: 200,
                    expires_at_unix_ms: 900,
                    version: LeaseVersion::new(2).unwrap(),
                },
                500,
                EmptyAuthorityPolicy::Reject,
            )
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
                parent.delegate(
                    DelegationInput {
                        id: LeaseId::from_u128(2),
                        delegation_id: DelegationId::from_u128(2),
                        subject: AgentId::from_u128(2),
                        task,
                        grants,
                        issued_at_unix_ms: 200,
                        expires_at_unix_ms: 900,
                        version: LeaseVersion::new(2).unwrap(),
                    },
                    500,
                    EmptyAuthorityPolicy::Reject
                ),
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
                parent.delegate(
                    DelegationInput {
                        id: LeaseId::from_u128(2),
                        delegation_id: DelegationId::from_u128(2),
                        subject: AgentId::from_u128(2),
                        task: parent.task(),
                        grants: grants.clone(),
                        issued_at_unix_ms: issued,
                        expires_at_unix_ms: expires,
                        version: LeaseVersion::new(version).unwrap(),
                    },
                    500,
                    EmptyAuthorityPolicy::Allow,
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn root_shaped_wire_cannot_be_promoted_through_delegated_validation() {
        let root = root();
        let wire =
            serde_json::from_str::<UntrustedAuthorityLease>(&serde_json::to_string(&root).unwrap())
                .unwrap();

        assert_eq!(
            root.validate_delegated(
                wire,
                DelegationBinding {
                    lease_id: LeaseId::from_u128(2),
                    delegation_id: DelegationId::from_u128(2),
                    subject: AgentId::from_u128(2),
                    task: root.task(),
                    version: LeaseVersion::new(2).unwrap(),
                },
                500,
                EmptyAuthorityPolicy::Reject,
            ),
            Err(AuthorityLeaseError::LineageMismatch)
        );
    }

    #[test]
    fn inactive_parent_or_child_authority_fails_closed() {
        let input = root().to_input();
        assert_eq!(
            AuthorityLease::root(input.clone(), 99, EmptyAuthorityPolicy::Reject),
            Err(AuthorityLeaseError::NotYetValid)
        );
        assert_eq!(
            AuthorityLease::root(input, 1_000, EmptyAuthorityPolicy::Reject),
            Err(AuthorityLeaseError::Expired)
        );

        let parent = root();
        let grants = GrantSet::new([CapabilityGrant::new(
            CapabilityName::new("repo.read").unwrap(),
            ResourceRef::new("repo:hexrift/WardOS").unwrap(),
            false,
        )])
        .unwrap();

        for (issued_at, expires_at, now, expected) in [
            (600, 900, 500, AuthorityLeaseError::NotYetValid),
            (200, 400, 500, AuthorityLeaseError::Expired),
            (200, 900, 1_000, AuthorityLeaseError::Expired),
        ] {
            assert_eq!(
                parent.delegate(
                    DelegationInput {
                        id: LeaseId::from_u128(2),
                        delegation_id: DelegationId::from_u128(2),
                        subject: AgentId::from_u128(2),
                        task: parent.task(),
                        grants: grants.clone(),
                        issued_at_unix_ms: issued_at,
                        expires_at_unix_ms: expires_at,
                        version: LeaseVersion::new(2).unwrap(),
                    },
                    now,
                    EmptyAuthorityPolicy::Reject,
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn child_cannot_reuse_parent_lease_id() {
        let parent = root();
        let grants = GrantSet::new([CapabilityGrant::new(
            CapabilityName::new("repo.read").unwrap(),
            ResourceRef::new("repo:hexrift/WardOS").unwrap(),
            false,
        )])
        .unwrap();

        assert_eq!(
            parent.delegate(
                DelegationInput {
                    id: parent.id(),
                    delegation_id: DelegationId::from_u128(2),
                    subject: AgentId::from_u128(2),
                    task: parent.task(),
                    grants,
                    issued_at_unix_ms: 200,
                    expires_at_unix_ms: 900,
                    version: LeaseVersion::new(2).unwrap(),
                },
                500,
                EmptyAuthorityPolicy::Reject,
            ),
            Err(AuthorityLeaseError::LeaseIdReuse)
        );
    }

    #[test]
    fn child_cannot_reuse_parent_delegation_id() {
        let parent = root();
        let grants = GrantSet::new([CapabilityGrant::new(
            CapabilityName::new("repo.read").unwrap(),
            ResourceRef::new("repo:hexrift/WardOS").unwrap(),
            false,
        )])
        .unwrap();

        assert_eq!(
            parent.delegate(
                DelegationInput {
                    id: LeaseId::from_u128(2),
                    delegation_id: parent.delegation_id(),
                    subject: AgentId::from_u128(2),
                    task: parent.task(),
                    grants,
                    issued_at_unix_ms: 200,
                    expires_at_unix_ms: 900,
                    version: LeaseVersion::new(2).unwrap(),
                },
                500,
                EmptyAuthorityPolicy::Reject,
            ),
            Err(AuthorityLeaseError::DelegationIdReuse)
        );
    }

    #[test]
    fn delegated_wire_rejects_stale_version_replay() {
        let parent = root();
        let child_v3 = parent
            .delegate(
                DelegationInput {
                    id: LeaseId::from_u128(3),
                    delegation_id: DelegationId::from_u128(3),
                    subject: AgentId::from_u128(3),
                    task: parent.task(),
                    grants: GrantSet::new([CapabilityGrant::new(
                        CapabilityName::new("repo.read").unwrap(),
                        ResourceRef::new("repo:hexrift/WardOS").unwrap(),
                        false,
                    )])
                    .unwrap(),
                    issued_at_unix_ms: 200,
                    expires_at_unix_ms: 900,
                    version: LeaseVersion::new(3).unwrap(),
                },
                500,
                EmptyAuthorityPolicy::Reject,
            )
            .unwrap();
        let expected = binding_for(&child_v3);
        let json = serde_json::to_value(&child_v3).unwrap();

        let current = decode_wire(&json);
        assert_eq!(
            parent
                .validate_delegated(current, expected, 500, EmptyAuthorityPolicy::Reject)
                .unwrap()
                .version(),
            LeaseVersion::new(3).unwrap()
        );

        let mut stale = json;
        stale["version"] = serde_json::Value::from(2_u64);
        let stale = decode_wire(&stale);
        assert_eq!(
            parent.validate_delegated(stale, expected, 500, EmptyAuthorityPolicy::Reject),
            Err(AuthorityLeaseError::DelegationBindingMismatch)
        );
    }

    #[test]
    fn delegated_wire_cannot_substitute_child_identity() {
        let parent = root();
        let child = parent
            .delegate(
                DelegationInput {
                    id: LeaseId::from_u128(2),
                    delegation_id: DelegationId::from_u128(2),
                    subject: AgentId::from_u128(2),
                    task: parent.task(),
                    grants: GrantSet::new([CapabilityGrant::new(
                        CapabilityName::new("repo.read").unwrap(),
                        ResourceRef::new("repo:hexrift/WardOS").unwrap(),
                        false,
                    )])
                    .unwrap(),
                    issued_at_unix_ms: 200,
                    expires_at_unix_ms: 900,
                    version: LeaseVersion::new(2).unwrap(),
                },
                500,
                EmptyAuthorityPolicy::Reject,
            )
            .unwrap();
        let expected = binding_for(&child);
        let original = serde_json::to_value(&child).unwrap();

        for (field, replacement) in [
            (
                "id",
                serde_json::Value::String(LeaseId::from_u128(9).to_string()),
            ),
            (
                "delegation_id",
                serde_json::Value::String(DelegationId::from_u128(9).to_string()),
            ),
            (
                "subject",
                serde_json::Value::String(AgentId::from_u128(9).to_string()),
            ),
            (
                "task",
                serde_json::Value::String(TaskId::from_u128(9).to_string()),
            ),
        ] {
            let mut tampered = original.clone();
            tampered[field] = replacement;
            let wire = decode_wire(&tampered);
            assert_eq!(
                parent.validate_delegated(wire, expected, 500, EmptyAuthorityPolicy::Reject,),
                Err(AuthorityLeaseError::DelegationBindingMismatch)
            );
        }
    }

    #[test]
    fn empty_authority_requires_explicit_opt_in() {
        let parent = root();
        let input = DelegationInput {
            id: LeaseId::from_u128(2),
            delegation_id: DelegationId::from_u128(2),
            subject: AgentId::from_u128(2),
            task: parent.task(),
            grants: GrantSet::new([]).unwrap(),
            issued_at_unix_ms: 200,
            expires_at_unix_ms: 900,
            version: LeaseVersion::new(2).unwrap(),
        };

        assert_eq!(
            parent.delegate(input.clone(), 500, EmptyAuthorityPolicy::Reject),
            Err(AuthorityLeaseError::EmptyAuthorityNotAllowed)
        );
        assert!(
            parent
                .delegate(input, 500, EmptyAuthorityPolicy::Allow)
                .unwrap()
                .grants()
                .is_empty()
        );
    }

    #[test]
    fn untrusted_delegated_wire_is_time_checked_against_the_parent() {
        let parent = root();
        let child = parent
            .delegate(
                DelegationInput {
                    id: LeaseId::from_u128(2),
                    delegation_id: DelegationId::from_u128(2),
                    subject: AgentId::from_u128(2),
                    task: parent.task(),
                    grants: GrantSet::new([CapabilityGrant::new(
                        CapabilityName::new("repo.read").unwrap(),
                        ResourceRef::new("repo:hexrift/WardOS").unwrap(),
                        false,
                    )])
                    .unwrap(),
                    issued_at_unix_ms: 200,
                    expires_at_unix_ms: 900,
                    version: LeaseVersion::new(2).unwrap(),
                },
                500,
                EmptyAuthorityPolicy::Reject,
            )
            .unwrap();
        let json = serde_json::to_string(&child).unwrap();

        for (now, expected) in [
            (150, AuthorityLeaseError::NotYetValid),
            (950, AuthorityLeaseError::Expired),
            (1_000, AuthorityLeaseError::Expired),
        ] {
            let wire = serde_json::from_str::<UntrustedAuthorityLease>(&json).unwrap();
            assert_eq!(
                parent.validate_delegated(
                    wire,
                    binding_for(&child),
                    now,
                    EmptyAuthorityPolicy::Reject,
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn root_empty_authority_requires_explicit_opt_in() {
        let input = AuthorityLeaseInput {
            id: LeaseId::from_u128(9),
            delegation_id: DelegationId::from_u128(9),
            issuer: PrincipalId::from_u128(9),
            subject: AgentId::from_u128(9),
            task: TaskId::from_u128(9),
            grants: GrantSet::new([]).unwrap(),
            issued_at_unix_ms: 100,
            expires_at_unix_ms: 1_000,
            version: LeaseVersion::new(1).unwrap(),
        };

        assert_eq!(
            AuthorityLease::root(input.clone(), 500, EmptyAuthorityPolicy::Reject),
            Err(AuthorityLeaseError::EmptyAuthorityNotAllowed)
        );
        assert!(
            AuthorityLease::root(input, 500, EmptyAuthorityPolicy::Allow)
                .unwrap()
                .grants()
                .is_empty()
        );
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
        let wire = serde_json::from_str::<UntrustedAuthorityLease>(&json).unwrap();
        assert_eq!(wire.parent_lease_id, None);
        assert_eq!(wire.delegated_by, None);

        let mut value = serde_json::from_str::<serde_json::Value>(&json).unwrap();
        value["provider"] = serde_json::Value::String("model".into());
        assert!(serde_json::from_value::<UntrustedAuthorityLease>(value).is_err());
    }
}
