//! Verification of protocol 1.3 `admit` requests (ADR-0030 §2).
//!
//! [`NodeAdmission`] holds what the node needs to admit work: its own [`NodeId`]
//! (audience), the trusted issuer keys, the durable [`NodeState`] and a clock. It checks,
//! in this order and before anything changes:
//!
//! 1. the issuer key id is trusted;
//! 2. the Ed25519 signature verifies over exactly the received envelope bytes;
//! 3. only then, the bytes decode strictly as one envelope;
//! 4. the root lease (the last lineage entry, or the lease itself when the lineage is
//!    empty) names as its issuer the principal the signing key is bound to in the trust
//!    store, so a trusted key never signs authority for another principal;
//! 5. the decoded binding equals the request binding and the audience is this node;
//! 6. `issued_at <= now < expires_at` at the node's clock;
//! 7. the version is strictly greater than the last one durably accepted for the task;
//! 8. the lease and lineage, promoted only because the trusted issuer signed them, pass
//!    the trusted task-authority check ([`TrustedTaskAdmission`]) for the binding and agent;
//! 9. no durable revocation covers the lease or its lineage;
//! 10. every grant in the decoded capability manifest is one this node honours. Every
//!     workload runs offline, so only `{"network":"offline"}` passes; any other network
//!     grant is refused `unsupported_grant`, after authority is proven and before the
//!     version is committed, so a refused grant consumes nothing.
//!
//! Each failure is a typed [`TaskLifecycleRejectionReason`]. Task-registry checks
//! (existence, exact binding, `Created` state) come first, in [`crate::task`].

use std::time::{SystemTime, UNIX_EPOCH};

use ward_authority::revocation::{
    AuthorityRevocation, AuthorityRevocations, LeaseLineage, RevocationReason,
};
use ward_authority::{
    AuthorityLease, AuthorityLeaseError, DelegationBinding, EmptyAuthorityPolicy,
    UntrustedAuthorityLease,
};
use ward_events::{LeaseId, NodeId};
use ward_node_protocol::{
    AdmissionEnvelopeJson, CapabilityManifest, IssuerProof, NetworkGrant, TaskAdmissionEnvelope,
    TaskBinding, TaskLifecycleRejectionReason,
};

use crate::admission::{TaskAdmissionIdentity, TaskAuthorityError, TrustedTaskAdmission};
use crate::issuer::TrustedIssuers;
use crate::state::{NodeState, NodeStateError};

type Reason = TaskLifecycleRejectionReason;

/// Source of the node's current time in Unix milliseconds.
pub trait NodeClock: Send {
    /// The current time in Unix milliseconds.
    fn now_unix_ms(&self) -> u64;
}

/// The host wall clock. A time before the Unix epoch reads as zero, which fails closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl NodeClock for SystemClock {
    fn now_unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// An envelope that passed every admission check, with its trusted authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAdmission {
    envelope: TaskAdmissionEnvelope,
    authority: TrustedTaskAdmission,
}

impl VerifiedAdmission {
    /// The decoded, verified envelope.
    #[must_use]
    pub const fn envelope(&self) -> &TaskAdmissionEnvelope {
        &self.envelope
    }

    /// The authority the envelope carried, bound to its exact admission identity.
    #[must_use]
    pub const fn authority(&self) -> &TrustedTaskAdmission {
        &self.authority
    }
}

/// The node's admission configuration and durable admission state.
pub struct NodeAdmission {
    issuers: TrustedIssuers,
    state: NodeState,
    clock: Box<dyn NodeClock>,
}

impl std::fmt::Debug for NodeAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeAdmission")
            .field("issuers", &self.issuers)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl NodeAdmission {
    /// Admit for the node whose identity `state` is pinned to, trusting `issuers`.
    #[must_use]
    pub fn new(issuers: TrustedIssuers, state: NodeState, clock: Box<dyn NodeClock>) -> Self {
        Self {
            issuers,
            state,
            clock,
        }
    }

    /// This node's identity: the only audience it admits.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.state.node()
    }

    /// The trusted issuer keys.
    #[must_use]
    pub const fn issuers(&self) -> &TrustedIssuers {
        &self.issuers
    }

    /// The durable admission state.
    #[must_use]
    pub const fn state(&self) -> &NodeState {
        &self.state
    }

    /// The durable admission state, for recording revocations.
    pub const fn state_mut(&mut self) -> &mut NodeState {
        &mut self.state
    }

    /// Check one admission request; nothing changes, whatever the outcome.
    ///
    /// # Errors
    ///
    /// Returns the typed refusal for the first failed check (see the module docs).
    pub fn verify(
        &self,
        binding: TaskBinding,
        envelope_json: &AdmissionEnvelopeJson,
        proof: &IssuerProof,
    ) -> Result<VerifiedAdmission, TaskLifecycleRejectionReason> {
        let issuer = self
            .issuers
            .verify(proof, envelope_json.as_bytes())
            .map_err(|_| Reason::AuthorityDenied)?;
        let envelope = envelope_json
            .decode()
            .map_err(|_| Reason::AuthorityDenied)?;
        let authority = envelope.authority();
        let root = authority.lineage().last().unwrap_or(authority.lease());
        if root.issuer() != issuer {
            return Err(Reason::AuthorityDenied);
        }

        check_binding(envelope.binding(), binding)?;
        if envelope.node() != self.node() {
            return Err(Reason::AuthorityDenied);
        }

        let now = self.clock.now_unix_ms();
        if now < envelope.issued_at_unix_ms() {
            return Err(Reason::AuthorityDenied);
        }
        if now >= envelope.expires_at_unix_ms() {
            return Err(Reason::LeaseExpired);
        }

        if self
            .state
            .last_admitted_version(binding.task())
            .is_some_and(|last| envelope.version() <= last)
        {
            return Err(Reason::StaleOperation);
        }

        let (lease, ancestors) = promote_authority(&envelope, now)?;
        let lineage = LeaseLineage::for_lease(&lease, ancestors.iter())
            .map_err(|_| Reason::AuthorityDenied)?;
        let identity = TaskAdmissionIdentity::new(
            binding,
            envelope.agent(),
            envelope.node(),
            envelope.session(),
        );
        let authority =
            TrustedTaskAdmission::new(identity, lease, lineage, &AuthorityRevocations::new(), now)
                .map_err(|error| match error {
                    TaskAuthorityError::LeaseMismatch => Reason::LeaseMismatch,
                    TaskAuthorityError::AuthorityUnavailable => Reason::LeaseExpired,
                    TaskAuthorityError::TaskMismatch | TaskAuthorityError::AgentMismatch => {
                        Reason::AuthorityDenied
                    }
                })?;
        authority
            .revalidate(self.state.revocations(), now)
            .map_err(|_| Reason::LeaseRevoked)?;
        check_grants(envelope.workload().capability_manifest().manifest())?;

        Ok(VerifiedAdmission {
            envelope,
            authority,
        })
    }

    /// Recheck, at the node clock, that an admitted envelope and its authority are still
    /// usable: the envelope and lease unexpired and no durable revocation covering the
    /// lease or its lineage. `start` calls this before anything is materialised or spawned.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleRejectionReason::LeaseExpired`],
    /// [`TaskLifecycleRejectionReason::LeaseRevoked`], or
    /// [`TaskLifecycleRejectionReason::AuthorityDenied`] for a clock before issuance.
    pub fn revalidate(
        &self,
        verified: &VerifiedAdmission,
    ) -> Result<(), TaskLifecycleRejectionReason> {
        let now = self.clock.now_unix_ms();
        let envelope = verified.envelope();
        if now < envelope.issued_at_unix_ms() {
            return Err(Reason::AuthorityDenied);
        }
        if now >= envelope.expires_at_unix_ms() {
            return Err(Reason::LeaseExpired);
        }
        verified
            .authority()
            .revalidate(&AuthorityRevocations::new(), now)
            .map_err(|_| Reason::LeaseExpired)?;
        verified
            .authority()
            .revalidate(self.state.revocations(), now)
            .map_err(|_| Reason::LeaseRevoked)
    }

    /// Durably revoke `lease` at the node clock, unless a revocation already in effect is
    /// recorded for it. Every later admission or start under the lease, or under a lease
    /// delegated from it, is then refused `lease_revoked`, across restarts.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleRejectionReason::ResourceUnavailable`] if the revocation
    /// cannot be persisted; nothing is recorded then.
    pub fn revoke(&mut self, lease: LeaseId) -> Result<(), TaskLifecycleRejectionReason> {
        let now = self.clock.now_unix_ms();
        if self
            .state
            .revocation(lease)
            .is_some_and(|fact| fact.revoked_at_unix_ms() <= now)
        {
            return Ok(());
        }
        match self.state.record_revocation(AuthorityRevocation::new(
            lease,
            now,
            RevocationReason::Operator,
        )) {
            Ok(()) | Err(NodeStateError::RevocationConflict) => Ok(()),
            Err(_) => Err(Reason::ResourceUnavailable),
        }
    }

    /// Durably record a verified admission's version before the task changes state.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleRejectionReason::StaleOperation`] if the version is no
    /// longer newer than the recorded one, and
    /// [`TaskLifecycleRejectionReason::ResourceUnavailable`] if it cannot be persisted.
    pub fn commit(
        &mut self,
        verified: &VerifiedAdmission,
    ) -> Result<(), TaskLifecycleRejectionReason> {
        self.state
            .record_admitted_version(
                verified.envelope.binding().task(),
                verified.envelope.version(),
            )
            .map_err(|error| match error {
                NodeStateError::NonIncreasingVersion => Reason::StaleOperation,
                _ => Reason::ResourceUnavailable,
            })
    }
}

fn check_binding(decoded: TaskBinding, request: TaskBinding) -> Result<(), Reason> {
    if decoded.task() != request.task() {
        return Err(Reason::AuthorityDenied);
    }
    if decoded.attempt() != request.attempt() {
        return Err(Reason::AttemptMismatch);
    }
    if decoded.lease() != request.lease() {
        return Err(Reason::LeaseMismatch);
    }
    Ok(())
}

fn promote_authority(
    envelope: &TaskAdmissionEnvelope,
    now_unix_ms: u64,
) -> Result<(AuthorityLease, Vec<AuthorityLease>), Reason> {
    let authority = envelope.authority();
    let mut chain = authority
        .lineage()
        .iter()
        .rev()
        .chain(std::iter::once(authority.lease()));
    let Some(root) = chain.next() else {
        return Err(Reason::AuthorityDenied);
    };
    let mut current = root
        .clone()
        .into_issuer_verified_root(now_unix_ms, EmptyAuthorityPolicy::Reject)
        .map_err(lease_refusal)?;
    let mut ancestors = Vec::with_capacity(authority.lineage().len());
    for wire in chain {
        let child = current
            .validate_delegated(
                wire.clone(),
                claimed_binding(wire),
                now_unix_ms,
                EmptyAuthorityPolicy::Reject,
            )
            .map_err(lease_refusal)?;
        ancestors.push(std::mem::replace(&mut current, child));
    }
    ancestors.reverse();
    Ok((current, ancestors))
}

const fn claimed_binding(wire: &UntrustedAuthorityLease) -> DelegationBinding {
    DelegationBinding {
        lease_id: wire.id(),
        delegation_id: wire.delegation_id(),
        subject: wire.subject(),
        task: wire.task(),
        version: wire.version(),
    }
}

const fn check_grants(manifest: &CapabilityManifest) -> Result<(), Reason> {
    match manifest.network() {
        NetworkGrant::Offline => Ok(()),
        NetworkGrant::Custom(_) => Err(Reason::UnsupportedGrant),
    }
}

const fn lease_refusal(error: AuthorityLeaseError) -> Reason {
    match error {
        AuthorityLeaseError::Expired => Reason::LeaseExpired,
        _ => Reason::AuthorityDenied,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use ring::signature::{Ed25519KeyPair, KeyPair};
    use ward_authority::{DelegationInput, LeaseVersion};
    use ward_events::{AgentId, DelegationId, LeaseId, PrincipalId};
    use ward_node_protocol::TaskAdmissionAuthority;

    use super::*;
    use crate::issuer::{IssuerPublicKey, TrustedIssuer};
    use crate::test_support::{
        FixedClock, ISSUER, NODE, NOW, envelope_input, envelope_input_issued_by, issuer_keypair,
        issuer_public_key, lifecycle_binding, node_admission, other_keypair, root_lease_issued_by,
        sign,
    };

    const OTHER_ISSUER: PrincipalId = PrincipalId::from_u128(9);

    fn admission_trusting_both_keys(dir: &std::path::Path) -> NodeAdmission {
        let other =
            IssuerPublicKey::from_bytes(other_keypair().public_key().as_ref().try_into().unwrap());
        NodeAdmission::new(
            TrustedIssuers::new([
                TrustedIssuer::new(issuer_public_key(), ISSUER),
                TrustedIssuer::new(other, OTHER_ISSUER),
            ]),
            NodeState::open(&dir.join("state"), NODE).unwrap(),
            Box::new(FixedClock::at(NOW)),
        )
    }

    fn delegated_from_root_issued_by(issuer: PrincipalId) -> TaskAdmissionEnvelope {
        let binding = lifecycle_binding();
        let root = root_lease_issued_by(
            TaskBinding::new(binding.task(), binding.attempt(), LeaseId::from_u128(20)),
            issuer,
            1_000,
            9_000,
        );
        let child = root
            .delegate(
                DelegationInput {
                    id: binding.lease(),
                    delegation_id: DelegationId::from_u128(22),
                    subject: AgentId::from_u128(3),
                    task: binding.task(),
                    grants: root.grants().clone(),
                    issued_at_unix_ms: 1_500,
                    expires_at_unix_ms: 8_500,
                    version: LeaseVersion::new(2).unwrap(),
                },
                2_000,
                EmptyAuthorityPolicy::Reject,
            )
            .unwrap();
        let mut input = envelope_input(binding);
        input.authority = TaskAdmissionAuthority::new(
            UntrustedAuthorityLease::from(&child),
            vec![UntrustedAuthorityLease::from(&root)],
        )
        .unwrap();
        TaskAdmissionEnvelope::new(input).unwrap()
    }

    fn verify_signed(
        admission: &NodeAdmission,
        envelope: &TaskAdmissionEnvelope,
        key: &Ed25519KeyPair,
    ) -> Result<VerifiedAdmission, Reason> {
        let json = AdmissionEnvelopeJson::encode(envelope).unwrap();
        admission.verify(envelope.binding(), &json, &sign(&json, key))
    }

    fn verify_issued_by(
        admission: &NodeAdmission,
        issuer: PrincipalId,
        key: &Ed25519KeyPair,
    ) -> Result<VerifiedAdmission, Reason> {
        let binding = lifecycle_binding();
        let envelope =
            TaskAdmissionEnvelope::new(envelope_input_issued_by(binding, issuer)).unwrap();
        let json = AdmissionEnvelopeJson::encode(&envelope).unwrap();
        admission.verify(binding, &json, &sign(&json, key))
    }

    #[test]
    fn a_trusted_key_admits_only_leases_issued_by_its_bound_principal() {
        let dir = tempfile::tempdir().unwrap();
        let admission = node_admission(&dir.path().join("state"), &FixedClock::at(NOW));

        assert!(verify_issued_by(&admission, ISSUER, &issuer_keypair()).is_ok());
        assert_eq!(
            verify_issued_by(&admission, PrincipalId::from_u128(9), &issuer_keypair()).unwrap_err(),
            Reason::AuthorityDenied
        );
        assert_eq!(
            admission
                .state()
                .last_admitted_version(lifecycle_binding().task()),
            None
        );
    }

    #[test]
    fn each_trusted_key_signs_only_for_its_own_principal() {
        let dir = tempfile::tempdir().unwrap();
        let admission = admission_trusting_both_keys(dir.path());
        let binding = lifecycle_binding();
        let by =
            |issuer| TaskAdmissionEnvelope::new(envelope_input_issued_by(binding, issuer)).unwrap();

        for (envelope, key) in [
            (by(ISSUER), other_keypair()),
            (by(OTHER_ISSUER), issuer_keypair()),
        ] {
            assert_eq!(
                verify_signed(&admission, &envelope, &key).unwrap_err(),
                Reason::AuthorityDenied
            );
        }
        for (envelope, key) in [
            (by(ISSUER), issuer_keypair()),
            (by(OTHER_ISSUER), other_keypair()),
        ] {
            assert!(verify_signed(&admission, &envelope, &key).is_ok());
        }
    }

    #[test]
    fn a_delegated_lease_is_held_to_the_issuer_of_its_root() {
        let dir = tempfile::tempdir().unwrap();
        let admission = admission_trusting_both_keys(dir.path());

        assert_eq!(
            verify_signed(
                &admission,
                &delegated_from_root_issued_by(OTHER_ISSUER),
                &issuer_keypair()
            )
            .unwrap_err(),
            Reason::AuthorityDenied
        );
        assert!(
            verify_signed(
                &admission,
                &delegated_from_root_issued_by(ISSUER),
                &issuer_keypair()
            )
            .is_ok()
        );
    }
}
