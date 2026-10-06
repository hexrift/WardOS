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
//! 10. every grant in the decoded capability manifest is one this node honours:
//!     `{"network":"offline"}` always, `{"network":{"custom":[…]}}` only on a node
//!     that enforces a network allowlist ([`NodeAdmission::with_network_allowlist`], set by
//!     the registry from its execution), and an `output` grant only on a node that returns
//!     output ([`NodeAdmission::with_output_return`]) and only within its ceilings
//!     ([`ward_node_protocol::MAX_OUTPUT_STDIO_BYTES`],
//!     [`ward_node_protocol::MAX_OUTPUT_FILES_BYTES`]), a `resources` grant only on a
//!     node that runs attempts in cgroups, only for limits it has a controller for and
//!     within the host's ceilings ([`NodeAdmission::with_resource_enforcement`]), and an
//!     `actions` grant only on a node that offers the action channel
//!     ([`NodeAdmission::with_action_channel`]) and only within its ceilings
//!     ([`ward_node_protocol::MAX_ACTION_PENDING`], [`ward_node_protocol::MAX_ACTION_TOTAL`],
//!     [`ward_node_protocol::MAX_ACTION_WAIT_SECS`]), and a `credentials` grant only on a
//!     node that enforces a network allowlist and whose operator configured every service
//!     it names, for that service's host and within its ceiling
//!     ([`NodeAdmission::with_credentials`]); any other grant is refused
//!     `unsupported_grant`, after authority is proven and before the version is committed,
//!     so a refused grant consumes nothing.
//!
//! Each failure is a typed [`TaskLifecycleRejectionReason`]. Task-registry checks
//! (existence, exact binding, `Created` state) come first, in [`crate::task`].

use std::sync::Arc;
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
use crate::cgroup::ResourceEnforcement;
use crate::credentials::NodeCredentials;
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

/// An envelope that passed every admission check, with its trusted authority, the
/// promoted ancestors that proved its contraction and the node time it was verified at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAdmission {
    envelope: TaskAdmissionEnvelope,
    authority: TrustedTaskAdmission,
    ancestors: Vec<AuthorityLease>,
    verified_at_unix_ms: u64,
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

    /// The lease's promoted ancestors, nearest parent first and the root last; empty for a
    /// root lease.
    #[must_use]
    pub fn ancestors(&self) -> &[AuthorityLease] {
        &self.ancestors
    }

    /// The node clock, in Unix milliseconds, when the envelope was verified.
    #[must_use]
    pub const fn verified_at_unix_ms(&self) -> u64 {
        self.verified_at_unix_ms
    }
}

/// The node's admission configuration and durable admission state.
pub struct NodeAdmission {
    issuers: TrustedIssuers,
    state: NodeState,
    clock: Box<dyn NodeClock>,
    network_allowlist: bool,
    output_return: bool,
    resources: Option<ResourceEnforcement>,
    action_channel: bool,
    credentials: Option<Arc<NodeCredentials>>,
}

impl std::fmt::Debug for NodeAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeAdmission")
            .field("issuers", &self.issuers)
            .field("state", &self.state)
            .field("network_allowlist", &self.network_allowlist)
            .field("output_return", &self.output_return)
            .field("resources", &self.resources)
            .field("action_channel", &self.action_channel)
            .field("credentials", &self.credentials)
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
            network_allowlist: false,
            output_return: false,
            resources: None,
            action_channel: false,
            credentials: None,
        }
    }

    /// Whether a `{"network":{"custom":[…]}}` manifest is honoured (check 10). The task
    /// registry sets this from its execution, so what `admit` accepts is exactly what
    /// `start` enforces and the capability document advertises.
    #[must_use]
    pub const fn with_network_allowlist(mut self, enabled: bool) -> Self {
        self.network_allowlist = enabled;
        self
    }

    /// Whether a `{"network":{"custom":[…]}}` manifest is honoured.
    #[must_use]
    pub const fn honours_network_allowlist(&self) -> bool {
        self.network_allowlist
    }

    /// Whether a manifest's `output` grant is honoured, within the ceilings (check 10).
    /// The task registry sets this from its execution, so what `admit` accepts is exactly
    /// what the reaper collects and `result` returns.
    #[must_use]
    pub const fn with_output_return(mut self, enabled: bool) -> Self {
        self.output_return = enabled;
        self
    }

    /// Whether a manifest's `output` grant is honoured.
    #[must_use]
    pub const fn honours_output_return(&self) -> bool {
        self.output_return
    }

    /// Which `resources` grants are honoured (check 10): only on a node that runs attempts
    /// in cgroups, only limits it has a controller for, within the host's ceilings. The
    /// task registry sets this from its execution, so what `admit` accepts is exactly what
    /// the launcher writes into the attempt's cgroup.
    #[must_use]
    pub const fn with_resource_enforcement(
        mut self,
        resources: Option<ResourceEnforcement>,
    ) -> Self {
        self.resources = resources;
        self
    }

    /// Whether a manifest's `actions` grant is honoured, within the ceilings (check 10).
    /// The task registry sets this from its execution, so what `admit` accepts is exactly
    /// what `start` gives a channel.
    #[must_use]
    pub const fn with_action_channel(mut self, enabled: bool) -> Self {
        self.action_channel = enabled;
        self
    }

    /// Whether a manifest's `actions` grant is honoured.
    #[must_use]
    pub const fn honours_action_channel(&self) -> bool {
        self.action_channel
    }

    /// Which `credentials` grants are honoured (check 10): only on a node whose operator
    /// configured services ([`NodeCredentials`]) and that enforces a network allowlist,
    /// only for a configured service, its host and within its ceiling. The task registry
    /// sets this from its execution, so what `admit` accepts is exactly what `start`
    /// leases.
    #[must_use]
    pub fn with_credentials(mut self, credentials: Option<Arc<NodeCredentials>>) -> Self {
        self.credentials = credentials;
        self
    }

    /// Whether a manifest's `credentials` grant can be honoured at all.
    #[must_use]
    pub const fn honours_credentials(&self) -> bool {
        self.network_allowlist && self.credentials.is_some()
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
        let manifest = envelope.workload().capability_manifest().manifest();
        check_grants(
            manifest,
            self.network_allowlist,
            self.output_return,
            self.action_channel,
        )?;
        if let Some(grant) = manifest.resources()
            && !self
                .resources
                .is_some_and(|enforcement| enforcement.honours(grant))
        {
            return Err(Reason::UnsupportedGrant);
        }
        if let Some(grants) = manifest.credentials() {
            let honoured = self.network_allowlist
                && self.credentials.as_ref().is_some_and(|credentials| {
                    grants
                        .grants()
                        .iter()
                        .all(|grant| credentials.honours(grant))
                });
            if !honoured {
                return Err(Reason::UnsupportedGrant);
            }
        }

        Ok(VerifiedAdmission {
            envelope,
            authority,
            ancestors,
            verified_at_unix_ms: now,
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

const fn check_grants(
    manifest: &CapabilityManifest,
    network_allowlist: bool,
    output_return: bool,
    action_channel: bool,
) -> Result<(), Reason> {
    match manifest.network() {
        NetworkGrant::Offline => {}
        NetworkGrant::Custom(_) if network_allowlist => {}
        NetworkGrant::Custom(_) => return Err(Reason::UnsupportedGrant),
    }
    match manifest.output() {
        None => {}
        Some(output) if output_return && output.within_ceilings() => {}
        Some(_) => return Err(Reason::UnsupportedGrant),
    }
    match manifest.actions() {
        None => Ok(()),
        Some(actions) if action_channel && actions.within_ceilings() => Ok(()),
        Some(_) => Err(Reason::UnsupportedGrant),
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

    #[test]
    fn an_output_grant_is_honoured_only_when_enabled_and_within_the_ceilings() {
        let dir = tempfile::tempdir().unwrap();
        let plain = node_admission(&dir.path().join("state"), &FixedClock::at(NOW));
        let returning = node_admission(&dir.path().join("returning"), &FixedClock::at(NOW))
            .with_output_return(true);
        assert!(!plain.honours_output_return());
        assert!(returning.honours_output_return());
        let with = |manifest| {
            let mut input = envelope_input(lifecycle_binding());
            crate::test_support::with_manifest(&mut input, manifest);
            TaskAdmissionEnvelope::new(input).unwrap()
        };
        let modest = with(crate::test_support::output_manifest(1024, &["a"], 1024));
        assert_eq!(
            verify_signed(&plain, &modest, &issuer_keypair()).unwrap_err(),
            Reason::UnsupportedGrant
        );
        assert!(verify_signed(&returning, &modest, &issuer_keypair()).is_ok());
        for over in [
            crate::test_support::output_manifest(
                ward_node_protocol::MAX_OUTPUT_STDIO_BYTES + 1,
                &[],
                0,
            ),
            crate::test_support::output_manifest(
                0,
                &[],
                ward_node_protocol::MAX_OUTPUT_FILES_BYTES + 1,
            ),
        ] {
            assert_eq!(
                verify_signed(&returning, &with(over), &issuer_keypair()).unwrap_err(),
                Reason::UnsupportedGrant
            );
        }
        let offline = TaskAdmissionEnvelope::new(envelope_input(lifecycle_binding())).unwrap();
        assert!(verify_signed(&plain, &offline, &issuer_keypair()).is_ok());
        assert!(verify_signed(&returning, &offline, &issuer_keypair()).is_ok());
    }

    #[test]
    fn an_actions_grant_is_honoured_only_when_enabled_and_within_the_ceilings() {
        let dir = tempfile::tempdir().unwrap();
        let plain = node_admission(&dir.path().join("state"), &FixedClock::at(NOW));
        let channel = node_admission(&dir.path().join("channel"), &FixedClock::at(NOW))
            .with_action_channel(true);
        assert!(!plain.honours_action_channel());
        assert!(channel.honours_action_channel());
        let with = |manifest| {
            let mut input = envelope_input(lifecycle_binding());
            crate::test_support::with_manifest(&mut input, manifest);
            TaskAdmissionEnvelope::new(input).unwrap()
        };
        let modest = with(crate::test_support::actions_manifest(2, 4, 30));
        assert_eq!(
            verify_signed(&plain, &modest, &issuer_keypair()).unwrap_err(),
            Reason::UnsupportedGrant
        );
        assert!(verify_signed(&channel, &modest, &issuer_keypair()).is_ok());
        let ceilings = with(crate::test_support::actions_manifest(
            ward_node_protocol::MAX_ACTION_PENDING,
            ward_node_protocol::MAX_ACTION_TOTAL,
            ward_node_protocol::MAX_ACTION_WAIT_SECS,
        ));
        assert!(verify_signed(&channel, &ceilings, &issuer_keypair()).is_ok());
        for over in [
            crate::test_support::actions_manifest(
                ward_node_protocol::MAX_ACTION_PENDING + 1,
                99,
                1,
            ),
            crate::test_support::actions_manifest(1, ward_node_protocol::MAX_ACTION_TOTAL + 1, 1),
            crate::test_support::actions_manifest(
                1,
                1,
                ward_node_protocol::MAX_ACTION_WAIT_SECS + 1,
            ),
        ] {
            assert_eq!(
                verify_signed(&channel, &with(over), &issuer_keypair()).unwrap_err(),
                Reason::UnsupportedGrant
            );
        }
        let offline = TaskAdmissionEnvelope::new(envelope_input(lifecycle_binding())).unwrap();
        assert!(verify_signed(&plain, &offline, &issuer_keypair()).is_ok());
        assert!(verify_signed(&channel, &offline, &issuer_keypair()).is_ok());
    }

    #[test]
    fn a_credentials_grant_is_honoured_only_for_a_configured_service_within_its_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let configured = Some(std::sync::Arc::new(
            crate::credentials::NodeCredentials::parse(crate::test_support::CREDENTIALS).unwrap(),
        ));
        let allowlisting = node_admission(&dir.path().join("plain"), &FixedClock::at(NOW))
            .with_network_allowlist(true);
        let brokering = node_admission(&dir.path().join("brokering"), &FixedClock::at(NOW))
            .with_network_allowlist(true)
            .with_credentials(configured.clone());
        let offline_brokering = node_admission(&dir.path().join("offline"), &FixedClock::at(NOW))
            .with_credentials(configured);
        assert!(!allowlisting.honours_credentials());
        assert!(brokering.honours_credentials());
        let with = |grants: &[(&str, &str, u32)]| {
            let mut input = envelope_input(lifecycle_binding());
            crate::test_support::with_manifest(
                &mut input,
                crate::test_support::credentials_manifest(grants),
            );
            TaskAdmissionEnvelope::new(input).unwrap()
        };
        let modest = with(&[
            ("artifacts", "artifacts.example.com", 900),
            ("registry", "registry.example.com", 60),
        ]);
        assert!(verify_signed(&brokering, &modest, &issuer_keypair()).is_ok());
        for node in [&allowlisting, &offline_brokering] {
            assert_eq!(
                verify_signed(node, &modest, &issuer_keypair()).unwrap_err(),
                Reason::UnsupportedGrant
            );
        }
        for refused in [
            with(&[("artifacts", "artifacts.example.com", 901)]),
            with(&[("registry", "registry.example.com", 61)]),
            with(&[("unknown", "artifacts.example.com", 60)]),
            with(&[("artifacts", "registry.example.com", 60)]),
        ] {
            assert_eq!(
                verify_signed(&brokering, &refused, &issuer_keypair()).unwrap_err(),
                Reason::UnsupportedGrant
            );
        }
        let offline = TaskAdmissionEnvelope::new(envelope_input(lifecycle_binding())).unwrap();
        assert!(verify_signed(&allowlisting, &offline, &issuer_keypair()).is_ok());
        assert!(verify_signed(&brokering, &offline, &issuer_keypair()).is_ok());
    }
}
