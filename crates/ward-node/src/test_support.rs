#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ring::signature::{Ed25519KeyPair, KeyPair};
use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::{
    AgentId, Blake3Hash, DelegationId, ExecutionAttemptId, LeaseId, NodeId, PrincipalId, SessionId,
    SnapshotId, TaskId,
};
use ward_node_protocol::{
    AdmissionEnvelopeJson, AdmissionVersion, CapabilityManifestBytes, IssuerProof, IssuerSignature,
    OperationId, TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput,
    TaskBinding, TaskLifecycleContext, TaskLifecycleRequest, TaskWorkload, WorkloadArgv,
};

use crate::admit::{NodeAdmission, NodeClock};
use crate::issuer::{IssuerPublicKey, TrustedIssuers};
use crate::state::NodeState;

/// Deterministic seed of the trusted test issuer key.
pub const ISSUER_SEED: [u8; 32] = [7; 32];

/// Deterministic seed of an issuer key the node does not trust.
pub const OTHER_SEED: [u8; 32] = [8; 32];

/// The node identity every admission test runs as.
pub const NODE: NodeId = NodeId::from_u128(4);

/// A time at which the default test envelope and lease are both valid.
pub const NOW: u64 = 5_000;

pub fn issuer_keypair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&ISSUER_SEED).unwrap()
}

pub fn other_keypair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&OTHER_SEED).unwrap()
}

pub fn issuer_public_key() -> IssuerPublicKey {
    IssuerPublicKey::from_bytes(issuer_keypair().public_key().as_ref().try_into().unwrap())
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

pub fn lifecycle_binding() -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(7),
        ExecutionAttemptId::from_u128(8),
        LeaseId::from_u128(9),
    )
}

pub fn trusted_root_lease() -> AuthorityLease {
    root_lease(lifecycle_binding(), 1_000, 9_000)
}

pub fn root_lease(binding: TaskBinding, issued_at: u64, expires_at: u64) -> AuthorityLease {
    AuthorityLease::root(
        AuthorityLeaseInput {
            id: binding.lease(),
            delegation_id: DelegationId::from_u128(6),
            issuer: PrincipalId::from_u128(2),
            subject: AgentId::from_u128(3),
            task: binding.task(),
            grants: GrantSet::new([CapabilityGrant::new(
                CapabilityName::new("repo.read").unwrap(),
                ResourceRef::new("repo:hexrift/WardOS").unwrap(),
                true,
            )])
            .unwrap(),
            issued_at_unix_ms: issued_at,
            expires_at_unix_ms: expires_at,
            version: LeaseVersion::new(1).unwrap(),
        },
        issued_at,
        EmptyAuthorityPolicy::Reject,
    )
    .unwrap()
}

/// A valid envelope input for `binding`, addressed to [`NODE`], signed-ready.
pub fn envelope_input(binding: TaskBinding) -> TaskAdmissionEnvelopeInput {
    let lease = root_lease(binding, 1_000, 9_000);
    TaskAdmissionEnvelopeInput {
        binding,
        agent: AgentId::from_u128(3),
        node: NODE,
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new())
            .unwrap(),
        workload: TaskWorkload::new(
            WorkloadArgv::new(vec!["cargo".to_owned(), "test".to_owned()]).unwrap(),
            CapabilityManifestBytes::new(br#"{"network":"offline"}"#.to_vec()).unwrap(),
            SnapshotId::new(Blake3Hash::from_bytes([0x11; 32])),
            600_000,
        )
        .unwrap(),
        issued_at_unix_ms: 2_000,
        expires_at_unix_ms: 8_000,
        version: AdmissionVersion::new(1).unwrap(),
    }
}

pub fn sign(json: &AdmissionEnvelopeJson, key_pair: &Ed25519KeyPair) -> IssuerProof {
    IssuerProof::new(
        Blake3Hash::hash(key_pair.public_key().as_ref()),
        IssuerSignature::from_bytes(key_pair.sign(json.as_bytes()).as_ref().try_into().unwrap()),
    )
}

/// An `admit` for `envelope`, signed by the trusted test issuer.
pub fn signed_admit(
    context: TaskLifecycleContext,
    operation_id: OperationId,
    binding: TaskBinding,
    envelope: &TaskAdmissionEnvelope,
) -> TaskLifecycleRequest {
    let json = AdmissionEnvelopeJson::encode(envelope).unwrap();
    let proof = sign(&json, &issuer_keypair());
    context.admit(operation_id, binding, json, proof).unwrap()
}

/// A settable test clock.
#[derive(Clone, Debug)]
pub struct FixedClock(Arc<AtomicU64>);

impl FixedClock {
    pub fn at(now_unix_ms: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now_unix_ms)))
    }

    pub fn set(&self, now_unix_ms: u64) {
        self.0.store(now_unix_ms, Ordering::SeqCst);
    }
}

impl NodeClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Admission for [`NODE`] trusting only the test issuer, with state under `dir`.
pub fn node_admission(dir: &Path, clock: &FixedClock) -> NodeAdmission {
    NodeAdmission::new(
        TrustedIssuers::new([issuer_public_key()]),
        NodeState::open(dir, NODE).unwrap(),
        Box::new(clock.clone()),
    )
}

pub fn admit(
    context: TaskLifecycleContext,
    operation_id: OperationId,
    binding: TaskBinding,
) -> TaskLifecycleRequest {
    context
        .admit(
            operation_id,
            binding,
            AdmissionEnvelopeJson::encode(&admission_envelope(binding)).unwrap(),
            IssuerProof::new(
                Blake3Hash::from_bytes([0x22; 32]),
                IssuerSignature::from_bytes([0x33; 64]),
            ),
        )
        .unwrap()
}

fn admission_envelope(binding: TaskBinding) -> TaskAdmissionEnvelope {
    let lease = AuthorityLease::root(
        AuthorityLeaseInput {
            id: binding.lease(),
            delegation_id: DelegationId::from_u128(6),
            issuer: PrincipalId::from_u128(2),
            subject: AgentId::from_u128(3),
            task: binding.task(),
            grants: GrantSet::new([CapabilityGrant::new(
                CapabilityName::new("repo.read").unwrap(),
                ResourceRef::new("repo:hexrift/WardOS").unwrap(),
                false,
            )])
            .unwrap(),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 9_000,
            version: LeaseVersion::new(1).unwrap(),
        },
        2_000,
        EmptyAuthorityPolicy::Reject,
    )
    .unwrap();

    TaskAdmissionEnvelope::new(TaskAdmissionEnvelopeInput {
        binding,
        agent: AgentId::from_u128(3),
        node: NodeId::from_u128(4),
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new())
            .unwrap(),
        workload: TaskWorkload::new(
            WorkloadArgv::new(vec!["cargo".to_owned(), "test".to_owned()]).unwrap(),
            CapabilityManifestBytes::new(br#"{"network":"offline"}"#.to_vec()).unwrap(),
            SnapshotId::new(Blake3Hash::from_bytes([0x11; 32])),
            600_000,
        )
        .unwrap(),
        issued_at_unix_ms: 2_000,
        expires_at_unix_ms: 8_000,
        version: AdmissionVersion::new(1).unwrap(),
    })
    .unwrap()
}
