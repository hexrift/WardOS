#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::{AgentId, Blake3Hash, DelegationId, NodeId, PrincipalId, SessionId, SnapshotId};
use ward_node_protocol::{
    AdmissionEnvelopeJson, AdmissionVersion, CapabilityManifestBytes, IssuerProof, IssuerSignature,
    OperationId, TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput,
    TaskBinding, TaskLifecycleContext, TaskLifecycleRequest, TaskWorkload, WorkloadArgv,
};

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
