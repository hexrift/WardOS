#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::{
    AgentId, Blake3Hash, DelegationId, ExecutionAttemptId, LeaseId, NodeId, PrincipalId, SessionId,
    SnapshotId, TaskId,
};

use crate::{
    AdmissionVersion, CapabilityManifestBytes, IssuerProof, IssuerSignature,
    TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput, TaskBinding,
    TaskWorkload, WorkloadArgv,
};

pub const MANIFEST_BYTES: &[u8] = br#"{"network":"offline"}"#;

pub const ENVELOPE_JSON: &str = concat!(
    r#"{"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"},"#,
    r#""agent":"agent_00000000000000000000000003","#,
    r#""node":"node_00000000000000000000000004","#,
    r#""session":"sess_00000000000000000000000005","#,
    r#""authority":{"lease":{"id":"lease_00000000000000000000000009","delegation_id":"deleg_00000000000000000000000006","issuer":"prn_00000000000000000000000002","subject":"agent_00000000000000000000000003","task":"task_00000000000000000000000007","parent_lease_id":null,"delegated_by":null,"grants":[{"capability":"repo.read","resource":"repo:hexrift/WardOS","delegable":false}],"issued_at_unix_ms":1000,"expires_at_unix_ms":9000,"version":1},"lineage":[]},"#,
    r#""workload":{"argv":["cargo","test"],"capability_manifest":{"hash":"eb3e889be30ae8dd712a52c33e37aaca72e52ccff1aa770ecbd962d0cdb0d0c3","bytes":"7b226e6574776f726b223a226f66666c696e65227d"},"snapshot":"1111111111111111111111111111111111111111111111111111111111111111","wall_clock_budget_ms":600000},"#,
    r#""issued_at_unix_ms":2000,"#,
    r#""expires_at_unix_ms":8000,"#,
    r#""version":1}"#,
);

pub const PROOF_JSON: &str = r#"{"issuer_key_id":"2222222222222222222222222222222222222222222222222222222222222222","signature":"33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"}"#;

pub fn binding() -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(7),
        ExecutionAttemptId::from_u128(8),
        LeaseId::from_u128(9),
    )
}

pub fn trusted_lease() -> AuthorityLease {
    AuthorityLease::root(
        AuthorityLeaseInput {
            id: LeaseId::from_u128(9),
            delegation_id: DelegationId::from_u128(6),
            issuer: PrincipalId::from_u128(2),
            subject: AgentId::from_u128(3),
            task: TaskId::from_u128(7),
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
    .unwrap()
}

pub fn lease() -> UntrustedAuthorityLease {
    UntrustedAuthorityLease::from(&trusted_lease())
}

pub fn argv() -> WorkloadArgv {
    WorkloadArgv::new(vec!["cargo".to_owned(), "test".to_owned()]).unwrap()
}

pub fn manifest() -> CapabilityManifestBytes {
    CapabilityManifestBytes::new(MANIFEST_BYTES.to_vec()).unwrap()
}

pub fn snapshot() -> SnapshotId {
    SnapshotId::new(Blake3Hash::from_bytes([0x11; 32]))
}

pub fn workload() -> TaskWorkload {
    TaskWorkload::new(argv(), manifest(), snapshot(), 600_000).unwrap()
}

pub fn proof() -> IssuerProof {
    IssuerProof::new(
        Blake3Hash::from_bytes([0x22; 32]),
        IssuerSignature::from_bytes([0x33; 64]),
    )
}

pub fn input() -> TaskAdmissionEnvelopeInput {
    TaskAdmissionEnvelopeInput {
        binding: binding(),
        agent: AgentId::from_u128(3),
        node: NodeId::from_u128(4),
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(lease(), Vec::new()).unwrap(),
        workload: workload(),
        issued_at_unix_ms: 2_000,
        expires_at_unix_ms: 8_000,
        version: AdmissionVersion::new(1).unwrap(),
    }
}

pub fn envelope() -> TaskAdmissionEnvelope {
    TaskAdmissionEnvelope::new(input()).unwrap()
}
