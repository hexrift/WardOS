//! The envelope input refuses anything out of bounds, or not bound to its own binding,
//! before an issuer can sign it (node-integration.md §7.3).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::{
    AgentId, Blake3Hash, DelegationId, ExecutionAttemptId, LeaseId, NodeId, PrincipalId, SessionId,
    SnapshotId, TaskId,
};
use ward_node_client::{EnvelopeError, EnvelopeInput, WorkloadInput, offline_manifest};
use ward_node_protocol::{
    CapabilityManifestBytes, NetworkGrant, TaskAdmissionAuthority, TaskAdmissionError, TaskBinding,
};

fn binding() -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(7),
        ExecutionAttemptId::from_u128(8),
        LeaseId::from_u128(9),
    )
}

fn lease(id: LeaseId, task: TaskId, subject: AgentId) -> UntrustedAuthorityLease {
    UntrustedAuthorityLease::from(
        &AuthorityLease::root(
            AuthorityLeaseInput {
                id,
                delegation_id: DelegationId::from_u128(6),
                issuer: PrincipalId::from_u128(2),
                subject,
                task,
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
        .unwrap(),
    )
}

fn input() -> EnvelopeInput {
    EnvelopeInput {
        binding: binding(),
        agent: AgentId::from_u128(3),
        node: NodeId::from_u128(4),
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(
            lease(
                LeaseId::from_u128(9),
                TaskId::from_u128(7),
                AgentId::from_u128(3),
            ),
            Vec::new(),
        )
        .unwrap(),
        workload: WorkloadInput {
            argv: vec!["cargo".to_owned(), "test".to_owned()],
            capability_manifest: None,
            snapshot: SnapshotId::new(Blake3Hash::from_bytes([0x11; 32])),
            wall_clock_budget_ms: 600_000,
        },
        issued_at_unix_ms: 2_000,
        expires_at_unix_ms: 8_000,
        version: 1,
    }
}

const JSON: &str = r#"{
  "binding": {"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"},
  "agent": "agent_00000000000000000000000003",
  "node": "node_00000000000000000000000004",
  "session": "sess_00000000000000000000000005",
  "authority": {"lease": {"id":"lease_00000000000000000000000009","delegation_id":"deleg_00000000000000000000000006","issuer":"prn_00000000000000000000000002","subject":"agent_00000000000000000000000003","task":"task_00000000000000000000000007","parent_lease_id":null,"delegated_by":null,"grants":[{"capability":"repo.read","resource":"repo:hexrift/WardOS","delegable":false}],"issued_at_unix_ms":1000,"expires_at_unix_ms":9000,"version":1}, "lineage": []},
  "workload": {"argv":["cargo","test"],"snapshot":"1111111111111111111111111111111111111111111111111111111111111111","wall_clock_budget_ms":600000},
  "issued_at_unix_ms": 2000,
  "expires_at_unix_ms": 8000,
  "version": 1
}"#;

#[test]
fn a_well_formed_input_builds_the_envelope_with_an_offline_manifest_by_default() {
    let envelope = input().build().unwrap();
    assert_eq!(envelope.binding(), binding());
    assert_eq!(
        envelope.workload().capability_manifest().bytes(),
        br#"{"network":"offline"}"#
    );
    assert_eq!(
        envelope.workload().capability_manifest(),
        &offline_manifest().unwrap()
    );
    assert_eq!(envelope.workload().wall_clock_budget_ms(), 600_000);
    assert_eq!(envelope.version().get(), 1);

    let parsed: EnvelopeInput = serde_json::from_str(JSON).unwrap();
    assert_eq!(parsed, input());
    assert_eq!(parsed.build().unwrap(), envelope);
}

#[test]
fn the_manifest_is_given_as_its_object_and_read_strictly() {
    let with_manifest = JSON.replace(
        r#""argv":["cargo","test"],"#,
        r#""argv":["cargo","test"],"capability_manifest":{"network":{"custom":["github.com"]}},"#,
    );
    let parsed: EnvelopeInput = serde_json::from_str(&with_manifest).unwrap();
    let manifest = parsed.workload.capability_manifest.clone().unwrap();
    assert!(matches!(
        manifest.manifest().network(),
        NetworkGrant::Custom(hosts) if hosts.patterns() == ["github.com"]
    ));
    assert_eq!(
        parsed.build().unwrap().workload().capability_manifest(),
        &manifest
    );

    let preset = JSON.replace(
        r#""argv":["cargo","test"],"#,
        r#""argv":["cargo","test"],"capability_manifest":{"network":"development"},"#,
    );
    assert!(serde_json::from_str::<EnvelopeInput>(&preset).is_err());
    let hashed = JSON.replace(
        r#""argv":["cargo","test"],"#,
        r#""argv":["cargo","test"],"capability_manifest":{"hash":"00","bytes":"00"},"#,
    );
    assert!(serde_json::from_str::<EnvelopeInput>(&hashed).is_err());
}

#[test]
fn unknown_fields_and_host_paths_are_refused_at_parse_time() {
    let with_path = JSON.replace(r#""version": 1"#, r#""version": 1, "workspace": "/tmp/x""#);
    assert!(serde_json::from_str::<EnvelopeInput>(&with_path).is_err());
    let lower_case_id = JSON.replace(
        "task_00000000000000000000000007",
        "task_0000000000000000000000000z",
    );
    assert!(serde_json::from_str::<EnvelopeInput>(&lower_case_id).is_err());
}

#[test]
fn out_of_bound_inputs_are_refused_before_signing() {
    let mut zero_budget = input();
    zero_budget.workload.wall_clock_budget_ms = 0;
    assert_eq!(
        zero_budget.build().unwrap_err(),
        EnvelopeError::Admission(TaskAdmissionError::ZeroBudget)
    );

    let mut inverted = input();
    inverted.expires_at_unix_ms = inverted.issued_at_unix_ms;
    assert_eq!(
        inverted.build().unwrap_err(),
        EnvelopeError::Admission(TaskAdmissionError::InvalidLifetime)
    );

    let mut no_argv = input();
    no_argv.workload.argv.clear();
    assert_eq!(
        no_argv.build().unwrap_err(),
        EnvelopeError::Admission(TaskAdmissionError::EmptyArgv)
    );

    let mut long_argv = input();
    long_argv.workload.argv = vec!["x".repeat(4_097)];
    assert_eq!(
        long_argv.build().unwrap_err(),
        EnvelopeError::Admission(TaskAdmissionError::ArgumentTooLong)
    );

    let mut zero_version = input();
    zero_version.version = 0;
    assert_eq!(
        zero_version.build().unwrap_err(),
        EnvelopeError::Admission(TaskAdmissionError::ZeroVersion)
    );

    let mut too_large = input();
    too_large.workload.argv = (0..250).map(|_| "y".repeat(80)).collect();
    assert_eq!(
        too_large.build().unwrap_err(),
        EnvelopeError::Admission(TaskAdmissionError::ArgvTooLong)
    );
}

#[test]
fn a_lease_that_does_not_bind_this_task_agent_and_lease_is_refused() {
    let mut other_lease = input();
    other_lease.authority = TaskAdmissionAuthority::new(
        lease(
            LeaseId::from_u128(99),
            TaskId::from_u128(7),
            AgentId::from_u128(3),
        ),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        other_lease.build().unwrap_err(),
        EnvelopeError::LeaseNotBound
    );

    let mut other_task = input();
    other_task.authority = TaskAdmissionAuthority::new(
        lease(
            LeaseId::from_u128(9),
            TaskId::from_u128(77),
            AgentId::from_u128(3),
        ),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        other_task.build().unwrap_err(),
        EnvelopeError::LeaseTaskMismatch
    );

    let mut other_agent = input();
    other_agent.authority = TaskAdmissionAuthority::new(
        lease(
            LeaseId::from_u128(9),
            TaskId::from_u128(7),
            AgentId::from_u128(33),
        ),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        other_agent.build().unwrap_err(),
        EnvelopeError::AgentNotSubject
    );

    let lineage: Vec<_> = (0..17)
        .map(|_| {
            lease(
                LeaseId::from_u128(1),
                TaskId::from_u128(7),
                AgentId::from_u128(3),
            )
        })
        .collect();
    assert_eq!(
        TaskAdmissionAuthority::new(
            lease(
                LeaseId::from_u128(9),
                TaskId::from_u128(7),
                AgentId::from_u128(3)
            ),
            lineage
        )
        .unwrap_err(),
        TaskAdmissionError::LineageTooLong
    );
    let _ = CapabilityManifestBytes::MAX_BYTES;
}
