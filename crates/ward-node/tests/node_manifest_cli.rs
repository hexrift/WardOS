//! End-to-end `ward-node` capability-manifest interpretation over its real local socket
//! (ADR-0030 §2): the node admits only a manifest whose every grant it honours.
//!
//! The admission cases run everywhere. The executing-node case needs a working bubblewrap
//! and skips without one, except under `WARD_REQUIRE_ISOLATION=1`, where CI runs it for
//! real.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    AdmissionEnvelopeJson, AdmissionVersion, CapabilityDiscoveryContext,
    CapabilityDiscoveryResponse, CapabilityManifest, CapabilityManifestBytes, HandshakeRequest,
    HandshakeResponse, HostAllowlist, IssuerProof, IssuerSignature, NetworkGrant, NodeCapabilities,
    OperationId, ProtocolVersion, TaskAdmissionAuthority, TaskAdmissionEnvelope,
    TaskAdmissionEnvelopeInput, TaskBinding, TaskLifecycleContext, TaskLifecycleRejectionReason,
    TaskLifecycleRequest, TaskLifecycleResponse, TaskLifecycleState, TaskWorkload,
    WARD_NODE_PROTOCOL, WorkloadArgv,
};

const NODE: NodeId = NodeId::from_u128(4);

fn key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn binding() -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(7),
        ExecutionAttemptId::from_u128(8),
        LeaseId::from_u128(9),
    )
}

fn op(value: u64) -> OperationId {
    OperationId::new(value).unwrap()
}

fn context() -> TaskLifecycleContext {
    TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
}

fn isolation() -> bool {
    ward_sandbox::ci::isolation_ready(ward_launch::available(), "bubblewrap")
}

fn offline_manifest() -> CapabilityManifestBytes {
    CapabilityManifestBytes::encode(&CapabilityManifest::new(NetworkGrant::Offline)).unwrap()
}

fn network_manifest() -> CapabilityManifestBytes {
    CapabilityManifestBytes::encode(&CapabilityManifest::new(NetworkGrant::Custom(
        HostAllowlist::new(vec!["github.com".to_owned(), "*.crates.io".to_owned()]).unwrap(),
    )))
    .unwrap()
}

fn lease(now: u64) -> AuthorityLease {
    AuthorityLease::root(
        AuthorityLeaseInput {
            id: binding().lease(),
            delegation_id: DelegationId::from_u128(6),
            issuer: PrincipalId::from_u128(2),
            subject: AgentId::from_u128(3),
            task: binding().task(),
            grants: GrantSet::new([CapabilityGrant::new(
                CapabilityName::new("repo.read").unwrap(),
                ResourceRef::new("repo:hexrift/WardOS").unwrap(),
                false,
            )])
            .unwrap(),
            issued_at_unix_ms: now - 60_000,
            expires_at_unix_ms: now + 600_000,
            version: LeaseVersion::new(1).unwrap(),
        },
        now,
        EmptyAuthorityPolicy::Reject,
    )
    .unwrap()
}

fn envelope_json(version: u64, manifest: CapabilityManifestBytes) -> AdmissionEnvelopeJson {
    let now = now_ms();
    let lease = lease(now);
    let envelope = TaskAdmissionEnvelope::new(TaskAdmissionEnvelopeInput {
        binding: binding(),
        agent: AgentId::from_u128(3),
        node: NODE,
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new())
            .unwrap(),
        workload: TaskWorkload::new(
            WorkloadArgv::new(vec!["cargo".to_owned(), "test".to_owned()]).unwrap(),
            manifest,
            SnapshotId::new(Blake3Hash::from_bytes([0x11; 32])),
            600_000,
        )
        .unwrap(),
        issued_at_unix_ms: now - 60_000,
        expires_at_unix_ms: now + 600_000,
        version: AdmissionVersion::new(version).unwrap(),
    })
    .unwrap();
    AdmissionEnvelopeJson::encode(&envelope).unwrap()
}

fn signed(json: AdmissionEnvelopeJson) -> TaskLifecycleRequest {
    let key_pair = key_pair();
    let proof = IssuerProof::new(
        Blake3Hash::hash(key_pair.public_key().as_ref()),
        IssuerSignature::from_bytes(key_pair.sign(json.as_bytes()).as_ref().try_into().unwrap()),
    );
    context().admit(op(2), binding(), json, proof).unwrap()
}

fn signed_admit(version: u64, manifest: CapabilityManifestBytes) -> TaskLifecycleRequest {
    signed(envelope_json(version, manifest))
}

/// A signed envelope whose manifest bytes are `raw`, hash-bound but outside the grammar.
fn signed_admit_with_raw_manifest(raw: &[u8]) -> TaskLifecycleRequest {
    let mut value: serde_json::Value =
        serde_json::from_slice(envelope_json(1, offline_manifest()).as_bytes()).unwrap();
    value["workload"]["capability_manifest"] = serde_json::json!({
        "hash": Blake3Hash::hash(raw).to_hex(),
        "bytes": hex(raw),
    });
    signed(AdmissionEnvelopeJson::new(value.to_string()).unwrap())
}

struct Node {
    child: Child,
    socket: PathBuf,
}

impl Node {
    fn spawn(dir: &Path, task_root: Option<&Path>) -> Self {
        let socket = dir.join("node.sock");
        let _ = std::fs::remove_file(&socket);
        let mut command = Command::new(env!("CARGO_BIN_EXE_ward-node"));
        command
            .arg("--socket")
            .arg(&socket)
            .arg("--state-dir")
            .arg(dir.join("state"))
            .arg("--node-id")
            .arg(NODE.to_string())
            .arg("--trusted-issuers")
            .arg(trust_store(dir))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(task_root) = task_root {
            command.arg("--task-root").arg(task_root);
        }
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while UnixStream::connect(&socket).is_err() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "ward-node exited before serving"
            );
            assert!(
                Instant::now() < deadline,
                "ward-node did not bind its socket"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Self { child, socket }
    }

    fn request(&self, request: &str) -> String {
        let mut client = UnixStream::connect(&self.socket).unwrap();
        let hello = HandshakeRequest::Hello {
            protocol: WARD_NODE_PROTOCOL,
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(
            serde_json::from_str::<HandshakeResponse>(line.trim()).unwrap(),
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 3)
            }
        );
        writeln!(client, "{request}").unwrap();
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        response.trim().to_owned()
    }

    fn lifecycle(&self, request: &TaskLifecycleRequest) -> TaskLifecycleResponse {
        context()
            .decode_response(&self.request(&serde_json::to_string(request).unwrap()))
            .unwrap()
    }

    fn capabilities(&self) -> NodeCapabilities {
        let discovery = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let CapabilityDiscoveryResponse::Capabilities { capabilities } = discovery
            .decode_response(&self.request(&serde_json::to_string(&discovery.request()).unwrap()))
            .unwrap();
        capabilities
    }

    fn state(&self) -> TaskLifecycleState {
        match self.lifecycle(&context().inspect(binding())) {
            TaskLifecycleResponse::Inspected { state, .. } => state,
            other => panic!("inspect failed: {other:?}"),
        }
    }

    #[track_caller]
    fn assert_refused(&self, request: &TaskLifecycleRequest, reason: TaskLifecycleRejectionReason) {
        assert_eq!(
            self.lifecycle(request),
            context().rejected(Some(op(2)), binding(), reason)
        );
        assert_eq!(self.state(), TaskLifecycleState::Created);
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn trust_store(dir: &Path) -> PathBuf {
    let path = dir.join("trusted-issuers");
    std::fs::write(
        &path,
        format!(
            "{} {}\n",
            hex(key_pair().public_key().as_ref()),
            PrincipalId::from_u128(2)
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

#[test]
fn ward_node_refuses_a_network_grant_it_cannot_honour_and_admits_the_offline_manifest() {
    let dir = private_dir();
    let node = Node::spawn(dir.path(), None);
    let capabilities = node.capabilities();
    assert!(capabilities.lifecycle().admit);
    assert!(!capabilities.network().proxy_allowlist);

    node.lifecycle(&context().create(op(1), binding()));
    let network = signed_admit(1, network_manifest());
    node.assert_refused(&network, TaskLifecycleRejectionReason::UnsupportedGrant);
    node.assert_refused(&network, TaskLifecycleRejectionReason::UnsupportedGrant);

    for raw in [
        &b"{}"[..],
        br#"{"network":"development"}"#,
        br#"{"network":{"custom":[]}}"#,
        br#"{"network":{"allow_hosts":["github.com"]}}"#,
    ] {
        node.assert_refused(
            &signed_admit_with_raw_manifest(raw),
            TaskLifecycleRejectionReason::AuthorityDenied,
        );
    }

    assert_eq!(
        node.lifecycle(&signed_admit(1, offline_manifest())),
        context().accepted(op(2), binding(), TaskLifecycleState::Ready)
    );
    assert_eq!(node.state(), TaskLifecycleState::Ready);
    assert_eq!(
        node.lifecycle(&network),
        context().rejected(
            Some(op(2)),
            binding(),
            TaskLifecycleRejectionReason::InvalidState
        )
    );
    assert_eq!(node.state(), TaskLifecycleState::Ready);
}

#[test]
fn an_executing_ward_node_refuses_a_network_grant_before_anything_exists_under_its_task_root() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let dir = private_dir();
    let task_root = dir.path().join("tasks");
    let node = Node::spawn(dir.path(), Some(&task_root));
    let capabilities = node.capabilities();
    assert!(capabilities.lifecycle().start);
    assert!(capabilities.network().offline);
    assert!(!capabilities.network().proxy_allowlist);

    node.lifecycle(&context().create(op(1), binding()));
    node.assert_refused(
        &signed_admit(1, network_manifest()),
        TaskLifecycleRejectionReason::UnsupportedGrant,
    );
    assert!(
        std::fs::read_dir(&task_root).unwrap().next().is_none(),
        "a refused admit must leave the task root empty"
    );

    assert_eq!(
        node.lifecycle(&signed_admit(1, offline_manifest())),
        context().accepted(op(2), binding(), TaskLifecycleState::Ready)
    );
    assert!(task_root.join(binding().task().to_string()).is_dir());
}
