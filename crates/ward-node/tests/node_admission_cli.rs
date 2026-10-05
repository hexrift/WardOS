//! End-to-end `ward-node` admission over its real local socket (ADR-0030 §2).

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
    CapabilityDiscoveryResponse, CapabilityManifestBytes, HandshakeRequest, HandshakeResponse,
    IssuerProof, IssuerSignature, OperationId, ProtocolVersion, TaskAdmissionAuthority,
    TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput, TaskBinding, TaskLifecycleContext,
    TaskLifecycleRejectionReason, TaskLifecycleRequest, TaskLifecycleResponse, TaskLifecycleState,
    TaskWorkload, WARD_NODE_PROTOCOL, WorkloadArgv,
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

fn signed_admit(context: TaskLifecycleContext, version: u64) -> TaskLifecycleRequest {
    signed_admit_issued_by(context, version, PrincipalId::from_u128(2))
}

fn signed_admit_issued_by(
    context: TaskLifecycleContext,
    version: u64,
    issuer: PrincipalId,
) -> TaskLifecycleRequest {
    let now = now_ms();
    let lease = AuthorityLease::root(
        AuthorityLeaseInput {
            id: binding().lease(),
            delegation_id: DelegationId::from_u128(6),
            issuer,
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
    .unwrap();
    let envelope = TaskAdmissionEnvelope::new(TaskAdmissionEnvelopeInput {
        binding: binding(),
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
        issued_at_unix_ms: now - 60_000,
        expires_at_unix_ms: now + 600_000,
        version: AdmissionVersion::new(version).unwrap(),
    })
    .unwrap();
    let json = AdmissionEnvelopeJson::encode(&envelope).unwrap();
    let key_pair = key_pair();
    let proof = IssuerProof::new(
        Blake3Hash::hash(key_pair.public_key().as_ref()),
        IssuerSignature::from_bytes(key_pair.sign(json.as_bytes()).as_ref().try_into().unwrap()),
    );
    context
        .admit(OperationId::new(2).unwrap(), binding(), json, proof)
        .unwrap()
}

struct Node {
    child: Child,
    socket: PathBuf,
}

impl Node {
    fn spawn(dir: &Path, trusted_issuers: Option<&Path>) -> Self {
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
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(path) = trusted_issuers {
            command.arg("--trusted-issuers").arg(path);
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
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn context() -> TaskLifecycleContext {
    TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn trust_store(dir: &Path, mode: u32) -> PathBuf {
    let path = dir.join("trusted-issuers");
    std::fs::write(
        &path,
        format!(
            "# local issuer\n{} {}\n",
            hex(key_pair().public_key().as_ref()),
            PrincipalId::from_u128(2)
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn issuer_key_id_helper_prints_the_blake3_id_of_the_public_key() {
    let public_key = hex(key_pair().public_key().as_ref());
    let output = Command::new(env!("CARGO_BIN_EXE_ward-node"))
        .args(["issuer-key-id", &public_key])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        Blake3Hash::hash(key_pair().public_key().as_ref()).to_hex()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_ward-node"))
        .args(["issuer-key-id", "not-a-key"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn ward_node_admits_a_signed_envelope_and_refuses_its_replay_after_restart() {
    let dir = private_dir();
    let issuers = trust_store(dir.path(), 0o600);
    let ctx = context();
    let create = ctx.create(OperationId::new(1).unwrap(), binding());

    let node = Node::spawn(dir.path(), Some(&issuers));
    let discovery = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
    let CapabilityDiscoveryResponse::Capabilities { capabilities } = discovery
        .decode_response(&node.request(&serde_json::to_string(&discovery.request()).unwrap()))
        .unwrap();
    assert!(capabilities.lifecycle().admit);
    assert!(!capabilities.lifecycle().stop);

    node.lifecycle(&create);
    let admit = signed_admit(ctx, 1);
    assert_eq!(
        node.lifecycle(&admit),
        ctx.accepted(
            OperationId::new(2).unwrap(),
            binding(),
            TaskLifecycleState::Ready
        )
    );
    assert_eq!(
        node.lifecycle(&ctx.inspect(binding())),
        ctx.inspected(binding(), TaskLifecycleState::Ready)
    );
    assert_eq!(
        std::fs::metadata(dir.path().join("state"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    drop(node);

    let node = Node::spawn(dir.path(), Some(&issuers));
    node.lifecycle(&create);
    assert_eq!(
        node.lifecycle(&admit),
        ctx.rejected(
            Some(OperationId::new(2).unwrap()),
            binding(),
            TaskLifecycleRejectionReason::StaleOperation
        )
    );
    assert_eq!(
        node.lifecycle(&ctx.inspect(binding())),
        ctx.inspected(binding(), TaskLifecycleState::Created)
    );
    assert_eq!(
        node.lifecycle(&signed_admit(ctx, 2)),
        ctx.accepted(
            OperationId::new(2).unwrap(),
            binding(),
            TaskLifecycleState::Ready
        )
    );
}

#[test]
fn ward_node_without_trusted_issuers_denies_every_admit() {
    let dir = private_dir();
    let node = Node::spawn(dir.path(), None);
    let ctx = context();
    node.lifecycle(&ctx.create(OperationId::new(1).unwrap(), binding()));
    assert_eq!(
        node.lifecycle(&signed_admit(ctx, 1)),
        ctx.rejected(
            Some(OperationId::new(2).unwrap()),
            binding(),
            TaskLifecycleRejectionReason::AuthorityDenied
        )
    );
    assert_eq!(
        node.lifecycle(&ctx.inspect(binding())),
        ctx.inspected(binding(), TaskLifecycleState::Created)
    );
}

#[test]
fn ward_node_refuses_to_start_with_an_unsafe_trust_store_or_a_foreign_state_dir() {
    let dir = private_dir();
    let status = Command::new(env!("CARGO_BIN_EXE_ward-node"))
        .arg("--socket")
        .arg(dir.path().join("node.sock"))
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .arg("--node-id")
        .arg(NODE.to_string())
        .arg("--trusted-issuers")
        .arg(trust_store(dir.path(), 0o666))
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
    assert!(!dir.path().join("node.sock").exists());

    drop(Node::spawn(dir.path(), None));
    let status = Command::new(env!("CARGO_BIN_EXE_ward-node"))
        .arg("--socket")
        .arg(dir.path().join("other.sock"))
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .arg("--node-id")
        .arg(NodeId::from_u128(99).to_string())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
    assert!(!dir.path().join("other.sock").exists());
}

#[test]
fn ward_node_admits_only_leases_issued_by_the_principal_bound_to_the_signing_key() {
    let dir = private_dir();
    let issuers = trust_store(dir.path(), 0o600);
    let node = Node::spawn(dir.path(), Some(&issuers));
    let ctx = context();
    node.lifecycle(&ctx.create(OperationId::new(1).unwrap(), binding()));

    assert_eq!(
        node.lifecycle(&signed_admit_issued_by(ctx, 1, PrincipalId::from_u128(9))),
        ctx.rejected(
            Some(OperationId::new(2).unwrap()),
            binding(),
            TaskLifecycleRejectionReason::AuthorityDenied
        )
    );
    assert_eq!(
        node.lifecycle(&ctx.inspect(binding())),
        ctx.inspected(binding(), TaskLifecycleState::Created)
    );
    assert_eq!(
        node.lifecycle(&signed_admit(ctx, 1)),
        ctx.accepted(
            OperationId::new(2).unwrap(),
            binding(),
            TaskLifecycleState::Ready
        )
    );
}

#[test]
fn ward_node_refuses_to_start_with_a_trusted_key_bound_to_no_issuer() {
    let dir = private_dir();
    let path = dir.path().join("trusted-issuers");
    std::fs::write(
        &path,
        format!("{}\n", hex(key_pair().public_key().as_ref())),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ward-node"))
        .arg("--socket")
        .arg(dir.path().join("node.sock"))
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .arg("--node-id")
        .arg(NODE.to_string())
        .arg("--trusted-issuers")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("ward-node served with a trusted key bound to no issuer");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("MissingIssuer { line: 1 }"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!dir.path().join("node.sock").exists());
}
