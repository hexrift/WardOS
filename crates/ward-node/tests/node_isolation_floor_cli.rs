//! End-to-end isolation floors on a real `ward-node` over its local socket (#263,
//! ADR-0039): a node runs an attempt only on a Capsule backend at least as strong as its
//! manifest's `isolation.minimum`, refuses any floor it cannot meet `unsupported_grant`
//! at `admit` with nothing materialised, runs a manifest without a floor exactly as
//! before, and records the backend that ran it in the attempt's task record.
//!
//! The admission cases run everywhere. The executing-node cases need a working bubblewrap
//! and skip without one, except under `WARD_REQUIRE_ISOLATION=1`, where CI runs them for
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
    HandshakeResponse, IsolationGrant, IsolationLevel, IssuerProof, IssuerSignature, NetworkGrant,
    NodeCapabilities, OperationId, ProtocolVersion, TaskAdmissionAuthority, TaskAdmissionEnvelope,
    TaskAdmissionEnvelopeInput, TaskBinding, TaskExecutionOutcome, TaskLifecycleContext,
    TaskLifecycleRejectionReason, TaskLifecycleRequest, TaskLifecycleResponse, TaskLifecycleState,
    TaskWorkload, WARD_NODE_PROTOCOL, WorkloadArgv,
};

const NODE: NodeId = NodeId::from_u128(4);

const FLOORS: [IsolationLevel; 3] = [
    IsolationLevel::Container,
    IsolationLevel::Microvm,
    IsolationLevel::Vm,
];

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

fn unmarked() -> CapabilityManifestBytes {
    CapabilityManifestBytes::encode(&CapabilityManifest::new(NetworkGrant::Offline)).unwrap()
}

fn floored(level: IsolationLevel) -> CapabilityManifestBytes {
    CapabilityManifestBytes::encode(
        &CapabilityManifest::new(NetworkGrant::Offline)
            .with_isolation(IsolationGrant::new(level).unwrap()),
    )
    .unwrap()
}

fn signed_admit(
    version: u64,
    manifest: CapabilityManifestBytes,
    snapshot: SnapshotId,
    argv: &[&str],
) -> TaskLifecycleRequest {
    let now = now_ms();
    let lease = AuthorityLease::root(
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
    .unwrap();
    let envelope = TaskAdmissionEnvelope::new(TaskAdmissionEnvelopeInput {
        binding: binding(),
        agent: AgentId::from_u128(3),
        node: NODE,
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new())
            .unwrap(),
        workload: TaskWorkload::new(
            WorkloadArgv::new(argv.iter().map(|arg| (*arg).to_owned()).collect()).unwrap(),
            manifest,
            snapshot,
            60_000,
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
    context().admit(op(2), binding(), json, proof).unwrap()
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

fn imported(dir: &Path) -> SnapshotId {
    let project = dir.join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("input.txt"), b"from the snapshot\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ward-node"))
        .args(["snapshot", "import", "--state-dir"])
        .arg(dir.join("state"))
        .arg(&project)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn record(dir: &Path) -> serde_json::Value {
    let path = dir
        .join("state")
        .join("tasks")
        .join(format!("{}.json", binding().task()));
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
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

    fn capabilities(&self) -> (String, NodeCapabilities) {
        let discovery = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let raw = self.request(&serde_json::to_string(&discovery.request()).unwrap());
        let CapabilityDiscoveryResponse::Capabilities { capabilities } =
            discovery.decode_response(&raw).unwrap();
        (raw, capabilities)
    }

    fn state(&self) -> TaskLifecycleState {
        match self.lifecycle(&context().inspect(binding())) {
            TaskLifecycleResponse::Inspected { state, .. } => state,
            other => panic!("inspect failed: {other:?}"),
        }
    }

    fn create(&self) {
        assert_eq!(
            self.lifecycle(&context().create(op(1), binding())),
            context().accepted(op(1), binding(), TaskLifecycleState::Created)
        );
    }

    /// Every floor above `sandbox` is refused `unsupported_grant` and leaves the task
    /// `created`, under the same version each time, so no refusal consumed it.
    #[track_caller]
    fn refuses_every_floor(&self, snapshot: SnapshotId) {
        for level in FLOORS {
            assert_eq!(
                self.lifecycle(&signed_admit(1, floored(level), snapshot, &["true"])),
                context().rejected(
                    Some(op(2)),
                    binding(),
                    TaskLifecycleRejectionReason::UnsupportedGrant
                ),
                "{level}"
            );
            assert_eq!(self.state(), TaskLifecycleState::Created, "{level}");
        }
    }

    fn wait_until_finished(&self) -> TaskLifecycleResponse {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let response = self.lifecycle(&context().inspect(binding()));
            if response != context().inspected(binding(), TaskLifecycleState::Running) {
                return response;
            }
            assert!(Instant::now() < deadline, "the workload never finished");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_node_without_a_backend_refuses_every_floor_and_admits_an_unmarked_manifest() {
    let dir = private_dir();
    let node = Node::spawn(dir.path(), None);
    let (_, capabilities) = node.capabilities();
    for level in IsolationLevel::ALL {
        assert!(!capabilities.isolation().offers(level), "{level}");
    }

    node.create();
    let snapshot = SnapshotId::new(Blake3Hash::from_bytes([0x11; 32]));
    node.refuses_every_floor(snapshot);
    assert_eq!(
        node.lifecycle(&signed_admit(1, unmarked(), snapshot, &["true"])),
        context().accepted(op(2), binding(), TaskLifecycleState::Ready)
    );
}

#[test]
fn a_sandbox_only_node_refuses_a_stronger_floor_before_anything_exists_under_its_task_root() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let task_root = dir.path().join("tasks");
    let node = Node::spawn(dir.path(), Some(&task_root));
    let (raw, capabilities) = node.capabilities();
    assert!(capabilities.lifecycle().start);
    for level in IsolationLevel::ALL {
        assert_eq!(
            capabilities.isolation().offers(level),
            level == IsolationLevel::Sandbox,
            "{level}"
        );
    }
    assert!(
        raw.contains(r#""isolation":{"namespaces":{"sandbox":true,"user_namespace":true},"backends":{"container":false,"microvm":false,"vm":false}}"#),
        "the isolation section is the one every 1.3 revision decodes: {raw}"
    );

    node.create();
    node.refuses_every_floor(snapshot);
    assert!(
        std::fs::read_dir(&task_root).unwrap().next().is_none(),
        "a refused floor must leave the task root empty"
    );
    assert!(record(dir.path()).get("capsule").is_none());

    assert_eq!(
        node.lifecycle(&signed_admit(1, unmarked(), snapshot, &["true"])),
        context().accepted(op(2), binding(), TaskLifecycleState::Ready)
    );
}

#[test]
fn an_unmarked_manifest_runs_as_before_and_its_record_names_the_backend_that_ran_it() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let task_root = dir.path().join("tasks");
    let node = Node::spawn(dir.path(), Some(&task_root));
    node.create();
    assert_eq!(
        node.lifecycle(&signed_admit(
            1,
            unmarked(),
            snapshot,
            &["sh", "-c", "cat input.txt > copy.txt"],
        )),
        context().accepted(op(2), binding(), TaskLifecycleState::Ready)
    );
    assert!(
        record(dir.path()).get("capsule").is_none(),
        "nothing is placed before start"
    );
    assert_eq!(
        node.lifecycle(&context().start(op(3), binding())),
        context().accepted(op(3), binding(), TaskLifecycleState::Running)
    );
    assert_eq!(
        node.wait_until_finished(),
        context()
            .inspected_with_outcome(
                binding(),
                TaskLifecycleState::Exited,
                TaskExecutionOutcome::Completed
            )
            .unwrap()
    );
    let workspace = task_root
        .join(binding().task().to_string())
        .join(binding().attempt().to_string());
    assert_eq!(
        std::fs::read(workspace.join("copy.txt")).unwrap(),
        b"from the snapshot\n"
    );
    assert_eq!(
        record(dir.path())["capsule"],
        serde_json::json!({"backend": "bubblewrap", "isolation": "sandbox"})
    );

    drop(node);
    let node = Node::spawn(dir.path(), Some(&task_root));
    assert_eq!(node.state(), TaskLifecycleState::Exited);
    assert_eq!(
        record(dir.path())["capsule"],
        serde_json::json!({"backend": "bubblewrap", "isolation": "sandbox"}),
        "the record keeps the backend across a restart"
    );
}
