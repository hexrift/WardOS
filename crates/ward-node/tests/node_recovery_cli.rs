//! End-to-end `ward-node` recovery across a node that is killed outright (#332 slice 7,
//! ADR-0030 §6).
//!
//! A task's state, receipt and applied operations survive a `SIGKILL` of the node; an
//! attempt that was running is recovered as `exited` with an `unknown` outcome, its
//! workload is gone and it never runs again. The `created` and `ready` cases run
//! everywhere. The sandbox cases need a working bubblewrap and skip without one, except
//! under `WARD_REQUIRE_ISOLATION=1`, where CI runs them for real.

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
    AdmissionEnvelopeJson, AdmissionVersion, CapabilityManifestBytes, HandshakeRequest,
    HandshakeResponse, IssuerProof, IssuerSignature, OperationId, ProtocolVersion,
    TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput, TaskBinding,
    TaskExecutionOutcome, TaskLifecycleContext, TaskLifecycleRejectionReason, TaskLifecycleRequest,
    TaskLifecycleResponse, TaskLifecycleState, TaskWorkload, WARD_NODE_PROTOCOL, WorkloadArgv,
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

fn signed_admit(
    operation: OperationId,
    version: u64,
    snapshot: SnapshotId,
    argv: &[&str],
) -> TaskLifecycleRequest {
    let now = now_ms();
    let binding = binding();
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
            issued_at_unix_ms: now - 60_000,
            expires_at_unix_ms: now + 600_000,
            version: LeaseVersion::new(1).unwrap(),
        },
        now,
        EmptyAuthorityPolicy::Reject,
    )
    .unwrap();
    let envelope = TaskAdmissionEnvelope::new(TaskAdmissionEnvelopeInput {
        binding,
        agent: AgentId::from_u128(3),
        node: NODE,
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new())
            .unwrap(),
        workload: TaskWorkload::new(
            WorkloadArgv::new(argv.iter().map(|arg| (*arg).to_owned()).collect()).unwrap(),
            CapabilityManifestBytes::new(br#"{"network":"offline"}"#.to_vec()).unwrap(),
            snapshot,
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
    context().admit(operation, binding, json, proof).unwrap()
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
            .arg(trust_store(dir));
        if let Some(task_root) = task_root {
            command.arg("--task-root").arg(task_root);
        }
        let mut child = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
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

    fn kill(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }

    fn lifecycle(&self, request: &TaskLifecycleRequest) -> TaskLifecycleResponse {
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
        writeln!(client, "{}", serde_json::to_string(request).unwrap()).unwrap();
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        context().decode_response(response.trim()).unwrap()
    }

    fn admit_and_start(&self, snapshot: SnapshotId, script: &str) {
        let ctx = context();
        assert_eq!(
            self.lifecycle(&ctx.create(op(1), binding())),
            ctx.accepted(op(1), binding(), TaskLifecycleState::Created)
        );
        assert_eq!(
            self.lifecycle(&signed_admit(op(2), 1, snapshot, &["sh", "-c", script])),
            ctx.accepted(op(2), binding(), TaskLifecycleState::Ready)
        );
        assert_eq!(
            self.lifecycle(&ctx.start(op(3), binding())),
            ctx.accepted(op(3), binding(), TaskLifecycleState::Running)
        );
    }

    fn finished(&self, state: TaskLifecycleState, outcome: TaskExecutionOutcome) -> bool {
        self.lifecycle(&context().inspect(binding()))
            == context()
                .inspected_with_outcome(binding(), state, outcome)
                .unwrap()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn marker() -> String {
    format!(
        "ward-node-recovery-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn processes_with(marker: &str) -> usize {
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().parse::<u32>().is_ok())
        .filter_map(|entry| std::fs::read(entry.path().join("cmdline")).ok())
        .filter(|cmdline| {
            cmdline
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        })
        .count()
}

fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn lines(path: &Path) -> usize {
    std::fs::read_to_string(path).map_or(0, |text| text.lines().count())
}

fn workspace(task_root: &Path) -> PathBuf {
    task_root
        .join(binding().task().to_string())
        .join(binding().attempt().to_string())
}

#[test]
fn created_and_ready_tasks_survive_a_killed_node_and_a_ready_one_must_be_admitted_again() {
    let dir = private_dir();
    let ctx = context();
    let node = Node::spawn(dir.path(), None);
    assert_eq!(
        node.lifecycle(&ctx.create(op(1), binding())),
        ctx.accepted(op(1), binding(), TaskLifecycleState::Created)
    );
    node.kill();

    let node = Node::spawn(dir.path(), None);
    assert_eq!(
        node.lifecycle(&ctx.inspect(binding())),
        ctx.inspected(binding(), TaskLifecycleState::Created)
    );
    let snapshot = SnapshotId::new(Blake3Hash::from_bytes([0x11; 32]));
    let first = signed_admit(op(2), 1, snapshot, &["true"]);
    assert_eq!(
        node.lifecycle(&first),
        ctx.accepted(op(2), binding(), TaskLifecycleState::Ready)
    );
    node.kill();

    let node = Node::spawn(dir.path(), None);
    assert_eq!(
        node.lifecycle(&ctx.create(op(1), binding())),
        ctx.accepted(op(1), binding(), TaskLifecycleState::Created)
    );
    assert_eq!(
        node.lifecycle(&first),
        ctx.rejected(
            Some(op(2)),
            binding(),
            TaskLifecycleRejectionReason::StaleOperation
        )
    );
    assert_eq!(
        node.lifecycle(&signed_admit(op(4), 2, snapshot, &["true"])),
        ctx.accepted(op(4), binding(), TaskLifecycleState::Ready)
    );
}

#[test]
fn a_running_attempt_of_a_killed_node_is_exited_unknown_gone_and_never_run_again() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let task_root = dir.path().join("tasks");
    let node = Node::spawn(dir.path(), Some(&task_root));
    let marker = marker();
    node.admit_and_start(
        snapshot,
        &format!(
            "echo run >> runs; while :; do echo beat >> beats; sleep 0.1; done; echo {marker}"
        ),
    );
    let runs = workspace(&task_root).join("runs");
    let beats = workspace(&task_root).join("beats");
    eventually("the workload never started", || {
        lines(&beats) > 0 && processes_with(&marker) >= 3
    });
    assert_eq!(lines(&runs), 1);

    node.kill();
    let node = Node::spawn(dir.path(), Some(&task_root));
    let ctx = context();
    assert!(node.finished(TaskLifecycleState::Exited, TaskExecutionOutcome::Unknown));
    eventually("a workload process outlived its node", || {
        processes_with(&marker) == 0
    });
    let settled = lines(&beats);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(lines(&beats), settled, "the workload no longer runs");

    assert_eq!(
        node.lifecycle(&ctx.start(op(3), binding())),
        ctx.accepted(op(3), binding(), TaskLifecycleState::Exited)
    );
    assert_eq!(
        node.lifecycle(&ctx.start(op(9), binding())),
        ctx.rejected(
            Some(op(9)),
            binding(),
            TaskLifecycleRejectionReason::InvalidState
        )
    );
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(lines(&runs), 1, "the attempt never ran again");
    assert_eq!(processes_with(&marker), 0);
    assert_eq!(
        node.lifecycle(&ctx.seal(op(5), binding())),
        ctx.accepted(op(5), binding(), TaskLifecycleState::Sealed)
    );
}

#[test]
fn an_ended_attempt_keeps_its_receipt_and_replays_across_killed_nodes() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let task_root = dir.path().join("tasks");
    let node = Node::spawn(dir.path(), Some(&task_root));
    node.admit_and_start(snapshot, "echo run >> runs");
    eventually("the workload never exited", || {
        node.finished(TaskLifecycleState::Exited, TaskExecutionOutcome::Completed)
    });
    node.kill();

    let node = Node::spawn(dir.path(), Some(&task_root));
    let ctx = context();
    assert!(node.finished(TaskLifecycleState::Exited, TaskExecutionOutcome::Completed));
    assert_eq!(
        node.lifecycle(&ctx.seal(op(5), binding())),
        ctx.accepted(op(5), binding(), TaskLifecycleState::Sealed)
    );
    node.kill();

    let node = Node::spawn(dir.path(), Some(&task_root));
    assert!(node.finished(TaskLifecycleState::Sealed, TaskExecutionOutcome::Completed));
    for (request, operation) in [
        (ctx.create(op(1), binding()), op(1)),
        (ctx.start(op(3), binding()), op(3)),
        (ctx.seal(op(5), binding()), op(5)),
    ] {
        assert_eq!(
            node.lifecycle(&request),
            ctx.accepted(operation, binding(), TaskLifecycleState::Sealed)
        );
    }
    assert_eq!(lines(&workspace(&task_root).join("runs")), 1);
}
