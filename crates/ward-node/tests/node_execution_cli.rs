//! End-to-end `ward-node` execution over its real local socket (ADR-0030 §3–§6).
//!
//! The snapshot-import and task-root checks run everywhere. The start, stop and shutdown
//! cases need a working bubblewrap and skip without one, except under
//! `WARD_REQUIRE_ISOLATION=1`, where CI runs them for real.

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
    IssuerProof, IssuerSignature, NodeCapabilities, OperationId, ProtocolVersion,
    TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput, TaskBinding,
    TaskExecutionOutcome, TaskLifecycleContext, TaskLifecycleRequest, TaskLifecycleResponse,
    TaskLifecycleState, TaskWorkload, WARD_NODE_PROTOCOL, WorkloadArgv,
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

fn signed_admit(snapshot: SnapshotId, argv: &[&str], budget_ms: u64) -> TaskLifecycleRequest {
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
            CapabilityManifestBytes::new(br#"{"network":"offline"}"#.to_vec()).unwrap(),
            snapshot,
            budget_ms,
        )
        .unwrap(),
        issued_at_unix_ms: now - 60_000,
        expires_at_unix_ms: now + 600_000,
        version: AdmissionVersion::new(1).unwrap(),
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

fn project(dir: &Path) -> PathBuf {
    let project = dir.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("src/input.txt"), b"from the snapshot\n").unwrap();
    project
}

fn import(state_dir: &Path, project: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ward-node"))
        .args(["snapshot", "import", "--state-dir"])
        .arg(state_dir)
        .arg(project)
        .output()
        .unwrap()
}

fn imported(state_dir: &Path, project: &Path) -> SnapshotId {
    let output = import(state_dir, project);
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

fn node_command(dir: &Path, socket: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ward-node"));
    command
        .arg("--socket")
        .arg(socket)
        .arg("--state-dir")
        .arg(dir.join("state"))
        .arg("--node-id")
        .arg(NODE.to_string())
        .arg("--trusted-issuers")
        .arg(trust_store(dir));
    command
}

struct Node {
    child: Child,
    socket: PathBuf,
}

impl Node {
    fn spawn(dir: &Path, task_root: Option<&Path>) -> Self {
        let socket = dir.join("node.sock");
        let _ = std::fs::remove_file(&socket);
        let mut command = node_command(dir, &socket);
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

    fn lifecycle_flags(&self) -> (bool, bool) {
        let capabilities = self.capabilities();
        (
            capabilities.lifecycle().start,
            capabilities.lifecycle().stop,
        )
    }

    fn admit_and_start(&self, snapshot: SnapshotId, argv: &[&str], budget_ms: u64) {
        let ctx = context();
        assert_eq!(
            self.lifecycle(&ctx.create(op(1), binding())),
            ctx.accepted(op(1), binding(), TaskLifecycleState::Created)
        );
        assert_eq!(
            self.lifecycle(&signed_admit(snapshot, argv, budget_ms)),
            ctx.accepted(op(2), binding(), TaskLifecycleState::Ready)
        );
        assert_eq!(
            self.lifecycle(&ctx.start(op(3), binding())),
            ctx.accepted(op(3), binding(), TaskLifecycleState::Running)
        );
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

fn marker() -> String {
    format!(
        "ward-node-e2e-{}-{}",
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

/// Wait until the workload's shell runs inside the sandbox: the outer and inner
/// bubblewrap processes and the shell all carry the marker. Only then have both
/// bubblewrap processes armed `--die-with-parent`.
fn wait_until_sandboxed(marker: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while processes_with(marker) < 3 {
        assert!(Instant::now() < deadline, "the workload never started");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_until_gone(marker: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while processes_with(marker) > 0 {
        assert!(
            Instant::now() < deadline,
            "a workload process outlived its stop"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn snapshot_import_prints_the_content_id_an_envelope_names() {
    let dir = private_dir();
    let project = project(dir.path());
    let state = dir.path().join("state");

    let id = imported(&state, &project);
    let expected = ward_snapshot::digest_worktree(
        &project,
        ward_snapshot::CaptureOptions::default(),
        &mut ward_snapshot::HashCache::new(),
    )
    .unwrap();
    assert_eq!(id.to_string(), expected.to_string());
    assert_eq!(imported(&state, &project), id);
    assert_eq!(
        std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(state.join("cas").is_dir());

    assert!(!import(&state, &dir.path().join("missing")).status.success());
    let exposed = dir.path().join("exposed");
    std::fs::create_dir(&exposed).unwrap();
    std::fs::set_permissions(&exposed, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!import(&exposed, &project).status.success());
    assert!(!exposed.join("cas").exists());
}

#[test]
fn snapshot_import_output_is_exactly_the_envelope_snapshot_value() {
    let dir = private_dir();
    let project = project(dir.path());
    let output = import(&dir.path().join("state"), &project);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let printed = stdout.strip_suffix('\n').unwrap();
    assert_eq!(printed.len(), 64, "{stdout:?}");
    assert!(
        printed
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "{stdout:?}"
    );

    let admit = signed_admit(SnapshotId::new(Blake3Hash::ZERO), &["true"], 60_000);
    let TaskLifecycleRequest::Admit { envelope_json, .. } = admit else {
        panic!("not an admit");
    };
    let mut envelope: serde_json::Value = serde_json::from_slice(envelope_json.as_bytes()).unwrap();
    envelope["workload"]["snapshot"] = serde_json::json!(printed);
    let decoded = TaskAdmissionEnvelope::decode_json(envelope.to_string().as_bytes()).unwrap();
    assert_eq!(
        decoded.workload().snapshot(),
        imported(&dir.path().join("state"), &project)
    );
}

#[test]
fn ward_node_refuses_to_serve_over_an_exposed_task_root() {
    let dir = private_dir();
    let task_root = dir.path().join("tasks");
    std::fs::create_dir(&task_root).unwrap();
    std::fs::set_permissions(&task_root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let socket = dir.path().join("node.sock");

    let output = node_command(dir.path(), &socket)
        .arg("--task-root")
        .arg(&task_root)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("task root"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!socket.exists());
}

#[test]
fn ward_node_without_a_task_root_advertises_neither_start_nor_stop() {
    let dir = private_dir();
    let node = Node::spawn(dir.path(), None);
    assert_eq!(node.lifecycle_flags(), (false, false));
    let ctx = context();
    node.lifecycle(&ctx.create(op(1), binding()));
    assert_eq!(
        node.lifecycle(&ctx.start(op(3), binding())),
        ctx.rejected(
            Some(op(3)),
            binding(),
            ward_node_protocol::TaskLifecycleRejectionReason::UnsupportedOperation
        )
    );
}

#[test]
fn ward_node_starts_an_admitted_workload_and_records_its_exit() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(&dir.path().join("state"), &project(dir.path()));
    let task_root = dir.path().join("tasks");
    let node = Node::spawn(dir.path(), Some(&task_root));
    assert_eq!(node.lifecycle_flags(), (true, true));

    node.admit_and_start(
        snapshot,
        &[
            "sh",
            "-c",
            "cat src/input.txt > copy.txt && echo ok > out.txt",
        ],
        60_000,
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
    assert_eq!(std::fs::read(workspace.join("out.txt")).unwrap(), b"ok\n");
    assert_eq!(
        std::fs::read(workspace.join("copy.txt")).unwrap(),
        b"from the snapshot\n"
    );
    assert_eq!(
        std::fs::metadata(&workspace).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn an_executing_ward_node_advertises_the_isolation_it_enforces() {
    let dir = private_dir();
    let plain = Node::spawn(dir.path(), None).capabilities();
    assert!(!plain.isolation().namespaces.sandbox);
    assert!(!plain.network().offline);
    assert!(!plain.snapshots().content_addressed);
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let executing = Node::spawn(dir.path(), Some(&dir.path().join("tasks"))).capabilities();
    assert!(executing.isolation().namespaces.sandbox);
    assert!(executing.isolation().namespaces.user_namespace);
    assert!(executing.network().offline);
    assert!(!executing.network().proxy_allowlist);
    assert!(executing.snapshots().content_addressed);
    assert!(executing.lifecycle().start && executing.lifecycle().stop);
}

#[test]
fn ward_node_records_a_failing_workload_as_failed() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(&dir.path().join("state"), &project(dir.path()));
    let node = Node::spawn(dir.path(), Some(&dir.path().join("tasks")));
    node.admit_and_start(snapshot, &["sh", "-c", "exit 3"], 60_000);
    assert_eq!(
        node.wait_until_finished(),
        context()
            .inspected_with_outcome(
                binding(),
                TaskLifecycleState::Exited,
                TaskExecutionOutcome::Failed
            )
            .unwrap()
    );
}

#[test]
fn ward_node_kills_a_workload_at_its_budget() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(&dir.path().join("state"), &project(dir.path()));
    let node = Node::spawn(dir.path(), Some(&dir.path().join("tasks")));
    let marker = marker();
    let script = format!("sleep 300; echo {marker}");
    let started = Instant::now();
    node.admit_and_start(snapshot, &["sh", "-c", &script], 500);
    assert_eq!(
        node.wait_until_finished(),
        context()
            .inspected_with_outcome(
                binding(),
                TaskLifecycleState::Exited,
                TaskExecutionOutcome::Failed
            )
            .unwrap()
    );
    assert!(started.elapsed() < Duration::from_secs(20));
    wait_until_gone(&marker);
}

#[test]
fn ward_node_stops_a_long_running_workload_and_reaps_it() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(&dir.path().join("state"), &project(dir.path()));
    let node = Node::spawn(dir.path(), Some(&dir.path().join("tasks")));
    let marker = marker();
    let script = format!("sleep 300; echo {marker}");
    node.admit_and_start(snapshot, &["sh", "-c", &script], 600_000);

    wait_until_sandboxed(&marker);
    let ctx = context();
    let started = Instant::now();
    assert_eq!(
        node.lifecycle(&ctx.stop(op(4), binding())),
        ctx.accepted(op(4), binding(), TaskLifecycleState::Stopped)
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    wait_until_gone(&marker);
    assert_eq!(
        node.lifecycle(&ctx.inspect(binding())),
        ctx.inspected_with_outcome(
            binding(),
            TaskLifecycleState::Stopped,
            TaskExecutionOutcome::Failed
        )
        .unwrap()
    );
    assert_eq!(
        node.lifecycle(&ctx.stop(op(4), binding())),
        ctx.accepted(op(4), binding(), TaskLifecycleState::Stopped)
    );
}

#[test]
fn a_node_shutdown_kills_its_running_workloads() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(&dir.path().join("state"), &project(dir.path()));
    let node = Node::spawn(dir.path(), Some(&dir.path().join("tasks")));
    let marker = marker();
    let script = format!("sleep 300; echo {marker}");
    node.admit_and_start(snapshot, &["sh", "-c", &script], 600_000);

    wait_until_sandboxed(&marker);
    drop(node);
    wait_until_gone(&marker);
}
