//! End-to-end `ward-node` pause, resume, revoke and seal over its real local socket
//! (ADR-0030 §3, §5, #324).
//!
//! The capability check runs everywhere. The sandbox cases need a working bubblewrap and
//! skip without one, except under `WARD_REQUIRE_ISOLATION=1`, where CI runs them for real.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
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
    IssuerProof, IssuerSignature, LifecycleCapabilities, OperationId, ProtocolVersion,
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
    binding: TaskBinding,
    version: u64,
    snapshot: SnapshotId,
    argv: &[&str],
) -> TaskLifecycleRequest {
    let now = now_ms();
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

fn imported(state_dir: &Path, dir: &Path) -> SnapshotId {
    let project = dir.join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("input.txt"), b"from the snapshot\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ward-node"))
        .args(["snapshot", "import", "--state-dir"])
        .arg(state_dir)
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

    fn capabilities(&self) -> LifecycleCapabilities {
        let discovery = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let CapabilityDiscoveryResponse::Capabilities { capabilities } = discovery
            .decode_response(&self.request(&serde_json::to_string(&discovery.request()).unwrap()))
            .unwrap();
        capabilities.lifecycle()
    }

    fn admit_and_start(&self, snapshot: SnapshotId, script: &str) {
        let ctx = context();
        assert_eq!(
            self.lifecycle(&ctx.create(op(1), binding())),
            ctx.accepted(op(1), binding(), TaskLifecycleState::Created)
        );
        assert_eq!(
            self.lifecycle(&signed_admit(
                op(2),
                binding(),
                1,
                snapshot,
                &["sh", "-c", script]
            )),
            ctx.accepted(op(2), binding(), TaskLifecycleState::Ready)
        );
        assert_eq!(
            self.lifecycle(&ctx.start(op(3), binding())),
            ctx.accepted(op(3), binding(), TaskLifecycleState::Running)
        );
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
        "ward-node-lifecycle-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn stat(pid: u32) -> Option<(char, u32)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let mut fields = stat[stat.rfind(')')? + 1..].split_whitespace();
    let state = fields.next()?.chars().next()?;
    Some((state, fields.next()?.parse().ok()?))
}

fn host_pids() -> Vec<u32> {
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
        .collect()
}

/// Every process whose command line carries `marker`, and all their descendants.
fn workload_pids(marker: &str) -> BTreeSet<u32> {
    let mut pids: BTreeSet<u32> = host_pids()
        .into_iter()
        .filter(|pid| {
            std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmdline| {
                cmdline
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes())
            })
        })
        .collect();
    loop {
        let children: Vec<u32> = host_pids()
            .into_iter()
            .filter(|pid| !pids.contains(pid))
            .filter(|pid| stat(*pid).is_some_and(|(_, parent)| pids.contains(&parent)))
            .collect();
        if children.is_empty() {
            return pids;
        }
        pids.extend(children);
    }
}

/// Wait until the sandbox runs its workload: outer and inner bubblewrap, the shell and the
/// `sleep` it forked.
fn wait_until_sandboxed(marker: &str) -> BTreeSet<u32> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let pids = workload_pids(marker);
        let sleeping = pids.iter().any(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .is_ok_and(|comm| comm.trim() == "sleep")
        });
        if pids.len() >= 4 && sleeping {
            return pids;
        }
        assert!(Instant::now() < deadline, "the workload never started");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn states(pids: &BTreeSet<u32>) -> Vec<(u32, Option<char>)> {
    pids.iter()
        .map(|pid| (*pid, stat(*pid).map(|(state, _)| state)))
        .collect()
}

fn wait_until_gone(pids: &BTreeSet<u32>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while pids
        .iter()
        .any(|pid| stat(*pid).is_some_and(|(state, _)| state != 'Z'))
    {
        assert!(
            Instant::now() < deadline,
            "a workload process outlived its end: {:?}",
            states(pids)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_node_without_a_task_root_advertises_neither_pause_nor_revoke() {
    let dir = private_dir();
    let node = Node::spawn(dir.path(), None);
    let lifecycle = node.capabilities();
    assert!(!lifecycle.pause && !lifecycle.revoke && !lifecycle.start && !lifecycle.stop);
    let ctx = context();
    node.lifecycle(&ctx.create(op(1), binding()));
    for (request, operation) in [
        (ctx.pause(op(4), binding()), op(4)),
        (ctx.resume(op(5), binding()), op(5)),
        (ctx.revoke(op(6), binding()), op(6)),
        (ctx.seal(op(7), binding()), op(7)),
    ] {
        assert_eq!(
            node.lifecycle(&request),
            ctx.rejected(
                Some(operation),
                binding(),
                TaskLifecycleRejectionReason::UnsupportedOperation
            )
        );
    }
}

#[test]
fn ward_node_pauses_a_running_sandbox_resumes_it_and_stops_it_while_paused() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(&dir.path().join("state"), dir.path());
    let node = Node::spawn(dir.path(), Some(&dir.path().join("tasks")));
    let lifecycle = node.capabilities();
    assert!(lifecycle.pause && lifecycle.revoke && lifecycle.start && lifecycle.stop);
    let marker = marker();
    node.admit_and_start(snapshot, &format!("sleep 300; echo {marker}"));
    let pids = wait_until_sandboxed(&marker);
    let ctx = context();

    assert_eq!(
        node.lifecycle(&ctx.pause(op(4), binding())),
        ctx.accepted(op(4), binding(), TaskLifecycleState::Paused)
    );
    let frozen = states(&pids);
    assert!(
        frozen.iter().all(|(_, state)| *state == Some('T')),
        "every workload process is stopped: {frozen:?}"
    );
    assert_eq!(
        node.lifecycle(&ctx.inspect(binding())),
        ctx.inspected(binding(), TaskLifecycleState::Paused)
    );

    assert_eq!(
        node.lifecycle(&ctx.resume(op(5), binding())),
        ctx.accepted(op(5), binding(), TaskLifecycleState::Running)
    );
    let thawed = states(&pids);
    assert!(
        thawed.iter().all(|(_, state)| *state != Some('T')),
        "no workload process is left stopped: {thawed:?}"
    );

    assert_eq!(
        node.lifecycle(&ctx.pause(op(6), binding())),
        ctx.accepted(op(6), binding(), TaskLifecycleState::Paused)
    );
    let started = Instant::now();
    assert_eq!(
        node.lifecycle(&ctx.stop(op(7), binding())),
        ctx.accepted(op(7), binding(), TaskLifecycleState::Stopped)
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    wait_until_gone(&pids);
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
        node.lifecycle(&ctx.seal(op(8), binding())),
        ctx.accepted(op(8), binding(), TaskLifecycleState::Sealed)
    );
}

#[test]
fn ward_node_revokes_a_running_task_and_refuses_its_lease_after_a_restart() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(&dir.path().join("state"), dir.path());
    let task_root = dir.path().join("tasks");
    let node = Node::spawn(dir.path(), Some(&task_root));
    let marker = marker();
    node.admit_and_start(snapshot, &format!("sleep 300; echo {marker}"));
    let pids = wait_until_sandboxed(&marker);
    let ctx = context();

    assert_eq!(
        node.lifecycle(&ctx.revoke(op(4), binding())),
        ctx.accepted(op(4), binding(), TaskLifecycleState::Revoked)
    );
    wait_until_gone(&pids);
    assert_eq!(
        node.lifecycle(&ctx.inspect(binding())),
        ctx.inspected_with_outcome(
            binding(),
            TaskLifecycleState::Revoked,
            TaskExecutionOutcome::Failed
        )
        .unwrap()
    );

    drop(node);
    let node = Node::spawn(dir.path(), Some(&task_root));
    let retry = TaskBinding::new(
        binding().task(),
        ExecutionAttemptId::from_u128(10),
        binding().lease(),
    );
    assert_eq!(
        node.lifecycle(&ctx.create(op(11), retry)),
        ctx.accepted(op(11), retry, TaskLifecycleState::Created)
    );
    assert_eq!(
        node.lifecycle(&signed_admit(op(12), retry, 2, snapshot, &["true"])),
        ctx.rejected(
            Some(op(12)),
            retry,
            TaskLifecycleRejectionReason::LeaseRevoked
        )
    );
    assert_eq!(
        node.lifecycle(&ctx.inspect(retry)),
        ctx.inspected(retry, TaskLifecycleState::Created)
    );
}
