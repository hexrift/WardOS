//! End-to-end per-attempt evidence logs of a real `ward-node` (#332, ADR-0030 §3).
//!
//! The node is the single writer of one hash-chained evidence log per attempt it admits,
//! beside the attempt's workspace under its task root. A real workload's log verifies with
//! the `ward-events` log verifier and its sealed `HEAD`; a node killed with `SIGKILL` mid-run
//! continues the same chain after its restart with one recovery record, written before it
//! serves. The cases need a working bubblewrap and skip without one, except under
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
use ward_events::log::{head_file_path, parse_head};
use ward_events::{
    AgentId, Blake3Hash, ChainHead, DelegationId, EventRecord, ExecutionAttemptId, LeaseId,
    LogReader, NodeAttemptEnd, NodeAttemptOutcome, NodeAttemptState, NodeId, Origin, PrincipalId,
    SessionId, SnapshotId, TaskId, WardEvent,
};
use ward_node::evidence;
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
) -> (TaskLifecycleRequest, Blake3Hash) {
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
    let digest = Blake3Hash::hash(json.as_bytes());
    (
        context().admit(operation, binding, json, proof).unwrap(),
        digest,
    )
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

    fn admit_and_start(&self, snapshot: SnapshotId, script: &str) -> Blake3Hash {
        let ctx = context();
        assert_eq!(
            self.lifecycle(&ctx.create(op(1), binding())),
            ctx.accepted(op(1), binding(), TaskLifecycleState::Created)
        );
        let (admit, envelope) = signed_admit(op(2), 1, snapshot, &["sh", "-c", script]);
        assert_eq!(
            self.lifecycle(&admit),
            ctx.accepted(op(2), binding(), TaskLifecycleState::Ready)
        );
        assert_eq!(
            self.lifecycle(&ctx.start(op(3), binding())),
            ctx.accepted(op(3), binding(), TaskLifecycleState::Running)
        );
        envelope
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

fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn marker() -> String {
    format!(
        "ward-node-evidence-{}-{}",
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

fn evidence_log(task_root: &Path) -> PathBuf {
    evidence::evidence_dir(task_root, binding()).join(evidence::EVIDENCE_LOG)
}

fn verified(task_root: &Path) -> (Vec<EventRecord>, ChainHead) {
    let path = evidence_log(task_root);
    let records: Vec<EventRecord> = LogReader::open(&path)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let head = LogReader::open(&path).unwrap().verify_all().unwrap();
    assert_eq!(head.session, evidence::session(binding()));
    assert_eq!(head.genesis, evidence::genesis(binding()));
    assert_eq!(records.first().unwrap().prev, evidence::genesis(binding()));
    assert!(records.iter().all(|record| record.origin == Origin::Node));
    assert_eq!(
        evidence::verify(&evidence::evidence_dir(task_root, binding()), binding())
            .unwrap()
            .records(),
        records.as_slice()
    );
    (records, head)
}

fn admitted(envelope: Blake3Hash) -> WardEvent {
    WardEvent::NodeAttemptAdmitted {
        task: binding().task(),
        attempt: binding().attempt(),
        lease: binding().lease(),
        session: SessionId::from_u128(5),
        operation: 2,
        envelope,
        issuer_key: Blake3Hash::hash(key_pair().public_key().as_ref()),
        version: 1,
    }
}

fn launched_pid(records: &[EventRecord]) -> u32 {
    match records[1].event {
        WardEvent::NodeAttemptLaunched {
            operation: 3,
            host_pid,
        } => host_pid,
        ref other => panic!("expected the launch, found {other:?}"),
    }
}

#[test]
fn a_real_workload_leaves_one_sealed_evidence_log_that_verifies() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let task_root = dir.path().join("tasks");
    let node = Node::spawn(dir.path(), Some(&task_root));
    let marker = format!("ward-node-evidence-output-{}", std::process::id());
    let envelope = node.admit_and_start(
        snapshot,
        &format!("echo {marker}; echo {marker} >&2; echo done > out.txt"),
    );
    eventually("the workload never exited", || {
        node.finished(TaskLifecycleState::Exited, TaskExecutionOutcome::Completed)
    });
    assert!(
        evidence::verify(&evidence::evidence_dir(&task_root, binding()), binding())
            .is_ok_and(|log| !log.is_sealed())
    );
    let ctx = context();
    assert_eq!(
        node.lifecycle(&ctx.seal(op(5), binding())),
        ctx.accepted(op(5), binding(), TaskLifecycleState::Sealed)
    );

    let (records, head) = verified(&task_root);
    assert!(launched_pid(&records) > 0);
    let events: Vec<WardEvent> = records.iter().map(|record| record.event.clone()).collect();
    assert_eq!(
        events,
        vec![
            admitted(envelope),
            records[1].event.clone(),
            WardEvent::NodeAttemptEnded {
                state: NodeAttemptState::Exited,
                outcome: NodeAttemptOutcome::Completed,
                end: NodeAttemptEnd::Exited { code: Some(0) },
                operation: None,
            },
            WardEvent::NodeAttemptSealed { operation: 5 },
        ]
    );
    let path = evidence_log(&task_root);
    let sealed = parse_head(&std::fs::read_to_string(head_file_path(&path)).unwrap()).unwrap();
    assert_eq!(sealed, head);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o400
    );
    assert_eq!(
        std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let workspace = task_root
        .join(binding().task().to_string())
        .join(binding().attempt().to_string());
    assert_eq!(
        std::fs::read_to_string(workspace.join("out.txt")).unwrap(),
        "done\n"
    );
    assert!(
        !path.starts_with(&workspace),
        "the log is outside the workspace"
    );
    let bytes = std::fs::read(&path).unwrap();
    assert!(
        !bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes()),
        "workload output is never logged"
    );

    let copy = dir.path().join("tampered.log");
    let mut tampered = bytes.clone();
    let target = tampered.len() / 2;
    tampered[target] ^= 0x01;
    std::fs::write(&copy, &tampered).unwrap();
    assert!(LogReader::open(&copy).unwrap().verify_all().is_err());

    drop(node);
    let node = Node::spawn(dir.path(), Some(&task_root));
    assert!(node.finished(TaskLifecycleState::Sealed, TaskExecutionOutcome::Completed));
    assert_eq!(
        verified(&task_root),
        (records, head),
        "a sealed log never changes"
    );
}

#[test]
fn a_node_killed_mid_run_continues_the_chain_with_one_recovery_record() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let task_root = dir.path().join("tasks");
    let node = Node::spawn(dir.path(), Some(&task_root));
    let marker = marker();
    let envelope = node.admit_and_start(
        snapshot,
        &format!("while :; do echo beat >> beats; sleep 0.1; done; echo {marker}"),
    );
    let beats = task_root
        .join(binding().task().to_string())
        .join(binding().attempt().to_string())
        .join("beats");
    eventually("the workload never started", || {
        std::fs::read_to_string(&beats).is_ok_and(|text| !text.is_empty())
            && processes_with(&marker) >= 3
    });
    let (before, _) = verified(&task_root);
    assert_eq!(before.len(), 2);
    assert_eq!(before[0].event, admitted(envelope));
    launched_pid(&before);

    node.kill();
    let node = Node::spawn(dir.path(), Some(&task_root));
    eventually("a workload process outlived its node", || {
        processes_with(&marker) == 0
    });
    let (after, head) = verified(&task_root);
    assert_eq!(
        &after[..2],
        before.as_slice(),
        "the chain continues unchanged"
    );
    assert_eq!(
        after[2].event,
        WardEvent::NodeAttemptRecovered {
            state: NodeAttemptState::Exited,
            outcome: Some(NodeAttemptOutcome::Unknown),
        }
    );
    assert_eq!(after.len(), 3);
    assert_eq!(after[2].prev, after[1].hash);
    assert!(!head_file_path(&evidence_log(&task_root)).exists());
    assert!(node.finished(TaskLifecycleState::Exited, TaskExecutionOutcome::Unknown));

    node.kill();
    let node = Node::spawn(dir.path(), Some(&task_root));
    assert_eq!(
        verified(&task_root),
        (after.clone(), head),
        "no second recovery"
    );
    let ctx = context();
    assert_eq!(
        node.lifecycle(&ctx.seal(op(5), binding())),
        ctx.accepted(op(5), binding(), TaskLifecycleState::Sealed)
    );
    let (sealed, head) = verified(&task_root);
    assert_eq!(&sealed[..3], after.as_slice());
    assert_eq!(
        sealed[3].event,
        WardEvent::NodeAttemptSealed { operation: 5 }
    );
    assert_eq!(
        parse_head(&std::fs::read_to_string(head_file_path(&evidence_log(&task_root))).unwrap())
            .unwrap(),
        head
    );
    assert_eq!(
        node.lifecycle(&ctx.start(op(9), binding())),
        ctx.rejected(
            Some(op(9)),
            binding(),
            TaskLifecycleRejectionReason::InvalidState
        )
    );
    assert_eq!(processes_with(&marker), 0);
}
