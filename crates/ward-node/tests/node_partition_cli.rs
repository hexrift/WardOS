//! A real `ward-node` whose control plane is gone (#262): nothing connects and nothing
//! answers, and the node's authority never widens for it. An attempt nobody watches runs
//! with the authority it was admitted with and ends at its budget; an admission whose
//! envelope expires meanwhile can be neither started nor admitted afterwards, and a
//! restart without the control plane brings nothing back. The attempt case needs a working
//! bubblewrap and skips without one, except under `WARD_REQUIRE_ISOLATION=1`.

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
    AgentId, Blake3Hash, DelegationId, EventRecord, ExecutionAttemptId, LeaseId, LogReader,
    NodeAttemptEnd, NodeAttemptOutcome, NodeAttemptState, NodeId, PrincipalId, SessionId,
    SnapshotId, TaskId, WardEvent,
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

fn binding(task: u128) -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(task),
        ExecutionAttemptId::from_u128(task + 1),
        LeaseId::from_u128(task + 2),
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

/// What the control plane signed for one attempt, before it went away.
struct Admission {
    binding: TaskBinding,
    snapshot: SnapshotId,
    argv: Vec<String>,
    budget_ms: u64,
    expires_at_unix_ms: u64,
}

/// The exact bytes the issuer signed and its proof, as the control plane holds them.
struct Signed {
    binding: TaskBinding,
    json: AdmissionEnvelopeJson,
    proof: IssuerProof,
}

impl Signed {
    fn admit(&self, operation: OperationId) -> TaskLifecycleRequest {
        context()
            .admit(operation, self.binding, self.json.clone(), self.proof)
            .unwrap()
    }

    fn digest(&self) -> Blake3Hash {
        Blake3Hash::hash(self.json.as_bytes())
    }
}

impl Admission {
    fn sign(&self) -> Signed {
        let now = now_ms();
        let lease = AuthorityLease::root(
            AuthorityLeaseInput {
                id: self.binding.lease(),
                delegation_id: DelegationId::from_u128(6),
                issuer: PrincipalId::from_u128(2),
                subject: AgentId::from_u128(3),
                task: self.binding.task(),
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
            binding: self.binding,
            agent: AgentId::from_u128(3),
            node: NODE,
            session: SessionId::from_u128(5),
            authority: TaskAdmissionAuthority::new(
                UntrustedAuthorityLease::from(&lease),
                Vec::new(),
            )
            .unwrap(),
            workload: TaskWorkload::new(
                WorkloadArgv::new(self.argv.clone()).unwrap(),
                CapabilityManifestBytes::new(br#"{"network":"offline"}"#.to_vec()).unwrap(),
                self.snapshot,
                self.budget_ms,
            )
            .unwrap(),
            issued_at_unix_ms: now - 60_000,
            expires_at_unix_ms: self.expires_at_unix_ms,
            version: AdmissionVersion::new(1).unwrap(),
        })
        .unwrap();
        let json = AdmissionEnvelopeJson::encode(&envelope).unwrap();
        let key_pair = key_pair();
        let proof = IssuerProof::new(
            Blake3Hash::hash(key_pair.public_key().as_ref()),
            IssuerSignature::from_bytes(
                key_pair.sign(json.as_bytes()).as_ref().try_into().unwrap(),
            ),
        );
        Signed {
            binding: self.binding,
            json,
            proof,
        }
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
    fn spawn(dir: &Path, task_root: &Path) -> Self {
        let socket = dir.join("node.sock");
        let _ = std::fs::remove_file(&socket);
        let mut child = Command::new(env!("CARGO_BIN_EXE_ward-node"))
            .arg("--socket")
            .arg(&socket)
            .arg("--state-dir")
            .arg(dir.join("state"))
            .arg("--node-id")
            .arg(NODE.to_string())
            .arg("--trusted-issuers")
            .arg(trust_store(dir))
            .arg("--task-root")
            .arg(task_root)
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

    fn accepts(&self, request: &TaskLifecycleRequest, state: TaskLifecycleState) {
        let (operation, binding) = match request {
            TaskLifecycleRequest::Create {
                operation_id,
                binding,
                ..
            }
            | TaskLifecycleRequest::Admit {
                operation_id,
                binding,
                ..
            }
            | TaskLifecycleRequest::Start {
                operation_id,
                binding,
                ..
            } => (*operation_id, *binding),
            other => panic!("not a verb these cases send: {other:?}"),
        };
        assert_eq!(
            self.lifecycle(request),
            context().accepted(operation, binding, state)
        );
    }

    fn refuses(
        &self,
        request: &TaskLifecycleRequest,
        operation: OperationId,
        binding: TaskBinding,
        reason: TaskLifecycleRejectionReason,
    ) {
        assert_eq!(
            self.lifecycle(request),
            context().rejected(Some(operation), binding, reason)
        );
    }

    fn inspected(&self, binding: TaskBinding) -> TaskLifecycleResponse {
        self.lifecycle(&context().inspect(binding))
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn eventually(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn marker() -> String {
    format!(
        "ward-node-partition-{}-{}",
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

fn lines(path: &Path) -> usize {
    std::fs::read_to_string(path).map_or(0, |text| text.lines().count())
}

fn workspace(task_root: &Path, binding: TaskBinding) -> PathBuf {
    task_root
        .join(binding.task().to_string())
        .join(binding.attempt().to_string())
}

fn evidence(task_root: &Path, binding: TaskBinding) -> Vec<WardEvent> {
    let path = evidence::evidence_dir(task_root, binding).join(evidence::EVIDENCE_LOG);
    LogReader::open(&path).unwrap().verify_all().unwrap();
    LogReader::open(&path)
        .unwrap()
        .map(Result::unwrap)
        .map(|record: EventRecord| record.event)
        .collect()
}

fn sleep_until(unix_ms: u64) {
    let now = now_ms();
    if unix_ms > now {
        std::thread::sleep(Duration::from_millis(unix_ms - now));
    }
}

#[test]
fn an_attempt_nobody_watches_ends_at_its_budget_with_only_the_authority_it_was_admitted_with() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let task_root = dir.path().join("tasks");
    let node = Node::spawn(dir.path(), &task_root);
    let binding = binding(7);
    let marker = marker();
    let admission = Admission {
        binding,
        snapshot: imported(dir.path()),
        argv: [
            "sh",
            "-c",
            &format!("while :; do echo beat >> beats; sleep 0.1; done; echo {marker}"),
        ]
        .map(str::to_owned)
        .to_vec(),
        budget_ms: 2_000,
        expires_at_unix_ms: now_ms() + 600_000,
    };
    let ctx = context();
    node.accepts(&ctx.create(op(1), binding), TaskLifecycleState::Created);
    let signed = admission.sign();
    node.accepts(&signed.admit(op(2)), TaskLifecycleState::Ready);
    let started = Instant::now();
    node.accepts(&ctx.start(op(3), binding), TaskLifecycleState::Running);

    // The control plane is gone: from here until the workload is over, nothing connects.
    let beats = workspace(&task_root, binding).join("beats");
    eventually("the workload never ran", Duration::from_secs(10), || {
        lines(&beats) > 0 && processes_with(&marker) > 0
    });
    eventually(
        "the workload outlived its budget",
        Duration::from_secs(20),
        || processes_with(&marker) == 0,
    );
    let ran = started.elapsed();
    assert!(
        ran >= Duration::from_millis(1_900),
        "the workload ended before its budget: {ran:?}"
    );
    assert!(
        ran < Duration::from_secs(6),
        "the workload ran well past its budget: {ran:?}"
    );
    let settled = lines(&beats);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(lines(&beats), settled, "the workload no longer runs");

    assert_eq!(
        node.inspected(binding),
        ctx.inspected_with_outcome(
            binding,
            TaskLifecycleState::Exited,
            TaskExecutionOutcome::Failed
        )
        .unwrap()
    );
    let events = evidence(&task_root, binding);
    assert_eq!(events.len(), 3, "{events:?}");
    assert_eq!(
        events[0],
        WardEvent::NodeAttemptAdmitted {
            task: binding.task(),
            attempt: binding.attempt(),
            lease: binding.lease(),
            session: SessionId::from_u128(5),
            operation: 2,
            envelope: signed.digest(),
            issuer_key: Blake3Hash::hash(key_pair().public_key().as_ref()),
            version: 1,
        }
    );
    assert!(matches!(
        events[1],
        WardEvent::NodeAttemptLaunched { operation: 3, .. }
    ));
    assert_eq!(
        events[2],
        WardEvent::NodeAttemptEnded {
            state: NodeAttemptState::Exited,
            outcome: NodeAttemptOutcome::Failed,
            end: NodeAttemptEnd::BudgetExceeded,
            operation: None,
        }
    );
    node.refuses(
        &ctx.start(op(9), binding),
        op(9),
        binding,
        TaskLifecycleRejectionReason::InvalidState,
    );
    assert_eq!(processes_with(&marker), 0);
}

#[test]
fn an_envelope_that_expires_while_the_control_plane_is_away_is_never_started_or_admitted() {
    let dir = private_dir();
    let task_root = dir.path().join("tasks");
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), &task_root);
    let expires_at_unix_ms = now_ms() + 3_000;
    let admission = |task| Admission {
        binding: binding(task),
        snapshot,
        argv: ["sh", "-c", "echo run >> runs"].map(str::to_owned).to_vec(),
        budget_ms: 600_000,
        expires_at_unix_ms,
    };
    let (ready, waiting) = (admission(7).sign(), admission(17).sign());
    let ctx = context();
    node.accepts(
        &ctx.create(op(1), ready.binding),
        TaskLifecycleState::Created,
    );
    node.accepts(&ready.admit(op(2)), TaskLifecycleState::Ready);
    node.accepts(
        &ctx.create(op(1), waiting.binding),
        TaskLifecycleState::Created,
    );

    // The control plane is gone until both envelopes have expired.
    sleep_until(expires_at_unix_ms + 200);
    node.refuses(
        &ctx.start(op(3), ready.binding),
        op(3),
        ready.binding,
        TaskLifecycleRejectionReason::LeaseExpired,
    );
    assert_eq!(
        node.inspected(ready.binding),
        ctx.inspected(ready.binding, TaskLifecycleState::Ready)
    );
    assert!(!workspace(&task_root, ready.binding).exists());
    node.refuses(
        &waiting.admit(op(2)),
        op(2),
        waiting.binding,
        TaskLifecycleRejectionReason::LeaseExpired,
    );
    assert_eq!(
        node.inspected(waiting.binding),
        ctx.inspected(waiting.binding, TaskLifecycleState::Created)
    );

    // A restart without the control plane brings back neither the admission nor a start.
    node.kill();
    let node = Node::spawn(dir.path(), &task_root);
    for admission in [&ready, &waiting] {
        assert_eq!(
            node.inspected(admission.binding),
            ctx.inspected(admission.binding, TaskLifecycleState::Created)
        );
        node.refuses(
            &ctx.start(op(5), admission.binding),
            op(5),
            admission.binding,
            TaskLifecycleRejectionReason::InvalidState,
        );
        node.refuses(
            &admission.admit(op(6)),
            op(6),
            admission.binding,
            TaskLifecycleRejectionReason::LeaseExpired,
        );
        assert!(!workspace(&task_root, admission.binding).exists());
    }
}
