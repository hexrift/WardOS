//! `ward-node audit` against a real node's state directory (#259).
//!
//! The audit answers who delegated what authority to which task and when from the task's
//! durable record alone, and with `--task-root` cross-checks the attempt's evidence log.
//! The record cases run everywhere; the evidence cases need a working bubblewrap and skip
//! without one, except under `WARD_REQUIRE_ISOLATION=1`, where CI runs them for real.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ring::signature::{Ed25519KeyPair, KeyPair};
use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, DelegationInput,
    EmptyAuthorityPolicy, GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::log::{head_file_path, parse_head};
use ward_events::{
    AgentId, Blake3Hash, DelegationId, ExecutionAttemptId, LeaseId, NodeId, PrincipalId, SessionId,
    SnapshotId, TaskId,
};
use ward_node::evidence;
use ward_node_protocol::{
    AdmissionEnvelopeJson, AdmissionVersion, CapabilityManifestBytes, HandshakeRequest,
    HandshakeResponse, IssuerProof, IssuerSignature, OperationId, ProtocolVersion,
    TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput, TaskBinding,
    TaskExecutionOutcome, TaskLifecycleContext, TaskLifecycleRequest, TaskLifecycleResponse,
    TaskLifecycleState, TaskWorkload, WARD_NODE_PROTOCOL, WorkloadArgv,
};

const NODE: NodeId = NodeId::from_u128(4);
const PRINCIPAL: PrincipalId = PrincipalId::from_u128(2);
const PARENT_AGENT: AgentId = AgentId::from_u128(3);
const AGENT: AgentId = AgentId::from_u128(13);
const ROOT_LEASE: LeaseId = LeaseId::from_u128(20);
const ROOT_DELEGATION: DelegationId = DelegationId::from_u128(21);
const DELEGATION: DelegationId = DelegationId::from_u128(6);
const SESSION: SessionId = SessionId::from_u128(5);

const ROOT_ISSUED: u64 = 1_767_225_600_000;
const ROOT_EXPIRES: u64 = 1_893_456_000_000;
const LEASE_ISSUED: u64 = ROOT_ISSUED + 3_600_000;
const LEASE_EXPIRES: u64 = ROOT_EXPIRES - 3_600_000;
const ROOT_ISSUED_TEXT: &str = "2026-01-01T00:00:00.000Z";
const ROOT_EXPIRES_TEXT: &str = "2030-01-01T00:00:00.000Z";
const LEASE_ISSUED_TEXT: &str = "2026-01-01T01:00:00.000Z";
const LEASE_EXPIRES_TEXT: &str = "2029-12-31T23:00:00.000Z";

fn key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
}

fn key_id() -> Blake3Hash {
    Blake3Hash::hash(key_pair().public_key().as_ref())
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

fn other_binding() -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(17),
        ExecutionAttemptId::from_u128(18),
        LeaseId::from_u128(19),
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

fn grant(capability: &str, delegable: bool) -> CapabilityGrant {
    CapabilityGrant::new(
        CapabilityName::new(capability).unwrap(),
        ResourceRef::new("repo:hexrift/WardOS").unwrap(),
        delegable,
    )
}

fn chain() -> (AuthorityLease, AuthorityLease) {
    let binding = binding();
    let root = AuthorityLease::root(
        AuthorityLeaseInput {
            id: ROOT_LEASE,
            delegation_id: ROOT_DELEGATION,
            issuer: PRINCIPAL,
            subject: PARENT_AGENT,
            task: binding.task(),
            grants: GrantSet::new([grant("repo.read", true), grant("repo.write", false)]).unwrap(),
            issued_at_unix_ms: ROOT_ISSUED,
            expires_at_unix_ms: ROOT_EXPIRES,
            version: LeaseVersion::new(1).unwrap(),
        },
        now_ms(),
        EmptyAuthorityPolicy::Reject,
    )
    .unwrap();
    let child = root
        .delegate(
            DelegationInput {
                id: binding.lease(),
                delegation_id: DELEGATION,
                subject: AGENT,
                task: binding.task(),
                grants: GrantSet::new([grant("repo.read", false)]).unwrap(),
                issued_at_unix_ms: LEASE_ISSUED,
                expires_at_unix_ms: LEASE_EXPIRES,
                version: LeaseVersion::new(2).unwrap(),
            },
            now_ms(),
            EmptyAuthorityPolicy::Reject,
        )
        .unwrap();
    (root, child)
}

fn signed_admit(
    operation: OperationId,
    snapshot: SnapshotId,
    argv: &[&str],
) -> (TaskLifecycleRequest, Blake3Hash) {
    let binding = binding();
    let (root, child) = chain();
    let envelope = TaskAdmissionEnvelope::new(TaskAdmissionEnvelopeInput {
        binding,
        agent: AGENT,
        node: NODE,
        session: SESSION,
        authority: TaskAdmissionAuthority::new(
            UntrustedAuthorityLease::from(&child),
            vec![UntrustedAuthorityLease::from(&root)],
        )
        .unwrap(),
        workload: TaskWorkload::new(
            WorkloadArgv::new(argv.iter().map(|arg| (*arg).to_owned()).collect()).unwrap(),
            CapabilityManifestBytes::new(br#"{"network":"offline"}"#.to_vec()).unwrap(),
            snapshot,
            600_000,
        )
        .unwrap(),
        issued_at_unix_ms: ROOT_ISSUED,
        expires_at_unix_ms: ROOT_EXPIRES,
        version: AdmissionVersion::new(1).unwrap(),
    })
    .unwrap();
    let json = AdmissionEnvelopeJson::encode(&envelope).unwrap();
    let key_pair = key_pair();
    let proof = IssuerProof::new(
        key_id(),
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
        format!("{} {PRINCIPAL}\n", hex(key_pair().public_key().as_ref())),
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

    fn create_and_admit(&self, snapshot: SnapshotId, argv: &[&str]) -> Blake3Hash {
        let ctx = context();
        assert_eq!(
            self.lifecycle(&ctx.create(op(1), binding())),
            ctx.accepted(op(1), binding(), TaskLifecycleState::Created)
        );
        let (admit, envelope) = signed_admit(op(2), snapshot, argv);
        assert_eq!(
            self.lifecycle(&admit),
            ctx.accepted(op(2), binding(), TaskLifecycleState::Ready)
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

fn audit(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ward-node"))
        .args(["audit", "--state-dir"])
        .arg(dir.join("state"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[track_caller]
fn passing(output: &Output) -> String {
    assert!(output.status.success(), "{}", stderr(output));
    assert!(stderr(output).is_empty(), "{}", stderr(output));
    stdout(output)
}

#[track_caller]
fn failing(output: &Output) -> String {
    assert_eq!(output.status.code(), Some(1), "{}", stdout(output));
    format!("{}{}", stdout(output), stderr(output))
}

fn json(dir: &Path, args: &[&str]) -> (Output, serde_json::Value) {
    let output = audit(dir, &[args, &["--json"]].concat());
    let value = serde_json::from_str(&stdout(&output)).unwrap();
    (output, value)
}

fn record_path(dir: &Path) -> PathBuf {
    dir.join("state")
        .join("tasks")
        .join(format!("{}.json", binding().task()))
}

fn evidence_log(task_root: &Path) -> PathBuf {
    evidence::evidence_dir(task_root, binding()).join(evidence::EVIDENCE_LOG)
}

const ATTEMPT_LINE: usize = 5;

fn delegation_lines(envelope: Blake3Hash) -> [String; 5] {
    let binding = binding();
    [
        format!(
            "agent {PARENT_AGENT} delegated lease {} (delegation {DELEGATION}) to agent {AGENT} \
             for task {} at {LEASE_ISSUED_TEXT}, expires {LEASE_EXPIRES_TEXT}, under principal \
             {PRINCIPAL} from lease {ROOT_LEASE}",
            binding.lease(),
            binding.task()
        ),
        "grants: repo.read on repo:hexrift/WardOS".to_owned(),
        "lineage, root first:".to_owned(),
        format!(
            "  lease {ROOT_LEASE} (delegation {ROOT_DELEGATION}) from principal {PRINCIPAL} to \
             agent {PARENT_AGENT}, valid {ROOT_ISSUED_TEXT} to {ROOT_EXPIRES_TEXT}, grants: \
             repo.read on repo:hexrift/WardOS (delegable); repo.write on repo:hexrift/WardOS"
        ),
        format!(
            "; envelope {envelope} valid {ROOT_ISSUED_TEXT} to {ROOT_EXPIRES_TEXT}, session \
             {SESSION}"
        ),
    ]
}

#[track_caller]
fn assert_chain(text: &str, envelope: Blake3Hash) {
    let lines: Vec<&str> = text.lines().collect();
    let [first, grants, lineage, root, admitted_tail] = delegation_lines(envelope);
    assert_eq!(lines[0], first, "{text}");
    assert_eq!(lines[1], grants, "{text}");
    assert_eq!(lines[2], lineage, "{text}");
    assert_eq!(lines[3], root, "{text}");
    assert!(
        lines[4].starts_with(&format!("admitted by key {} as version 1 at 2", key_id())),
        "{text}"
    );
    assert!(lines[4].contains("Z (operation 2)"), "{text}");
    assert!(lines[4].ends_with(&admitted_tail), "{text}");
}

#[track_caller]
fn assert_chain_json(value: &serde_json::Value, envelope: Blake3Hash, before: u64, after: u64) {
    let binding = binding();
    assert_eq!(value["schema"], 1);
    assert_eq!(value["task"], binding.task().to_string());
    assert_eq!(value["attempt"], binding.attempt().to_string());
    assert_eq!(value["lease"], binding.lease().to_string());
    let admitted = &value["admitted"];
    assert_eq!(admitted["operation"], 2);
    assert_eq!(admitted["envelope"], envelope.to_hex());
    assert_eq!(admitted["issuer_key"], key_id().to_hex());
    assert_eq!(admitted["session"], SESSION.to_string());
    let authority = &admitted["authority"];
    assert_eq!(
        authority["lease"],
        serde_json::json!({
            "lease": binding.lease().to_string(),
            "delegation": DELEGATION.to_string(),
            "issuer": PRINCIPAL.to_string(),
            "subject": AGENT.to_string(),
            "parent_lease": ROOT_LEASE.to_string(),
            "delegated_by": PARENT_AGENT.to_string(),
            "grants": [{"capability": "repo.read", "resource": "repo:hexrift/WardOS", "delegable": false}],
            "issued_at_unix_ms": LEASE_ISSUED,
            "expires_at_unix_ms": LEASE_EXPIRES,
            "version": 2,
        })
    );
    assert_eq!(
        authority["lineage"],
        serde_json::json!([{
            "lease": ROOT_LEASE.to_string(),
            "delegation": ROOT_DELEGATION.to_string(),
            "issuer": PRINCIPAL.to_string(),
            "subject": PARENT_AGENT.to_string(),
            "parent_lease": null,
            "delegated_by": null,
            "grants": [
                {"capability": "repo.read", "resource": "repo:hexrift/WardOS", "delegable": true},
                {"capability": "repo.write", "resource": "repo:hexrift/WardOS", "delegable": false},
            ],
            "issued_at_unix_ms": ROOT_ISSUED,
            "expires_at_unix_ms": ROOT_EXPIRES,
            "version": 1,
        }])
    );
    assert_eq!(authority["issued_at_unix_ms"], ROOT_ISSUED);
    assert_eq!(authority["expires_at_unix_ms"], ROOT_EXPIRES);
    assert_eq!(authority["version"], 1);
    let admitted_at = authority["admitted_at_unix_ms"].as_u64().unwrap();
    assert!(
        (before..=after).contains(&admitted_at),
        "{admitted_at} outside {before}..={after}"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn audit_answers_who_delegated_what_from_the_durable_record() {
    let dir = private_dir();
    let node = Node::spawn(dir.path(), None);
    let before = now_ms();
    let envelope = node.create_and_admit(
        SnapshotId::new(Blake3Hash::from_bytes([0x11; 32])),
        &["sh", "-c", "true"],
    );
    let after = now_ms();
    let task = binding().task().to_string();
    let attempt = binding().attempt().to_string();

    let text = passing(&audit(dir.path(), &[&task]));
    assert_chain(&text, envelope);
    assert_eq!(
        text.lines().nth(ATTEMPT_LINE).unwrap(),
        format!("attempt {attempt}: state ready, receipt none, evidence not checked")
    );
    assert_eq!(text.lines().count(), ATTEMPT_LINE + 1);
    assert_eq!(
        passing(&audit(dir.path(), &[&task, "--attempt", &attempt])),
        text
    );

    let (output, value) = json(dir.path(), &[&task, "--attempt", &attempt]);
    passing(&output);
    assert_chain_json(&value, envelope, before, after);
    assert_eq!(value["state"], "ready");
    assert!(value["receipt"].is_null());
    assert!(value["evidence"].is_null());

    let wrong_attempt = other_binding().attempt().to_string();
    let refused = failing(&audit(dir.path(), &[&task, "--attempt", &wrong_attempt]));
    assert!(refused.contains(&wrong_attempt), "{refused}");
    assert!(refused.contains(&attempt), "{refused}");

    let ctx = context();
    assert_eq!(
        node.lifecycle(&ctx.create(op(3), other_binding())),
        ctx.accepted(op(3), other_binding(), TaskLifecycleState::Created)
    );
    let other = other_binding().task().to_string();
    let never = passing(&audit(dir.path(), &[&other]));
    assert_eq!(
        never,
        format!(
            "task {other} attempt {} was never admitted\nattempt {}: state created, receipt \
             none, evidence not checked\n",
            other_binding().attempt(),
            other_binding().attempt()
        )
    );
    let (output, value) = json(dir.path(), &[&other]);
    passing(&output);
    assert!(value["admitted"].is_null());
    assert_eq!(value["state"], "created");

    let unknown = TaskId::from_u128(99).to_string();
    let missing = failing(&audit(dir.path(), &[&unknown]));
    assert!(missing.contains(&unknown), "{missing}");
    assert!(missing.contains("no record"), "{missing}");

    node.kill();
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(record_path(dir.path())).unwrap()).unwrap();
    assert!(
        record["admitted"]
            .as_object_mut()
            .unwrap()
            .remove("authority")
            .is_some()
    );
    std::fs::write(
        record_path(dir.path()),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    let before_facts = passing(&audit(dir.path(), &[&task]));
    assert_eq!(
        before_facts.lines().next().unwrap(),
        format!(
            "task {task} attempt {attempt} was admitted before authority facts were recorded \
             (operation 2, envelope {envelope}, key {}, session {SESSION})",
            key_id()
        )
    );
    assert_eq!(
        before_facts.lines().nth(1).unwrap(),
        format!("attempt {attempt}: state ready, receipt none, evidence not checked")
    );
    let (output, value) = json(dir.path(), &[&task]);
    passing(&output);
    assert_eq!(value["admitted"]["operation"], 2);
    assert!(value["admitted"]["authority"].is_null());
    let node = Node::spawn(dir.path(), None);
    assert_eq!(
        node.lifecycle(&ctx.inspect(binding())),
        ctx.inspected(binding(), TaskLifecycleState::Created)
    );
    node.kill();

    std::fs::write(record_path(dir.path()), b"{not a record").unwrap();
    let malformed = failing(&audit(dir.path(), &[&task]));
    assert!(malformed.contains("invalid"), "{malformed}");
    std::fs::write(record_path(dir.path()), vec![b' '; 8 * 1024 * 1024 + 1]).unwrap();
    assert!(failing(&audit(dir.path(), &[&task])).contains("invalid"));

    let empty = private_dir();
    let nothing = failing(&audit(empty.path(), &[&task]));
    assert!(nothing.contains("no task records"), "{nothing}");
    assert!(!empty.path().join("state").exists());
}

#[test]
#[allow(clippy::too_many_lines)]
fn audit_cross_checks_the_attempts_evidence_log_under_the_task_root() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let task_root = dir.path().join("tasks");
    let node = Node::spawn(dir.path(), Some(&task_root));
    let envelope = node.create_and_admit(snapshot, &["sh", "-c", "echo done > out.txt"]);
    let task = binding().task().to_string();
    let attempt = binding().attempt().to_string();
    let root = task_root.to_str().unwrap();
    let log = evidence_log(&task_root);
    let log_text = log.to_str().unwrap();

    let ready = passing(&audit(dir.path(), &[&task, "--task-root", root]));
    assert_chain(&ready, envelope);
    let head_before = evidence::verify(&evidence::evidence_dir(&task_root, binding()), binding())
        .unwrap()
        .head()
        .hash;
    assert_eq!(
        ready.lines().nth(ATTEMPT_LINE).unwrap(),
        format!(
            "attempt {attempt}: state ready, receipt none, evidence {log_text}: 1 record, head \
             {head_before}, not sealed"
        )
    );

    let ctx = context();
    assert_eq!(
        node.lifecycle(&ctx.start(op(3), binding())),
        ctx.accepted(op(3), binding(), TaskLifecycleState::Running)
    );
    eventually("the workload never exited", || {
        node.finished(TaskLifecycleState::Exited, TaskExecutionOutcome::Completed)
    });
    assert_eq!(
        node.lifecycle(&ctx.seal(op(5), binding())),
        ctx.accepted(op(5), binding(), TaskLifecycleState::Sealed)
    );
    let head = parse_head(&std::fs::read_to_string(head_file_path(&log)).unwrap()).unwrap();

    let sealed = passing(&audit(dir.path(), &[&task, "--task-root", root]));
    assert_chain(&sealed, envelope);
    assert_eq!(
        sealed.lines().nth(ATTEMPT_LINE).unwrap(),
        format!(
            "attempt {attempt}: state sealed, receipt completed, evidence {log_text}: 4 \
             records, head {}, sealed",
            head.hash
        )
    );
    let (output, value) = json(dir.path(), &[&task, "--task-root", root]);
    passing(&output);
    assert_eq!(value["state"], "sealed");
    assert_eq!(value["receipt"], "completed");
    assert_eq!(
        value["evidence"],
        serde_json::json!({
            "log": log_text,
            "verified": {"records": 4, "head": head.hash.to_hex(), "sealed": true},
            "disagreement": null,
        })
    );

    let copy_root = dir.path().join("copy");
    let copy_dir = evidence::evidence_dir(&copy_root, binding());
    std::fs::create_dir_all(&copy_dir).unwrap();
    let mut tampered = std::fs::read(&log).unwrap();
    let target = tampered.len() / 2;
    tampered[target] ^= 0x01;
    std::fs::write(copy_dir.join(evidence::EVIDENCE_LOG), &tampered).unwrap();
    std::fs::copy(
        head_file_path(&log),
        head_file_path(&copy_dir.join(evidence::EVIDENCE_LOG)),
    )
    .unwrap();
    let disagrees = failing(&audit(
        dir.path(),
        &[&task, "--task-root", copy_root.to_str().unwrap()],
    ));
    assert_chain(&disagrees, envelope);
    assert!(
        disagrees.contains("evidence disagrees with the record"),
        "{disagrees}"
    );
    let (output, value) = json(
        dir.path(),
        &[&task, "--task-root", copy_root.to_str().unwrap()],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(value["evidence"]["verified"].is_null());
    assert!(
        value["evidence"]["disagreement"]
            .as_str()
            .unwrap()
            .contains("verify")
    );

    let empty_root = dir.path().join("empty");
    std::fs::create_dir(&empty_root).unwrap();
    let absent = failing(&audit(
        dir.path(),
        &[&task, "--task-root", empty_root.to_str().unwrap()],
    ));
    assert!(
        absent.contains("evidence disagrees with the record"),
        "{absent}"
    );
    assert!(absent.contains("no evidence log"), "{absent}");

    let forged_root = dir.path().join("forged");
    let forged_dir = evidence::evidence_dir(&forged_root, binding());
    std::fs::create_dir_all(&forged_dir).unwrap();
    std::fs::copy(&log, forged_dir.join(evidence::EVIDENCE_LOG)).unwrap();
    node.kill();
    std::fs::write(record_path(dir.path()), {
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(record_path(dir.path())).unwrap()).unwrap();
        record["admitted"]["authority"]["version"] = 2.into();
        serde_json::to_vec(&record).unwrap()
    })
    .unwrap();
    let forged = failing(&audit(
        dir.path(),
        &[&task, "--task-root", forged_root.to_str().unwrap()],
    ));
    assert!(
        forged.contains("evidence disagrees with the record"),
        "{forged}"
    );
    assert!(forged.contains("version"), "{forged}");
}
