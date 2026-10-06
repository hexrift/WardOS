//! Cross-system acceptance of the `ward-node` action channel (#404, ADR-0031;
//! node-integration.md §6.7, §7.5 and §9): a real node started with `--action-channel`,
//! driven through the real transport by `ward-node-client`, runs a real workload (a Python
//! agent in the sandbox) that asks the control plane through the socket bound at
//! `/run/ward/actions.sock` and proceeds only on an approval. The cases prove approval and
//! denial, expiry, that stop, revoke and a node restart answer a pending request
//! `cancelled`, that a pause keeps it pending, that hostile lines get nothing and are
//! recorded, that a replayed answer is idempotent and a second one refused, and that the
//! channel is advertised and honoured only when the operator enabled it. One `#[test]` per
//! case; each case's pass criterion is stated in [`CASES`] and, word for word, in
//! `docs/node-acceptance.md`, and `scripts/acceptance/node.sh` runs these cases beside the
//! main suite. The cases need a working bubblewrap and skip without one, except under
//! `WARD_REQUIRE_ISOLATION=1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{
    NODE, envelope_input, isolation, issuer, marker, private_dir, processes_with, trust_store,
    wait_until_gone, ward_node_binary,
};
use ward_events::{
    NodeActionDecision, NodeActionKind, NodeActionRefusal, NodeAttemptState, Origin, SnapshotId,
    WardEvent,
};
use ward_node::actions::{ACTION_SOCKET_FILE, actions_dir};
use ward_node::evidence::{self, VerifiedEvidence};
use ward_node_client::{
    ActionsListed, AnswerApplied, Applied, AttemptRequest, Client, EnvelopeInput, Inspection,
    Timeouts, UnixTransport,
};
use ward_node_protocol::{
    ActionCapabilities, ActionDecision, ActionNote, ActionRejectionReason, CapabilityManifestBytes,
    OperationId, PendingAction, TaskBinding, TaskExecutionOutcome, TaskLifecycleRejectionReason,
    TaskLifecycleState,
};

/// One acceptance case: the test of that name and the criterion it passes on.
struct Case {
    name: &'static str,
    criterion: &'static str,
}

/// The action-channel acceptance cases, in the order `docs/node-acceptance.md` lists them.
const CASES: [Case; 8] = [
    Case {
        name: "action_channel_approval_lets_the_workload_proceed_and_a_denial_stops_it",
        criterion: "a workload admitted with an actions grant on a node started with --action-channel finds WARD_ACTION_SOCKET=/run/ward/actions.sock, asks for approval and waits; the control plane lists the request with its id, kind, summary and detail and approves it, the workload receives approved with the note and exits 0, and a second attempt that is denied receives denied and exits non-zero without proceeding; each sealed log records NodeActionRequested with the summary and detail digests and NodeActionAnswered with the answer's operation id before NodeAttemptEnded, never the text; the socket lives in a 0700 directory beside the workspace and is gone once the attempt ends",
    },
    Case {
        name: "action_channel_unanswered_request_expires_after_its_wait",
        criterion: "a request nobody answers is answered expired by the node once the grant's wait_secs ran out, the workload fails closed with a non-zero exit, the log records NodeActionAnswered expired with no operation id, and a late answer once the attempt has ended is refused invalid_state",
    },
    Case {
        name: "action_channel_stop_and_revoke_cancel_a_pending_request",
        criterion: "a stop and a revoke while a request is pending each end the attempt (stopped, revoked) with no workload left, answer the request cancelled and record NodeActionAnswered cancelled before NodeAttemptEnded; a later answer is refused invalid_state and the listing is empty",
    },
    Case {
        name: "action_channel_pause_keeps_a_request_pending_until_answered_after_resume",
        criterion: "a pause while a request is pending keeps it pending past its wait (the listing reads paused with the request in it, nothing is answered expired), and an approval given after resume is delivered: the workload proceeds and exits 0, and the log shows the pause and resume around the request and its answer",
    },
    Case {
        name: "action_channel_hostile_lines_get_nothing_and_are_recorded",
        criterion: "an oversized line, a malformed line, a node lifecycle request and a hello sent on the channel, each on its own connection, are each answered with zero bytes and a closed connection and recorded as NodeActionRefused oversized, malformed, control_request and control_request; nothing of them reaches the control plane's listing, and a well-formed request afterwards is still listed and approved",
    },
    Case {
        name: "action_channel_replayed_answer_is_idempotent_and_a_second_answer_is_refused",
        criterion: "replaying an answer with the same operation id and the same decision is answered answered again and appends nothing, a different answer to the same request is refused already_answered, the same operation id with another decision is refused stale_operation, an unknown request number is refused unknown_request, and the log holds exactly one NodeActionAnswered for the request",
    },
    Case {
        name: "action_channel_pending_request_is_cancelled_when_a_restarted_node_recovers_the_attempt",
        criterion: "after SIGKILL of the node while a request is pending and a restart with the flag, the attempt is exited with an unknown receipt, its log records NodeActionAnswered cancelled for the request before NodeAttemptRecovered and still verifies, the listing is empty and the attempt seals",
    },
    Case {
        name: "action_channel_is_advertised_and_honoured_only_when_enabled",
        criterion: "a node started without --action-channel carries no actions section in its 1.3 capability document, refuses an actions grant unsupported_grant with nothing materialised and answers actions and answer unsupported_operation; the same node started with it reports actions with approval and decision and its ceilings, and refuses a grant above them unsupported_grant",
    },
];

fn case(name: &str) -> &'static Case {
    CASES.iter().find(|case| case.name == name).unwrap()
}

fn pass(name: &str, started: Instant) {
    let case = case(name);
    eprintln!(
        "acceptance {}: PASS in {} ms -- {}",
        case.name,
        started.elapsed().as_millis(),
        case.criterion
    );
}

/// The agent the workloads run: asks through the channel and acts on the reply.
const AGENT: &str = r#"
import json
import os
import socket
import sys


def connect():
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    peer.settimeout(300)
    peer.connect(os.environ["WARD_ACTION_SOCKET"])
    return peer


def ask(peer, rid, kind, summary, detail):
    line = json.dumps({"id": rid, "kind": kind, "summary": summary, "detail": detail})
    peer.sendall((line + "\n").encode())
    data = b""
    while not data.endswith(b"\n"):
        chunk = peer.recv(4096)
        if not chunk:
            return None
        data += chunk
    return json.loads(data)


def write(name, text):
    with open(name, "w") as out:
        out.write(text)


def drain(peer):
    got = b""
    try:
        while True:
            chunk = peer.recv(4096)
            if not chunk:
                break
            got += chunk
    except OSError:
        pass
    return got


EXIT = {"approved": 0, "denied": 3, "expired": 4, "cancelled": 5}

mode = sys.argv[1]
write("env.txt", json.dumps(dict(os.environ)))
if mode == "hostile":
    rows = []
    lifecycle = {"request": "stop", "protocol": {"major": 1, "minor": 3}, "operation_id": 9,
                 "binding": {"task": "t", "attempt": "a", "lease": "l"}}
    hello = {"request": "hello", "protocol": {"major": 1, "min_minor": 3, "max_minor": 3}}
    for name, payload in [
        ("oversized", b"x" * (200 * 1024) + b"\n"),
        ("malformed", b"{\"id\": \"half\n"),
        ("lifecycle", (json.dumps(lifecycle) + "\n").encode()),
        ("hello", (json.dumps(hello) + "\n").encode()),
    ]:
        peer = connect()
        try:
            peer.sendall(payload)
        except OSError:
            pass
        rows.append("%s %d" % (name, len(drain(peer))))
        peer.close()
    write("hostile.txt", "\n".join(rows) + "\n")
reply = ask(connect(), sys.argv[2], "approval", "deploy to staging", "plan: rotate 3 services")
write("reply.json", json.dumps(reply))
if reply is None:
    sys.exit(6)
if reply["decision"] == "approved":
    write("proceeded", "yes")
sys.exit(EXIT.get(reply["decision"], 7))
"#;

const SUMMARY: &str = "deploy to staging";
const DETAIL: &str = "plan: rotate 3 services";

fn op(value: u64) -> OperationId {
    OperationId::new(value).unwrap()
}

fn binding(task: u128, attempt: u128, lease: u128) -> TaskBinding {
    TaskBinding::new(
        ward_events::TaskId::from_u128(task),
        ward_events::ExecutionAttemptId::from_u128(attempt),
        ward_events::LeaseId::from_u128(lease),
    )
}

fn connect(socket: &Path) -> Client<UnixTransport> {
    Client::connect(UnixTransport::new(socket, Timeouts::default())).unwrap()
}

/// Import a project holding the agent into the node's snapshot store.
fn imported(dir: &Path) -> SnapshotId {
    let project = dir.join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("agent.py"), AGENT).unwrap();
    let output = Command::new(ward_node_binary())
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

fn actions_manifest_bytes(max_pending: u32, max_total: u32, wait_secs: u32) -> Vec<u8> {
    format!(
        r#"{{"network":"offline","actions":{{"kinds":["approval","decision"],"max_pending":{max_pending},"max_total":{max_total},"wait_secs":{wait_secs}}}}}"#
    )
    .into_bytes()
}

fn actions_manifest(wait_secs: u32) -> CapabilityManifestBytes {
    CapabilityManifestBytes::new(actions_manifest_bytes(2, 4, wait_secs)).unwrap()
}

fn workload(
    binding: TaskBinding,
    snapshot: SnapshotId,
    agent_args: &[&str],
    manifest: CapabilityManifestBytes,
) -> EnvelopeInput {
    let command: Vec<&str> = ["python3", "agent.py"]
        .into_iter()
        .chain(agent_args.iter().copied())
        .collect();
    let mut input = envelope_input(binding, snapshot, &command);
    input.workload.wall_clock_budget_ms = 300_000;
    input.workload.capability_manifest = Some(manifest);
    input
}

fn signed(node: &Node, input: &EnvelopeInput) -> AttemptRequest {
    AttemptRequest::sign(
        &input.clone().build().unwrap(),
        &issuer(),
        Some(node.task_root.clone()),
    )
    .unwrap()
}

fn accepted(applied: Result<Applied, ward_node_client::ClientError>) -> TaskLifecycleState {
    match applied.unwrap() {
        Applied::Accepted { state } => state,
        Applied::Rejected { reason } => panic!("rejected: {reason:?}"),
    }
}

fn rejected(
    applied: Result<Applied, ward_node_client::ClientError>,
) -> TaskLifecycleRejectionReason {
    match applied.unwrap() {
        Applied::Rejected { reason } => reason,
        Applied::Accepted { state } => panic!("accepted: {state:?}"),
    }
}

fn inspected(
    client: &Client<UnixTransport>,
    binding: TaskBinding,
) -> (TaskLifecycleState, Option<TaskExecutionOutcome>) {
    match client.inspect(binding).unwrap() {
        Inspection::Inspected { state, outcome } => (state, outcome),
        Inspection::Rejected { reason } => panic!("inspect refused: {reason:?}"),
    }
}

/// Create, admit and start `request`, operation ids 1 to 3.
fn started(client: &Client<UnixTransport>, binding: TaskBinding, request: &AttemptRequest) {
    assert_eq!(
        accepted(client.create(binding, op(1))),
        TaskLifecycleState::Created
    );
    assert_eq!(
        accepted(client.admit(binding, op(2), &request.envelope)),
        TaskLifecycleState::Ready
    );
    assert_eq!(
        accepted(client.start(binding, op(3))),
        TaskLifecycleState::Running
    );
}

/// The listing once it holds `count` requests; it never holds more on the way.
fn pending(
    client: &Client<UnixTransport>,
    binding: TaskBinding,
    count: usize,
) -> (TaskLifecycleState, Vec<PendingAction>) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match client.actions(binding).unwrap() {
            ActionsListed::Actions { state, pending } if pending.len() == count => {
                return (state, pending);
            }
            ActionsListed::Actions { pending, .. } => {
                assert!(pending.len() < count, "{pending:?}");
            }
            ActionsListed::Rejected { reason } => panic!("actions refused: {reason:?}"),
        }
        assert!(Instant::now() < deadline, "never {count} pending");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn answered(
    client: &Client<UnixTransport>,
    binding: TaskBinding,
    operation: u64,
    action: u32,
    decision: ActionDecision,
    note: Option<&str>,
) -> AnswerApplied {
    client
        .answer(
            binding,
            op(operation),
            action,
            decision,
            note.map(|note| ActionNote::new(note).unwrap()),
        )
        .unwrap()
}

/// Wait until the attempt's workload has ended on its own.
fn exited(client: &Client<UnixTransport>, binding: TaskBinding) -> Option<TaskExecutionOutcome> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (state, outcome) = inspected(client, binding);
        if state == TaskLifecycleState::Exited {
            return outcome;
        }
        assert!(matches!(state, TaskLifecycleState::Running), "{state:?}");
        assert!(Instant::now() < deadline, "the workload never exited");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn verified(node: &Node, binding: TaskBinding) -> VerifiedEvidence {
    let dir = evidence::evidence_dir(&node.task_root, binding);
    let log = evidence::verify(&dir, binding).unwrap();
    for record in log.records() {
        assert_eq!(record.origin, Origin::Node, "{record:?}");
    }
    log
}

fn events(log: &VerifiedEvidence) -> Vec<WardEvent> {
    log.records()
        .iter()
        .map(|record| record.event.clone())
        .collect()
}

fn answers(log: &VerifiedEvidence) -> Vec<(u32, NodeActionDecision, Option<u64>)> {
    events(log)
        .into_iter()
        .filter_map(|event| match event {
            WardEvent::NodeActionAnswered {
                action,
                decision,
                operation,
                ..
            } => Some((action, decision, operation)),
            _ => None,
        })
        .collect()
}

/// The index of the first record matching `wanted`.
fn position(log: &VerifiedEvidence, wanted: impl Fn(&WardEvent) -> bool) -> usize {
    events(log)
        .iter()
        .position(wanted)
        .unwrap_or_else(|| panic!("no such record in {:?}", events(log)))
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

fn log_carries(node: &Node, binding: TaskBinding, text: &str) -> bool {
    let bytes = std::fs::read(
        evidence::evidence_dir(&node.task_root, binding).join(evidence::EVIDENCE_LOG),
    )
    .unwrap();
    bytes
        .windows(text.len())
        .any(|window| window == text.as_bytes())
}

fn reply(node: &Node, binding: TaskBinding) -> serde_json::Value {
    serde_json::from_str(
        &std::fs::read_to_string(node.workspace(binding).join("reply.json")).unwrap(),
    )
    .unwrap()
}

struct Node {
    child: Child,
    socket: PathBuf,
    task_root: PathBuf,
}

impl Node {
    fn spawn(dir: &Path, action_channel: bool) -> Self {
        let socket = dir.join("node.sock");
        let task_root = dir.join("tasks");
        let _ = std::fs::remove_file(&socket);
        let mut command = Command::new(ward_node_binary());
        command
            .arg("--socket")
            .arg(&socket)
            .arg("--state-dir")
            .arg(dir.join("state"))
            .arg("--node-id")
            .arg(NODE.to_string())
            .arg("--trusted-issuers")
            .arg(trust_store(dir))
            .arg("--task-root")
            .arg(&task_root)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if action_channel {
            command.arg("--action-channel");
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
        Self {
            child,
            socket,
            task_root,
        }
    }

    fn kill(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }

    fn workspace(&self, binding: TaskBinding) -> PathBuf {
        self.task_root
            .join(binding.task().to_string())
            .join(binding.attempt().to_string())
    }

    fn channel(&self, binding: TaskBinding) -> PathBuf {
        actions_dir(&self.task_root, binding).join(ACTION_SOCKET_FILE)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn every_action_acceptance_case_is_documented() {
    let doc = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/node-acceptance.md"),
    )
    .unwrap();
    for case in &CASES {
        assert!(doc.contains(case.name), "undocumented case {}", case.name);
        assert!(
            doc.contains(case.criterion),
            "the documented criterion of {} differs from the code's",
            case.name
        );
    }
    let runner = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/acceptance/node.sh"),
    )
    .unwrap();
    assert!(runner.contains("--test acceptance_actions"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn action_channel_approval_lets_the_workload_proceed_and_a_denial_stops_it() {
    if !isolation() {
        return;
    }
    let started_at = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);

    let approved = binding(0xa0, 0xa1, 0xa2);
    let request = signed(
        &node,
        &workload(
            approved,
            snapshot,
            &["ask", "deploy-1"],
            actions_manifest(120),
        ),
    );
    started(&client, approved, &request);
    let (state, listed) = pending(&client, approved, 1);
    assert_eq!(state, TaskLifecycleState::Running);
    assert_eq!(listed[0].action(), 1);
    assert_eq!(listed[0].id().as_str(), "deploy-1");
    assert_eq!(listed[0].summary(), SUMMARY);
    assert_eq!(listed[0].detail(), DETAIL);
    assert!(listed[0].expires_in_ms() <= 120_000);
    let channel_dir = actions_dir(&node.task_root, approved);
    assert_eq!(mode(&channel_dir), 0o700);
    assert_eq!(channel_dir.parent(), node.workspace(approved).parent());
    assert!(node.channel(approved).exists());
    assert!(!node.workspace(approved).join(ACTION_SOCKET_FILE).exists());
    assert_eq!(
        answered(
            &client,
            approved,
            10,
            1,
            ActionDecision::Approved,
            Some("go ahead")
        ),
        AnswerApplied::Answered {
            action: 1,
            decision: ActionDecision::Approved
        }
    );
    assert_eq!(
        exited(&client, approved),
        Some(TaskExecutionOutcome::Completed)
    );
    let got = reply(&node, approved);
    assert_eq!(got["id"], "deploy-1");
    assert_eq!(got["decision"], "approved");
    assert_eq!(got["note"], "go ahead");
    assert!(node.workspace(approved).join("proceeded").exists());
    let env: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(node.workspace(approved).join("env.txt")).unwrap(),
    )
    .unwrap();
    assert_eq!(env["WARD_ACTION_SOCKET"], "/run/ward/actions.sock");
    assert!(env.get("WARD_PROXY_SOCKET").is_none());
    assert!(
        !node.channel(approved).exists(),
        "the socket ends with the attempt"
    );
    assert_eq!(
        accepted(client.seal(approved, op(4))),
        TaskLifecycleState::Sealed
    );
    let log = verified(&node, approved);
    assert!(log.is_sealed());
    let requested = position(&log, |event| {
        matches!(event, WardEvent::NodeActionRequested { action: 1, .. })
    });
    assert_eq!(
        events(&log)[requested],
        WardEvent::NodeActionRequested {
            action: 1,
            kind: NodeActionKind::Approval,
            summary_bytes: SUMMARY.len() as u64,
            summary: ward_events::Blake3Hash::hash(SUMMARY.as_bytes()),
            detail_bytes: DETAIL.len() as u64,
            detail: ward_events::Blake3Hash::hash(DETAIL.as_bytes()),
        }
    );
    let answer = position(&log, |event| {
        matches!(event, WardEvent::NodeActionAnswered { action: 1, .. })
    });
    assert_eq!(
        events(&log)[answer],
        WardEvent::NodeActionAnswered {
            action: 1,
            decision: NodeActionDecision::Approved,
            operation: Some(10),
            note_bytes: 8,
            note: Some(ward_events::Blake3Hash::hash(b"go ahead")),
        }
    );
    let ended = position(&log, |event| {
        matches!(event, WardEvent::NodeAttemptEnded { .. })
    });
    assert!(requested < answer && answer < ended);
    for text in [SUMMARY, DETAIL, "go ahead"] {
        assert!(!log_carries(&node, approved, text), "{text}");
    }

    let denied = binding(0xa3, 0xa4, 0xa5);
    let request = signed(
        &node,
        &workload(
            denied,
            snapshot,
            &["ask", "deploy-2"],
            actions_manifest(120),
        ),
    );
    started(&client, denied, &request);
    pending(&client, denied, 1);
    assert_eq!(
        answered(&client, denied, 10, 1, ActionDecision::Denied, None),
        AnswerApplied::Answered {
            action: 1,
            decision: ActionDecision::Denied
        }
    );
    assert_eq!(exited(&client, denied), Some(TaskExecutionOutcome::Failed));
    assert_eq!(reply(&node, denied)["decision"], "denied");
    assert!(!node.workspace(denied).join("proceeded").exists());
    assert_eq!(
        accepted(client.seal(denied, op(4))),
        TaskLifecycleState::Sealed
    );
    assert_eq!(
        answers(&verified(&node, denied)),
        [(1, NodeActionDecision::Denied, Some(10))]
    );
    pass(
        "action_channel_approval_lets_the_workload_proceed_and_a_denial_stops_it",
        started_at,
    );
}

#[test]
fn action_channel_unanswered_request_expires_after_its_wait() {
    if !isolation() {
        return;
    }
    let started_at = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);
    let expiring = binding(0xb0, 0xb1, 0xb2);
    let request = signed(
        &node,
        &workload(expiring, snapshot, &["ask", "slow"], actions_manifest(1)),
    );
    started(&client, expiring, &request);
    assert_eq!(
        exited(&client, expiring),
        Some(TaskExecutionOutcome::Failed)
    );
    assert_eq!(reply(&node, expiring)["decision"], "expired");
    assert!(!node.workspace(expiring).join("proceeded").exists());
    assert_eq!(
        answered(&client, expiring, 10, 1, ActionDecision::Approved, None),
        AnswerApplied::Rejected {
            reason: ActionRejectionReason::InvalidState
        },
        "the attempt has ended"
    );
    let log = verified(&node, expiring);
    assert_eq!(answers(&log), [(1, NodeActionDecision::Expired, None)]);
    pass(
        "action_channel_unanswered_request_expires_after_its_wait",
        started_at,
    );
}

#[test]
fn action_channel_stop_and_revoke_cancel_a_pending_request() {
    if !isolation() {
        return;
    }
    let started_at = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);
    for (attempt, revoke) in [
        (binding(0xc0, 0xc1, 0xc2), false),
        (binding(0xc3, 0xc4, 0xc5), true),
    ] {
        let marker = marker("ward-acceptance-actions");
        let request = signed(
            &node,
            &workload(
                attempt,
                snapshot,
                &["ask", "held", &marker],
                actions_manifest(120),
            ),
        );
        started(&client, attempt, &request);
        pending(&client, attempt, 1);
        assert!(
            processes_with(&marker) > 0,
            "the workload waits in the sandbox"
        );
        let ended = if revoke {
            accepted(client.revoke(attempt, op(5)))
        } else {
            accepted(client.stop(attempt, op(5)))
        };
        let expected = if revoke {
            TaskLifecycleState::Revoked
        } else {
            TaskLifecycleState::Stopped
        };
        assert_eq!(ended, expected);
        wait_until_gone(&marker);
        assert_eq!(
            answered(&client, attempt, 10, 1, ActionDecision::Approved, None),
            AnswerApplied::Rejected {
                reason: ActionRejectionReason::InvalidState
            }
        );
        assert_eq!(pending(&client, attempt, 0).1, Vec::new());
        assert!(!node.channel(attempt).exists());
        let log = verified(&node, attempt);
        assert_eq!(answers(&log), [(1, NodeActionDecision::Cancelled, None)]);
        let cancelled = position(&log, |event| {
            matches!(event, WardEvent::NodeActionAnswered { .. })
        });
        let end = position(&log, |event| {
            matches!(event, WardEvent::NodeAttemptEnded { .. })
        });
        assert!(cancelled < end);
        let state = if revoke {
            NodeAttemptState::Revoked
        } else {
            NodeAttemptState::Stopped
        };
        assert!(matches!(
            events(&log)[end],
            WardEvent::NodeAttemptEnded { state: got, .. } if got == state
        ));
        assert_eq!(
            accepted(client.seal(attempt, op(6))),
            TaskLifecycleState::Sealed
        );
    }
    pass(
        "action_channel_stop_and_revoke_cancel_a_pending_request",
        started_at,
    );
}

#[test]
fn action_channel_pause_keeps_a_request_pending_until_answered_after_resume() {
    if !isolation() {
        return;
    }
    let started_at = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);
    let paused = binding(0xd0, 0xd1, 0xd2);
    let request = signed(
        &node,
        &workload(paused, snapshot, &["ask", "paused"], actions_manifest(5)),
    );
    started(&client, paused, &request);
    pending(&client, paused, 1);
    assert_eq!(
        accepted(client.pause(paused, op(4))),
        TaskLifecycleState::Paused
    );
    let (_, frozen) = pending(&client, paused, 1);
    // Hold the pause past the request's whole wait: its clock is stopped, so the time it
    // has left reads the same before and after, and nothing is answered expired.
    std::thread::sleep(Duration::from_secs(6));
    let (state, listed) = pending(&client, paused, 1);
    assert_eq!(state, TaskLifecycleState::Paused);
    assert_eq!(listed[0].id().as_str(), "paused");
    assert_eq!(listed[0].expires_in_ms(), frozen[0].expires_in_ms());
    assert!(listed[0].expires_in_ms() > 0);
    assert!(
        answers(&verified(&node, paused)).is_empty(),
        "nothing expired"
    );
    assert_eq!(
        accepted(client.resume(paused, op(5))),
        TaskLifecycleState::Running
    );
    assert_eq!(
        answered(&client, paused, 10, 1, ActionDecision::Approved, None),
        AnswerApplied::Answered {
            action: 1,
            decision: ActionDecision::Approved
        }
    );
    assert_eq!(
        exited(&client, paused),
        Some(TaskExecutionOutcome::Completed)
    );
    assert!(node.workspace(paused).join("proceeded").exists());
    let log = verified(&node, paused);
    assert_eq!(answers(&log), [(1, NodeActionDecision::Approved, Some(10))]);
    let requested = position(&log, |event| {
        matches!(event, WardEvent::NodeActionRequested { .. })
    });
    let pause = position(&log, |event| {
        matches!(event, WardEvent::NodeAttemptIntervened { operation: 4, .. })
    });
    let resume = position(&log, |event| {
        matches!(event, WardEvent::NodeAttemptIntervened { operation: 5, .. })
    });
    let answer = position(&log, |event| {
        matches!(event, WardEvent::NodeActionAnswered { .. })
    });
    assert!(requested < pause && pause < resume && resume < answer);
    pass(
        "action_channel_pause_keeps_a_request_pending_until_answered_after_resume",
        started_at,
    );
}

#[test]
fn action_channel_hostile_lines_get_nothing_and_are_recorded() {
    if !isolation() {
        return;
    }
    let started_at = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);
    let hostile = binding(0xe0, 0xe1, 0xe2);
    let request = signed(
        &node,
        &workload(
            hostile,
            snapshot,
            &["hostile", "after"],
            actions_manifest(120),
        ),
    );
    started(&client, hostile, &request);
    let (_, listed) = pending(&client, hostile, 1);
    assert_eq!(
        listed[0].id().as_str(),
        "after",
        "only the well-formed request"
    );
    assert_eq!(listed[0].action(), 1);
    assert_eq!(
        std::fs::read_to_string(node.workspace(hostile).join("hostile.txt")).unwrap(),
        "oversized 0\nmalformed 0\nlifecycle 0\nhello 0\n"
    );
    assert_eq!(
        answered(&client, hostile, 10, 1, ActionDecision::Approved, None),
        AnswerApplied::Answered {
            action: 1,
            decision: ActionDecision::Approved
        }
    );
    assert_eq!(
        exited(&client, hostile),
        Some(TaskExecutionOutcome::Completed)
    );
    let log = verified(&node, hostile);
    let refusals: Vec<(NodeActionRefusal, u64)> = events(&log)
        .into_iter()
        .filter_map(|event| match event {
            WardEvent::NodeActionRefused { reason, bytes } => Some((reason, bytes)),
            _ => None,
        })
        .collect();
    assert_eq!(
        refusals
            .iter()
            .map(|(reason, _)| *reason)
            .collect::<Vec<_>>(),
        [
            NodeActionRefusal::Oversized,
            NodeActionRefusal::Malformed,
            NodeActionRefusal::ControlRequest,
            NodeActionRefusal::ControlRequest,
        ]
    );
    assert!(refusals.iter().all(|(_, bytes)| *bytes > 0), "{refusals:?}");
    assert_eq!(answers(&log), [(1, NodeActionDecision::Approved, Some(10))]);
    pass(
        "action_channel_hostile_lines_get_nothing_and_are_recorded",
        started_at,
    );
}

#[test]
fn action_channel_replayed_answer_is_idempotent_and_a_second_answer_is_refused() {
    if !isolation() {
        return;
    }
    let started_at = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);
    let replayed = binding(0xf0, 0xf1, 0xf2);
    let request = signed(
        &node,
        &workload(replayed, snapshot, &["ask", "once"], actions_manifest(120)),
    );
    started(&client, replayed, &request);
    pending(&client, replayed, 1);
    let approve = AnswerApplied::Answered {
        action: 1,
        decision: ActionDecision::Approved,
    };
    assert_eq!(
        answered(
            &client,
            replayed,
            10,
            1,
            ActionDecision::Approved,
            Some("ok")
        ),
        approve
    );
    assert_eq!(
        answered(
            &client,
            replayed,
            10,
            1,
            ActionDecision::Approved,
            Some("ok")
        ),
        approve,
        "a replay of the same answer"
    );
    assert_eq!(
        answered(&client, replayed, 11, 1, ActionDecision::Denied, None),
        AnswerApplied::Rejected {
            reason: ActionRejectionReason::AlreadyAnswered
        }
    );
    assert_eq!(
        answered(&client, replayed, 10, 1, ActionDecision::Denied, None),
        AnswerApplied::Rejected {
            reason: ActionRejectionReason::StaleOperation
        }
    );
    assert_eq!(
        answered(&client, replayed, 12, 7, ActionDecision::Approved, None),
        AnswerApplied::Rejected {
            reason: ActionRejectionReason::UnknownRequest
        }
    );
    assert_eq!(
        exited(&client, replayed),
        Some(TaskExecutionOutcome::Completed)
    );
    assert_eq!(
        answered(
            &client,
            replayed,
            10,
            1,
            ActionDecision::Approved,
            Some("ok")
        ),
        approve,
        "a replay after the attempt ended"
    );
    assert_eq!(reply(&node, replayed)["decision"], "approved");
    assert_eq!(
        answers(&verified(&node, replayed)),
        [(1, NodeActionDecision::Approved, Some(10))]
    );
    pass(
        "action_channel_replayed_answer_is_idempotent_and_a_second_answer_is_refused",
        started_at,
    );
}

#[test]
fn action_channel_pending_request_is_cancelled_when_a_restarted_node_recovers_the_attempt() {
    if !isolation() {
        return;
    }
    let started_at = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);
    let recovered = binding(0x90, 0x91, 0x92);
    let request = signed(
        &node,
        &workload(
            recovered,
            snapshot,
            &["ask", "orphan"],
            actions_manifest(120),
        ),
    );
    started(&client, recovered, &request);
    pending(&client, recovered, 1);
    drop(client);
    node.kill();

    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);
    assert_eq!(
        inspected(&client, recovered),
        (
            TaskLifecycleState::Exited,
            Some(TaskExecutionOutcome::Unknown)
        )
    );
    assert_eq!(pending(&client, recovered, 0).1, Vec::new());
    assert_eq!(
        answered(&client, recovered, 10, 1, ActionDecision::Approved, None),
        AnswerApplied::Rejected {
            reason: ActionRejectionReason::InvalidState
        }
    );
    let log = verified(&node, recovered);
    assert_eq!(answers(&log), [(1, NodeActionDecision::Cancelled, None)]);
    let cancelled = position(&log, |event| {
        matches!(event, WardEvent::NodeActionAnswered { .. })
    });
    let recovery = position(&log, |event| {
        matches!(event, WardEvent::NodeAttemptRecovered { .. })
    });
    assert!(cancelled < recovery);
    assert_eq!(
        accepted(client.seal(recovered, op(6))),
        TaskLifecycleState::Sealed
    );
    assert!(verified(&node, recovered).is_sealed());
    pass(
        "action_channel_pending_request_is_cancelled_when_a_restarted_node_recovers_the_attempt",
        started_at,
    );
}

#[test]
fn action_channel_is_advertised_and_honoured_only_when_enabled() {
    if !isolation() {
        return;
    }
    let started_at = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());

    let plain = Node::spawn(dir.path(), false);
    let client = connect(&plain.socket);
    let capabilities = client.capabilities().unwrap();
    assert_eq!(capabilities.actions(), ActionCapabilities::NONE);
    assert!(capabilities.lifecycle().start);
    let refused = binding(0x80, 0x81, 0x82);
    let request = signed(
        &plain,
        &workload(refused, snapshot, &["ask", "x"], actions_manifest(30)),
    );
    assert_eq!(
        accepted(client.create(refused, op(1))),
        TaskLifecycleState::Created
    );
    assert_eq!(
        rejected(client.admit(refused, op(2), &request.envelope)),
        TaskLifecycleRejectionReason::UnsupportedGrant
    );
    assert!(!plain.task_root.join(refused.task().to_string()).exists());
    assert_eq!(
        client.actions(refused).unwrap(),
        ActionsListed::Rejected {
            reason: ActionRejectionReason::UnsupportedOperation
        }
    );
    assert_eq!(
        answered(&client, refused, 3, 1, ActionDecision::Approved, None),
        AnswerApplied::Rejected {
            reason: ActionRejectionReason::UnsupportedOperation
        }
    );
    drop(client);
    plain.kill();

    let channel = Node::spawn(dir.path(), true);
    let client = connect(&channel.socket);
    let capabilities = client.capabilities().unwrap();
    assert_eq!(capabilities.actions(), ActionCapabilities::CEILINGS);
    assert!(capabilities.actions().approval && capabilities.actions().decision);
    assert!(!capabilities.output().any());
    let over = binding(0x83, 0x84, 0x85);
    let request = signed(
        &channel,
        &workload(
            over,
            snapshot,
            &["ask", "x"],
            CapabilityManifestBytes::new(actions_manifest_bytes(9, 9, 30)).unwrap(),
        ),
    );
    assert_eq!(
        accepted(client.create(over, op(1))),
        TaskLifecycleState::Created
    );
    assert_eq!(
        rejected(client.admit(over, op(2), &request.envelope)),
        TaskLifecycleRejectionReason::UnsupportedGrant
    );
    assert!(!channel.task_root.join(over.task().to_string()).exists());
    pass(
        "action_channel_is_advertised_and_honoured_only_when_enabled",
        started_at,
    );
}
