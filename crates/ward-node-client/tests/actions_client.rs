//! The client's `actions` and `answer` requests and the adapter's `actions` and `answer`
//! commands over a scripted socket peer (node-integration.md §6.7, §11): a listing larger
//! than a lifecycle line is read within its own bound and decoded strictly, an answer is
//! checked against its operation, binding and request, refusals are typed, and the adapter
//! turns both into events without changing any other command.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{Value, json};
use ward_events::{ExecutionAttemptId, LeaseId, TaskId};
use ward_node_client::{
    ActionsListed, AnswerApplied, Client, ClientError, MAX_LINE_BYTES, Timeouts, UnixTransport,
    Verb,
};
use ward_node_protocol::{
    ActionDecision, ActionId, ActionKind, ActionNote, ActionRejectionReason, ActionRequest,
    HandshakeRequest, HandshakeResponse, MAX_ACTION_DETAIL_BYTES, OperationId, PendingAction,
    ProtocolVersion, TaskBinding, TaskLifecycleContext, TaskLifecycleState, WARD_NODE_PROTOCOL,
    negotiate,
};

fn binding() -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(7),
        ExecutionAttemptId::from_u128(8),
        LeaseId::from_u128(9),
    )
}

fn other_binding() -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(7),
        ExecutionAttemptId::from_u128(80),
        LeaseId::from_u128(9),
    )
}

fn context() -> TaskLifecycleContext {
    TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
}

fn op(value: u64) -> OperationId {
    OperationId::new(value).unwrap()
}

fn socket_path() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sock");
    (dir, path)
}

fn transport(socket: &Path) -> UnixTransport {
    UnixTransport::new(
        socket,
        Timeouts {
            connect: Duration::from_secs(5),
            request: Duration::from_secs(5),
        },
    )
}

/// A scripted node: negotiates the window, then answers each request line with what
/// `answer` returns for its index (requests, not connections), recording every line.
fn fake_node(
    socket: &Path,
    connections: usize,
    answer: impl Fn(usize, &str) -> String + Send + 'static,
) -> (JoinHandle<()>, Arc<Mutex<Vec<String>>>) {
    let listener = UnixListener::bind(socket).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let worker = std::thread::spawn(move || {
        for _ in 0..connections {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            let mut hello = String::new();
            reader.read_line(&mut hello).unwrap();
            let HandshakeRequest::Hello { protocol } = serde_json::from_str(hello.trim()).unwrap();
            let response = negotiate(WARD_NODE_PROTOCOL, protocol);
            writeln!(writer, "{}", serde_json::to_string(&response).unwrap()).unwrap();
            assert!(matches!(response, HandshakeResponse::Accepted { .. }));
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                continue;
            }
            let index = recorded.lock().unwrap().len();
            recorded.lock().unwrap().push(line.trim().to_owned());
            let reply = answer(index, line.trim());
            if !reply.is_empty() {
                match writeln!(writer, "{reply}") {
                    Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
                    written => written.unwrap(),
                }
            }
        }
    });
    (worker, seen)
}

/// A full listing: every request at its bounds, so the line is far past a lifecycle line.
fn large_pending() -> Vec<PendingAction> {
    (1..=4)
        .map(|action| {
            PendingAction::new(
                action,
                ActionRequest::new(
                    ActionId::new(format!("req-{action}")).unwrap(),
                    ActionKind::Approval,
                    "deploy",
                    "\u{1}".repeat(MAX_ACTION_DETAIL_BYTES),
                )
                .unwrap(),
                1_000,
            )
            .unwrap()
        })
        .collect()
}

fn listing_line(binding: TaskBinding, pending: Vec<PendingAction>) -> String {
    serde_json::to_string(
        &context()
            .actions_listed(binding, TaskLifecycleState::Running, pending)
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn a_listing_larger_than_a_lifecycle_line_is_read_within_its_own_bound() {
    let (_dir, socket) = socket_path();
    let pending = large_pending();
    let line = listing_line(binding(), pending.clone());
    assert!(line.len() > MAX_LINE_BYTES, "{}", line.len());
    let (worker, seen) = fake_node(&socket, 2, move |_, _| line.clone());
    let client = Client::connect(transport(&socket)).unwrap();
    assert_eq!(
        client.actions(binding()).unwrap(),
        ActionsListed::Actions {
            state: TaskLifecycleState::Running,
            pending,
        }
    );
    worker.join().unwrap();
    let sent: Value = serde_json::from_str(&seen.lock().unwrap()[0]).unwrap();
    assert_eq!(sent["request"], "actions");
    assert_eq!(sent["protocol"], json!({"major": 1, "minor": 3}));
    assert!(sent.get("operation_id").is_none());
}

#[test]
fn a_refused_listing_is_typed_and_a_mismatched_or_malformed_one_is_refused() {
    let (_dir, socket) = socket_path();
    let (worker, _) = fake_node(&socket, 5, |index, _| match index {
        0 => serde_json::to_string(&context().actions_rejected(
            None,
            binding(),
            ActionRejectionReason::UnsupportedOperation,
        ))
        .unwrap(),
        1 => listing_line(other_binding(), Vec::new()),
        2 => serde_json::to_string(&context().actions_rejected(
            Some(op(1)),
            binding(),
            ActionRejectionReason::TaskNotFound,
        ))
        .unwrap(),
        _ => r#"{"response":"actions"}"#.to_owned(),
    });
    let client = Client::connect(transport(&socket)).unwrap();
    assert_eq!(
        client.actions(binding()).unwrap(),
        ActionsListed::Rejected {
            reason: ActionRejectionReason::UnsupportedOperation
        }
    );
    for _ in 0..2 {
        assert!(matches!(
            client.actions(binding()),
            Err(ClientError::ResponseMismatch {
                verb: Verb::Actions
            })
        ));
    }
    assert!(matches!(
        client.actions(binding()),
        Err(ClientError::MalformedResponse {
            verb: Verb::Actions
        })
    ));
    worker.join().unwrap();
}

#[test]
fn an_answer_is_checked_against_its_operation_binding_and_request() {
    let (_dir, socket) = socket_path();
    let answered = |operation, binding, action, decision| {
        serde_json::to_string(&context().answered(operation, binding, action, decision)).unwrap()
    };
    let (worker, seen) = fake_node(&socket, 7, move |index, _| match index {
        0 => answered(op(5), binding(), 1, ActionDecision::Approved),
        1 => serde_json::to_string(&context().actions_rejected(
            Some(op(6)),
            binding(),
            ActionRejectionReason::AlreadyAnswered,
        ))
        .unwrap(),
        2 => answered(op(99), binding(), 1, ActionDecision::Approved),
        3 => answered(op(7), other_binding(), 1, ActionDecision::Approved),
        4 => answered(op(8), binding(), 2, ActionDecision::Approved),
        _ => String::new(),
    });
    let client = Client::connect(transport(&socket)).unwrap();
    let note = ActionNote::new("ship it").unwrap();
    assert_eq!(
        client
            .answer(binding(), op(5), 1, ActionDecision::Approved, Some(note))
            .unwrap(),
        AnswerApplied::Answered {
            action: 1,
            decision: ActionDecision::Approved
        }
    );
    assert_eq!(
        client
            .answer(binding(), op(6), 1, ActionDecision::Denied, None)
            .unwrap(),
        AnswerApplied::Rejected {
            reason: ActionRejectionReason::AlreadyAnswered
        }
    );
    for (operation, action) in [(op(6), 1), (op(7), 1), (op(8), 1)] {
        assert!(matches!(
            client.answer(binding(), operation, action, ActionDecision::Approved, None),
            Err(ClientError::ResponseMismatch { verb: Verb::Answer })
        ));
    }
    assert!(matches!(
        client.answer(binding(), op(9), 1, ActionDecision::Approved, None),
        Err(ClientError::NoResponse { verb: Verb::Answer })
    ));
    for decision in [ActionDecision::Expired, ActionDecision::Cancelled] {
        assert!(matches!(
            client.answer(binding(), op(10), 1, decision, None),
            Err(ClientError::Encoding)
        ));
    }
    assert!(matches!(
        client.answer(binding(), op(10), 0, ActionDecision::Approved, None),
        Err(ClientError::Encoding)
    ));
    worker.join().unwrap();
    let first: Value = serde_json::from_str(&seen.lock().unwrap()[0]).unwrap();
    assert_eq!(first["request"], "answer");
    assert_eq!(first["operation_id"], 5);
    assert_eq!(first["action"], 1);
    assert_eq!(first["decision"], "approved");
    assert_eq!(first["note"], "ship it");
    assert_eq!(seen.lock().unwrap().len(), 6, "nothing invalid was sent");
}

fn adapter(socket: &Path, commands: &[Value]) -> (Vec<Value>, bool) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ward-node-adapter"))
        .arg("--socket")
        .arg(socket)
        .arg("--timeout-ms")
        .arg("5000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for command in commands {
            writeln!(stdin, "{command}").unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    let events = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (events, output.status.success())
}

#[test]
fn the_adapter_lists_and_answers_as_events() {
    let (_dir, socket) = socket_path();
    let small = vec![
        PendingAction::new(
            1,
            ActionRequest::new(
                ActionId::new("deploy-1").unwrap(),
                ActionKind::Approval,
                "deploy to staging",
                "3 services",
            )
            .unwrap(),
            29_000,
        )
        .unwrap(),
    ];
    let listing = listing_line(binding(), small);
    // Each command connects once for the handshake and once for its request.
    let (worker, seen) = fake_node(&socket, 8, move |index, _| match index {
        0 => listing.clone(),
        1 => serde_json::to_string(&context().answered(
            op(4),
            binding(),
            1,
            ActionDecision::Approved,
        ))
        .unwrap(),
        2 => serde_json::to_string(&context().actions_rejected(
            Some(op(5)),
            binding(),
            ActionRejectionReason::UnknownRequest,
        ))
        .unwrap(),
        _ => serde_json::to_string(&context().actions_rejected(
            None,
            binding(),
            ActionRejectionReason::UnsupportedOperation,
        ))
        .unwrap(),
    });
    let binding_json = serde_json::to_value(binding()).unwrap();
    let (events, clean) = adapter(
        &socket,
        &[
            json!({"cmd": "actions", "binding": binding_json}),
            json!({"cmd": "answer", "binding": binding_json, "request": 1, "decision": "approved", "operation_id": 4, "note": "go"}),
            json!({"cmd": "answer", "binding": binding_json, "request": 9, "decision": "denied", "operation_id": 5}),
            json!({"cmd": "actions", "binding": binding_json}),
        ],
    );
    worker.join().unwrap();
    assert!(clean, "{events:?}");
    assert_eq!(events.len(), 4, "{events:?}");
    assert!(events.iter().all(|event| event["schema"] == 1));
    assert_eq!(events[0]["event"], "actions");
    assert_eq!(events[0]["state"], "running");
    assert_eq!(events[0]["pending"][0]["action"], 1);
    assert_eq!(events[0]["pending"][0]["id"], "deploy-1");
    assert_eq!(events[0]["pending"][0]["summary"], "deploy to staging");
    assert_eq!(
        events[1],
        json!({"schema": 1, "event": "answered", "operation_id": 4, "request": 1, "decision": "approved"})
    );
    assert_eq!(
        events[2],
        json!({"schema": 1, "event": "rejected", "verb": "answer", "operation_id": 5, "reason": "unknown_request"})
    );
    assert_eq!(
        events[3],
        json!({"schema": 1, "event": "rejected", "verb": "actions", "operation_id": null, "reason": "unsupported_operation"})
    );
    let sent: Value = serde_json::from_str(&seen.lock().unwrap()[1]).unwrap();
    assert_eq!(sent["note"], "go");
}

#[test]
fn the_adapter_refuses_a_malformed_answer_without_contacting_the_node() {
    let (_dir, socket) = socket_path();
    let binding_json = serde_json::to_value(binding()).unwrap();
    let (events, clean) = adapter(
        &socket,
        &[
            json!({"cmd": "answer", "binding": binding_json, "request": 1, "decision": "expired", "operation_id": 4}),
            json!({"cmd": "answer", "binding": binding_json, "request": 1, "decision": "approved"}),
            json!({"cmd": "actions", "binding": binding_json, "extra": true}),
        ],
    );
    assert!(!clean);
    assert_eq!(events.len(), 3, "{events:?}");
    assert!(
        events.iter().all(|event| event["event"] == "error"),
        "{events:?}"
    );
}
