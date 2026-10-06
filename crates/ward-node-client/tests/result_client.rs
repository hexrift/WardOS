//! The client's `result` request and the driver's result read over a scripted socket peer
//! (node-integration.md §6.6, §11): a result answer is read within its own, larger bound
//! and decoded strictly, a refusal is typed, an answer for another binding is refused, the
//! driver asks for the result only when the envelope's manifest granted output, and a
//! refused result leaves the receipt as it was.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::{
    AgentId, Blake3Hash, DelegationId, ExecutionAttemptId, LeaseId, NodeId, PrincipalId, SessionId,
    SnapshotId, TaskId,
};
use ward_node_client::{
    AttemptEvent, AttemptOutcome, AttemptRequest, CancelToken, Client, ClientError, Driver,
    EnvelopeInput, IssuerKey, MAX_LINE_BYTES, OperationIds, Resulted, RunConfig, Timeouts,
    TransportError, UnixTransport, Verb, WorkloadInput,
};
use ward_node_protocol::{
    AttemptOutput, CapabilityManifestBytes, HandshakeRequest, HandshakeResponse,
    MAX_RESULT_RESPONSE_BYTES, OutputFile, OutputFileSkip, OutputFileStatus, OutputPath,
    OutputStream, ProtocolVersion, TaskAdmissionAuthority, TaskBinding, TaskExecutionOutcome,
    TaskLifecycleContext, TaskLifecycleRejectionReason, TaskLifecycleRequest, TaskLifecycleState,
    WARD_NODE_PROTOCOL, negotiate,
};

fn binding() -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(7),
        ExecutionAttemptId::from_u128(8),
        LeaseId::from_u128(9),
    )
}

fn context() -> TaskLifecycleContext {
    TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
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

/// What a scripted node saw on one connection: the request's `request` field and line.
#[derive(Clone, Debug)]
struct Seen {
    verb: String,
    line: String,
}

/// A scripted node: negotiates the window, then answers each request line with what
/// `answer` returns for it (a raw line), recording every request it saw. `answer`'s index
/// counts requests, not connections: the client's handshake-only connection is not one.
fn fake_node(
    socket: &Path,
    connections: usize,
    answer: impl Fn(usize, &Seen) -> String + Send + 'static,
) -> (JoinHandle<()>, Arc<Mutex<Vec<Seen>>>) {
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
            let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
            let seen_request = Seen {
                verb: value["request"].as_str().unwrap().to_owned(),
                line: line.trim().to_owned(),
            };
            let index = recorded.lock().unwrap().len();
            recorded.lock().unwrap().push(seen_request.clone());
            let reply = answer(index, &seen_request);
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

fn large_output(stdout_len: usize) -> AttemptOutput {
    AttemptOutput::new(
        OutputStream::new(vec![b'o'; stdout_len], 5).unwrap(),
        OutputStream::new(b"warn".to_vec(), 0).unwrap(),
        vec![
            OutputFile {
                path: OutputPath::new("out/report.json").unwrap(),
                status: OutputFileStatus::Returned {
                    size: 2,
                    digest: Blake3Hash::hash(b"{}"),
                    content: b"{}".to_vec(),
                },
            },
            OutputFile {
                path: OutputPath::new("missing").unwrap(),
                status: OutputFileStatus::Skipped(OutputFileSkip::Missing),
            },
        ],
    )
    .unwrap()
}

fn result_line(output: &AttemptOutput, state: TaskLifecycleState) -> String {
    serde_json::to_string(
        &context()
            .result_response(binding(), state, output.clone())
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn a_result_answer_larger_than_a_lifecycle_line_is_read_within_its_own_bound() {
    let (_dir, socket) = socket_path();
    let output = large_output(3 * MAX_LINE_BYTES);
    let reply = result_line(&output, TaskLifecycleState::Exited);
    assert!(reply.len() > MAX_LINE_BYTES, "the case needs a long answer");
    let (node, seen) = fake_node(&socket, 4, move |index, seen| {
        assert_eq!(seen.verb, "result");
        match index {
            1 => reply.clone(),
            2 => {
                let mut padded = reply.clone();
                let filler = MAX_RESULT_RESPONSE_BYTES + 1 - padded.len();
                padded.truncate(padded.len() - 1);
                padded.push_str(&" ".repeat(filler));
                padded.push('}');
                padded
            }
            _ => String::new(),
        }
    });
    let client = Client::connect(transport(&socket)).unwrap();
    assert!(matches!(
        client.result(binding()),
        Err(ClientError::NoResponse { verb: Verb::Result })
    ));
    assert_eq!(
        client.result(binding()).unwrap(),
        Resulted::Result {
            state: TaskLifecycleState::Exited,
            output: output.clone(),
        }
    );
    assert!(matches!(
        client.result(binding()),
        Err(ClientError::Transport(TransportError::ResponseTooLong))
    ));
    node.join().unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&seen[0].line).unwrap(),
        serde_json::json!({
            "request": "result",
            "protocol": {"major": 1, "minor": 3},
            "binding": binding(),
        })
    );
}

#[test]
fn a_refused_result_is_typed_and_a_mismatched_or_malformed_answer_is_refused() {
    let (_dir, socket) = socket_path();
    let other = TaskBinding::new(
        TaskId::from_u128(70),
        ExecutionAttemptId::from_u128(8),
        LeaseId::from_u128(9),
    );
    let (node, _) = fake_node(&socket, 5, move |index, _| match index {
        0 => serde_json::to_string(
            &context()
                .result_rejected(binding(), TaskLifecycleRejectionReason::ResourceUnavailable),
        )
        .unwrap(),
        1 => serde_json::to_string(
            &context()
                .result_response(other, TaskLifecycleState::Sealed, AttemptOutput::default())
                .unwrap(),
        )
        .unwrap(),
        2 => serde_json::to_string(&context().inspected(binding(), TaskLifecycleState::Exited))
            .unwrap(),
        _ => result_line(&AttemptOutput::default(), TaskLifecycleState::Exited)
            .replace(r#""state":"exited""#, r#""state":"running""#),
    });
    let client = Client::connect(transport(&socket)).unwrap();
    assert_eq!(
        client.result(binding()).unwrap(),
        Resulted::Rejected {
            reason: TaskLifecycleRejectionReason::ResourceUnavailable
        }
    );
    assert!(matches!(
        client.result(binding()),
        Err(ClientError::ResponseMismatch { verb: Verb::Result })
    ));
    assert!(matches!(
        client.result(binding()),
        Err(ClientError::MalformedResponse { verb: Verb::Result })
    ));
    assert!(matches!(
        client.result(binding()),
        Err(ClientError::MalformedResponse { verb: Verb::Result })
    ));
    node.join().unwrap();
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

fn request_with(manifest: Option<CapabilityManifestBytes>) -> AttemptRequest {
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
    let input = EnvelopeInput {
        binding,
        agent: AgentId::from_u128(3),
        node: NodeId::from_u128(4),
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new())
            .unwrap(),
        workload: WorkloadInput {
            argv: vec!["true".to_owned()],
            capability_manifest: manifest,
            snapshot: SnapshotId::new(Blake3Hash::hash(b"snapshot")),
            wall_clock_budget_ms: 10_000,
        },
        issued_at_unix_ms: now - 60_000,
        expires_at_unix_ms: now + 600_000,
        version: 1,
    };
    AttemptRequest::sign(
        &input.build().unwrap(),
        &IssuerKey::from_seed([7; 32]).unwrap(),
        None,
    )
    .unwrap()
}

fn output_manifest() -> CapabilityManifestBytes {
    CapabilityManifestBytes::new(
        br#"{"network":"offline","output":{"stdio_bytes":4096,"files":["out/report.json","missing"],"files_bytes":1024}}"#.to_vec(),
    )
    .unwrap()
}

/// A node that runs the attempt through to `exited`/`completed`, seals it and answers
/// `result` with `result_reply`.
fn completing_node(
    socket: &Path,
    connections: usize,
    result_reply: String,
) -> (JoinHandle<()>, Arc<Mutex<Vec<Seen>>>) {
    fake_node(socket, connections, move |_, seen| {
        let context = context();
        if seen.verb == "result" {
            return result_reply.clone();
        }
        let request = context.decode_request(&seen.line).unwrap();
        let response = match request {
            TaskLifecycleRequest::Create { operation_id, .. } => {
                context.accepted(operation_id, binding(), TaskLifecycleState::Created)
            }
            TaskLifecycleRequest::Admit { operation_id, .. } => {
                context.accepted(operation_id, binding(), TaskLifecycleState::Ready)
            }
            TaskLifecycleRequest::Start { operation_id, .. } => {
                context.accepted(operation_id, binding(), TaskLifecycleState::Running)
            }
            TaskLifecycleRequest::Inspect { .. } => context
                .inspected_with_outcome(
                    binding(),
                    TaskLifecycleState::Exited,
                    TaskExecutionOutcome::Completed,
                )
                .unwrap(),
            TaskLifecycleRequest::Seal { operation_id, .. } => {
                context.accepted(operation_id, binding(), TaskLifecycleState::Sealed)
            }
            other => panic!("unexpected {other:?}"),
        };
        serde_json::to_string(&response).unwrap()
    })
}

fn config() -> RunConfig {
    RunConfig {
        poll_interval: Duration::from_millis(10),
        max_poll_interval: Duration::from_millis(20),
        grace: Duration::from_secs(5),
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_driver_reads_the_result_after_sealing_only_when_the_manifest_granted_output() {
    let (_dir, socket) = socket_path();
    let output = large_output(100);
    let (node, seen) =
        completing_node(&socket, 7, result_line(&output, TaskLifecycleState::Sealed));
    let client = Client::connect(transport(&socket)).unwrap();
    let mut events = Vec::new();
    let report = Driver::new(&client, config()).run_attempt(
        &request_with(Some(output_manifest())),
        &OperationIds::default(),
        &CancelToken::default(),
        &mut |event| events.push(event.clone()),
    );
    node.join().unwrap();
    let verbs: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|seen| seen.verb.clone())
        .collect();
    assert_eq!(
        verbs,
        ["create", "admit", "start", "inspect", "seal", "result"],
        "the result is read once, after the seal"
    );
    assert_eq!(report.outcome, AttemptOutcome::Completed);
    assert!(report.sealed);
    assert_eq!(report.output.as_ref(), Some(&output));
    assert!(events.contains(&AttemptEvent::Output {
        stdout_bytes: 100,
        stderr_bytes: 4,
        files: 2,
        truncated: true,
    }));
    let text = serde_json::to_string(&report).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["output"]["stdout"]["dropped"], 5);
    assert_eq!(json["output"]["files"][1]["skipped"], "missing");
    let back: ward_node_client::AttemptReport = serde_json::from_str(&text).unwrap();
    assert_eq!(back, report);

    // Without an output grant the driver never asks.
    let (_dir, socket) = socket_path();
    let (node, seen) = completing_node(&socket, 6, String::new());
    let client = Client::connect(transport(&socket)).unwrap();
    let report = Driver::new(&client, config()).run_attempt(
        &request_with(None),
        &OperationIds::default(),
        &CancelToken::default(),
        &mut |_| {},
    );
    node.join().unwrap();
    let verbs: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|seen| seen.verb.clone())
        .collect();
    assert_eq!(verbs, ["create", "admit", "start", "inspect", "seal"]);
    assert_eq!(report.output, None);
    assert_eq!(report.outcome, AttemptOutcome::Completed);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["output"], serde_json::Value::Null);

    // A refused result is recorded and leaves the receipt as it was.
    let (_dir, socket) = socket_path();
    let (node, _) = completing_node(
        &socket,
        7,
        serde_json::to_string(
            &context()
                .result_rejected(binding(), TaskLifecycleRejectionReason::ResourceUnavailable),
        )
        .unwrap(),
    );
    let client = Client::connect(transport(&socket)).unwrap();
    let mut events = Vec::new();
    let report = Driver::new(&client, config()).run_attempt(
        &request_with(Some(output_manifest())),
        &OperationIds::default(),
        &CancelToken::default(),
        &mut |event| events.push(event.clone()),
    );
    node.join().unwrap();
    assert_eq!(report.outcome, AttemptOutcome::Completed);
    assert!(report.outcome_certain);
    assert_eq!(report.output, None);
    assert!(events.contains(&AttemptEvent::Rejected {
        verb: Verb::Result,
        operation_id: None,
        reason: TaskLifecycleRejectionReason::ResourceUnavailable,
    }));

    // A result answer that never arrives is a lost answer: recovered once, then unknown.
    let (_dir, socket) = socket_path();
    let (node, seen) = completing_node(&socket, 8, String::new());
    let client = Client::connect(transport(&socket)).unwrap();
    let report = Driver::new(&client, config()).run_attempt(
        &request_with(Some(output_manifest())),
        &OperationIds::default(),
        &CancelToken::default(),
        &mut |_| {},
    );
    node.join().unwrap();
    let verbs: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|seen| seen.verb.clone())
        .collect();
    assert_eq!(
        verbs,
        [
            "create", "admit", "start", "inspect", "seal", "result", "result"
        ]
    );
    assert_eq!(report.outcome, AttemptOutcome::Unknown);
    assert!(!report.outcome_certain);
    assert!(report.transport_error.is_some());
    assert_eq!(report.receipt, Some(TaskExecutionOutcome::Completed));
    assert_eq!(report.output, None);
}
