//! Framing, handshake and response checks of the client over a scripted socket peer
//! (node-integration.md §3, §4, §10).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::Duration;

use ward_events::{ExecutionAttemptId, LeaseId, TaskId};
use ward_node_client::{
    Applied, Client, ClientError, MAX_LINE_BYTES, Timeouts, Transport, TransportError,
    UnixTransport, Verb, protocol_window,
};
use ward_node_protocol::{
    HandshakeRequest, HandshakeResponse, OperationId, ProtocolRejectionReason, ProtocolVersion,
    SupportedProtocolRange, TASK_ADMISSION_PROTOCOL, TaskBinding, TaskLifecycleContext,
    TaskLifecycleRequest, TaskLifecycleState, WARD_NODE_PROTOCOL, negotiate,
};

fn hello() -> String {
    serde_json::to_string(&HandshakeRequest::Hello {
        protocol: protocol_window(),
    })
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

fn socket_path() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sock");
    (dir, path)
}

fn fake_node(
    socket: &Path,
    connections: usize,
    handler: impl Fn(usize, UnixStream) + Send + 'static,
) -> JoinHandle<()> {
    let listener = UnixListener::bind(socket).unwrap();
    std::thread::spawn(move || {
        for index in 0..connections {
            let (stream, _) = listener.accept().unwrap();
            handler(index, stream);
        }
    })
}

fn read_line(stream: &mut BufReader<UnixStream>) -> String {
    let mut line = String::new();
    stream.read_line(&mut line).unwrap();
    line.trim_end().to_owned()
}

fn negotiated(stream: UnixStream, range: SupportedProtocolRange) -> Option<BufReader<UnixStream>> {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let peer = match serde_json::from_str::<HandshakeRequest>(&read_line(&mut reader)).unwrap() {
        HandshakeRequest::Hello { protocol } => protocol,
    };
    let response = negotiate(range, peer);
    let mut writer = stream;
    writeln!(writer, "{}", serde_json::to_string(&response).unwrap()).unwrap();
    matches!(response, HandshakeResponse::Accepted { .. }).then_some(reader)
}

fn request_line(reader: &mut BufReader<UnixStream>) -> Option<String> {
    let line = read_line(reader);
    (!line.is_empty()).then_some(line)
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

fn lifecycle_node(socket: &Path, connections: usize) -> JoinHandle<()> {
    fake_node(socket, connections, |_, stream| {
        if let Some(mut reader) = negotiated(stream, WARD_NODE_PROTOCOL) {
            let Some(line) = request_line(&mut reader) else {
                return;
            };
            let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
            let request = context.decode_request(&line).unwrap();
            let response = match request {
                TaskLifecycleRequest::Create {
                    operation_id,
                    binding,
                    ..
                } => context.accepted(operation_id, binding, TaskLifecycleState::Created),
                other => panic!("unexpected {other:?}"),
            };
            let mut writer = reader.into_inner();
            writeln!(writer, "{}", serde_json::to_string(&response).unwrap()).unwrap();
        }
    })
}

#[test]
fn a_request_over_the_line_bound_is_refused_before_connecting() {
    let (_dir, socket) = socket_path();
    let transport = transport(&socket);
    let hello = hello();
    assert!(matches!(
        transport.exchange(&hello, &"x".repeat(MAX_LINE_BYTES + 1)),
        Err(TransportError::RequestTooLarge)
    ));
    assert!(matches!(
        transport.exchange(&hello, &"x".repeat(MAX_LINE_BYTES)),
        Err(TransportError::Connect(_))
    ));
    assert_eq!(MAX_LINE_BYTES, 64 * 1024);
}

#[test]
fn eof_before_the_handshake_answer_fails_closed() {
    let (_dir, socket) = socket_path();
    let node = fake_node(&socket, 2, |_, stream| drop(stream));
    let transport = transport(&socket);
    assert!(matches!(
        transport.handshake(&hello()),
        Err(TransportError::ClosedWithoutResponse)
    ));
    assert!(matches!(
        transport.exchange(&hello(), "{}"),
        Err(TransportError::ClosedWithoutResponse)
    ));
    node.join().unwrap();
}

#[test]
fn eof_after_the_handshake_is_no_response_for_the_request() {
    let (_dir, socket) = socket_path();
    let node = fake_node(&socket, 2, |_, stream| {
        let reader = negotiated(stream, WARD_NODE_PROTOCOL).unwrap();
        drop(reader);
    });
    let client = Client::connect(transport(&socket)).unwrap();
    assert!(matches!(
        client.create(binding(), op(1)),
        Err(ClientError::NoResponse { verb: Verb::Create })
    ));
    node.join().unwrap();
}

#[test]
fn a_truncated_or_oversized_response_fails_closed() {
    let (_dir, socket) = socket_path();
    let node = fake_node(&socket, 2, |index, stream| {
        let reader = negotiated(stream, WARD_NODE_PROTOCOL).unwrap();
        let mut writer = reader.into_inner();
        if index == 0 {
            writer.write_all(br#"{"response":"accepted""#).unwrap();
        } else {
            writer.write_all(&vec![b'x'; MAX_LINE_BYTES + 1]).unwrap();
            writer.write_all(b"\n").unwrap();
        }
    });
    let transport = transport(&socket);
    assert!(matches!(
        transport.exchange(&hello(), "{}"),
        Err(TransportError::TruncatedResponse)
    ));
    assert!(matches!(
        transport.exchange(&hello(), "{}"),
        Err(TransportError::ResponseTooLong)
    ));
    node.join().unwrap();
}

#[test]
fn a_silent_node_times_out() {
    let (_dir, socket) = socket_path();
    let node = fake_node(&socket, 1, |_, mut stream| {
        let mut byte = [0_u8; 1];
        let _ = stream.read(&mut byte);
        std::thread::sleep(Duration::from_millis(600));
    });
    let transport = UnixTransport::new(
        &socket,
        Timeouts {
            connect: Duration::from_millis(200),
            request: Duration::from_millis(200),
        },
    );
    assert!(matches!(
        transport.handshake(&hello()),
        Err(TransportError::TimedOut)
    ));
    node.join().unwrap();
}

#[test]
fn a_carriage_return_before_the_newline_is_tolerated() {
    let (_dir, socket) = socket_path();
    let node = fake_node(&socket, 1, |_, stream| {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        read_line(&mut reader);
        let mut writer = stream;
        writer
            .write_all(br#"{"response":"accepted","protocol":{"major":1,"minor":3}}"#)
            .unwrap();
        writer.write_all(b"\r\n").unwrap();
    });
    let line = transport(&socket).handshake(&hello()).unwrap();
    assert_eq!(
        serde_json::from_str::<HandshakeResponse>(&line).unwrap(),
        HandshakeResponse::Accepted {
            protocol: ProtocolVersion::new(1, 3)
        }
    );
    node.join().unwrap();
}

#[test]
fn the_client_lands_on_1_3_against_todays_node() {
    assert_eq!(protocol_window().major(), 1);
    assert_eq!(
        protocol_window().min_minor(),
        TASK_ADMISSION_PROTOCOL.minor()
    );
    assert_eq!(
        protocol_window().max_minor(),
        WARD_NODE_PROTOCOL.max_minor()
    );
    let (_dir, socket) = socket_path();
    let node = lifecycle_node(&socket, 2);
    let client = Client::connect(transport(&socket)).unwrap();
    assert_eq!(client.protocol(), ProtocolVersion::new(1, 3));
    assert_eq!(
        client.create(binding(), op(1)).unwrap(),
        Applied::Accepted {
            state: TaskLifecycleState::Created
        }
    );
    node.join().unwrap();
}

#[test]
fn a_node_without_1_3_is_refused_at_the_handshake() {
    let (_dir, socket) = socket_path();
    let node = fake_node(&socket, 1, |_, stream| {
        assert!(negotiated(stream, SupportedProtocolRange::new(1, 0, 2).unwrap()).is_none());
    });
    match Client::connect(transport(&socket)) {
        Err(ClientError::HandshakeRejected { reason, supported }) => {
            assert_eq!(reason, ProtocolRejectionReason::NoCommonMinor);
            assert_eq!(supported, SupportedProtocolRange::new(1, 0, 2).unwrap());
        }
        other => panic!("expected a handshake rejection, got {other:?}"),
    }
    node.join().unwrap();
}

#[test]
fn a_node_accepting_below_1_3_or_changing_its_answer_is_refused() {
    let (_dir, socket) = socket_path();
    let node = fake_node(&socket, 3, |index, stream| {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        read_line(&mut reader);
        let minor = if index == 0 {
            2
        } else {
            3 + u16::from(index == 2)
        };
        let mut writer = stream;
        writeln!(
            writer,
            r#"{{"response":"accepted","protocol":{{"major":1,"minor":{minor}}}}}"#
        )
        .unwrap();
        if index == 2 {
            read_line(&mut reader);
        }
    });
    assert!(matches!(
        Client::connect(transport(&socket)),
        Err(ClientError::ProtocolTooOld { accepted }) if accepted == ProtocolVersion::new(1, 2)
    ));
    let client = Client::connect(transport(&socket)).unwrap();
    assert!(matches!(
        client.create(binding(), op(1)),
        Err(ClientError::ProtocolChanged { expected, accepted })
            if expected == ProtocolVersion::new(1, 3) && accepted == ProtocolVersion::new(1, 4)
    ));
    node.join().unwrap();
}

#[test]
fn a_response_for_another_operation_or_binding_is_refused() {
    let (_dir, socket) = socket_path();
    let node = fake_node(&socket, 3, |index, stream| {
        if let Some(mut reader) = negotiated(stream, WARD_NODE_PROTOCOL) {
            if request_line(&mut reader).is_none() {
                return;
            }
            let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
            let other = TaskBinding::new(
                TaskId::from_u128(70),
                ExecutionAttemptId::from_u128(8),
                LeaseId::from_u128(9),
            );
            let response = if index == 1 {
                context.accepted(op(2), binding(), TaskLifecycleState::Created)
            } else {
                context.accepted(op(1), other, TaskLifecycleState::Created)
            };
            let mut writer = reader.into_inner();
            writeln!(writer, "{}", serde_json::to_string(&response).unwrap()).unwrap();
        }
    });
    let client = Client::connect(transport(&socket)).unwrap();
    assert!(matches!(
        client.create(binding(), op(1)),
        Err(ClientError::ResponseMismatch { verb: Verb::Create })
    ));
    assert!(matches!(
        client.create(binding(), op(1)),
        Err(ClientError::ResponseMismatch { verb: Verb::Create })
    ));
    node.join().unwrap();
}

#[test]
fn a_malformed_response_line_is_refused() {
    let (_dir, socket) = socket_path();
    let node = fake_node(&socket, 2, |_, stream| {
        if let Some(mut reader) = negotiated(stream, WARD_NODE_PROTOCOL) {
            if request_line(&mut reader).is_none() {
                return;
            }
            let mut writer = reader.into_inner();
            writeln!(writer, r#"{{"response":"accepted","state":"created"}}"#).unwrap();
        }
    });
    let client = Client::connect(transport(&socket)).unwrap();
    assert!(matches!(
        client.inspect(binding()),
        Err(ClientError::MalformedResponse {
            verb: Verb::Inspect
        })
    ));
    node.join().unwrap();
}
