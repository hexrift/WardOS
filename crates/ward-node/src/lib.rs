//! Local ward-node service.
//!
//! The service negotiates the node protocol, then serves exactly one request per
//! connection:
//!
//! * at protocol 1.1, read-only node capability discovery;
//! * at protocol 1.2, read-only discovery or one task lifecycle request against
//!   the node-owned [`task::TaskRegistry`]. Only `create` and `inspect` are
//!   implemented; every other verb is refused explicitly (see [`task`]);
//! * at protocol 1.3, the same, plus the `admit` verb. A service built with
//!   [`NodeService::with_admission`] verifies the signed envelope against its trusted
//!   issuers, its node id, its clock and its durable state, and moves the task
//!   `Created → Ready` (see [`admit`]); it then advertises `admit` in 1.3 capability
//!   discovery. Without admission, `admit` is refused as unsupported.
//! * at protocol 1.3, a service built with [`NodeService::with_execution`] also starts,
//!   pauses, resumes, stops, revokes and seals admitted tasks in an offline sandbox over a
//!   node-allocated workspace, reaps them on a node-owned thread and records `exited` with
//!   a receipt (see [`task`] and [`execution`]). It advertises `start`, `stop`, `pause`
//!   and `revoke` together in 1.3 capability discovery (`resume` comes with `pause` and
//!   `seal` with execution; the document has no flag for either); any other 1.3 node
//!   advertises none of them. 1.1 and 1.2 documents are unchanged, and a 1.2 connection is
//!   refused every one of these verbs as unsupported.
//!   Only such a node also advertises, at 1.3, the isolation its execution enforces: the
//!   namespace sandbox and its user namespace, the offline network and the
//!   content-addressed snapshot store.
//!
//! A connection's request (handshake and request line) must arrive within
//! [`REQUEST_TIMEOUT`]; its answer is written within [`ANSWER_TIMEOUT`] of being ready, so
//! a `stop` or `start` whose bounded work outlasts the request deadline is still answered.
//!
//! `stream` stays unsupported, and remote transport is deliberately absent. Serving a
//! lifecycle request never waits on a running workload.

#![forbid(unsafe_code)]

pub mod admission;
pub mod admit;
pub mod execution;
pub mod issuer;
pub mod state;
pub mod task;
#[cfg(test)]
mod test_support;
pub mod workspace;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use thiserror::Error;
use ward_node_protocol::{
    CapabilityDiscoveryContext, HandshakeRequest, HandshakeResponse, LifecycleCapabilities,
    NamespaceCapabilities, NodeCapabilities, SupportedProtocolRange, TaskLifecycleContext,
    WARD_NODE_PROTOCOL, negotiate, supports_task_admission, supports_task_lifecycle,
};

use crate::admit::NodeAdmission;
use crate::execution::NodeExecution;
use crate::task::{MAX_NODE_TASKS, TaskRegistry};

/// Maximum bytes in one node-protocol JSON request, excluding the terminating newline.
pub const MAX_REQUEST_LINE_BYTES: usize = 64 * 1024;

/// Absolute bound, from accept, on reading one request: the handshake line, the
/// handshake answer and the request line must all complete within it. Partial progress
/// never extends it, so a slow or idle client cannot hold the single-threaded server for
/// longer.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on writing a request's answer, counted from the moment the answer is ready.
///
/// The work a verb does between reading its request and answering is bounded by the
/// verb itself, not by [`REQUEST_TIMEOUT`]: `stop` waits at most its stop timeout
/// ([`execution::DEFAULT_STOP_TIMEOUT`]) and `start` materialises a size-bounded snapshot
/// and then waits at most its spawn timeout ([`execution::DEFAULT_SPAWN_TIMEOUT`]); every
/// other verb answers at once. A verb that takes longer than [`REQUEST_TIMEOUT`] is
/// therefore still answered.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);

/// Local ward-node protocol failure.
#[derive(Debug, Error)]
pub enum NodeServiceError {
    /// Local socket I/O failed.
    #[error("ward-node I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// First request was not a valid handshake.
    #[error("ward-node handshake is invalid")]
    MalformedHandshake,
    /// Capability request did not satisfy the negotiated protocol context.
    #[error("ward-node capability request is invalid")]
    MalformedCapabilityRequest,
    /// Task lifecycle request was malformed or not bound to the negotiated protocol.
    #[error("ward-node task lifecycle request is invalid")]
    MalformedLifecycleRequest,
    /// A request exceeded the fixed wire bound.
    #[error("ward-node request exceeds the maximum line size")]
    RequestTooLarge,
    /// The peer closed a connection before the required request arrived.
    #[error("ward-node connection closed before request completed")]
    UnexpectedEof,
    /// Trusted startup capability configuration is invalid for discovery.
    #[error("ward-node capability configuration is invalid")]
    InvalidCapabilities,
    /// JSON response serialization failed.
    #[error("ward-node response serialization failed")]
    Serialization,
    /// Administrative socket parent directory is accessible to another Unix identity.
    #[error("ward-node socket parent directory must be private (mode 0700 or stricter)")]
    InsecureSocketDirectory,
    /// The request was not read within [`REQUEST_TIMEOUT`], or its answer not written
    /// within [`ANSWER_TIMEOUT`].
    #[error("ward-node connection exceeded its deadline")]
    ConnectionDeadlineExceeded,
    /// The node task registry lock was poisoned by an earlier panic.
    #[error("ward-node task registry is unavailable")]
    TaskRegistryUnavailable,
}

/// Local node service for handshake, capability discovery and the task registry.
///
/// Clones share one task registry, so a task created on one connection is visible to
/// every later connection served by any clone.
#[derive(Clone)]
pub struct NodeService {
    capabilities: NodeCapabilities,
    supported: SupportedProtocolRange,
    admits: bool,
    executes: bool,
    tasks: Arc<Mutex<TaskRegistry>>,
}

impl NodeService {
    /// Create a service bound to trusted node-owned capabilities.
    ///
    /// # Errors
    ///
    /// Returns `InvalidCapabilities` if the capability document is not valid for
    /// capability discovery in this build.
    pub fn new(capabilities: NodeCapabilities) -> Result<Self, NodeServiceError> {
        CapabilityDiscoveryContext::new(capabilities.protocol())
            .map_err(|_| NodeServiceError::InvalidCapabilities)?;
        Ok(Self {
            capabilities,
            supported: WARD_NODE_PROTOCOL,
            admits: false,
            executes: false,
            tasks: Arc::new(Mutex::new(TaskRegistry::default())),
        })
    }

    /// Create a service that admits signed envelopes through `admission` (protocol 1.3).
    ///
    /// # Errors
    ///
    /// Returns `InvalidCapabilities` if the capability document is not valid for
    /// capability discovery in this build.
    pub fn with_admission(
        capabilities: NodeCapabilities,
        admission: NodeAdmission,
    ) -> Result<Self, NodeServiceError> {
        CapabilityDiscoveryContext::new(capabilities.protocol())
            .map_err(|_| NodeServiceError::InvalidCapabilities)?;
        Ok(Self {
            capabilities,
            supported: WARD_NODE_PROTOCOL,
            admits: true,
            executes: false,
            tasks: Arc::new(Mutex::new(TaskRegistry::with_admission(
                MAX_NODE_TASKS,
                admission,
            ))),
        })
    }

    /// Create a service that admits signed envelopes through `admission` and executes
    /// admitted tasks through `execution` (protocol 1.3).
    ///
    /// # Errors
    ///
    /// Returns `InvalidCapabilities` if the capability document is not valid for
    /// capability discovery in this build.
    pub fn with_execution(
        capabilities: NodeCapabilities,
        admission: NodeAdmission,
        execution: NodeExecution,
    ) -> Result<Self, NodeServiceError> {
        CapabilityDiscoveryContext::new(capabilities.protocol())
            .map_err(|_| NodeServiceError::InvalidCapabilities)?;
        Ok(Self {
            capabilities,
            supported: WARD_NODE_PROTOCOL,
            admits: true,
            executes: true,
            tasks: Arc::new(Mutex::new(TaskRegistry::with_execution(
                MAX_NODE_TASKS,
                admission,
                execution,
            ))),
        })
    }

    /// Serve exactly one local protocol connection.
    ///
    /// The first request must be a handshake. Rejected handshakes receive a bounded
    /// machine-readable response and close. A connection accepted at the capability
    /// negotiated protocol may issue one read-only capability-discovery request; a
    /// connection accepted at 1.2 or later may instead issue one lifecycle request. The
    /// connection then closes.
    ///
    /// The handshake, its answer and the request line must complete within
    /// [`REQUEST_TIMEOUT`] of the call. The request's answer is then written within
    /// [`ANSWER_TIMEOUT`] of being ready, however long the verb's own bounded work took.
    ///
    /// A lifecycle request is applied to the registry before its response is written, so
    /// a `create` whose client disconnects before reading the response still took effect;
    /// the client recovers by replaying the same operation id or by inspecting.
    ///
    /// # Errors
    ///
    /// Returns an explicit bounded protocol/I/O error. No error path falls back to the
    /// per-session ward-daemon control protocol.
    pub fn serve_connection(&self, stream: UnixStream) -> Result<(), NodeServiceError> {
        self.serve_connection_with_lifetime(stream, REQUEST_TIMEOUT)
    }

    fn serve_connection_with_lifetime(
        &self,
        mut stream: UnixStream,
        request_timeout: Duration,
    ) -> Result<(), NodeServiceError> {
        let deadline = deadline_after(request_timeout)?;

        let reader_stream = stream.try_clone()?;
        let mut reader = BufReader::new(reader_stream);

        let handshake_line = read_request_line(&mut reader, deadline)?;
        let handshake = serde_json::from_str::<HandshakeRequest>(&handshake_line)
            .map_err(|_| NodeServiceError::MalformedHandshake)?;
        let HandshakeRequest::Hello { protocol: peer } = handshake;
        let response = negotiate(self.supported, peer);
        write_json_line(&mut stream, &response, deadline)?;

        let HandshakeResponse::Accepted { protocol } = response else {
            return Ok(());
        };

        if !ward_node_protocol::supports_capability_discovery(protocol) {
            return Ok(());
        }

        let request_line = read_request_line(&mut reader, deadline)?;
        if serde_json::from_str::<serde_json::Value>(&request_line)
            .is_ok_and(|value| value["request"] == "capabilities")
        {
            return self.serve_capabilities(&mut stream, protocol, &request_line);
        }
        if supports_task_lifecycle(protocol) {
            return self.serve_lifecycle(&mut stream, protocol, &request_line);
        }
        Err(NodeServiceError::MalformedCapabilityRequest)
    }

    fn serve_capabilities(
        &self,
        stream: &mut UnixStream,
        protocol: ward_node_protocol::ProtocolVersion,
        request_line: &str,
    ) -> Result<(), NodeServiceError> {
        let context = CapabilityDiscoveryContext::new(protocol)
            .map_err(|_| NodeServiceError::MalformedCapabilityRequest)?;
        context
            .decode_request(request_line)
            .map_err(|_| NodeServiceError::MalformedCapabilityRequest)?;
        let configured = self.capabilities;
        let mut isolation = configured.isolation();
        let mut network = configured.network();
        let mut snapshots = configured.snapshots();
        let lifecycle = if supports_task_admission(protocol) {
            isolation.namespaces = NamespaceCapabilities {
                sandbox: self.executes,
                user_namespace: self.executes,
            };
            network.offline = self.executes;
            snapshots.content_addressed = self.executes;
            LifecycleCapabilities {
                admit: self.admits,
                start: self.executes,
                stop: self.executes,
                pause: self.executes,
                revoke: self.executes,
            }
        } else {
            LifecycleCapabilities {
                admit: false,
                start: false,
                ..configured.lifecycle()
            }
        };
        let capabilities = NodeCapabilities::new(
            protocol,
            configured.architecture(),
            configured.capacity(),
            isolation,
            network,
            configured.credentials(),
            snapshots,
            configured.verifier(),
            lifecycle,
        )
        .map_err(|_| NodeServiceError::InvalidCapabilities)?;
        let response = context
            .response(capabilities)
            .map_err(|_| NodeServiceError::InvalidCapabilities)?;
        write_answer(stream, &response)
    }

    fn serve_lifecycle(
        &self,
        stream: &mut UnixStream,
        protocol: ward_node_protocol::ProtocolVersion,
        request_line: &str,
    ) -> Result<(), NodeServiceError> {
        let context = TaskLifecycleContext::new(protocol)
            .map_err(|_| NodeServiceError::MalformedLifecycleRequest)?;
        let request = context
            .decode_request(request_line)
            .map_err(|_| NodeServiceError::MalformedLifecycleRequest)?;
        let response = TaskRegistry::serve(&self.tasks, context, request)
            .map_err(|_| NodeServiceError::TaskRegistryUnavailable)?;
        write_answer(stream, &response)
    }
}

/// Bind a local ward-node socket and serve connections for `service` indefinitely.
///
/// Connections are handled sequentially in this initial endpoint. That deliberately caps
/// active protocol handlers at one instead of allocating an unbounded thread per client.
/// The socket is created mode 0600 so unprivileged sibling users cannot connect merely
/// because they can name the path. This is a local bootstrap boundary, not the remote
/// authenticated transport tracked by #262.
///
/// # Errors
///
/// Returns if the listener cannot be created/configured. Existing socket paths are never
/// removed automatically.
pub fn serve_local(socket: &Path, service: &NodeService) -> Result<(), NodeServiceError> {
    let listener = bind_local(socket)?;

    for connection in listener.incoming() {
        let stream = connection?;
        let _ = service.serve_connection(stream);
    }

    Ok(())
}

fn bind_local(socket: &Path) -> Result<UnixListener, NodeServiceError> {
    let parent = socket
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = std::fs::metadata(parent)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(NodeServiceError::InsecureSocketDirectory);
    }

    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn read_request_line(
    reader: &mut BufReader<UnixStream>,
    deadline: Instant,
) -> Result<String, NodeServiceError> {
    let mut bytes = Vec::new();

    loop {
        let remaining = remaining_until(deadline)?;
        reader.get_mut().set_read_timeout(Some(remaining))?;

        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if is_timeout(&error) => {
                return Err(NodeServiceError::ConnectionDeadlineExceeded);
            }
            Err(error) => return Err(NodeServiceError::Io(error)),
        };

        if available.is_empty() {
            return if bytes.is_empty() {
                Err(NodeServiceError::UnexpectedEof)
            } else {
                Err(NodeServiceError::MalformedHandshake)
            };
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if bytes.len().saturating_add(take) > MAX_REQUEST_LINE_BYTES + 1 {
            return Err(NodeServiceError::RequestTooLarge);
        }

        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);

        if newline.is_some() {
            break;
        }
    }

    if !bytes.ends_with(b"\n") {
        return Err(NodeServiceError::MalformedHandshake);
    }

    bytes.pop();
    if bytes.ends_with(b"\r") {
        bytes.pop();
    }
    if bytes.len() > MAX_REQUEST_LINE_BYTES {
        return Err(NodeServiceError::RequestTooLarge);
    }

    String::from_utf8(bytes).map_err(|_| NodeServiceError::MalformedHandshake)
}

fn write_json_line(
    writer: &mut UnixStream,
    value: &impl serde::Serialize,
    deadline: Instant,
) -> Result<(), NodeServiceError> {
    let remaining = remaining_until(deadline)?;
    writer.set_write_timeout(Some(remaining))?;
    serde_json::to_writer(&mut *writer, value).map_err(|_| NodeServiceError::Serialization)?;
    writer.write_all(b"\n").map_err(map_timeout)?;
    writer.flush().map_err(map_timeout)?;
    Ok(())
}

fn write_answer(
    writer: &mut UnixStream,
    value: &impl serde::Serialize,
) -> Result<(), NodeServiceError> {
    write_json_line(writer, value, deadline_after(ANSWER_TIMEOUT)?)
}

fn deadline_after(timeout: Duration) -> Result<Instant, NodeServiceError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or(NodeServiceError::ConnectionDeadlineExceeded)
}

fn remaining_until(deadline: Instant) -> Result<Duration, NodeServiceError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(NodeServiceError::ConnectionDeadlineExceeded)
}

fn is_timeout(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

fn map_timeout(error: std::io::Error) -> NodeServiceError {
    if is_timeout(&error) {
        NodeServiceError::ConnectionDeadlineExceeded
    } else {
        NodeServiceError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    use ward_events::{ExecutionAttemptId, LeaseId, TaskId};
    use ward_node_protocol::{
        CapabilityDiscoveryContext, CredentialCapabilities, ExecutionBackendCapabilities,
        HandshakeRequest, HandshakeResponse, IsolationCapabilities, LifecycleCapabilities,
        NamespaceCapabilities, NetworkCapabilities, NodeArchitecture, NodeCapabilities,
        NodeCapacity, ProtocolRejectionReason, ProtocolVersion, SnapshotCapabilities,
        SupportedProtocolRange, VerifierCapabilities, WARD_NODE_PROTOCOL,
    };
    use ward_node_protocol::{
        OperationId, TaskBinding, TaskLifecycleContext, TaskLifecycleRejectionReason,
        TaskLifecycleRequest, TaskLifecycleResponse, TaskLifecycleState,
    };

    use super::*;

    fn capabilities() -> NodeCapabilities {
        NodeCapabilities::new(
            ProtocolVersion::new(1, 1),
            NodeArchitecture::X86_64,
            NodeCapacity::new(8, 16 * 1024 * 1024 * 1024).unwrap(),
            IsolationCapabilities {
                namespaces: NamespaceCapabilities {
                    sandbox: true,
                    user_namespace: true,
                },
                backends: ExecutionBackendCapabilities::default(),
            },
            NetworkCapabilities {
                offline: true,
                proxy_allowlist: true,
            },
            CredentialCapabilities {
                proxy_injection: true,
                scoped_http_gateway: true,
            },
            SnapshotCapabilities {
                content_addressed: true,
                diff: true,
                read: true,
            },
            VerifierCapabilities { isolated: true },
            LifecycleCapabilities {
                pause: true,
                stop: true,
                revoke: true,
                admit: false,
                start: false,
            },
        )
        .unwrap()
    }

    fn line(stream: &mut UnixStream) -> String {
        let reader_stream = stream.try_clone().unwrap();
        let mut reader = BufReader::new(reader_stream);
        let mut value = String::new();
        reader.read_line(&mut value).unwrap();
        value
    }

    #[test]
    fn admin_socket_requires_private_parent_and_is_mode_six_hundred() {
        let private = tempfile::tempdir().unwrap();
        std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = private.path().join("node.sock");
        let listener = bind_local(&socket).unwrap();
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(listener);

        let exposed = tempfile::tempdir().unwrap();
        std::fs::set_permissions(exposed.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            bind_local(&exposed.path().join("node.sock")),
            Err(NodeServiceError::InsecureSocketDirectory)
        ));
    }

    #[test]
    fn one_one_client_receives_capabilities_bound_to_negotiated_protocol() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || service.serve_connection(server));

        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 1, 1).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();

        let accepted: HandshakeResponse = serde_json::from_str(line(&mut client).trim()).unwrap();
        assert_eq!(
            accepted,
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 1),
            }
        );

        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 1)).unwrap();
        writeln!(
            client,
            "{}",
            serde_json::to_string(&context.request()).unwrap()
        )
        .unwrap();

        let response = line(&mut client);
        assert!(context.decode_response(response.trim()).is_ok());
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn one_zero_handshake_succeeds_but_capability_discovery_is_unavailable() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || service.serve_connection(server));

        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 0, 0).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();

        let response: HandshakeResponse = serde_json::from_str(line(&mut client).trim()).unwrap();
        assert_eq!(
            response,
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 0),
            }
        );
        assert_eq!(line(&mut client), "");
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn major_and_disjoint_minor_ranges_are_rejected_fail_closed() {
        for (peer, reason) in [
            (
                SupportedProtocolRange::new(2, 0, 1).unwrap(),
                ProtocolRejectionReason::MajorVersionMismatch,
            ),
            (
                SupportedProtocolRange::new(1, 4, 5).unwrap(),
                ProtocolRejectionReason::NoCommonMinor,
            ),
        ] {
            let service = NodeService::new(capabilities()).unwrap();
            let (mut client, server) = UnixStream::pair().unwrap();
            let worker = std::thread::spawn(move || service.serve_connection(server));

            let hello = HandshakeRequest::Hello { protocol: peer };
            writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();

            let response: HandshakeResponse =
                serde_json::from_str(line(&mut client).trim()).unwrap();
            assert_eq!(
                response,
                HandshakeResponse::Rejected {
                    reason,
                    supported: WARD_NODE_PROTOCOL,
                }
            );
            worker.join().unwrap().unwrap();
        }
    }

    #[test]
    fn malformed_or_oversized_first_request_fails_closed() {
        for payload in [
            "{not-json}\n".to_owned(),
            format!("{}\n", "x".repeat(MAX_REQUEST_LINE_BYTES + 1)),
        ] {
            let service = NodeService::new(capabilities()).unwrap();
            let (mut client, server) = UnixStream::pair().unwrap();
            let worker = std::thread::spawn(move || service.serve_connection(server));

            client.write_all(payload.as_bytes()).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();

            assert!(worker.join().unwrap().is_err());
        }
    }

    #[test]
    fn slow_drip_cannot_extend_the_absolute_connection_deadline() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let started = Instant::now();
        let worker = std::thread::spawn(move || {
            service.serve_connection_with_lifetime(server, Duration::from_millis(120))
        });

        client.write_all(b"{").unwrap();
        std::thread::sleep(Duration::from_millis(70));
        client.write_all(b"{").unwrap();

        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeServiceError::ConnectionDeadlineExceeded)
        ));
        assert!(
            started.elapsed() < Duration::from_millis(190),
            "partial progress must not reset the 120 ms absolute deadline"
        );
    }

    #[test]
    fn handshake_and_capability_request_share_one_absolute_deadline() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            service.serve_connection_with_lifetime(server, Duration::from_millis(100))
        });

        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 1, 1).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        let _: HandshakeResponse = serde_json::from_str(line(&mut client).trim()).unwrap();

        std::thread::sleep(Duration::from_millis(120));

        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeServiceError::ConnectionDeadlineExceeded)
        ));
    }

    #[test]
    fn malformed_capability_request_fails_closed_after_valid_handshake() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || service.serve_connection(server));

        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 1, 1).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        let _: HandshakeResponse = serde_json::from_str(line(&mut client).trim()).unwrap();

        writeln!(client, "{{not-json").unwrap();
        let _ = client.shutdown(std::net::Shutdown::Write);

        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeServiceError::MalformedCapabilityRequest)
        ));
        assert_eq!(line(&mut client), "");
    }

    #[test]
    fn oversized_capability_request_fails_closed_after_valid_handshake() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || service.serve_connection(server));

        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 1, 1).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        let _: HandshakeResponse = serde_json::from_str(line(&mut client).trim()).unwrap();

        let payload = format!("{}\n", "x".repeat(MAX_REQUEST_LINE_BYTES + 1));
        let _ = client.write_all(payload.as_bytes());
        let _ = client.shutdown(std::net::Shutdown::Write);

        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeServiceError::RequestTooLarge)
        ));
        assert_eq!(line(&mut client), "");
    }

    fn lifecycle_binding() -> TaskBinding {
        TaskBinding::new(
            TaskId::from_u128(7),
            ExecutionAttemptId::from_u128(8),
            LeaseId::from_u128(9),
        )
    }

    fn lifecycle_context() -> TaskLifecycleContext {
        TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap()
    }

    /// Open a connection, negotiate 1.2 and return the client end plus the server worker.
    fn lifecycle_connection(
        service: &NodeService,
    ) -> (
        UnixStream,
        std::thread::JoinHandle<Result<(), NodeServiceError>>,
    ) {
        let service = service.clone();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || service.serve_connection(server));

        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 2, 2).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        assert_eq!(
            serde_json::from_str::<HandshakeResponse>(line(&mut client).trim()).unwrap(),
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 2),
            }
        );
        (client, worker)
    }

    #[test]
    fn one_two_client_discovers_capabilities_without_registering_a_task() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, worker) = lifecycle_connection(&service);
        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 2)).unwrap();
        writeln!(
            client,
            "{}",
            serde_json::to_string(&context.request()).unwrap()
        )
        .unwrap();

        let response = context.decode_response(line(&mut client).trim()).unwrap();
        let ward_node_protocol::CapabilityDiscoveryResponse::Capabilities {
            capabilities: observed,
        } = response;
        assert_eq!(observed.protocol(), ProtocolVersion::new(1, 2));
        assert_eq!(observed.architecture(), service.capabilities.architecture());
        assert_eq!(observed.capacity(), service.capabilities.capacity());
        assert_eq!(observed.isolation(), service.capabilities.isolation());
        assert_eq!(observed.network(), service.capabilities.network());
        assert_eq!(observed.credentials(), service.capabilities.credentials());
        assert_eq!(observed.snapshots(), service.capabilities.snapshots());
        assert_eq!(observed.verifier(), service.capabilities.verifier());
        assert_eq!(observed.lifecycle(), service.capabilities.lifecycle());
        worker.join().unwrap().unwrap();
        assert!(service.tasks.lock().unwrap().is_empty());
    }

    #[test]
    fn one_two_capability_request_with_one_one_version_fails_closed() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, worker) = lifecycle_connection(&service);
        let one_one = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 1)).unwrap();
        writeln!(
            client,
            "{}",
            serde_json::to_string(&one_one.request()).unwrap()
        )
        .unwrap();

        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeServiceError::MalformedCapabilityRequest)
        ));
        assert_eq!(line(&mut client), "");
        assert!(service.tasks.lock().unwrap().is_empty());
    }

    /// One lifecycle request on its own 1.2 connection; returns the decoded response.
    #[allow(clippy::needless_pass_by_value)]
    fn lifecycle_round_trip(
        service: &NodeService,
        request: TaskLifecycleRequest,
    ) -> TaskLifecycleResponse {
        let (mut client, worker) = lifecycle_connection(service);
        writeln!(client, "{}", serde_json::to_string(&request).unwrap()).unwrap();
        let response = lifecycle_context()
            .decode_response(line(&mut client).trim())
            .unwrap();
        worker.join().unwrap().unwrap();
        response
    }

    #[test]
    fn one_two_create_registers_a_node_task_that_a_later_connection_inspects() {
        let service = NodeService::new(capabilities()).unwrap();
        let ctx = lifecycle_context();
        let binding = lifecycle_binding();
        let operation = OperationId::new(1).unwrap();

        assert_eq!(
            lifecycle_round_trip(&service, ctx.inspect(binding)),
            ctx.rejected(None, binding, TaskLifecycleRejectionReason::TaskNotFound)
        );
        assert_eq!(
            lifecycle_round_trip(&service, ctx.create(operation, binding)),
            ctx.accepted(operation, binding, TaskLifecycleState::Created)
        );
        assert_eq!(
            lifecycle_round_trip(&service, ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Created)
        );
    }

    #[test]
    fn one_two_start_is_refused_over_the_socket_and_the_task_stays_created() {
        let service = NodeService::new(capabilities()).unwrap();
        let ctx = lifecycle_context();
        let binding = lifecycle_binding();
        let create = OperationId::new(1).unwrap();
        let start = OperationId::new(2).unwrap();

        lifecycle_round_trip(&service, ctx.create(create, binding));
        assert_eq!(
            lifecycle_round_trip(&service, ctx.start(start, binding)),
            ctx.rejected(
                Some(start),
                binding,
                TaskLifecycleRejectionReason::UnsupportedOperation
            )
        );
        assert_eq!(
            lifecycle_round_trip(&service, ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Created)
        );
    }

    #[test]
    fn create_applies_even_if_the_client_disconnects_before_reading_and_replays() {
        let service = NodeService::new(capabilities()).unwrap();
        let ctx = lifecycle_context();
        let binding = lifecycle_binding();
        let operation = OperationId::new(1).unwrap();

        let (mut client, worker) = lifecycle_connection(&service);
        writeln!(
            client,
            "{}",
            serde_json::to_string(&ctx.create(operation, binding)).unwrap()
        )
        .unwrap();
        client.shutdown(std::net::Shutdown::Both).unwrap();
        drop(client);
        let _ = worker.join().unwrap();

        assert_eq!(
            lifecycle_round_trip(&service, ctx.create(operation, binding)),
            ctx.accepted(operation, binding, TaskLifecycleState::Created)
        );
    }

    #[test]
    fn malformed_or_wrong_version_lifecycle_request_fails_closed_without_registering() {
        let service = NodeService::new(capabilities()).unwrap();
        let binding = lifecycle_binding();
        let operation = OperationId::new(1).unwrap();
        let wrong_version = serde_json::to_string(&TaskLifecycleRequest::Create {
            protocol: ProtocolVersion::new(1, 1),
            operation_id: operation,
            binding,
        })
        .unwrap();

        for payload in ["{not-json".to_owned(), wrong_version] {
            let (mut client, worker) = lifecycle_connection(&service);
            writeln!(client, "{payload}").unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(matches!(
                worker.join().unwrap(),
                Err(NodeServiceError::MalformedLifecycleRequest)
            ));
            assert_eq!(line(&mut client), "");
        }

        let ctx = lifecycle_context();
        assert_eq!(
            lifecycle_round_trip(&service, ctx.inspect(binding)),
            ctx.rejected(None, binding, TaskLifecycleRejectionReason::TaskNotFound)
        );
    }

    /// Open a connection, negotiate 1.3 and return the client end plus the server worker.
    fn admission_connection(
        service: &NodeService,
    ) -> (
        UnixStream,
        std::thread::JoinHandle<Result<(), NodeServiceError>>,
    ) {
        let service = service.clone();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || service.serve_connection(server));

        let hello = HandshakeRequest::Hello {
            protocol: WARD_NODE_PROTOCOL,
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        assert_eq!(
            serde_json::from_str::<HandshakeResponse>(line(&mut client).trim()).unwrap(),
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 3),
            }
        );
        (client, worker)
    }

    #[test]
    fn one_three_admit_is_refused_over_the_socket_and_the_task_stays_created() {
        let service = NodeService::new(capabilities()).unwrap();
        let ctx = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let binding = lifecycle_binding();
        let create = OperationId::new(1).unwrap();
        let admit = OperationId::new(2).unwrap();

        lifecycle_round_trip(&service, lifecycle_context().create(create, binding));

        let (mut client, worker) = admission_connection(&service);
        let request = crate::test_support::admit(ctx, admit, binding);
        writeln!(client, "{}", serde_json::to_string(&request).unwrap()).unwrap();
        assert_eq!(
            ctx.decode_response(line(&mut client).trim()).unwrap(),
            ctx.rejected(
                Some(admit),
                binding,
                TaskLifecycleRejectionReason::UnsupportedOperation
            )
        );
        worker.join().unwrap().unwrap();

        let (mut client, worker) = admission_connection(&service);
        writeln!(
            client,
            "{}",
            serde_json::to_string(&ctx.inspect(binding)).unwrap()
        )
        .unwrap();
        assert_eq!(
            ctx.decode_response(line(&mut client).trim()).unwrap(),
            ctx.inspected(binding, TaskLifecycleState::Created)
        );
        worker.join().unwrap().unwrap();
        assert_eq!(service.tasks.lock().unwrap().len(), 1);
    }

    #[test]
    fn one_two_connection_refuses_admit_like_an_unknown_request() {
        let service = NodeService::new(capabilities()).unwrap();
        let binding = lifecycle_binding();
        let admit = crate::test_support::admit(
            TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap(),
            OperationId::new(2).unwrap(),
            binding,
        );
        let one_three = serde_json::to_string(&admit).unwrap();
        let claiming_one_two = one_three.replace(r#""minor":3"#, r#""minor":2"#);
        let unknown = one_three.replace(r#""request":"admit""#, r#""request":"unknown""#);

        for payload in [one_three, claiming_one_two, unknown] {
            let (mut client, worker) = lifecycle_connection(&service);
            writeln!(client, "{payload}").unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(matches!(
                worker.join().unwrap(),
                Err(NodeServiceError::MalformedLifecycleRequest)
            ));
            assert_eq!(line(&mut client), "");
        }
        assert!(service.tasks.lock().unwrap().is_empty());
    }

    #[test]
    fn one_three_client_discovers_the_same_capabilities() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, worker) = admission_connection(&service);
        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        writeln!(
            client,
            "{}",
            serde_json::to_string(&context.request()).unwrap()
        )
        .unwrap();

        let response = context.decode_response(line(&mut client).trim()).unwrap();
        let ward_node_protocol::CapabilityDiscoveryResponse::Capabilities {
            capabilities: observed,
        } = response;
        assert_eq!(observed.protocol(), ProtocolVersion::new(1, 3));
        assert_eq!(
            observed.lifecycle(),
            LifecycleCapabilities {
                stop: false,
                start: false,
                pause: false,
                revoke: false,
                ..service.capabilities.lifecycle()
            },
            "a 1.3 node without execution advertises none of start, stop, pause or revoke"
        );
        assert_eq!(
            observed.isolation(),
            IsolationCapabilities {
                namespaces: NamespaceCapabilities::default(),
                ..service.capabilities.isolation()
            },
            "a 1.3 node without execution advertises no execution sandbox"
        );
        worker.join().unwrap().unwrap();
        assert!(service.tasks.lock().unwrap().is_empty());
    }

    #[test]
    fn capability_discovery_at_one_one_is_unchanged_by_the_task_registry() {
        let service = NodeService::new(capabilities()).unwrap();
        let ctx = lifecycle_context();
        let binding = lifecycle_binding();
        lifecycle_round_trip(&service, ctx.create(OperationId::new(1).unwrap(), binding));

        let (mut client, server) = UnixStream::pair().unwrap();
        let discovery_service = service.clone();
        let worker = std::thread::spawn(move || discovery_service.serve_connection(server));
        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 1, 1).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        let _: HandshakeResponse = serde_json::from_str(line(&mut client).trim()).unwrap();
        let discovery = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 1)).unwrap();
        writeln!(
            client,
            "{}",
            serde_json::to_string(&discovery.request()).unwrap()
        )
        .unwrap();
        assert!(discovery.decode_response(line(&mut client).trim()).is_ok());
        worker.join().unwrap().unwrap();
    }

    struct LocalNode {
        _dir: tempfile::TempDir,
        socket: std::path::PathBuf,
        service: NodeService,
        worker: std::thread::JoinHandle<()>,
    }

    impl LocalNode {
        /// Bind a real private socket and serve exactly `connections` connections.
        fn serve(service: NodeService, connections: usize) -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let socket = dir.path().join("node.sock");
            let listener = bind_local(&socket).unwrap();
            let served = service.clone();
            let worker = std::thread::spawn(move || {
                for connection in listener.incoming().take(connections) {
                    served.serve_connection(connection.unwrap()).unwrap();
                }
            });
            Self {
                _dir: dir,
                socket,
                service,
                worker,
            }
        }

        /// One request on its own connection negotiated at `protocol`; the raw response.
        fn request(&self, protocol: SupportedProtocolRange, request: &str) -> String {
            let mut client = UnixStream::connect(&self.socket).unwrap();
            let hello = HandshakeRequest::Hello { protocol };
            writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
            let mut reader = BufReader::new(client.try_clone().unwrap());
            let mut accepted = String::new();
            reader.read_line(&mut accepted).unwrap();
            assert!(matches!(
                serde_json::from_str::<HandshakeResponse>(accepted.trim()).unwrap(),
                HandshakeResponse::Accepted { .. }
            ));
            writeln!(client, "{request}").unwrap();
            let mut response = String::new();
            reader.read_line(&mut response).unwrap();
            response.trim().to_owned()
        }

        fn lifecycle(&self, request: &TaskLifecycleRequest) -> TaskLifecycleResponse {
            let ctx = admission_context();
            let raw = self.request(WARD_NODE_PROTOCOL, &serde_json::to_string(request).unwrap());
            ctx.decode_response(&raw).unwrap()
        }

        fn join(self) {
            self.worker.join().unwrap();
        }
    }

    fn admission_context() -> TaskLifecycleContext {
        TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
    }

    fn admitting_service(state: &std::path::Path) -> NodeService {
        let clock = crate::test_support::FixedClock::at(crate::test_support::NOW);
        NodeService::with_admission(
            capabilities(),
            crate::test_support::node_admission(state, &clock),
        )
        .unwrap()
    }

    #[test]
    fn one_three_admit_over_the_local_socket_moves_the_task_to_ready() {
        let state = tempfile::tempdir().unwrap();
        let node = LocalNode::serve(admitting_service(&state.path().join("state")), 5);
        let ctx = admission_context();
        let binding = lifecycle_binding();
        let create = OperationId::new(1).unwrap();
        let admit = OperationId::new(2).unwrap();
        let envelope = ward_node_protocol::TaskAdmissionEnvelope::new(
            crate::test_support::envelope_input(binding),
        )
        .unwrap();
        let request = crate::test_support::signed_admit(ctx, admit, binding, &envelope);

        assert_eq!(
            node.lifecycle(&ctx.create(create, binding)),
            ctx.accepted(create, binding, TaskLifecycleState::Created)
        );
        let accepted = node.lifecycle(&request);
        assert_eq!(
            accepted,
            ctx.accepted(admit, binding, TaskLifecycleState::Ready)
        );
        assert_eq!(
            node.lifecycle(&ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Ready)
        );
        assert_eq!(node.lifecycle(&request), accepted);
        assert_eq!(
            node.lifecycle(&ctx.start(OperationId::new(3).unwrap(), binding)),
            ctx.rejected(
                Some(OperationId::new(3).unwrap()),
                binding,
                TaskLifecycleRejectionReason::UnsupportedOperation
            )
        );
        assert_eq!(
            node.service
                .tasks
                .lock()
                .unwrap()
                .admitted(binding)
                .unwrap()
                .envelope(),
            &envelope
        );
        node.join();
    }

    #[test]
    fn one_three_refused_admit_over_the_local_socket_leaves_the_task_created() {
        let state = tempfile::tempdir().unwrap();
        let node = LocalNode::serve(admitting_service(&state.path().join("state")), 3);
        let ctx = admission_context();
        let binding = lifecycle_binding();
        let admit = OperationId::new(2).unwrap();
        let json = ward_node_protocol::AdmissionEnvelopeJson::encode(
            &ward_node_protocol::TaskAdmissionEnvelope::new(crate::test_support::envelope_input(
                binding,
            ))
            .unwrap(),
        )
        .unwrap();
        let proof = crate::test_support::sign(&json, &crate::test_support::other_keypair());

        node.lifecycle(&ctx.create(OperationId::new(1).unwrap(), binding));
        assert_eq!(
            node.lifecycle(&ctx.admit(admit, binding, json, proof).unwrap()),
            ctx.rejected(
                Some(admit),
                binding,
                TaskLifecycleRejectionReason::AuthorityDenied
            )
        );
        assert_eq!(
            node.lifecycle(&ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Created)
        );
        node.join();
    }

    #[test]
    fn capability_discovery_advertises_admit_only_at_one_three_with_admission() {
        let state = tempfile::tempdir().unwrap();
        let admitting = LocalNode::serve(admitting_service(&state.path().join("state")), 3);
        let plain = LocalNode::serve(NodeService::new(capabilities()).unwrap(), 3);

        for minor in [1, 2] {
            let protocol = SupportedProtocolRange::new(1, minor, minor).unwrap();
            let request = serde_json::to_string(
                &CapabilityDiscoveryContext::new(ProtocolVersion::new(1, minor))
                    .unwrap()
                    .request(),
            )
            .unwrap();
            let advertised = admitting.request(protocol, &request);
            assert_eq!(advertised, plain.request(protocol, &request));
            assert!(
                advertised.ends_with(r#""lifecycle":{"pause":true,"stop":true,"revoke":true}}}"#),
                "{advertised}"
            );
        }

        let one_three = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let request = serde_json::to_string(&one_three.request()).unwrap();
        for (node, admit) in [(&admitting, true), (&plain, false)] {
            let raw = node.request(WARD_NODE_PROTOCOL, &request);
            let ward_node_protocol::CapabilityDiscoveryResponse::Capabilities {
                capabilities: observed,
            } = one_three.decode_response(&raw).unwrap();
            assert_eq!(observed.lifecycle().admit, admit, "{raw}");
        }
        admitting.join();
        plain.join();
    }

    struct Executing {
        _dir: tempfile::TempDir,
        service: NodeService,
        launcher: crate::test_support::FakeLauncher,
        snapshot: ward_events::SnapshotId,
    }

    fn executing_service() -> Executing {
        executing_service_with(capabilities(), crate::execution::DEFAULT_STOP_TIMEOUT)
    }

    fn executing_service_with(configured: NodeCapabilities, stop_timeout: Duration) -> Executing {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let clock = crate::test_support::FixedClock::at(crate::test_support::NOW);
        let admission = crate::test_support::node_admission(&state, &clock);
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("hello.txt"), b"hello").unwrap();
        let snapshots = crate::workspace::open_snapshot_store(&state).unwrap();
        let snapshot = crate::workspace::import_snapshot(&snapshots, &project).unwrap();
        let launcher = crate::test_support::FakeLauncher::new();
        let execution = NodeExecution::new(
            crate::workspace::TaskRoot::open(&dir.path().join("tasks")).unwrap(),
            snapshots,
            Arc::new(launcher.clone()),
        )
        .with_stop_timeout(stop_timeout);
        let service = NodeService::with_execution(configured, admission, execution).unwrap();
        Executing {
            _dir: dir,
            service,
            launcher,
            snapshot,
        }
    }

    #[test]
    fn capability_discovery_advertises_start_and_stop_together_only_with_execution() {
        let state = tempfile::tempdir().unwrap();
        let executing = executing_service();
        let executing_node = LocalNode::serve(executing.service.clone(), 3);
        let admitting = LocalNode::serve(admitting_service(&state.path().join("state")), 1);
        let plain = LocalNode::serve(NodeService::new(capabilities()).unwrap(), 2);

        for minor in [1, 2] {
            let protocol = SupportedProtocolRange::new(1, minor, minor).unwrap();
            let request = serde_json::to_string(
                &CapabilityDiscoveryContext::new(ProtocolVersion::new(1, minor))
                    .unwrap()
                    .request(),
            )
            .unwrap();
            assert_eq!(
                executing_node.request(protocol, &request),
                plain.request(protocol, &request),
                "1.{minor} documents are unchanged by execution"
            );
        }

        let one_three = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let request = serde_json::to_string(&one_three.request()).unwrap();
        for (node, executes) in [(&executing_node, true), (&admitting, false)] {
            let raw = node.request(WARD_NODE_PROTOCOL, &request);
            let ward_node_protocol::CapabilityDiscoveryResponse::Capabilities {
                capabilities: observed,
            } = one_three.decode_response(&raw).unwrap();
            let lifecycle = observed.lifecycle();
            assert_eq!(lifecycle.start, executes, "{raw}");
            assert_eq!(lifecycle.stop, executes, "{raw}");
            assert!(lifecycle.admit, "{raw}");
            assert_eq!(lifecycle.pause, executes, "{raw}");
            assert_eq!(lifecycle.revoke, executes, "{raw}");
        }
        executing_node.join();
        admitting.join();
        plain.join();
    }

    #[test]
    fn one_three_start_and_stop_over_the_local_socket() {
        let executing = executing_service();
        let node = LocalNode::serve(executing.service.clone(), 7);
        let ctx = admission_context();
        let binding = lifecycle_binding();
        let mut input = crate::test_support::envelope_input(binding);
        input.workload = ward_node_protocol::TaskWorkload::new(
            input.workload.argv().clone(),
            input.workload.capability_manifest().clone(),
            executing.snapshot,
            60_000,
        )
        .unwrap();
        let envelope = ward_node_protocol::TaskAdmissionEnvelope::new(input).unwrap();
        let start = OperationId::new(3).unwrap();
        let stop = OperationId::new(4).unwrap();

        node.lifecycle(&ctx.create(OperationId::new(1).unwrap(), binding));
        node.lifecycle(&crate::test_support::signed_admit(
            ctx,
            OperationId::new(2).unwrap(),
            binding,
            &envelope,
        ));
        assert_eq!(
            node.lifecycle(&ctx.start(start, binding)),
            ctx.accepted(start, binding, TaskLifecycleState::Running)
        );
        assert_eq!(
            node.lifecycle(&ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Running)
        );
        assert_eq!(
            node.lifecycle(&ctx.stop(stop, binding)),
            ctx.accepted(stop, binding, TaskLifecycleState::Stopped)
        );
        assert_eq!(
            node.lifecycle(&ctx.inspect(binding)),
            ctx.inspected_with_outcome(
                binding,
                TaskLifecycleState::Stopped,
                ward_node_protocol::TaskExecutionOutcome::Failed
            )
            .unwrap()
        );
        assert_eq!(
            node.lifecycle(&ctx.stop(stop, binding)),
            ctx.accepted(stop, binding, TaskLifecycleState::Stopped)
        );
        assert_eq!(executing.launcher.stopped(), 1);
        node.join();
    }

    /// One request on its own connection negotiated at `protocol`, whose request deadline
    /// is `request_timeout`; the raw response line and how serving ended.
    fn exchange(
        service: &NodeService,
        protocol: SupportedProtocolRange,
        request: &str,
        request_timeout: Duration,
    ) -> (String, Result<(), NodeServiceError>) {
        let service = service.clone();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            service.serve_connection_with_lifetime(server, request_timeout)
        });
        let hello = HandshakeRequest::Hello { protocol };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        assert!(matches!(
            serde_json::from_str::<HandshakeResponse>(line(&mut client).trim()).unwrap(),
            HandshakeResponse::Accepted { .. }
        ));
        writeln!(client, "{request}").unwrap();
        let response = line(&mut client);
        (response.trim().to_owned(), worker.join().unwrap())
    }

    fn runnable_admit(executing: &Executing, binding: TaskBinding) -> TaskLifecycleRequest {
        let mut input = crate::test_support::envelope_input(binding);
        input.workload = ward_node_protocol::TaskWorkload::new(
            input.workload.argv().clone(),
            input.workload.capability_manifest().clone(),
            executing.snapshot,
            60_000,
        )
        .unwrap();
        let envelope = ward_node_protocol::TaskAdmissionEnvelope::new(input).unwrap();
        crate::test_support::signed_admit(
            admission_context(),
            OperationId::new(2).unwrap(),
            binding,
            &envelope,
        )
    }

    #[test]
    fn a_stop_whose_reap_outlasts_the_request_deadline_still_gets_its_answer() {
        let executing = executing_service_with(capabilities(), Duration::from_secs(10));
        let ctx = admission_context();
        let binding = lifecycle_binding();
        let request_timeout = Duration::from_millis(100);
        let lifecycle = |request: &TaskLifecycleRequest| {
            let (raw, served) = exchange(
                &executing.service,
                WARD_NODE_PROTOCOL,
                &serde_json::to_string(request).unwrap(),
                request_timeout,
            );
            (ctx.decode_response(&raw), served)
        };
        let start = OperationId::new(3).unwrap();
        let stop = OperationId::new(4).unwrap();

        lifecycle(&ctx.create(OperationId::new(1).unwrap(), binding))
            .1
            .unwrap();
        lifecycle(&runnable_admit(&executing, binding)).1.unwrap();
        assert_eq!(
            lifecycle(&ctx.start(start, binding)).0.unwrap(),
            ctx.accepted(start, binding, TaskLifecycleState::Running)
        );

        executing
            .launcher
            .set_on_stop(crate::test_support::FakeStop::Ignore);
        let launcher = executing.launcher.clone();
        let reap_after = request_timeout * 4;
        let release = std::thread::spawn(move || {
            std::thread::sleep(reap_after);
            launcher.set_on_stop(crate::test_support::FakeStop::Honour);
        });
        let asked = Instant::now();
        let (answer, served) = lifecycle(&ctx.stop(stop, binding));
        assert!(asked.elapsed() >= reap_after, "the reap was not slow");
        release.join().unwrap();
        assert_eq!(
            answer.expect("a slow stop is answered, not closed"),
            ctx.accepted(stop, binding, TaskLifecycleState::Stopped)
        );
        served.unwrap();
        assert_eq!(executing.launcher.stopped(), 1);
    }

    fn conservative_capabilities() -> NodeCapabilities {
        NodeCapabilities::new(
            ProtocolVersion::new(1, 1),
            NodeArchitecture::X86_64,
            NodeCapacity::new(8, 16 * 1024 * 1024 * 1024).unwrap(),
            IsolationCapabilities::default(),
            NetworkCapabilities::default(),
            CredentialCapabilities::default(),
            SnapshotCapabilities::default(),
            VerifierCapabilities::default(),
            LifecycleCapabilities::default(),
        )
        .unwrap()
    }

    fn discovered(service: &NodeService, minor: u16) -> (String, NodeCapabilities) {
        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, minor)).unwrap();
        let (raw, served) = exchange(
            service,
            SupportedProtocolRange::new(1, minor, minor).unwrap(),
            &serde_json::to_string(&context.request()).unwrap(),
            REQUEST_TIMEOUT,
        );
        served.unwrap();
        let ward_node_protocol::CapabilityDiscoveryResponse::Capabilities { capabilities } =
            context.decode_response(&raw).unwrap();
        (raw, capabilities)
    }

    #[test]
    fn an_executing_node_advertises_the_isolation_it_enforces_only_at_one_three() {
        let executing = executing_service_with(
            conservative_capabilities(),
            crate::execution::DEFAULT_STOP_TIMEOUT,
        );
        let state = tempfile::tempdir().unwrap();
        let clock = crate::test_support::FixedClock::at(crate::test_support::NOW);
        let admitting = NodeService::with_admission(
            conservative_capabilities(),
            crate::test_support::node_admission(&state.path().join("state"), &clock),
        )
        .unwrap();
        let plain = NodeService::new(conservative_capabilities()).unwrap();

        let observed = discovered(&executing.service, 3).1;
        assert_eq!(
            observed.isolation(),
            IsolationCapabilities {
                namespaces: NamespaceCapabilities {
                    sandbox: true,
                    user_namespace: true,
                },
                backends: ExecutionBackendCapabilities::default(),
            }
        );
        assert_eq!(
            observed.network(),
            NetworkCapabilities {
                offline: true,
                proxy_allowlist: false,
            }
        );
        assert_eq!(
            observed.snapshots(),
            SnapshotCapabilities {
                content_addressed: true,
                diff: false,
                read: false,
            }
        );
        assert_eq!(observed.credentials(), CredentialCapabilities::default());
        assert_eq!(observed.verifier(), VerifierCapabilities::default());
        assert!(observed.lifecycle().start && observed.lifecycle().stop);

        for service in [&admitting, &plain] {
            let observed = discovered(service, 3).1;
            assert_eq!(observed.isolation(), IsolationCapabilities::default());
            assert_eq!(observed.network(), NetworkCapabilities::default());
            assert_eq!(observed.snapshots(), SnapshotCapabilities::default());
        }

        for minor in [1, 2] {
            let (raw, observed) = discovered(&executing.service, minor);
            assert_eq!(raw, discovered(&plain, minor).0, "1.{minor}");
            assert_eq!(observed.isolation(), IsolationCapabilities::default());
            assert_eq!(observed.network(), NetworkCapabilities::default());
            assert_eq!(observed.snapshots(), SnapshotCapabilities::default());
        }
    }

    #[test]
    fn a_node_that_does_not_execute_never_advertises_execution_isolation_at_one_three() {
        let state = tempfile::tempdir().unwrap();
        let clock = crate::test_support::FixedClock::at(crate::test_support::NOW);
        let admitting = NodeService::with_admission(
            capabilities(),
            crate::test_support::node_admission(&state.path().join("state"), &clock),
        )
        .unwrap();
        let observed = discovered(&admitting, 3).1;
        assert_eq!(
            observed.isolation().namespaces,
            NamespaceCapabilities::default()
        );
        assert!(!observed.network().offline);
        assert!(!observed.snapshots().content_addressed);
        assert_eq!(
            observed.isolation().backends,
            capabilities().isolation().backends
        );
        assert_eq!(observed.credentials(), capabilities().credentials());
        assert_eq!(observed.verifier(), capabilities().verifier());
        assert_eq!(
            discovered(&admitting, 1).1.isolation(),
            capabilities().isolation()
        );
    }

    #[test]
    fn capability_discovery_advertises_pause_and_revoke_only_at_one_three_with_execution() {
        let executing = executing_service();
        let base = capabilities();
        let configured = NodeCapabilities::new(
            base.protocol(),
            base.architecture(),
            base.capacity(),
            base.isolation(),
            base.network(),
            base.credentials(),
            base.snapshots(),
            base.verifier(),
            LifecycleCapabilities::default(),
        )
        .unwrap();
        let state = tempfile::tempdir().unwrap();
        let clock = crate::test_support::FixedClock::at(crate::test_support::NOW);
        let quiet = NodeService::with_execution(
            configured,
            crate::test_support::node_admission(&state.path().join("state"), &clock),
            NodeExecution::new(
                crate::workspace::TaskRoot::open(&state.path().join("tasks")).unwrap(),
                crate::workspace::open_snapshot_store(&state.path().join("state")).unwrap(),
                Arc::new(executing.launcher.clone()),
            ),
        )
        .unwrap();
        let node = LocalNode::serve(quiet, 3);
        for minor in [1, 2] {
            let protocol = SupportedProtocolRange::new(1, minor, minor).unwrap();
            let request = serde_json::to_string(
                &CapabilityDiscoveryContext::new(ProtocolVersion::new(1, minor))
                    .unwrap()
                    .request(),
            )
            .unwrap();
            assert!(
                node.request(protocol, &request)
                    .ends_with(r#""lifecycle":{"pause":false,"stop":false,"revoke":false}}}"#),
                "1.{minor} documents are unchanged by execution"
            );
        }
        let one_three = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let raw = node.request(
            WARD_NODE_PROTOCOL,
            &serde_json::to_string(&one_three.request()).unwrap(),
        );
        assert!(
            raw.ends_with(
                r#""lifecycle":{"pause":true,"stop":true,"revoke":true,"admit":true,"start":true}}}"#
            ),
            "{raw}"
        );
        node.join();
    }

    fn one_three_round_trip(
        service: &NodeService,
        request: &TaskLifecycleRequest,
    ) -> TaskLifecycleResponse {
        let (mut client, worker) = admission_connection(service);
        writeln!(client, "{}", serde_json::to_string(request).unwrap()).unwrap();
        let response = admission_context()
            .decode_response(line(&mut client).trim())
            .unwrap();
        worker.join().unwrap().unwrap();
        response
    }

    #[test]
    fn a_transition_whose_client_disconnects_is_applied_whole_or_not_at_all() {
        let executing = executing_service();
        let service = &executing.service;
        let ctx = admission_context();
        let binding = lifecycle_binding();
        let mut input = crate::test_support::envelope_input(binding);
        input.workload = ward_node_protocol::TaskWorkload::new(
            input.workload.argv().clone(),
            input.workload.capability_manifest().clone(),
            executing.snapshot,
            60_000,
        )
        .unwrap();
        let envelope = ward_node_protocol::TaskAdmissionEnvelope::new(input).unwrap();
        one_three_round_trip(service, &ctx.create(OperationId::new(1).unwrap(), binding));
        one_three_round_trip(
            service,
            &crate::test_support::signed_admit(
                ctx,
                OperationId::new(2).unwrap(),
                binding,
                &envelope,
            ),
        );
        let start = OperationId::new(3).unwrap();
        assert_eq!(
            one_three_round_trip(service, &ctx.start(start, binding)),
            ctx.accepted(start, binding, TaskLifecycleState::Running)
        );
        crate::test_support::eventually(|| executing.launcher.waiting() == 1);

        let pause = OperationId::new(5).unwrap();
        let request = serde_json::to_string(&ctx.pause(pause, binding)).unwrap();
        let (mut client, worker) = admission_connection(service);
        client
            .write_all(&request.as_bytes()[..request.len() / 2])
            .unwrap();
        client.shutdown(std::net::Shutdown::Both).unwrap();
        drop(client);
        assert!(worker.join().unwrap().is_err());
        assert_eq!(
            one_three_round_trip(service, &ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Running),
            "a request cut off before its newline is never applied"
        );
        assert_eq!(executing.launcher.freezes(), 0);

        let (mut client, worker) = admission_connection(service);
        writeln!(client, "{request}").unwrap();
        client.shutdown(std::net::Shutdown::Both).unwrap();
        drop(client);
        let _ = worker.join().unwrap();
        assert_eq!(
            one_three_round_trip(service, &ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Paused),
            "a complete request is applied whole although nobody read the answer"
        );
        assert_eq!(
            one_three_round_trip(service, &ctx.pause(pause, binding)),
            ctx.accepted(pause, binding, TaskLifecycleState::Paused)
        );
        assert_eq!(executing.launcher.freezes(), 1);

        let revoke = OperationId::new(6).unwrap();
        let (mut client, worker) = admission_connection(service);
        writeln!(
            client,
            "{}",
            serde_json::to_string(&ctx.revoke(revoke, binding)).unwrap()
        )
        .unwrap();
        client.shutdown(std::net::Shutdown::Both).unwrap();
        drop(client);
        let _ = worker.join().unwrap();
        assert_eq!(
            one_three_round_trip(service, &ctx.revoke(revoke, binding)),
            ctx.accepted(revoke, binding, TaskLifecycleState::Revoked)
        );
        assert_eq!(executing.launcher.stopped(), 1);
        assert!(
            service
                .tasks
                .lock()
                .unwrap()
                .admission()
                .unwrap()
                .state()
                .revocation(binding.lease())
                .is_some()
        );
    }

    #[test]
    fn protocol_state_is_connection_local() {
        let service = NodeService::new(capabilities()).unwrap();

        let (mut rejected_client, rejected_server) = UnixStream::pair().unwrap();
        let rejected_service = service.clone();
        let rejected =
            std::thread::spawn(move || rejected_service.serve_connection(rejected_server));
        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(2, 0, 0).unwrap(),
        };
        writeln!(
            rejected_client,
            "{}",
            serde_json::to_string(&hello).unwrap()
        )
        .unwrap();
        let _: HandshakeResponse = serde_json::from_str(line(&mut rejected_client).trim()).unwrap();
        rejected.join().unwrap().unwrap();

        let (mut accepted_client, accepted_server) = UnixStream::pair().unwrap();
        let accepted = std::thread::spawn(move || service.serve_connection(accepted_server));
        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 1, 1).unwrap(),
        };
        writeln!(
            accepted_client,
            "{}",
            serde_json::to_string(&hello).unwrap()
        )
        .unwrap();
        assert!(matches!(
            serde_json::from_str::<HandshakeResponse>(line(&mut accepted_client).trim()).unwrap(),
            HandshakeResponse::Accepted { .. }
        ));
        accepted_client.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(accepted.join().unwrap().is_err());
    }
}
