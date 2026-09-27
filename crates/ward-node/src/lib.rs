//! Local ward-node service.
//!
//! The first service slice exposes only protocol negotiation and read-only node capability
//! discovery. Task lifecycle and remote transport are deliberately absent.

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use thiserror::Error;
use ward_node_protocol::{
    CapabilityDiscoveryContext, HandshakeRequest, HandshakeResponse, NodeCapabilities,
    SupportedProtocolRange, WARD_NODE_PROTOCOL, negotiate,
};

/// Maximum bytes in one node-protocol JSON request, excluding the terminating newline.
pub const MAX_REQUEST_LINE_BYTES: usize = 64 * 1024;

/// Per-read/per-write bound for a local node protocol connection.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// The absolute connection lifetime expired.
    #[error("ward-node connection exceeded its lifetime")]
    ConnectionDeadlineExceeded,
}

/// Read-only local node service for handshake and capability discovery.
#[derive(Clone)]
pub struct NodeService {
    capabilities: NodeCapabilities,
    context: CapabilityDiscoveryContext,
    supported: SupportedProtocolRange,
}

impl NodeService {
    /// Create a service bound to trusted node-owned capabilities.
    ///
    /// # Errors
    ///
    /// Returns `InvalidCapabilities` if the capability document is not valid for
    /// capability discovery in this build.
    pub fn new(capabilities: NodeCapabilities) -> Result<Self, NodeServiceError> {
        let protocol = capabilities.protocol();
        let context = CapabilityDiscoveryContext::new(protocol)
            .map_err(|_| NodeServiceError::InvalidCapabilities)?;
        Ok(Self {
            capabilities,
            context,
            supported: WARD_NODE_PROTOCOL,
        })
    }

    /// Serve exactly one local protocol connection.
    ///
    /// The first request must be a handshake. Rejected handshakes receive a bounded
    /// machine-readable response and close. Accepted connections may issue one read-only
    /// capability-discovery request before closing.
    ///
    /// # Errors
    ///
    /// Returns an explicit bounded protocol/I/O error. No error path falls back to the
    /// per-session ward-daemon control protocol.
    pub fn serve_connection(&self, stream: UnixStream) -> Result<(), NodeServiceError> {
        self.serve_connection_with_lifetime(stream, CONNECTION_TIMEOUT)
    }

    fn serve_connection_with_lifetime(
        &self,
        mut stream: UnixStream,
        lifetime: Duration,
    ) -> Result<(), NodeServiceError> {
        let deadline = Instant::now()
            .checked_add(lifetime)
            .ok_or(NodeServiceError::ConnectionDeadlineExceeded)?;

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

        if protocol != self.context.protocol() {
            return Ok(());
        }

        let request_line = read_request_line(&mut reader, deadline)?;
        self.context
            .decode_request(&request_line)
            .map_err(|_| NodeServiceError::MalformedCapabilityRequest)?;
        let response = self
            .context
            .response(self.capabilities)
            .map_err(|_| NodeServiceError::InvalidCapabilities)?;
        write_json_line(&mut stream, &response, deadline)
    }
}

/// Bind a local ward-node socket and serve connections indefinitely.
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
pub fn serve_local(socket: &Path, capabilities: NodeCapabilities) -> Result<(), NodeServiceError> {
    let service = NodeService::new(capabilities)?;
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

    use ward_node_protocol::{
        CapabilityDiscoveryContext, CredentialCapabilities, ExecutionBackendCapabilities,
        HandshakeRequest, HandshakeResponse, IsolationCapabilities, LifecycleCapabilities,
        NamespaceCapabilities, NetworkCapabilities, NodeArchitecture, NodeCapabilities,
        NodeCapacity, ProtocolRejectionReason, ProtocolVersion, SnapshotCapabilities,
        SupportedProtocolRange, VerifierCapabilities, WARD_NODE_PROTOCOL,
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
                SupportedProtocolRange::new(1, 2, 3).unwrap(),
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
