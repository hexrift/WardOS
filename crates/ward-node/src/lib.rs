//! Local ward-node service.
//!
//! The first service slice exposes only protocol negotiation and read-only node capability
//! discovery. Task lifecycle and remote transport are deliberately absent.

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use thiserror::Error;
use ward_node_protocol::{
    negotiate, CapabilityDiscoveryContext, HandshakeRequest, HandshakeResponse, NodeCapabilities,
    SupportedProtocolRange,
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
    /// Returns InvalidCapabilities if the capability document is not valid for
    /// capability discovery in this build.
    pub fn new(capabilities: NodeCapabilities) -> Result<Self, NodeServiceError> {
        let protocol = capabilities.protocol();
        let context = CapabilityDiscoveryContext::new(protocol)
            .map_err(|_| NodeServiceError::InvalidCapabilities)?;
        let supported =
            SupportedProtocolRange::new(protocol.major(), protocol.minor(), protocol.minor())
                .map_err(|_| NodeServiceError::InvalidCapabilities)?;

        Ok(Self {
            capabilities,
            context,
            supported,
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
    pub fn serve_connection(&self, mut stream: UnixStream) -> Result<(), NodeServiceError> {
        stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
        stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;

        let reader_stream = stream.try_clone()?;
        let mut reader = BufReader::new(reader_stream);

        let handshake_line = read_request_line(&mut reader)?;
        let handshake = serde_json::from_str::<HandshakeRequest>(&handshake_line)
            .map_err(|_| NodeServiceError::MalformedHandshake)?;
        let HandshakeRequest::Hello { protocol: peer } = handshake;
        let response = negotiate(self.supported, peer);
        write_json_line(&mut stream, &response)?;

        let HandshakeResponse::Accepted { protocol } = response else {
            return Ok(());
        };

        if protocol != self.context.protocol() {
            return Err(NodeServiceError::InvalidCapabilities);
        }

        let request_line = read_request_line(&mut reader)?;
        self.context
            .decode_request(&request_line)
            .map_err(|_| NodeServiceError::MalformedCapabilityRequest)?;
        let response = self
            .context
            .response(self.capabilities)
            .map_err(|_| NodeServiceError::InvalidCapabilities)?;
        write_json_line(&mut stream, &response)
    }
}

/// Bind a local ward-node socket and serve connections indefinitely.
///
/// The socket is created mode 0600 so unprivileged sibling users cannot connect merely
/// because they can name the path. This is a local bootstrap boundary, not the remote
/// authenticated transport tracked by #262.
///
/// # Errors
///
/// Returns if the listener cannot be created/configured. Existing socket paths are never
/// removed automatically.
pub fn serve_local(
    socket: &Path,
    capabilities: NodeCapabilities,
) -> Result<(), NodeServiceError> {
    let service = NodeService::new(capabilities)?;
    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;

    for connection in listener.incoming() {
        let stream = connection?;
        let connection_service = service.clone();
        std::thread::spawn(move || {
            let _ = connection_service.serve_connection(stream);
        });
    }

    Ok(())
}

fn read_request_line(reader: &mut BufReader<UnixStream>) -> Result<String, NodeServiceError> {
    let mut bytes = Vec::new();
    {
        let mut limited = reader.take((MAX_REQUEST_LINE_BYTES + 2) as u64);
        limited.read_until(b'\n', &mut bytes)?;
    }

    if bytes.is_empty() {
        return Err(NodeServiceError::UnexpectedEof);
    }

    if !bytes.ends_with(b"\n") {
        if bytes.len() > MAX_REQUEST_LINE_BYTES {
            return Err(NodeServiceError::RequestTooLarge);
        }
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
) -> Result<(), NodeServiceError> {
    serde_json::to_writer(&mut *writer, value).map_err(|_| NodeServiceError::Serialization)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
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
        SupportedProtocolRange, VerifierCapabilities,
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
    fn one_zero_client_is_rejected_instead_of_downgrading_to_wardd() {
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
            HandshakeResponse::Rejected {
                reason: ProtocolRejectionReason::NoCommonMinor,
                supported: SupportedProtocolRange::new(1, 1, 1).unwrap(),
            }
        );
        worker.join().unwrap().unwrap();
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
        let _: HandshakeResponse =
            serde_json::from_str(line(&mut rejected_client).trim()).unwrap();
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
