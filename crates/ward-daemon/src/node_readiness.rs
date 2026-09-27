//! Read-only readiness probe for the local Ward node endpoint.
//!
//! This module performs version negotiation only. It never starts work, requests
//! capabilities, grants authority, or falls back to the per-session daemon protocol.

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ward_node_protocol::{
    HandshakeRequest, HandshakeResponse, ProtocolVersion, WARD_NODE_PROTOCOL, negotiate,
};

/// Explicit operator setting used by ward doctor to locate the local node endpoint.
pub const WARD_NODE_SOCKET_ENV: &str = "WARD_NODE_SOCKET";

/// Default total budget for one diagnostic handshake.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(750);

const MAX_RESPONSE_LINE_BYTES: usize = 4 * 1024;

/// Stable machine-readable readiness state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WardNodeReadinessState {
    /// The ward-node executable is not installed.
    BinaryAbsent,
    /// The executable exists but no socket was explicitly configured.
    NotConfigured,
    /// The configured socket is absent or refuses connections.
    NotRunning,
    /// The configured node negotiated a supported protocol version.
    ProtocolCompatible,
    /// A node responded but no supported protocol version overlaps.
    ProtocolIncompatible,
    /// The configured endpoint timed out, was malformed, or failed another bounded probe.
    Unhealthy,
}

impl WardNodeReadinessState {
    /// Stable diagnostic value for logs and future machine-readable output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BinaryAbsent => "binary_absent",
            Self::NotConfigured => "not_configured",
            Self::NotRunning => "not_running",
            Self::ProtocolCompatible => "protocol_compatible",
            Self::ProtocolIncompatible => "protocol_incompatible",
            Self::Unhealthy => "unhealthy",
        }
    }
}

/// Result of one read-only node readiness assessment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WardNodeReadiness {
    /// Stable state.
    pub state: WardNodeReadinessState,
    /// Negotiated protocol when compatible.
    pub protocol: Option<ProtocolVersion>,
}

impl WardNodeReadiness {
    const fn state(state: WardNodeReadinessState) -> Self {
        Self {
            state,
            protocol: None,
        }
    }

    const fn compatible(protocol: ProtocolVersion) -> Self {
        Self {
            state: WardNodeReadinessState::ProtocolCompatible,
            protocol: Some(protocol),
        }
    }
}

/// Assess node readiness without granting any authority.
///
/// # Parameters
///
/// - `binary_present`: whether the ward-node executable is installed.
/// - `socket`: explicitly configured local administrative socket.
/// - `timeout`: total absolute budget covering connect, write and response read.
///
/// # Security
///
/// The probe sends only the version handshake. Protocol incompatibility never triggers
/// a fallback to wardd.
///
/// # Returns
///
/// A stable readiness state. Operational failures are represented as states because
/// ward-node remains informational during migration.
#[must_use]
pub fn assess(binary_present: bool, socket: Option<&Path>, timeout: Duration) -> WardNodeReadiness {
    if !binary_present {
        return WardNodeReadiness::state(WardNodeReadinessState::BinaryAbsent);
    }
    let Some(socket) = socket else {
        return WardNodeReadiness::state(WardNodeReadinessState::NotConfigured);
    };

    match probe(socket, timeout) {
        Ok(HandshakeResponse::Accepted { protocol }) if protocol_is_supported(protocol) => {
            WardNodeReadiness::compatible(protocol)
        }
        Ok(HandshakeResponse::Accepted { .. } | HandshakeResponse::Rejected { .. }) => {
            WardNodeReadiness::state(WardNodeReadinessState::ProtocolIncompatible)
        }
        Err(ProbeError::NotRunning) => WardNodeReadiness::state(WardNodeReadinessState::NotRunning),
        Err(ProbeError::Unhealthy) => WardNodeReadiness::state(WardNodeReadinessState::Unhealthy),
    }
}

fn protocol_is_supported(protocol: ProtocolVersion) -> bool {
    let Ok(peer) = ward_node_protocol::SupportedProtocolRange::new(
        protocol.major(),
        protocol.minor(),
        protocol.minor(),
    ) else {
        return false;
    };
    matches!(
        negotiate(WARD_NODE_PROTOCOL, peer),
        HandshakeResponse::Accepted { protocol: selected } if selected == protocol
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeError {
    NotRunning,
    Unhealthy,
}

fn probe(socket: &Path, timeout: Duration) -> Result<HandshakeResponse, ProbeError> {
    let started = Instant::now();
    let deadline = started.checked_add(timeout).ok_or(ProbeError::Unhealthy)?;
    let mut stream = connect_with_deadline(socket, deadline)?;

    stream
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|_| ProbeError::Unhealthy)?;
    let request = HandshakeRequest::Hello {
        protocol: WARD_NODE_PROTOCOL,
    };
    serde_json::to_writer(&mut stream, &request).map_err(|_| ProbeError::Unhealthy)?;
    stream.write_all(b"\n").map_err(|_| ProbeError::Unhealthy)?;
    stream.flush().map_err(|_| ProbeError::Unhealthy)?;

    let mut reader = BufReader::new(stream);
    let line = read_line_with_deadline(&mut reader, deadline)?;
    serde_json::from_str(&line).map_err(|_| ProbeError::Unhealthy)
}

fn connect_with_deadline(socket: &Path, deadline: Instant) -> Result<UnixStream, ProbeError> {
    let path = PathBuf::from(socket);
    let (sender, receiver) = mpsc::sync_channel(1);
    let _connector = std::thread::spawn(move || {
        let _ = sender.send(UnixStream::connect(path));
    });

    let result = receiver
        .recv_timeout(remaining(deadline)?)
        .map_err(|_| ProbeError::Unhealthy)?;
    result.map_err(classify_connect_error)
}

fn classify_connect_error(error: std::io::Error) -> ProbeError {
    match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            ProbeError::NotRunning
        }
        _ => ProbeError::Unhealthy,
    }
}

fn read_line_with_deadline(
    reader: &mut BufReader<UnixStream>,
    deadline: Instant,
) -> Result<String, ProbeError> {
    let mut bytes = Vec::new();
    loop {
        reader
            .get_mut()
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| ProbeError::Unhealthy)?;
        let available = reader.fill_buf().map_err(|_| ProbeError::Unhealthy)?;
        if available.is_empty() {
            return Err(ProbeError::Unhealthy);
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if bytes.len().saturating_add(take) > MAX_RESPONSE_LINE_BYTES + 1 {
            return Err(ProbeError::Unhealthy);
        }

        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            break;
        }
    }

    bytes.pop();
    if bytes.ends_with(b"\r") {
        bytes.pop();
    }
    String::from_utf8(bytes).map_err(|_| ProbeError::Unhealthy)
}

fn remaining(deadline: Instant) -> Result<Duration, ProbeError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(ProbeError::Unhealthy)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    use ward_node_protocol::{ProtocolRejectionReason, SupportedProtocolRange};

    use super::*;

    fn fixture(
        response: FixtureResponse,
        delay: Duration,
    ) -> (tempfile::TempDir, std::thread::JoinHandle<()>) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("node.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let reader_stream = stream.try_clone().unwrap();
            let mut reader = BufReader::new(reader_stream);
            let mut request = String::new();
            reader.read_line(&mut request).unwrap();
            let _: HandshakeRequest = serde_json::from_str(request.trim()).unwrap();
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            match response {
                FixtureResponse::Handshake(response) => {
                    let _ = writeln!(stream, "{}", serde_json::to_string(&response).unwrap());
                }
                FixtureResponse::Malformed => {
                    let _ = writeln!(stream, "{{not-json");
                }
            }
        });
        (dir, handle)
    }

    #[derive(Clone, Copy)]
    enum FixtureResponse {
        Handshake(HandshakeResponse),
        Malformed,
    }

    #[test]
    fn state_values_are_stable() {
        assert_eq!(
            WardNodeReadinessState::BinaryAbsent.as_str(),
            "binary_absent"
        );
        assert_eq!(
            WardNodeReadinessState::NotConfigured.as_str(),
            "not_configured"
        );
        assert_eq!(WardNodeReadinessState::NotRunning.as_str(), "not_running");
        assert_eq!(
            WardNodeReadinessState::ProtocolCompatible.as_str(),
            "protocol_compatible"
        );
        assert_eq!(
            WardNodeReadinessState::ProtocolIncompatible.as_str(),
            "protocol_incompatible"
        );
        assert_eq!(WardNodeReadinessState::Unhealthy.as_str(), "unhealthy");
    }

    #[test]
    fn absent_and_unconfigured_are_distinct() {
        assert_eq!(
            assess(false, None, PROBE_TIMEOUT).state,
            WardNodeReadinessState::BinaryAbsent
        );
        assert_eq!(
            assess(true, None, PROBE_TIMEOUT).state,
            WardNodeReadinessState::NotConfigured
        );
    }

    #[test]
    fn missing_socket_is_not_running() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            assess(
                true,
                Some(&dir.path().join("missing.sock")),
                Duration::from_millis(100),
            )
            .state,
            WardNodeReadinessState::NotRunning
        );
    }

    #[test]
    fn compatible_handshake_reports_selected_protocol() {
        let response = HandshakeResponse::Accepted {
            protocol: ProtocolVersion::new(1, 1),
        };
        let (dir, server) = fixture(FixtureResponse::Handshake(response), Duration::ZERO);

        let result = assess(
            true,
            Some(&dir.path().join("node.sock")),
            Duration::from_secs(1),
        );
        assert_eq!(result.state, WardNodeReadinessState::ProtocolCompatible);
        assert_eq!(result.protocol, Some(ProtocolVersion::new(1, 1)));
        server.join().unwrap();
    }

    #[test]
    fn incompatible_handshake_never_falls_back() {
        let response = HandshakeResponse::Rejected {
            reason: ProtocolRejectionReason::MajorVersionMismatch,
            supported: SupportedProtocolRange::new(2, 0, 0).unwrap(),
        };
        let (dir, server) = fixture(FixtureResponse::Handshake(response), Duration::ZERO);

        assert_eq!(
            assess(
                true,
                Some(&dir.path().join("node.sock")),
                Duration::from_secs(1),
            )
            .state,
            WardNodeReadinessState::ProtocolIncompatible
        );
        server.join().unwrap();
    }

    #[test]
    fn malformed_or_timed_out_node_is_unhealthy() {
        let (malformed_dir, malformed_server) = fixture(FixtureResponse::Malformed, Duration::ZERO);
        assert_eq!(
            assess(
                true,
                Some(&malformed_dir.path().join("node.sock")),
                Duration::from_secs(1),
            )
            .state,
            WardNodeReadinessState::Unhealthy
        );
        malformed_server.join().unwrap();

        let response = HandshakeResponse::Accepted {
            protocol: ProtocolVersion::new(1, 1),
        };
        let (slow_dir, slow_server) = fixture(
            FixtureResponse::Handshake(response),
            Duration::from_millis(100),
        );
        assert_eq!(
            assess(
                true,
                Some(&slow_dir.path().join("node.sock")),
                Duration::from_millis(30),
            )
            .state,
            WardNodeReadinessState::Unhealthy
        );
        slow_server.join().unwrap();
    }

    #[test]
    fn accepted_out_of_range_protocol_is_incompatible() {
        let response = HandshakeResponse::Accepted {
            protocol: ProtocolVersion::new(9, 9),
        };
        let (dir, server) = fixture(FixtureResponse::Handshake(response), Duration::ZERO);

        assert_eq!(
            assess(
                true,
                Some(&dir.path().join("node.sock")),
                Duration::from_secs(1),
            )
            .state,
            WardNodeReadinessState::ProtocolIncompatible
        );
        server.join().unwrap();
    }
}
