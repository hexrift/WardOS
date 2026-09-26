//! ward-node-protocol: dependency-light protocol contracts shared by a future
//! ward-node and its local or remote clients.
//!
//! This crate starts with version negotiation only. Task identity, authority leases,
//! authentication, lifecycle operations and transport belong to later slices of #258,
//! #259 and #262. Incompatible peers fail closed rather than falling back to the
//! per-session ward-daemon control protocol.

#![forbid(unsafe_code)]

use std::fmt::{Display, Formatter};
use std::num::{NonZeroU16, NonZeroU64};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

/// The node protocol version currently implemented by this revision.
///
/// Minor versions are backwards-compatible within one major version. The initial
/// implementation supports only 1.0; later compatible additions widen the supported
/// minor range explicitly.
pub const WARD_NODE_PROTOCOL: SupportedProtocolRange = SupportedProtocolRange::valid(1, 0, 1);

/// The first protocol version that supports node capability discovery.
pub const CAPABILITY_DISCOVERY_PROTOCOL: ProtocolVersion = ProtocolVersion::new(1, 1);

/// One negotiated node protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    /// Construct a protocol version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Major protocol version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Minor protocol version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

/// A contiguous range of minor versions supported for one major protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SupportedProtocolRange {
    major: u16,
    min_minor: u16,
    max_minor: u16,
}

impl SupportedProtocolRange {
    const fn valid(major: u16, min_minor: u16, max_minor: u16) -> Self {
        Self {
            major,
            min_minor,
            max_minor,
        }
    }

    /// Construct a supported protocol range.
    ///
    /// # Errors
    ///
    /// Returns `SupportedProtocolRangeError::InvertedMinorRange` when
    /// `min_minor` is greater than `max_minor`.
    pub const fn new(
        major: u16,
        min_minor: u16,
        max_minor: u16,
    ) -> Result<Self, SupportedProtocolRangeError> {
        if min_minor > max_minor {
            return Err(SupportedProtocolRangeError::InvertedMinorRange);
        }

        Ok(Self::valid(major, min_minor, max_minor))
    }

    /// Major protocol version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Lowest supported minor protocol version.
    #[must_use]
    pub const fn min_minor(self) -> u16 {
        self.min_minor
    }

    /// Highest supported minor protocol version.
    #[must_use]
    pub const fn max_minor(self) -> u16 {
        self.max_minor
    }
}

/// A malformed supported protocol range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupportedProtocolRangeError {
    /// The advertised minimum minor version exceeds the advertised maximum.
    InvertedMinorRange,
}

impl Display for SupportedProtocolRangeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvertedMinorRange => {
                formatter.write_str("minimum supported minor exceeds maximum supported minor")
            }
        }
    }
}

impl std::error::Error for SupportedProtocolRangeError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SupportedProtocolRangeWire {
    major: u16,
    min_minor: u16,
    max_minor: u16,
}

impl<'de> Deserialize<'de> for SupportedProtocolRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SupportedProtocolRangeWire::deserialize(deserializer)?;
        Self::new(wire.major, wire.min_minor, wire.max_minor).map_err(D::Error::custom)
    }
}

/// The first message a node protocol client sends on a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
pub enum HandshakeRequest {
    /// Advertise the protocol range the client can speak.
    Hello {
        /// Client-supported protocol range.
        protocol: SupportedProtocolRange,
    },
}

/// Stable machine-readable reasons a node rejects protocol negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolRejectionReason {
    /// The peers do not implement the same major version.
    MajorVersionMismatch,
    /// The peers share a major version but their supported minor ranges do not overlap.
    NoCommonMinor,
}

/// The node's response to a protocol handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case", deny_unknown_fields)]
pub enum HandshakeResponse {
    /// Both peers support the selected protocol version.
    Accepted {
        /// Highest protocol version both peers support.
        protocol: ProtocolVersion,
    },
    /// No compatible protocol version exists.
    Rejected {
        /// Stable rejection reason for automation and diagnostics.
        reason: ProtocolRejectionReason,
        /// Protocol range supported by the rejecting node.
        supported: SupportedProtocolRange,
    },
}

/// Negotiate the highest mutually supported protocol version.
///
/// Major versions must match exactly. Within one major version the highest common
/// minor version is selected. Incompatibility returns an explicit rejection response;
/// callers must not fall back to the per-session daemon protocol.
#[must_use]
pub const fn negotiate(
    local: SupportedProtocolRange,
    peer: SupportedProtocolRange,
) -> HandshakeResponse {
    if local.major != peer.major {
        return HandshakeResponse::Rejected {
            reason: ProtocolRejectionReason::MajorVersionMismatch,
            supported: local,
        };
    }

    let common_min = if local.min_minor > peer.min_minor {
        local.min_minor
    } else {
        peer.min_minor
    };
    let common_max = if local.max_minor < peer.max_minor {
        local.max_minor
    } else {
        peer.max_minor
    };

    if common_min > common_max {
        return HandshakeResponse::Rejected {
            reason: ProtocolRejectionReason::NoCommonMinor,
            supported: local,
        };
    }

    HandshakeResponse::Accepted {
        protocol: ProtocolVersion::new(local.major, common_max),
    }
}

/// Whether a negotiated protocol version supports capability discovery.
#[must_use]
pub const fn supports_capability_discovery(protocol: ProtocolVersion) -> bool {
    protocol.major == CAPABILITY_DISCOVERY_PROTOCOL.major
        && protocol.minor >= CAPABILITY_DISCOVERY_PROTOCOL.minor
}

/// Architectures the current Ward node protocol can identify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeArchitecture {
    /// 64-bit x86.
    X86_64,
    /// 64-bit ARM.
    Aarch64,
}

/// Validated finite node capacity used for placement decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCapacity {
    logical_cpus: NonZeroU16,
    memory_bytes: NonZeroU64,
}

impl NodeCapacity {
    /// Construct validated node capacity.
    ///
    /// # Errors
    ///
    /// Returns an error when either required capacity is zero.
    pub const fn new(logical_cpus: u16, memory_bytes: u64) -> Result<Self, NodeCapacityError> {
        let Some(logical_cpus) = NonZeroU16::new(logical_cpus) else {
            return Err(NodeCapacityError::ZeroLogicalCpus);
        };
        let Some(memory_bytes) = NonZeroU64::new(memory_bytes) else {
            return Err(NodeCapacityError::ZeroMemoryBytes);
        };

        Ok(Self {
            logical_cpus,
            memory_bytes,
        })
    }

    /// Logical CPU capacity.
    #[must_use]
    pub const fn logical_cpus(self) -> u16 {
        self.logical_cpus.get()
    }

    /// Memory capacity in bytes.
    #[must_use]
    pub const fn memory_bytes(self) -> u64 {
        self.memory_bytes.get()
    }
}

/// Invalid node capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeCapacityError {
    /// A node cannot advertise zero logical CPUs.
    ZeroLogicalCpus,
    /// A node cannot advertise zero bytes of memory.
    ZeroMemoryBytes,
}

impl Display for NodeCapacityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroLogicalCpus => formatter.write_str("logical CPU capacity must be non-zero"),
            Self::ZeroMemoryBytes => formatter.write_str("memory capacity must be non-zero"),
        }
    }
}

impl std::error::Error for NodeCapacityError {}

/// Namespace isolation mechanisms a node can enforce locally.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceCapabilities {
    /// Ward's Linux namespace sandbox backend.
    pub sandbox: bool,
    /// Unprivileged user namespaces are available where required.
    pub user_namespace: bool,
}

/// Execution isolation backends available on a node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBackendCapabilities {
    /// Container-backed task isolation is available.
    pub container: bool,
    /// MicroVM-backed task isolation is available.
    pub microvm: bool,
    /// VM-backed task isolation is available.
    pub vm: bool,
}

/// Isolation mechanisms a node can enforce locally.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationCapabilities {
    /// Namespace-related isolation support.
    pub namespaces: NamespaceCapabilities,
    /// Supported execution isolation backends.
    pub backends: ExecutionBackendCapabilities,
}

/// Network enforcement mechanisms a node can enforce locally.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCapabilities {
    /// The node can enforce an offline/no-egress task.
    pub offline: bool,
    /// The node can enforce proxy-mediated destination allowlists.
    pub proxy_allowlist: bool,
}

/// Credential delivery mechanisms a node can enforce locally.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialCapabilities {
    /// Credentials can be injected by a node-owned proxy without entering the sandbox.
    pub proxy_injection: bool,
    /// Scoped HTTP gateway routes can be granted to a task.
    pub scoped_http_gateway: bool,
}

/// Snapshot and content-addressed storage mechanisms available on a node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCapabilities {
    /// Content-addressed immutable snapshots are available.
    pub content_addressed: bool,
    /// Snapshot manifests can be diffed.
    pub diff: bool,
    /// Immutable snapshot content can be read by trusted components.
    pub read: bool,
}

/// Independent verifier capabilities available on a node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierCapabilities {
    /// The node can run the trusted verifier outside task authority.
    pub isolated: bool,
}

/// Host-confirmed lifecycle operations available on a node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCapabilities {
    /// Running work can be paused by the host boundary.
    pub pause: bool,
    /// Running work can be stopped by the host boundary.
    pub stop: bool,
    /// Temporary grants can be revoked by the host boundary.
    pub revoke: bool,
}

/// Trusted, read-only node facts exposed after a compatible handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct NodeCapabilities {
    protocol: ProtocolVersion,
    architecture: NodeArchitecture,
    capacity: NodeCapacity,
    isolation: IsolationCapabilities,
    network: NetworkCapabilities,
    credentials: CredentialCapabilities,
    snapshots: SnapshotCapabilities,
    verifier: VerifierCapabilities,
    lifecycle: LifecycleCapabilities,
}

impl NodeCapabilities {
    /// Construct a capability document for a negotiated protocol.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected protocol predates capability discovery.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        protocol: ProtocolVersion,
        architecture: NodeArchitecture,
        capacity: NodeCapacity,
        isolation: IsolationCapabilities,
        network: NetworkCapabilities,
        credentials: CredentialCapabilities,
        snapshots: SnapshotCapabilities,
        verifier: VerifierCapabilities,
        lifecycle: LifecycleCapabilities,
    ) -> Result<Self, NodeCapabilitiesError> {
        if !supports_capability_discovery(protocol) {
            return Err(NodeCapabilitiesError::ProtocolDoesNotSupportDiscovery);
        }

        Ok(Self {
            protocol,
            architecture,
            capacity,
            isolation,
            network,
            credentials,
            snapshots,
            verifier,
            lifecycle,
        })
    }

    /// Negotiated protocol version this document belongs to.
    #[must_use]
    pub const fn protocol(self) -> ProtocolVersion {
        self.protocol
    }

    /// Node architecture.
    #[must_use]
    pub const fn architecture(self) -> NodeArchitecture {
        self.architecture
    }

    /// Node capacity.
    #[must_use]
    pub const fn capacity(self) -> NodeCapacity {
        self.capacity
    }

    /// Isolation capabilities.
    #[must_use]
    pub const fn isolation(self) -> IsolationCapabilities {
        self.isolation
    }

    /// Network capabilities.
    #[must_use]
    pub const fn network(self) -> NetworkCapabilities {
        self.network
    }

    /// Credential capabilities.
    #[must_use]
    pub const fn credentials(self) -> CredentialCapabilities {
        self.credentials
    }

    /// Snapshot capabilities.
    #[must_use]
    pub const fn snapshots(self) -> SnapshotCapabilities {
        self.snapshots
    }

    /// Verifier capabilities.
    #[must_use]
    pub const fn verifier(self) -> VerifierCapabilities {
        self.verifier
    }

    /// Lifecycle capabilities.
    #[must_use]
    pub const fn lifecycle(self) -> LifecycleCapabilities {
        self.lifecycle
    }
}

/// Invalid capability document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeCapabilitiesError {
    /// Capability discovery was attempted under a protocol version that does not support it.
    ProtocolDoesNotSupportDiscovery,
}

impl Display for NodeCapabilitiesError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProtocolDoesNotSupportDiscovery => {
                formatter.write_str("protocol version does not support capability discovery")
            }
        }
    }
}

impl std::error::Error for NodeCapabilitiesError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeCapabilitiesWire {
    protocol: ProtocolVersion,
    architecture: NodeArchitecture,
    capacity: NodeCapacity,
    isolation: IsolationCapabilities,
    network: NetworkCapabilities,
    credentials: CredentialCapabilities,
    snapshots: SnapshotCapabilities,
    verifier: VerifierCapabilities,
    lifecycle: LifecycleCapabilities,
}

impl NodeCapabilitiesWire {
    fn into_capabilities(self) -> Result<NodeCapabilities, NodeCapabilitiesError> {
        NodeCapabilities::new(
            self.protocol,
            self.architecture,
            self.capacity,
            self.isolation,
            self.network,
            self.credentials,
            self.snapshots,
            self.verifier,
            self.lifecycle,
        )
    }
}

/// Read-only node capability discovery request.
///
/// This semantic type is serializable but intentionally not directly deserializable.
/// Incoming wire data must be decoded through [`CapabilityDiscoveryContext`], which
/// binds it to the protocol version selected by the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum CapabilityDiscoveryRequest {
    /// Request the node-owned capability document.
    Capabilities,
}

#[derive(Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
enum CapabilityDiscoveryRequestWire {
    Capabilities,
}

/// Read-only node capability discovery response.
///
/// Incoming wire data is accepted only through [`CapabilityDiscoveryContext`] so the
/// capability document must name the exact negotiated protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum CapabilityDiscoveryResponse {
    /// Trusted host facts for the negotiated protocol version.
    Capabilities {
        /// Node-owned capability document.
        capabilities: NodeCapabilities,
    },
}

#[derive(Deserialize)]
#[serde(tag = "response", rename_all = "snake_case", deny_unknown_fields)]
enum CapabilityDiscoveryResponseWire {
    Capabilities {
        capabilities: NodeCapabilitiesWire,
    },
}

/// A negotiated capability-discovery protocol context.
///
/// Constructing this context proves that discovery is available for the selected
/// handshake version. All inbound discovery messages are decoded through this value,
/// preventing a transport from accepting capability wire data without checking the
/// negotiated protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityDiscoveryContext {
    protocol: ProtocolVersion,
}

impl CapabilityDiscoveryContext {
    /// Bind capability discovery to the exact protocol selected by the handshake.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityDiscoveryError::ProtocolDoesNotSupportDiscovery`] when the
    /// selected protocol predates capability discovery.
    pub const fn new(protocol: ProtocolVersion) -> Result<Self, CapabilityDiscoveryError> {
        if !supports_capability_discovery(protocol) {
            return Err(CapabilityDiscoveryError::ProtocolDoesNotSupportDiscovery);
        }

        Ok(Self { protocol })
    }

    /// Exact protocol version selected by the handshake.
    #[must_use]
    pub const fn protocol(self) -> ProtocolVersion {
        self.protocol
    }

    /// Build the only read-only discovery request valid for this negotiated context.
    #[must_use]
    pub const fn request(self) -> CapabilityDiscoveryRequest {
        CapabilityDiscoveryRequest::Capabilities
    }

    /// Decode an inbound discovery request under the negotiated protocol.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityDiscoveryError::MalformedMessage`] for any unknown,
    /// malformed or unsupported wire value.
    pub fn decode_request(
        self,
        json: &str,
    ) -> Result<CapabilityDiscoveryRequest, CapabilityDiscoveryError> {
        let wire = serde_json::from_str::<CapabilityDiscoveryRequestWire>(json)
            .map_err(|_| CapabilityDiscoveryError::MalformedMessage)?;

        match wire {
            CapabilityDiscoveryRequestWire::Capabilities => {
                Ok(CapabilityDiscoveryRequest::Capabilities)
            }
        }
    }

    /// Build a discovery response bound to the exact negotiated protocol.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityDiscoveryError::ProtocolMismatch`] if the supplied
    /// capability document names any other protocol version.
    pub const fn response(
        self,
        capabilities: NodeCapabilities,
    ) -> Result<CapabilityDiscoveryResponse, CapabilityDiscoveryError> {
        if capabilities.protocol != self.protocol {
            return Err(CapabilityDiscoveryError::ProtocolMismatch);
        }

        Ok(CapabilityDiscoveryResponse::Capabilities { capabilities })
    }

    /// Decode and validate an inbound discovery response.
    ///
    /// # Errors
    ///
    /// Rejects malformed wire data, capability documents invalid for discovery, and any
    /// document whose protocol does not exactly equal the handshake-selected version.
    pub fn decode_response(
        self,
        json: &str,
    ) -> Result<CapabilityDiscoveryResponse, CapabilityDiscoveryError> {
        let wire = serde_json::from_str::<CapabilityDiscoveryResponseWire>(json)
            .map_err(|_| CapabilityDiscoveryError::MalformedMessage)?;

        match wire {
            CapabilityDiscoveryResponseWire::Capabilities { capabilities } => {
                let capabilities = capabilities
                    .into_capabilities()
                    .map_err(|_| CapabilityDiscoveryError::MalformedMessage)?;
                self.response(capabilities)
            }
        }
    }
}

/// Fail-closed capability-discovery protocol errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityDiscoveryError {
    /// The negotiated protocol predates capability discovery.
    ProtocolDoesNotSupportDiscovery,
    /// The capability document names a protocol other than the negotiated version.
    ProtocolMismatch,
    /// The discovery message is malformed, unknown or contains invalid capability data.
    MalformedMessage,
}

impl Display for CapabilityDiscoveryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProtocolDoesNotSupportDiscovery => {
                formatter.write_str("protocol version does not support capability discovery")
            }
            Self::ProtocolMismatch => {
                formatter.write_str("capability document protocol does not match negotiated protocol")
            }
            Self::MalformedMessage => formatter.write_str("capability discovery message is invalid"),
        }
    }
}

impl std::error::Error for CapabilityDiscoveryError {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn range(major: u16, min_minor: u16, max_minor: u16) -> SupportedProtocolRange {
        SupportedProtocolRange::new(major, min_minor, max_minor).unwrap()
    }

    #[test]
    fn previous_minor_negotiates_to_highest_common_version() {
        let local = range(1, 1, 2);
        let previous_minor_peer = range(1, 0, 1);

        assert_eq!(
            negotiate(local, previous_minor_peer),
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 1),
            }
        );
        assert_eq!(
            negotiate(local, previous_minor_peer),
            negotiate(previous_minor_peer, local)
        );
    }

    #[test]
    fn exact_minor_match_is_accepted() {
        let supported = range(1, 0, 0);

        assert_eq!(
            negotiate(supported, supported),
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 0),
            }
        );
    }

    #[test]
    fn major_mismatch_fails_closed_with_stable_reason() {
        let local = range(1, 0, 2);
        let peer = range(2, 0, 2);

        assert_eq!(
            negotiate(local, peer),
            HandshakeResponse::Rejected {
                reason: ProtocolRejectionReason::MajorVersionMismatch,
                supported: local,
            }
        );
    }

    #[test]
    fn disjoint_minor_ranges_fail_closed_with_stable_reason() {
        let local = range(1, 2, 3);
        let peer = range(1, 0, 1);

        assert_eq!(
            negotiate(local, peer),
            HandshakeResponse::Rejected {
                reason: ProtocolRejectionReason::NoCommonMinor,
                supported: local,
            }
        );
    }

    #[test]
    fn inverted_minor_range_is_rejected_at_construction_and_deserialisation() {
        assert_eq!(
            SupportedProtocolRange::new(1, 2, 1),
            Err(SupportedProtocolRangeError::InvertedMinorRange)
        );

        let error = serde_json::from_str::<SupportedProtocolRange>(
            r#"{"major":1,"min_minor":2,"max_minor":1}"#,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("minimum supported minor exceeds maximum supported minor"),
            "{error}"
        );
    }

    #[test]
    fn handshake_wire_shape_is_stable_and_machine_readable() {
        let protocol = range(1, 0, 1);
        let request = HandshakeRequest::Hello { protocol };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"request":"hello","protocol":{"major":1,"min_minor":0,"max_minor":1}}"#
        );
        assert_eq!(
            serde_json::from_str::<HandshakeRequest>(
                r#"{"request":"hello","protocol":{"major":1,"min_minor":0,"max_minor":1}}"#,
            )
            .unwrap(),
            request
        );

        let accepted = HandshakeResponse::Accepted {
            protocol: ProtocolVersion::new(1, 1),
        };
        assert_eq!(
            serde_json::to_string(&accepted).unwrap(),
            r#"{"response":"accepted","protocol":{"major":1,"minor":1}}"#
        );

        let rejected = HandshakeResponse::Rejected {
            reason: ProtocolRejectionReason::MajorVersionMismatch,
            supported: protocol,
        };
        assert_eq!(
            serde_json::to_string(&rejected).unwrap(),
            r#"{"response":"rejected","reason":"major_version_mismatch","supported":{"major":1,"min_minor":0,"max_minor":1}}"#
        );
    }

    #[test]
    fn handshake_wire_rejects_unknown_fields() {
        for raw in [
            r#"{"request":"hello","protocol":{"major":1,"min_minor":0,"max_minor":1},"extra":true}"#,
            r#"{"request":"hello","protocol":{"major":1,"min_minor":0,"max_minor":1,"extra":true}}"#,
        ] {
            assert!(
                serde_json::from_str::<HandshakeRequest>(raw).is_err(),
                "{raw} must fail closed"
            );
        }

        for raw in [
            r#"{"response":"accepted","protocol":{"major":1,"minor":0},"extra":true}"#,
            r#"{"response":"accepted","protocol":{"major":1,"minor":0,"extra":true}}"#,
            r#"{"response":"rejected","reason":"major_version_mismatch","supported":{"major":1,"min_minor":0,"max_minor":0},"extra":true}"#,
        ] {
            assert!(
                serde_json::from_str::<HandshakeResponse>(raw).is_err(),
                "{raw} must fail closed"
            );
        }
    }

    #[test]
    fn current_protocol_supports_one_zero_through_one_one() {
        assert_eq!(WARD_NODE_PROTOCOL.major(), 1);
        assert_eq!(WARD_NODE_PROTOCOL.min_minor(), 0);
        assert_eq!(WARD_NODE_PROTOCOL.max_minor(), 1);
    }

    fn minimal_capabilities() -> NodeCapabilities {
        NodeCapabilities::new(
            ProtocolVersion::new(1, 1),
            NodeArchitecture::X86_64,
            NodeCapacity::new(1, 1024).unwrap(),
            IsolationCapabilities {
                namespaces: NamespaceCapabilities {
                    sandbox: false,
                    user_namespace: false,
                },
                backends: ExecutionBackendCapabilities {
                    container: false,
                    microvm: false,
                    vm: false,
                },
            },
            NetworkCapabilities {
                offline: false,
                proxy_allowlist: false,
            },
            CredentialCapabilities {
                proxy_injection: false,
                scoped_http_gateway: false,
            },
            SnapshotCapabilities {
                content_addressed: false,
                diff: false,
                read: false,
            },
            VerifierCapabilities { isolated: false },
            LifecycleCapabilities {
                pause: false,
                stop: false,
                revoke: false,
            },
        )
        .unwrap()
    }

    fn full_capabilities() -> NodeCapabilities {
        NodeCapabilities::new(
            ProtocolVersion::new(1, 1),
            NodeArchitecture::Aarch64,
            NodeCapacity::new(64, 137_438_953_472).unwrap(),
            IsolationCapabilities {
                namespaces: NamespaceCapabilities {
                    sandbox: true,
                    user_namespace: true,
                },
                backends: ExecutionBackendCapabilities {
                    container: true,
                    microvm: true,
                    vm: true,
                },
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

    #[test]
    fn capability_discovery_is_a_protocol_one_one_feature() {
        assert!(!supports_capability_discovery(ProtocolVersion::new(1, 0)));
        assert!(supports_capability_discovery(ProtocolVersion::new(1, 1)));
        assert!(supports_capability_discovery(ProtocolVersion::new(1, 2)));
        assert!(!supports_capability_discovery(ProtocolVersion::new(2, 0)));

        assert_eq!(
            CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 0)),
            Err(CapabilityDiscoveryError::ProtocolDoesNotSupportDiscovery)
        );
    }

    #[test]
    fn minimal_capability_discovery_wire_is_stable() {
        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 1)).unwrap();
        let request = context.request();
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"request":"capabilities"}"#
        );
        assert_eq!(
            context
                .decode_request(r#"{"request":"capabilities"}"#)
                .unwrap(),
            request
        );

        let response = context.response(minimal_capabilities()).unwrap();
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            json,
            r#"{"response":"capabilities","capabilities":{"protocol":{"major":1,"minor":1},"architecture":"x86_64","capacity":{"logical_cpus":1,"memory_bytes":1024},"isolation":{"namespaces":{"sandbox":false,"user_namespace":false},"backends":{"container":false,"microvm":false,"vm":false}},"network":{"offline":false,"proxy_allowlist":false},"credentials":{"proxy_injection":false,"scoped_http_gateway":false},"snapshots":{"content_addressed":false,"diff":false,"read":false},"verifier":{"isolated":false},"lifecycle":{"pause":false,"stop":false,"revoke":false}}}"#
        );
        assert_eq!(context.decode_response(&json).unwrap(), response);
    }

    #[test]
    fn fully_capable_node_wire_is_stable() {
        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 1)).unwrap();
        let response = context.response(full_capabilities()).unwrap();
        assert_eq!(
            serde_json::to_string(&response).unwrap(),
            r#"{"response":"capabilities","capabilities":{"protocol":{"major":1,"minor":1},"architecture":"aarch64","capacity":{"logical_cpus":64,"memory_bytes":137438953472},"isolation":{"namespaces":{"sandbox":true,"user_namespace":true},"backends":{"container":true,"microvm":true,"vm":true}},"network":{"offline":true,"proxy_allowlist":true},"credentials":{"proxy_injection":true,"scoped_http_gateway":true},"snapshots":{"content_addressed":true,"diff":true,"read":true},"verifier":{"isolated":true},"lifecycle":{"pause":true,"stop":true,"revoke":true}}}"#
        );
    }

    #[test]
    fn capability_response_must_match_the_exact_negotiated_protocol() {
        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 1)).unwrap();

        for claimed_minor in [0, 2] {
            let raw = format!(
                r#"{{"response":"capabilities","capabilities":{{"protocol":{{"major":1,"minor":{claimed_minor}}},"architecture":"x86_64","capacity":{{"logical_cpus":1,"memory_bytes":1024}},"isolation":{{"namespaces":{{"sandbox":false,"user_namespace":false}},"backends":{{"container":false,"microvm":false,"vm":false}}}},"network":{{"offline":false,"proxy_allowlist":false}},"credentials":{{"proxy_injection":false,"scoped_http_gateway":false}},"snapshots":{{"content_addressed":false,"diff":false,"read":false}},"verifier":{{"isolated":false}},"lifecycle":{{"pause":false,"stop":false,"revoke":false}}}}}}"#
            );
            assert_eq!(
                context.decode_response(&raw),
                Err(CapabilityDiscoveryError::ProtocolMismatch),
                "claimed protocol 1.{claimed_minor} must not be accepted for negotiated 1.1"
            );
        }
    }

    #[test]
    fn invalid_or_unknown_capability_facts_fail_closed() {
        assert_eq!(
            NodeCapacity::new(0, 1024),
            Err(NodeCapacityError::ZeroLogicalCpus)
        );
        assert_eq!(
            NodeCapacity::new(1, 0),
            Err(NodeCapacityError::ZeroMemoryBytes)
        );
        assert_eq!(
            NodeCapabilities::new(
                ProtocolVersion::new(1, 0),
                NodeArchitecture::X86_64,
                NodeCapacity::new(1, 1024).unwrap(),
                IsolationCapabilities::default(),
                NetworkCapabilities::default(),
                CredentialCapabilities::default(),
                SnapshotCapabilities::default(),
                VerifierCapabilities::default(),
                LifecycleCapabilities::default(),
            ),
            Err(NodeCapabilitiesError::ProtocolDoesNotSupportDiscovery)
        );

        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 1)).unwrap();
        for raw in [
            r#"{"request":"capabilities","extra":true}"#,
            r#"{"response":"capabilities","capabilities":{"protocol":{"major":1,"minor":1},"architecture":"sparc","capacity":{"logical_cpus":1,"memory_bytes":1024},"isolation":{"namespaces":{"sandbox":false,"user_namespace":false},"backends":{"container":false,"microvm":false,"vm":false}},"network":{"offline":false,"proxy_allowlist":false},"credentials":{"proxy_injection":false,"scoped_http_gateway":false},"snapshots":{"content_addressed":false,"diff":false,"read":false},"verifier":{"isolated":false},"lifecycle":{"pause":false,"stop":false,"revoke":false}}}"#,
            r#"{"response":"capabilities","capabilities":{"protocol":{"major":1,"minor":1},"architecture":"x86_64","capacity":{"logical_cpus":0,"memory_bytes":1024},"isolation":{"namespaces":{"sandbox":false,"user_namespace":false},"backends":{"container":false,"microvm":false,"vm":false}},"network":{"offline":false,"proxy_allowlist":false},"credentials":{"proxy_injection":false,"scoped_http_gateway":false},"snapshots":{"content_addressed":false,"diff":false,"read":false},"verifier":{"isolated":false},"lifecycle":{"pause":false,"stop":false,"revoke":false}}}"#,
            r#"{"response":"capabilities","capabilities":{"protocol":{"major":1,"minor":1},"architecture":"x86_64","capacity":{"logical_cpus":1,"memory_bytes":1024},"isolation":{"namespaces":{"sandbox":false,"user_namespace":false},"backends":{"container":false,"microvm":false,"vm":false}},"network":{"offline":false,"proxy_allowlist":false},"credentials":{"proxy_injection":false,"scoped_http_gateway":false},"snapshots":{"content_addressed":false,"diff":false,"read":false},"verifier":{"isolated":false},"lifecycle":{"pause":false,"stop":false,"revoke":false},"extra":true}}"#,
        ] {
            let failed = if raw.contains(r#""request":"#) {
                context.decode_request(raw).is_err()
            } else {
                context.decode_response(raw).is_err()
            };
            assert!(failed, "{raw} must fail closed");
        }
    }

}
