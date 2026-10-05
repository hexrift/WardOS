//! ward-node-protocol: dependency-light protocol contracts shared by ward-node and its
//! local or remote clients.
//!
//! Protocol 1.0 negotiates a version, 1.1 adds read-only capability discovery, 1.2 adds
//! the identity-only task lifecycle, and 1.3 adds the signed admission envelope (`admit`),
//! its typed capability manifest, the `exited` state and the receipt outcome on `inspect`
//! of ADR-0030, and the `unsupported_grant` refusal of a manifest the node cannot honour.
//! Issuer verification and execution are the node's (`ward-node`); transport
//! authentication belongs to #262. A 1.3 capability document may advertise `admit`, and `start` and
//! `stop` only together. Incompatible peers fail closed rather than falling back to the
//! per-session ward-daemon control protocol.

#![forbid(unsafe_code)]

mod admission;
mod receipt;
#[cfg(test)]
mod test_fixtures;

pub use admission::{
    AdmissionEnvelopeJson, AdmissionVersion, CapabilityManifest, CapabilityManifestBytes,
    HostAllowlist, IssuerProof, IssuerSignature, MAX_ADMISSION_ENVELOPE_BYTES,
    MAX_ADMISSION_LINEAGE, NetworkGrant, TaskAdmissionAuthority, TaskAdmissionEnvelope,
    TaskAdmissionEnvelopeInput, TaskAdmissionError, TaskWorkload, WorkloadArgv,
};
pub use receipt::{
    TaskExecutionOutcome, TaskExecutionReceipt, TaskReceiptContext, TaskReceiptError,
};

use std::fmt::{Display, Formatter};
use std::num::{NonZeroU16, NonZeroU64};

use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ward_events::{ExecutionAttemptId, LeaseId, TaskId};

/// The node protocol version currently implemented by this revision.
///
/// Minor versions are backwards-compatible within one major version; each compatible
/// addition widens the supported minor range explicitly. This revision supports 1.0
/// through 1.3.
pub const WARD_NODE_PROTOCOL: SupportedProtocolRange = SupportedProtocolRange::valid(1, 0, 3);

/// The first protocol version that supports node capability discovery.
pub const CAPABILITY_DISCOVERY_PROTOCOL: ProtocolVersion = ProtocolVersion::new(1, 1);

/// The first protocol version that supports task lifecycle messages.
pub const TASK_LIFECYCLE_PROTOCOL: ProtocolVersion = ProtocolVersion::new(1, 2);

/// The first protocol version that supports task admission and the `exited` state.
pub const TASK_ADMISSION_PROTOCOL: ProtocolVersion = ProtocolVersion::new(1, 3);

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
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCapabilities {
    /// Running work can be paused by the host boundary.
    pub pause: bool,
    /// Running work can be stopped by the host boundary.
    pub stop: bool,
    /// The node serves `revoke`: it durably revokes a task's lease, so no later admission
    /// or start under that lease (or a lease delegated from it) is accepted, and kills and
    /// reaps the task's workload.
    pub revoke: bool,
    /// Signed admission envelopes are verified and admitted (`admit`). Protocol 1.3 and
    /// later only: a document for an earlier version never carries this field, and a 1.3
    /// document carries it only when it is `true`.
    #[serde(default)]
    pub admit: bool,
    /// Admitted tasks can be started (`start`). Protocol 1.3 and later only, and only
    /// together with `stop`: a 1.3 document advertises both or neither, carrying
    /// `"start":true` only when it is `true`; an earlier document never carries it.
    #[serde(default)]
    pub start: bool,
}

/// Trusted, read-only node facts exposed after a compatible handshake.
///
/// The `lifecycle.admit` field is version-gated on the wire: a 1.3 or later document carries
/// `"admit":true` only when the node admits signed envelopes (absent means `false`), and a
/// 1.1 or 1.2 document never carries it, so those stay byte-for-byte unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        if lifecycle.admit && !supports_task_admission(protocol) {
            return Err(NodeCapabilitiesError::ProtocolDoesNotSupportAdmission);
        }
        if lifecycle.start && !supports_task_admission(protocol) {
            return Err(NodeCapabilitiesError::ProtocolDoesNotSupportExecution);
        }
        if supports_task_admission(protocol) && lifecycle.start != lifecycle.stop {
            return Err(NodeCapabilitiesError::UnpairedStartAndStop);
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
    /// `admit` was advertised under a protocol version that predates task admission.
    ProtocolDoesNotSupportAdmission,
    /// `start` was advertised under a protocol version that predates node execution.
    ProtocolDoesNotSupportExecution,
    /// A protocol 1.3 or later document advertised `start` without `stop`, or `stop`
    /// without `start`.
    UnpairedStartAndStop,
}

impl Display for NodeCapabilitiesError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProtocolDoesNotSupportDiscovery => {
                formatter.write_str("protocol version does not support capability discovery")
            }
            Self::ProtocolDoesNotSupportAdmission => {
                formatter.write_str("protocol version does not support task admission")
            }
            Self::ProtocolDoesNotSupportExecution => {
                formatter.write_str("protocol version does not support task execution")
            }
            Self::UnpairedStartAndStop => {
                formatter.write_str("start and stop must be advertised together")
            }
        }
    }
}

impl std::error::Error for NodeCapabilitiesError {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleCapabilitiesWire {
    pause: bool,
    stop: bool,
    revoke: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_bool"
    )]
    admit: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_bool"
    )]
    start: Option<bool>,
}

fn deserialize_present_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    bool::deserialize(deserializer).map(Some)
}

#[derive(Serialize, Deserialize)]
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
    lifecycle: LifecycleCapabilitiesWire,
}

impl NodeCapabilitiesWire {
    fn into_capabilities(self) -> Option<NodeCapabilities> {
        let admit = one_three_flag(self.protocol, self.lifecycle.admit)?;
        let start = one_three_flag(self.protocol, self.lifecycle.start)?;
        NodeCapabilities::new(
            self.protocol,
            self.architecture,
            self.capacity,
            self.isolation,
            self.network,
            self.credentials,
            self.snapshots,
            self.verifier,
            LifecycleCapabilities {
                pause: self.lifecycle.pause,
                stop: self.lifecycle.stop,
                revoke: self.lifecycle.revoke,
                admit,
                start,
            },
        )
        .ok()
    }
}

/// A lifecycle flag that only protocol 1.3 and later documents may carry.
const fn one_three_flag(protocol: ProtocolVersion, flag: Option<bool>) -> Option<bool> {
    match (supports_task_admission(protocol), flag) {
        (true, Some(flag)) => Some(flag),
        (_, None) => Some(false),
        (false, Some(_)) => None,
    }
}

impl Serialize for NodeCapabilities {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        NodeCapabilitiesWire {
            protocol: self.protocol,
            architecture: self.architecture,
            capacity: self.capacity,
            isolation: self.isolation,
            network: self.network,
            credentials: self.credentials,
            snapshots: self.snapshots,
            verifier: self.verifier,
            lifecycle: LifecycleCapabilitiesWire {
                pause: self.lifecycle.pause,
                stop: self.lifecycle.stop,
                revoke: self.lifecycle.revoke,
                admit: self.lifecycle.admit.then_some(true),
                start: self.lifecycle.start.then_some(true),
            },
        }
        .serialize(serializer)
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
    Capabilities {
        /// Exact protocol version selected by the handshake.
        protocol: ProtocolVersion,
    },
}

#[derive(Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
enum CapabilityDiscoveryRequestWire {
    Capabilities { protocol: ProtocolVersion },
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
    Capabilities { capabilities: NodeCapabilitiesWire },
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
        if protocol.major != WARD_NODE_PROTOCOL.major
            || protocol.minor > WARD_NODE_PROTOCOL.max_minor
        {
            return Err(CapabilityDiscoveryError::ProtocolOutsideSupportedRange);
        }

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
        CapabilityDiscoveryRequest::Capabilities {
            protocol: self.protocol,
        }
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
            CapabilityDiscoveryRequestWire::Capabilities { protocol } => {
                if protocol != self.protocol {
                    return Err(CapabilityDiscoveryError::ProtocolMismatch);
                }

                Ok(CapabilityDiscoveryRequest::Capabilities { protocol })
            }
        }
    }

    /// Build a discovery response bound to the exact negotiated protocol.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityDiscoveryError::ProtocolMismatch`] if the supplied
    /// capability document names any other protocol version.
    pub fn response(
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
                if capabilities.protocol != self.protocol {
                    return Err(CapabilityDiscoveryError::ProtocolMismatch);
                }

                let capabilities = capabilities
                    .into_capabilities()
                    .ok_or(CapabilityDiscoveryError::MalformedMessage)?;
                self.response(capabilities)
            }
        }
    }
}

/// Fail-closed capability-discovery protocol errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityDiscoveryError {
    /// The supplied protocol is outside the range implemented by this build.
    ProtocolOutsideSupportedRange,
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
            Self::ProtocolOutsideSupportedRange => {
                formatter.write_str("protocol version is outside this build's supported range")
            }
            Self::ProtocolDoesNotSupportDiscovery => {
                formatter.write_str("protocol version does not support capability discovery")
            }
            Self::ProtocolMismatch => formatter
                .write_str("capability document protocol does not match negotiated protocol"),
            Self::MalformedMessage => {
                formatter.write_str("capability discovery message is invalid")
            }
        }
    }
}

impl std::error::Error for CapabilityDiscoveryError {}

/// Whether a negotiated protocol version supports task lifecycle messages.
#[must_use]
pub const fn supports_task_lifecycle(protocol: ProtocolVersion) -> bool {
    protocol.major == TASK_LIFECYCLE_PROTOCOL.major
        && protocol.minor >= TASK_LIFECYCLE_PROTOCOL.minor
}

/// Whether a negotiated protocol version supports task admission and the `exited` state.
#[must_use]
pub const fn supports_task_admission(protocol: ProtocolVersion) -> bool {
    protocol.major == TASK_ADMISSION_PROTOCOL.major
        && protocol.minor >= TASK_ADMISSION_PROTOCOL.minor
}

const fn supports_state(protocol: ProtocolVersion, state: TaskLifecycleState) -> bool {
    match state {
        TaskLifecycleState::Exited => supports_task_admission(protocol),
        TaskLifecycleState::Created
        | TaskLifecycleState::Ready
        | TaskLifecycleState::Running
        | TaskLifecycleState::Paused
        | TaskLifecycleState::Stopped
        | TaskLifecycleState::Revoked
        | TaskLifecycleState::Sealed => true,
    }
}

/// Stable idempotency identity for one mutating lifecycle command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationId(NonZeroU64);

impl OperationId {
    /// Construct a non-zero operation identity.
    ///
    /// # Errors
    ///
    /// Returns [`OperationIdError::Zero`] if `value` is zero.
    pub const fn new(value: u64) -> Result<Self, OperationIdError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(OperationIdError::Zero),
        }
    }

    /// The wrapped non-zero value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl From<NonZeroU64> for OperationId {
    fn from(value: NonZeroU64) -> Self {
        Self(value)
    }
}

/// Reasons [`OperationId::new`] can be refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationIdError {
    /// The supplied value was zero, which is not a valid operation id.
    Zero,
}

impl Display for OperationIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("lifecycle operation id must be non-zero")
    }
}

impl std::error::Error for OperationIdError {}

/// Immutable task, execution-attempt and authority-lease identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBinding {
    task: TaskId,
    attempt: ExecutionAttemptId,
    lease: LeaseId,
}

impl TaskBinding {
    /// Bind a task, its execution attempt and the authority lease covering it.
    #[must_use]
    pub const fn new(task: TaskId, attempt: ExecutionAttemptId, lease: LeaseId) -> Self {
        Self {
            task,
            attempt,
            lease,
        }
    }

    /// The bound task's identity.
    #[must_use]
    pub const fn task(self) -> TaskId {
        self.task
    }

    /// The bound execution attempt's identity.
    #[must_use]
    pub const fn attempt(self) -> ExecutionAttemptId {
        self.attempt
    }

    /// The authority lease this binding was authorized under.
    #[must_use]
    pub const fn lease(self) -> LeaseId {
        self.lease
    }
}

/// The lifecycle state of a task as reported by a lifecycle response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskLifecycleState {
    /// The task has been created but has not yet started running.
    Created,
    /// The task is admitted and ready to start.
    Ready,
    /// The task is actively running.
    Running,
    /// The task's execution is paused.
    Paused,
    /// The task's workloads have been terminated.
    Stopped,
    /// The task's workload exited on its own, without an operator stop. Protocol 1.3 and
    /// later only.
    Exited,
    /// The task's authority lease has been revoked.
    Revoked,
    /// The task's evidence has been sealed; the task is terminal.
    Sealed,
}

/// Why a lifecycle request was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskLifecycleRejectionReason {
    /// The referenced task is not known to the node.
    TaskNotFound,
    /// The request's execution attempt does not match the task's current attempt.
    AttemptMismatch,
    /// The request's lease does not match the task's current lease.
    LeaseMismatch,
    /// The request's lease has expired.
    LeaseExpired,
    /// The request's lease has been revoked.
    LeaseRevoked,
    /// The request is stale. It covers two cases:
    ///
    /// * for `admit`, the admission envelope's `version` is not greater than the last
    ///   version the node durably accepted for the same task (an old or replayed
    ///   envelope, including after a node restart);
    /// * for any mutating verb, the request's idempotency id has already been superseded
    ///   by a later operation on the task, or names an execution attempt that a later
    ///   attempt of the task has replaced.
    StaleOperation,
    /// The task is not in a state that allows this operation.
    InvalidState,
    /// The bound authority lease does not grant this operation.
    AuthorityDenied,
    /// The admission envelope's capability manifest asks for a grant this node cannot
    /// honour, so the task was not admitted and no version was consumed. Protocol 1.3 and
    /// later, from `admit` only; a node that honours only `offline` refuses every other
    /// network grant this way.
    UnsupportedGrant,
    /// A resource required to service the request is unavailable.
    ResourceUnavailable,
    /// The negotiated protocol version, or the node implementation serving it, does not
    /// support this operation. The request was not applied.
    UnsupportedOperation,
}

/// Version-bound task lifecycle request. Inbound data is decoded through `TaskLifecycleContext`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum TaskLifecycleRequest {
    /// Create the task's execution attempt.
    Create {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// Idempotency identity for this mutating command.
        operation_id: OperationId,
        /// The task/attempt/lease this command applies to.
        binding: TaskBinding,
    },
    /// Admit a created task's workload and authority. Protocol 1.3 and later only.
    ///
    /// The envelope travels as the exact bytes the issuer signed. A receiver verifies
    /// `proof` over `envelope_json` before decoding it, and then requires the decoded
    /// envelope's binding to equal `binding`.
    Admit {
        /// The negotiated protocol version this message is bound to.
        #[serde(serialize_with = "serialize_admission_protocol")]
        protocol: ProtocolVersion,
        /// Idempotency identity for this mutating command.
        operation_id: OperationId,
        /// The task/attempt/lease this command applies to.
        binding: TaskBinding,
        /// The signed admission envelope, carried verbatim.
        envelope_json: AdmissionEnvelopeJson,
        /// Detached issuer proof over exactly `envelope_json`.
        proof: IssuerProof,
    },
    /// Start the task's admitted execution attempt.
    Start {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// Idempotency identity for this mutating command.
        operation_id: OperationId,
        /// The task/attempt/lease this command applies to.
        binding: TaskBinding,
    },
    /// Pause the task's running execution.
    Pause {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// Idempotency identity for this mutating command.
        operation_id: OperationId,
        /// The task/attempt/lease this command applies to.
        binding: TaskBinding,
    },
    /// Resume a previously paused execution.
    Resume {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// Idempotency identity for this mutating command.
        operation_id: OperationId,
        /// The task/attempt/lease this command applies to.
        binding: TaskBinding,
    },
    /// Terminate the task's workloads.
    Stop {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// Idempotency identity for this mutating command.
        operation_id: OperationId,
        /// The task/attempt/lease this command applies to.
        binding: TaskBinding,
    },
    /// Revoke the task's authority lease.
    Revoke {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// Idempotency identity for this mutating command.
        operation_id: OperationId,
        /// The task/attempt/lease this command applies to.
        binding: TaskBinding,
    },
    /// Query the task's current lifecycle state.
    Inspect {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// The task/attempt/lease this command applies to.
        binding: TaskBinding,
    },
    /// Subscribe to the task's event stream from a given sequence number.
    Stream {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// The task/attempt/lease this command applies to.
        binding: TaskBinding,
        /// The first sequence number the caller has not yet observed.
        from_seq: u64,
    },
    /// Seal the task's evidence, making it terminal.
    Seal {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// Idempotency identity for this mutating command.
        operation_id: OperationId,
        /// The task/attempt/lease this command applies to.
        binding: TaskBinding,
    },
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn serialize_admission_protocol<S>(
    protocol: &ProtocolVersion,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if !supports_task_admission(*protocol) {
        return Err(S::Error::custom(TaskLifecycleError::UnsupportedByProtocol));
    }
    protocol.serialize(serializer)
}

impl TaskLifecycleRequest {
    const fn protocol(&self) -> ProtocolVersion {
        match *self {
            Self::Create { protocol, .. }
            | Self::Admit { protocol, .. }
            | Self::Start { protocol, .. }
            | Self::Pause { protocol, .. }
            | Self::Resume { protocol, .. }
            | Self::Stop { protocol, .. }
            | Self::Revoke { protocol, .. }
            | Self::Inspect { protocol, .. }
            | Self::Stream { protocol, .. }
            | Self::Seal { protocol, .. } => protocol,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
enum TaskLifecycleRequestWire {
    Create {
        protocol: ProtocolVersion,
        operation_id: OperationId,
        binding: TaskBinding,
    },
    Admit {
        protocol: ProtocolVersion,
        operation_id: OperationId,
        binding: TaskBinding,
        envelope_json: AdmissionEnvelopeJson,
        proof: IssuerProof,
    },
    Start {
        protocol: ProtocolVersion,
        operation_id: OperationId,
        binding: TaskBinding,
    },
    Pause {
        protocol: ProtocolVersion,
        operation_id: OperationId,
        binding: TaskBinding,
    },
    Resume {
        protocol: ProtocolVersion,
        operation_id: OperationId,
        binding: TaskBinding,
    },
    Stop {
        protocol: ProtocolVersion,
        operation_id: OperationId,
        binding: TaskBinding,
    },
    Revoke {
        protocol: ProtocolVersion,
        operation_id: OperationId,
        binding: TaskBinding,
    },
    Inspect {
        protocol: ProtocolVersion,
        binding: TaskBinding,
    },
    Stream {
        protocol: ProtocolVersion,
        binding: TaskBinding,
        from_seq: u64,
    },
    Seal {
        protocol: ProtocolVersion,
        operation_id: OperationId,
        binding: TaskBinding,
    },
}

impl From<TaskLifecycleRequestWire> for TaskLifecycleRequest {
    fn from(wire: TaskLifecycleRequestWire) -> Self {
        match wire {
            TaskLifecycleRequestWire::Create {
                protocol,
                operation_id,
                binding,
            } => Self::Create {
                protocol,
                operation_id,
                binding,
            },
            TaskLifecycleRequestWire::Admit {
                protocol,
                operation_id,
                binding,
                envelope_json,
                proof,
            } => Self::Admit {
                protocol,
                operation_id,
                binding,
                envelope_json,
                proof,
            },
            TaskLifecycleRequestWire::Start {
                protocol,
                operation_id,
                binding,
            } => Self::Start {
                protocol,
                operation_id,
                binding,
            },
            TaskLifecycleRequestWire::Pause {
                protocol,
                operation_id,
                binding,
            } => Self::Pause {
                protocol,
                operation_id,
                binding,
            },
            TaskLifecycleRequestWire::Resume {
                protocol,
                operation_id,
                binding,
            } => Self::Resume {
                protocol,
                operation_id,
                binding,
            },
            TaskLifecycleRequestWire::Stop {
                protocol,
                operation_id,
                binding,
            } => Self::Stop {
                protocol,
                operation_id,
                binding,
            },
            TaskLifecycleRequestWire::Revoke {
                protocol,
                operation_id,
                binding,
            } => Self::Revoke {
                protocol,
                operation_id,
                binding,
            },
            TaskLifecycleRequestWire::Inspect { protocol, binding } => {
                Self::Inspect { protocol, binding }
            }
            TaskLifecycleRequestWire::Stream {
                protocol,
                binding,
                from_seq,
            } => Self::Stream {
                protocol,
                binding,
                from_seq,
            },
            TaskLifecycleRequestWire::Seal {
                protocol,
                operation_id,
                binding,
            } => Self::Seal {
                protocol,
                operation_id,
                binding,
            },
        }
    }
}

/// Version-bound task lifecycle response. Inbound data is decoded through `TaskLifecycleContext`.
///
/// A response whose state is not part of its protocol version does not serialize.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskLifecycleResponse {
    /// The mutating command was accepted and applied.
    Accepted {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// The idempotency identity of the command this responds to.
        operation_id: OperationId,
        /// The task/attempt/lease this response applies to.
        binding: TaskBinding,
        /// The task's lifecycle state after applying the command.
        state: TaskLifecycleState,
    },
    /// The task's current lifecycle state, in response to an inspect request.
    Inspected {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// The task/attempt/lease this response applies to.
        binding: TaskBinding,
        /// The task's current lifecycle state.
        state: TaskLifecycleState,
        /// The outcome of the attempt's execution receipt, for an `exited`, `stopped`,
        /// `revoked` or `sealed` task that has one. Protocol 1.3 and later only.
        outcome: Option<TaskExecutionOutcome>,
    },
    /// The task's event stream is ready starting from a given sequence number.
    StreamReady {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// The task/attempt/lease this response applies to.
        binding: TaskBinding,
        /// The sequence number the stream will resume from.
        from_seq: u64,
    },
    /// The request was rejected.
    Rejected {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// The idempotency identity of the rejected command, if it carried one.
        operation_id: Option<OperationId>,
        /// The task/attempt/lease this response applies to.
        binding: TaskBinding,
        /// Why the request was rejected.
        reason: TaskLifecycleRejectionReason,
    },
}

impl TaskLifecycleResponse {
    const fn protocol(self) -> ProtocolVersion {
        match self {
            Self::Accepted { protocol, .. }
            | Self::Inspected { protocol, .. }
            | Self::StreamReady { protocol, .. }
            | Self::Rejected { protocol, .. } => protocol,
        }
    }

    const fn state(self) -> Option<TaskLifecycleState> {
        match self {
            Self::Accepted { state, .. } | Self::Inspected { state, .. } => Some(state),
            Self::StreamReady { .. } | Self::Rejected { .. } => None,
        }
    }

    const fn outcome_supported(self) -> bool {
        match self {
            Self::Inspected {
                protocol,
                state,
                outcome: Some(_),
                ..
            } => supports_outcome(protocol, state),
            _ => true,
        }
    }
}

/// Whether an inspect response at `protocol` may carry a receipt outcome for `state`: at
/// 1.3 and later, for a task whose attempt has ended (`exited`, `stopped`, `revoked` or
/// `sealed`).
const fn supports_outcome(protocol: ProtocolVersion, state: TaskLifecycleState) -> bool {
    supports_task_admission(protocol)
        && matches!(
            state,
            TaskLifecycleState::Exited
                | TaskLifecycleState::Stopped
                | TaskLifecycleState::Revoked
                | TaskLifecycleState::Sealed
        )
}

impl Serialize for TaskLifecycleResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(state) = self.state()
            && !supports_state(self.protocol(), state)
        {
            return Err(S::Error::custom(TaskLifecycleError::UnsupportedByProtocol));
        }
        if !self.outcome_supported() {
            return Err(S::Error::custom(TaskLifecycleError::UnsupportedByProtocol));
        }
        TaskLifecycleResponseWire::from(*self).serialize(serializer)
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case", deny_unknown_fields)]
enum TaskLifecycleResponseWire {
    Accepted {
        protocol: ProtocolVersion,
        operation_id: OperationId,
        binding: TaskBinding,
        state: TaskLifecycleState,
    },
    Inspected {
        protocol: ProtocolVersion,
        binding: TaskBinding,
        state: TaskLifecycleState,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_present_outcome"
        )]
        outcome: Option<TaskExecutionOutcome>,
    },
    StreamReady {
        protocol: ProtocolVersion,
        binding: TaskBinding,
        from_seq: u64,
    },
    Rejected {
        protocol: ProtocolVersion,
        operation_id: Option<OperationId>,
        binding: TaskBinding,
        reason: TaskLifecycleRejectionReason,
    },
}

fn deserialize_present_outcome<'de, D>(
    deserializer: D,
) -> Result<Option<TaskExecutionOutcome>, D::Error>
where
    D: Deserializer<'de>,
{
    TaskExecutionOutcome::deserialize(deserializer).map(Some)
}

impl From<TaskLifecycleResponse> for TaskLifecycleResponseWire {
    fn from(response: TaskLifecycleResponse) -> Self {
        match response {
            TaskLifecycleResponse::Accepted {
                protocol,
                operation_id,
                binding,
                state,
            } => Self::Accepted {
                protocol,
                operation_id,
                binding,
                state,
            },
            TaskLifecycleResponse::Inspected {
                protocol,
                binding,
                state,
                outcome,
            } => Self::Inspected {
                protocol,
                binding,
                state,
                outcome,
            },
            TaskLifecycleResponse::StreamReady {
                protocol,
                binding,
                from_seq,
            } => Self::StreamReady {
                protocol,
                binding,
                from_seq,
            },
            TaskLifecycleResponse::Rejected {
                protocol,
                operation_id,
                binding,
                reason,
            } => Self::Rejected {
                protocol,
                operation_id,
                binding,
                reason,
            },
        }
    }
}

impl From<TaskLifecycleResponseWire> for TaskLifecycleResponse {
    fn from(wire: TaskLifecycleResponseWire) -> Self {
        match wire {
            TaskLifecycleResponseWire::Accepted {
                protocol,
                operation_id,
                binding,
                state,
            } => Self::Accepted {
                protocol,
                operation_id,
                binding,
                state,
            },
            TaskLifecycleResponseWire::Inspected {
                protocol,
                binding,
                state,
                outcome,
            } => Self::Inspected {
                protocol,
                binding,
                state,
                outcome,
            },
            TaskLifecycleResponseWire::StreamReady {
                protocol,
                binding,
                from_seq,
            } => Self::StreamReady {
                protocol,
                binding,
                from_seq,
            },
            TaskLifecycleResponseWire::Rejected {
                protocol,
                operation_id,
                binding,
                reason,
            } => Self::Rejected {
                protocol,
                operation_id,
                binding,
                reason,
            },
        }
    }
}

/// Negotiated context for lifecycle messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskLifecycleContext {
    protocol: ProtocolVersion,
}

impl TaskLifecycleContext {
    /// Bind a lifecycle context to a negotiated protocol version.
    ///
    /// Fails closed if the version is outside the range this revision supports, or if it
    /// predates task lifecycle support.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleError::ProtocolOutsideSupportedRange`] or
    /// [`TaskLifecycleError::ProtocolDoesNotSupportLifecycle`] as appropriate.
    pub const fn new(protocol: ProtocolVersion) -> Result<Self, TaskLifecycleError> {
        if protocol.major != WARD_NODE_PROTOCOL.major
            || protocol.minor > WARD_NODE_PROTOCOL.max_minor
        {
            return Err(TaskLifecycleError::ProtocolOutsideSupportedRange);
        }
        if !supports_task_lifecycle(protocol) {
            return Err(TaskLifecycleError::ProtocolDoesNotSupportLifecycle);
        }
        Ok(Self { protocol })
    }

    /// The protocol version this context is bound to.
    #[must_use]
    pub const fn protocol(self) -> ProtocolVersion {
        self.protocol
    }

    /// Build a [`TaskLifecycleRequest::Create`] bound to this context's protocol.
    #[must_use]
    pub const fn create(
        self,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> TaskLifecycleRequest {
        TaskLifecycleRequest::Create {
            protocol: self.protocol,
            operation_id,
            binding,
        }
    }

    /// Build a [`TaskLifecycleRequest::Admit`] bound to this context's protocol.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleError::UnsupportedByProtocol`] before protocol 1.3.
    pub fn admit(
        self,
        operation_id: OperationId,
        binding: TaskBinding,
        envelope_json: AdmissionEnvelopeJson,
        proof: IssuerProof,
    ) -> Result<TaskLifecycleRequest, TaskLifecycleError> {
        if !supports_task_admission(self.protocol) {
            return Err(TaskLifecycleError::UnsupportedByProtocol);
        }
        Ok(TaskLifecycleRequest::Admit {
            protocol: self.protocol,
            operation_id,
            binding,
            envelope_json,
            proof,
        })
    }

    /// Build a [`TaskLifecycleRequest::Start`] bound to this context's protocol.
    #[must_use]
    pub const fn start(
        self,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> TaskLifecycleRequest {
        TaskLifecycleRequest::Start {
            protocol: self.protocol,
            operation_id,
            binding,
        }
    }

    /// Build a [`TaskLifecycleRequest::Pause`] bound to this context's protocol.
    #[must_use]
    pub const fn pause(
        self,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> TaskLifecycleRequest {
        TaskLifecycleRequest::Pause {
            protocol: self.protocol,
            operation_id,
            binding,
        }
    }

    /// Build a [`TaskLifecycleRequest::Resume`] bound to this context's protocol.
    #[must_use]
    pub const fn resume(
        self,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> TaskLifecycleRequest {
        TaskLifecycleRequest::Resume {
            protocol: self.protocol,
            operation_id,
            binding,
        }
    }

    /// Build a [`TaskLifecycleRequest::Stop`] bound to this context's protocol.
    #[must_use]
    pub const fn stop(
        self,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> TaskLifecycleRequest {
        TaskLifecycleRequest::Stop {
            protocol: self.protocol,
            operation_id,
            binding,
        }
    }

    /// Build a [`TaskLifecycleRequest::Revoke`] bound to this context's protocol.
    #[must_use]
    pub const fn revoke(
        self,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> TaskLifecycleRequest {
        TaskLifecycleRequest::Revoke {
            protocol: self.protocol,
            operation_id,
            binding,
        }
    }

    /// Build a [`TaskLifecycleRequest::Inspect`] bound to this context's protocol.
    #[must_use]
    pub const fn inspect(self, binding: TaskBinding) -> TaskLifecycleRequest {
        TaskLifecycleRequest::Inspect {
            protocol: self.protocol,
            binding,
        }
    }

    /// Build a [`TaskLifecycleRequest::Stream`] bound to this context's protocol.
    #[must_use]
    pub const fn stream(self, binding: TaskBinding, from_seq: u64) -> TaskLifecycleRequest {
        TaskLifecycleRequest::Stream {
            protocol: self.protocol,
            binding,
            from_seq,
        }
    }

    /// Build a [`TaskLifecycleRequest::Seal`] bound to this context's protocol.
    #[must_use]
    pub const fn seal(
        self,
        operation_id: OperationId,
        binding: TaskBinding,
    ) -> TaskLifecycleRequest {
        TaskLifecycleRequest::Seal {
            protocol: self.protocol,
            operation_id,
            binding,
        }
    }

    /// Decode a wire-format lifecycle request, rejecting anything not bound to this context's
    /// exact protocol version.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleError::MalformedMessage`] if `json` cannot be decoded, or
    /// [`TaskLifecycleError::ProtocolMismatch`] if it is bound to a different protocol version.
    pub fn decode_request(self, json: &str) -> Result<TaskLifecycleRequest, TaskLifecycleError> {
        let request: TaskLifecycleRequest = serde_json::from_str::<TaskLifecycleRequestWire>(json)
            .map(Into::into)
            .map_err(|_| TaskLifecycleError::MalformedMessage)?;
        if matches!(request, TaskLifecycleRequest::Admit { .. })
            && !supports_task_admission(self.protocol)
        {
            return Err(TaskLifecycleError::MalformedMessage);
        }
        if request.protocol() != self.protocol {
            return Err(TaskLifecycleError::ProtocolMismatch);
        }
        Ok(request)
    }

    /// Build a [`TaskLifecycleResponse::Accepted`] bound to this context's protocol.
    #[must_use]
    pub const fn accepted(
        self,
        operation_id: OperationId,
        binding: TaskBinding,
        state: TaskLifecycleState,
    ) -> TaskLifecycleResponse {
        TaskLifecycleResponse::Accepted {
            protocol: self.protocol,
            operation_id,
            binding,
            state,
        }
    }

    /// Build a [`TaskLifecycleResponse::Inspected`] bound to this context's protocol.
    #[must_use]
    pub const fn inspected(
        self,
        binding: TaskBinding,
        state: TaskLifecycleState,
    ) -> TaskLifecycleResponse {
        TaskLifecycleResponse::Inspected {
            protocol: self.protocol,
            binding,
            state,
            outcome: None,
        }
    }

    /// Build a [`TaskLifecycleResponse::Inspected`] carrying the outcome of the attempt's
    /// execution receipt.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleError::UnsupportedByProtocol`] before protocol 1.3, or for a
    /// state other than [`TaskLifecycleState::Exited`], [`TaskLifecycleState::Stopped`],
    /// [`TaskLifecycleState::Revoked`] or [`TaskLifecycleState::Sealed`].
    pub const fn inspected_with_outcome(
        self,
        binding: TaskBinding,
        state: TaskLifecycleState,
        outcome: TaskExecutionOutcome,
    ) -> Result<TaskLifecycleResponse, TaskLifecycleError> {
        if !supports_outcome(self.protocol, state) {
            return Err(TaskLifecycleError::UnsupportedByProtocol);
        }
        Ok(TaskLifecycleResponse::Inspected {
            protocol: self.protocol,
            binding,
            state,
            outcome: Some(outcome),
        })
    }

    /// Build a [`TaskLifecycleResponse::StreamReady`] bound to this context's protocol.
    #[must_use]
    pub const fn stream_ready(self, binding: TaskBinding, from_seq: u64) -> TaskLifecycleResponse {
        TaskLifecycleResponse::StreamReady {
            protocol: self.protocol,
            binding,
            from_seq,
        }
    }

    /// Build a [`TaskLifecycleResponse::Rejected`] bound to this context's protocol.
    #[must_use]
    pub const fn rejected(
        self,
        operation_id: Option<OperationId>,
        binding: TaskBinding,
        reason: TaskLifecycleRejectionReason,
    ) -> TaskLifecycleResponse {
        TaskLifecycleResponse::Rejected {
            protocol: self.protocol,
            operation_id,
            binding,
            reason,
        }
    }

    /// Decode a wire-format lifecycle response, rejecting anything not bound to this context's
    /// exact protocol version.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleError::MalformedMessage`] if `json` cannot be decoded, or
    /// [`TaskLifecycleError::ProtocolMismatch`] if it is bound to a different protocol version.
    pub fn decode_response(self, json: &str) -> Result<TaskLifecycleResponse, TaskLifecycleError> {
        let response: TaskLifecycleResponse =
            serde_json::from_str::<TaskLifecycleResponseWire>(json)
                .map(Into::into)
                .map_err(|_| TaskLifecycleError::MalformedMessage)?;
        if let Some(state) = response.state()
            && !supports_state(self.protocol, state)
        {
            return Err(TaskLifecycleError::MalformedMessage);
        }
        if !response.outcome_supported() {
            return Err(TaskLifecycleError::MalformedMessage);
        }
        if response.protocol() != self.protocol {
            return Err(TaskLifecycleError::ProtocolMismatch);
        }
        Ok(response)
    }
}

/// Reasons a task lifecycle message can be refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskLifecycleError {
    /// The protocol version is outside the range this revision supports.
    ProtocolOutsideSupportedRange,
    /// The protocol version predates task lifecycle support.
    ProtocolDoesNotSupportLifecycle,
    /// The message's protocol version does not match the context's negotiated version.
    ProtocolMismatch,
    /// The message could not be decoded from its wire format.
    MalformedMessage,
    /// The operation or state is not part of the negotiated protocol version.
    UnsupportedByProtocol,
}

impl Display for TaskLifecycleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProtocolOutsideSupportedRange => {
                formatter.write_str("protocol version is outside this build's supported range")
            }
            Self::ProtocolDoesNotSupportLifecycle => {
                formatter.write_str("protocol version does not support task lifecycle")
            }
            Self::ProtocolMismatch => formatter
                .write_str("task lifecycle message protocol does not match negotiated protocol"),
            Self::MalformedMessage => formatter.write_str("task lifecycle message is invalid"),
            Self::UnsupportedByProtocol => {
                formatter.write_str("operation is not part of the negotiated protocol")
            }
        }
    }
}

impl std::error::Error for TaskLifecycleError {}

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
    fn current_protocol_supports_one_zero_through_one_three() {
        assert_eq!(WARD_NODE_PROTOCOL.major(), 1);
        assert_eq!(WARD_NODE_PROTOCOL.min_minor(), 0);
        assert_eq!(WARD_NODE_PROTOCOL.max_minor(), 3);
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
                admit: false,
                start: false,
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
                admit: false,
                start: false,
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
        assert!(
            CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 2)).is_ok(),
            "capability discovery remains available in later compatible minors"
        );
        assert_eq!(
            CapabilityDiscoveryContext::new(ProtocolVersion::new(2, 0)),
            Err(CapabilityDiscoveryError::ProtocolOutsideSupportedRange)
        );
    }

    #[test]
    fn minimal_capability_discovery_wire_is_stable() {
        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 1)).unwrap();
        let request = context.request();
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"request":"capabilities","protocol":{"major":1,"minor":1}}"#
        );
        assert_eq!(
            context
                .decode_request(r#"{"request":"capabilities","protocol":{"major":1,"minor":1}}"#)
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

    fn capabilities_at(minor: u16, admit: bool) -> NodeCapabilities {
        let base = minimal_capabilities();
        NodeCapabilities::new(
            ProtocolVersion::new(1, minor),
            base.architecture(),
            base.capacity(),
            base.isolation(),
            base.network(),
            base.credentials(),
            base.snapshots(),
            base.verifier(),
            LifecycleCapabilities {
                admit,
                ..base.lifecycle()
            },
        )
        .unwrap()
    }

    fn minimal_capabilities_json(minor: u16, lifecycle_tail: &str) -> String {
        format!(
            r#"{{"response":"capabilities","capabilities":{{"protocol":{{"major":1,"minor":{minor}}},"architecture":"x86_64","capacity":{{"logical_cpus":1,"memory_bytes":1024}},"isolation":{{"namespaces":{{"sandbox":false,"user_namespace":false}},"backends":{{"container":false,"microvm":false,"vm":false}}}},"network":{{"offline":false,"proxy_allowlist":false}},"credentials":{{"proxy_injection":false,"scoped_http_gateway":false}},"snapshots":{{"content_addressed":false,"diff":false,"read":false}},"verifier":{{"isolated":false}},"lifecycle":{{"pause":false,"stop":false,"revoke":false{lifecycle_tail}}}}}}}"#
        )
    }

    #[test]
    fn one_one_and_one_two_capability_documents_never_carry_admit() {
        for minor in [1, 2] {
            let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, minor)).unwrap();
            let response = context.response(capabilities_at(minor, false)).unwrap();
            let json = serde_json::to_string(&response).unwrap();
            assert_eq!(json, minimal_capabilities_json(minor, ""));
            assert_eq!(context.decode_response(&json).unwrap(), response);

            assert_eq!(
                NodeCapabilities::new(
                    ProtocolVersion::new(1, minor),
                    NodeArchitecture::X86_64,
                    NodeCapacity::new(1, 1024).unwrap(),
                    IsolationCapabilities::default(),
                    NetworkCapabilities::default(),
                    CredentialCapabilities::default(),
                    SnapshotCapabilities::default(),
                    VerifierCapabilities::default(),
                    LifecycleCapabilities {
                        admit: true,
                        ..LifecycleCapabilities::default()
                    },
                ),
                Err(NodeCapabilitiesError::ProtocolDoesNotSupportAdmission)
            );

            for tail in [r#","admit":false"#, r#","admit":true"#] {
                assert_eq!(
                    context.decode_response(&minimal_capabilities_json(minor, tail)),
                    Err(CapabilityDiscoveryError::MalformedMessage),
                    "a 1.{minor} document must not carry admit"
                );
            }
        }
    }

    #[test]
    fn one_three_capability_document_carries_admit_only_when_supported() {
        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        for (admit, tail) in [(true, r#","admit":true"#), (false, "")] {
            let response = context.response(capabilities_at(3, admit)).unwrap();
            let json = serde_json::to_string(&response).unwrap();
            assert_eq!(json, minimal_capabilities_json(3, tail));
            let decoded = context.decode_response(&json).unwrap();
            assert_eq!(decoded, response);
            let CapabilityDiscoveryResponse::Capabilities { capabilities } = decoded;
            assert_eq!(capabilities.lifecycle().admit, admit);
        }
        assert_eq!(
            context.decode_response(&minimal_capabilities_json(3, r#","admit":false"#)),
            context.response(capabilities_at(3, false))
        );
        for tail in [r#","admit":null"#, r#","admit":1"#] {
            assert_eq!(
                context.decode_response(&minimal_capabilities_json(3, tail)),
                Err(CapabilityDiscoveryError::MalformedMessage),
                "{tail}"
            );
        }
    }

    #[test]
    fn capability_request_must_match_the_exact_negotiated_protocol() {
        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 1)).unwrap();

        for claimed_minor in [0, 2] {
            let raw = format!(
                r#"{{"request":"capabilities","protocol":{{"major":1,"minor":{claimed_minor}}}}}"#
            );
            assert_eq!(
                context.decode_request(&raw),
                Err(CapabilityDiscoveryError::ProtocolMismatch),
                "claimed protocol 1.{claimed_minor} must not be accepted for negotiated 1.1"
            );
        }
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
            r#"{"request":"capabilities","protocol":{"major":1,"minor":1},"extra":true}"#,
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

    fn lifecycle_binding() -> TaskBinding {
        TaskBinding::new(
            ward_events::TaskId::from_u128(7),
            ward_events::ExecutionAttemptId::from_u128(8),
            ward_events::LeaseId::from_u128(9),
        )
    }

    #[test]
    fn task_lifecycle_is_a_protocol_one_two_feature() {
        assert!(!supports_task_lifecycle(ProtocolVersion::new(1, 0)));
        assert!(!supports_task_lifecycle(ProtocolVersion::new(1, 1)));
        assert!(supports_task_lifecycle(ProtocolVersion::new(1, 2)));
        assert!(!supports_task_lifecycle(ProtocolVersion::new(2, 0)));

        assert_eq!(
            TaskLifecycleContext::new(ProtocolVersion::new(1, 1)),
            Err(TaskLifecycleError::ProtocolDoesNotSupportLifecycle)
        );
        assert_eq!(
            TaskLifecycleContext::new(ProtocolVersion::new(1, 4)),
            Err(TaskLifecycleError::ProtocolOutsideSupportedRange)
        );
    }

    #[test]
    fn task_binding_keeps_task_attempt_and_lease_together() {
        let binding = lifecycle_binding();
        assert_eq!(binding.task(), ward_events::TaskId::from_u128(7));
        assert_eq!(
            binding.attempt(),
            ward_events::ExecutionAttemptId::from_u128(8)
        );
        assert_eq!(binding.lease(), ward_events::LeaseId::from_u128(9));

        assert_eq!(
            serde_json::to_string(&binding).unwrap(),
            r#"{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}"#
        );
    }

    #[test]
    fn mutating_lifecycle_requests_have_stable_idempotency_and_binding_wire() {
        let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap();
        let binding = lifecycle_binding();
        let operation = OperationId::new(11).unwrap();

        let cases = [
            (
                context.create(operation, binding),
                r#"{"request":"create","protocol":{"major":1,"minor":2},"operation_id":11,"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}}"#,
            ),
            (
                context.start(operation, binding),
                r#"{"request":"start","protocol":{"major":1,"minor":2},"operation_id":11,"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}}"#,
            ),
            (
                context.pause(operation, binding),
                r#"{"request":"pause","protocol":{"major":1,"minor":2},"operation_id":11,"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}}"#,
            ),
            (
                context.resume(operation, binding),
                r#"{"request":"resume","protocol":{"major":1,"minor":2},"operation_id":11,"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}}"#,
            ),
            (
                context.stop(operation, binding),
                r#"{"request":"stop","protocol":{"major":1,"minor":2},"operation_id":11,"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}}"#,
            ),
            (
                context.revoke(operation, binding),
                r#"{"request":"revoke","protocol":{"major":1,"minor":2},"operation_id":11,"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}}"#,
            ),
            (
                context.seal(operation, binding),
                r#"{"request":"seal","protocol":{"major":1,"minor":2},"operation_id":11,"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}}"#,
            ),
        ];

        for (request, expected) in cases {
            assert_eq!(serde_json::to_string(&request).unwrap(), expected);
            assert_eq!(context.decode_request(expected).unwrap(), request);
        }
    }

    #[test]
    fn read_only_lifecycle_requests_are_bound_and_bounded() {
        let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap();
        let binding = lifecycle_binding();
        let inspect = context.inspect(binding);
        let stream = context.stream(binding, 42);

        let inspect_json = r#"{"request":"inspect","protocol":{"major":1,"minor":2},"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}}"#;
        let stream_json = r#"{"request":"stream","protocol":{"major":1,"minor":2},"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"},"from_seq":42}"#;

        assert_eq!(serde_json::to_string(&inspect).unwrap(), inspect_json);
        assert_eq!(serde_json::to_string(&stream).unwrap(), stream_json);
        assert_eq!(context.decode_request(inspect_json).unwrap(), inspect);
        assert_eq!(context.decode_request(stream_json).unwrap(), stream);
    }

    #[test]
    fn lifecycle_responses_and_rejection_reasons_have_stable_wire() {
        let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap();
        let binding = lifecycle_binding();
        let operation = OperationId::new(11).unwrap();
        let bound_binding = r#""task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009""#;

        let cases = [
            (
                context.accepted(operation, binding, TaskLifecycleState::Running),
                format!(
                    r#"{{"response":"accepted","protocol":{{"major":1,"minor":2}},"operation_id":11,"binding":{{{bound_binding}}},"state":"running"}}"#
                ),
            ),
            (
                context.inspected(binding, TaskLifecycleState::Paused),
                format!(
                    r#"{{"response":"inspected","protocol":{{"major":1,"minor":2}},"binding":{{{bound_binding}}},"state":"paused"}}"#
                ),
            ),
            (
                context.stream_ready(binding, 42),
                format!(
                    r#"{{"response":"stream_ready","protocol":{{"major":1,"minor":2}},"binding":{{{bound_binding}}},"from_seq":42}}"#
                ),
            ),
            (
                context.rejected(
                    Some(operation),
                    binding,
                    TaskLifecycleRejectionReason::LeaseRevoked,
                ),
                format!(
                    r#"{{"response":"rejected","protocol":{{"major":1,"minor":2}},"operation_id":11,"binding":{{{bound_binding}}},"reason":"lease_revoked"}}"#
                ),
            ),
        ];

        for (response, expected) in cases {
            assert_eq!(serde_json::to_string(&response).unwrap(), expected);
            assert_eq!(context.decode_response(&expected).unwrap(), response);
        }

        let reasons = [
            (TaskLifecycleRejectionReason::TaskNotFound, "task_not_found"),
            (
                TaskLifecycleRejectionReason::AttemptMismatch,
                "attempt_mismatch",
            ),
            (
                TaskLifecycleRejectionReason::LeaseMismatch,
                "lease_mismatch",
            ),
            (TaskLifecycleRejectionReason::LeaseExpired, "lease_expired"),
            (TaskLifecycleRejectionReason::LeaseRevoked, "lease_revoked"),
            (
                TaskLifecycleRejectionReason::StaleOperation,
                "stale_operation",
            ),
            (TaskLifecycleRejectionReason::InvalidState, "invalid_state"),
            (
                TaskLifecycleRejectionReason::AuthorityDenied,
                "authority_denied",
            ),
            (
                TaskLifecycleRejectionReason::UnsupportedGrant,
                "unsupported_grant",
            ),
            (
                TaskLifecycleRejectionReason::ResourceUnavailable,
                "resource_unavailable",
            ),
            (
                TaskLifecycleRejectionReason::UnsupportedOperation,
                "unsupported_operation",
            ),
        ];

        for (reason, wire_name) in reasons {
            let rejected = context.rejected(None, binding, reason);
            let expected = format!(
                r#"{{"response":"rejected","protocol":{{"major":1,"minor":2}},"operation_id":null,"binding":{{{bound_binding}}},"reason":"{wire_name}"}}"#
            );
            assert_eq!(serde_json::to_string(&rejected).unwrap(), expected);
            assert_eq!(context.decode_response(&expected).unwrap(), rejected);
        }
    }

    #[test]
    fn lifecycle_wire_rejects_protocol_mismatch_unknown_fields_and_bad_ids() {
        let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap();

        for raw in [
            r#"{"request":"inspect","protocol":{"major":1,"minor":1},"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}}"#,
            r#"{"request":"inspect","protocol":{"major":1,"minor":2},"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"},"extra":true}"#,
            r#"{"request":"inspect","protocol":{"major":1,"minor":2},"binding":{"task":"not-a-task","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}}"#,
            r#"{"request":"unknown","protocol":{"major":1,"minor":2},"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}}"#,
        ] {
            assert!(
                context.decode_request(raw).is_err(),
                "{raw} must fail closed"
            );
        }

        for raw in [
            // Wrong protocol version.
            r#"{"response":"inspected","protocol":{"major":1,"minor":1},"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"},"state":"paused"}"#,
            // Unknown field.
            r#"{"response":"inspected","protocol":{"major":1,"minor":2},"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"},"state":"paused","extra":true}"#,
            // Unknown response variant.
            r#"{"response":"unknown","protocol":{"major":1,"minor":2},"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"},"state":"paused"}"#,
            // Malformed typed id.
            r#"{"response":"inspected","protocol":{"major":1,"minor":2},"binding":{"task":"not-a-task","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"},"state":"paused"}"#,
        ] {
            assert!(
                context.decode_response(raw).is_err(),
                "{raw} must fail closed"
            );
        }

        let wrong_protocol_response = r#"{"response":"inspected","protocol":{"major":1,"minor":1},"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"},"state":"paused"}"#;
        assert_eq!(
            context.decode_response(wrong_protocol_response),
            Err(TaskLifecycleError::ProtocolMismatch)
        );
    }

    #[test]
    fn lifecycle_operation_id_must_be_non_zero() {
        assert_eq!(OperationId::new(0), Err(OperationIdError::Zero));
        assert_eq!(OperationId::new(1).unwrap().get(), 1);
    }

    fn admit_fixture(minor: u16) -> String {
        format!(
            r#"{{"request":"admit","protocol":{{"major":1,"minor":{minor}}},"operation_id":11,{BOUND_BINDING},"envelope_json":"{}","proof":{}}}"#,
            test_fixtures::ENVELOPE_JSON.replace('"', "\\\""),
            test_fixtures::PROOF_JSON
        )
    }

    const BOUND_BINDING: &str = r#""binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}"#;

    fn envelope_json() -> AdmissionEnvelopeJson {
        AdmissionEnvelopeJson::encode(&test_fixtures::envelope()).unwrap()
    }

    #[test]
    fn task_admission_is_a_protocol_one_three_feature() {
        assert_eq!(TASK_ADMISSION_PROTOCOL, ProtocolVersion::new(1, 3));
        assert!(!supports_task_admission(ProtocolVersion::new(1, 1)));
        assert!(!supports_task_admission(ProtocolVersion::new(1, 2)));
        assert!(supports_task_admission(ProtocolVersion::new(1, 3)));
        assert!(!supports_task_admission(ProtocolVersion::new(2, 3)));

        let one_two = TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap();
        let one_three = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let operation = OperationId::new(11).unwrap();
        let binding = lifecycle_binding();
        let proof = test_fixtures::proof();

        assert_eq!(
            one_two.admit(operation, binding, envelope_json(), proof),
            Err(TaskLifecycleError::UnsupportedByProtocol)
        );
        assert_eq!(
            one_three.admit(operation, binding, envelope_json(), proof),
            Ok(TaskLifecycleRequest::Admit {
                protocol: ProtocolVersion::new(1, 3),
                operation_id: operation,
                binding,
                envelope_json: envelope_json(),
                proof,
            })
        );
    }

    #[test]
    fn admit_request_wire_fixture_is_stable_at_one_three() {
        let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let request = context
            .admit(
                OperationId::new(11).unwrap(),
                lifecycle_binding(),
                envelope_json(),
                test_fixtures::proof(),
            )
            .unwrap();
        let fixture = admit_fixture(3);

        assert_eq!(serde_json::to_string(&request).unwrap(), fixture);
        let decoded = context.decode_request(&fixture).unwrap();
        assert_eq!(decoded, request);

        let TaskLifecycleRequest::Admit {
            envelope_json,
            proof,
            ..
        } = decoded
        else {
            panic!("admit must decode as admit");
        };
        assert_eq!(
            envelope_json.as_bytes(),
            test_fixtures::ENVELOPE_JSON.as_bytes()
        );
        assert_eq!(envelope_json.decode().unwrap(), test_fixtures::envelope());
        assert_eq!(proof, test_fixtures::proof());
    }

    #[test]
    fn one_two_context_refuses_admit_exactly_like_an_unknown_request() {
        let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap();
        let unknown = format!(
            r#"{{"request":"unknown","protocol":{{"major":1,"minor":2}},{BOUND_BINDING}}}"#
        );
        let unknown_error = context.decode_request(&unknown).unwrap_err();
        assert_eq!(unknown_error, TaskLifecycleError::MalformedMessage);

        for minor in [2, 3] {
            assert_eq!(
                context.decode_request(&admit_fixture(minor)),
                Err(unknown_error),
                "admit claiming 1.{minor} on a 1.2 connection"
            );
        }

        let forged = TaskLifecycleRequest::Admit {
            protocol: ProtocolVersion::new(1, 2),
            operation_id: OperationId::new(11).unwrap(),
            binding: lifecycle_binding(),
            envelope_json: envelope_json(),
            proof: test_fixtures::proof(),
        };
        assert!(
            serde_json::to_string(&forged).is_err(),
            "admit must not be representable on the 1.2 wire"
        );
    }

    #[test]
    fn admit_request_decode_refuses_unknown_fields_and_unbounded_parts() {
        let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let fixture: serde_json::Value = serde_json::from_str(&admit_fixture(3)).unwrap();

        let mut extra = fixture.clone();
        extra["extra"] = serde_json::json!(true);
        let mut decoded_envelope = fixture.clone();
        decoded_envelope["envelope"] = serde_json::from_str(test_fixtures::ENVELOPE_JSON).unwrap();
        let mut extra_proof = fixture.clone();
        extra_proof["proof"]["algorithm"] = serde_json::json!("none");
        let mut short_signature = fixture.clone();
        short_signature["proof"]["signature"] = serde_json::json!("33");
        let mut empty_envelope = fixture.clone();
        empty_envelope["envelope_json"] = serde_json::json!("");
        let mut oversized_envelope = fixture.clone();
        oversized_envelope["envelope_json"] =
            serde_json::json!(" ".repeat(MAX_ADMISSION_ENVELOPE_BYTES + 1));
        let mut object_envelope = fixture.clone();
        object_envelope["envelope_json"] =
            serde_json::from_str(test_fixtures::ENVELOPE_JSON).unwrap();
        let mut zero_operation = fixture.clone();
        zero_operation["operation_id"] = serde_json::json!(0);

        let mut cases = vec![
            extra,
            decoded_envelope,
            extra_proof,
            short_signature,
            empty_envelope,
            oversized_envelope,
            object_envelope,
            zero_operation,
        ];
        for field in ["binding", "envelope_json", "proof", "operation_id"] {
            let mut missing = fixture.clone();
            missing.as_object_mut().unwrap().remove(field);
            cases.push(missing);
        }

        for value in cases {
            assert_eq!(
                context.decode_request(&value.to_string()),
                Err(TaskLifecycleError::MalformedMessage),
                "{value}"
            );
        }

        let one_three_claiming_one_two = admit_fixture(2);
        assert_eq!(
            context.decode_request(&one_three_claiming_one_two),
            Err(TaskLifecycleError::ProtocolMismatch)
        );
    }

    #[test]
    fn admit_carries_envelope_bytes_opaquely_until_they_are_decoded() {
        let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let mut invalid: serde_json::Value =
            serde_json::from_str(test_fixtures::ENVELOPE_JSON).unwrap();
        invalid["workload"]["argv"] = serde_json::json!([]);
        invalid["workspace"] = serde_json::json!("/srv/tasks/7");
        let invalid = invalid.to_string();

        let mut request: serde_json::Value = serde_json::from_str(&admit_fixture(3)).unwrap();
        request["envelope_json"] = serde_json::json!(invalid);
        let TaskLifecycleRequest::Admit { envelope_json, .. } =
            context.decode_request(&request.to_string()).unwrap()
        else {
            panic!("admit must decode as admit");
        };

        assert_eq!(envelope_json.as_bytes(), invalid.as_bytes());
        assert_eq!(
            envelope_json.decode(),
            Err(TaskAdmissionError::MalformedEnvelope)
        );
    }

    #[test]
    fn exited_state_has_stable_wire_at_one_three() {
        let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let binding = lifecycle_binding();
        let operation = OperationId::new(11).unwrap();

        let cases = [
            (
                context.accepted(operation, binding, TaskLifecycleState::Exited),
                format!(
                    r#"{{"response":"accepted","protocol":{{"major":1,"minor":3}},"operation_id":11,{BOUND_BINDING},"state":"exited"}}"#
                ),
            ),
            (
                context.inspected(binding, TaskLifecycleState::Exited),
                format!(
                    r#"{{"response":"inspected","protocol":{{"major":1,"minor":3}},{BOUND_BINDING},"state":"exited"}}"#
                ),
            ),
        ];
        for (response, expected) in cases {
            assert_eq!(serde_json::to_string(&response).unwrap(), expected);
            assert_eq!(context.decode_response(&expected).unwrap(), response);
        }
    }

    #[test]
    fn exited_state_is_neither_representable_nor_accepted_before_one_three() {
        let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap();
        let binding = lifecycle_binding();
        let operation = OperationId::new(11).unwrap();

        for response in [
            context.accepted(operation, binding, TaskLifecycleState::Exited),
            context.inspected(binding, TaskLifecycleState::Exited),
        ] {
            assert!(
                serde_json::to_string(&response).is_err(),
                "{response:?} must not be representable on the 1.2 wire"
            );
        }

        let unknown_state = format!(
            r#"{{"response":"inspected","protocol":{{"major":1,"minor":2}},{BOUND_BINDING},"state":"vanished"}}"#
        );
        let unknown_error = context.decode_response(&unknown_state).unwrap_err();
        assert_eq!(unknown_error, TaskLifecycleError::MalformedMessage);
        for raw in [
            format!(
                r#"{{"response":"accepted","protocol":{{"major":1,"minor":2}},"operation_id":11,{BOUND_BINDING},"state":"exited"}}"#
            ),
            format!(
                r#"{{"response":"inspected","protocol":{{"major":1,"minor":2}},{BOUND_BINDING},"state":"exited"}}"#
            ),
            format!(
                r#"{{"response":"inspected","protocol":{{"major":1,"minor":3}},{BOUND_BINDING},"state":"exited"}}"#
            ),
        ] {
            assert_eq!(context.decode_response(&raw), Err(unknown_error), "{raw}");
        }

        let stopped = context.inspected(binding, TaskLifecycleState::Stopped);
        assert_eq!(
            serde_json::to_string(&stopped).unwrap(),
            format!(
                r#"{{"response":"inspected","protocol":{{"major":1,"minor":2}},{BOUND_BINDING},"state":"stopped"}}"#
            )
        );
    }

    #[test]
    fn one_two_lifecycle_verbs_keep_their_wire_at_one_three() {
        let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let binding = lifecycle_binding();
        let operation = OperationId::new(11).unwrap();

        for (request, verb) in [
            (context.create(operation, binding), "create"),
            (context.start(operation, binding), "start"),
            (context.pause(operation, binding), "pause"),
            (context.resume(operation, binding), "resume"),
            (context.stop(operation, binding), "stop"),
            (context.revoke(operation, binding), "revoke"),
            (context.seal(operation, binding), "seal"),
        ] {
            let expected = format!(
                r#"{{"request":"{verb}","protocol":{{"major":1,"minor":3}},"operation_id":11,{BOUND_BINDING}}}"#
            );
            assert_eq!(serde_json::to_string(&request).unwrap(), expected);
            assert_eq!(context.decode_request(&expected).unwrap(), request);
        }
    }

    #[test]
    fn capability_discovery_at_one_three_advertises_nothing_new() {
        let one_one = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 1)).unwrap();
        let one_three = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let minimal = minimal_capabilities();
        let restamped = NodeCapabilities::new(
            ProtocolVersion::new(1, 3),
            minimal.architecture(),
            minimal.capacity(),
            minimal.isolation(),
            minimal.network(),
            minimal.credentials(),
            minimal.snapshots(),
            minimal.verifier(),
            minimal.lifecycle(),
        )
        .unwrap();

        let old = serde_json::to_string(&one_one.response(minimal).unwrap()).unwrap();
        let new = serde_json::to_string(&one_three.response(restamped).unwrap()).unwrap();
        assert_eq!(
            new,
            old.replace(r#""minor":1"#, r#""minor":3"#),
            "a 1.3 capability document must not advertise admission or execution"
        );
        assert!(one_three.decode_response(&new).is_ok());
    }

    fn capabilities_with_lifecycle(
        minor: u16,
        lifecycle: LifecycleCapabilities,
    ) -> Result<NodeCapabilities, NodeCapabilitiesError> {
        let base = minimal_capabilities();
        NodeCapabilities::new(
            ProtocolVersion::new(1, minor),
            base.architecture(),
            base.capacity(),
            base.isolation(),
            base.network(),
            base.credentials(),
            base.snapshots(),
            base.verifier(),
            lifecycle,
        )
    }

    fn executing(start: bool, stop: bool) -> LifecycleCapabilities {
        LifecycleCapabilities {
            stop,
            start,
            ..LifecycleCapabilities::default()
        }
    }

    #[test]
    fn start_is_advertised_only_at_one_three_and_only_paired_with_stop() {
        for minor in [1, 2] {
            assert_eq!(
                capabilities_with_lifecycle(minor, executing(true, true)),
                Err(NodeCapabilitiesError::ProtocolDoesNotSupportExecution)
            );
            assert!(capabilities_with_lifecycle(minor, executing(false, true)).is_ok());
        }
        for (start, stop) in [(true, false), (false, true)] {
            assert_eq!(
                capabilities_with_lifecycle(3, executing(start, stop)),
                Err(NodeCapabilitiesError::UnpairedStartAndStop),
                "start={start} stop={stop}"
            );
        }
        assert!(capabilities_with_lifecycle(3, executing(true, true)).is_ok());
        assert!(capabilities_with_lifecycle(3, executing(false, false)).is_ok());
    }

    #[test]
    fn one_three_capability_document_carries_start_with_stop() {
        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let executes = capabilities_with_lifecycle(3, executing(true, true)).unwrap();
        let response = context.response(executes).unwrap();
        let json = serde_json::to_string(&response).unwrap();
        let expected = minimal_capabilities_json(3, r#","start":true"#).replace(
            r#""pause":false,"stop":false"#,
            r#""pause":false,"stop":true"#,
        );
        assert_eq!(json, expected);
        let decoded = context.decode_response(&json).unwrap();
        assert_eq!(decoded, response);
        let CapabilityDiscoveryResponse::Capabilities { capabilities } = decoded;
        assert!(capabilities.lifecycle().start && capabilities.lifecycle().stop);

        let stop_only = minimal_capabilities_json(3, "").replace(
            r#""pause":false,"stop":false"#,
            r#""pause":false,"stop":true"#,
        );
        for raw in [
            stop_only,
            minimal_capabilities_json(3, r#","start":true"#),
            minimal_capabilities_json(3, r#","start":null"#),
            minimal_capabilities_json(3, r#","start":1"#),
        ] {
            assert_eq!(
                context.decode_response(&raw),
                Err(CapabilityDiscoveryError::MalformedMessage),
                "{raw}"
            );
        }
        assert_eq!(
            context.decode_response(&minimal_capabilities_json(3, r#","start":false"#)),
            context.response(capabilities_at(3, false))
        );
    }

    #[test]
    fn one_one_and_one_two_capability_documents_never_carry_start() {
        for minor in [1, 2] {
            let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, minor)).unwrap();
            for tail in [r#","start":false"#, r#","start":true"#] {
                assert_eq!(
                    context.decode_response(&minimal_capabilities_json(minor, tail)),
                    Err(CapabilityDiscoveryError::MalformedMessage),
                    "a 1.{minor} document must not carry start"
                );
            }
        }
    }

    #[test]
    fn one_three_inspect_carries_the_receipt_outcome_of_a_finished_task() {
        let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let binding = lifecycle_binding();
        for (state, outcome, wire_state, wire_outcome) in [
            (
                TaskLifecycleState::Exited,
                TaskExecutionOutcome::Completed,
                "exited",
                "completed",
            ),
            (
                TaskLifecycleState::Exited,
                TaskExecutionOutcome::Unknown,
                "exited",
                "unknown",
            ),
            (
                TaskLifecycleState::Stopped,
                TaskExecutionOutcome::Failed,
                "stopped",
                "failed",
            ),
            (
                TaskLifecycleState::Revoked,
                TaskExecutionOutcome::Failed,
                "revoked",
                "failed",
            ),
            (
                TaskLifecycleState::Revoked,
                TaskExecutionOutcome::Completed,
                "revoked",
                "completed",
            ),
            (
                TaskLifecycleState::Sealed,
                TaskExecutionOutcome::Unknown,
                "sealed",
                "unknown",
            ),
        ] {
            let response = context
                .inspected_with_outcome(binding, state, outcome)
                .unwrap();
            let expected = format!(
                r#"{{"response":"inspected","protocol":{{"major":1,"minor":3}},{BOUND_BINDING},"state":"{wire_state}","outcome":"{wire_outcome}"}}"#
            );
            assert_eq!(serde_json::to_string(&response).unwrap(), expected);
            assert_eq!(context.decode_response(&expected).unwrap(), response);
            assert_ne!(response, context.inspected(binding, state));
        }
    }

    #[test]
    fn inspect_outcome_is_refused_before_one_three_and_for_unfinished_states() {
        let one_three = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let one_two = TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap();
        let binding = lifecycle_binding();
        let outcome = TaskExecutionOutcome::Completed;

        assert_eq!(
            one_two.inspected_with_outcome(binding, TaskLifecycleState::Stopped, outcome),
            Err(TaskLifecycleError::UnsupportedByProtocol)
        );
        for state in [
            TaskLifecycleState::Created,
            TaskLifecycleState::Ready,
            TaskLifecycleState::Running,
            TaskLifecycleState::Paused,
        ] {
            assert_eq!(
                one_three.inspected_with_outcome(binding, state, outcome),
                Err(TaskLifecycleError::UnsupportedByProtocol),
                "{state:?}"
            );
        }

        let forged = TaskLifecycleResponse::Inspected {
            protocol: ProtocolVersion::new(1, 2),
            binding,
            state: TaskLifecycleState::Stopped,
            outcome: Some(outcome),
        };
        assert!(serde_json::to_string(&forged).is_err());
        let running = TaskLifecycleResponse::Inspected {
            protocol: ProtocolVersion::new(1, 3),
            binding,
            state: TaskLifecycleState::Running,
            outcome: Some(outcome),
        };
        assert!(serde_json::to_string(&running).is_err());

        for (context, raw) in [
            (
                one_two,
                format!(
                    r#"{{"response":"inspected","protocol":{{"major":1,"minor":2}},{BOUND_BINDING},"state":"stopped","outcome":"failed"}}"#
                ),
            ),
            (
                one_three,
                format!(
                    r#"{{"response":"inspected","protocol":{{"major":1,"minor":3}},{BOUND_BINDING},"state":"running","outcome":"failed"}}"#
                ),
            ),
            (
                one_three,
                format!(
                    r#"{{"response":"inspected","protocol":{{"major":1,"minor":3}},{BOUND_BINDING},"state":"exited","outcome":null}}"#
                ),
            ),
            (
                one_three,
                format!(
                    r#"{{"response":"inspected","protocol":{{"major":1,"minor":3}},{BOUND_BINDING},"state":"exited","outcome":"possibly_completed"}}"#
                ),
            ),
            (
                one_three,
                format!(
                    r#"{{"response":"accepted","protocol":{{"major":1,"minor":3}},"operation_id":11,{BOUND_BINDING},"state":"exited","outcome":"completed"}}"#
                ),
            ),
        ] {
            assert_eq!(
                context.decode_response(&raw),
                Err(TaskLifecycleError::MalformedMessage),
                "{raw}"
            );
        }
    }

    #[test]
    fn revoked_and_sealed_outcomes_are_one_three_only() {
        let one_three = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let one_two = TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap();
        let binding = lifecycle_binding();
        let outcome = TaskExecutionOutcome::Failed;
        for state in [TaskLifecycleState::Revoked, TaskLifecycleState::Sealed] {
            assert_eq!(
                one_two.inspected_with_outcome(binding, state, outcome),
                Err(TaskLifecycleError::UnsupportedByProtocol),
                "{state:?}"
            );
            let forged = TaskLifecycleResponse::Inspected {
                protocol: ProtocolVersion::new(1, 2),
                binding,
                state,
                outcome: Some(outcome),
            };
            assert!(serde_json::to_string(&forged).is_err(), "{state:?}");
            assert!(
                one_three
                    .inspected_with_outcome(binding, state, outcome)
                    .is_ok()
            );
        }

        for (context, raw) in [
            (
                one_two,
                format!(
                    r#"{{"response":"inspected","protocol":{{"major":1,"minor":2}},{BOUND_BINDING},"state":"revoked","outcome":"failed"}}"#
                ),
            ),
            (
                one_two,
                format!(
                    r#"{{"response":"inspected","protocol":{{"major":1,"minor":2}},{BOUND_BINDING},"state":"sealed","outcome":"completed"}}"#
                ),
            ),
            (
                one_three,
                format!(
                    r#"{{"response":"inspected","protocol":{{"major":1,"minor":3}},{BOUND_BINDING},"state":"paused","outcome":"failed"}}"#
                ),
            ),
            (
                one_three,
                format!(
                    r#"{{"response":"accepted","protocol":{{"major":1,"minor":3}},"operation_id":11,{BOUND_BINDING},"state":"sealed","outcome":"failed"}}"#
                ),
            ),
        ] {
            assert_eq!(
                context.decode_response(&raw),
                Err(TaskLifecycleError::MalformedMessage),
                "{raw}"
            );
        }
        for state in ["revoked", "sealed"] {
            assert_eq!(
                one_two.decode_response(&format!(
                    r#"{{"response":"inspected","protocol":{{"major":1,"minor":2}},{BOUND_BINDING},"state":"{state}"}}"#
                )),
                Ok(one_two.inspected(binding, if state == "revoked" {
                    TaskLifecycleState::Revoked
                } else {
                    TaskLifecycleState::Sealed
                })),
                "a 1.2 response without an outcome is unchanged"
            );
        }
    }
}
