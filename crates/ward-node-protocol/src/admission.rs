//! Protocol 1.3 task admission envelope (ADR-0030).
//!
//! The envelope binds what runs to who may run it, where and until when. On the wire it
//! travels as opaque JSON bytes ([`AdmissionEnvelopeJson`]) next to a detached
//! [`IssuerProof`] over exactly those bytes, so a signer never has to re-canonicalise
//! anything. A receiver verifies the proof over the received bytes first and only then
//! decodes them strictly with [`TaskAdmissionEnvelope::decode_json`].
//!
//! This module only defines, bounds and structurally validates these values; issuer-proof
//! verification, audience, expiry and replay checks belong to the node (ADR-0030 §2). The
//! envelope never names a host path: the node allocates the workspace itself.

use std::fmt::{Display, Formatter};
use std::num::NonZeroU64;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ward_authority::UntrustedAuthorityLease;
use ward_events::{AgentId, Blake3Hash, NodeId, SessionId, SnapshotId};

use crate::TaskBinding;

/// Maximum number of ancestor leases one admission envelope may carry.
pub const MAX_ADMISSION_LINEAGE: usize = 16;

/// Maximum size in bytes of one serialized admission envelope.
///
/// Escaped inside an `admit` request it must still fit the receiver's request bound
/// (64 KiB for the local `ward-node` socket).
pub const MAX_ADMISSION_ENVELOPE_BYTES: usize = 32 * 1024;

/// Structurally invalid admission envelope content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskAdmissionError {
    /// The workload argv has no entries.
    EmptyArgv,
    /// The workload program (argv\[0\]) is empty.
    EmptyProgram,
    /// The workload argv has more than [`WorkloadArgv::MAX_ARGS`] entries.
    TooManyArguments,
    /// One argv entry exceeds [`WorkloadArgv::MAX_ARG_BYTES`].
    ArgumentTooLong,
    /// The argv entries together exceed [`WorkloadArgv::MAX_TOTAL_BYTES`].
    ArgvTooLong,
    /// An argv entry contains a NUL byte and cannot be passed to exec.
    NulInArgument,
    /// The capability manifest is empty.
    EmptyManifest,
    /// The capability manifest exceeds [`CapabilityManifestBytes::MAX_BYTES`].
    ManifestTooLarge,
    /// The capability manifest hash does not match its bytes.
    ManifestHashMismatch,
    /// The wall-clock budget is zero.
    ZeroBudget,
    /// The admission version is zero.
    ZeroVersion,
    /// The lease lineage exceeds [`MAX_ADMISSION_LINEAGE`] ancestors.
    LineageTooLong,
    /// The envelope expiry is not strictly after its issue time.
    InvalidLifetime,
    /// The serialized envelope is empty.
    EmptyEnvelope,
    /// The serialized envelope exceeds [`MAX_ADMISSION_ENVELOPE_BYTES`].
    EnvelopeTooLarge,
    /// The serialized envelope is not a valid admission envelope.
    MalformedEnvelope,
}

impl Display for TaskAdmissionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EmptyArgv => "workload argv is empty",
            Self::EmptyProgram => "workload program is empty",
            Self::TooManyArguments => "workload argv has too many entries",
            Self::ArgumentTooLong => "workload argv entry is too long",
            Self::ArgvTooLong => "workload argv is too long",
            Self::NulInArgument => "workload argv entry contains a NUL byte",
            Self::EmptyManifest => "capability manifest is empty",
            Self::ManifestTooLarge => "capability manifest is too large",
            Self::ManifestHashMismatch => "capability manifest hash does not match its bytes",
            Self::ZeroBudget => "wall-clock budget must be non-zero",
            Self::ZeroVersion => "admission version must be non-zero",
            Self::LineageTooLong => "authority lineage is too long",
            Self::InvalidLifetime => "admission envelope lifetime is invalid",
            Self::EmptyEnvelope => "admission envelope is empty",
            Self::EnvelopeTooLarge => "admission envelope is too large",
            Self::MalformedEnvelope => "admission envelope is invalid",
        })
    }
}

impl std::error::Error for TaskAdmissionError {}

/// A bounded, exec-safe argument vector for an admitted workload.
///
/// Unlike an evidence argv, this is never truncated: anything over a bound is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct WorkloadArgv(Vec<String>);

impl WorkloadArgv {
    /// Maximum number of entries.
    pub const MAX_ARGS: usize = 256;
    /// Maximum bytes in one entry.
    pub const MAX_ARG_BYTES: usize = 4096;
    /// Maximum bytes across all entries.
    pub const MAX_TOTAL_BYTES: usize = 16 * 1024;

    /// Validate a workload argv; the first entry is the program.
    ///
    /// # Errors
    ///
    /// Rejects an empty argv or program, NUL bytes and anything over the bounds.
    pub fn new(args: Vec<String>) -> Result<Self, TaskAdmissionError> {
        let Some(program) = args.first() else {
            return Err(TaskAdmissionError::EmptyArgv);
        };
        if program.is_empty() {
            return Err(TaskAdmissionError::EmptyProgram);
        }
        if args.len() > Self::MAX_ARGS {
            return Err(TaskAdmissionError::TooManyArguments);
        }
        let mut total = 0_usize;
        for arg in &args {
            if arg.len() > Self::MAX_ARG_BYTES {
                return Err(TaskAdmissionError::ArgumentTooLong);
            }
            if arg.contains('\0') {
                return Err(TaskAdmissionError::NulInArgument);
            }
            total = total.saturating_add(arg.len());
        }
        if total > Self::MAX_TOTAL_BYTES {
            return Err(TaskAdmissionError::ArgvTooLong);
        }
        Ok(Self(args))
    }

    /// The argv entries, program first.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for WorkloadArgv {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let args = Vec::<String>::deserialize(deserializer)?;
        Self::new(args).map_err(D::Error::custom)
    }
}

/// The serialized capability manifest the sandbox is built from, bound to its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityManifestBytes {
    hash: Blake3Hash,
    bytes: Vec<u8>,
}

impl CapabilityManifestBytes {
    /// Maximum serialized manifest size in bytes.
    pub const MAX_BYTES: usize = 8 * 1024;

    /// Bind serialized manifest bytes to their `BLAKE3` hash.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized manifest.
    pub fn new(bytes: Vec<u8>) -> Result<Self, TaskAdmissionError> {
        if bytes.is_empty() {
            return Err(TaskAdmissionError::EmptyManifest);
        }
        if bytes.len() > Self::MAX_BYTES {
            return Err(TaskAdmissionError::ManifestTooLarge);
        }
        Ok(Self {
            hash: Blake3Hash::hash(&bytes),
            bytes,
        })
    }

    /// `BLAKE3` hash of the serialized manifest.
    #[must_use]
    pub const fn hash(&self) -> Blake3Hash {
        self.hash
    }

    /// The serialized manifest bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityManifestBytesWire {
    hash: Blake3Hash,
    bytes: String,
}

impl Serialize for CapabilityManifestBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        CapabilityManifestBytesWire {
            hash: self.hash,
            bytes: encode_hex(&self.bytes),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CapabilityManifestBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CapabilityManifestBytesWire::deserialize(deserializer)?;
        if wire.bytes.len() > Self::MAX_BYTES.saturating_mul(2) {
            return Err(D::Error::custom(TaskAdmissionError::ManifestTooLarge));
        }
        let bytes = decode_hex(&wire.bytes)
            .ok_or_else(|| D::Error::custom("capability manifest bytes are not hex"))?;
        let manifest = Self::new(bytes).map_err(D::Error::custom)?;
        if manifest.hash != wire.hash {
            return Err(D::Error::custom(TaskAdmissionError::ManifestHashMismatch));
        }
        Ok(manifest)
    }
}

/// What an admitted task runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TaskWorkload {
    argv: WorkloadArgv,
    capability_manifest: CapabilityManifestBytes,
    snapshot: SnapshotId,
    wall_clock_budget_ms: NonZeroU64,
}

impl TaskWorkload {
    /// Bind argv, capability manifest, project snapshot and a mandatory budget.
    ///
    /// # Errors
    ///
    /// Returns [`TaskAdmissionError::ZeroBudget`] for a zero wall-clock budget.
    pub fn new(
        argv: WorkloadArgv,
        capability_manifest: CapabilityManifestBytes,
        snapshot: SnapshotId,
        wall_clock_budget_ms: u64,
    ) -> Result<Self, TaskAdmissionError> {
        let wall_clock_budget_ms =
            NonZeroU64::new(wall_clock_budget_ms).ok_or(TaskAdmissionError::ZeroBudget)?;
        Ok(Self {
            argv,
            capability_manifest,
            snapshot,
            wall_clock_budget_ms,
        })
    }

    /// The workload argv.
    #[must_use]
    pub const fn argv(&self) -> &WorkloadArgv {
        &self.argv
    }

    /// The capability manifest the sandbox is built from.
    #[must_use]
    pub const fn capability_manifest(&self) -> &CapabilityManifestBytes {
        &self.capability_manifest
    }

    /// Content id of the project snapshot the node materialises.
    #[must_use]
    pub const fn snapshot(&self) -> SnapshotId {
        self.snapshot
    }

    /// Mandatory wall-clock budget in milliseconds.
    #[must_use]
    pub const fn wall_clock_budget_ms(&self) -> u64 {
        self.wall_clock_budget_ms.get()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskWorkloadWire {
    argv: WorkloadArgv,
    capability_manifest: CapabilityManifestBytes,
    snapshot: SnapshotId,
    wall_clock_budget_ms: u64,
}

impl<'de> Deserialize<'de> for TaskWorkload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TaskWorkloadWire::deserialize(deserializer)?;
        Self::new(
            wire.argv,
            wire.capability_manifest,
            wire.snapshot,
            wire.wall_clock_budget_ms,
        )
        .map_err(D::Error::custom)
    }
}

/// The authority lease and the ancestors needed to prove its contraction.
///
/// Both are untrusted here; the node promotes them only after verifying the issuer proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TaskAdmissionAuthority {
    lease: UntrustedAuthorityLease,
    lineage: Vec<UntrustedAuthorityLease>,
}

impl TaskAdmissionAuthority {
    /// Carry a lease and its ancestors, nearest parent first.
    ///
    /// # Errors
    ///
    /// Returns [`TaskAdmissionError::LineageTooLong`] beyond [`MAX_ADMISSION_LINEAGE`].
    pub fn new(
        lease: UntrustedAuthorityLease,
        lineage: Vec<UntrustedAuthorityLease>,
    ) -> Result<Self, TaskAdmissionError> {
        if lineage.len() > MAX_ADMISSION_LINEAGE {
            return Err(TaskAdmissionError::LineageTooLong);
        }
        Ok(Self { lease, lineage })
    }

    /// The lease authorising this task.
    #[must_use]
    pub const fn lease(&self) -> &UntrustedAuthorityLease {
        &self.lease
    }

    /// Ancestor leases, nearest parent first; empty for a root lease.
    #[must_use]
    pub fn lineage(&self) -> &[UntrustedAuthorityLease] {
        &self.lineage
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskAdmissionAuthorityWire {
    lease: UntrustedAuthorityLease,
    lineage: Vec<UntrustedAuthorityLease>,
}

impl<'de> Deserialize<'de> for TaskAdmissionAuthority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TaskAdmissionAuthorityWire::deserialize(deserializer)?;
        Self::new(wire.lease, wire.lineage).map_err(D::Error::custom)
    }
}

/// Per-task monotonic admission version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AdmissionVersion(NonZeroU64);

impl AdmissionVersion {
    /// Construct a non-zero admission version.
    ///
    /// # Errors
    ///
    /// Returns [`TaskAdmissionError::ZeroVersion`] for zero.
    pub const fn new(value: u64) -> Result<Self, TaskAdmissionError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(TaskAdmissionError::ZeroVersion),
        }
    }

    /// The raw version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Detached 64-byte Ed25519 signature bytes, opaque to the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuerSignature([u8; 64]);

impl IssuerSignature {
    /// Signature length in bytes.
    pub const LEN: usize = 64;

    /// Wrap raw signature bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The raw signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl Serialize for IssuerSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for IssuerSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        decode_hex(&hex)
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
            .map(Self)
            .ok_or_else(|| D::Error::custom("issuer signature must be 64 hex-encoded bytes"))
    }
}

/// Detached issuer proof over the exact bytes of an [`AdmissionEnvelopeJson`].
///
/// On the JSON wire both fields are lowercase hex: `issuer_key_id` is 32 bytes (the
/// `BLAKE3` identifier of the issuer key) and `signature` is the 64-byte Ed25519
/// signature. The proof is opaque here; it is verified by the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerProof {
    issuer_key_id: Blake3Hash,
    signature: IssuerSignature,
}

impl IssuerProof {
    /// Bind a signature to the identifier (hash) of the issuer key that made it.
    #[must_use]
    pub const fn new(issuer_key_id: Blake3Hash, signature: IssuerSignature) -> Self {
        Self {
            issuer_key_id,
            signature,
        }
    }

    /// Identifier (hash) of the issuer key.
    #[must_use]
    pub const fn issuer_key_id(&self) -> Blake3Hash {
        self.issuer_key_id
    }

    /// The detached signature bytes.
    #[must_use]
    pub const fn signature(&self) -> IssuerSignature {
        self.signature
    }
}

/// Input for [`TaskAdmissionEnvelope::new`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskAdmissionEnvelopeInput {
    /// Exact task, execution attempt and lease.
    pub binding: TaskBinding,
    /// Agent whose authority applies.
    pub agent: AgentId,
    /// Audience node.
    pub node: NodeId,
    /// Ward session.
    pub session: SessionId,
    /// Lease and lineage.
    pub authority: TaskAdmissionAuthority,
    /// What runs.
    pub workload: TaskWorkload,
    /// Inclusive issue time in Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Exclusive expiry in Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Per-task monotonic version.
    pub version: AdmissionVersion,
}

/// One versioned, audience-bound admission envelope for protocol 1.3 `admit`.
///
/// Inbound bytes are decoded only through [`Self::decode_json`], which bounds their size
/// and refuses unknown fields at every level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TaskAdmissionEnvelope {
    binding: TaskBinding,
    agent: AgentId,
    node: NodeId,
    session: SessionId,
    authority: TaskAdmissionAuthority,
    workload: TaskWorkload,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    version: AdmissionVersion,
}

impl TaskAdmissionEnvelope {
    /// Construct a structurally valid envelope.
    ///
    /// # Errors
    ///
    /// Returns [`TaskAdmissionError::InvalidLifetime`] unless expiry is after issue time.
    pub fn new(input: TaskAdmissionEnvelopeInput) -> Result<Self, TaskAdmissionError> {
        if input.expires_at_unix_ms <= input.issued_at_unix_ms {
            return Err(TaskAdmissionError::InvalidLifetime);
        }
        Ok(Self {
            binding: input.binding,
            agent: input.agent,
            node: input.node,
            session: input.session,
            authority: input.authority,
            workload: input.workload,
            issued_at_unix_ms: input.issued_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
            version: input.version,
        })
    }

    /// Strictly decode envelope bytes received on the wire.
    ///
    /// Callers must verify the detached issuer proof over exactly these bytes first.
    ///
    /// # Errors
    ///
    /// Returns [`TaskAdmissionError::EmptyEnvelope`] or
    /// [`TaskAdmissionError::EnvelopeTooLarge`] for out-of-bounds input, and
    /// [`TaskAdmissionError::MalformedEnvelope`] for anything that is not exactly one valid
    /// envelope (including unknown fields).
    pub fn decode_json(bytes: &[u8]) -> Result<Self, TaskAdmissionError> {
        check_envelope_size(bytes.len())?;
        let wire = serde_json::from_slice::<TaskAdmissionEnvelopeWire>(bytes)
            .map_err(|_| TaskAdmissionError::MalformedEnvelope)?;
        Self::new(TaskAdmissionEnvelopeInput {
            binding: wire.binding,
            agent: wire.agent,
            node: wire.node,
            session: wire.session,
            authority: wire.authority,
            workload: wire.workload,
            issued_at_unix_ms: wire.issued_at_unix_ms,
            expires_at_unix_ms: wire.expires_at_unix_ms,
            version: wire.version,
        })
    }

    /// Exact task, execution attempt and lease.
    #[must_use]
    pub const fn binding(&self) -> TaskBinding {
        self.binding
    }

    /// Agent whose authority applies.
    #[must_use]
    pub const fn agent(&self) -> AgentId {
        self.agent
    }

    /// Audience node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Ward session.
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// Lease and lineage.
    #[must_use]
    pub const fn authority(&self) -> &TaskAdmissionAuthority {
        &self.authority
    }

    /// What runs.
    #[must_use]
    pub const fn workload(&self) -> &TaskWorkload {
        &self.workload
    }

    /// Inclusive issue time in Unix milliseconds.
    #[must_use]
    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.issued_at_unix_ms
    }

    /// Exclusive expiry in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// Per-task monotonic version.
    #[must_use]
    pub const fn version(&self) -> AdmissionVersion {
        self.version
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskAdmissionEnvelopeWire {
    binding: TaskBinding,
    agent: AgentId,
    node: NodeId,
    session: SessionId,
    authority: TaskAdmissionAuthority,
    workload: TaskWorkload,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    version: AdmissionVersion,
}

const fn check_envelope_size(len: usize) -> Result<(), TaskAdmissionError> {
    if len == 0 {
        return Err(TaskAdmissionError::EmptyEnvelope);
    }
    if len > MAX_ADMISSION_ENVELOPE_BYTES {
        return Err(TaskAdmissionError::EnvelopeTooLarge);
    }
    Ok(())
}

/// The exact serialized envelope bytes an issuer signed, carried opaquely by `admit`.
///
/// On the JSON wire this is a string whose UTF-8 bytes (after JSON string unescaping)
/// are the signed envelope. It is non-empty and at most [`MAX_ADMISSION_ENVELOPE_BYTES`].
/// Holding it proves nothing; decode it with [`Self::decode`] only after the proof checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct AdmissionEnvelopeJson(String);

impl AdmissionEnvelopeJson {
    /// Carry already-serialized envelope JSON verbatim.
    ///
    /// # Errors
    ///
    /// Returns [`TaskAdmissionError::EmptyEnvelope`] or
    /// [`TaskAdmissionError::EnvelopeTooLarge`] for out-of-bounds input.
    pub fn new(json: String) -> Result<Self, TaskAdmissionError> {
        check_envelope_size(json.len())?;
        Ok(Self(json))
    }

    /// Serialize an envelope into the bytes an issuer signs.
    ///
    /// # Errors
    ///
    /// Returns [`TaskAdmissionError::EnvelopeTooLarge`] if the encoding exceeds the bound.
    pub fn encode(envelope: &TaskAdmissionEnvelope) -> Result<Self, TaskAdmissionError> {
        let json =
            serde_json::to_string(envelope).map_err(|_| TaskAdmissionError::MalformedEnvelope)?;
        Self::new(json)
    }

    /// The exact bytes the issuer proof covers.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Strictly decode the carried bytes; see [`TaskAdmissionEnvelope::decode_json`].
    ///
    /// # Errors
    ///
    /// Returns [`TaskAdmissionError`] if the bytes are not exactly one valid envelope.
    pub fn decode(&self) -> Result<TaskAdmissionEnvelope, TaskAdmissionError> {
        TaskAdmissionEnvelope::decode_json(self.as_bytes())
    }
}

impl<'de> Deserialize<'de> for AdmissionEnvelopeJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let json = String::deserialize(deserializer)?;
        Self::new(json).map_err(D::Error::custom)
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Some((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use ward_authority::{
        AuthorityLease, DelegationInput, EmptyAuthorityPolicy, GrantSet, LeaseVersion,
        UntrustedAuthorityLease,
    };
    use ward_events::{AgentId, Blake3Hash, DelegationId, LeaseId, NodeId, SessionId};

    use crate::test_fixtures::{
        ENVELOPE_JSON, MANIFEST_BYTES, PROOF_JSON, argv, binding, envelope, input, lease, manifest,
        proof, snapshot, trusted_lease, workload,
    };
    use crate::{
        AdmissionEnvelopeJson, AdmissionVersion, CapabilityManifestBytes, IssuerProof,
        IssuerSignature, MAX_ADMISSION_ENVELOPE_BYTES, MAX_ADMISSION_LINEAGE,
        TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskAdmissionError, TaskWorkload,
        WorkloadArgv,
    };

    fn decode(json: &str) -> Result<TaskAdmissionEnvelope, TaskAdmissionError> {
        TaskAdmissionEnvelope::decode_json(json.as_bytes())
    }

    fn envelope_value() -> serde_json::Value {
        serde_json::from_str(ENVELOPE_JSON).unwrap()
    }

    fn delegated_lease(parent: &AuthorityLease, id: u128, version: u64) -> AuthorityLease {
        parent
            .delegate(
                DelegationInput {
                    id: LeaseId::from_u128(id),
                    delegation_id: DelegationId::from_u128(id),
                    subject: AgentId::from_u128(3),
                    task: parent.task(),
                    grants: GrantSet::new([]).unwrap(),
                    issued_at_unix_ms: parent.issued_at_unix_ms(),
                    expires_at_unix_ms: parent.expires_at_unix_ms(),
                    version: LeaseVersion::new(version).unwrap(),
                },
                2_000,
                EmptyAuthorityPolicy::Allow,
            )
            .unwrap()
    }

    #[test]
    fn envelope_wire_fixture_is_stable_and_round_trips() {
        let envelope = envelope();
        assert_eq!(serde_json::to_string(&envelope).unwrap(), ENVELOPE_JSON);
        assert_eq!(decode(ENVELOPE_JSON).unwrap(), envelope);

        assert_eq!(envelope.binding(), binding());
        assert_eq!(envelope.agent(), AgentId::from_u128(3));
        assert_eq!(envelope.node(), NodeId::from_u128(4));
        assert_eq!(envelope.session(), SessionId::from_u128(5));
        assert_eq!(envelope.authority().lease(), &lease());
        assert!(envelope.authority().lineage().is_empty());
        assert_eq!(envelope.workload(), &workload());
        assert_eq!(envelope.workload().argv().args(), ["cargo", "test"]);
        assert_eq!(
            envelope.workload().capability_manifest().bytes(),
            MANIFEST_BYTES
        );
        assert_eq!(
            envelope.workload().capability_manifest().hash(),
            Blake3Hash::hash(MANIFEST_BYTES)
        );
        assert_eq!(envelope.workload().snapshot(), snapshot());
        assert_eq!(envelope.workload().wall_clock_budget_ms(), 600_000);
        assert_eq!(envelope.issued_at_unix_ms(), 2_000);
        assert_eq!(envelope.expires_at_unix_ms(), 8_000);
        assert_eq!(envelope.version().get(), 1);
    }

    #[test]
    fn envelope_json_carries_the_exact_signed_bytes_and_decodes_strictly() {
        let encoded = AdmissionEnvelopeJson::encode(&envelope()).unwrap();
        assert_eq!(encoded.as_bytes(), ENVELOPE_JSON.as_bytes());
        assert_eq!(encoded.decode().unwrap(), envelope());

        let reordered = {
            let value = envelope_value();
            let mut fields: Vec<_> = value.as_object().unwrap().iter().collect();
            fields.reverse();
            let body: Vec<_> = fields
                .iter()
                .map(|(key, value)| format!("{}:{value}", serde_json::json!(key)))
                .collect();
            format!(" {{ {} }} ", body.join(" , "))
        };
        let carried = AdmissionEnvelopeJson::new(reordered.clone()).unwrap();
        assert_eq!(carried.as_bytes(), reordered.as_bytes());
        assert_eq!(carried.decode().unwrap(), envelope());

        assert_eq!(
            serde_json::to_string(&carried).unwrap(),
            serde_json::to_string(&reordered).unwrap()
        );
        assert_eq!(
            serde_json::from_str::<AdmissionEnvelopeJson>(
                &serde_json::to_string(&reordered).unwrap()
            )
            .unwrap(),
            carried
        );
    }

    #[test]
    fn envelope_bytes_are_non_empty_and_bounded() {
        assert_eq!(
            AdmissionEnvelopeJson::new(String::new()),
            Err(TaskAdmissionError::EmptyEnvelope)
        );
        assert_eq!(decode(""), Err(TaskAdmissionError::EmptyEnvelope));

        let oversized = format!(
            "{}{}",
            ENVELOPE_JSON,
            " ".repeat(MAX_ADMISSION_ENVELOPE_BYTES + 1 - ENVELOPE_JSON.len())
        );
        assert_eq!(oversized.len(), MAX_ADMISSION_ENVELOPE_BYTES + 1);
        assert_eq!(
            AdmissionEnvelopeJson::new(oversized.clone()),
            Err(TaskAdmissionError::EnvelopeTooLarge)
        );
        assert_eq!(
            decode(&oversized),
            Err(TaskAdmissionError::EnvelopeTooLarge)
        );
        assert!(
            serde_json::from_str::<AdmissionEnvelopeJson>(
                &serde_json::to_string(&oversized).unwrap()
            )
            .is_err()
        );

        let at_bound = &oversized[..MAX_ADMISSION_ENVELOPE_BYTES];
        assert_eq!(decode(at_bound).unwrap(), envelope());
        assert!(AdmissionEnvelopeJson::new(at_bound.to_owned()).is_ok());

        for raw in [
            "not json",
            "[]",
            "null",
            &format!("{ENVELOPE_JSON}{ENVELOPE_JSON}"),
            &format!("{ENVELOPE_JSON} trailing"),
        ] {
            assert_eq!(
                decode(raw),
                Err(TaskAdmissionError::MalformedEnvelope),
                "{raw}"
            );
        }
        assert_eq!(
            AdmissionEnvelopeJson::new("not json".to_owned())
                .unwrap()
                .decode(),
            Err(TaskAdmissionError::MalformedEnvelope)
        );
    }

    #[test]
    fn envelope_names_no_host_path_or_workspace() {
        let value = envelope_value();
        let keys = |value: &serde_json::Value| {
            let mut keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
            keys.sort();
            keys
        };
        assert_eq!(
            keys(&value),
            [
                "agent",
                "authority",
                "binding",
                "expires_at_unix_ms",
                "issued_at_unix_ms",
                "node",
                "session",
                "version",
                "workload",
            ]
        );
        assert_eq!(
            keys(&value["workload"]),
            [
                "argv",
                "capability_manifest",
                "snapshot",
                "wall_clock_budget_ms"
            ]
        );
        assert_eq!(keys(&value["authority"]), ["lease", "lineage"]);
    }

    #[test]
    fn envelope_lifetime_must_be_non_empty() {
        for (issued, expires) in [(2_000, 2_000), (2_000, 1_999), (2_000, 0)] {
            let mut bad = input();
            bad.issued_at_unix_ms = issued;
            bad.expires_at_unix_ms = expires;
            assert_eq!(
                TaskAdmissionEnvelope::new(bad),
                Err(TaskAdmissionError::InvalidLifetime)
            );

            let mut value = envelope_value();
            value["issued_at_unix_ms"] = serde_json::json!(issued);
            value["expires_at_unix_ms"] = serde_json::json!(expires);
            assert!(decode(&value.to_string()).is_err(), "{issued}..{expires}");
        }
    }

    #[test]
    fn workload_budget_is_mandatory_and_non_zero() {
        assert_eq!(
            TaskWorkload::new(argv(), manifest(), snapshot(), 0),
            Err(TaskAdmissionError::ZeroBudget)
        );

        let mut zero = envelope_value();
        zero["workload"]["wall_clock_budget_ms"] = serde_json::json!(0);
        assert!(decode(&zero.to_string()).is_err());

        let mut missing = envelope_value();
        missing["workload"]
            .as_object_mut()
            .unwrap()
            .remove("wall_clock_budget_ms");
        assert!(decode(&missing.to_string()).is_err());
    }

    #[test]
    fn workload_argv_is_non_empty_bounded_and_exec_safe() {
        let args = |values: &[&str]| values.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>();

        assert_eq!(
            WorkloadArgv::new(Vec::new()),
            Err(TaskAdmissionError::EmptyArgv)
        );
        assert_eq!(
            WorkloadArgv::new(args(&["", "x"])),
            Err(TaskAdmissionError::EmptyProgram)
        );
        assert_eq!(
            WorkloadArgv::new(args(&["sh", "a\0b"])),
            Err(TaskAdmissionError::NulInArgument)
        );
        assert_eq!(
            WorkloadArgv::new(vec!["x".to_owned(); WorkloadArgv::MAX_ARGS + 1]),
            Err(TaskAdmissionError::TooManyArguments)
        );
        assert_eq!(
            WorkloadArgv::new(vec!["x".repeat(WorkloadArgv::MAX_ARG_BYTES + 1)]),
            Err(TaskAdmissionError::ArgumentTooLong)
        );
        let per_arg = WorkloadArgv::MAX_ARG_BYTES;
        let count = WorkloadArgv::MAX_TOTAL_BYTES / per_arg + 1;
        assert_eq!(
            WorkloadArgv::new(vec!["x".repeat(per_arg); count]),
            Err(TaskAdmissionError::ArgvTooLong)
        );
        assert!(WorkloadArgv::new(vec!["x".repeat(per_arg); count - 1]).is_ok());

        for bad in [
            serde_json::json!([]),
            serde_json::json!([""]),
            serde_json::json!(["sh", "a\u{0}b"]),
            serde_json::json!("cargo test"),
        ] {
            let mut value = envelope_value();
            value["workload"]["argv"] = bad.clone();
            assert!(decode(&value.to_string()).is_err(), "{bad}");
        }
    }

    #[test]
    fn capability_manifest_is_bounded_and_hash_bound() {
        assert_eq!(
            CapabilityManifestBytes::new(Vec::new()),
            Err(TaskAdmissionError::EmptyManifest)
        );
        assert_eq!(
            CapabilityManifestBytes::new(vec![b'x'; CapabilityManifestBytes::MAX_BYTES + 1]),
            Err(TaskAdmissionError::ManifestTooLarge)
        );
        assert!(
            CapabilityManifestBytes::new(vec![b'x'; CapabilityManifestBytes::MAX_BYTES]).is_ok()
        );

        let mut wrong_hash = envelope_value();
        wrong_hash["workload"]["capability_manifest"]["hash"] =
            serde_json::json!(Blake3Hash::hash(b"other").to_hex());
        let mut odd_hex = envelope_value();
        odd_hex["workload"]["capability_manifest"]["bytes"] = serde_json::json!("7b2");
        let mut not_hex = envelope_value();
        not_hex["workload"]["capability_manifest"]["bytes"] = serde_json::json!("zz");
        let mut empty = envelope_value();
        empty["workload"]["capability_manifest"]["bytes"] = serde_json::json!("");
        empty["workload"]["capability_manifest"]["hash"] =
            serde_json::json!(Blake3Hash::hash(b"").to_hex());

        for value in [wrong_hash, odd_hex, not_hex, empty] {
            assert!(decode(&value.to_string()).is_err(), "{value}");
        }
    }

    #[test]
    fn admission_version_is_non_zero() {
        assert_eq!(
            AdmissionVersion::new(0),
            Err(TaskAdmissionError::ZeroVersion)
        );
        assert_eq!(AdmissionVersion::new(7).unwrap().get(), 7);

        let mut value = envelope_value();
        value["version"] = serde_json::json!(0);
        assert!(decode(&value.to_string()).is_err());
    }

    #[test]
    fn authority_carries_bounded_untrusted_lineage() {
        let root = trusted_lease();
        let child = delegated_lease(&root, 10, 2);
        let authority = TaskAdmissionAuthority::new(
            UntrustedAuthorityLease::from(&child),
            vec![UntrustedAuthorityLease::from(&root)],
        )
        .unwrap();
        assert_eq!(authority.lineage(), [UntrustedAuthorityLease::from(&root)]);

        let mut delegated = input();
        delegated.authority = authority;
        let delegated = TaskAdmissionEnvelope::new(delegated).unwrap();
        let json = serde_json::to_string(&delegated).unwrap();
        assert_eq!(decode(&json).unwrap(), delegated);

        let too_long = vec![UntrustedAuthorityLease::from(&root); MAX_ADMISSION_LINEAGE + 1];
        assert_eq!(
            TaskAdmissionAuthority::new(lease(), too_long.clone()),
            Err(TaskAdmissionError::LineageTooLong)
        );
        let mut value = envelope_value();
        value["authority"]["lineage"] = serde_json::to_value(&too_long).unwrap();
        assert!(decode(&value.to_string()).is_err());
    }

    #[test]
    fn issuer_proof_is_an_opaque_hex_ed25519_sized_signature() {
        assert_eq!(
            IssuerSignature::from_bytes([7; 64]).as_bytes(),
            &[7; IssuerSignature::LEN]
        );
        let proof = proof();
        assert_eq!(proof.issuer_key_id(), Blake3Hash::from_bytes([0x22; 32]));
        assert_eq!(proof.signature().as_bytes(), &[0x33; 64]);
        assert_eq!(serde_json::to_string(&proof).unwrap(), PROOF_JSON);
        assert_eq!(
            serde_json::from_str::<IssuerProof>(PROOF_JSON).unwrap(),
            proof
        );

        let proof_value = || serde_json::from_str::<serde_json::Value>(PROOF_JSON).unwrap();
        for signature in [
            "33".repeat(63),
            "33".repeat(65),
            "zz".repeat(64),
            "3".repeat(127),
            "AB".repeat(64),
            String::new(),
        ] {
            let mut value = proof_value();
            value["signature"] = serde_json::json!(signature);
            assert!(
                serde_json::from_str::<IssuerProof>(&value.to_string()).is_err(),
                "{signature}"
            );
        }

        let mut bad_key = proof_value();
        bad_key["issuer_key_id"] = serde_json::json!("22");
        let mut extra = proof_value();
        extra["algorithm"] = serde_json::json!("none");
        let mut missing = proof_value();
        missing.as_object_mut().unwrap().remove("signature");
        for value in [bad_key, extra, missing] {
            assert!(serde_json::from_str::<IssuerProof>(&value.to_string()).is_err());
        }
    }

    #[test]
    fn envelope_decode_refuses_unknown_fields_at_every_level() {
        let pointers: [&[&str]; 6] = [
            &[],
            &["binding"],
            &["authority"],
            &["authority", "lease"],
            &["workload"],
            &["workload", "capability_manifest"],
        ];
        for pointer in pointers {
            let mut value = envelope_value();
            let mut target = &mut value;
            for key in pointer {
                target = &mut target[*key];
            }
            target["host_path"] = serde_json::json!("/home/user/project");
            assert!(
                decode(&value.to_string()).is_err(),
                "unknown field under {pointer:?} must fail closed"
            );
        }

        for field in [
            "binding",
            "agent",
            "node",
            "session",
            "authority",
            "workload",
            "issued_at_unix_ms",
            "expires_at_unix_ms",
            "version",
        ] {
            let mut value = envelope_value();
            value.as_object_mut().unwrap().remove(field);
            assert!(
                decode(&value.to_string()).is_err(),
                "missing {field} must fail closed"
            );
        }
    }
}
