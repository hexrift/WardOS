//! Strongly typed primitives shared by the policy schema and the capability manifest.
//!
//! Every identifier and limit is a validated newtype; no free-form strings reach the
//! merge or the enforcement layer.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::PolicyError;

// ---------------------------------------------------------------------------
// Decision and Layer
// ---------------------------------------------------------------------------

/// The outcome of a capability decision.
///
/// The derived total order is `Deny < Ask < Allow`: the *minimum* of two decisions is
/// always the more restrictive one, which is what the three-layer merge relies on.
///
/// There is deliberately **no** `Default` implementation: a decision must always be
/// produced from explicit policy, never conjured from missing data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Refused. Final for the session; never overridable in a prompt.
    Deny,
    /// Routed to the approval surface.
    Ask,
    /// Granted silently (Quiet) or with a log line (Live).
    Allow,
}

impl Decision {
    /// Returns the more restrictive of the two decisions.
    #[must_use]
    pub fn narrow(self, other: Decision) -> Decision {
        self.min(other)
    }

    /// `true` for [`Decision::Deny`].
    #[must_use]
    pub fn is_deny(self) -> bool {
        matches!(self, Decision::Deny)
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Decision::Deny => "deny",
            Decision::Ask => "ask",
            Decision::Allow => "allow",
        })
    }
}

/// One of the three policy layers, ordered from most to least trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    /// `/etc/ward/policy.d/*.yaml` — root-owned, image-shipped defaults plus admin.
    System,
    /// `~/.config/ward/policy.yaml`.
    User,
    /// `<project>/.ward/policy.yaml` — untrusted; may only narrow.
    Project,
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Layer::System => "system",
            Layer::User => "user",
            Layer::Project => "project",
        })
    }
}

/// Filesystem access level for a mount. Ordered `Read < Write`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FsAccess {
    /// Read-only.
    Read,
    /// Read-write.
    Write,
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = char::from(chunk[0]).to_digit(16)?;
        let lo = char::from(chunk[1]).to_digit(16)?;
        // Both digits are < 16 so the value fits in a byte.
        out[i] = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Blake3Hash
// ---------------------------------------------------------------------------

/// A 32-byte BLAKE3 digest. Serialised as 64 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Blake3Hash([u8; 32]);

impl Blake3Hash {
    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex encoding.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }

    /// Parses 64 lowercase hex characters.
    ///
    /// # Errors
    /// Returns [`PolicyError::InvalidId`] if the input is not exactly 64 lowercase hex
    /// digits.
    pub fn from_hex(s: &str) -> Result<Self, PolicyError> {
        decode_hex_32(s)
            .map(Self)
            .ok_or_else(|| PolicyError::InvalidId {
                kind: "blake3 hash",
                value: s.to_owned(),
                reason: "expected 64 lowercase hex characters",
            })
    }
}

impl From<blake3::Hash> for Blake3Hash {
    fn from(h: blake3::Hash) -> Self {
        Self(*h.as_bytes())
    }
}

impl fmt::Debug for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blake3Hash({})", self.to_hex())
    }
}

impl fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for Blake3Hash {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl Serialize for Blake3Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Blake3Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Opaque identifiers
// ---------------------------------------------------------------------------

/// Maximum length of an opaque identifier such as a session or project id.
pub const MAX_ID_LEN: usize = 128;

fn validate_opaque_id(kind: &'static str, s: &str) -> Result<(), PolicyError> {
    let reject = |reason| PolicyError::InvalidId {
        kind,
        value: s.to_owned(),
        reason,
    };
    if s.is_empty() {
        return Err(reject("must not be empty"));
    }
    if s.len() > MAX_ID_LEN {
        return Err(reject("too long"));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(reject(
            "only ASCII letters, digits, `-`, `_`, `.` and `:` are allowed",
        ));
    }
    Ok(())
}

macro_rules! opaque_id {
    ($(#[$meta:meta])* $name:ident, $kind:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates and wraps an identifier.
            ///
            /// # Errors
            /// Returns [`PolicyError::InvalidId`] if the value is empty, longer than
            /// [`MAX_ID_LEN`], or contains characters outside `[A-Za-z0-9._:-]`.
            pub fn new(s: impl Into<String>) -> Result<Self, PolicyError> {
                let s = s.into();
                validate_opaque_id($kind, &s)?;
                Ok(Self(s))
            }

            /// The identifier as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = PolicyError;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }

        impl FromStr for $name {
            type Err = PolicyError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

opaque_id!(
    /// Identifier of a supervised session.
    SessionId,
    "session id"
);
opaque_id!(
    /// Identifier of a project (repository) known to `wardd`.
    ProjectId,
    "project id"
);

// ---------------------------------------------------------------------------
// ImageDigest / SnapshotId
// ---------------------------------------------------------------------------

/// A pinned OCI image digest of the form `sha256:<64 lowercase hex>`.
///
/// Local newtype; a later integration unifies this with `ward-events`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ImageDigest(String);

impl ImageDigest {
    /// Validates and wraps an image digest.
    ///
    /// # Errors
    /// Returns [`PolicyError::InvalidId`] unless the value is `sha256:` followed by
    /// exactly 64 lowercase hex digits.
    pub fn new(s: impl Into<String>) -> Result<Self, PolicyError> {
        let s = s.into();
        let reject = |reason| PolicyError::InvalidId {
            kind: "image digest",
            value: s.clone(),
            reason,
        };
        match s.strip_prefix("sha256:") {
            Some(hex) if decode_hex_32(hex).is_some() => Ok(Self(s)),
            Some(_) => Err(reject("expected 64 lowercase hex digits after `sha256:`")),
            None => Err(reject("expected `sha256:` prefix")),
        }
    }

    /// The digest as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ImageDigest {
    type Error = PolicyError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl FromStr for ImageDigest {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl From<ImageDigest> for String {
    fn from(v: ImageDigest) -> String {
        v.0
    }
}

impl fmt::Display for ImageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Content address of a snapshot in the snapshot store (a BLAKE3 digest).
///
/// Local newtype; a later integration unifies this with `ward-events`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SnapshotId(Blake3Hash);

impl SnapshotId {
    /// Wraps a snapshot digest.
    #[must_use]
    pub const fn new(hash: Blake3Hash) -> Self {
        Self(hash)
    }

    /// The underlying digest.
    #[must_use]
    pub const fn hash(&self) -> &Blake3Hash {
        &self.0
    }
}

impl FromStr for SnapshotId {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Blake3Hash::from_hex(s)
            .map(Self)
            .map_err(|_| PolicyError::InvalidId {
                kind: "snapshot id",
                value: s.to_owned(),
                reason: "expected 64 lowercase hex characters",
            })
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

// ---------------------------------------------------------------------------
// Resource newtypes
// ---------------------------------------------------------------------------

/// Helper: accept either an integer or a string from serde.
#[derive(Deserialize)]
#[serde(untagged)]
enum IntOrString {
    Int(u64),
    Str(String),
}

/// A byte count, parsed from `20GiB`, `512MiB`, `1TB` or a plain integer.
///
/// Binary suffixes (`K`/`KiB`, `M`/`MiB`, `G`/`GiB`, `T`/`TiB`) are powers of 1024;
/// decimal suffixes (`KB`, `MB`, `GB`, `TB`) are powers of 1000. Serialised as a plain
/// integer number of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSize(u64);

impl ByteSize {
    /// Wraps a positive byte count.
    ///
    /// # Errors
    /// Returns [`PolicyError::InvalidResource`] for zero.
    pub fn new(bytes: u64) -> Result<Self, PolicyError> {
        if bytes == 0 {
            return Err(PolicyError::InvalidResource {
                field: "bytes",
                value: "0".to_owned(),
                reason: "must be positive",
            });
        }
        Ok(Self(bytes))
    }

    /// Crate-internal constructor for compile-time constants.
    pub(crate) const fn from_const(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Number of bytes.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }

    /// Parses a byte size string (see the type documentation).
    ///
    /// # Errors
    /// Returns [`PolicyError::InvalidResource`] for an unknown suffix, a non-numeric
    /// prefix, zero, or overflow.
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let reject = |reason| PolicyError::InvalidResource {
            field: "bytes",
            value: s.to_owned(),
            reason,
        };
        let trimmed = s.trim();
        let digits_end = trimmed.bytes().take_while(u8::is_ascii_digit).count();
        let (num, suffix) = trimmed.split_at(digits_end);
        if num.is_empty() {
            return Err(reject("expected a number"));
        }
        let value: u64 = num.parse().map_err(|_| reject("number too large"))?;
        let multiplier: u64 = match suffix.trim().to_ascii_lowercase().as_str() {
            "" | "b" => 1,
            "k" | "kib" => 1 << 10,
            "m" | "mib" => 1 << 20,
            "g" | "gib" => 1 << 30,
            "t" | "tib" => 1 << 40,
            "kb" => 1_000,
            "mb" => 1_000_000,
            "gb" => 1_000_000_000,
            "tb" => 1_000_000_000_000,
            _ => return Err(reject("unknown size suffix")),
        };
        let bytes = value
            .checked_mul(multiplier)
            .ok_or_else(|| reject("value overflows u64"))?;
        Self::new(bytes).map_err(|_| reject("must be positive"))
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const UNITS: [(u64, &str); 4] = [
            (1 << 40, "TiB"),
            (1 << 30, "GiB"),
            (1 << 20, "MiB"),
            (1 << 10, "KiB"),
        ];
        for (size, name) in UNITS {
            if self.0.is_multiple_of(size) {
                return write!(f, "{}{name}", self.0 / size);
            }
        }
        write!(f, "{}", self.0)
    }
}

impl FromStr for ByteSize {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match IntOrString::deserialize(d)? {
            IntOrString::Int(n) => Self::new(n),
            IntOrString::Str(s) => Self::parse(&s),
        }
        .map_err(serde::de::Error::custom)
    }
}

/// A percentage in `1..=100`, parsed from `50%` or a plain integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Percent(u8);

impl Percent {
    /// Wraps a percentage.
    ///
    /// # Errors
    /// Returns [`PolicyError::InvalidResource`] unless `1 <= value <= 100`.
    pub fn new(value: u64) -> Result<Self, PolicyError> {
        match u8::try_from(value) {
            Ok(v) if (1..=100).contains(&v) => Ok(Self(v)),
            _ => Err(PolicyError::InvalidResource {
                field: "percent",
                value: value.to_string(),
                reason: "must be between 1 and 100",
            }),
        }
    }

    /// Crate-internal constructor for compile-time constants.
    pub(crate) const fn from_const(value: u8) -> Self {
        Self(value)
    }

    /// The percentage value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Parses `NN%` or `NN`.
    ///
    /// # Errors
    /// Returns [`PolicyError::InvalidResource`] for anything else.
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let body = s.trim().strip_suffix('%').unwrap_or_else(|| s.trim());
        let value: u64 = body
            .trim()
            .parse()
            .map_err(|_| PolicyError::InvalidResource {
                field: "percent",
                value: s.to_owned(),
                reason: "expected `NN%`",
            })?;
        Self::new(value)
    }
}

impl fmt::Display for Percent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}%", self.0)
    }
}

impl Serialize for Percent {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(self.0)
    }
}

impl<'de> Deserialize<'de> for Percent {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match IntOrString::deserialize(d)? {
            IntOrString::Int(n) => Self::new(n),
            IntOrString::Str(s) => Self::parse(&s),
        }
        .map_err(serde::de::Error::custom)
    }
}

/// cgroup v2 `cpu.weight`, in `1..=10000`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct CpuWeight(u32);

impl CpuWeight {
    /// Smallest valid weight.
    pub const MIN: CpuWeight = CpuWeight(1);
    /// Largest valid weight.
    pub const MAX: CpuWeight = CpuWeight(10_000);

    /// Wraps a weight.
    ///
    /// # Errors
    /// Returns [`PolicyError::InvalidResource`] unless `1 <= value <= 10000`.
    pub fn new(value: u64) -> Result<Self, PolicyError> {
        match u32::try_from(value) {
            Ok(v) if (1..=10_000).contains(&v) => Ok(Self(v)),
            _ => Err(PolicyError::InvalidResource {
                field: "cpu_weight",
                value: value.to_string(),
                reason: "must be between 1 and 10000",
            }),
        }
    }

    /// Crate-internal constructor for compile-time constants.
    pub(crate) const fn from_const(value: u32) -> Self {
        Self(value)
    }

    /// The weight value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl TryFrom<u64> for CpuWeight {
    type Error = PolicyError;
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        Self::new(v)
    }
}

impl From<CpuWeight> for u64 {
    fn from(v: CpuWeight) -> u64 {
        u64::from(v.0)
    }
}

/// cgroup v2 `pids.max`, at least 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct PidsMax(u32);

impl PidsMax {
    /// Wraps a pid limit.
    ///
    /// # Errors
    /// Returns [`PolicyError::InvalidResource`] for zero or values above `u32::MAX`.
    pub fn new(value: u64) -> Result<Self, PolicyError> {
        match u32::try_from(value) {
            Ok(v) if v >= 1 => Ok(Self(v)),
            _ => Err(PolicyError::InvalidResource {
                field: "pids_max",
                value: value.to_string(),
                reason: "must be between 1 and 4294967295",
            }),
        }
    }

    /// Crate-internal constructor for compile-time constants.
    pub(crate) const fn from_const(value: u32) -> Self {
        Self(value)
    }

    /// The limit value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl TryFrom<u64> for PidsMax {
    type Error = PolicyError;
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        Self::new(v)
    }
}

impl From<PidsMax> for u64 {
    fn from(v: PidsMax) -> u64 {
        u64::from(v.0)
    }
}

/// A memory ceiling as written in policy: either a fraction of host RAM or an absolute
/// byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryLimit {
    /// Percentage of host memory.
    Percent(Percent),
    /// Absolute number of bytes.
    Bytes(ByteSize),
}

impl MemoryLimit {
    /// Parses `50%`, `8GiB`, or a plain integer (bytes).
    ///
    /// # Errors
    /// Returns [`PolicyError::InvalidResource`] for anything else.
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        if s.trim().ends_with('%') {
            Percent::parse(s).map(Self::Percent)
        } else {
            ByteSize::parse(s).map(Self::Bytes)
        }
        .map_err(|_| PolicyError::InvalidResource {
            field: "memory_max",
            value: s.to_owned(),
            reason: "expected `NN%` or a byte size such as `8GiB`",
        })
    }
}

impl fmt::Display for MemoryLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryLimit::Percent(p) => fmt::Display::fmt(p, f),
            MemoryLimit::Bytes(b) => fmt::Display::fmt(b, f),
        }
    }
}

impl Serialize for MemoryLimit {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MemoryLimit {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match IntOrString::deserialize(d)? {
            IntOrString::Int(n) => ByteSize::new(n).map(Self::Bytes),
            IntOrString::Str(s) => Self::parse(&s),
        }
        .map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Structural "always denied" markers
// ---------------------------------------------------------------------------

/// Marker type for host filesystem access: the only expressible value is *denied*.
///
/// Serialises as the string `deny`; deserialising anything else is an error, so an
/// `allow` for the host filesystem cannot even be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct HostDenied;

impl Serialize for HostDenied {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str("deny")
    }
}

impl<'de> Deserialize<'de> for HostDenied {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == "deny" {
            Ok(HostDenied)
        } else {
            Err(serde::de::Error::custom(
                PolicyError::HostFilesystemNotDeny(s),
            ))
        }
    }
}

/// Marker type for private-network egress: the only expressible value is *denied*.
///
/// Serialises as `true` (for `deny_private_networks: true`); deserialising `false` is an
/// error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PrivateNetworksDenied;

impl Serialize for PrivateNetworksDenied {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for PrivateNetworksDenied {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if bool::deserialize(d)? {
            Ok(PrivateNetworksDenied)
        } else {
            Err(serde::de::Error::custom(
                PolicyError::PrivateNetworksMustBeDenied,
            ))
        }
    }
}
