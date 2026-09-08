//! Strong identifier newtypes (`security-model.md` §5: all identifiers are newtypes).
//!
//! Every type here validates on construction, on `FromStr`, and on deserialisation, so a
//! value of one of these types is always well-formed.

use core::fmt;
use core::num::NonZeroU32;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Errors produced while parsing or validating identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdError {
    /// A hex string had the wrong length.
    #[error("expected {expected} hex characters, found {found}")]
    HexLength {
        /// Required number of hex characters.
        expected: usize,
        /// Number of characters found.
        found: usize,
    },
    /// A hex string contained a non-hex character.
    #[error("invalid hex digit at byte {index}")]
    HexDigit {
        /// Byte offset of the offending character.
        index: usize,
    },
    /// The required prefix was missing.
    #[error("missing prefix `{expected}`")]
    Prefix {
        /// The prefix that was expected.
        expected: &'static str,
    },
    /// A Crockford base32 body had the wrong length.
    #[error("expected {expected} Crockford base32 characters, found {found}")]
    Base32Length {
        /// Required number of characters.
        expected: usize,
        /// Number found.
        found: usize,
    },
    /// A Crockford base32 body contained an invalid character.
    #[error("invalid Crockford base32 character at byte {index}")]
    Base32Char {
        /// Byte offset of the offending character.
        index: usize,
    },
    /// A 26-character `ULID` body encodes more than 128 bits.
    #[error("identifier overflows 128 bits")]
    Overflow,
    /// A process id of zero was supplied.
    #[error("pid must be non-zero")]
    ZeroPid,
    /// An identifier was empty.
    #[error("identifier is empty")]
    Empty,
    /// An identifier exceeded its length cap.
    #[error("identifier longer than {max} bytes ({found})")]
    TooLong {
        /// Maximum permitted length in bytes.
        max: usize,
        /// Length found.
        found: usize,
    },
    /// An identifier contained a character outside its alphabet.
    #[error("invalid character at byte {index}")]
    InvalidChar {
        /// Byte offset of the offending character.
        index: usize,
    },
}

// ---------------------------------------------------------------------------------------
// hex helpers
// ---------------------------------------------------------------------------------------

const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn decode_hex_32(s: &str) -> Result<[u8; 32], IdError> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(IdError::HexLength {
            expected: 64,
            found: bytes.len(),
        });
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_val(pair[0]).ok_or(IdError::HexDigit { index: i * 2 })?;
        let lo = hex_val(pair[1]).ok_or(IdError::HexDigit { index: i * 2 + 1 })?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn serialize_32<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.serialize_str(&encode_hex(bytes))
    } else {
        bytes.serialize(serializer)
    }
}

fn deserialize_32<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
    if deserializer.is_human_readable() {
        let s = <&str>::deserialize(deserializer)?;
        decode_hex_32(s).map_err(serde::de::Error::custom)
    } else {
        <[u8; 32]>::deserialize(deserializer)
    }
}

// ---------------------------------------------------------------------------------------
// Blake3Hash
// ---------------------------------------------------------------------------------------

/// A 32-byte `BLAKE3` digest.
///
/// Displays as 64 lowercase hex characters; parses with or without a `blake3:` prefix.
/// Binary serialisation is the raw 32 bytes; human-readable serialisation is hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Blake3Hash([u8; 32]);

impl Blake3Hash {
    /// Length of the digest in bytes.
    pub const LEN: usize = 32;
    /// The all-zero digest (useful as a placeholder in tests and fixtures).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Computes the `BLAKE3` digest of `data`.
    #[must_use]
    pub fn hash(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    /// Lowercase hex rendering without a prefix.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }

    /// Parses 64 hex characters, optionally prefixed with `blake3:`.
    ///
    /// # Errors
    /// Returns [`IdError`] if the length or characters are wrong.
    pub fn from_hex(s: &str) -> Result<Self, IdError> {
        let body = s.strip_prefix("blake3:").unwrap_or(s);
        decode_hex_32(body).map(Self)
    }
}

impl From<blake3::Hash> for Blake3Hash {
    fn from(h: blake3::Hash) -> Self {
        Self(*h.as_bytes())
    }
}

impl fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blake3Hash({})", self.to_hex())
    }
}

impl FromStr for Blake3Hash {
    type Err = IdError;
    fn from_str(s: &str) -> Result<Self, IdError> {
        Self::from_hex(s)
    }
}

impl Serialize for Blake3Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_32(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Blake3Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_32(deserializer).map(Self)
    }
}

// ---------------------------------------------------------------------------------------
// SnapshotId
// ---------------------------------------------------------------------------------------

/// Identifier of a Ward Snapshot: the `BLAKE3` Merkle root of its canonical manifest
/// (`snapshots-and-git.md`). Displays as `blake3:<hex>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SnapshotId(Blake3Hash);

impl SnapshotId {
    /// Wraps a digest as a snapshot id.
    #[must_use]
    pub const fn new(hash: Blake3Hash) -> Self {
        Self(hash)
    }

    /// The underlying digest.
    #[must_use]
    pub const fn hash(&self) -> Blake3Hash {
        self.0
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blake3:{}", self.0)
    }
}

impl fmt::Debug for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SnapshotId({self})")
    }
}

impl FromStr for SnapshotId {
    type Err = IdError;
    fn from_str(s: &str) -> Result<Self, IdError> {
        Blake3Hash::from_hex(s).map(Self)
    }
}

// ---------------------------------------------------------------------------------------
// ImageDigest
// ---------------------------------------------------------------------------------------

/// An OCI image digest (SHA-256). Displays and parses as `sha256:<64 hex>`; the prefix
/// is mandatory when parsing because OCI digests always carry their algorithm.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ImageDigest([u8; 32]);

impl ImageDigest {
    /// Wraps raw SHA-256 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex rendering without the `sha256:` prefix.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }
}

impl fmt::Display for ImageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.to_hex())
    }
}

impl fmt::Debug for ImageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ImageDigest({self})")
    }
}

impl FromStr for ImageDigest {
    type Err = IdError;
    fn from_str(s: &str) -> Result<Self, IdError> {
        let body = s.strip_prefix("sha256:").ok_or(IdError::Prefix {
            expected: "sha256:",
        })?;
        decode_hex_32(body).map(Self)
    }
}

impl Serialize for ImageDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_32(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for ImageDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_32(deserializer).map(Self)
    }
}

// ---------------------------------------------------------------------------------------
// ULID-style ids: SessionId, ProjectId
// ---------------------------------------------------------------------------------------

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const ULID_LEN: usize = 26;

fn crockford_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'H' => Some(c - b'A' + 10),
        b'J' | b'K' => Some(c - b'J' + 18),
        b'M' | b'N' => Some(c - b'M' + 20),
        b'P'..=b'T' => Some(c - b'P' + 22),
        b'V'..=b'Z' => Some(c - b'V' + 27),
        _ => None,
    }
}

fn encode_ulid(value: u128) -> String {
    let mut out = String::with_capacity(ULID_LEN);
    for i in (0..ULID_LEN).rev() {
        let shift = 5 * i;
        // `shift` is at most 125, so the shift is in range and the mask keeps 5 bits.
        let idx = ((value >> shift) & 0x1f) as usize;
        out.push(CROCKFORD[idx] as char);
    }
    out
}

fn decode_ulid(body: &str) -> Result<u128, IdError> {
    let bytes = body.as_bytes();
    if bytes.len() != ULID_LEN {
        return Err(IdError::Base32Length {
            expected: ULID_LEN,
            found: bytes.len(),
        });
    }
    let mut value: u128 = 0;
    for (index, &c) in bytes.iter().enumerate() {
        let v = crockford_val(c).ok_or(IdError::Base32Char { index })?;
        if index == 0 && v > 7 {
            return Err(IdError::Overflow);
        }
        value = (value << 5) | u128::from(v);
    }
    Ok(value)
}

macro_rules! ulid_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(u128);

        impl $name {
            /// The textual prefix of this identifier kind.
            pub const PREFIX: &'static str = $prefix;

            /// Constructs the identifier from its 128-bit value.
            #[must_use]
            pub const fn from_u128(value: u128) -> Self {
                Self(value)
            }

            /// Returns the 128-bit value.
            #[must_use]
            pub const fn as_u128(&self) -> u128 {
                self.0
            }

            /// Returns the 26-character Crockford base32 body (without prefix).
            #[must_use]
            pub fn body(&self) -> String {
                encode_ulid(self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", Self::PREFIX, self.body())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({self})", stringify!($name))
            }
        }

        impl FromStr for $name {
            type Err = IdError;
            fn from_str(s: &str) -> Result<Self, IdError> {
                let body = s
                    .strip_prefix(Self::PREFIX)
                    .ok_or(IdError::Prefix { expected: Self::PREFIX })?;
                decode_ulid(body).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&self.to_string())
                } else {
                    self.0.to_be_bytes().serialize(serializer)
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                if deserializer.is_human_readable() {
                    let s = <&str>::deserialize(deserializer)?;
                    s.parse().map_err(serde::de::Error::custom)
                } else {
                    let bytes = <[u8; 16]>::deserialize(deserializer)?;
                    Ok(Self(u128::from_be_bytes(bytes)))
                }
            }
        }
    };
}

ulid_id!(
    /// Session identifier: `sess_` followed by a 26-character Crockford base32 `ULID` body.
    ///
    /// Assigned by `wardd` at session open. Binary serialisation is the 16 big-endian
    /// bytes of the `ULID`; human-readable serialisation is the prefixed string.
    SessionId,
    "sess_"
);

ulid_id!(
    /// Project identifier: `proj_` followed by a 26-character Crockford base32 `ULID` body.
    ///
    /// Stable per project root; keys the persistent project environment.
    ProjectId,
    "proj_"
);

// ---------------------------------------------------------------------------------------
// Pid
// ---------------------------------------------------------------------------------------

/// A process id inside the session's pid namespace. Never zero.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Pid(NonZeroU32);

impl Pid {
    /// Wraps a raw pid.
    ///
    /// # Errors
    /// Returns [`IdError::ZeroPid`] for `0`.
    pub fn new(raw: u32) -> Result<Self, IdError> {
        NonZeroU32::new(raw).map(Self).ok_or(IdError::ZeroPid)
    }

    /// Returns the raw pid.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl From<NonZeroU32> for Pid {
    fn from(v: NonZeroU32) -> Self {
        Self(v)
    }
}

impl fmt::Display for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pid({})", self.0)
    }
}

impl FromStr for Pid {
    type Err = IdError;
    fn from_str(s: &str) -> Result<Self, IdError> {
        let raw: u32 = s.parse().map_err(|_| IdError::InvalidChar { index: 0 })?;
        Self::new(raw)
    }
}

// ---------------------------------------------------------------------------------------
// RuleRef, ServiceId
// ---------------------------------------------------------------------------------------

/// Reference to the policy rule that produced a decision, e.g. `project:network.allow[2]`.
///
/// 1–128 bytes of printable ASCII without whitespace. Opaque to this crate; the format is
/// owned by `ward-policy`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RuleRef(String);

impl RuleRef {
    /// Maximum length in bytes.
    pub const MAX_BYTES: usize = 128;

    /// Validates and wraps a rule reference.
    ///
    /// # Errors
    /// Returns [`IdError`] if empty, over-long, or containing non-printable or whitespace
    /// characters.
    pub fn new(s: &str) -> Result<Self, IdError> {
        validate_ascii_id(s, Self::MAX_BYTES, |i, c| i >= 0 && c.is_ascii_graphic())?;
        Ok(Self(s.to_owned()))
    }

    /// The rule reference as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Identifier of a credential-broker service, e.g. `github`, `ssh:github`, `aws-prod`.
///
/// 1–64 bytes; lowercase ASCII letters, digits, and `. _ : -` after the first character,
/// which must be a letter or digit.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceId(String);

impl ServiceId {
    /// Maximum length in bytes.
    pub const MAX_BYTES: usize = 64;

    /// Validates and wraps a service identifier.
    ///
    /// # Errors
    /// Returns [`IdError`] if empty, over-long, or outside the alphabet.
    pub fn new(s: &str) -> Result<Self, IdError> {
        validate_ascii_id(s, Self::MAX_BYTES, |i, c| {
            c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || (i > 0 && matches!(c, b'.' | b'_' | b':' | b'-'))
        })?;
        Ok(Self(s.to_owned()))
    }

    /// The service identifier as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_ascii_id(
    s: &str,
    max: usize,
    allowed: impl Fn(i64, u8) -> bool,
) -> Result<(), IdError> {
    if s.is_empty() {
        return Err(IdError::Empty);
    }
    if s.len() > max {
        return Err(IdError::TooLong {
            max,
            found: s.len(),
        });
    }
    for (index, &c) in s.as_bytes().iter().enumerate() {
        let i = i64::try_from(index).unwrap_or(i64::MAX);
        if !allowed(i, c) {
            return Err(IdError::InvalidChar { index });
        }
    }
    Ok(())
}

macro_rules! string_id_impls {
    ($name:ident) => {
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdError;
            fn from_str(s: &str) -> Result<Self, IdError> {
                Self::new(s)
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;
            fn try_from(s: String) -> Result<Self, IdError> {
                Self::new(&s)
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

string_id_impls!(RuleRef);
string_id_impls!(ServiceId);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn blake3_hash_hex_roundtrip_with_and_without_prefix() {
        let h = Blake3Hash::hash(b"ward");
        let plain = h.to_string();
        assert_eq!(plain.len(), 64);
        assert_eq!(Blake3Hash::from_hex(&plain).unwrap(), h);
        assert_eq!(format!("blake3:{plain}").parse::<Blake3Hash>().unwrap(), h);
        assert_eq!(
            Blake3Hash::from_hex("zz"),
            Err(IdError::HexLength {
                expected: 64,
                found: 2
            })
        );
        let bad = format!("{}zz", &plain[..62]);
        assert_eq!(
            Blake3Hash::from_hex(&bad),
            Err(IdError::HexDigit { index: 62 })
        );
    }

    #[test]
    fn snapshot_id_display_carries_prefix() {
        let id = SnapshotId::new(Blake3Hash::hash(b"snap"));
        let s = id.to_string();
        assert!(s.starts_with("blake3:"));
        assert_eq!(s.parse::<SnapshotId>().unwrap(), id);
    }

    #[test]
    fn image_digest_requires_sha256_prefix() {
        let d = ImageDigest::from_bytes([7u8; 32]);
        let s = d.to_string();
        assert_eq!(s.parse::<ImageDigest>().unwrap(), d);
        assert_eq!(
            d.to_hex().parse::<ImageDigest>(),
            Err(IdError::Prefix {
                expected: "sha256:"
            })
        );
    }

    #[test]
    fn session_and_project_ids_roundtrip_through_text() {
        let s = SessionId::from_u128(0x0192_8f6a_1234_5678_9abc_def0_1122_3344);
        let text = s.to_string();
        assert!(text.starts_with("sess_"));
        assert_eq!(text.len(), 5 + 26);
        assert_eq!(text.parse::<SessionId>().unwrap(), s);
        assert_eq!(
            SessionId::from_u128(u128::MAX)
                .to_string()
                .parse::<SessionId>()
                .unwrap()
                .as_u128(),
            u128::MAX
        );
        assert_eq!(SessionId::from_u128(0).body(), "0".repeat(26));

        let p = ProjectId::from_u128(42);
        assert_eq!(p.to_string().parse::<ProjectId>().unwrap(), p);
        assert_eq!(
            "sess_".parse::<ProjectId>(),
            Err(IdError::Prefix { expected: "proj_" })
        );
    }

    #[test]
    fn ulid_rejects_bad_alphabet_length_and_overflow() {
        let good = SessionId::from_u128(1).to_string();
        let with_i = good.replacen('0', "I", 1);
        assert_eq!(
            with_i.parse::<SessionId>(),
            Err(IdError::Base32Char { index: 0 })
        );
        assert_eq!(
            "sess_0".parse::<SessionId>(),
            Err(IdError::Base32Length {
                expected: 26,
                found: 1
            })
        );
        let overflow = format!("sess_8{}", "0".repeat(25));
        assert_eq!(overflow.parse::<SessionId>(), Err(IdError::Overflow));
    }

    #[test]
    fn ids_binary_serde_roundtrip() {
        let s = SessionId::from_u128(0xdead_beef);
        let bytes = postcard::to_allocvec(&s).unwrap();
        assert_eq!(bytes.len(), 16);
        let back: SessionId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, s);

        let h = Blake3Hash::hash(b"x");
        let bytes = postcard::to_allocvec(&h).unwrap();
        assert_eq!(bytes.len(), 32);
        let back: Blake3Hash = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn pid_rejects_zero() {
        assert_eq!(Pid::new(0), Err(IdError::ZeroPid));
        assert_eq!(Pid::new(7).unwrap().get(), 7);
        assert_eq!("12".parse::<Pid>().unwrap().get(), 12);
        assert!("0".parse::<Pid>().is_err());
        assert!(postcard::from_bytes::<Pid>(&[0]).is_err());
    }

    #[test]
    fn rule_ref_and_service_id_validation() {
        assert!(RuleRef::new("project:network.allow[2]").is_ok());
        assert_eq!(RuleRef::new(""), Err(IdError::Empty));
        assert_eq!(
            RuleRef::new("has space"),
            Err(IdError::InvalidChar { index: 3 })
        );
        assert_eq!(
            RuleRef::new("ctl\u{1}"),
            Err(IdError::InvalidChar { index: 3 })
        );
        let long = "a".repeat(129);
        assert_eq!(
            RuleRef::new(&long),
            Err(IdError::TooLong {
                max: 128,
                found: 129
            })
        );

        assert!(ServiceId::new("ssh:github").is_ok());
        assert!(ServiceId::new("aws-prod").is_ok());
        assert_eq!(
            ServiceId::new("GitHub"),
            Err(IdError::InvalidChar { index: 0 })
        );
        assert_eq!(ServiceId::new(":x"), Err(IdError::InvalidChar { index: 0 }));
        assert_eq!(
            ServiceId::new("a b"),
            Err(IdError::InvalidChar { index: 1 })
        );

        // Deserialisation validates too.
        let bytes = postcard::to_allocvec("Bad Id").unwrap();
        assert!(postcard::from_bytes::<ServiceId>(&bytes).is_err());
        let bytes = postcard::to_allocvec("ok").unwrap();
        assert_eq!(
            postcard::from_bytes::<ServiceId>(&bytes).unwrap().as_str(),
            "ok"
        );
    }
}
