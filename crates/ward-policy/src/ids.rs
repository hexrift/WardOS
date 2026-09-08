//! Strongly-typed identifiers. No security decision interprets a free-form string.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Opaque identifier of a single agent session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub String);

/// Stable identifier of a project (keys its persistent environment).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProjectId(pub String);

/// Content digest of a tool or agent image layer, e.g. `sha256:…`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ImageDigest(pub String);

/// Identifier of a credential-brokered service, e.g. `github` or `cloud-*`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServiceId(pub String);

/// A 32-byte BLAKE3 digest, rendered as lowercase hex on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Blake3Hash(pub [u8; 32]);

impl Blake3Hash {
    /// Lowercase hex rendering of the digest.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            use fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

impl fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Blake3Hash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Blake3Hash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(d)?;
        let bytes = (0..32)
            .map(|i| {
                hex.get(i * 2..i * 2 + 2)
                    .and_then(|p| u8::from_str_radix(p, 16).ok())
                    .ok_or_else(|| serde::de::Error::custom("expected 64 hex chars"))
            })
            .collect::<Result<Vec<u8>, _>>()?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}
