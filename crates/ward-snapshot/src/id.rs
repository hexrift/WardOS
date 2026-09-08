//! Content digests, snapshot identifiers, and roles.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::SnapshotError;

/// A BLAKE3 digest, rendered as `blake3:<hex>`.
///
/// Used both for per-file content hashes (Merkle leaves) and for the manifest
/// hash (the Merkle root that names a snapshot).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    /// BLAKE3 of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    /// Lowercase hex of the raw 32 bytes (no `blake3:` prefix).
    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Parse from bare hex (64 chars, no prefix).
    pub fn from_hex(hex: &str) -> Result<Self, SnapshotError> {
        if hex.len() != 64 {
            return Err(SnapshotError::Manifest(format!(
                "bad digest length: {}",
                hex.len()
            )));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let hi = hex_val(chunk[0])?;
            let lo = hex_val(chunk[1])?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

fn hex_val(c: u8) -> Result<u8, SnapshotError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(SnapshotError::Manifest(
            "non-hex character in digest".into(),
        )),
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blake3:{}", self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl FromStr for Digest {
    type Err = SnapshotError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s
            .strip_prefix("blake3:")
            .ok_or_else(|| SnapshotError::Manifest("digest missing blake3: prefix".into()))?;
        Self::from_hex(hex)
    }
}

/// The identity of a snapshot: the BLAKE3 hash of its serialized manifest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SnapshotId(pub Digest);

impl SnapshotId {
    /// The manifest (Merkle-root) digest behind this id.
    pub fn digest(self) -> Digest {
        self.0
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for SnapshotId {
    type Err = SnapshotError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Digest::from_str(s)?))
    }
}

impl Serialize for SnapshotId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SnapshotId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Lifecycle role a stored snapshot plays (see `docs/snapshots-and-git.md` §5).
///
/// The same [`SnapshotId`] may hold more than one role over time (an accepted
/// snapshot reuses the candidate's id under a new role record).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotRole {
    /// Captured at session start.
    Entry,
    /// Captured for a verification request.
    Candidate,
    /// A candidate that verification accepted.
    Accepted,
    /// Captured at session end.
    Final,
}

impl SnapshotRole {
    /// Stable lowercase token, used in metadata filenames.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::Candidate => "candidate",
            Self::Accepted => "accepted",
            Self::Final => "final",
        }
    }
}

impl fmt::Display for SnapshotRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
