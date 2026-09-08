//! The 32-byte BLAKE3 hash used throughout the event chain.

use serde::{Deserialize, Serialize};

/// A BLAKE3-256 digest. Used for record hashes, chain links, snapshot roots and the
/// truncation proofs kept by the ingest sanitisers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Blake3Hash([u8; 32]);

impl Blake3Hash {
    /// Hash `bytes` with BLAKE3.
    pub fn hash(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    /// Wrap an already-computed digest.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case hex rendering.
    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

impl std::fmt::Debug for Blake3Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Short prefix keeps logs readable, matching the replay renderer.
        write!(f, "blake3:{}…", &self.to_hex()[..12])
    }
}
