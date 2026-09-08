//! Content hashes and snapshot identifiers (BLAKE3, 32 bytes, lowercase hex).

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Files at or above this size are hashed through BLAKE3's memory-mapped, multi-threaded
/// path (`update_mmap_rayon`); smaller files are read with a plain buffered loop, which
/// is faster for the many-small-files case that dominates real worktrees.
pub const MMAP_THRESHOLD: u64 = 4 * 1024 * 1024;

/// Hex-encode 32 bytes.
fn to_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[usize::from(b >> 4)] as char);
        s.push(HEX[usize::from(b & 0x0f)] as char);
    }
    s
}

/// Decode exactly 64 lowercase hex characters.
fn from_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// BLAKE3 hash of an entry's content (file bytes or symlink target).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    /// The "no content" marker used for directories and unsupported entries (all zero
    /// bytes). It is not the hash of anything.
    pub const NONE: ContentHash = ContentHash([0u8; 32]);

    /// Hash an in-memory buffer.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        ContentHash(*blake3::hash(bytes).as_bytes())
    }

    /// Hash the contents of a regular file.
    ///
    /// Large files (see [`MMAP_THRESHOLD`]) are memory-mapped and hashed on the rayon
    /// pool; a file truncated *while* mapped can raise `SIGBUS`, which is why capture
    /// assumes a quiescent (frozen) tree. Returns the hash and the number of bytes read.
    ///
    /// # Errors
    /// I/O errors opening or reading `path`.
    pub fn of_file(path: &Path) -> Result<(Self, u64)> {
        let mut file = File::open(path).map_err(|e| Error::io("open", path, e))?;
        let len = file
            .metadata()
            .map_err(|e| Error::io("stat", path, e))?
            .len();
        let mut hasher = blake3::Hasher::new();
        if len >= MMAP_THRESHOLD {
            hasher
                .update_mmap_rayon(path)
                .map_err(|e| Error::io("read", path, e))?;
            return Ok((ContentHash(*hasher.finalize().as_bytes()), len));
        }
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| Error::io("read", path, e))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total += n as u64;
        }
        Ok((ContentHash(*hasher.finalize().as_bytes()), total))
    }

    /// Hash everything readable from `reader`.
    ///
    /// # Errors
    /// I/O errors from the reader.
    pub fn of_reader(mut reader: impl Read) -> std::io::Result<(Self, u64)> {
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total += n as u64;
        }
        Ok((ContentHash(*hasher.finalize().as_bytes()), total))
    }

    /// The raw 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        ContentHash(bytes)
    }

    /// Lowercase hex encoding (64 characters).
    #[must_use]
    pub fn to_hex(self) -> String {
        to_hex(&self.0)
    }

    /// True for [`ContentHash::NONE`].
    #[must_use]
    pub fn is_none(&self) -> bool {
        *self == Self::NONE
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({})", self.to_hex())
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for ContentHash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        from_hex(s)
            .map(ContentHash)
            .ok_or_else(|| Error::ManifestParse {
                index: 0,
                reason: format!("invalid content hash {s:?}"),
            })
    }
}

/// Identity of a snapshot: BLAKE3 over the canonical manifest bytes.
///
/// Rendered as `blake3:<hex>` by [`fmt::Display`]; [`FromStr`] accepts both the prefixed
/// and the bare hex form.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SnapshotId([u8; 32]);

impl SnapshotId {
    /// Compute the id of canonical manifest bytes.
    #[must_use]
    pub fn of_manifest_bytes(bytes: &[u8]) -> Self {
        SnapshotId(*blake3::hash(bytes).as_bytes())
    }

    /// The raw 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SnapshotId(bytes)
    }

    /// Lowercase hex encoding without the `blake3:` prefix (used for file names).
    #[must_use]
    pub fn to_hex(self) -> String {
        to_hex(&self.0)
    }
}

impl fmt::Debug for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SnapshotId(blake3:{})", self.to_hex())
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blake3:{}", self.to_hex())
    }
}

impl FromStr for SnapshotId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let hex = s.strip_prefix("blake3:").unwrap_or(s);
        from_hex(hex)
            .map(SnapshotId)
            .ok_or_else(|| Error::ManifestParse {
                index: 0,
                reason: format!("invalid snapshot id {s:?}"),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let h = ContentHash::of(b"hello");
        let parsed: Option<ContentHash> = h.to_hex().parse().ok();
        assert_eq!(parsed, Some(h));
        assert_eq!(h.to_hex().len(), 64);
        assert!("zz".parse::<ContentHash>().is_err());
        assert!("ABCDEF".repeat(11).parse::<ContentHash>().is_err());
    }

    #[test]
    fn snapshot_id_display_prefix() {
        let id = SnapshotId::of_manifest_bytes(b"");
        let s = id.to_string();
        assert!(s.starts_with("blake3:"));
        assert_eq!(s.parse::<SnapshotId>().ok(), Some(id));
        assert_eq!(id.to_hex().parse::<SnapshotId>().ok(), Some(id));
    }

    #[test]
    fn known_vector() {
        // BLAKE3 of the empty input.
        assert_eq!(
            ContentHash::of(b"").to_hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }
}
