//! Versioned, size-bounded wire format.
//!
//! This is the Zone 3 → Zone 0 decoder, so [`from_bytes`] is deliberately defensive: it
//! rejects empty input, input larger than [`MAX_WIRE_BYTES`], and any unrecognised format
//! version before handing the remainder to `postcard`.

use serde::{Serialize, de::DeserializeOwned};

/// Leading byte identifying the encoding of everything after it.
pub const FORMAT_VERSION: u8 = 1;

/// Hard cap on the size of an encoded value accepted by [`from_bytes`] (1 MiB).
pub const MAX_WIRE_BYTES: usize = 1 << 20;

/// A wire encode/decode failure.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// Serialisation failed.
    #[error("serialisation failed: {0}")]
    Encode(postcard::Error),
    /// Deserialisation failed.
    #[error("deserialisation failed: {0}")]
    Decode(postcard::Error),
    /// The input was empty.
    #[error("empty input")]
    Empty,
    /// The leading version byte was not understood.
    #[error("unsupported wire format version {found} (expected {expected})")]
    Version {
        /// Version byte found on the input.
        found: u8,
        /// Version byte this build understands.
        expected: u8,
    },
    /// The input exceeded [`MAX_WIRE_BYTES`].
    #[error("input of {size} bytes exceeds the {max}-byte limit")]
    TooLarge {
        /// Size of the rejected input.
        size: usize,
        /// The enforced maximum.
        max: usize,
    },
}

/// Encode a value as a version-prefixed `postcard` byte string.
///
/// # Errors
/// Returns [`WireError::Encode`] if `postcard` serialisation fails.
pub fn to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, WireError> {
    let body = postcard::to_allocvec(value).map_err(WireError::Encode)?;
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a value from a version-prefixed `postcard` byte string.
///
/// # Errors
/// Returns [`WireError::TooLarge`] if the input exceeds [`MAX_WIRE_BYTES`],
/// [`WireError::Empty`] on empty input, [`WireError::Version`] on an unknown format byte,
/// or [`WireError::Decode`] if `postcard` deserialisation fails.
pub fn from_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WireError> {
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(WireError::TooLarge {
            size: bytes.len(),
            max: MAX_WIRE_BYTES,
        });
    }
    let (&version, body) = bytes.split_first().ok_or(WireError::Empty)?;
    if version != FORMAT_VERSION {
        return Err(WireError::Version {
            found: version,
            expected: FORMAT_VERSION,
        });
    }
    postcard::from_bytes(body).map_err(WireError::Decode)
}
