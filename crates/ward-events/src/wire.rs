//! Wire format for records and subscription messages (`event-model.md` §2, §6).
//!
//! # Frame layout
//!
//! ```text
//! offset  len  content
//! 0        2   magic       b"WE"
//! 2        1   version     WIRE_VERSION (1)
//! 3        1   kind        1 = EventRecord, 2 = Subscribe
//! 4        4   length      payload length, u32 little-endian
//! 8        n   payload     postcard-encoded body
//! ```
//!
//! A frame is at most [`MAX_FRAME_LEN`] bytes (64 KiB) including the header. Decoders
//! check the length field against that cap **before** allocating or reading the payload,
//! so a hostile length can never cause a large allocation (threat-model ST-017).

use std::io::{self, Read};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::chain::{ChainError, EventRecord};
use crate::event::{ClaimKind, EventKind, EventKindSet};
use crate::ids::SessionId;
use crate::origin::{Origin, OriginSet};

/// Frame magic.
pub const MAGIC: [u8; 2] = *b"WE";
/// Current wire version.
pub const WIRE_VERSION: u8 = 1;
/// Header length in bytes.
pub const HEADER_LEN: usize = 8;
/// Hard maximum frame size including the header.
pub const MAX_FRAME_LEN: usize = 64 * 1024;
/// Hard maximum payload size.
pub const MAX_PAYLOAD_LEN: usize = MAX_FRAME_LEN - HEADER_LEN;

/// Errors from encoding and decoding frames.
#[derive(Debug, Error)]
pub enum WireError {
    /// The magic bytes were wrong.
    #[error("bad frame magic")]
    BadMagic,
    /// The version byte is not supported.
    #[error("unsupported wire version {0}")]
    UnsupportedVersion(u8),
    /// The kind byte is unknown.
    #[error("unknown frame kind {0}")]
    UnknownKind(u8),
    /// The frame kind did not match what the caller asked for.
    #[error("expected a {expected:?} frame, found {found:?}")]
    UnexpectedKind {
        /// The kind the caller wanted.
        expected: FrameKind,
        /// The kind found.
        found: FrameKind,
    },
    /// The length field exceeds [`MAX_PAYLOAD_LEN`].
    #[error("frame payload of {len} bytes exceeds the {max}-byte limit")]
    Oversized {
        /// Length claimed by the header.
        len: usize,
        /// The limit.
        max: usize,
    },
    /// The input ended before the frame was complete.
    #[error("truncated frame: needed {needed} bytes, had {available}")]
    Truncated {
        /// Bytes the frame needs in total.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
    /// The payload had bytes left over after decoding the body.
    #[error("{0} trailing bytes after the frame body")]
    TrailingBytes(usize),
    /// Postcard decoding failed.
    #[error("frame body decoding failed: {0}")]
    Decode(postcard::Error),
    /// Postcard encoding failed.
    #[error("frame body encoding failed: {0}")]
    Encode(postcard::Error),
    /// A decoded record's stored hash did not match its content.
    #[error(transparent)]
    Chain(#[from] ChainError),
    /// An I/O error while reading or writing a frame.
    #[error("frame I/O failed: {0}")]
    Io(#[from] io::Error),
}

/// What a frame carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameKind {
    /// An [`EventRecord`].
    Record = 1,
    /// A [`Subscribe`] request.
    Subscribe = 2,
}

impl FrameKind {
    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(FrameKind::Record),
            2 => Some(FrameKind::Subscribe),
            _ => None,
        }
    }
}

/// A parsed frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// What the payload carries.
    pub kind: FrameKind,
    /// Payload length in bytes (already checked against [`MAX_PAYLOAD_LEN`]).
    pub payload_len: usize,
}

impl FrameHeader {
    /// Total frame length including the header.
    #[must_use]
    pub const fn frame_len(&self) -> usize {
        HEADER_LEN + self.payload_len
    }
}

/// Parses and validates a frame header from the first [`HEADER_LEN`] bytes of `buf`.
///
/// # Errors
/// [`WireError::Truncated`] if fewer than [`HEADER_LEN`] bytes are available, and the
/// magic / version / kind / size errors otherwise. Oversized frames are rejected here,
/// before any payload is touched.
pub fn peek_header(buf: &[u8]) -> Result<FrameHeader, WireError> {
    let header: [u8; HEADER_LEN] = buf
        .get(..HEADER_LEN)
        .and_then(|h| h.try_into().ok())
        .ok_or(WireError::Truncated {
            needed: HEADER_LEN,
            available: buf.len(),
        })?;
    parse_header(header)
}

fn parse_header(h: [u8; HEADER_LEN]) -> Result<FrameHeader, WireError> {
    if h[..2] != MAGIC {
        return Err(WireError::BadMagic);
    }
    if h[2] != WIRE_VERSION {
        return Err(WireError::UnsupportedVersion(h[2]));
    }
    let kind = FrameKind::from_byte(h[3]).ok_or(WireError::UnknownKind(h[3]))?;
    let len = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
    let payload_len = usize::try_from(len).map_err(|_| WireError::Oversized {
        len: usize::MAX,
        max: MAX_PAYLOAD_LEN,
    })?;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(WireError::Oversized {
            len: payload_len,
            max: MAX_PAYLOAD_LEN,
        });
    }
    Ok(FrameHeader { kind, payload_len })
}

fn encode_frame<T: Serialize>(kind: FrameKind, body: &T) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::with_capacity(HEADER_LEN + 256);
    out.extend_from_slice(&MAGIC);
    out.push(WIRE_VERSION);
    out.push(kind as u8);
    out.extend_from_slice(&[0u8; 4]);
    let out = postcard::to_extend(body, out).map_err(WireError::Encode)?;
    let payload_len = out.len() - HEADER_LEN;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(WireError::Oversized {
            len: payload_len,
            max: MAX_PAYLOAD_LEN,
        });
    }
    let len = u32::try_from(payload_len).map_err(|_| WireError::Oversized {
        len: payload_len,
        max: MAX_PAYLOAD_LEN,
    })?;
    let mut out = out;
    out[4..8].copy_from_slice(&len.to_le_bytes());
    Ok(out)
}

fn decode_body<'a, T: Deserialize<'a>>(payload: &'a [u8]) -> Result<T, WireError> {
    let (value, rest) = postcard::take_from_bytes::<T>(payload).map_err(WireError::Decode)?;
    if !rest.is_empty() {
        return Err(WireError::TrailingBytes(rest.len()));
    }
    Ok(value)
}

/// Splits one frame of the expected `kind` off the front of `buf`.
///
/// Returns the payload slice and the total number of bytes consumed.
fn split_frame(buf: &[u8], kind: FrameKind) -> Result<(&[u8], usize), WireError> {
    let header = peek_header(buf)?;
    if header.kind != kind {
        return Err(WireError::UnexpectedKind {
            expected: kind,
            found: header.kind,
        });
    }
    let total = header.frame_len();
    let payload = buf.get(HEADER_LEN..total).ok_or(WireError::Truncated {
        needed: total,
        available: buf.len(),
    })?;
    Ok((payload, total))
}

/// Encodes a record as one frame.
///
/// # Errors
/// [`WireError::Encode`] or [`WireError::Oversized`].
pub fn encode_record(record: &EventRecord) -> Result<Vec<u8>, WireError> {
    encode_frame(FrameKind::Record, record)
}

/// Decodes one record frame from the front of `buf`, returning it and the number of
/// bytes consumed. The record's own hash is verified; chain linkage is the caller's job.
///
/// # Errors
/// See [`WireError`]. Oversized frames are refused from the header alone.
pub fn decode_record(buf: &[u8]) -> Result<(EventRecord, usize), WireError> {
    let (payload, consumed) = split_frame(buf, FrameKind::Record)?;
    let record: EventRecord = decode_body(payload)?;
    record.verify_hash()?;
    Ok((record, consumed))
}

/// Encodes a subscription request as one frame.
///
/// # Errors
/// [`WireError::Encode`] or [`WireError::Oversized`].
pub fn encode_subscribe(sub: &Subscribe) -> Result<Vec<u8>, WireError> {
    encode_frame(FrameKind::Subscribe, sub)
}

/// Decodes one subscription frame from the front of `buf`.
///
/// # Errors
/// See [`WireError`].
pub fn decode_subscribe(buf: &[u8]) -> Result<(Subscribe, usize), WireError> {
    let (payload, consumed) = split_frame(buf, FrameKind::Subscribe)?;
    Ok((decode_body(payload)?, consumed))
}

/// A raw frame read from a stream: header plus undecoded payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawFrame {
    /// The header.
    pub header: FrameHeader,
    /// The payload bytes.
    pub payload: Vec<u8>,
}

impl RawFrame {
    /// Decodes the payload as a record (verifying its hash).
    ///
    /// # Errors
    /// See [`WireError`].
    pub fn into_record(self) -> Result<EventRecord, WireError> {
        if self.header.kind != FrameKind::Record {
            return Err(WireError::UnexpectedKind {
                expected: FrameKind::Record,
                found: self.header.kind,
            });
        }
        let record: EventRecord = decode_body(&self.payload)?;
        record.verify_hash()?;
        Ok(record)
    }

    /// Decodes the payload as a subscription request.
    ///
    /// # Errors
    /// See [`WireError`].
    pub fn into_subscribe(self) -> Result<Subscribe, WireError> {
        if self.header.kind != FrameKind::Subscribe {
            return Err(WireError::UnexpectedKind {
                expected: FrameKind::Subscribe,
                found: self.header.kind,
            });
        }
        decode_body(&self.payload)
    }
}

/// Reads one frame from `reader`.
///
/// Returns `Ok(None)` on a clean end of stream (no bytes at all). The payload buffer is
/// allocated only after the header has been validated against [`MAX_PAYLOAD_LEN`].
///
/// # Errors
/// [`WireError::Truncated`] if the stream ends mid-frame; [`WireError::Io`] for other I/O
/// failures; header errors as in [`peek_header`].
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<RawFrame>, WireError> {
    let mut header = [0u8; HEADER_LEN];
    let mut filled = 0usize;
    while filled < HEADER_LEN {
        let n = reader.read(&mut header[filled..])?;
        if n == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(WireError::Truncated {
                needed: HEADER_LEN,
                available: filled,
            });
        }
        filled += n;
    }
    let header = parse_header(header)?;
    let mut payload = vec![0u8; header.payload_len];
    let mut filled = 0usize;
    while filled < payload.len() {
        let n = reader.read(&mut payload[filled..])?;
        if n == 0 {
            return Err(WireError::Truncated {
                needed: header.frame_len(),
                available: HEADER_LEN + filled,
            });
        }
        filled += n;
    }
    Ok(Some(RawFrame { header, payload }))
}

// ---------------------------------------------------------------------------------------
// Subscription API
// ---------------------------------------------------------------------------------------

/// Which records a subscriber wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Filter {
    /// Origins to include.
    pub origins: OriginSet,
    /// Event kinds to include.
    pub kinds: EventKindSet,
    /// Drop `AgentClaim { kind: Note }` records (the Live observer mode).
    pub exclude_agent_notes: bool,
}

impl Filter {
    /// Everything.
    pub const ALL: Self = Self {
        origins: OriginSet::ALL,
        kinds: EventKindSet::ALL,
        exclude_agent_notes: false,
    };

    /// Everything except agent notes (`event-model.md` §7, Live mode).
    #[must_use]
    pub const fn live() -> Self {
        Self {
            exclude_agent_notes: true,
            ..Self::ALL
        }
    }

    /// The Quiet observer mode: state changes, policy denials, capability requests and
    /// decisions, verification outcomes, the host's interventions, session end.
    #[must_use]
    pub const fn quiet() -> Self {
        Self {
            origins: OriginSet::ALL,
            kinds: EventKindSet::EMPTY
                .with(EventKind::AgentStateChanged)
                .with(EventKind::PolicyDenied)
                .with(EventKind::TamperDetected)
                .with(EventKind::CapabilityRequested)
                .with(EventKind::CapabilityDecided)
                .with(EventKind::VerificationPassed)
                .with(EventKind::VerificationFailed)
                .with(EventKind::SessionPaused)
                .with(EventKind::SessionResumed)
                .with(EventKind::EntryRestored)
                .with(EventKind::SessionEnded),
            exclude_agent_notes: true,
        }
    }

    /// Only enforcement facts, of every kind. What `TamperWard` subscribes to.
    #[must_use]
    pub const fn enforcement_facts() -> Self {
        Self {
            origins: OriginSet::enforcement_facts(),
            ..Self::ALL
        }
    }

    /// Whether `record` passes this filter.
    #[must_use]
    pub fn matches(self, record: &EventRecord) -> bool {
        self.origins.contains(record.origin)
            && self.kinds.contains(record.kind())
            && !(self.exclude_agent_notes && record.event.claim_kind() == Some(ClaimKind::Note))
    }
}

impl Default for Filter {
    fn default() -> Self {
        Self::ALL
    }
}

/// A subscription request sent to `wardd`'s event socket (`event-model.md` §6).
///
/// The subscriber receives matching records from `from_seq` onwards, in order. A slow
/// subscriber is dropped and must resubscribe from the last sequence number it saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Subscribe {
    /// The session to follow.
    pub session: SessionId,
    /// First sequence number to deliver.
    pub from_seq: u64,
    /// What to deliver.
    pub filter: Filter,
}

impl Subscribe {
    /// Subscribes to everything from the start of `session`.
    #[must_use]
    pub const fn all(session: SessionId) -> Self {
        Self {
            session,
            from_seq: 0,
            filter: Filter::ALL,
        }
    }

    /// Whether `record` should be delivered to this subscriber.
    #[must_use]
    pub fn wants(&self, record: &EventRecord) -> bool {
        record.session == self.session && record.seq >= self.from_seq && self.filter.matches(record)
    }
}

/// Convenience: the enforcement-fact origins, for callers building filters.
#[must_use]
pub const fn enforcement_origins() -> [Origin; 6] {
    [
        Origin::Kernel,
        Origin::Proxy,
        Origin::Wardd,
        Origin::Verifier,
        Origin::TamperWard,
        Origin::User,
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use core::time::Duration;

    use super::*;
    use crate::chain::{Chain, Timestamp};
    use crate::event::{AgentState, PayloadText, WardEvent};
    use crate::ids::Blake3Hash;

    fn record() -> EventRecord {
        let mut chain = Chain::genesis(SessionId::from_u128(9), Blake3Hash::hash(b"m"));
        chain
            .append(
                Origin::Wardd,
                WardEvent::AgentStateChanged {
                    state: AgentState::Working,
                },
                Timestamp::mono(Duration::from_secs(1)),
            )
            .unwrap()
    }

    #[test]
    fn record_frame_roundtrip_and_header() {
        let r = record();
        let bytes = encode_record(&r).unwrap();
        assert_eq!(&bytes[..2], b"WE");
        assert_eq!(bytes[2], WIRE_VERSION);
        assert_eq!(bytes[3], FrameKind::Record as u8);
        let header = peek_header(&bytes).unwrap();
        assert_eq!(header.frame_len(), bytes.len());
        let (back, consumed) = decode_record(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(back, r);

        // Two frames back to back decode independently.
        let mut two = bytes.clone();
        two.extend_from_slice(&bytes);
        let (_, first) = decode_record(&two).unwrap();
        let (_, second) = decode_record(&two[first..]).unwrap();
        assert_eq!(first + second, two.len());
    }

    #[test]
    fn oversized_length_is_rejected_from_the_header_alone() {
        let mut bytes = encode_record(&record()).unwrap();
        bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            peek_header(&bytes),
            Err(WireError::Oversized { .. })
        ));
        assert!(matches!(
            decode_record(&bytes),
            Err(WireError::Oversized { .. })
        ));
        let just_over = u32::try_from(MAX_PAYLOAD_LEN + 1).unwrap();
        bytes[4..8].copy_from_slice(&just_over.to_le_bytes());
        assert!(matches!(
            peek_header(&bytes),
            Err(WireError::Oversized { len, max }) if len == MAX_PAYLOAD_LEN + 1 && max == MAX_PAYLOAD_LEN
        ));
        // A header claiming a huge payload over a stream must not allocate: the reader
        // sees only 8 bytes and fails on the header.
        let mut cursor = io::Cursor::new(bytes[..HEADER_LEN].to_vec());
        assert!(matches!(
            read_frame(&mut cursor),
            Err(WireError::Oversized { .. })
        ));
    }

    #[test]
    fn oversized_bodies_are_refused_at_encode_time() {
        let mut chain = Chain::genesis(SessionId::from_u128(1), Blake3Hash::ZERO);
        let mut record = chain
            .append(
                Origin::Agent,
                WardEvent::AgentClaim {
                    kind: ClaimKind::Plan,
                    payload: PayloadText::new("x"),
                },
                Timestamp::default(),
            )
            .unwrap();
        // Bypass the typed caps by giving the record an unbounded vector field.
        record.event = WardEvent::SessionStarted {
            project: crate::ids::ProjectId::from_u128(1),
            agent: crate::event::AgentIdentity {
                kind: crate::event::AgentKind::Other,
                name: "a".into(),
                version: "b".into(),
                image: None,
            },
            manifest_hash: Blake3Hash::ZERO,
            entry_snapshot: crate::ids::SnapshotId::new(Blake3Hash::ZERO),
            policy_hash: Blake3Hash::ZERO,
            tool_images: vec![crate::ids::ImageDigest::from_bytes([1; 32]); 3000],
        };
        assert!(matches!(
            encode_record(&record),
            Err(WireError::Oversized { .. })
        ));
    }

    #[test]
    fn bad_magic_version_kind_and_truncation_are_distinct_errors() {
        let bytes = encode_record(&record()).unwrap();
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert!(matches!(decode_record(&bad), Err(WireError::BadMagic)));
        let mut bad = bytes.clone();
        bad[2] = 9;
        assert!(matches!(
            decode_record(&bad),
            Err(WireError::UnsupportedVersion(9))
        ));
        let mut bad = bytes.clone();
        bad[3] = 0;
        assert!(matches!(
            decode_record(&bad),
            Err(WireError::UnknownKind(0))
        ));
        let mut bad = bytes.clone();
        bad[3] = FrameKind::Subscribe as u8;
        assert!(matches!(
            decode_record(&bad),
            Err(WireError::UnexpectedKind { .. })
        ));
        assert!(matches!(
            decode_record(&bytes[..5]),
            Err(WireError::Truncated { .. })
        ));
        assert!(matches!(
            decode_record(&bytes[..bytes.len() - 1]),
            Err(WireError::Truncated { needed, .. }) if needed == bytes.len()
        ));
        let mut cursor = io::Cursor::new(bytes[..bytes.len() - 3].to_vec());
        assert!(matches!(
            read_frame(&mut cursor),
            Err(WireError::Truncated { .. })
        ));
        let mut empty = io::Cursor::new(Vec::new());
        assert!(read_frame(&mut empty).unwrap().is_none());
    }

    #[test]
    fn trailing_bytes_and_corrupted_hash_are_rejected() {
        let mut bytes = encode_record(&record()).unwrap();
        bytes.push(0);
        let len = u32::try_from(bytes.len() - HEADER_LEN).unwrap();
        bytes[4..8].copy_from_slice(&len.to_le_bytes());
        assert!(matches!(
            decode_record(&bytes),
            Err(WireError::TrailingBytes(1))
        ));

        let mut r = record();
        r.hash = Blake3Hash::ZERO;
        let bytes = encode_record(&r).unwrap();
        assert!(matches!(
            decode_record(&bytes),
            Err(WireError::Chain(ChainError::HashMismatch { .. }))
        ));
    }

    #[test]
    fn read_frame_roundtrip_over_a_stream() {
        let r = record();
        let bytes = encode_record(&r).unwrap();
        let mut cursor = io::Cursor::new([bytes.clone(), bytes].concat());
        let a = read_frame(&mut cursor).unwrap().unwrap();
        let b = read_frame(&mut cursor).unwrap().unwrap();
        assert!(read_frame(&mut cursor).unwrap().is_none());
        assert_eq!(a.into_record().unwrap(), r);
        assert!(b.into_subscribe().is_err());
    }

    #[test]
    fn subscribe_roundtrip_and_filters() {
        let r = record();
        let sub = Subscribe {
            session: r.session,
            from_seq: 0,
            filter: Filter::enforcement_facts(),
        };
        let bytes = encode_subscribe(&sub).unwrap();
        let (back, n) = decode_subscribe(&bytes).unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(back, sub);
        assert!(matches!(
            decode_record(&bytes),
            Err(WireError::UnexpectedKind { .. })
        ));

        assert!(sub.wants(&r));
        let later = Subscribe { from_seq: 1, ..sub };
        assert!(!later.wants(&r));
        let other = Subscribe {
            session: SessionId::from_u128(2),
            ..sub
        };
        assert!(!other.wants(&r));

        let mut agent = r.clone();
        agent.origin = Origin::Agent;
        assert!(!Filter::enforcement_facts().matches(&agent));
        assert!(Filter::ALL.matches(&agent));
        assert!(Filter::quiet().matches(&r));
        let mut file = r.clone();
        file.event = WardEvent::AgentClaim {
            kind: ClaimKind::Note,
            payload: "n".into(),
        };
        assert!(!Filter::live().matches(&file));
        assert!(Filter::ALL.matches(&file));
        file.event = WardEvent::AgentClaim {
            kind: ClaimKind::ToolUse,
            payload: "t".into(),
        };
        assert!(Filter::live().matches(&file));
        assert!(!Filter::quiet().matches(&file));
        assert_eq!(enforcement_origins().len(), 6);
        assert!(!enforcement_origins().contains(&Origin::Agent));
    }
}
