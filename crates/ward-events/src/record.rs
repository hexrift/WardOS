//! The [`EventRecord`] envelope and the BLAKE3 hash [`Chain`] that seals a session log.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::event::{Origin, WardEvent};
use crate::hash::Blake3Hash;
use crate::ids::SessionId;
use crate::wire::WireError;

/// One record in a session's append-only, hash-chained log (event-model §2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    /// The session this record belongs to.
    pub session: SessionId,
    /// Dense per-session sequence number, assigned by `wardd`.
    pub seq: u64,
    /// Monotonic time since session genesis.
    pub ts_mono: Duration,
    /// Informational wall-clock time.
    pub ts_wall: Option<SystemTime>,
    /// The producer of the record — the primary trust signal.
    pub origin: Origin,
    /// Hash of the previous record (genesis: hash of the manifest).
    pub prev: Blake3Hash,
    /// The event payload.
    pub event: WardEvent,
    /// `BLAKE3(prev || seq || origin || event bytes)`.
    pub hash: Blake3Hash,
}

/// Compute a record hash over `prev || seq(LE) || origin || postcard(event)`.
fn record_hash(
    prev: &Blake3Hash,
    seq: u64,
    origin: Origin,
    event: &WardEvent,
) -> Result<Blake3Hash, WireError> {
    let event_bytes = postcard::to_allocvec(event).map_err(WireError::Encode)?;
    let mut h = blake3::Hasher::new();
    h.update(prev.as_bytes());
    h.update(&seq.to_le_bytes());
    h.update(&[origin.code()]);
    h.update(&event_bytes);
    Ok(Blake3Hash::from_bytes(*h.finalize().as_bytes()))
}

/// Chain verification failure, naming the offending sequence number.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    /// A record's stored hash does not match its recomputed hash.
    #[error("record at seq {seq} has a mismatched hash")]
    HashMismatch {
        /// The offending sequence number.
        seq: u64,
    },
    /// A record does not link to its predecessor's hash.
    #[error("record at seq {seq} does not chain to its predecessor")]
    BrokenLink {
        /// The offending sequence number.
        seq: u64,
    },
    /// Sequence numbers are not dense and ascending by one.
    #[error("record at seq {seq} breaks dense sequencing")]
    SequenceGap {
        /// The offending sequence number.
        seq: u64,
    },
    /// A record's event could not be re-encoded for hashing.
    #[error("record at seq {seq} could not be re-encoded")]
    Encode {
        /// The offending sequence number.
        seq: u64,
    },
}

impl VerifyError {
    /// The sequence number of the offending record.
    pub fn seq(&self) -> u64 {
        match *self {
            VerifyError::HashMismatch { seq }
            | VerifyError::BrokenLink { seq }
            | VerifyError::SequenceGap { seq }
            | VerifyError::Encode { seq } => seq,
        }
    }
}

/// Appends events to a session log, assigning dense sequence numbers and maintaining the
/// BLAKE3 hash chain.
#[derive(Clone, Debug)]
pub struct Chain {
    session: SessionId,
    next_seq: u64,
    head: Blake3Hash,
}

impl Chain {
    /// Start a chain for `session`, anchored at `genesis` (the manifest hash).
    pub fn new(session: SessionId, genesis: Blake3Hash) -> Self {
        Self {
            session,
            next_seq: 0,
            head: genesis,
        }
    }

    /// The current chain head (hash of the last appended record, or genesis).
    pub fn head(&self) -> Blake3Hash {
        self.head
    }

    /// The sequence number the next appended record will receive.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Append an event, producing a sealed [`EventRecord`] and advancing the chain.
    ///
    /// # Errors
    /// Returns [`WireError::Encode`] if the event cannot be serialised for hashing.
    pub fn append(
        &mut self,
        origin: Origin,
        ts_mono: Duration,
        ts_wall: Option<SystemTime>,
        event: WardEvent,
    ) -> Result<EventRecord, WireError> {
        let seq = self.next_seq;
        let prev = self.head;
        let hash = record_hash(&prev, seq, origin, &event)?;
        self.next_seq += 1;
        self.head = hash;
        Ok(EventRecord {
            session: self.session.clone(),
            seq,
            ts_mono,
            ts_wall,
            origin,
            prev,
            event,
            hash,
        })
    }

    /// Verify an ordered slice of records: dense sequencing, correct per-record hashes and
    /// intact `prev` links. The first record's `prev` is taken as the chain anchor.
    ///
    /// # Errors
    /// Returns the [`VerifyError`] naming the sequence number of the first record that
    /// fails a check.
    pub fn verify(records: &[EventRecord]) -> Result<(), VerifyError> {
        for (i, rec) in records.iter().enumerate() {
            if i > 0 {
                let prior = &records[i - 1];
                if rec.seq != prior.seq + 1 {
                    return Err(VerifyError::SequenceGap { seq: rec.seq });
                }
                if rec.prev != prior.hash {
                    return Err(VerifyError::BrokenLink { seq: rec.seq });
                }
            }
            let recomputed = record_hash(&rec.prev, rec.seq, rec.origin, &rec.event)
                .map_err(|_| VerifyError::Encode { seq: rec.seq })?;
            if recomputed != rec.hash {
                return Err(VerifyError::HashMismatch { seq: rec.seq });
            }
        }
        Ok(())
    }
}
