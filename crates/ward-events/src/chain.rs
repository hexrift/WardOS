//! The record envelope and the per-session hash chain (`event-model.md` §2, §5).
//!
//! # Hash layout
//!
//! `EventRecord::hash` is the `BLAKE3` digest of the following bytes, in order:
//!
//! ```text
//! offset  len  content
//! 0       32   prev             hash of the previous record (genesis: manifest hash)
//! 32       8   seq              u64, little-endian
//! 40       1   origin.tag()     1 = Kernel … 7 = User (see `Origin::tag`)
//! 41       n   postcard(event)  the event body, postcard-encoded
//! ```
//!
//! Nothing else is covered: `session`, `ts_mono` and `ts_wall` are *not* part of the hash
//! (the design document lists exactly `prev || seq || origin || event bytes`). The
//! session id is bound indirectly through the genesis hash, which is the hash of the
//! session's capability manifest.

use core::fmt;
use core::time::Duration;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::event::{EventKind, WardEvent};
use crate::ids::{Blake3Hash, SessionId};
use crate::origin::Origin;

/// Errors from chain construction and verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChainError {
    /// No records were supplied.
    #[error("no records to verify")]
    Empty,
    /// Verification from genesis requires the first record to have `seq == 0`.
    #[error("expected the chain to start at seq 0, found seq {first_seq}")]
    NotGenesis {
        /// Sequence number of the first record supplied.
        first_seq: u64,
    },
    /// A record belongs to a different session.
    #[error("record {seq} belongs to session {found}, expected {expected}")]
    SessionMismatch {
        /// Sequence number of the offending record.
        seq: u64,
        /// The session the chain is for.
        expected: SessionId,
        /// The session the record claims.
        found: SessionId,
    },
    /// One or more records are missing.
    #[error("sequence gap: expected seq {expected}, found {found}")]
    Gap {
        /// Sequence number that should have come next.
        expected: u64,
        /// Sequence number that was found.
        found: u64,
    },
    /// A record was replayed or delivered out of order.
    #[error("sequence replay/reorder: expected seq {expected}, found {found}")]
    Replay {
        /// Sequence number that should have come next.
        expected: u64,
        /// Sequence number that was found.
        found: u64,
    },
    /// A record's `prev` does not match the preceding record's hash.
    #[error("record {seq}: prev {found} does not match chain head {expected}")]
    PrevMismatch {
        /// Sequence number of the offending record.
        seq: u64,
        /// The hash of the preceding record.
        expected: Blake3Hash,
        /// The `prev` field found.
        found: Blake3Hash,
    },
    /// A record's `hash` does not match its content.
    #[error("record {seq}: stored hash {stored} does not match computed {computed}")]
    HashMismatch {
        /// Sequence number of the offending record.
        seq: u64,
        /// The hash stored in the record.
        stored: Blake3Hash,
        /// The hash recomputed from the record's content.
        computed: Blake3Hash,
    },
    /// The sequence counter would overflow.
    #[error("sequence number overflow")]
    SeqOverflow,
    /// The event body could not be encoded.
    #[error("event encoding failed: {0}")]
    Encode(#[from] postcard::Error),
}

/// Timestamps supplied by `wardd` when appending a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Timestamp {
    /// Monotonic time since session genesis.
    pub mono: Duration,
    /// Informational wall-clock time.
    pub wall: Option<SystemTime>,
}

impl Timestamp {
    /// A timestamp with only the monotonic component.
    #[must_use]
    pub const fn mono(mono: Duration) -> Self {
        Self { mono, wall: None }
    }
}

/// One hash-chained record in a session log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    /// The session this record belongs to.
    pub session: SessionId,
    /// Dense per-session sequence number, assigned by `wardd`, starting at 0.
    pub seq: u64,
    /// Monotonic time since session genesis.
    pub ts_mono: Duration,
    /// Informational wall-clock time.
    pub ts_wall: Option<SystemTime>,
    /// Who produced the record.
    pub origin: Origin,
    /// Hash of the previous record (genesis: hash of the capability manifest).
    pub prev: Blake3Hash,
    /// The event.
    pub event: WardEvent,
    /// `BLAKE3(prev || seq_le || origin_tag || postcard(event))`; see the module docs.
    pub hash: Blake3Hash,
}

impl EventRecord {
    /// Computes the record hash for the given components (see the module docs).
    ///
    /// # Errors
    /// Returns [`ChainError::Encode`] if the event cannot be postcard-encoded.
    pub fn compute_hash(
        prev: &Blake3Hash,
        seq: u64,
        origin: Origin,
        event: &WardEvent,
    ) -> Result<Blake3Hash, ChainError> {
        let body = postcard::to_allocvec(event)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(prev.as_bytes());
        hasher.update(&seq.to_le_bytes());
        hasher.update(&[origin.tag()]);
        hasher.update(&body);
        Ok(Blake3Hash::from(hasher.finalize()))
    }

    /// Recomputes this record's hash and compares it to the stored one.
    ///
    /// # Errors
    /// Returns [`ChainError::HashMismatch`] or [`ChainError::Encode`].
    pub fn verify_hash(&self) -> Result<(), ChainError> {
        let computed = Self::compute_hash(&self.prev, self.seq, self.origin, &self.event)?;
        if computed != self.hash {
            return Err(ChainError::HashMismatch {
                seq: self.seq,
                stored: self.hash,
                computed,
            });
        }
        Ok(())
    }

    /// The event's kind.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        self.event.kind()
    }

    /// Whether this record may be used for enforcement decisions.
    #[must_use]
    pub const fn is_enforcement_fact(&self) -> bool {
        self.origin.is_enforcement_fact()
    }
}

/// The verified state of a chain: where it started and where it currently ends.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainHead {
    /// The session.
    pub session: SessionId,
    /// Genesis hash (hash of the capability manifest).
    pub genesis: Blake3Hash,
    /// Sequence number the next record will receive (= number of records so far).
    pub next_seq: u64,
    /// Hash of the latest record, or `genesis` if there are none.
    pub hash: Blake3Hash,
}

impl ChainHead {
    /// Sequence number of the latest record, if any.
    #[must_use]
    pub const fn last_seq(&self) -> Option<u64> {
        if self.next_seq == 0 {
            None
        } else {
            Some(self.next_seq - 1)
        }
    }

    /// Number of records in the chain.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.next_seq
    }

    /// Whether the chain has no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.next_seq == 0
    }
}

impl fmt::Debug for ChainHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainHead")
            .field("session", &self.session)
            .field("genesis", &self.genesis)
            .field("next_seq", &self.next_seq)
            .field("hash", &self.hash)
            .finish()
    }
}

impl fmt::Display for ChainHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} seq={} blake3:{}",
            self.session, self.next_seq, self.hash
        )
    }
}

/// Builder that assigns sequence numbers and hashes to new records.
///
/// `wardd` owns exactly one `Chain` per open session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    head: ChainHead,
}

impl Chain {
    /// Starts a new chain whose genesis hash is the session's capability manifest hash.
    #[must_use]
    pub const fn genesis(session: SessionId, manifest_hash: Blake3Hash) -> Self {
        Self {
            head: ChainHead {
                session,
                genesis: manifest_hash,
                next_seq: 0,
                hash: manifest_hash,
            },
        }
    }

    /// Resumes a chain from a previously verified head (e.g. after `wardd` restarts).
    #[must_use]
    pub const fn resume(head: ChainHead) -> Self {
        Self { head }
    }

    /// Appends an event, returning the fully hashed record.
    ///
    /// # Errors
    /// Returns [`ChainError::SeqOverflow`] or [`ChainError::Encode`].
    pub fn append(
        &mut self,
        origin: Origin,
        event: WardEvent,
        ts: Timestamp,
    ) -> Result<EventRecord, ChainError> {
        let seq = self.head.next_seq;
        let next = seq.checked_add(1).ok_or(ChainError::SeqOverflow)?;
        let prev = self.head.hash;
        let hash = EventRecord::compute_hash(&prev, seq, origin, &event)?;
        let record = EventRecord {
            session: self.head.session,
            seq,
            ts_mono: ts.mono,
            ts_wall: ts.wall,
            origin,
            prev,
            event,
            hash,
        };
        self.head.next_seq = next;
        self.head.hash = hash;
        Ok(record)
    }

    /// The current head.
    #[must_use]
    pub const fn head(&self) -> ChainHead {
        self.head
    }

    /// The session.
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.head.session
    }

    /// Sequence number the next record will receive.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.head.next_seq
    }
}

/// Incremental verifier: feed records in order and it maintains the expected head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainVerifier {
    head: ChainHead,
}

impl ChainVerifier {
    /// Starts verifying from genesis.
    #[must_use]
    pub const fn from_genesis(session: SessionId, manifest_hash: Blake3Hash) -> Self {
        Self::from_head(ChainHead {
            session,
            genesis: manifest_hash,
            next_seq: 0,
            hash: manifest_hash,
        })
    }

    /// Continues verifying after an already-verified head.
    #[must_use]
    pub const fn from_head(head: ChainHead) -> Self {
        Self { head }
    }

    /// Verifies `record` against the expected head and advances.
    ///
    /// The checks are performed in this order: session, sequence (gap / replay), `prev`
    /// linkage, then the record's own hash. On error the verifier's state is unchanged.
    ///
    /// # Errors
    /// See [`ChainError`].
    pub fn push(&mut self, record: &EventRecord) -> Result<(), ChainError> {
        if record.session != self.head.session {
            return Err(ChainError::SessionMismatch {
                seq: record.seq,
                expected: self.head.session,
                found: record.session,
            });
        }
        let expected = self.head.next_seq;
        if record.seq > expected {
            return Err(ChainError::Gap {
                expected,
                found: record.seq,
            });
        }
        if record.seq < expected {
            return Err(ChainError::Replay {
                expected,
                found: record.seq,
            });
        }
        if record.prev != self.head.hash {
            return Err(ChainError::PrevMismatch {
                seq: record.seq,
                expected: self.head.hash,
                found: record.prev,
            });
        }
        record.verify_hash()?;
        let next = expected.checked_add(1).ok_or(ChainError::SeqOverflow)?;
        self.head.next_seq = next;
        self.head.hash = record.hash;
        Ok(())
    }

    /// The verified head so far.
    #[must_use]
    pub const fn head(&self) -> ChainHead {
        self.head
    }
}

/// Verifies a complete chain from genesis.
///
/// The first record must have `seq == 0`; its `prev` is taken as the genesis hash and
/// returned in the head so the caller can compare it with the manifest hash it expects.
///
/// # Errors
/// See [`ChainError`]: gaps, replays/reordering, forged `prev`, and content tampering are
/// each reported distinctly.
pub fn verify(records: &[EventRecord]) -> Result<ChainHead, ChainError> {
    let first = records.first().ok_or(ChainError::Empty)?;
    if first.seq != 0 {
        return Err(ChainError::NotGenesis {
            first_seq: first.seq,
        });
    }
    verify_from(
        ChainHead {
            session: first.session,
            genesis: first.prev,
            next_seq: 0,
            hash: first.prev,
        },
        records,
    )
}

/// Verifies records that continue an already-verified `head`.
///
/// # Errors
/// See [`ChainError`].
pub fn verify_from(head: ChainHead, records: &[EventRecord]) -> Result<ChainHead, ChainError> {
    let mut v = ChainVerifier::from_head(head);
    for r in records {
        v.push(r)?;
    }
    Ok(v.head())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::event::AgentState;

    fn session() -> SessionId {
        SessionId::from_u128(1)
    }

    fn manifest() -> Blake3Hash {
        Blake3Hash::hash(b"manifest")
    }

    fn state(s: AgentState) -> WardEvent {
        WardEvent::AgentStateChanged { state: s }
    }

    fn sample(n: u64) -> Vec<EventRecord> {
        let mut chain = Chain::genesis(session(), manifest());
        (0..n)
            .map(|i| {
                let ev = if i % 2 == 0 {
                    state(AgentState::Working)
                } else {
                    state(AgentState::Idle)
                };
                chain
                    .append(Origin::Wardd, ev, Timestamp::mono(Duration::from_millis(i)))
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn hash_layout_is_exactly_prev_seq_le_origin_tag_event() {
        let ev = state(AgentState::Blocked);
        let prev = Blake3Hash::hash(b"p");
        let mut expected = Vec::new();
        expected.extend_from_slice(prev.as_bytes());
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.push(Origin::Agent.tag());
        expected.extend_from_slice(&postcard::to_allocvec(&ev).unwrap());
        assert_eq!(
            EventRecord::compute_hash(&prev, 7, Origin::Agent, &ev).unwrap(),
            Blake3Hash::hash(&expected)
        );
    }

    #[test]
    fn genesis_links_to_manifest_and_records_chain() {
        let records = sample(3);
        assert_eq!(records[0].prev, manifest());
        assert_eq!(records[0].seq, 0);
        assert_eq!(records[1].prev, records[0].hash);
        assert_eq!(records[2].prev, records[1].hash);
        let head = verify(&records).unwrap();
        assert_eq!(head.genesis, manifest());
        assert_eq!(head.next_seq, 3);
        assert_eq!(head.last_seq(), Some(2));
        assert_eq!(head.hash, records[2].hash);
        assert_eq!(head.session, session());
    }

    #[test]
    fn empty_and_non_genesis_inputs_are_rejected() {
        assert_eq!(verify(&[]), Err(ChainError::Empty));
        let records = sample(3);
        assert_eq!(
            verify(&records[1..]),
            Err(ChainError::NotGenesis { first_seq: 1 })
        );
        // But they verify fine as a continuation of a known head.
        let head = verify(&records[..1]).unwrap();
        assert_eq!(
            verify_from(head, &records[1..]).unwrap(),
            verify(&records).unwrap()
        );
    }

    #[test]
    fn mutated_event_is_detected() {
        let mut records = sample(3);
        records[1].event = state(AgentState::Finished);
        assert!(matches!(
            verify(&records),
            Err(ChainError::HashMismatch { seq: 1, .. })
        ));
    }

    #[test]
    fn mutated_origin_is_detected() {
        let mut records = sample(2);
        records[1].origin = Origin::Agent;
        assert!(matches!(
            verify(&records),
            Err(ChainError::HashMismatch { seq: 1, .. })
        ));
    }

    #[test]
    fn dropped_record_is_a_gap() {
        let mut records = sample(4);
        records.remove(2);
        assert_eq!(
            verify(&records),
            Err(ChainError::Gap {
                expected: 2,
                found: 3
            })
        );
    }

    #[test]
    fn reordered_records_are_detected() {
        let mut records = sample(4);
        records.swap(1, 2);
        assert_eq!(
            verify(&records),
            Err(ChainError::Gap {
                expected: 1,
                found: 2
            })
        );
    }

    #[test]
    fn replayed_record_is_detected() {
        let mut records = sample(3);
        let dup = records[1].clone();
        records.push(dup);
        assert_eq!(
            verify(&records),
            Err(ChainError::Replay {
                expected: 3,
                found: 1
            })
        );
    }

    #[test]
    fn forged_prev_with_recomputed_hash_is_detected() {
        let mut records = sample(3);
        let forged_prev = Blake3Hash::hash(b"forged");
        records[2].prev = forged_prev;
        records[2].hash =
            EventRecord::compute_hash(&forged_prev, 2, records[2].origin, &records[2].event)
                .unwrap();
        assert!(records[2].verify_hash().is_ok());
        assert!(matches!(
            verify(&records),
            Err(ChainError::PrevMismatch { seq: 2, .. })
        ));
    }

    #[test]
    fn rewritten_history_with_recomputed_hashes_moves_the_head() {
        // An attacker who rewrites record 1 and recomputes every later hash produces a
        // self-consistent chain; only the head differs from what an anchor recorded.
        let records = sample(3);
        let honest = verify(&records).unwrap();
        let mut chain = Chain::genesis(session(), manifest());
        chain
            .append(
                Origin::Wardd,
                records[0].event.clone(),
                Timestamp::default(),
            )
            .unwrap();
        chain
            .append(
                Origin::Wardd,
                state(AgentState::Finished),
                Timestamp::default(),
            )
            .unwrap();
        chain
            .append(
                Origin::Wardd,
                records[2].event.clone(),
                Timestamp::default(),
            )
            .unwrap();
        assert_ne!(chain.head().hash, honest.hash);
        assert_eq!(chain.head().next_seq, honest.next_seq);
    }

    #[test]
    fn foreign_session_record_is_rejected() {
        let mut records = sample(2);
        records[1].session = SessionId::from_u128(2);
        assert!(matches!(
            verify(&records),
            Err(ChainError::SessionMismatch { seq: 1, .. })
        ));
    }

    #[test]
    fn verifier_state_is_unchanged_after_an_error() {
        let records = sample(3);
        let mut v = ChainVerifier::from_genesis(session(), manifest());
        v.push(&records[0]).unwrap();
        let before = v.head();
        assert!(v.push(&records[2]).is_err());
        assert_eq!(v.head(), before);
        v.push(&records[1]).unwrap();
        assert_eq!(v.head().next_seq, 2);
    }

    #[test]
    fn resume_continues_the_same_chain() {
        let mut chain = Chain::genesis(session(), manifest());
        let r0 = chain
            .append(Origin::Wardd, state(AgentState::Idle), Timestamp::default())
            .unwrap();
        let mut resumed = Chain::resume(chain.head());
        let r1 = resumed
            .append(
                Origin::User,
                state(AgentState::Working),
                Timestamp::default(),
            )
            .unwrap();
        assert_eq!(r1.prev, r0.hash);
        assert!(verify(&[r0, r1]).is_ok());
    }

    #[test]
    fn seq_overflow_is_an_error_not_a_panic() {
        let mut chain = Chain::resume(ChainHead {
            session: session(),
            genesis: manifest(),
            next_seq: u64::MAX,
            hash: manifest(),
        });
        assert_eq!(
            chain.append(Origin::Wardd, state(AgentState::Idle), Timestamp::default()),
            Err(ChainError::SeqOverflow)
        );
    }
}
