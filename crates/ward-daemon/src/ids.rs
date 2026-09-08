//! Id generation and cross-crate id bridges.
//!
//! Each Phase 1 crate defines its own id newtypes so it can be built and tested
//! independently. The daemon is where they meet, so the few conversions live here.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ward_events::{Blake3Hash as EvHash, ProjectId, SessionId, SnapshotId as EvSnapshotId};
use ward_snapshot::SnapshotId as SnapSnapshotId;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh, time-ordered session id (ULID-shaped: 48-bit ms timestamp, 80 random bits).
pub fn new_session_id() -> SessionId {
    SessionId::from_u128(ulid_u128())
}

/// A stable project id derived from the canonical project path.
pub fn project_id_for(path: &std::path::Path) -> ProjectId {
    let digest = blake3::hash(path.to_string_lossy().as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    ProjectId::from_u128(u128::from_be_bytes(bytes))
}

/// Bridge a `ward-snapshot` id into the `ward-events` id used in the log.
pub fn ev_snapshot(id: SnapSnapshotId) -> EvSnapshotId {
    // Both render as `blake3:<hex>`; `from_hex` tolerates the prefix.
    let hash = EvHash::from_hex(&id.to_string()).unwrap_or_else(|_| EvHash::from_bytes([0u8; 32]));
    EvSnapshotId::new(hash)
}

/// Bridge raw manifest-hash bytes into the `ward-events` hash used as the chain genesis.
pub fn ev_hash(bytes: [u8; 32]) -> EvHash {
    EvHash::from_bytes(bytes)
}

#[allow(clippy::cast_possible_truncation)]
fn ulid_u128() -> u128 {
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let ms = (ns / 1_000_000) & ((1 << 48) - 1);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut seed = [0u8; 16];
    seed[..8].copy_from_slice(&(ns as u64).to_le_bytes());
    seed[8..].copy_from_slice(&seq.to_le_bytes());
    let rand = blake3::hash(&seed);
    let mut low = [0u8; 16];
    low[6..].copy_from_slice(&rand.as_bytes()[..10]);
    (ms << 80) | (u128::from_be_bytes(low) & ((1 << 80) - 1))
}
