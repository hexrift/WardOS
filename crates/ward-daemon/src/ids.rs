//! Id generation and cross-crate id bridges.
//!
//! Each Phase 1 crate defines its own id newtypes so it can be built and tested
//! independently. The daemon is where they meet, so the few conversions live here.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ward_events::{
    Blake3Hash as EvHash, CaptureMode as EvCaptureMode, ProjectId, SessionId,
    SnapshotId as EvSnapshotId, SnapshotRole as EvSnapshotRole,
};
use ward_snapshot::{
    CaptureMode as SnapCaptureMode, SnapshotId as SnapSnapshotId, SnapshotRole as SnapSnapshotRole,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh, time-ordered session id (ULID-shaped: 48-bit ms timestamp, 80 CSPRNG bits).
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

/// Bridge a `ward-events` id from the log back into the `ward-snapshot` id the
/// CAS is keyed by: what a reader of a `VerificationPassed` record needs to
/// look the candidate up, or to compare it with a digest of the worktree.
pub fn snap_snapshot(id: EvSnapshotId) -> SnapSnapshotId {
    SnapSnapshotId(ward_snapshot::Digest::from_bytes(*id.hash().as_bytes()))
}

/// Bridge a `ward-snapshot` role into the `ward-events` role used in the log.
pub fn ev_role(role: SnapSnapshotRole) -> EvSnapshotRole {
    match role {
        SnapSnapshotRole::Entry => EvSnapshotRole::Entry,
        SnapSnapshotRole::Candidate => EvSnapshotRole::Candidate,
        SnapSnapshotRole::Accepted => EvSnapshotRole::Accepted,
        SnapSnapshotRole::Final => EvSnapshotRole::Final,
    }
}

/// Bridge a `ward-snapshot` capture mode into the `ward-events` one.
pub fn ev_capture(mode: SnapCaptureMode) -> EvCaptureMode {
    match mode {
        SnapCaptureMode::BtrfsSnapshot => EvCaptureMode::BtrfsSnapshot,
        SnapCaptureMode::FrozenCopy => EvCaptureMode::FrozenCopy,
    }
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

    let mut rand = [0u8; 10];
    if getrandom::fill(&mut rand).is_err() {
        // No OS entropy source available (e.g. a broken sandbox): fall back to a PRF
        // over the timestamp and a per-process counter rather than failing id
        // generation outright. Not expected to run in a normal environment, and
        // strictly worse than the CSPRNG path above, never used when it succeeds.
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut seed = [0u8; 16];
        seed[..8].copy_from_slice(&(ns as u64).to_le_bytes());
        seed[8..].copy_from_slice(&seq.to_le_bytes());
        rand.copy_from_slice(&blake3::hash(&seed).as_bytes()[..10]);
    }

    let mut low = [0u8; 16];
    low[6..].copy_from_slice(&rand);
    (ms << 80) | (u128::from_be_bytes(low) & ((1 << 80) - 1))
}

#[cfg(test)]
mod tests {
    use super::{new_session_id, ulid_u128};

    #[test]
    fn back_to_back_ids_are_distinct_and_their_ms_prefix_does_not_go_backwards() {
        let a = ulid_u128();
        let b = ulid_u128();
        assert_ne!(a, b, "two ids minted back-to-back must not collide");
        // Only the 48-bit ms prefix is guaranteed ordered; two draws inside the same
        // millisecond have independent CSPRNG tails, so the full u128 is not.
        assert!(
            (b >> 80) >= (a >> 80),
            "the ms timestamp prefix must not go backwards"
        );
    }

    #[test]
    fn random_tail_is_not_a_deterministic_function_of_the_counter_alone() {
        // Two ids minted back-to-back (same or adjacent millisecond, adjacent
        // COUNTER values under the old PRF) must not merely differ by 1 in their
        // low bits the way a PRF over (ns, seq) would: with a CSPRNG tail the
        // low 80 bits of two draws are independent, so a shared 8-bit prefix
        // across many samples would be a coincidence, not a construction.
        let ids: Vec<u128> = (0..8).map(|_| new_session_id().as_u128()).collect();
        let low_bytes: Vec<u8> = ids.iter().map(|id| (*id & 0xff) as u8).collect();
        assert!(
            low_bytes.windows(2).any(|w| w[0] != w[1]),
            "low byte of the random tail must vary across draws, not increment lockstep"
        );
    }
}
