//! Id generation and cross-crate id bridges.
//!
//! Each Phase 1 crate defines its own id newtypes so it can be built and tested
//! independently. The daemon is where they meet, so the few conversions live here.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use ward_events::{
    Blake3Hash as EvHash, CaptureMode as EvCaptureMode, ProjectId, SessionId,
    SnapshotId as EvSnapshotId, SnapshotRole as EvSnapshotRole,
};
use ward_snapshot::{
    CaptureMode as SnapCaptureMode, SnapshotId as SnapSnapshotId, SnapshotRole as SnapSnapshotRole,
};

use crate::error::Error;

/// No OS entropy source was available to mint an id's random bits.
#[derive(Debug)]
pub struct NoEntropy;

impl fmt::Display for NoEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no OS entropy source available")
    }
}

impl std::error::Error for NoEntropy {}

/// A fresh, time-ordered session id (ULID-shaped: 48-bit ms timestamp, 80 CSPRNG bits).
///
/// Fails rather than falling back to a predictable construction if the OS entropy
/// source is unavailable: a session id that looks random but isn't would be worse
/// than an explicit startup failure.
pub fn new_session_id() -> Result<SessionId, Error> {
    ulid_u128()
        .map(SessionId::from_u128)
        .map_err(|e| Error::Events(e.to_string()))
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

fn ulid_u128() -> Result<u128, NoEntropy> {
    ulid_u128_from(|buf| getrandom::fill(buf).map_err(|_| NoEntropy))
}

/// The ULID construction, parameterized over how the random tail is filled so tests
/// can drive it with a fixed source or a forced failure instead of real OS entropy.
#[allow(clippy::cast_possible_truncation)]
fn ulid_u128_from<F>(fill: F) -> Result<u128, NoEntropy>
where
    F: FnOnce(&mut [u8]) -> Result<(), NoEntropy>,
{
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let ms = (ns / 1_000_000) & ((1 << 48) - 1);

    let mut rand = [0u8; 10];
    fill(&mut rand)?;

    let mut low = [0u8; 16];
    low[6..].copy_from_slice(&rand);
    Ok((ms << 80) | (u128::from_be_bytes(low) & ((1 << 80) - 1)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{NoEntropy, ulid_u128, ulid_u128_from};

    #[test]
    fn back_to_back_ids_are_distinct_and_their_ms_prefix_does_not_go_backwards() {
        let a = ulid_u128().expect("OS entropy source available in tests");
        let b = ulid_u128().expect("OS entropy source available in tests");
        assert_ne!(a, b, "two ids minted back-to-back must not collide");
        // Only the 48-bit ms prefix is guaranteed ordered; two draws inside the same
        // millisecond have independent CSPRNG tails, so the full u128 is not.
        assert!(
            (b >> 80) >= (a >> 80),
            "the ms timestamp prefix must not go backwards"
        );
    }

    #[test]
    fn successful_fill_places_exactly_those_bytes_in_the_low_80_bits() {
        let id = ulid_u128_from(|buf| {
            buf.copy_from_slice(&[0xAA; 10]);
            Ok(())
        })
        .expect("fill succeeded");
        let low = id & ((1u128 << 80) - 1);
        assert_eq!(low, u128::from_be_bytes([0xAAu8; 16]) & ((1u128 << 80) - 1));
    }

    #[test]
    fn two_fills_with_different_bytes_produce_different_ids() {
        let a = ulid_u128_from(|buf| {
            buf.copy_from_slice(&[0x11; 10]);
            Ok(())
        })
        .expect("fill succeeded");
        let b = ulid_u128_from(|buf| {
            buf.copy_from_slice(&[0x22; 10]);
            Ok(())
        })
        .expect("fill succeeded");
        assert_ne!(
            a & ((1u128 << 80) - 1),
            b & ((1u128 << 80) - 1),
            "distinct entropy must produce distinct random tails"
        );
    }

    #[test]
    fn entropy_source_failure_fails_closed_instead_of_falling_back() {
        let result = ulid_u128_from(|_| Err(NoEntropy));
        assert!(
            result.is_err(),
            "a broken entropy source must not silently produce a predictable id"
        );
    }
}
