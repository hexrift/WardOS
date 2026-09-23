//! Low-space preflight guard for CAS-writing operations (#151 item 6).
//!
//! `ward_snapshot`'s capture walks a worktree and writes blobs, manifests and
//! meta as it goes ([`crate::session::Session::snapshot`], `ward verify`'s own
//! candidate capture inside [`crate::verify::prepare`]) — there is no separate
//! dry-run pass that first totals up what a given capture is about to write,
//! and computing that total in advance would itself require walking (and
//! often hashing) the whole worktree: exactly the expensive step this guard
//! exists to avoid paying for on a filesystem that is already too full to
//! finish it. So this is deliberately not a predictive "will this specific
//! capture fit" sizer; it is a coarse, cheap-to-check floor — refuse to even
//! start an expensive capture when the filesystem backing `<state>/cas` is
//! already below a configurable minimum of free space, the same shape a
//! low-disk-space guard takes in most other systems.
//!
//! This module only ever reads `statvfs(2)`. It never deletes, moves or
//! truncates anything on a trip, and it never runs `ward snapshot gc` itself
//! — the issue's own explicit constraint: the previous valid snapshot and its
//! receipt are never at risk from this check, only the *new* operation is
//! refused before it starts, with [`crate::error::Error::LowSpace`] pointing
//! the caller at `ward snapshot gc`/`ward snapshot usage` as the way out.
//!
//! Wired into [`crate::session::Session::snapshot`] (`ward snapshot create`)
//! and the candidate capture inside [`crate::session::Session::verify`]
//! (`ward verify`'s own worktree-walk-and-hash step) — the two call-outs the
//! issue itself names. The initial entry-snapshot capture at `ward up`
//! ([`crate::session::Session::start_in`]) and the candidate capture inside
//! `ward stop --restore-entry` ([`crate::session::Session::restore_entry`])
//! are both CAS-writing captures too, but are left uncovered here: scoping
//! this preflight to the two highest-value, largest-worktree-walk paths keeps
//! this change reviewable as the single, tightly-scoped step #151 item 6
//! asks for, matching how items 1–3 and 7 each landed as their own PR rather
//! than one that tried to cover every capture site at once. Extending the
//! guard to the remaining sites is a natural, small follow-up.

use std::path::Path;

use crate::error::{Error, Result};

/// Default minimum bytes of free space required on the filesystem backing
/// `<state>/cas` before an expensive CAS-writing capture is allowed to start.
///
/// 512 MiB: comfortably above what a single blob, manifest or meta write
/// needs even for a large individual file, while small enough that it does
/// not itself become a nuisance on a modest disk. [`min_free_bytes`] lets an
/// operator raise or lower it per host; this is a floor on *available* space,
/// not an estimate of what any one capture will actually write (see the
/// module doc comment for why).
pub const DEFAULT_MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;

/// The configured minimum: `$WARD_MIN_FREE_BYTES` (a plain byte count), else
/// [`DEFAULT_MIN_FREE_BYTES`]. An unset, empty, or unparsable value falls back
/// to the default rather than failing — the same tolerance
/// [`crate::session::approval_timeout`] already gives
/// `$WARD_APPROVAL_TIMEOUT_SECS`.
#[must_use]
pub fn min_free_bytes() -> u64 {
    std::env::var("WARD_MIN_FREE_BYTES")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_MIN_FREE_BYTES)
}

/// Bytes free on the filesystem backing `path`, counting only what an
/// unprivileged writer could actually use — `statvfs`'s `f_bavail` via
/// [`nix::sys::statvfs::Statvfs::blocks_available`], never `f_bfree`
/// (`blocks_free`), which also counts space the kernel reserves for root and
/// this process could not actually write into.
///
/// `path` need not exist: `<state>/cas` may not have been created yet (a
/// brand-new state root), so a missing path walks up to its nearest existing
/// ancestor and reports that filesystem's free space — the filesystem the
/// missing path would itself be created on.
pub fn available_bytes(path: &Path) -> Result<u64> {
    let mut probe: &Path = path;
    loop {
        match nix::sys::statvfs::statvfs(probe) {
            Ok(vfs) => {
                // `fsblkcnt_t`/the fragment size are already `u64` on every target
                // this workspace builds for (`rust-toolchain.toml`'s Linux x86_64),
                // so this is a plain multiplication, not a narrowing cast.
                let avail_blocks: u64 = vfs.blocks_available();
                let frag_size: u64 = vfs.fragment_size();
                return Ok(avail_blocks.saturating_mul(frag_size));
            }
            Err(nix::Error::ENOENT) => match probe.parent() {
                Some(parent) if parent != probe => probe = parent,
                _ => {
                    return Err(Error::io(
                        path,
                        std::io::Error::from(std::io::ErrorKind::NotFound),
                    ));
                }
            },
            Err(e) => return Err(Error::io(probe, std::io::Error::from(e))),
        }
    }
}

/// Refuse to proceed when `available` is below `min_free_bytes`, naming
/// `cas_root` in the resulting [`Error::LowSpace`]. A plain, deterministic
/// comparison over two numbers with no filesystem access of its own — split
/// out of [`check`] so the part a test needs to exercise both ways (trips /
/// does not trip) never has to touch a real disk, mock `statvfs`, or actually
/// fill one up to prove it.
fn require(cas_root: &Path, available: u64, min_free_bytes: u64) -> Result<()> {
    if available < min_free_bytes {
        return Err(Error::LowSpace {
            path: cas_root.to_path_buf(),
            available,
            required: min_free_bytes,
        });
    }
    Ok(())
}

/// The full preflight (#151 item 6): read real free space on the filesystem
/// backing `<state>/cas`, then [`require`] it clear `min_free_bytes`. Never
/// deletes, moves or truncates anything, on either outcome — see the module
/// doc comment.
pub fn check(state: &Path, min_free_bytes: u64) -> Result<()> {
    let cas_root = state.join("cas");
    let available = available_bytes(&cas_root)?;
    require(&cas_root, available, min_free_bytes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn require_trips_when_available_is_below_the_minimum() {
        let err = require(Path::new("/state/cas"), 100, 200).unwrap_err();
        match err {
            Error::LowSpace {
                path,
                available,
                required,
            } => {
                assert_eq!(path, PathBuf::from("/state/cas"));
                assert_eq!(available, 100);
                assert_eq!(required, 200);
            }
            other => panic!("expected Error::LowSpace, got {other:?}"),
        }
    }

    #[test]
    fn require_does_not_trip_when_available_meets_the_minimum() {
        require(Path::new("/state/cas"), 200, 200).unwrap();
        require(Path::new("/state/cas"), 201, 200).unwrap();
    }

    #[test]
    fn require_does_not_trip_against_a_zero_minimum() {
        // A caller that wants the preflight effectively disabled (or is simply
        // not worried about space at all) can pass 0: `require` never demands
        // more headroom than it was asked to.
        require(Path::new("/state/cas"), 0, 0).unwrap();
    }

    #[test]
    fn min_free_bytes_falls_back_to_the_default_when_unset() {
        // The env var is process-global, so only assert the *fallback* shape
        // here rather than mutate it: `min_free_bytes` must never panic and
        // must return the compiled-in default whenever the var is absent,
        // which is the state of any process that never set it, including this
        // one during a normal test run.
        if std::env::var("WARD_MIN_FREE_BYTES").is_err() {
            assert_eq!(min_free_bytes(), DEFAULT_MIN_FREE_BYTES);
        }
    }

    #[test]
    fn available_bytes_reports_something_positive_for_a_real_directory() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = available_bytes(dir.path()).unwrap();
        assert!(
            bytes > 0,
            "a real, writable filesystem must report nonzero free space"
        );
    }

    #[test]
    fn available_bytes_of_a_missing_path_reports_its_nearest_existing_ancestors_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does").join("not").join("exist");
        // Same filesystem as `dir` itself (a temp directory's descendants
        // never cross a mount point), so the two reports should be very close
        // — exactly equal barring a write landing between the two calls,
        // which a fresh empty tempdir makes vanishingly unlikely in a test.
        let via_missing = available_bytes(&missing).unwrap();
        let via_real = available_bytes(dir.path()).unwrap();
        let diff = via_missing.abs_diff(via_real);
        assert!(
            diff < 64 * 1024 * 1024,
            "expected the same filesystem's free space via a missing path ({via_missing}) \
             and its real ancestor ({via_real}), got a {diff}-byte difference"
        );
    }

    #[test]
    fn check_trips_against_an_unreasonably_high_minimum() {
        // No real disk has exabytes free: this deterministically trips the
        // real `available_bytes` path without needing to fill, or mock, an
        // actual filesystem.
        let state = tempfile::tempdir().unwrap();
        let err = check(state.path(), u64::MAX).unwrap_err();
        assert!(matches!(err, Error::LowSpace { .. }));
    }

    #[test]
    fn check_does_not_trip_against_a_zero_minimum() {
        // Symmetric to the above: 0 bytes required is always satisfied, on
        // any real filesystem, without needing a mock either.
        let state = tempfile::tempdir().unwrap();
        check(state.path(), 0).unwrap();
    }

    #[test]
    fn a_low_space_error_names_the_cas_root_and_is_actionable() {
        let err = require(Path::new("/state/cas"), 1, 1024).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("/state/cas"), "{msg}");
        assert!(
            msg.contains("ward snapshot gc") && msg.contains("ward snapshot usage"),
            "a low-space refusal must point at the way out: {msg}"
        );
    }
}
