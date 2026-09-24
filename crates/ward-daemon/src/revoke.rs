//! Host-confirmed credential revocation (#245, closing the gap #243 left open
//! in #140 items 4-5): reaching the egress proxy that holds an active
//! gateway route the same way [`crate::pause`] reaches it — through a file,
//! since `wardd` has no direct handle onto a proxy that lives in another
//! process (`ward_proxy::Proxy::spawn` runs inside `Session::run_launch`,
//! not the daemon; see `pause`'s own module doc).
//!
//! One marker file per still-pending revoke request,
//! `sessions/<id>/revoke/<grant-id>`, written empty by the daemon
//! ([`request`], from `daemon::revoke`) and polled by every launch's egress
//! of the session ([`crate::egress::Egress::watch_revocations`], alongside
//! the existing pause marker). Only the one egress that actually holds a
//! gateway route carrying `<grant-id>` acts on it
//! ([`ward_proxy::Handle::revoke_credential`], keyed by the same id a
//! `GatewayRoute` was tagged with when its credential was granted) and
//! overwrites the file with the outcome; any other egress of the session
//! leaves it untouched. [`wait_for_ack`] is what `daemon::revoke` polls for
//! that outcome, bounded by [`ACK_TIMEOUT`] — a launch that already crashed,
//! or whose egress simply has not polled yet, must never be silently
//! reported as having withdrawn the route.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::session::session_dir;

/// Directory holding one pending-revoke marker per grant id, under `sessions/<id>/`.
pub const DIR: &str = "revoke";

/// How often an egress checks [`DIR`] for a new marker
/// ([`crate::egress::Egress::watch_revocations`]) — the same cadence
/// `pause`'s own marker is polled at.
pub const POLL: Duration = Duration::from_millis(50);

/// How long [`wait_for_ack`] waits for an owning egress to acknowledge a
/// revoke before giving up: generous next to [`POLL`] (dozens of chances to
/// notice), and bounded well under the control socket's own read timeout
/// (`control::TIMEOUT`, 10 s), so a client blocked on `ward session revoke`
/// is never the one that appears to hang.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(2);

/// The text an owning egress writes back once it has revoked its route and
/// nothing was relaying with it at that instant.
pub const CONFIRMED: &str = "confirmed";

/// The text an owning egress writes back when `n` connections were already
/// relaying with the credential injected at the instant of revocation: the
/// route no longer honors it for anything new, but those connections finish
/// on their own (bytes already handed to a socket are not recalled).
#[must_use]
pub fn in_flight_text(n: usize) -> String {
    format!("confirmed-in-flight:{n}")
}

/// Parse [`in_flight_text`]'s own format back into the count it named.
#[must_use]
pub fn parse_in_flight(text: &str) -> Option<u32> {
    text.strip_prefix("confirmed-in-flight:")?.parse().ok()
}

/// `sessions/<id>/revoke/`.
#[must_use]
pub fn dir_path(state: &Path, session: &str) -> PathBuf {
    session_dir(state, session).join(DIR)
}

/// `sessions/<id>/revoke/<grant-id>`.
#[must_use]
pub fn marker_path(state: &Path, session: &str, grant_id: u64) -> PathBuf {
    dir_path(state, session).join(grant_id.to_string())
}

/// Write the pending marker for `grant_id`, creating [`DIR`] if this is the
/// session's first revoke. Idempotent: a marker already there (a concurrent
/// or retried revoke of the same id) is left as it is, so it never clobbers
/// an outcome an egress may have already written.
pub fn request(state: &Path, session: &str, grant_id: u64) -> Result<()> {
    let dir = dir_path(state, session);
    fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
    let path = marker_path(state, session, grant_id);
    if path.exists() {
        return Ok(());
    }
    fs::write(&path, "").map_err(|e| Error::io(&path, e))
}

/// The outcome an owning egress has written for `grant_id`, once there is
/// one; `None` while the marker is still empty (nothing has acted yet) or
/// gone.
#[must_use]
pub fn ack(state: &Path, session: &str, grant_id: u64) -> Option<String> {
    let text = fs::read_to_string(marker_path(state, session, grant_id)).ok()?;
    (!text.is_empty()).then_some(text)
}

/// Remove the marker for `grant_id`: called once its outcome has been read,
/// or to give up waiting. A marker already gone is fine.
pub fn clear(state: &Path, session: &str, grant_id: u64) {
    let _ = fs::remove_file(marker_path(state, session, grant_id));
}

/// Wait up to `timeout` for `grant_id`'s marker to carry an outcome, polling
/// every [`POLL`]. `None` on timeout — the marker is left for a late
/// straggler to still write to (nothing further waits on it once this
/// returns; the caller clears it either way).
#[must_use]
pub fn wait_for_ack(
    state: &Path,
    session: &str,
    grant_id: u64,
    timeout: Duration,
) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(outcome) = ack(state, session, grant_id) {
            return Some(outcome);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn in_flight_text_round_trips_through_parse() {
        assert_eq!(
            parse_in_flight(CONFIRMED),
            None,
            "confirmed carries no count"
        );
        assert_eq!(parse_in_flight(&in_flight_text(0)), Some(0));
        assert_eq!(parse_in_flight(&in_flight_text(7)), Some(7));
        assert_eq!(parse_in_flight("garbage"), None);
    }

    #[test]
    fn request_creates_an_empty_marker_and_ack_reads_nothing_until_written() {
        let state = tempfile::tempdir().unwrap();
        let session = "sess_revoke_marker";
        std::fs::create_dir_all(session_dir(state.path(), session)).unwrap();

        assert_eq!(ack(state.path(), session, 5), None, "no marker yet");
        request(state.path(), session, 5).unwrap();
        assert!(marker_path(state.path(), session, 5).exists());
        assert_eq!(
            ack(state.path(), session, 5),
            None,
            "written, but still empty"
        );

        std::fs::write(marker_path(state.path(), session, 5), CONFIRMED).unwrap();
        assert_eq!(ack(state.path(), session, 5).as_deref(), Some(CONFIRMED));

        clear(state.path(), session, 5);
        assert!(!marker_path(state.path(), session, 5).exists());
        clear(state.path(), session, 5); // already gone is fine
    }

    #[test]
    fn request_is_idempotent_and_never_clobbers_an_outcome_already_written() {
        let state = tempfile::tempdir().unwrap();
        let session = "sess_idempotent";
        std::fs::create_dir_all(session_dir(state.path(), session)).unwrap();
        request(state.path(), session, 1).unwrap();
        std::fs::write(marker_path(state.path(), session, 1), CONFIRMED).unwrap();
        // A second, concurrent `request` for the same id must not blank out
        // an outcome that already landed.
        request(state.path(), session, 1).unwrap();
        assert_eq!(ack(state.path(), session, 1).as_deref(), Some(CONFIRMED));
    }

    #[test]
    fn wait_for_ack_returns_as_soon_as_a_late_writer_lands() {
        let state = tempfile::tempdir().unwrap();
        let session = "sess_wait";
        std::fs::create_dir_all(session_dir(state.path(), session)).unwrap();
        request(state.path(), session, 9).unwrap();
        let path = marker_path(state.path(), session, 9);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            std::fs::write(path, in_flight_text(2)).unwrap();
        });
        let outcome = wait_for_ack(state.path(), session, 9, Duration::from_secs(2));
        assert_eq!(outcome.as_deref(), Some("confirmed-in-flight:2"));
    }

    #[test]
    fn wait_for_ack_gives_up_after_its_bound_when_nothing_ever_answers() {
        let state = tempfile::tempdir().unwrap();
        let session = "sess_timeout";
        std::fs::create_dir_all(session_dir(state.path(), session)).unwrap();
        request(state.path(), session, 3).unwrap();
        let started = Instant::now();
        let outcome = wait_for_ack(state.path(), session, 3, Duration::from_millis(120));
        assert_eq!(outcome, None);
        assert!(started.elapsed() >= Duration::from_millis(120));
        // Left in place for a late straggler; the caller decides whether to clear it.
        assert!(marker_path(state.path(), session, 3).exists());
    }
}
