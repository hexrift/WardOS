//! Storage retention roots and mark-and-sweep reclamation (#151 items 2–3).
//!
//! `ward_snapshot::gc` knows how to sweep a CAS given an opaque [`ward_snapshot::gc::RootSet`]
//! and never decides what belongs in it — see that module's own doc comment. This module
//! is where the actual decision lives: reading this daemon's on-disk session, attempt and
//! event-log state to build the root set the issue's own list asks for —
//!
//! * **active session entry/candidate snapshots** — [`session_roots`]: a session's
//!   `entry_snapshot` counts for as long as its log is not yet sealed (`SessionEnded` not
//!   yet recorded); a sealed session's entry is no longer a root through this rule (its
//!   pristine state was only ever needed for verification *during* the session).
//! * **in-flight verification** — [`crate::attempt::candidate_snapshot_ids`]: every
//!   candidate an attempt marker currently names, for any session, sealed or not.
//! * **pinned evidence** — [`evidence_roots`]: every `StateAccepted { snapshot, .. }`
//!   record in a session's event log, TamperWard's own concept of an accepted, evidenced
//!   state — kept regardless of whether the session itself is sealed.
//! * **user-kept restore backups** — [`ward_snapshot::gc::kept_ids`]: the minimal explicit
//!   "keep this" marker `ward_snapshot::gc` provides, since no other durable record of a
//!   user-kept snapshot exists yet in this codebase.
//!
//! [`roots`] unions all four. It is deliberately generous: a session directory that will
//! never be reopened but has not been otherwise cleaned up still keeps every snapshot its
//! log ever mentioned as accepted, and an unsealed session (including one nothing is
//! actually still driving — reconciling *that* is #151 item 5, explicitly out of scope
//! here) keeps its entry. Narrowing this further is exactly the kind of policy decision
//! the issue's own items 4/6/7 defer to follow-up work; this module only has to be
//! *correct*, not maximally reclaiming.

use std::path::Path;

use ward_events::{LogReader, WardEvent};
use ward_snapshot::gc::{RootSet, SweepPlan, SweepReport};

use crate::attempt::candidate_snapshot_ids;
use crate::error::{Error, Result};
use crate::session::{SessionMeta, session_dir};

fn cas_root(state: &Path) -> std::path::PathBuf {
    state.join("cas")
}

/// Every session id with a directory under `<state>/sessions/`.
fn session_ids(state: &Path) -> Result<Vec<String>> {
    let dir = state.join("sessions");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(&dir, e)),
    };
    let mut ids = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(&dir, e))?;
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::io(&dir, e)),
        };
        if !file_type.is_dir() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str() {
            ids.push(name.to_owned());
        }
    }
    Ok(ids)
}

/// Whether session `id`'s log has been sealed (`SessionEnded` durably recorded —
/// `LocalLog::seal`'s own chain-head file existing, the same check `ward-daemon::usage`
/// already uses to classify leftover scratch).
fn is_sealed(state: &Path, id: &str) -> bool {
    let log_path = session_dir(state, id).join("events.log");
    ward_events::log::head_file_path(&log_path).exists()
}

/// The entry-snapshot root for every session whose log is not yet sealed (see the module
/// doc comment). A `session.json` this process cannot load or parse (never expected in
/// practice, but a directory could in principle be mid-write, or from a future format)
/// contributes nothing — silently, not an error: an entry snapshot that cannot even be
/// identified cannot be added as a root, and the conservative response to "can't tell"
/// lives one level up, in `ward_snapshot::gc::plan`'s own refusal to delete around an
/// unresolvable root, not here.
fn session_roots(state: &Path, ids: &[String]) -> RootSet {
    let mut roots = RootSet::new();
    for id in ids {
        if is_sealed(state, id) {
            continue;
        }
        let Ok(meta) = SessionMeta::load(state, id) else {
            continue;
        };
        if let Ok(entry) = meta.entry_snapshot.parse() {
            roots.insert(entry);
        }
    }
    roots
}

/// Every `StateAccepted { snapshot, .. }` id across every session's event log —
/// TamperWard's own "pinned evidence" concept (see the module doc comment). Reads the log
/// regardless of whether it is sealed: evidence must survive the session that produced it.
/// A log this process cannot open (never written, or an id with no log at all) simply
/// contributes nothing for that session, not an error — the same "can't tell, don't guess,
/// but don't abort everyone else's roots either" shape [`session_roots`] uses.
fn evidence_roots(state: &Path, ids: &[String]) -> RootSet {
    let mut roots = RootSet::new();
    for id in ids {
        let log_path = session_dir(state, id).join("events.log");
        let Ok(reader) = LogReader::open(&log_path) else {
            continue;
        };
        for record in reader.filter_map(std::result::Result::ok) {
            if let WardEvent::StateAccepted { snapshot, .. } = record.event
                && let Ok(id) = snapshot.to_string().parse()
            {
                roots.insert(id);
            }
        }
    }
    roots
}

/// Every in-flight verification candidate across every session, sealed or not (a sealed
/// session should never have a live attempt marker in practice, but nothing here assumes
/// that — see [`crate::attempt::candidate_snapshot_ids`]'s own doc comment).
fn attempt_roots(state: &Path, ids: &[String]) -> RootSet {
    let mut roots = RootSet::new();
    for id in ids {
        roots.extend(candidate_snapshot_ids(&session_dir(state, id)));
    }
    roots
}

/// The full retention root set for `<state>/cas` — every session's entry (while
/// unsealed), every in-flight verification candidate, every accepted-evidence snapshot,
/// and every explicitly kept id. See the module doc comment for what each source means
/// and why. A failure to even *list* `<state>/sessions/` (as opposed to one session's own
/// unreadable files, tolerated per-session above) is propagated: `ward_snapshot::gc::plan`
/// treats an incomplete root set as unsafe to sweep against, and a caller that could not
/// even enumerate sessions has exactly that problem.
pub fn roots(state: &Path) -> Result<RootSet> {
    let ids = session_ids(state)?;
    let mut roots = session_roots(state, &ids);
    roots.extend(evidence_roots(state, &ids).iter().copied());
    roots.extend(attempt_roots(state, &ids).iter().copied());
    let kept = ward_snapshot::gc::kept_ids(&cas_root(state))
        .map_err(|e| Error::Snapshot(e.to_string()))?;
    roots.extend(kept.iter().copied());
    Ok(roots)
}

/// Compute what a sweep of `<state>/cas` would reclaim right now, against the roots
/// [`roots`] builds. Never deletes anything — see [`apply`].
pub fn plan(state: &Path, now: std::time::SystemTime) -> Result<SweepPlan> {
    let roots = roots(state)?;
    ward_snapshot::gc::plan(&cas_root(state), &roots, now)
        .map_err(|e| Error::Snapshot(e.to_string()))
}

/// Execute a previously computed `plan` against `<state>/cas`.
pub fn apply(state: &Path, plan: &SweepPlan, now: std::time::SystemTime) -> Result<SweepReport> {
    ward_snapshot::gc::apply(&cas_root(state), plan, now)
        .map_err(|e| Error::Snapshot(e.to_string()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::time::SystemTime;
    use ward_events::Origin;
    use ward_policy::{Policy, merge};

    use crate::control::{LocalLog, Sink};
    use crate::session::session_dir;

    fn sample_meta(id: &str, entry: ward_snapshot::SnapshotId) -> SessionMeta {
        let manifest = merge(
            &Policy::default(),
            &Policy::default(),
            &Policy::default(),
            ward_policy::SessionId(id.to_owned()),
            ward_policy::ProjectId("proj_test".to_owned()),
        );
        SessionMeta {
            id: id.to_owned(),
            project: std::path::PathBuf::from("/tmp/demo"),
            project_id: "proj_test".to_owned(),
            entry_snapshot: entry.to_string(),
            origin_repo: None,
            manifest,
            started_unix_ms: 1_700_000_000_000,
            agent: None,
        }
    }

    fn write_session(state: &Path, id: &str, entry: ward_snapshot::SnapshotId) {
        let dir = session_dir(state, id);
        std::fs::create_dir_all(&dir).unwrap();
        let meta = sample_meta(id, entry);
        std::fs::write(dir.join("session.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
    }

    /// Distinct content per call (`content_<n>`), so two calls in the same test never
    /// collide on the same content-addressed id by accident.
    fn store_snapshot(state: &Path) -> ward_snapshot::SnapshotId {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cas = state.join("cas");
        let store = ward_snapshot::SnapshotStore::open(&cas).unwrap();
        let worktree = tempfile::tempdir().unwrap();
        std::fs::write(worktree.path().join("f"), format!("content_{n}")).unwrap();
        store
            .store_snapshot(
                worktree.path(),
                ward_snapshot::SnapshotRole::Entry,
                ward_snapshot::CaptureOptions::default(),
            )
            .unwrap()
    }

    fn open_log(state: &Path, id: &str) -> LocalLog {
        let dir = session_dir(state, id);
        std::fs::create_dir_all(&dir).unwrap();
        LocalLog::create(
            &dir.join("events.log"),
            crate::ids::new_session_id().unwrap(),
            ward_events::Blake3Hash::ZERO,
            SystemTime::now(),
        )
        .unwrap()
    }

    #[test]
    fn an_unsealed_sessions_entry_snapshot_is_a_root() {
        let state = tempfile::tempdir().unwrap();
        let entry = store_snapshot(state.path());
        write_session(state.path(), "sess_unsealed", entry);
        // No events.log/HEAD at all: unsealed by definition.

        let roots = roots(state.path()).unwrap();
        assert!(roots.contains(&entry));
    }

    #[test]
    fn a_sealed_sessions_entry_snapshot_is_no_longer_a_root_through_that_rule_alone() {
        let state = tempfile::tempdir().unwrap();
        let entry = store_snapshot(state.path());
        write_session(state.path(), "sess_sealed", entry);
        let log = open_log(state.path(), "sess_sealed");
        Box::new(log).seal().unwrap();

        let roots = roots(state.path()).unwrap();
        assert!(
            !roots.contains(&entry),
            "sealed, so the entry-snapshot rule no longer protects it"
        );
    }

    #[test]
    fn a_state_accepted_record_pins_its_snapshot_regardless_of_sealing() {
        let state = tempfile::tempdir().unwrap();
        let accepted = store_snapshot(state.path());
        let entry = store_snapshot(state.path());
        write_session(state.path(), "sess_evidence", entry);
        let mut log = open_log(state.path(), "sess_evidence");
        log.append(
            Origin::Wardd,
            WardEvent::StateAccepted {
                snapshot: accepted.to_string().parse().unwrap(),
                by: ward_events::Acceptor::TamperWard,
            },
            SystemTime::now(),
        )
        .unwrap();
        Box::new(log).seal().unwrap();

        let roots = roots(state.path()).unwrap();
        assert!(roots.contains(&accepted), "evidence survives sealing");
        assert!(!roots.contains(&entry), "sealed entry is not itself pinned");
    }

    #[test]
    fn an_in_flight_attempt_marker_pins_its_candidate() {
        let state = tempfile::tempdir().unwrap();
        let entry = store_snapshot(state.path());
        let candidate = store_snapshot(state.path());
        write_session(state.path(), "sess_attempt", entry);
        let dir = session_dir(state.path(), "sess_attempt");
        let guard = crate::attempt::AttemptGuard::start(
            &dir,
            ward_events::AttemptId::new(1),
            ward_events::VerifyRequester::User,
        )
        .unwrap();
        guard.bind_candidate(candidate.to_string().parse().unwrap());

        let live = roots(state.path()).unwrap();
        assert!(live.contains(&candidate));
        guard.finish();
        let after = roots(state.path()).unwrap();
        assert!(
            !after.contains(&candidate),
            "finishing the attempt removes its marker, so the candidate is no longer pinned by it"
        );
    }

    #[test]
    fn kept_ids_are_included() {
        let state = tempfile::tempdir().unwrap();
        let id = store_snapshot(state.path());
        ward_snapshot::gc::mark_kept(&state.path().join("cas"), id).unwrap();

        let roots = roots(state.path()).unwrap();
        assert!(roots.contains(&id));
    }

    #[test]
    fn plan_and_apply_round_trip_through_the_daemon_wrapper() {
        let state = tempfile::tempdir().unwrap();
        let cas = ward_snapshot::SnapshotStore::open(state.path().join("cas")).unwrap();
        let worktree = tempfile::tempdir().unwrap();
        std::fs::write(worktree.path().join("f"), b"orphaned").unwrap();
        cas.store_snapshot(
            worktree.path(),
            ward_snapshot::SnapshotRole::Candidate,
            ward_snapshot::CaptureOptions::default(),
        )
        .unwrap();
        // No session references it at all: fully reclaimable.

        let now = SystemTime::now();
        let p = plan(state.path(), now).unwrap();
        assert!(!p.is_empty(), "the unreferenced snapshot must be planned");
        let report = apply(state.path(), &p, now).unwrap();
        assert_eq!(report.deleted.len(), p.objects.len());
    }
}
