#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end session test. Requires bubblewrap; skips cleanly without it.

use std::fs;

use ward_daemon::{Session, SessionMeta, sandbox, selftest};
use ward_events::{EndReason, FileChangeKind, LogReader, WardEvent};

fn scratch_project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join(".ward")).unwrap();
    fs::write(dir.path().join("README.md"), "demo\n").unwrap();
    fs::write(
        dir.path().join(".ward/policy.yaml"),
        "network: localhost_only\ncontainers: none\n",
    )
    .unwrap();
    dir
}

#[test]
fn session_runs_and_seals_a_log() {
    if !sandbox::available() {
        eprintln!("skipping: bubblewrap not available");
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let log = session.log_path();
    let report = session
        .run(&["/bin/sh".into(), "-c".into(), "echo hi > note.txt".into()])
        .expect("run");
    assert_eq!(report.code, Some(0));
    assert!(report.files_changed >= 1, "the write should be observed");
    session.stop(EndReason::UserStop).expect("stop");

    assert!(fs::metadata(&log).expect("log exists").len() > 0);
}

#[test]
fn up_run_status_stop_lifecycle() {
    if !sandbox::available() {
        eprintln!("skipping: bubblewrap not available");
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();

    // `ward up`: start a session and record it as the project's current session.
    let up = Session::start_in(project.path(), state.path()).expect("up");
    let session_id = up.id().to_owned();
    let log = up.log_path();
    up.persist_current().expect("persist");
    drop(up);

    // `ward run`: reopen the current session, run a command that creates a file, and
    // keep the session active.
    let mut run = Session::open_current(project.path(), state.path())
        .expect("open current")
        .expect("a current session exists");
    assert_eq!(run.id(), session_id, "run resumes the same session");
    let report = run
        .run(&[
            "/bin/sh".into(),
            "-c".into(),
            "echo hi > created.txt".into(),
        ])
        .expect("run");
    assert_eq!(report.code, Some(0));
    assert!(
        report.files_changed >= 1,
        "the created file must be counted, got {}",
        report.files_changed
    );
    run.sync().expect("sync");
    drop(run);

    // The log must carry a FileModified{Create} for the new file.
    let reader = LogReader::open(&log).expect("open log");
    let mut saw_create = false;
    for rec in reader {
        let rec = rec.expect("record");
        if let WardEvent::FileModified { path, kind, .. } = &rec.event
            && *kind == FileChangeKind::Create
            && path.to_string().contains("created.txt")
        {
            saw_create = true;
        }
    }
    assert!(
        saw_create,
        "expected a FileModified{{Create}} for created.txt"
    );

    // `ward status`: the current session is visible without starting a new one.
    let meta = SessionMeta::current(project.path(), state.path())
        .expect("status")
        .expect("status shows the active session");
    assert_eq!(meta.id, session_id);

    // `ward stop`: end the session and clear the current pointer.
    let stop = Session::open_current(project.path(), state.path())
        .expect("open current")
        .expect("still active");
    stop.stop(EndReason::UserStop).expect("stop");
    assert!(
        SessionMeta::current(project.path(), state.path())
            .expect("status after stop")
            .is_none(),
        "the current pointer must be cleared on stop"
    );
    assert!(
        Session::open_current(project.path(), state.path())
            .expect("open after stop")
            .is_none(),
        "no session should reopen after stop"
    );
}

#[test]
fn selftest_blocks_every_probe() {
    if !sandbox::available() {
        eprintln!("skipping: bubblewrap not available");
        return;
    }
    let project = scratch_project();
    let results = selftest(project.path()).expect("selftest");
    assert!(
        results.iter().all(|r| r.blocked),
        "all probes must be blocked"
    );
    // The escape probes added for this work must be present and denied.
    for id in ["ST-013", "ST-014", "ST-015"] {
        let probe = results.iter().find(|r| r.name.starts_with(id));
        assert!(probe.is_some(), "{id} probe must exist");
        assert!(
            probe.is_some_and(|p| p.blocked),
            "{id} must be denied in the sandbox"
        );
    }
}
