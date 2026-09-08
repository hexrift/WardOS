#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end session test. Requires bubblewrap; skips cleanly without it.

use std::fs;

use ward_daemon::{Session, sandbox, selftest};
use ward_events::EndReason;

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
}
