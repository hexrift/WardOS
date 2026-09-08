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

/// A sandboxed process can reach the session proxy only through the bind-mounted Unix
/// socket, and a private destination is denied there and recorded (ADR-0014).
#[test]
fn sandboxed_egress_goes_through_the_proxy_and_private_is_denied() {
    if !sandbox::available()
        || !std::path::Path::new("/usr/bin/python3").exists()
            && !std::path::Path::new("/usr/local/bin/python3").exists()
    {
        eprintln!("skipping: bubblewrap or python3 not available");
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let log = session.log_path();
    let script = "import socket\n\
s=socket.socket(socket.AF_UNIX)\ns.connect('/run/ward/proxy.sock')\n\
s.sendall(b'CONNECT 10.0.0.1:80 HTTP/1.1\\r\\nHost: 10.0.0.1:80\\r\\n\\r\\n')\n\
print(s.recv(200).split(b'\\r\\n')[0].decode())";
    let report = session
        .run(&["python3".into(), "-c".into(), script.into()])
        .expect("run");
    assert!(
        report.stdout.contains("403"),
        "expected 403 from proxy, got: {}",
        report.stdout
    );
    session.stop(EndReason::UserStop).expect("stop");

    let denied = ward_events::LogReader::open(&log)
        .unwrap()
        .filter_map(Result::ok)
        .any(|r| matches!(r.event, ward_events::WardEvent::NetworkDenied { .. }));
    assert!(denied, "a NetworkDenied record must be in the sealed log");
}
