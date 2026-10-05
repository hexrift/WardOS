//! `ward-shell worker` on a desktop with no session anywhere — a headless
//! run, a machine before its first `ward up`, the gap after the last
//! session sealed — must wait for one at a bounded interval, saying so once,
//! not spin on `locate` (filling the journal, or a disk, with the same
//! line) and not exit either, since `wardos-shell-worker.service`'s
//! `Restart=on-failure` is pacing for a crash, not the worker's idle loop.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::{Command, Stdio};
use std::time::Duration;

/// Longer than two of the worker's idle polls at its documented 2s interval
/// (and than one at the 5s a solo Waybar segment is relaunched at), so a
/// worker that logged once per poll rather than once per state change would
/// show it here as a second line.
const OBSERVED: Duration = Duration::from_millis(5500);

#[test]
fn a_worker_with_no_session_waits_quietly_and_stays_alive() {
    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ward-shell"))
        .arg("worker")
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("WARD_STATE_DIR", home.path().join("state"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(OBSERVED);
    let exited = child.try_wait().unwrap();
    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        exited.is_none(),
        "the worker must keep waiting for a session, not exit ({exited:?}):\n{stderr}"
    );
    let lines: Vec<&str> = stderr.lines().collect();
    let startup_notices = usize::from(cfg!(feature = "gui"));
    assert_eq!(
        lines.len(),
        1 + startup_notices,
        "one no-session line over {OBSERVED:?}, not one per poll:\n{stderr}"
    );
    assert!(
        lines
            .last()
            .is_some_and(|line| line.contains("no session for")),
        "the one line names why it is waiting: {stderr}"
    );
}
