//! Runs the built `ward-agent` binary on the host (no container needed) and
//! checks that Landlock confines writes, that the seccomp/PID 1 path relays
//! exit codes, and that termination signals reach the agent.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

const BIN: &str = env!("CARGO_BIN_EXE_ward-agent");

/// The shim with `rw` as its only writable tree and no Landlock opt-out.
fn bare(rw: &Path) -> Command {
    let mut command = Command::new(BIN);
    command
        .env("WARD_AGENT_QUIET", "1")
        .arg("--rw")
        .arg(rw)
        .stdin(Stdio::null())
        .stderr(Stdio::piped());
    command
}

/// The shim as the tests that do not depend on Landlock run it: opted out of
/// the Landlock requirement only where the kernel cannot provide it.
fn shim(rw: &Path) -> Command {
    let mut command = bare(rw);
    if !landlock_available() {
        command.arg("--allow-no-landlock");
    }
    command
}

fn landlock_available() -> bool {
    if ward_agent::landlock::is_available() {
        return true;
    }
    eprintln!("landlock unavailable on this kernel");
    false
}

#[test]
fn writes_outside_rw_fail_with_eacces_and_inside_succeed() {
    if !landlock_available() {
        eprintln!("skipping: needs landlock");
        return;
    }
    let rw = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();

    let denied = shim(rw.path())
        .args(["--", "sh", "-c"])
        .arg(format!("touch {}/x", other.path().display()))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(
        !denied.status.success(),
        "touch outside rw succeeded: {stderr}"
    );
    assert!(
        stderr.contains("Permission denied"),
        "expected EACCES, got: {stderr}"
    );
    assert!(!other.path().join("x").exists());

    let allowed = shim(rw.path())
        .args(["--", "sh", "-c"])
        .arg(format!("touch {}/y", rw.path().display()))
        .output()
        .unwrap();
    assert!(
        allowed.status.success(),
        "touch inside rw failed: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(rw.path().join("y").exists());
}

#[test]
fn refuses_to_exec_without_landlock_unless_allowed() {
    // Only observable on kernels without Landlock; elsewhere the flag is a no-op.
    if landlock_available() {
        return;
    }
    let rw = tempfile::tempdir().unwrap();
    let refused = bare(rw.path()).args(["--", "true"]).output().unwrap();
    assert_eq!(refused.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("landlock is unavailable"));
    let allowed = bare(rw.path())
        .args(["--allow-no-landlock", "--", "true"])
        .output()
        .unwrap();
    assert!(allowed.status.success());
}

#[test]
fn relays_the_agent_exit_code() {
    if !landlock_available() {
        return;
    }
    let rw = tempfile::tempdir().unwrap();
    let out = shim(rw.path())
        .args(["--", "sh", "-c", "exit 7"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn denied_syscalls_fail_with_eperm() {
    if !landlock_available() {
        return;
    }
    let rw = tempfile::tempdir().unwrap();
    // `mount` is EPERM in the baseline profile; without seccomp, root would succeed
    // or fail with a different error (ENOENT/EINVAL) for this bogus request.
    let out = shim(rw.path())
        .args([
            "--",
            "sh",
            "-c",
            "mount -t tmpfs none /nonexistent 2>&1; echo rc=$?",
        ])
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ermission denied") || stdout.contains("not permitted"),
        "expected EPERM from mount, got: {stdout}"
    );
}

#[test]
fn forwards_sigterm_to_the_agent() {
    if !landlock_available() {
        return;
    }
    let rw = tempfile::tempdir().unwrap();
    let mut child = shim(rw.path())
        .args([
            "--",
            "sh",
            "-c",
            "trap 'exit 42' TERM; while :; do sleep 0.05; done",
        ])
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    kill(
        Pid::from_raw(i32::try_from(child.id()).unwrap()),
        Signal::SIGTERM,
    )
    .unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(42));
}
