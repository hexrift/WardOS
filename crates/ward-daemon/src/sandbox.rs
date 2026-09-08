//! Bubblewrap sandbox backend.
//!
//! ADR-0002 selects `crun` for the production host. In a nested/dev environment
//! `crun` cannot manage cgroups, so the daemon runs commands through
//! `bubblewrap`, which provides the same *filesystem and network* isolation the
//! Phase 1 guarantees rely on: the worktree is the only writable host path, the
//! host home and secrets are simply never mounted, and egress is an isolated
//! network namespace (loopback only) unless policy widens it.
//!
//! This backend is defence-by-construction, not defence-in-depth: what the agent
//! cannot see, it cannot reach.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ward_policy::NetworkCapability;

use crate::error::{Error, Result};

/// Outcome of running one command in the sandbox.
pub struct Outcome {
    /// Exit code, or `None` if terminated by a signal.
    pub code: Option<i32>,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
    /// Wall-clock duration.
    pub duration: Duration,
}

/// Whether the sandbox actually works on this host.
///
/// `bwrap --version` succeeding is not enough: on hardened hosts (e.g. Ubuntu with
/// `apparmor_restrict_unprivileged_userns`) `bwrap` is installed but cannot create a
/// user namespace, so every sandboxed command fails. This runs a minimal real
/// sandbox and returns true only if it exits cleanly, so bwrap-guarded tests skip
/// rather than fail where isolation is unavailable.
pub fn available() -> bool {
    let mut cmd = Command::new("bwrap");
    cmd.arg("--unshare-all")
        .args(["--ro-bind", "/usr", "/usr"])
        .args(["--ro-bind", "/bin", "/bin"])
        .args(["--ro-bind", "/lib", "/lib"])
        .args(["--ro-bind-try", "/lib64", "/lib64"])
        .args(["--proc", "/proc"])
        .args(["--dev", "/dev"])
        .args(["--", "/bin/true"]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    // Short timeout so a stuck `bwrap` cannot hang the caller; `/bin/true` returns
    // near-instantly, so a probe that overruns is a broken sandbox, not a slow one.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return false,
        }
    }
}

/// Run `argv` inside the sandbox for `worktree`, honouring the network capability.
pub fn run(worktree: &Path, network: &NetworkCapability, argv: &[String]) -> Result<Outcome> {
    if argv.is_empty() {
        return Err(Error::Sandbox("empty command".into()));
    }
    let worktree = worktree
        .canonicalize()
        .map_err(|e| Error::io(worktree, e))?;

    let mut cmd = Command::new("bwrap");
    // Read-only system directories the toolchain needs; host home is never bound.
    for dir in [
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/etc/alternatives",
    ] {
        if Path::new(dir).exists() {
            cmd.args(["--ro-bind", dir, dir]);
        }
    }
    cmd.args(["--proc", "/proc"])
        .args(["--dev", "/dev"])
        .args(["--tmpfs", "/tmp"])
        .args(["--tmpfs", "/home"])
        .args(["--setenv", "HOME", "/home/agent"])
        .args([
            "--setenv",
            "PATH",
            "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
        ])
        .args(["--setenv", "TERM", "xterm"])
        .args(["--bind", &worktree.to_string_lossy(), "/work"])
        .args(["--chdir", "/work"])
        .args(["--hostname", "ward-sandbox"])
        .arg("--unshare-user")
        .arg("--unshare-pid")
        .arg("--unshare-ipc")
        .arg("--unshare-uts")
        .arg("--unshare-cgroup-try")
        .arg("--die-with-parent")
        .arg("--new-session");
    // Offline and localhost-only get an isolated netns (loopback only). Wider modes
    // still route through a proxy that Phase 1 does not ship, so they too run isolated
    // for now; the observer records the effective restriction.
    if !matches!(network, NetworkCapability::Unrestricted) {
        cmd.arg("--unshare-net");
    }
    cmd.arg("--");
    cmd.args(argv);

    let start = Instant::now();
    let out = cmd.output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::Sandbox("bubblewrap (bwrap) is not installed".into())
        } else {
            Error::Sandbox(format!("failed to launch bwrap: {e}"))
        }
    })?;
    Ok(Outcome {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        duration: start.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_probe_returns_a_bool_without_panicking() {
        // The value depends on the host (bwrap present and userns permitted); we only
        // assert the probe completes and yields a bool either way.
        let _: bool = available();
    }
}
