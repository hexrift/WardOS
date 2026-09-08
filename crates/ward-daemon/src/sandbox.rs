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
use std::process::Command;
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

/// Whether `bwrap` is available on this host.
pub fn available() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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
