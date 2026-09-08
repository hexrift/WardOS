//! `ward doctor`: what this host can and cannot give a session. Each check is
//! a fact with a fix, so a new machine is set up from the output alone.

use std::path::Path;
use std::process::Command;

use crate::{daemon, sandbox, session, verify};

/// Outcome of one check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Works as designed.
    Ok,
    /// Works with a documented degradation.
    Warn,
    /// A session cannot run until this is fixed.
    Fail,
}

/// One host check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    /// Short name.
    pub name: &'static str,
    /// Outcome.
    pub status: Status,
    /// What was found and, on `Warn`/`Fail`, what to do.
    pub detail: String,
}

impl Check {
    fn new(name: &'static str, status: Status, detail: impl Into<String>) -> Self {
        Self {
            name,
            status,
            detail: detail.into(),
        }
    }
}

/// Run every check against this host.
#[must_use]
pub fn run() -> Vec<Check> {
    let state = session::state_root();
    vec![
        bubblewrap(),
        userns_policy(
            read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref(),
            read("/proc/sys/kernel/unprivileged_userns_clone").as_deref(),
        ),
        landlock(),
        seccomp(read("/proc/self/status").as_deref()),
        cgroup_v2(Path::new("/sys/fs/cgroup/cgroup.controllers").exists()),
        inotify(read("/proc/sys/fs/inotify/max_user_watches").as_deref()),
        companions(),
        toolchain(),
        tool("git", true),
        tool("curl", false),
        state_dir(&state),
        socket_path(&state),
        agents(),
    ]
}

/// Whether any check failed.
#[must_use]
pub fn healthy(checks: &[Check]) -> bool {
    checks.iter().all(|c| c.status != Status::Fail)
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn bubblewrap() -> Check {
    let version = Command::new("bwrap")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
    match version {
        None => Check::new(
            "bubblewrap",
            Status::Fail,
            "bwrap not found; install bubblewrap (apt/dnf/pacman: bubblewrap)",
        ),
        Some(v) if sandbox::available() => Check::new("bubblewrap", Status::Ok, v),
        Some(v) => Check::new(
            "bubblewrap",
            Status::Fail,
            format!(
                "{v} found but a user-namespace sandbox cannot start; see the user namespaces row"
            ),
        ),
    }
}

/// The two kernel knobs that stop unprivileged user namespaces.
#[must_use]
pub fn userns_policy(apparmor: Option<&str>, clone: Option<&str>) -> Check {
    let restricted = apparmor.is_some_and(|v| v.trim() == "1");
    let disabled = clone.is_some_and(|v| v.trim() == "0");
    if restricted {
        Check::new(
            "user namespaces",
            Status::Fail,
            "AppArmor restricts unprivileged user namespaces (Ubuntu 24.04+); run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 (persist in /etc/sysctl.d/)",
        )
    } else if disabled {
        Check::new(
            "user namespaces",
            Status::Fail,
            "kernel.unprivileged_userns_clone=0; run: sudo sysctl -w kernel.unprivileged_userns_clone=1",
        )
    } else {
        Check::new(
            "user namespaces",
            Status::Ok,
            "unprivileged user namespaces allowed",
        )
    }
}

fn landlock() -> Check {
    if ward_agent::landlock::is_available() {
        Check::new(
            "landlock",
            Status::Ok,
            "kernel enforces Landlock; inner file rules apply",
        )
    } else {
        Check::new(
            "landlock",
            Status::Warn,
            "no Landlock (kernel < 5.13 or disabled); the shim runs with seccomp only and records the degradation",
        )
    }
}

/// Kernel seccomp support, read from the process status.
#[must_use]
pub fn seccomp(status: Option<&str>) -> Check {
    if status.is_some_and(|s| s.lines().any(|l| l.starts_with("Seccomp:"))) {
        Check::new("seccomp", Status::Ok, "kernel reports seccomp")
    } else {
        Check::new(
            "seccomp",
            Status::Fail,
            "no seccomp in /proc/self/status; the shim cannot install its filter",
        )
    }
}

/// cgroup v2 is what nested containers (crun) need; sessions themselves do not.
#[must_use]
pub fn cgroup_v2(present: bool) -> Check {
    if present {
        Check::new("cgroup v2", Status::Ok, "unified hierarchy mounted")
    } else {
        Check::new(
            "cgroup v2",
            Status::Warn,
            "no unified cgroup hierarchy; sessions run, nested containers (E-04) will not",
        )
    }
}

/// inotify watch budget for the live file observer.
#[must_use]
pub fn inotify(max_watches: Option<&str>) -> Check {
    match max_watches.and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(n) if n >= 65536 => Check::new("inotify", Status::Ok, format!("max_user_watches {n}")),
        Some(n) => Check::new(
            "inotify",
            Status::Warn,
            format!(
                "max_user_watches {n}; large worktrees fall back to a scan (sysctl fs.inotify.max_user_watches=524288)"
            ),
        ),
        None => Check::new(
            "inotify",
            Status::Warn,
            "cannot read fs.inotify.max_user_watches",
        ),
    }
}

fn companions() -> Check {
    let wardd = daemon::find_binary();
    let shim = sandbox::find_shim();
    match (wardd, shim) {
        (Some(d), Some(s)) if s.relay => Check::new(
            "companion binaries",
            Status::Ok,
            format!("wardd {} · ward-agent {}", d.display(), s.path.display()),
        ),
        (_, Some(s)) => Check::new(
            "companion binaries",
            Status::Fail,
            format!(
                "ward-agent at {} lacks --relay; install matching binaries",
                s.path.display()
            ),
        ),
        (Some(_), None) => Check::new(
            "companion binaries",
            Status::Fail,
            "ward-agent not found beside ward or on PATH; the sandbox has no egress relay",
        ),
        (None, _) => Check::new(
            "companion binaries",
            Status::Fail,
            "wardd not found beside ward or on PATH; sessions cannot have a daemon",
        ),
    }
}

fn toolchain() -> Check {
    if verify::Toolchains::detect().has_rust() {
        Check::new(
            "verifier toolchain",
            Status::Ok,
            "Rust toolchain found (~/.rustup, ~/.cargo)",
        )
    } else {
        Check::new(
            "verifier toolchain",
            Status::Warn,
            "no Rust toolchain for the verifier; `ward verify` can run only commands from the base system",
        )
    }
}

fn tool(name: &'static str, required: bool) -> Check {
    let found = Command::new(name)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    match (found, required) {
        (true, _) => Check::new(name, Status::Ok, "on PATH"),
        (false, true) => Check::new(
            name,
            Status::Fail,
            format!("{name} not found; the GitHub adapter and repository probes need it"),
        ),
        (false, false) => Check::new(
            name,
            Status::Warn,
            format!("{name} not found; optional (used by the demo)"),
        ),
    }
}

fn state_dir(state: &Path) -> Check {
    match std::fs::create_dir_all(state) {
        Ok(()) => Check::new("state dir", Status::Ok, state.display().to_string()),
        Err(e) => Check::new(
            "state dir",
            Status::Fail,
            format!(
                "{}: {e}; set WARD_STATE_DIR to a writable directory",
                state.display()
            ),
        ),
    }
}

/// A control socket path must fit `sockaddr_un`; the session id is 31 bytes.
#[must_use]
pub fn socket_path(state: &Path) -> Check {
    let longest = session::session_dir(state, "sess_00000000000000000000000000")
        .join(crate::control::SOCKET_NAME);
    let len = longest.as_os_str().len();
    if len <= daemon::MAX_SOCKET_PATH {
        Check::new(
            "socket path",
            Status::Ok,
            format!("{len} of {} bytes", daemon::MAX_SOCKET_PATH),
        )
    } else {
        Check::new(
            "socket path",
            Status::Fail,
            format!(
                "{len} bytes exceeds {}; set WARD_STATE_DIR to a shorter path",
                daemon::MAX_SOCKET_PATH
            ),
        )
    }
}

fn agents() -> Check {
    let found: Vec<&str> = ["claude", "codex"]
        .into_iter()
        .filter(|a| {
            Command::new(a)
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
        })
        .collect();
    if found.is_empty() {
        Check::new(
            "agents",
            Status::Warn,
            "neither claude nor codex on PATH; `ward run` works, `ward claude` needs Claude Code installed",
        )
    } else {
        Check::new("agents", Status::Ok, found.join(", "))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn userns_policy_names_the_fix() {
        let c = userns_policy(Some("1\n"), None);
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("apparmor_restrict_unprivileged_userns=0"));
        let c = userns_policy(None, Some("0"));
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("unprivileged_userns_clone=1"));
        assert_eq!(userns_policy(Some("0"), Some("1")).status, Status::Ok);
        assert_eq!(userns_policy(None, None).status, Status::Ok);
    }

    #[test]
    fn thresholds_and_presence_checks() {
        assert_eq!(seccomp(Some("Name: x\nSeccomp:\t2\n")).status, Status::Ok);
        assert_eq!(seccomp(Some("Name: x\n")).status, Status::Fail);
        assert_eq!(cgroup_v2(true).status, Status::Ok);
        assert_eq!(cgroup_v2(false).status, Status::Warn);
        assert_eq!(inotify(Some("524288")).status, Status::Ok);
        assert_eq!(inotify(Some("8192")).status, Status::Warn);
        assert_eq!(inotify(None).status, Status::Warn);
    }

    #[test]
    fn socket_path_check_uses_the_longest_session_id() {
        assert_eq!(socket_path(Path::new("/tmp/w")).status, Status::Ok);
        let long = "/".to_owned() + &"d".repeat(120);
        let c = socket_path(Path::new(&long));
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("WARD_STATE_DIR"));
    }

    #[test]
    fn run_reports_every_check_once() {
        let checks = run();
        let names: Vec<&str> = checks.iter().map(|c| c.name).collect();
        for n in [
            "bubblewrap",
            "user namespaces",
            "landlock",
            "seccomp",
            "cgroup v2",
            "inotify",
            "companion binaries",
            "verifier toolchain",
            "git",
            "state dir",
            "socket path",
            "agents",
        ] {
            assert_eq!(names.iter().filter(|x| **x == n).count(), 1, "{n}");
        }
        let _ = healthy(&checks);
    }
}
