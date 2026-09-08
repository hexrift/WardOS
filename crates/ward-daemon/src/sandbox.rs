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

use std::path::{Path, PathBuf};
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

/// Mount point of the egress socket inside the sandbox.
pub const PROXY_SOCKET: &str = "/run/ward/proxy.sock";
/// Mount point of the `ward-agent` shim inside the sandbox.
pub const AGENT_SHIM: &str = "/run/ward/ward-agent";
/// Loopback address the in-sandbox relay listens on (ADR-0014).
pub const RELAY_ADDR: &str = "127.0.0.1:3128";

/// How the command's stdio is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdioMode {
    /// Capture stdout/stderr (batch commands).
    Capture,
    /// Inherit the terminal (interactive agents).
    Inherit,
}

/// One sandboxed launch, built up then executed.
pub struct Launch {
    worktree: PathBuf,
    argv: Vec<String>,
    env: Vec<(String, String)>,
    proxy_socket: Option<PathBuf>,
    shim: Option<PathBuf>,
    stdio: StdioMode,
}

impl Launch {
    /// A launch of `argv` over `worktree` with the default isolation.
    pub fn new(worktree: impl Into<PathBuf>, argv: Vec<String>) -> Self {
        Self {
            worktree: worktree.into(),
            argv,
            env: Vec::new(),
            proxy_socket: None,
            shim: None,
            stdio: StdioMode::Capture,
        }
    }

    /// Bind the session's egress socket into the sandbox (ADR-0014).
    #[must_use]
    pub fn egress(mut self, socket: impl Into<PathBuf>) -> Self {
        self.proxy_socket = Some(socket.into());
        self
    }

    /// Run through the `ward-agent` shim at this host path (Landlock, seccomp, relay).
    #[must_use]
    pub fn shim(mut self, path: impl Into<PathBuf>) -> Self {
        self.shim = Some(path.into());
        self
    }

    /// Add an environment variable inside the sandbox.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Inherit or capture stdio.
    #[must_use]
    pub fn stdio(mut self, stdio: StdioMode) -> Self {
        self.stdio = stdio;
        self
    }

    /// The `bwrap` argument vector (without the program name). Pure, for tests.
    pub fn args(&self, worktree: &Path) -> Vec<String> {
        fn push(a: &mut Vec<String>, xs: &[&str]) {
            a.extend(xs.iter().map(|x| (*x).to_string()));
        }
        let mut a: Vec<String> = Vec::new();
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
                push(&mut a, &["--ro-bind", dir, dir]);
            }
        }
        push(
            &mut a,
            &[
                "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home",
            ],
        );
        push(&mut a, &["--tmpfs", "/run"]);
        push(&mut a, &["--setenv", "HOME", "/home/agent"]);
        push(
            &mut a,
            &[
                "--setenv",
                "PATH",
                "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
            ],
        );
        push(&mut a, &["--setenv", "TERM", "xterm"]);
        for (k, v) in &self.env {
            push(&mut a, &["--setenv", k, v]);
        }
        push(
            &mut a,
            &[
                "--bind",
                &worktree.to_string_lossy(),
                "/work",
                "--chdir",
                "/work",
            ],
        );
        push(&mut a, &["--hostname", "ward-sandbox"]);
        // The network namespace is always isolated: the only way out is the egress
        // socket, and only when the session provides one (ADR-0014).
        push(
            &mut a,
            &[
                "--unshare-user",
                "--unshare-pid",
                "--unshare-ipc",
                "--unshare-uts",
                "--unshare-cgroup-try",
                "--unshare-net",
            ],
        );
        push(&mut a, &["--die-with-parent", "--new-session"]);
        if let Some(sock) = &self.proxy_socket {
            push(&mut a, &["--bind", &sock.to_string_lossy(), PROXY_SOCKET]);
        }
        if let Some(shim) = &self.shim {
            push(&mut a, &["--ro-bind", &shim.to_string_lossy(), AGENT_SHIM]);
        }
        push(&mut a, &["--"]);
        if self.shim.is_some() {
            push(&mut a, &[AGENT_SHIM]);
            if self.proxy_socket.is_some() {
                a.push("--relay".into());
                a.push(format!("{RELAY_ADDR}={PROXY_SOCKET}"));
            }
            push(&mut a, &["--"]);
        }
        a.extend(self.argv.iter().cloned());
        a
    }

    /// Execute the launch.
    pub fn run(&self) -> Result<Outcome> {
        if self.argv.is_empty() {
            return Err(Error::Sandbox("empty command".into()));
        }
        let worktree = self
            .worktree
            .canonicalize()
            .map_err(|e| Error::io(&self.worktree, e))?;
        let mut cmd = Command::new("bwrap");
        cmd.args(self.args(&worktree));
        let start = Instant::now();
        let launch_err = |e: std::io::Error| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Sandbox("bubblewrap (bwrap) is not installed".into())
            } else {
                Error::Sandbox(format!("failed to launch bwrap: {e}"))
            }
        };
        let (code, stdout, stderr) = match self.stdio {
            StdioMode::Capture => {
                let out = cmd.output().map_err(launch_err)?;
                (
                    out.status.code(),
                    String::from_utf8_lossy(&out.stdout).into_owned(),
                    String::from_utf8_lossy(&out.stderr).into_owned(),
                )
            }
            StdioMode::Inherit => {
                let status = cmd.status().map_err(launch_err)?;
                (status.code(), String::new(), String::new())
            }
        };
        Ok(Outcome {
            code,
            stdout,
            stderr,
            duration: start.elapsed(),
        })
    }
}

/// Run `argv` inside the sandbox for `worktree` with no egress (used by selftest).
pub fn run(worktree: &Path, _network: &NetworkCapability, argv: &[String]) -> Result<Outcome> {
    Launch::new(worktree, argv.to_vec()).run()
}

/// Locate the `ward-agent` shim: `$WARD_AGENT_BIN`, else a sibling of this executable.
pub fn find_shim() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("WARD_AGENT_BIN") {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    let exe = std::env::current_exe().ok()?;
    let sibling = exe.parent()?.join("ward-agent");
    sibling.is_file().then_some(sibling)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_isolate_net_and_bind_egress_and_shim() {
        let l = Launch::new("/tmp", vec!["true".into()])
            .egress("/host/proxy.sock")
            .shim("/host/ward-agent")
            .env("FOO", "bar");
        let a = l.args(Path::new("/tmp")).join(" ");
        assert!(a.contains("--unshare-net"));
        assert!(a.contains("--bind /host/proxy.sock /run/ward/proxy.sock"));
        assert!(a.contains("--ro-bind /host/ward-agent /run/ward/ward-agent"));
        assert!(a.contains("--setenv FOO bar"));
        assert!(a.ends_with(
            "-- /run/ward/ward-agent --relay 127.0.0.1:3128=/run/ward/proxy.sock -- true"
        ));
        assert!(!a.contains("/root"), "host home must never be bound");
    }

    #[test]
    fn args_without_shim_exec_argv_directly() {
        let a = Launch::new("/tmp", vec!["sh".into(), "-c".into(), "id".into()])
            .args(Path::new("/tmp"));
        assert_eq!(&a[a.len() - 4..], &["--", "sh", "-c", "id"]);
    }
}
