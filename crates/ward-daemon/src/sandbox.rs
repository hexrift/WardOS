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
    /// The launch was killed because it outran its budget.
    pub timed_out: bool,
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
/// Read-only system directories bound into the sandbox: the toolchains the agent
/// needs (`/opt` carries vendor installs such as Node and Claude Code). The host
/// home, `/etc` beyond trust roots, and everything else are never bound.
const SYSTEM_RO: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/opt",
    "/etc/alternatives",
    "/etc/ssl",
    "/etc/ca-certificates",
];
/// `PATH` inside the sandbox when the host offers nothing under a bound directory.
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin";
/// Mount point of the session's hook socket inside the sandbox (`hooks.rs`).
pub const HOOK_SOCKET: &str = "/run/ward/hooks.sock";
/// Loopback address the in-sandbox relay listens on (ADR-0014).
pub const RELAY_ADDR: &str = "127.0.0.1:3128";

fn host_path() -> String {
    std::env::var("PATH").unwrap_or_default()
}

/// The sandbox `PATH`: the host's entries that live under a bound system directory,
/// in host order, then the defaults. Nothing under the host home or elsewhere leaks in.
fn sandbox_path(host: &str) -> String {
    let bound = |dir: &&str| {
        SYSTEM_RO
            .iter()
            .any(|root| Path::new(dir).starts_with(root))
    };
    let mut out: Vec<&str> = Vec::new();
    for dir in host.split(':').filter(bound).chain(DEFAULT_PATH.split(':')) {
        if !out.contains(&dir) {
            out.push(dir);
        }
    }
    out.join(":")
}

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
    hook_socket: Option<PathBuf>,
    seeds: Vec<(PathBuf, String)>,
    ro_binds: Vec<(PathBuf, String)>,
    tmpfs: Vec<String>,
    shim: Option<PathBuf>,
    shim_flags: Vec<String>,
    stdio: StdioMode,
    budget: Option<Duration>,
}

impl Launch {
    /// A launch of `argv` over `worktree` with the default isolation.
    pub fn new(worktree: impl Into<PathBuf>, argv: Vec<String>) -> Self {
        Self {
            worktree: worktree.into(),
            argv,
            env: Vec::new(),
            proxy_socket: None,
            hook_socket: None,
            seeds: Vec::new(),
            ro_binds: Vec::new(),
            tmpfs: Vec::new(),
            shim: None,
            shim_flags: Vec::new(),
            stdio: StdioMode::Capture,
            budget: None,
        }
    }

    /// Bind the session's egress socket into the sandbox (ADR-0014).
    #[must_use]
    pub fn egress(mut self, socket: impl Into<PathBuf>) -> Self {
        self.proxy_socket = Some(socket.into());
        self
    }

    /// Bind the session's hook socket into the sandbox; the shim's Landlock `io`
    /// tier picks it up through `WARD_SOCKET`.
    #[must_use]
    pub fn hooks(mut self, socket: impl Into<PathBuf>) -> Self {
        self.hook_socket = Some(socket.into());
        self
    }

    /// Bind a host file read-only at `path` inside the sandbox (agent settings).
    #[must_use]
    pub fn seed(mut self, host_file: impl Into<PathBuf>, path: impl Into<String>) -> Self {
        self.seeds.push((host_file.into(), path.into()));
        self
    }

    /// Bind a host directory read-only at `path` (verifier toolchains, ADR-0004).
    #[must_use]
    pub fn ro_bind(mut self, host_dir: impl Into<PathBuf>, path: impl Into<String>) -> Self {
        self.ro_binds.push((host_dir.into(), path.into()));
        self
    }

    /// Mount a private tmpfs at `path`, before any binds beneath it.
    #[must_use]
    pub fn tmpfs(mut self, path: impl Into<String>) -> Self {
        self.tmpfs.push(path.into());
        self
    }

    /// Run through the `ward-agent` shim at this host path (Landlock, seccomp, relay).
    #[must_use]
    pub fn shim(mut self, path: impl Into<PathBuf>) -> Self {
        self.shim = Some(path.into());
        self
    }

    /// Extra flags for the shim (e.g. `--allow-no-landlock` on kernels without Landlock).
    #[must_use]
    pub fn shim_flags(mut self, flags: Vec<String>) -> Self {
        self.shim_flags = flags;
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

    /// Kill the launch if it runs longer than this (verifier wall-clock budget).
    #[must_use]
    pub fn budget(mut self, budget: Duration) -> Self {
        self.budget = Some(budget);
        self
    }

    /// The `bwrap` argument vector (without the program name). Pure, for tests.
    pub fn args(&self, worktree: &Path) -> Vec<String> {
        fn push(a: &mut Vec<String>, xs: &[&str]) {
            a.extend(xs.iter().map(|x| (*x).to_string()));
        }
        let mut a: Vec<String> = Vec::new();
        // Read-only system directories the toolchain needs; host home is never bound.
        // TLS trust roots are read-only system data the agent needs for HTTPS via CONNECT.
        for dir in SYSTEM_RO {
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
        // The shim's read-write set is /work, /env, /tmp and $HOME; every one must exist
        // (it fails closed otherwise), so create the sandbox-private ones here.
        push(&mut a, &["--dir", "/home/agent", "--tmpfs", "/env"]);
        push(&mut a, &["--setenv", "HOME", "/home/agent"]);
        push(&mut a, &["--setenv", "PATH", &sandbox_path(&host_path())]);
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
        if let Some(sock) = &self.hook_socket {
            push(&mut a, &["--bind", &sock.to_string_lossy(), HOOK_SOCKET]);
            push(&mut a, &["--setenv", "WARD_SOCKET", HOOK_SOCKET]);
        }
        for (file, path) in &self.seeds {
            push(&mut a, &["--ro-bind", &file.to_string_lossy(), path]);
        }
        for path in &self.tmpfs {
            push(&mut a, &["--tmpfs", path]);
        }
        for (dir, path) in &self.ro_binds {
            push(&mut a, &["--ro-bind", &dir.to_string_lossy(), path]);
        }
        if let Some(shim) = &self.shim {
            push(&mut a, &["--ro-bind", &shim.to_string_lossy(), AGENT_SHIM]);
        }
        push(&mut a, &["--"]);
        if self.shim.is_some() {
            push(&mut a, &[AGENT_SHIM]);
            a.extend(self.shim_flags.iter().cloned());
            // The shim only forwards whitelisted env to the agent; name ours explicitly.
            for (k, _) in &self.env {
                push(&mut a, &["--env", k]);
            }
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
        if self.stdio == StdioMode::Capture {
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        let mut child = cmd.spawn().map_err(launch_err)?;
        let stdout = child.stdout.take().map(drain);
        let stderr = child.stderr.take().map(drain);
        let (status, timed_out) = wait_within(&mut child, self.budget)?;
        let collect = |h: Option<std::thread::JoinHandle<Vec<u8>>>| {
            h.and_then(|h| h.join().ok())
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default()
        };
        Ok(Outcome {
            code: status.and_then(|s| s.code()),
            stdout: collect(stdout),
            stderr: collect(stderr),
            duration: start.elapsed(),
            timed_out,
        })
    }
}

/// Read a child stream to the end on its own thread.
fn drain<R: std::io::Read + Send + 'static>(mut r: R) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = r.read_to_end(&mut buf);
        buf
    })
}

/// Wait for `child`, killing it once `budget` elapses. Returns the exit status
/// (`None` when killed) and whether the budget was exceeded.
fn wait_within(
    child: &mut std::process::Child,
    budget: Option<Duration>,
) -> Result<(Option<std::process::ExitStatus>, bool)> {
    let wait_err = |e: std::io::Error| Error::Sandbox(format!("waiting for bwrap: {e}"));
    let Some(budget) = budget else {
        return Ok((Some(child.wait().map_err(wait_err)?), false));
    };
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = child.try_wait().map_err(wait_err)? {
            return Ok((Some(status), false));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok((None, true));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Run `argv` inside the sandbox for `worktree` with no egress (used by selftest).
pub fn run(worktree: &Path, _network: &NetworkCapability, argv: &[String]) -> Result<Outcome> {
    Launch::new(worktree, argv.to_vec()).run()
}

/// What the located `ward-agent` shim supports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shim {
    /// Host path of the binary (bound read-only into the sandbox).
    pub path: PathBuf,
    /// Whether this build accepts `--relay` (ADR-0014).
    pub relay: bool,
    /// Whether the running kernel enforces Landlock; if not the shim is told to
    /// continue with seccomp only, and the session records the degradation.
    pub landlock: bool,
}

impl Shim {
    /// Flags the daemon passes to this shim.
    #[must_use]
    pub fn flags(&self) -> Vec<String> {
        if self.landlock {
            Vec::new()
        } else {
            vec!["--allow-no-landlock".into()]
        }
    }
}

/// Locate and probe the `ward-agent` shim: `$WARD_AGENT_BIN`, else a sibling of this
/// executable. Returns `None` when no usable shim exists.
pub fn find_shim() -> Option<Shim> {
    let path = match std::env::var("WARD_AGENT_BIN") {
        Ok(p) => PathBuf::from(p),
        Err(_) => std::env::current_exe().ok()?.parent()?.join("ward-agent"),
    };
    if !path.is_file() {
        return None;
    }
    let help = Command::new(&path).arg("--help").output().ok()?;
    let text = String::from_utf8_lossy(&help.stdout);
    Some(Shim {
        path,
        relay: text.contains("--relay"),
        landlock: ward_agent::landlock::is_available(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
        assert!(
            a.contains("--env FOO"),
            "shim must be told to pass FOO through"
        );
        assert!(a.ends_with(
            "-- /run/ward/ward-agent --env FOO --relay 127.0.0.1:3128=/run/ward/proxy.sock -- true"
        ));
        assert!(!a.contains("/root"), "host home must never be bound");
        assert!(
            a.contains("--dir /home/agent") && a.contains("--tmpfs /env"),
            "shim rw paths exist"
        );
    }

    #[test]
    fn sandbox_path_keeps_only_bound_host_entries_then_defaults() {
        let host = "/root/.cargo/bin:/opt/node22/bin:/usr/local/bin:/home/u/bin:/usr/bin";
        assert_eq!(
            sandbox_path(host),
            "/opt/node22/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"
        );
        assert_eq!(sandbox_path(""), DEFAULT_PATH);
        assert!(!sandbox_path("/optical/bin").contains("optical"));
    }

    #[test]
    fn args_bind_hook_socket_and_seed_files() {
        let a = Launch::new("/tmp", vec!["true".into()])
            .hooks("/host/hooks.sock")
            .seed("/host/settings.json", "/home/agent/.claude/settings.json")
            .args(Path::new("/tmp"))
            .join(" ");
        assert!(a.contains("--bind /host/hooks.sock /run/ward/hooks.sock"));
        assert!(a.contains("--setenv WARD_SOCKET /run/ward/hooks.sock"));
        assert!(a.contains("--ro-bind /host/settings.json /home/agent/.claude/settings.json"));
    }

    #[test]
    fn args_mount_tmpfs_before_ro_binds_beneath_it() {
        let a = Launch::new("/tmp", vec!["true".into()])
            .tmpfs("/run/verifier/cargo")
            .ro_bind("/root/.cargo/bin", "/run/verifier/cargo/bin")
            .args(Path::new("/tmp"))
            .join(" ");
        let tmpfs = a.find("--tmpfs /run/verifier/cargo").unwrap();
        let bind = a
            .find("--ro-bind /root/.cargo/bin /run/verifier/cargo/bin")
            .unwrap();
        assert!(tmpfs < bind);
    }

    #[test]
    fn budget_kills_an_overrunning_launch() {
        if !available() {
            eprintln!("skipping: bubblewrap not available");
            return;
        }
        let out = Launch::new("/tmp", vec!["sh".into(), "-c".into(), "sleep 5".into()])
            .budget(Duration::from_millis(300))
            .run()
            .unwrap();
        assert!(out.timed_out);
        assert_eq!(out.code, None);
        assert!(out.duration < Duration::from_secs(3), "{:?}", out.duration);
        let ok = Launch::new("/tmp", vec!["sh".into(), "-c".into(), "echo fine".into()])
            .budget(Duration::from_secs(5))
            .run()
            .unwrap();
        assert!(!ok.timed_out);
        assert_eq!(ok.stdout.trim(), "fine");
    }

    #[test]
    fn args_without_shim_exec_argv_directly() {
        let a = Launch::new("/tmp", vec!["sh".into(), "-c".into(), "id".into()])
            .args(Path::new("/tmp"));
        assert_eq!(&a[a.len() - 4..], &["--", "sh", "-c", "id"]);
    }
}
