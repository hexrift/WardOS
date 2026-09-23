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

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ward_policy::NetworkCapability;

use crate::error::{Error, Result};

/// Outcome of running one command in the sandbox.
pub struct Outcome {
    /// Exit code, or `None` if terminated by a signal.
    pub code: Option<i32>,
    /// Captured stdout. Bounded to a head and tail when a capture limit is set.
    pub stdout: String,
    /// Captured stderr. Bounded to a head and tail when a capture limit is set.
    pub stderr: String,
    /// Total bytes the child wrote to stdout, before any truncation.
    pub stdout_bytes: u64,
    /// Total bytes the child wrote to stderr, before any truncation.
    pub stderr_bytes: u64,
    /// Whether `stdout` or `stderr` dropped bytes from the middle to stay in budget.
    pub truncated: bool,
    /// Full copies of lines whose start matched the capture's keep-prefix, taken from
    /// the complete streams (stdout then stderr) regardless of head/tail truncation.
    pub kept_lines: Vec<String>,
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
/// Whether `path` is guaranteed to exist, read-only, at this same path inside
/// every sandbox `Launch::args` builds — one of the fixed [`SYSTEM_RO`]
/// `--ro-bind`s, always added when the host has the directory. Never true for a
/// project's own worktree (bound at `/work`, an unrelated host path) or a
/// toolchain mount (`verify::Toolchains`, mounted under the sandbox-only
/// `/run/verifier`, with no fixed host equivalent) — those need their own
/// reasoning, not this one. `ward ready`'s `runtime` row uses this to judge an
/// absolute path candidate in `verify.command`: anything outside these roots is
/// not merely unverified, it is *guaranteed absent* inside the verifier, since
/// `/tmp`, `/home` and `/run` are replaced with empty private filesystems and
/// nothing else is bound at all.
#[must_use]
pub(crate) fn is_system_ro(path: &Path) -> bool {
    SYSTEM_RO.iter().any(|root| path.starts_with(root))
}

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
    capture_bytes: Option<usize>,
    keep_prefix: Option<String>,
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
            capture_bytes: None,
            keep_prefix: None,
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

    /// Bound each captured stream to roughly `bytes` retained in memory (a head and a
    /// tail), draining and dropping the middle so a large writer can neither exhaust
    /// memory nor deadlock on a full pipe. Only meaningful with [`StdioMode::Capture`].
    #[must_use]
    pub fn capture_bytes(mut self, bytes: usize) -> Self {
        self.capture_bytes = Some(bytes);
        self
    }

    /// Keep full copies of captured lines that start with `prefix` (e.g. test-result
    /// summaries), taken from the whole stream even when the retained text is
    /// truncated — so counts are never read from text that was dropped.
    #[must_use]
    pub fn keep_lines(mut self, prefix: impl Into<String>) -> Self {
        self.keep_prefix = Some(prefix.into());
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
        self.run_observed(&mut || {})
    }

    /// [`run`](Self::run), calling `on_tick` about every [`WAIT_POLL`] while the
    /// child is still running.
    ///
    /// This is what lets the session drain its observers into the event log *during*
    /// a command instead of only after it (#137): the callback runs on this thread,
    /// between waits, so the session's single log writer stays the only writer and
    /// no second thread is introduced to append records. It is never called after
    /// the child has been reaped, which leaves the final flush unambiguously the
    /// caller's to do exactly once.
    pub fn run_observed(&self, on_tick: &mut dyn FnMut()) -> Result<Outcome> {
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
        let bound = self.capture_bytes;
        let keep = self.keep_prefix.clone();
        let stdout = child.stdout.take().map(|r| drain(r, bound, keep.clone()));
        let stderr = child.stderr.take().map(|r| drain(r, bound, keep));
        let (status, timed_out) = wait_within(&mut child, self.budget, on_tick)?;
        let collect = |h: Option<std::thread::JoinHandle<StreamCapture>>| {
            h.and_then(|h| h.join().ok()).unwrap_or_default()
        };
        let out = collect(stdout);
        let err = collect(stderr);
        let mut kept_lines = out.kept_lines;
        kept_lines.extend(err.kept_lines);
        Ok(Outcome {
            code: status.and_then(|s| s.code()),
            stdout: out.text,
            stderr: err.text,
            stdout_bytes: out.total,
            stderr_bytes: err.total,
            truncated: out.truncated || err.truncated,
            kept_lines,
            duration: start.elapsed(),
            timed_out,
        })
    }
}

/// A single child stream captured within a memory budget.
#[derive(Default)]
struct StreamCapture {
    /// Retained text: the head, a truncation marker when bytes were dropped, then the tail.
    text: String,
    /// Total bytes read from the stream, before truncation.
    total: u64,
    /// Whether any bytes were dropped from the middle.
    truncated: bool,
    /// Full copies of lines that started with the keep-prefix, from the whole stream.
    kept_lines: Vec<String>,
}

/// Bytes of matched lines kept per stream before further matches are ignored (the
/// stream is still drained), so a pathological writer cannot grow this without bound.
const MAX_KEPT_LINE_BYTES: usize = 256 * 1024;

/// Longest single line buffered while scanning for the keep-prefix; a longer line
/// is still drained but only its first `MAX_LINE_SCAN` bytes are examined.
const MAX_LINE_SCAN: usize = 8 * 1024;

/// Read a child stream to EOF on its own thread. With no `bound` this is a plain
/// read-to-end (the original behaviour for callers that set no capture limit). With
/// a `bound` it retains only a head and tail within roughly `bound` bytes while still
/// draining the rest, and with a `keep_prefix` it also retains full copies of matching
/// lines taken from the complete stream, independent of the head/tail truncation.
fn drain<R: std::io::Read + Send + 'static>(
    mut r: R,
    bound: Option<usize>,
    keep_prefix: Option<String>,
) -> std::thread::JoinHandle<StreamCapture> {
    std::thread::spawn(move || {
        if let Some(bound) = bound {
            return drain_bounded(&mut r, bound, keep_prefix.as_deref());
        }
        // Unbounded: the original read-to-end behaviour for callers with no limit.
        let mut buf = Vec::new();
        let _ = r.read_to_end(&mut buf);
        let text = String::from_utf8_lossy(&buf).into_owned();
        let mut kept_lines = Vec::new();
        if let Some(prefix) = keep_prefix.as_deref() {
            let mut kept_bytes = 0;
            for line in text.lines() {
                push_kept_line(line.as_bytes(), prefix, &mut kept_lines, &mut kept_bytes);
            }
        }
        StreamCapture {
            total: buf.len() as u64,
            text,
            truncated: false,
            kept_lines,
        }
    })
}

/// Retain a head and a tail within `bound` bytes, dropping the middle, while
/// counting the full byte total and capturing keep-prefix lines from the whole stream.
fn drain_bounded<R: std::io::Read>(
    r: &mut R,
    bound: usize,
    keep_prefix: Option<&str>,
) -> StreamCapture {
    use std::fmt::Write as _;
    let tail_limit = (bound / 4).max(1);
    let head_limit = bound.saturating_sub(tail_limit);
    let mut head: Vec<u8> = Vec::new();
    let mut tail: VecDeque<u8> = VecDeque::new();
    let mut total: u64 = 0;
    let mut truncated = false;
    let mut kept_lines: Vec<String> = Vec::new();
    let mut kept_bytes = 0usize;
    let mut line: Vec<u8> = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                for &b in &buf[..n] {
                    if head.len() < head_limit {
                        head.push(b);
                    } else {
                        tail.push_back(b);
                        if tail.len() > tail_limit {
                            tail.pop_front();
                            truncated = true;
                        }
                    }
                    if let Some(prefix) = keep_prefix {
                        if b == b'\n' {
                            push_kept_line(&line, prefix, &mut kept_lines, &mut kept_bytes);
                            line.clear();
                        } else if line.len() < MAX_LINE_SCAN {
                            line.push(b);
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    if let Some(prefix) = keep_prefix
        && !line.is_empty()
    {
        push_kept_line(&line, prefix, &mut kept_lines, &mut kept_bytes);
    }
    let text = if truncated {
        let dropped = total.saturating_sub((head.len() + tail.len()) as u64);
        let mut s = String::from_utf8_lossy(&head).into_owned();
        let _ = write!(
            s,
            "\n[verifier output truncated: {dropped} bytes dropped; kept first {} and last {} of {total} bytes]\n",
            head.len(),
            tail.len(),
        );
        let tail_bytes: Vec<u8> = tail.into_iter().collect();
        s.push_str(&String::from_utf8_lossy(&tail_bytes));
        s
    } else {
        // Nothing was dropped: head then tail is the whole stream, in order.
        let mut bytes = head;
        bytes.extend(tail);
        String::from_utf8_lossy(&bytes).into_owned()
    };
    StreamCapture {
        text,
        total,
        truncated,
        kept_lines,
    }
}

/// Push `line` (a full line, without its newline) to `out` when it starts with
/// `prefix` and the per-stream keep budget is not yet spent.
fn push_kept_line(line: &[u8], prefix: &str, out: &mut Vec<String>, kept_bytes: &mut usize) {
    if *kept_bytes >= MAX_KEPT_LINE_BYTES {
        return;
    }
    let text = String::from_utf8_lossy(line);
    let text = text.strip_suffix('\r').unwrap_or(&text);
    if text.starts_with(prefix) {
        *kept_bytes += text.len();
        out.push(text.to_string());
    }
}

/// How long one park between `try_wait` calls lasts; also the rate `on_tick` is
/// offered to the caller at.
pub const WAIT_POLL: Duration = Duration::from_millis(20);

/// Wait for `child`, killing it once `budget` elapses, and call `on_tick` between
/// waits so the caller can make progress (draining observers, #137) while the child
/// still runs. Returns the exit status (`None` when killed) and whether the budget
/// was exceeded.
///
/// The wait polls even with no budget, where it used to block in `wait(2)`: a
/// blocking wait cannot offer the caller a turn, and an interactive agent session
/// is exactly the case where the whole run would otherwise pass with nothing on the
/// log. `on_tick` never runs after the child has been reaped.
fn wait_within(
    child: &mut std::process::Child,
    budget: Option<Duration>,
    on_tick: &mut dyn FnMut(),
) -> Result<(Option<std::process::ExitStatus>, bool)> {
    let wait_err = |e: std::io::Error| Error::Sandbox(format!("waiting for bwrap: {e}"));
    let deadline = budget.map(|b| Instant::now() + b);
    loop {
        if let Some(status) = child.try_wait().map_err(wait_err)? {
            return Ok((Some(status), false));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok((None, true));
        }
        std::thread::sleep(WAIT_POLL);
        on_tick();
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
    fn is_system_ro_matches_only_a_real_bound_root_by_path_component() {
        assert!(is_system_ro(Path::new("/usr/bin/cargo")));
        assert!(is_system_ro(Path::new("/opt/node22/bin/npm")));
        // Component-wise, not a raw string prefix: "/optical" must not match "/opt".
        assert!(!is_system_ro(Path::new("/optical/bin/tool")));
        assert!(!is_system_ro(Path::new("/tmp/ward-test-tool")));
        assert!(!is_system_ro(Path::new("/home/user/bin/tool")));
        assert!(!is_system_ro(Path::new("/work/scripts/verify.sh")));
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
        if !ward_sandbox::ci::isolation_ready(available(), "bubblewrap") {
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
    fn bounded_capture_drains_a_large_pipe_without_hanging() {
        if !ward_sandbox::ci::isolation_ready(available(), "bubblewrap") {
            return;
        }
        // Emit far more than the pipe buffer and the capture budget, with a summary
        // line at the end, then exit non-zero. A reader that stopped at the budget
        // instead of draining would leave the child blocked on a full pipe until the
        // budget killed it (timed_out, code None); asserting a clean exit 7 proves it
        // drained everything while keeping only a bounded head and tail.
        let script = "for i in $(seq 1 5000); do echo \"line $i padded xxxxxxxxxxxxxxxxxxxxxxxxxx\"; done; echo 'test result: ok. 3 passed; 1 failed; 0 ignored'; exit 7";
        let out = Launch::new("/tmp", vec!["sh".into(), "-c".into(), script.into()])
            .capture_bytes(4096)
            .keep_lines("test result:")
            .budget(Duration::from_secs(20))
            .run()
            .unwrap();
        assert!(
            !out.timed_out,
            "the pipe was drained, so the child finished"
        );
        assert_eq!(out.code, Some(7), "exit code survives truncation");
        assert!(out.truncated);
        assert!(
            out.stdout.len() < 4096 + 256,
            "retained {} bytes",
            out.stdout.len()
        );
        assert!(
            out.stdout_bytes > 100_000,
            "full total {} counted",
            out.stdout_bytes
        );
        assert!(
            out.kept_lines.iter().any(|l| l.contains("3 passed")),
            "summary kept from the full stream: {:?}",
            out.kept_lines
        );
    }

    #[test]
    fn args_without_shim_exec_argv_directly() {
        let a = Launch::new("/tmp", vec!["sh".into(), "-c".into(), "id".into()])
            .args(Path::new("/tmp"));
        assert_eq!(&a[a.len() - 4..], &["--", "sh", "-c", "id"]);
    }

    #[test]
    fn bounded_capture_keeps_head_and_tail_and_counts_every_byte() {
        // 10 KiB of distinct content, captured within a 1 KiB budget.
        let input: Vec<u8> = (0..10_000u32).map(|i| b'a' + (i % 26) as u8).collect();
        let cap = drain_bounded(&mut std::io::Cursor::new(input.clone()), 1024, None);
        assert!(cap.truncated);
        assert_eq!(
            cap.total, 10_000,
            "full byte total is reported, not the kept size"
        );
        // Retained text stays within budget plus the one marker line.
        assert!(
            cap.text.len() < 1024 + 128,
            "retained {} bytes",
            cap.text.len()
        );
        // The very start and the very end both survive; the middle is gone.
        assert!(
            cap.text
                .starts_with(std::str::from_utf8(&input[..64]).unwrap())
        );
        let tail = std::str::from_utf8(&input[input.len() - 64..]).unwrap();
        assert!(cap.text.ends_with(tail));
        assert!(cap.text.contains("verifier output truncated"));
        assert!(cap.text.contains("10000 bytes"));
    }

    #[test]
    fn bounded_capture_keeps_everything_under_budget() {
        let input = b"short and complete output\n".to_vec();
        let cap = drain_bounded(&mut std::io::Cursor::new(input.clone()), 1 << 20, None);
        assert!(!cap.truncated);
        assert_eq!(cap.total, input.len() as u64);
        assert_eq!(cap.text.as_bytes(), &input[..]);
    }

    #[test]
    fn bounded_capture_keeps_summary_line_dropped_from_the_middle() {
        // A `test result:` line buried in the middle is dropped from the retained
        // head/tail text, yet still captured in full for the summary parser.
        let mut input = vec![b'x'; 4000];
        input.extend_from_slice(b"\ntest result: ok. 7 passed; 2 failed; 0 ignored\n");
        input.extend(std::iter::repeat_n(b'y', 4000));
        let cap = drain_bounded(&mut std::io::Cursor::new(input), 1024, Some("test result:"));
        assert!(cap.truncated);
        assert!(
            !cap.text.contains("test result:"),
            "the summary line is not in the retained window",
        );
        assert_eq!(
            cap.kept_lines,
            vec!["test result: ok. 7 passed; 2 failed; 0 ignored"]
        );
    }

    #[test]
    fn bounded_capture_handles_multibyte_without_panicking() {
        // 2-byte chars across an odd budget: must stay bounded and not panic on a
        // split char boundary (from_utf8_lossy handles the seam).
        let input = "é".repeat(5000).into_bytes();
        let cap = drain_bounded(&mut std::io::Cursor::new(input.clone()), 999, None);
        assert!(cap.truncated);
        assert_eq!(cap.total, input.len() as u64);
        assert!(cap.text.len() < 999 + 128);
    }
}
