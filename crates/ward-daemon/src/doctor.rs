//! `ward doctor`: what this host can and cannot give a session. Each check is
//! a fact with a fix, so a new machine is set up from the output alone.

use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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

/// The oldest Node the shipped agents run on: the highest `engines` floor of
/// `image/agents/package.json` (Claude Code wants 22; the image build checks the same).
pub const NODE_FLOOR: u64 = 22;

/// How long a version probe may take before it is killed and counted as absent: a
/// wedged agent must not hang the report.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Where a key can be found on the host, never its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// The host environment.
    Environment,
    /// `$WARD_STATE_DIR/vault/<NAME>` (`ward vault set`).
    Vault,
}

/// The agents the image ships (ADR-0017) and the npm package each comes from.
const AGENTS: &[(&str, &str)] = &[
    ("claude", "@anthropic-ai/claude-code"),
    ("codex", "@openai/codex"),
    ("tamperward", "tamperward"),
];

/// The keys the gateways inject (`agents.rs`); presence only is reported.
const KEYS: &[&str] = &["ANTHROPIC_API_KEY", "OPENAI_API_KEY"];

/// Default zones that admit nothing inbound.
const CLOSED_ZONES: &[&str] = &["wardos", "drop", "block"];

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
        node(probe("node", &["--version"]).as_deref()),
        agents(&agent_versions()),
        keys(&key_sources(&state), &state),
        firewall(firewalld_active(), firewalld_zone().as_deref()),
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

/// `program args…` with stdin closed, killed after [`PROBE_TIMEOUT`]: its stdout on
/// exit 0, `None` when absent, failing or too slow. Stdout is drained on a thread so
/// a chatty program cannot block on a full pipe and be mistaken for a hung one.
fn probe(program: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        s
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() < PROBE_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let out = reader.join().unwrap_or_default();
    status
        .filter(std::process::ExitStatus::success)
        .map(|_| out)
}

/// The first token of `text` that looks like a version (`2.1.263 (Claude Code)`,
/// `codex-cli 0.153.4`, `v22.22.2`), without a leading `v`.
#[must_use]
pub fn version_in(text: &str) -> Option<&str> {
    text.split_whitespace()
        .map(|t| t.strip_prefix('v').unwrap_or(t))
        .find(|t| t.starts_with(|c: char| c.is_ascii_digit()) && t.contains('.'))
}

/// The first `name` on `PATH`.
fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|p| p.is_file())
    })
}

/// The `version` of the npm package `package` an installed `command` belongs to: the
/// first `package.json` above the command's real path whose `name` is the package.
/// For a CLI that has no `--version` (TamperWard) and as a fallback for the rest.
fn package_version(command: &str, package: &str) -> Option<String> {
    package_version_at(&which(command)?, package)
}

/// [`package_version`] for a command at `path` (a `/usr/bin` symlink, usually).
fn package_version_at(path: &Path, package: &str) -> Option<String> {
    let real = std::fs::canonicalize(path).ok()?;
    real.ancestors()
        .filter_map(|dir| std::fs::read_to_string(dir.join("package.json")).ok())
        .filter_map(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .find(|v| v["name"].as_str() == Some(package))
        .and_then(|v| v["version"].as_str().map(str::to_owned))
}

/// Each shipped agent with its version, or `None` when it is not on `PATH`.
fn agent_versions() -> Vec<(&'static str, Option<String>)> {
    AGENTS
        .iter()
        .map(|(command, package)| {
            let version = probe(command, &["--version"])
                .and_then(|out| version_in(&out).map(str::to_owned))
                .or_else(|| package_version(command, package))
                .or_else(|| probe(command, &["--help"]).map(|_| "present".to_owned()));
            (*command, version)
        })
        .collect()
}

/// Where each key of [`KEYS`] is, looking where the gateways look (`gateway.rs`):
/// the environment, then `<state>/vault/<NAME>`. Values are never read into the
/// report.
fn key_sources(state: &Path) -> Vec<(&'static str, Option<KeySource>)> {
    KEYS.iter()
        .map(|name| {
            let in_env = std::env::var(name).is_ok_and(|v| !v.trim().is_empty());
            let in_vault = std::fs::read_to_string(state.join("vault").join(name))
                .is_ok_and(|v| !v.trim().is_empty());
            let source = if in_env {
                Some(KeySource::Environment)
            } else if in_vault {
                Some(KeySource::Vault)
            } else {
                None
            };
            (*name, source)
        })
        .collect()
}

/// `None` when firewalld is not installed, else whether it is running.
fn firewalld_active() -> Option<bool> {
    let installed = which("firewall-cmd").is_some()
        || Path::new("/usr/lib/systemd/system/firewalld.service").exists();
    installed.then(|| {
        probe("systemctl", &["is-active", "firewalld.service"])
            .is_some_and(|out| out.trim() == "active")
            || probe("firewall-cmd", &["--state"]).is_some()
    })
}

/// The default zone, from `firewall-cmd` (which may need polkit) or the
/// configuration file it reads.
fn firewalld_zone() -> Option<String> {
    probe("firewall-cmd", &["--get-default-zone"])
        .map(|z| z.trim().to_owned())
        .filter(|z| !z.is_empty())
        .or_else(|| read("/etc/firewalld/firewalld.conf").and_then(|c| default_zone_in(&c)))
}

/// `DefaultZone=` in `firewalld.conf`.
#[must_use]
pub fn default_zone_in(conf: &str) -> Option<String> {
    conf.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("DefaultZone="))
        .map(|z| z.trim().to_owned())
        .filter(|z| !z.is_empty())
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

/// Node against [`NODE_FLOOR`], from `node --version` output (`None`: not on `PATH`).
#[must_use]
pub fn node(version: Option<&str>) -> Check {
    let ships = "ships in the WardOS image; elsewhere install nodejs (Fedora: nodejs24)";
    match version.and_then(version_in) {
        Some(v) => match v.split('.').next().and_then(|m| m.parse::<u64>().ok()) {
            Some(major) if major >= NODE_FLOOR => Check::new(
                "node",
                Status::Ok,
                format!("{v} (the agents need {NODE_FLOOR}+)"),
            ),
            _ => Check::new(
                "node",
                Status::Warn,
                format!(
                    "{v} is older than the {NODE_FLOOR} the agents need; Node {NODE_FLOOR}+ {ships} {NODE_FLOOR}+"
                ),
            ),
        },
        None => Check::new(
            "node",
            Status::Warn,
            format!("node not found; the agents need Node {NODE_FLOOR}+, which {ships}"),
        ),
    }
}

/// The shipped agents (`claude`, `codex`, `tamperward`) with their versions; `Warn`
/// names the missing ones and the package each comes from.
#[must_use]
pub fn agents(found: &[(&str, Option<String>)]) -> Check {
    let present: Vec<String> = found
        .iter()
        .filter_map(|(name, v)| v.as_ref().map(|v| format!("{name} {v}")))
        .collect();
    let missing: Vec<&str> = found
        .iter()
        .filter(|(_, v)| v.is_none())
        .map(|(name, _)| *name)
        .collect();
    if missing.is_empty() {
        return Check::new("agents", Status::Ok, present.join(" · "));
    }
    let packages: Vec<&str> = AGENTS
        .iter()
        .filter(|(command, _)| missing.contains(command))
        .map(|(_, package)| *package)
        .collect();
    let mut detail = String::new();
    if !present.is_empty() {
        detail.push_str(&present.join(" · "));
        detail.push_str(" · ");
    }
    let _ = write!(
        detail,
        "{} not found; ships in the WardOS image; elsewhere `npm install -g {}`",
        missing.join(", "),
        packages.join(" ")
    );
    Check::new("agents", Status::Warn, detail)
}

/// Whether the model-API keys are on the host, and where; never their values.
#[must_use]
pub fn keys(found: &[(&str, Option<KeySource>)], state: &Path) -> Check {
    let detail: Vec<String> = found
        .iter()
        .map(|(name, source)| match source {
            Some(KeySource::Environment) => format!("{name} (environment)"),
            Some(KeySource::Vault) => format!("{name} (vault)"),
            None => format!("{name} not set"),
        })
        .collect();
    if found.iter().any(|(_, s)| s.is_some()) {
        Check::new("keys", Status::Ok, detail.join(" · "))
    } else {
        let names: Vec<&str> = found.iter().map(|(n, _)| *n).collect();
        let first = names.first().copied().unwrap_or("ANTHROPIC_API_KEY");
        Check::new(
            "keys",
            Status::Warn,
            format!(
                "no {} in the environment or in {}; `ward vault set {first}` (the proxy injects it, the sandbox never sees it)",
                names.join(" or "),
                state.join("vault").display()
            ),
        )
    }
}

/// firewalld: `active` is `None` when it is not installed; `zone` its default zone.
#[must_use]
pub fn firewall(active: Option<bool>, zone: Option<&str>) -> Check {
    let enable =
        "`sudo systemctl enable --now firewalld && sudo firewall-cmd --set-default-zone=drop`";
    match (active, zone) {
        (None, _) => Check::new(
            "firewall",
            Status::Warn,
            format!(
                "no firewalld; the WardOS image ships it enabled with nothing inbound; elsewhere {enable}"
            ),
        ),
        (Some(false), _) => Check::new(
            "firewall",
            Status::Warn,
            format!("firewalld installed but not running; {enable}"),
        ),
        (Some(true), Some(z)) if CLOSED_ZONES.contains(&z) => Check::new(
            "firewall",
            Status::Ok,
            format!("firewalld active, default zone {z} (nothing inbound)"),
        ),
        (Some(true), Some(z)) => Check::new(
            "firewall",
            Status::Warn,
            format!(
                "firewalld active, default zone {z} admits inbound services; `sudo firewall-cmd --set-default-zone=drop`"
            ),
        ),
        (Some(true), None) => Check::new(
            "firewall",
            Status::Warn,
            "firewalld active, default zone unknown (firewall-cmd --get-default-zone failed and /etc/firewalld/firewalld.conf has no DefaultZone)",
        ),
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
    fn version_is_the_first_dotted_number_in_the_output() {
        assert_eq!(version_in("2.1.263 (Claude Code)\n"), Some("2.1.263"));
        assert_eq!(version_in("codex-cli 0.153.4"), Some("0.153.4"));
        assert_eq!(version_in("v22.22.2\n"), Some("22.22.2"));
        assert_eq!(version_in("usage: tamperward <command>"), None);
        assert_eq!(version_in(""), None);
    }

    #[test]
    fn node_is_checked_against_the_agents_floor() {
        let c = node(Some("v22.22.2\n"));
        assert_eq!(c.status, Status::Ok);
        assert!(c.detail.starts_with("22.22.2"));
        assert_eq!(node(Some("v24.1.0")).status, Status::Ok);
        let c = node(Some("v20.19.0"));
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("20.19.0"), "{}", c.detail);
        assert!(c.detail.contains("22"), "{}", c.detail);
        let c = node(None);
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("node not found"));
        assert!(c.detail.contains("WardOS image"));
    }

    #[test]
    fn agents_lists_versions_and_names_what_is_missing_with_its_package() {
        let all = [
            ("claude", Some("2.1.263".to_owned())),
            ("codex", Some("0.153.4".to_owned())),
            ("tamperward", Some("2.10.3".to_owned())),
        ];
        let c = agents(&all);
        assert_eq!(c.status, Status::Ok);
        assert_eq!(
            c.detail,
            "claude 2.1.263 · codex 0.153.4 · tamperward 2.10.3"
        );

        let some = [
            ("claude", Some("2.1.263".to_owned())),
            ("codex", None),
            ("tamperward", None),
        ];
        let c = agents(&some);
        assert_eq!(c.status, Status::Warn);
        assert!(
            c.detail
                .starts_with("claude 2.1.263 · codex, tamperward not found"),
            "{}",
            c.detail
        );
        assert!(c.detail.contains("ships in the WardOS image"));
        assert!(
            c.detail
                .contains("`npm install -g @openai/codex tamperward`"),
            "{}",
            c.detail
        );

        let none = [("claude", None), ("codex", None), ("tamperward", None)];
        let c = agents(&none);
        assert_eq!(c.status, Status::Warn);
        assert!(
            c.detail.starts_with("claude, codex, tamperward not found"),
            "{}",
            c.detail
        );
        assert!(
            c.detail
                .contains("@anthropic-ai/claude-code @openai/codex tamperward")
        );
    }

    #[test]
    fn keys_reports_where_a_key_is_and_never_its_value() {
        let state = Path::new("/tmp/w");
        let c = keys(
            &[
                ("ANTHROPIC_API_KEY", Some(KeySource::Vault)),
                ("OPENAI_API_KEY", None),
            ],
            state,
        );
        assert_eq!(c.status, Status::Ok);
        assert_eq!(
            c.detail,
            "ANTHROPIC_API_KEY (vault) · OPENAI_API_KEY not set"
        );
        let c = keys(
            &[
                ("ANTHROPIC_API_KEY", Some(KeySource::Environment)),
                ("OPENAI_API_KEY", Some(KeySource::Vault)),
            ],
            state,
        );
        assert_eq!(c.status, Status::Ok);
        assert_eq!(
            c.detail,
            "ANTHROPIC_API_KEY (environment) · OPENAI_API_KEY (vault)"
        );
        let c = keys(
            &[("ANTHROPIC_API_KEY", None), ("OPENAI_API_KEY", None)],
            state,
        );
        assert_eq!(c.status, Status::Warn);
        assert!(
            c.detail.contains("`ward vault set ANTHROPIC_API_KEY`"),
            "{}",
            c.detail
        );
        assert!(c.detail.contains("/tmp/w/vault"), "{}", c.detail);
    }

    #[test]
    fn key_sources_look_at_the_environment_then_the_vault_without_reading_values_into_the_report() {
        let state = tempfile::tempdir().unwrap();
        let vault = state.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        std::fs::write(vault.join("OPENAI_API_KEY"), "sk-secret-value\n").unwrap();
        std::fs::write(vault.join("ANTHROPIC_API_KEY"), "  \n").unwrap();
        // The test process's own environment is not touched: only the vault is asked
        // for the key that is not in the environment; an empty vault file is no key.
        let found = key_sources(state.path());
        let openai = found.iter().find(|(n, _)| *n == "OPENAI_API_KEY").unwrap();
        let expected = if std::env::var("OPENAI_API_KEY").is_ok_and(|v| !v.trim().is_empty()) {
            KeySource::Environment
        } else {
            KeySource::Vault
        };
        assert_eq!(openai.1, Some(expected));
        let anthropic = found
            .iter()
            .find(|(n, _)| *n == "ANTHROPIC_API_KEY")
            .unwrap();
        if std::env::var("ANTHROPIC_API_KEY").is_err() {
            assert_eq!(anthropic.1, None);
        }
        let c = keys(&found, state.path());
        assert!(!c.detail.contains("sk-secret-value"));
    }

    #[test]
    fn firewall_wants_firewalld_running_with_a_closed_default_zone() {
        let c = firewall(Some(true), Some("wardos"));
        assert_eq!(c.status, Status::Ok);
        assert!(c.detail.contains("wardos"));
        assert_eq!(firewall(Some(true), Some("drop")).status, Status::Ok);
        let c = firewall(Some(true), Some("public"));
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("public"));
        assert!(c.detail.contains("--set-default-zone=drop"));
        assert_eq!(firewall(Some(true), None).status, Status::Warn);
        let c = firewall(Some(false), Some("wardos"));
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("systemctl enable --now firewalld"));
        let c = firewall(None, None);
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("no firewalld"));
        assert!(c.detail.contains("WardOS image"));
    }

    #[test]
    fn default_zone_is_read_from_the_configuration_file() {
        assert_eq!(
            default_zone_in("# firewalld config\nDefaultZone=wardos\nCleanupOnExit=yes\n")
                .as_deref(),
            Some("wardos")
        );
        assert_eq!(default_zone_in("DefaultZone=\n"), None);
        assert_eq!(default_zone_in("# DefaultZone=public\n"), None);
    }

    #[test]
    fn a_probe_that_hangs_is_killed_and_counted_absent() {
        assert!(probe("ward-doctor-no-such-command", &["--version"]).is_none());
        assert!(probe("false", &[]).is_none());
        assert_eq!(probe("echo", &["v1.2.3"]).as_deref(), Some("v1.2.3\n"));
    }

    #[test]
    fn package_version_walks_up_to_the_package_json_of_the_command() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("node_modules/tamperward");
        std::fs::create_dir_all(pkg.join("dist/cli")).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            r#"{"name":"tamperward","version":"2.10.3"}"#,
        )
        .unwrap();
        std::fs::write(pkg.join("dist/cli/index.js"), "").unwrap();
        // Through a /usr/bin-style symlink, the way the image links the commands.
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let link = bin.join("tamperward");
        std::os::unix::fs::symlink(pkg.join("dist/cli/index.js"), &link).unwrap();
        assert_eq!(
            package_version_at(&link, "tamperward").as_deref(),
            Some("2.10.3")
        );
        assert_eq!(package_version_at(&link, "@openai/codex"), None);
        assert_eq!(
            package_version_at(&dir.path().join("missing"), "tamperward"),
            None
        );
        assert!(package_version("ward-doctor-no-such-command", "x").is_none());
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
            "node",
            "agents",
            "keys",
            "firewall",
        ] {
            assert_eq!(names.iter().filter(|x| **x == n).count(), 1, "{n}");
        }
        let _ = healthy(&checks);
    }
}
