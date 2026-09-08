//! Command line and the hardening sequence the binary runs.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use clap::Parser;
use ward_sandbox::seccomp::Profile;

use crate::error::Result;
use crate::landlock::{self, Outcome, PathSets};
use crate::relay::Relay;
use crate::{privs, relay, seccomp, supervise};

/// Environment variables forwarded to the agent when present.
pub const ENV_PASSTHROUGH: &[&str] = &[
    "PATH",
    "HOME",
    "TERM",
    "LANG",
    "LC_ALL",
    "USER",
    "SHELL",
    "TMPDIR",
    "WARD_SOCKET",
];

/// `PATH` used when the shim's own environment has none.
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Exit code when the shim itself fails before or while supervising the agent.
pub const SHIM_FAILURE: u8 = 125;

/// In-sandbox PID 1: apply Landlock, seccomp and `no_new_privs`, then run the agent.
///
/// `ward-agent hook` reads a Claude Code hook payload on stdin, asks wardd over
/// $WARD_HOOK_SOCKET (default /run/ward/hooks.sock) and prints the decision.
#[derive(Debug, Parser)]
#[command(name = "ward-agent", version, about)]
pub struct Args {
    /// Directory the agent may read, write and execute under (repeatable;
    /// replaces the defaults /work, /env, /tmp and $HOME).
    #[arg(long = "rw", value_name = "DIR")]
    pub rw: Vec<PathBuf>,

    /// Directory the agent may read and execute under (repeatable; replaces
    /// the defaults /usr, /bin, /lib, /lib64, /etc, /proc).
    #[arg(long = "ro", value_name = "DIR")]
    pub ro: Vec<PathBuf>,

    /// Path the agent may read, write and ioctl but not create under
    /// (repeatable; replaces the defaults /dev and $WARD_SOCKET; relay
    /// sockets are always included).
    #[arg(long = "io", value_name = "PATH")]
    pub io: Vec<PathBuf>,

    /// Loopback address to forward into a Unix socket, e.g.
    /// 127.0.0.1:3128=/run/ward/proxy.sock (repeatable; ADR-0014 egress).
    #[arg(long = "relay", value_name = "LISTEN=SOCKET")]
    pub relay: Vec<Relay>,

    /// Exec the agent even if the kernel has no Landlock (outer layers alone must hold).
    #[arg(long)]
    pub allow_no_landlock: bool,

    /// Additional environment variable to forward by name (repeatable).
    #[arg(long = "env", value_name = "NAME")]
    pub env: Vec<String>,

    /// The agent command line, after `--`.
    #[arg(last = true, required = true, value_name = "ARGV")]
    pub argv: Vec<OsString>,
}

impl Args {
    /// The Landlock path sets: defaults unless the corresponding flag was
    /// given, plus every relay socket in the `io` tier.
    pub fn path_sets(&self) -> PathSets {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let socket = std::env::var_os("WARD_SOCKET").map(PathBuf::from);
        let defaults = PathSets::defaults(home.as_deref(), socket.as_deref());
        let pick = |given: &[PathBuf], default: Vec<PathBuf>| {
            if given.is_empty() {
                default
            } else {
                given.to_vec()
            }
        };
        let mut io = pick(&self.io, defaults.io);
        io.extend(self.relay.iter().map(|r| r.socket.clone()));
        PathSets {
            rw: pick(&self.rw, defaults.rw),
            ro: pick(&self.ro, defaults.ro),
            io,
        }
    }

    /// The agent command with a minimal, explicitly forwarded environment.
    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.argv[0]);
        command.args(&self.argv[1..]).env_clear();
        for name in ENV_PASSTHROUGH
            .iter()
            .copied()
            .chain(self.env.iter().map(String::as_str))
        {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        if std::env::var_os("PATH").is_none() {
            command.env("PATH", DEFAULT_PATH);
        }
        command
    }
}

/// Apply the inner hardening in order, then supervise the agent to completion.
pub fn run(args: &Args) -> Result<i32> {
    match landlock::apply(&args.path_sets(), args.allow_no_landlock)? {
        Outcome::Enforced(status) => note(&format!("landlock {status:?}")),
        Outcome::Skipped => note("landlock unavailable, continuing (--allow-no-landlock)"),
    }
    privs::ensure_no_new_privs()?;
    if !privs::drop_capabilities()? {
        note("capability bounding set left as-is (no CAP_SETPCAP)");
    }
    let compiled = seccomp::apply(&Profile::baseline())?;
    note(&format!(
        "seccomp: {} filters installed; not on this ABI: {:?}",
        compiled.programs.len(),
        compiled.unreachable
    ));
    // Relays start only now: the Landlock domain and the seccomp filter are
    // per-thread and inherited by threads created afterwards, so this is what
    // makes the relay as confined as the agent. The supervisor's signal mask
    // is inherited the same way and must already be in place, or a
    // termination signal could be delivered to a relay thread and kill the
    // shim instead of reaching `sigwait`.
    supervise::block_signals()?;
    for relay in &args.relay {
        relay::start(relay)?;
        note(&format!("relay {relay}"));
    }
    supervise::run(&mut args.command())
}

/// Diagnostic on stderr unless `WARD_AGENT_QUIET` is set.
pub(crate) fn note(message: &str) {
    if std::env::var_os("WARD_AGENT_QUIET").is_none() {
        eprintln!("ward-agent: {message}");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn parse(argv: &[&str]) -> Args {
        Args::try_parse_from(std::iter::once("ward-agent").chain(argv.iter().copied())).unwrap()
    }

    #[test]
    fn double_dash_separates_agent_argv() {
        let args = parse(&["--rw", "/x", "--", "sh", "-c", "--rw"]);
        assert_eq!(args.rw, vec![PathBuf::from("/x")]);
        assert_eq!(args.argv, vec!["sh", "-c", "--rw"]);
    }

    #[test]
    fn agent_argv_is_required() {
        assert!(Args::try_parse_from(["ward-agent", "--rw", "/x"]).is_err());
    }

    #[test]
    fn given_sets_replace_defaults_per_tier() {
        let args = parse(&["--rw", "/only", "--", "true"]);
        let sets = args.path_sets();
        assert_eq!(sets.rw, vec![PathBuf::from("/only")]);
        assert_eq!(sets.ro, PathSets::defaults(None, None).ro);
    }

    #[test]
    fn relay_is_repeatable_and_typed() {
        let args = parse(&[
            "--relay",
            "127.0.0.1:3128=/run/ward/proxy.sock",
            "--relay",
            "[::1]:8080=/run/ward/other.sock",
            "--",
            "true",
        ]);
        assert_eq!(args.relay.len(), 2);
        assert_eq!(args.relay[0].listen.port(), 3128);
        assert_eq!(args.relay[1].socket, PathBuf::from("/run/ward/other.sock"));
    }

    #[test]
    fn relay_rejects_non_loopback_and_malformed() {
        for bad in ["0.0.0.0:3128=/s", "192.168.1.1:3128=/s", "3128=/s", "x"] {
            let err = Args::try_parse_from(["ward-agent", "--relay", bad, "--", "true"])
                .expect_err(bad)
                .to_string();
            assert!(err.contains("--relay"), "{bad}: {err}");
        }
    }

    #[test]
    fn relay_sockets_join_the_io_tier() {
        let args = parse(&[
            "--io",
            "/dev/null",
            "--relay",
            "127.0.0.1:1=/x.sock",
            "--",
            "true",
        ]);
        assert_eq!(
            args.path_sets().io,
            vec![PathBuf::from("/dev/null"), PathBuf::from("/x.sock")]
        );
        let defaults = parse(&["--relay", "127.0.0.1:1=/x.sock", "--", "true"]);
        assert!(
            defaults
                .path_sets()
                .io
                .ends_with(&[PathBuf::from("/x.sock")])
        );
    }

    #[test]
    fn command_forwards_only_the_allow_list() {
        let args = parse(&["--env", "WARD_EXTRA", "--", "prog", "a"]);
        let command = args.command();
        assert_eq!(command.get_program(), "prog");
        let names: Vec<_> = command.get_envs().map(|(k, _)| k.to_os_string()).collect();
        assert!(names.iter().all(|n| {
            let n = n.to_str().unwrap();
            ENV_PASSTHROUGH.contains(&n) || n == "WARD_EXTRA"
        }));
        assert!(names.contains(&OsString::from("PATH")));
    }
}
