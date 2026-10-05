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
//!
//! The launch primitive itself ([`Launch`], [`RunningLaunch`], [`Outcome`],
//! [`StdioMode`], [`available`] and the in-sandbox mount points) lives in
//! [`ward_launch`] so `ward-node` can use it without depending on this crate
//! (ADR-0030 §3); it is re-exported here unchanged. What stays here is what
//! needs the daemon's other dependencies: the policy-typed [`run`] used by
//! selftest and locating the `ward-agent` shim, which probes Landlock.

use std::path::{Path, PathBuf};
use std::process::Command;

use ward_policy::NetworkCapability;

use crate::error::Result;

pub use ward_launch::Error as LaunchError;
pub use ward_launch::{
    AGENT_SHIM, HOOK_SOCKET, Launch, Outcome, PROXY_SOCKET, RELAY_ADDR, RunningLaunch, StdioMode,
    WAIT_POLL, available,
};
pub(crate) use ward_launch::{WORK_ROOT, is_system_ro};

/// Run `argv` inside the sandbox for `worktree` with no egress (used by selftest).
pub fn run(worktree: &Path, _network: &NetworkCapability, argv: &[String]) -> Result<Outcome> {
    Ok(Launch::new(worktree, argv.to_vec()).run()?)
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
