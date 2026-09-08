//! `ward-daemon` — the WardOS session supervisor.
//!
//! Phase 1 runs the session lifecycle in-process behind the `ward` CLI: it loads
//! and merges policy into a capability manifest ([`ward_policy`]), freezes an entry
//! snapshot ([`ward_snapshot`]), runs commands in an isolated sandbox
//! ([`sandbox`]), and records everything to the append-only event log
//! ([`ward_events`]). The daemon/control-socket split (ADR-0009) lands in Phase 2;
//! the module boundaries here are drawn so that split is mechanical.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::struct_field_names
)]

pub mod error;
pub mod ids;
pub mod render;
pub mod sandbox;
pub mod session;

pub use error::{Error, Result};
pub use session::{RunReport, Session};

use std::path::Path;
use ward_policy::NetworkCapability;

/// One hostile self-test probe and whether the sandbox blocked it.
pub struct ProbeResult {
    /// Stable probe name (matches the ST-* catalogue in the threat model).
    pub name: &'static str,
    /// True if the sandbox prevented the probe from reaching its target.
    pub blocked: bool,
}

/// Run the Phase 1 isolation probes against a real sandbox over `worktree`.
///
/// Each probe tries a hostile action and is *blocked* when it cannot reach its
/// target — which, by construction, is because the host path or network was never
/// mounted into the sandbox.
pub fn selftest(worktree: &Path) -> Result<Vec<ProbeResult>> {
    // Each probe exits 0 only if it REACHED the resource (a failure of isolation).
    const PROBES: &[(&str, &str)] = &[
        ("ST-001 read-host-home", "cat /root/.ssh/id_ed25519"),
        (
            "ST-002 read-ssh-key",
            "cat \"$HOME/.ssh/\"* 2>/dev/null; ls \"$HOME/.ssh\"",
        ),
        ("ST-003 write-host-file", "touch /usr/bin/wardos_escape"),
        (
            "ST-004 access-docker-socket",
            "test -S /var/run/docker.sock",
        ),
        (
            "ST-011 private-network",
            "timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53'",
        ),
    ];
    let mut out = Vec::with_capacity(PROBES.len());
    for (name, script) in PROBES {
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            (*script).to_string(),
        ];
        let outcome = sandbox::run(worktree, &NetworkCapability::LocalhostOnly, &argv)?;
        out.push(ProbeResult {
            name,
            blocked: outcome.code != Some(0),
        });
    }
    Ok(out)
}
