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
pub mod watch;

pub use error::{Error, Result};
pub use session::{RunReport, Session, SessionMeta};
pub use watch::CaptureMode;

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
        // ST-013: exit 0 only if a namespace trick reads a host-only file. The host's
        // /etc/hostname is never bound into the sandbox, so reaching it means escape.
        (
            "ST-013 namespace-escape",
            "r=1; \
             nsenter -t 1 -m -p -- cat /etc/hostname 2>/dev/null && r=0; \
             unshare -m mount -t proc proc /proc 2>/dev/null; \
             cat /etc/hostname 2>/dev/null && r=0; \
             exit $r",
        ),
        // ST-014: exit 0 only if our pid can be written into a host cgroup. The host
        // cgroupfs is not mounted writable in the sandbox, so both writes must fail.
        (
            "ST-014 cgroup-escape",
            "r=1; \
             echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null && r=0; \
             echo $$ > /sys/fs/cgroup/../cgroup.procs 2>/dev/null && r=0; \
             exit $r",
        ),
        // ST-015: inside /work, a symlink to /root or a ../../.. traversal must not
        // resolve outside the bind mount. exit 0 only if a host file is read through one.
        (
            "ST-015 symlink-boundary-escape",
            "cd /work || exit 1; rm -f evil up; r=1; \
             ln -s /root evil 2>/dev/null && cat evil/.bashrc 2>/dev/null && r=0; \
             ln -s ../../../.. up 2>/dev/null && cat up/etc/passwd 2>/dev/null && r=0; \
             rm -f evil up; exit $r",
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
