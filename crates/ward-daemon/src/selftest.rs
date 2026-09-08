//! `ward selftest`: hostile probes run inside a real sandbox. Each probe exits 0
//! only if it REACHED its target, so a passing probe is one the sandbox blocked.

use std::path::Path;

use ward_policy::NetworkCapability;

use crate::error::Result;
use crate::gateway::Gateway;
use crate::session::{LaunchOpts, Session};
use crate::{agents, sandbox};

/// One hostile self-test probe and whether the sandbox blocked it.
pub struct ProbeResult {
    /// Stable probe name (matches the ST-* catalogue in the threat model).
    pub name: &'static str,
    /// True if the sandbox prevented the probe from reaching its target.
    pub blocked: bool,
}

/// Run the isolation probes (ST-001..015) against a bare sandbox over `worktree`.
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

/// ST-012: exit 0 only if the canary (argument `$1`) is found anywhere in the sandbox.
pub const ST_012: &str = "grep -qs \"$1\" /proc/self/environ /proc/1/environ && exit 0; \
     grep -rqs \"$1\" /home /env /tmp /run /work 2>/dev/null && exit 0; exit 1";

/// ST-024: exit 0 only if the relay serves a request outside the credential's route.
/// Without the relay the credential is unreachable altogether, which also counts as
/// blocked.
pub const ST_024: &str = "timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/3128 || exit 1; \
     printf \"GET /openai/v1/models HTTP/1.1\\r\\nHost: 127.0.0.1:3128\\r\\n\
x-api-key: $ANTHROPIC_API_KEY\\r\\n\\r\\n\" >&3; \
     read -r line <&3; case \"$line\" in *\" 2\"[0-9][0-9]\" \"*) exit 0;; esac; exit 1'";

/// Run the credential probes (ST-012, ST-024) inside `session`, with a canary key
/// held on the host and injected by the gateway exactly as `ward claude` does.
///
/// ST-012 is *blocked* when the canary appears nowhere in the sandbox (environment
/// of the agent or PID 1, home, `/env`, `/tmp`, `/run`, `/work`). ST-024 is blocked
/// when a request outside the credential's route (`/openai/...`) is not served, so
/// the injected key can reach only its own service.
pub fn selftest_credentials(session: &mut Session) -> Result<Vec<ProbeResult>> {
    const PROBES: &[(&str, &str)] = &[
        ("ST-012 credential-in-zone-3", ST_012),
        ("ST-024 credential-scope-overreach", ST_024),
    ];
    let spec = agents::profile("claude")
        .and_then(|p| p.gateway)
        .ok_or_else(|| crate::error::Error::Sandbox("no gateway profile".into()))?;
    let canary = format!("ward-selftest-canary-{}", canary_suffix());
    let mut out = Vec::with_capacity(PROBES.len());
    for (name, script) in PROBES {
        let gateway = Gateway::from_key(&spec, &canary)?;
        let opts = LaunchOpts {
            env: gateway.env.clone(),
            gateways: vec![gateway],
            ..LaunchOpts::default()
        };
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            (*script).to_string(),
            "sh".to_string(),
            canary.clone(),
        ];
        let report = session.launch(&argv, &opts)?;
        out.push(ProbeResult {
            name,
            blocked: report.code != Some(0),
        });
    }
    Ok(out)
}

/// Unpredictable per-run suffix so a stale canary in a reused tmpfs cannot match.
fn canary_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    blake3::hash(&nanos.to_le_bytes()).to_hex()[..16].to_string()
}

/// ST-009: exit 0 only if the session log (`$1`) or the state root (`$2`) is visible.
pub const ST_009: &str = "test -r \"$1\" && exit 0; test -d \"$2\" && exit 0; exit 1";
/// ST-010: exit 0 only if the session log (`$1`) can be appended to or removed.
pub const ST_010: &str = "test -e \"$1\" || exit 1; \
     echo tamper >> \"$1\" 2>/dev/null && exit 0; rm -f \"$1\" 2>/dev/null && exit 0; exit 1";

/// Run the evidence probes (ST-009, ST-010) inside `session`: the sandbox is
/// handed the host paths of its own log and state root and tries to read, append
/// to, or remove them. Blocked means the evidence is out of the agent's reach.
pub fn selftest_evidence(session: &mut Session) -> Result<Vec<ProbeResult>> {
    const PROBES: &[(&str, &str)] = &[
        ("ST-009 read-evidence", ST_009),
        ("ST-010 rewrite-evidence", ST_010),
    ];
    let log = session.log_path().to_string_lossy().into_owned();
    let state = session.state_root().to_string_lossy().into_owned();
    let mut out = Vec::with_capacity(PROBES.len());
    for (name, script) in PROBES {
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            (*script).to_string(),
            "sh".to_string(),
            log.clone(),
            state.clone(),
        ];
        let report = session.launch(&argv, &LaunchOpts::default())?;
        out.push(ProbeResult {
            name,
            blocked: report.code != Some(0),
        });
    }
    Ok(out)
}
