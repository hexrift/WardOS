//! Terminal rendering for the WardOS observer and status panel.
//!
//! Colour follows `docs/design-language.md`: neutral by default, one accent for
//! the active agent, green for verified, amber for restricted, red for denied.

use std::fmt::Write as _;

use ward_events::{EventRecord, WardEvent};
use ward_policy::{
    AccessMode, CapabilityManifest, ContainerCapability, CredentialRule, NetworkCapability,
    ObserverMode,
};

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[38;5;245m";
const INK: &str = "\x1b[38;5;252m";
const ACCENT: &str = "\x1b[38;5;110m";
const OK: &str = "\x1b[38;5;108m";
const WARN: &str = "\x1b[38;5;179m";
const DENY: &str = "\x1b[38;5;167m";
const BOLD: &str = "\x1b[1m";

/// Render the session status panel (the design-language session view).
#[must_use]
pub fn status_panel(
    session_id: &str,
    project: &str,
    entry_snapshot: &str,
    m: &CapabilityManifest,
) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{BOLD}{ACCENT}WARD{RESET} {INK}session{RESET}  {DIM}{session_id}{RESET}"
    );
    let _ = writeln!(
        s,
        "{DIM}────────────────────────────────────────────{RESET}"
    );
    row(&mut s, "Project", &format!("{INK}{project}{RESET}"));
    row(
        &mut s,
        "Runtime",
        &format!("{INK}isolated (bubblewrap){RESET}"),
    );
    row(&mut s, "Repository", access(m.filesystem.worktree));
    row(&mut s, "Network", &network(&m.network));
    row(&mut s, "Credentials", &credentials(m));
    row(&mut s, "Containers", containers(m.containers));
    row(&mut s, "Observer", observer(m.observer));
    let _ = writeln!(s);
    let _ = writeln!(s, "{DIM}TamperWard{RESET}");
    row(
        &mut s,
        "Policy",
        &format!(
            "{OK}locked{RESET} {DIM}{}{RESET}",
            short_hex(&m.policy_hash.to_hex())
        ),
    );
    row(
        &mut s,
        "Entry state",
        &format!(
            "{OK}frozen{RESET} {DIM}{}{RESET}",
            short_hex(entry_snapshot)
        ),
    );
    row(
        &mut s,
        "Verifier",
        &format!("{DIM}isolated (phase 4){RESET}"),
    );
    s
}

fn row(s: &mut String, label: &str, value: &str) {
    let _ = writeln!(s, "  {INK}{label:<14}{RESET}{value}");
}

fn access(mode: AccessMode) -> &'static str {
    match mode {
        AccessMode::None => "denied",
        AccessMode::ReadOnly => "read",
        AccessMode::ReadWrite => "read & write",
    }
}

fn network(n: &NetworkCapability) -> String {
    match n {
        NetworkCapability::Offline => format!("{OK}offline{RESET}"),
        NetworkCapability::LocalhostOnly => format!("{WARN}localhost only{RESET}"),
        NetworkCapability::Registries => format!("{WARN}package registries{RESET}"),
        NetworkCapability::Development => format!("{WARN}restricted (dev){RESET}"),
        NetworkCapability::Custom(hosts) => {
            format!("{WARN}allowlist ({} hosts){RESET}", hosts.len())
        }
        NetworkCapability::Unrestricted => format!("{DENY}open{RESET}"),
    }
}

fn credentials(m: &CapabilityManifest) -> String {
    let granted = m
        .credentials
        .values()
        .filter(|r| matches!(r, CredentialRule::Allow(_)))
        .count();
    if granted == 0 {
        format!(
            "{OK}none{RESET} {DIM}(brokered, {} services){RESET}",
            m.credentials.len()
        )
    } else {
        format!("{WARN}{granted} granted{RESET}")
    }
}

fn containers(c: ContainerCapability) -> &'static str {
    match c {
        ContainerCapability::None => "denied",
        ContainerCapability::NestedRootless => "nested rootless",
    }
}

fn observer(o: ObserverMode) -> &'static str {
    match o {
        ObserverMode::Quiet => "quiet",
        ObserverMode::Live => "live",
        ObserverMode::StepThrough(_) => "step-through",
    }
}

fn short_hex(s: &str) -> String {
    let body = s.strip_prefix("blake3:").unwrap_or(s);
    body.chars().take(12).collect()
}

/// Render one observer row for a log record. Returns `None` for records with no
/// row in the compact view.
#[must_use]
pub fn observer_row(rec: &EventRecord) -> Option<String> {
    let t = rec.ts_mono.as_secs();
    let ts = format!("{DIM}{:02}:{:02}{RESET}", t / 60, t % 60);
    let (verb, color, subject) = match &rec.event {
        WardEvent::SessionStarted { .. } => ("START", ACCENT, "session".to_string()),
        WardEvent::CommandStarted { argv, .. } => ("RUN", INK, argv_text(argv)),
        WardEvent::CommandFinished { exit, .. } => ("EXIT", exit_color(*exit), exit_text(*exit)),
        WardEvent::FileModified { path, kind, .. } => (change_verb(*kind), INK, path.to_string()),
        WardEvent::FileRead { path, .. } => ("READ", DIM, path.to_string()),
        WardEvent::NetworkRequested { host, port, .. } => ("NET", WARN, format!("{host}:{port}")),
        WardEvent::NetworkDenied { dst, .. } => ("DENY", DENY, denied_dst(dst)),
        WardEvent::SessionEnded { .. } => ("END", DIM, "session".to_string()),
        _ => return None,
    };
    Some(format!(
        "{ts}  {color}{verb:<5}{RESET} {INK}{subject}{RESET}"
    ))
}

fn change_verb(kind: ward_events::FileChangeKind) -> &'static str {
    use ward_events::FileChangeKind as K;
    match kind {
        K::Create => "NEW",
        K::Write => "EDIT",
        K::Delete => "DEL",
        K::Rename => "MOVE",
        K::Chmod => "MODE",
        K::Symlink => "LINK",
    }
}

fn denied_dst(dst: &ward_events::DeniedDst) -> String {
    use ward_events::DeniedDst as D;
    match dst {
        D::Host { host, port } => format!("{host}:{port}"),
        D::Ip { addr, port } => format!("{addr}:{port}"),
        D::Raw { .. } => "raw destination".to_string(),
    }
}

fn argv_text(argv: &ward_events::BoundedArgv) -> String {
    argv.args()
        .iter()
        .map(|a| a.as_str().to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn exit_color(exit: ward_events::ExitStatus) -> &'static str {
    match exit {
        ward_events::ExitStatus::Exited { code: 0 } => OK,
        _ => DENY,
    }
}

fn exit_text(exit: ward_events::ExitStatus) -> String {
    match exit {
        ward_events::ExitStatus::Exited { code: 0 } => "exit 0".into(),
        ward_events::ExitStatus::Exited { code } => format!("exit {code}"),
        ward_events::ExitStatus::Signaled { signal, .. } => format!("signal {signal}"),
    }
}

/// One-line session state for the status panel: `session ACTIVE · started Ns ago`
/// when a session is running, or `no session` otherwise.
#[must_use]
pub fn session_status_line(active: Option<std::time::Duration>) -> String {
    match active {
        Some(ago) => {
            format!(
                "  {OK}session ACTIVE{RESET} {DIM}· started {} ago{RESET}",
                human_ago(ago)
            )
        }
        None => format!("  {DIM}no session{RESET}"),
    }
}

fn human_ago(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

/// Colour a self-test outcome line (`PASS`/`DENIED`).
#[must_use]
pub fn selftest_row(name: &str, blocked: bool) -> String {
    if blocked {
        format!("  {INK}{name:<32}{RESET}{OK}DENIED{RESET}")
    } else {
        format!("  {INK}{name:<32}{RESET}{DENY}REACHED{RESET}")
    }
}
