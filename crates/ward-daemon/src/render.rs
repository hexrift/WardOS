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

use crate::describe::SessionDescription;
use crate::snapshot::DiffReport;

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
        &format!("{DIM}disposable namespace · no network · protected tests from entry{RESET}"),
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

/// Render `ward session describe`: the immutable facts, ids in full so they can be
/// copied into a TamperWard request, then the capability manifest as facts.
#[must_use]
pub fn describe_panel(d: &SessionDescription) -> String {
    let m = &d.manifest;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{BOLD}{ACCENT}WARD{RESET} {INK}session{RESET}  {DIM}{}{RESET}",
        d.session
    );
    let _ = writeln!(
        s,
        "{DIM}────────────────────────────────────────────{RESET}"
    );
    row(&mut s, "Session", &format!("{INK}{}{RESET}", d.session));
    row(&mut s, "Project", &format!("{INK}{}{RESET}", d.project));
    row(
        &mut s,
        "Worktree",
        &format!("{INK}{}{RESET}", d.worktree.display()),
    );
    row(
        &mut s,
        "Started",
        &format!("{INK}{}{RESET}", utc_stamp(d.started_unix_ms)),
    );
    let agent = match &d.agent {
        Some(a) => {
            let image = a.image.as_deref().unwrap_or("no image");
            format!(
                "{INK}{} {}{RESET} {DIM}({}) · {image}{RESET}",
                a.name, a.version, a.kind
            )
        }
        None => format!("{DIM}unknown{RESET}"),
    };
    row(&mut s, "Agent", &agent);
    row(&mut s, "Entry", &format!("{OK}{}{RESET}", d.entry_snapshot));
    row(&mut s, "Policy", &format!("{OK}{}{RESET}", d.policy_hash));
    let _ = writeln!(s);
    let _ = writeln!(s, "{DIM}Capabilities{RESET}");
    row(&mut s, "Filesystem", &filesystem(m));
    row(&mut s, "Network", &network(&m.network));
    row(&mut s, "Containers", containers(m.containers));
    row(&mut s, "Observer", observer(m.observer));
    row(&mut s, "Credentials", &credential_rules(m));
    if !m.tool_images.is_empty() {
        let images: Vec<&str> = m.tool_images.iter().map(|i| i.0.as_str()).collect();
        row(
            &mut s,
            "Tool images",
            &format!("{DIM}{}{RESET}", images.join(" ")),
        );
    }
    s
}

/// `work rw · env rw · home rw · tmp rw` plus any extra mounts.
fn filesystem(m: &CapabilityManifest) -> String {
    let f = &m.filesystem;
    let mut parts = vec![
        format!("work {}", access(f.worktree)),
        format!("env {}", access(f.environment)),
        format!("home {}", access(f.home)),
        format!("tmp {}", access(f.tmp)),
    ];
    parts.extend(
        f.extra
            .iter()
            .map(|(p, mode)| format!("{} {}", p.display(), access(*mode))),
    );
    format!("{INK}{}{RESET}", parts.join(" · "))
}

/// Every credential rule, coloured by decision: `github ask · npm-publish deny`.
fn credential_rules(m: &CapabilityManifest) -> String {
    if m.credentials.is_empty() {
        return format!("{DIM}none{RESET}");
    }
    m.credentials
        .iter()
        .map(|(service, rule)| {
            let (color, word) = match rule {
                CredentialRule::Deny => (OK, "deny"),
                CredentialRule::Ask(_) => (WARN, "ask"),
                CredentialRule::Allow(_) => (WARN, "allow"),
            };
            format!("{INK}{}{RESET} {color}{word}{RESET}", service.0)
        })
        .collect::<Vec<_>>()
        .join(&format!(" {DIM}·{RESET} "))
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix-epoch millisecond count.
#[must_use]
pub fn utc_stamp(unix_ms: u64) -> String {
    let secs = unix_ms / 1000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (hour, minute, second) = (rem / 3600, rem % 3600 / 60, rem % 60);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Render `ward snapshot diff`: one row per path in path order with a fixed verb
/// column (`added` verified-green, `removed` red, `changed` amber), then a count
/// footer.
#[must_use]
pub fn snapshot_diff(d: &DiffReport) -> String {
    let mut rows: Vec<(&str, &str, &str)> = Vec::new();
    rows.extend(d.added.iter().map(|p| ("added", OK, p.as_str())));
    rows.extend(d.removed.iter().map(|p| ("removed", DENY, p.as_str())));
    rows.extend(d.changed.iter().map(|p| ("changed", WARN, p.as_str())));
    rows.sort_by(|a, b| a.2.cmp(b.2));
    let mut s = String::new();
    for (verb, color, path) in rows {
        let _ = writeln!(s, "  {color}{verb:<8}{RESET} {INK}{path}{RESET}");
    }
    if d.is_empty() {
        let _ = writeln!(s, "  {DIM}identical{RESET}");
    } else {
        let _ = writeln!(
            s,
            "  {DIM}{} changed · {} added · {} removed{RESET}",
            d.changed.len(),
            d.added.len(),
            d.removed.len()
        );
    }
    s
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
        WardEvent::CredentialGranted { service, scope, .. } => (
            "CRED",
            ACCENT,
            format!("{service} → {} (proxy-injected)", scope.subject.as_str()),
        ),
        WardEvent::AgentClaim { kind, payload } => (claim_verb(*kind), DIM, payload.to_string()),
        WardEvent::SnapshotCreated { role, id, .. } => (
            "SNAP",
            ACCENT,
            format!("{} {}", snapshot_role(*role), short_hex(&id.to_string())),
        ),
        WardEvent::VerificationRequested { candidate, .. } => (
            "VERIFY",
            ACCENT,
            format!("candidate {}", short_hex(&candidate.to_string())),
        ),
        WardEvent::VerificationStarted {
            candidate,
            pristine,
            ..
        } => (
            "VERIFY",
            ACCENT,
            format!(
                "trusted verifier started · pristine {} · candidate {}",
                short_hex(&pristine.to_string()),
                short_hex(&candidate.to_string())
            ),
        ),
        WardEvent::VerificationProgress { step, status } => {
            ("STEP", step_color(*status), step.to_string())
        }
        WardEvent::VerificationPassed {
            candidate, summary, ..
        } => (
            "PASS",
            OK,
            format!(
                "✓ VERIFIED · {} tests · candidate {}",
                summary.tests_run,
                short_hex(&candidate.to_string())
            ),
        ),
        WardEvent::VerificationFailed {
            candidate, summary, ..
        } => (
            "FAIL",
            DENY,
            format!(
                "verification failed · {}/{} tests failed · candidate {}",
                summary.tests_failed,
                summary.tests_run,
                short_hex(&candidate.to_string())
            ),
        ),
        WardEvent::SessionEnded { .. } => ("END", DIM, "session".to_string()),
        _ => return None,
    };
    Some(format!(
        "{ts}  {color}{verb:<5}{RESET} {INK}{subject}{RESET}"
    ))
}

fn snapshot_role(role: ward_events::SnapshotRole) -> &'static str {
    use ward_events::SnapshotRole as R;
    match role {
        R::Entry => "entry",
        R::Candidate => "candidate",
        R::Accepted => "accepted",
        R::Final => "final",
    }
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

/// The `ward verify` summary block: what was restored, the verdict, and on failure
/// the tail of the verifier's output.
#[must_use]
pub fn verify_report(r: &crate::session::VerifyReport) -> String {
    let mut s = format!(
        "{ACCENT}WARD{RESET} {INK}verify{RESET}  {DIM}candidate {}{RESET}\n",
        short_hex(&r.candidate)
    );
    for rel in &r.restored {
        let _ = writeln!(
            s,
            "  {WARN}restored{RESET} {INK}{rel}{RESET} {DIM}(pristine copy; worktree edit ignored){RESET}"
        );
    }
    if r.passed {
        let _ = writeln!(
            s,
            "  {OK}✓ VERIFIED{RESET} {DIM}· {} tests · {:.1}s{RESET}",
            r.summary.tests_run,
            r.summary.duration.as_secs_f64()
        );
    } else {
        let _ = writeln!(
            s,
            "  {DENY}✗ VERIFICATION FAILED{RESET} {DIM}· {}/{} tests failed · {:.1}s{RESET}",
            r.summary.tests_failed,
            r.summary.tests_run,
            r.summary.duration.as_secs_f64()
        );
        let tail: Vec<&str> = r.output.lines().rev().take(12).collect();
        for line in tail.iter().rev() {
            let _ = writeln!(s, "    {DIM}{line}{RESET}");
        }
    }
    s
}

fn step_color(status: ward_events::StepStatus) -> &'static str {
    match status {
        ward_events::StepStatus::Running => DIM,
        ward_events::StepStatus::Pass => OK,
        ward_events::StepStatus::Fail => DENY,
    }
}

fn claim_verb(kind: ward_events::ClaimKind) -> &'static str {
    use ward_events::ClaimKind as K;
    match kind {
        K::ToolUse => "TOOL",
        K::Note | K::Plan => "NOTE",
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
        format!("  {INK}{name:<36}{RESET}{OK}DENIED{RESET}")
    } else {
        format!("  {INK}{name:<36}{RESET}{DENY}REACHED{RESET}")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn plain(s: &str) -> String {
        // Strip SGR sequences so assertions see the text.
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn diff_rows_are_in_path_order_with_verb_column_and_counts() {
        let d = DiffReport {
            added: vec!["z.txt".into()],
            removed: vec!["a.txt".into()],
            changed: vec!["m/lib.rs".into()],
        };
        let out = snapshot_diff(&d);
        assert!(out.contains(OK), "added is verified-green");
        assert!(out.contains(DENY), "removed is red");
        assert!(out.contains(WARN), "changed is amber");
        let lines: Vec<String> = plain(&out).lines().map(str::to_owned).collect();
        assert_eq!(
            lines,
            vec![
                "  removed  a.txt",
                "  changed  m/lib.rs",
                "  added    z.txt",
                "  1 changed · 1 added · 1 removed",
            ]
        );
        assert_eq!(
            plain(&snapshot_diff(&DiffReport::default())),
            "  identical\n"
        );
    }

    #[test]
    fn utc_stamp_is_iso_8601() {
        assert_eq!(utc_stamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_stamp(1_700_000_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(utc_stamp(951_782_400_000), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn describe_panel_carries_full_ids_and_every_capability_row() {
        let manifest = ward_policy::merge(
            &ward_policy::Policy::default(),
            &ward_policy::Policy::default(),
            &ward_policy::Policy::default(),
            ward_policy::SessionId("sess_panel".to_owned()),
            ward_policy::ProjectId("proj_panel".to_owned()),
        );
        let d = SessionDescription {
            session: "sess_panel".to_owned(),
            project: "proj_panel".to_owned(),
            worktree: "/tmp/demo".into(),
            started_unix_ms: 1_700_000_000_000,
            agent: None,
            entry_snapshot: format!("blake3:{}", "ab".repeat(32)),
            policy_hash: manifest.policy_hash.to_hex(),
            manifest,
        };
        let out = plain(&describe_panel(&d));
        assert!(out.contains(&format!("Entry         blake3:{}", "ab".repeat(32))));
        assert!(out.contains(&format!("Policy        {}", d.policy_hash)));
        assert!(out.contains("Started       2023-11-14T22:13:20Z"));
        assert!(out.contains("Agent         unknown"));
        for label in [
            "Filesystem",
            "Network",
            "Containers",
            "Observer",
            "Credentials",
        ] {
            assert!(out.contains(label), "{label} row missing:\n{out}");
        }
        assert!(out.contains("work read & write"));
        assert!(out.contains("github ask"));
    }
}
