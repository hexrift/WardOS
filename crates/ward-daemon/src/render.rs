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
use crate::selftest::Verdict;
use crate::snapshot::DiffReport;

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[38;5;245m";
const INK: &str = "\x1b[38;5;252m";
const ACCENT: &str = "\x1b[38;5;110m";
const OK: &str = "\x1b[38;5;108m";
const WARN: &str = "\x1b[38;5;179m";
const DENY: &str = "\x1b[38;5;167m";
const BOLD: &str = "\x1b[1m";

/// The colour roles of `docs/design-language.md` §3, as the observer uses them.
/// Every renderer (line mode, the TUI) maps a role to its own colour space, so a
/// verb is the same colour everywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tone {
    /// Muted text: timestamps, hidden kinds, reads, ended.
    Dim,
    /// Primary text.
    Ink,
    /// The active agent: session start, credentials, snapshots, verification.
    Accent,
    /// Verified: passes, accepts, exit 0, offline network.
    Ok,
    /// Restricted: network requests, `ask`, limited network.
    Warn,
    /// Denied or failed; used sparingly.
    Deny,
}

impl Tone {
    /// The 256-colour SGR sequence line mode prints for this role.
    #[must_use]
    pub const fn sgr(self) -> &'static str {
        match self {
            Self::Dim => DIM,
            Self::Ink => INK,
            Self::Accent => ACCENT,
            Self::Ok => OK,
            Self::Warn => WARN,
            Self::Deny => DENY,
        }
    }

    /// The xterm-256 palette index behind [`Tone::sgr`], for renderers that set
    /// colours by index rather than by escape sequence.
    #[must_use]
    pub const fn palette_index(self) -> u8 {
        match self {
            Self::Dim => 245,
            Self::Ink => 252,
            Self::Accent => 110,
            Self::Ok => 108,
            Self::Warn => 179,
            Self::Deny => 167,
        }
    }
}

/// The colour role of a network mode in the trust state: `offline` is verified
/// green, every limited mode is restricted amber, `open` is red; the same rule
/// the status panel's `Network` row follows.
#[must_use]
pub const fn network_tone(n: &NetworkCapability) -> Tone {
    match n {
        NetworkCapability::Offline => Tone::Ok,
        NetworkCapability::LocalhostOnly
        | NetworkCapability::Registries
        | NetworkCapability::Development
        | NetworkCapability::Custom(_) => Tone::Warn,
        NetworkCapability::Unrestricted => Tone::Deny,
    }
}

/// The network mode as the panels name it, uncoloured.
#[must_use]
pub fn network_text(n: &NetworkCapability) -> String {
    match n {
        NetworkCapability::Offline => "offline".to_owned(),
        NetworkCapability::LocalhostOnly => "localhost only".to_owned(),
        NetworkCapability::Registries => "package registries".to_owned(),
        NetworkCapability::Development => "restricted (dev)".to_owned(),
        NetworkCapability::Custom(hosts) => format!("allowlist ({} hosts)", hosts.len()),
        NetworkCapability::Unrestricted => "open".to_owned(),
    }
}

/// The observer mode as the panels name it.
#[must_use]
pub const fn observer_text(o: ObserverMode) -> &'static str {
    match o {
        ObserverMode::Quiet => "quiet",
        ObserverMode::Live => "live",
        ObserverMode::StepThrough(_) => "step-through",
    }
}

/// How many credential rules grant outright.
#[must_use]
pub fn credentials_granted(m: &CapabilityManifest) -> usize {
    m.credentials
        .values()
        .filter(|r| matches!(r, CredentialRule::Allow(_)))
        .count()
}

/// One observer row before it is coloured: the columns of the agent activity
/// panel (`docs/design-language.md` §8), so the TUI and line mode agree on
/// text and colour by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObserverCells {
    /// `MM:SS` since session genesis.
    pub time: String,
    /// The fixed verb column (`READ EDIT RUN DENY NET …`).
    pub verb: &'static str,
    /// The verb's colour role.
    pub tone: Tone,
    /// The subject: a path, a command, a host, a summary.
    pub subject: String,
}

impl ObserverCells {
    /// The line-mode rendering: dim time, coloured verb padded to the column,
    /// subject in ink.
    #[must_use]
    pub fn to_ansi(&self) -> String {
        let color = self.tone.sgr();
        format!(
            "{DIM}{}{RESET}  {color}{:<5}{RESET} {INK}{}{RESET}",
            self.time, self.verb, self.subject
        )
    }
}

/// `MM:SS` since session genesis.
fn mono_time(rec: &EventRecord) -> String {
    let t = rec.ts_mono.as_secs();
    format!("{:02}:{:02}", t / 60, t % 60)
}

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
    format!("{}{}{RESET}", network_tone(n).sgr(), network_text(n))
}

fn credentials(m: &CapabilityManifest) -> String {
    let granted = credentials_granted(m);
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
    observer_text(o)
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
    observer_cells(rec).map(|cells| cells.to_ansi())
}

/// The columns of one observer row for a log record, uncoloured. Returns `None`
/// for records with no row in the compact view.
#[must_use]
pub fn observer_cells(rec: &EventRecord) -> Option<ObserverCells> {
    let (verb, tone, subject) = match &rec.event {
        WardEvent::SessionStarted { .. } => ("START", Tone::Accent, "session".to_string()),
        WardEvent::CommandStarted { argv, .. } => ("RUN", Tone::Ink, argv_text(argv)),
        WardEvent::CommandFinished { exit, .. } => ("EXIT", exit_color(*exit), exit_text(*exit)),
        WardEvent::FileModified { path, kind, .. } => {
            (change_verb(*kind), Tone::Ink, path.to_string())
        }
        WardEvent::FileRead { path, .. } => ("READ", Tone::Dim, path.to_string()),
        ev @ WardEvent::NetworkRequested { .. } => net_requested_cells(ev),
        WardEvent::NetworkDenied { dst, .. } => ("DENY", Tone::Deny, denied_dst(dst)),
        WardEvent::CredentialGranted { service, scope, .. } => (
            "CRED",
            Tone::Accent,
            format!("{service} → {} (proxy-injected)", scope.subject.as_str()),
        ),
        WardEvent::AgentClaim { kind, payload } => {
            (claim_verb(*kind), Tone::Dim, payload.to_string())
        }
        WardEvent::SnapshotCreated { role, id, .. } => (
            "SNAP",
            Tone::Accent,
            format!("{} {}", snapshot_role(*role), short_hex(&id.to_string())),
        ),
        WardEvent::VerificationRequested { .. }
        | WardEvent::VerificationStarted { .. }
        | WardEvent::VerificationProgress { .. }
        | WardEvent::VerificationPassed { .. }
        | WardEvent::VerificationFailed { .. } => verification_cells(&rec.event)?,
        WardEvent::PolicyDecision {
            subject,
            decision,
            rule,
            detail,
        } => {
            let (verb, tone) = decision_verb(*decision);
            (verb, tone, evidence_text(subject, Some(rule), detail))
        }
        WardEvent::PolicyDenied {
            subject,
            rule,
            detail,
        } => (
            "DENIED",
            Tone::Deny,
            evidence_text(subject, Some(rule), detail),
        ),
        WardEvent::TamperDetected { subject, detail } => {
            ("TAMPER", Tone::Deny, evidence_text(subject, None, detail))
        }
        WardEvent::StateAccepted { snapshot, .. } => (
            "ACCEPT",
            Tone::Ok,
            format!("snapshot {}", short_hex(&snapshot.to_string())),
        ),
        WardEvent::SessionPaused { method, reason } => (
            "PAUSE",
            Tone::Deny,
            format!(
                "agents paused · network closed · grants suspended · processes frozen ({}) · {}",
                method.as_str(),
                reason.as_str()
            ),
        ),
        WardEvent::SessionResumed { paused_for } => (
            "RESUME",
            Tone::Accent,
            format!("agents resumed · paused {}", duration_text(*paused_for)),
        ),
        WardEvent::EntryRestored {
            snapshot,
            files,
            backup,
        } => (
            "RESTORE",
            Tone::Accent,
            if backup.as_str().is_empty() {
                format!(
                    "entry {} · worktree already matched",
                    short_hex(&snapshot.to_string())
                )
            } else {
                format!(
                    "entry {} · {files} paths · replaced files in {}",
                    short_hex(&snapshot.to_string()),
                    backup.as_str()
                )
            },
        ),
        WardEvent::SessionEnded { .. } => ("END", Tone::Dim, "session".to_string()),
        _ => return None,
    };
    Some(ObserverCells {
        time: mono_time(rec),
        verb,
        tone,
        subject,
    })
}

/// A duration as the observer says it: `12s`, `3m 05s`, `1h 02m`.
#[must_use]
pub fn duration_text(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    match (secs / 3600, (secs % 3600) / 60, secs % 60) {
        (0, 0, s) => format!("{s}s"),
        (0, m, s) => format!("{m}m {s:02}s"),
        (h, m, _) => format!("{h}h {m:02}m"),
    }
}

/// The verification phase's rows (`docs/design-language.md` §11): `VERIFY` in
/// accent while it runs, `PASS` green, `FAIL` red.
fn verification_cells(event: &WardEvent) -> Option<(&'static str, Tone, String)> {
    Some(match event {
        WardEvent::VerificationRequested { candidate, .. } => (
            "VERIFY",
            Tone::Accent,
            format!("candidate {}", short_hex(&candidate.to_string())),
        ),
        WardEvent::VerificationStarted {
            candidate,
            pristine,
            ..
        } => (
            "VERIFY",
            Tone::Accent,
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
            Tone::Ok,
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
            Tone::Deny,
            format!(
                "verification failed · {}/{} tests failed · candidate {}",
                summary.tests_failed,
                summary.tests_run,
                short_hex(&candidate.to_string())
            ),
        ),
        _ => return None,
    })
}

/// The row for a record [`observer_row`] hides in the compact view: the same time
/// column, then the event kind in dim (`ward watch --all`).
#[must_use]
pub fn kind_row(rec: &EventRecord) -> String {
    format!(
        "{DIM}{}{RESET}  {DIM}{}{RESET}",
        mono_time(rec),
        rec.event.kind()
    )
}

/// The uncoloured columns of [`kind_row`]: the kind name stands in the verb
/// column, dim, with an empty subject.
#[must_use]
pub fn kind_cells(rec: &EventRecord) -> ObserverCells {
    ObserverCells {
        time: mono_time(rec),
        verb: rec.event.kind().name(),
        tone: Tone::Dim,
        subject: String::new(),
    }
}

/// `ALLOW` green, `ASK` amber, `DENIED` red.
fn decision_verb(decision: ward_events::Decision) -> (&'static str, Tone) {
    use ward_events::Decision as D;
    match decision {
        D::Allow => ("ALLOW", Tone::Ok),
        D::Ask => ("ASK", Tone::Warn),
        D::Deny => ("DENIED", Tone::Deny),
    }
}

/// `protected tests · rule protected-tests · tests/verify.rs`.
fn evidence_text(
    subject: &ward_events::PolicySubject,
    rule: Option<&ward_events::RuleRef>,
    detail: &ward_events::DetailText,
) -> String {
    let mut parts = vec![policy_subject(subject)];
    if let Some(rule) = rule {
        parts.push(format!("rule {}", rule.as_str()));
    }
    if !detail.as_str().is_empty() {
        parts.push(detail.as_str().to_string());
    }
    parts.join(" · ")
}

fn policy_subject(subject: &ward_events::PolicySubject) -> String {
    use ward_events::PolicySubject as S;
    match subject {
        S::Session => "session".into(),
        S::Manifest => "manifest".into(),
        S::Policy => "policy".into(),
        S::ProtectedTests => "protected tests".into(),
        S::VerifyConfig => "verify config".into(),
        S::Ci => "ci".into(),
        S::Hooks => "hooks".into(),
        S::Fixtures => "fixtures".into(),
        S::Snapshot { id } => format!("snapshot {}", short_hex(&id.to_string())),
        S::Path { path } => path.to_string(),
        S::Other { detail } => detail.as_str().to_string(),
    }
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

/// The `ward doctor` panel: one row per check, colour by status.
#[must_use]
pub fn doctor_panel(checks: &[crate::doctor::Check]) -> String {
    use crate::doctor::Status;
    let mut s = format!("{ACCENT}WARD{RESET} {INK}doctor{RESET}  {DIM}host readiness{RESET}\n\n");
    for c in checks {
        let (color, word) = match c.status {
            Status::Ok => (OK, "OK"),
            Status::Warn => (WARN, "WARN"),
            Status::Fail => (DENY, "FAIL"),
        };
        let _ = writeln!(
            s,
            "  {INK}{:<20}{RESET}{color}{word:<5}{RESET} {DIM}{}{RESET}",
            c.name, c.detail
        );
    }
    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warns = checks.iter().filter(|c| c.status == Status::Warn).count();
    let verdict = if fails > 0 {
        format!("{DENY}{fails} blocking{RESET}")
    } else if warns > 0 {
        format!("{OK}ready{RESET} {DIM}· {warns} degraded{RESET}")
    } else {
        format!("{OK}ready{RESET}")
    };
    let _ = write!(s, "\n  {verdict}\n");
    s
}

/// The `ward doctor` hardware baseline block (Hardware Baseline 1): what this machine
/// gives a session and how fast, with an overall verdict. A report — a degraded row is
/// a dot, never a blocker.
#[must_use]
pub fn hardware_panel(checks: &[crate::doctor::Check]) -> String {
    use crate::doctor::Status;
    let mut s = format!("\n{ACCENT}WARDOS{RESET} {INK}hardware baseline{RESET}\n\n");
    for c in checks {
        let (color, mark) = match c.status {
            Status::Ok => (OK, "✓"),
            Status::Warn => (WARN, "·"),
            Status::Fail => (DENY, "✗"),
        };
        let _ = writeln!(
            s,
            "  {INK}{:<20}{RESET}{color}{mark}{RESET} {DIM}{}{RESET}",
            c.name, c.detail
        );
    }
    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warns = checks.iter().filter(|c| c.status == Status::Warn).count();
    let verdict = if fails > 0 {
        format!("{DENY}not ready{RESET} {DIM}· {fails} blocking{RESET}")
    } else if warns > 0 {
        format!("{OK}usable{RESET} {DIM}· {warns} to verify{RESET}")
    } else {
        format!("{OK}READY{RESET}")
    };
    let _ = write!(s, "\n  {INK}Overall{RESET}  {verdict}\n");
    s
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

fn step_color(status: ward_events::StepStatus) -> Tone {
    match status {
        ward_events::StepStatus::Running => Tone::Dim,
        ward_events::StepStatus::Pass => Tone::Ok,
        ward_events::StepStatus::Fail => Tone::Deny,
    }
}

fn claim_verb(kind: ward_events::ClaimKind) -> &'static str {
    use ward_events::ClaimKind as K;
    match kind {
        K::ToolUse => "TOOL",
        K::Note | K::Plan => "NOTE",
    }
}

/// Observer cells for a `NetworkRequested` record. Honour the decision so a denied
/// request never reads as amber "attention": today the egress path emits denials as
/// `NetworkDenied` (so this is `Allow` in practice), but `feed.rs` already counts a
/// `Deny` here as denied — keep the row consistent with that and with any future or
/// replayed `Deny`.
fn net_requested_cells(event: &WardEvent) -> (&'static str, Tone, String) {
    let WardEvent::NetworkRequested {
        host,
        port,
        decision,
        ..
    } = event
    else {
        // Only ever called for the NetworkRequested arm of observer_cells.
        return ("NET", Tone::Warn, String::new());
    };
    let (verb, tone) = match decision {
        ward_events::Decision::Deny => ("DENY", Tone::Deny),
        _ => ("NET", Tone::Warn),
    };
    (verb, tone, format!("{host}:{port}"))
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

fn exit_color(exit: ward_events::ExitStatus) -> Tone {
    match exit {
        ward_events::ExitStatus::Exited { code: 0 } => Tone::Ok,
        _ => Tone::Deny,
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

/// One-line daemon state for the status panel: `daemon wardd · control <socket>`
/// when a `wardd` answers on the session's control socket, or a note that
/// commands write the log in-process otherwise.
#[must_use]
pub fn daemon_status_line(control: Option<&str>) -> String {
    match control {
        Some(socket) => format!("  {INK}daemon wardd{RESET} {DIM}· control {socket}{RESET}"),
        None => format!("  {DIM}daemon none · commands write the log in-process{RESET}"),
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

/// Colour a self-test outcome line: `DENIED` (the sandbox held), `REACHED`
/// (it did not, with how), or `CANNOT-MEASURE-HERE` with the reason (E-06's
/// convention: a probe this host cannot run is never shown as a pass).
#[must_use]
pub fn selftest_row(name: &str, verdict: &Verdict) -> String {
    match verdict {
        Verdict::Denied => format!("  {INK}{name:<36}{RESET}{OK}DENIED{RESET}"),
        Verdict::Reached(how) => {
            format!("  {INK}{name:<36}{RESET}{DENY}REACHED{RESET}  {DIM}{how}{RESET}")
        }
        Verdict::CannotMeasure(why) => {
            format!("  {INK}{name:<36}{RESET}{WARN}CANNOT-MEASURE-HERE{RESET}  {DIM}{why}{RESET}")
        }
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
    fn evidence_kinds_have_observer_rows_and_hidden_kinds_a_dim_kind_row() {
        use std::time::Duration;
        use ward_events::{
            Acceptor, AgentState, Blake3Hash, Chain, Decision, DetailText, Origin, PolicySubject,
            RuleRef, SessionId, SnapshotId, Timestamp,
        };
        let rule = RuleRef::new("protected-tests").unwrap();
        let events = [
            WardEvent::PolicyDecision {
                subject: PolicySubject::Session,
                decision: Decision::Allow,
                rule: rule.clone(),
                detail: DetailText::new(""),
            },
            WardEvent::PolicyDecision {
                subject: PolicySubject::Hooks,
                decision: Decision::Deny,
                rule: rule.clone(),
                detail: DetailText::new(".claude/settings.json"),
            },
            WardEvent::PolicyDenied {
                subject: PolicySubject::ProtectedTests,
                rule,
                detail: DetailText::new("tests/verify.rs"),
            },
            WardEvent::TamperDetected {
                subject: PolicySubject::VerifyConfig,
                detail: DetailText::new(".tamperward/config.yml"),
            },
            WardEvent::StateAccepted {
                snapshot: SnapshotId::new(Blake3Hash::from_bytes([0xab; 32])),
                by: Acceptor::TamperWard,
            },
            WardEvent::AgentStateChanged {
                state: AgentState::Working,
            },
        ];
        let mut chain = Chain::genesis(SessionId::from_u128(1), Blake3Hash::ZERO);
        let records: Vec<EventRecord> = events
            .into_iter()
            .map(|e| {
                chain
                    .append(
                        Origin::TamperWard,
                        e,
                        Timestamp::mono(Duration::from_secs(61)),
                    )
                    .unwrap()
            })
            .collect();
        let rows: Vec<String> = records
            .iter()
            .take(5)
            .map(|r| plain(&observer_row(r).unwrap()))
            .collect();
        assert_eq!(
            rows,
            vec![
                "01:01  ALLOW session · rule protected-tests",
                "01:01  DENIED hooks · rule protected-tests · .claude/settings.json",
                "01:01  DENIED protected tests · rule protected-tests · tests/verify.rs",
                "01:01  TAMPER verify config · .tamperward/config.yml",
                "01:01  ACCEPT snapshot abababababab",
            ]
        );
        assert!(observer_row(&records[0]).unwrap().contains(OK));
        assert!(observer_row(&records[1]).unwrap().contains(DENY));
        assert!(observer_row(&records[2]).unwrap().contains(DENY));
        assert!(observer_row(&records[3]).unwrap().contains(DENY));
        assert!(observer_row(&records[4]).unwrap().contains(OK));
        assert_eq!(observer_row(&records[5]), None);
        assert_eq!(plain(&kind_row(&records[5])), "01:01  agent_state_changed");
    }

    #[test]
    fn network_request_row_colour_follows_the_decision() {
        use std::time::Duration;
        use ward_events::{
            Blake3Hash, Chain, Decision, HostName, Origin, Pid, ProcessRef, RuleRef, SessionId,
            Timestamp,
        };
        let by = ProcessRef {
            pid: Pid::new(7).unwrap(),
            comm: None,
        };
        let rule = RuleRef::new("allowlisted").unwrap();
        let mk = |decision| WardEvent::NetworkRequested {
            host: HostName::new("api.github.com").unwrap(),
            port: 443,
            decision,
            rule: rule.clone(),
            by: by.clone(),
        };
        let mut chain = Chain::genesis(SessionId::from_u128(1), Blake3Hash::ZERO);
        let allow = chain
            .append(
                Origin::Proxy,
                mk(Decision::Allow),
                Timestamp::mono(Duration::from_secs(1)),
            )
            .unwrap();
        let deny = chain
            .append(
                Origin::Proxy,
                mk(Decision::Deny),
                Timestamp::mono(Duration::from_secs(2)),
            )
            .unwrap();
        // Allowed: amber NET. Denied: red DENY — never amber. (The verb column is
        // padded to five, so NET/DENY carry trailing spaces before the subject.)
        assert_eq!(
            plain(&observer_row(&allow).unwrap()),
            "00:01  NET   api.github.com:443"
        );
        assert!(observer_row(&allow).unwrap().contains(WARN));
        assert_eq!(
            plain(&observer_row(&deny).unwrap()),
            "00:02  DENY  api.github.com:443"
        );
        assert!(observer_row(&deny).unwrap().contains(DENY));
    }

    #[test]
    fn daemon_line_names_the_socket_or_the_fallback() {
        let served = plain(&daemon_status_line(Some("sessions/sess_x/control.sock")));
        assert_eq!(
            served,
            "  daemon wardd · control sessions/sess_x/control.sock"
        );
        assert_eq!(
            plain(&daemon_status_line(None)),
            "  daemon none · commands write the log in-process"
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
