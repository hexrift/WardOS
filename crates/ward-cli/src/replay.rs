//! `ward replay`: read a session log, verify its hash chain, and render it
//! (`docs/event-model.md` §8).
//!
//! The whole command is driven through [`replay`], which returns a [`Report`] holding
//! the rendered output and the verdict so callers (and tests) never need to spawn the
//! binary. Only a log that cannot be *opened* is an `Err`; a broken chain, truncated
//! tail or `HEAD` mismatch is a normal [`Report`] whose [`Report::ok`] is `false`.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use serde_json::json;
use ward_daemon::render;
use ward_events::log::{head_file_path, parse_head};
use ward_events::{
    ChainHead, Decision, DeniedDst, EventRecord, ExitStatus, LogError, LogReader, SessionId,
    SnapshotId, WardEvent,
};

// Colour follows `docs/design-language.md`, mirroring `ward_daemon::render`.
const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[38;5;245m";
const INK: &str = "\x1b[38;5;252m";
const OK: &str = "\x1b[38;5;108m";
const DENY: &str = "\x1b[38;5;167m";

/// How to render the log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// Verify the chain and the sealed `HEAD`; print a verdict instead of rows.
    pub verify: bool,
    /// Emit one JSON object per record instead of rendered rows.
    pub json: bool,
}

/// Why verification failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Reading stopped at `seq` (the sequence number the next record should have had).
    Broken {
        /// Sequence number at which the chain broke.
        seq: u64,
        /// The reader's error, rendered.
        reason: String,
    },
    /// The log has no records.
    Empty,
    /// The sealed `HEAD` does not describe the chain in the log.
    HeadMismatch {
        /// The head the `HEAD` file claims.
        sealed: ChainHead,
        /// The head recomputed from the log.
        actual: ChainHead,
    },
    /// The `HEAD` file exists but could not be parsed or read.
    HeadUnreadable(String),
}

/// State of the sealed `HEAD` file beside the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sealed {
    /// No `HEAD` file: the session is probably still open.
    Absent,
    /// `HEAD` exists and matches the recomputed chain head.
    Matches,
    /// `HEAD` exists but disagrees with the log, or could not be read.
    Bad,
    /// Not consulted (only `--verify` reads it).
    NotChecked,
}

/// Counters for the §8 summary footer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Session id from the records.
    pub session: Option<SessionId>,
    /// Entry snapshot from `SessionStarted`.
    pub entry: Option<SnapshotId>,
    /// Distinct paths with a `FileModified` record.
    pub files_changed: u64,
    /// `CommandStarted` records.
    pub commands: u64,
    /// `NetworkRequested` records decided `Allow`.
    pub net_allowed: u64,
    /// `NetworkRequested` records decided `Deny`, plus `NetworkDenied` records.
    pub net_denied: u64,
}

/// Outcome of a replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// Records read and verified.
    pub records: u64,
    /// Chain head after the last verified record, if any.
    pub head: Option<ChainHead>,
    /// State of the sealed `HEAD`.
    pub sealed: Sealed,
    /// Why the log failed verification, if it did.
    pub failure: Option<Failure>,
    /// Footer counters.
    pub stats: Stats,
    /// Rendered text (rows, JSON lines, verdict), newline-terminated.
    pub output: String,
}

impl Report {
    /// Whether the log was read to a clean end and (under `--verify`) matched `HEAD`.
    #[must_use]
    pub const fn ok(&self) -> bool {
        self.failure.is_none()
    }
}

/// Replay `path` according to `opts`.
///
/// # Errors
/// [`ward_daemon::Error::Events`] if the log cannot be opened.
pub fn replay(path: &Path, opts: Options) -> ward_daemon::Result<Report> {
    let reader = LogReader::open(path)
        .map_err(|e| ward_daemon::Error::Events(format!("cannot open {}: {e}", path.display())))?;
    let mut report = Report {
        records: 0,
        head: None,
        sealed: Sealed::NotChecked,
        failure: None,
        stats: Stats::default(),
        output: String::new(),
    };
    let mut paths = BTreeSet::new();
    let mut read_error = None;
    let mut reader = reader;
    for item in reader.by_ref() {
        match item {
            Ok(rec) => {
                account(&mut report.stats, &mut paths, &rec);
                report.records += 1;
                emit_record(&mut report.output, &rec, opts);
            }
            Err(e) => {
                read_error = Some(e);
                break;
            }
        }
    }
    report.head = reader.head();
    report.failure = match read_error {
        Some(e) => Some(Failure::Broken {
            seq: report.records,
            reason: reason_text(&e),
        }),
        None if opts.verify && report.records == 0 => Some(Failure::Empty),
        None => None,
    };
    if opts.verify {
        check_head(path, &mut report);
        write_verdict(&mut report, opts.json);
    } else {
        write_footer(&mut report, opts.json);
    }
    Ok(report)
}

fn reason_text(e: &LogError) -> String {
    match e {
        LogError::TruncatedTail { offset } => {
            format!("truncated tail: incomplete frame at byte offset {offset}")
        }
        other => other.to_string(),
    }
}

fn account(stats: &mut Stats, paths: &mut BTreeSet<String>, rec: &EventRecord) {
    stats.session.get_or_insert(rec.session);
    match &rec.event {
        WardEvent::SessionStarted { entry_snapshot, .. } => {
            stats.entry.get_or_insert(*entry_snapshot);
        }
        WardEvent::FileModified { path, .. } => {
            if paths.insert(path.to_string()) {
                stats.files_changed += 1;
            }
        }
        WardEvent::CommandStarted { .. } => stats.commands += 1,
        WardEvent::NetworkRequested { decision, .. } => match decision {
            Decision::Allow => stats.net_allowed += 1,
            Decision::Deny => stats.net_denied += 1,
            Decision::Ask => {}
        },
        WardEvent::NetworkDenied { .. } => stats.net_denied += 1,
        _ => {}
    }
}

fn emit_record(out: &mut String, rec: &EventRecord, opts: Options) {
    if opts.verify {
        return;
    }
    if opts.json {
        let line = json!({
            "seq": rec.seq,
            "ts_mono_ms": u64::try_from(rec.ts_mono.as_millis()).unwrap_or(u64::MAX),
            "origin": rec.origin.label(),
            "kind": format!("{:?}", rec.kind()),
            "summary": summary(&rec.event),
        });
        let _ = writeln!(out, "{line}");
    } else if let Some(row) = render::observer_row(rec) {
        let _ = writeln!(out, "{row}");
    }
}

fn check_head(path: &Path, report: &mut Report) {
    let head_path = head_file_path(path);
    let text = match std::fs::read_to_string(&head_path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            report.sealed = Sealed::Absent;
            return;
        }
        Err(e) => {
            report.sealed = Sealed::Bad;
            report
                .failure
                .get_or_insert(Failure::HeadUnreadable(e.to_string()));
            return;
        }
    };
    let sealed = match parse_head(&text) {
        Ok(head) => head,
        Err(e) => {
            report.sealed = Sealed::Bad;
            report
                .failure
                .get_or_insert(Failure::HeadUnreadable(e.to_string()));
            return;
        }
    };
    match report.head {
        Some(actual) if actual == sealed => report.sealed = Sealed::Matches,
        Some(actual) => {
            report.sealed = Sealed::Bad;
            report
                .failure
                .get_or_insert(Failure::HeadMismatch { sealed, actual });
        }
        None => {
            report.sealed = Sealed::Bad;
            report.failure.get_or_insert(Failure::HeadMismatch {
                sealed,
                actual: ChainHead {
                    session: sealed.session,
                    genesis: sealed.genesis,
                    next_seq: 0,
                    hash: sealed.genesis,
                },
            });
        }
    }
}

fn write_verdict(report: &mut Report, json: bool) {
    let head_hex = report.head.map(|h| short_hex(&h.hash.to_hex()));
    if json {
        let line = json!({
            "kind": "Verdict",
            "ok": report.ok(),
            "records": report.records,
            "head": head_hex,
            "sealed": sealed_label(report.sealed),
            "failure": report.failure.as_ref().map(failure_text),
        });
        let _ = writeln!(report.output, "{line}");
        return;
    }
    let out = &mut report.output;
    match &report.failure {
        None => {
            let _ = writeln!(
                out,
                "  {OK}chain VERIFIED{RESET} {DIM}· {} records · head {}{RESET}",
                report.records,
                head_hex.unwrap_or_default()
            );
        }
        Some(Failure::HeadMismatch { sealed, actual }) => {
            let _ = writeln!(
                out,
                "  {DENY}HEAD mismatch{RESET} {DIM}· sealed {} seq {} · log {} seq {}{RESET}",
                short_hex(&sealed.hash.to_hex()),
                sealed.next_seq,
                short_hex(&actual.hash.to_hex()),
                actual.next_seq,
            );
        }
        Some(failure) => {
            let _ = writeln!(out, "  {DENY}{}{RESET}", failure_text(failure));
        }
    }
    let sealed = match report.sealed {
        Sealed::Absent => format!("{DIM}absent (session still open?){RESET}"),
        Sealed::Matches => format!("{OK}matches{RESET}"),
        Sealed::Bad => format!("{DENY}does not match{RESET}"),
        Sealed::NotChecked => format!("{DIM}not checked{RESET}"),
    };
    let _ = writeln!(out, "  {INK}sealed head:{RESET} {sealed}");
}

fn write_footer(report: &mut Report, json: bool) {
    if let Some(failure) = &report.failure {
        if json {
            let line = json!({ "kind": "Verdict", "ok": false, "failure": failure_text(failure) });
            let _ = writeln!(report.output, "{line}");
        } else {
            let _ = writeln!(report.output, "  {DENY}{}{RESET}", failure_text(failure));
        }
    }
    if json {
        return;
    }
    let s = &report.stats;
    let session = s
        .session
        .map_or_else(|| "unknown".to_owned(), |id| id.to_string());
    let entry = s
        .entry
        .map_or_else(|| "unknown".to_owned(), |id| short_hex(&id.hash().to_hex()));
    let _ = writeln!(
        report.output,
        "  {DIM}session {session} · {} records · entry {entry} · files changed {} · \
         commands {} · network {} allowed / {} denied{RESET}",
        report.records, s.files_changed, s.commands, s.net_allowed, s.net_denied
    );
}

fn failure_text(f: &Failure) -> String {
    match f {
        Failure::Broken { seq, reason } => format!("chain BROKEN at seq {seq}: {reason}"),
        Failure::Empty => "chain BROKEN: log is empty".to_owned(),
        Failure::HeadMismatch { sealed, actual } => format!(
            "HEAD mismatch: sealed {} seq {} vs log {} seq {}",
            short_hex(&sealed.hash.to_hex()),
            sealed.next_seq,
            short_hex(&actual.hash.to_hex()),
            actual.next_seq
        ),
        Failure::HeadUnreadable(e) => format!("HEAD unreadable: {e}"),
    }
}

const fn sealed_label(s: Sealed) -> &'static str {
    match s {
        Sealed::Absent => "absent",
        Sealed::Matches => "matches",
        Sealed::Bad => "mismatch",
        Sealed::NotChecked => "not_checked",
    }
}

fn short_hex(s: &str) -> String {
    s.strip_prefix("blake3:")
        .unwrap_or(s)
        .chars()
        .take(12)
        .collect()
}

fn short_snapshot(id: &SnapshotId) -> String {
    short_hex(&id.hash().to_hex())
}

/// A compact, secret-free one-line description of an event for `--json`.
fn summary(event: &WardEvent) -> String {
    match event {
        WardEvent::SessionStarted {
            project,
            agent,
            entry_snapshot,
            ..
        } => format!(
            "project {project} · agent {} {} · entry {}",
            agent.name,
            agent.version,
            short_snapshot(entry_snapshot)
        ),
        WardEvent::SessionEnded { reason, .. } => format!("reason {reason:?}"),
        WardEvent::AgentStateChanged { state } => format!("state {state:?}"),
        WardEvent::FileRead { path, .. } => path.to_string(),
        WardEvent::FileModified { path, kind, .. } => format!("{kind:?} {path}"),
        WardEvent::CommandStarted { argv, pid, .. } => format!("pid {pid} {argv}"),
        WardEvent::CommandFinished { pid, exit, .. } => match exit {
            ExitStatus::Exited { code } => format!("pid {pid} exit {code}"),
            ExitStatus::Signaled { signal, .. } => format!("pid {pid} signal {signal}"),
        },
        WardEvent::SnapshotCreated {
            role,
            id,
            entries,
            bytes,
            ..
        } => format!(
            "{role:?} {} · {entries} entries · {bytes} bytes",
            short_snapshot(id)
        ),
        WardEvent::PolicyDecision { decision, rule, .. } => {
            format!("{decision:?} ({})", rule.as_str())
        }
        WardEvent::PolicyDenied { rule, detail, .. } => {
            format!("Deny ({}) {detail}", rule.as_str())
        }
        WardEvent::TamperDetected { detail, .. } => detail.to_string(),
        WardEvent::VerificationRequested {
            candidate,
            requested_by,
        } => format!(
            "candidate {} by {requested_by:?}",
            short_snapshot(candidate)
        ),
        WardEvent::VerificationStarted { candidate, .. } => {
            format!("candidate {}", short_snapshot(candidate))
        }
        WardEvent::VerificationProgress { step, status } => format!("{step} {status:?}"),
        WardEvent::VerificationPassed { summary, .. }
        | WardEvent::VerificationFailed { summary, .. } => format!(
            "{}/{} steps · {} tests · {} failed",
            summary.steps_passed, summary.steps_total, summary.tests_run, summary.tests_failed
        ),
        WardEvent::StateAccepted { snapshot, .. } => {
            format!("snapshot {}", short_snapshot(snapshot))
        }
        WardEvent::AgentClaim { kind, .. } => format!("{kind:?}"),
        WardEvent::SessionPaused { method, reason } => format!("{} · {reason}", method.as_str()),
        WardEvent::SessionResumed { paused_for } => format!("paused {}s", paused_for.as_secs()),
        WardEvent::EntryRestored {
            snapshot,
            files,
            backup,
        } => format!(
            "entry {} · {files} paths · backup {backup}",
            short_snapshot(snapshot)
        ),
        WardEvent::Anchor {
            chain_head,
            seq,
            countersigned_by,
            degraded,
        } => format!(
            "seq {seq} head {}{}{}",
            short_hex(&chain_head.to_hex()),
            if countersigned_by.is_some() {
                " · countersigned"
            } else {
                ""
            },
            if *degraded { " · degraded" } else { "" }
        ),
        WardEvent::NetworkRequested { .. }
        | WardEvent::NetworkDenied { .. }
        | WardEvent::CapabilityRequested { .. }
        | WardEvent::CapabilityDecided { .. }
        | WardEvent::CredentialRequested { .. }
        | WardEvent::CredentialGranted { .. }
        | WardEvent::CredentialDenied { .. }
        | WardEvent::CredentialRevoked { .. } => access_summary(event).unwrap_or_default(),
    }
}

/// Summaries for the network, capability and credential variants. Credentials and
/// capabilities are reduced to service / scope / target names only.
fn access_summary(event: &WardEvent) -> Option<String> {
    Some(match event {
        WardEvent::NetworkRequested {
            host,
            port,
            decision,
            rule,
            ..
        } => format!("{host}:{port} {decision:?} ({})", rule.as_str()),
        WardEvent::NetworkDenied { dst, reason } => {
            let target = match dst {
                DeniedDst::Host { host, port } => format!("{host}:{port}"),
                DeniedDst::Ip { addr, port } => format!("{addr}:{port}"),
                DeniedDst::Raw { target } => target.to_string(),
            };
            format!("{target} {reason:?}")
        }
        WardEvent::CapabilityRequested { cap, .. } => format!("{:?} {}", cap.kind, cap.target),
        WardEvent::CapabilityDecided { cap, decision, .. } => {
            format!("{:?} {} {decision:?}", cap.kind, cap.target)
        }
        WardEvent::CredentialRequested { service, scope }
        | WardEvent::CredentialGranted { service, scope, .. } => {
            format!("{} {}", service.as_str(), scope_text(scope))
        }
        WardEvent::CredentialDenied {
            service,
            scope,
            reason,
        } => format!("{} {} {reason:?}", service.as_str(), scope_text(scope)),
        WardEvent::CredentialRevoked { service, reason } => {
            format!("{} {reason:?}", service.as_str())
        }
        _ => return None,
    })
}

fn scope_text(scope: &ward_events::Scope) -> String {
    let perms = scope
        .permissions
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("{} [{perms}]", scope.subject)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::time::Duration;

    use ward_events::{
        AgentIdentity, AgentKind, Blake3Hash, Chain, CredentialDelivery, DenyReason, EndReason,
        ExitStatus, FileChangeKind, FsyncPolicy, HostName, LogWriter, NameText, Origin, Pid,
        ProcessRef, ProjectId, RuleRef, SandboxPath, SandboxRoot, Scope, ServiceId, ShortText,
        Timestamp,
    };

    use super::*;

    const KINDS: &[&str] = &[
        "SessionStarted",
        "CommandStarted",
        "FileModified",
        "FileModified",
        "FileModified",
        "NetworkRequested",
        "NetworkDenied",
        "CredentialGranted",
        "CommandFinished",
        "SessionEnded",
    ];

    fn by() -> ProcessRef {
        ProcessRef {
            pid: Pid::new(7).unwrap(),
            comm: None,
        }
    }

    fn path(rel: &str) -> SandboxPath {
        SandboxPath::new(SandboxRoot::Work, rel).unwrap()
    }

    fn events() -> Vec<WardEvent> {
        let entry = SnapshotId::new(Blake3Hash::hash(b"entry"));
        vec![
            WardEvent::SessionStarted {
                project: ProjectId::from_u128(9),
                agent: AgentIdentity {
                    kind: AgentKind::Other,
                    name: NameText::new("shell"),
                    version: NameText::new("0.1.0"),
                    image: None,
                },
                manifest_hash: Blake3Hash::hash(b"manifest"),
                entry_snapshot: entry,
                policy_hash: Blake3Hash::hash(b"policy"),
                tool_images: Vec::new(),
            },
            WardEvent::CommandStarted {
                pid: Pid::new(7).unwrap(),
                parent: Pid::new(1).unwrap(),
                argv: ward_events::BoundedArgv::from_strs(&["cargo", "test"]),
                cwd: path("."),
                exe_digest: None,
            },
            WardEvent::FileModified {
                path: path("src/lib.rs"),
                by: by(),
                kind: FileChangeKind::Write,
            },
            WardEvent::FileModified {
                path: path("src/lib.rs"),
                by: by(),
                kind: FileChangeKind::Write,
            },
            WardEvent::FileModified {
                path: path("Cargo.toml"),
                by: by(),
                kind: FileChangeKind::Write,
            },
            WardEvent::NetworkRequested {
                host: HostName::new("crates.io").unwrap(),
                port: 443,
                decision: Decision::Allow,
                rule: RuleRef::new("project:network.allow[0]").unwrap(),
                by: by(),
            },
            WardEvent::NetworkDenied {
                dst: DeniedDst::Host {
                    host: HostName::new("evil.example").unwrap(),
                    port: 443,
                },
                reason: DenyReason::NotAllowlisted,
            },
            WardEvent::CredentialGranted {
                service: ServiceId::new("github").unwrap(),
                scope: Scope {
                    subject: ShortText::new("repo:hexrift/wardos"),
                    permissions: vec![NameText::new("contents:read")],
                },
                expires: Duration::from_secs(600),
                delivery: CredentialDelivery::ProxyInjected,
            },
            WardEvent::CommandFinished {
                pid: Pid::new(7).unwrap(),
                exit: ExitStatus::Exited { code: 0 },
                duration: Duration::from_secs(3),
            },
            WardEvent::SessionEnded {
                reason: EndReason::UserStop,
                final_snapshot: None,
            },
        ]
    }

    /// Writes a log with [`events`]; seals it unless `open` is set.
    fn write_log(dir: &Path, open: bool) -> PathBuf {
        let log = dir.join("events.log");
        let mut chain = Chain::genesis(SessionId::from_u128(42), Blake3Hash::hash(b"manifest"));
        let mut w = LogWriter::create(&log, chain.head(), FsyncPolicy::Never).unwrap();
        for (i, event) in events().into_iter().enumerate() {
            let ts = Timestamp::mono(Duration::from_millis(u64::try_from(i).unwrap() * 1500));
            let r = chain.append(Origin::Wardd, event, ts).unwrap();
            w.append(&r).unwrap();
        }
        if !open {
            w.seal().unwrap();
        }
        log
    }

    /// Sealed files are mode 0400; make one writable again for tampering.
    fn make_writable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn rewrite(log: &Path, edit: impl FnOnce(&mut Vec<u8>)) {
        let mut bytes = fs::read(log).unwrap();
        edit(&mut bytes);
        make_writable(log);
        let mut f = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(log)
            .unwrap();
        f.write_all(&bytes).unwrap();
    }

    const VERIFY: Options = Options {
        verify: true,
        json: false,
    };

    #[test]
    fn verify_passes_on_a_sealed_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = write_log(dir.path(), false);
        let report = replay(&log, VERIFY).unwrap();
        assert!(report.ok(), "{}", report.output);
        assert_eq!(report.records, 10);
        assert_eq!(report.sealed, Sealed::Matches);
        assert!(report.output.contains("chain VERIFIED"));
        assert!(report.output.contains("10 records"));
        assert!(report.output.contains("sealed head:"));
    }

    #[test]
    fn verify_without_head_still_checks_linkage() {
        let dir = tempfile::tempdir().unwrap();
        let log = write_log(dir.path(), true);
        let report = replay(&log, VERIFY).unwrap();
        assert!(report.ok());
        assert_eq!(report.sealed, Sealed::Absent);
        assert!(report.output.contains("absent (session still open?)"));
    }

    #[test]
    fn flipped_byte_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let log = write_log(dir.path(), false);
        // The last payload byte is the last record's stored hash.
        rewrite(&log, |b| *b.last_mut().unwrap() ^= 0xff);
        let report = replay(&log, VERIFY).unwrap();
        assert!(!report.ok());
        assert_eq!(report.records, 9);
        assert!(
            matches!(report.failure, Some(Failure::Broken { seq: 9, .. })),
            "{:?}",
            report.failure
        );
        assert!(report.output.contains("chain BROKEN at seq 9"));
    }

    #[test]
    fn truncated_tail_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let log = write_log(dir.path(), false);
        rewrite(&log, |b| b.truncate(b.len() - 3));
        let report = replay(&log, VERIFY).unwrap();
        assert!(!report.ok());
        assert!(
            report
                .output
                .contains("chain BROKEN at seq 9: truncated tail")
        );
    }

    #[test]
    fn head_mismatch_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let log = write_log(dir.path(), false);
        let head_path = head_file_path(&log);
        make_writable(&head_path);
        let forged = fs::read_to_string(&head_path)
            .unwrap()
            .replace("next_seq=10", "next_seq=9");
        fs::write(&head_path, forged).unwrap();
        let report = replay(&log, VERIFY).unwrap();
        assert!(!report.ok());
        assert_eq!(report.sealed, Sealed::Bad);
        assert!(report.output.contains("HEAD mismatch"));
    }

    #[test]
    fn json_emits_one_object_per_record() {
        let dir = tempfile::tempdir().unwrap();
        let log = write_log(dir.path(), false);
        let opts = Options {
            verify: false,
            json: true,
        };
        let report = replay(&log, opts).unwrap();
        assert!(report.ok());
        let rows: Vec<serde_json::Value> = report
            .output
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 10);
        let kinds: Vec<&str> = rows.iter().map(|r| r["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, KINDS);
        assert_eq!(rows[1]["seq"], 1);
        assert_eq!(rows[1]["ts_mono_ms"], 1500);
        assert_eq!(rows[1]["origin"], "wardd");
        assert_eq!(
            rows[7]["summary"],
            "github repo:hexrift/wardos [contents:read]"
        );
    }

    #[test]
    fn default_mode_renders_rows_and_footer() {
        let dir = tempfile::tempdir().unwrap();
        let log = write_log(dir.path(), false);
        let report = replay(&log, Options::default()).unwrap();
        assert!(report.ok());
        assert_eq!(report.stats.files_changed, 2);
        assert_eq!(report.stats.commands, 1);
        assert_eq!(report.stats.net_allowed, 1);
        assert_eq!(report.stats.net_denied, 1);
        let footer = report.output.lines().last().unwrap();
        assert!(footer.contains(&SessionId::from_u128(42).to_string()));
        assert!(footer.contains("10 records"));
        assert!(footer.contains("files changed 2 · commands 1 · network 1 allowed / 1 denied"));
        assert!(report.output.contains("START"));
    }
}
