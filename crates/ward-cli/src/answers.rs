//! `ward ready --answers`: the four E-14 questions (`docs/experiments.md` E-14,
//! ADR-0019), answered for a project from what WardOS recorded, and from nothing else
//! (#147 item 7). After a task a developer should be able to say what the agent could
//! reach, which credentials it could use, what it changed, and whether the current
//! candidate is verified; this is the one place that says all four:
//!
//! * **reach** — the session's capability manifest (`session.json`, resolved from the
//!   policy when the session started) and the temporary grants its log records, the same
//!   projection as the trust bar's authority panel ([`authority_panel`]);
//! * **credentials** — the `CredentialGranted`/`CredentialRevoked` records in its log;
//! * **changed** — its entry snapshot (in the CAS) against the worktree digested now;
//! * **verified** — its last verification record held against that same digest, the
//!   trust bar's `VERIFY` state ([`VerifyState`]).
//!
//! The session is the project's live one, else the most recent one that ran there. Every
//! answer names its source, and an answer WardOS has no record for is `unknown` with the
//! reason — never a guess from the policy file or the worktree alone.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use ward_daemon::SessionMeta;
use ward_daemon::describe::SessionDescription;
use ward_daemon::snapshot::{DiffReport, WorktreeChanges};
use ward_events::{EventRecord, LogReader};
use ward_shell_core::authority::authority_panel;
use ward_shell_core::feed::{Freshness, SessionState, Verification};
use ward_shell_core::{Authority, VerifyState, short_hex};

/// How many changed paths an answer lists before it counts the rest.
const MAX_PATHS: usize = 20;

/// The four answers for one project.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Answers {
    /// The project directory asked about.
    pub project: PathBuf,
    /// The session the answers come from, when there is one.
    pub session: Option<SessionRef>,
    /// `reach`, `credentials`, `changed`, `verified`, in that order.
    pub answers: Vec<Answer>,
}

/// Which session the answers come from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionRef {
    /// `sess_…`.
    pub id: String,
    /// Whether it is the project's current session (not yet ended).
    pub live: bool,
}

/// One answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Answer {
    /// `reach`, `credentials`, `changed` or `verified`.
    pub key: &'static str,
    /// The question, as E-14 asks it.
    pub question: &'static str,
    /// The answer in one line; starts with `unknown` when there is no record.
    pub answer: String,
    /// Whether WardOS has a record that answers it.
    pub known: bool,
    /// Where the answer comes from.
    pub source: String,
    /// Supporting lines: the grants, the changed paths, the counts.
    pub details: Vec<String>,
}

impl Answer {
    fn new(key: &'static str, question: &'static str) -> Self {
        Self {
            key,
            question,
            answer: String::new(),
            known: false,
            source: String::new(),
            details: Vec::new(),
        }
    }

    fn known(mut self, answer: impl Into<String>, source: impl Into<String>) -> Self {
        self.answer = answer.into();
        self.source = source.into();
        self.known = true;
        self
    }

    fn unknown(mut self, why: &str, source: impl Into<String>) -> Self {
        self.answer = format!("unknown: {why}");
        self.source = source.into();
        self.known = false;
        self
    }

    fn details(mut self, details: Vec<String>) -> Self {
        self.details = details;
        self
    }
}

const REACH: &str = "What can the agent reach?";
const CREDENTIALS: &str = "Which credentials can it use?";
const CHANGED: &str = "What did it change?";
const VERIFIED: &str = "Is the current candidate verified?";

/// What a session recorded, read once, for [`derive`].
pub struct SessionFacts {
    /// The session's immutable facts, its manifest among them.
    pub description: SessionDescription,
    /// Whether it is the project's current session.
    pub live: bool,
    /// Its log's records, or why they cannot be read.
    pub records: Result<Vec<EventRecord>, String>,
    /// The worktree now against its entry snapshot.
    pub worktree: WorktreeChanges,
}

/// Read what WardOS recorded for `dir` under `state` and answer the four questions.
#[must_use]
pub fn gather(dir: &Path, state: &Path) -> Answers {
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let session = find_session(dir, state).map(|(meta, live)| {
        let log = ward_daemon::session::session_dir(state, &meta.id).join("events.log");
        SessionFacts {
            records: read_records(&log),
            worktree: ward_daemon::snapshot::worktree_changes(state, &meta.entry_snapshot, dir),
            description: meta.describe(),
            live,
        }
    });
    let project = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    derive(&project, session.as_ref(), &policy_note(dir), now_unix_ms)
}

/// The project's live session, else the most recent session recorded for it.
fn find_session(dir: &Path, state: &Path) -> Option<(SessionMeta, bool)> {
    if let Ok(Some(meta)) = SessionMeta::current(dir, state) {
        return Some((meta, true));
    }
    let project = dir.canonicalize().ok()?;
    std::fs::read_dir(state.join("sessions"))
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|e| SessionMeta::load(state, &e.file_name().to_string_lossy()).ok())
        .filter(|meta| meta.project == project)
        .max_by_key(|meta| meta.started_unix_ms)
        .map(|meta| (meta, false))
}

/// Every record of the log at `path`, or why it cannot be read whole.
fn read_records(path: &Path) -> Result<Vec<EventRecord>, String> {
    LogReader::open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// What `.ward/policy.yaml` asks for, as a hint beside an `unknown` reach — never as
/// the answer, since a session merges it with the host's defaults.
fn policy_note(dir: &Path) -> String {
    match std::fs::read_to_string(dir.join(".ward/policy.yaml")) {
        Ok(yaml) => match ward_policy::Policy::from_yaml(&yaml) {
            Ok(policy) => format!(
                ".ward/policy.yaml asks for network {}; a session merges it with the host's defaults and can only narrow them",
                policy.network.as_ref().map_or_else(
                    || "(the host default)".to_owned(),
                    ward_daemon::render::network_text
                )
            ),
            Err(e) => format!(".ward/policy.yaml does not resolve ({e})"),
        },
        Err(_) => ".ward/policy.yaml is not written yet".to_owned(),
    }
}

/// The four answers from what was read. Pure: the tests drive it with hand-built records.
#[must_use]
pub fn derive(
    dir: &Path,
    session: Option<&SessionFacts>,
    policy_note: &str,
    now_unix_ms: u64,
) -> Answers {
    let Some(facts) = session else {
        let source = "no session has run in this project (none recorded under the state root)";
        return Answers {
            project: dir.to_path_buf(),
            session: None,
            answers: vec![
                Answer::new("reach", REACH)
                    .unknown(
                        "no session has run here, so nothing records what an agent could reach",
                        source,
                    )
                    .details(vec![policy_note.to_owned()]),
                Answer::new("credentials", CREDENTIALS).unknown(
                    "no session has run here, so no credential grant is recorded",
                    source,
                ),
                Answer::new("changed", CHANGED).unknown(
                    "no session has run here, so there is no entry snapshot to compare with",
                    source,
                ),
                Answer::new("verified", VERIFIED).unknown(
                    "no session has run here, so no verification is recorded",
                    source,
                ),
            ],
        };
    };
    let id = &facts.description.session;
    Answers {
        project: dir.to_path_buf(),
        session: Some(SessionRef {
            id: id.clone(),
            live: facts.live,
        }),
        answers: vec![
            during(facts, reach(facts, now_unix_ms)),
            during(facts, credentials(facts, now_unix_ms)),
            changed(facts),
            verified(facts),
        ],
    }
}

/// An ended session's authority is history: say so in the answer itself.
fn during(facts: &SessionFacts, mut answer: Answer) -> Answer {
    if !facts.live && answer.known {
        answer.answer = format!("while the session ran (it has ended): {}", answer.answer);
    }
    answer
}

fn reach(facts: &SessionFacts, now_unix_ms: u64) -> Answer {
    let d = &facts.description;
    let (authority, grants_note) = match &facts.records {
        Ok(records) => (Authority::from_records(records), None),
        Err(e) => (
            Authority::default(),
            Some(format!(
                "temporary grants: unknown (the log cannot be read: {e})"
            )),
        ),
    };
    let groups = authority_panel(d, &authority, now_unix_ms);
    let mut details = Vec::new();
    for group in &groups {
        // Filesystem and network are the answer itself; the rest supports it.
        for row in group
            .rows
            .iter()
            .filter(|r| r.label != "Filesystem" && r.label != "Network")
        {
            if row.value.is_empty() {
                details.push(format!("{}: {}", group.title, row.label));
            } else {
                details.push(format!("{}: {} {}", group.title, row.label, row.value));
            }
        }
    }
    let row = |label: &str| {
        groups
            .iter()
            .flat_map(|g| &g.rows)
            .find(|r| r.label == label)
            .map(|r| r.value.clone())
            .unwrap_or_default()
    };
    let mut answer = format!("{} · network {}", row("Filesystem"), row("Network"));
    if let Some(note) = &grants_note {
        answer.push_str(" · temporary grants unknown");
        details.push(note.clone());
    } else {
        let live = authority.len(now_unix_ms);
        if live > 0 {
            let _ = write!(answer, " · {live} temporary grant{}", plural(live));
        }
    }
    Answer::new("reach", REACH)
        .known(
            answer,
            format!(
                "session {}: its capability manifest (session.json, policy {}) and the grants in its log",
                d.session,
                &d.policy_hash[..12.min(d.policy_hash.len())]
            ),
        )
        .details(details)
}

fn credentials(facts: &SessionFacts, now_unix_ms: u64) -> Answer {
    let source = format!(
        "CredentialGranted and CredentialRevoked records in session {}'s log",
        facts.description.session
    );
    let records = match &facts.records {
        Ok(records) => records,
        Err(e) => {
            return Answer::new("credentials", CREDENTIALS)
                .unknown(&format!("the log cannot be read ({e})"), source);
        }
    };
    let authority = Authority::from_records(records);
    let creds: Vec<_> = authority
        .grants
        .iter()
        .filter(|g| g.lifetime == "launch")
        .collect();
    if creds.is_empty() {
        return Answer::new("credentials", CREDENTIALS)
            .known("none: no credential was granted in this session", source);
    }
    let current: Vec<_> = creds
        .iter()
        .filter(|g| !g.is_expired(now_unix_ms))
        .collect();
    let mut labels: Vec<&str> = current.iter().map(|g| g.label.as_str()).collect();
    labels.dedup();
    let answer = if current.is_empty() {
        format!(
            "none now: {} granted in this session, every one expired",
            creds.len()
        )
    } else {
        format!(
            "{} granted{}: {}",
            current.len(),
            if authority.suspended {
                ", suspended while the session is paused"
            } else {
                ""
            },
            labels.join(", ")
        )
    };
    let details = creds
        .iter()
        .map(|g| {
            format!(
                "{} · {} · {}{}",
                g.label,
                g.scope,
                g.lifetime,
                if g.is_expired(now_unix_ms) {
                    " · expired"
                } else {
                    ""
                }
            )
        })
        .collect();
    Answer::new("credentials", CREDENTIALS)
        .known(answer, source)
        .details(details)
}

fn changed(facts: &SessionFacts) -> Answer {
    let entry = &facts.description.entry_snapshot;
    let mut source = format!(
        "the entry snapshot {} of session {} against the worktree digested now",
        short_id(entry),
        facts.description.session
    );
    if !facts.live {
        source.push_str("; the session has ended, so edits made since are included");
    }
    let diff = match &facts.worktree.changes {
        Ok(diff) => diff,
        Err(e) => return Answer::new("changed", CHANGED).unknown(e, source),
    };
    if diff.is_empty() {
        return Answer::new("changed", CHANGED).known(
            format!(
                "nothing: the worktree is the entry snapshot {}, byte for byte",
                short_id(entry)
            ),
            source,
        );
    }
    let total = diff.added.len() + diff.changed.len() + diff.removed.len();
    Answer::new("changed", CHANGED)
        .known(
            format!(
                "{total} path{}: {} added, {} modified, {} removed",
                plural(total),
                diff.added.len(),
                diff.changed.len(),
                diff.removed.len()
            ),
            source,
        )
        .details(path_lines(diff))
}

/// `+ added`, `~ modified`, `- removed`, at most [`MAX_PATHS`], then a count.
fn path_lines(diff: &DiffReport) -> Vec<String> {
    let all: Vec<String> = diff
        .added
        .iter()
        .map(|p| format!("+ {p}"))
        .chain(diff.changed.iter().map(|p| format!("~ {p}")))
        .chain(diff.removed.iter().map(|p| format!("- {p}")))
        .collect();
    let mut lines: Vec<String> = all.iter().take(MAX_PATHS).cloned().collect();
    if all.len() > MAX_PATHS {
        lines.push(format!("… and {} more", all.len() - MAX_PATHS));
    }
    lines
}

fn verified(facts: &SessionFacts) -> Answer {
    let source = format!(
        "the last verification record in session {}'s log, held against the worktree's digest now",
        facts.description.session
    );
    let records = match &facts.records {
        Ok(records) => records,
        Err(e) => {
            return Answer::new("verified", VERIFIED)
                .unknown(&format!("the log cannot be read ({e})"), source);
        }
    };
    let mut state = SessionState::default();
    for rec in records {
        state.apply(rec);
    }
    let (worktree, freshness) = match &facts.worktree.worktree {
        Ok(id) => (Some(*id), Freshness::Fresh),
        Err(_) => (None, Freshness::Unavailable),
    };
    let counts = |v: &Verification| match v {
        Verification::Passed(v) | Verification::Failed(v) | Verification::TimedOut(v)
            if v.summary.tests_run > 0 =>
        {
            Some(format!(
                "{} test{}, {} failed",
                v.summary.tests_run,
                plural(usize::try_from(v.summary.tests_run).unwrap_or(usize::MAX)),
                v.summary.tests_failed
            ))
        }
        _ => None,
    };
    let answer = Answer::new("verified", VERIFIED);
    let answer = match VerifyState::of(&state.verification, worktree, freshness) {
        VerifyState::Never => answer.known("no: nothing has been verified in this session", source),
        VerifyState::Preparing => {
            answer.known("not yet: a verification is being prepared", source)
        }
        VerifyState::Verifying(c) => answer.known(
            format!("not yet: the verifier is running on candidate {}", short_hex(c)),
            source,
        ),
        VerifyState::Verified(c) => answer.known(
            format!(
                "yes: candidate {} passed and the worktree is that candidate, byte for byte",
                short_hex(c)
            ),
            source,
        ),
        VerifyState::Stale {
            candidate,
            worktree,
        } => answer.known(
            format!(
                "no: candidate {} passed, but the worktree has changed since (now {})",
                short_hex(candidate),
                short_hex(worktree)
            ),
            source,
        ),
        VerifyState::Unknown { candidate } => answer.unknown(
            &format!(
                "candidate {} passed, but the worktree cannot be digested now, so whether it is still that candidate cannot be said",
                short_hex(candidate)
            ),
            source,
        ),
        VerifyState::Failed(c) => answer.known(
            format!("no: the last verification, of candidate {}, failed", short_hex(c)),
            source,
        ),
        VerifyState::TimedOut(c) => answer.known(
            format!(
                "no: the last verification, of candidate {}, was killed at its budget",
                short_hex(c)
            ),
            source,
        ),
        VerifyState::Errored(c) => answer.known(
            format!(
                "no: the last verification, of candidate {}, could not run to a result",
                short_hex(c)
            ),
            source,
        ),
        VerifyState::Cancelled(_) => {
            answer.known("no: the last verification was cancelled", source)
        }
        VerifyState::Interrupted(_) => {
            answer.known("no: the last verification was interrupted", source)
        }
    };
    let details = counts(&state.verification).into_iter().collect();
    answer.details(details)
}

const fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// The first 12 hex digits of a `blake3:…` id.
fn short_id(id: &str) -> &str {
    let hex = id.strip_prefix("blake3:").unwrap_or(id);
    &hex[..12.min(hex.len())]
}

/// The answers as a terminal panel: each question, its answer, the details and the source.
#[must_use]
pub fn render(answers: &Answers) -> String {
    use ward_daemon::render::Tone;
    let (ink, dim, ok, warn, reset) = (
        Tone::Ink.sgr(),
        Tone::Dim.sgr(),
        Tone::Ok.sgr(),
        Tone::Warn.sgr(),
        "\x1b[0m",
    );
    let mut s = format!(
        "{}WARD{reset} {ink}answers{reset}  {dim}{}{reset}\n",
        Tone::Accent.sgr(),
        answers.project.display()
    );
    let _ = writeln!(
        s,
        "  {dim}{}{reset}\n",
        answers.session.as_ref().map_or_else(
            || "no session recorded for this project".to_owned(),
            |r| format!(
                "session {} · {}",
                r.id,
                if r.live { "live" } else { "ended" }
            )
        )
    );
    for a in &answers.answers {
        let tone = if a.known { ok } else { warn };
        let _ = writeln!(s, "  {ink}{}{reset}", a.question);
        let _ = writeln!(s, "    {tone}{}{reset}", a.answer);
        for d in &a.details {
            let _ = writeln!(s, "    {dim}· {d}{reset}");
        }
        let _ = writeln!(s, "    {dim}source: {}{reset}\n", a.source);
    }
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::time::Duration;
    use ward_events::{
        Blake3Hash, Chain, CredentialDelivery, NameText, Origin, Scope, SessionId, ShortText,
        Timestamp, VerifySummary, WardEvent,
    };

    fn ev_id(byte: u8) -> ward_events::SnapshotId {
        ward_events::SnapshotId::new(Blake3Hash::from_bytes([byte; 32]))
    }

    fn records(events: &[WardEvent]) -> Vec<EventRecord> {
        let mut chain = Chain::genesis(SessionId::from_u128(7), Blake3Hash::from_bytes([1; 32]));
        events
            .iter()
            .enumerate()
            .map(|(i, e)| {
                chain
                    .append(
                        Origin::Wardd,
                        e.clone(),
                        Timestamp::mono(Duration::from_secs(i as u64)),
                    )
                    .unwrap()
            })
            .collect()
    }

    fn description() -> SessionDescription {
        let manifest = ward_policy::merge(
            &ward_policy::Policy::default(),
            &ward_policy::Policy::default(),
            &ward_policy::Policy::default(),
            ward_policy::SessionId("sess_01ANSWERS".to_owned()),
            ward_policy::ProjectId("proj_x".to_owned()),
        );
        SessionDescription {
            session: "sess_01ANSWERS".to_owned(),
            project: "proj_x".to_owned(),
            worktree: PathBuf::from("/home/dev/app"),
            started_unix_ms: 1_700_000_000_000,
            agent: None,
            entry_snapshot: format!("blake3:{}", "11".repeat(32)),
            policy_hash: manifest.policy_hash.to_hex(),
            manifest,
        }
    }

    fn facts(events: &[WardEvent], worktree: WorktreeChanges) -> SessionFacts {
        SessionFacts {
            description: description(),
            live: true,
            records: Ok(records(events)),
            worktree,
        }
    }

    fn unchanged(id: ward_events::SnapshotId) -> WorktreeChanges {
        WorktreeChanges {
            worktree: Ok(id),
            changes: Ok(DiffReport::default()),
        }
    }

    fn get<'a>(answers: &'a Answers, key: &str) -> &'a Answer {
        answers.answers.iter().find(|a| a.key == key).unwrap()
    }

    fn passed(candidate: ward_events::SnapshotId) -> WardEvent {
        WardEvent::VerificationPassed {
            candidate,
            summary: VerifySummary {
                tests_run: 3,
                ..VerifySummary::default()
            },
            result_hash: Blake3Hash::from_bytes([9; 32]),
        }
    }

    #[test]
    fn without_a_session_every_answer_is_unknown_and_says_why() {
        let answers = derive(Path::new("/p"), None, "policy note", 0);
        assert_eq!(answers.session, None);
        let keys: Vec<&str> = answers.answers.iter().map(|a| a.key).collect();
        assert_eq!(keys, ["reach", "credentials", "changed", "verified"]);
        for a in &answers.answers {
            assert!(!a.known, "{a:?}");
            assert!(a.answer.starts_with("unknown: "), "{a:?}");
            assert!(!a.source.is_empty());
        }
        assert_eq!(get(&answers, "reach").details, ["policy note"]);
    }

    #[test]
    fn reach_comes_from_the_manifest_and_the_grants_in_the_log() {
        let f = facts(&[], unchanged(ev_id(1)));
        let answers = derive(Path::new("/p"), Some(&f), "", 0);
        let reach = get(&answers, "reach");
        assert!(reach.known);
        assert!(reach.answer.contains("/work read-write"), "{reach:?}");
        assert!(reach.answer.contains("network"), "{reach:?}");
        assert!(reach.source.contains("sess_01ANSWERS"), "{reach:?}");
        assert!(
            reach
                .details
                .iter()
                .any(|d| d.starts_with("Denied: Host files")),
            "{reach:?}"
        );

        let mut broken = facts(&[], unchanged(ev_id(1)));
        broken.records = Err("truncated".to_owned());
        let answers = derive(Path::new("/p"), Some(&broken), "", 0);
        let reach = get(&answers, "reach");
        assert!(
            reach.answer.contains("temporary grants unknown"),
            "{reach:?}"
        );
        assert!(!get(&answers, "credentials").known);
        assert!(!get(&answers, "verified").known);
    }

    #[test]
    fn credentials_are_the_granted_ones_or_none() {
        let none = derive(
            Path::new("/p"),
            Some(&facts(&[], unchanged(ev_id(1)))),
            "",
            0,
        );
        let creds = get(&none, "credentials");
        assert!(creds.known);
        assert!(creds.answer.starts_with("none:"), "{creds:?}");

        let granted = WardEvent::CredentialGranted {
            service: ward_events::ServiceId::new("anthropic").unwrap(),
            scope: Scope {
                subject: ShortText::new("api.anthropic.com:443"),
                permissions: vec![NameText::new("messages")],
            },
            expires: Duration::from_secs(3600),
            delivery: CredentialDelivery::ProxyInjected,
        };
        let one = derive(
            Path::new("/p"),
            Some(&facts(&[granted], unchanged(ev_id(1)))),
            "",
            0,
        );
        let creds = get(&one, "credentials");
        assert!(creds.answer.starts_with("1 granted"), "{creds:?}");
        assert!(creds.details[0].contains("launch"), "{creds:?}");
    }

    #[test]
    fn changes_list_the_paths_against_the_entry_snapshot() {
        let diff = DiffReport {
            added: vec!["src/new.rs".to_owned()],
            changed: vec!["src/lib.rs".to_owned()],
            removed: vec![],
        };
        let f = facts(
            &[],
            WorktreeChanges {
                worktree: Ok(ev_id(2)),
                changes: Ok(diff),
            },
        );
        let answers = derive(Path::new("/p"), Some(&f), "", 0);
        let changed = get(&answers, "changed");
        assert_eq!(changed.answer, "2 paths: 1 added, 1 modified, 0 removed");
        assert_eq!(changed.details, ["+ src/new.rs", "~ src/lib.rs"]);
        assert!(
            changed.source.contains("entry snapshot 111111111111"),
            "{changed:?}"
        );

        let same = derive(
            Path::new("/p"),
            Some(&facts(&[], unchanged(ev_id(1)))),
            "",
            0,
        );
        assert!(get(&same, "changed").answer.starts_with("nothing:"));

        let mut ended = facts(
            &[],
            WorktreeChanges {
                worktree: Err("gone".to_owned()),
                changes: Err("the worktree cannot be digested (gone)".to_owned()),
            },
        );
        ended.live = false;
        let answers = derive(Path::new("/p"), Some(&ended), "", 0);
        assert!(
            get(&answers, "reach")
                .answer
                .starts_with("while the session ran (it has ended): /work"),
            "{answers:?}"
        );
        let changed = get(&answers, "changed");
        assert!(!changed.known);
        assert!(
            changed
                .answer
                .starts_with("unknown: the worktree cannot be digested")
        );
        assert!(changed.source.contains("session has ended"), "{changed:?}");
    }

    #[test]
    fn many_changed_paths_are_counted_past_the_cap() {
        let diff = DiffReport {
            added: (0..MAX_PATHS + 5).map(|i| format!("f{i}")).collect(),
            ..DiffReport::default()
        };
        let lines = path_lines(&diff);
        assert_eq!(lines.len(), MAX_PATHS + 1);
        assert_eq!(lines.last().unwrap(), "… and 5 more");
    }

    #[test]
    fn verified_holds_the_last_verdict_against_the_worktree() {
        let never = derive(
            Path::new("/p"),
            Some(&facts(&[], unchanged(ev_id(5)))),
            "",
            0,
        );
        assert!(
            get(&never, "verified")
                .answer
                .starts_with("no: nothing has been verified")
        );

        let yes = derive(
            Path::new("/p"),
            Some(&facts(&[passed(ev_id(5))], unchanged(ev_id(5)))),
            "",
            0,
        );
        let v = get(&yes, "verified");
        assert!(v.answer.starts_with("yes: candidate 05050505"), "{v:?}");
        assert_eq!(v.details, ["3 tests, 0 failed"]);

        let stale = derive(
            Path::new("/p"),
            Some(&facts(&[passed(ev_id(5))], unchanged(ev_id(6)))),
            "",
            0,
        );
        let v = get(&stale, "verified");
        assert!(
            v.answer.starts_with("no: candidate 05050505 passed"),
            "{v:?}"
        );
        assert!(v.answer.contains("changed since (now 06060606)"), "{v:?}");

        let undigestable = derive(
            Path::new("/p"),
            Some(&facts(
                &[passed(ev_id(5))],
                WorktreeChanges {
                    worktree: Err("unreadable".to_owned()),
                    changes: Err("unreadable".to_owned()),
                },
            )),
            "",
            0,
        );
        let v = get(&undigestable, "verified");
        assert!(!v.known);
        assert!(v.answer.starts_with("unknown:"), "{v:?}");

        let failed = WardEvent::VerificationFailed {
            candidate: ev_id(5),
            summary: VerifySummary {
                tests_run: 2,
                tests_failed: 1,
                ..VerifySummary::default()
            },
            result_hash: Blake3Hash::from_bytes([9; 32]),
        };
        let no = derive(
            Path::new("/p"),
            Some(&facts(&[failed], unchanged(ev_id(5)))),
            "",
            0,
        );
        let v = get(&no, "verified");
        assert!(v.answer.starts_with("no: the last verification"), "{v:?}");
        assert_eq!(v.details, ["2 tests, 1 failed"]);
    }

    #[test]
    fn the_panel_names_every_question_answer_and_source() {
        let answers = derive(Path::new("/p"), None, "note", 0);
        let text = render(&answers);
        for q in [REACH, CREDENTIALS, CHANGED, VERIFIED] {
            assert!(text.contains(q), "{text}");
        }
        assert!(text.contains("source: no session"), "{text}");
        assert!(text.contains("no session recorded"), "{text}");
        let json = serde_json::to_value(&answers).unwrap();
        assert!(json["session"].is_null());
        assert_eq!(json["answers"][0]["key"], "reach");
        assert_eq!(json["answers"][0]["known"], false);
    }
}
