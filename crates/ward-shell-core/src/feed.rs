//! The observer feed: the agent activity panel of `docs/design-language.md` §8
//! and the state a session's records add up to.
//!
//! [`Model`] holds the records, the status-line counters
//! (`docs/event-model.md` §8), the follow/scroll state and the seal transition;
//! [`SessionState`] is the part of it the trust bar reads (agent state,
//! verification verdict, TamperWard's presence). Both are derived from records as
//! they arrive, never from rendered rows, and never from the worktree.

use std::collections::BTreeSet;

use ward_daemon::render::{self, ObserverCells};
use ward_events::{AgentState, Decision, EventRecord, Origin, WardEvent};

/// The counters of the status line (`docs/event-model.md` §8), derived from
/// records as they arrive, never from rendered rows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Distinct paths with a `FileModified` record.
    pub files_changed: u64,
    /// `CommandStarted` records.
    pub commands: u64,
    /// `NetworkRequested` records decided `Allow`.
    pub net_allowed: u64,
    /// `NetworkRequested` records decided `Deny`, plus `NetworkDenied` records.
    pub net_denied: u64,
    /// `AgentClaim` records: what the agent says about itself, never enforcement.
    pub claims: u64,
}

/// Text of the status line's counters, uncoloured.
#[must_use]
pub fn counters_text(c: &Counters) -> String {
    format!(
        "files changed {} · commands {} · network {} allowed / {} denied · claims {}",
        c.files_changed, c.commands, c.net_allowed, c.net_denied, c.claims
    )
}

/// Where the verification phase (`docs/design-language.md` §11) stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Verification {
    /// No verification has been requested in this session.
    #[default]
    NotRun,
    /// Requested or started; the trusted verifier is running.
    Running,
    /// The last verification passed: `✓ VERIFIED`.
    Passed,
    /// The last verification failed.
    Failed,
}

/// What the stream says about TamperWard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TamperWard {
    /// No TamperWard-origin record yet: the daemon does not know.
    #[default]
    Unknown,
    /// TamperWard has spoken and has detected no tampering.
    Clean,
    /// A `TamperDetected` record arrived.
    Tampered,
}

/// The session state the trust bar shows, as the records so far describe it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionState {
    /// The agent's last reported coarse state, once it has reported one.
    pub agent: Option<AgentState>,
    /// The verification phase.
    pub verification: Verification,
    /// TamperWard's presence and verdict.
    pub tamperward: TamperWard,
}

impl SessionState {
    /// Account for one record.
    pub const fn apply(&mut self, rec: &EventRecord) {
        match &rec.event {
            WardEvent::AgentStateChanged { state } => self.agent = Some(*state),
            WardEvent::VerificationRequested { .. } | WardEvent::VerificationStarted { .. } => {
                self.verification = Verification::Running;
            }
            WardEvent::VerificationPassed { .. } => self.verification = Verification::Passed,
            WardEvent::VerificationFailed { .. } => self.verification = Verification::Failed,
            WardEvent::TamperDetected { .. } => self.tamperward = TamperWard::Tampered,
            _ => {}
        }
        // Any word from TamperWard means it is attached; a detection is never
        // downgraded by later evidence.
        if matches!(rec.origin, Origin::TamperWard)
            && matches!(self.tamperward, TamperWard::Unknown)
        {
            self.tamperward = TamperWard::Clean;
        }
    }
}

/// The observer's state: what has arrived, what it adds up to, and where the
/// viewer is looking.
#[derive(Clone, Debug)]
pub struct Model {
    /// Every record received, in sequence order.
    pub records: Vec<EventRecord>,
    /// The status-line counters.
    pub counters: Counters,
    /// The session state the trust bar shows.
    pub state: SessionState,
    /// The daemon closed the stream: the log is sealed.
    pub sealed: bool,
    /// The view tracks the newest row.
    pub follow: bool,
    /// Index of the first visible row while not following.
    pub scroll: usize,
    /// Show the kinds the compact view hides, as a dim kind name (`--all`).
    all: bool,
    /// The rendered rows, one per record that has one.
    rows: Vec<ObserverCells>,
    /// Paths already counted in `counters.files_changed`.
    paths: BTreeSet<String>,
}

impl Model {
    /// An empty, following model. `all` mirrors `ward watch --all`.
    #[must_use]
    pub fn new(all: bool) -> Self {
        Self {
            records: Vec::new(),
            counters: Counters::default(),
            state: SessionState::default(),
            sealed: false,
            follow: true,
            scroll: 0,
            all,
            rows: Vec::new(),
            paths: BTreeSet::new(),
        }
    }

    /// Account for one record: its counters, its state, and its row if it has one.
    pub fn apply(&mut self, rec: EventRecord) {
        match &rec.event {
            WardEvent::FileModified { path, .. } => {
                if self.paths.insert(path.to_string()) {
                    self.counters.files_changed += 1;
                }
            }
            WardEvent::CommandStarted { .. } => self.counters.commands += 1,
            WardEvent::NetworkRequested { decision, .. } => match decision {
                Decision::Allow => self.counters.net_allowed += 1,
                Decision::Deny => self.counters.net_denied += 1,
                Decision::Ask => {}
            },
            WardEvent::NetworkDenied { .. } => self.counters.net_denied += 1,
            WardEvent::AgentClaim { .. } => self.counters.claims += 1,
            _ => {}
        }
        self.state.apply(&rec);
        let cells =
            render::observer_cells(&rec).or_else(|| self.all.then(|| render::kind_cells(&rec)));
        if let Some(cells) = cells {
            self.rows.push(cells);
        }
        self.records.push(rec);
    }

    /// The daemon ended the stream: the log is sealed. The rows stay.
    pub const fn seal(&mut self) {
        self.sealed = true;
    }

    /// Every row so far.
    #[must_use]
    pub fn rows(&self) -> &[ObserverCells] {
        &self.rows
    }

    /// The largest first-row index at which a pane of `height` rows is full.
    fn max_top(&self, height: usize) -> usize {
        self.rows.len().saturating_sub(height)
    }

    /// The first visible row for a pane of `height` rows.
    #[must_use]
    pub fn top(&self, height: usize) -> usize {
        if self.follow {
            self.max_top(height)
        } else {
            self.scroll.min(self.max_top(height))
        }
    }

    /// The rows a pane of `height` rows shows: the newest ones while following,
    /// otherwise the window at [`Model::scroll`], clamped to the rows that exist.
    #[must_use]
    pub fn visible_rows(&self, height: usize) -> &[ObserverCells] {
        let top = self.top(height);
        let end = (top + height).min(self.rows.len());
        &self.rows[top..end]
    }

    /// Scroll `n` rows towards the oldest; the view stops following.
    pub fn scroll_up(&mut self, n: usize, height: usize) {
        self.scroll = self.top(height).saturating_sub(n);
        self.follow = false;
    }

    /// Scroll `n` rows towards the newest; reaching the newest row resumes
    /// following.
    pub fn scroll_down(&mut self, n: usize, height: usize) {
        let max = self.max_top(height);
        let next = self.top(height).saturating_add(n);
        if next >= max {
            self.follow_end();
        } else {
            self.scroll = next;
            self.follow = false;
        }
    }

    /// Jump to the oldest row.
    pub const fn scroll_top(&mut self) {
        self.scroll = 0;
        self.follow = false;
    }

    /// Track the newest row again.
    pub const fn follow_end(&mut self) {
        self.follow = true;
        self.scroll = 0;
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Synthetic records shared by the crate's tests.
    #![allow(clippy::unwrap_used)]
    use std::time::Duration;

    use ward_events::{
        AgentState, Blake3Hash, Chain, ClaimKind, DeniedDst, DenyReason, DetailText, EventRecord,
        FileChangeKind, HostName, Origin, PayloadText, Pid, PolicySubject, ProcessRef, RuleRef,
        SandboxPath, SandboxRoot, SessionId, SnapshotId, Timestamp, VerifyRequester, VerifySummary,
        WardEvent,
    };

    pub fn by() -> ProcessRef {
        ProcessRef {
            pid: Pid::new(7).unwrap(),
            comm: None,
        }
    }

    pub fn path(rel: &str) -> SandboxPath {
        SandboxPath::new(SandboxRoot::Work, rel).unwrap()
    }

    pub fn edit(rel: &str) -> WardEvent {
        WardEvent::FileModified {
            path: path(rel),
            by: by(),
            kind: FileChangeKind::Write,
        }
    }

    pub fn run_cmd(args: &[&str]) -> WardEvent {
        WardEvent::CommandStarted {
            pid: Pid::new(7).unwrap(),
            parent: Pid::new(1).unwrap(),
            argv: ward_events::BoundedArgv::from_strs(args),
            cwd: path("."),
            exe_digest: None,
        }
    }

    pub fn net(host: &str, decision: ward_events::Decision) -> WardEvent {
        WardEvent::NetworkRequested {
            host: HostName::new(host).unwrap(),
            port: 443,
            decision,
            rule: RuleRef::new("project:network.allow[0]").unwrap(),
            by: by(),
        }
    }

    pub fn net_denied(host: &str) -> WardEvent {
        WardEvent::NetworkDenied {
            dst: DeniedDst::Host {
                host: HostName::new(host).unwrap(),
                port: 443,
            },
            reason: DenyReason::NotAllowlisted,
        }
    }

    pub fn claim() -> WardEvent {
        WardEvent::AgentClaim {
            kind: ClaimKind::Note,
            payload: PayloadText::new("SessionStart"),
        }
    }

    pub fn agent(state: AgentState) -> WardEvent {
        WardEvent::AgentStateChanged { state }
    }

    pub fn snapshot() -> SnapshotId {
        SnapshotId::new(Blake3Hash::from_bytes([0xab; 32]))
    }

    pub fn verify_requested() -> WardEvent {
        WardEvent::VerificationRequested {
            candidate: snapshot(),
            requested_by: VerifyRequester::User,
        }
    }

    fn summary(tests_failed: u64) -> VerifySummary {
        VerifySummary {
            steps_total: 3,
            steps_passed: if tests_failed == 0 { 3 } else { 2 },
            steps_failed: u32::from(tests_failed > 0),
            tests_run: 184,
            tests_failed,
            duration: Duration::from_secs(12),
        }
    }

    pub fn verify_passed() -> WardEvent {
        WardEvent::VerificationPassed {
            candidate: snapshot(),
            summary: summary(0),
            result_hash: Blake3Hash::from_bytes([0x11; 32]),
        }
    }

    pub fn verify_failed() -> WardEvent {
        WardEvent::VerificationFailed {
            candidate: snapshot(),
            summary: summary(3),
            result_hash: Blake3Hash::from_bytes([0x22; 32]),
        }
    }

    pub fn denied() -> WardEvent {
        WardEvent::PolicyDenied {
            subject: PolicySubject::ProtectedTests,
            rule: RuleRef::new("protected-tests").unwrap(),
            detail: DetailText::new("tests/verify.rs"),
        }
    }

    pub fn tamper() -> WardEvent {
        WardEvent::TamperDetected {
            subject: PolicySubject::VerifyConfig,
            detail: DetailText::new(".tamperward/config.yml"),
        }
    }

    pub fn ended() -> WardEvent {
        WardEvent::SessionEnded {
            reason: ward_events::EndReason::UserStop,
            final_snapshot: None,
        }
    }

    /// A chain of synthetic records, one per event, one second apart.
    pub fn records(events: &[(Origin, WardEvent)]) -> Vec<EventRecord> {
        let mut chain = Chain::genesis(SessionId::from_u128(7), Blake3Hash::from_bytes([1; 32]));
        events
            .iter()
            .enumerate()
            .map(|(i, (origin, event))| {
                chain
                    .append(
                        *origin,
                        event.clone(),
                        Timestamp::mono(Duration::from_secs(i as u64)),
                    )
                    .unwrap()
            })
            .collect()
    }

    /// [`records`] with every record from `wardd`.
    pub fn wardd(events: &[WardEvent]) -> Vec<EventRecord> {
        let events: Vec<(Origin, WardEvent)> =
            events.iter().map(|e| (Origin::Wardd, e.clone())).collect();
        records(&events)
    }

    /// The §8 sequence the TUI tests use: two files, two commands, three
    /// network outcomes, one claim, one hidden kind.
    pub fn sequence() -> Vec<WardEvent> {
        use ward_events::Decision;
        vec![
            run_cmd(&["cargo", "test"]),
            edit("src/lib.rs"),
            edit("src/lib.rs"),
            edit("Cargo.toml"),
            net("crates.io", Decision::Allow),
            net("evil.example", Decision::Deny),
            net_denied("10.0.0.1"),
            net("api.example", Decision::Ask),
            claim(),
            agent(AgentState::Working),
            run_cmd(&["ls"]),
        ]
    }

    /// A model that has applied `events` from `wardd`.
    pub fn model_with(events: &[WardEvent], all: bool) -> super::Model {
        let mut model = super::Model::new(all);
        for rec in wardd(events) {
            model.apply(rec);
        }
        model
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::fixtures::*;
    use super::*;
    use ward_daemon::render::Tone;

    #[test]
    fn counters_are_derived_from_records_not_rows() {
        let model = model_with(&sequence(), false);
        assert_eq!(
            model.counters,
            Counters {
                files_changed: 2,
                commands: 2,
                net_allowed: 1,
                net_denied: 2,
                claims: 1,
            }
        );
        assert_eq!(model.records.len(), 11);
        // The hidden kind has no row in the compact view but is still counted.
        assert_eq!(model.rows().len(), 10);
        assert_eq!(
            counters_text(&model.counters),
            "files changed 2 · commands 2 · network 1 allowed / 2 denied · claims 1"
        );

        let all = model_with(&sequence(), true);
        assert_eq!(all.counters, model.counters);
        assert_eq!(all.rows().len(), 11);
        let kind = &all.rows()[9];
        assert_eq!(kind.verb, "agent_state_changed");
        assert_eq!(kind.tone, Tone::Dim);
        assert_eq!(kind.subject, "");
    }

    #[test]
    fn rows_carry_the_line_mode_columns() {
        let model = model_with(&sequence(), false);
        let rows = model.rows();
        assert_eq!(rows[0].time, "00:00");
        assert_eq!((rows[0].verb, rows[0].tone), ("RUN", Tone::Ink));
        assert_eq!(rows[0].subject, "cargo test");
        assert_eq!((rows[4].verb, rows[4].tone), ("NET", Tone::Warn));
        assert_eq!((rows[6].verb, rows[6].tone), ("DENY", Tone::Deny));
        assert_eq!((rows[8].verb, rows[8].tone), ("NOTE", Tone::Dim));
    }

    #[test]
    fn follow_shows_the_newest_rows_and_scrolling_pauses_it() {
        let mut model = model_with(&sequence(), false);
        assert!(model.follow);
        assert_eq!(
            model.visible_rows(3)[2].subject,
            "ls",
            "newest at the bottom"
        );
        assert_eq!(model.top(3), 7);

        model.scroll_up(2, 3);
        assert!(!model.follow);
        assert_eq!(model.top(3), 5);

        // A new record while paused does not move the window.
        model.apply(wardd(&[edit("README.md")]).remove(0));
        assert_eq!(model.top(3), 5);
        assert_eq!(model.rows().len(), 11);

        model.scroll_up(100, 3);
        assert_eq!(model.top(3), 0);
        model.scroll_down(1, 3);
        assert_eq!(model.top(3), 1);
        model.scroll_down(100, 3);
        assert!(model.follow);
        model.scroll_top();
        assert_eq!(model.top(3), 0);
        model.follow_end();
        assert_eq!(model.top(3), 8);

        let empty = Model::new(false);
        assert!(empty.visible_rows(5).is_empty());
        assert_eq!(empty.top(5), 0);
    }

    #[test]
    fn state_follows_agent_verification_and_tamperward_records() {
        let mut model = Model::new(false);
        assert_eq!(model.state, SessionState::default());
        assert_eq!(model.state.agent, None);

        for rec in wardd(&[agent(AgentState::Working), verify_requested()]) {
            model.apply(rec);
        }
        assert_eq!(model.state.agent, Some(AgentState::Working));
        assert_eq!(model.state.verification, Verification::Running);
        assert_eq!(
            model.state.tamperward,
            TamperWard::Unknown,
            "wardd is not TamperWard"
        );

        model.apply(wardd(&[verify_failed()]).remove(0));
        assert_eq!(model.state.verification, Verification::Failed);
        model.apply(wardd(&[verify_passed()]).remove(0));
        assert_eq!(model.state.verification, Verification::Passed);

        // A denial from TamperWard is the system handling it: TW stays clean.
        model.apply(records(&[(Origin::TamperWard, denied())]).remove(0));
        assert_eq!(model.state.tamperward, TamperWard::Clean);
        model.apply(records(&[(Origin::TamperWard, tamper())]).remove(0));
        assert_eq!(model.state.tamperward, TamperWard::Tampered);
        // Later evidence never downgrades a detection.
        model.apply(records(&[(Origin::TamperWard, denied())]).remove(0));
        assert_eq!(model.state.tamperward, TamperWard::Tampered);

        model.apply(wardd(&[agent(AgentState::Finished), ended()]).remove(0));
        assert_eq!(model.state.agent, Some(AgentState::Finished));
        assert!(!model.sealed);
        model.seal();
        assert!(model.sealed);
    }
}
