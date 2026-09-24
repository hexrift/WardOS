//! The observer feed: the agent activity panel of `docs/design-language.md` §8
//! and the state a session's records add up to.
//!
//! [`Model`] holds the records, the status-line counters
//! (`docs/event-model.md` §8), the follow/scroll state and the seal transition;
//! [`SessionState`] is the part of it the trust bar reads (agent state,
//! verification verdict, TamperWard's presence). Both are derived from records as
//! they arrive, never from rendered rows. The one input that is not a record is
//! the worktree's digest ([`Model::observe_worktree`]), supplied by a viewer
//! that can read the worktree so a verdict is shown only while it still
//! describes the tree (ADR-0019).

use std::collections::BTreeSet;
use std::time::Duration;

use ward_daemon::render::{self, ObserverCells};
use ward_events::{
    AgentState, Decision, EventRecord, Origin, SnapshotId, VerifySummary, WardEvent,
};

use crate::trust::VerifyState;

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

/// Where the verification phase (`docs/design-language.md` §11) stands, as the
/// stream says it: which candidate it concerns, and for a verdict what the
/// verifier found. Whether that verdict still describes the worktree is the
/// trust bar's question ([`VerifyState`](crate::trust::VerifyState)).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Verification {
    /// No verification has been requested in this session.
    #[default]
    NotRun,
    /// An attempt was allocated (`VerificationAttemptStarted`) and is preparing:
    /// no candidate has been captured yet (#139). Moves to [`Self::Running`] once
    /// capture succeeds, or straight to a terminal state if preparation ends it.
    Preparing,
    /// Requested or started; the trusted verifier is running on this candidate.
    Running(SnapshotId),
    /// The last verification passed: `✓ VERIFIED`.
    Passed(Verdict),
    /// The last verification failed.
    Failed(Verdict),
    /// The trusted command was killed at its `verify.budget_secs` before it
    /// finished (#139): no verdict on the tests either way, so distinct from
    /// [`Self::Failed`]. Its `Verdict` holds whatever the runner reported
    /// before it was killed.
    TimedOut(Verdict),
    /// The last attempt on this candidate could not run to a pass/fail result: an
    /// infrastructure error (the sandbox runtime failed to launch, a preparation
    /// step failed, …), never the trusted command itself exiting non-zero (#139).
    /// Carries only the candidate, like [`Verification::Failed`]'s bar segment
    /// does not carry its `Verdict`'s summary either — the reason text is a
    /// property of the `VerificationErrored` record, shown on its observer row,
    /// not of this aggregated state.
    Errored(SnapshotId),
    /// The last attempt was cancelled by the user before it reached a pass/fail
    /// result (#139) — distinct from [`Self::Errored`] (an infrastructure
    /// failure) and from [`Self::Failed`] (the trusted command ran and exited
    /// non-zero). `None` when the attempt was cancelled before a candidate was
    /// even captured.
    Cancelled(Option<SnapshotId>),
    /// The last attempt was reconciled as interrupted: the process that had been
    /// running it (a session daemon, or a daemonless `ward` invocation) ended —
    /// crashed, was killed, or was restarted — before the attempt reached a
    /// terminal result (#139). `None` when no candidate had been captured yet.
    Interrupted(Option<SnapshotId>),
}

impl Verification {
    /// The candidate the phase concerns, once there is one.
    #[must_use]
    pub const fn candidate(&self) -> Option<SnapshotId> {
        match self {
            Self::NotRun | Self::Preparing => None,
            Self::Running(c) | Self::Errored(c) => Some(*c),
            Self::Passed(v) | Self::Failed(v) | Self::TimedOut(v) => Some(v.candidate),
            Self::Cancelled(c) | Self::Interrupted(c) => *c,
        }
    }
}

/// What a verdict record said: the candidate it judged, when (session time),
/// the test counts, and how many protected files the verifier restored from
/// the entry snapshot because the worktree's copy differed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The candidate snapshot the verifier judged.
    pub candidate: SnapshotId,
    /// When the verdict was recorded, as time since the session started.
    pub at: Duration,
    /// The verifier's counts.
    pub summary: VerifySummary,
    /// Protected files taken from the entry snapshot instead of the worktree.
    pub restored: u32,
}

/// The worktree as the shell last digested it (ADR-0019 decision 1): the one
/// input to the trust bar that is not a record. Only the shell, which can read
/// the worktree, supplies it; `ward watch` never does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Worktree {
    /// The id the worktree would get if captured now.
    pub digest: SnapshotId,
    /// Manifest entries that differ from the verified candidate, when the shell
    /// could compare (a stored candidate manifest, and a digest that differs).
    pub changes: Option<u64>,
}

/// Whether the current worktree freshness is known (#136). Separates a
/// *reading* viewer that has, or has not, a current successful digest from a
/// viewer that never reads the worktree at all (`ward watch`), so a green
/// verdict is only ever shown for a tree that was actually observed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Freshness {
    /// This viewer does not read the worktree (e.g. `ward watch`): the recorded
    /// verdict stands as history, unqualified by freshness.
    #[default]
    NotObserving,
    /// A reading viewer's last digest succeeded; [`Model::worktree`] is current.
    Fresh,
    /// A reading viewer's last digest attempt failed (unreadable, removed or
    /// interrupted): freshness cannot be asserted, so green is withdrawn.
    Unavailable,
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
    /// The agent's last reported coarse state, once it has reported one; `Paused`
    /// while the host holds the session (ADR-0019 §3), or `PauseUnsettled` while
    /// held by a freeze the host could not yet confirm settled (#145 items 3-4,
    /// PR #207 review finding 1) — the two are never conflated.
    pub agent: Option<AgentState>,
    /// The verification phase.
    pub verification: Verification,
    /// TamperWard's presence and verdict.
    pub tamperward: TamperWard,
    /// `restore …` steps of the verification in progress, for its verdict.
    restored: u32,
    /// What the agent said last before the host paused it, restored on resume.
    before_pause: Option<AgentState>,
}

impl SessionState {
    /// Account for one record.
    pub fn apply(&mut self, rec: &EventRecord) {
        match &rec.event {
            WardEvent::AgentStateChanged { state } => self.agent = Some(*state),
            WardEvent::SessionPaused { .. } => {
                self.before_pause = self.agent;
                self.agent = Some(AgentState::Paused);
            }
            // PR #207 review finding 1: the daemon now appends this *instead of*
            // `SessionPaused` whenever the freeze could not be confirmed settled —
            // never both — so the trust bar must derive a state distinct from a
            // confirmed `Paused` here too, not just at the log/render/replay layer.
            // Deriving `Paused` from this record (as an earlier revision of this
            // fix did, by leaving it unhandled and falling through to `_ => {}`,
            // which simply kept whatever `self.agent` already was) is exactly the
            // false-confirmation bug #145 is about.
            WardEvent::SessionPauseUnsettled { .. } => {
                self.before_pause = self.agent;
                self.agent = Some(AgentState::PauseUnsettled);
            }
            // #145 item 5: a `ward stop` the daemon refused because it could not
            // confirm every sandboxed process ended leaves the session held
            // paused over what is still there — unconfirmed, exactly the state
            // an unsettled pause is, and never a clean `Paused` or `Finished`.
            // A confirmed stop (`pending == 0`) changes nothing here: its
            // `SessionEnded` follows at once.
            WardEvent::WorkloadsTerminated { pending, .. } if *pending > 0 => {
                if !matches!(
                    self.agent,
                    Some(AgentState::Paused | AgentState::PauseUnsettled)
                ) {
                    self.before_pause = self.agent;
                }
                self.agent = Some(AgentState::PauseUnsettled);
            }
            WardEvent::SessionResumed { .. } => {
                self.agent = self.before_pause;
                self.before_pause = None;
            }
            WardEvent::VerificationAttemptStarted { .. } => {
                self.verification = Verification::Preparing;
                self.restored = 0;
            }
            WardEvent::VerificationRequested { candidate, .. }
            | WardEvent::VerificationStarted { candidate, .. } => {
                self.verification = Verification::Running(*candidate);
                self.restored = 0;
            }
            WardEvent::VerificationProgress { step, .. } => {
                if step.as_str().starts_with("restore ") {
                    self.restored += 1;
                }
            }
            WardEvent::VerificationPassed {
                candidate, summary, ..
            } => self.verification = Verification::Passed(self.verdict(rec, *candidate, *summary)),
            WardEvent::VerificationFailed {
                candidate, summary, ..
            } => self.verification = Verification::Failed(self.verdict(rec, *candidate, *summary)),
            WardEvent::VerificationTimedOut {
                candidate, summary, ..
            } => {
                self.verification = Verification::TimedOut(self.verdict(rec, *candidate, *summary));
            }
            WardEvent::VerificationErrored { candidate, .. } => {
                self.verification = Verification::Errored(*candidate);
            }
            WardEvent::VerificationCancelled { candidate, .. } => {
                self.verification = Verification::Cancelled(*candidate);
            }
            WardEvent::VerificationInterrupted { candidate, .. } => {
                self.verification = Verification::Interrupted(*candidate);
            }
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

    const fn verdict(
        &self,
        rec: &EventRecord,
        candidate: SnapshotId,
        summary: VerifySummary,
    ) -> Verdict {
        Verdict {
            candidate,
            at: rec.ts_mono,
            summary,
            restored: self.restored,
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
    /// The worktree as last *successfully* digested, when the viewer can read it.
    /// A failed later read does not clear this history; [`Model::freshness`] says
    /// whether it still describes the tree.
    pub worktree: Option<Worktree>,
    /// Whether [`Model::worktree`] is a current observation, a stale/failed one,
    /// or absent because this viewer never reads the worktree (#136).
    pub freshness: Freshness,
    /// Observation generation: bumped whenever freshness is invalidated, so a
    /// digest that began before the invalidation cannot restore green after it.
    obs_gen: u64,
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
            worktree: None,
            freshness: Freshness::NotObserving,
            obs_gen: 0,
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

    /// The worktree digests to `digest` now, with `changes` manifest entries
    /// differing from the verified candidate where that could be counted. The
    /// trust bar compares this with the candidate the stream verified. Marks the
    /// observation fresh (a reading viewer with a current digest).
    pub const fn observe_worktree(&mut self, digest: SnapshotId, changes: Option<u64>) {
        self.worktree = Some(Worktree { digest, changes });
        self.freshness = Freshness::Fresh;
    }

    /// The generation to capture before a (possibly slow) digest, so its result
    /// can be discarded if freshness was invalidated in the meantime (#136).
    #[must_use]
    pub const fn observation_gen(&self) -> u64 {
        self.obs_gen
    }

    /// Apply a completed digest only if no invalidation has happened since the
    /// read began (`gen` from [`Model::observation_gen`]). A late result that
    /// lost the race is dropped, so it cannot restore green over a newer change.
    pub const fn observe_if_current(
        &mut self,
        generation: u64,
        digest: SnapshotId,
        changes: Option<u64>,
    ) {
        if generation == self.obs_gen {
            self.observe_worktree(digest, changes);
        }
    }

    /// The reading viewer could not digest the worktree: withdraw the current
    /// (green) freshness while keeping the historical verdict and last digest.
    /// Applied only if no invalidation has happened since the read began
    /// (`generation` from [`Model::observation_gen`]), mirroring
    /// [`Model::observe_if_current`] — a late *failure* that lost the race must
    /// not clobber a newer, already-applied success back to unavailable (#136).
    pub const fn mark_freshness_unavailable(&mut self, generation: u64) {
        if generation == self.obs_gen {
            self.freshness = Freshness::Unavailable;
        }
    }

    /// A worktree change invalidates freshness at once and bumps the generation,
    /// so a digest that began earlier cannot restore green after it (#136).
    pub const fn invalidate_freshness(&mut self) {
        self.obs_gen = self.obs_gen.wrapping_add(1);
        self.freshness = Freshness::Unavailable;
    }

    /// The verify segment's state: the stream's verdict held against the
    /// observed worktree and whether that observation is current (#136).
    #[must_use]
    pub const fn verify_state(&self) -> VerifyState {
        let worktree = match self.worktree {
            Some(w) => Some(w.digest),
            None => None,
        };
        VerifyState::of(&self.state.verification, worktree, self.freshness)
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

    pub fn paused() -> WardEvent {
        WardEvent::SessionPaused {
            method: ward_events::PauseMethod::Sigstop,
            reason: ward_events::ShortText::new("looks wrong"),
        }
    }

    pub fn pause_unsettled() -> WardEvent {
        WardEvent::SessionPauseUnsettled {
            method: ward_events::PauseMethod::Sigstop,
            reason: ward_events::ShortText::new("looks wrong"),
            pending: 2,
        }
    }

    pub fn resumed() -> WardEvent {
        WardEvent::SessionResumed {
            paused_for: Duration::from_secs(12),
        }
    }

    pub fn snapshot() -> SnapshotId {
        SnapshotId::new(Blake3Hash::from_bytes([0xab; 32]))
    }

    /// What a worktree digests to once it differs from [`snapshot`].
    pub fn edited() -> SnapshotId {
        SnapshotId::new(Blake3Hash::from_bytes([0xcd; 32]))
    }

    pub fn verify_progress(step: &str) -> WardEvent {
        WardEvent::VerificationProgress {
            step: ward_events::ShortText::new(step),
            status: ward_events::StepStatus::Pass,
        }
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

    pub fn verify_errored() -> WardEvent {
        WardEvent::VerificationErrored {
            candidate: snapshot(),
            reason: ward_events::ShortText::new("sandbox: bubblewrap (bwrap) is not installed"),
        }
    }

    pub fn verify_timed_out() -> WardEvent {
        WardEvent::VerificationTimedOut {
            attempt: ward_events::AttemptId::new(1),
            candidate: snapshot(),
            summary: VerifySummary {
                steps_total: 1,
                steps_passed: 0,
                steps_failed: 1,
                tests_run: 40,
                tests_failed: 0,
                duration: Duration::from_secs(600),
            },
            result_hash: Blake3Hash::from_bytes([0x33; 32]),
            budget_secs: 600,
        }
    }

    pub fn verify_attempt_started() -> WardEvent {
        WardEvent::VerificationAttemptStarted {
            attempt: ward_events::AttemptId::new(1),
            requested_by: VerifyRequester::User,
        }
    }

    pub fn verify_cancelled() -> WardEvent {
        WardEvent::VerificationCancelled {
            attempt: ward_events::AttemptId::new(1),
            candidate: Some(snapshot()),
        }
    }

    pub fn verify_cancelled_before_capture() -> WardEvent {
        WardEvent::VerificationCancelled {
            attempt: ward_events::AttemptId::new(1),
            candidate: None,
        }
    }

    pub fn verify_interrupted() -> WardEvent {
        WardEvent::VerificationInterrupted {
            attempt: ward_events::AttemptId::new(1),
            candidate: Some(snapshot()),
            reason: ward_events::ShortText::new(
                "the process serving this session ended before the attempt reached a terminal result",
            ),
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
    #![allow(clippy::unwrap_used, clippy::panic)]
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
        assert_eq!(model.state.verification, Verification::Running(snapshot()));
        assert_eq!(model.state.verification.candidate(), Some(snapshot()));
        assert_eq!(
            model.state.tamperward,
            TamperWard::Unknown,
            "wardd is not TamperWard"
        );

        // Two protected files restored, then the verdict: the verdict carries
        // the candidate the record names, the record's session time, the
        // counts and the restore count.
        for rec in wardd(&[
            verify_progress("restore tests/security_expiry.rs"),
            verify_progress("restore tests/other.rs"),
            verify_progress("cargo test"),
            verify_failed(),
        ]) {
            model.apply(rec);
        }
        let Verification::Failed(failed) = model.state.verification else {
            panic!("{:?}", model.state.verification);
        };
        assert_eq!(failed.candidate, snapshot());
        assert_eq!(failed.at, Duration::from_secs(3), "the record's time");
        assert_eq!(failed.summary.tests_failed, 3);
        assert_eq!(failed.restored, 2);

        // The next run starts its own count.
        for rec in wardd(&[verify_requested(), verify_passed()]) {
            model.apply(rec);
        }
        let Verification::Passed(passed) = model.state.verification else {
            panic!("{:?}", model.state.verification);
        };
        assert_eq!(passed.candidate, snapshot());
        assert_eq!(passed.summary.tests_run, 184);
        assert_eq!(passed.restored, 0);
        assert_eq!(model.state.verification.candidate(), Some(snapshot()));
        assert_eq!(Verification::NotRun.candidate(), None);

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

    /// #139: a verification attempt that could not run to a pass/fail result (an
    /// infrastructure error after `VerificationStarted`) must land in a state that
    /// is neither "still running" nor "tests failed".
    #[test]
    fn an_errored_attempt_is_neither_running_nor_failed() {
        let mut model = Model::new(false);
        for rec in wardd(&[verify_requested()]) {
            model.apply(rec);
        }
        assert_eq!(model.state.verification, Verification::Running(snapshot()));

        model.apply(wardd(&[verify_errored()]).remove(0));
        assert_eq!(model.state.verification, Verification::Errored(snapshot()));
        assert_eq!(model.state.verification.candidate(), Some(snapshot()));
        assert_ne!(
            model.state.verification,
            Verification::Running(snapshot()),
            "an errored attempt must not still read as running"
        );
        assert!(
            !matches!(model.state.verification, Verification::Failed(_)),
            "an infra error must not be presented as a test failure"
        );
        assert!(
            !matches!(model.state.verification, Verification::Passed(_)),
            "an infra error must never be presented as a pass"
        );

        // A retry after an error runs and can still pass: the error does not stick.
        for rec in wardd(&[verify_requested(), verify_passed()]) {
            model.apply(rec);
        }
        let Verification::Passed(passed) = model.state.verification else {
            panic!("{:?}", model.state.verification);
        };
        assert_eq!(passed.candidate, snapshot());
    }

    /// #139: a user-cancelled attempt reads as its own state, neither running,
    /// failed, nor errored. `VerificationAttemptStarted` on its own moves the
    /// phase to `Preparing` — progress from the attempt's first action, with no
    /// candidate yet.
    #[test]
    fn a_cancelled_attempt_is_its_own_state_not_running_failed_or_errored() {
        let mut model = Model::new(false);
        assert_eq!(model.state.verification, Verification::NotRun);

        model.apply(wardd(&[verify_attempt_started()]).remove(0));
        assert_eq!(
            model.state.verification,
            Verification::Preparing,
            "the earliest attempt signal shows the attempt preparing"
        );
        assert_eq!(model.state.verification.candidate(), None);

        for rec in wardd(&[verify_requested()]) {
            model.apply(rec);
        }
        model.apply(wardd(&[verify_cancelled()]).remove(0));
        assert_eq!(
            model.state.verification,
            Verification::Cancelled(Some(snapshot()))
        );
        assert_eq!(model.state.verification.candidate(), Some(snapshot()));
        assert_ne!(model.state.verification, Verification::Running(snapshot()));
        assert!(!matches!(model.state.verification, Verification::Failed(_)));
        assert!(!matches!(
            model.state.verification,
            Verification::Errored(_)
        ));

        // Cancelled before a candidate was even captured: no candidate to show.
        model.apply(wardd(&[verify_attempt_started()]).remove(0));
        model.apply(wardd(&[verify_cancelled_before_capture()]).remove(0));
        assert_eq!(model.state.verification, Verification::Cancelled(None));
        assert_eq!(model.state.verification.candidate(), None);

        // A retry after a cancel runs and can still pass: the cancel does not stick.
        for rec in wardd(&[verify_requested(), verify_passed()]) {
            model.apply(rec);
        }
        assert!(matches!(model.state.verification, Verification::Passed(_)));
    }

    /// #139: a reconciled, interrupted attempt (the daemon or process that had
    /// been running it disappeared) reads as its own state too — never as a
    /// silent "still running".
    #[test]
    fn an_interrupted_attempt_is_its_own_state_not_running() {
        let mut model = Model::new(false);
        for rec in wardd(&[verify_requested(), verify_interrupted()]) {
            model.apply(rec);
        }
        assert_eq!(
            model.state.verification,
            Verification::Interrupted(Some(snapshot()))
        );
        assert_ne!(model.state.verification, Verification::Running(snapshot()));
    }

    /// #139: an attempt allocated after an earlier pass shows `Preparing`, not the
    /// earlier verdict, until its own candidate is captured.
    #[test]
    fn a_new_attempt_leaves_the_previous_verdict_while_preparing() {
        let mut model = Model::new(false);
        for rec in wardd(&[verify_requested(), verify_passed()]) {
            model.apply(rec);
        }
        assert!(matches!(model.state.verification, Verification::Passed(_)));
        model.apply(wardd(&[verify_attempt_started()]).remove(0));
        assert_eq!(model.state.verification, Verification::Preparing);
        model.apply(wardd(&[verify_requested()]).remove(0));
        assert_eq!(model.state.verification, Verification::Running(snapshot()));
    }

    /// #139 item 1: a verifier killed at its budget reads as its own state,
    /// carrying the partial counts, and is never a test failure or a pass.
    #[test]
    fn a_timed_out_attempt_is_its_own_state_not_failed() {
        let mut model = Model::new(false);
        for rec in wardd(&[
            verify_attempt_started(),
            verify_requested(),
            verify_timed_out(),
        ]) {
            model.apply(rec);
        }
        let Verification::TimedOut(verdict) = model.state.verification else {
            panic!("expected TimedOut, got {:?}", model.state.verification);
        };
        assert_eq!(verdict.candidate, snapshot());
        assert_eq!(verdict.summary.tests_run, 40);
        assert_eq!(model.state.verification.candidate(), Some(snapshot()));
        assert!(!matches!(model.state.verification, Verification::Failed(_)));
        assert!(!matches!(model.state.verification, Verification::Passed(_)));
    }

    /// #145 items 3-4, PR #207 review finding 1: the daemon now appends
    /// `SessionPauseUnsettled` *instead of* `SessionPaused` whenever the freeze
    /// could not be confirmed settled, so `SessionState::apply` must derive a
    /// state distinct from a confirmed `Paused` for it too — an earlier revision
    /// of this fix left the record unhandled here, which simply kept whatever
    /// `self.agent` already was and let the trust bar keep showing a stale,
    /// unrelated state (or nothing at all) rather than the actual, uncertain
    /// pause — the same false-confirmation gap #145 is about, just moved one
    /// layer up from the log to the desktop's own consumer of it.
    #[test]
    fn an_unsettled_pause_is_distinct_from_a_confirmed_one_and_resume_restores_the_prior_state() {
        let mut model = Model::new(false);
        for rec in wardd(&[agent(AgentState::Working)]) {
            model.apply(rec);
        }
        assert_eq!(model.state.agent, Some(AgentState::Working));

        model.apply(wardd(&[pause_unsettled()]).remove(0));
        assert_eq!(
            model.state.agent,
            Some(AgentState::PauseUnsettled),
            "never `Paused` — that would be the exact false confirmation #145 is about"
        );
        assert_ne!(model.state.agent, Some(AgentState::Paused));

        model.apply(wardd(&[resumed()]).remove(0));
        assert_eq!(
            model.state.agent,
            Some(AgentState::Working),
            "resume restores what the agent said last before the (unsettled) pause"
        );
    }

    /// #145 item 5: a refused stop (`WorkloadsTerminated { pending > 0 }`)
    /// leaves the session held paused and unconfirmed — the bar must say so,
    /// whether the session was running or already paused, and resume must
    /// still restore what the agent said before either. A confirmed stop
    /// changes nothing by itself: its `SessionEnded` follows.
    #[test]
    fn a_refused_stop_reads_as_an_unconfirmed_pause_and_a_confirmed_one_changes_nothing() {
        let refused = || WardEvent::WorkloadsTerminated {
            ended: 2,
            pending: 1,
        };
        let mut model = Model::new(false);
        for rec in wardd(&[agent(AgentState::Working)]) {
            model.apply(rec);
        }
        model.apply(
            wardd(&[WardEvent::WorkloadsTerminated {
                ended: 3,
                pending: 0,
            }])
            .remove(0),
        );
        assert_eq!(model.state.agent, Some(AgentState::Working));

        model.apply(wardd(&[refused()]).remove(0));
        assert_eq!(model.state.agent, Some(AgentState::PauseUnsettled));
        model.apply(wardd(&[resumed()]).remove(0));
        assert_eq!(model.state.agent, Some(AgentState::Working));

        // From a confirmed pause: the refused stop downgrades it to unconfirmed,
        // and a resume still restores the state from before the pause, not
        // `Paused`.
        model.apply(wardd(&[paused()]).remove(0));
        model.apply(wardd(&[refused()]).remove(0));
        assert_eq!(model.state.agent, Some(AgentState::PauseUnsettled));
        model.apply(wardd(&[resumed()]).remove(0));
        assert_eq!(model.state.agent, Some(AgentState::Working));
    }
}
