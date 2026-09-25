//! The desktop's session registry (#141 item 1): every live session's
//! shared, host-derived facts — project, agent, run state, pending-approval
//! count and last verification outcome — read fresh in one call instead of
//! each desktop surface independently reconnecting to every live session and
//! re-deriving the same handful of answers its neighbour just computed
//! slightly differently (or not at all).
//!
//! [`crate::selection`] is the other half of item 1: it says *which* session
//! is the desktop's current explicit choice. This module says what is true
//! of *every* live one, so a future bar/panel/switcher (#141 items 2-5, not
//! this change) has exactly one place to read both from. [`snapshot`] hands
//! back both together in one [`Registry`], because a caller almost always
//! wants "the candidates" and "which one is picked" in the same breath —
//! `ward-shell switcher` (`desktop/shell/src/main.rs`, landed by #210) reads
//! them the same way today, just inline in a desktop binary instead of
//! through a documented, reusable, host-owned API; wiring that binary to
//! this module instead is item 2's job, not this change's.
//!
//! ## Why this derives instead of maintaining a second copy
//!
//! Every fact a [`RegistryEntry`] carries already lives somewhere: the
//! project and agent are [`crate::describe::SessionDescription`]'s immutable
//! facts; whether a session is live at all is
//! [`crate::daemon::live_sessions`]'s directory scan; the pending-approval
//! count is the same [`crate::control::Request::Pending`] answer
//! `ward session pending` already gets; and the run/verification state is
//! exactly what the `ward-shell-core` crate's `SessionState::apply`
//! (`feed.rs`) already derives from a session's own event log for the bar and
//! the switcher, just re-derived here from the same records instead of imported
//! from that crate — `ward-shell-core` depends on `ward-daemon`, not the
//! other way around, so this crate cannot borrow its projection even though
//! the two amount to the same handful of `match` arms over the same events.
//! [`snapshot`] therefore never persists a parallel copy of any of this: it
//! opens a fresh connection to each live session, asks the same questions
//! `describe`/`pending` already answer, and replays the same event log a
//! subscriber already would — so there is nothing here that can drift out of
//! sync with the session it describes, only ever a snapshot of one moment
//! that a concurrent change (a new approval, a pause, a session ending) can
//! immediately make stale, exactly as `switcher()`'s equivalent snapshot
//! already can today. A caller that needs to notice such a change makes
//! another call; nothing here claims to push one.
//!
//! ## "Notified over the existing lifecycle-notification channel" (#138)
//!
//! Item 1 asks for registry changes to be "notified over the existing
//! lifecycle-notification channel" rather than left to be separately
//! rediscovered by whichever surface cares. There is no single desktop-wide
//! push channel today for that — #138 (still open) is exactly the issue
//! about building a shared subscription/cache layer across sessions — so
//! this module wires into the two mechanisms that *do* already exist and
//! already play that role for the surfaces #210 shipped, rather than
//! inventing a third:
//!
//! - **A session already known to a caller**: its own event log, over
//!   [`crate::control::Request::Subscribe`] ([`crate::client::catch_up`]) —
//!   the `SessionStarted`/`SessionEnded`/`AgentStateChanged`/`SessionPaused`/
//!   `SessionResumed`/`Verification*` records `event.rs` labels "-- lifecycle
//!   (origin: Wardd) --" and its verification section, the same stream
//!   [`snapshot`]'s own per-entry replay below reads. A caller already
//!   watching one of those (`wardos-approve --watch`'s per-session watcher,
//!   a future bar segment) learns of a change to that session the moment the
//!   record for it arrives, with no extra hook needed: re-run [`snapshot`],
//!   or update just the one entry, whichever it already does for its other
//!   per-session state.
//! - **A session not yet known to a caller** (a new one started, or one that
//!   ended): [`crate::daemon::live_sessions`]'s directory scan, on the same
//!   bounded rediscovery rhythm [`crate::client::follow_pending_all`]
//!   already established for exactly this (`REDISCOVER`, 30s) — a fixed
//!   poll, not push, because session directories appearing and disappearing
//!   is not itself an event any log can carry (the log that would carry it
//!   is the thing being discovered). [`snapshot`] does this same scan on
//!   every call, so a caller that re-invokes it on that rhythm (as
//!   `follow_pending_all` already does for approvals) sees new and gone
//!   sessions on the same schedule, with nothing new to wire up.
//!
//! Binding a specific desktop surface to either rhythm is item 2's work
//! (`ward-shell`'s bar/panels) and item 4's (`wardos-approve`'s multiplexed
//! discovery already does, for approvals specifically) — this module only
//! makes the combined answer available as one documented call so that
//! wiring has something correct to bind to.
//!
//! ## Verification: last outcome, not qualified freshness
//!
//! (Review 5306729614 of #254, finding 2.)
//!
//! [`VerificationState`] is honestly scoped to what a session's own event log
//! can answer unqualified: what the *last* attempt concluded, and against
//! which candidate. It never compares that candidate against the *current*
//! worktree digest, so [`VerificationState::Passed`] does not by itself mean
//! "the workspace right now matches what passed" — only "the last attempt,
//! whenever it ran, passed". That qualification is `ward-shell-core::feed::
//! Freshness`'s job (a live viewer's own worktree digest, #138 items 2-3),
//! deliberately not redone here (see "Why this derives" above for the crate-
//! dependency reason it cannot even be imported).
//!
//! The issue text this PR implements lists "verification freshness" among
//! item 1's facts, and an earlier draft of this PR's own tracking comment
//! (issue #141, comment 5817293723) repeated that phrase for what this
//! module delivers; that overstated it, and has been corrected there. What
//! this module actually delivers, and all it claims to, is the *last
//! verification outcome* — [`VerificationState`]'s own doc comment above is
//! the source of truth, not the issue's shorthand. Actually qualifying that
//! outcome against a live worktree digest, shared through the #138 boundary
//! so every consumer stops redoing the same per-viewer digest work, is left
//! to a follow-up (naturally #138 or a #141 item built on it) rather than
//! folded into this PR, which is scoped to item 1's registry-and-selection
//! primitive, not item 1's superset of every reasonable reading of "freshness".
//!
//! ## Consistency: a snapshot is not one instant (review 5306729614 of #254)
//!
//! [`snapshot`] is not a transaction. [`Registry::selection`] is read from
//! `<state>/desktop-selection.json`; each [`RegistryEntry`]'s `project`/
//! `agent` come from one `Describe` call, its `pending_approvals` from a
//! second call on the *same* connection made microseconds later, and its
//! `agent_state`/`verification` from a bounded replay on a *third*, separate
//! connection opened after both — four reads, at four different times, none
//! coordinated with any other, and none coordinated across sessions either
//! (`entries` is built one session at a time). Nothing here takes a lock,
//! holds a consistent read snapshot, or retries to make these agree: a pause,
//! a new approval, or a verification landing between any two of those reads
//! is not just possible but ordinary, and the [`Registry`] returned can
//! combine facts that were never simultaneously true of the live system —
//! same as `ward-shell switcher`'s own equivalent, pre-existing reads do
//! today. This is adequate for what item 1 asks this module to be: a shared,
//! correct-per-field *read* API replacing several ad hoc ones. It is **not**
//! adequate, on its own, as the foundation for binding a correctness-bearing
//! action (item 3: pause/stop) to a stale combination of fields read at
//! different times — a future PR doing that must either re-verify the
//! specific fact it depends on immediately before acting (the way `pause`
//! already takes a fresh connection and lets the daemon be the authority) or
//! add real cross-field consistency here first. This paragraph is that flag,
//! not a mechanism.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use ward_events::{AgentState, EventRecord, SnapshotId, WardEvent};

use crate::client::{self, WatchEnd, catch_up};
use crate::control::SOCKET_NAME;
use crate::daemon;
use crate::describe::AgentDescription;
use crate::error::Error;
use crate::selection::{self, Selection};
use crate::session::{SessionMeta, session_dir};

/// How long [`snapshot`] waits for a session's backlog to settle before
/// treating its projection as current (`WatchEnd::CaughtUp`, #138 item 1):
/// the same default `ward-shell` already uses for its own equivalent reads
/// (`desktop/shell/src/main.rs`'s `SETTLE_MS`), kept here too so a caller
/// that has no opinion of its own gets the value this repo has already
/// tuned, rather than picking a new one.
pub const DEFAULT_SETTLE: Duration = Duration::from_millis(250);

/// The last verification attempt's outcome for one session, as its own event
/// log records it — never re-derived against the current worktree (that
/// requires a reading viewer to actually digest it, a per-viewer cost #138
/// items 2-3 are about sharing/bounding, not this module's job to redo for
/// every registry read). A consumer that also has a current worktree digest
/// (a bar segment, `ward-shell-core`'s `Freshness`) still needs to qualify
/// [`Self::Passed`] against it itself, exactly as `TrustBar` does today; what
/// this records is the daemon's own unqualified fact: what the last attempt
/// on this session concluded, and against which candidate snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationState {
    /// No verification attempt has been made yet this session.
    #[default]
    NeverRun,
    /// An attempt is in flight: requested, preparing, capturing, restoring or
    /// running the verifier, with no terminal record yet.
    Running,
    /// The last attempt passed.
    Passed {
        /// The candidate snapshot it verified.
        candidate: SnapshotId,
        /// When the terminal record landed, milliseconds since the Unix epoch.
        at_unix_ms: u64,
    },
    /// The last attempt's verifier ran to completion and reported failures.
    Failed {
        /// The candidate snapshot it verified.
        candidate: SnapshotId,
        /// When the terminal record landed, milliseconds since the Unix epoch.
        at_unix_ms: u64,
    },
    /// The last attempt exhausted its time budget before finishing.
    TimedOut {
        /// The candidate snapshot it verified.
        candidate: SnapshotId,
        /// When the terminal record landed, milliseconds since the Unix epoch.
        at_unix_ms: u64,
    },
    /// The last attempt could not run at all (infrastructure failure, not a
    /// test result) once a candidate had already been captured.
    Errored {
        /// The candidate snapshot the attempt concerned.
        candidate: SnapshotId,
        /// When the terminal record landed, milliseconds since the Unix epoch.
        at_unix_ms: u64,
    },
    /// The last attempt was cancelled before reaching a pass/fail result;
    /// `Some` when capture had already succeeded by then.
    Cancelled {
        /// The candidate snapshot, when capture had already succeeded.
        candidate: Option<SnapshotId>,
        /// When the terminal record landed, milliseconds since the Unix epoch.
        at_unix_ms: u64,
    },
    /// The last attempt ended without reaching a candidate-bearing terminal
    /// result at all (a step before capture failed, or the daemon serving it
    /// went away mid-attempt); `Some` when capture had already succeeded.
    Interrupted {
        /// The candidate snapshot, when capture had already succeeded.
        candidate: Option<SnapshotId>,
        /// When the terminal record landed, milliseconds since the Unix epoch.
        at_unix_ms: u64,
    },
}

impl VerificationState {
    /// Fold one record's effect on the verification state, mirroring
    /// `ward_shell_core::feed::SessionState::apply`'s verification arms
    /// (see this module's doc comment for why the projection is
    /// re-implemented here rather than shared with that crate). A
    /// `VerificationProgress` record changes nothing here: the registry
    /// tracks the attempt's terminal outcome, not its step-by-step progress,
    /// which is a bar-segment concern (`docs/design-language.md` §7), not a
    /// registry one.
    fn apply(&mut self, rec: &EventRecord) {
        let at_unix_ms = unix_ms(rec);
        match rec.event {
            WardEvent::VerificationAttemptStarted { .. }
            | WardEvent::VerificationRequested { .. }
            | WardEvent::VerificationStarted { .. } => *self = Self::Running,
            WardEvent::VerificationPassed { candidate, .. } => {
                *self = Self::Passed {
                    candidate,
                    at_unix_ms,
                };
            }
            WardEvent::VerificationFailed { candidate, .. } => {
                *self = Self::Failed {
                    candidate,
                    at_unix_ms,
                };
            }
            WardEvent::VerificationTimedOut { candidate, .. } => {
                *self = Self::TimedOut {
                    candidate,
                    at_unix_ms,
                };
            }
            WardEvent::VerificationErrored { candidate, .. } => {
                *self = Self::Errored {
                    candidate,
                    at_unix_ms,
                };
            }
            WardEvent::VerificationCancelled { candidate, .. } => {
                *self = Self::Cancelled {
                    candidate,
                    at_unix_ms,
                };
            }
            WardEvent::VerificationInterrupted { candidate, .. } => {
                *self = Self::Interrupted {
                    candidate,
                    at_unix_ms,
                };
            }
            _ => {}
        }
    }
}

/// A record's wall-clock time, milliseconds since the Unix epoch, saturating
/// to `0` for the rare record with no wall time at all (informational only
/// — `ts_mono`, not this, orders the chain) rather than panicking or
/// propagating an error for a field the registry only ever displays.
fn unix_ms(rec: &EventRecord) -> u64 {
    rec.ts_wall
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// One live session's shared facts, as [`snapshot`] read them just now —
/// "just now" meaning across several separate reads at several different
/// times, not one instant; see the module doc comment's "Consistency"
/// section before binding a correctness-bearing decision to this.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// Session id (`sess_…`).
    pub session: String,
    /// Canonical project worktree.
    pub project: PathBuf,
    /// The agent identity, when the session recorded one.
    pub agent: Option<AgentDescription>,
    /// The agent's last reported coarse state; `None` when no
    /// `AgentStateChanged` (or pause/resume) record has arrived yet — a
    /// session in the gap between `SessionStarted` and its agent's first
    /// report. See [`Self::running`] for the running/paused distinction
    /// the issue text asks for.
    pub agent_state: Option<AgentState>,
    /// Approvals waiting for an answer right now.
    pub pending_approvals: usize,
    /// The last verification attempt's outcome.
    pub verification: VerificationState,
}

impl RegistryEntry {
    /// The coarse running/paused fact the issue text names: `false` while
    /// the host holds the session paused, confirmed
    /// ([`AgentState::Paused`]) or not yet confirmed settled
    /// ([`AgentState::PauseUnsettled`], #145) — both are "not running" from
    /// a registry consumer's point of view, since approvals are held and no
    /// sandboxed process is scheduled either way; `true` otherwise, including
    /// while nothing has reported yet (`agent_state` is `None`), since a
    /// session with no report at all is not a paused one.
    #[must_use]
    pub const fn running(&self) -> bool {
        !matches!(
            self.agent_state,
            Some(AgentState::Paused | AgentState::PauseUnsettled)
        )
    }
}

/// The desktop's session registry, as of one moment: every live session's
/// facts alongside the explicit [`Selection`] the bar/switcher/panels should
/// treat as current (`crate::selection`, #210). Bundled together because a
/// consumer of this module almost always wants both — "what is there to
/// choose from" and "what is chosen" — in the same read, not two separate
/// calls that could observe two different moments. That said, "the same
/// read" is a convenience for the caller, not a consistency guarantee: see
/// the module doc comment's "Consistency" section — `selection` and every
/// field of every entry are still each read over their own separate
/// connection, at their own separate time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    /// Every session with a live daemon, in [`crate::daemon::live_sessions`]'s
    /// order (newest first).
    pub entries: Vec<RegistryEntry>,
    /// The desktop's current explicit choice, unrelated to this snapshot's
    /// own moment: it can name a session already missing from `entries`
    /// (ended in the gap between reading the selection and finishing this
    /// scan) or none at all yet. A caller deciding what counts as "selected"
    /// checks membership in `entries` itself, the same way
    /// `switcher_label`'s `is_selected` already does.
    pub selection: Selection,
}

impl Registry {
    /// The entry named by [`Self::selection`], when it is still live. `None`
    /// both when nothing is selected and when the selection names a session
    /// that ended before (or during) this snapshot — a caller that needs to
    /// tell those two apart already has `self.selection.session` itself.
    #[must_use]
    pub fn selected(&self) -> Option<&RegistryEntry> {
        let id = self.selection.session.as_deref()?;
        self.entries.iter().find(|e| e.session == id)
    }
}

/// Read the registry fresh: every live session under `state`, each probed on
/// its own connection, plus the desktop's current selection. `settle` bounds
/// how long each session's own catch-up read waits for its backlog to
/// settle before this call moves on ([`DEFAULT_SETTLE`] matches what
/// `ward-shell` already uses for the equivalent single-session read).
///
/// Never fails outright: a session whose record cannot be read, whose
/// daemon does not answer, or whose control connection ends before this
/// finishes probing it is simply left out of [`Registry::entries`] rather
/// than failing the whole read — exactly the degrade [`daemon::live_sessions`]
/// already applies to an unreadable session record, extended to the probe
/// this function adds on top. A session missing this way because it ended in
/// the gap between being listed and being probed is the expected shape of a
/// live system, not a bug to propagate as an error a caller (most of which
/// have no better answer than "try again") is not equipped to handle; a
/// genuine, unexpected failure to read an otherwise-live session is still
/// logged to stderr, the same latitude [`selection::current`] takes for its
/// own read failures and for the identical reason given there.
#[must_use]
pub fn snapshot(state: &Path, settle: Duration) -> Registry {
    let selection = selection::current(state);
    let live = daemon::live_sessions(state).unwrap_or_else(|e| {
        eprintln!(
            "ward: desktop registry: listing live sessions under {}: {e}",
            state.display()
        );
        Vec::new()
    });
    let mut entries = Vec::with_capacity(live.len());
    for meta in &live {
        match entry_for(state, meta, settle) {
            Ok(Some(entry)) => entries.push(entry),
            // The session ended (or its daemon stopped answering) in the gap
            // between `live_sessions` listing it and this probe reaching it
            // — not an error, just a session that is no longer part of this
            // snapshot's moment.
            Ok(None) => {}
            Err(e) => eprintln!(
                "ward: desktop registry: session {} unreadable: {e}",
                meta.id
            ),
        }
    }
    Registry { entries, selection }
}

/// One session's [`RegistryEntry`], or `None` when the session itself is
/// gone (not reachable at all, or its subscription replayed and closed
/// without ever confirming live) by the time this call reaches it — see
/// [`snapshot`]'s doc comment on why that is not an error here. A response
/// [`disconnected`] does not recognise (a malformed reply, or the daemon
/// explicitly refusing a request) is a different thing — a protocol or
/// daemon-side problem on an otherwise-live session — and is propagated as
/// `Err` instead, so [`snapshot`]'s own `eprintln!` on that path (its doc
/// comment already promises this) actually fires rather than the session
/// silently vanishing from the registry indistinguishably from having ended
/// (review 5306729614 of #254, finding 3).
fn entry_for(
    state: &Path,
    meta: &SessionMeta,
    settle: Duration,
) -> crate::error::Result<Option<RegistryEntry>> {
    let socket = session_dir(state, &meta.id).join(SOCKET_NAME);
    let mut sink = match client::connect(&socket) {
        Ok(sink) => sink,
        Err(Error::Project(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    let description = match client::describe(&mut sink) {
        Ok(d) => d,
        Err(e) if disconnected(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    let pending = match client::pending(&mut sink) {
        Ok(p) => p,
        Err(e) if disconnected(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    let pending = pending.len();
    drop(sink);

    // The subscription is served on its own connection, same as every other
    // caller of `catch_up` in this crate (`client.rs`'s own doc comment).
    let subscriber = match client::connect(&socket) {
        Ok(s) => s,
        Err(Error::Project(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut agent_state = None;
    let mut before_pause = None;
    let mut verification = VerificationState::NeverRun;
    let end = catch_up(subscriber, 0, settle, |rec| {
        apply(&rec, &mut agent_state, &mut before_pause, &mut verification);
    })?;

    // Only `CaughtUp` actually proves the session is live: `catch_up` legitimately
    // finishes with `Closed`/`Sealed` instead when the session sealed (ended) in
    // the gap between `describe`/`pending` above and this subscribe reaching it —
    // a real, if narrow, window, not a hypothetical one, since those are three
    // separate connections at three separate times (module doc comment,
    // "Consistency"). Reporting an entry built from a replay that never reached
    // `CaughtUp` would claim a sealed session is still live; treat it the same as
    // every other "session ended before this probe finished" case instead
    // (review 5306729614 of #254, finding 1).
    match end {
        WatchEnd::CaughtUp { .. } => {}
        WatchEnd::Closed { .. } | WatchEnd::Sealed { .. } => return Ok(None),
    }

    Ok(Some(RegistryEntry {
        session: meta.id.clone(),
        project: description.worktree,
        agent: description.agent,
        agent_state,
        pending_approvals: pending,
        verification,
    }))
}

/// Whether `e` is the shape `describe`/`pending` fail with when the session's
/// daemon has simply stopped answering mid-call — the expected "ended between
/// being listed and being probed" case [`snapshot`]'s doc comment already
/// names, not a protocol or daemon-refusal error. `client.rs`'s socket I/O
/// layer (`RemoteSink::send`/`read_response`/`next_response`) maps every write
/// failure, read failure and clean EOF to [`Error::Sandbox`], and it is the
/// only way `describe`/`pending` produce that variant — a malformed response
/// is [`Error::Events`] (`parse_response`) and an explicit daemon refusal is
/// [`Error::Events`] (`describe`) or [`Error::Daemon`] (`pending`), never
/// [`Error::Sandbox`] — so matching on it here is a closed-socket check, not a
/// guess (review 5306729614 of #254, finding 3).
fn disconnected(e: &Error) -> bool {
    matches!(e, Error::Sandbox(_))
}

/// Fold one record into the running/paused and verification projections,
/// mirroring `ward_shell_core::feed::SessionState::apply`'s equivalent arms
/// (module doc comment: re-implemented here, not imported, because of the
/// crate dependency direction between `ward-daemon` and `ward-shell-core`).
fn apply(
    rec: &EventRecord,
    agent_state: &mut Option<AgentState>,
    before_pause: &mut Option<AgentState>,
    verification: &mut VerificationState,
) {
    match rec.event {
        WardEvent::AgentStateChanged { state } => *agent_state = Some(state),
        WardEvent::SessionPaused { .. } => {
            *before_pause = *agent_state;
            *agent_state = Some(AgentState::Paused);
        }
        WardEvent::SessionPauseUnsettled { .. } => {
            *before_pause = *agent_state;
            *agent_state = Some(AgentState::PauseUnsettled);
        }
        WardEvent::SessionResumed { .. } => {
            *agent_state = before_pause.take();
        }
        _ => {}
    }
    verification.apply(rec);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use std::io::Write as _;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use ward_events::{
        AgentIdentity, AgentKind, Blake3Hash, NameText, Origin, PauseMethod, SessionId, ShortText,
        VerifyRequester, VerifySummary,
    };
    use ward_policy::{Policy, merge};

    use super::*;
    use crate::control::{Request, Response};
    use crate::session::{SessionMeta, session_dir};

    /// A minimal fake daemon: answers `Ping`/`Describe`/`Pending`/`Subscribe`
    /// from a canned script of records, exactly the requests `entry_for`
    /// makes, on a real Unix socket so `client::connect`/`catch_up` exercise
    /// their real code paths (the same double this crate's other modules use
    /// — see `client.rs`'s own `tests` for the fuller version this borrows
    /// the shape of).
    #[derive(Default)]
    struct FakeSession {
        records: Vec<EventRecord>,
        pending: Vec<crate::approvals::Approval>,
        /// Finding 1 (review 5306729614 of #254): when `true`, `Subscribe`
        /// replays `records` and then closes the connection without ever
        /// sending the `CaughtUp` marker — the shape `catch_up` sees when a
        /// session seals in the gap between `entry_for`'s `describe`/
        /// `pending` probe and its later, separate subscribe connection,
        /// distinct from `a_session_whose_daemon_does_not_answer_is_silently_skipped`
        /// below, which never reaches `entry_for` at all.
        seal_on_subscribe: bool,
        /// Finding 3: how `Describe` answers, to exercise the malformed-
        /// response and daemon-refusal paths distinctly from an ordinary
        /// disconnect.
        describe_behavior: DescribeBehavior,
    }

    /// See [`FakeSession::describe_behavior`].
    #[derive(Default)]
    enum DescribeBehavior {
        #[default]
        Normal,
        /// A line that is not valid `Response` JSON at all.
        Malformed,
        /// The daemon explicitly refuses the request.
        Refused(String),
    }

    /// The [`SessionMeta`] `spawn` writes for `id`, factored out so a test
    /// that wants to call `entry_for` directly (bypassing `snapshot`'s own
    /// `live_sessions` scan, to assert on the specific `Result` it returns)
    /// can build the same value `spawn` did.
    fn meta_for(id: &str) -> SessionMeta {
        SessionMeta {
            id: id.to_owned(),
            project: PathBuf::from(format!("/tmp/{id}")),
            project_id: format!("proj_{id}"),
            entry_snapshot: format!("blake3:{}", "ab".repeat(32)),
            origin_repo: None,
            manifest: description(id).manifest,
            started_unix_ms: 1_700_000_000_000,
            agent: Some(AgentIdentity {
                kind: AgentKind::ClaudeCode,
                name: NameText::new("claude"),
                version: NameText::new("1.0.0"),
                image: None,
            }),
        }
    }

    fn description(id: &str) -> crate::describe::SessionDescription {
        let manifest = merge(
            &Policy::default(),
            &Policy::default(),
            &Policy::default(),
            ward_policy::SessionId(id.to_owned()),
            ward_policy::ProjectId(format!("proj_{id}")),
        );
        crate::describe::SessionDescription {
            session: id.to_owned(),
            project: format!("proj_{id}"),
            worktree: PathBuf::from(format!("/tmp/{id}")),
            started_unix_ms: 1_700_000_000_000,
            agent: Some(crate::describe::AgentDescription::from(&AgentIdentity {
                kind: AgentKind::ClaudeCode,
                name: NameText::new("claude"),
                version: NameText::new("1.0.0"),
                image: None,
            })),
            entry_snapshot: format!("blake3:{}", "ab".repeat(32)),
            policy_hash: manifest.policy_hash.to_hex(),
            manifest,
        }
    }

    fn record(seq: u64, event: WardEvent) -> EventRecord {
        EventRecord {
            session: SessionId::from_u128(1),
            seq,
            ts_mono: Duration::from_secs(seq),
            ts_wall: Some(std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + seq)),
            origin: Origin::Wardd,
            prev: Blake3Hash::from_bytes([0; 32]),
            event,
            hash: Blake3Hash::from_bytes([0; 32]),
        }
    }

    fn snapshot_id(byte: u8) -> SnapshotId {
        SnapshotId::new(Blake3Hash::from_bytes([byte; 32]))
    }

    /// Spawn `FakeSession` behind a real socket at `state/sessions/<id>/control.sock`
    /// and write its `session.json`, so `live_sessions`/`entry_for` find it
    /// exactly as they would a real daemon's.
    fn spawn(state: &Path, id: &str, session: FakeSession) {
        let dir = session_dir(state, id);
        std::fs::create_dir_all(&dir).unwrap();
        let meta = meta_for(id);
        std::fs::write(dir.join("session.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
        std::fs::write(
            dir.join(crate::daemon::PID_NAME),
            std::process::id().to_string(),
        )
        .unwrap();

        let socket = dir.join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        let desc = description(id);
        let session = Arc::new(session);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let desc = desc.clone();
                let session = Arc::clone(&session);
                thread::spawn(move || serve(stream, &desc, &session));
            }
        });
        // Give the listener a moment to be ready to accept before the test's
        // first connection attempt.
        thread::sleep(Duration::from_millis(20));
    }

    fn serve(
        stream: std::os::unix::net::UnixStream,
        desc: &crate::describe::SessionDescription,
        session: &FakeSession,
    ) {
        use std::io::{BufRead, BufReader};
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut writer = stream;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let Ok(req) = serde_json::from_str::<Request>(&line) else {
                return;
            };
            let reply = |writer: &mut std::os::unix::net::UnixStream, resp: &Response| {
                let mut out = serde_json::to_vec(resp).unwrap();
                out.push(b'\n');
                let _ = writer.write_all(&out);
            };
            match req {
                Request::Ping => reply(&mut writer, &Response::Ok),
                Request::Describe => match &session.describe_behavior {
                    DescribeBehavior::Normal => reply(
                        &mut writer,
                        &Response::Description(serde_json::to_value(desc).unwrap()),
                    ),
                    // Not even a JSON object, let alone a `Response` — the
                    // shape `parse_response` (`control.rs`) rejects with
                    // `Error::Events`, exercised by finding 3's test.
                    DescribeBehavior::Malformed => {
                        let _ = writer.write_all(b"not a response at all\n");
                    }
                    DescribeBehavior::Refused(reason) => {
                        reply(&mut writer, &Response::Error(reason.clone()));
                    }
                },
                Request::Pending => {
                    reply(&mut writer, &Response::Pending(session.pending.clone()));
                }
                Request::Subscribe { from_seq } => {
                    for rec in session.records.iter().filter(|r| r.seq >= from_seq) {
                        reply(&mut writer, &Response::Record(Box::new(rec.clone())));
                    }
                    if session.seal_on_subscribe {
                        // Close the connection right after the replay, with
                        // no `CaughtUp` marker — `catch_up` sees this as
                        // `WatchEnd::Closed`, exactly as it would a real
                        // daemon that sealed before this subscribe reached
                        // it (finding 1's test).
                        return;
                    }
                    let next_seq = session.records.last().map_or(from_seq, |r| r.seq + 1);
                    reply(&mut writer, &Response::CaughtUp { next_seq });
                    // Stay open, quiet, until the client's settle bound
                    // elapses and it moves on — `catch_up`'s own contract.
                    thread::sleep(Duration::from_secs(2));
                }
                _ => reply(&mut writer, &Response::Error("unsupported in test".into())),
            }
        }
    }

    fn approval(id: u64) -> crate::approvals::Approval {
        crate::approvals::Approval::new(
            id,
            "Write",
            "/tmp/x",
            crate::approvals::Authority::none("rule", "/tmp/x"),
            1_700_000_000_000,
        )
    }

    #[test]
    fn snapshot_of_no_sessions_is_an_empty_registry_at_the_current_selection() {
        let state = tempfile::tempdir().unwrap();
        let reg = snapshot(state.path(), Duration::from_millis(50));
        assert!(reg.entries.is_empty());
        assert_eq!(reg.selection, Selection::default());
        assert!(reg.selected().is_none());
    }

    #[test]
    fn snapshot_reports_project_agent_pending_and_never_run_verification() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_a",
            FakeSession {
                records: vec![record(
                    0,
                    WardEvent::SessionStarted {
                        project: ward_events::ProjectId::from_u128(1),
                        agent: AgentIdentity {
                            kind: AgentKind::ClaudeCode,
                            name: NameText::new("claude"),
                            version: NameText::new("1.0.0"),
                            image: None,
                        },
                        manifest_hash: Blake3Hash::from_bytes([0; 32]),
                        entry_snapshot: snapshot_id(1),
                        policy_hash: Blake3Hash::from_bytes([0; 32]),
                        tool_images: Vec::new(),
                    },
                )],
                pending: vec![approval(0), approval(1)],
                ..Default::default()
            },
        );

        let reg = snapshot(state.path(), Duration::from_millis(100));
        assert_eq!(reg.entries.len(), 1);
        let entry = &reg.entries[0];
        assert_eq!(entry.session, "sess_a");
        assert_eq!(entry.project, PathBuf::from("/tmp/sess_a"));
        assert_eq!(
            entry.agent.as_ref().map(|a| a.kind.as_str()),
            Some("claude_code")
        );
        assert_eq!(entry.pending_approvals, 2);
        assert_eq!(entry.verification, VerificationState::NeverRun);
        assert!(entry.running(), "no report yet still counts as running");
    }

    #[test]
    fn pause_and_resume_records_round_trip_through_running() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_b",
            FakeSession {
                records: vec![
                    record(
                        0,
                        WardEvent::AgentStateChanged {
                            state: AgentState::Working,
                        },
                    ),
                    record(
                        1,
                        WardEvent::SessionPaused {
                            method: PauseMethod::CgroupFreezer,
                            reason: ShortText::new(""),
                        },
                    ),
                ],
                pending: Vec::new(),
                ..Default::default()
            },
        );
        let reg = snapshot(state.path(), Duration::from_millis(100));
        let entry = &reg.entries[0];
        assert_eq!(entry.agent_state, Some(AgentState::Paused));
        assert!(!entry.running());
    }

    #[test]
    fn pause_unsettled_also_counts_as_not_running() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_c",
            FakeSession {
                records: vec![record(
                    0,
                    WardEvent::SessionPauseUnsettled {
                        method: PauseMethod::Sigstop,
                        reason: ShortText::new(""),
                        pending: 1,
                    },
                )],
                pending: Vec::new(),
                ..Default::default()
            },
        );
        let reg = snapshot(state.path(), Duration::from_millis(100));
        assert_eq!(reg.entries[0].agent_state, Some(AgentState::PauseUnsettled));
        assert!(!reg.entries[0].running());
    }

    #[test]
    fn resume_restores_the_state_from_before_the_pause() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_d",
            FakeSession {
                records: vec![
                    record(
                        0,
                        WardEvent::AgentStateChanged {
                            state: AgentState::Working,
                        },
                    ),
                    record(
                        1,
                        WardEvent::SessionPaused {
                            method: PauseMethod::CgroupFreezer,
                            reason: ShortText::new(""),
                        },
                    ),
                    record(
                        2,
                        WardEvent::SessionResumed {
                            paused_for: Duration::from_secs(1),
                        },
                    ),
                ],
                pending: Vec::new(),
                ..Default::default()
            },
        );
        let reg = snapshot(state.path(), Duration::from_millis(100));
        assert_eq!(reg.entries[0].agent_state, Some(AgentState::Working));
        assert!(reg.entries[0].running());
    }

    #[test]
    fn a_passed_verification_is_reported_with_its_candidate_and_time() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_e",
            FakeSession {
                records: vec![
                    record(
                        0,
                        WardEvent::VerificationAttemptStarted {
                            attempt: ward_events::AttemptId::new(1),
                            requested_by: VerifyRequester::User,
                        },
                    ),
                    record(
                        1,
                        WardEvent::VerificationPassed {
                            candidate: snapshot_id(7),
                            summary: VerifySummary::default(),
                            result_hash: Blake3Hash::from_bytes([0; 32]),
                        },
                    ),
                ],
                pending: Vec::new(),
                ..Default::default()
            },
        );
        let reg = snapshot(state.path(), Duration::from_millis(100));
        match reg.entries[0].verification {
            VerificationState::Passed {
                candidate,
                at_unix_ms,
            } => {
                assert_eq!(candidate, snapshot_id(7));
                assert!(at_unix_ms > 0);
            }
            other => panic!("expected Passed, got {other:?}"),
        }
    }

    #[test]
    fn an_attempt_in_flight_reports_running_not_never_run() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_f",
            FakeSession {
                records: vec![record(
                    0,
                    WardEvent::VerificationAttemptStarted {
                        attempt: ward_events::AttemptId::new(1),
                        requested_by: VerifyRequester::User,
                    },
                )],
                pending: Vec::new(),
                ..Default::default()
            },
        );
        let reg = snapshot(state.path(), Duration::from_millis(100));
        assert_eq!(reg.entries[0].verification, VerificationState::Running);
    }

    #[test]
    fn selected_finds_the_entry_the_selection_names() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_g",
            FakeSession {
                records: Vec::new(),
                pending: Vec::new(),
                ..Default::default()
            },
        );
        selection::select(state.path(), Some("sess_g")).unwrap();
        let reg = snapshot(state.path(), Duration::from_millis(100));
        assert_eq!(reg.selected().map(|e| e.session.as_str()), Some("sess_g"));
    }

    #[test]
    fn selected_is_none_when_the_selection_names_a_session_not_in_this_snapshot() {
        let state = tempfile::tempdir().unwrap();
        selection::select(state.path(), Some("sess_gone")).unwrap();
        let reg = snapshot(state.path(), Duration::from_millis(100));
        assert!(reg.entries.is_empty());
        assert_eq!(reg.selection.session.as_deref(), Some("sess_gone"));
        assert!(
            reg.selected().is_none(),
            "a selection naming a session missing from this snapshot is not resolved to one"
        );
    }

    /// A session whose directory exists but whose daemon does not answer
    /// (crashed, or ended between `live_sessions` listing it and this probe
    /// reaching it) must not fail the whole snapshot — just be absent from
    /// it, exactly as `daemon::live_sessions` already treats an unreadable
    /// session record.
    #[test]
    fn a_session_whose_daemon_does_not_answer_is_silently_skipped() {
        let state = tempfile::tempdir().unwrap();
        let dir = session_dir(state.path(), "sess_dead");
        std::fs::create_dir_all(&dir).unwrap();
        let meta = SessionMeta {
            id: "sess_dead".to_owned(),
            project: PathBuf::from("/tmp/sess_dead"),
            project_id: "proj_sess_dead".to_owned(),
            entry_snapshot: format!("blake3:{}", "ab".repeat(32)),
            origin_repo: None,
            manifest: description("sess_dead").manifest,
            started_unix_ms: 1_700_000_000_000,
            agent: None,
        };
        std::fs::write(dir.join("session.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
        // No pid file, no socket: `daemon::serving` reports it as not live,
        // so this session never even reaches `entry_for` — the registry is
        // simply empty, which is the same outcome as `entry_for` itself
        // returning `Ok(None)` for a session that answers `live_sessions`'
        // liveness probe but nothing further.
        let reg = snapshot(state.path(), Duration::from_millis(50));
        assert!(reg.entries.is_empty());
    }

    /// Concurrent snapshots of an unchanging registry must agree with each
    /// other: nothing here is a compare-and-swap or a write, so there is no
    /// lost-update race to close, but a snapshot must still be internally
    /// consistent under concurrent readers hammering the same sessions.
    #[test]
    fn concurrent_snapshots_of_the_same_registry_agree() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_h",
            FakeSession {
                records: vec![record(
                    0,
                    WardEvent::AgentStateChanged {
                        state: AgentState::Idle,
                    },
                )],
                pending: vec![approval(0)],
                ..Default::default()
            },
        );
        let state_path = state.path().to_path_buf();
        let seen: Arc<Mutex<Vec<Registry>>> = Arc::new(Mutex::new(Vec::new()));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let state_path = state_path.clone();
                let seen = Arc::clone(&seen);
                thread::spawn(move || {
                    let reg = snapshot(&state_path, Duration::from_millis(100));
                    seen.lock().unwrap().push(reg);
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 4);
        for reg in seen.iter() {
            assert_eq!(reg.entries.len(), 1);
            assert_eq!(reg.entries[0].pending_approvals, 1);
            assert_eq!(reg.entries[0].session, "sess_h");
        }
    }

    /// Finding 1 (review 5306729614 of #254): a session that seals — its log
    /// closes for good — in the narrow gap between `entry_for`'s `describe`/
    /// `pending` probe (one connection) and its later, separate `catch_up`
    /// subscribe must not be reported as a live entry. `catch_up`
    /// legitimately finishes by replaying the backlog and closing
    /// (`WatchEnd::Closed`), never reaching `CaughtUp`; `entry_for` must
    /// treat that the same as every other "the session ended before this
    /// probe finished" case, not build a `RegistryEntry` from it. Unlike
    /// `a_session_whose_daemon_does_not_answer_is_silently_skipped` above —
    /// which never reaches `entry_for` at all, because `live_sessions`
    /// itself does not consider the session live — this session answers
    /// `describe`/`pending` normally and only seals once the subscribe
    /// arrives, so it is the path that test does not cover.
    #[test]
    fn a_session_sealed_between_probing_and_subscribing_is_not_reported_live() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_sealed",
            FakeSession {
                records: vec![record(
                    0,
                    WardEvent::AgentStateChanged {
                        state: AgentState::Working,
                    },
                )],
                seal_on_subscribe: true,
                ..Default::default()
            },
        );
        let reg = snapshot(state.path(), Duration::from_millis(100));
        assert!(
            reg.entries.is_empty(),
            "a session that sealed before its subscribe ever reached CaughtUp must not appear live"
        );
    }

    /// Finding 3 (review 5306729614 of #254): a malformed `Describe` reply —
    /// something `entry_for` cannot even parse as a `Response` — is a
    /// protocol failure on an otherwise-live session, not the ordinary
    /// "session ended" case `Error::Project` (a missing socket) already
    /// covers. `entry_for` must return it as `Err` so `snapshot`'s own
    /// `eprintln!` on that path actually fires, instead of the session
    /// silently vanishing from the registry indistinguishably from having
    /// disconnected.
    #[test]
    fn a_malformed_describe_response_is_a_protocol_error_not_a_vanished_session() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_malformed",
            FakeSession {
                describe_behavior: DescribeBehavior::Malformed,
                ..Default::default()
            },
        );
        let err = match entry_for(
            state.path(),
            &meta_for("sess_malformed"),
            Duration::from_millis(100),
        ) {
            Err(e) => e,
            Ok(ok) => panic!("a malformed Describe reply must surface as an error, not {ok:?}"),
        };
        assert!(
            !disconnected(&err),
            "a malformed response is not the disconnected-session shape: {err}"
        );
    }

    /// Finding 3: the daemon explicitly refusing `Describe` (`Response::Error`)
    /// is a daemon-side refusal, not a disconnect either, and must surface
    /// the same way a malformed response does rather than being swallowed as
    /// "session ended".
    #[test]
    fn a_refused_describe_response_is_a_protocol_error_not_a_vanished_session() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_refused",
            FakeSession {
                describe_behavior: DescribeBehavior::Refused("no".into()),
                ..Default::default()
            },
        );
        let err = match entry_for(
            state.path(),
            &meta_for("sess_refused"),
            Duration::from_millis(100),
        ) {
            Err(e) => e,
            Ok(ok) => {
                panic!("a daemon-refused Describe reply must surface as an error, not {ok:?}")
            }
        };
        assert!(
            !disconnected(&err),
            "a daemon refusal is not the disconnected-session shape: {err}"
        );
    }

    /// Finding 2 (review 5306729614 of #254): `Errored`/`Cancelled`/
    /// `Interrupted` must carry the terminal timestamp their doc comments
    /// (and `Passed`/`Failed`/`TimedOut`, which already did) say every
    /// terminal outcome carries.
    #[test]
    fn an_errored_verification_carries_its_terminal_timestamp() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_errored",
            FakeSession {
                records: vec![record(
                    0,
                    WardEvent::VerificationErrored {
                        candidate: snapshot_id(3),
                        reason: ShortText::new("sandbox: bubblewrap (bwrap) is not installed"),
                    },
                )],
                ..Default::default()
            },
        );
        let reg = snapshot(state.path(), Duration::from_millis(100));
        match reg.entries[0].verification {
            VerificationState::Errored {
                candidate,
                at_unix_ms,
            } => {
                assert_eq!(candidate, snapshot_id(3));
                assert!(at_unix_ms > 0);
            }
            other => panic!("expected Errored, got {other:?}"),
        }
    }

    /// Finding 2, `Cancelled`'s share of the same fix.
    #[test]
    fn a_cancelled_verification_carries_its_terminal_timestamp() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_cancelled",
            FakeSession {
                records: vec![record(
                    0,
                    WardEvent::VerificationCancelled {
                        attempt: ward_events::AttemptId::new(1),
                        candidate: Some(snapshot_id(4)),
                    },
                )],
                ..Default::default()
            },
        );
        let reg = snapshot(state.path(), Duration::from_millis(100));
        match reg.entries[0].verification {
            VerificationState::Cancelled {
                candidate,
                at_unix_ms,
            } => {
                assert_eq!(candidate, Some(snapshot_id(4)));
                assert!(at_unix_ms > 0);
            }
            other => panic!("expected Cancelled, got {other:?}"),
        }
    }

    /// Finding 2, `Interrupted`'s share of the same fix.
    #[test]
    fn an_interrupted_verification_carries_its_terminal_timestamp() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_interrupted",
            FakeSession {
                records: vec![record(
                    0,
                    WardEvent::VerificationInterrupted {
                        attempt: ward_events::AttemptId::new(1),
                        candidate: None,
                        reason: ShortText::new(
                            "the process serving this session ended before the attempt \
                             reached a terminal result",
                        ),
                    },
                )],
                ..Default::default()
            },
        );
        let reg = snapshot(state.path(), Duration::from_millis(100));
        match reg.entries[0].verification {
            VerificationState::Interrupted {
                candidate,
                at_unix_ms,
            } => {
                assert_eq!(candidate, None);
                assert!(at_unix_ms > 0);
            }
            other => panic!("expected Interrupted, got {other:?}"),
        }
    }

    /// Finding 2 (review 5306729614 of #254): the sense in which
    /// [`VerificationState`] can honestly distinguish stale from current
    /// (module doc comment, "Verification: last outcome, not qualified
    /// freshness") is that a new attempt's terminal record supersedes an
    /// older one on the same session — a first pass must not still be
    /// reported once a later attempt has its own terminal outcome. What it
    /// still does not do, by the same doc comment, is qualify that against
    /// the *current worktree digest* (#138's job).
    #[test]
    fn a_later_verification_attempt_supersedes_an_earlier_ones_outcome() {
        let state = tempfile::tempdir().unwrap();
        spawn(
            state.path(),
            "sess_i",
            FakeSession {
                records: vec![
                    record(
                        0,
                        WardEvent::VerificationAttemptStarted {
                            attempt: ward_events::AttemptId::new(1),
                            requested_by: VerifyRequester::User,
                        },
                    ),
                    record(
                        1,
                        WardEvent::VerificationPassed {
                            candidate: snapshot_id(1),
                            summary: VerifySummary::default(),
                            result_hash: Blake3Hash::from_bytes([0; 32]),
                        },
                    ),
                    record(
                        2,
                        WardEvent::VerificationAttemptStarted {
                            attempt: ward_events::AttemptId::new(2),
                            requested_by: VerifyRequester::User,
                        },
                    ),
                    record(
                        3,
                        WardEvent::VerificationFailed {
                            candidate: snapshot_id(2),
                            summary: VerifySummary::default(),
                            result_hash: Blake3Hash::from_bytes([0; 32]),
                        },
                    ),
                ],
                ..Default::default()
            },
        );
        let reg = snapshot(state.path(), Duration::from_millis(100));
        match reg.entries[0].verification {
            VerificationState::Failed { candidate, .. } => {
                assert_eq!(
                    candidate,
                    snapshot_id(2),
                    "the stale first pass must not still be reported once a later attempt \
                     has its own terminal outcome"
                );
            }
            other => panic!("expected Failed (the later attempt), got {other:?}"),
        }
    }
}
