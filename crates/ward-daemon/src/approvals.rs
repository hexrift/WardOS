//! Approvals held by the daemon (ADR-0016, `docs/design-language.md` §10).
//!
//! When the hook adapter would answer `ask`, the answer is no longer handed
//! straight to the agent's own prompt: the `ward` process asks the session
//! daemon to hold it ([`Request::Hold`](crate::control::Request::Hold)), the
//! daemon registers a pending [`Approval`], the desktop shows it, and only an
//! answer over the control socket
//! ([`Request::Approve`](crate::control::Request::Approve)) or the timeout
//! releases it. Deny is the default on timeout, and when the session ends
//! with the question open.
//!
//! [`Approvals`] is the hold itself: the pending set, the answers, the
//! `allow-session` memory, and the wait. It knows nothing about sockets or the
//! log; the daemon appends the `CapabilityRequested` / `CapabilityDecided`
//! records around it ([`requested_event`], [`decided_event`]), which is how
//! the log, a subscriber and `ward replay` see the same question and the same
//! answer. An approval's id is the sequence number of its request record, so
//! the stream carries the id by construction.

use std::collections::BTreeSet;
use std::str::FromStr;
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use ward_events::{
    CapabilityKind, CapabilityRequest, Decision, DecisionSource, GrantScope, ShortText, WardEvent,
};

use crate::error::{Error, Result};
use crate::hooks::{HookDecision, HookResponse};

/// The default hold before an unanswered approval is denied, in seconds
/// (`WARD_APPROVAL_TIMEOUT_SECS` overrides it for the sessions a shell starts).
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// One question waiting for the user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    /// The sequence number of the `CapabilityRequested` record that asked.
    pub id: u64,
    /// The tool the agent wants to use (`Write`, `WebFetch`, …).
    pub tool: String,
    /// What it wants to use it on: the path or the host, sanitised.
    pub summary: String,
    /// Why the daemon asks (`step-through: pause before writes`).
    pub reason: String,
    /// When, milliseconds since the Unix epoch.
    pub requested_at_unix_ms: u64,
}

/// The user's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalDecision {
    /// This once.
    Allow,
    /// This, and the same tool on the same target, for the rest of the session.
    AllowSession,
    /// No.
    Deny,
}

impl ApprovalDecision {
    /// The word on the command line and the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AllowSession => "allow-session",
            Self::Deny => "deny",
        }
    }
}

impl FromStr for ApprovalDecision {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "allow" => Ok(Self::Allow),
            "allow-session" => Ok(Self::AllowSession),
            "deny" => Ok(Self::Deny),
            other => Err(format!(
                "unknown decision `{other}` (one of allow, allow-session, deny)"
            )),
        }
    }
}

impl std::fmt::Display for ApprovalDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a held approval was released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The user answered.
    Answered(ApprovalDecision),
    /// An earlier `allow-session` for the same tool and target covered it.
    Remembered,
    /// Nobody answered in time.
    TimedOut,
    /// The session ended with the question open.
    Closed,
}

impl Outcome {
    /// What the hook tells the agent: allow or deny, and why.
    #[must_use]
    pub fn response(self) -> HookResponse {
        let (decision, reason) = match self {
            Self::Answered(ApprovalDecision::Allow) => {
                (HookDecision::Allow, "approval: allowed once")
            }
            Self::Answered(ApprovalDecision::AllowSession) => {
                (HookDecision::Allow, "approval: allowed for the session")
            }
            Self::Remembered => (HookDecision::Allow, "approval: allowed for the session"),
            Self::Answered(ApprovalDecision::Deny) => (HookDecision::Deny, "approval: denied"),
            Self::TimedOut => (HookDecision::Deny, "approval: timed out"),
            Self::Closed => (HookDecision::Deny, "approval: session ended"),
        };
        HookResponse {
            decision,
            reason: reason.to_owned(),
        }
    }
}

/// One held question and its answer, once there is one.
#[derive(Debug)]
struct Held {
    approval: Approval,
    answer: Option<ApprovalDecision>,
}

#[derive(Debug, Default)]
struct State {
    held: Vec<Held>,
    /// `(tool, summary)` pairs an `allow-session` covers.
    remembered: BTreeSet<(String, String)>,
    closed: bool,
}

/// The daemon's hold: what is pending, what was answered, what is remembered.
#[derive(Debug, Default)]
pub struct Approvals {
    state: Mutex<State>,
    changed: Condvar,
}

impl Approvals {
    /// An empty hold.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether an earlier `allow-session` covers `tool` on `summary`.
    #[must_use]
    pub fn remembered(&self, tool: &str, summary: &str) -> bool {
        self.lock()
            .remembered
            .contains(&(tool.to_owned(), summary.to_owned()))
    }

    /// Register a question. Refused once the session has ended.
    pub fn register(&self, approval: Approval) -> Result<()> {
        let mut state = self.lock();
        if state.closed {
            return Err(Error::Daemon("approval: session ended".into()));
        }
        state.held.push(Held {
            approval,
            answer: None,
        });
        drop(state);
        self.changed.notify_all();
        Ok(())
    }

    /// Wait up to `timeout` for the answer to `id`, then forget the question.
    /// The answer stays remembered when it was `allow-session`.
    pub fn wait(&self, id: u64, timeout: Duration) -> Outcome {
        let deadline = Instant::now() + timeout;
        let mut state = self.lock();
        loop {
            let Some(index) = state.held.iter().position(|h| h.approval.id == id) else {
                return Outcome::Closed;
            };
            if let Some(answer) = state.held[index].answer {
                let held = state.held.remove(index);
                if answer == ApprovalDecision::AllowSession {
                    state
                        .remembered
                        .insert((held.approval.tool, held.approval.summary));
                }
                return Outcome::Answered(answer);
            }
            if state.closed {
                state.held.remove(index);
                return Outcome::Closed;
            }
            let now = Instant::now();
            if now >= deadline {
                state.held.remove(index);
                return Outcome::TimedOut;
            }
            state = self
                .changed
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Answer `id`. Unknown ids (never asked, already released) are an error;
    /// a second answer to the same open question is too.
    pub fn answer(&self, id: u64, decision: ApprovalDecision) -> Result<()> {
        let mut state = self.lock();
        let held = state
            .held
            .iter_mut()
            .find(|h| h.approval.id == id)
            .ok_or_else(|| Error::Daemon(format!("approval {id}: not pending")))?;
        if held.answer.is_some() {
            return Err(Error::Daemon(format!("approval {id}: already answered")));
        }
        held.answer = Some(decision);
        drop(state);
        self.changed.notify_all();
        Ok(())
    }

    /// The open questions, oldest first.
    #[must_use]
    pub fn pending(&self) -> Vec<Approval> {
        self.lock()
            .held
            .iter()
            .filter(|h| h.answer.is_none())
            .map(|h| h.approval.clone())
            .collect()
    }

    /// The session ended: every open question is released as denied, and no
    /// new one is taken.
    pub fn close(&self) {
        self.lock().closed = true;
        self.changed.notify_all();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The capability a hook tool stands for: writes, reads, the network, a
/// command, or something else.
#[must_use]
pub fn capability_kind(tool: &str) -> CapabilityKind {
    match tool {
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => CapabilityKind::FileWrite,
        "Read" | "Grep" | "Glob" | "LS" => CapabilityKind::FileRead,
        "WebFetch" | "WebSearch" => CapabilityKind::Network,
        "Bash" => CapabilityKind::Exec,
        _ => CapabilityKind::Other,
    }
}

fn capability(tool: &str, summary: &str) -> CapabilityRequest {
    CapabilityRequest {
        kind: capability_kind(tool),
        target: ShortText::new(&format!("{tool} {summary}")),
    }
}

/// The record that asks: `CapabilityRequested` with the tool and target and
/// the hook's reason.
#[must_use]
pub fn requested_event(tool: &str, summary: &str, reason: &str) -> WardEvent {
    WardEvent::CapabilityRequested {
        cap: capability(tool, summary),
        reason: Some(ShortText::new(reason)),
    }
}

/// The record that answers: `CapabilityDecided` by the user (with the grant's
/// scope) or by the timeout. A question the session's end released has no
/// record: the log is sealed by then.
#[must_use]
pub fn decided_event(tool: &str, summary: &str, outcome: Outcome) -> Option<WardEvent> {
    let (decision, by, grant) = match outcome {
        Outcome::Answered(ApprovalDecision::Allow) => (
            Decision::Allow,
            DecisionSource::User,
            Some(GrantScope::Once),
        ),
        Outcome::Answered(ApprovalDecision::AllowSession) | Outcome::Remembered => (
            Decision::Allow,
            DecisionSource::User,
            Some(GrantScope::Session),
        ),
        Outcome::Answered(ApprovalDecision::Deny) => (Decision::Deny, DecisionSource::User, None),
        Outcome::TimedOut => (Decision::Deny, DecisionSource::Timeout, None),
        Outcome::Closed => return None,
    };
    Some(WardEvent::CapabilityDecided {
        cap: capability(tool, summary),
        decision,
        by,
        grant,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::sync::Arc;

    fn approval(id: u64) -> Approval {
        Approval {
            id,
            tool: "Write".into(),
            summary: "/work/src/lib.rs".into(),
            reason: "step-through: pause before writes".into(),
            requested_at_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn decisions_parse_print_and_serialise_as_their_words() {
        for (word, decision) in [
            ("allow", ApprovalDecision::Allow),
            ("allow-session", ApprovalDecision::AllowSession),
            ("deny", ApprovalDecision::Deny),
        ] {
            assert_eq!(word.parse::<ApprovalDecision>(), Ok(decision));
            assert_eq!(decision.to_string(), word);
            assert_eq!(
                serde_json::to_string(&decision).unwrap(),
                format!("\"{word}\"")
            );
        }
        let err = "yes".parse::<ApprovalDecision>().unwrap_err();
        assert_eq!(
            err,
            "unknown decision `yes` (one of allow, allow-session, deny)"
        );
    }

    #[test]
    fn an_answer_releases_the_hold_with_the_users_decision() {
        let approvals = Arc::new(Approvals::new());
        approvals.register(approval(3)).unwrap();
        assert_eq!(approvals.pending(), [approval(3)]);
        let waiter = {
            let approvals = Arc::clone(&approvals);
            std::thread::spawn(move || approvals.wait(3, Duration::from_secs(5)))
        };
        // The question stays pending until answered.
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(approvals.pending().len(), 1);
        approvals.answer(3, ApprovalDecision::Allow).unwrap();
        assert_eq!(
            waiter.join().unwrap(),
            Outcome::Answered(ApprovalDecision::Allow)
        );
        assert!(approvals.pending().is_empty(), "released");
        assert!(!approvals.remembered("Write", "/work/src/lib.rs"));
        let err = approvals.answer(3, ApprovalDecision::Deny).unwrap_err();
        assert_eq!(err.to_string(), "daemon: approval 3: not pending");
    }

    #[test]
    fn a_timeout_denies_and_forgets_the_question() {
        let approvals = Approvals::new();
        approvals.register(approval(1)).unwrap();
        let started = Instant::now();
        assert_eq!(
            approvals.wait(1, Duration::from_millis(50)),
            Outcome::TimedOut
        );
        assert!(started.elapsed() >= Duration::from_millis(50));
        assert!(approvals.pending().is_empty());
        assert_eq!(
            approvals.wait(1, Duration::from_millis(10)),
            Outcome::Closed,
            "waiting on a question that is gone"
        );
    }

    #[test]
    fn allow_session_is_remembered_for_the_same_tool_and_target() {
        let approvals = Approvals::new();
        approvals.register(approval(1)).unwrap();
        approvals.answer(1, ApprovalDecision::AllowSession).unwrap();
        assert_eq!(
            approvals.wait(1, Duration::from_secs(1)),
            Outcome::Answered(ApprovalDecision::AllowSession)
        );
        assert!(approvals.remembered("Write", "/work/src/lib.rs"));
        assert!(
            !approvals.remembered("Edit", "/work/src/lib.rs"),
            "same tool"
        );
        assert!(
            !approvals.remembered("Write", "/work/src/main.rs"),
            "same path"
        );
        // An answered question is no longer pending, and cannot be answered twice.
        approvals.register(approval(2)).unwrap();
        approvals.answer(2, ApprovalDecision::Deny).unwrap();
        assert!(approvals.pending().is_empty());
        assert_eq!(
            approvals
                .answer(2, ApprovalDecision::Allow)
                .unwrap_err()
                .to_string(),
            "daemon: approval 2: already answered"
        );
        assert_eq!(
            approvals.wait(2, Duration::ZERO),
            Outcome::Answered(ApprovalDecision::Deny)
        );
    }

    #[test]
    fn closing_releases_every_open_question_and_refuses_new_ones() {
        let approvals = Arc::new(Approvals::new());
        approvals.register(approval(1)).unwrap();
        let waiter = {
            let approvals = Arc::clone(&approvals);
            std::thread::spawn(move || approvals.wait(1, Duration::from_secs(5)))
        };
        std::thread::sleep(Duration::from_millis(20));
        approvals.close();
        assert_eq!(waiter.join().unwrap(), Outcome::Closed);
        assert!(approvals.pending().is_empty());
        let err = approvals.register(approval(2)).unwrap_err();
        assert_eq!(err.to_string(), "daemon: approval: session ended");
    }

    #[test]
    fn outcomes_become_hook_responses_and_log_records() {
        let cases = [
            (
                Outcome::Answered(ApprovalDecision::Allow),
                HookDecision::Allow,
                "approval: allowed once",
                Some((
                    Decision::Allow,
                    DecisionSource::User,
                    Some(GrantScope::Once),
                )),
            ),
            (
                Outcome::Answered(ApprovalDecision::AllowSession),
                HookDecision::Allow,
                "approval: allowed for the session",
                Some((
                    Decision::Allow,
                    DecisionSource::User,
                    Some(GrantScope::Session),
                )),
            ),
            (
                Outcome::Remembered,
                HookDecision::Allow,
                "approval: allowed for the session",
                Some((
                    Decision::Allow,
                    DecisionSource::User,
                    Some(GrantScope::Session),
                )),
            ),
            (
                Outcome::Answered(ApprovalDecision::Deny),
                HookDecision::Deny,
                "approval: denied",
                Some((Decision::Deny, DecisionSource::User, None)),
            ),
            (
                Outcome::TimedOut,
                HookDecision::Deny,
                "approval: timed out",
                Some((Decision::Deny, DecisionSource::Timeout, None)),
            ),
            (
                Outcome::Closed,
                HookDecision::Deny,
                "approval: session ended",
                None,
            ),
        ];
        for (outcome, decision, reason, record) in cases {
            let response = outcome.response();
            assert_eq!(response.decision, decision, "{outcome:?}");
            assert_eq!(response.reason, reason, "{outcome:?}");
            let event = decided_event("Write", "/work/src/lib.rs", outcome);
            match (event, record) {
                (None, None) => {}
                (
                    Some(WardEvent::CapabilityDecided {
                        cap,
                        decision,
                        by,
                        grant,
                    }),
                    Some((want_decision, want_by, want_grant)),
                ) => {
                    assert_eq!(cap.kind, CapabilityKind::FileWrite);
                    assert_eq!(cap.target.as_str(), "Write /work/src/lib.rs");
                    assert_eq!(decision, want_decision, "{outcome:?}");
                    assert_eq!(by, want_by, "{outcome:?}");
                    assert_eq!(grant, want_grant, "{outcome:?}");
                }
                (event, record) => panic!("{outcome:?}: {event:?} vs {record:?}"),
            }
        }
        match requested_event(
            "WebFetch",
            "api.github.com",
            "step-through: pause before network",
        ) {
            WardEvent::CapabilityRequested { cap, reason } => {
                assert_eq!(cap.kind, CapabilityKind::Network);
                assert_eq!(cap.target.as_str(), "WebFetch api.github.com");
                assert_eq!(
                    reason.unwrap().as_str(),
                    "step-through: pause before network"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(capability_kind("Bash"), CapabilityKind::Exec);
        assert_eq!(capability_kind("Read"), CapabilityKind::FileRead);
        assert_eq!(capability_kind("Task"), CapabilityKind::Other);
    }
}
