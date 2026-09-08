//! The session panel (`docs/design-language.md` §6): what opens when the
//! agent segment of the trust bar is chosen.
//!
//! Two groups, `Session` and `TamperWard`, of read-only [`Row`]s. The session
//! rows come from the description; the verification and evidence rows from
//! the stream. The design's `Verifier  isolated` row is an architectural fact
//! the stream does not carry, so it is not shown until a verifier record does.
//! The verify segment opens its own panel ([`verify_panel`], ADR-0019): the
//! verified candidate held against the worktree's current digest.

use ward_daemon::describe::SessionDescription;
use ward_daemon::render::{Tone, network_text, observer_text};
use ward_policy::AccessMode;

use crate::feed::{Model, TamperWard, Verification};
use crate::settings::Row;
use crate::trust::{VerifyState, short_hex};

/// One group of the panel: its heading and its rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// `Session` or `TamperWard`.
    pub title: &'static str,
    /// The rows.
    pub rows: Vec<Row>,
}

/// The session panel of a described session at `now_unix_ms`, given what its
/// stream has said.
#[must_use]
pub fn session_panel(d: &SessionDescription, model: &Model, now_unix_ms: u64) -> Vec<Group> {
    let m = &d.manifest;
    let agent = d.agent.as_ref().map_or_else(
        || "unknown".to_owned(),
        |a| format!("{} {}", a.name, a.version),
    );
    let elapsed = now_unix_ms.saturating_sub(d.started_unix_ms) / 1000;
    let (repo, repo_tone) = match m.filesystem.worktree {
        AccessMode::ReadWrite => ("allowed", Tone::Ink),
        AccessMode::ReadOnly => ("read-only", Tone::Ok),
        AccessMode::None => ("denied", Tone::Ok),
    };
    let granted = ward_daemon::render::credentials_granted(m);
    let (secrets, secrets_tone) = match granted {
        0 => ("none".to_owned(), Tone::Ink),
        n => (format!("{n} granted"), Tone::Warn),
    };
    let session = vec![
        Row::new("Agent", agent, Tone::Ink),
        Row::new("Duration", duration_text(elapsed), Tone::Ink),
        Row::new("Repo write", repo, repo_tone),
        Row::new(
            "Network",
            network_text(&m.network),
            ward_daemon::render::network_tone(&m.network),
        ),
        Row::new("Secrets", secrets, secrets_tone),
        Row::new("Observer", observer_text(m.observer), Tone::Ink),
    ];
    let verify_state = model.verify_state();
    let verify = match verify_state {
        VerifyState::Never => "none",
        VerifyState::Verifying(_) => "running",
        VerifyState::Verified(_) => "pass",
        VerifyState::Stale { .. } => "pass · stale",
        VerifyState::Failed(_) => "fail",
    };
    let verify_tone = verify_state.tone();
    let (evidence, evidence_tone) = match model.state.tamperward {
        TamperWard::Unknown => ("none yet", Tone::Dim),
        TamperWard::Clean => ("clean", Tone::Ok),
        TamperWard::Tampered => ("tamper detected", Tone::Deny),
    };
    let hash: String = d.policy_hash.chars().take(12).collect();
    let tamperward = vec![
        Row::new("Policy", format!("locked · {hash}"), Tone::Ok),
        Row::new("Last verify", verify, verify_tone),
        Row::new("Evidence", evidence, evidence_tone),
    ];
    vec![
        Group {
            title: "Session",
            rows: session,
        },
        Group {
            title: "TamperWard",
            rows: tamperward,
        },
    ]
}

/// The verify panel (ADR-0019 decision 1): what opens when the verify segment
/// is chosen. One group, `Verify`, answering what was verified, when, what the
/// worktree is now and how far it has moved, and what the verifier found.
#[must_use]
pub fn verify_panel(d: &SessionDescription, model: &Model, now_unix_ms: u64) -> Vec<Group> {
    let state = model.verify_state();
    let tone = state.tone();
    let (verdict, at) = match model.state.verification {
        Verification::Passed(v) | Verification::Failed(v) => (Some(v), Some(v.at)),
        Verification::NotRun | Verification::Running(_) => (None, None),
    };
    let candidate = match state {
        VerifyState::Never => Row::new("Verified candidate", "none", Tone::Dim),
        VerifyState::Verifying(c) => Row::new(
            "Verified candidate",
            format!("{} · verifying", short_hex(c)),
            tone,
        ),
        VerifyState::Verified(c) | VerifyState::Stale { candidate: c, .. } => {
            Row::new("Verified candidate", short_hex(c), tone)
        }
        VerifyState::Failed(c) => Row::new(
            "Verified candidate",
            format!("{} · failed", short_hex(c)),
            tone,
        ),
    };
    let time = at.map_or_else(
        || Row::new("Verified time", "—", Tone::Dim),
        |at| {
            let elapsed = now_unix_ms
                .saturating_sub(d.started_unix_ms)
                .saturating_sub(u64::try_from(at.as_millis()).unwrap_or(u64::MAX))
                / 1000;
            Row::new(
                "Verified time",
                format!("at {} · {} ago", session_time(at), duration_text(elapsed)),
                Tone::Ink,
            )
        },
    );
    let (digest, changes) = match (model.worktree, state) {
        (None, _) => (
            Row::new("Current digest", "not digested", Tone::Dim),
            Row::new("Changes", "unknown", Tone::Dim),
        ),
        (Some(w), VerifyState::Stale { .. }) => (
            Row::new("Current digest", short_hex(w.digest), Tone::Warn),
            Row::new(
                "Changes",
                w.changes.map_or_else(
                    || "unknown".to_owned(),
                    |n| format!("{n} {}", if n == 1 { "entry" } else { "entries" }),
                ),
                Tone::Warn,
            ),
        ),
        (Some(w), VerifyState::Verified(_)) => (
            Row::new("Current digest", short_hex(w.digest), Tone::Ok),
            Row::new("Changes", "0", Tone::Ok),
        ),
        (Some(w), _) => (
            Row::new("Current digest", short_hex(w.digest), Tone::Ink),
            Row::new("Changes", "—", Tone::Dim),
        ),
    };
    let (evidence, evidence_tone) = match model.state.tamperward {
        TamperWard::Unknown => ("none yet", Tone::Dim),
        TamperWard::Clean => ("clean", Tone::Ok),
        TamperWard::Tampered => ("tamper detected", Tone::Deny),
    };
    let tests = verdict.map_or_else(
        || Row::new("Tests", "—", Tone::Dim),
        |v| {
            let s = v.summary;
            let passed = s.tests_run.saturating_sub(s.tests_failed);
            let tone = if s.tests_failed == 0 {
                Tone::Ok
            } else {
                Tone::Deny
            };
            Row::new("Tests", format!("{passed}/{}", s.tests_run), tone)
        },
    );
    let integrity = verdict.map_or_else(
        || Row::new("Integrity", "—", Tone::Dim),
        |v| match v.restored {
            0 => Row::new("Integrity", "pass", Tone::Ok),
            n => Row::new("Integrity", format!("{n} protected restored"), Tone::Warn),
        },
    );
    vec![Group {
        title: "Verify",
        rows: vec![
            candidate,
            time,
            digest,
            changes,
            Row::new("TamperWard", evidence, evidence_tone),
            tests,
            integrity,
        ],
    }]
}

/// `12:43`: minutes and seconds into the session, as the observer's time column.
fn session_time(at: std::time::Duration) -> String {
    let t = at.as_secs();
    format!("{:02}:{:02}", t / 60, t % 60)
}

/// The panel as text: each group's heading, a rule, its aligned rows.
#[must_use]
pub fn panel_text(groups: &[Group]) -> String {
    groups
        .iter()
        .map(|g| {
            format!(
                "{}\n────────────────────────\n{}",
                g.title,
                crate::settings::rows_text(&g.rows)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `12m 43s`, `1h 02m`, `43s`: tabular, never more than two units.
#[must_use]
pub fn duration_text(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m:02}m")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::feed::fixtures::{
        denied, edited, records, snapshot, verify_failed, verify_passed, verify_progress,
        verify_requested, wardd,
    };
    use crate::trust::fixtures::description;
    use ward_events::Origin;
    use ward_policy::NetworkCapability;

    fn value<'a>(groups: &'a [Group], title: &str, label: &str) -> &'a Row {
        groups
            .iter()
            .find(|g| g.title == title)
            .unwrap()
            .rows
            .iter()
            .find(|r| r.label == label)
            .unwrap()
    }

    #[test]
    fn durations_read_like_the_design() {
        assert_eq!(duration_text(0), "0s");
        assert_eq!(duration_text(43), "43s");
        assert_eq!(duration_text(12 * 60 + 43), "12m 43s");
        assert_eq!(duration_text(3600 + 2 * 60), "1h 02m");
    }

    #[test]
    fn the_panel_carries_the_design_rows_from_description_and_stream() {
        let d = description(NetworkCapability::Development);
        let mut model = Model::new(false);
        let now = d.started_unix_ms + (12 * 60 + 43) * 1000;
        let groups = session_panel(&d, &model, now);
        assert_eq!(groups.len(), 2);
        assert_eq!(value(&groups, "Session", "Agent").value, "claude 1.2.3");
        assert_eq!(value(&groups, "Session", "Duration").value, "12m 43s");
        assert_eq!(value(&groups, "Session", "Repo write").value, "allowed");
        let network = value(&groups, "Session", "Network");
        assert_eq!(
            (network.value.as_str(), network.tone),
            ("restricted (dev)", Tone::Warn)
        );
        assert_eq!(value(&groups, "Session", "Secrets").value, "none");
        let policy = value(&groups, "TamperWard", "Policy");
        assert!(policy.value.starts_with("locked · "));
        assert_eq!(policy.value.len(), "locked · ".len() + 12);
        assert_eq!(value(&groups, "TamperWard", "Last verify").tone, Tone::Dim);
        assert_eq!(value(&groups, "TamperWard", "Evidence").value, "none yet");

        model.apply(wardd(&[verify_passed()]).remove(0));
        model.apply(records(&[(Origin::TamperWard, denied())]).remove(0));
        let groups = session_panel(&d, &model, d.started_unix_ms);
        let verify = value(&groups, "TamperWard", "Last verify");
        assert_eq!((verify.value.as_str(), verify.tone), ("pass", Tone::Ok));
        assert_eq!(value(&groups, "TamperWard", "Evidence").value, "clean");
        assert_eq!(value(&groups, "Session", "Duration").value, "0s");

        let text = panel_text(&groups);
        assert!(
            text.starts_with("Session\n────────────────────────\nAgent        claude 1.2.3\n"),
            "{text}"
        );
        assert!(
            text.contains("\n\nTamperWard\n────────────────────────\nPolicy        locked · "),
            "{text}"
        );
        assert!(text.ends_with("Evidence      clean\n"), "{text}");

        // Started in the future (clock skew) never underflows.
        let groups = session_panel(&d, &model, 0);
        assert_eq!(value(&groups, "Session", "Duration").value, "0s");

        // The tree moves on: the session panel says so in its one verify row.
        model.observe_worktree(edited(), Some(2));
        let stale = value(&session_panel(&d, &model, 0), "TamperWard", "Last verify").clone();
        assert_eq!(
            (stale.value.as_str(), stale.tone),
            ("pass · stale", Tone::Warn)
        );
    }

    #[test]
    fn the_verify_panel_holds_the_verdict_against_the_worktree() {
        let d = description(NetworkCapability::Development);
        let now = |secs: u64| d.started_unix_ms + secs * 1000;
        let row = |model: &Model, label: &str, at: u64| {
            value(&verify_panel(&d, model, now(at)), "Verify", label).clone()
        };
        let text = |model: &Model, label: &str, at: u64| row(model, label, at).value;

        // Never verified, worktree unread: every row says so, dim.
        let mut model = Model::new(false);
        let groups = verify_panel(&d, &model, now(0));
        assert_eq!(groups.len(), 1);
        let labels: Vec<&str> = groups[0].rows.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "Verified candidate",
                "Verified time",
                "Current digest",
                "Changes",
                "TamperWard",
                "Tests",
                "Integrity"
            ]
        );
        for r in &groups[0].rows {
            assert_eq!(r.tone, Tone::Dim, "{}", r.label);
        }
        assert_eq!(text(&model, "Verified candidate", 0), "none");
        assert_eq!(text(&model, "Current digest", 0), "not digested");
        assert_eq!(text(&model, "Changes", 0), "unknown");

        // Verifying: the candidate is named, nothing judged yet.
        model.apply(wardd(&[verify_requested()]).remove(0));
        let r = row(&model, "Verified candidate", 0);
        assert_eq!(
            (r.value.as_str(), r.tone),
            ("abababab · verifying", Tone::Accent)
        );
        assert_eq!(text(&model, "Tests", 0), "—");

        // Failed after two restores: the counts and the integrity finding, red and amber.
        for rec in wardd(&[
            verify_progress("restore tests/security_expiry.rs"),
            verify_progress("restore tests/other.rs"),
            verify_failed(),
        ]) {
            model.apply(rec);
        }
        let r = row(&model, "Verified candidate", 0);
        assert_eq!(
            (r.value.as_str(), r.tone),
            ("abababab · failed", Tone::Deny)
        );
        let r = row(&model, "Tests", 0);
        assert_eq!((r.value.as_str(), r.tone), ("181/184", Tone::Deny));
        let r = row(&model, "Integrity", 0);
        assert_eq!(
            (r.value.as_str(), r.tone),
            ("2 protected restored", Tone::Warn)
        );

        // Passed at 00:03, seen 12m 43s later, the worktree being the candidate.
        for rec in wardd(&[verify_requested(), verify_passed()]) {
            model.apply(rec);
        }
        model.apply(records(&[(Origin::TamperWard, denied())]).remove(0));
        model.observe_worktree(snapshot(), Some(0));
        let at = 1 + 12 * 60 + 43;
        let r = row(&model, "Verified candidate", at);
        assert_eq!((r.value.as_str(), r.tone), ("abababab", Tone::Ok));
        assert_eq!(text(&model, "Verified time", at), "at 00:01 · 12m 43s ago");
        let r = row(&model, "Current digest", at);
        assert_eq!((r.value.as_str(), r.tone), ("abababab", Tone::Ok));
        let r = row(&model, "Changes", at);
        assert_eq!((r.value.as_str(), r.tone), ("0", Tone::Ok));
        let r = row(&model, "TamperWard", at);
        assert_eq!((r.value.as_str(), r.tone), ("clean", Tone::Ok));
        let r = row(&model, "Tests", at);
        assert_eq!((r.value.as_str(), r.tone), ("184/184", Tone::Ok));
        let r = row(&model, "Integrity", at);
        assert_eq!((r.value.as_str(), r.tone), ("pass", Tone::Ok));

        // Stale: the digest and the count of what differs, amber; one entry is singular.
        model.observe_worktree(edited(), Some(1));
        let r = row(&model, "Current digest", at);
        assert_eq!((r.value.as_str(), r.tone), ("cdcdcdcd", Tone::Warn));
        let r = row(&model, "Changes", at);
        assert_eq!((r.value.as_str(), r.tone), ("1 entry", Tone::Warn));
        model.observe_worktree(edited(), None);
        assert_eq!(text(&model, "Changes", at), "unknown");
        assert_eq!(
            text(&model, "Verified candidate", at),
            "abababab",
            "the verdict is still about the candidate"
        );

        // Clock skew never underflows.
        assert_eq!(text(&model, "Verified time", 0), "at 00:01 · 0s ago");
        let text = panel_text(&verify_panel(&d, &model, now(at)));
        assert!(
            text.starts_with("Verify\n────────────────────────\nVerified candidate   abababab\n"),
            "{text}"
        );
    }
}
