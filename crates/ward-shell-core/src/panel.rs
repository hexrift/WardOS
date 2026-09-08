//! The session panel (`docs/design-language.md` §6): what opens when the
//! agent segment of the trust bar is chosen.
//!
//! Two groups, `Session` and `TamperWard`, of read-only [`Row`]s. The session
//! rows come from the description; the verification and evidence rows from
//! the stream. The design's `Verifier  isolated` row is an architectural fact
//! the stream does not carry, so it is not shown until a verifier record does.

use ward_daemon::describe::SessionDescription;
use ward_daemon::render::{Tone, network_text, observer_text};
use ward_policy::AccessMode;

use crate::feed::{Model, TamperWard, Verification};
use crate::settings::Row;

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
    let (verify, verify_tone) = match model.state.verification {
        Verification::NotRun => ("none", Tone::Dim),
        Verification::Running => ("running", Tone::Accent),
        Verification::Passed => ("pass", Tone::Ok),
        Verification::Failed => ("fail", Tone::Deny),
    };
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
    use crate::feed::fixtures::{denied, records, verify_passed, wardd};
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
    }
}
