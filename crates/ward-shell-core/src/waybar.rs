//! The trust bar as Waybar custom modules (ADR-0016): until the shell has
//! its own toolkit, Waybar draws the bar from what `ward-shell bar --waybar`
//! prints, one [`Module`] per segment or one for the whole row.
//!
//! What is shown, its order, words and colour roles come from [`TrustBar`];
//! Waybar is the pixel renderer. A module's `class` carries the colour role by
//! its §3 name (`dim`, `ink`, `accent`, `verified`, `restricted`, `denied`) so
//! the theme's `waybar.css` colours the glyph and the word and nothing else,
//! plus the agent's state word on the agent module and `live`/`sealed` on the
//! whole-bar module. A segment the stream has not established, and every
//! segment but the host mark when there is no session, is the empty module
//! (`text: ""`, class `none`), which Waybar hides.

use serde::Serialize;

use ward_daemon::describe::SessionDescription;

use crate::feed::Model;
use crate::panel::{Group, panel_text, session_panel};
use crate::settings::{Row, rows_text};
use crate::trust::{Header, SegmentName, TrustBar, agent_word, tone_name};
use ward_daemon::render::Tone;

/// One Waybar custom module's JSON (`return-type: json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Module {
    /// The module's text; empty hides it.
    pub text: String,
    /// The hover text: the session panel for the bar, an explanation for a
    /// segment.
    pub tooltip: String,
    /// CSS classes: the colour role, and what else the module says.
    pub class: Vec<String>,
}

impl Module {
    /// The empty module for a segment with nothing to show; the host mark with
    /// no session is `WARD`, dim, since the host layer is always there.
    #[must_use]
    pub fn none(segment: Option<SegmentName>) -> Self {
        match segment {
            Some(SegmentName::Mark) => Self {
                text: "WARD".to_owned(),
                tooltip: "no session".to_owned(),
                class: vec![tone_name(Tone::Dim).to_owned()],
            },
            _ => Self {
                text: String::new(),
                tooltip: String::new(),
                class: vec!["none".to_owned()],
            },
        }
    }

    /// The whole bar as one module: the row's text, the session panel as the
    /// tooltip, `live`/`sealed` and the bar's state tone as classes.
    #[must_use]
    pub fn bar(d: &SessionDescription, header: &Header, model: &Model, now_unix_ms: u64) -> Self {
        let bar = TrustBar::new(header, model);
        let state = if bar.sealed { "sealed" } else { "live" };
        Self {
            text: bar.text(),
            tooltip: panel_text(&session_panel(d, model, now_unix_ms))
                .trim_end()
                .to_owned(),
            class: vec![state.to_owned(), tone_name(bar.tone()).to_owned()],
        }
    }

    /// One segment as a module: its text, its explanation, its tone (and the
    /// agent's state word).
    #[must_use]
    pub fn segment(
        d: &SessionDescription,
        header: &Header,
        model: &Model,
        name: SegmentName,
        now_unix_ms: u64,
    ) -> Self {
        let bar = TrustBar::new(header, model);
        let Some(segment) = bar.segment(name) else {
            return Self::none(Some(name));
        };
        let mut class = vec![tone_name(segment.tone).to_owned()];
        if let (SegmentName::Agent, Some(state)) = (name, model.state.agent) {
            class.push(agent_word(state).to_owned());
        }
        Self {
            text: segment.text,
            tooltip: explanation(d, model, &bar, name, now_unix_ms),
            class,
        }
    }
}

/// The hover text of a segment: the session panel's rows that explain it.
fn explanation(
    d: &SessionDescription,
    model: &Model,
    bar: &TrustBar,
    name: SegmentName,
    now_unix_ms: u64,
) -> String {
    let panel = session_panel(d, model, now_unix_ms);
    let row = |label: &str| panel_row(&panel, label);
    let state = if bar.sealed { "sealed" } else { "live" };
    let rows = match name {
        SegmentName::Mark => vec![
            Row::new("Session", d.session.clone(), Tone::Ink),
            Row::new("Log", state, Tone::Ink),
        ],
        SegmentName::Session => vec![
            Row::new("Session", d.session.clone(), Tone::Ink),
            row("Duration"),
        ],
        SegmentName::Project => vec![Row::new(
            "Worktree",
            d.worktree.display().to_string(),
            Tone::Ink,
        )],
        SegmentName::Agent => {
            let word = model.state.agent.map_or("unknown", agent_word);
            vec![row("Agent"), Row::new("State", word, Tone::Ink)]
        }
        SegmentName::Network => vec![row("Network")],
        SegmentName::Credentials => vec![row("Secrets")],
        SegmentName::Observer => vec![row("Observer")],
        SegmentName::Tamperward => vec![row("Policy"), row("Evidence")],
        SegmentName::Verify => vec![row("Last verify")],
        SegmentName::Daemon => vec![Row::new("Log", state, Tone::Ink), row("Duration")],
    };
    rows_text(&rows).trim_end().to_owned()
}

/// The panel row with `label`, whichever group holds it; a row that says so
/// when the panel has none (a label typo is then visible, not silent).
fn panel_row(panel: &[Group], label: &str) -> Row {
    panel
        .iter()
        .flat_map(|g| g.rows.iter())
        .find(|r| r.label == label)
        .cloned()
        .unwrap_or_else(|| Row::new(label, "unknown", Tone::Dim))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::feed::fixtures::{
        agent, denied, ended, model_with, records, sequence, verify_passed, wardd,
    };
    use crate::trust::fixtures::description;
    use ward_events::{AgentState, Origin};
    use ward_policy::NetworkCapability;

    fn live() -> (SessionDescription, Header, Model) {
        let d = description(NetworkCapability::Development);
        let header = Header::from_description(&d);
        let mut model = model_with(&sequence(), false);
        model.apply(wardd(&[verify_passed()]).remove(0));
        model.apply(records(&[(Origin::TamperWard, denied())]).remove(0));
        (d, header, model)
    }

    fn sealed() -> (SessionDescription, Header, Model) {
        let (d, header, mut model) = live();
        model.apply(wardd(&[ended()]).remove(0));
        model.seal();
        (d, header, model)
    }

    fn now(d: &SessionDescription) -> u64 {
        d.started_unix_ms + (12 * 60 + 43) * 1000
    }

    #[test]
    fn the_whole_bar_is_one_module_with_the_panel_as_tooltip() {
        let (d, header, model) = live();
        let module = Module::bar(&d, &header, &model, now(&d));
        assert_eq!(
            module.text,
            "● WARD │ sess_01J8ZK3… │ payments-api │ CLAUDE ● working │ NET restricted (dev) │ CRED 0 granted │ OBS live │ TW ✓ │ VERIFY ✓ │ LIVE"
        );
        assert_eq!(module.class, ["live", "restricted"]);
        assert!(
            module.tooltip.starts_with("Session\n"),
            "{}",
            module.tooltip
        );
        assert!(
            module.tooltip.contains("Duration     12m 43s\n"),
            "{}",
            module.tooltip
        );
        assert!(module.tooltip.ends_with("Evidence      clean"));

        let (d, header, model) = sealed();
        let module = Module::bar(&d, &header, &model, now(&d));
        assert!(module.text.starts_with("■ WARD"));
        assert!(module.text.ends_with("│ SEALED"));
        assert_eq!(module.class, ["sealed", "dim"]);
    }

    #[test]
    fn every_segment_is_a_module_in_the_live_state() {
        let (d, header, model) = live();
        let module = |name| Module::segment(&d, &header, &model, name, now(&d));
        let cases = [
            (SegmentName::Mark, "WARD", vec!["accent"], "Log       live"),
            (
                SegmentName::Session,
                "sess_01J8ZK3…",
                vec!["dim"],
                "Duration   12m 43s",
            ),
            (
                SegmentName::Project,
                "payments-api",
                vec!["ink"],
                "Worktree   /home/dev/payments-api",
            ),
            (
                SegmentName::Agent,
                "CLAUDE ● working",
                vec!["accent", "working"],
                "State   working",
            ),
            (
                SegmentName::Network,
                "NET restricted (dev)",
                vec!["restricted"],
                "Network   restricted (dev)",
            ),
            (
                SegmentName::Credentials,
                "CRED 0 granted",
                vec!["ink"],
                "Secrets   none",
            ),
            (
                SegmentName::Observer,
                "OBS live",
                vec!["ink"],
                "Observer   live",
            ),
            (
                SegmentName::Tamperward,
                "TW ✓",
                vec!["verified"],
                "Evidence   clean",
            ),
            (
                SegmentName::Verify,
                "VERIFY ✓",
                vec!["verified"],
                "Last verify   pass",
            ),
            (
                SegmentName::Daemon,
                "LIVE",
                vec!["restricted"],
                "Duration   12m 43s",
            ),
        ];
        for (name, text, class, tooltip_line) in cases {
            let m = module(name);
            assert_eq!(m.text, text, "{name}");
            assert_eq!(m.class, class, "{name}");
            assert!(
                m.tooltip.lines().any(|l| l == tooltip_line),
                "{name}: {}",
                m.tooltip
            );
        }
        assert_eq!(
            module(SegmentName::Agent).tooltip,
            "Agent   claude 1.2.3\nState   working"
        );
        assert_eq!(
            module(SegmentName::Tamperward).tooltip.lines().count(),
            2,
            "policy and evidence"
        );
    }

    #[test]
    fn every_segment_is_a_module_in_the_sealed_state() {
        let (d, header, model) = sealed();
        let module = |name| Module::segment(&d, &header, &model, name, now(&d));
        let cases = [
            (SegmentName::Mark, "WARD", vec!["dim"]),
            (SegmentName::Session, "sess_01J8ZK3…", vec!["dim"]),
            (SegmentName::Project, "payments-api", vec!["ink"]),
            (
                SegmentName::Agent,
                "CLAUDE ● working",
                vec!["dim", "working"],
            ),
            (SegmentName::Network, "NET restricted (dev)", vec!["dim"]),
            (SegmentName::Credentials, "CRED 0 granted", vec!["ink"]),
            (SegmentName::Observer, "OBS live", vec!["ink"]),
            (SegmentName::Tamperward, "TW ✓", vec!["verified"]),
            (SegmentName::Verify, "VERIFY ✓", vec!["verified"]),
            (SegmentName::Daemon, "SEALED", vec!["dim"]),
        ];
        for (name, text, class) in cases {
            let m = module(name);
            assert_eq!(m.text, text, "{name}");
            assert_eq!(m.class, class, "{name}");
        }
        assert_eq!(
            module(SegmentName::Mark).tooltip,
            "Session   sess_01J8ZK3Q9X7VY2\nLog       sealed"
        );
        assert!(
            module(SegmentName::Daemon)
                .tooltip
                .starts_with("Log        sealed\n")
        );
    }

    #[test]
    fn every_segment_is_the_empty_module_with_no_session_except_the_mark() {
        for name in SegmentName::ALL {
            let m = Module::none(Some(name));
            if name == SegmentName::Mark {
                assert_eq!(m.text, "WARD");
                assert_eq!(m.class, ["dim"]);
                assert_eq!(m.tooltip, "no session");
            } else {
                assert_eq!(m.text, "", "{name}");
                assert_eq!(m.class, ["none"], "{name}");
                assert_eq!(m.tooltip, "", "{name}");
            }
        }
        assert_eq!(Module::none(None).class, ["none"], "the whole bar");
    }

    #[test]
    fn a_segment_the_stream_has_not_said_is_the_empty_module_even_when_live() {
        let d = description(NetworkCapability::Offline);
        let header = Header::from_description(&d);
        let model = Model::new(false);
        for name in [
            SegmentName::Agent,
            SegmentName::Tamperward,
            SegmentName::Verify,
        ] {
            let m = Module::segment(&d, &header, &model, name, now(&d));
            assert_eq!(m, Module::none(Some(name)), "{name}");
        }
        let mut model = model;
        model.apply(wardd(&[agent(AgentState::Blocked)]).remove(0));
        let m = Module::segment(&d, &header, &model, SegmentName::Agent, now(&d));
        assert_eq!(m.text, "CLAUDE ■ blocked");
        assert_eq!(m.class, ["denied", "blocked"]);
        let daemon = Module::segment(&d, &header, &model, SegmentName::Daemon, now(&d));
        assert_eq!(daemon.class, ["verified"], "offline is the verified tone");
    }
}
