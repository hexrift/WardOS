//! The command centre (`docs/design-language.md` §13): a command surface over
//! `wardd` (projects, sessions, verification, permissions) as well as an
//! application launcher, opened with `Super + Space`.
//!
//! [`Launcher`] holds the entries in their four sections and the text typed so
//! far; [`Launcher::matches`] is the filtered list a renderer draws. Entries
//! that stand for sessions carry the agent states §7 names, so a project row
//! reads `payments-api   ● working`.

use std::path::PathBuf;

use ward_daemon::describe::SessionDescription;
use ward_daemon::render::Tone;
use ward_events::{AgentKind, AgentState};

use crate::feed::Model;
use crate::trust::{agent_glyph, agent_tone, agent_word, project_name};

/// The four groups of the command centre, in display order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Section {
    /// Projects `wardd` knows, with their session state.
    Projects,
    /// Start or resume an agent.
    Agents,
    /// Verification, permissions, replay.
    Security,
    /// Terminal, browser, settings.
    System,
}

impl Section {
    /// Every section, in display order.
    pub const ALL: [Self; 4] = [Self::Projects, Self::Agents, Self::Security, Self::System];

    /// The section heading as §13 sets it.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Projects => "PROJECTS",
            Self::Agents => "AGENTS",
            Self::Security => "SECURITY",
            Self::System => "SYSTEM",
        }
    }
}

/// What choosing an entry asks the shell to do. The shell carries these to
/// `ward`; it never acts on the filesystem itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Switch to the project's workspace.
    OpenProject {
        /// The project worktree.
        worktree: PathBuf,
    },
    /// `ward claude` / `ward codex` in the current project.
    StartAgent {
        /// Which agent.
        kind: AgentKind,
    },
    /// Attach to a live session.
    ResumeSession {
        /// Session id.
        session: String,
    },
    /// `ward verify` on the current project.
    VerifyProject,
    /// Open the semantic settings (§14) for the current session.
    ReviewPermissions,
    /// `ward replay` of a sealed session.
    ReplaySession {
        /// Session id.
        session: String,
    },
    /// A terminal.
    Terminal,
    /// A browser.
    Browser,
    /// System settings.
    Settings,
}

/// One row of the command centre.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its section.
    pub section: Section,
    /// The label, in sans.
    pub label: String,
    /// A secondary text: the session state of a project, the project of a
    /// session.
    pub detail: Option<String>,
    /// The colour role of the detail (a state colour) — the label stays ink.
    pub tone: Tone,
    /// What choosing it does.
    pub command: Command,
}

impl Entry {
    fn fixed(section: Section, label: &str, command: Command) -> Self {
        Self {
            section,
            label: label.to_owned(),
            detail: None,
            tone: Tone::Ink,
            command,
        }
    }

    /// Whether the entry matches typed text: a case-insensitive substring of
    /// the label, the detail or the section title. Empty text matches all.
    #[must_use]
    pub fn matches(&self, query: &str) -> bool {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        self.label.to_lowercase().contains(&q)
            || self
                .detail
                .as_ref()
                .is_some_and(|d| d.to_lowercase().contains(&q))
            || self.section.title().to_lowercase().contains(&q)
    }
}

/// A session as the command centre lists it: the facts from its description
/// and the state from its stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCard {
    /// Session id.
    pub session: String,
    /// Project name.
    pub project: String,
    /// Project worktree.
    pub worktree: PathBuf,
    /// The agent's product name, when recorded.
    pub agent: Option<String>,
    /// The agent's last reported state.
    pub state: Option<AgentState>,
    /// The log is sealed.
    pub sealed: bool,
}

impl SessionCard {
    /// The card for a session, from its description and what its stream said.
    #[must_use]
    pub fn new(d: &SessionDescription, model: &Model) -> Self {
        Self {
            session: d.session.clone(),
            project: project_name(&d.worktree),
            worktree: d.worktree.clone(),
            agent: d.agent.as_ref().map(|a| a.name.clone()),
            state: model.state.agent,
            sealed: model.sealed,
        }
    }

    /// The state text and its tone: `● working` in the state's colour, `sealed`
    /// dim, `live` accent when the agent has not reported yet.
    #[must_use]
    pub fn status(&self) -> (String, Tone) {
        if self.sealed {
            return ("sealed".to_owned(), Tone::Dim);
        }
        match self.state {
            Some(s) => (
                format!("{} {}", agent_glyph(s), agent_word(s)),
                agent_tone(s),
            ),
            None => ("live".to_owned(), Tone::Accent),
        }
    }
}

/// The command centre's model: every entry, and the text typed so far.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launcher {
    entries: Vec<Entry>,
    query: String,
}

impl Launcher {
    /// The command centre for `sessions` (newest first): one PROJECTS row per
    /// worktree, a `Resume session` per live session, `Replay last session` for
    /// the newest sealed one, and the fixed AGENTS, SECURITY and SYSTEM rows.
    #[must_use]
    pub fn new(sessions: &[SessionCard]) -> Self {
        let mut entries = Vec::new();
        let mut seen = Vec::new();
        for card in sessions {
            if seen.contains(&card.worktree) {
                continue;
            }
            seen.push(card.worktree.clone());
            let (status, tone) = card.status();
            entries.push(Entry {
                section: Section::Projects,
                label: card.project.clone(),
                detail: Some(status),
                tone,
                command: Command::OpenProject {
                    worktree: card.worktree.clone(),
                },
            });
        }
        entries.push(Entry::fixed(
            Section::Agents,
            "Start Claude",
            Command::StartAgent {
                kind: AgentKind::ClaudeCode,
            },
        ));
        entries.push(Entry::fixed(
            Section::Agents,
            "Start Codex",
            Command::StartAgent {
                kind: AgentKind::Codex,
            },
        ));
        for card in sessions.iter().filter(|c| !c.sealed) {
            let (status, tone) = card.status();
            entries.push(Entry {
                section: Section::Agents,
                label: "Resume session".to_owned(),
                detail: Some(format!("{} · {status}", card.project)),
                tone,
                command: Command::ResumeSession {
                    session: card.session.clone(),
                },
            });
        }
        entries.push(Entry::fixed(
            Section::Security,
            "Verify current project",
            Command::VerifyProject,
        ));
        entries.push(Entry::fixed(
            Section::Security,
            "Review permissions",
            Command::ReviewPermissions,
        ));
        if let Some(card) = sessions.iter().find(|c| c.sealed) {
            entries.push(Entry {
                section: Section::Security,
                label: "Replay last session".to_owned(),
                detail: Some(card.project.clone()),
                tone: Tone::Dim,
                command: Command::ReplaySession {
                    session: card.session.clone(),
                },
            });
        }
        entries.push(Entry::fixed(Section::System, "Terminal", Command::Terminal));
        entries.push(Entry::fixed(Section::System, "Browser", Command::Browser));
        entries.push(Entry::fixed(Section::System, "Settings", Command::Settings));
        Self {
            entries,
            query: String::new(),
        }
    }

    /// Every entry, in section order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The text typed so far.
    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Replace the typed text.
    pub fn set_query(&mut self, query: impl Into<String>) {
        self.query = query.into();
    }

    /// Type one character.
    pub fn push(&mut self, c: char) {
        self.query.push(c);
    }

    /// Erase the last character.
    pub fn pop(&mut self) {
        self.query.pop();
    }

    /// Clear the typed text.
    pub fn clear(&mut self) {
        self.query.clear();
    }

    /// The entries that match the typed text, in section order.
    #[must_use]
    pub fn matches(&self) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| e.matches(&self.query))
            .collect()
    }

    /// The matching entries grouped by section; sections with no match are
    /// left out, so a filtered list never shows an empty heading.
    #[must_use]
    pub fn sections(&self) -> Vec<(Section, Vec<&Entry>)> {
        Section::ALL
            .into_iter()
            .filter_map(|section| {
                let rows: Vec<&Entry> = self
                    .matches()
                    .into_iter()
                    .filter(|e| e.section == section)
                    .collect();
                (!rows.is_empty()).then_some((section, rows))
            })
            .collect()
    }

    /// The §13 layout as text: the host mark, the search line, and each
    /// section with its heading.
    #[must_use]
    pub fn text(&self) -> String {
        let mut s = String::from("WARD\n\n");
        if self.query.is_empty() {
            s.push_str("Search anything…\n");
        } else {
            s.push_str(&self.query);
            s.push('\n');
        }
        for (section, rows) in self.sections() {
            s.push('\n');
            s.push_str(section.title());
            s.push('\n');
            for row in rows {
                s.push_str(&row.label);
                if let Some(detail) = &row.detail {
                    s.push_str("   ");
                    s.push_str(detail);
                }
                s.push('\n');
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::feed::fixtures::{agent, ended, wardd};
    use crate::trust::fixtures::description;
    use ward_policy::NetworkCapability;

    fn card(project: &str, session: &str, state: Option<AgentState>, sealed: bool) -> SessionCard {
        SessionCard {
            session: session.to_owned(),
            project: project.to_owned(),
            worktree: PathBuf::from("/home/dev").join(project),
            agent: Some("claude".to_owned()),
            state,
            sealed,
        }
    }

    #[test]
    fn a_card_takes_its_facts_from_the_description_and_its_state_from_the_stream() {
        let d = description(NetworkCapability::Development);
        let mut model = Model::new(false);
        let card = SessionCard::new(&d, &model);
        assert_eq!(card.project, "payments-api");
        assert_eq!(card.worktree, PathBuf::from("/home/dev/payments-api"));
        assert_eq!(card.agent.as_deref(), Some("claude"));
        assert_eq!(card.status(), ("live".to_owned(), Tone::Accent));

        model.apply(wardd(&[agent(AgentState::Waiting)]).remove(0));
        let card = SessionCard::new(&d, &model);
        assert_eq!(card.state, Some(AgentState::Waiting));
        assert_eq!(card.status(), ("▲ waiting".to_owned(), Tone::Warn));

        model.apply(wardd(&[ended()]).remove(0));
        model.seal();
        let card = SessionCard::new(&d, &model);
        assert!(card.sealed);
        assert_eq!(card.status(), ("sealed".to_owned(), Tone::Dim));
    }

    #[test]
    fn the_launcher_lists_the_four_sections_in_order_with_session_rows() {
        let sessions = [
            card(
                "payments-api",
                "sess_live",
                Some(AgentState::Working),
                false,
            ),
            card("tamperward", "sess_old", Some(AgentState::Finished), true),
            card("payments-api", "sess_older", None, true),
        ];
        let launcher = Launcher::new(&sessions);
        let sections = launcher.sections();
        let titles: Vec<&str> = sections.iter().map(|(s, _)| s.title()).collect();
        assert_eq!(titles, ["PROJECTS", "AGENTS", "SECURITY", "SYSTEM"]);

        let projects: Vec<&str> = sections[0].1.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(
            projects,
            ["payments-api", "tamperward"],
            "one row per worktree"
        );
        assert_eq!(sections[0].1[0].detail.as_deref(), Some("● working"));
        assert_eq!(sections[0].1[0].tone, Tone::Accent);
        assert_eq!(sections[0].1[1].detail.as_deref(), Some("sealed"));
        assert_eq!(
            sections[0].1[0].command,
            Command::OpenProject {
                worktree: PathBuf::from("/home/dev/payments-api")
            }
        );

        let agents: Vec<&str> = sections[1].1.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(agents, ["Start Claude", "Start Codex", "Resume session"]);
        assert_eq!(
            sections[1].1[2].command,
            Command::ResumeSession {
                session: "sess_live".to_owned()
            }
        );
        assert_eq!(
            sections[1].1[2].detail.as_deref(),
            Some("payments-api · ● working")
        );

        let security: Vec<&str> = sections[2].1.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(
            security,
            [
                "Verify current project",
                "Review permissions",
                "Replay last session"
            ]
        );
        assert_eq!(
            sections[2].1[2].command,
            Command::ReplaySession {
                session: "sess_old".to_owned()
            },
            "the newest sealed session"
        );

        let system: Vec<&str> = sections[3].1.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(system, ["Terminal", "Browser", "Settings"]);
        assert_eq!(launcher.entries().len(), 11);
        assert!(
            launcher
                .text()
                .starts_with("WARD\n\nSearch anything…\n\nPROJECTS\npayments-api   ● working\n")
        );
    }

    #[test]
    fn without_sessions_the_fixed_rows_remain() {
        let launcher = Launcher::new(&[]);
        let titles: Vec<&str> = launcher.sections().iter().map(|(s, _)| s.title()).collect();
        assert_eq!(
            titles,
            ["AGENTS", "SECURITY", "SYSTEM"],
            "no empty PROJECTS heading"
        );
        assert!(
            launcher
                .entries()
                .iter()
                .all(|e| e.label != "Resume session")
        );
        assert!(
            launcher
                .entries()
                .iter()
                .all(|e| e.label != "Replay last session")
        );
    }

    #[test]
    fn typed_text_filters_by_label_detail_or_section_case_insensitively() {
        let sessions = [card(
            "payments-api",
            "sess_live",
            Some(AgentState::Blocked),
            false,
        )];
        let mut launcher = Launcher::new(&sessions);
        assert_eq!(launcher.matches().len(), launcher.entries().len());

        launcher.set_query("PAY");
        let labels: Vec<&str> = launcher
            .matches()
            .iter()
            .map(|e| e.label.as_str())
            .collect();
        assert_eq!(
            labels,
            ["payments-api", "Resume session"],
            "label and detail"
        );

        launcher.set_query("blocked");
        assert_eq!(launcher.matches().len(), 2, "the state word is searchable");

        launcher.set_query("sec");
        let labels: Vec<&str> = launcher
            .matches()
            .iter()
            .map(|e| e.label.as_str())
            .collect();
        assert_eq!(labels, ["Verify current project", "Review permissions"]);
        assert_eq!(launcher.sections().len(), 1);
        assert_eq!(launcher.sections()[0].0, Section::Security);

        launcher.clear();
        for c in "term".chars() {
            launcher.push(c);
        }
        assert_eq!(launcher.query(), "term");
        assert_eq!(launcher.matches().len(), 1);
        assert_eq!(launcher.matches()[0].command, Command::Terminal);
        launcher.pop();
        assert_eq!(launcher.query(), "ter");
        launcher.set_query("  ");
        assert_eq!(
            launcher.matches().len(),
            launcher.entries().len(),
            "blank is empty"
        );
        launcher.set_query("zzz");
        assert!(launcher.matches().is_empty());
        assert!(launcher.sections().is_empty());
        assert_eq!(launcher.text(), "WARD\n\nzzz\n");
    }
}
