//! The trust bar (`docs/design-language.md` §6): trust state, not system trivia.
//!
//! [`Header`] holds the session facts that never change; [`TrustBar`] joins them
//! with the [`SessionState`](crate::feed::SessionState) the stream has
//! established so far. Every segment carries its own colour role, and state
//! colour sits on the marker and the state words, never on the whole bar (§3).
//! The bar the `ward watch` TUI draws
//! is [`TrustBar::from_header`]: the stream-independent segments only, exactly
//! as `docs/design-language.md` "As built: `ward watch`" describes it. The shell
//! adds the agent, TamperWard and verification segments as the stream reports
//! them ([`TrustBar::new`]).

use std::path::Path;

use ward_daemon::SessionMeta;
use ward_daemon::describe::SessionDescription;
use ward_daemon::render::{self, Tone, network_tone};
use ward_events::AgentState;
use ward_policy::{CapabilityManifest, NetworkCapability};

use crate::feed::{Model, TamperWard, Verification};

/// The session facts the trust bar shows. Fixed for the session's lifetime; the
/// daemon state ([`Model::sealed`]) and the stream-derived segments are the
/// things on the bar that change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Session id (`sess_…`), shown in short form.
    pub session: String,
    /// Project name (the worktree's last path component).
    pub project: String,
    /// The agent's product name as recorded, when one was.
    pub agent: Option<String>,
    /// Network mode; its tone is the bar's state colour.
    pub network: NetworkCapability,
    /// Credential rules that grant outright.
    pub credentials_granted: usize,
    /// Observer mode as the panels name it.
    pub observer: &'static str,
}

impl Header {
    /// The trust bar facts of a session, from its description.
    #[must_use]
    pub fn from_description(d: &SessionDescription) -> Self {
        let agent = d.agent.as_ref().map(|a| a.name.clone());
        Self::build(&d.session, &d.worktree, agent, &d.manifest)
    }

    /// The trust bar facts of a session, from its persisted metadata.
    #[must_use]
    pub fn from_meta(meta: &SessionMeta) -> Self {
        let agent = meta.agent.as_ref().map(|a| a.name.as_str().to_owned());
        Self::build(&meta.id, &meta.project, agent, &meta.manifest)
    }

    fn build(
        session: &str,
        worktree: &Path,
        agent: Option<String>,
        manifest: &CapabilityManifest,
    ) -> Self {
        Self {
            session: session.to_owned(),
            project: project_name(worktree),
            agent,
            network: manifest.network.clone(),
            credentials_granted: render::credentials_granted(manifest),
            observer: render::observer_text(manifest.observer),
        }
    }
}

/// The project name the bar shows: the worktree's last path component.
#[must_use]
pub fn project_name(worktree: &Path) -> String {
    worktree.file_name().map_or_else(
        || worktree.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// The colour that carries the trust bar's state: dim neutral once the log is
/// sealed, otherwise the network mode's tone (verified green for offline,
/// restricted amber for every limited mode, red for open).
#[must_use]
pub const fn trust_tone(network: &NetworkCapability, sealed: bool) -> Tone {
    if sealed {
        Tone::Dim
    } else {
        network_tone(network)
    }
}

/// `sess_01J…`: the session id cut to twelve characters plus an ellipsis.
#[must_use]
pub fn short_id(id: &str) -> String {
    const KEEP: usize = 12;
    if id.chars().count() <= KEEP + 1 {
        id.to_owned()
    } else {
        let mut s: String = id.chars().take(KEEP).collect();
        s.push('…');
        s
    }
}

/// The agent's glyph (`docs/design-language.md` §7): a small geometric mark,
/// never an avatar.
#[must_use]
pub const fn agent_glyph(state: AgentState) -> &'static str {
    match state {
        AgentState::Idle => "◌",
        AgentState::Working => "●",
        AgentState::Waiting => "▲",
        AgentState::Blocked => "■",
        AgentState::Verifying => "◐",
        AgentState::Finished => "✓",
    }
}

/// The agent's state word (§7): `idle · working · waiting · blocked · verifying
/// · finished`.
#[must_use]
pub const fn agent_word(state: AgentState) -> &'static str {
    match state {
        AgentState::Idle => "idle",
        AgentState::Working => "working",
        AgentState::Waiting => "waiting",
        AgentState::Blocked => "blocked",
        AgentState::Verifying => "verifying",
        AgentState::Finished => "finished",
    }
}

/// The agent's colour role: accent while it moves (working, verifying), amber
/// while it waits on someone, red while blocked, green when finished, dim when
/// idle.
#[must_use]
pub const fn agent_tone(state: AgentState) -> Tone {
    match state {
        AgentState::Idle => Tone::Dim,
        AgentState::Working | AgentState::Verifying => Tone::Accent,
        AgentState::Waiting => Tone::Warn,
        AgentState::Blocked => Tone::Deny,
        AgentState::Finished => Tone::Ok,
    }
}

/// One piece of the trust bar: its text, its colour role, and whether it is
/// emphasised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    /// The text.
    pub text: String,
    /// The colour role.
    pub tone: Tone,
    /// Rendered bold.
    pub bold: bool,
}

impl Segment {
    /// A plain segment.
    pub fn new(text: impl Into<String>, tone: Tone) -> Self {
        Self {
            text: text.into(),
            tone,
            bold: false,
        }
    }

    /// An emphasised segment.
    pub fn bold(text: impl Into<String>, tone: Tone) -> Self {
        Self {
            bold: true,
            ..Self::new(text, tone)
        }
    }
}

/// The name of a Waybar class for a colour role: the six roles of §3 by the
/// words the design uses for them.
#[must_use]
pub const fn tone_name(tone: Tone) -> &'static str {
    match tone {
        Tone::Dim => "dim",
        Tone::Ink => "ink",
        Tone::Accent => "accent",
        Tone::Ok => "verified",
        Tone::Warn => "restricted",
        Tone::Deny => "denied",
    }
}

/// One segment of the trust bar by name, as `ward-shell bar --waybar --segment`
/// addresses it: the §6 order, with the host mark first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SegmentName {
    /// `WARD`, the host mark.
    Mark,
    /// The session id, short form.
    Session,
    /// The project name.
    Project,
    /// `CLAUDE ● working`.
    Agent,
    /// `NET restricted (dev)`.
    Network,
    /// `CRED n granted`.
    Credentials,
    /// `OBS live`.
    Observer,
    /// `TW ✓` / `TW ■`.
    Tamperward,
    /// `VERIFYING` / `VERIFY ✓` / `VERIFY ✗`.
    Verify,
    /// `LIVE` / `SEALED`.
    Daemon,
}

impl SegmentName {
    /// Every segment, in bar order.
    pub const ALL: [Self; 10] = [
        Self::Mark,
        Self::Session,
        Self::Project,
        Self::Agent,
        Self::Network,
        Self::Credentials,
        Self::Observer,
        Self::Tamperward,
        Self::Verify,
        Self::Daemon,
    ];

    /// The name on the command line and in Waybar's module names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mark => "mark",
            Self::Session => "session",
            Self::Project => "project",
            Self::Agent => "agent",
            Self::Network => "network",
            Self::Credentials => "credentials",
            Self::Observer => "observer",
            Self::Tamperward => "tamperward",
            Self::Verify => "verify",
            Self::Daemon => "daemon",
        }
    }
}

impl std::str::FromStr for SegmentName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|n| n.as_str() == s)
            .ok_or_else(|| {
                let names: Vec<&str> = Self::ALL.iter().map(|n| n.as_str()).collect();
                format!("unknown segment `{s}` (one of {})", names.join(", "))
            })
    }
}

impl std::fmt::Display for SegmentName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The trust bar's segments, left to right as §6 orders them. The three the
/// session daemon cannot know at start (`agent`, `tamperward`, `verified`) are
/// `None` until the stream reports them, and are then omitted from the row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustBar {
    /// Session id, short form, dim.
    pub session: Segment,
    /// Project name, ink.
    pub project: Segment,
    /// `CLAUDE ● working`: name, glyph and state word in the state's tone.
    pub agent: Option<Segment>,
    /// The network mode, in the bar's state tone.
    pub network: Segment,
    /// `CRED n granted`: amber once anything is granted outright.
    pub credentials: Segment,
    /// `OBS live`, ink.
    pub observer: Segment,
    /// `TW ✓` green, or `TW ■` red once tampering was detected.
    pub tamperward: Option<Segment>,
    /// `VERIFYING` accent, `VERIFY ✓` green, `VERIFY ✗` red.
    pub verified: Option<Segment>,
    /// `LIVE` or `SEALED`, bold, in the state tone.
    pub daemon: Segment,
    /// The log is sealed: the marker is `■` and the state tone is dim.
    pub sealed: bool,
}

impl TrustBar {
    /// The bar from the session facts alone: what `ward watch` shows.
    #[must_use]
    pub fn from_header(header: &Header, sealed: bool) -> Self {
        let tone = trust_tone(&header.network, sealed);
        let cred_tone = if header.credentials_granted == 0 {
            Tone::Ink
        } else {
            Tone::Warn
        };
        let state = if sealed { "SEALED" } else { "LIVE" };
        Self {
            session: Segment::new(short_id(&header.session), Tone::Dim),
            project: Segment::new(header.project.clone(), Tone::Ink),
            agent: None,
            network: Segment::new(render::network_text(&header.network), tone),
            credentials: Segment::new(
                format!("CRED {} granted", header.credentials_granted),
                cred_tone,
            ),
            observer: Segment::new(format!("OBS {}", header.observer), Tone::Ink),
            tamperward: None,
            verified: None,
            daemon: Segment::bold(state, tone),
            sealed,
        }
    }

    /// The bar from the session facts and everything the stream has said: the
    /// shell's bar.
    #[must_use]
    pub fn new(header: &Header, model: &Model) -> Self {
        let state = &model.state;
        let mut bar = Self::from_header(header, model.sealed);
        bar.agent = state.agent.map(|s| agent_segment(header, s, model.sealed));
        bar.tamperward = match state.tamperward {
            TamperWard::Unknown => None,
            TamperWard::Clean => Some(Segment::new("TW ✓", Tone::Ok)),
            TamperWard::Tampered => Some(Segment::new("TW ■", Tone::Deny)),
        };
        bar.verified = match state.verification {
            Verification::NotRun => None,
            Verification::Running => Some(Segment::new("VERIFYING", Tone::Accent)),
            Verification::Passed => Some(Segment::new("VERIFY ✓", Tone::Ok)),
            Verification::Failed => Some(Segment::new("VERIFY ✗", Tone::Deny)),
        };
        bar
    }

    /// The host mark as a module of its own: `WARD`, accent while the session
    /// is live, dim once the log is sealed. In the row it is always accent (the
    /// host layer never changes); alone on a bar whose other modules are
    /// hidden it is the one place the session's state still shows.
    #[must_use]
    pub fn mark(&self) -> Segment {
        let tone = if self.sealed { Tone::Dim } else { Tone::Accent };
        Segment::bold("WARD", tone)
    }

    /// One segment by name: `None` for a stream-derived segment the stream has
    /// not established yet. The network segment carries its `NET ` prefix, as
    /// the row shows it.
    #[must_use]
    pub fn segment(&self, name: SegmentName) -> Option<Segment> {
        Some(match name {
            SegmentName::Mark => self.mark(),
            SegmentName::Session => self.session.clone(),
            SegmentName::Project => self.project.clone(),
            SegmentName::Agent => self.agent.clone()?,
            SegmentName::Network => {
                Segment::new(format!("NET {}", self.network.text), self.network.tone)
            }
            SegmentName::Credentials => self.credentials.clone(),
            SegmentName::Observer => self.observer.clone(),
            SegmentName::Tamperward => self.tamperward.clone()?,
            SegmentName::Verify => self.verified.clone()?,
            SegmentName::Daemon => self.daemon.clone(),
        })
    }

    /// The tone that carries the bar's state (the marker, the network mode and
    /// the daemon word share it).
    #[must_use]
    pub const fn tone(&self) -> Tone {
        self.daemon.tone
    }

    /// The bar as one row of segments: state marker, host mark, then the
    /// segments in §6 order with a dim `│` between them.
    #[must_use]
    pub fn row(&self) -> Vec<Segment> {
        let sep = || Segment::new(" │ ", Tone::Dim);
        let marker = if self.sealed { "■ " } else { "● " };
        let mut row = vec![
            Segment::new(marker, self.tone()),
            Segment::bold("WARD", Tone::Accent),
            sep(),
            self.session.clone(),
            sep(),
            self.project.clone(),
        ];
        if let Some(agent) = &self.agent {
            row.push(sep());
            row.push(agent.clone());
        }
        row.extend([
            sep(),
            Segment::new("NET ", Tone::Ink),
            self.network.clone(),
            sep(),
            self.credentials.clone(),
            sep(),
            self.observer.clone(),
        ]);
        for verdict in [&self.tamperward, &self.verified].into_iter().flatten() {
            row.push(sep());
            row.push(verdict.clone());
        }
        row.push(sep());
        row.push(self.daemon.clone());
        row
    }

    /// Text of the bar, uncoloured: the row's segments joined.
    #[must_use]
    pub fn text(&self) -> String {
        self.row().iter().map(|s| s.text.as_str()).collect()
    }
}

/// `CLAUDE ● working`: the agent's name in capitals, its glyph and its state
/// word. Dim once the log is sealed: the agent is gone, whatever it last said.
fn agent_segment(header: &Header, state: AgentState, sealed: bool) -> Segment {
    let name = header
        .agent
        .as_deref()
        .map_or_else(|| "AGENT".to_owned(), str::to_uppercase);
    let tone = if sealed { Tone::Dim } else { agent_tone(state) };
    Segment::new(
        format!("{name} {} {}", agent_glyph(state), agent_word(state)),
        tone,
    )
}

/// The trust bar of `ward watch`, as segments: [`TrustBar::from_header`]'s row.
#[must_use]
pub fn trust_bar_segments(header: &Header, sealed: bool) -> Vec<Segment> {
    TrustBar::from_header(header, sealed).row()
}

/// Text of the trust bar of `ward watch`, uncoloured.
#[must_use]
pub fn trust_bar_text(header: &Header, sealed: bool) -> String {
    TrustBar::from_header(header, sealed).text()
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! A session description shared by the crate's tests.
    use std::path::PathBuf;

    use ward_daemon::describe::{AgentDescription, SessionDescription};
    use ward_policy::{NetworkCapability, Policy, merge};

    /// A described session on `payments-api`, Claude recorded, the default
    /// manifest with `network` overridden.
    pub fn description(network: NetworkCapability) -> SessionDescription {
        let mut manifest = merge(
            &Policy::default(),
            &Policy::default(),
            &Policy::default(),
            ward_policy::SessionId("sess_01J8ZK3Q9X7VY2".to_owned()),
            ward_policy::ProjectId("proj_x".to_owned()),
        );
        manifest.network = network;
        SessionDescription {
            session: "sess_01J8ZK3Q9X7VY2".to_owned(),
            project: "proj_x".to_owned(),
            worktree: PathBuf::from("/home/dev/payments-api"),
            started_unix_ms: 1_700_000_000_000,
            agent: Some(AgentDescription {
                kind: "claude_code".to_owned(),
                name: "claude".to_owned(),
                version: "1.2.3".to_owned(),
                image: None,
            }),
            entry_snapshot: format!("blake3:{}", "ab".repeat(32)),
            policy_hash: manifest.policy_hash.to_hex(),
            manifest,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::fixtures::description;
    use super::*;
    use crate::feed::fixtures::{
        agent, denied, ended, model_with, records, sequence, tamper, verify_failed, verify_passed,
        verify_requested, wardd,
    };
    use ward_events::Origin;
    use ward_policy::merge;

    fn header(network: NetworkCapability) -> Header {
        Header::from_description(&description(network))
    }

    #[test]
    fn header_comes_from_the_description_or_the_meta_and_ids_are_shortened() {
        let h = header(NetworkCapability::Development);
        assert_eq!(h.project, "payments-api");
        assert_eq!(h.session, "sess_01J8ZK3Q9X7VY2");
        assert_eq!(h.agent.as_deref(), Some("claude"));
        assert_eq!(h.network, NetworkCapability::Development);
        assert_eq!(h.credentials_granted, 0);
        assert_eq!(h.observer, "live");
        assert_eq!(
            trust_bar_text(&h, false),
            "● WARD │ sess_01J8ZK3… │ payments-api │ NET restricted (dev) │ CRED 0 granted │ OBS live │ LIVE"
        );

        let manifest = merge(
            &ward_policy::Policy::default(),
            &ward_policy::Policy::default(),
            &ward_policy::Policy::default(),
            ward_policy::SessionId("sess_01J8ZK3Q9X7VY2".to_owned()),
            ward_policy::ProjectId("proj_x".to_owned()),
        );
        let meta = SessionMeta {
            id: "sess_01J8ZK3Q9X7VY2".to_owned(),
            project: "/home/dev/payments-api".into(),
            project_id: "proj_x".to_owned(),
            entry_snapshot: format!("blake3:{}", "ab".repeat(32)),
            manifest,
            started_unix_ms: 0,
            agent: None,
        };
        let from_meta = Header::from_meta(&meta);
        assert_eq!(from_meta.agent, None, "nothing recorded, nothing invented");
        assert_eq!(
            Header {
                agent: Some("claude".to_owned()),
                ..from_meta
            },
            h,
            "the same facts whichever record they come from"
        );
        assert_eq!(
            project_name(Path::new("/")),
            "/",
            "a root has no last component"
        );

        assert_eq!(short_id("sess_0123"), "sess_0123");
        assert_eq!(
            short_id("sess_01234567"),
            "sess_01234567",
            "13 chars stay whole"
        );
        assert_eq!(short_id("sess_0123456789"), "sess_0123456…");
    }

    #[test]
    fn trust_tone_follows_the_network_mode_and_goes_dim_when_sealed() {
        use NetworkCapability as N;
        let custom = N::Custom(["example.com".to_owned()].into_iter().collect());
        let cases = [
            (N::Offline, Tone::Ok),
            (N::LocalhostOnly, Tone::Warn),
            (N::Registries, Tone::Warn),
            (N::Development, Tone::Warn),
            (custom.clone(), Tone::Warn),
            (N::Unrestricted, Tone::Deny),
        ];
        for (network, tone) in &cases {
            assert_eq!(trust_tone(network, false), *tone, "{network:?}");
            assert_eq!(trust_tone(network, true), Tone::Dim, "{network:?} sealed");
            let live = TrustBar::from_header(&header(network.clone()), false);
            assert_eq!(live.tone(), *tone);
            assert_eq!(live.network.tone, *tone, "the mode word carries the tone");
            assert_eq!(live.daemon.tone, *tone, "so does the daemon word");
            assert_eq!(live.row()[0].tone, *tone, "and the marker");
            assert_eq!(live.project.tone, Tone::Ink, "the project never does");
            let sealed = TrustBar::from_header(&header(network.clone()), true);
            assert_eq!(sealed.tone(), Tone::Dim);
            assert!(sealed.sealed);
            assert!(sealed.text().starts_with("■ WARD"));
            assert!(sealed.text().ends_with("│ SEALED"));
        }
        assert!(trust_bar_text(&header(N::Offline), false).contains("NET offline"));
        assert!(trust_bar_text(&header(custom), false).contains("NET allowlist (1 hosts)"));
        assert!(trust_bar_text(&header(N::Unrestricted), false).contains("NET open"));
    }

    #[test]
    fn credentials_go_amber_once_anything_is_granted() {
        let mut h = header(NetworkCapability::Offline);
        assert_eq!(TrustBar::from_header(&h, false).credentials.tone, Tone::Ink);
        h.credentials_granted = 2;
        let bar = TrustBar::from_header(&h, false);
        assert_eq!(bar.credentials.tone, Tone::Warn);
        assert_eq!(bar.credentials.text, "CRED 2 granted");
    }

    #[test]
    fn the_watch_bar_omits_what_the_stream_has_not_said() {
        let h = header(NetworkCapability::Development);
        let bar = TrustBar::from_header(&h, false);
        assert_eq!(bar.agent, None);
        assert_eq!(bar.tamperward, None);
        assert_eq!(bar.verified, None);
        assert_eq!(bar.row(), trust_bar_segments(&h, false));
        assert_eq!(bar.row().len(), 15);
        assert!(bar.row()[1].bold, "WARD");
        assert_eq!(bar.row()[1].tone, Tone::Accent);
        assert!(bar.daemon.bold);
        // A model with nothing in it changes nothing.
        assert_eq!(TrustBar::new(&h, &Model::new(false)), bar);
    }

    #[test]
    fn the_shell_bar_adds_agent_tamperward_and_verification_segments() {
        let h = header(NetworkCapability::Development);
        let mut model = model_with(&sequence(), false);
        let bar = TrustBar::new(&h, &model);
        assert_eq!(
            bar.agent,
            Some(Segment::new("CLAUDE ● working", Tone::Accent))
        );
        assert_eq!(
            bar.text(),
            "● WARD │ sess_01J8ZK3… │ payments-api │ CLAUDE ● working │ NET restricted (dev) │ CRED 0 granted │ OBS live │ LIVE"
        );

        for rec in wardd(&[verify_requested()]) {
            model.apply(rec);
        }
        let bar = TrustBar::new(&h, &model);
        assert_eq!(bar.verified, Some(Segment::new("VERIFYING", Tone::Accent)));
        model.apply(wardd(&[verify_failed()]).remove(0));
        assert_eq!(
            TrustBar::new(&h, &model).verified,
            Some(Segment::new("VERIFY ✗", Tone::Deny))
        );
        model.apply(wardd(&[verify_passed()]).remove(0));
        let bar = TrustBar::new(&h, &model);
        assert_eq!(bar.verified, Some(Segment::new("VERIFY ✓", Tone::Ok)));
        assert_eq!(
            bar.tamperward, None,
            "wardd has said nothing for TamperWard"
        );

        model.apply(records(&[(Origin::TamperWard, denied())]).remove(0));
        let bar = TrustBar::new(&h, &model);
        assert_eq!(bar.tamperward, Some(Segment::new("TW ✓", Tone::Ok)));
        assert!(
            bar.text().ends_with("│ OBS live │ TW ✓ │ VERIFY ✓ │ LIVE"),
            "{}",
            bar.text()
        );
        model.apply(records(&[(Origin::TamperWard, tamper())]).remove(0));
        assert_eq!(
            TrustBar::new(&h, &model).tamperward,
            Some(Segment::new("TW ■", Tone::Deny))
        );
    }

    #[test]
    fn every_agent_state_has_a_glyph_a_word_and_a_tone() {
        use AgentState as S;
        let cases = [
            (S::Idle, "◌", "idle", Tone::Dim),
            (S::Working, "●", "working", Tone::Accent),
            (S::Waiting, "▲", "waiting", Tone::Warn),
            (S::Blocked, "■", "blocked", Tone::Deny),
            (S::Verifying, "◐", "verifying", Tone::Accent),
            (S::Finished, "✓", "finished", Tone::Ok),
        ];
        let h = header(NetworkCapability::Offline);
        for (state, glyph, word, tone) in cases {
            assert_eq!(agent_glyph(state), glyph);
            assert_eq!(agent_word(state), word);
            assert_eq!(agent_tone(state), tone);
            let mut model = Model::new(false);
            model.apply(wardd(&[agent(state)]).remove(0));
            let segment = TrustBar::new(&h, &model).agent.unwrap();
            assert_eq!(segment.text, format!("CLAUDE {glyph} {word}"));
            assert_eq!(segment.tone, tone);
        }
        // No recorded agent: a neutral name, never an invented one.
        let mut anon = h.clone();
        anon.agent = None;
        let mut model = Model::new(false);
        model.apply(wardd(&[agent(S::Working)]).remove(0));
        assert_eq!(
            TrustBar::new(&anon, &model).agent.unwrap().text,
            "AGENT ● working"
        );
    }

    #[test]
    fn segment_names_round_trip_and_reject_strangers() {
        for name in SegmentName::ALL {
            assert_eq!(name.as_str().parse::<SegmentName>(), Ok(name));
            assert_eq!(name.to_string(), name.as_str());
        }
        let err = "clock".parse::<SegmentName>().unwrap_err();
        assert!(
            err.starts_with("unknown segment `clock` (one of mark, session"),
            "{err}"
        );
        assert!(err.ends_with("verify, daemon)"), "{err}");
    }

    #[test]
    fn tone_names_are_the_six_words_of_the_design() {
        let names: Vec<&str> = [
            Tone::Dim,
            Tone::Ink,
            Tone::Accent,
            Tone::Ok,
            Tone::Warn,
            Tone::Deny,
        ]
        .into_iter()
        .map(tone_name)
        .collect();
        assert_eq!(
            names,
            ["dim", "ink", "accent", "verified", "restricted", "denied"]
        );
    }

    #[test]
    fn every_segment_is_addressable_by_name_live_and_sealed() {
        let h = header(NetworkCapability::Development);
        let watch = TrustBar::from_header(&h, false);
        let seg = |bar: &TrustBar, name| bar.segment(name).unwrap();
        assert_eq!(
            watch.segment(SegmentName::Mark),
            Some(Segment::bold("WARD", Tone::Accent))
        );
        assert_eq!(seg(&watch, SegmentName::Session).text, "sess_01J8ZK3…");
        assert_eq!(seg(&watch, SegmentName::Project).text, "payments-api");
        assert_eq!(watch.segment(SegmentName::Agent), None, "not said yet");
        assert_eq!(
            watch.segment(SegmentName::Network),
            Some(Segment::new("NET restricted (dev)", Tone::Warn)),
            "the prefix travels with the mode"
        );
        assert_eq!(seg(&watch, SegmentName::Credentials).text, "CRED 0 granted");
        assert_eq!(seg(&watch, SegmentName::Observer).text, "OBS live");
        assert_eq!(watch.segment(SegmentName::Tamperward), None);
        assert_eq!(watch.segment(SegmentName::Verify), None);
        assert_eq!(
            watch.segment(SegmentName::Daemon),
            Some(Segment::bold("LIVE", Tone::Warn))
        );

        let mut model = model_with(&sequence(), false);
        for rec in wardd(&[verify_passed()]) {
            model.apply(rec);
        }
        model.apply(records(&[(Origin::TamperWard, denied())]).remove(0));
        let live = TrustBar::new(&h, &model);
        assert_eq!(
            live.segment(SegmentName::Agent),
            Some(Segment::new("CLAUDE ● working", Tone::Accent))
        );
        assert_eq!(
            live.segment(SegmentName::Tamperward),
            Some(Segment::new("TW ✓", Tone::Ok))
        );
        assert_eq!(
            live.segment(SegmentName::Verify),
            Some(Segment::new("VERIFY ✓", Tone::Ok))
        );
        // Every name answers, and the answers are the row's segments.
        for name in SegmentName::ALL {
            let segment = seg(&live, name);
            if name == SegmentName::Network {
                assert!(live.text().contains(&segment.text), "{name}");
            } else if name != SegmentName::Mark {
                assert!(live.row().contains(&segment), "{name}");
            }
        }

        model.seal();
        let sealed = TrustBar::new(&h, &model);
        assert_eq!(
            sealed.segment(SegmentName::Mark),
            Some(Segment::bold("WARD", Tone::Dim))
        );
        assert_eq!(seg(&sealed, SegmentName::Agent).tone, Tone::Dim);
        assert_eq!(seg(&sealed, SegmentName::Network).tone, Tone::Dim);
        assert_eq!(
            sealed.segment(SegmentName::Daemon),
            Some(Segment::bold("SEALED", Tone::Dim))
        );
        assert_eq!(
            seg(&sealed, SegmentName::Verify).tone,
            Tone::Ok,
            "verdicts keep their colour"
        );
        assert_eq!(seg(&sealed, SegmentName::Project).tone, Tone::Ink);
        assert_eq!(
            sealed.row()[1],
            Segment::bold("WARD", Tone::Accent),
            "in the row the host mark never changes"
        );
    }

    #[test]
    fn a_sealed_session_dims_the_state_and_the_agent_but_keeps_verdicts() {
        let h = header(NetworkCapability::Development);
        let mut model = model_with(&sequence(), false);
        for rec in wardd(&[verify_passed(), ended()]) {
            model.apply(rec);
        }
        model.apply(records(&[(Origin::TamperWard, denied())]).remove(0));
        model.seal();
        let bar = TrustBar::new(&h, &model);
        assert!(bar.sealed);
        assert_eq!(bar.tone(), Tone::Dim);
        assert_eq!(bar.network.tone, Tone::Dim);
        assert_eq!(bar.daemon, Segment::bold("SEALED", Tone::Dim));
        assert_eq!(bar.row()[0], Segment::new("■ ", Tone::Dim));
        assert_eq!(
            bar.agent.as_ref().unwrap().tone,
            Tone::Dim,
            "the agent is gone"
        );
        assert_eq!(
            bar.verified.as_ref().unwrap().tone,
            Tone::Ok,
            "a verdict does not expire"
        );
        assert_eq!(bar.tamperward.as_ref().unwrap().tone, Tone::Ok);
        assert!(bar.text().ends_with("│ TW ✓ │ VERIFY ✓ │ SEALED"));
    }
}
