//! `ward watch --tui`: the full-screen observer (ADR-0012, TUI first).
//!
//! The layout follows `docs/design-language.md`: a trust bar on top whose colour
//! carries the session's state, the agent activity stream as the main pane with
//! the same columns as line mode ([`ward_daemon::render::observer_cells`]), and a status line
//! with the counters of `docs/event-model.md` §8 and the key hints.
//!
//! The module is split so that everything but the terminal is testable without
//! one: [`Model`] holds the records, counters, follow/scroll state and the seal
//! transition and [`Header`] the session facts the trust bar shows, both shared
//! with the Ward Shell through `ward-shell-core` so there is one implementation
//! of the observer's state; [`Action`] maps keys; [`draw`] renders a frame onto
//! any ratatui backend, including the `TestBackend`. [`run`] owns the terminal,
//! the background reader thread and the 50 ms tick loop.

use std::io::{self, Stdout, Write as _};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Frame;
#[cfg(test)]
use ratatui::backend::Backend;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ward_daemon::SessionMeta;
use ward_daemon::client::{self, WatchEnd, WatchOptions};
use ward_daemon::control::RemoteSink;
use ward_daemon::render::{ObserverCells, Tone};
use ward_events::EventRecord;
use ward_shell_core::{Header, Model, Segment, counters_text, trust_bar_segments};

/// How often the UI loop wakes to drain the channel and redraw.
pub const TICK: Duration = Duration::from_millis(50);

/// Rows a page key moves by, when the pane height is unknown.
const PAGE_FALLBACK: usize = 10;

/// What a key asks the observer to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Leave the observer (exit 0).
    Quit,
    /// One row towards the oldest.
    Up,
    /// One row towards the newest.
    Down,
    /// A page towards the oldest.
    PageUp,
    /// A page towards the newest.
    PageDown,
    /// Jump to the oldest row.
    Top,
    /// Re-follow the newest row.
    Follow,
}

impl Action {
    /// The action for a key press, if it has one. `q`, `Esc` and Ctrl-C quit;
    /// `j`/`k`, the arrows, `PageUp`/`PageDown` and `Home` scroll; `End` and
    /// `G` re-follow.
    #[must_use]
    pub fn from_key(key: KeyEvent) -> Option<Self> {
        if key.kind == KeyEventKind::Release {
            return None;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        Some(match key.code {
            KeyCode::Char('q') | KeyCode::Esc => Self::Quit,
            KeyCode::Char('c' | 'C') if ctrl => Self::Quit,
            KeyCode::Char('k') | KeyCode::Up => Self::Up,
            KeyCode::Char('j') | KeyCode::Down => Self::Down,
            KeyCode::PageUp => Self::PageUp,
            KeyCode::PageDown => Self::PageDown,
            KeyCode::Home | KeyCode::Char('g') => Self::Top,
            KeyCode::End | KeyCode::Char('G') => Self::Follow,
            _ => return None,
        })
    }
}

/// Apply `action` to `model` for a pane of `height` rows. Returns `true` when
/// the observer should exit.
pub fn dispatch(model: &mut Model, action: Action, height: usize) -> bool {
    let page = if height == 0 { PAGE_FALLBACK } else { height };
    match action {
        Action::Quit => return true,
        Action::Up => model.scroll_up(1, height),
        Action::Down => model.scroll_down(1, height),
        Action::PageUp => model.scroll_up(page, height),
        Action::PageDown => model.scroll_down(page, height),
        Action::Top => model.scroll_top(),
        Action::Follow => model.follow_end(),
    }
    false
}

/// The key hints on the status line, in full.
pub const KEY_HINTS: &str = "j/k scroll · PgUp/PgDn · End follow · q quit";
/// The hints when the full set does not fit beside the counters.
const KEY_HINTS_SHORT: &str = "End follow · q quit";
/// The one hint that is never dropped.
const KEY_HINTS_MIN: &str = "q quit";
/// Cells between the counters and the hints.
const STATUS_GAP: usize = 3;

/// The key hints that fit in `width` cells: the full set, else `End follow ·
/// q quit`, else `q quit`. The way out is never the hint that gets clipped.
#[must_use]
pub fn key_hints(width: usize) -> &'static str {
    [KEY_HINTS, KEY_HINTS_SHORT]
        .into_iter()
        .find(|h| h.chars().count() <= width)
        .unwrap_or(KEY_HINTS_MIN)
}

/// The status line's left half: the counters, and `PAUSED` while not following.
#[must_use]
pub fn status_left(model: &Model) -> Vec<Segment> {
    let mut segments = vec![Segment::new(counters_text(&model.counters), Tone::Ink)];
    if !model.follow {
        segments.push(Segment::new("   ", Tone::Dim));
        segments.push(Segment::bold("PAUSED", Tone::Warn));
    }
    segments
}

fn color(tone: Tone) -> Color {
    Color::Indexed(tone.palette_index())
}

fn style(tone: Tone) -> Style {
    Style::default().fg(color(tone))
}

/// The three regions of the screen: trust bar, stream, status line.
fn regions(area: Rect) -> (Rect, Rect, Rect) {
    let [bar, stream, status] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .areas(area);
    (bar, stream, status)
}

/// Rows the stream pane can show on a screen of `area`.
#[must_use]
pub fn pane_height(area: Rect) -> usize {
    let (_, stream, _) = regions(area);
    usize::from(stream.height)
}

/// Draw one frame of `model` under `header`.
pub fn draw(frame: &mut Frame<'_>, header: &Header, model: &Model) {
    let (bar, stream, status) = regions(frame.area());
    frame.render_widget(trust_bar(header, model.sealed), bar);
    frame.render_widget(stream_pane(model, usize::from(stream.height)), stream);
    frame.render_widget(status_line(model, usize::from(status.width)), status);
}

/// The trust bar as a widget, with its 1-cell separator below.
fn trust_bar(header: &Header, sealed: bool) -> Paragraph<'static> {
    let spans: Vec<Span<'static>> = trust_bar_segments(header, sealed)
        .into_iter()
        .map(|seg| {
            let mut st = style(seg.tone);
            if seg.bold {
                st = st.add_modifier(Modifier::BOLD);
            }
            Span::styled(seg.text, st)
        })
        .collect();
    Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(style(Tone::Dim)),
    )
}

/// The stream pane: the visible rows, each in the columns of line mode.
fn stream_pane(model: &Model, height: usize) -> Paragraph<'static> {
    let lines: Vec<Line<'static>> = model.visible_rows(height).iter().map(row_line).collect();
    Paragraph::new(lines)
}

fn row_line(cells: &ObserverCells) -> Line<'static> {
    Line::from(vec![
        Span::styled(cells.time.clone(), style(Tone::Dim)),
        Span::raw("  "),
        Span::styled(format!("{:<5}", cells.verb), style(cells.tone)),
        Span::raw(" "),
        Span::styled(cells.subject.clone(), style(Tone::Ink)),
    ])
}

/// The status line: counters (and `PAUSED`) on the left, key hints pushed to
/// the right edge and shortened before the counters would be clipped.
fn status_line(model: &Model, width: usize) -> Paragraph<'static> {
    let left = status_left(model);
    let left_width: usize = left.iter().map(|s| s.text.chars().count()).sum();
    let room = width.saturating_sub(left_width + STATUS_GAP);
    let hints = key_hints(room);
    let pad = width
        .saturating_sub(left_width + hints.chars().count())
        .max(STATUS_GAP);
    let mut spans: Vec<Span<'static>> = left
        .into_iter()
        .map(|seg| {
            let mut st = style(seg.tone);
            if seg.bold {
                st = st.add_modifier(Modifier::BOLD);
            }
            Span::styled(seg.text, st)
        })
        .collect();
    spans.push(Span::raw(" ".repeat(pad)));
    spans.push(Span::styled(hints, style(Tone::Dim)));
    Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(style(Tone::Dim)),
    )
}

/// Raw mode and the alternate screen, undone in `Drop` so every exit path
/// (`q`, an error, a panic reaching `main`) leaves the terminal as it was.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut out = io::stdout();
        if let Err(e) = crossterm::execute!(out, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(e);
        }
        Ok(Self)
    }

    fn restore() {
        let mut out = io::stdout();
        let _ = crossterm::execute!(out, LeaveAlternateScreen);
        let _ = disable_raw_mode();
        let _ = out.flush();
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        Self::restore();
    }
}

/// What the reader thread sends.
enum Msg {
    Record(Box<EventRecord>),
    End(ward_daemon::Result<WatchEnd>),
}

/// Run the observer on `sink` for the session `meta` describes until the viewer
/// quits. Enters raw mode only after the daemon has answered, so a missing
/// daemon is reported on a plain terminal by the caller.
pub fn run(sink: RemoteSink, meta: &SessionMeta, opts: WatchOptions) -> ward_daemon::Result<()> {
    let header = Header::from_meta(meta);
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let end = client::watch_records(sink, opts.from_seq, |rec| {
            let _ = tx.send(Msg::Record(Box::new(rec)));
        });
        let _ = tx.send(Msg::End(end));
    });
    let guard = TerminalGuard::enter().map_err(io_error)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = ratatui::Terminal::new(backend).map_err(io_error)?;
    let result = event_loop(&mut terminal, &header, &rx, opts.all);
    drop(guard);
    result
}

/// Poll keys at [`TICK`], drain the channel, redraw. A stream error ends the
/// observer with that error; a clean end seals the view until `q`.
fn event_loop(
    terminal: &mut ratatui::Terminal<CrosstermBackend<Stdout>>,
    header: &Header,
    rx: &Receiver<Msg>,
    all: bool,
) -> ward_daemon::Result<()> {
    let mut model = Model::new(all);
    let mut height = pane_height(terminal.size().map_err(io_error)?.into());
    loop {
        if event::poll(TICK).map_err(io_error)? {
            // A resize is picked up from the next drawn frame; only keys act.
            if let Event::Key(key) = event::read().map_err(io_error)?
                && let Some(action) = Action::from_key(key)
                && dispatch(&mut model, action, height)
            {
                return Ok(());
            }
        }
        drain(rx, &mut model)?;
        let frame = terminal
            .draw(|f| draw(f, header, &model))
            .map_err(io_error)?;
        height = pane_height(frame.area);
    }
}

/// Move every queued message into `model` without blocking.
fn drain(rx: &Receiver<Msg>, model: &mut Model) -> ward_daemon::Result<()> {
    loop {
        match rx.recv_timeout(Duration::ZERO) {
            Ok(Msg::Record(rec)) => model.apply(*rec),
            Ok(Msg::End(Ok(_))) => model.seal(),
            Ok(Msg::End(Err(e))) => return Err(e),
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

fn io_error(e: io::Error) -> ward_daemon::Error {
    ward_daemon::Error::Io {
        path: Path::new("<terminal>").to_path_buf(),
        source: e,
    }
}

/// Render `model` under `header` through `terminal` and return the frame's rows
/// as plain text, for snapshot assertions on an off-screen backend.
#[cfg(test)]
pub fn render_to_text<B: Backend>(
    terminal: &mut ratatui::Terminal<B>,
    header: &Header,
    model: &Model,
) -> Result<Vec<String>, B::Error> {
    let frame = terminal.draw(|f| draw(f, header, model))?;
    let area = frame.area;
    let buffer = frame.buffer;
    Ok((0..area.height)
        .map(|y| {
            (0..area.width)
                .filter_map(|x| buffer.cell((x, y)).map(|c| c.symbol().to_owned()))
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use ratatui::backend::TestBackend;
    use ward_events::{
        AgentState, Blake3Hash, Chain, ClaimKind, Decision, DeniedDst, DenyReason, EndReason,
        FileChangeKind, HostName, Origin, PayloadText, Pid, ProcessRef, RuleRef, SandboxPath,
        SandboxRoot, SessionId, Timestamp, WardEvent,
    };
    use ward_policy::{NetworkCapability, Policy, merge};
    use ward_shell_core::{Counters, short_id, trust_bar_text, trust_tone};

    fn by() -> ProcessRef {
        ProcessRef {
            pid: Pid::new(7).unwrap(),
            comm: None,
        }
    }

    fn path(rel: &str) -> SandboxPath {
        SandboxPath::new(SandboxRoot::Work, rel).unwrap()
    }

    fn edit(rel: &str) -> WardEvent {
        WardEvent::FileModified {
            path: path(rel),
            by: by(),
            kind: FileChangeKind::Write,
        }
    }

    fn run_cmd(args: &[&str]) -> WardEvent {
        WardEvent::CommandStarted {
            pid: Pid::new(7).unwrap(),
            parent: Pid::new(1).unwrap(),
            argv: ward_events::BoundedArgv::from_strs(args),
            cwd: path("."),
            exe_digest: None,
        }
    }

    fn net(host: &str, decision: Decision) -> WardEvent {
        WardEvent::NetworkRequested {
            host: HostName::new(host).unwrap(),
            port: 443,
            decision,
            rule: RuleRef::new("project:network.allow[0]").unwrap(),
            by: by(),
        }
    }

    fn net_denied(host: &str) -> WardEvent {
        WardEvent::NetworkDenied {
            dst: DeniedDst::Host {
                host: HostName::new(host).unwrap(),
                port: 443,
            },
            reason: DenyReason::NotAllowlisted,
        }
    }

    fn claim() -> WardEvent {
        WardEvent::AgentClaim {
            kind: ClaimKind::Note,
            payload: PayloadText::new("SessionStart"),
        }
    }

    fn hidden() -> WardEvent {
        WardEvent::AgentStateChanged {
            state: AgentState::Working,
        }
    }

    fn ended() -> WardEvent {
        WardEvent::SessionEnded {
            reason: EndReason::UserStop,
            final_snapshot: None,
        }
    }

    /// A chain of synthetic records, one per event, one second apart.
    fn records(events: &[WardEvent]) -> Vec<EventRecord> {
        let mut chain = Chain::genesis(SessionId::from_u128(7), Blake3Hash::from_bytes([1; 32]));
        events
            .iter()
            .enumerate()
            .map(|(i, event)| {
                chain
                    .append(
                        Origin::Wardd,
                        event.clone(),
                        Timestamp::mono(Duration::from_secs(i as u64)),
                    )
                    .unwrap()
            })
            .collect()
    }

    fn sequence() -> Vec<WardEvent> {
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
            hidden(),
            run_cmd(&["ls"]),
        ]
    }

    fn model_with(events: &[WardEvent], all: bool) -> Model {
        let mut model = Model::new(all);
        for rec in records(events) {
            model.apply(rec);
        }
        model
    }

    fn header(network: NetworkCapability) -> Header {
        Header {
            session: "sess_01J8ZK3Q9X7VY2".to_owned(),
            project: "payments-api".to_owned(),
            agent: None,
            network,
            credentials_granted: 0,
            observer: "live",
        }
    }

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
    fn rows_carry_the_line_mode_columns_and_verb_colours() {
        let model = model_with(&sequence(), false);
        let rows = model.rows();
        assert_eq!(rows[0].time, "00:00");
        assert_eq!(rows[0].verb, "RUN");
        assert_eq!(rows[0].tone, Tone::Ink);
        assert_eq!(rows[0].subject, "cargo test");
        assert_eq!((rows[1].verb, rows[1].tone), ("EDIT", Tone::Ink));
        assert_eq!((rows[4].verb, rows[4].tone), ("NET", Tone::Warn));
        assert_eq!(rows[4].subject, "crates.io:443");
        assert_eq!((rows[6].verb, rows[6].tone), ("DENY", Tone::Deny));
        assert_eq!((rows[7].verb, rows[7].tone), ("NET", Tone::Warn), "ask");
        assert_eq!((rows[8].verb, rows[8].tone), ("NOTE", Tone::Dim));
        // The TUI paints the same palette index line mode prints.
        assert_eq!(color(Tone::Deny), Color::Indexed(167));
        assert!(Tone::Deny.sgr().contains("167"));
    }

    #[test]
    fn follow_shows_the_newest_rows_and_scrolling_pauses_it() {
        let mut model = model_with(&sequence(), false);
        assert!(model.follow);
        let visible = model.visible_rows(3);
        assert_eq!(visible.len(), 3);
        assert_eq!(visible[2].subject, "ls", "newest at the bottom");
        assert_eq!(model.top(3), 7);

        model.scroll_up(2, 3);
        assert!(!model.follow);
        assert_eq!(model.top(3), 5);
        assert_eq!(model.visible_rows(3)[0].subject, "evil.example:443");

        // A new record while paused does not move the window.
        model.apply(records(&[edit("README.md")]).remove(0));
        assert_eq!(model.top(3), 5);
        assert_eq!(model.rows().len(), 11);

        // Up past the top clamps to the oldest row.
        model.scroll_up(100, 3);
        assert_eq!(model.top(3), 0);
        assert_eq!(model.visible_rows(3)[0].subject, "cargo test");

        // Down one at a time; reaching the bottom resumes following.
        model.scroll_down(1, 3);
        assert_eq!(model.top(3), 1);
        assert!(!model.follow);
        model.scroll_down(100, 3);
        assert!(model.follow);
        assert_eq!(model.visible_rows(3)[2].subject, "/work/README.md");

        model.scroll_top();
        assert_eq!(model.top(3), 0);
        model.follow_end();
        assert!(model.follow);
        assert_eq!(model.top(3), 8);

        // Fewer rows than the pane: everything is visible, nothing to scroll.
        let small = model_with(&[edit("a")], false);
        assert_eq!(small.visible_rows(10).len(), 1);
        assert_eq!(small.top(10), 0);
        let empty = Model::new(false);
        assert!(empty.visible_rows(5).is_empty());
    }

    #[test]
    fn dispatch_maps_actions_and_quit_returns_true() {
        let mut model = model_with(&sequence(), false);
        assert!(!dispatch(&mut model, Action::Up, 3));
        assert_eq!(model.top(3), 6);
        assert!(!dispatch(&mut model, Action::PageUp, 3));
        assert_eq!(model.top(3), 3);
        assert!(!dispatch(&mut model, Action::PageDown, 3));
        assert_eq!(model.top(3), 6);
        assert!(!dispatch(&mut model, Action::Top, 3));
        assert_eq!(model.top(3), 0);
        assert!(!dispatch(&mut model, Action::Down, 3));
        assert_eq!(model.top(3), 1);
        assert!(!dispatch(&mut model, Action::Follow, 3));
        assert!(model.follow);
        // An unknown height pages by the fallback instead of not at all.
        assert!(!dispatch(&mut model, Action::PageUp, 0));
        assert!(!model.follow);
        assert!(dispatch(&mut model, Action::Quit, 3));
    }

    #[test]
    fn keys_map_to_actions() {
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert_eq!(
            Action::from_key(press(KeyCode::Char('q'))),
            Some(Action::Quit)
        );
        assert_eq!(Action::from_key(press(KeyCode::Esc)), Some(Action::Quit));
        assert_eq!(
            Action::from_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(Action::Quit)
        );
        assert_eq!(Action::from_key(press(KeyCode::Char('c'))), None);
        assert_eq!(
            Action::from_key(press(KeyCode::Char('j'))),
            Some(Action::Down)
        );
        assert_eq!(Action::from_key(press(KeyCode::Down)), Some(Action::Down));
        assert_eq!(
            Action::from_key(press(KeyCode::Char('k'))),
            Some(Action::Up)
        );
        assert_eq!(Action::from_key(press(KeyCode::Up)), Some(Action::Up));
        assert_eq!(
            Action::from_key(press(KeyCode::PageUp)),
            Some(Action::PageUp)
        );
        assert_eq!(
            Action::from_key(press(KeyCode::PageDown)),
            Some(Action::PageDown)
        );
        assert_eq!(Action::from_key(press(KeyCode::End)), Some(Action::Follow));
        assert_eq!(Action::from_key(press(KeyCode::Home)), Some(Action::Top));
        assert_eq!(Action::from_key(press(KeyCode::Char('x'))), None);
        let release = KeyEvent {
            kind: KeyEventKind::Release,
            ..press(KeyCode::Char('q'))
        };
        assert_eq!(Action::from_key(release), None, "a key-up is not a quit");
    }

    #[test]
    fn sealing_keeps_the_rows_and_flips_the_trust_bar() {
        let mut model = model_with(&sequence(), false);
        let header = header(NetworkCapability::Development);
        assert!(!model.sealed);
        assert!(trust_bar_text(&header, model.sealed).ends_with("│ LIVE"));
        assert_eq!(trust_tone(&header.network, model.sealed), Tone::Warn);

        model.apply(records(&[ended()]).remove(0));
        model.seal();
        assert!(model.sealed);
        assert_eq!(model.rows().len(), 11, "the view is kept");
        assert_eq!(model.rows()[10].verb, "END");
        assert!(trust_bar_text(&header, model.sealed).ends_with("│ SEALED"));
        assert_eq!(trust_tone(&header.network, model.sealed), Tone::Dim);
        // Scrolling still works on a sealed view.
        model.scroll_up(1, 3);
        assert!(!model.follow);
    }

    #[test]
    fn trust_bar_colour_follows_the_network_mode() {
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
        }
        assert!(trust_bar_text(&header(N::Offline), false).contains("NET offline"));
        assert!(trust_bar_text(&header(custom), false).contains("NET allowlist (1 hosts)"));
        assert!(trust_bar_text(&header(N::Unrestricted), false).contains("NET open"));
    }

    #[test]
    fn header_comes_from_session_meta_and_ids_are_shortened() {
        let manifest = merge(
            &Policy::default(),
            &Policy::default(),
            &Policy::default(),
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
        let h = Header::from_meta(&meta);
        assert_eq!(h.project, "payments-api");
        assert_eq!(h.session, "sess_01J8ZK3Q9X7VY2");
        assert_eq!(h.network, NetworkCapability::Development);
        assert_eq!(h.credentials_granted, 0);
        assert_eq!(h.observer, "live");
        assert_eq!(
            trust_bar_text(&h, false),
            "● WARD │ sess_01J8ZK3… │ payments-api │ NET restricted (dev) │ CRED 0 granted │ OBS live │ LIVE"
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
    fn layout_renders_bar_stream_and_status_on_a_test_backend() {
        let header = header(NetworkCapability::Development);
        let model = model_with(&sequence(), false);
        let mut terminal = ratatui::Terminal::new(TestBackend::new(140, 12)).unwrap();
        let rows = render_to_text(&mut terminal, &header, &model).unwrap();
        assert_eq!(rows.len(), 12, "row count is the screen height");
        assert_eq!(pane_height(Rect::new(0, 0, 140, 12)), 8);
        assert_eq!(
            rows[0],
            "● WARD │ sess_01J8ZK3… │ payments-api │ NET restricted (dev) │ CRED 0 granted │ OBS live │ LIVE"
        );
        assert!(rows[1].starts_with("───"), "1-cell separator under the bar");
        // Eight stream rows: the newest eight of ten, newest at the bottom.
        assert_eq!(rows[2], "00:02  EDIT  /work/src/lib.rs");
        assert_eq!(rows[9], "00:10  RUN   ls");
        assert!(
            rows[10].starts_with("───"),
            "1-cell separator over the status line"
        );
        assert!(
            rows[11].starts_with(
                "files changed 2 · commands 2 · network 1 allowed / 2 denied · claims 1   "
            ),
            "{}",
            rows[11]
        );
        assert!(rows[11].ends_with(KEY_HINTS), "{}", rows[11]);
        assert_eq!(rows[11].chars().count(), 140, "hints sit at the right edge");

        // Sealed: the bar says so and the marker changes; the rows stay.
        let mut sealed = model.clone();
        sealed.seal();
        sealed.scroll_up(1, 8);
        let rows = render_to_text(&mut terminal, &header, &sealed).unwrap();
        assert!(rows[0].starts_with("■ WARD"));
        assert!(rows[0].ends_with("│ SEALED"));
        assert_eq!(rows[2], "00:01  EDIT  /work/src/lib.rs");
        assert!(rows[11].contains("claims 1   PAUSED"), "{}", rows[11]);
        assert!(rows[11].ends_with(KEY_HINTS), "{}", rows[11]);

        // The state colour sits on the marker and the state word, not the row.
        let frame_buffer = terminal.backend().buffer();
        let marker = frame_buffer.cell((0, 0)).unwrap();
        assert_eq!(marker.fg, color(Tone::Dim));
        let live_model = model_with(&[], false);
        render_to_text(&mut terminal, &header, &live_model).unwrap();
        let buffer = terminal.backend().buffer();
        assert_eq!(buffer.cell((0, 0)).unwrap().fg, color(Tone::Warn));
        assert_eq!(buffer.cell((2, 0)).unwrap().fg, color(Tone::Accent), "WARD");
        // Narrower screens shorten the hints before they would clip the counters.
        let mut narrow = ratatui::Terminal::new(TestBackend::new(100, 12)).unwrap();
        let rows = render_to_text(&mut narrow, &header, &model).unwrap();
        assert!(rows[11].starts_with("files changed 2"), "{}", rows[11]);
        assert!(rows[11].ends_with("End follow · q quit"), "{}", rows[11]);
        assert!(!rows[11].contains("PgUp"), "{}", rows[11]);
        let mut eighty = ratatui::Terminal::new(TestBackend::new(80, 12)).unwrap();
        let rows = render_to_text(&mut eighty, &header, &model).unwrap();
        assert!(rows[11].ends_with("claims 1    q quit"), "{}", rows[11]);
        assert_eq!(rows[11].chars().count(), 80, "{}", rows[11]);
        assert_eq!(key_hints(200), KEY_HINTS);
        assert_eq!(key_hints(20), "End follow · q quit");
        assert_eq!(key_hints(0), "q quit");
        // A screen too small for the chrome still renders without panicking.
        let mut tiny = ratatui::Terminal::new(TestBackend::new(20, 3)).unwrap();
        let rows = render_to_text(&mut tiny, &header, &model).unwrap();
        assert_eq!(rows.len(), 3);
    }
}
