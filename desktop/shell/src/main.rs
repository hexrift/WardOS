//! `ward-shell` — the Ward Shell (ADR-0007), as a text dump until E-10 picks
//! the layer-shell toolkit, and as the feed of the components that draw it
//! meanwhile (ADR-0016): Waybar reads `bar --waybar`, fuzzel reads
//! `launcher --lines`.
//!
//! Each subcommand is one surface of `docs/design-language.md`: the trust bar
//! (§6), the session panel (§6), the command centre (§13), the observer (§8)
//! and the semantic settings (§14). The shell is a client of the session daemon
//! like `ward watch` (ADR-0015): it asks for the session's description and
//! catches up with its event stream over the control socket, derives every
//! surface in [`ward_shell_core`], and prints it. It has no privileged access
//! and reads nothing from the worktree. With no session, or no daemon serving
//! it, it prints `no session` (or the empty Waybar module).

#![allow(clippy::missing_errors_doc, clippy::doc_markdown)]

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use ward_daemon::client::{self, WatchEnd};
use ward_daemon::session::state_root;
use ward_shell_core::{
    Header, Launcher, LineContext, Model, Module, SegmentName, SessionCard, SessionDescription,
    Settings, TrustBar, counters_text, panel_text, session_panel,
};

/// How long the catch-up waits for one more record before calling the log
/// caught up with.
const SETTLE_MS: u64 = 250;

#[derive(Parser)]
#[command(name = "ward-shell", version, about = "The Ward Shell, printed")]
struct Cli {
    /// Project directory whose current session to show (default: current).
    #[arg(long, global = true)]
    dir: Option<PathBuf>,
    /// Milliseconds of silence after which the stream counts as caught up with.
    #[arg(long, global = true, default_value_t = SETTLE_MS)]
    settle_ms: u64,
    #[command(subcommand)]
    surface: Option<Surface>,
}

#[derive(Subcommand)]
enum Surface {
    /// The trust bar (default).
    Bar {
        /// Waybar custom-module JSON (`return-type: json`) instead of text.
        #[arg(long)]
        waybar: bool,
        /// One segment only: mark, session, project, agent, network,
        /// credentials, observer, tamperward, verify or daemon.
        #[arg(long, requires = "waybar")]
        segment: Option<SegmentName>,
        /// Keep the daemon subscription open and print a new line whenever the
        /// JSON changes; exit 0 when the daemon closes the stream.
        #[arg(long, requires = "waybar")]
        follow: bool,
    },
    /// The trust bar and the session panel behind its agent segment.
    Session,
    /// The command centre, optionally filtered as if `query` had been typed.
    Launcher {
        /// Typed text.
        #[arg(long, default_value = "")]
        query: String,
        /// dmenu lines, `SECTION<TAB>label<TAB>command`, for fuzzel.
        #[arg(long)]
        lines: bool,
    },
    /// The agent activity panel: the newest rows and the counters.
    Observer {
        /// Rows to show.
        #[arg(long, default_value_t = 20)]
        rows: usize,
    },
    /// Agent Access and Advanced, read-only.
    Settings,
}

/// A session as the shell sees it: its facts and its stream so far.
struct Snapshot {
    description: SessionDescription,
    header: Header,
    model: Model,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    #[cfg(feature = "gui")]
    eprintln!("ward-shell: gui: toolkit pending E-10; printing the text surfaces");
    let dir = cli.dir.unwrap_or_else(|| PathBuf::from("."));
    let settle = Duration::from_millis(cli.settle_ms);
    let surface = cli.surface.unwrap_or(Surface::Bar {
        waybar: false,
        segment: None,
        follow: false,
    });
    let result = match surface {
        Surface::Bar {
            waybar: true,
            segment,
            follow,
        } => waybar(&dir, settle, segment, follow),
        Surface::Launcher { query, lines: true } => launcher_lines(&dir, settle, &query),
        surface => text(&dir, settle, surface),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ward-shell: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Print one text surface, or `no session`.
fn text(dir: &Path, settle: Duration, surface: Surface) -> ward_daemon::Result<()> {
    match load(dir, settle)? {
        Some(snapshot) => print!("{}", render(&snapshot, surface)),
        None => println!("no session"),
    }
    Ok(())
}

/// `bar --waybar`: the module's JSON, once or on every change.
fn waybar(
    dir: &Path,
    settle: Duration,
    segment: Option<SegmentName>,
    follow: bool,
) -> ward_daemon::Result<()> {
    let Some(socket) = locate(dir)? else {
        return emit(&Module::none(segment));
    };
    let Some(mut snapshot) = load_from(&socket, settle)? else {
        return emit(&Module::none(segment));
    };
    let mut last = module(&snapshot, segment);
    emit(&last)?;
    if !follow || snapshot.model.sealed {
        return Ok(());
    }
    // Waybar reads line by line: print only when the module changes. The
    // stream continues where the catch-up stopped; the daemon closing it means
    // the log is sealed (or the daemon is gone), and that is the last line.
    let from_seq = snapshot.model.records.last().map_or(0, |r| r.seq + 1);
    let subscriber = client::connect(&socket)?;
    let mut failed = None;
    client::watch_records(subscriber, from_seq, |rec| {
        snapshot.model.apply(rec);
        let now = module(&snapshot, segment);
        if now != last {
            if let Err(e) = emit(&now) {
                failed = Some(e);
            }
            last = now;
        }
    })?;
    if let Some(e) = failed {
        return Err(e);
    }
    snapshot.model.seal();
    let now = module(&snapshot, segment);
    if now != last {
        emit(&now)?;
    }
    Ok(())
}

/// The whole bar or one segment of `s`.
fn module(s: &Snapshot, segment: Option<SegmentName>) -> Module {
    match segment {
        Some(name) => Module::segment(&s.description, &s.header, &s.model, name, now_unix_ms()),
        None => Module::bar(&s.description, &s.header, &s.model, now_unix_ms()),
    }
}

/// One JSON line, flushed, since a reader waits on it.
fn emit(module: &Module) -> ward_daemon::Result<()> {
    let line = serde_json::to_string(module)
        .map_err(|e| ward_daemon::Error::Events(format!("waybar json: {e}")))?;
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}")
        .and_then(|()| out.flush())
        .map_err(|e| ward_daemon::Error::Io {
            path: PathBuf::from("<stdout>"),
            source: e,
        })
}

/// `launcher --lines`: the matching rows as `SECTION<TAB>label<TAB>command`.
/// Without a session the fixed rows remain, with the given directory as the
/// project.
fn launcher_lines(dir: &Path, settle: Duration, query: &str) -> ward_daemon::Result<()> {
    let state = state_root();
    let snapshot = load(dir, settle)?;
    let (cards, worktree) = match &snapshot {
        Some(s) => (
            vec![SessionCard::new(&s.description, &s.model)],
            s.description.worktree.clone(),
        ),
        None => (
            Vec::new(),
            dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf()),
        ),
    };
    let mut launcher = Launcher::new(&cards);
    launcher.set_query(query);
    let ctx = LineContext {
        worktree: &worktree,
        state: &state,
    };
    for line in launcher.lines(&ctx) {
        println!("{line}");
    }
    Ok(())
}

/// The control socket of the session the shell shows: `dir`'s current one,
/// else the newest one a daemon serves (the bar runs from home, not a
/// project); `None` when there is neither (the reason goes to stderr).
fn locate(dir: &Path) -> ward_daemon::Result<Option<PathBuf>> {
    match client::desktop_socket(dir, &state_root(), None) {
        Ok(socket) => Ok(Some(socket)),
        Err(ward_daemon::Error::Project(reason)) => {
            eprintln!("ward-shell: {reason}");
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// The current session of `dir` through its daemon, or `None` when there is no
/// session or nothing serves it.
fn load(dir: &Path, settle: Duration) -> ward_daemon::Result<Option<Snapshot>> {
    match locate(dir)? {
        Some(socket) => load_from(&socket, settle),
        None => Ok(None),
    }
}

/// The session behind `socket`: its description and its stream so far, or
/// `None` when nothing serves it.
fn load_from(socket: &Path, settle: Duration) -> ward_daemon::Result<Option<Snapshot>> {
    let Ok(mut sink) = client::connect(socket) else {
        eprintln!("ward-shell: {}", client::NO_DAEMON);
        return Ok(None);
    };
    let description = client::describe(&mut sink)?;
    drop(sink);
    // A subscription is served on its own connection.
    let subscriber = client::connect(socket)?;
    let mut model = Model::new(false);
    let end = client::catch_up(subscriber, 0, settle, |rec| model.apply(rec))?;
    if !matches!(end, WatchEnd::Quiet { .. }) {
        model.seal();
    }
    Ok(Some(Snapshot {
        header: Header::from_description(&description),
        description,
        model,
    }))
}

/// The text of one surface.
fn render(s: &Snapshot, surface: Surface) -> String {
    let bar = TrustBar::new(&s.header, &s.model).text();
    match surface {
        Surface::Bar { .. } => format!("{bar}\n"),
        Surface::Session => {
            let panel = session_panel(&s.description, &s.model, now_unix_ms());
            format!("{bar}\n\n{}", panel_text(&panel))
        }
        Surface::Launcher { query, .. } => {
            let card = SessionCard::new(&s.description, &s.model);
            let mut launcher = Launcher::new(&[card]);
            launcher.set_query(query);
            launcher.text()
        }
        Surface::Observer { rows } => {
            let mut text = String::new();
            for cells in s.model.visible_rows(rows) {
                let _ = writeln!(text, "{}  {:<5} {}", cells.time, cells.verb, cells.subject);
            }
            text.push('\n');
            text.push_str(&counters_text(&s.model.counters));
            text.push('\n');
            text
        }
        Surface::Settings => Settings::from_description(&s.description).text(),
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn the_cli_parses_and_defaults_to_the_bar() {
        Cli::command().debug_assert();
        let cli = Cli::parse_from(["ward-shell"]);
        assert!(cli.surface.is_none());
        assert_eq!(cli.settle_ms, SETTLE_MS);
        let cli = Cli::parse_from(["ward-shell", "launcher", "--query", "pay", "--dir", "/p"]);
        assert!(matches!(
            cli.surface,
            Some(Surface::Launcher { query, lines: false }) if query == "pay"
        ));
        assert_eq!(cli.dir.as_deref(), Some(Path::new("/p")));
        let cli = Cli::parse_from(["ward-shell", "launcher", "--lines"]);
        assert!(matches!(
            cli.surface,
            Some(Surface::Launcher { lines: true, .. })
        ));
    }

    #[test]
    fn waybar_flags_parse_and_need_waybar() {
        let cli = Cli::parse_from([
            "ward-shell",
            "bar",
            "--waybar",
            "--segment",
            "agent",
            "--follow",
        ]);
        assert!(matches!(
            cli.surface,
            Some(Surface::Bar {
                waybar: true,
                segment: Some(SegmentName::Agent),
                follow: true
            })
        ));
        assert!(Cli::try_parse_from(["ward-shell", "bar", "--segment", "agent"]).is_err());
        assert!(Cli::try_parse_from(["ward-shell", "bar", "--follow"]).is_err());
        let err = Cli::try_parse_from(["ward-shell", "bar", "--waybar", "--segment", "clock"])
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("unknown segment `clock`"), "{err}");
    }

    #[test]
    fn a_project_without_a_session_is_no_session_not_an_error() {
        #![allow(clippy::unwrap_used)]
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            load(dir.path(), Duration::from_millis(10)),
            Ok(None)
        ));
        assert!(matches!(locate(dir.path()), Ok(None)));
    }

    #[test]
    fn the_empty_module_is_the_waybar_none_state() {
        #![allow(clippy::unwrap_used)]
        let none = serde_json::to_string(&Module::none(Some(SegmentName::Agent))).unwrap();
        assert_eq!(none, r#"{"text":"","tooltip":"","class":["none"]}"#);
        let mark = serde_json::to_string(&Module::none(Some(SegmentName::Mark))).unwrap();
        assert_eq!(
            mark,
            r#"{"text":"WARD","tooltip":"no session","class":["dim"]}"#
        );
    }
}
