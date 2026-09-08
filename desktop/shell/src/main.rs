//! `ward-shell` — the Ward Shell (ADR-0007), as a text dump until E-10 picks
//! the layer-shell toolkit.
//!
//! Each subcommand is one surface of `docs/design-language.md`: the trust bar
//! (§6), the session panel (§6), the command centre (§13), the observer (§8)
//! and the semantic settings (§14). The shell is a client of the session daemon
//! like `ward watch` (ADR-0015): it asks for the session's description and
//! catches up with its event stream over the control socket, derives every
//! surface in [`ward_shell_core`], and prints it. It has no privileged access
//! and reads nothing from the worktree. With no session, or no daemon serving
//! it, it prints `no session`.

#![allow(clippy::missing_errors_doc, clippy::doc_markdown)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use ward_daemon::client::{self, WatchEnd};
use ward_daemon::session::state_root;
use ward_shell_core::{
    Header, Launcher, Model, SessionCard, SessionDescription, Settings, TrustBar, counters_text,
    panel_text, session_panel,
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
    Bar,
    /// The trust bar and the session panel behind its agent segment.
    Session,
    /// The command centre, optionally filtered as if `query` had been typed.
    Launcher {
        /// Typed text.
        #[arg(long, default_value = "")]
        query: String,
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
    match load(&dir, settle) {
        Ok(Some(snapshot)) => {
            print!("{}", render(&snapshot, cli.surface.unwrap_or(Surface::Bar)));
            ExitCode::SUCCESS
        }
        Ok(None) => {
            println!("no session");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ward-shell: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The current session of `dir` through its daemon, or `None` when there is no
/// session or nothing serves it (the reason goes to stderr).
fn load(dir: &Path, settle: Duration) -> ward_daemon::Result<Option<Snapshot>> {
    let state = state_root();
    let socket = match client::socket_path(dir, &state) {
        Ok(socket) => socket,
        Err(ward_daemon::Error::Project(reason)) => {
            eprintln!("ward-shell: {reason}");
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let Ok(mut sink) = client::connect(&socket) else {
        eprintln!("ward-shell: {}", client::NO_DAEMON);
        return Ok(None);
    };
    let description = client::describe(&mut sink)?;
    drop(sink);
    // A subscription is served on its own connection.
    let subscriber = client::connect(&socket)?;
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
        Surface::Bar => format!("{bar}\n"),
        Surface::Session => {
            let panel = session_panel(&s.description, &s.model, now_unix_ms());
            format!("{bar}\n\n{}", panel_text(&panel))
        }
        Surface::Launcher { query } => {
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
        assert!(matches!(cli.surface, Some(Surface::Launcher { query }) if query == "pay"));
        assert_eq!(cli.dir.as_deref(), Some(Path::new("/p")));
    }

    #[test]
    fn a_project_without_a_session_is_no_session_not_an_error() {
        #![allow(clippy::unwrap_used)]
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            load(dir.path(), Duration::from_millis(10)),
            Ok(None)
        ));
    }
}
