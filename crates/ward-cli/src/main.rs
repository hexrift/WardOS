//! `ward` — the WardOS command-line client.
//!
//! Phase 1 drives the session in-process via [`ward_daemon`]; the daemon/socket
//! split (ADR-0009) lands in Phase 2.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::struct_field_names
)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use ward_daemon::{Session, render, selftest};
use ward_events::{EndReason, LogReader};

#[derive(Parser)]
#[command(
    name = "ward",
    version,
    about = "Secure sessions for autonomous coding agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start a session and print its security panel.
    Up {
        /// Project directory (default: current).
        dir: Option<PathBuf>,
    },
    /// Print the session security panel (alias of `up`).
    Status {
        /// Project directory (default: current).
        dir: Option<PathBuf>,
    },
    /// Run a command inside the sandbox and show the observer view.
    Run {
        /// Project directory (default: current).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Command and arguments to run.
        #[arg(trailing_var_arg = true, required = true)]
        argv: Vec<String>,
    },
    /// Run the isolation self-tests against a real sandbox.
    Selftest {
        /// Project directory (default: current).
        dir: Option<PathBuf>,
    },
    /// Replay a sealed session log.
    Replay {
        /// Path to an `events.log`.
        log: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ward: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> ward_daemon::Result<ExitCode> {
    match cli.command {
        Command::Up { dir } | Command::Status { dir } => {
            let dir = dir.unwrap_or_else(cwd);
            let session = Session::start(&dir)?;
            print!(
                "{}",
                render::status_panel(
                    session.id(),
                    &dir.display().to_string(),
                    session.entry_snapshot(),
                    session.manifest(),
                )
            );
            println!();
            println!("  session ready · log {}", session.log_path().display());
            session.stop(EndReason::UserStop)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Run { dir, argv } => {
            let dir = dir.unwrap_or_else(cwd);
            let mut session = Session::start(&dir)?;
            let log = session.log_path();
            let report = session.run(&argv)?;
            let code = report.code;
            session.stop(EndReason::UserStop)?;
            render_log(&log);
            if !report.stdout.is_empty() {
                println!("\n{}", report.stdout.trim_end());
            }
            Ok(exit_code(code))
        }
        Command::Selftest { dir } => {
            let dir = dir.unwrap_or_else(cwd);
            let results = selftest(&dir)?;
            let passed = results.iter().filter(|r| r.blocked).count();
            println!("WARD selftest · isolation\n");
            for r in &results {
                println!("{}", render::selftest_row(r.name, r.blocked));
            }
            println!("\n  {passed}/{} PASS", results.len());
            Ok(if passed == results.len() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Command::Replay { log } => {
            render_log(&log);
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn render_log(path: &Path) {
    let Ok(reader) = LogReader::open(path) else {
        eprintln!("ward: cannot open log {}", path.display());
        return;
    };
    for record in reader {
        match record {
            Ok(rec) => {
                if let Some(row) = render::observer_row(&rec) {
                    println!("{row}");
                }
            }
            Err(e) => {
                eprintln!("ward: log error: {e}");
                break;
            }
        }
    }
}

fn exit_code(code: Option<i32>) -> ExitCode {
    match code {
        Some(0) => ExitCode::SUCCESS,
        Some(c) => ExitCode::from(u8::try_from(c).unwrap_or(1)),
        None => ExitCode::FAILURE,
    }
}

fn cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}
