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

use std::time::Duration;

use clap::{Parser, Subcommand};

mod replay;
use ward_daemon::{Session, SessionMeta, render, selftest};
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
    /// Start a session, record it as the project's current session, and print its
    /// security panel.
    Up {
        /// Project directory (default: current).
        dir: Option<PathBuf>,
    },
    /// Print the current session's security panel without starting one.
    Status {
        /// Project directory (default: current).
        dir: Option<PathBuf>,
    },
    /// Run a command in the current session's sandbox (starting a throwaway session
    /// if none is active), and show the observer view.
    Run {
        /// Project directory (default: current).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Command and arguments to run.
        #[arg(trailing_var_arg = true, required = true)]
        argv: Vec<String>,
    },
    /// Launch Claude Code inside the session sandbox (interactive).
    Claude {
        /// Project directory (default: current).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Host environment variables to pass through (explicit, visible opt-in).
        #[arg(long = "pass-env")]
        pass_env: Vec<String>,
        /// Extra arguments for the agent.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Launch OpenAI Codex inside the session sandbox (interactive).
    Codex {
        /// Project directory (default: current).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Host environment variables to pass through (explicit, visible opt-in).
        #[arg(long = "pass-env")]
        pass_env: Vec<String>,
        /// Extra arguments for the agent.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// End the current session and seal its log.
    Stop {
        /// Project directory (default: current).
        dir: Option<PathBuf>,
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
        /// Verify the hash chain and the sealed `HEAD`; print a verdict instead of rows.
        #[arg(long)]
        verify: bool,
        /// Emit one JSON object per record.
        #[arg(long)]
        json: bool,
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
        Command::Up { dir } => cmd_up(&dir.unwrap_or_else(cwd)),
        Command::Status { dir } => cmd_status(&dir.unwrap_or_else(cwd)),
        Command::Run { dir, argv } => cmd_run(&dir.unwrap_or_else(cwd), &argv),
        Command::Claude {
            dir,
            pass_env,
            args,
        } => cmd_agent(&dir.unwrap_or_else(cwd), "claude", &args, &pass_env),
        Command::Codex {
            dir,
            pass_env,
            args,
        } => cmd_agent(&dir.unwrap_or_else(cwd), "codex", &args, &pass_env),
        Command::Stop { dir } => cmd_stop(&dir.unwrap_or_else(cwd)),
        Command::Selftest { dir } => cmd_selftest(&dir.unwrap_or_else(cwd)),
        Command::Replay { log, verify, json } => {
            let report = replay::replay(&log, replay::Options { verify, json })?;
            print!("{}", report.output);
            Ok(if report.ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
    }
}

fn cmd_up(dir: &Path) -> ward_daemon::Result<ExitCode> {
    let session = Session::start(dir)?;
    session.persist_current()?;
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
    println!("{}", render::session_status_line(Some(Duration::ZERO)));
    println!("  session ready · log {}", session.log_path().display());
    Ok(ExitCode::SUCCESS)
}

fn cmd_status(dir: &Path) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    if let Some(meta) = SessionMeta::current(dir, &state)? {
        print!(
            "{}",
            render::status_panel(
                &meta.id,
                &dir.display().to_string(),
                &meta.entry_snapshot,
                &meta.manifest,
            )
        );
        println!();
        println!("{}", render::session_status_line(Some(meta.started_ago())));
    } else {
        println!("{}", render::session_status_line(None));
        println!("  run `ward up {}` to start one", dir.display());
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_agent(
    dir: &Path,
    agent: &str,
    args: &[String],
    pass_env: &[String],
) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    let (mut session, throwaway) = match Session::open_current(dir, &state)? {
        Some(session) => (session, false),
        None => (Session::start(dir)?, true),
    };
    if !pass_env.is_empty() {
        eprintln!(
            "ward: passing host environment through to the sandbox: {}",
            pass_env.join(", ")
        );
    }
    let log = session.log_path();
    let (command, opts) = session.agent_launch(agent, args, pass_env)?;
    for g in &opts.gateways {
        eprintln!(
            "ward: {} credential stays on the host; the proxy injects it",
            g.service
        );
    }
    let report = session.launch(&command, &opts)?;
    if throwaway {
        session.stop(EndReason::UserStop)?;
    } else {
        session.sync()?;
    }
    println!();
    render_log(&log);
    Ok(exit_code(report.code))
}

fn cmd_run(dir: &Path, argv: &[String]) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    // Append to the project's current session, or start a throwaway that seals its
    // own log when none is active.
    let (mut session, throwaway) = match Session::open_current(dir, &state)? {
        Some(session) => (session, false),
        None => (Session::start(dir)?, true),
    };
    let log = session.log_path();
    let report = session.run(argv)?;
    let code = report.code;
    if throwaway {
        session.stop(EndReason::UserStop)?;
    } else {
        session.sync()?;
    }
    render_log(&log);
    if !report.stdout.is_empty() {
        println!("\n{}", report.stdout.trim_end());
    }
    if code != Some(0) && !report.stderr.is_empty() {
        eprintln!("\n{}", report.stderr.trim_end());
    }
    Ok(exit_code(code))
}

fn cmd_stop(dir: &Path) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    if let Some(session) = Session::open_current(dir, &state)? {
        let id = session.id().to_owned();
        session.stop(EndReason::UserStop)?;
        println!("  session {id} stopped");
    } else {
        println!("{}", render::session_status_line(None));
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_selftest(dir: &Path) -> ward_daemon::Result<ExitCode> {
    let results = selftest(dir)?;
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
