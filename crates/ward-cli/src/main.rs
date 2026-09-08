//! `ward` — the WardOS command-line client.
//!
//! Sandboxes, proxies and hook listeners run in this process (ADR-0013); the
//! session log is written by the per-session `wardd` that `ward up` starts
//! (ADR-0015), or by this process when none is serving.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::struct_field_names
)]

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};

mod replay;
use ward_daemon::{Session, SessionMeta, SnapshotRole, client, daemon, render, selftest, snapshot};
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
        dir: Option<PathBuf>,
        /// Host environment variables to pass through (explicit, visible opt-in).
        #[arg(long = "pass-env")]
        pass_env: Vec<String>,
        /// Grant a brokered credential the policy marks `ask` (e.g. `github`).
        #[arg(long = "grant")]
        grant: Vec<String>,
        /// Extra arguments for the agent.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Launch OpenAI Codex inside the session sandbox (interactive).
    Codex {
        /// Project directory (default: current).
        dir: Option<PathBuf>,
        /// Host environment variables to pass through (explicit, visible opt-in).
        #[arg(long = "pass-env")]
        pass_env: Vec<String>,
        /// Grant a brokered credential the policy marks `ask` (e.g. `github`).
        #[arg(long = "grant")]
        grant: Vec<String>,
        /// Extra arguments for the agent.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// End the current session and seal its log.
    Stop {
        /// Project directory (default: current).
        dir: Option<PathBuf>,
    },
    /// Verify the worktree in a disposable trusted verifier (`.tamperward/config.yml`).
    Verify {
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
    /// Session facts for TamperWard (`docs/tamperward-integration.md` §2).
    #[command(subcommand)]
    Session(SessionCmd),
    /// Snapshot primitives for TamperWard, answered from the session CAS.
    #[command(subcommand)]
    Snapshot(SnapshotCmd),
    /// Evidence records for TamperWard, appended by the session daemon.
    #[command(subcommand)]
    Evidence(EvidenceCmd),
    /// Follow the current session's log live: one observer row per record, from
    /// the daemon, until the log is sealed (exit 0) or Ctrl-C (exit 130).
    Watch {
        /// Project directory (default: current).
        dir: Option<PathBuf>,
        /// First sequence number to show; earlier records are skipped.
        #[arg(long, default_value_t = 0)]
        from: u64,
        /// Also show the kinds the compact view hides, as a dim kind name.
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum EvidenceCmd {
    /// Append one `TamperWard`-origin record to the current session's log through
    /// its daemon, and print the record's `seq` and observer row.
    #[command(after_help = EVIDENCE_EXAMPLES)]
    Append {
        /// Project directory (default: current).
        dir: Option<PathBuf>,
        /// The record as `WardEvent` JSON, or `-` to read it from stdin.
        #[arg(long, value_name = "RECORD")]
        json: String,
    },
}

const EVIDENCE_EXAMPLES: &str = "\
The record is a `WardEvent` in its serde JSON shape and must be an evidence kind:
PolicyDecision, PolicyDenied, TamperDetected or StateAccepted. `detail` may be a bare
string. Subjects: Session, Manifest, Policy, ProtectedTests, VerifyConfig, Ci, Hooks,
Fixtures, {\"Snapshot\":{\"id\":\"<hex>\"}}, {\"Path\":{\"path\":…}}, {\"Other\":{\"detail\":…}}.

Examples:
  ward evidence append --json '{\"PolicyDenied\":{\"subject\":\"ProtectedTests\",
      \"rule\":\"protected-tests\",\"detail\":\"tests/verify.rs\"}}'
  ward evidence append --json '{\"TamperDetected\":{\"subject\":\"VerifyConfig\",
      \"detail\":\".tamperward/config.yml\"}}'
  ward evidence append --json '{\"StateAccepted\":{\"snapshot\":\"<64 hex>\",
      \"by\":\"TamperWard\"}}'
  ward evidence append --json - < record.json
";

#[derive(Subcommand)]
enum SessionCmd {
    /// Print the immutable facts of the current session: ids, worktree, start time,
    /// agent, entry snapshot, policy hash, and the capability manifest.
    Describe {
        /// Project directory (default: current).
        dir: Option<PathBuf>,
        /// Emit the `SessionDescription` as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum SnapshotCmd {
    /// Capture the worktree into the session CAS and print the snapshot id; the
    /// current session records it (a throwaway session is used when none is active).
    Create {
        /// Project directory (default: current).
        dir: Option<PathBuf>,
        /// Lifecycle role to record for the snapshot.
        #[arg(long, value_enum, default_value_t = Role::Candidate)]
        role: Role,
    },
    /// Manifest-level diff of two stored snapshots (never reads the worktree).
    /// Ids are `blake3:<hex>` or bare hex, in full: the store has no prefix lookup.
    Diff {
        /// The earlier snapshot.
        a: String,
        /// The later snapshot.
        b: String,
        /// Emit `{added, removed, changed}` as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write the pristine bytes of a path within a snapshot to stdout, undecorated.
    /// The id is `blake3:<hex>` or bare hex, in full.
    Cat {
        /// The snapshot.
        id: String,
        /// Worktree-relative path.
        path: PathBuf,
    },
}

/// The roles a snapshot may be created with from the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Role {
    /// A state offered for verification.
    Candidate,
    /// The state at session end.
    Final,
}

impl From<Role> for SnapshotRole {
    fn from(r: Role) -> Self {
        match r {
            Role::Candidate => Self::Candidate,
            Role::Final => Self::Final,
        }
    }
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
            grant,
            args,
        } => cmd_agent(&dir.unwrap_or_else(cwd), "claude", &args, &pass_env, &grant),
        Command::Codex {
            dir,
            pass_env,
            grant,
            args,
        } => cmd_agent(&dir.unwrap_or_else(cwd), "codex", &args, &pass_env, &grant),
        Command::Stop { dir } => cmd_stop(&dir.unwrap_or_else(cwd)),
        Command::Verify { dir } => cmd_verify(&dir.unwrap_or_else(cwd)),
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
        Command::Session(SessionCmd::Describe { dir, json }) => {
            cmd_describe(&dir.unwrap_or_else(cwd), json)
        }
        Command::Snapshot(SnapshotCmd::Create { dir, role }) => {
            cmd_snapshot_create(&dir.unwrap_or_else(cwd), role.into())
        }
        Command::Snapshot(SnapshotCmd::Diff { a, b, json }) => cmd_snapshot_diff(&a, &b, json),
        Command::Snapshot(SnapshotCmd::Cat { id, path }) => cmd_snapshot_cat(&id, &path),
        Command::Evidence(EvidenceCmd::Append { dir, json }) => {
            cmd_evidence_append(&dir.unwrap_or_else(cwd), &json)
        }
        Command::Watch { dir, from, all } => cmd_watch(
            &dir.unwrap_or_else(cwd),
            client::WatchOptions {
                from_seq: from,
                all,
            },
        ),
    }
}

/// `ward evidence append`: parse and check the record here, so a refused kind never
/// reaches the socket; then the daemon appends it with `origin = TamperWard`.
fn cmd_evidence_append(dir: &Path, json: &str) -> ward_daemon::Result<ExitCode> {
    let text = if json == "-" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|e| ward_daemon::Error::Io {
                path: PathBuf::from("<stdin>"),
                source: e,
            })?;
        text
    } else {
        json.to_owned()
    };
    let event = client::parse_evidence(&text)?;
    let state = ward_daemon::session::state_root();
    let mut sink = client::connect(&client::socket_path(dir, &state)?)?;
    let record = client::append_evidence(&mut sink, event)?;
    if let Some(row) = render::observer_row(&record) {
        println!("{row}");
    }
    println!("seq {}", record.seq);
    Ok(ExitCode::SUCCESS)
}

/// `ward watch`: a line-at-a-time reader over the daemon's subscription. Ctrl-C is
/// left to SIGINT's default disposition, which ends the process with status 130.
fn cmd_watch(dir: &Path, opts: client::WatchOptions) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    let sink = client::connect(&client::socket_path(dir, &state)?)?;
    let mut out = std::io::stdout();
    client::watch(sink, opts, |row| {
        // A closed pipe (`ward watch | head`) is the reader's choice, not an error.
        let _ = writeln!(out, "{row}").and_then(|()| out.flush());
    })?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_describe(dir: &Path, json: bool) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    let session = Session::open_current(dir, &state)?.ok_or_else(|| {
        ward_daemon::Error::Project(format!(
            "no session for {}; run `ward up {0}` to start one",
            dir.display()
        ))
    })?;
    let description = session.describe();
    if json {
        println!("{}", to_json(&description)?);
    } else {
        print!("{}", render::describe_panel(&description));
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_snapshot_create(dir: &Path, role: SnapshotRole) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    let (mut session, throwaway) = match Session::open_current(dir, &state)? {
        Some(session) => (session, false),
        None => (Session::start(dir)?, true),
    };
    let meta = session.snapshot(role)?;
    if throwaway {
        session.stop(EndReason::UserStop)?;
    } else {
        session.sync()?;
    }
    println!("{}", meta.id);
    Ok(ExitCode::SUCCESS)
}

/// The CAS is shared by every project under one state root, so `diff` and `cat`
/// take no project directory.
fn cmd_snapshot_diff(a: &str, b: &str, json: bool) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    let report = snapshot::diff(&state, snapshot::parse_id(a)?, snapshot::parse_id(b)?)?;
    if json {
        println!("{}", to_json(&report)?);
    } else {
        print!("{}", render::snapshot_diff(&report));
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_snapshot_cat(id: &str, path: &Path) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    let bytes = snapshot::cat(&state, snapshot::parse_id(id)?, path)?;
    let mut out = std::io::stdout().lock();
    out.write_all(&bytes)
        .and_then(|()| out.flush())
        .map_err(|e| ward_daemon::Error::Io {
            path: PathBuf::from("<stdout>"),
            source: e,
        })?;
    Ok(ExitCode::SUCCESS)
}

fn to_json<T: serde::Serialize>(value: &T) -> ward_daemon::Result<String> {
    serde_json::to_string_pretty(value).map_err(|e| ward_daemon::Error::Project(e.to_string()))
}

fn cmd_up(dir: &Path) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    let mut session = Session::start_in(dir, &state)?;
    session.persist_current()?;
    session.sync()?;
    let id = session.id().to_owned();
    let log = session.log_path();
    print!(
        "{}",
        render::status_panel(
            &id,
            &dir.display().to_string(),
            session.entry_snapshot(),
            session.manifest(),
        )
    );
    // Hand the log over: from here on the daemon is its writer (ADR-0015).
    drop(session);
    let control = match daemon::spawn(&state, &id) {
        Ok(Some(_)) => Some(control_name(&id)),
        Ok(None) => {
            eprintln!("ward: wardd not found beside `ward` or on PATH; staying in-process");
            None
        }
        Err(e) => {
            eprintln!("ward: {e}; staying in-process");
            None
        }
    };
    println!();
    println!("{}", render::session_status_line(Some(Duration::ZERO)));
    println!("{}", render::daemon_status_line(control.as_deref()));
    println!("  session ready · log {}", log.display());
    Ok(ExitCode::SUCCESS)
}

/// The control socket relative to the state root, as the panel names it.
fn control_name(id: &str) -> String {
    format!("sessions/{id}/{}", ward_daemon::control::SOCKET_NAME)
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
        let control = daemon::serving(&state, &meta.id).then(|| control_name(&meta.id));
        println!("{}", render::daemon_status_line(control.as_deref()));
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
    grants: &[String],
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
    let (command, opts) = session.agent_launch(agent, args, pass_env, grants)?;
    for g in opts.gateways.iter().filter(|g| g.service != "github") {
        eprintln!(
            "ward: {} credential stays on the host; the proxy injects it",
            g.service
        );
    }
    for note in &opts.notes {
        eprintln!("ward: {note}");
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
        // With a daemon serving, `stop` is a `Request::Stop`: the daemon writes
        // `SessionEnded`, seals, and exits; otherwise this process seals the log.
        let served = daemon::serving(&state, &id);
        session.stop(EndReason::UserStop)?;
        if served && !daemon::wait_stopped(&state, &id, daemon::STARTUP_TIMEOUT) {
            eprintln!("ward: wardd has not released {}", control_name(&id));
        }
        println!("  session {id} stopped");
    } else {
        println!("{}", render::session_status_line(None));
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(dir: &Path) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    let (mut session, throwaway) = match Session::open_current(dir, &state)? {
        Some(session) => (session, false),
        None => (Session::start(dir)?, true),
    };
    let log = session.log_path();
    let report = session.verify()?;
    if throwaway {
        session.stop(EndReason::UserStop)?;
    } else {
        session.sync()?;
    }
    print!("{}", render::verify_report(&report));
    println!();
    render_log(&log);
    Ok(if report.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn cmd_selftest(dir: &Path) -> ward_daemon::Result<ExitCode> {
    let isolation = selftest(dir)?;
    let state = ward_daemon::session::state_root();
    let (mut session, throwaway) = match Session::open_current(dir, &state)? {
        Some(session) => (session, false),
        None => (Session::start(dir)?, true),
    };
    let credentials = ward_daemon::selftest_credentials(&mut session)?;
    let evidence = ward_daemon::selftest_evidence(&mut session)?;
    if throwaway {
        session.stop(EndReason::UserStop)?;
    } else {
        session.sync()?;
    }
    let groups = [
        ("isolation", &isolation),
        ("credentials", &credentials),
        ("evidence", &evidence),
    ];
    for (name, results) in &groups {
        println!("WARD selftest · {name}\n");
        for r in *results {
            println!("{}", render::selftest_row(r.name, r.blocked));
        }
        println!();
    }
    let total: usize = groups.iter().map(|(_, r)| r.len()).sum();
    let passed: usize = groups
        .iter()
        .map(|(_, r)| r.iter().filter(|p| p.blocked).count())
        .sum();
    println!("  {passed}/{total} PASS");
    Ok(if passed == total {
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
