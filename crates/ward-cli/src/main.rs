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

use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};

mod init;
mod replay;
mod tui;
mod vault;
use ward_daemon::approvals::ApprovalDecision;
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
    /// Make a directory a WardOS project: `.ward/policy.yaml`, the verifier config,
    /// a `.gitignore` line and TamperWard's wiring. Idempotent; never overwrites
    /// a file you wrote.
    Init {
        /// Project directory (default: current); created when missing.
        dir: Option<PathBuf>,
        /// The agent the closing "next" block names and whose key is looked for.
        #[arg(long, value_enum, default_value_t = init::Agent::Claude)]
        agent: init::Agent,
        /// Leave TamperWard's wiring alone even when `tamperward` is installed.
        #[arg(long)]
        no_tamperward: bool,
        /// Print what would be written and write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// The keys the host keeps for the proxy (`$WARD_STATE_DIR/vault/<NAME>`, mode
    /// 0600). A stored value is never printed back.
    #[command(subcommand)]
    Vault(VaultCmd),
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
    /// Check what this host can give a session, with a fix for each gap.
    Doctor,
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
    /// Follow the current session's log live from its daemon. On a terminal this
    /// is a full-screen observer (trust bar, activity stream, counters; `q` quits);
    /// on a pipe, or with `--plain`, one observer row per record until the log is
    /// sealed (exit 0) or Ctrl-C (exit 130).
    Watch {
        /// Project directory (default: current).
        dir: Option<PathBuf>,
        /// First sequence number to show; earlier records are skipped.
        #[arg(long, default_value_t = 0)]
        from: u64,
        /// Also show the kinds the compact view hides, as a dim kind name.
        #[arg(long)]
        all: bool,
        /// The full-screen observer, even when stdout is not a terminal.
        #[arg(long, conflicts_with = "plain")]
        tui: bool,
        /// One row per line on stdout, even on a terminal.
        #[arg(long, conflicts_with = "tui")]
        plain: bool,
    },
}

/// How `ward watch` shows the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WatchMode {
    /// The full-screen observer.
    Tui,
    /// One row per line.
    Plain,
}

impl WatchMode {
    /// `--tui` and `--plain` decide; otherwise a terminal gets the TUI and a
    /// pipe gets lines.
    fn select(tui: bool, plain: bool, stdout_is_terminal: bool) -> Self {
        if tui || (stdout_is_terminal && !plain) {
            Self::Tui
        } else {
            Self::Plain
        }
    }
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
enum VaultCmd {
    /// Store a key: typed at the terminal without echo, or the first line of stdin.
    Set {
        /// The host variable the key stands for (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
        /// `GITHUB_TOKEN`); `[A-Z][A-Z0-9_]*`.
        name: String,
        /// Read the value from stdin even on a terminal.
        #[arg(long)]
        stdin: bool,
    },
    /// Every known key and whether it is set (vault, environment, neither); no values.
    List,
    /// Forget a key.
    Rm {
        /// The key's name.
        name: String,
    },
    /// Print the vault directory.
    Path,
}

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
    /// The approvals the session daemon holds (ADR-0016), one JSON object per
    /// line: `{id, tool, summary, reason, requested_at_unix_ms, agent, session}`.
    /// The session is the project's current one, else (the desktop asks from
    /// home, not a project) the newest one a daemon serves.
    Pending {
        /// Project directory (default: current).
        dir: Option<PathBuf>,
        /// The session id, instead of looking one up.
        #[arg(long)]
        session: Option<String>,
        /// Keep printing each approval as it becomes pending, until the daemon
        /// closes the stream (exit 0).
        #[arg(long)]
        follow: bool,
    },
    /// Answer a held approval: `allow` (once), `allow-session` (the same tool on
    /// the same target for the rest of the session) or `deny`.
    Approve {
        /// The approval's id, as `ward session pending` lists it.
        id: u64,
        /// The answer.
        decision: ApprovalDecision,
        /// Project directory (default: current).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// The session id, as `ward session pending` lists it.
        #[arg(long)]
        session: Option<String>,
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
        Command::Init {
            dir,
            agent,
            no_tamperward,
            dry_run,
        } => cmd_init(
            dir.unwrap_or_else(|| PathBuf::from(".")),
            agent,
            no_tamperward,
            dry_run,
        ),
        Command::Vault(cmd) => cmd_vault(cmd),
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
        Command::Doctor => {
            let checks = ward_daemon::doctor::run();
            print!("{}", render::doctor_panel(&checks));
            Ok(if ward_daemon::doctor::healthy(&checks) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
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
        Command::Session(SessionCmd::Pending {
            dir,
            session,
            follow,
        }) => cmd_pending(&dir.unwrap_or_else(cwd), session.as_deref(), follow),
        Command::Session(SessionCmd::Approve {
            id,
            decision,
            dir,
            session,
        }) => cmd_approve(&dir.unwrap_or_else(cwd), session.as_deref(), id, decision),
        Command::Snapshot(SnapshotCmd::Create { dir, role }) => {
            cmd_snapshot_create(&dir.unwrap_or_else(cwd), role.into())
        }
        Command::Snapshot(SnapshotCmd::Diff { a, b, json }) => cmd_snapshot_diff(&a, &b, json),
        Command::Snapshot(SnapshotCmd::Cat { id, path }) => cmd_snapshot_cat(&id, &path),
        Command::Evidence(EvidenceCmd::Append { dir, json }) => {
            cmd_evidence_append(&dir.unwrap_or_else(cwd), &json)
        }
        Command::Watch {
            dir,
            from,
            all,
            tui,
            plain,
        } => cmd_watch(
            &dir.unwrap_or_else(cwd),
            client::WatchOptions {
                from_seq: from,
                all,
            },
            WatchMode::select(tui, plain, std::io::stdout().is_terminal()),
        ),
    }
}

/// `ward init`: everything the command reads from its environment is gathered here
/// and handed to [`init::run`] as values.
fn cmd_init(
    dir: PathBuf,
    agent: init::Agent,
    no_tamperward: bool,
    dry_run: bool,
) -> ward_daemon::Result<ExitCode> {
    let key_env = match agent {
        init::Agent::Claude => "ANTHROPIC_API_KEY",
        init::Agent::Codex => "OPENAI_API_KEY",
    };
    let opts = init::Options {
        dir,
        agent,
        tamperward: init::find_tamperward(&std::env::var("PATH").unwrap_or_default()),
        no_tamperward,
        dry_run,
        state: ward_daemon::session::state_root(),
        key_in_env: std::env::var(key_env).is_ok_and(|v| !v.trim().is_empty()),
    };
    let report = init::run(&opts)?;
    print!("{}", report.render());
    Ok(ExitCode::SUCCESS)
}

/// `ward vault …`: the value of a key is read once, on `set`, and never shown.
fn cmd_vault(cmd: VaultCmd) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    match cmd {
        VaultCmd::Set { name, stdin } => {
            vault::validate(&name)?;
            let value = vault::read_value(&name, stdin)?;
            let path = vault::set(&state, &name, &value)?;
            println!(
                "  {name} stored in {} (0600); the proxy injects it, the sandbox never sees it",
                path.display()
            );
        }
        VaultCmd::List => {
            let rows = vault::list(&state, |name| {
                std::env::var(name).is_ok_and(|v| !v.trim().is_empty())
            })?;
            let width = rows.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
            for (name, source) in rows {
                println!("  {name:<width$}   {}", source.text());
            }
        }
        VaultCmd::Rm { name } => {
            if vault::remove(&state, &name)? {
                println!("  {name} forgotten");
            } else {
                println!("  {name} was not set");
            }
        }
        VaultCmd::Path => println!("{}", vault::dir(&state).display()),
    }
    Ok(ExitCode::SUCCESS)
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

/// `ward watch`: the daemon's subscription, as the full-screen observer or as a
/// line-at-a-time reader. The daemon is contacted first, on a plain terminal, so
/// a missing one is reported as `NO_DAEMON` (exit 1) before raw mode. In line
/// mode Ctrl-C is left to SIGINT's default disposition, which ends the process
/// with status 130; in the TUI it is a key that quits like `q`.
fn cmd_watch(
    dir: &Path,
    opts: client::WatchOptions,
    mode: WatchMode,
) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    let meta = SessionMeta::current(dir, &state)?.ok_or_else(|| {
        ward_daemon::Error::Project(format!(
            "no session for {}; run `ward up {0}` to start one",
            dir.display()
        ))
    })?;
    let sink = client::connect(&client::socket_path(dir, &state)?)?;
    match mode {
        WatchMode::Tui => tui::run(sink, &meta, opts)?,
        WatchMode::Plain => {
            let mut out = std::io::stdout();
            client::watch(sink, opts, |row| {
                // A closed pipe (`ward watch | head`) is the reader's choice, not an error.
                let _ = writeln!(out, "{row}").and_then(|()| out.flush());
            })?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// One line of `ward session pending`: the approval plus who asks and where.
#[derive(serde::Serialize)]
struct PendingLine<'a> {
    #[serde(flatten)]
    approval: &'a ward_daemon::approvals::Approval,
    /// The agent's product name, for the notification's title.
    agent: &'a str,
    /// The session id.
    session: &'a str,
}

/// `ward session pending [--follow]`: what the daemon holds, as JSON lines the
/// desktop's `wardos-approve` reads. A quiet stream is not a dead daemon; the
/// stream ending is the log sealed, and the command exits 0.
fn cmd_pending(dir: &Path, session: Option<&str>, follow: bool) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    let socket = client::desktop_socket(dir, &state, session)?;
    let mut sink = client::connect(&socket)?;
    let description = client::describe(&mut sink)?;
    let agent = description
        .agent
        .as_ref()
        .map_or("agent", |a| a.name.as_str());
    let mut out = std::io::stdout();
    let mut print = |approval: &ward_daemon::approvals::Approval| {
        let line = PendingLine {
            approval,
            agent,
            session: &description.session,
        };
        if let Ok(json) = serde_json::to_string(&line) {
            // A closed pipe is the reader's choice, not an error.
            let _ = writeln!(out, "{json}").and_then(|()| out.flush());
        }
    };
    if follow {
        client::follow_pending(&socket, FOLLOW_SETTLE, |approval| print(&approval))?;
    } else {
        for approval in client::pending(&mut sink)? {
            print(&approval);
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// How long `ward session pending --follow` lets the stream go quiet before
/// it counts the backlog as read.
const FOLLOW_SETTLE: Duration = Duration::from_millis(250);

/// `ward session approve <id> <decision>`.
fn cmd_approve(
    dir: &Path,
    session: Option<&str>,
    id: u64,
    decision: ApprovalDecision,
) -> ward_daemon::Result<ExitCode> {
    let state = ward_daemon::session::state_root();
    let mut sink = client::connect(&client::desktop_socket(dir, &state, session)?)?;
    client::approve(&mut sink, id, decision)?;
    println!("  approval {id} {decision}");
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
    let verifier = ward_daemon::selftest_verifier(&mut session)?;
    let control = ward_daemon::session::session_dir(session.state_root(), session.id())
        .join(ward_daemon::control::SOCKET_NAME);
    if throwaway {
        session.stop(EndReason::UserStop)?;
    } else {
        session.sync()?;
    }
    let egress = ward_daemon::selftest_egress(dir, Some(&control))?;
    let groups = [
        ("isolation", &isolation),
        ("credentials", &credentials),
        ("evidence", &evidence),
        ("verifier boundary", &verifier),
        ("egress and surfaces", &egress),
    ];
    for (name, results) in &groups {
        println!("WARD selftest · {name}\n");
        for r in *results {
            println!("{}", render::selftest_row(r.name, &r.verdict));
        }
        println!();
    }
    let all = groups.iter().flat_map(|(_, r)| r.iter());
    let total = all.clone().count();
    let passed = all.clone().filter(|p| p.blocked()).count();
    let reached = all.clone().filter(|p| p.reached()).count();
    // A probe this host cannot run is reported, never counted as a pass.
    let unmeasured = total - passed - reached;
    if unmeasured == 0 {
        println!("  {passed}/{total} PASS");
    } else {
        println!("  {passed}/{total} PASS · {unmeasured} CANNOT-MEASURE-HERE");
    }
    Ok(if reached == 0 {
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

#[cfg(test)]
mod tests {
    use super::WatchMode;

    #[test]
    fn watch_mode_prefers_the_tui_on_a_terminal_unless_plain() {
        assert_eq!(WatchMode::select(false, false, true), WatchMode::Tui);
        assert_eq!(WatchMode::select(false, false, false), WatchMode::Plain);
        assert_eq!(WatchMode::select(false, true, true), WatchMode::Plain);
        assert_eq!(WatchMode::select(true, false, false), WatchMode::Tui);
    }
}
