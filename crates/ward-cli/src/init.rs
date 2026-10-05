//! `ward init`: make a directory a WardOS project (ADR-0017).
//!
//! One command writes what a session needs and nothing it does not: the project
//! policy (`.ward/policy.yaml`, from [`Policy::template`]), the verifier's config
//! (`.tamperward/config.yml`, what `ward verify` reads), a `.gitignore` line for the
//! session state, and TamperWard's own wiring through `tamperward init` when it is
//! installed (a minimal `.tamperward.yml` when it is not). Every file is written only
//! when absent, so the command is idempotent and never overwrites a file the user
//! wrote; `--dry-run` reports the plan and touches nothing.
//!
//! The verification boundary — the command `ward verify` runs and the paths it
//! restores — is proposed from the project's lockfiles and test configuration
//! ([`ward_daemon::verify_proposal`], #147 item 2) and written *active* only when a trusted user
//! accepts it: `--accept-verify`, or a yes at the terminal. Without that it is written
//! commented out, so nothing the project's files merely suggest ever runs in the
//! verifier on the strength of a guess; `ward ready` then says the command is not
//! accepted and shows the same proposal.

use std::fmt::Write as _;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::ValueEnum;
use ward_daemon::verify::CONFIG_PATH;
use ward_daemon::verify_proposal::{Input, Proposal, Survey};
use ward_daemon::{Error, Result, gateway};
use ward_policy::Policy;

/// An I/O error with the path it happened at.
fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Error {
    Error::Io {
        path: path.into(),
        source,
    }
}

/// The line that marks a verifier config or TamperWard policy as `ward init`'s own
/// unaccepted proposal: the only kind of existing file acceptance may replace.
const PROPOSED_MARKER: &str = "# Proposed by `ward init`, not accepted.";

/// The question asked at a terminal when one boundary is proposed and none accepted.
const ACCEPT_PROMPT: &str = "Accept this verification boundary? It becomes verify.command and \
                             protected.tests in .tamperward/config.yml; nothing runs before \
                             you accept. [y/N] ";

/// The agent the closing "next" block names, and whose key is looked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Agent {
    /// Claude Code (`ward claude`, `ANTHROPIC_API_KEY`).
    Claude,
    /// OpenAI Codex (`ward codex`, `OPENAI_API_KEY`).
    Codex,
}

impl Agent {
    /// The `ward` subcommand that launches this agent.
    const fn command(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }

    /// The host variable (and vault file) holding its model-API key.
    pub(crate) const fn key_env(self) -> &'static str {
        match self {
            Self::Claude => "ANTHROPIC_API_KEY",
            Self::Codex => "OPENAI_API_KEY",
        }
    }
}

/// Everything `ward init` reads from its environment, gathered by the caller.
pub struct Options {
    /// The directory to make a project; the argument as typed, for the "next" block.
    pub dir: PathBuf,
    /// The agent to name in the "next" block.
    pub agent: Agent,
    /// The `tamperward` binary to run, `None` when it is not installed.
    pub tamperward: Option<PathBuf>,
    /// `--no-tamperward`: leave TamperWard's wiring alone even when it is installed.
    pub no_tamperward: bool,
    /// Report the plan and write nothing.
    pub dry_run: bool,
    /// The state root whose `vault/` is checked for the key.
    pub state: PathBuf,
    /// Whether the agent's key variable is set on the host.
    pub key_in_env: bool,
    /// Who may accept the proposed verification boundary during this run.
    pub accept: Accept,
}

/// Who may accept the proposed verification boundary during a run.
#[derive(Clone, Copy)]
pub enum Accept {
    /// `--accept-verify`: the one proposal, without a question.
    Flag,
    /// Ask at the terminal, with this function, when exactly one is proposed.
    Ask(fn(&str) -> bool),
    /// Nobody: no flag, and stdin or stdout is not a terminal, so a script never
    /// blocks on a question.
    Nobody,
}

/// What happened to one item of the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    /// The file was written (or, dry: would be).
    Written,
    /// The unaccepted proposal `ward init` wrote earlier was replaced by the accepted
    /// boundary (or, dry: would be).
    Accepted,
    /// The file was already there and left as it is.
    Kept,
    /// Nothing to do, with the reason.
    Skipped(String),
    /// A free-form result (the TamperWard step).
    Note(String),
}

/// How the proposed verification boundary ended up.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Acceptance {
    /// Written active, with this command: `--accept-verify`, or yes at the terminal.
    Accepted(String),
    /// One proposal, written commented out.
    Proposed,
    /// Several proposals, all commented out; none chosen for the user.
    Several,
    /// Nothing could be proposed; the key is left for the user to fill.
    Nothing,
    /// The verifier config already existed and was not `ward init`'s own unaccepted
    /// proposal: the user's file, left alone.
    Kept,
}

/// One row of the report.
#[derive(Debug)]
struct Step {
    label: &'static str,
    path: String,
    outcome: Outcome,
}

/// The result of `ward init`: the rows, and what to do next.
#[derive(Debug)]
pub struct Report {
    steps: Vec<Step>,
    survey: Survey,
    acceptance: Acceptance,
    next: Vec<(String, &'static str)>,
    dry_run: bool,
    dir: PathBuf,
}

impl Report {
    /// Render the report in the style of the other panels.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "WARD init · {}", self.dir.display());
        if self.dry_run {
            let _ = writeln!(out, "  dry run: nothing is written");
        }
        let _ = writeln!(out);
        let width = self.steps.iter().map(|s| s.path.len()).max().unwrap_or(0);
        for s in &self.steps {
            let outcome = match &s.outcome {
                Outcome::Written if self.dry_run => "would write".to_owned(),
                Outcome::Written => "written".to_owned(),
                Outcome::Accepted if self.dry_run => "would accept".to_owned(),
                Outcome::Accepted => "accepted".to_owned(),
                Outcome::Kept => "already there, left as is".to_owned(),
                Outcome::Skipped(why) => format!("skipped · {why}"),
                Outcome::Note(text) => text.clone(),
            };
            let _ = writeln!(out, "  {:<11} {:<width$}  {outcome}", s.label, s.path);
        }
        if self.acceptance != Acceptance::Kept {
            let _ = write!(out, "\n{}", self.survey.render());
            let would = if self.dry_run { "would be " } else { "" };
            match &self.acceptance {
                Acceptance::Accepted(command) => {
                    let _ = writeln!(
                        out,
                        "  accepted: `{command}` {would}written to {CONFIG_PATH} as verify.command, its protected inputs as protected.tests"
                    );
                }
                Acceptance::Proposed => {
                    let _ = writeln!(
                        out,
                        "  not accepted: {would}written commented out; nothing runs until a trusted user accepts it with `ward init --accept-verify`"
                    );
                }
                Acceptance::Several => {
                    let _ = writeln!(
                        out,
                        "  several match: none accepted; `ward init --accept-verify` needs one, so uncomment one in {CONFIG_PATH}"
                    );
                }
                Acceptance::Nothing => {
                    let _ = writeln!(
                        out,
                        "  name the test command in {CONFIG_PATH} to make the project verifiable"
                    );
                }
                Acceptance::Kept => {}
            }
        }
        let _ = writeln!(out, "\nNext");
        let width = self.next.iter().map(|(c, _)| c.len()).max().unwrap_or(0);
        for (command, why) in &self.next {
            let _ = writeln!(out, "  {command:<width$}   {why}");
        }
        out
    }
}

/// Run `ward init` with `opts`, returning the report; TamperWard's own output goes
/// straight to the terminal as it runs.
pub fn run(opts: &Options) -> Result<Report> {
    if !opts.dry_run {
        std::fs::create_dir_all(&opts.dir).map_err(|e| io(&opts.dir, e))?;
    }
    let dir = if opts.dir.is_dir() {
        opts.dir.canonicalize().map_err(|e| io(&opts.dir, e))?
    } else {
        opts.dir.clone()
    };
    let survey = Survey::of(&dir);
    let config_path = dir.join(CONFIG_PATH);
    let awaiting = awaiting_acceptance(&config_path);
    let accepted = accepted_proposal(opts, &survey, awaiting)?;
    let mut steps = Vec::new();

    steps.push(Step {
        label: "policy",
        path: ".ward/policy.yaml".to_owned(),
        outcome: write_new(
            &dir.join(".ward/policy.yaml"),
            Policy::template(),
            opts.dry_run,
        )?,
    });
    steps.push(Step {
        label: "gitignore",
        path: ".gitignore".to_owned(),
        outcome: ignore_sessions(&dir, opts.dry_run)?,
    });
    let verifier = write_boundary(
        &config_path,
        &verifier_config(&survey, accepted),
        accepted.is_some(),
        opts.dry_run,
    )?;
    let acceptance = match (&verifier, accepted, survey.proposals.as_slice()) {
        (Outcome::Kept | Outcome::Skipped(_) | Outcome::Note(_), _, _) => Acceptance::Kept,
        (_, Some(p), _) => Acceptance::Accepted(p.command.clone()),
        (_, None, []) => Acceptance::Nothing,
        (_, None, [_]) => Acceptance::Proposed,
        (_, None, _) => Acceptance::Several,
    };
    steps.push(verifier_step(verifier, &acceptance, &survey, opts.dry_run));
    steps.push(tamperward_step(&dir, &survey, accepted, opts)?);
    let next = next_steps(opts, &acceptance);
    Ok(Report {
        steps,
        survey,
        acceptance,
        next,
        dry_run: opts.dry_run,
        dir,
    })
}

/// The verifier row of the report: what was written, and whether as an accepted
/// boundary, an unaccepted proposal, several candidates or a blank to fill.
fn verifier_step(verifier: Outcome, acceptance: &Acceptance, survey: &Survey, dry: bool) -> Step {
    let would = |done: &str, would: &str| if dry { would } else { done }.to_owned();
    let outcome = match verifier {
        Outcome::Written => Outcome::Note(format!(
            "{} ({})",
            would("written", "would write"),
            match acceptance {
                Acceptance::Accepted(command) => format!("accepted: {command}"),
                Acceptance::Proposed =>
                    format!("proposed, not accepted: {}", survey.proposals[0].command),
                Acceptance::Several =>
                    format!("{} candidates, none accepted", survey.proposals.len()),
                Acceptance::Nothing | Acceptance::Kept =>
                    "no test command could be proposed: set verify.command".to_owned(),
            }
        )),
        Outcome::Accepted => Outcome::Note(format!(
            "{} ({}); replaces the proposal written earlier",
            would("accepted", "would accept"),
            match acceptance {
                Acceptance::Accepted(command) => command.as_str(),
                _ => "",
            }
        )),
        other => other,
    };
    Step {
        label: "verifier",
        path: CONFIG_PATH.to_owned(),
        outcome,
    }
}

/// The closing "next" block: accepting the proposal while one waits, the key while
/// none is stored, then the agent and the verifier.
fn next_steps(opts: &Options, acceptance: &Acceptance) -> Vec<(String, &'static str)> {
    let key_in_vault =
        std::fs::read_to_string(gateway::vault_file(&opts.state, opts.agent.key_env()))
            .is_ok_and(|k| !k.trim().is_empty());
    let mut next = Vec::new();
    let arg = dir_argument(&opts.dir);
    if *acceptance == Acceptance::Proposed {
        next.push((
            format!("ward init --accept-verify{arg}"),
            "accept the proposed verification boundary; nothing is verified before",
        ));
    }
    if !(opts.key_in_env || key_in_vault) {
        next.push((
            format!("ward vault set {}", opts.agent.key_env()),
            "the model key, kept on the host; the proxy injects it",
        ));
    }
    next.push((
        format!("ward {}{arg}", opts.agent.command()),
        "start the agent in the sandbox",
    ));
    next.push((
        format!("ward verify{arg}"),
        "run the protected tests in the disposable verifier",
    ));
    next
}

/// The one proposal a trusted user accepted, if any: by `--accept-verify` (which
/// refuses to pick among several or to accept nothing), or by answering yes at the
/// terminal to the one proposal shown. Nothing is asked when the config is already
/// the user's own, when there is no terminal, or on a dry run.
fn accepted_proposal<'a>(
    opts: &Options,
    survey: &'a Survey,
    awaiting: bool,
) -> Result<Option<&'a Proposal>> {
    if !awaiting {
        return Ok(None);
    }
    if matches!(opts.accept, Accept::Flag) {
        return match survey.proposals.as_slice() {
            [one] => Ok(Some(one)),
            [] => Err(Error::Project(format!(
                "--accept-verify: no verification command can be proposed from {}'s files ({}); name it in {CONFIG_PATH}",
                opts.dir.display(),
                survey.declined.join("; ")
            ))),
            several => Err(Error::Project(format!(
                "--accept-verify: several verification commands match ({}); uncomment the one to run in {CONFIG_PATH}",
                several
                    .iter()
                    .map(|p| format!("`{}`", p.command))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        };
    }
    if let (Accept::Ask(ask), [one], false) =
        (opts.accept, survey.proposals.as_slice(), opts.dry_run)
    {
        print!("{}", survey.render());
        println!();
        return Ok(ask(ACCEPT_PROMPT).then_some(one));
    }
    Ok(None)
}

/// Read the question's answer from the terminal: `y` or `yes`, case-insensitively,
/// means yes; anything else, or no line at all, means no.
pub fn ask_on_terminal(prompt: &str) -> bool {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Whether a YAML text has an active (uncommented) `command:` key.
fn has_active_command(text: &str) -> bool {
    text.lines()
        .any(|line| line.trim_start().starts_with("command:"))
}

/// Whether the boundary at `path` is still waiting for acceptance: absent, or
/// `ward init`'s own marked proposal with its command still commented out. Any other
/// node — the user's file, a symlink, something unreadable — is not ours to replace.
fn awaiting_acceptance(path: &Path) -> bool {
    match path.symlink_metadata() {
        Err(_) => true,
        Ok(meta) if !meta.is_file() => false,
        Ok(_) => std::fs::read_to_string(path)
            .is_ok_and(|text| text.contains(PROPOSED_MARKER) && !has_active_command(&text)),
    }
}

/// Write the boundary file at `path`: created when absent ([`write_new`]), replaced
/// when `accept` and it is `ward init`'s own unaccepted proposal
/// ([`replace_proposed`]), otherwise left as the user's.
fn write_boundary(path: &Path, content: &str, accept: bool, dry: bool) -> Result<Outcome> {
    if accept && path.symlink_metadata().is_ok() {
        return replace_proposed(path, content, dry);
    }
    write_new(path, content, dry)
}

/// Replace the file at `path` with `content` when, read through the very fd that is
/// then written, it is `ward init`'s marked proposal with no active command; `Kept`
/// otherwise. The same open-once discipline as [`ignore_sessions`]: `O_NOFOLLOW`
/// refuses a symlink, `O_NONBLOCK` and the regular-file check refuse a FIFO, the
/// link count refuses a hard link to some other file.
fn replace_proposed(path: &Path, content: &str, dry: bool) -> Result<Outcome> {
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(Error::Project(format!(
                "{}: refusing to write through a symlink",
                path.display()
            )));
        }
        Err(e) => return Err(io(path, e)),
    };
    let meta = file.metadata().map_err(|e| io(path, e))?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(Error::Project(format!(
            "{}: refusing to read or write a non-regular or hard-linked file",
            path.display()
        )));
    }
    let mut existing = String::new();
    file.read_to_string(&mut existing)
        .map_err(|e| io(path, e))?;
    if !existing.contains(PROPOSED_MARKER) || has_active_command(&existing) {
        return Ok(Outcome::Kept);
    }
    if dry {
        return Ok(Outcome::Accepted);
    }
    file.set_len(0).map_err(|e| io(path, e))?;
    file.seek(SeekFrom::Start(0)).map_err(|e| io(path, e))?;
    file.write_all(content.as_bytes())
        .map_err(|e| io(path, e))?;
    Ok(Outcome::Accepted)
}

/// The directory as it must be repeated on the next commands: nothing for `.`.
fn dir_argument(dir: &Path) -> String {
    if dir == Path::new(".") {
        String::new()
    } else {
        format!(" {}", dir.display())
    }
}

/// Open `dir` as a verified, non-symlink real directory, creating it first if it is
/// absent (its own parent must already exist — every caller here is one level under
/// an already-created, canonicalized directory). Returns a directory fd so the caller
/// can create a leaf beneath *that exact directory instance* via `openat`: unlike a
/// pathname, an fd-relative open resolves against the fd's inode, not whatever name
/// currently points there, so it stays correct even if `dir` is renamed away and
/// replaced with a symlink immediately after this call returns.
///
/// `O_DIRECTORY` (with `O_NOFOLLOW`) is what makes the open itself the whole check:
/// success guarantees a real directory, so no follow-up `fstat` is needed, and a
/// symlink or any other non-directory node (`ELOOP`/`ENOTDIR`) is refused uniformly.
/// Critically, `O_DIRECTORY` is also what keeps this safe against a pre-planted FIFO
/// — a plain `O_RDONLY` open with no `O_DIRECTORY` would instead block indefinitely
/// waiting for a writer that will never come, turning `ward init` into a hang.
fn open_real_dir(dir: &Path) -> Result<rustix::fd::OwnedFd> {
    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io(dir, e)),
    }
    rustix::fs::open(
        dir,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| {
        if matches!(e, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
            Error::Project(format!(
                "{}: refusing to use a symlink or non-directory as a directory",
                dir.display()
            ))
        } else {
            io(dir, e.into())
        }
    })
}

/// Write `content` to `path` unless the file exists; `dry` only reports.
///
/// A cloned project directory is untrusted content, not just an unwritten disk: it can
/// ship a dangling symlink at one of these paths, and `Path::exists` follows symlinks
/// and reports `false` for a dangling one. `symlink_metadata` sees the link itself, so
/// any pre-existing node here — dangling or not — counts as present and is left alone.
/// The leaf is then created beneath a freshly opened, verified parent directory fd
/// (`open_real_dir`) with `O_EXCL | O_NOFOLLOW`, so neither the parent nor the leaf
/// can be redirected through a symlink planted at any point up to that single call.
fn write_new(path: &Path, content: &str, dry: bool) -> Result<Outcome> {
    if path.symlink_metadata().is_ok() {
        return Ok(Outcome::Kept);
    }
    if dry {
        return Ok(Outcome::Written);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let leaf = path
        .file_name()
        .ok_or_else(|| Error::Project(format!("{}: not a file path", path.display())))?;
    let dir_fd = open_real_dir(parent)?;
    let file_fd = match rustix::fs::openat(
        &dir_fd,
        leaf,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o666),
    ) {
        Ok(fd) => fd,
        Err(e) if e == rustix::io::Errno::EXIST => return Ok(Outcome::Kept),
        Err(e) => return Err(io(path, e.into())),
    };
    let mut file: std::fs::File = file_fd.into();
    file.write_all(content.as_bytes())
        .map_err(|e| io(path, e))?;
    Ok(Outcome::Written)
}

/// The path the session state would take inside a project, kept out of git.
const SESSIONS_IGNORE: &str = ".ward/sessions/";

/// Append the session-state line to `.gitignore` in a git repository that does not
/// ignore it yet. Appending is the one edit `ward init` makes to a user's file: the
/// line is additive and marked, and a repository that commits session state leaks it.
///
/// Unlike the template files above, `.gitignore` is meant to be read and appended to
/// when it already exists, so it can't just refuse any pre-existing node the way
/// `write_new` does — only a symlink, via `O_NOFOLLOW`. That refusal has to be the
/// open itself, not a check before it: a `.gitignore` that exists is opened exactly
/// once here, and every read and write goes through that same fd, so there is no
/// separate pathname lookup later in the function for a concurrent rename or
/// replacement to target.
///
/// `O_NOFOLLOW` alone only refuses a symlink; it says nothing about what kind of
/// non-symlink node was opened. `O_NONBLOCK` (a no-op once we know it's a plain
/// regular file) keeps a pre-planted FIFO from turning the read below into an
/// indefinite block, and the `is_file`/`nlink` check right after the open refuses a
/// FIFO outright and refuses a hard link to some other same-user file — opening one
/// succeeds like any regular file, so only that check stops its target from being
/// silently rewritten.
fn ignore_sessions(dir: &Path, dry: bool) -> Result<Outcome> {
    if !dir.join(".git").exists() {
        return Ok(Outcome::Skipped("not a git repository".to_owned()));
    }
    let path = dir.join(".gitignore");
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path);
    let (existing_file, existing) = match opened {
        Ok(mut f) => {
            let meta = f.metadata().map_err(|e| io(&path, e))?;
            if !meta.is_file() || meta.nlink() != 1 {
                return Err(Error::Project(format!(
                    "{}: refusing to read or write a non-regular or hard-linked file",
                    path.display()
                )));
            }
            let mut text = String::new();
            f.read_to_string(&mut text).map_err(|e| io(&path, e))?;
            (Some(f), text)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, String::new()),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(Error::Project(format!(
                "{}: refusing to write through a symlink",
                path.display()
            )));
        }
        Err(e) => return Err(io(&path, e)),
    };
    if existing.lines().any(ignores_sessions) {
        return Ok(Outcome::Kept);
    }
    let outcome = Outcome::Note(format!(
        "{SESSIONS_IGNORE} {}",
        if dry { "would be added" } else { "added" }
    ));
    if dry {
        return Ok(outcome);
    }
    let mut text = existing;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    let _ = writeln!(text, "# WardOS session state, never committed (ward init)");
    let _ = writeln!(text, "{SESSIONS_IGNORE}");
    match existing_file {
        // The line above always makes `text` strictly longer than what was read, so
        // overwriting from the start needs no truncate.
        Some(mut f) => {
            f.seek(SeekFrom::Start(0)).map_err(|e| io(&path, e))?;
            f.write_all(text.as_bytes()).map_err(|e| io(&path, e))?;
        }
        // Didn't exist when opened above: create it fresh with the same O_EXCL
        // guarantee `write_new` uses, refusing a symlink planted in the meantime too.
        None => {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .and_then(|mut f| f.write_all(text.as_bytes()))
                .map_err(|e| io(&path, e))?;
        }
    }
    Ok(outcome)
}

/// Whether one `.gitignore` line already covers the session state (`.ward/sessions`,
/// with or without slashes, or all of `.ward`).
fn ignores_sessions(line: &str) -> bool {
    let pattern = line
        .trim()
        .trim_start_matches('/')
        .trim_end_matches('/')
        .trim_end_matches("/**");
    matches!(pattern, ".ward/sessions" | ".ward")
}

/// The YAML list items for a proposal's protected inputs, each with its evidence as
/// a trailing comment, at `indent`.
fn protected_items(inputs: &[Input], indent: &str) -> String {
    let width = inputs.iter().map(|i| i.path.len()).max().unwrap_or(0);
    let mut text = String::new();
    for input in inputs {
        let _ = writeln!(text, "{indent}- {:<width$}  # {}", input.path, input.why);
    }
    text
}

/// A comment block naming a proposal's read-only inputs and gaps, for the user to
/// see beside the command; the verifier reads these files from the candidate as it
/// is and never rewrites them, and the prepared-environment phase keys on them.
fn inputs_comment(proposal: &Proposal) -> String {
    let mut text = String::new();
    if !proposal.read_only.is_empty() {
        let _ = writeln!(
            text,
            "  # Read-only inputs, read by the verifier and never rewritten:"
        );
        for input in &proposal.read_only {
            let _ = writeln!(text, "  #   {}  ({})", input.path, input.why);
        }
    }
    for gap in &proposal.gaps {
        let _ = writeln!(text, "  # Gap: {gap}");
    }
    text
}

/// `.tamperward/config.yml`, the verifier's view: the tests only it may judge, and
/// the command it runs. Both come from the project's own files
/// ([`Survey`]), with the evidence beside each, and are active only
/// for the proposal a trusted user `accepted`. Otherwise the proposals are written
/// commented out under [`PROPOSED_MARKER`], so `ward verify` says exactly what is
/// missing, `ward ready` shows the proposal, and a later `ward init --accept-verify`
/// can replace this file, and only this file, with the accepted boundary.
fn verifier_config(survey: &Survey, accepted: Option<&Proposal>) -> String {
    let mut text = String::from(
        "# .tamperward/config.yml — what `ward verify` runs (written by `ward init`).\n\
         #\n\
         # The verifier takes this file and every protected path from the session's entry\n\
         # snapshot, so an agent that edits a test listed here only changes what the verifier\n\
         # restores. The command runs offline, in a disposable sandbox, at the root of the tree.\n\
         # Reference: docs/tamperward-integration.md §5.\n\
         protected:\n",
    );
    match (accepted, survey.proposals.as_slice()) {
        (Some(p), _) => {
            if p.protected.is_empty() {
                text.push_str("  tests: []\n");
            } else {
                text.push_str("  tests:\n");
                text.push_str(&protected_items(&p.protected, "    "));
            }
            let _ = writeln!(
                text,
                "verify:\n  # Accepted from {} (ward init --accept-verify).\n  command: {}",
                p.evidence.join(", "),
                p.command
            );
            text.push_str(&inputs_comment(p));
        }
        (None, []) => {
            text.push_str("  tests: []\n");
            for why in &survey.declined {
                let _ = writeln!(text, "  # Cannot propose: {why}");
            }
            text.push_str(
                "verify:\n  # No test command could be proposed from this project's files: name it.\n  \
                 # command: <the command that runs this project's tests>\n",
            );
        }
        (None, [only]) => {
            text.push_str("  tests: []\n");
            let _ = writeln!(text, "  {PROPOSED_MARKER}");
            text.push_str(&protected_items(&only.protected, "  #   "));
            let _ = writeln!(
                text,
                "verify:\n  {PROPOSED_MARKER} From {}.\n  \
                 # `ward init --accept-verify` writes it, or uncomment it to accept by hand.\n  \
                 # command: {}",
                only.evidence.join(", "),
                only.command
            );
            text.push_str(&inputs_comment(only));
        }
        (None, several) => {
            text.push_str("  tests: []\n");
            let _ = writeln!(
                text,
                "verify:\n  {PROPOSED_MARKER} Several test commands match this project: uncomment the one to run."
            );
            for p in several {
                let _ = writeln!(
                    text,
                    "  # From {}:\n  # command: {}",
                    p.evidence.join(", "),
                    p.command
                );
                text.push_str(&protected_items(&p.protected, "  #   protect: "));
            }
        }
    }
    text.push_str("  budget_secs: 600\n");
    text
}

/// A TamperWard `tests:` pattern for one protected input: a directory covers
/// everything under it.
fn tamperward_pattern(input: &Input) -> String {
    if input.path.ends_with('/') {
        format!("'{}**'", input.path)
    } else {
        format!("'{}'", input.path)
    }
}

/// TamperWard's own policy, written only when `tamperward` is not installed: enough
/// for `tamperward check` to guard the tests once it is, and a pointer to the full
/// wiring. `tamperward init` keeps this file when it runs later. The tests and the
/// verify block are active only for the `accepted` proposal, as in
/// [`verifier_config`].
fn tamperward_policy(survey: &Survey, accepted: Option<&Proposal>) -> String {
    let mut text = String::from(
        "# .tamperward.yml — TamperWard policy (written by `ward init`; TamperWard was not\n\
         # installed). Once it is (`npx tamperward init`, Node.js 20.19 or later; the WardOS\n\
         # image ships it), run `tamperward init`: it keeps this file and adds the Claude Code\n\
         # hooks, a pre-commit hook and a CI workflow.\n\
         version: 1\n\
         protected:\n",
    );
    let patterns = |p: &Proposal| {
        p.protected
            .iter()
            .map(tamperward_pattern)
            .collect::<Vec<_>>()
            .join(", ")
    };
    match (accepted, survey.proposals.as_slice()) {
        (Some(p), _) => {
            let _ = writeln!(
                text,
                "  tests: [{}]\nverify:\n  command: {}\n  budget: 600",
                patterns(p),
                p.command
            );
        }
        (None, []) => {
            text.push_str(
                "  tests: []\n# verify:\n#   command: <the command that runs this project's tests>\n#   budget: 600\n",
            );
        }
        (None, [only]) => {
            let _ = writeln!(
                text,
                "  tests: []\n{PROPOSED_MARKER}\n#   tests: [{}]\n# verify:\n#   command: {}\n#   budget: 600",
                patterns(only),
                only.command
            );
        }
        (None, several) => {
            let _ = writeln!(
                text,
                "  tests: []\n{PROPOSED_MARKER} Several test commands match this project: keep one.\n# verify:"
            );
            for p in several {
                let _ = writeln!(text, "#   command: {}", p.command);
            }
            text.push_str("#   budget: 600\n");
        }
    }
    text
}

/// The TamperWard step: run `tamperward init --cwd <dir>` and show its output, or
/// write the minimal policy and say how to get the rest.
fn tamperward_step(
    dir: &Path,
    survey: &Survey,
    accepted: Option<&Proposal>,
    opts: &Options,
) -> Result<Step> {
    let path = ".tamperward.yml".to_owned();
    if opts.no_tamperward {
        return Ok(Step {
            label: "tamperward",
            path,
            outcome: Outcome::Skipped("--no-tamperward".to_owned()),
        });
    }
    let Some(bin) = &opts.tamperward else {
        let would = if opts.dry_run { "would be " } else { "" };
        let outcome = match write_boundary(
            &dir.join(&path),
            &tamperward_policy(survey, accepted),
            accepted.is_some(),
            opts.dry_run,
        )? {
            Outcome::Written => Outcome::Note(format!(
                "tamperward not installed; minimal policy {would}written. `npx tamperward init` adds the hooks, pre-commit and CI"
            )),
            Outcome::Accepted => Outcome::Note(format!(
                "tamperward not installed; minimal policy {would}accepted, replacing the proposal written earlier"
            )),
            other => other,
        };
        return Ok(Step {
            label: "tamperward",
            path,
            outcome,
        });
    };
    let mut command = Command::new(bin);
    command.arg("init").arg("--cwd").arg(dir);
    if opts.dry_run {
        command.arg("--dry-run");
    }
    println!("tamperward init --cwd {}", dir.display());
    let status = command.status().map_err(|e| io(bin, e))?;
    println!();
    let outcome = if status.success() {
        Outcome::Note("tamperward init ran (its report is above)".to_owned())
    } else {
        Outcome::Note(format!(
            "tamperward init exited with {}; see its report above",
            status.code().unwrap_or(-1)
        ))
    };
    Ok(Step {
        label: "tamperward",
        path,
        outcome,
    })
}

/// The first `tamperward` on a PATH-style list of directories.
#[must_use]
pub fn find_tamperward(path_var: &str) -> Option<PathBuf> {
    path_var
        .split(':')
        .filter(|d| !d.is_empty())
        .map(|d| Path::new(d).join("tamperward"))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn options(dir: &Path, state: &Path) -> Options {
        Options {
            dir: dir.to_path_buf(),
            agent: Agent::Claude,
            tamperward: None,
            no_tamperward: false,
            dry_run: false,
            state: state.to_path_buf(),
            key_in_env: false,
            accept: Accept::Nobody,
        }
    }

    fn accepting(dir: &Path, state: &Path) -> Options {
        let mut opts = options(dir, state);
        opts.accept = Accept::Flag;
        opts
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    fn cargo_project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"app\"\n").unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "version = 4\n").unwrap();
        std::fs::create_dir(dir.path().join("tests")).unwrap();
        dir
    }

    #[test]
    fn writes_the_template_the_accepted_verifier_config_and_the_minimal_policy() {
        let dir = cargo_project();
        let state = tempfile::tempdir().unwrap();
        let report = run(&accepting(dir.path(), state.path())).unwrap();
        assert_eq!(
            read(&dir.path().join(".ward/policy.yaml")),
            Policy::template()
        );
        let verifier = read(&dir.path().join(".tamperward/config.yml"));
        assert!(
            verifier.contains("\n  command: cargo test --locked\n"),
            "{verifier}"
        );
        assert!(verifier.contains("- tests/"), "{verifier}");
        assert!(verifier.contains("Cargo.lock  (lockfile"), "{verifier}");
        let config = ward_daemon::verify::Config::parse(&verifier).unwrap();
        assert_eq!(config.protected.tests, ["tests/"]);
        let policy = read(&dir.path().join(".tamperward.yml"));
        assert!(policy.contains("tests: ['tests/**']"), "{policy}");
        assert!(
            policy.contains("\n  command: cargo test --locked\n"),
            "{policy}"
        );
        let text = report.render();
        assert!(text.contains(".ward/policy.yaml"), "{text}");
        assert!(text.contains("npx tamperward init"), "{text}");
        assert!(text.contains("accepted: `cargo test --locked`"), "{text}");
        assert!(!text.contains("ward init --accept-verify"), "{text}");
    }

    #[test]
    fn without_acceptance_the_boundary_is_written_commented_out_and_the_report_says_so() {
        let dir = cargo_project();
        let state = tempfile::tempdir().unwrap();
        let text = run(&options(dir.path(), state.path())).unwrap().render();
        let verifier = read(&dir.path().join(".tamperward/config.yml"));
        assert!(verifier.contains(PROPOSED_MARKER), "{verifier}");
        assert!(
            verifier.contains("# command: cargo test --locked"),
            "{verifier}"
        );
        assert!(verifier.contains("#   - tests/"), "{verifier}");
        assert!(!has_active_command(&verifier), "{verifier}");
        let err = ward_daemon::verify::Config::parse(&verifier)
            .unwrap_err()
            .to_string();
        assert!(err.contains("verify.command is empty"), "{err}");
        let policy = read(&dir.path().join(".tamperward.yml"));
        assert!(policy.contains("  tests: []\n"), "{policy}");
        assert!(
            policy.contains("#   command: cargo test --locked"),
            "{policy}"
        );
        assert!(!has_active_command(&policy), "{policy}");
        assert!(
            text.contains("proposed, not accepted: cargo test --locked"),
            "{text}"
        );
        assert!(text.contains("Proposed verification boundary"), "{text}");
        assert!(text.contains("tests/"), "{text}");
        assert!(text.contains("not accepted:"), "{text}");
        assert!(text.contains("ward init --accept-verify"), "{text}");
        let ready = ward_daemon::readiness::check(dir.path());
        assert_eq!(
            ready.verdict(),
            ward_daemon::readiness::Verdict::SetupRequired
        );
    }

    #[test]
    fn accept_verify_replaces_the_unaccepted_proposal_but_never_the_users_file() {
        let dir = cargo_project();
        let state = tempfile::tempdir().unwrap();
        run(&options(dir.path(), state.path())).unwrap();
        let report = run(&accepting(dir.path(), state.path())).unwrap();
        let verifier = read(&dir.path().join(".tamperward/config.yml"));
        assert!(
            verifier.contains("\n  command: cargo test --locked\n"),
            "{verifier}"
        );
        assert!(!verifier.contains(PROPOSED_MARKER), "{verifier}");
        let policy = read(&dir.path().join(".tamperward.yml"));
        assert!(
            policy.contains("\n  command: cargo test --locked\n"),
            "{policy}"
        );
        let text = report.render();
        assert!(
            text.contains("replaces the proposal written earlier"),
            "{text}"
        );
        assert_eq!(
            report.acceptance,
            Acceptance::Accepted("cargo test --locked".to_owned())
        );
        let ready = ward_daemon::readiness::check(dir.path());
        assert!(ready.survey.is_none(), "{ready:?}");

        let mine = "protected:\n  tests: []\nverify:\n  budget_secs: 5\n";
        std::fs::write(dir.path().join(".tamperward/config.yml"), mine).unwrap();
        let report = run(&accepting(dir.path(), state.path())).unwrap();
        assert_eq!(read(&dir.path().join(".tamperward/config.yml")), mine);
        assert_eq!(report.acceptance, Acceptance::Kept);
        assert!(
            !report.render().contains("Proposed verification"),
            "{}",
            report.render()
        );

        let by_hand = format!("{PROPOSED_MARKER}\nverify:\n  command: make check\n");
        std::fs::write(dir.path().join(".tamperward/config.yml"), &by_hand).unwrap();
        run(&accepting(dir.path(), state.path())).unwrap();
        assert_eq!(
            read(&dir.path().join(".tamperward/config.yml")),
            by_hand,
            "a proposal the user accepted by uncommenting is theirs now"
        );
    }

    #[test]
    fn accept_verify_refuses_to_pick_among_several_or_to_accept_nothing() {
        let dir = cargo_project();
        let state = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Makefile"), "test:\n\tcargo test\n").unwrap();
        let err = run(&accepting(dir.path(), state.path()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("several verification commands match"), "{err}");
        assert!(
            err.contains("`cargo test --locked`") && err.contains("`make test`"),
            "{err}"
        );
        assert!(
            !dir.path().join(".ward").exists(),
            "nothing is written on a refusal"
        );

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"build":"tsc"}}"#,
        )
        .unwrap();
        let err = run(&accepting(dir.path(), state.path()))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no verification command can be proposed"),
            "{err}"
        );
        assert!(err.contains("no scripts.test"), "{err}");
    }

    static ASKED: AtomicUsize = AtomicUsize::new(0);

    fn say_yes(prompt: &str) -> bool {
        assert!(prompt.contains("[y/N]"), "{prompt}");
        ASKED.fetch_add(1, Ordering::SeqCst);
        true
    }

    fn say_no(_: &str) -> bool {
        ASKED.fetch_add(1, Ordering::SeqCst);
        false
    }

    #[test]
    fn a_terminal_is_asked_once_and_only_a_yes_accepts() {
        let state = tempfile::tempdir().unwrap();
        let dir = cargo_project();
        let mut opts = options(dir.path(), state.path());
        opts.accept = Accept::Ask(say_no);
        let before = ASKED.load(Ordering::SeqCst);
        let report = run(&opts).unwrap();
        assert_eq!(ASKED.load(Ordering::SeqCst), before + 1);
        assert_eq!(report.acceptance, Acceptance::Proposed);
        assert!(!has_active_command(&read(
            &dir.path().join(".tamperward/config.yml")
        )));

        opts.accept = Accept::Ask(say_yes);
        let report = run(&opts).unwrap();
        assert_eq!(ASKED.load(Ordering::SeqCst), before + 2);
        assert_eq!(
            report.acceptance,
            Acceptance::Accepted("cargo test --locked".to_owned())
        );
        assert!(has_active_command(&read(
            &dir.path().join(".tamperward/config.yml")
        )));

        let report = run(&opts).unwrap();
        assert_eq!(
            ASKED.load(Ordering::SeqCst),
            before + 2,
            "an accepted project is not asked again"
        );
        assert_eq!(report.acceptance, Acceptance::Kept);

        let dir = cargo_project();
        std::fs::write(dir.path().join("Makefile"), "test:\n\tcargo test\n").unwrap();
        let mut opts = options(dir.path(), state.path());
        opts.accept = Accept::Ask(say_yes);
        let report = run(&opts).unwrap();
        assert_eq!(
            ASKED.load(Ordering::SeqCst),
            before + 2,
            "several candidates are never a question"
        );
        assert_eq!(report.acceptance, Acceptance::Several);

        let dir = cargo_project();
        let mut opts = options(dir.path(), state.path());
        opts.accept = Accept::Ask(say_yes);
        opts.dry_run = true;
        run(&opts).unwrap();
        assert_eq!(
            ASKED.load(Ordering::SeqCst),
            before + 2,
            "a dry run asks nothing"
        );
    }

    #[test]
    fn a_dry_run_acceptance_writes_nothing_and_says_what_it_would_do() {
        let dir = cargo_project();
        let state = tempfile::tempdir().unwrap();
        let mut opts = accepting(dir.path(), state.path());
        opts.dry_run = true;
        let text = run(&opts).unwrap().render();
        assert!(!dir.path().join(".tamperward").exists());
        assert!(
            text.contains("would write (accepted: cargo test --locked)"),
            "{text}"
        );
        assert!(text.contains("would be written"), "{text}");

        opts.dry_run = false;
        opts.accept = Accept::Nobody;
        run(&opts).unwrap();
        opts.dry_run = true;
        opts.accept = Accept::Flag;
        let text = run(&opts).unwrap().render();
        assert!(
            text.contains("would accept (cargo test --locked)"),
            "{text}"
        );
        assert!(!has_active_command(&read(
            &dir.path().join(".tamperward/config.yml")
        )));
    }

    #[test]
    fn a_symlinked_proposal_is_left_alone_even_when_accepting() {
        let dir = cargo_project();
        let state = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("config.yml");
        std::fs::write(
            &target,
            format!("{PROPOSED_MARKER}\nverify:\n  # command: x\n"),
        )
        .unwrap();
        std::fs::create_dir(dir.path().join(".tamperward")).unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(".tamperward/config.yml")).unwrap();
        let report = run(&accepting(dir.path(), state.path())).unwrap();
        assert_eq!(report.acceptance, Acceptance::Kept);
        assert!(
            read(&target).contains("# command: x"),
            "the target is never rewritten"
        );
    }

    #[test]
    fn is_idempotent_and_never_overwrites_a_file_the_user_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        run(&options(dir.path(), state.path())).unwrap();
        let mine = "network: offline\n";
        std::fs::write(dir.path().join(".ward/policy.yaml"), mine).unwrap();
        std::fs::write(dir.path().join(".tamperward.yml"), "version: 1\n").unwrap();
        let report = run(&options(dir.path(), state.path())).unwrap();
        assert_eq!(read(&dir.path().join(".ward/policy.yaml")), mine);
        assert_eq!(read(&dir.path().join(".tamperward.yml")), "version: 1\n");
        assert!(
            report
                .steps
                .iter()
                .all(|s| s.outcome == Outcome::Kept || matches!(&s.outcome, Outcome::Skipped(_))),
            "{}",
            report.render()
        );
    }

    #[test]
    fn dry_run_writes_nothing_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        let mut opts = options(dir.path(), state.path());
        opts.dry_run = true;
        let text = run(&opts).unwrap().render();
        assert!(!dir.path().join(".ward").exists());
        assert!(!dir.path().join(".tamperward").exists());
        assert!(!dir.path().join(".tamperward.yml").exists());
        assert!(!dir.path().join(".gitignore").exists());
        assert!(text.contains("dry run"), "{text}");
        assert!(text.contains("would write"), "{text}");
        // A missing directory is not created either.
        opts.dir = dir.path().join("new");
        run(&opts).unwrap();
        assert!(!opts.dir.exists());
    }

    #[test]
    fn creates_a_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let project = dir.path().join("fresh");
        run(&options(&project, state.path())).unwrap();
        assert!(project.join(".ward/policy.yaml").is_file());
    }

    #[test]
    fn the_proposed_command_is_active_only_once_accepted_for_every_ecosystem() {
        for (file, content, command) in [
            ("Cargo.toml", "[package]\nname = \"app\"\n", "cargo test"),
            ("package.json", r#"{"scripts":{"test":"jest"}}"#, "npm test"),
            ("pyproject.toml", "[tool.pytest.ini_options]\n", "pytest"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(file), content).unwrap();
            run(&options(dir.path(), state.path())).unwrap();
            let verifier = read(&dir.path().join(".tamperward/config.yml"));
            assert!(
                verifier.contains(&format!("# command: {command}")),
                "{file}: {verifier}"
            );
            assert!(
                ward_daemon::verify::Config::parse(&verifier).is_err(),
                "{file}: not accepted, so the verifier has no command"
            );
            run(&accepting(dir.path(), state.path())).unwrap();
            let verifier = read(&dir.path().join(".tamperward/config.yml"));
            assert!(
                verifier.contains(&format!("\n  command: {command}\n")),
                "{file}: {verifier}"
            );
            assert!(
                ward_daemon::verify::Config::parse(&verifier).is_ok(),
                "{file}: the verifier parses what init wrote"
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let text = run(&options(dir.path(), state.path())).unwrap().render();
        let verifier = read(&dir.path().join(".tamperward/config.yml"));
        assert!(verifier.contains("# command: <the command"), "{verifier}");
        assert!(
            verifier.contains("# Cannot propose: no manifest"),
            "{verifier}"
        );
        assert!(text.contains("no test command could be proposed"), "{text}");
        assert!(text.contains("cannot propose: no manifest"), "{text}");
        let err = ward_daemon::verify::Config::parse(&verifier)
            .unwrap_err()
            .to_string();
        assert!(err.contains("verify.command is empty"), "{err}");
    }

    #[test]
    fn proposes_the_verify_command_from_the_project_files_and_shows_why() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"test":"vitest run"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n",
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("__tests__")).unwrap();
        let text = run(&options(dir.path(), state.path())).unwrap().render();
        let verifier = read(&dir.path().join(".tamperward/config.yml"));
        assert!(verifier.contains("  # command: pnpm test\n"), "{verifier}");
        assert!(verifier.contains("#   - __tests__/"), "{verifier}");
        assert!(verifier.contains("pnpm-lock.yaml  (lockfile"), "{verifier}");
        let policy = read(&dir.path().join(".tamperward.yml"));
        assert!(policy.contains("#   command: pnpm test"), "{policy}");
        assert!(policy.contains("#   tests: ['__tests__/**']"), "{policy}");
        assert!(text.contains("pnpm test"), "{text}");
        assert!(text.contains("package.json scripts.test"), "{text}");
        assert!(text.contains("pnpm-lock.yaml"), "{text}");
        assert!(text.contains("__tests__/"), "{text}");
    }

    #[test]
    fn several_candidates_are_all_shown_and_none_is_chosen_for_the_user() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\n").unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "version = 4\n").unwrap();
        std::fs::write(dir.path().join("Makefile"), "test:\n\tcargo test\n").unwrap();
        let text = run(&options(dir.path(), state.path())).unwrap().render();
        let verifier = read(&dir.path().join(".tamperward/config.yml"));
        assert!(
            verifier.contains("# command: cargo test --locked"),
            "{verifier}"
        );
        assert!(verifier.contains("# command: make test"), "{verifier}");
        let err = ward_daemon::verify::Config::parse(&verifier)
            .unwrap_err()
            .to_string();
        assert!(err.contains("verify.command is empty"), "{err}");
        let policy = read(&dir.path().join(".tamperward.yml"));
        assert!(!policy.contains("\nverify:"), "{policy}");
        assert!(policy.contains("#   command: make test"), "{policy}");
        assert!(text.contains("cargo test --locked"), "{text}");
        assert!(text.contains("test target in Makefile"), "{text}");
        assert!(text.contains("uncomment one"), "{text}");
    }

    #[test]
    fn a_package_json_without_a_test_script_is_declined_with_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"build":"tsc"}}"#,
        )
        .unwrap();
        let text = run(&options(dir.path(), state.path())).unwrap().render();
        let verifier = read(&dir.path().join(".tamperward/config.yml"));
        assert!(
            verifier.contains("# Cannot propose: package.json has no scripts.test"),
            "{verifier}"
        );
        assert!(
            !verifier.contains("npm test"),
            "no default guess: {verifier}"
        );
        assert!(
            text.contains("cannot propose: package.json has no scripts.test"),
            "{text}"
        );
        assert!(text.contains("no test command could be proposed"), "{text}");
    }

    #[test]
    fn ignores_the_session_state_in_a_git_repository_once() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let report = run(&options(dir.path(), state.path())).unwrap();
        assert!(
            !dir.path().join(".gitignore").exists(),
            "no repository, no .gitignore"
        );
        assert!(report.render().contains("not a git repository"));

        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".gitignore"), "target").unwrap();
        run(&options(dir.path(), state.path())).unwrap();
        let ignore = read(&dir.path().join(".gitignore"));
        assert_eq!(
            ignore,
            "target\n# WardOS session state, never committed (ward init)\n.ward/sessions/\n"
        );
        run(&options(dir.path(), state.path())).unwrap();
        assert_eq!(read(&dir.path().join(".gitignore")), ignore, "added once");

        std::fs::write(dir.path().join(".gitignore"), "/.ward/\n").unwrap();
        run(&options(dir.path(), state.path())).unwrap();
        assert_eq!(
            read(&dir.path().join(".gitignore")),
            "/.ward/\n",
            "already covered"
        );
    }

    #[test]
    fn refuses_to_write_a_template_through_a_pre_planted_symlink() {
        // A cloned project can ship a dangling symlink at one of `write_new`'s paths.
        // `Path::exists` would report that as absent and `std::fs::write` would follow
        // it, so this must never create or touch whatever the link points at.
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("clobbered");
        std::fs::create_dir_all(dir.path().join(".ward")).unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(".ward/policy.yaml")).unwrap();

        let report = run(&options(dir.path(), state.path())).unwrap();
        assert!(!target.exists(), "the symlink's target must not be created");
        assert!(
            dir.path()
                .join(".ward/policy.yaml")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "the planted symlink itself is left untouched"
        );
        let policy_step = report
            .steps
            .iter()
            .find(|s| s.path == ".ward/policy.yaml")
            .unwrap();
        assert_eq!(policy_step.outcome, Outcome::Kept);
    }

    #[test]
    fn refuses_to_write_through_a_symlinked_parent_directory() {
        // A hostile project can ship `.ward` itself as a symlink to a real, existing
        // directory outside the project — with no `policy.yaml` inside it yet. The
        // leaf-level `O_EXCL` in `write_new` can't catch this: it only ever governs
        // the final path component, and `create_dir_all` would otherwise treat an
        // existing symlink-to-directory as "already there" and write straight through
        // it. `ensure_real_dir` must refuse it before any leaf write is attempted.
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join(".ward")).unwrap();

        let Err(err) = run(&options(dir.path(), state.path())) else {
            panic!("expected the symlinked .ward directory to be refused");
        };
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(
            !outside.path().join("policy.yaml").exists(),
            "must never write into the symlink's target directory"
        );
    }

    #[test]
    fn refuses_a_fifo_planted_at_the_parent_directory_path() {
        // `open_real_dir` opens `dir` with plain O_RDONLY before the O_DIRECTORY fix,
        // opening a FIFO with no writer blocks forever — turning a hostile project
        // into a hang instead of a clean refusal. This must return an error, not
        // block; if it regressed to blocking this test itself would hang.
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.path().join(".ward"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();

        let Err(err) = run(&options(dir.path(), state.path())) else {
            panic!("expected the FIFO at .ward to be refused");
        };
        assert!(err.to_string().contains("non-directory"), "{err}");
    }

    #[test]
    fn the_leaf_lands_in_the_validated_directory_even_if_its_name_is_later_replaced() {
        // Simulates exactly the race the second review round flagged: after
        // `open_real_dir` validates `.ward` and returns its fd, an attacker renames
        // that real directory aside and puts a symlink in its place before the leaf
        // is created. Because `openat` resolves against the held fd's inode, not
        // whatever the name currently points at, the leaf must still land inside the
        // original directory — proving the fd-relative design closes the window a
        // second pathname-based check could not.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join(".ward");
        std::fs::create_dir(&real).unwrap();
        let dir_fd = open_real_dir(&real).unwrap();

        let moved_aside = dir.path().join("moved-aside");
        std::fs::rename(&real, &moved_aside).unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), &real).unwrap();

        let file_fd = rustix::fs::openat(
            &dir_fd,
            "leaf.txt",
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o644),
        )
        .unwrap();
        drop(std::fs::File::from(file_fd));

        assert!(
            moved_aside.join("leaf.txt").exists(),
            "the leaf must land in the directory open_real_dir actually validated"
        );
        assert!(
            !outside.path().join("leaf.txt").exists(),
            "never in the replacement symlink's target"
        );
    }

    #[test]
    fn refuses_to_append_the_gitignore_line_through_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("clobbered");
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(".gitignore")).unwrap();

        let Err(err) = run(&options(dir.path(), state.path())) else {
            panic!("expected the planted symlink to be refused");
        };
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(!target.exists(), "the symlink's target must not be created");
    }

    #[test]
    fn refuses_a_fifo_planted_at_the_gitignore_path() {
        // O_NOFOLLOW alone says nothing about the node's type: opening a FIFO
        // read/write succeeds even without O_NONBLOCK (a Linux-specific exception
        // for O_RDWR on a FIFO), and the subsequent blocking read then waits forever
        // for data that will never arrive. This must return an error quickly, never
        // hang — a regression here would hang this test.
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.path().join(".gitignore"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();

        let Err(err) = run(&options(dir.path(), state.path())) else {
            panic!("expected the FIFO at .gitignore to be refused");
        };
        assert!(err.to_string().contains("non-regular"), "{err}");
    }

    #[test]
    fn refuses_a_hard_linked_gitignore() {
        // O_NOFOLLOW refuses a symlink but not a hard link: opening one succeeds
        // like any other regular file, so only the st_nlink check stops the
        // aliased file from being silently rewritten with .gitignore's contents.
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        let aliased = dir.path().join("aliased-secret");
        std::fs::write(&aliased, "do not touch").unwrap();
        std::fs::hard_link(&aliased, dir.path().join(".gitignore")).unwrap();

        let Err(err) = run(&options(dir.path(), state.path())) else {
            panic!("expected the hard-linked .gitignore to be refused");
        };
        assert!(err.to_string().contains("hard-linked"), "{err}");
        assert_eq!(
            std::fs::read_to_string(&aliased).unwrap(),
            "do not touch",
            "the aliased file must never be truncated or rewritten"
        );
    }

    #[test]
    fn runs_tamperward_init_when_it_is_installed_and_writes_no_policy_of_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let log = bin.path().join("log");
        let mock = bin.path().join("tamperward");
        std::fs::write(
            &mock,
            format!(
                "#!/bin/sh\necho \"$@\" >>{}\necho 'tamperward init: 3 changes'\n",
                log.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&mock, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path_var = format!("{}:/nonexistent", bin.path().display());
        assert_eq!(find_tamperward(&path_var).as_deref(), Some(mock.as_path()));
        assert_eq!(find_tamperward("/nonexistent"), None);

        let mut opts = options(dir.path(), state.path());
        opts.tamperward = Some(mock.clone());
        let text = run(&opts).unwrap().render();
        let canonical = dir.path().canonicalize().unwrap();
        assert_eq!(read(&log), format!("init --cwd {}\n", canonical.display()));
        assert!(
            !dir.path().join(".tamperward.yml").exists(),
            "tamperward writes its own"
        );
        assert!(text.contains("tamperward init ran"), "{text}");

        opts.dry_run = true;
        run(&opts).unwrap();
        assert!(read(&log).ends_with("--dry-run\n"), "{}", read(&log));

        opts.no_tamperward = true;
        std::fs::remove_file(&log).unwrap();
        let text = run(&opts).unwrap().render();
        assert!(!log.exists(), "--no-tamperward does not run it");
        assert!(text.contains("--no-tamperward"), "{text}");
    }

    #[test]
    fn the_next_block_names_the_key_only_until_one_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let text = run(&options(dir.path(), state.path())).unwrap().render();
        assert!(text.contains("ward vault set ANTHROPIC_API_KEY"), "{text}");
        assert!(text.contains("ward claude "), "{text}");
        assert!(text.contains("ward verify "), "{text}");

        let vault = state.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        std::fs::write(vault.join("ANTHROPIC_API_KEY"), "sk-x\n").unwrap();
        let text = run(&options(dir.path(), state.path())).unwrap().render();
        assert!(!text.contains("ward vault set"), "{text}");

        let mut opts = options(dir.path(), state.path());
        opts.agent = Agent::Codex;
        let text = run(&opts).unwrap().render();
        assert!(text.contains("ward vault set OPENAI_API_KEY"), "{text}");
        assert!(text.contains("ward codex "), "{text}");
        opts.key_in_env = true;
        assert!(!run(&opts).unwrap().render().contains("ward vault set"));
    }

    #[test]
    fn the_current_directory_needs_no_argument_on_the_next_commands() {
        assert_eq!(dir_argument(Path::new(".")), "");
        assert_eq!(dir_argument(Path::new("app")), " app");
    }
}
