//! `ward init`: make a directory a WardOS project (ADR-0017).
//!
//! One command writes what a session needs and nothing it does not: the project
//! policy (`.ward/policy.yaml`, from [`Policy::template`]), the verifier's config
//! (`.tamperward/config.yml`, what `ward verify` reads), a `.gitignore` line for the
//! session state, and TamperWard's own wiring through `tamperward init` when it is
//! installed (a minimal `.tamperward.yml` when it is not). Every file is written only
//! when absent, so the command is idempotent and never overwrites a file the user
//! wrote; `--dry-run` reports the plan and touches nothing.

use std::fmt::Write as _;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::ValueEnum;
use ward_daemon::{Error, Result, gateway};
use ward_policy::Policy;

/// An I/O error with the path it happened at.
fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Error {
    Error::Io {
        path: path.into(),
        source,
    }
}

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

/// What `ward init` was asked to do. Everything the command reads from its
/// environment (PATH, the key variable, the state root) arrives here as a value, so
/// the tests drive it without touching the process environment.
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
}

/// The build system a directory shows, which decides the verify command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ecosystem {
    Cargo,
    Npm,
    Python,
    Unknown,
}

impl Ecosystem {
    fn detect(dir: &Path) -> Self {
        if dir.join("Cargo.toml").is_file() {
            Self::Cargo
        } else if dir.join("package.json").is_file() {
            Self::Npm
        } else if dir.join("pyproject.toml").is_file() {
            Self::Python
        } else {
            Self::Unknown
        }
    }

    const fn verify_command(self) -> Option<&'static str> {
        match self {
            Self::Cargo => Some("cargo test"),
            Self::Npm => Some("npm test"),
            Self::Python => Some("pytest"),
            Self::Unknown => None,
        }
    }
}

/// What happened to one item of the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    /// The file was written (or, dry: would be).
    Written,
    /// The file was already there and left as it is.
    Kept,
    /// Nothing to do, with the reason.
    Skipped(String),
    /// A free-form result (the TamperWard step).
    Note(String),
}

/// One row of the report.
struct Step {
    label: &'static str,
    path: String,
    outcome: Outcome,
}

/// The result of `ward init`: the rows, and what to do next.
pub struct Report {
    steps: Vec<Step>,
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
                Outcome::Kept => "already there, left as is".to_owned(),
                Outcome::Skipped(why) => format!("skipped · {why}"),
                Outcome::Note(text) => text.clone(),
            };
            let _ = writeln!(out, "  {:<11} {:<width$}  {outcome}", s.label, s.path);
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
    let ecosystem = Ecosystem::detect(&dir);
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
    steps.push(Step {
        label: "verifier",
        path: ".tamperward/config.yml".to_owned(),
        outcome: match write_new(
            &dir.join(".tamperward/config.yml"),
            &verifier_config(ecosystem),
            opts.dry_run,
        )? {
            Outcome::Written => Outcome::Note(format!(
                "{} ({})",
                if opts.dry_run {
                    "would write"
                } else {
                    "written"
                },
                ecosystem
                    .verify_command()
                    .unwrap_or("no test command recognised: set verify.command")
            )),
            other => other,
        },
    });
    steps.push(tamperward_step(&dir, ecosystem, opts)?);

    let key_in_vault =
        std::fs::read_to_string(gateway::vault_file(&opts.state, opts.agent.key_env()))
            .is_ok_and(|k| !k.trim().is_empty());
    let mut next = Vec::new();
    if !(opts.key_in_env || key_in_vault) {
        next.push((
            format!("ward vault set {}", opts.agent.key_env()),
            "the model key, kept on the host; the proxy injects it",
        ));
    }
    let arg = dir_argument(&opts.dir);
    next.push((
        format!("ward {}{arg}", opts.agent.command()),
        "start the agent in the sandbox",
    ));
    next.push((
        format!("ward verify{arg}"),
        "run the protected tests in the disposable verifier",
    ));
    Ok(Report {
        steps,
        next,
        dry_run: opts.dry_run,
        dir,
    })
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

/// `.tamperward/config.yml`, the verifier's view: the tests only it may judge, and
/// the command it runs. The command is guessed from the build files; without one the
/// key is left commented so `ward verify` says exactly what is missing.
fn verifier_config(ecosystem: Ecosystem) -> String {
    let mut text = String::from(
        "# .tamperward/config.yml — what `ward verify` runs (written by `ward init`).\n\
         #\n\
         # The verifier takes this file and every protected path from the session's entry\n\
         # snapshot, so an agent that edits a test listed here only changes what the verifier\n\
         # restores. The command runs offline, in a disposable sandbox, at the root of the tree.\n\
         # Reference: docs/tamperward-integration.md §5.\n\
         protected:\n  tests:\n    - tests/\n\
         verify:\n",
    );
    match ecosystem.verify_command() {
        Some(command) => {
            let _ = writeln!(text, "  command: {command}");
        }
        None => {
            let _ = writeln!(
                text,
                "  # No Cargo.toml, package.json or pyproject.toml here: name the test command.\n  \
                 # command: make test"
            );
        }
    }
    text.push_str("  budget_secs: 600\n");
    text
}

/// TamperWard's own policy, written only when `tamperward` is not installed: enough
/// for `tamperward check` to guard the tests once it is, and a pointer to the full
/// wiring. `tamperward init` keeps this file when it runs later.
fn tamperward_policy(ecosystem: Ecosystem) -> String {
    let mut text = String::from(
        "# .tamperward.yml — TamperWard policy (written by `ward init`; TamperWard was not\n\
         # installed). Once it is (`npx tamperward init`, Node.js 20.19 or later; the WardOS\n\
         # image ships it), run `tamperward init`: it keeps this file and adds the Claude Code\n\
         # hooks, a pre-commit hook and a CI workflow.\n\
         version: 1\n\
         protected:\n  tests: ['tests/**']\n",
    );
    match ecosystem.verify_command() {
        Some(command) => {
            let _ = writeln!(text, "verify:\n  command: {command}\n  budget: 600");
        }
        None => {
            text.push_str(
                "# verify:\n#   command: <the command that runs this project's tests>\n#   budget: 600\n",
            );
        }
    }
    text
}

/// The TamperWard step: run `tamperward init --cwd <dir>` and show its output, or
/// write the minimal policy and say how to get the rest.
fn tamperward_step(dir: &Path, ecosystem: Ecosystem, opts: &Options) -> Result<Step> {
    let path = ".tamperward.yml".to_owned();
    if opts.no_tamperward {
        return Ok(Step {
            label: "tamperward",
            path,
            outcome: Outcome::Skipped("--no-tamperward".to_owned()),
        });
    }
    let Some(bin) = &opts.tamperward else {
        let outcome = match write_new(
            &dir.join(&path),
            &tamperward_policy(ecosystem),
            opts.dry_run,
        )? {
            Outcome::Written => Outcome::Note(format!(
                "tamperward not installed; minimal policy {}. `npx tamperward init` adds the hooks, pre-commit and CI",
                if opts.dry_run {
                    "would be written"
                } else {
                    "written"
                }
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
        }
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    #[test]
    fn writes_the_template_the_verifier_config_and_the_minimal_policy() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\n").unwrap();
        let report = run(&options(dir.path(), state.path())).unwrap();
        assert_eq!(
            read(&dir.path().join(".ward/policy.yaml")),
            Policy::template()
        );
        let verifier = read(&dir.path().join(".tamperward/config.yml"));
        assert!(verifier.contains("command: cargo test"), "{verifier}");
        assert!(verifier.contains("- tests/"), "{verifier}");
        let policy = read(&dir.path().join(".tamperward.yml"));
        assert!(policy.contains("tests: ['tests/**']"), "{policy}");
        assert!(policy.contains("command: cargo test"), "{policy}");
        let text = report.render();
        assert!(text.contains(".ward/policy.yaml"), "{text}");
        assert!(text.contains("npx tamperward init"), "{text}");
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
    fn guesses_the_verify_command_from_the_build_files() {
        for (file, command) in [
            ("Cargo.toml", "cargo test"),
            ("package.json", "npm test"),
            ("pyproject.toml", "pytest"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(file), "").unwrap();
            run(&options(dir.path(), state.path())).unwrap();
            let verifier = read(&dir.path().join(".tamperward/config.yml"));
            assert!(
                verifier.contains(&format!("command: {command}")),
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
        assert!(verifier.contains("# command: make test"), "{verifier}");
        assert!(text.contains("no test command recognised"), "{text}");
        let err = ward_daemon::verify::Config::parse(&verifier)
            .unwrap_err()
            .to_string();
        assert!(err.contains("verify.command is empty"), "{err}");
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
