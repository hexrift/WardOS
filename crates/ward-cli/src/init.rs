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
    const fn key_env(self) -> &'static str {
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

/// Write `content` to `path` unless the file exists; `dry` only reports.
fn write_new(path: &Path, content: &str, dry: bool) -> Result<Outcome> {
    if path.exists() {
        return Ok(Outcome::Kept);
    }
    if !dry {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
        }
        std::fs::write(path, content).map_err(|e| io(path, e))?;
    }
    Ok(Outcome::Written)
}

/// The path the session state would take inside a project, kept out of git.
const SESSIONS_IGNORE: &str = ".ward/sessions/";

/// Append the session-state line to `.gitignore` in a git repository that does not
/// ignore it yet. Appending is the one edit `ward init` makes to a user's file: the
/// line is additive and marked, and a repository that commits session state leaks it.
fn ignore_sessions(dir: &Path, dry: bool) -> Result<Outcome> {
    if !dir.join(".git").exists() {
        return Ok(Outcome::Skipped("not a git repository".to_owned()));
    }
    let path = dir.join(".gitignore");
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(io(&path, e)),
    };
    if existing.lines().any(ignores_sessions) {
        return Ok(Outcome::Kept);
    }
    if !dry {
        let mut text = existing;
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        let _ = writeln!(text, "# WardOS session state, never committed (ward init)");
        let _ = writeln!(text, "{SESSIONS_IGNORE}");
        std::fs::write(&path, text).map_err(|e| io(&path, e))?;
    }
    Ok(Outcome::Note(format!(
        "{SESSIONS_IGNORE} {}",
        if dry { "would be added" } else { "added" }
    )))
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
    #![allow(clippy::unwrap_used, clippy::expect_used)]

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
