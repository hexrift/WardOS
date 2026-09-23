//! `ward ready`: a structured preflight report of what a project needs before an
//! agent starts (#147) — so a missing prerequisite is visible up front, in one
//! command, instead of surfacing mid-run as a confusing `ward verify` failure.
//!
//! This is the project-scoped counterpart to [`crate::doctor`]'s host-scoped report:
//! where `ward doctor` asks "can this host run a session at all", `ward ready` asks
//! "does *this* project resolve to a runnable, protected verification" — reading
//! exactly what `ward init` writes (`.ward/policy.yaml`, `.tamperward/config.yml`)
//! and reporting whether it resolves, not merely whether the files exist.
//!
//! Scope: this covers items 1 and 5 of #147's suggested implementation (a structured
//! report; Ready / Ready with limitations / Setup required / Verification
//! unavailable). It does not run the guessed command to distinguish a legitimate
//! pre-existing failing test ("baseline failing") from a broken setup, and it does
//! not prepare or cache an isolated dependency environment (items 2–4, 6) — both are
//! substantial follow-ups of their own (the second needs the same disposable-sandbox
//! machinery `ward verify` already owns) and are left for later PRs against #147.

use std::path::{Path, PathBuf};

use crate::doctor::Status;
use crate::verify;

/// The build system a directory shows: decides the guessed verify command `ward
/// init` writes into `.tamperward/config.yml`. Only used for that guess and for the
/// report's header line — the `runtime` row below checks the *configured* command,
/// not this detection, so a project that overrides the guess is checked correctly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ecosystem {
    /// `Cargo.toml` at the root.
    Cargo,
    /// `package.json` at the root.
    Npm,
    /// `pyproject.toml` at the root.
    Python,
    /// No recognised build manifest.
    Unknown,
}

impl Ecosystem {
    /// Detect from the build manifest a directory has at its root.
    #[must_use]
    pub fn detect(dir: &Path) -> Self {
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

    /// The command `ward init` guesses for this ecosystem.
    #[must_use]
    pub const fn verify_command(self) -> Option<&'static str> {
        match self {
            Self::Cargo => Some("cargo test"),
            Self::Npm => Some("npm test"),
            Self::Python => Some("pytest"),
            Self::Unknown => None,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::Python => "python",
            Self::Unknown => "unrecognised",
        }
    }
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// One row of the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// Short name.
    pub name: &'static str,
    /// Outcome.
    pub status: Status,
    /// What was found and, on `Warn`/`Fail`, what to do.
    pub detail: String,
}

impl Row {
    fn new(name: &'static str, status: Status, detail: impl Into<String>) -> Self {
        Self {
            name,
            status,
            detail: detail.into(),
        }
    }
}

/// The report's overall outcome (#147's suggested five states, minus "baseline
/// failing" — see the module doc for why that one needs a later PR).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every row resolves; an agent can start and `ward verify` can run.
    Ready,
    /// Every row resolves well enough to proceed, with a documented degradation
    /// (e.g. nothing is listed under `protected.tests` yet).
    Limited,
    /// A row that blocks a session is unresolved (missing runtime, unparsable
    /// policy or verifier config).
    SetupRequired,
    /// No verify command is configured at all, so readiness cannot be judged past
    /// that point — distinct from `SetupRequired`, whose command exists but fails
    /// one of its own preconditions.
    Unavailable,
}

impl Verdict {
    /// The word `ward ready` prints for this outcome.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Limited => "ready, with limitations",
            Self::SetupRequired => "setup required",
            Self::Unavailable => "verification unavailable",
        }
    }

    /// Whether an agent should be allowed to start without an explicit override.
    #[must_use]
    pub const fn blocks(self) -> bool {
        matches!(self, Self::SetupRequired | Self::Unavailable)
    }
}

/// The full preflight report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The detected build system, for the header line.
    pub ecosystem: Ecosystem,
    /// One row per check, in the order a user would fix them.
    pub rows: Vec<Row>,
    /// No verify command is configured; see [`Verdict::Unavailable`].
    unavailable: bool,
}

impl Report {
    /// Append a row a caller computed itself (the CLI adds the credential row,
    /// which needs to know which agent's key to look for — this crate does not).
    pub fn push(&mut self, row: Row) {
        self.rows.push(row);
    }

    /// The overall outcome across every row pushed so far.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        if self.unavailable {
            Verdict::Unavailable
        } else if self.rows.iter().any(|r| r.status == Status::Fail) {
            Verdict::SetupRequired
        } else if self.rows.iter().any(|r| r.status == Status::Warn) {
            Verdict::Limited
        } else {
            Verdict::Ready
        }
    }
}

/// Run the project-scoped checks against `dir` (a `ward init`-style project root).
/// Does not touch the network and runs no project command — only reads the two
/// config files `ward init` writes and probes `PATH` for the runtime the
/// *configured* command actually needs.
#[must_use]
pub fn check(dir: &Path) -> Report {
    let ecosystem = Ecosystem::detect(dir);
    let mut rows = vec![policy_row(dir)];
    let (verify_row, config) = verify_row(dir);
    let unavailable = config.is_none();
    rows.push(verify_row);
    if let Some(config) = &config {
        rows.push(runtime_row(dir, &config.verify.command));
        rows.push(protected_row(dir, config));
    }
    Report {
        ecosystem,
        rows,
        unavailable,
    }
}

fn policy_row(dir: &Path) -> Row {
    let path = dir.join(".ward/policy.yaml");
    match std::fs::read_to_string(&path) {
        Ok(yaml) => match ward_policy::Policy::from_yaml(&yaml) {
            Ok(_) => Row::new("policy", Status::Ok, ".ward/policy.yaml resolves"),
            Err(e) => Row::new(
                "policy",
                Status::Fail,
                format!(".ward/policy.yaml: {e}; a session cannot resolve its policy"),
            ),
        },
        // Absent is the ordinary pre-`ward init` state; any other I/O failure (the
        // path is a directory, permission denied, …) means the policy genuinely
        // cannot be read and must not be reported as a harmless "not written yet".
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Row::new(
            "policy",
            Status::Warn,
            "not written yet; `ward init` writes secure defaults",
        ),
        Err(e) => Row::new(
            "policy",
            Status::Fail,
            format!(".ward/policy.yaml: {e}; a session cannot resolve its policy"),
        ),
    }
}

/// The verify-config row, and the parsed config when one could be read — `None`
/// triggers `Verdict::Unavailable` and skips the rows that need a real command
/// (`runtime`, `protected paths`), tracked separately from a merely failing row so
/// the two stay distinguishable in the overall verdict.
fn verify_row(dir: &Path) -> (Row, Option<verify::Config>) {
    let path = dir.join(verify::CONFIG_PATH);
    let yaml = match std::fs::read_to_string(&path) {
        Ok(y) => y,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (
                Row::new(
                    "verify config",
                    Status::Fail,
                    format!(
                        "{} not written yet; `ward init` writes a guess",
                        verify::CONFIG_PATH
                    ),
                ),
                None,
            );
        }
        Err(e) => {
            return (
                Row::new(
                    "verify config",
                    Status::Fail,
                    format!("{}: {e}", verify::CONFIG_PATH),
                ),
                None,
            );
        }
    };
    match verify::Config::parse(&yaml) {
        Ok(config) => {
            let row = Row::new(
                "verify config",
                Status::Ok,
                format!("command: {}", config.verify.command),
            );
            (row, Some(config))
        }
        Err(_) => (
            Row::new(
                "verify config",
                Status::Fail,
                format!(
                    "{} has no verify.command; name the test command before an agent starts",
                    verify::CONFIG_PATH
                ),
            ),
            None,
        ),
    }
}

/// Shell metacharacters whose presence means `verify.command` is not a single
/// simple command: pipelines and lists (`|`, `&`, `;`), substitution (`` ` ``,
/// `$(`), and redirection (`<`, `>`). A command containing any of these has no
/// single "the program" this check can name with confidence, so [`runtime_row`]
/// reports it indeterminate rather than guessing at a piece of it — `cd subdir &&
/// cargo test` must not be judged runnable or not by probing `cd`.
const SHELL_METACHARACTERS: &[&str] = &["|", "&", ";", "`", "$("];

/// Builtins and keywords a shell resolves itself, never via `PATH`, so `which`
/// would wrongly report them absent. Deliberately small: only ones in common use
/// at the start of a verify command that do not also exist as a real binary on a
/// typical system (`true`, `test`, `[` usually do and are left to the `PATH`
/// check, which finds them correctly either way).
const SHELL_BUILTINS: &[&str] = &[
    "cd", "exec", "eval", "export", "unset", "set", "shift", "source", ".", ":", "type", "alias",
    "unalias", "trap", "wait", "return",
];

/// Whether `token` is a POSIX environment-variable assignment prefix (`NAME=value`,
/// e.g. `FOO=bar` in `FOO=bar cargo test`) rather than the command itself.
fn is_assignment(token: &str) -> bool {
    let Some((name, _)) = token.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether the binary the *configured* `verify.command` would actually invoke is
/// available — checked against the real command, not guessed from the project
/// manifest, so a Cargo project configured to run `npm test` is checked against
/// `npm`, and one running a custom `bash scripts/…` is checked against `bash`, not
/// against `cargo` either way.
///
/// Deliberately narrow: only a single simple command — optionally prefixed with
/// `NAME=value` assignments, as `FOO=bar cargo test` is — is resolved. A command
/// containing shell metacharacters ([`SHELL_METACHARACTERS`]: pipelines, lists,
/// substitution, redirection) or led by a shell builtin ([`SHELL_BUILTINS`]) is
/// reported indeterminate rather than misjudged: no PATH search can tell whether
/// `cd subdir && cargo test` is runnable without a real shell. A path candidate
/// (containing `/`, e.g. `./scripts/verify.sh`) is resolved against `dir` — the
/// verifier's own working directory — not against the process's `PATH`, matching
/// where the verifier actually looks for it.
fn runtime_row(dir: &Path, command: &str) -> Row {
    if let Some(op) = SHELL_METACHARACTERS.iter().find(|op| command.contains(*op)) {
        return Row::new(
            "runtime",
            Status::Warn,
            format!("verify.command contains `{op}`; runtime availability not verified"),
        );
    }
    let Some(candidate) = command.split_whitespace().find(|t| !is_assignment(t)) else {
        return Row::new(
            "runtime",
            Status::Warn,
            "verify.command is blank or only environment assignments; cannot determine a runtime",
        );
    };
    if SHELL_BUILTINS.contains(&candidate) {
        return Row::new(
            "runtime",
            Status::Warn,
            format!(
                "verify.command starts with the shell builtin `{candidate}`; runtime availability not verified"
            ),
        );
    }
    if candidate.contains('/') {
        let path = if Path::new(candidate).is_absolute() {
            PathBuf::from(candidate)
        } else {
            dir.join(candidate)
        };
        return if path.is_file() {
            Row::new("runtime", Status::Ok, format!("{candidate} present"))
        } else {
            Row::new(
                "runtime",
                Status::Fail,
                format!(
                    "{candidate} not found relative to the project; fix the path before `ward verify` can run"
                ),
            )
        };
    }
    if crate::doctor::which(candidate).is_some() {
        Row::new("runtime", Status::Ok, format!("{candidate} on PATH"))
    } else {
        Row::new(
            "runtime",
            Status::Fail,
            format!("{candidate} not found on PATH; install it before `ward verify` can run"),
        )
    }
}

fn protected_row(dir: &Path, config: &verify::Config) -> Row {
    if config.protected.tests.is_empty() {
        return Row::new(
            "protected paths",
            Status::Warn,
            "protected.tests is empty; the verifier has nothing to restore across a run",
        );
    }
    let missing: Vec<&str> = config
        .protected
        .tests
        .iter()
        .map(String::as_str)
        .filter(|p| !dir.join(p).exists())
        .collect();
    if missing.is_empty() {
        Row::new(
            "protected paths",
            Status::Ok,
            format!("{} path(s) present", config.protected.tests.len()),
        )
    } else {
        Row::new(
            "protected paths",
            Status::Warn,
            format!("not yet on disk: {}", missing.join(", ")),
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn write(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn a_freshly_initialised_cargo_project_is_ready_or_limited_never_setup_required() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\n").unwrap();
        write(
            dir.path(),
            ".ward/policy.yaml",
            ward_policy::Policy::template(),
        );
        write(
            dir.path(),
            ".tamperward/config.yml",
            "protected:\n  tests:\n    - tests/\nverify:\n  command: cargo test\n",
        );
        std::fs::create_dir(dir.path().join("tests")).unwrap();
        let report = check(dir.path());
        assert_eq!(report.ecosystem, Ecosystem::Cargo);
        // `cargo` may or may not be on this machine's PATH; either way the verdict
        // must never be `Unavailable` (a command *is* configured) and never silently
        // skip a row.
        assert_ne!(report.verdict(), Verdict::Unavailable);
        assert!(report.rows.iter().any(|r| r.name == "policy"));
        assert!(report.rows.iter().any(|r| r.name == "verify config"));
        assert!(report.rows.iter().any(|r| r.name == "runtime"));
        assert!(report.rows.iter().any(|r| r.name == "protected paths"));
    }

    #[test]
    fn no_ward_init_at_all_is_unavailable_not_setup_required() {
        let dir = tempfile::tempdir().unwrap();
        let report = check(dir.path());
        assert_eq!(report.verdict(), Verdict::Unavailable);
        // Unavailable stops before the protected-paths row: there is no config to
        // read a protected list from.
        assert!(!report.rows.iter().any(|r| r.name == "protected paths"));
    }

    #[test]
    fn a_verify_config_with_no_command_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "protected:\n  tests: []\n",
        );
        let report = check(dir.path());
        assert_eq!(report.verdict(), Verdict::Unavailable);
    }

    #[test]
    fn empty_protected_tests_is_limited_not_setup_required() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: echo ok\n",
        );
        let report = check(dir.path());
        assert_eq!(report.verdict(), Verdict::Limited);
        let row = report
            .rows
            .iter()
            .find(|r| r.name == "protected paths")
            .unwrap();
        assert_eq!(row.status, Status::Warn);
        assert!(row.detail.contains("nothing to restore"));
    }

    #[test]
    fn a_protected_path_not_yet_on_disk_is_limited() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "protected:\n  tests:\n    - tests/\nverify:\n  command: echo ok\n",
        );
        let report = check(dir.path());
        assert_eq!(report.verdict(), Verdict::Limited);
        let row = report
            .rows
            .iter()
            .find(|r| r.name == "protected paths")
            .unwrap();
        assert!(row.detail.contains("tests/"), "{}", row.detail);
    }

    #[test]
    fn a_malformed_policy_is_setup_required_not_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".ward/policy.yaml", "network: [not, a, mode]\n");
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: echo ok\n",
        );
        let report = check(dir.path());
        assert_eq!(report.verdict(), Verdict::SetupRequired);
        let row = report.rows.iter().find(|r| r.name == "policy").unwrap();
        assert_eq!(row.status, Status::Fail);
    }

    #[test]
    fn an_unreadable_policy_is_setup_required_not_a_harmless_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        // A directory sitting at the policy's path is not "not written yet" — it is
        // unreadable, and must not be reported as the same harmless absence.
        std::fs::create_dir_all(dir.path().join(".ward/policy.yaml")).unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: echo ok\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "policy").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_checks_the_configured_command_not_the_manifest_guess() {
        let dir = tempfile::tempdir().unwrap();
        // A Cargo project can still configure a different verifier command; the
        // runtime row must judge that command, not assume `cargo` from Cargo.toml.
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\n").unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: npm test\n",
        );
        let report = check(dir.path());
        assert_eq!(report.ecosystem, Ecosystem::Cargo);
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert!(row.detail.contains("npm"), "{}", row.detail);
        assert!(!row.detail.contains("cargo"), "{}", row.detail);
    }

    #[test]
    fn runtime_checks_a_custom_shell_commands_own_first_token() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\n").unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: bash scripts/verify.sh\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert!(row.detail.contains("bash"), "{}", row.detail);
        assert!(!row.detail.contains("cargo"), "{}", row.detail);
    }

    #[test]
    fn runtime_skips_a_leading_environment_assignment() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: FOO=bar cargo test\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        // `cargo` is genuinely on PATH in this build's own environment (it is what
        // ran this test), so a correct implementation resolves past `FOO=bar` to a
        // real Ok, not a Fail against the literal token `FOO=bar`.
        assert_eq!(row.status, Status::Ok, "{}", row.detail);
        assert!(row.detail.contains("cargo"), "{}", row.detail);
        assert!(!row.detail.contains("FOO"), "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_resolves_a_project_relative_executable_against_the_project_not_path() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "scripts/verify.sh", "#!/bin/sh\ntrue\n");
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: ./scripts/verify.sh\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Ok, "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);

        // The same relative path, absent, is a real Fail — not silently ignored.
        let missing = tempfile::tempdir().unwrap();
        write(
            missing.path(),
            ".tamperward/config.yml",
            "verify:\n  command: ./scripts/verify.sh\n",
        );
        let report = check(missing.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_a_compound_command_indeterminate_rather_than_probing_a_builtin() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: cd subdir && cargo test\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        // Neither a false Ok nor a false Fail: `cd` is a shell builtin with no PATH
        // entry, and the command as a whole is a list (`&&`), not a single program.
        assert_eq!(row.status, Status::Warn, "{}", row.detail);
        assert_ne!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn runtime_reports_a_bare_assignment_indeterminate() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: FOO=bar\n",
        );
        let report = check(dir.path());
        let row = report.rows.iter().find(|r| r.name == "runtime").unwrap();
        assert_eq!(row.status, Status::Warn, "{}", row.detail);
    }

    #[test]
    fn a_pushed_row_participates_in_the_verdict() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".tamperward/config.yml",
            "verify:\n  command: echo ok\n",
        );
        let mut report = check(dir.path());
        assert_eq!(report.verdict(), Verdict::Limited); // empty protected.tests
        report.push(Row::new("credential", Status::Fail, "no key configured"));
        assert_eq!(report.verdict(), Verdict::SetupRequired);
    }

    #[test]
    fn ecosystem_detects_the_recognised_manifests() {
        for (file, eco, label) in [
            ("Cargo.toml", Ecosystem::Cargo, "cargo"),
            ("package.json", Ecosystem::Npm, "npm"),
            ("pyproject.toml", Ecosystem::Python, "python"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(file), "").unwrap();
            assert_eq!(Ecosystem::detect(dir.path()), eco);
            assert_eq!(eco.to_string(), label);
        }
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Ecosystem::detect(dir.path()), Ecosystem::Unknown);
    }

    #[test]
    fn verdict_blocks_only_setup_required_and_unavailable() {
        assert!(!Verdict::Ready.blocks());
        assert!(!Verdict::Limited.blocks());
        assert!(Verdict::SetupRequired.blocks());
        assert!(Verdict::Unavailable.blocks());
    }
}
