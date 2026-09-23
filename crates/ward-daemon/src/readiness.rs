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

use std::path::Path;

use crate::doctor::Status;
use crate::verify;

/// The build system a directory shows: decides the guessed verify command and the
/// runtime binary that command needs on `PATH`. The same detection `ward init` uses
/// to write `.tamperward/config.yml`'s guessed command.
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

    /// The binary that guessed command needs on `PATH`.
    const fn runtime(self) -> Option<&'static str> {
        match self {
            Self::Cargo => Some("cargo"),
            Self::Npm => Some("npm"),
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
/// config files `ward init` writes and probes `PATH` for the runtime they need.
#[must_use]
pub fn check(dir: &Path) -> Report {
    let ecosystem = Ecosystem::detect(dir);
    let mut rows = vec![policy_row(dir)];
    let (verify_row, unavailable) = verify_row(dir);
    let protected = if unavailable {
        None
    } else {
        Some(protected_row(dir, &verify_row))
    };
    rows.push(verify_row);
    rows.push(runtime_row(ecosystem));
    if let Some(row) = protected {
        rows.push(row);
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
        Err(_) => Row::new(
            "policy",
            Status::Warn,
            "not written yet; `ward init` writes secure defaults",
        ),
    }
}

/// The verify-config row, and whether no command is configured at all (the
/// `Verdict::Unavailable` trigger, tracked separately from a merely failing row so
/// the two stay distinguishable in the overall verdict).
fn verify_row(dir: &Path) -> (Row, bool) {
    let path = dir.join(verify::CONFIG_PATH);
    let Ok(yaml) = std::fs::read_to_string(&path) else {
        return (
            Row::new(
                "verify config",
                Status::Fail,
                format!(
                    "{} not written yet; `ward init` writes a guess",
                    verify::CONFIG_PATH
                ),
            ),
            true,
        );
    };
    match verify::Config::parse(&yaml) {
        Ok(config) => (
            Row::new(
                "verify config",
                Status::Ok,
                format!("command: {}", config.verify.command),
            ),
            false,
        ),
        Err(_) => (
            Row::new(
                "verify config",
                Status::Fail,
                format!(
                    "{} has no verify.command; name the test command before an agent starts",
                    verify::CONFIG_PATH
                ),
            ),
            true,
        ),
    }
}

fn runtime_row(ecosystem: Ecosystem) -> Row {
    let Some(bin) = ecosystem.runtime() else {
        return Row::new(
            "runtime",
            Status::Warn,
            "no recognised build manifest; cannot confirm a runtime for the configured command",
        );
    };
    if crate::doctor::which(bin).is_some() {
        Row::new("runtime", Status::Ok, format!("{bin} on PATH"))
    } else {
        Row::new(
            "runtime",
            Status::Fail,
            format!("{bin} not found on PATH; install it before `ward verify` can run"),
        )
    }
}

fn protected_row(dir: &Path, verify_row: &Row) -> Row {
    // Only reachable once `verify_row` parsed the config successfully.
    let path = dir.join(verify::CONFIG_PATH);
    let config = std::fs::read_to_string(&path)
        .ok()
        .and_then(|y| verify::Config::parse(&y).ok())
        .unwrap_or_else(|| {
            debug_assert!(verify_row.status == Status::Ok, "{verify_row:?}");
            verify::Config::default()
        });
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
