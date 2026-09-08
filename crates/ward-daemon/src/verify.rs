//! `ward verify`: a disposable Zone 2 verifier (ADR-0004, 0.1 namespace form).
//!
//! The candidate is a snapshot, materialised from the CAS into a scratch tree; the
//! verification config and every protected path come from the *entry* snapshot, so
//! an agent that edits a protected test only changes what the verifier overwrites.
//! The command runs in a bare sandbox with no egress and the host toolchains bound
//! read-only, and the parsed result is what the session records.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use ward_events::VerifySummary;
use ward_snapshot::{CaptureOptions, SnapshotId, SnapshotRole, SnapshotStore};

use crate::error::{Error, Result};
use crate::sandbox::{Launch, StdioMode};

/// Where the project keeps its `TamperWard` config.
pub const CONFIG_PATH: &str = ".tamperward/config.yml";
/// Mount point of the verifier toolchains inside the sandbox.
const TOOLCHAIN_ROOT: &str = "/run/verifier";

/// The parts of `.tamperward/config.yml` the verifier needs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct Config {
    /// Paths only the verifier may decide about.
    #[serde(default)]
    pub protected: Protected,
    /// What to run.
    #[serde(default)]
    pub verify: VerifyCommand,
}

/// Protected surfaces.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct Protected {
    /// Worktree-relative test files (or `dir/` prefixes).
    #[serde(default)]
    pub tests: Vec<String>,
}

/// The verification command.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct VerifyCommand {
    /// Shell command run at the root of the candidate tree.
    #[serde(default)]
    pub command: String,
}

impl Config {
    /// Parse the config; an empty command is a configuration error.
    pub fn parse(yaml: &str) -> Result<Self> {
        let config: Self = serde_yaml::from_str(yaml)
            .map_err(|e| Error::Project(format!("{CONFIG_PATH}: {e}")))?;
        if config.verify.command.trim().is_empty() {
            return Err(Error::Project(format!(
                "{CONFIG_PATH}: verify.command is empty"
            )));
        }
        Ok(config)
    }
}

/// A verification prepared but not yet run.
pub struct Verification {
    /// The candidate snapshot.
    pub candidate: SnapshotId,
    /// Config as read from the entry snapshot.
    pub config: Config,
    /// BLAKE3 of the config bytes.
    pub manifest_hash: [u8; 32],
    /// Protected paths whose candidate bytes differed from pristine and were replaced.
    pub restored: Vec<String>,
    /// The materialised tree the command runs over.
    pub scratch: PathBuf,
}

/// Snapshot the worktree as the candidate, then build the verifier tree under
/// `scratch_root`: the candidate with every protected path taken from `entry`.
pub fn prepare(
    store: &SnapshotStore,
    worktree: &Path,
    entry: SnapshotId,
    scratch_root: &Path,
) -> Result<Verification> {
    let snap = |e: ward_snapshot::SnapshotError| Error::Snapshot(e.to_string());
    let candidate = store
        .store_snapshot(worktree, SnapshotRole::Candidate, CaptureOptions::default())
        .map_err(snap)?;
    let yaml = store
        .cat(entry, Path::new(CONFIG_PATH))
        .map_err(|_| Error::Project(format!("{CONFIG_PATH} missing from the entry snapshot")))?;
    let config = Config::parse(&String::from_utf8_lossy(&yaml))?;
    let manifest_hash = *blake3::hash(&yaml).as_bytes();

    let scratch = scratch_root.join(format!("verify-{}", &candidate.digest().to_hex()[..12]));
    store.materialize(candidate, &scratch).map_err(snap)?;
    let mut restored = Vec::new();
    for rel in &config.protected.tests {
        let pristine = store.cat(entry, Path::new(rel)).ok();
        let target = scratch.join(rel);
        let current = std::fs::read(&target).ok();
        if pristine == current {
            continue;
        }
        match pristine {
            Some(bytes) => {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
                }
                std::fs::write(&target, bytes).map_err(|e| Error::io(&target, e))?;
            }
            None => drop(std::fs::remove_file(&target)),
        }
        restored.push(rel.clone());
    }
    Ok(Verification {
        candidate,
        config,
        manifest_hash,
        restored,
        scratch,
    })
}

/// What the verifier produced.
pub struct Outcome {
    /// Whether the command succeeded.
    pub passed: bool,
    /// Counts parsed from the output.
    pub summary: VerifySummary,
    /// Combined stdout and stderr.
    pub output: String,
    /// BLAKE3 of `output`: the result document's hash in the log.
    pub result_hash: [u8; 32],
}

/// Run the verification command over the prepared tree, offline, with the host
/// toolchains read-only.
pub fn execute(v: &Verification) -> Result<Outcome> {
    let argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        v.config.verify.command.clone(),
    ];
    let mut launch = Launch::new(&v.scratch, argv).stdio(StdioMode::Capture);
    for (k, val) in Toolchains::detect().env() {
        launch = launch.env(k, val);
    }
    launch = Toolchains::detect().mount(launch);
    let out = launch.run()?;
    let output = format!("{}{}", out.stdout, out.stderr);
    let mut summary = parse_summary(&output);
    summary.steps_total = 1;
    summary.duration = out.duration;
    let passed = out.code == Some(0);
    if passed {
        summary.steps_passed = 1;
    } else {
        summary.steps_failed = 1;
    }
    Ok(Outcome {
        passed,
        summary,
        result_hash: *blake3::hash(output.as_bytes()).as_bytes(),
        output,
    })
}

/// Per-test counts from `cargo test` style result lines
/// (`test result: ok. 3 passed; 1 failed; ...`); zero when the runner prints none.
#[must_use]
pub fn parse_summary(output: &str) -> VerifySummary {
    let mut summary = VerifySummary::default();
    for line in output.lines().filter(|l| l.starts_with("test result:")) {
        for part in line.split(';') {
            let mut words = part.split_whitespace().rev();
            let (Some(kind), Some(n)) = (words.next(), words.next()) else {
                continue;
            };
            let Ok(n) = n.parse::<u64>() else {
                continue;
            };
            match kind {
                "passed" => summary.tests_run += n,
                "failed" => {
                    summary.tests_run += n;
                    summary.tests_failed += n;
                }
                _ => {}
            }
        }
    }
    summary
}

/// Host toolchains the verifier gets read-only, the 0.1 stand-in for a verifier
/// image: a Rust toolchain from `$RUSTUP_HOME`/`~/.rustup` and `$CARGO_HOME`/`~/.cargo`
/// (binaries and registry only; the cargo home itself is a private tmpfs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Toolchains {
    rustup: Option<PathBuf>,
    cargo: Option<PathBuf>,
}

impl Toolchains {
    /// Look the toolchains up on this host.
    #[must_use]
    pub fn detect() -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let find = |var: &str, dot: &str| {
            std::env::var_os(var)
                .map(PathBuf::from)
                .or_else(|| home.as_ref().map(|h| h.join(dot)))
                .filter(|p| p.is_dir())
        };
        Self {
            rustup: find("RUSTUP_HOME", ".rustup"),
            cargo: find("CARGO_HOME", ".cargo"),
        }
    }

    /// Whether a Rust toolchain is available to the verifier.
    #[must_use]
    pub fn has_rust(&self) -> bool {
        self.rustup.is_some() && self.cargo.is_some()
    }

    /// Environment inside the verifier.
    #[must_use]
    pub fn env(&self) -> Vec<(String, String)> {
        let mut env = vec![("HOME".to_owned(), "/tmp".to_owned())];
        let mut path = String::new();
        if self.rustup.is_some() {
            env.push(("RUSTUP_HOME".into(), format!("{TOOLCHAIN_ROOT}/rustup")));
        }
        if self.cargo.is_some() {
            env.push(("CARGO_HOME".into(), format!("{TOOLCHAIN_ROOT}/cargo")));
            path.push_str(TOOLCHAIN_ROOT);
            path.push_str("/cargo/bin:");
        }
        path.push_str("/usr/local/bin:/usr/bin:/bin");
        env.push(("PATH".into(), path));
        env
    }

    /// Add the mounts to `launch`.
    #[must_use]
    pub fn mount(&self, mut launch: Launch) -> Launch {
        if let Some(rustup) = &self.rustup {
            launch = launch.ro_bind(rustup, format!("{TOOLCHAIN_ROOT}/rustup"));
        }
        if let Some(cargo) = &self.cargo {
            launch = launch.tmpfs(format!("{TOOLCHAIN_ROOT}/cargo"));
            for sub in ["bin", "registry"] {
                let dir = cargo.join(sub);
                if dir.is_dir() {
                    launch = launch.ro_bind(dir, format!("{TOOLCHAIN_ROOT}/cargo/{sub}"));
                }
            }
        }
        launch
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn config_needs_a_command_and_reads_protected_tests() {
        let c = Config::parse(
            "version: 1\nprotected:\n  tests:\n    - tests/security_expiry.rs\nverify:\n  command: cargo test --all-targets\n",
        )
        .unwrap();
        assert_eq!(c.protected.tests, vec!["tests/security_expiry.rs"]);
        assert_eq!(c.verify.command, "cargo test --all-targets");
        assert!(Config::parse("version: 1\n").is_err());
        assert!(Config::parse("verify:\n  command: '  '\n").is_err());
    }

    #[test]
    fn summary_sums_cargo_result_lines() {
        let out = "running 2 tests\n\
                   test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured\n\
                   test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured\n\
                   error: test failed";
        let s = parse_summary(out);
        assert_eq!((s.tests_run, s.tests_failed), (3, 1));
        assert_eq!(parse_summary("no runner output").tests_run, 0);
    }

    #[test]
    fn toolchain_env_puts_cargo_first_on_a_private_path() {
        let t = Toolchains {
            rustup: Some("/root/.rustup".into()),
            cargo: Some("/root/.cargo".into()),
        };
        let env = t.env();
        assert!(env.contains(&("RUSTUP_HOME".into(), "/run/verifier/rustup".into())));
        assert!(env.contains(&("CARGO_HOME".into(), "/run/verifier/cargo".into())));
        let path = env.iter().find(|(k, _)| k == "PATH").unwrap();
        assert!(path.1.starts_with("/run/verifier/cargo/bin:"));
        assert!(!path.1.contains("/root"));
        assert_eq!(Toolchains::default().env().len(), 2, "HOME and PATH only");
    }

    #[test]
    fn prepare_overlays_protected_paths_from_the_entry_snapshot() {
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let w = work.path();
        std::fs::create_dir_all(w.join(".tamperward")).unwrap();
        std::fs::create_dir_all(w.join("tests")).unwrap();
        std::fs::write(
            w.join(CONFIG_PATH),
            "protected:\n  tests: [tests/judge.txt]\nverify:\n  command: true\n",
        )
        .unwrap();
        std::fs::write(w.join("tests/judge.txt"), "strict").unwrap();
        std::fs::write(w.join("src.txt"), "v1").unwrap();
        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let entry = store
            .store_snapshot(w, SnapshotRole::Entry, CaptureOptions::default())
            .unwrap();

        // The agent weakens the judge and changes the code; the verifier sees the
        // code change and the pristine judge.
        std::fs::write(w.join("tests/judge.txt"), "lenient").unwrap();
        std::fs::write(w.join("src.txt"), "v2").unwrap();
        let v = prepare(&store, w, entry, state.path()).unwrap();
        assert_eq!(v.restored, vec!["tests/judge.txt"]);
        assert_eq!(
            std::fs::read_to_string(v.scratch.join("tests/judge.txt")).unwrap(),
            "strict"
        );
        assert_eq!(
            std::fs::read_to_string(v.scratch.join("src.txt")).unwrap(),
            "v2"
        );
        assert_ne!(v.candidate, entry);

        // A config edit in the worktree does not reach the verifier either.
        std::fs::write(w.join(CONFIG_PATH), "verify:\n  command: false\n").unwrap();
        let v = prepare(&store, w, entry, state.path()).unwrap();
        assert_eq!(v.config.verify.command, "true");
    }
}
