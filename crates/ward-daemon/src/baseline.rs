//! The project's baseline (#147 item 5, its last state): the accepted verification
//! command run once, offline, in the verifier's own sandbox, over the project's current
//! tree — the entry state, before any agent work — so a legitimate pre-existing failing
//! test is known up front and is never mistaken for an installation failure.
//!
//! Running it is an explicit choice (`ward ready --baseline`, or the welcome asking),
//! never part of a plain `ward ready`. [`run`] goes through exactly the verifier's path:
//! the tree is captured into the CAS ([`verify::prepare`], with the same capture options
//! a candidate gets), materialised into a private scratch tree, the prepared dependency
//! environment whose key matches its lockfile is mounted read-only
//! ([`prepare::lookup_in`]), and the command runs with no network
//! ([`verify::execute_with`]). Nothing is written into the project.
//!
//! The result is recorded durably in the project's readiness state,
//! `<state>/readiness/<digest of the canonical project path>/baseline.json`, beside the
//! verifier's capped output (`baseline-output.txt`), keyed by what decides it: the tree
//! digest, the prepared environment key (`ward prepare`) and the command. A later `ward
//! ready` reads the record and holds it against the project as it is now ([`status`]):
//! current when all three still match, stale (with which one moved) otherwise. Only a
//! *current* red baseline is the "baseline failing" verdict.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use ward_snapshot::{HashCache, SnapshotRole, SnapshotStore};

use crate::error::{Error, Result};
use crate::prepare;
use crate::verify;

/// Directory under the state root holding each project's readiness state.
pub const READINESS_DIR: &str = "readiness";
/// The baseline record, in a project's readiness directory.
pub const RECORD_FILE: &str = "baseline.json";
/// The verifier's capped output of the last baseline, beside the record.
pub const OUTPUT_FILE: &str = "baseline-output.txt";
/// Bytes of the output's end kept in the record itself.
pub const OUTPUT_TAIL_BYTES: usize = 4096;
/// Lines of that tail `ward ready` shows under a red baseline.
pub const TAIL_LINES: usize = 12;
/// The record format this module writes and reads.
const RECORD_VERSION: u32 = 1;

/// `baseline.json`: one run of the accepted command over one tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Format version ([`RECORD_VERSION`]).
    pub version: u32,
    /// The canonical project path.
    pub project: PathBuf,
    /// The accepted command, as `.tamperward/config.yml` named it.
    pub command: String,
    /// The tree it ran over: the snapshot id (`blake3:…`) the verifier's capture gave it.
    pub tree: String,
    /// The prepared environment key (hex) the project's inputs resolved to, mounted when
    /// ready; `None` when the project needs none.
    pub environment: Option<String>,
    /// What was mounted, or why nothing was, in words.
    pub environment_note: String,
    /// Whether the command exited 0 within its budget.
    pub passed: bool,
    /// Whether it was killed at `verify.budget_secs`.
    pub timed_out: bool,
    /// The budget it ran under, in seconds.
    pub budget_secs: u64,
    /// The command's exit status; `None` when it was killed.
    pub exit_code: Option<i32>,
    /// Tests the runner reported (`test result:` lines), zero when it reports none.
    pub tests_run: u64,
    /// Of those, how many failed.
    pub tests_failed: u64,
    /// Wall-clock milliseconds of the command.
    pub duration_ms: u64,
    /// Unix seconds when it finished.
    pub finished_at: u64,
    /// Bytes the command wrote, before the verifier's cap.
    pub output_bytes: u64,
    /// Whether the verifier's cap dropped part of the output.
    pub output_truncated: bool,
    /// BLAKE3 (hex) of the capped output kept in [`OUTPUT_FILE`].
    pub result_hash: String,
    /// The last [`OUTPUT_TAIL_BYTES`] of that output.
    pub output_tail: String,
}

impl Record {
    /// A record of `outcome`, the verifier's result for `command` over `tree`.
    #[must_use]
    pub fn of(
        project: &Path,
        command: &str,
        budget_secs: u64,
        tree: &str,
        environment: Option<String>,
        environment_note: String,
        outcome: &verify::Outcome,
    ) -> Self {
        Self {
            version: RECORD_VERSION,
            project: project.to_path_buf(),
            command: command.to_owned(),
            tree: tree.to_owned(),
            environment,
            environment_note,
            passed: outcome.passed,
            timed_out: outcome.timed_out,
            budget_secs,
            exit_code: outcome.exit_code,
            tests_run: outcome.summary.tests_run,
            tests_failed: outcome.summary.tests_failed,
            duration_ms: u64::try_from(outcome.summary.duration.as_millis()).unwrap_or(u64::MAX),
            finished_at: unix_now(),
            output_bytes: outcome.output_bytes,
            output_truncated: outcome.output_truncated,
            result_hash: blake3::Hash::from_bytes(outcome.result_hash)
                .to_hex()
                .to_string(),
            output_tail: tail(&outcome.output),
        }
    }

    /// Parse a record; a format this module does not know is refused, not guessed at.
    pub fn parse(json: &str) -> Result<Self> {
        let record: Self = serde_json::from_str(json)
            .map_err(|e| Error::Project(format!("{RECORD_FILE}: {e}")))?;
        if record.version != RECORD_VERSION {
            return Err(Error::Project(format!(
                "{RECORD_FILE}: version {} is not {RECORD_VERSION}",
                record.version
            )));
        }
        Ok(record)
    }

    /// `green` or `red`.
    #[must_use]
    pub const fn color(&self) -> &'static str {
        if self.passed { "green" } else { "red" }
    }

    /// How the command ended: `exit 1`, `killed at its 600 s budget`, `killed by a signal`.
    #[must_use]
    pub fn ending(&self) -> String {
        if self.timed_out {
            format!("killed at its {} s budget", self.budget_secs)
        } else {
            self.exit_code
                .map_or_else(|| "killed by a signal".to_owned(), |c| format!("exit {c}"))
        }
    }

    /// `1 of 2 tests failed`, `2 tests passed`, or `None` when the runner printed no counts.
    #[must_use]
    pub fn counts(&self) -> Option<String> {
        if self.tests_run == 0 {
            None
        } else if self.tests_failed > 0 {
            Some(format!(
                "{} of {} tests failed",
                self.tests_failed, self.tests_run
            ))
        } else {
            Some(format!("{} tests passed", self.tests_run))
        }
    }

    /// The last `n` non-empty lines of the recorded output.
    #[must_use]
    pub fn tail_lines(&self, n: usize) -> Vec<&str> {
        let lines: Vec<&str> = self
            .output_tail
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect();
        lines[lines.len().saturating_sub(n)..].to_vec()
    }

    /// The first 12 hex digits of the tree it ran over.
    #[must_use]
    pub fn short_tree(&self) -> &str {
        short(&self.tree)
    }
}

/// The first 12 hex digits of a `blake3:<hex>` id (or of bare hex).
#[must_use]
pub fn short(id: &str) -> &str {
    let hex = id.strip_prefix("blake3:").unwrap_or(id);
    &hex[..12.min(hex.len())]
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The last [`OUTPUT_TAIL_BYTES`] of `output`, on a char boundary, with a marker when cut.
fn tail(output: &str) -> String {
    if output.len() <= OUTPUT_TAIL_BYTES {
        return output.to_owned();
    }
    let mut start = output.len() - OUTPUT_TAIL_BYTES;
    while !output.is_char_boundary(start) {
        start += 1;
    }
    format!("[…{start} bytes omitted]\n{}", &output[start..])
}

/// `<state>/readiness/<first 32 hex of BLAKE3 over the canonical project path>`.
#[must_use]
pub fn project_dir(state: &Path, dir: &Path) -> PathBuf {
    let canonical = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let digest = blake3::hash(canonical.as_os_str().as_encoded_bytes()).to_hex();
    state.join(READINESS_DIR).join(&digest[..32])
}

/// The project's last baseline, if one was recorded.
pub fn load(state: &Path, dir: &Path) -> Result<Option<Record>> {
    let path = project_dir(state, dir).join(RECORD_FILE);
    match std::fs::read_to_string(&path) {
        Ok(json) => Record::parse(&json).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(&path, e)),
    }
}

/// Record `record` (and the verifier's capped `output`) as the project's baseline,
/// replacing the previous one; each file is written whole and renamed into place.
pub fn save(state: &Path, dir: &Path, record: &Record, output: &str) -> Result<()> {
    let root = project_dir(state, dir);
    std::fs::create_dir_all(&root).map_err(|e| Error::io(&root, e))?;
    let write = |name: &str, bytes: &[u8]| -> Result<()> {
        let path = root.join(name);
        let tmp = root.join(format!("{name}.tmp"));
        std::fs::write(&tmp, bytes).map_err(|e| Error::io(&tmp, e))?;
        std::fs::rename(&tmp, &path).map_err(|e| Error::io(&path, e))
    };
    write(OUTPUT_FILE, output.as_bytes())?;
    let json = serde_json::to_string_pretty(record)
        .map_err(|e| Error::Project(format!("{RECORD_FILE}: {e}")))?;
    write(RECORD_FILE, json.as_bytes())
}

/// The prepared environment key the project's inputs resolve to, the half of the
/// baseline's key `ward prepare` decides: present for an environment that is ready or
/// missing (the key exists either way), absent when the project needs none or none can
/// be keyed.
#[must_use]
pub fn environment_key(lookup: &prepare::Lookup) -> Option<String> {
    match lookup {
        prepare::Lookup::Ready(env) => Some(env.key.hex()),
        prepare::Lookup::Missing { key, .. } => Some(key.hex()),
        prepare::Lookup::NotNeeded(_)
        | prepare::Lookup::Declined(_)
        | prepare::Lookup::Unavailable(_) => None,
    }
}

/// The last baseline held against the project as it is now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// No baseline has been recorded for this project.
    NotRun,
    /// The record describes the project as it is now: same tree, same prepared
    /// environment, same command.
    Current(Box<Record>),
    /// The record is history: `why` names what moved since.
    Stale {
        /// The last record.
        record: Box<Record>,
        /// What changed since it was taken.
        why: String,
    },
    /// Whether a record describes the project cannot be said: the record cannot be
    /// read, or the tree cannot be digested now.
    Unknown {
        /// The record, when it could be read.
        record: Option<Box<Record>>,
        /// Why.
        why: String,
    },
}

impl Status {
    /// A current baseline that did not pass: the "baseline failing" verdict.
    #[must_use]
    pub fn is_failing(&self) -> bool {
        matches!(self, Self::Current(record) if !record.passed)
    }
}

/// The project's baseline status: the record, if any, against `dir`'s tree digested now
/// (the verifier's capture options, nothing stored), the `command` accepted now and the
/// `environment` key its inputs resolve to now ([`environment_key`]). Reads files only;
/// runs nothing, and digests the tree only when there is a record to compare it with.
#[must_use]
pub fn status(state: &Path, dir: &Path, command: &str, environment: Option<&str>) -> Status {
    let record = match load(state, dir) {
        Ok(None) => return Status::NotRun,
        Ok(Some(record)) => record,
        Err(e) => {
            return Status::Unknown {
                record: None,
                why: format!(
                    "the last baseline cannot be read ({e}); `ward ready --baseline` records it again"
                ),
            };
        }
    };
    let tree =
        ward_snapshot::digest_worktree(dir, verify::candidate_options(), &mut HashCache::new())
            .map(|id| id.to_string())
            .map_err(|e| e.to_string());
    judge(record, tree, command, environment)
}

/// [`status`]'s comparison, given the record and the tree's digest now.
pub(crate) fn judge(
    record: Record,
    tree: std::result::Result<String, String>,
    command: &str,
    environment: Option<&str>,
) -> Status {
    let tree = match tree {
        Ok(tree) => tree,
        Err(e) => {
            return Status::Unknown {
                record: Some(Box::new(record)),
                why: format!(
                    "the tree cannot be digested now ({e}), so whether the last baseline still describes it is unknown"
                ),
            };
        }
    };
    let mut moved = Vec::new();
    if record.tree != tree {
        moved.push(format!("the tree changed since (now {})", short(&tree)));
    }
    if record.environment.as_deref() != environment {
        let name =
            |key: Option<&str>| key.map_or_else(|| "none".to_owned(), |k| short(k).to_owned());
        moved.push(format!(
            "the prepared environment changed ({} → {})",
            name(record.environment.as_deref()),
            name(environment)
        ));
    }
    if record.command != command {
        moved.push(format!(
            "the verification command changed (`{}` → `{command}`)",
            record.command
        ));
    }
    if moved.is_empty() {
        Status::Current(Box::new(record))
    } else {
        Status::Stale {
            record: Box::new(record),
            why: moved.join("; "),
        }
    }
}

/// What [`run`] reports while it works, for a caller that shows progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The tree is being captured.
    Capturing,
    /// The command is running over the materialised tree.
    Running,
}

/// Run the accepted command once, offline, in the verifier's sandbox, over `dir`'s
/// current tree, and record the result as the project's baseline. Refuses — recording
/// nothing — when no command is accepted, and when a session is live whose worktree has
/// moved away from its entry snapshot (the baseline is the state before any agent
/// work). An error running the command is returned, never recorded as a red baseline.
pub fn run(state: &Path, dir: &Path, progress: &mut dyn FnMut(Step, &str)) -> Result<Record> {
    let config_path = dir.join(verify::CONFIG_PATH);
    let yaml = std::fs::read_to_string(&config_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::Project(format!(
                "{} not written yet; `ward init --accept-verify` accepts a verification command",
                verify::CONFIG_PATH
            ))
        } else {
            Error::io(&config_path, e)
        }
    })?;
    let config = verify::Config::parse(&yaml)?;
    if let Some(meta) = crate::session::SessionMeta::current(dir, state)? {
        let now =
            ward_snapshot::digest_worktree(dir, verify::candidate_options(), &mut HashCache::new())
                .map_err(|e| Error::Snapshot(e.to_string()))?;
        if now.to_string() != meta.entry_snapshot {
            return Err(Error::Project(format!(
                "session {} is live and the worktree has changed since its entry snapshot; a \
                 baseline is the tree before any agent work: run it before `ward up`, or after \
                 `ward stop --restore-entry`",
                meta.id
            )));
        }
    }
    crate::space::check(state, crate::space::min_free_bytes())?;
    progress(Step::Capturing, &config.verify.command);
    let store =
        SnapshotStore::open(state.join("cas")).map_err(|e| Error::Snapshot(e.to_string()))?;
    let entry = store
        .store_snapshot(dir, SnapshotRole::Entry, verify::candidate_options())
        .map_err(|e| Error::Snapshot(e.to_string()))?;
    let scratch_root = project_dir(state, dir).join("scratch");
    std::fs::create_dir_all(&scratch_root).map_err(|e| Error::io(&scratch_root, e))?;
    std::fs::set_permissions(&scratch_root, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::io(&scratch_root, e))?;
    let prepared = verify::prepare(&store, dir, entry, &scratch_root)?;
    let toolchains = verify::Toolchains::detect();
    let dependencies = prepare::lookup_in(
        state,
        &prepared.scratch,
        dir,
        &prepare::Settings::from_env(),
        &toolchains.search_dirs(),
    );
    let (mounted, note) = match &dependencies {
        prepare::Lookup::Ready(env) => {
            (Some(&**env), format!("{} mounted read-only", env.summary()))
        }
        prepare::Lookup::NotNeeded(why) => (None, format!("none to prepare: {why}")),
        prepare::Lookup::Missing { reason, .. } => (None, format!("not mounted: {reason}")),
        prepare::Lookup::Declined(why) | prepare::Lookup::Unavailable(why) => {
            (None, format!("not mounted: {why}"))
        }
    };
    progress(Step::Running, &config.verify.command);
    let outcome = verify::execute_with(&prepared, mounted);
    let _ = std::fs::remove_dir_all(&prepared.scratch);
    let outcome = outcome?;
    let canonical = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let record = Record::of(
        &canonical,
        &config.verify.command,
        config.verify.budget_secs,
        &prepared.candidate.to_string(),
        environment_key(&dependencies),
        note,
        &outcome,
    );
    save(state, dir, &record, &outcome.output)?;
    Ok(record)
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// A record of `command` over `tree`, red unless `passed`.
    pub(crate) fn record(
        tree: &str,
        environment: Option<&str>,
        command: &str,
        passed: bool,
    ) -> Record {
        let output = if passed {
            "running 2 tests\ntest result: ok. 2 passed; 0 failed\n".to_owned()
        } else {
            "running 2 tests\nassertion failed: parse(\"1\") == Some(1)\ntest result: FAILED. 1 passed; 1 failed\n".to_owned()
        };
        let outcome = verify::Outcome {
            passed,
            timed_out: false,
            summary: ward_events::VerifySummary {
                tests_run: 2,
                tests_failed: u64::from(!passed),
                duration: std::time::Duration::from_millis(1200),
                ..ward_events::VerifySummary::default()
            },
            result_hash: *blake3::hash(output.as_bytes()).as_bytes(),
            output_bytes: output.len() as u64,
            output_truncated: false,
            exit_code: Some(i32::from(!passed)),
            output,
        };
        Record::of(
            Path::new("/p"),
            command,
            600,
            tree,
            environment.map(str::to_owned),
            "none to prepare".to_owned(),
            &outcome,
        )
    }

    const TREE: &str = "blake3:1a2b3c4d5e6f00000000000000000000000000000000000000000000000000ff";
    const OTHER: &str = "blake3:9f8e7d6c5b4a00000000000000000000000000000000000000000000000000ff";

    #[test]
    fn a_record_says_how_the_command_ended_and_what_failed() {
        let red = record(TREE, None, "sh tests/run.sh", false);
        assert_eq!(red.color(), "red");
        assert_eq!(red.ending(), "exit 1");
        assert_eq!(red.counts().as_deref(), Some("1 of 2 tests failed"));
        assert_eq!(
            red.tail_lines(2),
            [
                "assertion failed: parse(\"1\") == Some(1)",
                "test result: FAILED. 1 passed; 1 failed"
            ]
        );
        assert_eq!(red.short_tree(), "1a2b3c4d5e6f");
        let green = record(TREE, None, "sh tests/run.sh", true);
        assert_eq!(green.color(), "green");
        assert_eq!(green.ending(), "exit 0");
        assert_eq!(green.counts().as_deref(), Some("2 tests passed"));

        let mut killed = red.clone();
        killed.timed_out = true;
        killed.exit_code = None;
        assert_eq!(killed.ending(), "killed at its 600 s budget");
        killed.timed_out = false;
        assert_eq!(killed.ending(), "killed by a signal");
        killed.tests_run = 0;
        assert_eq!(killed.counts(), None);
    }

    #[test]
    fn the_tail_is_bounded_and_marked() {
        let long = "x".repeat(OUTPUT_TAIL_BYTES * 2);
        let cut = tail(&long);
        assert!(cut.starts_with("[…"), "{}", &cut[..20]);
        assert!(cut.len() < OUTPUT_TAIL_BYTES + 64);
        assert_eq!(tail("short"), "short");
    }

    #[test]
    fn a_record_round_trips_and_an_unknown_version_is_refused() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(state.path(), dir.path()).unwrap(), None);
        let rec = record(TREE, Some("ab"), "sh tests/run.sh", false);
        save(state.path(), dir.path(), &rec, "the whole output\n").unwrap();
        assert_eq!(load(state.path(), dir.path()).unwrap(), Some(rec.clone()));
        let root = project_dir(state.path(), dir.path());
        assert_eq!(
            std::fs::read_to_string(root.join(OUTPUT_FILE)).unwrap(),
            "the whole output\n"
        );
        let json = std::fs::read_to_string(root.join(RECORD_FILE))
            .unwrap()
            .replace("\"version\": 1", "\"version\": 9");
        std::fs::write(root.join(RECORD_FILE), json).unwrap();
        assert!(load(state.path(), dir.path()).is_err());
        assert!(matches!(
            status(state.path(), dir.path(), "sh tests/run.sh", None),
            Status::Unknown { record: None, .. }
        ));
    }

    #[test]
    fn a_record_is_current_only_while_tree_environment_and_command_all_match() {
        let cmd = "sh tests/run.sh";
        let red = record(TREE, Some("aa11"), cmd, false);
        let current = judge(red.clone(), Ok(TREE.to_owned()), cmd, Some("aa11"));
        assert!(current.is_failing(), "{current:?}");

        let Status::Stale { why, .. } = judge(red.clone(), Ok(OTHER.to_owned()), cmd, Some("aa11"))
        else {
            panic!("a changed tree is stale");
        };
        assert!(why.contains("tree changed"), "{why}");
        assert!(why.contains("9f8e7d6c5b4a"), "{why}");

        let Status::Stale { why, .. } = judge(red.clone(), Ok(TREE.to_owned()), cmd, Some("bb22"))
        else {
            panic!("a changed environment is stale");
        };
        assert!(
            why.contains("prepared environment changed (aa11 → bb22)"),
            "{why}"
        );

        let Status::Stale { why, .. } = judge(red.clone(), Ok(TREE.to_owned()), cmd, None) else {
            panic!("an environment no longer needed is a change too");
        };
        assert!(why.contains("aa11 → none"), "{why}");

        let Status::Stale { why, .. } =
            judge(red.clone(), Ok(TREE.to_owned()), "make test", Some("aa11"))
        else {
            panic!("a changed command is stale");
        };
        assert!(why.contains("verification command changed"), "{why}");

        let stale = judge(red.clone(), Ok(OTHER.to_owned()), cmd, Some("aa11"));
        assert!(
            !stale.is_failing(),
            "a stale red baseline is history, not a verdict"
        );

        let unknown = judge(red, Err("permission denied".to_owned()), cmd, Some("aa11"));
        assert!(matches!(
            unknown,
            Status::Unknown {
                record: Some(_),
                ..
            }
        ));
        assert!(!unknown.is_failing());

        let green = judge(
            record(TREE, None, cmd, true),
            Ok(TREE.to_owned()),
            cmd,
            None,
        );
        assert!(matches!(green, Status::Current(_)));
        assert!(!green.is_failing());
    }

    #[test]
    fn status_digests_the_tree_with_the_verifiers_capture_options() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "a\n").unwrap();
        let cmd = "sh tests/run.sh";
        assert_eq!(status(state.path(), dir.path(), cmd, None), Status::NotRun);
        let tree = ward_snapshot::digest_worktree(
            dir.path(),
            verify::candidate_options(),
            &mut HashCache::new(),
        )
        .unwrap()
        .to_string();
        save(
            state.path(),
            dir.path(),
            &record(&tree, None, cmd, false),
            "",
        )
        .unwrap();
        assert!(status(state.path(), dir.path(), cmd, None).is_failing());
        std::fs::write(dir.path().join("a.txt"), "b\n").unwrap();
        assert!(matches!(
            status(state.path(), dir.path(), cmd, None),
            Status::Stale { .. }
        ));
    }

    #[test]
    fn the_environment_key_is_the_one_prepare_would_use() {
        assert_eq!(
            environment_key(&prepare::Lookup::NotNeeded("cargo".into())),
            None
        );
        assert_eq!(
            environment_key(&prepare::Lookup::Declined("x".into())),
            None
        );
        assert_eq!(
            environment_key(&prepare::Lookup::Unavailable("x".into())),
            None
        );
        let key = prepare::Key::parse(&"ab".repeat(32)).unwrap();
        assert_eq!(
            environment_key(&prepare::Lookup::Missing {
                ecosystem: prepare::Ecosystem::NodeNpm,
                key,
                reason: String::new(),
            }),
            Some("ab".repeat(32))
        );
    }

    #[test]
    fn run_refuses_without_an_accepted_command_and_records_nothing() {
        let state = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let err = run(state.path(), dir.path(), &mut |_, _| {}).unwrap_err();
        assert!(
            err.to_string().contains("ward init --accept-verify"),
            "{err}"
        );
        std::fs::create_dir_all(dir.path().join(".tamperward")).unwrap();
        std::fs::write(
            dir.path().join(verify::CONFIG_PATH),
            "verify:\n  command: \"\"\n",
        )
        .unwrap();
        assert!(run(state.path(), dir.path(), &mut |_, _| {}).is_err());
        assert_eq!(load(state.path(), dir.path()).unwrap(), None);
    }
}
