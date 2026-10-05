//! Runs the built `ward` binary against small fixtures and checks the last two parts of
//! #147: the "baseline failing" verdict (item 5) and the four E-14 answers (item 7).
//!
//! `ward ready --baseline` runs the accepted verification command once, offline, in the
//! verifier's own sandbox, over the project's current tree (the entry state, before any
//! agent work), and records the result under the state root keyed by the tree digest and
//! the prepared environment key. A red baseline is "ready, baseline failing" — the
//! environment is ready and the project's own tests are red — never "setup required";
//! a later plain `ward ready` shows the recorded baseline without running anything, and
//! says it is stale once the tree, the prepared environment or the command changes.
//!
//! `ward ready --answers` answers the four E-14 questions from what was recorded (the
//! session's capability manifest and grants, its credential grants, its entry snapshot
//! against the worktree, its last verification), each with its source, and says
//! "unknown" when there is no record to answer from.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};

const BIN: &str = env!("CARGO_BIN_EXE_ward");

/// Writing an executable and spawning a process are never concurrent across
/// the tests of this process: a fork in one test while another's copy of
/// `ward` or fake tool is still open for writing fails that other's `exec`
/// with `ETXTBSY`.
static FORK: Mutex<()> = Mutex::new(());

fn fork_lock() -> MutexGuard<'static, ()> {
    FORK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The sandbox is a prerequisite of every baseline and session test here;
/// `WARD_REQUIRE_ISOLATION` turns a skip into a failure, as in the daemon's own suite.
fn sandbox_ready() -> bool {
    ward_sandbox::ci::isolation_ready(ward_daemon::sandbox::available(), "bubblewrap")
}

const GREEN: &str =
    "#!/bin/sh\necho 'running 2 tests'\necho 'test result: ok. 2 passed; 0 failed'\n";
const RED: &str = "#!/bin/sh\necho 'running 2 tests'\necho 'thread parse panicked: assertion failed: parse(\"1\") == Some(1)'\necho 'test result: FAILED. 1 passed; 1 failed'\nexit 1\n";

struct Fixture {
    dir: tempfile::TempDir,
    state: tempfile::TempDir,
    /// A copy of `ward` with no `wardd` beside it, so a session stays in this process
    /// (deterministic, and nothing outlives the test).
    bin: PathBuf,
    _bin_dir: tempfile::TempDir,
}

impl Fixture {
    fn new(files: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        for (rel, content) in files {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        let state = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(state.path().join("cargo/bin")).unwrap();
        let bin_dir = tempfile::tempdir().unwrap();
        let bin = bin_dir.path().join("ward");
        {
            let _fork = fork_lock();
            std::fs::copy(BIN, &bin).unwrap();
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self {
            dir,
            state,
            bin,
            _bin_dir: bin_dir,
        }
    }

    /// A project whose accepted verification command is `sh tests/run.sh`.
    fn project(run_sh: &str) -> Self {
        Self::new(&[
            (".ward/policy.yaml", ward_policy::Policy::template()),
            (
                ".tamperward/config.yml",
                "protected:\n  tests:\n    - tests/\nverify:\n  command: sh tests/run.sh\n",
            ),
            ("tests/run.sh", run_sh),
            ("src/parse.txt", "fn parse\n"),
        ])
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn write(&self, rel: &str, content: &str) {
        std::fs::write(self.path().join(rel), content).unwrap();
    }

    /// Place a fake tool where the verifier looks (`$CARGO_HOME/bin`).
    fn tool(&self, name: &str, script: &str) {
        let path = self.state.path().join("cargo/bin").join(name);
        let _fork = fork_lock();
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// `ward <args…> <project>`.
    fn ward(&self, args: &[&str]) -> Output {
        let mut all: Vec<&str> = args.to_vec();
        let dir = self.path().to_str().unwrap();
        all.push(dir);
        self.raw(&all)
    }

    /// `ward <args…>` exactly as given.
    fn raw(&self, args: &[&str]) -> Output {
        let child = {
            let _fork = fork_lock();
            Command::new(&self.bin)
                .args(args)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", self.state.path())
                .env("WARD_STATE_DIR", self.state.path())
                .env("CARGO_HOME", self.state.path().join("cargo"))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        };
        child.wait_with_output().unwrap()
    }

    /// Every baseline record under the state root.
    fn baseline_records(&self) -> Vec<PathBuf> {
        let root = self.state.path().join("readiness");
        let Ok(entries) = std::fs::read_dir(&root) else {
            return Vec::new();
        };
        let mut out: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path().join("baseline.json"))
            .filter(|p| p.is_file())
            .collect();
        out.sort();
        out
    }

    fn record(&self) -> serde_json::Value {
        let records = self.baseline_records();
        assert_eq!(records.len(), 1, "{records:?}");
        serde_json::from_slice(&std::fs::read(&records[0]).unwrap()).unwrap()
    }

    fn tree(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut out = BTreeMap::new();
        let mut pending = vec![self.path().to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let bytes = std::fs::read(&path).unwrap();
                    out.insert(path.strip_prefix(self.path()).unwrap().to_path_buf(), bytes);
                }
            }
        }
        out
    }
}

/// Both streams, with the panel's ANSI colour sequences removed.
fn text(output: &Output) -> String {
    let raw = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            for d in chars.by_ref() {
                if d == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn row<'a>(report: &'a str, name: &str) -> &'a str {
    report
        .lines()
        .find(|l| l.trim_start().starts_with(name))
        .unwrap_or_else(|| panic!("no `{name}` row in:\n{report}"))
}

fn overall(report: &str) -> &str {
    row(report, "Overall")
}

#[test]
fn a_green_baseline_is_recorded_and_a_later_ready_shows_it_without_running_it() {
    if !sandbox_ready() {
        return;
    }
    let f = Fixture::project(GREEN);

    // Never on a plain `ward ready`: the row says how to run it, and nothing is recorded.
    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    assert!(ready.status.success(), "{out}");
    let line = row(&out, "baseline");
    assert!(line.contains("not run"), "{line}");
    assert!(line.contains("ward ready --baseline"), "{line}");
    assert!(!out.contains("baseline failing"), "{out}");
    assert!(
        f.baseline_records().is_empty(),
        "a plain `ward ready` runs nothing"
    );

    // The explicit run: offline, in the verifier's sandbox, over the current tree.
    let before = f.tree();
    let run = f.ward(&["ready", "--baseline"]);
    let out = text(&run);
    assert!(run.status.success(), "{out}");
    let line = row(&out, "baseline");
    assert!(line.contains("green"), "{line}");
    assert!(line.contains("exit 0"), "{line}");
    assert!(!overall(&out).contains("baseline failing"), "{out}");
    assert_eq!(
        f.tree(),
        before,
        "the baseline never writes into the project"
    );

    let rec = f.record();
    assert_eq!(rec["passed"], true, "{rec}");
    assert_eq!(rec["exit_code"], 0, "{rec}");
    assert_eq!(rec["command"], "sh tests/run.sh", "{rec}");
    assert!(
        rec["tree"].as_str().unwrap().starts_with("blake3:"),
        "keyed by the tree digest: {rec}"
    );
    assert!(
        rec["environment"].is_null(),
        "no prepared environment is needed here: {rec}"
    );
    assert_eq!(rec["tests_run"], 2, "{rec}");

    // A later `ward ready` shows the recorded baseline as current and runs nothing.
    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    assert!(ready.status.success(), "{out}");
    let line = row(&out, "baseline");
    assert!(line.contains("green"), "{line}");
    assert!(!line.contains("stale"), "{line}");
    assert_eq!(
        f.record(),
        rec,
        "a plain `ward ready` never re-runs the baseline"
    );
}

#[test]
fn a_red_baseline_is_ready_with_a_red_baseline_never_setup_required() {
    if !sandbox_ready() {
        return;
    }
    let f = Fixture::project(RED);
    let run = f.ward(&["ready", "--baseline"]);
    let out = text(&run);
    // A pre-existing failing test is not an installation failure: it does not block.
    assert!(run.status.success(), "{out}");
    assert!(!out.contains("setup required"), "{out}");
    assert!(overall(&out).contains("baseline failing"), "{out}");
    assert!(out.contains("environment is ready"), "{out}");
    let line = row(&out, "baseline");
    assert!(line.contains("exit 1"), "{line}");
    assert!(line.contains("1 of 2"), "the counts are named: {line}");
    assert!(
        out.contains("assertion failed: parse(\"1\") == Some(1)"),
        "the tail of the recorded output is shown: {out}"
    );

    let rec = f.record();
    assert_eq!(rec["passed"], false, "{rec}");
    assert_eq!(rec["exit_code"], 1, "{rec}");
    assert_eq!(rec["tests_failed"], 1, "{rec}");
    assert!(
        rec["output_tail"]
            .as_str()
            .unwrap()
            .contains("assertion failed"),
        "{rec}"
    );

    // A later plain `ward ready` reports the same verdict from the record.
    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    assert!(ready.status.success(), "{out}");
    assert!(overall(&out).contains("baseline failing"), "{out}");
    assert!(!out.contains("setup required"), "{out}");
    assert!(out.contains("assertion failed"), "{out}");
}

#[test]
fn a_baseline_goes_stale_when_the_tree_changes_and_runs_again_on_request() {
    if !sandbox_ready() {
        return;
    }
    let f = Fixture::project(RED);
    let run = f.ward(&["ready", "--baseline"]);
    assert!(run.status.success(), "{}", text(&run));

    // The tree changes (the failing test is fixed): the red record no longer describes it.
    f.write("tests/run.sh", GREEN);
    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    assert!(ready.status.success(), "{out}");
    let line = row(&out, "baseline");
    assert!(line.contains("stale"), "{line}");
    assert!(line.contains("tree changed"), "{line}");
    assert!(
        line.contains("red"),
        "the stale record still says what it was: {line}"
    );
    assert!(line.contains("ward ready --baseline"), "{line}");
    assert!(
        !overall(&out).contains("baseline failing"),
        "a stale red baseline is history, not a verdict on this tree: {out}"
    );

    let again = f.ward(&["ready", "--baseline"]);
    let out = text(&again);
    assert!(again.status.success(), "{out}");
    let line = row(&out, "baseline");
    assert!(line.contains("green"), "{line}");
    assert!(!line.contains("stale"), "{line}");
    assert_eq!(f.record()["passed"], true);
}

#[test]
fn the_baseline_is_not_run_while_setup_is_required() {
    if !sandbox_ready() {
        return;
    }
    let f = Fixture::new(&[
        (".ward/policy.yaml", ward_policy::Policy::template()),
        (
            ".tamperward/config.yml",
            "protected:\n  tests:\n    - tests/\nverify:\n  command: no-such-runner --all\n",
        ),
        ("tests/run.sh", GREEN),
    ]);
    let run = f.ward(&["ready", "--baseline"]);
    let out = text(&run);
    assert!(!run.status.success(), "{out}");
    assert!(out.contains("setup required"), "{out}");
    assert!(out.contains("baseline not run"), "{out}");
    assert!(
        f.baseline_records().is_empty(),
        "nothing is recorded for a run that did not happen"
    );

    // Without an accepted command there is nothing to run either.
    let bare = Fixture::new(&[("src/a.txt", "a\n")]);
    let run = bare.ward(&["ready", "--baseline"]);
    let out = text(&run);
    assert!(!run.status.success(), "{out}");
    assert!(out.contains("baseline not run"), "{out}");
    assert!(bare.baseline_records().is_empty());
}

const FAKE_NODE_V1: &str =
    "#!/bin/sh\ncase \"$1\" in --version) echo \"v22.0.0-fake\";; *) exit 2;; esac\n";
const FAKE_NODE_V2: &str =
    "#!/bin/sh\ncase \"$1\" in --version) echo \"v24.0.0-fake\";; *) exit 2;; esac\n";
/// `ci` installs one package; `test` fails one test when it is there (a real, red
/// baseline with every dependency prepared) and cannot run at all without it.
const FAKE_NPM: &str = r#"#!/bin/sh
case "$1" in
  ci)
    mkdir -p node_modules/left-pad
    echo "module.exports = 1" > node_modules/left-pad/index.js
    echo "added 1 package"
    ;;
  test)
    [ -f node_modules/left-pad/index.js ] || { echo "Cannot find module 'left-pad'"; exit 2; }
    echo "FAIL test/app.test.js: expected 2, received 1"
    echo "test result: FAILED. 0 passed; 1 failed"
    exit 1
    ;;
  *) exit 2;;
esac
"#;

#[test]
fn the_baseline_is_keyed_by_the_prepared_environment_and_goes_stale_with_it() {
    if !sandbox_ready() {
        return;
    }
    let f = Fixture::new(&[
        (".ward/policy.yaml", ward_policy::Policy::template()),
        (
            ".tamperward/config.yml",
            "protected:\n  tests:\n    - test/\nverify:\n  command: npm test\n",
        ),
        (
            "package.json",
            r#"{"name":"app","version":"1.0.0","scripts":{"test":"node test/app.test.js"}}"#,
        ),
        (
            "package-lock.json",
            r#"{"name":"app","lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}"#,
        ),
        ("test/app.test.js", "// a test\n"),
    ]);
    f.tool("node", FAKE_NODE_V1);
    f.tool("npm", FAKE_NPM);

    // Dependencies not prepared: setup is required, so no baseline runs over it.
    let run = f.ward(&["ready", "--baseline"]);
    let out = text(&run);
    assert!(!run.status.success(), "{out}");
    assert!(out.contains("baseline not run"), "{out}");
    assert!(f.baseline_records().is_empty());

    let prepare = f.ward(&["prepare"]);
    assert!(prepare.status.success(), "{}", text(&prepare));

    // Prepared: the red baseline is the project's own, with its environment mounted.
    let run = f.ward(&["ready", "--baseline"]);
    let out = text(&run);
    assert!(run.status.success(), "{out}");
    assert!(overall(&out).contains("baseline failing"), "{out}");
    assert!(out.contains("expected 2, received 1"), "{out}");
    assert!(!out.contains("Cannot find module"), "{out}");
    let rec = f.record();
    let key = rec["environment"].as_str().unwrap().to_owned();
    assert_eq!(key.len(), 64, "the prepared environment key: {rec}");
    let envs: Vec<String> = std::fs::read_dir(f.state.path().join("prepared"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(envs.contains(&key), "{key} not in {envs:?}");

    // The runtime changes: a different environment key, so the baseline is stale too.
    f.tool("node", FAKE_NODE_V2);
    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    let line = row(&out, "baseline");
    assert!(line.contains("stale"), "{line}");
    assert!(line.contains("prepared environment changed"), "{line}");
    assert!(
        overall(&out).contains("setup required"),
        "the stale environment itself is what blocks: {out}"
    );
}

fn answers(f: &Fixture) -> serde_json::Value {
    let out = f.ward(&["ready", "--answers", "--json"]);
    assert!(out.status.success(), "{}", text(&out));
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&out)))
}

fn answer<'a>(all: &'a serde_json::Value, key: &str) -> &'a serde_json::Value {
    all["answers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["key"] == key)
        .unwrap_or_else(|| panic!("no `{key}` answer in {all}"))
}

#[test]
fn the_four_answers_say_unknown_without_a_session() {
    let f = Fixture::project(GREEN);
    let plain = f.ward(&["ready", "--answers"]);
    let out = text(&plain);
    assert!(plain.status.success(), "{out}");
    for question in [
        "What can the agent reach",
        "Which credentials can it use",
        "What did it change",
        "Is the current candidate verified",
    ] {
        assert!(out.contains(question), "{question} missing from:\n{out}");
    }
    assert!(out.contains("unknown"), "{out}");
    assert!(
        out.contains("source"),
        "every answer names its source: {out}"
    );

    let all = answers(&f);
    assert!(all["session"].is_null(), "{all}");
    let keys: Vec<&str> = all["answers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["key"].as_str().unwrap())
        .collect();
    assert_eq!(keys, ["reach", "credentials", "changed", "verified"]);
    for key in keys {
        let a = answer(&all, key);
        assert_eq!(a["known"], false, "nothing recorded, nothing guessed: {a}");
        assert!(a["answer"].as_str().unwrap().starts_with("unknown"), "{a}");
        assert!(!a["source"].as_str().unwrap().is_empty(), "{a}");
    }
}

#[test]
fn the_four_answers_come_from_the_sessions_records() {
    if !sandbox_ready() {
        return;
    }
    let f = Fixture::project(GREEN);
    let dir = f.path().to_str().unwrap().to_owned();
    let up = f.ward(&["up"]);
    assert!(up.status.success(), "{}", text(&up));
    let run = f.raw(&[
        "run",
        "--dir",
        &dir,
        "--",
        "/bin/sh",
        "-c",
        "echo new > src/added.txt && echo changed > src/parse.txt",
    ]);
    assert!(run.status.success(), "{}", text(&run));

    let all = answers(&f);
    let session = all["session"]["id"].as_str().unwrap().to_owned();
    assert!(session.starts_with("sess_"), "{all}");
    assert_eq!(all["session"]["live"], true, "{all}");

    let reach = answer(&all, "reach");
    assert_eq!(reach["known"], true, "{reach}");
    assert!(
        reach["answer"].as_str().unwrap().contains("/work"),
        "{reach}"
    );
    assert!(
        reach["source"].as_str().unwrap().contains(&session),
        "{reach}"
    );

    let creds = answer(&all, "credentials");
    assert_eq!(creds["known"], true, "{creds}");
    assert!(
        creds["answer"].as_str().unwrap().starts_with("none"),
        "no credential was granted in this session: {creds}"
    );

    let changed = answer(&all, "changed");
    assert_eq!(changed["known"], true, "{changed}");
    let details = changed["details"].to_string();
    assert!(details.contains("src/added.txt"), "{changed}");
    assert!(details.contains("src/parse.txt"), "{changed}");
    assert!(
        changed["source"]
            .as_str()
            .unwrap()
            .contains("entry snapshot"),
        "{changed}"
    );

    let verified = answer(&all, "verified");
    assert_eq!(verified["known"], true, "{verified}");
    assert!(
        verified["answer"].as_str().unwrap().starts_with("no"),
        "nothing verified yet: {verified}"
    );

    // Verified: the current candidate passed.
    let verify = f.ward(&["verify"]);
    assert!(verify.status.success(), "{}", text(&verify));
    let all = answers(&f);
    let verified = answer(&all, "verified");
    assert!(
        verified["answer"].as_str().unwrap().starts_with("yes"),
        "{verified}"
    );

    // An edit afterwards: the verdict is history, not a description of the tree.
    f.write("src/parse.txt", "edited after verify\n");
    let all = answers(&f);
    let verified = answer(&all, "verified");
    let text_of = verified["answer"].as_str().unwrap();
    assert!(text_of.starts_with("no"), "{verified}");
    assert!(text_of.contains("changed since"), "{verified}");

    // The plain form names all four, with their sources.
    let plain = f.ward(&["ready", "--answers"]);
    let out = text(&plain);
    assert!(plain.status.success(), "{out}");
    assert!(out.contains(&session), "{out}");
    assert!(out.contains("src/added.txt"), "{out}");

    // After the session ends, the answers still come from its sealed log.
    let stop = f.ward(&["stop"]);
    assert!(stop.status.success(), "{}", text(&stop));
    let all = answers(&f);
    assert_eq!(all["session"]["id"], session.as_str(), "{all}");
    assert_eq!(all["session"]["live"], false, "{all}");
    assert_eq!(answer(&all, "changed")["known"], true);
}
