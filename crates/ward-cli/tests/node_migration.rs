//! #278 through the real binaries: a per-session installation (a sealed session log with
//! its project policy, a pinned snapshot) migrates into local node mode with nothing lost,
//! a session then runs and seals through the local node, a migration that fails midway
//! leaves the prior state byte-identical and a re-run succeeds, and a rollback restores
//! per-session mode (ADR-0040).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ward");

/// A project policy the node enforces exactly as a session would.
const RUNNABLE_POLICY: &str =
    "network: offline\ncredentials:\n  github: deny\n  ssh-signing: deny\n";

fn sandbox_ready() -> bool {
    ward_sandbox::ci::isolation_ready(ward_daemon::sandbox::available(), "bubblewrap")
}

/// `ward-node` built from this checkout: `WARD_NODE_BIN` when set, otherwise a build into
/// `<target>/node-shipped`, the directory the node client's acceptance tests use.
fn ward_node_dir() -> PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        if let Some(binary) = std::env::var_os("WARD_NODE_BIN") {
            return PathBuf::from(binary).parent().unwrap().to_path_buf();
        }
        let exe = std::env::current_exe().unwrap();
        let profile_dir = exe.parent().unwrap().parent().unwrap();
        let profile = profile_dir.file_name().unwrap();
        let target = profile_dir.parent().unwrap().join("node-shipped");
        let mut build = Command::new(env!("CARGO"));
        build
            .args([
                "build",
                "-p",
                "ward-node",
                "--bin",
                "ward-node",
                "--target-dir",
            ])
            .arg(&target);
        if profile == "release" {
            build.arg("--release");
        }
        assert!(
            build.status().unwrap().success(),
            "building ward-node failed"
        );
        target.join(profile)
    })
    .clone()
}

struct Installation {
    root: tempfile::TempDir,
    state: PathBuf,
    project: PathBuf,
    pinned: String,
}

impl Installation {
    /// A per-session installation: a project with a runnable policy, one sealed session
    /// over it, and that session's entry snapshot pinned with `ward snapshot keep`; the
    /// project's file then changes, so the pinned snapshot is the only copy of the old one.
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let project = root.path().join("project");
        std::fs::create_dir_all(project.join(".ward")).unwrap();
        std::fs::create_dir_all(root.path().join("home")).unwrap();
        std::fs::write(project.join(".ward/policy.yaml"), RUNNABLE_POLICY).unwrap();
        std::fs::write(project.join("input.txt"), "carried\n").unwrap();
        let installation = Self {
            root,
            state,
            project,
            pinned: String::new(),
        };
        installation.ok(&["up", installation.project.to_str().unwrap()]);
        installation.ok(&["stop", installation.project.to_str().unwrap()]);
        let session = only_entry(&installation.state.join("sessions"));
        let meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(session.join("session.json")).unwrap()).unwrap();
        let entry = meta["entry_snapshot"].as_str().unwrap().to_owned();
        installation.ok(&["snapshot", "keep", &entry]);
        std::fs::write(installation.project.join("input.txt"), "changed\n").unwrap();
        Self {
            pinned: entry.trim_start_matches("blake3:").to_owned(),
            ..installation
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(BIN);
        command
            .args(args)
            .env("WARD_STATE_DIR", &self.state)
            .env("HOME", self.root.path().join("home"))
            .env_remove("WARD_NODE_SOCKET")
            .stdin(Stdio::null());
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> Output {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "ward {args:?} failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn sealed_logs(&self) -> Vec<PathBuf> {
        let mut logs: Vec<PathBuf> = std::fs::read_dir(self.state.join("sessions"))
            .unwrap()
            .map(|entry| entry.unwrap().path().join("events.log"))
            .filter(|log| log.exists())
            .collect();
        logs.sort();
        logs
    }

    fn mode(&self) -> String {
        stdout(&self.ok(&["node", "status"]))
            .lines()
            .next()
            .unwrap()
            .to_owned()
    }

    fn socket(&self) -> PathBuf {
        self.state.join("node/node.sock")
    }

    /// `ward node serve`, once its socket answers.
    fn serve(&self) -> Served {
        let path = std::env::join_paths(std::iter::once(ward_node_dir()).chain(
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
        ))
        .unwrap();
        let mut child = self
            .command(&["node", "serve"])
            .env("PATH", path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while UnixStream::connect(self.socket()).is_err() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "ward node serve exited"
            );
            assert!(Instant::now() < deadline, "the local node never served");
            std::thread::sleep(Duration::from_millis(20));
        }
        Served(child)
    }
}

struct Served(Child);

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn only_entry(dir: &Path) -> PathBuf {
    let entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1, "{entries:?}");
    entries.into_iter().next().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Every file under `root` with its bytes, and every directory and socket, by relative
/// path.
fn tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(root).unwrap().to_path_buf();
            let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
            if kind.is_dir() {
                out.insert(rel, b"<dir>".to_vec());
                stack.push(path);
            } else if kind.is_file() {
                out.insert(rel, std::fs::read(&path).unwrap());
            } else {
                out.insert(rel, b"<special>".to_vec());
            }
        }
    }
    out
}

fn without(mut tree: BTreeMap<PathBuf, Vec<u8>>, prefix: &str) -> BTreeMap<PathBuf, Vec<u8>> {
    tree.retain(|path, _| !path.to_string_lossy().starts_with(prefix));
    tree
}

/// The evidence log `ward run --via-node` names on stderr.
fn evidence_log(output: &Output) -> PathBuf {
    let text = stderr(output);
    let line = text
        .lines()
        .find_map(|line| line.strip_prefix("ward: evidence "))
        .unwrap_or_else(|| panic!("no evidence line in {text}"));
    PathBuf::from(line.split(" (sealed ").next().unwrap())
}

/// With the local node serving: a session runs over a fresh snapshot and seals, the
/// migrated snapshot runs as it was pinned, a failing command fails, a policy the node
/// cannot enforce is refused by name, and a rollback is refused while the node serves.
fn sessions_run_and_seal_on_the_node(home: &Installation) {
    let _node = home.serve();
    let fresh = home.ok(&[
        "run",
        "--via-node",
        "--dir",
        home.project.to_str().unwrap(),
        "--",
        "cat",
        "input.txt",
    ]);
    assert_eq!(stdout(&fresh), "changed\n");
    assert!(stderr(&fresh).contains(" completed"), "{}", stderr(&fresh));
    let attempt = evidence_log(&fresh);
    assert!(attempt.starts_with(home.state.join("node/tasks")));
    let verified = home.ok(&["replay", "--verify", attempt.to_str().unwrap()]);
    assert!(
        stdout(&verified).contains("sealed head:"),
        "{}",
        stdout(&verified)
    );

    let pinned = home.ok(&[
        "run",
        "--via-node",
        "--dir",
        home.project.to_str().unwrap(),
        "--snapshot",
        &home.pinned,
        "--",
        "cat",
        "input.txt",
    ]);
    assert_eq!(
        stdout(&pinned),
        "carried\n",
        "the migrated snapshot did not run"
    );

    let failing = home.run(&[
        "run",
        "--via-node",
        "--dir",
        home.project.to_str().unwrap(),
        "--",
        "sh",
        "-c",
        "exit 3",
    ]);
    assert!(!failing.status.success());
    assert!(stderr(&failing).contains(" failed"), "{}", stderr(&failing));

    let unenforceable = home.root.path().join("default-policy");
    std::fs::create_dir(&unenforceable).unwrap();
    let refused = home.run(&[
        "run",
        "--via-node",
        "--dir",
        unenforceable.to_str().unwrap(),
        "--",
        "true",
    ]);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("credentials.github: ask"),
        "{}",
        stderr(&refused)
    );
    assert!(
        stderr(&refused).contains("nothing ran"),
        "{}",
        stderr(&refused)
    );

    let busy = home.run(&["node", "migrate", "--rollback"]);
    assert!(!busy.status.success());
    assert!(stderr(&busy).contains("serving"), "{}", stderr(&busy));
}

#[test]
fn an_installation_migrates_with_nothing_lost_and_a_session_then_runs_and_seals_on_the_node() {
    if !sandbox_ready() {
        return;
    }
    let home = Installation::new();
    home.ok(&[
        "run",
        "--dir",
        home.project.to_str().unwrap(),
        "--",
        "cat",
        "input.txt",
    ]);
    let logs = home.sealed_logs();
    assert_eq!(logs.len(), 2);
    let before = tree(&home.state);

    let dry = home.ok(&["node", "migrate", "--dry-run"]);
    assert!(stdout(&dry).contains("nothing was written"));
    assert!(stdout(&dry).contains(&home.pinned), "{}", stdout(&dry));
    assert!(stdout(&dry).contains("policy.yaml"), "{}", stdout(&dry));
    assert_eq!(tree(&home.state), before, "a dry run wrote to the state");
    assert_eq!(home.mode(), "mode      per-session");

    home.ok(&["node", "migrate"]);
    assert_eq!(home.mode(), "mode      local-node");
    assert_eq!(
        without(tree(&home.state), "node"),
        before,
        "the migration changed the session tree"
    );
    for log in &logs {
        let verified = home.ok(&["replay", "--verify", log.to_str().unwrap()]);
        assert!(
            stdout(&verified).contains("VERIFIED"),
            "{}",
            stdout(&verified)
        );
    }
    let manifest =
        |cas: &str| std::fs::read(home.state.join(cas).join("manifests").join(&home.pinned));
    assert_eq!(
        manifest("node/state/cas").unwrap(),
        manifest("cas").unwrap(),
        "the pinned snapshot's manifest differs in the node's store"
    );
    let status = home.ok(&["node", "status"]);
    assert_eq!(
        stdout(&status).matches("  ok    ").count(),
        5,
        "{}",
        stdout(&status)
    );

    sessions_run_and_seal_on_the_node(&home);

    let rolled = home.ok(&["node", "migrate", "--rollback"]);
    assert!(stdout(&rolled).contains("kept at"), "{}", stdout(&rolled));
    assert_eq!(home.mode(), "mode      per-session");
    assert_eq!(without(tree(&home.state), "node.rolled-back-"), before);
    let refused = home.run(&["run", "--via-node", "--", "true"]);
    assert!(
        stderr(&refused).contains("not in local node mode"),
        "{}",
        stderr(&refused)
    );
}

#[test]
fn a_migration_failing_midway_leaves_the_prior_state_byte_identical_and_rollback_restores_it() {
    let home = Installation::new();
    let blobs = home.state.join("cas/blobs");
    let blob = std::fs::read_dir(&blobs)
        .unwrap()
        .flat_map(|shard| std::fs::read_dir(shard.unwrap().path()).unwrap())
        .map(|entry| entry.unwrap().path())
        .find(|path| std::fs::read(path).unwrap() == b"carried\n")
        .expect("the pinned snapshot's blob");
    let mode = std::fs::metadata(&blob).unwrap().permissions();
    std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&blob, b"tampered\n").unwrap();
    std::fs::set_permissions(&blob, mode.clone()).unwrap();

    let damaged = tree(&home.state);
    let failed = home.run(&["node", "migrate"]);
    assert!(!failed.status.success());
    assert!(
        stderr(&failed).contains(&format!("snapshot {}", home.pinned)),
        "{}",
        stderr(&failed)
    );
    assert_eq!(
        tree(&home.state),
        damaged,
        "a failed migration changed the state"
    );
    assert_eq!(home.mode(), "mode      per-session");

    std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&blob, b"carried\n").unwrap();
    std::fs::set_permissions(&blob, mode).unwrap();
    let before = tree(&home.state);
    home.ok(&["node", "migrate"]);
    assert_eq!(home.mode(), "mode      local-node");
    let again = home.run(&["node", "migrate"]);
    assert!(!again.status.success());
    assert!(
        stderr(&again).contains("already in local node mode"),
        "{}",
        stderr(&again)
    );

    let rolled = home.ok(&["node", "migrate", "--rollback"]);
    assert!(stdout(&rolled).contains("removed"), "{}", stdout(&rolled));
    assert_eq!(home.mode(), "mode      per-session");
    assert_eq!(
        tree(&home.state),
        before,
        "the rollback did not restore the prior state"
    );
}
