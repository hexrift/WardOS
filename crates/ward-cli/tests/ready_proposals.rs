//! Runs the built `ward` binary against small project fixtures and checks #147 item 2:
//! `ward init` proposes the verification boundary from lockfiles and test configuration
//! and writes it only when accepted, `ward ready` reports an unaccepted proposal as
//! setup required with the proposal shown, and `ward ready --propose` re-prints it
//! without changing a byte of the project.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_ward");

struct Fixture {
    dir: tempfile::TempDir,
    state: tempfile::TempDir,
}

impl Fixture {
    fn new(files: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        for (rel, content) in files {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        Self {
            dir,
            state: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn ward(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .arg(self.path())
            .env_clear()
            .env("PATH", "/nonexistent")
            .env("HOME", self.state.path())
            .env("WARD_STATE_DIR", self.state.path())
            .output()
            .unwrap()
    }

    fn config(&self) -> String {
        std::fs::read_to_string(self.path().join(".tamperward/config.yml")).unwrap_or_default()
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

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn active_command_lines(config: &str) -> Vec<&str> {
    config
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("command:"))
        .collect()
}

fn cargo_workspace() -> Fixture {
    Fixture::new(&[
        ("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n"),
        ("Cargo.lock", "version = 4\n"),
        ("crates/a/Cargo.toml", "[package]\nname = \"a\"\n"),
        ("crates/a/tests/it.rs", "#[test]\nfn it() {}\n"),
        ("crates/b/Cargo.toml", "[package]\nname = \"b\"\n"),
        ("crates/b/src/lib.rs", ""),
    ])
}

const WITH_TEST: &str = r#"{"name":"app","scripts":{"test":"vitest run"}}"#;

#[test]
fn init_without_acceptance_writes_the_proposal_commented_and_ready_says_not_accepted() {
    let f = cargo_workspace();
    let init = f.ward(&["init", "--no-tamperward"]);
    assert!(init.status.success(), "{}", text(&init));
    let out = text(&init);
    assert!(out.contains("cargo test --workspace --locked"), "{out}");
    assert!(out.contains("not accepted"), "{out}");
    assert!(out.contains("--accept-verify"), "{out}");
    let config = f.config();
    assert!(
        active_command_lines(&config).is_empty(),
        "nothing is accepted for the user:\n{config}"
    );
    assert!(
        config.contains("# command: cargo test --workspace --locked"),
        "{config}"
    );

    let ready = f.ward(&["ready"]);
    assert!(!ready.status.success(), "{}", text(&ready));
    let out = text(&ready);
    assert!(out.contains("setup required"), "{out}");
    assert!(out.contains("not accepted"), "{out}");
    assert!(out.contains("cargo test --workspace --locked"), "{out}");
    assert!(out.contains("crates/a/tests/"), "{out}");
    assert!(out.contains("Cargo.lock"), "{out}");
}

#[test]
fn accept_verify_writes_the_boundary_and_ready_sees_the_command() {
    let f = cargo_workspace();
    let init = f.ward(&["init", "--no-tamperward", "--accept-verify"]);
    assert!(init.status.success(), "{}", text(&init));
    let out = text(&init);
    assert!(out.contains("accepted"), "{out}");
    let config = f.config();
    assert_eq!(
        active_command_lines(&config),
        ["command: cargo test --workspace --locked"],
        "{config}"
    );
    assert!(config.contains("- crates/a/tests/"), "{config}");
    assert!(!config.contains("- crates/b/"), "{config}");

    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    assert!(
        out.contains("command: cargo test --workspace --locked"),
        "{out}"
    );
    assert!(!out.contains("not accepted"), "{out}");
}

#[test]
fn accept_verify_later_replaces_only_the_proposal_ward_init_wrote() {
    let f = cargo_workspace();
    assert!(f.ward(&["init", "--no-tamperward"]).status.success());
    assert!(active_command_lines(&f.config()).is_empty());
    let accept = f.ward(&["init", "--no-tamperward", "--accept-verify"]);
    assert!(accept.status.success(), "{}", text(&accept));
    assert_eq!(
        active_command_lines(&f.config()),
        ["command: cargo test --workspace --locked"]
    );

    let mine = "protected:\n  tests: []\nverify:\n  budget_secs: 5\n";
    std::fs::write(f.path().join(".tamperward/config.yml"), mine).unwrap();
    let accept = f.ward(&["init", "--no-tamperward", "--accept-verify"]);
    assert!(accept.status.success(), "{}", text(&accept));
    assert_eq!(f.config(), mine, "a file the user wrote is never rewritten");
}

#[test]
fn propose_reprints_the_proposal_and_changes_nothing() {
    let f = cargo_workspace();
    assert!(f.ward(&["init", "--no-tamperward"]).status.success());
    let before = f.tree();
    let propose = f.ward(&["ready", "--propose"]);
    assert!(propose.status.success(), "{}", text(&propose));
    let out = text(&propose);
    assert!(out.contains("cargo test --workspace --locked"), "{out}");
    assert!(out.contains("crates/a/tests/"), "{out}");
    assert!(out.contains("[workspace] in Cargo.toml"), "{out}");
    assert_eq!(f.tree(), before, "--propose writes nothing");
    assert_eq!(text(&f.ward(&["ready", "--propose"])), out, "deterministic");
}

#[test]
fn each_fixture_is_classified_from_its_own_files() {
    let npm_no_test = Fixture::new(&[
        (
            "package.json",
            r#"{"name":"app","scripts":{"build":"tsc"}}"#,
        ),
        ("package-lock.json", "{}"),
    ]);
    let out = text(&npm_no_test.ward(&["ready", "--propose"]));
    assert!(out.contains("cannot propose"), "{out}");
    assert!(out.contains("scripts.test"), "{out}");
    assert!(!out.contains("npm test"), "no default guess: {out}");
    assert!(!npm_no_test.ward(&["ready", "--propose"]).status.success());

    let pnpm = Fixture::new(&[
        ("package.json", WITH_TEST),
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        ("__tests__/app.test.js", ""),
    ]);
    let out = text(&pnpm.ward(&["ready", "--propose"]));
    assert!(out.contains("pnpm test"), "{out}");
    assert!(out.contains("pnpm-lock.yaml"), "{out}");
    assert!(out.contains("__tests__/"), "{out}");
    assert!(!out.contains(" npm test"), "{out}");

    let yarn = Fixture::new(&[
        ("package.json", WITH_TEST),
        ("yarn.lock", "# yarn lockfile v1\n"),
        ("test/app.test.js", ""),
    ]);
    let out = text(&yarn.ward(&["ready", "--propose"]));
    assert!(out.contains("yarn test"), "{out}");
    assert!(out.contains("yarn.lock"), "{out}");
    assert!(out.contains("test/"), "{out}");

    let python = Fixture::new(&[
        (
            "pyproject.toml",
            "[project]\nname = \"app\"\n\n[tool.pytest.ini_options]\ntestpaths = [\"src/app/testing\"]\n",
        ),
        ("uv.lock", "version = 1\n"),
        ("src/app/testing/test_app.py", "def test_x():\n    pass\n"),
    ]);
    let out = text(&python.ward(&["ready", "--propose"]));
    assert!(out.contains("pytest"), "{out}");
    assert!(out.contains("src/app/testing/"), "{out}");
    assert!(out.contains("testpaths"), "{out}");
    assert!(out.contains("uv.lock"), "{out}");
    assert!(!out.contains("tests/ "), "tests/ is not assumed: {out}");

    let empty = Fixture::new(&[("README.md", "# nothing to build\n")]);
    let propose = empty.ward(&["ready", "--propose"]);
    assert!(!propose.status.success());
    let out = text(&propose);
    assert!(out.contains("cannot propose"), "{out}");
    assert!(out.contains("no manifest"), "{out}");
    let ready = empty.ward(&["ready"]);
    assert!(!ready.status.success());
    let out = text(&ready);
    assert!(out.contains("verification unavailable"), "{out}");
    assert!(out.contains("cannot propose"), "{out}");
}
