//! Runs the built `ward` binary against small Node and Python fixtures and checks #147
//! items 3, 4 and 6: `ward prepare` installs the dependency set named by the lockfile
//! once, online, into a sealed environment under the state directory, keyed by lockfile
//! digest, runtime and platform; `ward verify` stays offline and mounts that environment
//! read-only beside the candidate; `ward ready` reports the environment's state (never
//! prepared, prepared, stale, incomplete) with the recorded timings; a changed lockfile
//! invalidates it; an interrupted preparation is marked incomplete, never used, and
//! retried from scratch; a project without a lockfile is declined.
//!
//! The package managers are fakes placed where the verifier actually looks
//! (`$CARGO_HOME/bin`, mounted read-only at `/run/verifier/cargo/bin`): each records
//! whether it saw a network interface besides loopback and what it was asked to do, so
//! the tests can prove the prepare phase was online and the verification was not.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_ward");

/// The sandbox is a prerequisite of every test here; `WARD_REQUIRE_ISOLATION` turns a
/// skip into a failure exactly as it does for the daemon's own suite (#124).
fn sandbox_ready() -> bool {
    ward_sandbox::ci::isolation_ready(ward_daemon::sandbox::available(), "bubblewrap")
}

/// Shell that reports whether any network interface besides loopback is visible: the
/// prepare phase must see one, the verifier must not.
const NET_PROBE: &str = r"net() { if tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | grep -qv '^lo$'; then echo online; else echo offline; fi; }";

const FAKE_NODE: &str =
    "#!/bin/sh\ncase \"$1\" in --version) echo \"v22.0.0-fake\";; *) exit 2;; esac\n";

/// A working `npm`: `ci` installs one package and records what it saw; `test` passes
/// only when that package is present, read-only, and no network is visible.
fn fake_npm_ok() -> String {
    format!(
        r#"#!/bin/sh
{NET_PROBE}
case "$1" in
  ci)
    [ -f package-lock.json ] || {{ echo "fake npm: no package-lock.json in $(pwd)" >&2; exit 1; }}
    mkdir -p node_modules/left-pad
    echo "module.exports = 1" > node_modules/left-pad/index.js
    net > node_modules/.ward-net
    echo "$*" > node_modules/.ward-args
    echo "added 1 package"
    ;;
  test)
    [ -f node_modules/left-pad/index.js ] || {{ echo "fake npm: node_modules missing"; echo "test result: FAILED. 0 passed; 1 failed"; exit 1; }}
    [ "$(cat node_modules/.ward-net)" = online ] || {{ echo "fake npm: the install was not online"; echo "test result: FAILED. 0 passed; 1 failed"; exit 1; }}
    [ "$(net)" = offline ] || {{ echo "fake npm: the verifier has a network"; echo "test result: FAILED. 0 passed; 1 failed"; exit 1; }}
    if touch node_modules/.scribble 2>/dev/null; then echo "fake npm: node_modules is writable"; echo "test result: FAILED. 0 passed; 1 failed"; exit 1; fi
    echo "test result: ok. 1 passed; 0 failed"
    ;;
  *) echo "fake npm: unsupported $*" >&2; exit 2;;
esac
"#
    )
}

/// An `npm` whose `ci` dies partway through, leaving a partial tree behind.
fn fake_npm_dies() -> String {
    r#"#!/bin/sh
case "$1" in
  ci)
    mkdir -p node_modules/left-pad
    echo "partial" > node_modules/left-pad/PARTIAL
    echo "fake npm: interrupted" >&2
    kill -KILL $$
    ;;
  *) exit 2;;
esac
"#
    .to_owned()
}

/// A `python3` whose `-m pip install --target …` writes a package and a `pytest` script
/// that passes only when it runs from the prepared environment's mount.
const FAKE_PYTHON: &str = r#"#!/bin/sh
case "$1" in
  --version) echo "Python 3.99.0-fake";;
  -m)
    shift; [ "$1" = pip ] || exit 2; shift; [ "$1" = install ] || exit 2; shift
    target=""; reqs=""
    while [ $# -gt 0 ]; do
      case "$1" in --target) target="$2"; shift 2;; -r) reqs="$reqs $2"; shift 2;; *) shift;; esac
    done
    [ -n "$target" ] || { echo "fake pip: no --target" >&2; exit 1; }
    for r in $reqs; do [ -f "$r" ] || { echo "fake pip: missing $r" >&2; exit 1; }; done
    mkdir -p "$target/fakelib" "$target/bin"
    echo "x = 1" > "$target/fakelib/__init__.py"
    cat > "$target/bin/pytest" <<'EOF'
#!/bin/sh
case "$PYTHONPATH" in
  */run/verifier/deps/site-packages*) ;;
  *) echo "PYTHONPATH does not name the prepared environment: '$PYTHONPATH'"; echo "test result: FAILED. 0 passed; 1 failed"; exit 1;;
esac
[ -f /run/verifier/deps/site-packages/fakelib/__init__.py ] || { echo "site-packages not mounted"; exit 1; }
echo "pytest from the prepared environment"
echo "test result: ok. 2 passed; 0 failed"
EOF
    chmod +x "$target/bin/pytest"
    echo "Successfully installed fakelib"
    ;;
  *) exit 2;;
esac
"#;

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
        let state = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(state.path().join("cargo/bin")).unwrap();
        Self { dir, state }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Place a fake tool where the verifier looks (`$CARGO_HOME/bin`).
    fn tool(&self, name: &str, script: &str) {
        let path = self.state.path().join("cargo/bin").join(name);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn ward(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .arg(self.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.state.path())
            .env("WARD_STATE_DIR", self.state.path())
            .env("CARGO_HOME", self.state.path().join("cargo"))
            .output()
            .unwrap()
    }

    fn prepared_root(&self) -> PathBuf {
        self.state.path().join("prepared")
    }

    /// Every complete or partial environment directory (64 hex characters).
    fn environments(&self) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(self.prepared_root()) else {
            return Vec::new();
        };
        let mut dirs: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.len() == 64 && n.chars().all(|c| c.is_ascii_hexdigit()))
            })
            .collect();
        dirs.sort();
        dirs
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

fn record(env_dir: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(env_dir.join("prepared.json")).unwrap()).unwrap()
}

fn is_read_only(path: &Path) -> bool {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o222 == 0
}

const PACKAGE_JSON: &str = r#"{"name":"app","version":"1.0.0","scripts":{"test":"npm run unit"}}"#;
const LOCK_V1: &str = r#"{"name":"app","lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}"#;
const LOCK_V2: &str = r#"{"name":"app","lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.1"}}}"#;

fn npm_project() -> Fixture {
    let f = Fixture::new(&[
        ("package.json", PACKAGE_JSON),
        ("package-lock.json", LOCK_V1),
        ("test/app.test.js", "// a test\n"),
    ]);
    f.tool("node", FAKE_NODE);
    f.tool("npm", &fake_npm_ok());
    f
}

#[test]
fn prepare_installs_online_once_and_verify_runs_offline_from_the_sealed_environment() {
    if !sandbox_ready() {
        return;
    }
    let f = npm_project();
    let init = f.ward(&["init", "--no-tamperward", "--accept-verify"]);
    assert!(init.status.success(), "{}", text(&init));
    assert!(text(&init).contains("npm test"), "{}", text(&init));

    // Before any preparation: setup required, with the one step that fixes it named.
    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    assert!(!ready.status.success(), "{out}");
    let deps = row(&out, "dependencies");
    assert!(deps.contains("FAIL"), "{deps}");
    assert!(deps.contains("never prepared"), "{deps}");
    assert!(deps.contains("ward prepare"), "{deps}");
    assert!(out.contains("setup required"), "{out}");

    // The explicit, online preparation phase.
    let before = f.tree();
    let prepare = f.ward(&["prepare"]);
    let out = text(&prepare);
    assert!(prepare.status.success(), "{out}");
    assert!(out.contains("npm ci"), "{out}");
    assert!(out.contains("--ignore-scripts"), "{out}");
    assert!(out.contains("package-lock.json"), "{out}");
    assert!(out.contains("v22.0.0-fake"), "{out}");
    assert!(out.contains("network"), "the network use is stated: {out}");
    assert!(out.contains("cold"), "the cold timing is reported: {out}");
    assert_eq!(f.tree(), before, "prepare never writes into the project");
    assert!(!f.path().join("node_modules").exists());

    let envs = f.environments();
    assert_eq!(envs.len(), 1, "{envs:?}");
    let env_dir = &envs[0];
    let rec = record(env_dir);
    assert_eq!(rec["outcome"], "complete", "{rec}");
    assert_eq!(rec["ecosystem"], "node-npm", "{rec}");
    assert_eq!(rec["runtime"]["version"], "v22.0.0-fake", "{rec}");
    assert!(rec["cold_ms"].is_number(), "{rec}");
    assert_eq!(rec["attempt"], 1, "{rec}");
    assert!(
        rec["network"].as_str().unwrap().contains("host"),
        "the record says the install had the host's network: {rec}"
    );
    let inputs: Vec<&str> = rec["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["path"].as_str().unwrap())
        .collect();
    assert_eq!(inputs, ["package-lock.json", "package.json"], "{rec}");
    let stage = env_dir.join("stage");
    assert_eq!(
        std::fs::read_to_string(stage.join("node_modules/.ward-net"))
            .unwrap()
            .trim(),
        "online",
        "the fake npm saw the network during prepare"
    );
    assert!(
        std::fs::read_to_string(stage.join("node_modules/.ward-args"))
            .unwrap()
            .contains("--ignore-scripts"),
        "install scripts are never run during prepare"
    );
    assert!(is_read_only(&stage), "the stage is sealed");
    assert!(is_read_only(&stage.join("node_modules/left-pad/index.js")));

    // Reuse: the same inputs give the same environment, warm.
    let again = f.ward(&["prepare"]);
    let out = text(&again);
    assert!(again.status.success(), "{out}");
    assert!(out.contains("already prepared"), "{out}");
    assert!(out.contains("warm"), "{out}");
    assert_eq!(f.environments().len(), 1);

    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    assert!(ready.status.success(), "{out}");
    let deps = row(&out, "dependencies");
    assert!(deps.contains("OK"), "{deps}");
    assert!(deps.contains("prepared"), "{deps}");
    assert!(deps.contains("node-npm"), "{deps}");
    assert!(deps.contains("warm"), "{deps}");
    assert!(deps.contains("cold"), "{deps}");
    let short = &env_dir.file_name().unwrap().to_str().unwrap()[..12];
    assert!(deps.contains(short), "the key is shown: {deps}");

    // Offline verification mounts the environment read-only beside the candidate: the
    // fake `npm test` passes only when node_modules is there, read-only, was installed
    // online, and no network is visible now.
    let verify = f.ward(&["verify"]);
    let out = text(&verify);
    assert!(verify.status.success(), "{out}");
    assert!(out.contains("VERIFIED"), "{out}");
    assert!(out.contains("1 tests"), "{out}");
    assert!(out.contains("dependencies prepared"), "{out}");
    assert!(out.contains("mounted read-only"), "{out}");
    assert!(out.contains(short), "{out}");
    assert!(
        !f.path().join("node_modules").exists(),
        "the worktree stays clean"
    );
}

#[test]
fn a_changed_lockfile_invalidates_the_environment_until_prepared_again() {
    if !sandbox_ready() {
        return;
    }
    let f = npm_project();
    assert!(
        f.ward(&["init", "--no-tamperward", "--accept-verify"])
            .status
            .success()
    );
    let first = f.ward(&["prepare"]);
    assert!(first.status.success(), "{}", text(&first));
    let first_key = f.environments()[0].file_name().unwrap().to_owned();

    std::fs::write(f.path().join("package-lock.json"), LOCK_V2).unwrap();
    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    assert!(!ready.status.success(), "{out}");
    let deps = row(&out, "dependencies");
    assert!(deps.contains("FAIL"), "{deps}");
    assert!(deps.contains("stale"), "{deps}");
    assert!(deps.contains("package-lock.json changed"), "{deps}");
    assert!(deps.contains("ward prepare"), "{deps}");

    // Verification does not fetch: it runs without the stale environment and says so.
    let verify = f.ward(&["verify"]);
    let out = text(&verify);
    assert!(!verify.status.success(), "{out}");
    assert!(out.contains("stale"), "{out}");
    assert!(out.contains("node_modules missing"), "{out}");

    let second = f.ward(&["prepare"]);
    assert!(second.status.success(), "{}", text(&second));
    let envs = f.environments();
    assert_eq!(
        envs.len(),
        2,
        "a new key, the old environment untouched: {envs:?}"
    );
    assert!(envs.iter().any(|e| e.file_name().unwrap() == first_key));
    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    assert!(ready.status.success(), "{out}");
    assert!(row(&out, "dependencies").contains("prepared"), "{out}");
    let verify = f.ward(&["verify"]);
    assert!(verify.status.success(), "{}", text(&verify));
}

#[test]
fn a_changed_runtime_invalidates_the_environment() {
    if !sandbox_ready() {
        return;
    }
    let f = npm_project();
    assert!(
        f.ward(&["init", "--no-tamperward", "--accept-verify"])
            .status
            .success()
    );
    assert!(f.ward(&["prepare"]).status.success());
    f.tool(
        "node",
        "#!/bin/sh\ncase \"$1\" in --version) echo \"v24.0.0-fake\";; *) exit 2;; esac\n",
    );
    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    assert!(!ready.status.success(), "{out}");
    let deps = row(&out, "dependencies");
    assert!(deps.contains("stale"), "{deps}");
    assert!(deps.contains("runtime changed"), "{deps}");
    assert!(deps.contains("v22.0.0-fake"), "{deps}");
    assert!(deps.contains("v24.0.0-fake"), "{deps}");
}

#[test]
fn an_interrupted_prepare_is_incomplete_never_used_and_retried_from_scratch() {
    if !sandbox_ready() {
        return;
    }
    let f = npm_project();
    f.tool("npm", &fake_npm_dies());
    assert!(
        f.ward(&["init", "--no-tamperward", "--accept-verify"])
            .status
            .success()
    );

    let prepare = f.ward(&["prepare"]);
    let out = text(&prepare);
    assert!(!prepare.status.success(), "{out}");
    assert!(
        out.contains("fake npm: interrupted"),
        "the tool's output is shown: {out}"
    );
    assert!(out.contains("incomplete"), "{out}");
    let envs = f.environments();
    assert_eq!(envs.len(), 1, "{envs:?}");
    let rec = record(&envs[0]);
    assert_eq!(rec["outcome"], "incomplete", "{rec}");
    assert_eq!(rec["attempt"], 1, "{rec}");
    assert!(
        envs[0].join("stage/node_modules/left-pad/PARTIAL").exists(),
        "the partial tree is kept for inspection"
    );
    assert!(!is_read_only(&envs[0].join("stage")), "never sealed");

    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    assert!(!ready.status.success(), "{out}");
    let deps = row(&out, "dependencies");
    assert!(deps.contains("FAIL"), "{deps}");
    assert!(deps.contains("incomplete"), "{deps}");
    assert!(deps.contains("ward prepare"), "{deps}");

    // Verification never mounts an incomplete environment.
    let verify = f.ward(&["verify"]);
    let out = text(&verify);
    assert!(!verify.status.success(), "{out}");
    assert!(out.contains("incomplete"), "{out}");

    // The retry starts from scratch with a working tool and counts the attempt.
    f.tool("npm", &fake_npm_ok());
    let retry = f.ward(&["prepare"]);
    let out = text(&retry);
    assert!(retry.status.success(), "{out}");
    assert!(out.contains("attempt 2"), "{out}");
    let envs = f.environments();
    assert_eq!(envs.len(), 1, "same key, same directory: {envs:?}");
    let rec = record(&envs[0]);
    assert_eq!(rec["outcome"], "complete", "{rec}");
    assert_eq!(rec["attempt"], 2, "{rec}");
    assert!(
        !envs[0].join("stage/node_modules/left-pad/PARTIAL").exists(),
        "nothing of the partial tree survives"
    );
    assert!(is_read_only(&envs[0].join("stage")));
    let verify = f.ward(&["verify"]);
    assert!(verify.status.success(), "{}", text(&verify));
}

#[test]
fn python_requirements_are_installed_to_site_packages_and_mounted_on_pythonpath() {
    if !sandbox_ready() {
        return;
    }
    let f = Fixture::new(&[
        (
            "pyproject.toml",
            "[project]\nname = \"app\"\n\n[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\n",
        ),
        ("requirements.txt", "pytest==8.0.0\n"),
        ("tests/test_app.py", "def test_x():\n    pass\n"),
    ]);
    f.tool("python3", FAKE_PYTHON);
    let init = f.ward(&["init", "--no-tamperward", "--accept-verify"]);
    assert!(init.status.success(), "{}", text(&init));

    // `pytest` lives nowhere the verifier looks until the environment exists.
    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    assert!(!ready.status.success(), "{out}");
    assert!(row(&out, "runtime").contains("FAIL"), "{out}");
    assert!(
        row(&out, "dependencies").contains("never prepared"),
        "{out}"
    );

    let prepare = f.ward(&["prepare"]);
    let out = text(&prepare);
    assert!(prepare.status.success(), "{out}");
    assert!(out.contains("python3 -m pip install"), "{out}");
    assert!(out.contains("requirements.txt"), "{out}");
    assert!(out.contains("Python 3.99.0-fake"), "{out}");
    let envs = f.environments();
    assert_eq!(envs.len(), 1);
    let rec = record(&envs[0]);
    assert_eq!(rec["ecosystem"], "python-pip", "{rec}");
    assert!(envs[0].join("stage/site-packages/bin/pytest").exists());
    assert!(is_read_only(&envs[0].join("stage")));

    // The prepared `bin` is a verifier search directory now, so the runtime row resolves.
    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    assert!(ready.status.success(), "{out}");
    assert!(row(&out, "runtime").contains("OK"), "{out}");
    assert!(row(&out, "dependencies").contains("python-pip"), "{out}");

    // The fake `pytest` passes only from the mount named by PYTHONPATH.
    let verify = f.ward(&["verify"]);
    let out = text(&verify);
    assert!(verify.status.success(), "{out}");
    assert!(out.contains("VERIFIED"), "{out}");
    assert!(out.contains("2 tests"), "{out}");
    assert!(out.contains("dependencies prepared"), "{out}");
}

#[test]
fn a_project_without_a_lockfile_is_declined_not_guessed() {
    if !sandbox_ready() {
        return;
    }
    let f = Fixture::new(&[
        ("package.json", PACKAGE_JSON),
        ("test/app.test.js", "// a test\n"),
    ]);
    f.tool("node", FAKE_NODE);
    f.tool("npm", &fake_npm_ok());
    assert!(
        f.ward(&["init", "--no-tamperward", "--accept-verify"])
            .status
            .success()
    );
    let prepare = f.ward(&["prepare"]);
    let out = text(&prepare);
    assert!(!prepare.status.success(), "{out}");
    assert!(out.contains("no lockfile"), "{out}");
    assert!(out.contains("package-lock.json"), "{out}");
    assert!(f.environments().is_empty(), "nothing is installed");
    let ready = f.ward(&["ready"]);
    let out = text(&ready);
    assert!(!ready.status.success(), "{out}");
    let deps = row(&out, "dependencies");
    assert!(deps.contains("FAIL"), "{deps}");
    assert!(deps.contains("no lockfile"), "{deps}");
}

#[test]
fn prepare_requires_the_accepted_verification_boundary() {
    if !sandbox_ready() {
        return;
    }
    let f = npm_project();
    assert!(f.ward(&["init", "--no-tamperward"]).status.success());
    let prepare = f.ward(&["prepare"]);
    let out = text(&prepare);
    assert!(!prepare.status.success(), "{out}");
    assert!(out.contains("not accepted"), "{out}");
    assert!(out.contains("ward init --accept-verify"), "{out}");
    assert!(
        f.environments().is_empty(),
        "nothing runs before acceptance"
    );
}

#[test]
fn a_cargo_project_needs_no_prepared_environment() {
    if !sandbox_ready() {
        return;
    }
    let f = Fixture::new(&[
        (
            "Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
        ),
        ("Cargo.lock", "version = 4\n"),
        ("src/lib.rs", ""),
        ("tests/it.rs", "#[test]\nfn it() {}\n"),
    ]);
    assert!(
        f.ward(&["init", "--no-tamperward", "--accept-verify"])
            .status
            .success()
    );
    let ready = f.ward(&["ready"]);
    let deps = row(&text(&ready), "dependencies").to_owned();
    assert!(deps.contains("OK"), "{deps}");
    assert!(deps.contains("cargo"), "{deps}");
    assert!(deps.contains("registry"), "{deps}");
    let prepare = f.ward(&["prepare"]);
    let out = text(&prepare);
    assert!(prepare.status.success(), "{out}");
    assert!(out.contains("nothing to prepare"), "{out}");
    assert!(f.environments().is_empty());
}
