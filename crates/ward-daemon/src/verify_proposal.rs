//! Verify-command proposals for `ward init` (#147 item 2): which command would run
//! this project's tests, read from its manifests, lockfiles and test configuration
//! rather than guessed from a manifest's presence alone.
//!
//! Detection is pure and deterministic: it reads a handful of files at the project
//! root, never touches the network and never executes project code. Every proposal
//! carries the evidence that produced it, and a project that matches several
//! ecosystems yields several proposals in a fixed order, so the caller decides how to
//! present the choice instead of this module silently picking one.

use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

/// The largest file read for evidence; anything bigger is treated as unreadable.
const MAX_READ: u64 = 1 << 20;

/// The `test` script `npm init` writes, which fails by design.
const NPM_PLACEHOLDER: &str = "Error: no test specified";

/// Node lockfiles, most specific manager first, with the manager each one implies.
const NODE_LOCKFILES: [(&str, &str); 4] = [
    ("pnpm-lock.yaml", "pnpm"),
    ("yarn.lock", "yarn"),
    ("package-lock.json", "npm"),
    ("npm-shrinkwrap.json", "npm"),
];

/// One command that could run this project's tests, and why it was proposed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    /// The command, as it would be written to `verify.command`.
    pub command: String,
    /// The files and settings that led to it, in the order they were checked.
    pub evidence: Vec<String>,
}

impl Proposal {
    fn new(command: impl Into<String>, evidence: Vec<String>) -> Self {
        Self {
            command: command.into(),
            evidence,
        }
    }
}

/// Inspect `dir` and return every verify command its files support, in a fixed
/// order: Cargo, Node (pnpm, yarn, npm), Python, Go, Make. Empty when nothing is
/// recognised.
///
/// Only regular files at the root are consulted: a symlink, FIFO or other special
/// node at a manifest's path counts as absent, and no file larger than 1 MiB is read.
#[must_use]
pub fn propose(dir: &Path) -> Vec<Proposal> {
    let mut proposals = Vec::new();
    proposals.extend(cargo(dir));
    proposals.extend(node(dir));
    proposals.extend(python(dir));
    proposals.extend(go(dir));
    proposals.extend(make(dir));
    proposals
}

fn cargo(dir: &Path) -> Option<Proposal> {
    let manifest = read(dir, "Cargo.toml")?;
    let mut command = String::from("cargo test");
    let mut evidence = vec!["Cargo.toml".to_owned()];
    if has_header(&manifest, "[workspace]") {
        command.push_str(" --workspace");
        evidence.push("[workspace] in Cargo.toml".to_owned());
    }
    if is_regular_file(dir, "Cargo.lock") {
        command.push_str(" --locked");
        evidence.push("Cargo.lock".to_owned());
    }
    Some(Proposal::new(command, evidence))
}

fn node(dir: &Path) -> Vec<Proposal> {
    let Some(manifest) = read(dir, "package.json")
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
    else {
        return Vec::new();
    };
    let has_test = manifest
        .pointer("/scripts/test")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|script| !script.trim().is_empty() && !script.contains(NPM_PLACEHOLDER));
    if !has_test {
        return Vec::new();
    }
    let script = "package.json scripts.test".to_owned();
    let mut managers: Vec<(&str, String)> = Vec::new();
    for (lockfile, manager) in NODE_LOCKFILES {
        if is_regular_file(dir, lockfile) && !managers.iter().any(|(m, _)| *m == manager) {
            managers.push((manager, lockfile.to_owned()));
        }
    }
    if managers.is_empty() {
        let declared = manifest
            .get("packageManager")
            .and_then(serde_json::Value::as_str)
            .and_then(|spec| spec.split('@').next())
            .and_then(|name| {
                NODE_LOCKFILES
                    .iter()
                    .map(|(_, manager)| *manager)
                    .find(|manager| *manager == name)
            });
        managers.push(match declared {
            Some(manager) => (manager, format!("package.json packageManager: {manager}")),
            None => ("npm", "no lockfile: npm".to_owned()),
        });
    }
    managers
        .into_iter()
        .map(|(manager, why)| Proposal::new(format!("{manager} test"), vec![script.clone(), why]))
        .collect()
}

fn python(dir: &Path) -> Option<Proposal> {
    let mut evidence = Vec::new();
    if let Some(text) = read(dir, "pyproject.toml") {
        if let Some(header) = ["[tool.pytest.ini_options]", "[tool.pytest]"]
            .into_iter()
            .find(|header| has_header(&text, header))
        {
            evidence.push(format!("{header} in pyproject.toml"));
        } else if text.contains("\"pytest") || text.contains("'pytest") {
            evidence.push("pytest in pyproject.toml dependencies".to_owned());
        }
    }
    if is_regular_file(dir, "pytest.ini") {
        evidence.push("pytest.ini".to_owned());
    }
    if read(dir, "tox.ini").is_some_and(|text| has_header(&text, "[pytest]")) {
        evidence.push("[pytest] in tox.ini".to_owned());
    }
    if read(dir, "setup.cfg").is_some_and(|text| has_header(&text, "[tool:pytest]")) {
        evidence.push("[tool:pytest] in setup.cfg".to_owned());
    }
    (!evidence.is_empty()).then(|| Proposal::new("pytest", evidence))
}

fn go(dir: &Path) -> Option<Proposal> {
    is_regular_file(dir, "go.mod")
        .then(|| Proposal::new("go test ./...", vec!["go.mod".to_owned()]))
}

fn make(dir: &Path) -> Option<Proposal> {
    let (name, text) = ["GNUmakefile", "makefile", "Makefile"]
        .into_iter()
        .find_map(|name| read(dir, name).map(|text| (name, text)))?;
    text.lines()
        .any(defines_test_target)
        .then(|| Proposal::new("make test", vec![format!("test target in {name}")]))
}

/// Whether a makefile line is a rule naming `test` among its targets.
fn defines_test_target(line: &str) -> bool {
    if line.starts_with(|c: char| c.is_whitespace()) || line.starts_with('#') {
        return false;
    }
    let Some((targets, rest)) = line.split_once(':') else {
        return false;
    };
    !rest.starts_with('=')
        && !rest.starts_with(":=")
        && targets.split_whitespace().any(|target| target == "test")
}

/// Whether an INI- or TOML-style text has `header` alone on a line.
fn has_header(text: &str, header: &str) -> bool {
    text.lines().any(|line| line.trim() == header)
}

/// Whether `name` under `dir` is a regular file, not following a symlink.
fn is_regular_file(dir: &Path, name: &str) -> bool {
    dir.join(name)
        .symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_file())
}

/// The text of `name` under `dir` when it is a regular, not symlinked, UTF-8 file of
/// at most [`MAX_READ`] bytes. The open itself refuses a symlink and never blocks on
/// a FIFO, so a hostile project cannot redirect or stall detection.
fn read(dir: &Path, name: &str) -> Option<String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(dir.join(name))
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_READ + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_READ {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const PLACEHOLDER: &str =
        r#"{"scripts":{"test":"echo \"Error: no test specified\" && exit 1"}}"#;
    const WITH_TEST: &str = r#"{"name":"app","scripts":{"test":"vitest run"}}"#;
    const NO_TEST: &str = r#"{"name":"app","scripts":{"build":"tsc"}}"#;

    /// The named project fixture: the files a real project of that kind has at its
    /// root, written into a fresh temporary directory.
    fn fixture(name: &str) -> tempfile::TempDir {
        let files: &[(&str, &str)] = match name {
            "cargo" => &[
                ("Cargo.toml", "[package]\nname = \"app\"\n"),
                ("Cargo.lock", "version = 4\n"),
            ],
            "cargo-workspace" => &[
                ("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n"),
                ("Cargo.lock", "version = 4\n"),
            ],
            "cargo-unlocked" => &[("Cargo.toml", "[package]\nname = \"lib\"\n")],
            "npm" => &[("package.json", WITH_TEST), ("package-lock.json", "{}")],
            "npm-unlocked" => &[("package.json", WITH_TEST)],
            "npm-no-test" => &[("package.json", NO_TEST), ("package-lock.json", "{}")],
            "npm-placeholder" => &[("package.json", PLACEHOLDER)],
            "pnpm" => &[
                ("package.json", WITH_TEST),
                ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
            ],
            "pnpm-declared" => &[(
                "package.json",
                r#"{"packageManager":"pnpm@9.1.0","scripts":{"test":"jest"}}"#,
            )],
            "yarn" => &[("package.json", WITH_TEST), ("yarn.lock", "# yarn\n")],
            "node-two-lockfiles" => &[
                ("package.json", WITH_TEST),
                ("package-lock.json", "{}"),
                ("yarn.lock", "# yarn\n"),
            ],
            "python-pyproject" => &[(
                "pyproject.toml",
                "[project]\nname = \"app\"\n\n[tool.pytest.ini_options]\ntestpaths = [\"src\"]\n",
            )],
            "python-dependency" => &[(
                "pyproject.toml",
                "[project]\nname = \"app\"\n[project.optional-dependencies]\ntest = [\"pytest>=8\"]\n",
            )],
            "python-bare" => &[("pyproject.toml", "[project]\nname = \"app\"\n")],
            "pytest-ini" => &[("pytest.ini", "[pytest]\naddopts = -q\n")],
            "tox" => &[(
                "tox.ini",
                "[tox]\nenvlist = py3\n\n[pytest]\naddopts = -q\n",
            )],
            "tox-no-pytest" => &[("tox.ini", "[tox]\nenvlist = py3\n")],
            "setup-cfg" => &[("setup.cfg", "[metadata]\nname = app\n\n[tool:pytest]\n")],
            "go" => &[("go.mod", "module example.com/app\n\ngo 1.22\n")],
            "make" => &[(
                "Makefile",
                ".PHONY: build test\nbuild:\n\tcc main.c\n\ntest: build\n\t./run-tests\n",
            )],
            "make-multi-target" => &[("Makefile", "check test:\n\t./run-tests\n")],
            "make-no-test" => &[(
                "Makefile",
                ".PHONY: test\nbuild:\n\tcc main.c\ntest_flags := -q\n\t# test: not a target\n",
            )],
            "mixed" => &[
                ("Cargo.toml", "[package]\nname = \"app\"\n"),
                ("Cargo.lock", "version = 4\n"),
                ("package.json", WITH_TEST),
                ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
                ("Makefile", "test:\n\tcargo test\n"),
            ],
            "none" => &[("README.md", "# nothing to build\n")],
            other => panic!("unknown fixture {other}"),
        };
        let dir = tempfile::tempdir().unwrap();
        for (path, content) in files {
            std::fs::write(dir.path().join(path), content).unwrap();
        }
        dir
    }

    fn commands(name: &str) -> Vec<String> {
        propose(fixture(name).path())
            .into_iter()
            .map(|p| p.command)
            .collect()
    }

    fn evidence(name: &str) -> Vec<String> {
        propose(fixture(name).path())
            .into_iter()
            .flat_map(|p| p.evidence)
            .collect()
    }

    #[test]
    fn cargo_pins_the_lockfile_when_there_is_one() {
        assert_eq!(commands("cargo"), ["cargo test --locked"]);
        assert_eq!(evidence("cargo"), ["Cargo.toml", "Cargo.lock"]);
        assert_eq!(commands("cargo-unlocked"), ["cargo test"]);
        assert_eq!(evidence("cargo-unlocked"), ["Cargo.toml"]);
    }

    #[test]
    fn a_cargo_workspace_tests_every_member() {
        assert_eq!(
            commands("cargo-workspace"),
            ["cargo test --workspace --locked"]
        );
        assert_eq!(
            evidence("cargo-workspace"),
            ["Cargo.toml", "[workspace] in Cargo.toml", "Cargo.lock"]
        );
    }

    #[test]
    fn node_runs_the_test_script_with_the_lockfile_s_package_manager() {
        assert_eq!(commands("npm"), ["npm test"]);
        assert_eq!(
            evidence("npm"),
            ["package.json scripts.test", "package-lock.json"]
        );
        assert_eq!(commands("pnpm"), ["pnpm test"]);
        assert_eq!(
            evidence("pnpm"),
            ["package.json scripts.test", "pnpm-lock.yaml"]
        );
        assert_eq!(commands("yarn"), ["yarn test"]);
        assert_eq!(evidence("yarn"), ["package.json scripts.test", "yarn.lock"]);
    }

    #[test]
    fn node_without_a_lockfile_uses_the_declared_manager_or_npm() {
        assert_eq!(commands("pnpm-declared"), ["pnpm test"]);
        assert_eq!(
            evidence("pnpm-declared"),
            [
                "package.json scripts.test",
                "package.json packageManager: pnpm"
            ]
        );
        assert_eq!(commands("npm-unlocked"), ["npm test"]);
        assert_eq!(
            evidence("npm-unlocked"),
            ["package.json scripts.test", "no lockfile: npm"]
        );
    }

    #[test]
    fn package_json_without_a_real_test_script_proposes_nothing() {
        assert!(commands("npm-no-test").is_empty());
        assert!(
            commands("npm-placeholder").is_empty(),
            "npm init's stub fails by design"
        );
    }

    #[test]
    fn two_node_lockfiles_are_two_proposals_not_a_pick() {
        assert_eq!(commands("node-two-lockfiles"), ["yarn test", "npm test"]);
    }

    #[test]
    fn python_needs_pytest_configuration_or_a_pytest_dependency() {
        for (name, why) in [
            (
                "python-pyproject",
                "[tool.pytest.ini_options] in pyproject.toml",
            ),
            ("python-dependency", "pytest in pyproject.toml dependencies"),
            ("pytest-ini", "pytest.ini"),
            ("tox", "[pytest] in tox.ini"),
            ("setup-cfg", "[tool:pytest] in setup.cfg"),
        ] {
            assert_eq!(commands(name), ["pytest"], "{name}");
            assert_eq!(evidence(name), [why], "{name}");
        }
        assert!(
            commands("python-bare").is_empty(),
            "a bare manifest is not test configuration"
        );
        assert!(commands("tox-no-pytest").is_empty());
    }

    #[test]
    fn go_tests_every_package_of_the_module() {
        assert_eq!(commands("go"), ["go test ./..."]);
        assert_eq!(evidence("go"), ["go.mod"]);
    }

    #[test]
    fn make_needs_a_test_target() {
        assert_eq!(commands("make"), ["make test"]);
        assert_eq!(evidence("make"), ["test target in Makefile"]);
        assert_eq!(commands("make-multi-target"), ["make test"]);
        assert!(commands("make-no-test").is_empty());
    }

    #[test]
    fn several_ecosystems_are_several_proposals_in_a_fixed_order() {
        assert_eq!(
            commands("mixed"),
            ["cargo test --locked", "pnpm test", "make test"]
        );
        let dir = fixture("mixed");
        assert_eq!(propose(dir.path()), propose(dir.path()), "deterministic");
    }

    #[test]
    fn nothing_recognised_proposes_nothing() {
        assert!(commands("none").is_empty());
        assert!(propose(&fixture("none").path().join("absent")).is_empty());
    }

    #[test]
    fn manifests_are_never_read_through_a_symlink_or_from_a_fifo() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("package.json"), WITH_TEST).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("package.json"),
            dir.path().join("package.json"),
        )
        .unwrap();
        assert!(
            propose(dir.path()).is_empty(),
            "symlinked manifest is not read"
        );

        let dir = tempfile::tempdir().unwrap();
        nix::unistd::mkfifo(
            &dir.path().join("Makefile"),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        assert!(
            propose(dir.path()).is_empty(),
            "a FIFO must not hang detection"
        );
    }
}
