//! Verification-boundary proposals for `ward init` and `ward ready` (#147 item 2):
//! which command would run this project's tests, which inputs the verifier must
//! restore from the entry snapshot (test directories, test configuration) and which it
//! must read without rewriting (manifests, lockfiles), read from the project's
//! manifests, lockfiles and test configuration rather than guessed from a manifest's
//! presence alone.
//!
//! Detection is pure and deterministic: it reads a handful of files at the project
//! root, never touches the network and never executes project code. Every proposal
//! carries the evidence that produced it, a project that matches several ecosystems
//! yields several proposals in a fixed order, and a manifest that cannot support a
//! proposal is declined with the reason, so the caller presents a choice or an
//! explanation instead of a default guess. Nothing here is written anywhere: a
//! proposal becomes the project's verification boundary only when a trusted user
//! accepts it (`ward init --accept-verify`, or an interactive yes).

use std::fmt::Write as _;
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

/// Directories a Node test runner is conventionally pointed at.
const NODE_TEST_DIRS: [&str; 4] = ["test", "tests", "__tests__", "spec"];

/// Test-runner configuration files a Node project keeps at its root.
const NODE_TEST_CONFIGS: [&str; 18] = [
    "jest.config.js",
    "jest.config.cjs",
    "jest.config.mjs",
    "jest.config.ts",
    "jest.config.json",
    "vitest.config.js",
    "vitest.config.mjs",
    "vitest.config.ts",
    "vitest.config.mts",
    "vitest.workspace.ts",
    ".mocharc.js",
    ".mocharc.cjs",
    ".mocharc.json",
    ".mocharc.yml",
    ".mocharc.yaml",
    "playwright.config.ts",
    "playwright.config.js",
    "ava.config.js",
];

/// Python lockfiles, with what each one pins.
const PYTHON_LOCKFILES: [(&str, &str); 3] = [
    ("poetry.lock", "lockfile (poetry): pins the dependency set"),
    ("uv.lock", "lockfile (uv): pins the dependency set"),
    ("Pipfile.lock", "lockfile (pipenv): pins the dependency set"),
];

/// Every file whose presence at the root makes a directory a recognised project.
const MANIFESTS: [&str; 10] = [
    "Cargo.toml",
    "package.json",
    "pyproject.toml",
    "pytest.ini",
    "tox.ini",
    "setup.cfg",
    "go.mod",
    "GNUmakefile",
    "makefile",
    "Makefile",
];

/// One worktree-relative input of the verification, and why it is one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    /// The path, with a trailing `/` for a directory.
    pub path: String,
    /// Which file or key named it.
    pub why: String,
}

impl Input {
    fn new(path: impl Into<String>, why: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            why: why.into(),
        }
    }
}

/// One verification boundary this project's files support, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    /// The command, as it would be written to `verify.command`.
    pub command: String,
    /// The files and settings that led to the command, in the order they were checked.
    pub evidence: Vec<String>,
    /// What the verifier restores from the entry snapshot: test directories, test
    /// targets and test-runner configuration.
    pub protected: Vec<Input>,
    /// What the verifier reads and never rewrites: the manifests and lockfiles that
    /// pin the dependency set the command runs against.
    pub read_only: Vec<Input>,
    /// What the files could not establish, stated rather than guessed.
    pub gaps: Vec<String>,
}

impl Proposal {
    fn new(command: impl Into<String>, evidence: Vec<String>) -> Self {
        Self {
            command: command.into(),
            evidence,
            protected: Vec::new(),
            read_only: Vec::new(),
            gaps: Vec::new(),
        }
    }
}

/// Everything the proposer found: the proposals, in a fixed order (Cargo, Node,
/// Python, Go, Make), and each manifest that was recognised but could not support
/// one, with the reason.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Survey {
    /// The commands this project's files support, with their inputs.
    pub proposals: Vec<Proposal>,
    /// Why a recognised manifest proposes nothing (`package.json` without a `test`
    /// script, a bare `pyproject.toml`, no manifest at all).
    pub declined: Vec<String>,
}

impl Survey {
    /// Inspect `dir`. Only regular files at the root are consulted: a symlink, FIFO or
    /// other special node at a manifest's path counts as absent, and no file larger
    /// than 1 MiB is read.
    #[must_use]
    pub fn of(dir: &Path) -> Self {
        let mut survey = Self::default();
        if !MANIFESTS.iter().any(|name| is_regular_file(dir, name)) {
            survey.declined.push(
                "no manifest at the root; looked for Cargo.toml, package.json, pyproject.toml, \
                 pytest.ini, tox.ini, setup.cfg, go.mod and a Makefile"
                    .to_owned(),
            );
            return survey;
        }
        cargo(dir, &mut survey);
        node(dir, &mut survey);
        python(dir, &mut survey);
        go(dir, &mut survey);
        make(dir, &mut survey);
        survey
    }

    /// The proposals and refusals as the terminal shows them, two-space indented, with
    /// the evidence beside every command and input. Says nothing about acceptance: the
    /// caller adds what accepting means where it is shown.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        if self.proposals.is_empty() {
            let _ = writeln!(
                out,
                "No verification command can be proposed from this project's files"
            );
        } else {
            let _ = writeln!(
                out,
                "Proposed verification boundary, from the project's files (nothing was run)"
            );
        }
        for (i, p) in self.proposals.iter().enumerate() {
            if i > 0 {
                let _ = writeln!(out);
            }
            let width = p
                .protected
                .iter()
                .chain(&p.read_only)
                .map(|input| input.path.len())
                .max()
                .unwrap_or(0)
                .max(p.command.len());
            let _ = writeln!(
                out,
                "  {:<11} {:<width$}  {}",
                "command",
                p.command,
                p.evidence.join(" · ")
            );
            render_inputs(&mut out, "protected", &p.protected, width, "none found");
            render_inputs(&mut out, "read-only", &p.read_only, width, "none found");
            for gap in &p.gaps {
                let _ = writeln!(out, "  {:<11} {gap}", "gap");
            }
        }
        if !self.proposals.is_empty() && !self.declined.is_empty() {
            let _ = writeln!(out);
        }
        for why in &self.declined {
            let _ = writeln!(out, "  cannot propose: {why}");
        }
        out
    }
}

fn render_inputs(out: &mut String, label: &str, inputs: &[Input], width: usize, none: &str) {
    if inputs.is_empty() {
        let _ = writeln!(out, "  {label:<11} {none}");
        return;
    }
    for (i, input) in inputs.iter().enumerate() {
        let label = if i == 0 { label } else { "" };
        let _ = writeln!(out, "  {label:<11} {:<width$}  {}", input.path, input.why);
    }
}

/// Inspect `dir` and return every verify command its files support, in a fixed
/// order: Cargo, Node (pnpm, yarn, npm), Python, Go, Make. Empty when nothing is
/// recognised; [`Survey::of`] says why.
#[must_use]
pub fn propose(dir: &Path) -> Vec<Proposal> {
    Survey::of(dir).proposals
}

fn cargo(dir: &Path, survey: &mut Survey) {
    let Some(text) = read(dir, "Cargo.toml") else {
        return;
    };
    let manifest: toml::Value = match toml::from_str(&text) {
        Ok(value) => value,
        Err(e) => {
            survey.declined.push(format!(
                "Cargo.toml does not parse as TOML: {}",
                e.message()
            ));
            return;
        }
    };
    let mut proposal = Proposal::new("cargo test", vec!["Cargo.toml".to_owned()]);
    let workspace = manifest.get("workspace");
    if workspace.is_some() {
        proposal.command.push_str(" --workspace");
        proposal
            .evidence
            .push("[workspace] in Cargo.toml".to_owned());
    }
    let locked = is_regular_file(dir, "Cargo.lock");
    if locked {
        proposal.command.push_str(" --locked");
        proposal.evidence.push("Cargo.lock".to_owned());
    }
    if manifest.get("package").is_some() || workspace.is_none() {
        cargo_package_tests(dir, "", &manifest, &mut proposal.protected);
    }
    for member in workspace
        .map(|w| workspace_members(dir, w))
        .unwrap_or_default()
    {
        let Some(member_text) = read(dir, &format!("{member}/Cargo.toml")) else {
            continue;
        };
        let Ok(member_manifest) = toml::from_str::<toml::Value>(&member_text) else {
            proposal.gaps.push(format!(
                "{member}/Cargo.toml does not parse; its tests are not listed"
            ));
            continue;
        };
        let before = proposal.protected.len();
        cargo_package_tests(dir, &member, &member_manifest, &mut proposal.protected);
        for input in &mut proposal.protected[before..] {
            input.why = format!("workspace member {member}, members in Cargo.toml");
        }
    }
    if proposal.protected.is_empty() {
        proposal.gaps.push(
            "no tests/ directory and no [[test]] target: unit tests beside the code are not \
             restorable by path"
                .to_owned(),
        );
    }
    proposal
        .read_only
        .push(Input::new("Cargo.toml", "manifest"));
    if locked {
        proposal.read_only.push(Input::new(
            "Cargo.lock",
            "lockfile: pins the dependency set `--locked` checks",
        ));
    } else {
        proposal.gaps.push(
            "no Cargo.lock: the dependency set is not pinned, so `cargo test` may resolve new \
             versions"
                .to_owned(),
        );
    }
    if is_regular_file(dir, "rust-toolchain.toml") {
        proposal
            .read_only
            .push(Input::new("rust-toolchain.toml", "pins the toolchain"));
    }
    survey.proposals.push(proposal);
}

/// The test inputs of one Cargo package at `prefix` (empty for the root): its `tests/`
/// directory and every `[[test]]` target with a path of its own.
fn cargo_package_tests(dir: &Path, prefix: &str, manifest: &toml::Value, out: &mut Vec<Input>) {
    let rel = |name: &str| {
        if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        }
    };
    if is_dir(dir, &rel("tests")) {
        out.push(Input::new(
            format!("{}/", rel("tests")),
            "cargo integration tests directory",
        ));
    }
    let Some(targets) = manifest.get("test").and_then(toml::Value::as_array) else {
        return;
    };
    for target in targets {
        let path = target.get("path").and_then(toml::Value::as_str);
        let name = target.get("name").and_then(toml::Value::as_str);
        let (path, why) = match (path, name) {
            (Some(path), _) => (rel(path), "[[test]] path in Cargo.toml"),
            (None, Some(name)) => (
                rel(&format!("tests/{name}.rs")),
                "[[test]] name in Cargo.toml",
            ),
            (None, None) => continue,
        };
        if path.contains("..") || path.starts_with('/') || !is_regular_file(dir, &path) {
            continue;
        }
        if !out
            .iter()
            .any(|input| path.starts_with(input.path.as_str()))
        {
            out.push(Input::new(
                path,
                format!(
                    "{why}{}",
                    if prefix.is_empty() {
                        ""
                    } else {
                        " of the member"
                    }
                ),
            ));
        }
    }
}

/// `[workspace] members` minus `exclude`, with `*` and `?` in path components expanded
/// against the directories that exist, sorted.
fn workspace_members(dir: &Path, workspace: &toml::Value) -> Vec<String> {
    let patterns = |key: &str| -> Vec<String> {
        workspace
            .get(key)
            .and_then(toml::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .map(|s| s.trim_matches('/').to_owned())
                    .collect()
            })
            .unwrap_or_default()
    };
    let excluded = patterns("exclude");
    let mut members: Vec<String> = patterns("members")
        .iter()
        .flat_map(|pattern| expand(dir, pattern))
        .filter(|member| !excluded.contains(member))
        .collect();
    members.sort();
    members.dedup();
    members
}

/// The directories under `dir` matching `pattern`, component by component.
fn expand(dir: &Path, pattern: &str) -> Vec<String> {
    let mut found = vec![String::new()];
    for component in pattern.split('/').filter(|c| !c.is_empty()) {
        if component == "." || component == ".." {
            return Vec::new();
        }
        let mut next = Vec::new();
        for base in &found {
            if component.contains(['*', '?']) {
                let Ok(entries) = std::fs::read_dir(dir.join(base)) else {
                    continue;
                };
                let mut names: Vec<String> = entries
                    .filter_map(Result::ok)
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|name| glob_matches(component, name))
                    .collect();
                names.sort();
                next.extend(names.into_iter().map(|name| join(base, &name)));
            } else {
                let candidate = join(base, component);
                if is_dir(dir, &candidate) {
                    next.push(candidate);
                }
            }
        }
        found = next;
    }
    found.retain(|member| !member.is_empty());
    found
}

fn join(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_owned()
    } else {
        format!("{base}/{name}")
    }
}

/// Whether `name` matches `pattern`, where `*` is any run and `?` any one character.
fn glob_matches(pattern: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        match p.get(pi) {
            Some('*') => {
                star = Some((pi, ni));
                pi += 1;
            }
            Some(&c) if c == '?' || c == n[ni] => {
                pi += 1;
                ni += 1;
            }
            _ => match star {
                Some((sp, sn)) => {
                    pi = sp + 1;
                    ni = sn + 1;
                    star = Some((sp, sn + 1));
                }
                None => return false,
            },
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

fn node(dir: &Path, survey: &mut Survey) {
    let Some(text) = read(dir, "package.json") else {
        return;
    };
    let manifest: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(e) => {
            survey
                .declined
                .push(format!("package.json does not parse as JSON: {e}"));
            return;
        }
    };
    let has_test = manifest
        .pointer("/scripts/test")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|script| !script.trim().is_empty() && !script.contains(NPM_PLACEHOLDER));
    if !has_test {
        survey.declined.push(
            "package.json has no scripts.test (npm init's placeholder counts as none); the \
             package manager has nothing to run"
                .to_owned(),
        );
        return;
    }
    let script = "package.json scripts.test".to_owned();
    let mut managers: Vec<(&str, String, Option<&str>)> = Vec::new();
    for (lockfile, manager) in NODE_LOCKFILES {
        if is_regular_file(dir, lockfile) && !managers.iter().any(|(m, _, _)| *m == manager) {
            managers.push((manager, lockfile.to_owned(), Some(lockfile)));
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
            Some(manager) => (
                manager,
                format!("package.json packageManager: {manager}"),
                None,
            ),
            None => ("npm", "no lockfile: npm".to_owned(), None),
        });
    }
    let mut protected = Vec::new();
    for name in NODE_TEST_DIRS {
        if is_dir(dir, name) {
            protected.push(Input::new(format!("{name}/"), "test directory"));
        }
    }
    for name in NODE_TEST_CONFIGS {
        if is_regular_file(dir, name) {
            protected.push(Input::new(name, "test runner configuration"));
        }
    }
    for (manager, why, lockfile) in managers {
        let mut proposal = Proposal::new(format!("{manager} test"), vec![script.clone(), why]);
        proposal.protected.clone_from(&protected);
        if proposal.protected.is_empty() {
            proposal.gaps.push(
                "no test directory (test/, tests/, __tests__/, spec/) or runner configuration at \
                 the root: the test script decides what runs; name the test files to protect"
                    .to_owned(),
            );
        }
        proposal.read_only.push(Input::new(
            "package.json",
            "manifest; holds the test script",
        ));
        match lockfile {
            Some(lockfile) => proposal.read_only.push(Input::new(
                lockfile,
                format!("lockfile: pins the dependency set {manager} installs"),
            )),
            None => proposal
                .gaps
                .push("no lockfile: the dependency set is not pinned".to_owned()),
        }
        survey.proposals.push(proposal);
    }
}

/// What the Python test configuration at the root says, before it becomes a proposal.
#[derive(Default)]
struct PythonConfig {
    evidence: Vec<String>,
    protected: Vec<Input>,
    declined: Vec<String>,
    testpaths: Vec<(String, String)>,
}

impl PythonConfig {
    fn read_pyproject(&mut self, text: &str) {
        let manifest: toml::Value = match toml::from_str(text) {
            Ok(manifest) => manifest,
            Err(e) => {
                self.declined.push(format!(
                    "pyproject.toml does not parse as TOML: {}",
                    e.message()
                ));
                return;
            }
        };
        let pytest = manifest.get("tool").and_then(|t| t.get("pytest"));
        let section = ["ini_options", "ini-options"]
            .into_iter()
            .find_map(|key| pytest?.get(key));
        if let Some(options) = section {
            self.evidence
                .push("[tool.pytest.ini_options] in pyproject.toml".to_owned());
            for path in toml_paths(options.get("testpaths")) {
                self.testpaths.push((
                    path,
                    "testpaths in [tool.pytest.ini_options] in pyproject.toml".to_owned(),
                ));
            }
        } else if pytest.is_some() {
            self.evidence
                .push("[tool.pytest] in pyproject.toml".to_owned());
        } else if text.contains("\"pytest") || text.contains("'pytest") {
            self.evidence
                .push("pytest in pyproject.toml dependencies".to_owned());
        } else {
            self.declined.push(
                "pyproject.toml has no [tool.pytest.ini_options] section and no pytest \
                 dependency; no test command can be read from it"
                    .to_owned(),
            );
        }
    }

    fn read_ini_files(&mut self, dir: &Path) {
        for (file, section, why) in [
            ("pytest.ini", "pytest", "pytest configuration"),
            ("tox.ini", "pytest", "holds the [pytest] section"),
            (
                "setup.cfg",
                "tool:pytest",
                "holds the [tool:pytest] section",
            ),
        ] {
            let Some(text) = read(dir, file) else {
                continue;
            };
            if !has_header(&text, &format!("[{section}]")) {
                self.declined
                    .push(format!("{file} has no [{section}] section"));
                continue;
            }
            self.evidence.push(format!("[{section}] in {file}"));
            self.protected.push(Input::new(file, why));
            for path in ini_value(&text, section, "testpaths")
                .unwrap_or_default()
                .split_whitespace()
            {
                self.testpaths.push((
                    path.to_owned(),
                    format!("testpaths in [{section}] in {file}"),
                ));
            }
        }
    }
}

fn python(dir: &Path, survey: &mut Survey) {
    let mut config = PythonConfig::default();
    let pyproject = read(dir, "pyproject.toml");
    if let Some(text) = &pyproject {
        config.read_pyproject(text);
    }
    config.read_ini_files(dir);
    if config.evidence.is_empty() {
        survey.declined.extend(config.declined);
        return;
    }
    let mut proposal = Proposal::new("pytest", config.evidence);
    for (path, why) in config.testpaths {
        let path = path.trim_matches('/').to_owned();
        if path.is_empty() || path.contains("..") {
            continue;
        }
        let shown = if is_dir(dir, &path) {
            format!("{path}/")
        } else {
            path
        };
        if !proposal.protected.iter().any(|input| input.path == shown) {
            proposal.protected.push(Input::new(shown, why));
        }
    }
    if proposal
        .protected
        .iter()
        .all(|input| !input.path.ends_with('/'))
    {
        if let Some(name) = ["tests", "test"].into_iter().find(|name| is_dir(dir, name)) {
            proposal.protected.push(Input::new(
                format!("{name}/"),
                "test directory (no testpaths configured; pytest discovers test_*.py from the root)",
            ));
        } else {
            proposal.gaps.push(
                "no testpaths and no tests/ directory: pytest discovers test_*.py anywhere under \
                 the root; set testpaths to name the files to protect"
                    .to_owned(),
            );
        }
    }
    proposal.protected.extend(config.protected);
    if is_regular_file(dir, "conftest.py") {
        proposal
            .protected
            .push(Input::new("conftest.py", "pytest fixtures and hooks"));
    }
    if pyproject.is_some() {
        proposal
            .read_only
            .push(Input::new("pyproject.toml", "manifest"));
    }
    python_lockfiles(dir, &mut proposal);
    proposal.gaps.extend(config.declined);
    survey.proposals.push(proposal);
}

/// The lockfiles and pinned requirements a Python project keeps at its root, as
/// read-only inputs; a gap when there are none.
fn python_lockfiles(dir: &Path, proposal: &mut Proposal) {
    let mut pinned = false;
    for (lockfile, why) in PYTHON_LOCKFILES {
        if is_regular_file(dir, lockfile) {
            proposal.read_only.push(Input::new(lockfile, why));
            pinned = true;
        }
    }
    for name in requirements_files(dir) {
        proposal
            .read_only
            .push(Input::new(name, "pinned requirements"));
        pinned = true;
    }
    if !pinned {
        proposal.gaps.push(
            "no lockfile (poetry.lock, uv.lock, Pipfile.lock, requirements*.txt): the dependency \
             set is not pinned"
                .to_owned(),
        );
    }
}

/// `requirements*.txt` at the root, sorted.
fn requirements_files(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| {
            name.starts_with("requirements")
                && Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"))
        })
        .collect();
    names.sort();
    names
}

/// The strings of a TOML array, or a lone string, as a list.
fn toml_paths(value: Option<&toml::Value>) -> Vec<String> {
    match value {
        Some(toml::Value::Array(items)) => items
            .iter()
            .filter_map(toml::Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(toml::Value::String(one)) => vec![one.clone()],
        _ => Vec::new(),
    }
}

/// The value of `key` in INI `[section]`, continuation lines (indented) joined with
/// spaces.
fn ini_value(text: &str, section: &str, key: &str) -> Option<String> {
    let header = format!("[{section}]");
    let mut in_section = false;
    let mut value: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if value.is_some() {
                break;
            }
            in_section = trimmed == header;
            continue;
        }
        if !in_section || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(current) = &mut value {
            if line.starts_with([' ', '\t']) && !trimmed.is_empty() {
                current.push(' ');
                current.push_str(trimmed);
                continue;
            }
            break;
        }
        let Some((name, rest)) = trimmed.split_once(['=', ':']) else {
            continue;
        };
        if name.trim() == key {
            value = Some(rest.trim().to_owned());
        }
    }
    value.map(|v| v.trim().to_owned())
}

fn go(dir: &Path, survey: &mut Survey) {
    if !is_regular_file(dir, "go.mod") {
        return;
    }
    let mut proposal = Proposal::new("go test ./...", vec!["go.mod".to_owned()]);
    proposal.gaps.push(
        "Go tests live beside the code (*_test.go): nothing is restorable by directory".to_owned(),
    );
    proposal
        .read_only
        .push(Input::new("go.mod", "module manifest"));
    if is_regular_file(dir, "go.sum") {
        proposal
            .read_only
            .push(Input::new("go.sum", "checksums: pin the module set"));
    } else {
        proposal
            .gaps
            .push("no go.sum: the module set is not pinned".to_owned());
    }
    survey.proposals.push(proposal);
}

fn make(dir: &Path, survey: &mut Survey) {
    let Some((name, text)) = ["GNUmakefile", "makefile", "Makefile"]
        .into_iter()
        .find_map(|name| read(dir, name).map(|text| (name, text)))
    else {
        return;
    };
    if !text.lines().any(defines_test_target) {
        survey.declined.push(format!("{name} has no `test` target"));
        return;
    }
    let mut proposal = Proposal::new("make test", vec![format!("test target in {name}")]);
    for dir_name in ["tests", "test"] {
        if is_dir(dir, dir_name) {
            proposal
                .protected
                .push(Input::new(format!("{dir_name}/"), "test directory"));
        }
    }
    if proposal.protected.is_empty() {
        proposal.gaps.push(
            "no tests/ directory: the `test` target decides what runs; name the test files to \
             protect"
                .to_owned(),
        );
    }
    proposal
        .read_only
        .push(Input::new(name, "holds the `test` target"));
    survey.proposals.push(proposal);
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

/// Whether `rel` under `dir` is a directory, not following a symlink.
fn is_dir(dir: &Path, rel: &str) -> bool {
    dir.join(rel)
        .symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_dir())
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
    /// root (a path ending in `/` is a directory), written into a fresh temporary
    /// directory.
    fn fixture(name: &str) -> tempfile::TempDir {
        let files: &[(&str, &str)] = match name {
            "cargo" => &[
                ("Cargo.toml", "[package]\nname = \"app\"\n"),
                ("Cargo.lock", "version = 4\n"),
                ("tests/", ""),
            ],
            "cargo-workspace" => &[
                (
                    "Cargo.toml",
                    "[workspace]\nmembers = [\"crates/*\", \"tools/bench\"]\nexclude = [\"crates/skip\"]\n",
                ),
                ("Cargo.lock", "version = 4\n"),
                ("crates/a/Cargo.toml", "[package]\nname = \"a\"\n"),
                ("crates/a/tests/", ""),
                ("crates/b/Cargo.toml", "[package]\nname = \"b\"\n"),
                ("crates/skip/Cargo.toml", "[package]\nname = \"skip\"\n"),
                ("crates/skip/tests/", ""),
                ("tools/bench/Cargo.toml", "[package]\nname = \"bench\"\n"),
                ("tools/bench/tests/", ""),
                ("crates/not-a-crate/tests/", ""),
            ],
            "cargo-test-targets" => &[
                (
                    "Cargo.toml",
                    "[package]\nname = \"app\"\n\n[[test]]\nname = \"smoke\"\npath = \"qa/smoke.rs\"\n\n[[test]]\nname = \"named\"\n\n[[test]]\nname = \"escape\"\npath = \"../outside.rs\"\n",
                ),
                ("Cargo.lock", "version = 4\n"),
                ("rust-toolchain.toml", "[toolchain]\nchannel = \"1.94\"\n"),
                ("qa/smoke.rs", ""),
            ],
            "cargo-unlocked" => &[("Cargo.toml", "[package]\nname = \"lib\"\n")],
            "cargo-broken" => &[("Cargo.toml", "[package\nname = \"lib\"\n")],
            "npm" => &[
                ("package.json", WITH_TEST),
                ("package-lock.json", "{}"),
                ("test/", ""),
                ("jest.config.js", "module.exports = {};\n"),
            ],
            "npm-unlocked" => &[("package.json", WITH_TEST)],
            "npm-no-test" => &[("package.json", NO_TEST), ("package-lock.json", "{}")],
            "npm-placeholder" => &[("package.json", PLACEHOLDER)],
            "npm-broken" => &[("package.json", "{not json")],
            "pnpm" => &[
                ("package.json", WITH_TEST),
                ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
                ("__tests__/", ""),
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
            "python-pyproject" => &[
                (
                    "pyproject.toml",
                    "[project]\nname = \"app\"\n\n[tool.pytest.ini_options]\ntestpaths = [\"src/app/testing\", \"qa\"]\n",
                ),
                ("src/app/testing/", ""),
                ("qa/", ""),
                ("tests/", ""),
                ("uv.lock", "version = 1\n"),
                ("conftest.py", ""),
            ],
            "python-dependency" => &[
                (
                    "pyproject.toml",
                    "[project]\nname = \"app\"\n[project.optional-dependencies]\ntest = [\"pytest>=8\"]\n",
                ),
                ("tests/", ""),
                ("poetry.lock", ""),
            ],
            "python-bare" => &[("pyproject.toml", "[project]\nname = \"app\"\n")],
            "python-broken" => &[("pyproject.toml", "[project\n")],
            "pytest-ini" => &[
                (
                    "pytest.ini",
                    "[pytest]\naddopts = -q\ntestpaths =\n    integration\n    unit\n",
                ),
                ("integration/", ""),
                ("requirements.txt", "pytest==8.0.0\n"),
                ("requirements-dev.txt", "ruff\n"),
            ],
            "tox" => &[(
                "tox.ini",
                "[tox]\nenvlist = py3\n\n[pytest]\naddopts = -q\n",
            )],
            "tox-no-pytest" => &[("tox.ini", "[tox]\nenvlist = py3\n")],
            "setup-cfg" => &[("setup.cfg", "[metadata]\nname = app\n\n[tool:pytest]\n")],
            "go" => &[
                ("go.mod", "module example.com/app\n\ngo 1.22\n"),
                ("go.sum", ""),
            ],
            "make" => &[
                (
                    "Makefile",
                    ".PHONY: build test\nbuild:\n\tcc main.c\n\ntest: build\n\t./run-tests\n",
                ),
                ("tests/", ""),
            ],
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
            "cargo-and-scriptless-package" => &[
                ("Cargo.toml", "[package]\nname = \"app\"\n"),
                ("package.json", NO_TEST),
            ],
            "none" => &[("README.md", "# nothing to build\n")],
            other => panic!("unknown fixture {other}"),
        };
        let dir = tempfile::tempdir().unwrap();
        for (path, content) in files {
            let full = dir.path().join(path);
            if path.ends_with('/') {
                std::fs::create_dir_all(&full).unwrap();
            } else {
                std::fs::create_dir_all(full.parent().unwrap()).unwrap();
                std::fs::write(full, content).unwrap();
            }
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

    fn only(name: &str) -> Proposal {
        let mut proposals = propose(fixture(name).path());
        assert_eq!(proposals.len(), 1, "{name}: {proposals:?}");
        proposals.remove(0)
    }

    fn paths(inputs: &[Input]) -> Vec<&str> {
        inputs.iter().map(|i| i.path.as_str()).collect()
    }

    fn declined(name: &str) -> Vec<String> {
        Survey::of(fixture(name).path()).declined
    }

    #[test]
    fn cargo_pins_the_lockfile_when_there_is_one() {
        assert_eq!(commands("cargo"), ["cargo test --locked"]);
        assert_eq!(evidence("cargo"), ["Cargo.toml", "Cargo.lock"]);
        assert_eq!(commands("cargo-unlocked"), ["cargo test"]);
        assert_eq!(evidence("cargo-unlocked"), ["Cargo.toml"]);
    }

    #[test]
    fn cargo_protects_tests_and_reads_the_manifest_and_lockfile() {
        let p = only("cargo");
        assert_eq!(paths(&p.protected), ["tests/"]);
        assert_eq!(p.protected[0].why, "cargo integration tests directory");
        assert_eq!(paths(&p.read_only), ["Cargo.toml", "Cargo.lock"]);
        assert!(p.read_only[1].why.contains("lockfile"), "{:?}", p.read_only);
        assert!(p.gaps.is_empty(), "{:?}", p.gaps);

        let p = only("cargo-unlocked");
        assert!(p.protected.is_empty());
        assert_eq!(paths(&p.read_only), ["Cargo.toml"]);
        assert!(
            p.gaps.iter().any(|g| g.contains("no Cargo.lock")),
            "{:?}",
            p.gaps
        );
        assert!(
            p.gaps.iter().any(|g| g.contains("no tests/")),
            "{:?}",
            p.gaps
        );
    }

    #[test]
    fn a_cargo_workspace_tests_every_member_and_protects_each_member_s_tests() {
        assert_eq!(
            commands("cargo-workspace"),
            ["cargo test --workspace --locked"]
        );
        assert_eq!(
            evidence("cargo-workspace"),
            ["Cargo.toml", "[workspace] in Cargo.toml", "Cargo.lock"]
        );
        let p = only("cargo-workspace");
        assert_eq!(
            paths(&p.protected),
            ["crates/a/tests/", "tools/bench/tests/"],
            "globbed and literal members with tests, never an excluded or manifest-less directory"
        );
        assert_eq!(
            p.protected[0].why,
            "workspace member crates/a, members in Cargo.toml"
        );
    }

    #[test]
    fn cargo_test_targets_with_their_own_paths_are_protected_inside_the_tree_only() {
        let p = only("cargo-test-targets");
        assert_eq!(
            paths(&p.protected),
            ["qa/smoke.rs"],
            "a named target without a file on disk and a path escaping the tree are not inputs"
        );
        assert_eq!(p.protected[0].why, "[[test]] path in Cargo.toml");
        assert_eq!(
            paths(&p.read_only),
            ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
        );
    }

    #[test]
    fn an_unparsable_cargo_manifest_is_declined_not_guessed() {
        assert!(commands("cargo-broken").is_empty());
        let why = declined("cargo-broken");
        assert_eq!(why.len(), 1, "{why:?}");
        assert!(why[0].starts_with("Cargo.toml does not parse"), "{why:?}");
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
    fn node_protects_test_directories_and_runner_config_and_reads_the_lockfile() {
        let p = only("npm");
        assert_eq!(paths(&p.protected), ["test/", "jest.config.js"]);
        assert_eq!(p.protected[1].why, "test runner configuration");
        assert_eq!(paths(&p.read_only), ["package.json", "package-lock.json"]);
        assert!(
            p.read_only[1].why.contains("npm installs"),
            "{:?}",
            p.read_only
        );

        let p = only("pnpm");
        assert_eq!(paths(&p.protected), ["__tests__/"]);
        assert_eq!(paths(&p.read_only), ["package.json", "pnpm-lock.yaml"]);

        let p = only("yarn");
        assert!(p.protected.is_empty());
        assert!(
            p.gaps.iter().any(|g| g.contains("no test directory")),
            "{:?}",
            p.gaps
        );
        assert_eq!(paths(&p.read_only), ["package.json", "yarn.lock"]);
    }

    #[test]
    fn node_without_a_lockfile_uses_the_declared_manager_or_npm_and_says_nothing_is_pinned() {
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
        let p = only("npm-unlocked");
        assert_eq!(paths(&p.read_only), ["package.json"]);
        assert!(
            p.gaps.iter().any(|g| g.contains("no lockfile")),
            "{:?}",
            p.gaps
        );
    }

    #[test]
    fn package_json_without_a_real_test_script_is_declined_with_the_reason() {
        for name in ["npm-no-test", "npm-placeholder"] {
            assert!(commands(name).is_empty(), "{name}");
            let why = declined(name);
            assert_eq!(why.len(), 1, "{name}: {why:?}");
            assert!(why[0].contains("no scripts.test"), "{name}: {why:?}");
        }
        let why = declined("npm-broken");
        assert!(why[0].starts_with("package.json does not parse"), "{why:?}");
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
            ("pytest-ini", "[pytest] in pytest.ini"),
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
        assert!(declined("python-bare")[0].contains("no [tool.pytest.ini_options]"));
        assert!(commands("tox-no-pytest").is_empty());
        assert_eq!(
            declined("tox-no-pytest"),
            ["tox.ini has no [pytest] section"]
        );
        assert!(declined("python-broken")[0].starts_with("pyproject.toml does not parse"));
    }

    #[test]
    fn python_protects_the_configured_testpaths_not_an_assumed_tests_directory() {
        let p = only("python-pyproject");
        assert_eq!(
            paths(&p.protected),
            ["src/app/testing/", "qa/", "conftest.py"],
            "tests/ exists but testpaths names other directories"
        );
        assert_eq!(
            p.protected[0].why,
            "testpaths in [tool.pytest.ini_options] in pyproject.toml"
        );
        assert_eq!(paths(&p.read_only), ["pyproject.toml", "uv.lock"]);
        assert!(p.gaps.is_empty(), "{:?}", p.gaps);

        let p = only("pytest-ini");
        assert_eq!(
            paths(&p.protected),
            ["integration/", "unit", "pytest.ini"],
            "multi-line INI testpaths; a path not on disk is kept as written"
        );
        assert_eq!(p.protected[0].why, "testpaths in [pytest] in pytest.ini");
        assert_eq!(
            paths(&p.read_only),
            ["requirements-dev.txt", "requirements.txt"]
        );

        let p = only("python-dependency");
        assert_eq!(paths(&p.protected), ["tests/"]);
        assert!(p.protected[0].why.contains("no testpaths configured"));
        assert_eq!(paths(&p.read_only), ["pyproject.toml", "poetry.lock"]);

        let p = only("tox");
        assert_eq!(paths(&p.protected), ["tox.ini"]);
        assert!(
            p.gaps
                .iter()
                .any(|g| g.contains("no testpaths and no tests/")),
            "{:?}",
            p.gaps
        );
        assert!(
            p.gaps.iter().any(|g| g.contains("no lockfile")),
            "{:?}",
            p.gaps
        );
    }

    #[test]
    fn go_tests_every_package_of_the_module() {
        assert_eq!(commands("go"), ["go test ./..."]);
        assert_eq!(evidence("go"), ["go.mod"]);
        let p = only("go");
        assert!(p.protected.is_empty());
        assert_eq!(paths(&p.read_only), ["go.mod", "go.sum"]);
        assert!(p.gaps[0].contains("*_test.go"), "{:?}", p.gaps);
    }

    #[test]
    fn make_needs_a_test_target() {
        assert_eq!(commands("make"), ["make test"]);
        assert_eq!(evidence("make"), ["test target in Makefile"]);
        assert_eq!(paths(&only("make").protected), ["tests/"]);
        assert_eq!(paths(&only("make").read_only), ["Makefile"]);
        assert_eq!(commands("make-multi-target"), ["make test"]);
        assert!(commands("make-no-test").is_empty());
        assert_eq!(declined("make-no-test"), ["Makefile has no `test` target"]);
    }

    #[test]
    fn several_ecosystems_are_several_proposals_in_a_fixed_order() {
        assert_eq!(
            commands("mixed"),
            ["cargo test --locked", "pnpm test", "make test"]
        );
        let dir = fixture("mixed");
        assert_eq!(
            Survey::of(dir.path()),
            Survey::of(dir.path()),
            "deterministic"
        );
        let survey = Survey::of(fixture("cargo-and-scriptless-package").path());
        assert_eq!(survey.proposals.len(), 1);
        assert_eq!(survey.declined.len(), 1, "{:?}", survey.declined);
    }

    #[test]
    fn nothing_recognised_is_declined_naming_what_was_looked_for() {
        assert!(commands("none").is_empty());
        let why = declined("none");
        assert_eq!(why.len(), 1, "{why:?}");
        assert!(why[0].starts_with("no manifest at the root"), "{why:?}");
        assert!(why[0].contains("Cargo.toml"), "{why:?}");
        assert!(
            Survey::of(&fixture("none").path().join("absent"))
                .proposals
                .is_empty()
        );
    }

    #[test]
    fn the_rendering_shows_every_input_with_its_evidence_and_every_refusal() {
        let text = Survey::of(fixture("cargo-workspace").path()).render();
        assert!(text.starts_with("Proposed verification boundary"), "{text}");
        assert!(
            text.contains("cargo test --workspace --locked")
                && text.contains("[workspace] in Cargo.toml"),
            "{text}"
        );
        assert!(text.contains("crates/a/tests/"), "{text}");
        assert!(text.contains("workspace member crates/a"), "{text}");
        assert!(text.contains("read-only   Cargo.toml"), "{text}");
        assert!(!text.contains("gap"), "{text}");

        let text = Survey::of(fixture("npm-no-test").path()).render();
        assert!(text.starts_with("No verification command"), "{text}");
        assert!(
            text.contains("  cannot propose: package.json has no scripts.test"),
            "{text}"
        );

        let text = Survey::of(fixture("cargo-unlocked").path()).render();
        assert!(text.contains("protected   none found"), "{text}");
        assert!(text.contains("gap         no Cargo.lock"), "{text}");

        let text = Survey::of(fixture("cargo-and-scriptless-package").path()).render();
        assert!(text.contains("command     cargo test"), "{text}");
        assert!(text.contains("cannot propose: package.json"), "{text}");
    }

    #[test]
    fn globs_match_whole_components() {
        assert!(glob_matches("*", "anything"));
        assert!(glob_matches("ward-*", "ward-cli"));
        assert!(!glob_matches("ward-*", "wardcli"));
        assert!(glob_matches("a?c", "abc"));
        assert!(!glob_matches("a?c", "abbc"));
        assert!(glob_matches("*-*", "x-y-z"));
        assert!(!glob_matches("", "x"));
        assert!(glob_matches("**", ""));
    }

    #[test]
    fn ini_values_span_continuation_lines_and_stop_at_the_next_section_or_key() {
        let text = "[pytest]\naddopts = -q\ntestpaths =\n    a\n    b\nmarkers = slow\n[other]\ntestpaths = z\n";
        assert_eq!(
            ini_value(text, "pytest", "testpaths").as_deref(),
            Some("a b")
        );
        assert_eq!(
            ini_value(text, "pytest", "markers").as_deref(),
            Some("slow")
        );
        assert_eq!(ini_value(text, "other", "testpaths").as_deref(), Some("z"));
        assert_eq!(ini_value(text, "pytest", "missing"), None);
        assert_eq!(
            ini_value("[pytest]\n# testpaths = x\n", "pytest", "testpaths"),
            None
        );
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

        let dir = fixture("cargo-unlocked");
        std::os::unix::fs::symlink(outside.path(), dir.path().join("tests")).unwrap();
        assert!(
            only_in(dir.path()).protected.is_empty(),
            "a symlinked tests directory is not a protected input"
        );
    }

    fn only_in(dir: &Path) -> Proposal {
        propose(dir).remove(0)
    }
}
