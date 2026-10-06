//! Prepared verifier environments (#147 items 3, 4 and 6): the dependency set a
//! project's lockfile pins, installed once in an explicit online phase (`ward prepare`)
//! into a sealed directory under the state root, and mounted read-only into the
//! offline verifier whenever the project's current inputs still match.
//!
//! The environment is keyed by a digest over everything that decides its contents:
//! the ecosystem and package manager, the content digests of the lockfile and the
//! manifest beside it, the runtime's own `--version`, the platform and the configured
//! registry ([`Key::derive`]). A different key is a different directory, so nothing is
//! ever updated in place: a lockfile edit, a runtime upgrade or a new registry makes
//! the old environment *stale* ([`Lookup::Missing`]) and `ward ready` says so with the
//! reason; the verifier runs without it rather than fetching anything itself.
//!
//! The install runs in the same bubblewrap sandbox the verifier uses, with the same
//! read-only toolchain mounts and the same `PATH` — plus the host's network namespace,
//! which the launch asks for explicitly ([`crate::sandbox::Launch::host_network`]) and
//! this module records in the environment's `prepared.json`. The project's worktree is
//! not mounted at all: the install sees only a copy of its lockfile inputs and writes
//! only into the environment's `stage/`, which is sealed read-only on success. An
//! install that exits non-zero leaves a *failed* record, one that is killed or outruns
//! its budget an *incomplete* one; neither is ever mounted, and the next `ward prepare`
//! removes the partial tree and starts from scratch, counting the attempt.
//!
//! Ecosystems: Node with a lockfile (`npm ci`, `pnpm install --frozen-lockfile`,
//! `yarn install --frozen-lockfile`, each with `--ignore-scripts` so no project or
//! dependency script runs during preparation) and Python with `requirements*.txt`
//! (`pip install --target`). Cargo needs no prepared environment: the verifier already
//! mounts the host's `~/.cargo/registry` read-only ([`crate::verify::Toolchains`]) and
//! `cargo test --locked` resolves offline from it. Poetry, uv and pipenv lockfiles are
//! recognised and declined by name until their tools are supported.

use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::sandbox::{Launch, StdioMode, WORK_ROOT};
use crate::verify::{Mount, Toolchains};

/// Directory under the state root holding every prepared environment.
pub const PREPARED_DIR: &str = "prepared";
/// Directory under [`PREPARED_DIR`] holding one pointer per project to the environment
/// it last prepared, so a stale environment can be explained, not just missed.
const PROJECTS_DIR: &str = "projects";
/// The installed tree inside an environment: the sandbox's `/work` during the install.
pub const STAGE_DIR: &str = "stage";
/// The environment's record.
pub const RECORD_FILE: &str = "prepared.json";
/// Where a Python environment is mounted inside the verifier.
pub const DEPS_ROOT: &str = "/run/verifier/deps";
/// Bytes of the installer's output kept in the record.
pub const OUTPUT_TAIL_BYTES: usize = 4096;
/// Wall-clock budget of one install.
pub const BUDGET: Duration = Duration::from_secs(30 * 60);
/// What the record says about the network the install had.
pub const NETWORK_NOTE: &str = "host network namespace during `ward prepare` only; the verifier mounts the result with no network";
/// The record format this module writes and reads.
const RECORD_VERSION: u32 = 1;
/// The largest input file hashed and copied.
const MAX_INPUT_BYTES: u64 = 64 << 20;
/// Node lockfiles, most specific manager first, as [`crate::verify_proposal`] orders them.
const NODE_LOCKFILES: [(&str, Ecosystem); 4] = [
    ("pnpm-lock.yaml", Ecosystem::NodePnpm),
    ("yarn.lock", Ecosystem::NodeYarn),
    ("package-lock.json", Ecosystem::NodeNpm),
    ("npm-shrinkwrap.json", Ecosystem::NodeNpm),
];
/// Python lockfiles whose tools are not run yet, with the tool each needs.
const PYTHON_LOCKFILES: [(&str, &str); 3] = [
    ("poetry.lock", "poetry"),
    ("uv.lock", "uv"),
    ("Pipfile.lock", "pipenv"),
];
/// Proxy settings an install may need to reach its registry; passed through by name
/// when set on the host, and recorded by name only (a value may carry credentials).
const PROXY_ENV: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];

/// The package ecosystem and manager an environment is prepared with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ecosystem {
    /// `package.json` with `package-lock.json` or `npm-shrinkwrap.json`.
    NodeNpm,
    /// `package.json` with `pnpm-lock.yaml`.
    NodePnpm,
    /// `package.json` with `yarn.lock`.
    NodeYarn,
    /// `requirements*.txt`, installed with pip into a `--target` directory.
    PythonPip,
}

impl Ecosystem {
    /// The record's and the report's name for this ecosystem.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NodeNpm => "node-npm",
            Self::NodePnpm => "node-pnpm",
            Self::NodeYarn => "node-yarn",
            Self::PythonPip => "python-pip",
        }
    }

    /// The runtime whose `--version` is part of the key.
    #[must_use]
    pub const fn runtime_program(self) -> &'static str {
        match self {
            Self::NodeNpm | Self::NodePnpm | Self::NodeYarn => "node",
            Self::PythonPip => "python3",
        }
    }

    /// The installed tree, relative to the stage.
    #[must_use]
    pub const fn tree(self) -> &'static str {
        match self {
            Self::NodeNpm | Self::NodePnpm | Self::NodeYarn => "node_modules",
            Self::PythonPip => "site-packages",
        }
    }

    /// The executables the tree provides, relative to the stage.
    #[must_use]
    pub const fn bin(self) -> &'static str {
        match self {
            Self::NodeNpm | Self::NodePnpm | Self::NodeYarn => "node_modules/.bin",
            Self::PythonPip => "site-packages/bin",
        }
    }

    /// Where the verifier sees the tree: `node_modules` beside the candidate, where
    /// Node resolves it; a Python target directory under [`DEPS_ROOT`], named by
    /// `PYTHONPATH`.
    #[must_use]
    pub fn sandbox_tree(self) -> String {
        match self {
            Self::NodeNpm | Self::NodePnpm | Self::NodeYarn => format!("{WORK_ROOT}/node_modules"),
            Self::PythonPip => format!("{DEPS_ROOT}/site-packages"),
        }
    }

    /// The install command, run at the stage root. Every manager is told to install
    /// exactly the lockfile and to run no scripts.
    #[must_use]
    pub fn install_argv(self, recipe: &Recipe) -> Vec<String> {
        let argv: Vec<&str> = match self {
            Self::NodeNpm => vec!["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            Self::NodePnpm => vec!["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"],
            Self::NodeYarn => vec![
                "yarn",
                "install",
                "--frozen-lockfile",
                "--ignore-scripts",
                "--non-interactive",
            ],
            Self::PythonPip => {
                let mut argv = vec![
                    "python3",
                    "-m",
                    "pip",
                    "install",
                    "--target",
                    "site-packages",
                    "--no-input",
                    "--disable-pip-version-check",
                ];
                for input in &recipe.inputs {
                    argv.push("-r");
                    argv.push(&input.path);
                }
                return argv.into_iter().map(str::to_owned).collect();
            }
        };
        argv.into_iter().map(str::to_owned).collect()
    }

    /// The registry setting that applies to this ecosystem, from `settings`.
    fn registry(self, settings: &Settings) -> Option<&str> {
        match self {
            Self::NodeNpm | Self::NodePnpm | Self::NodeYarn => settings.npm_registry.as_deref(),
            Self::PythonPip => settings.pip_index_url.as_deref(),
        }
    }

    /// The environment variable the install reads its registry from.
    const fn registry_env(self) -> &'static str {
        match self {
            Self::NodeNpm | Self::NodePnpm | Self::NodeYarn => "NPM_CONFIG_REGISTRY",
            Self::PythonPip => "PIP_INDEX_URL",
        }
    }
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// One root-level input file and the digest of its content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputFile {
    /// The file name at the project root.
    pub path: String,
    /// BLAKE3 of its bytes, hex.
    pub digest: String,
}

impl InputFile {
    /// An input from its name and bytes.
    #[must_use]
    pub fn new(path: &str, bytes: &[u8]) -> Self {
        Self {
            path: path.to_owned(),
            digest: blake3::hash(bytes).to_hex().to_string(),
        }
    }
}

/// The trusted installation settings that change what an install produces: the
/// registry an ecosystem's manager fetches from. Read from the preparing process's
/// environment; a project's own `.npmrc` is an input file instead.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// `NPM_CONFIG_REGISTRY`, for the Node managers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub npm_registry: Option<String>,
    /// `PIP_INDEX_URL`, for pip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pip_index_url: Option<String>,
}

impl Settings {
    /// The settings in this process's environment.
    #[must_use]
    pub fn from_env() -> Self {
        let get = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        Self {
            npm_registry: get("NPM_CONFIG_REGISTRY"),
            pip_index_url: get("PIP_INDEX_URL"),
        }
    }

    /// Only the setting `ecosystem` reads.
    fn narrowed(&self, ecosystem: Ecosystem) -> Self {
        let mut out = Self::default();
        match ecosystem {
            Ecosystem::NodeNpm | Ecosystem::NodePnpm | Ecosystem::NodeYarn => {
                out.npm_registry.clone_from(&self.npm_registry);
            }
            Ecosystem::PythonPip => out.pip_index_url.clone_from(&self.pip_index_url),
        }
        out
    }
}

/// What a project's files say should be installed, and from what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipe {
    /// The ecosystem and manager.
    pub ecosystem: Ecosystem,
    /// The root-level files the install reads, sorted by name, each with its digest.
    pub inputs: Vec<InputFile>,
    /// The registry setting that applies.
    pub settings: Settings,
}

impl Recipe {
    /// The lockfile among the inputs, for messages.
    #[must_use]
    pub fn lockfile(&self) -> &str {
        self.inputs
            .iter()
            .map(|i| i.path.as_str())
            .find(|p| {
                NODE_LOCKFILES.iter().any(|(name, _)| name == p) || p.starts_with("requirements")
            })
            .unwrap_or("the lockfile")
    }
}

/// What [`plan`] found at a project root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Something to install, and how.
    Recipe(Recipe),
    /// A manifest that names dependencies but nothing this module can install from,
    /// with the reason.
    Declined(String),
    /// No prepared environment is needed, with the reason.
    NotNeeded(String),
}

/// Read the project root: a Node manifest with a lockfile, Python requirements, or
/// nothing to prepare. Pure: reads a handful of regular files, runs nothing.
#[must_use]
pub fn plan(dir: &Path, settings: &Settings) -> Plan {
    if is_regular_file(dir, "package.json") {
        return plan_node(dir, settings);
    }
    let python_marker = [
        "pyproject.toml",
        "setup.cfg",
        "pytest.ini",
        "tox.ini",
        "Pipfile",
    ]
    .iter()
    .any(|name| is_regular_file(dir, name))
        || PYTHON_LOCKFILES
            .iter()
            .any(|(name, _)| is_regular_file(dir, name));
    let requirements = requirements_files(dir);
    if python_marker || !requirements.is_empty() {
        return plan_python(dir, settings, &requirements);
    }
    if is_regular_file(dir, "Cargo.toml") {
        return Plan::NotNeeded(
            "cargo: the verifier mounts the host's ~/.cargo/registry read-only and `cargo test \
             --locked` resolves offline from it (`cargo fetch` on the host fills a missing crate); \
             not a `ward prepare` ecosystem"
                .to_owned(),
        );
    }
    Plan::NotNeeded("no Node or Python lockfile at the root; nothing to prepare".to_owned())
}

fn plan_node(dir: &Path, settings: &Settings) -> Plan {
    let Some((lockfile, ecosystem)) = NODE_LOCKFILES
        .iter()
        .copied()
        .find(|(name, _)| is_regular_file(dir, name))
    else {
        return Plan::Declined(
            "no lockfile beside package.json (package-lock.json, npm-shrinkwrap.json, \
             pnpm-lock.yaml or yarn.lock): `ward prepare` installs only a pinned dependency set"
                .to_owned(),
        );
    };
    let mut names = vec![lockfile, "package.json"];
    if is_regular_file(dir, ".npmrc") {
        names.push(".npmrc");
    }
    recipe(dir, ecosystem, &names, settings)
}

fn plan_python(dir: &Path, settings: &Settings, requirements: &[String]) -> Plan {
    if requirements.is_empty() {
        if let Some((lockfile, tool)) = PYTHON_LOCKFILES
            .iter()
            .find(|(name, _)| is_regular_file(dir, name))
        {
            return Plan::Declined(format!(
                "{lockfile} pins the dependency set but needs {tool}, which `ward prepare` does not \
                 run yet; export it to requirements.txt to prepare from"
            ));
        }
        return Plan::Declined(
            "no requirements*.txt at the root: nothing pins the dependency set `ward prepare` \
             would install"
                .to_owned(),
        );
    }
    let names: Vec<&str> = requirements.iter().map(String::as_str).collect();
    recipe(dir, Ecosystem::PythonPip, &names, settings)
}

/// Hash the named root-level files into a recipe, sorted by name.
fn recipe(dir: &Path, ecosystem: Ecosystem, names: &[&str], settings: &Settings) -> Plan {
    let mut inputs = Vec::new();
    for name in names {
        match read_input(dir, name) {
            Ok(bytes) => inputs.push(InputFile::new(name, &bytes)),
            Err(why) => return Plan::Declined(why),
        }
    }
    inputs.sort_by(|a, b| a.path.cmp(&b.path));
    Plan::Recipe(Recipe {
        ecosystem,
        inputs,
        settings: settings.narrowed(ecosystem),
    })
}

/// `requirements*.txt` at the root, sorted.
fn requirements_files(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(std::result::Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| {
            name.starts_with("requirements")
                && Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"))
                && is_regular_file(dir, name)
        })
        .collect();
    names.sort();
    names
}

/// Whether `name` at the root is a regular file (a symlink or special node counts as
/// absent, as [`crate::verify_proposal`] treats manifests).
fn is_regular_file(dir: &Path, name: &str) -> bool {
    std::fs::symlink_metadata(dir.join(name)).is_ok_and(|m| m.file_type().is_file())
}

/// The bytes of a root-level regular file, bounded.
fn read_input(dir: &Path, name: &str) -> std::result::Result<Vec<u8>, String> {
    let path = dir.join(name);
    let meta = std::fs::symlink_metadata(&path).map_err(|e| format!("{name}: {e}"))?;
    if !meta.file_type().is_file() {
        return Err(format!("{name} is not a regular file"));
    }
    if meta.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "{name} is larger than {} and is not hashed",
            crate::render::human_bytes(MAX_INPUT_BYTES)
        ));
    }
    std::fs::read(&path).map_err(|e| format!("{name}: {e}"))
}

/// The runtime an environment is built for, as the verifier would find it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Runtime {
    /// The bare program name the install and the verifier resolve (`node`, `python3`).
    pub program: String,
    /// Where it was found on the host, in the verifier's own search directories.
    pub host_path: PathBuf,
    /// The first line of its `--version`.
    pub version: String,
}

/// Find `ecosystem`'s runtime in the verifier's search directories
/// ([`Toolchains::search_dirs`]) and ask it for its version. The host directories here
/// are the verifier's own, so the version is the one the verifier would run — never
/// whatever the calling shell has on its `PATH`.
pub fn runtime_identity(ecosystem: Ecosystem, search_dirs: &[PathBuf]) -> Result<Runtime> {
    let program = ecosystem.runtime_program();
    let host_path = search_dirs
        .iter()
        .map(|dir| dir.join(program))
        .find(|p| {
            std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
        .ok_or_else(|| {
            Error::Project(format!(
                "{program} is not in the verifier's search directories ({}); the environment \
                 cannot be keyed to a runtime",
                search_dirs
                    .iter()
                    .map(|d| d.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;
    let out = std::process::Command::new(&host_path)
        .arg("--version")
        .env_clear()
        .env(
            "PATH",
            std::env::join_paths(search_dirs).unwrap_or_default(),
        )
        .output()
        .map_err(|e| Error::io(&host_path, e))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let version = text.lines().map(str::trim).find(|l| !l.is_empty());
    match version {
        Some(version) if out.status.success() => Ok(Runtime {
            program: program.to_owned(),
            host_path,
            version: version.to_owned(),
        }),
        _ => Err(Error::Project(format!(
            "{} --version failed ({}): {}",
            host_path.display(),
            out.status,
            text.trim()
        ))),
    }
}

/// The platform an environment is built on: architecture, OS and libc family of this
/// binary (the verifier runs the host's own toolchains, so they are the host's), and the
/// OS release when `/etc/os-release` names one.
#[must_use]
pub fn platform() -> String {
    let libc = if cfg!(target_env = "musl") {
        "musl"
    } else {
        "gnu"
    };
    let mut out = format!("{}-{}-{libc}", std::env::consts::ARCH, std::env::consts::OS);
    if let Ok(release) = std::fs::read_to_string("/etc/os-release") {
        let field = |key: &str| {
            release
                .lines()
                .find_map(|l| l.strip_prefix(key).and_then(|l| l.strip_prefix('=')))
                .map(|v| v.trim().trim_matches('"').to_owned())
                .filter(|v| !v.is_empty())
        };
        if let Some(id) = field("ID") {
            let _ = write!(out, "/{id}");
            if let Some(version) = field("VERSION_ID") {
                let _ = write!(out, "-{version}");
            }
        }
    }
    out
}

/// The digest that names an environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Key([u8; 32]);

impl Key {
    /// BLAKE3 over a canonical text of everything that decides the environment's
    /// contents: ecosystem, each input's name and digest in name order, the runtime's
    /// program and version, the platform, the registry.
    #[must_use]
    pub fn derive(recipe: &Recipe, runtime: &Runtime, platform: &str) -> Self {
        let mut text = format!("ward-prepared-environment/{RECORD_VERSION}\n");
        let _ = writeln!(text, "ecosystem {}", recipe.ecosystem);
        let mut inputs: Vec<&InputFile> = recipe.inputs.iter().collect();
        inputs.sort_by(|a, b| a.path.cmp(&b.path));
        for input in inputs {
            let _ = writeln!(text, "input {} {}", input.path, input.digest);
        }
        let _ = writeln!(text, "runtime {} {}", runtime.program, runtime.version);
        let _ = writeln!(text, "platform {platform}");
        let _ = writeln!(
            text,
            "registry {}",
            recipe.ecosystem.registry(&recipe.settings).unwrap_or("-")
        );
        Self(*blake3::hash(text.as_bytes()).as_bytes())
    }

    /// The 64-character hex form, the environment's directory name.
    #[must_use]
    pub fn hex(&self) -> String {
        blake3::Hash::from_bytes(self.0).to_hex().to_string()
    }

    /// The first 12 hex characters, for reports.
    #[must_use]
    pub fn short(&self) -> String {
        self.hex()[..12].to_owned()
    }

    /// Parse a 64-character hex name.
    #[must_use]
    pub fn parse(hex: &str) -> Option<Self> {
        blake3::Hash::from_hex(hex)
            .ok()
            .map(|h| Self(*h.as_bytes()))
    }
}

/// How an install ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// Started and not finished: still running, killed, interrupted or over budget.
    /// Never mounted.
    Incomplete,
    /// The installer exited non-zero. Never mounted.
    Failed,
    /// The installer exited 0 and the stage was sealed.
    Complete,
}

/// `prepared.json`: everything about how an environment was made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Format version ([`RECORD_VERSION`]).
    pub version: u32,
    /// The key, hex.
    pub key: String,
    /// The ecosystem and manager.
    pub ecosystem: Ecosystem,
    /// The inputs and their digests.
    pub inputs: Vec<InputFile>,
    /// The runtime it was built for.
    pub runtime: Runtime,
    /// The platform it was built on.
    pub platform: String,
    /// The registry setting that applied.
    pub settings: Settings,
    /// The install command, as run at the stage root.
    pub command: Vec<String>,
    /// What network the install had, and which proxy variables were passed (by name).
    pub network: String,
    /// How it ended.
    pub outcome: Outcome,
    /// Which attempt this is for this key (a retry removes the previous tree).
    pub attempt: u32,
    /// Unix seconds when the install started.
    pub started_at: u64,
    /// Unix seconds when it ended, once it has.
    pub finished_at: Option<u64>,
    /// Wall-clock milliseconds of the successful install: the cold timing.
    pub cold_ms: Option<u64>,
    /// The installer's exit code, when it exited.
    pub exit_code: Option<i32>,
    /// Whether it was killed at [`BUDGET`].
    pub timed_out: bool,
    /// The last [`OUTPUT_TAIL_BYTES`] of its output.
    pub output_tail: String,
}

impl Record {
    /// A record for an install about to start.
    #[must_use]
    pub fn incomplete(
        key: &Key,
        recipe: &Recipe,
        runtime: &Runtime,
        platform: &str,
        attempt: u32,
        command: Vec<String>,
    ) -> Self {
        let passed: Vec<&str> = PROXY_ENV
            .iter()
            .copied()
            .filter(|name| std::env::var_os(name).is_some_and(|v| !v.is_empty()))
            .collect();
        let mut network = NETWORK_NOTE.to_owned();
        if !passed.is_empty() {
            let _ = write!(
                network,
                "; proxy settings passed through: {}",
                passed.join(", ")
            );
        }
        Self {
            version: RECORD_VERSION,
            key: key.hex(),
            ecosystem: recipe.ecosystem,
            inputs: recipe.inputs.clone(),
            runtime: runtime.clone(),
            platform: platform.to_owned(),
            settings: recipe.settings.clone(),
            command,
            network,
            outcome: Outcome::Incomplete,
            attempt,
            started_at: unix_now(),
            finished_at: None,
            cold_ms: None,
            exit_code: None,
            timed_out: false,
            output_tail: String::new(),
        }
    }

    /// Record how the install ended.
    pub fn finish(
        &mut self,
        outcome: Outcome,
        exit_code: Option<i32>,
        elapsed_ms: u64,
        output: &str,
    ) {
        self.outcome = outcome;
        self.exit_code = exit_code;
        self.finished_at = Some(unix_now());
        self.cold_ms = (outcome == Outcome::Complete).then_some(elapsed_ms);
        self.output_tail = tail(output);
    }

    /// Parse a record; a format this module does not know is refused rather than guessed at.
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

    /// `prepared <short> (<ecosystem>)`.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "prepared {} ({})",
            &self.key[..12.min(self.key.len())],
            self.ecosystem
        )
    }
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
    format!("[…{} bytes omitted]\n{}", start, &output[start..])
}

/// One environment directory: `<state>/prepared/<key>/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Environment {
    dir: PathBuf,
}

impl Environment {
    /// Create the directory and its empty stage.
    pub fn create(state: &Path, key: &Key) -> Result<Self> {
        let env = Self {
            dir: state.join(PREPARED_DIR).join(key.hex()),
        };
        let stage_dir = env.stage();
        std::fs::create_dir_all(&stage_dir).map_err(|e| Error::io(&stage_dir, e))?;
        Ok(env)
    }

    /// The directory for `key`, if it exists.
    #[must_use]
    pub fn open(state: &Path, key: &Key) -> Option<Self> {
        let dir = state.join(PREPARED_DIR).join(key.hex());
        dir.is_dir().then_some(Self { dir })
    }

    /// The environment directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The installed tree's root, the sandbox's `/work` during the install.
    #[must_use]
    pub fn stage(&self) -> PathBuf {
        self.dir.join(STAGE_DIR)
    }

    /// Write the record atomically.
    pub fn record(&self, record: &Record) -> Result<()> {
        let path = self.dir.join(RECORD_FILE);
        let tmp = self.dir.join(format!("{RECORD_FILE}.tmp"));
        let json = serde_json::to_string_pretty(record)
            .map_err(|e| Error::Project(format!("{RECORD_FILE}: {e}")))?;
        std::fs::write(&tmp, json).map_err(|e| Error::io(&tmp, e))?;
        std::fs::rename(&tmp, &path).map_err(|e| Error::io(&path, e))
    }

    /// Read the record.
    pub fn read_record(&self) -> Result<Record> {
        let path = self.dir.join(RECORD_FILE);
        let json = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
        Record::parse(&json)
    }

    /// Make the stage immutable: every regular file and directory under it loses its
    /// write bits, children before parents. Symlinks are left alone — their modes are
    /// meaningless and following one could reach outside the stage.
    pub fn seal(&self) -> Result<()> {
        walk_post_order(&self.stage(), &mut |path, meta| {
            let mode = meta.permissions().mode() & !0o222;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                .map_err(|e| Error::io(path, e))
        })
    }

    /// Give the owner write access back, parents before children, so the tree can be
    /// removed.
    pub fn unseal(&self) -> Result<()> {
        walk_pre_order(&self.stage(), &mut |path, meta| {
            let mode = meta.permissions().mode() | 0o200;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                .map_err(|e| Error::io(path, e))
        })
    }

    /// Whether the stage exists and carries no write bit.
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        std::fs::metadata(self.stage())
            .is_ok_and(|m| m.is_dir() && m.permissions().mode() & 0o222 == 0)
    }

    /// Remove the whole environment, unsealing first.
    pub fn remove(&self) -> Result<()> {
        if self.stage().is_dir() {
            self.unseal()?;
        }
        std::fs::remove_dir_all(&self.dir).map_err(|e| Error::io(&self.dir, e))
    }
}

/// Visit every regular file and directory under `root` (inclusive), children first,
/// never following symlinks.
fn walk_post_order(
    root: &Path,
    visit: &mut dyn FnMut(&Path, &std::fs::Metadata) -> Result<()>,
) -> Result<()> {
    let meta = std::fs::symlink_metadata(root).map_err(|e| Error::io(root, e))?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_dir() {
        let entries = std::fs::read_dir(root).map_err(|e| Error::io(root, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| Error::io(root, e))?;
            walk_post_order(&entry.path(), visit)?;
        }
    }
    visit(root, &meta)
}

/// Visit every regular file and directory under `root` (inclusive), parents first,
/// never following symlinks.
fn walk_pre_order(
    root: &Path,
    visit: &mut dyn FnMut(&Path, &std::fs::Metadata) -> Result<()>,
) -> Result<()> {
    let meta = std::fs::symlink_metadata(root).map_err(|e| Error::io(root, e))?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    visit(root, &meta)?;
    if meta.is_dir() {
        let entries = std::fs::read_dir(root).map_err(|e| Error::io(root, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| Error::io(root, e))?;
            walk_pre_order(&entry.path(), visit)?;
        }
    }
    Ok(())
}

/// Files and bytes under `root`, for progress; symlinks are counted, not followed.
fn measure(root: &Path) -> (u64, u64) {
    let (mut files, mut bytes) = (0u64, 0u64);
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(std::result::Result::ok) {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                pending.push(entry.path());
            } else {
                files += 1;
                bytes += meta.len();
            }
        }
    }
    (files, bytes)
}

/// The pointer file for `dir`: `<state>/prepared/projects/<digest of the canonical path>.json`.
fn project_pointer(state: &Path, dir: &Path) -> PathBuf {
    let canonical = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let digest = blake3::hash(canonical.as_os_str().as_encoded_bytes()).to_hex();
    state
        .join(PREPARED_DIR)
        .join(PROJECTS_DIR)
        .join(format!("{}.json", &digest[..32]))
}

/// What the project pointer holds.
#[derive(Serialize, Deserialize)]
struct Pointer {
    project: PathBuf,
    key: String,
    at: u64,
}

/// Record that `dir` was last prepared into `key`.
pub fn point_project(state: &Path, dir: &Path, key: &Key) -> Result<()> {
    let path = project_pointer(state, dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let pointer = Pointer {
        project: dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf()),
        key: key.hex(),
        at: unix_now(),
    };
    let json = serde_json::to_string_pretty(&pointer)
        .map_err(|e| Error::Project(format!("project pointer: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json).map_err(|e| Error::io(&tmp, e))?;
    std::fs::rename(&tmp, &path).map_err(|e| Error::io(&path, e))
}

/// The key `dir` last prepared into, if any.
fn pointed_key(state: &Path, dir: &Path) -> Option<Key> {
    let json = std::fs::read_to_string(project_pointer(state, dir)).ok()?;
    let pointer: Pointer = serde_json::from_str(&json).ok()?;
    Key::parse(&pointer.key)
}

/// A complete, sealed environment the verifier can mount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    /// Its key.
    pub key: Key,
    /// Its directory.
    pub dir: PathBuf,
    /// Its ecosystem.
    pub ecosystem: Ecosystem,
    /// Its record.
    pub record: Record,
    /// How long finding and checking it took — the warm timing — when it was looked up.
    pub warm: Option<Duration>,
}

impl Prepared {
    /// The installed tree on the host.
    fn tree(&self) -> PathBuf {
        self.dir.join(STAGE_DIR).join(self.ecosystem.tree())
    }

    /// Bind the tree read-only where the verifier expects it.
    #[must_use]
    pub fn mount(&self, launch: Launch) -> Launch {
        launch.ro_bind(self.tree(), self.ecosystem.sandbox_tree())
    }

    /// Point the verifier's environment at the tree: its `bin` first on `PATH`, and for
    /// Python `PYTHONPATH` naming it with the user site disabled.
    pub fn apply_env(&self, env: &mut Vec<(String, String)>) {
        let bin = format!(
            "{}/{}",
            self.ecosystem.sandbox_tree(),
            Path::new(self.ecosystem.bin())
                .file_name()
                .map_or("bin", |n| n.to_str().unwrap_or("bin"))
        );
        match env.iter_mut().find(|(k, _)| k == "PATH") {
            Some((_, path)) => *path = format!("{bin}:{path}"),
            None => env.push(("PATH".to_owned(), bin)),
        }
        if self.ecosystem == Ecosystem::PythonPip {
            env.push(("PYTHONPATH".to_owned(), self.ecosystem.sandbox_tree()));
            env.push(("PYTHONNOUSERSITE".to_owned(), "1".to_owned()));
        }
    }

    /// The host directories the verifier's `PATH` gains, for `ward ready`'s `runtime` row.
    #[must_use]
    pub fn search_dirs(&self) -> Vec<PathBuf> {
        vec![self.dir.join(STAGE_DIR).join(self.ecosystem.bin())]
    }

    /// The host-to-sandbox mapping of what [`Prepared::mount`] binds, for the same row:
    /// the tree, and its `bin` named on its own so a search there is judged inside the
    /// mount it belongs to.
    #[must_use]
    pub fn mounts(&self) -> Vec<Mount> {
        let tree = self.ecosystem.sandbox_tree();
        let bin_name = Path::new(self.ecosystem.bin())
            .file_name()
            .map_or("bin", |n| n.to_str().unwrap_or("bin"));
        vec![
            Mount {
                host: self.tree(),
                sandbox: PathBuf::from(&tree),
            },
            Mount {
                host: self.dir.join(STAGE_DIR).join(self.ecosystem.bin()),
                sandbox: PathBuf::from(format!("{tree}/{bin_name}")),
            },
        ]
    }

    /// `prepared <short> (<ecosystem>)`.
    #[must_use]
    pub fn summary(&self) -> String {
        format!("prepared {} ({})", self.key.short(), self.ecosystem)
    }

    #[cfg(test)]
    fn for_test(state: &Path, ecosystem: Ecosystem, key: Key) -> Self {
        let recipe = Recipe {
            ecosystem,
            inputs: Vec::new(),
            settings: Settings::default(),
        };
        let runtime = Runtime {
            program: ecosystem.runtime_program().to_owned(),
            host_path: PathBuf::from("/usr/bin").join(ecosystem.runtime_program()),
            version: "test".to_owned(),
        };
        Self {
            key,
            dir: state.join(PREPARED_DIR).join(key.hex()),
            ecosystem,
            record: Record::incomplete(&key, &recipe, &runtime, "test", 1, Vec::new()),
            warm: None,
        }
    }
}

/// What a project's current inputs resolve to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Nothing to prepare, with the reason.
    NotNeeded(String),
    /// Dependencies are declared but cannot be prepared from these files, with the reason.
    Declined(String),
    /// The runtime cannot be found or asked, so no key exists, with the reason.
    Unavailable(String),
    /// A complete, sealed environment matches.
    Ready(Box<Prepared>),
    /// No usable environment for these inputs: never prepared, stale, incomplete or
    /// failed — `reason` says which and names `ward prepare`.
    Missing {
        /// The ecosystem that would be prepared.
        ecosystem: Ecosystem,
        /// The key the current inputs resolve to.
        key: Key,
        /// Why nothing usable is there, and what fixes it.
        reason: String,
    },
}

/// Resolve `dir`'s current inputs against the environments under `state`, finding the
/// runtime in `search_dirs` (the verifier's). Reads files and runs `<runtime> --version`;
/// installs nothing.
#[must_use]
pub fn lookup(state: &Path, dir: &Path, settings: &Settings, search_dirs: &[PathBuf]) -> Lookup {
    lookup_in(state, dir, dir, settings, search_dirs)
}

/// [`lookup`] with the inputs read from `inputs` — the verifier's materialised candidate
/// tree, so the key is the one *that* lockfile earns — while the project is still
/// `project`, whose pointer to the environment it last prepared is what explains a
/// miss as stale rather than never prepared.
#[must_use]
pub fn lookup_in(
    state: &Path,
    inputs: &Path,
    project: &Path,
    settings: &Settings,
    search_dirs: &[PathBuf],
) -> Lookup {
    lookup_with(
        state,
        inputs,
        project,
        settings,
        |ecosystem| runtime_identity(ecosystem, search_dirs),
        &platform(),
    )
}

/// [`lookup_in`] with the runtime and platform supplied, so the resolution can be
/// tested without a real toolchain.
pub(crate) fn lookup_with(
    state: &Path,
    inputs: &Path,
    project: &Path,
    settings: &Settings,
    runtime: impl FnOnce(Ecosystem) -> Result<Runtime>,
    platform: &str,
) -> Lookup {
    let start = Instant::now();
    let recipe = match plan(inputs, settings) {
        Plan::Recipe(recipe) => recipe,
        Plan::Declined(why) => return Lookup::Declined(why),
        Plan::NotNeeded(why) => return Lookup::NotNeeded(why),
    };
    let runtime = match runtime(recipe.ecosystem) {
        Ok(runtime) => runtime,
        Err(e) => return Lookup::Unavailable(e.to_string()),
    };
    let key = Key::derive(&recipe, &runtime, platform);
    let missing = |reason: String| Lookup::Missing {
        ecosystem: recipe.ecosystem,
        key,
        reason,
    };
    if let Some(env) = Environment::open(state, &key) {
        return match env.read_record() {
            Ok(record) if record.outcome == Outcome::Complete => {
                if env.is_sealed() {
                    Lookup::Ready(Box::new(Prepared {
                        key,
                        dir: env.dir.clone(),
                        ecosystem: recipe.ecosystem,
                        record,
                        warm: Some(start.elapsed()),
                    }))
                } else {
                    missing(format!(
                        "{} is not sealed (its stage is writable again); run `ward prepare --rebuild`",
                        record.summary()
                    ))
                }
            }
            Ok(record) if record.outcome == Outcome::Incomplete => missing(format!(
                "incomplete: attempt {} of `ward prepare` did not finish{}; run `ward prepare` again",
                record.attempt,
                if record.timed_out {
                    " (killed at its budget)"
                } else {
                    ""
                }
            )),
            Ok(record) => missing(format!(
                "failed: attempt {} of `ward prepare` exited {}; run `ward prepare` again",
                record.attempt,
                record
                    .exit_code
                    .map_or_else(|| "by signal".to_owned(), |c| c.to_string())
            )),
            Err(e) => missing(format!("{e}; run `ward prepare --rebuild`")),
        };
    }
    let previous = pointed_key(state, project)
        .and_then(|k| Environment::open(state, &k))
        .and_then(|env| env.read_record().ok());
    missing(match previous {
        Some(previous) => explain_stale(&previous, &recipe, &runtime, platform),
        None => format!(
            "never prepared; `ward prepare` installs the dependency set {} pins, once, online",
            recipe.lockfile()
        ),
    })
}

/// Why the environment `dir` last prepared no longer matches its current inputs.
fn explain_stale(previous: &Record, recipe: &Recipe, runtime: &Runtime, platform: &str) -> String {
    let short = &previous.key[..12.min(previous.key.len())];
    let fix = "; run `ward prepare`";
    if previous.ecosystem != recipe.ecosystem {
        return format!(
            "stale: package manager changed ({} → {}) since {short} was prepared{fix}",
            previous.ecosystem, recipe.ecosystem
        );
    }
    let changed: Vec<&str> = recipe
        .inputs
        .iter()
        .filter(|input| {
            previous
                .inputs
                .iter()
                .find(|p| p.path == input.path)
                .is_none_or(|p| p.digest != input.digest)
        })
        .map(|input| input.path.as_str())
        .chain(
            previous
                .inputs
                .iter()
                .filter(|p| !recipe.inputs.iter().any(|i| i.path == p.path))
                .map(|p| p.path.as_str()),
        )
        .collect();
    if !changed.is_empty() {
        return format!(
            "stale: {} changed since {short} was prepared{fix}",
            changed.join(", ")
        );
    }
    if previous.runtime.version != runtime.version || previous.runtime.program != runtime.program {
        return format!(
            "stale: runtime changed ({} {} → {} {}) since {short} was prepared{fix}",
            previous.runtime.program, previous.runtime.version, runtime.program, runtime.version
        );
    }
    if previous.platform != platform {
        return format!(
            "stale: platform changed ({} → {platform}) since {short} was prepared{fix}",
            previous.platform
        );
    }
    if previous.settings != recipe.settings {
        return format!("stale: registry setting changed since {short} was prepared{fix}");
    }
    format!("never prepared with these inputs ({short} was prepared with others){fix}")
}

/// A progress sample during an install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Which attempt is running.
    pub attempt: u32,
    /// Since the installer started.
    pub elapsed: Duration,
    /// Files under the stage so far.
    pub files: u64,
    /// Bytes under the stage so far.
    pub bytes: u64,
}

/// What [`run`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Done {
    /// A complete environment already matched; nothing was run.
    Reused(Prepared),
    /// The install ran, succeeded and was sealed.
    Prepared(Prepared),
    /// The install ran and did not succeed; the record and its directory are kept.
    Failed {
        /// The record, with the outcome and the output tail.
        record: Record,
        /// The environment's directory.
        dir: PathBuf,
    },
}

/// What to prepare.
pub struct Request<'a> {
    /// The state root.
    pub state: &'a Path,
    /// The project root the inputs are copied from.
    pub dir: &'a Path,
    /// What to install, from [`plan`].
    pub recipe: &'a Recipe,
    /// The runtime, from [`runtime_identity`].
    pub runtime: &'a Runtime,
    /// The platform, from [`platform`].
    pub platform: &'a str,
    /// Discard a complete environment and install again.
    pub rebuild: bool,
}

/// The explicit, online preparation phase: reuse a complete environment for these
/// inputs, or install one — in the verifier's sandbox with the host network, over a copy
/// of the inputs, writing only the stage — and seal it. `progress` is called about once
/// a second while the installer runs.
pub fn run(req: &Request<'_>, progress: &mut dyn FnMut(&Progress)) -> Result<Done> {
    let start = Instant::now();
    let key = Key::derive(req.recipe, req.runtime, req.platform);
    let mut attempt = 1;
    if let Some(env) = Environment::open(req.state, &key) {
        let previous = env.read_record().ok();
        if let Some(record) = &previous {
            if !req.rebuild && record.outcome == Outcome::Complete && env.is_sealed() {
                return Ok(Done::Reused(Prepared {
                    key,
                    dir: env.dir.clone(),
                    ecosystem: req.recipe.ecosystem,
                    record: record.clone(),
                    warm: Some(start.elapsed()),
                }));
            }
            attempt = record.attempt.saturating_add(1);
        }
        env.remove()?;
    }
    let env = Environment::create(req.state, &key)?;
    let stage = env.stage();
    copy_inputs(req, &stage)?;
    let argv = req.recipe.ecosystem.install_argv(req.recipe);
    let mut record = Record::incomplete(
        &key,
        req.recipe,
        req.runtime,
        req.platform,
        attempt,
        argv.clone(),
    );
    env.record(&record)?;
    point_project(req.state, req.dir, &key)?;

    let running = install_launch(req.recipe, &stage, argv).spawn()?;
    let started = Instant::now();
    let mut last = None::<Instant>;
    let out = running.wait_observed(&mut || {
        if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
            let (files, bytes) = measure(&stage);
            progress(&Progress {
                attempt,
                elapsed: started.elapsed(),
                files,
                bytes,
            });
            last = Some(Instant::now());
        }
    })?;
    let elapsed_ms = u64::try_from(out.duration.as_millis()).unwrap_or(u64::MAX);
    let output = format!("{}{}", out.stdout, out.stderr);
    record.timed_out = out.timed_out;
    let outcome = classify(out.code, out.timed_out);
    if outcome == Outcome::Complete {
        env.seal()?;
    }
    record.finish(outcome, out.code, elapsed_ms, &output);
    env.record(&record)?;
    if outcome == Outcome::Complete {
        Ok(Done::Prepared(Prepared {
            key,
            dir: env.dir.clone(),
            ecosystem: req.recipe.ecosystem,
            record,
            warm: None,
        }))
    } else {
        Ok(Done::Failed {
            record,
            dir: env.dir.clone(),
        })
    }
}

/// Copy the recipe's inputs from the project root into the stage, refusing one whose
/// bytes no longer match the digest the plan was made from.
fn copy_inputs(req: &Request<'_>, stage: &Path) -> Result<()> {
    for input in &req.recipe.inputs {
        if input.path.contains('/') || input.path.starts_with('.') && input.path != ".npmrc" {
            return Err(Error::Project(format!("refusing input {:?}", input.path)));
        }
        let bytes = read_input(req.dir, &input.path).map_err(Error::Project)?;
        if InputFile::new(&input.path, &bytes).digest != input.digest {
            return Err(Error::Project(format!(
                "{} changed while preparing; run `ward prepare` again",
                input.path
            )));
        }
        let dest = stage.join(&input.path);
        std::fs::write(&dest, bytes).map_err(|e| Error::io(&dest, e))?;
    }
    Ok(())
}

/// The install's launch: the verifier's own sandbox and toolchain view — same mounts,
/// same `PATH`, `/work` being the stage — plus the host network, the proxy variables
/// the host has set and the configured registry. Nothing else from the host
/// process's environment reaches it (#409): the environment is cleared, and only
/// those, the toolchain's variables and the session's non-secret forwarded set are
/// set.
fn install_launch(recipe: &Recipe, stage: &Path, argv: Vec<String>) -> Launch {
    let toolchains = Toolchains::detect();
    let mut launch = Launch::new(stage, argv)
        .clear_env()
        .host_network()
        .stdio(StdioMode::Capture)
        .capture_bytes(256 * 1024)
        .budget(BUDGET);
    for name in crate::session::FORWARDED_ENV {
        if let Ok(value) = std::env::var(name) {
            launch = launch.env(*name, value);
        }
    }
    for (k, v) in toolchains.env() {
        launch = launch.env(k, v);
    }
    launch = toolchains.mount(launch);
    for name in PROXY_ENV {
        if let Some(value) = std::env::var_os(name).filter(|v| !v.is_empty()) {
            launch = launch.env(name, value.to_string_lossy().into_owned());
        }
    }
    if let Some(registry) = recipe.ecosystem.registry(&recipe.settings) {
        launch = launch.env(recipe.ecosystem.registry_env(), registry);
    }
    launch
}

/// How an install ended, from its exit: 0 is complete; 1..127 is the installer's own
/// failure; anything else — killed (bubblewrap reports a signal death as 128 + signal),
/// no code at all, or over budget — did not finish.
const fn classify(code: Option<i32>, timed_out: bool) -> Outcome {
    match code {
        Some(0) if !timed_out => Outcome::Complete,
        Some(code) if code >= 1 && code < 128 && !timed_out => Outcome::Failed,
        _ => Outcome::Incomplete,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use super::*;

    /// Every variable a launch sets with `--setenv`, by name.
    fn setenv_names(args: &[String]) -> Vec<String> {
        args.windows(2)
            .filter(|w| w[0] == "--setenv")
            .map(|w| w[1].clone())
            .collect()
    }

    /// #409: the install runs with the host network over package code, so it
    /// inherits nothing from the host process beyond what it declares: the
    /// toolchain's variables, the proxy variables, the registry setting and the
    /// session's non-secret forwarded set.
    #[test]
    fn the_installer_inherits_no_host_environment() {
        let stage = tempfile::tempdir().unwrap();
        let recipe = Recipe {
            ecosystem: Ecosystem::NodeNpm,
            inputs: Vec::new(),
            settings: Settings::default(),
        };
        let launch = install_launch(&recipe, stage.path(), vec!["true".into()]);
        let args = launch.args(stage.path());
        assert!(args.iter().any(|a| a == "--clearenv"), "{args:?}");
        // The toolchain's own variables point inside the sandbox; `TERM=xterm` is
        // the launch primitive's own constant. Neither is a host value.
        let toolchain: Vec<String> = Toolchains::detect()
            .env()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        let allowed: Vec<&str> = ["HOME", "PATH", "TERM", Ecosystem::NodeNpm.registry_env()]
            .into_iter()
            .chain(PROXY_ENV)
            .chain(crate::session::FORWARDED_ENV.iter().copied())
            .chain(toolchain.iter().map(String::as_str))
            .collect();
        for name in setenv_names(&args) {
            assert!(
                allowed.contains(&name.as_str()),
                "{name} reached the installer"
            );
        }
    }

    fn write(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn recipe(ecosystem: Ecosystem, inputs: &[(&str, &str)]) -> Recipe {
        Recipe {
            ecosystem,
            inputs: inputs
                .iter()
                .map(|(path, content)| InputFile::new(path, content.as_bytes()))
                .collect(),
            settings: Settings::default(),
        }
    }

    fn runtime(version: &str) -> Runtime {
        Runtime {
            program: "node".to_owned(),
            host_path: "/usr/bin/node".into(),
            version: version.to_owned(),
        }
    }

    #[test]
    fn key_is_stable_and_changes_with_every_input() {
        let base = recipe(
            Ecosystem::NodeNpm,
            &[("package-lock.json", "lock-a"), ("package.json", "pkg")],
        );
        let k = Key::derive(&base, &runtime("v22.0.0"), "x86_64-linux-gnu");
        assert_eq!(
            k,
            Key::derive(&base, &runtime("v22.0.0"), "x86_64-linux-gnu")
        );
        assert_eq!(k.hex().len(), 64);
        assert_eq!(k.short(), k.hex()[..12]);
        assert_eq!(Key::parse(&k.hex()), Some(k));

        let reordered = recipe(
            Ecosystem::NodeNpm,
            &[("package.json", "pkg"), ("package-lock.json", "lock-a")],
        );
        assert_eq!(
            k,
            Key::derive(&reordered, &runtime("v22.0.0"), "x86_64-linux-gnu"),
            "input order is canonical"
        );

        let lock_changed = recipe(
            Ecosystem::NodeNpm,
            &[("package-lock.json", "lock-b"), ("package.json", "pkg")],
        );
        assert_ne!(
            k,
            Key::derive(&lock_changed, &runtime("v22.0.0"), "x86_64-linux-gnu")
        );
        assert_ne!(
            k,
            Key::derive(&base, &runtime("v24.0.0"), "x86_64-linux-gnu")
        );
        assert_ne!(
            k,
            Key::derive(&base, &runtime("v22.0.0"), "aarch64-linux-gnu")
        );
        let mut other_manager = base.clone();
        other_manager.ecosystem = Ecosystem::NodePnpm;
        assert_ne!(
            k,
            Key::derive(&other_manager, &runtime("v22.0.0"), "x86_64-linux-gnu")
        );
        let mut registry = base.clone();
        registry.settings.npm_registry = Some("https://registry.example/".to_owned());
        assert_ne!(
            k,
            Key::derive(&registry, &runtime("v22.0.0"), "x86_64-linux-gnu")
        );
        let mut irrelevant = base;
        irrelevant.settings.pip_index_url = Some("https://pypi.example/".to_owned());
        assert_eq!(
            k,
            Key::derive(&irrelevant, &runtime("v22.0.0"), "x86_64-linux-gnu"),
            "a setting another ecosystem reads does not key a Node environment"
        );
    }

    #[test]
    fn plan_names_the_manager_from_the_lockfile_and_declines_without_one() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "package.json", "{}");
        assert!(matches!(
            plan(dir.path(), &Settings::default()),
            Plan::Declined(why) if why.contains("no lockfile") && why.contains("package-lock.json")
        ));
        write(dir.path(), "package-lock.json", "{}");
        let Plan::Recipe(r) = plan(dir.path(), &Settings::default()) else {
            panic!("npm")
        };
        assert_eq!(r.ecosystem, Ecosystem::NodeNpm);
        assert_eq!(
            r.inputs.iter().map(|i| i.path.as_str()).collect::<Vec<_>>(),
            ["package-lock.json", "package.json"]
        );
        assert_eq!(r.lockfile(), "package-lock.json");
        assert_eq!(
            r.ecosystem.install_argv(&r),
            ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"]
        );
        write(dir.path(), ".npmrc", "registry=https://r.example/\n");
        let Plan::Recipe(r) = plan(dir.path(), &Settings::default()) else {
            panic!("npm")
        };
        assert!(r.inputs.iter().any(|i| i.path == ".npmrc"), "{r:?}");
        let narrowed = Settings {
            npm_registry: Some("https://r.example/".to_owned()),
            pip_index_url: Some("https://p.example/".to_owned()),
        };
        let Plan::Recipe(r) = plan(dir.path(), &narrowed) else {
            panic!("npm")
        };
        assert_eq!(
            r.settings.npm_registry.as_deref(),
            Some("https://r.example/")
        );
        assert_eq!(
            r.settings.pip_index_url, None,
            "only the Node setting is kept"
        );

        let pnpm = tempfile::tempdir().unwrap();
        write(pnpm.path(), "package.json", "{}");
        write(pnpm.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        let Plan::Recipe(r) = plan(pnpm.path(), &Settings::default()) else {
            panic!("pnpm")
        };
        assert_eq!(r.ecosystem, Ecosystem::NodePnpm);
        assert_eq!(r.ecosystem.install_argv(&r)[..2], ["pnpm", "install"]);
        assert!(
            r.ecosystem
                .install_argv(&r)
                .contains(&"--frozen-lockfile".to_owned())
        );

        let yarn = tempfile::tempdir().unwrap();
        write(yarn.path(), "package.json", "{}");
        write(yarn.path(), "yarn.lock", "# yarn lockfile v1\n");
        let Plan::Recipe(r) = plan(yarn.path(), &Settings::default()) else {
            panic!("yarn")
        };
        assert_eq!(r.ecosystem, Ecosystem::NodeYarn);
        assert!(
            r.ecosystem
                .install_argv(&r)
                .contains(&"--ignore-scripts".to_owned())
        );
    }

    #[test]
    fn plan_names_pip_from_requirements_and_declines_other_python_lockfiles() {
        let py = tempfile::tempdir().unwrap();
        write(py.path(), "pyproject.toml", "[project]\nname = 'a'\n");
        assert!(matches!(
            plan(py.path(), &Settings::default()),
            Plan::Declined(why) if why.contains("requirements")
        ));
        write(py.path(), "requirements-dev.txt", "pytest\n");
        write(py.path(), "requirements.txt", "requests\n");
        let Plan::Recipe(r) = plan(py.path(), &Settings::default()) else {
            panic!("pip")
        };
        assert_eq!(r.ecosystem, Ecosystem::PythonPip);
        assert_eq!(
            r.inputs.iter().map(|i| i.path.as_str()).collect::<Vec<_>>(),
            ["requirements-dev.txt", "requirements.txt"]
        );
        let argv = r.ecosystem.install_argv(&r);
        assert_eq!(argv[..4], ["python3", "-m", "pip", "install"]);
        assert!(argv.contains(&"--target".to_owned()));
        assert!(argv.contains(&"requirements-dev.txt".to_owned()));
        assert!(argv.contains(&"requirements.txt".to_owned()));

        let poetry = tempfile::tempdir().unwrap();
        write(poetry.path(), "pyproject.toml", "[tool.poetry]\n");
        write(poetry.path(), "poetry.lock", "");
        assert!(
            matches!(
                plan(poetry.path(), &Settings::default()),
                Plan::Declined(why) if why.contains("poetry.lock") && why.contains("poetry")
            ),
            "a lockfile whose tool is not supported is declined with its name"
        );

        let cargo = tempfile::tempdir().unwrap();
        write(cargo.path(), "Cargo.toml", "[package]\n");
        assert!(matches!(
            plan(cargo.path(), &Settings::default()),
            Plan::NotNeeded(why) if why.contains("cargo")
        ));
        let empty = tempfile::tempdir().unwrap();
        assert!(matches!(
            plan(empty.path(), &Settings::default()),
            Plan::NotNeeded(_)
        ));

        // A symlinked manifest is not a manifest.
        let linked = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc/hostname", linked.path().join("package.json")).unwrap();
        assert!(matches!(
            plan(linked.path(), &Settings::default()),
            Plan::NotNeeded(_)
        ));
    }

    #[test]
    fn lookup_distinguishes_never_prepared_stale_incomplete_and_ready() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        write(project.path(), "package.json", "{}");
        write(project.path(), "package-lock.json", "lock-a");
        let rt = runtime("v22.0.0");
        let Plan::Recipe(r) = plan(project.path(), &Settings::default()) else {
            panic!()
        };
        let key = Key::derive(&r, &rt, "plat");
        let settings = Settings::default();
        let with = |runtime: Result<Runtime>, platform: &str| {
            lookup_with(
                state.path(),
                project.path(),
                project.path(),
                &settings,
                |_| runtime,
                platform,
            )
        };

        let never = with(Ok(rt.clone()), "plat");
        assert!(
            matches!(&never, Lookup::Missing { reason, key: k, .. } if reason.contains("never prepared") && *k == key),
            "{never:?}"
        );

        // An environment under way: recorded incomplete, pointed at by the project.
        let env = Environment::create(state.path(), &key).unwrap();
        env.record(&Record::incomplete(
            &key,
            &r,
            &rt,
            "plat",
            1,
            vec!["npm".into()],
        ))
        .unwrap();
        point_project(state.path(), project.path(), &key).unwrap();
        let incomplete = with(Ok(rt.clone()), "plat");
        assert!(
            matches!(&incomplete, Lookup::Missing { reason, .. } if reason.contains("incomplete") && reason.contains("attempt 1")),
            "{incomplete:?}"
        );

        // Finished and sealed: ready, with the recorded cold time and a measured warm one.
        write(&env.stage(), "node_modules/x.js", "1");
        let mut done = Record::incomplete(&key, &r, &rt, "plat", 1, vec!["npm".into()]);
        done.finish(Outcome::Complete, Some(0), 4200, "added 1 package");
        env.seal().unwrap();
        env.record(&done).unwrap();
        let ready = with(Ok(rt.clone()), "plat");
        let Lookup::Ready(prepared) = ready else {
            panic!("{ready:?}")
        };
        assert_eq!(prepared.key, key);
        assert_eq!(prepared.record.cold_ms, Some(4200));
        assert_eq!(prepared.record.outcome, Outcome::Complete);
        assert!(prepared.warm.is_some());
        assert_eq!(
            prepared.summary(),
            format!("prepared {} (node-npm)", key.short())
        );

        // The lockfile changes: stale, naming the file, pointing at `ward prepare`.
        write(project.path(), "package-lock.json", "lock-b");
        let outdated = with(Ok(rt.clone()), "plat");
        assert!(
            matches!(&outdated, Lookup::Missing { reason, .. } if reason.contains("stale") && reason.contains("package-lock.json changed") && reason.contains("ward prepare")),
            "{outdated:?}"
        );
        write(project.path(), "package-lock.json", "lock-a");

        // The runtime changes: stale, naming both versions.
        let outdated = with(Ok(runtime("v24.0.0")), "plat");
        assert!(
            matches!(&outdated, Lookup::Missing { reason, .. } if reason.contains("runtime changed") && reason.contains("v22.0.0") && reason.contains("v24.0.0")),
            "{outdated:?}"
        );

        // The platform changes: stale.
        let outdated = with(Ok(rt.clone()), "other-plat");
        assert!(
            matches!(&outdated, Lookup::Missing { reason, .. } if reason.contains("platform changed")),
            "{outdated:?}"
        );

        // A record that says complete over a stage someone made writable again is not
        // trusted.
        std::fs::set_permissions(env.stage(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let unsealed = with(Ok(rt.clone()), "plat");
        assert!(
            matches!(&unsealed, Lookup::Missing { reason, .. } if reason.contains("not sealed")),
            "{unsealed:?}"
        );

        // No runtime at all: the environment cannot even be keyed.
        let none = with(Err(Error::Project("node not found".into())), "plat");
        assert!(matches!(&none, Lookup::Unavailable(why) if why.contains("node not found")));

        // Nothing to prepare and nothing preparable pass straight through.
        let cargo = tempfile::tempdir().unwrap();
        write(cargo.path(), "Cargo.toml", "[package]\n");
        assert!(matches!(
            lookup(state.path(), cargo.path(), &settings, &[]),
            Lookup::NotNeeded(_)
        ));
        let bare = tempfile::tempdir().unwrap();
        write(bare.path(), "package.json", "{}");
        assert!(matches!(
            lookup(state.path(), bare.path(), &settings, &[]),
            Lookup::Declined(_)
        ));
    }

    #[test]
    fn seal_makes_every_file_and_directory_read_only_and_unseal_reverses_it() {
        let state = tempfile::tempdir().unwrap();
        let key = Key::derive(
            &recipe(Ecosystem::PythonPip, &[("requirements.txt", "a")]),
            &runtime("3.12"),
            "plat",
        );
        let env = Environment::create(state.path(), &key).unwrap();
        write(&env.stage(), "site-packages/a/__init__.py", "");
        write(&env.stage(), "site-packages/bin/pytest", "#!/bin/sh\n");
        // A symlink out of the stage: sealing must not chmod its target.
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("target"), "t").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("target"),
            env.stage().join("site-packages/link"),
        )
        .unwrap();
        env.seal().unwrap();
        for rel in [
            "",
            "site-packages",
            "site-packages/a",
            "site-packages/a/__init__.py",
        ] {
            let mode = std::fs::metadata(env.stage().join(rel))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o222, 0, "{rel} is writable: {mode:o}");
        }
        assert_ne!(
            std::fs::metadata(outside.path().join("target"))
                .unwrap()
                .permissions()
                .mode()
                & 0o200,
            0,
            "the symlink's target outside the stage is untouched"
        );
        assert!(env.is_sealed());
        env.unseal().unwrap();
        assert!(!env.is_sealed());
        let mode = std::fs::metadata(env.stage().join("site-packages/a"))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(mode & 0o200, 0);
        env.remove().unwrap();
        assert!(!env.dir().exists());
        assert!(Environment::open(state.path(), &key).is_none());
    }

    #[test]
    fn the_verifier_mounts_node_modules_at_work_and_site_packages_under_run_verifier() {
        let state = tempfile::tempdir().unwrap();
        let node = Prepared::for_test(
            state.path(),
            Ecosystem::NodeNpm,
            Key::derive(&recipe(Ecosystem::NodeNpm, &[]), &runtime("v22"), "p"),
        );
        let launch = node.mount(Launch::new("/tmp", vec!["true".into()]));
        let args = launch.args(Path::new("/tmp")).join(" ");
        assert!(
            args.contains(&format!(
                "--ro-bind {} /work/node_modules",
                node.dir.join("stage/node_modules").display()
            )),
            "{args}"
        );
        assert!(args.contains("--unshare-net"), "the verifier stays offline");
        let mut env = vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())];
        node.apply_env(&mut env);
        assert_eq!(
            env,
            vec![(
                "PATH".to_owned(),
                "/work/node_modules/.bin:/usr/bin:/bin".to_owned()
            )]
        );
        assert_eq!(
            node.search_dirs(),
            vec![node.dir.join("stage/node_modules/.bin")]
        );
        assert_eq!(
            node.mounts(),
            vec![
                Mount {
                    host: node.dir.join("stage/node_modules"),
                    sandbox: "/work/node_modules".into(),
                },
                Mount {
                    host: node.dir.join("stage/node_modules/.bin"),
                    sandbox: "/work/node_modules/.bin".into(),
                },
            ]
        );

        let py = Prepared::for_test(
            state.path(),
            Ecosystem::PythonPip,
            Key::derive(&recipe(Ecosystem::PythonPip, &[]), &runtime("3"), "p"),
        );
        let launch = py.mount(Launch::new("/tmp", vec!["true".into()]));
        let args = launch.args(Path::new("/tmp")).join(" ");
        assert!(
            args.contains(&format!(
                "--ro-bind {} {DEPS_ROOT}/site-packages",
                py.dir.join("stage/site-packages").display()
            )),
            "{args}"
        );
        let mut env = Vec::new();
        py.apply_env(&mut env);
        assert!(
            env.contains(&(
                "PYTHONPATH".to_owned(),
                format!("{DEPS_ROOT}/site-packages")
            )),
            "{env:?}"
        );
        assert!(
            env.contains(&("PYTHONNOUSERSITE".to_owned(), "1".to_owned())),
            "{env:?}"
        );
        assert!(
            env.contains(&("PATH".to_owned(), format!("{DEPS_ROOT}/site-packages/bin"))),
            "{env:?}"
        );
        assert_eq!(
            py.search_dirs(),
            vec![py.dir.join("stage/site-packages/bin")]
        );
    }

    #[test]
    fn records_round_trip_and_an_unknown_version_is_refused() {
        let r = recipe(
            Ecosystem::NodeYarn,
            &[("yarn.lock", "y"), ("package.json", "p")],
        );
        let rt = runtime("v22");
        let key = Key::derive(&r, &rt, "plat");
        let mut rec = Record::incomplete(
            &key,
            &r,
            &rt,
            "plat",
            3,
            vec!["yarn".into(), "install".into()],
        );
        assert_eq!(rec.outcome, Outcome::Incomplete);
        assert_eq!(rec.cold_ms, None);
        rec.finish(Outcome::Failed, Some(1), 10, &"x".repeat(10_000));
        assert!(
            rec.output_tail.len() <= OUTPUT_TAIL_BYTES + 64,
            "{}",
            rec.output_tail.len()
        );
        assert!(
            rec.output_tail.starts_with("[…"),
            "{}",
            &rec.output_tail[..40]
        );
        assert_eq!(rec.cold_ms, None, "a failed install has no cold timing");
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"ecosystem\":\"node-yarn\""), "{json}");
        assert!(json.contains("\"outcome\":\"failed\""), "{json}");
        let back = Record::parse(&json).unwrap();
        assert_eq!(back, rec);
        assert_eq!(back.key, key.hex());
        assert_eq!(back.attempt, 3);
        assert_eq!(back.exit_code, Some(1));
        assert!(back.network.contains("host"));
        let future = json.replace("\"version\":1", "\"version\":99");
        assert!(Record::parse(&future).is_err());
        assert!(Record::parse("not json").is_err());

        let mut ok = Record::incomplete(&key, &r, &rt, "plat", 1, Vec::new());
        ok.finish(Outcome::Complete, Some(0), 777, "short");
        assert_eq!(ok.cold_ms, Some(777));
        assert_eq!(ok.output_tail, "short");
        assert_eq!(
            ok.summary(),
            format!("prepared {} (node-yarn)", key.short())
        );
    }

    #[test]
    fn an_exit_code_tells_a_failed_install_from_an_interrupted_one() {
        assert_eq!(classify(Some(0), false), Outcome::Complete);
        assert_eq!(classify(Some(1), false), Outcome::Failed);
        assert_eq!(classify(Some(127), false), Outcome::Failed);
        assert_eq!(classify(Some(137), false), Outcome::Incomplete, "SIGKILL");
        assert_eq!(classify(None, false), Outcome::Incomplete);
        assert_eq!(classify(Some(0), true), Outcome::Incomplete, "over budget");
    }

    #[test]
    fn platform_names_the_architecture_and_libc() {
        let p = platform();
        assert!(p.starts_with(std::env::consts::ARCH), "{p}");
        assert!(p.contains("-linux-"), "{p}");
    }

    #[test]
    fn runtime_identity_runs_the_verifiers_own_binary_not_the_callers_path() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let node = bin.join("node");
        std::fs::write(&node, "#!/bin/sh\necho v1.2.3-here\n").unwrap();
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
        let rt = runtime_identity(Ecosystem::NodeNpm, std::slice::from_ref(&bin)).unwrap();
        assert_eq!(rt.version, "v1.2.3-here");
        assert_eq!(rt.host_path, node);
        assert_eq!(rt.program, "node");
        let missing =
            runtime_identity(Ecosystem::PythonPip, std::slice::from_ref(&bin)).unwrap_err();
        assert!(missing.to_string().contains("python3"), "{missing}");
        std::fs::write(&node, "#!/bin/sh\necho broken >&2\nexit 3\n").unwrap();
        let broken = runtime_identity(Ecosystem::NodeNpm, &[bin]).unwrap_err();
        assert!(broken.to_string().contains("broken"), "{broken}");
    }

    #[test]
    fn run_refuses_an_input_that_changed_after_it_was_planned() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        write(project.path(), "package.json", "{}");
        write(project.path(), "package-lock.json", "lock-a");
        let recipe = match plan(project.path(), &Settings::default()) {
            Plan::Recipe(r) => r,
            other => panic!("{other:?}"),
        };
        write(project.path(), "package-lock.json", "lock-b");
        let rt = runtime("v0-test");
        let req = Request {
            state: state.path(),
            dir: project.path(),
            recipe: &recipe,
            runtime: &rt,
            platform: "test",
            rebuild: false,
        };
        let err = run(&req, &mut |_| {}).unwrap_err();
        assert!(
            err.to_string()
                .contains("package-lock.json changed while preparing"),
            "{err}"
        );
        assert!(!project.path().join("node_modules").exists());
    }
}
