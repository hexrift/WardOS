//! How the host launches an adapter: the launch half of the contract.
//!
//! A [`LaunchSpec`] is everything an adapter may ask of a launch: the program and its
//! arguments, non-secret environment it needs, settings files seeded read-only into the
//! sandbox home, and the model provider whose gateway it talks to. It cannot ask for a
//! mount, a network rule, a credential, a different working directory or a proxy
//! setting: the host builds those from the session's capability manifest, identically
//! for every adapter, and a spec that names a variable the host owns is refused.

use std::fmt::{Display, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

/// The working directory of every launch: the workspace root inside the sandbox.
pub const WORKSPACE: &str = "/work";
/// The sandbox-private home directory; settings files live under it.
pub const SANDBOX_HOME: &str = "/home/agent";

/// Largest settings file an adapter may seed.
pub const MAX_SETTINGS_BYTES: usize = 64 * 1024;
/// Largest environment value.
pub const MAX_ENV_VALUE_BYTES: usize = 4096;
/// Most environment variables or settings files in one spec.
pub const MAX_ENTRIES: usize = 32;

/// Variables the host sets for every launch; an adapter may not set or override them.
const RESERVED_ENV: &[&str] = &["HOME", "PATH", "TERM"];
/// Proxy variables, reserved in any letter case.
const RESERVED_PROXY_ENV: &[&str] = &["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];
/// Prefix of the host's own variables (`WARD_SOCKET`, …).
const RESERVED_PREFIX: &str = "WARD_";

/// Stable provider identifier: the model-API gateway an adapter talks to.
///
/// It selects a host-side gateway route (the host keeps the key, the proxy injects it);
/// it is metadata in evidence and never a credential or an authority by itself.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ProviderId(pub(crate) String);

impl ProviderId {
    /// Maximum bytes in a provider identifier.
    pub const MAX_BYTES: usize = 32;

    /// Construct a validated provider id: lowercase ASCII letters, digits and hyphens,
    /// starting with a letter.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderIdError`] for anything else.
    pub fn new(value: &str) -> Result<Self, ProviderIdError> {
        let valid = !value.is_empty()
            && value.len() <= Self::MAX_BYTES
            && value.as_bytes()[0].is_ascii_lowercase()
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !valid {
            return Err(ProviderIdError);
        }
        Ok(Self(value.to_owned()))
    }

    /// Identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Invalid provider identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderIdError;

impl Display for ProviderIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("provider id is invalid")
    }
}

impl std::error::Error for ProviderIdError {}

impl<'de> Deserialize<'de> for ProviderId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(&value).map_err(D::Error::custom)
    }
}

/// One environment variable an adapter needs (configuration, never a secret: a key
/// reaches the agent only through its provider gateway, as a placeholder).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvVar {
    /// Variable name.
    pub name: String,
    /// Value.
    pub value: String,
}

/// A settings file seeded read-only into the sandbox home.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsFile {
    /// Absolute path under [`SANDBOX_HOME`].
    pub path: String,
    /// File content.
    pub content: String,
}

/// What an adapter asks of a launch (contract 1.0).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LaunchSpec {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    pub(crate) env: Vec<EnvVar>,
    pub(crate) workdir: String,
    pub(crate) settings: Vec<SettingsFile>,
    pub(crate) provider: Option<ProviderId>,
}

impl LaunchSpec {
    /// Construct a validated spec. The working directory is always [`WORKSPACE`].
    ///
    /// # Errors
    ///
    /// See [`LaunchSpecError`].
    pub fn new(
        program: &str,
        args: Vec<String>,
        env: Vec<EnvVar>,
        settings: Vec<SettingsFile>,
        provider: Option<ProviderId>,
    ) -> Result<Self, LaunchSpecError> {
        validate_program(program)?;
        if args.iter().any(|arg| arg.contains('\0')) {
            return Err(LaunchSpecError::InvalidArgument);
        }
        if env.len() > MAX_ENTRIES || settings.len() > MAX_ENTRIES {
            return Err(LaunchSpecError::TooManyEntries);
        }
        for (i, var) in env.iter().enumerate() {
            validate_env(var)?;
            if env[..i].iter().any(|other| other.name == var.name) {
                return Err(LaunchSpecError::DuplicateEnv(var.name.clone()));
            }
        }
        for (i, file) in settings.iter().enumerate() {
            validate_settings(file)?;
            if settings[..i].iter().any(|other| other.path == file.path) {
                return Err(LaunchSpecError::DuplicateSettings(file.path.clone()));
            }
        }
        Ok(Self {
            program: program.to_owned(),
            args,
            env,
            workdir: WORKSPACE.to_owned(),
            settings,
            provider,
        })
    }

    /// The same spec running `program` instead (another install of the same runtime).
    ///
    /// # Errors
    ///
    /// Returns [`LaunchSpecError::InvalidProgram`] for an invalid program.
    pub fn with_program(mut self, program: &str) -> Result<Self, LaunchSpecError> {
        validate_program(program)?;
        program.clone_into(&mut self.program);
        Ok(self)
    }

    /// The program: a name looked up on the sandbox `PATH`, or an absolute path.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Arguments the adapter always passes, before the user's.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Environment the adapter needs.
    #[must_use]
    pub fn env(&self) -> &[EnvVar] {
        &self.env
    }

    /// The working directory: always [`WORKSPACE`].
    #[must_use]
    pub fn workdir(&self) -> &str {
        &self.workdir
    }

    /// Settings files to seed.
    #[must_use]
    pub fn settings(&self) -> &[SettingsFile] {
        &self.settings
    }

    /// The provider gateway the adapter talks to, if any.
    #[must_use]
    pub const fn provider(&self) -> Option<&ProviderId> {
        self.provider.as_ref()
    }

    /// The command line: program, the adapter's arguments, then `extra`.
    #[must_use]
    pub fn argv(&self, extra: &[String]) -> Vec<String> {
        std::iter::once(self.program.clone())
            .chain(self.args.iter().cloned())
            .chain(extra.iter().cloned())
            .collect()
    }
}

/// The model a command line requests with one of `flags` (`--model x`, `--model=x`), the
/// last one winning as it does for the runtimes; `None` when it names none, after a `--`,
/// or when `flags` is empty (an adapter that does not know its program's flags).
#[must_use]
pub fn requested_model(args: &[String], flags: &[&str]) -> Option<String> {
    let mut model = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            break;
        }
        for flag in flags {
            if arg == flag {
                model = iter.next().cloned();
            } else if let Some(value) = arg
                .strip_prefix(flag)
                .and_then(|rest| rest.strip_prefix('='))
            {
                model = Some(value.to_owned());
            }
        }
    }
    model.filter(|m| !m.is_empty())
}

fn validate_program(program: &str) -> Result<(), LaunchSpecError> {
    let valid = !program.is_empty()
        && program.len() <= 4096
        && !program.contains('\0')
        && (!program.contains('/') || program.starts_with('/'));
    if valid {
        Ok(())
    } else {
        Err(LaunchSpecError::InvalidProgram)
    }
}

/// Whether the host owns `name`, so an adapter may not set it.
#[must_use]
pub fn is_reserved_env(name: &str) -> bool {
    RESERVED_ENV.contains(&name)
        || RESERVED_PROXY_ENV
            .iter()
            .any(|reserved| reserved.eq_ignore_ascii_case(name))
        || name.starts_with(RESERVED_PREFIX)
}

fn validate_env(var: &EnvVar) -> Result<(), LaunchSpecError> {
    let name = &var.name;
    let valid_name = !name.is_empty()
        && name.len() <= 128
        && !name.as_bytes()[0].is_ascii_digit()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !valid_name {
        return Err(LaunchSpecError::InvalidEnvName(name.clone()));
    }
    if is_reserved_env(name) {
        return Err(LaunchSpecError::ReservedEnv(name.clone()));
    }
    if var.value.len() > MAX_ENV_VALUE_BYTES || var.value.contains('\0') {
        return Err(LaunchSpecError::InvalidEnvValue(name.clone()));
    }
    Ok(())
}

fn validate_settings(file: &SettingsFile) -> Result<(), LaunchSpecError> {
    let invalid = || LaunchSpecError::InvalidSettingsPath(file.path.clone());
    let rest = file
        .path
        .strip_prefix(SANDBOX_HOME)
        .and_then(|rest| rest.strip_prefix('/'))
        .ok_or_else(invalid)?;
    let valid = file.path.len() <= 255
        && !rest.is_empty()
        && rest
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !file.path.contains('\0');
    if !valid {
        return Err(invalid());
    }
    if file.content.len() > MAX_SETTINGS_BYTES {
        return Err(LaunchSpecError::SettingsTooLarge(file.path.clone()));
    }
    Ok(())
}

/// Invalid launch spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchSpecError {
    /// Empty, NUL-containing, oversized, or a relative path with a `/`.
    InvalidProgram,
    /// An argument contains NUL.
    InvalidArgument,
    /// More than [`MAX_ENTRIES`] variables or settings files.
    TooManyEntries,
    /// Not a portable variable name.
    InvalidEnvName(String),
    /// A variable the host owns (proxy settings, `HOME`, `PATH`, `TERM`, `WARD_*`).
    ReservedEnv(String),
    /// Oversized or NUL-containing value.
    InvalidEnvValue(String),
    /// The same variable twice.
    DuplicateEnv(String),
    /// A settings path outside the sandbox home, or with an empty, `.` or `..` part.
    InvalidSettingsPath(String),
    /// A settings file over [`MAX_SETTINGS_BYTES`].
    SettingsTooLarge(String),
    /// The same settings path twice.
    DuplicateSettings(String),
    /// A working directory other than [`WORKSPACE`].
    UnsupportedWorkdir(String),
}

impl Display for LaunchSpecError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProgram => formatter.write_str("launch program is invalid"),
            Self::InvalidArgument => formatter.write_str("a launch argument contains NUL"),
            Self::TooManyEntries => formatter.write_str("too many launch variables or settings"),
            Self::InvalidEnvName(name) => write!(formatter, "invalid variable name {name:?}"),
            Self::ReservedEnv(name) => {
                write!(formatter, "{name} is set by the host, not by an adapter")
            }
            Self::InvalidEnvValue(name) => write!(formatter, "invalid value for {name}"),
            Self::DuplicateEnv(name) => write!(formatter, "{name} is given twice"),
            Self::InvalidSettingsPath(path) => {
                write!(
                    formatter,
                    "settings path {path:?} is not under {SANDBOX_HOME}"
                )
            }
            Self::SettingsTooLarge(path) => write!(formatter, "settings file {path} is too large"),
            Self::DuplicateSettings(path) => {
                write!(formatter, "settings path {path} is given twice")
            }
            Self::UnsupportedWorkdir(dir) => write!(
                formatter,
                "working directory {dir:?} is not supported (every launch starts in {WORKSPACE})"
            ),
        }
    }
}

impl std::error::Error for LaunchSpecError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchSpecWire {
    program: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: Vec<EnvVar>,
    workdir: String,
    #[serde(default)]
    settings: Vec<SettingsFile>,
    #[serde(default)]
    provider: Option<ProviderId>,
}

impl<'de> Deserialize<'de> for LaunchSpec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = LaunchSpecWire::deserialize(deserializer)?;
        if wire.workdir != WORKSPACE {
            return Err(D::Error::custom(LaunchSpecError::UnsupportedWorkdir(
                wire.workdir,
            )));
        }
        Self::new(
            &wire.program,
            wire.args,
            wire.env,
            wire.settings,
            wire.provider,
        )
        .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn var(name: &str, value: &str) -> EnvVar {
        EnvVar {
            name: name.into(),
            value: value.into(),
        }
    }

    fn file(path: &str) -> SettingsFile {
        SettingsFile {
            path: path.into(),
            content: "{}".into(),
        }
    }

    fn spec(env: Vec<EnvVar>, settings: Vec<SettingsFile>) -> Result<LaunchSpec, LaunchSpecError> {
        LaunchSpec::new("agent", Vec::new(), env, settings, None)
    }

    #[test]
    fn provider_ids_are_bounded_lowercase_names() {
        assert_eq!(ProviderId::new("anthropic").unwrap().as_str(), "anthropic");
        assert!(ProviderId::new("open-ai2").is_ok());
        for bad in ["", "OpenAI", "2fast", "a b", "a_b", "a.b", &"a".repeat(33)] {
            assert!(ProviderId::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn programs_are_names_on_path_or_absolute_paths() {
        for good in ["claude", "/usr/bin/codex", "/work/.bin/agent"] {
            assert!(
                LaunchSpec::new(good, vec![], vec![], vec![], None).is_ok(),
                "{good}"
            );
        }
        for bad in ["", "./agent", "bin/agent", "a\0b"] {
            assert_eq!(
                LaunchSpec::new(bad, vec![], vec![], vec![], None),
                Err(LaunchSpecError::InvalidProgram),
                "{bad:?}"
            );
        }
        assert_eq!(
            LaunchSpec::new("agent", vec!["a\0".into()], vec![], vec![], None),
            Err(LaunchSpecError::InvalidArgument)
        );
        let spec = LaunchSpec::new("claude", vec!["--x".into()], vec![], vec![], None).unwrap();
        assert_eq!(spec.argv(&["-p".into()]), ["claude", "--x", "-p"]);
        let moved = spec.with_program("/opt/claude/bin/claude").unwrap();
        assert_eq!(moved.argv(&[]), ["/opt/claude/bin/claude", "--x"]);
        assert!(moved.with_program("rel/claude").is_err());
    }

    #[test]
    fn an_adapter_cannot_set_what_the_host_owns() {
        for name in [
            "HOME",
            "PATH",
            "TERM",
            "HTTP_PROXY",
            "https_proxy",
            "All_Proxy",
            "no_proxy",
            "WARD_SOCKET",
            "WARD_HOOK_SOCKET",
        ] {
            assert_eq!(
                spec(vec![var(name, "x")], vec![]),
                Err(LaunchSpecError::ReservedEnv(name.into())),
                "{name}"
            );
        }
        for bad in ["", "1X", "A-B", "A=B", "A B"] {
            assert_eq!(
                spec(vec![var(bad, "x")], vec![]),
                Err(LaunchSpecError::InvalidEnvName(bad.into())),
                "{bad:?}"
            );
        }
        assert_eq!(
            spec(vec![var("A", "x"), var("A", "y")], vec![]),
            Err(LaunchSpecError::DuplicateEnv("A".into()))
        );
        assert_eq!(
            spec(vec![var("A", &"x".repeat(MAX_ENV_VALUE_BYTES + 1))], vec![]),
            Err(LaunchSpecError::InvalidEnvValue("A".into()))
        );
        assert!(spec(vec![var("CODEX_HOME", "/home/agent/.codex")], vec![]).is_ok());
        let many = (0..=MAX_ENTRIES)
            .map(|i| var(&format!("V{i}"), "x"))
            .collect();
        assert_eq!(spec(many, vec![]), Err(LaunchSpecError::TooManyEntries));
    }

    #[test]
    fn settings_files_stay_in_the_sandbox_home() {
        assert!(spec(vec![], vec![file("/home/agent/.claude/settings.json")]).is_ok());
        for bad in [
            "/home/agent",
            "/home/agent/",
            "/home/agentx/a",
            "/home/agent/../etc/passwd",
            "/home/agent/./a",
            "/home/agent//a",
            "/work/.claude/settings.json",
            "/run/ward/hooks.sock",
            "home/agent/a",
        ] {
            assert_eq!(
                spec(vec![], vec![file(bad)]),
                Err(LaunchSpecError::InvalidSettingsPath(bad.into())),
                "{bad}"
            );
        }
        let big = SettingsFile {
            path: "/home/agent/a".into(),
            content: "x".repeat(MAX_SETTINGS_BYTES + 1),
        };
        assert_eq!(
            spec(vec![], vec![big]),
            Err(LaunchSpecError::SettingsTooLarge("/home/agent/a".into()))
        );
        assert_eq!(
            spec(vec![], vec![file("/home/agent/a"), file("/home/agent/a")]),
            Err(LaunchSpecError::DuplicateSettings("/home/agent/a".into()))
        );
    }

    #[test]
    fn requested_model_reads_the_last_flag_before_a_double_dash() {
        let s = |args: &[&str]| args.iter().map(ToString::to_string).collect::<Vec<_>>();
        let flags = &["--model", "-m"];
        assert_eq!(
            requested_model(&s(&["--model", "a"]), flags).as_deref(),
            Some("a")
        );
        assert_eq!(
            requested_model(&s(&["--model=b"]), flags).as_deref(),
            Some("b")
        );
        assert_eq!(
            requested_model(&s(&["-m", "c", "--model", "d"]), flags).as_deref(),
            Some("d")
        );
        assert_eq!(requested_model(&s(&["--", "--model", "f"]), flags), None);
        assert_eq!(requested_model(&s(&["--model"]), flags), None);
        assert_eq!(requested_model(&s(&["--model="]), flags), None);
        assert_eq!(requested_model(&s(&["--models", "g"]), flags), None);
        assert_eq!(requested_model(&s(&["--model", "h"]), &[]), None);
    }

    #[test]
    fn launch_wire_shape_is_stable_and_cannot_widen_the_launch() {
        let spec = LaunchSpec::new(
            "codex",
            vec![],
            vec![var("CODEX_HOME", "/home/agent/.codex")],
            vec![],
            Some(ProviderId::new("openai").unwrap()),
        )
        .unwrap();
        assert_eq!(spec.workdir(), WORKSPACE);
        let json = serde_json::to_string(&spec).unwrap();
        assert_eq!(
            json,
            r#"{"program":"codex","args":[],"env":[{"name":"CODEX_HOME","value":"/home/agent/.codex"}],"workdir":"/work","settings":[],"provider":"openai"}"#
        );
        assert_eq!(serde_json::from_str::<LaunchSpec>(&json).unwrap(), spec);

        for raw in [
            r#"{"program":"codex","workdir":"/"}"#,
            r#"{"program":"codex","workdir":"/work/sub"}"#,
            r#"{"program":"codex"}"#,
            r#"{"program":"codex","workdir":"/work","mounts":["/home"]}"#,
            r#"{"program":"codex","workdir":"/work","network":"unrestricted"}"#,
            r#"{"program":"codex","workdir":"/work","env":[{"name":"HTTPS_PROXY","value":"http://evil"}]}"#,
            r#"{"program":"codex","workdir":"/work","settings":[{"path":"/etc/profile","content":""}]}"#,
            r#"{"program":"codex","workdir":"/work","provider":"OpenAI"}"#,
        ] {
            assert!(serde_json::from_str::<LaunchSpec>(raw).is_err(), "{raw}");
        }
    }
}
