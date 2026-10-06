//! A provider's host configuration (#267): where it is, how the broker
//! authenticates to it, which CA to trust, how long a call may take and the
//! longest lease it may issue — the `[provider.<name>]` table of the session
//! broker's `credentials.toml` and of the node's credentials file alike.
//!
//! It holds no secret: the broker's provider token is read from `token_file`,
//! which must be a regular file owned by the user with no group or other access
//! (0600 or 0400), opened without following a symlink ([`read_token`]). A file
//! that decides where that token is sent must itself be the user's and writable
//! by no one else ([`open_private`]).

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::http::{self, Endpoint};
use crate::vault::{Engine, VaultProvider};
use crate::{DegradedState, LeasedSecret, ProviderError};

/// Which HTTP API a provider speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// HashiCorp Vault.
    Vault,
    /// OpenBao (the same API).
    Openbao,
}

/// One provider.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Which API.
    pub kind: ProviderKind,
    /// `https://host[:port]`.
    pub address: String,
    /// The broker's provider token, 0600.
    pub token_file: PathBuf,
    /// A PEM bundle to trust instead of the host store.
    #[serde(default)]
    pub ca_bundle: Option<PathBuf>,
    /// The bound on every call.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// The longest lease it may issue.
    #[serde(default = "default_max_ttl")]
    pub max_ttl_secs: u64,
    /// Plain HTTP to a loopback IP literal, for tests only.
    #[serde(default)]
    pub insecure_loopback: bool,
}

const fn default_timeout_ms() -> u64 {
    2000
}

const fn default_max_ttl() -> u64 {
    3600
}

impl ProviderConfig {
    /// Check the provider `name` and its address, timeout and maximum TTL
    /// without touching the network, the trust store or the token file.
    ///
    /// # Errors
    ///
    /// Returns the reason, naming the provider.
    pub fn check(&self, name: &str) -> Result<(), String> {
        if !name_ok(name) {
            return Err(format!("provider name {name:?} is not [a-z0-9-]{{1,32}}"));
        }
        http::check_address(
            &self.address,
            self.insecure_loopback,
            Duration::from_millis(self.timeout_ms),
        )
        .map_err(|e| format!("provider {name}: {e}"))?;
        if self.max_ttl_secs == 0 {
            return Err(format!("provider {name}: max_ttl_secs must be > 0"));
        }
        Ok(())
    }

    /// The provider `name`, ready to call for `engine`: its endpoint parsed
    /// (with its CA bundle) and its token read from the private token file. A
    /// failure is the provider's degraded state, so it fails closed like an
    /// outage.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Degraded`] when the address, the CA bundle or
    /// the token file cannot be used.
    pub fn connect(&self, name: &str, engine: Engine) -> Result<VaultProvider, ProviderError> {
        let endpoint = Endpoint::parse(
            &self.address,
            self.ca_bundle.as_deref(),
            self.insecure_loopback,
            Duration::from_millis(self.timeout_ms).min(http::MAX_TIMEOUT),
        )?;
        let token = read_token(&self.token_file)?;
        Ok(VaultProvider::new(name, endpoint, token, engine))
    }
}

/// `[a-z0-9-]{1,32}`: a provider name also appears in rule references.
#[must_use]
pub fn name_ok(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `a/b.c-d_e`: no empty segment, no `..`, nothing to escape.
#[must_use]
pub fn segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s.split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_'))
}

/// Which engine a service reads from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    /// KV v2.
    Kv,
    /// A token role.
    Token,
}

/// The engine a service of `kind` reads from: a token `role`, or a KV
/// `mount`, `path` and `field`, each a [`segment_ok`] path.
///
/// # Errors
///
/// Names the field that is missing or invalid.
pub fn engine(
    kind: EngineKind,
    role: Option<&str>,
    mount: Option<&str>,
    path: Option<&str>,
    field: Option<&str>,
) -> Result<Engine, String> {
    let valid = |v: Option<&str>, name: &str| {
        v.filter(|s| segment_ok(s))
            .map(str::to_owned)
            .ok_or_else(|| format!("engine needs a valid `{name}`"))
    };
    Ok(match kind {
        EngineKind::Kv => Engine::Kv {
            mount: valid(mount, "mount")?,
            path: valid(path, "path")?,
            field: valid(field, "field")?,
        },
        EngineKind::Token => Engine::Token {
            role: valid(role, "role")?,
        },
    })
}

/// Open `path` without following a symlink and read it, refusing anything
/// but a regular file owned by this user with none of `forbidden_mode` bits
/// set. `Ok(None)` when it does not exist.
///
/// # Errors
///
/// Returns the reason, naming the path.
pub fn open_private(
    path: &Path,
    forbidden_mode: u32,
) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits() | nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!(
                "{}: cannot open ({}; a symlink is refused)",
                path.display(),
                e.kind()
            ));
        }
    };
    let meta = file
        .metadata()
        .map_err(|e| format!("{}: {}", path.display(), e.kind()))?;
    if !meta.is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    if meta.uid() != nix::unistd::getuid().as_raw() {
        return Err(format!("{}: not owned by this user", path.display()));
    }
    if meta.mode() & forbidden_mode != 0 {
        return Err(format!(
            "{}: mode {:o} is too open",
            path.display(),
            meta.mode() & 0o777
        ));
    }
    let mut out = Zeroizing::new(Vec::new());
    let mut file: File = file;
    file.read_to_end(&mut out)
        .map_err(|e| format!("{}: {}", path.display(), e.kind()))?;
    Ok(Some(out))
}

/// The broker's provider token: a regular file of this user's with no group
/// or other access, its first line trimmed.
///
/// # Errors
///
/// Returns [`DegradedState::Misconfigured`] for a missing, too open, symlinked,
/// non-text or empty token file.
pub fn read_token(path: &Path) -> Result<LeasedSecret, ProviderError> {
    let misconfigured = |m: String| ProviderError::degraded(DegradedState::Misconfigured, m);
    let bytes = open_private(path, 0o077)
        .map_err(misconfigured)?
        .ok_or_else(|| misconfigured(format!("{}: token file missing", path.display())))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| misconfigured(format!("{}: token is not text", path.display())))?;
    let token = text.lines().next().unwrap_or_default().trim();
    if token.is_empty() {
        return Err(misconfigured(format!(
            "{}: token file is empty",
            path.display()
        )));
    }
    Ok(LeasedSecret::new(token.as_bytes().to_vec()))
}
