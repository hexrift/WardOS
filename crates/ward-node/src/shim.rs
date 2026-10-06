//! The `ward-agent` shim and the in-sandbox relay of hosted agent adapters and of workloads
//! behind an egress proxy (#424, #267, ADR-0037).
//!
//! A node started with `--agent-shim <file>` ([`crate::execution::NodeExecution::with_agent_shim`])
//! runs every attempt of a hosted adapter ([`crate::adapters`]), and every attempt with an
//! egress proxy, under that shim, bound read-only at [`ward_launch::AGENT_SHIM`] and run
//! ahead of the workload's command line. The shim applies its Landlock ruleset (read-only on
//! [`ward_launch::SHIM_READ_ONLY`], the shim itself included, so an adapter's command hooks
//! can run it as `ward-agent hook` against the attempt's hook socket), its seccomp filter and
//! `no_new_privs`; for an attempt with an egress proxy it then starts its relay, a TCP
//! listener on [`ward_launch::RELAY_ADDR`] inside the attempt's network namespace that
//! forwards every connection to the attempt's proxy socket. The relay is a pipe: whatever
//! passes it is decided by the proxy behind the socket the workload could already reach, so
//! it adds nothing beyond the manifest's allowlist, its brokered credentials and its holds.
//!
//! With the relay running the workload also gets [`relay_env`]: the proxy variables naming
//! the relay, so a stock HTTP client (`git`, `curl`, a package manager) reaches the
//! allowlist through it and a credential route as `http://127.0.0.1:3128/<service>/…`, and,
//! for a hosted adapter only when the attempt has the credential route of the service named
//! after the adapter's provider (the manifest grants it, ADR-0036 §4), the provider's base
//! URL on that route and [`PLACEHOLDER_KEY`], which the proxy replaces on the way out.
//!
//! The shim is the operator's: the node never looks for one beside itself, on the sandbox
//! `PATH` or in the workspace, and the envelope cannot name one. [`AgentShim::verify`]
//! refuses a path that is not absolute, not a regular file (a symlink included), writable
//! by group or others, not executable or owned by neither root nor the node's user, and a
//! program that does not answer as a `ward-agent` shim with a relay, or cannot harden
//! itself on this host.

use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nix::unistd::geteuid;
use thiserror::Error;
use ward_agent_adapter::catalogue::{self, PLACEHOLDER_KEY};
use ward_launch::RELAY_ADDR;
use ward_proxy::GatewayRoute;

/// The proxy variables that name the relay.
pub const PROXY_ENV: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"];

/// The variables that keep loopback, the relay included, off the proxy.
pub const NO_PROXY_ENV: [&str; 2] = ["NO_PROXY", "no_proxy"];

/// Why the node refuses a shim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShimRefusal {
    /// The path is relative.
    NotAbsolute,
    /// The path cannot be inspected.
    Unreadable(String),
    /// A symlink, a directory or anything but a regular file.
    NotAFile,
    /// Group or others may write it.
    Writable,
    /// The owner may not execute it.
    NotExecutable,
    /// Owned by neither root nor the node's user.
    Owner,
    /// It does not answer as a `ward-agent` shim with a relay.
    NotAShim,
    /// It could not apply its hardening and run a program.
    CannotHarden,
}

impl fmt::Display for ShimRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute => formatter.write_str("not an absolute path"),
            Self::Unreadable(error) => formatter.write_str(error),
            Self::NotAFile => formatter.write_str("not a regular file"),
            Self::Writable => formatter.write_str("writable by group or others"),
            Self::NotExecutable => formatter.write_str("not executable"),
            Self::Owner => formatter.write_str("owned by neither root nor the node's user"),
            Self::NotAShim => formatter.write_str("not a ward-agent shim with --relay"),
            Self::CannotHarden => {
                formatter.write_str("cannot apply Landlock and seccomp on this host")
            }
        }
    }
}

/// A shim the node refuses to start with.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("agent shim {}: {refusal}", path.display())]
pub struct ShimError {
    /// The path the operator named.
    pub path: PathBuf,
    /// Why it is refused.
    pub refusal: ShimRefusal,
}

/// The operator's verified `ward-agent` shim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentShim {
    path: PathBuf,
}

impl AgentShim {
    /// Verify the shim at `path`, running it once with `--help` and once hardened over the
    /// directory `scratch`, which must exist.
    ///
    /// # Errors
    ///
    /// Returns [`ShimError`] naming the path and the [`ShimRefusal`].
    pub fn verify(path: &Path, scratch: &Path) -> Result<Self, ShimError> {
        let refuse = |refusal| ShimError {
            path: path.to_path_buf(),
            refusal,
        };
        if !path.is_absolute() {
            return Err(refuse(ShimRefusal::NotAbsolute));
        }
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| refuse(ShimRefusal::Unreadable(error.to_string())))?;
        if !metadata.file_type().is_file() {
            return Err(refuse(ShimRefusal::NotAFile));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(refuse(ShimRefusal::Writable));
        }
        if metadata.mode() & 0o100 == 0 {
            return Err(refuse(ShimRefusal::NotExecutable));
        }
        if metadata.uid() != 0 && metadata.uid() != geteuid().as_raw() {
            return Err(refuse(ShimRefusal::Owner));
        }
        let help = quiet(Command::new(path).arg("--help"))
            .stdout(Stdio::piped())
            .output()
            .map_err(|_| refuse(ShimRefusal::NotAShim))?;
        if !help.status.success() || !String::from_utf8_lossy(&help.stdout).contains("--relay") {
            return Err(refuse(ShimRefusal::NotAShim));
        }
        let hardened = quiet(
            Command::new(path)
                .arg("--rw")
                .arg(scratch)
                .args(["--", "/bin/true"]),
        )
        .stdout(Stdio::null())
        .status()
        .map_err(|_| refuse(ShimRefusal::CannotHarden))?;
        if !hardened.success() {
            return Err(refuse(ShimRefusal::CannotHarden));
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// A shim at `path` taken as verified, for the launch tests.
    #[cfg(test)]
    pub(crate) const fn assumed(path: PathBuf) -> Self {
        Self { path }
    }

    /// The host path bound read-only into the sandbox.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn quiet(command: &mut Command) -> &mut Command {
    command
        .env_clear()
        .env("WARD_AGENT_QUIET", "1")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
}

/// What a workload running behind the relay is told: the proxy variables naming it and, for
/// a hosted adapter of `provider` when `routes` holds the route of the service named after
/// it, the provider's base URL on that route and the placeholder key.
#[must_use]
pub fn relay_env(provider: Option<&str>, routes: &[GatewayRoute]) -> Vec<(String, String)> {
    let relay = format!("http://{RELAY_ADDR}");
    let mut env: Vec<(String, String)> = PROXY_ENV
        .iter()
        .map(|name| ((*name).to_owned(), relay.clone()))
        .chain(
            NO_PROXY_ENV
                .iter()
                .map(|name| ((*name).to_owned(), "localhost,127.0.0.1".to_owned())),
        )
        .collect();
    let endpoint = provider.and_then(catalogue::provider_endpoint);
    if let Some(endpoint) = endpoint
        && routes
            .iter()
            .any(|route| route.prefix().strip_prefix('/') == Some(endpoint.provider))
    {
        env.push((
            endpoint.base_url_env.to_owned(),
            format!("{relay}/{}{}", endpoint.provider, endpoint.base_path),
        ));
        env.push((endpoint.key_env.to_owned(), PLACEHOLDER_KEY.to_owned()));
    }
    env
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::fs::PermissionsExt;

    use ward_proxy::Secret;

    use super::*;

    fn route(prefix: &str) -> GatewayRoute {
        GatewayRoute::new(
            prefix,
            "api.example.com",
            443,
            "x-api-key",
            Secret::new(b"k".to_vec()),
        )
        .unwrap()
    }

    fn names(env: &[(String, String)]) -> Vec<&str> {
        env.iter().map(|(name, _)| name.as_str()).collect()
    }

    #[test]
    fn the_base_url_points_at_the_relay_only_for_the_route_of_the_adapters_provider() {
        let env = relay_env(
            Some("anthropic"),
            &[route("/artifacts"), route("/anthropic")],
        );
        assert!(env.contains(&(
            "ANTHROPIC_BASE_URL".to_owned(),
            "http://127.0.0.1:3128/anthropic".to_owned()
        )));
        assert!(env.contains(&("ANTHROPIC_API_KEY".to_owned(), "ward-gateway".to_owned())));
        assert!(env.contains(&("HTTPS_PROXY".to_owned(), "http://127.0.0.1:3128".to_owned())));
        assert!(env.contains(&("no_proxy".to_owned(), "localhost,127.0.0.1".to_owned())));

        let codex = relay_env(Some("openai"), &[route("/openai")]);
        assert!(codex.contains(&(
            "OPENAI_BASE_URL".to_owned(),
            "http://127.0.0.1:3128/openai/v1".to_owned()
        )));

        let proxy_only = [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "NO_PROXY",
            "no_proxy",
        ];
        for (provider, routes) in [
            (
                Some("anthropic"),
                vec![route("/openai"), route("/anthropic-x")],
            ),
            (Some("openai"), vec![route("/anthropic")]),
            (Some("gemini"), vec![route("/gemini")]),
            (None, vec![route("/anthropic")]),
            (Some("anthropic"), vec![]),
        ] {
            assert_eq!(
                names(&relay_env(provider, &routes)),
                proxy_only,
                "{provider:?}"
            );
        }
    }

    #[test]
    fn a_shim_the_node_cannot_trust_is_refused_before_it_runs() {
        let dir = tempfile::tempdir().unwrap();
        let refusal = |path: &Path| AgentShim::verify(path, dir.path()).unwrap_err().refusal;
        assert_eq!(refusal(Path::new("ward-agent")), ShimRefusal::NotAbsolute);
        assert!(matches!(
            refusal(&dir.path().join("missing")),
            ShimRefusal::Unreadable(_)
        ));
        assert_eq!(refusal(dir.path()), ShimRefusal::NotAFile);
        let file = dir.path().join("shim");
        std::fs::write(&file, "").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(refusal(&link), ShimRefusal::NotAFile);
        for (mode, expected) in [
            (0o775, ShimRefusal::Writable),
            (0o757, ShimRefusal::Writable),
            (0o644, ShimRefusal::NotExecutable),
        ] {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(refusal(&file), expected, "{mode:o}");
        }
        let error = AgentShim::verify(Path::new("ward-agent"), dir.path()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "agent shim ward-agent: not an absolute path"
        );
    }

    #[test]
    fn a_program_that_is_not_the_shim_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let program = ["/usr/bin/true", "/bin/true"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.exists())
            .unwrap();
        assert_eq!(
            AgentShim::verify(program, dir.path()).unwrap_err().refusal,
            ShimRefusal::NotAShim
        );
    }
}
