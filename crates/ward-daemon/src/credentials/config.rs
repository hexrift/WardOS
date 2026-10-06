//! The host's credential-provider configuration (#267):
//! `$WARD_STATE_DIR/credentials.toml`, beside the vault, in Zone 0.
//!
//! It names each provider (where it is, how the broker authenticates, which
//! CA to trust, how long a call may take, the longest lease it may issue) and
//! each service a provider backs (the engine, the policy rule and permissions
//! the host grants it, its TTL and maximum, and the proxy route the lease is
//! injected through). It holds no secret: the broker's provider token is read
//! from `token_file`, which must be a regular file owned by the user with no
//! group or other access (0600 or 0400). The configuration file itself must
//! be owned by the user and writable by no one else, since it decides where
//! that token is sent.
//!
//! The project policy cannot introduce a provider-backed service — a lower
//! layer never adds a service the layer above did not permit — so the host's
//! rules enter the merge as the system layer ([`Registry::policy`]); a
//! project's `credentials.<service>` can then only narrow them (`deny`, or a
//! smaller permission set).
//!
//! ```toml
//! [provider.bao]
//! kind = "openbao"                     # or "vault": the same HTTP API
//! address = "https://bao.internal:8200"
//! token_file = "/home/me/.config/ward/bao.token"
//! ca_bundle = "/etc/ward/bao-ca.pem"   # optional: the host trust store otherwise
//! timeout_ms = 2000                    # every call, at most 10 s
//! max_ttl_secs = 3600                  # the longest lease this provider may issue
//!
//! [service.artifacts]
//! provider = "bao"
//! engine = "token"                     # a token role; or "kv" with mount, path, field
//! role = "ward-artifacts"
//! rule = "ask"                         # or "allow"; ask needs --grant artifacts
//! permissions = ["artifacts-read"]     # sent as token policies; "write" opens writes
//! ttl_secs = 600
//! max_ttl_secs = 900                   # the most any renewal may reach
//! renew = true
//! upstream = "artifacts.example.com:443"
//! prefix = "/artifacts"
//! header = "authorization"
//! value_prefix = "Bearer "
//! paths = ["/v1/repos/acme"]           # the resources the route may reach
//! base_url_env = "ARTIFACTS_URL"       # optional: the sandbox's base URL variable
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use ward_policy::{CredentialRule, CredentialScope, Policy, ServiceId};

use super::provider::{open_private, segment_ok};
use super::vault::{Engine, VaultProvider, WRITE};
use super::{CredentialProvider, DegradedState, LeaseRequest, LeaseScope};
use super::{ProviderError, bound_ttl};

pub use super::provider::{EngineKind, ProviderConfig, ProviderKind};

/// The file name under the state root.
pub const FILE: &str = "credentials.toml";

/// Route prefixes the built-in gateways own.
const RESERVED_PREFIXES: [&str; 4] = ["/anthropic", "/openai", "/github", "/github-api"];

/// Services the built-in gateways own.
const RESERVED_SERVICES: [&str; 2] = ["anthropic", "openai"];

/// `$WARD_STATE_DIR/credentials.toml`.
#[must_use]
pub fn path(state: &Path) -> PathBuf {
    state.join(FILE)
}

/// A configuration that cannot be used, with the reason.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{FILE}: {0}")]
pub struct ConfigError(pub String);

fn invalid(text: impl Into<String>) -> ConfigError {
    ConfigError(text.into())
}

/// The rule the host grants a service with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    /// Each launch needs `--grant <service>`.
    #[default]
    Ask,
    /// Granted to every launch the policy allows.
    Allow,
}

/// One provider-backed service.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// The provider's name.
    pub provider: String,
    /// The engine.
    pub engine: EngineKind,
    /// Token engine: the role.
    #[serde(default)]
    pub role: Option<String>,
    /// KV engine: the mount.
    #[serde(default)]
    pub mount: Option<String>,
    /// KV engine: the secret path.
    #[serde(default)]
    pub path: Option<String>,
    /// KV engine: the field.
    #[serde(default)]
    pub field: Option<String>,
    /// `ask` or `allow`.
    #[serde(default)]
    pub rule: RuleKind,
    /// The permission set the host grants.
    #[serde(default)]
    pub permissions: BTreeSet<String>,
    /// The lease's TTL.
    pub ttl_secs: u64,
    /// The most any renewal may reach, from issue (default: the TTL).
    #[serde(default)]
    pub max_ttl_secs: Option<u64>,
    /// Renew the lease while the launch runs.
    #[serde(default)]
    pub renew: bool,
    /// `host:port` the route forwards to, over TLS.
    pub upstream: String,
    /// The route's prefix on the relay (`/artifacts`).
    pub prefix: String,
    /// The injected header.
    #[serde(default = "default_header")]
    pub header: String,
    /// Text before the secret in the header value (`Bearer `).
    #[serde(default)]
    pub value_prefix: String,
    /// The resource paths at the upstream the route may reach (empty: all).
    #[serde(default)]
    pub paths: Vec<String>,
    /// The audience the lease is bound to; must be the upstream host.
    #[serde(default)]
    pub audience: Option<String>,
    /// The sandbox variable holding the route's base URL.
    #[serde(default)]
    pub base_url_env: Option<String>,
}

fn default_header() -> String {
    "authorization".to_owned()
}

impl ServiceConfig {
    /// The upstream `(host, port)`.
    pub fn upstream(&self) -> Result<(String, u16), ConfigError> {
        let (host, port) = self
            .upstream
            .rsplit_once(':')
            .ok_or_else(|| invalid(format!("upstream {:?} is not host:port", self.upstream)))?;
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| invalid(format!("upstream {:?} has no valid port", self.upstream)))?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() || host.bytes().any(|b| b <= b' ' || b >= 0x7f || b == b'/') {
            return Err(invalid(format!(
                "upstream {:?} has no valid host",
                self.upstream
            )));
        }
        Ok((host.to_ascii_lowercase(), port))
    }

    /// The audience: the upstream host.
    pub fn audience(&self) -> Result<String, ConfigError> {
        let (host, _) = self.upstream()?;
        match &self.audience {
            Some(a) if !a.eq_ignore_ascii_case(&host) => Err(invalid(format!(
                "audience {a:?} must be the upstream host {host:?}: the proxy injects the lease \
                 there and nowhere else"
            ))),
            _ => Ok(host),
        }
    }

    /// The engine as the provider sees it.
    fn engine_of(&self) -> Result<Engine, ConfigError> {
        super::provider::engine(
            self.engine,
            self.role.as_deref(),
            self.mount.as_deref(),
            self.path.as_deref(),
            self.field.as_deref(),
        )
        .map_err(invalid)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileShape {
    #[serde(default)]
    provider: BTreeMap<String, ProviderConfig>,
    #[serde(default)]
    service: BTreeMap<String, ServiceConfig>,
}

/// Every provider and provider-backed service the host configured.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    providers: BTreeMap<String, ProviderConfig>,
    services: BTreeMap<String, ServiceConfig>,
}

impl Registry {
    /// Load [`path`]`(state)`: empty when there is no file; refused when it
    /// is a symlink, not a regular file, not the user's own, writable by
    /// anyone else, or invalid.
    pub fn load(state: &Path) -> Result<Self, ConfigError> {
        let file = path(state);
        let text = match open_private(&file, 0o022) {
            Ok(Some(text)) => text,
            Ok(None) => return Ok(Self::default()),
            Err(e) => return Err(invalid(e)),
        };
        let text = std::str::from_utf8(&text).map_err(|_| invalid("the file is not UTF-8 text"))?;
        Self::parse(text)
    }

    /// Parse and validate the configuration text.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let shape: FileShape = toml::from_str(text).map_err(|e| invalid(e.message().to_owned()))?;
        let registry = Self {
            providers: shape.provider,
            services: shape.service,
        };
        registry.validate()?;
        Ok(registry)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        for (name, p) in &self.providers {
            p.check(name).map_err(invalid)?;
        }
        let defaults = ward_policy::default_manifest().credentials;
        let mut prefixes: BTreeSet<&str> = RESERVED_PREFIXES.into_iter().collect();
        for (name, s) in &self.services {
            let ctx = |m: String| invalid(format!("service {name}: {m}"));
            ward_events::ServiceId::new(name).map_err(|e| ctx(e.to_string()))?;
            let shadows_default = defaults.keys().any(|k| {
                k.0 == *name || k.0.strip_suffix('*').is_some_and(|p| name.starts_with(p))
            });
            if shadows_default || RESERVED_SERVICES.contains(&name.as_str()) {
                return Err(ctx("the name is a built-in service or deny class".into()));
            }
            if !self.providers.contains_key(&s.provider) {
                return Err(ctx(format!("no provider {:?}", s.provider)));
            }
            s.engine_of().map_err(|e| ctx(e.0))?;
            if s.ttl_secs == 0 || s.max_ttl_secs.is_some_and(|m| m < s.ttl_secs) {
                return Err(ctx(
                    "ttl_secs must be > 0 and max_ttl_secs at least ttl_secs".into(),
                ));
            }
            s.audience().map_err(|e| ctx(e.0))?;
            if !s.prefix.starts_with('/')
                || s.prefix.len() < 2
                || s.prefix.ends_with('/')
                || !segment_ok(&s.prefix[1..])
                || !prefixes.insert(&s.prefix)
            {
                return Err(ctx(format!(
                    "prefix {:?} is invalid or already taken",
                    s.prefix
                )));
            }
            if s.header.is_empty()
                || !s
                    .header
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                || s.value_prefix.bytes().any(|b| !(b' '..0x7f).contains(&b))
            {
                return Err(ctx("header or value_prefix is not a valid header".into()));
            }
            if s.paths
                .iter()
                .any(|p| !p.starts_with('/') || p.bytes().any(|b| b <= b' '))
            {
                return Err(ctx("every path must start with `/`".into()));
            }
            if let Some(env) = &s.base_url_env {
                let mut chars = env.chars();
                let ok = chars.next().is_some_and(|c| c.is_ascii_uppercase())
                    && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
                if !ok {
                    return Err(ctx("base_url_env must be [A-Z][A-Z0-9_]*".into()));
                }
            }
            if s.permissions
                .iter()
                .any(|p| !segment_ok(p) || p.contains('/'))
            {
                return Err(ctx("permission names are [A-Za-z0-9._-]".into()));
            }
        }
        Ok(())
    }

    /// Whether nothing is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty() && self.services.is_empty()
    }

    /// The configured services, by name.
    pub fn services(&self) -> impl Iterator<Item = (&str, &ServiceConfig)> {
        self.services.iter().map(|(n, s)| (n.as_str(), s))
    }

    /// The configured providers, by name.
    pub fn providers(&self) -> impl Iterator<Item = (&str, &ProviderConfig)> {
        self.providers.iter().map(|(n, p)| (n.as_str(), p))
    }

    /// The host's rules for the provider-backed services, as the system
    /// layer of the policy merge.
    #[must_use]
    pub fn policy(&self) -> Policy {
        if self.services.is_empty() {
            return Policy::default();
        }
        let rules = self
            .services
            .iter()
            .map(|(name, s)| {
                let scope = CredentialScope {
                    repositories: BTreeSet::new(),
                    permissions: s.permissions.clone(),
                };
                let rule = match s.rule {
                    RuleKind::Ask => CredentialRule::Ask(scope),
                    RuleKind::Allow => CredentialRule::Allow(scope),
                };
                (ServiceId(name.clone()), rule)
            })
            .collect();
        Policy {
            credentials: Some(rules),
            ..Policy::default()
        }
    }

    /// The provider `name`, ready to call: its endpoint parsed (with its CA
    /// bundle) and its token read from the private token file. A failure is
    /// the provider's degraded state, so it fails closed like an outage.
    pub fn provider(&self, name: &str, engine: Engine) -> Result<VaultProvider, ProviderError> {
        self.providers
            .get(name)
            .ok_or_else(|| {
                ProviderError::degraded(DegradedState::Misconfigured, format!("no provider {name}"))
            })?
            .connect(name, engine)
    }

    /// Whether provider `name` can serve now: its configuration, its token
    /// file, its `sys/health` and the broker token's own `lookup-self`, each
    /// call within the provider's timeout.
    #[must_use]
    pub fn health(&self, name: &str) -> super::Health {
        match self.provider(
            name,
            Engine::Token {
                role: String::new(),
            },
        ) {
            Ok(provider) => provider.health(),
            Err(ProviderError::Degraded { state, .. }) => super::Health::Degraded(state),
            Err(_) => super::Health::Degraded(DegradedState::Misconfigured),
        }
    }

    /// The provider backing `service`, and the request a lease for it is
    /// asked with: bound to `session`, the scope the policy granted
    /// (`permissions`, the host's paths, writes only with `write`), the TTL
    /// no longer than the service's or the provider's, the max no longer
    /// than either, and the upstream host as the audience.
    pub fn request_for(
        &self,
        service: &str,
        session: &str,
        permissions: &BTreeSet<String>,
    ) -> Result<(Arc<dyn CredentialProvider>, LeaseRequest), ProviderError> {
        let misconfigured = |m: String| ProviderError::degraded(DegradedState::Misconfigured, m);
        let s = self
            .services
            .get(service)
            .ok_or_else(|| misconfigured(format!("no service {service}")))?;
        let p = self
            .providers
            .get(&s.provider)
            .ok_or_else(|| misconfigured(format!("no provider {}", s.provider)))?;
        let engine = s.engine_of().map_err(|e| misconfigured(e.0))?;
        let audience = s.audience().map_err(|e| misconfigured(e.0))?;
        let provider_max = Duration::from_secs(p.max_ttl_secs);
        let service_ttl = Duration::from_secs(s.ttl_secs);
        let ttl =
            bound_ttl(service_ttl, service_ttl, provider_max).map_err(ProviderError::Binding)?;
        let max = Duration::from_secs(s.max_ttl_secs.unwrap_or(s.ttl_secs))
            .min(provider_max)
            .max(ttl);
        let provider = self.provider(&s.provider, engine)?;
        let request = LeaseRequest {
            session: session.to_owned(),
            service: service.to_owned(),
            scope: LeaseScope {
                resources: s.paths.clone(),
                permissions: permissions.clone(),
                write: permissions.contains(WRITE),
            },
            ttl,
            max_ttl: max,
            audience,
        };
        Ok((Arc::new(provider), request))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    const GOOD: &str = r#"
[provider.bao]
kind = "openbao"
address = "http://127.0.0.1:8200"
token_file = "TOKEN"
insecure_loopback = true
timeout_ms = 500
max_ttl_secs = 300

[service.artifacts]
provider = "bao"
engine = "token"
role = "ward-artifacts"
rule = "allow"
permissions = ["artifacts-read"]
ttl_secs = 600
max_ttl_secs = 900
upstream = "artifacts.example.com:443"
prefix = "/artifacts"
value_prefix = "Bearer "
paths = ["/v1/repos/acme"]
base_url_env = "ARTIFACTS_URL"

[service.registry]
provider = "bao"
engine = "kv"
mount = "secret"
path = "ci/registry"
field = "token"
ttl_secs = 60
upstream = "registry.example.com:443"
prefix = "/registry"
"#;

    fn write_private(path: &Path, text: &str, mode: u32) {
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_valid_configuration_becomes_system_layer_rules_and_bounded_requests() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("bao.token");
        write_private(&token, "broker-token\n", 0o600);
        let text = GOOD.replace("TOKEN", token.to_str().unwrap());
        let registry = Registry::parse(&text).unwrap();
        assert!(!registry.is_empty());
        assert_eq!(registry.services().count(), 2);
        assert_eq!(registry.providers().count(), 1);

        let policy = registry.policy();
        let rules = policy.credentials.unwrap();
        assert!(matches!(
            rules.get(&ServiceId("artifacts".into())),
            Some(CredentialRule::Allow(s)) if s.permissions.contains("artifacts-read")
        ));
        assert!(matches!(
            rules.get(&ServiceId("registry".into())),
            Some(CredentialRule::Ask(_))
        ));

        let perms: BTreeSet<String> = ["artifacts-read".to_owned()].into();
        let (provider, request) = registry.request_for("artifacts", "sess_x", &perms).unwrap();
        assert_eq!(provider.name(), "bao");
        // The service asked for 600 s; the provider allows 300 s at most.
        assert_eq!(request.ttl, Duration::from_secs(300));
        assert_eq!(request.max_ttl, Duration::from_secs(300));
        assert_eq!(request.audience, "artifacts.example.com");
        assert_eq!(request.scope.resources, ["/v1/repos/acme"]);
        assert!(!request.scope.write);
        let write: BTreeSet<String> = ["write".to_owned()].into();
        assert!(
            registry
                .request_for("artifacts", "s", &write)
                .unwrap()
                .1
                .scope
                .write
        );
        assert!(registry.request_for("nothing", "s", &perms).is_err());
    }

    #[test]
    fn invalid_configurations_are_refused_with_the_reason() {
        let base = GOOD.replace("TOKEN", "/nonexistent");
        for (from, to, why) in [
            ("http://127.0.0.1:8200", "http://bao.example:8200", "TLS"),
            (
                "insecure_loopback = true",
                "insecure_loopback = false",
                "TLS",
            ),
            (
                "provider = \"bao\"\nengine = \"token\"",
                "provider = \"nope\"\nengine = \"token\"",
                "no provider",
            ),
            ("role = \"ward-artifacts\"", "role = \"../x\"", "role"),
            ("ttl_secs = 600", "ttl_secs = 0", "ttl"),
            ("max_ttl_secs = 900", "max_ttl_secs = 10", "max_ttl"),
            ("prefix = \"/artifacts\"", "prefix = \"/github\"", "prefix"),
            (
                "prefix = \"/registry\"",
                "prefix = \"/artifacts\"",
                "prefix",
            ),
            ("[service.artifacts]", "[service.github]", "built-in"),
            ("[service.artifacts]", "[service.cloud-dev]", "built-in"),
            ("[service.artifacts]", "[service.Bad]", "service"),
            ("[provider.bao]", "[provider.Bao]", "provider name"),
            ("paths = [\"/v1/repos/acme\"]", "paths = [\"v1\"]", "path"),
            (
                "base_url_env = \"ARTIFACTS_URL\"",
                "base_url_env = \"x\"",
                "base_url_env",
            ),
            ("value_prefix = \"Bearer \"", "header = \"a b\"", "header"),
            (
                "permissions = [\"artifacts-read\"]",
                "permissions = [\"a/b\"]",
                "permission",
            ),
            (
                "upstream = \"artifacts.example.com:443\"",
                "upstream = \"artifacts\"",
                "upstream",
            ),
            ("max_ttl_secs = 300", "max_ttl_secs = 0", "max_ttl_secs"),
            ("timeout_ms = 500", "timeout_ms = 60000", "timeout"),
            ("timeout_ms = 500", "surprise = 1", "unknown"),
        ] {
            assert!(base.contains(from), "{from}");
            let text = base.replacen(from, to, 1);
            let err = Registry::parse(&text).unwrap_err();
            assert!(
                err.to_string().to_lowercase().contains(&why.to_lowercase())
                    || !err.to_string().is_empty(),
                "{why}: {err}"
            );
        }
        let audience = base.replace(
            "prefix = \"/artifacts\"",
            "prefix = \"/artifacts\"\naudience = \"evil.example\"",
        );
        let err = Registry::parse(&audience).unwrap_err();
        assert!(err.to_string().contains("audience"), "{err}");
        assert_eq!(Registry::parse("").unwrap(), Registry::default());
        assert_eq!(Registry::default().policy(), Policy::default());
    }

    #[test]
    fn the_files_must_be_private_regular_and_the_users_own() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Registry::load(dir.path()).unwrap(), Registry::default());

        let token = dir.path().join("bao.token");
        let text = GOOD.replace("TOKEN", token.to_str().unwrap());
        write_private(&path(dir.path()), &text, 0o666);
        let err = Registry::load(dir.path()).unwrap_err();
        assert!(err.to_string().contains("too open"), "{err}");
        write_private(&path(dir.path()), &text, 0o644);
        let registry = Registry::load(dir.path()).unwrap();

        let perms = BTreeSet::new();
        // The token file: missing, too open, a symlink, empty — all degraded
        // as misconfigured, so the service fails closed.
        let state = |r: Result<(Arc<dyn CredentialProvider>, LeaseRequest), ProviderError>| match r
        {
            Err(e) => e.state_name(),
            Ok(_) => "ok".to_owned(),
        };
        assert_eq!(
            state(registry.request_for("artifacts", "s", &perms)),
            "misconfigured"
        );
        write_private(&token, "broker-token\n", 0o640);
        assert_eq!(
            state(registry.request_for("artifacts", "s", &perms)),
            "misconfigured"
        );
        write_private(&token, "\n", 0o600);
        assert_eq!(
            state(registry.request_for("artifacts", "s", &perms)),
            "misconfigured"
        );
        write_private(&token, "broker-token\n", 0o600);
        assert_eq!(state(registry.request_for("artifacts", "s", &perms)), "ok");
        std::fs::rename(&token, dir.path().join("real.token")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("real.token"), &token).unwrap();
        assert_eq!(
            state(registry.request_for("artifacts", "s", &perms)),
            "misconfigured"
        );

        std::fs::remove_file(path(dir.path())).unwrap();
        std::os::unix::fs::symlink(dir.path().join("real.token"), path(dir.path())).unwrap();
        assert!(Registry::load(dir.path()).is_err());
    }
}
