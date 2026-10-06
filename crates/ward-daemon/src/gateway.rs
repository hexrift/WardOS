//! Gateway credentials (ADR-0008, `docs/credential-broker.md` §4): the host
//! keeps the model-API key and `ward-proxy` injects it on the way out. The
//! sandbox sees a base URL on the relay and a placeholder token, never the key.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ward_events::{CredentialDelivery, NameText, Scope, ServiceId, ShortText, WardEvent};
use ward_proxy::{GatewayRoute, Secret};

use crate::credentials::config::ServiceConfig;
use crate::credentials::keeper::HeldLease;
use crate::credentials::{CredentialProvider as _, LeaseRequest, LeaseScope, local::LocalVault};
use crate::error::{Error, Result};
use crate::sandbox::RELAY_ADDR;

/// Placeholder the agent presents; the proxy strips it before injection.
pub const PLACEHOLDER: &str = ward_agent_adapter::catalogue::PLACEHOLDER_KEY;

/// The lease a host-vault key is issued under: the validity a gateway grant
/// is recorded with (`session::GATEWAY_TTL`); the route ends with the launch.
const NOMINAL_TTL: core::time::Duration = core::time::Duration::from_secs(24 * 60 * 60);

/// The vault under `state`: one file per key, named by the host variable, written
/// by `ward vault set` and read by [`Gateway::resolve`]. Both go through here so the
/// two can never name different paths.
#[must_use]
pub fn vault_dir(state: &Path) -> PathBuf {
    state.join("vault")
}

/// `vault/<key_env>`, the file holding one key.
#[must_use]
pub fn vault_file(state: &Path, key_env: &str) -> PathBuf {
    vault_dir(state).join(key_env)
}

/// How one service is fronted by the proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewaySpec {
    /// Service name as it appears in policy and the log (`anthropic`).
    pub service: &'static str,
    /// Path prefix on the relay (`/anthropic`).
    pub prefix: &'static str,
    /// Upstream host and port, always TLS.
    pub upstream: (&'static str, u16),
    /// Header carrying the injected credential.
    pub header: &'static str,
    /// Text placed before the key in the header value (`Bearer ` for OAuth-style APIs).
    pub value_prefix: &'static str,
    /// When set, the header carries `Basic base64(user:key)` instead (git over HTTPS).
    pub basic_user: Option<&'static str>,
    /// Client headers removed before injection, so the placeholder never leaves.
    pub strip: &'static [&'static str],
    /// Host variable (and vault file name) holding the real key.
    pub key_env: &'static str,
    /// Variable the agent reads its base URL from (empty: none).
    pub base_url_env: &'static str,
    /// Path appended to the prefix in that base URL (`/v1` when the agent expects it).
    pub base_path: &'static str,
    /// Variable the agent reads its (placeholder) key from (empty: none).
    pub placeholder_env: &'static str,
}

/// Standard base64 without a dependency: only credentials pass through here.
#[must_use]
pub fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A resolved gateway: the route for the proxy and the sandbox's view of it.
#[derive(Clone, Debug)]
pub struct Gateway {
    /// Service name.
    pub service: String,
    /// Proxy route carrying the real key.
    pub route: GatewayRoute,
    /// Environment set inside the sandbox.
    pub env: Vec<(String, String)>,
    /// Permissions recorded in the grant.
    pub permissions: Vec<String>,
    subject: String,
    /// The provider lease the route injects (#267), when it is one.
    lease: Option<Arc<HeldLease>>,
}

impl Gateway {
    /// Resolve `spec` with a key from the host environment (`key_env`), else from
    /// `vault/<key_env>` under `state`. `None` when neither holds a key.
    ///
    /// The key is issued by the host vault through the credential-provider
    /// interface (#267, [`LocalVault`]), with a nominal lease as long as the
    /// grant's recorded validity; the route itself lives as long as the launch.
    pub fn resolve(spec: &GatewaySpec, state: &Path) -> Result<Option<Self>> {
        let request = LeaseRequest {
            session: String::new(),
            service: spec.service.to_owned(),
            scope: LeaseScope::default(),
            ttl: NOMINAL_TTL,
            max_ttl: NOMINAL_TTL,
            audience: spec.upstream.0.to_owned(),
        };
        match LocalVault::new(state, spec.key_env).issue(&request) {
            Ok(lease) => {
                let key = std::str::from_utf8(lease.secret().expose())
                    .map_err(|_| Error::Sandbox(format!("{}: key is not text", spec.key_env)))?;
                Self::from_key(spec, key).map(Some)
            }
            Err(_) => Ok(None),
        }
    }

    /// The gateway of a provider-backed service (#267): `held`'s lease
    /// injected as `config.header: config.value_prefix<value>` on the route
    /// `config.prefix` to `config.upstream`, restricted to `config.paths`,
    /// read-only unless the lease's scope writes, and bound to the lease's
    /// deadline so the proxy stops injecting it when the lease ends. The
    /// sandbox sees only the relay URL in `config.base_url_env`. A value the
    /// provider returned that could not be a header (a control byte) is
    /// refused rather than injected.
    pub fn leased(
        service: &str,
        config: &ServiceConfig,
        held: Arc<HeldLease>,
        permissions: Vec<String>,
    ) -> Result<Self> {
        let refuse = |m: &str| Error::Sandbox(format!("credential {service}: {m}"));
        let lease = held.lease().ok_or_else(|| refuse("the lease is gone"))?;
        let secret = lease.secret().expose();
        if secret.is_empty() || secret.iter().any(|b| *b < b' ' || *b == 0x7f) {
            return Err(refuse("the provider's value cannot be sent as a header"));
        }
        let mut value = Vec::with_capacity(config.value_prefix.len() + secret.len());
        value.extend_from_slice(config.value_prefix.as_bytes());
        value.extend_from_slice(secret);
        let (host, port) = config.upstream().map_err(|e| refuse(&e.0))?;
        let route = GatewayRoute::new(
            config.prefix.as_str(),
            &host,
            port,
            config.header.as_str(),
            Secret::new(value),
        )
        .map_err(|e| refuse(&e.to_string()))?
        .strip_headers([config.header.as_str()])
        .scope(config.paths.iter().cloned(), lease.scope.write)
        .until(held.deadline());
        let env = config
            .base_url_env
            .iter()
            .map(|var| (var.clone(), format!("http://{RELAY_ADDR}{}", config.prefix)))
            .collect();
        Ok(Self {
            service: service.to_owned(),
            route,
            env,
            permissions,
            subject: format!("{host}:{port}"),
            lease: Some(held),
        })
    }

    /// The provider lease this gateway injects, when it is one (#267).
    #[must_use]
    pub fn lease(&self) -> Option<&Arc<HeldLease>> {
        self.lease.as_ref()
    }

    /// Build the gateway for `spec` around `key`.
    pub fn from_key(spec: &GatewaySpec, key: &str) -> Result<Self> {
        let (host, port) = spec.upstream;
        let value = Secret::from(match spec.basic_user {
            Some(user) => format!("Basic {}", base64(format!("{user}:{key}").as_bytes())),
            None => format!("{}{key}", spec.value_prefix),
        });
        let route = GatewayRoute::new(spec.prefix, host, port, spec.header, value)
            .map_err(|e| Error::Sandbox(format!("gateway {}: {e}", spec.service)))?
            .strip_headers(spec.strip);
        Ok(Self::new(spec, route))
    }

    /// Pair `spec` with an already built route.
    #[must_use]
    pub fn new(spec: &GatewaySpec, route: GatewayRoute) -> Self {
        let mut env = Vec::new();
        if !spec.base_url_env.is_empty() {
            env.push((
                spec.base_url_env.to_owned(),
                format!("http://{RELAY_ADDR}{}{}", spec.prefix, spec.base_path),
            ));
        }
        if !spec.placeholder_env.is_empty() {
            env.push((spec.placeholder_env.to_owned(), PLACEHOLDER.to_owned()));
        }
        Self {
            service: spec.service.to_owned(),
            route,
            env,
            permissions: vec!["proxy-injected".to_owned()],
            subject: format!("{}:{}", spec.upstream.0, spec.upstream.1),
            lease: None,
        }
    }

    /// Transform the route (scope it, for instance).
    #[must_use]
    pub fn map_route(mut self, f: impl FnOnce(GatewayRoute) -> GatewayRoute) -> Self {
        self.route = f(self.route);
        self
    }

    /// Record these permissions in the grant instead of the default.
    #[must_use]
    pub fn with_permissions(mut self, permissions: Vec<String>) -> Self {
        self.permissions = permissions;
        self
    }

    /// The grant as recorded in the log. Its validity is the launch: the route is
    /// torn down with the session proxy when the command exits.
    ///
    /// Carries no launch identity of its own: `ward-daemon::daemon::Served::handle_appendable`
    /// appends a second `WardEvent::CredentialGrantedLaunch` record right after this one,
    /// stamped from its own `open_launches`, when it can attribute this grant to a launch
    /// it is tracking (PR #318 review round 3) -- this client has no way to know that
    /// value in advance, the same way it does not own `EventRecord::ts_wall`.
    pub fn granted(&self, expires: core::time::Duration) -> Result<WardEvent> {
        Ok(WardEvent::CredentialGranted {
            service: ServiceId::new(&self.service).map_err(|e| Error::Events(e.to_string()))?,
            scope: Scope {
                subject: ShortText::new(&self.subject),
                permissions: self.permissions.iter().map(|p| NameText::new(p)).collect(),
            },
            expires,
            delivery: CredentialDelivery::ProxyInjected,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn spec() -> GatewaySpec {
        crate::agents::profile("claude")
            .and_then(|p| p.gateway)
            .expect("claude has a gateway")
    }

    #[test]
    fn sandbox_sees_relay_url_and_placeholder_only() {
        let g = Gateway::from_key(&spec(), "sk-ant-real").unwrap();
        assert_eq!(g.service, "anthropic");
        assert!(g.env.contains(&(
            "ANTHROPIC_BASE_URL".into(),
            format!("http://{RELAY_ADDR}/anthropic")
        )));
        assert!(
            g.env
                .contains(&("ANTHROPIC_API_KEY".into(), PLACEHOLDER.into()))
        );
        assert!(!format!("{:?}", g.route).contains("sk-ant-real"));
        assert_eq!(g.route.prefix(), "/anthropic");
    }

    #[test]
    fn openai_gateway_uses_bearer_and_v1_base_path() {
        let spec = crate::agents::profile("codex")
            .and_then(|p| p.gateway)
            .expect("codex has a gateway");
        let g = Gateway::from_key(&spec, "sk-openai").unwrap();
        assert_eq!(g.service, "openai");
        assert!(g.env.contains(&(
            "OPENAI_BASE_URL".into(),
            format!("http://{RELAY_ADDR}/openai/v1")
        )));
        assert!(
            g.env
                .contains(&("OPENAI_API_KEY".into(), PLACEHOLDER.into()))
        );
        assert_eq!(spec.value_prefix, "Bearer ");
    }

    #[test]
    fn base64_matches_the_standard_alphabet_and_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"x-access-token:tok"), "eC1hY2Nlc3MtdG9rZW46dG9r");
    }

    #[test]
    fn key_comes_from_the_vault_when_the_host_env_is_unset() {
        let spec = GatewaySpec {
            key_env: "WARD_TEST_NO_SUCH_KEY",
            ..spec()
        };
        let state = tempfile::tempdir().unwrap();
        assert!(Gateway::resolve(&spec, state.path()).unwrap().is_none());
        // The file `ward vault set WARD_TEST_NO_SUCH_KEY` would write.
        let file = vault_file(state.path(), spec.key_env);
        assert_eq!(
            file,
            state.path().join("vault").join("WARD_TEST_NO_SUCH_KEY")
        );
        std::fs::create_dir_all(vault_dir(state.path())).unwrap();
        std::fs::write(&file, "  \n").unwrap();
        assert!(Gateway::resolve(&spec, state.path()).unwrap().is_none());
        std::fs::write(&file, "sk-vault\n").unwrap();
        let g = Gateway::resolve(&spec, state.path()).unwrap().expect("key");
        assert_eq!(g.service, "anthropic");
    }

    #[test]
    fn grant_event_names_the_service_and_proxy_delivery() {
        let g = Gateway::from_key(&spec(), "k").unwrap();
        match g.granted(core::time::Duration::from_secs(1)).unwrap() {
            WardEvent::CredentialGranted {
                service,
                scope,
                delivery,
                ..
            } => {
                assert_eq!(service.as_str(), "anthropic");
                assert_eq!(scope.subject.as_str(), "api.anthropic.com:443");
                assert_eq!(delivery, CredentialDelivery::ProxyInjected);
            }
            other => panic!("{other:?}"),
        }
    }
}
