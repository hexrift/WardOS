//! Gateway credentials (ADR-0008, `docs/credential-broker.md` §4): the host
//! keeps the model-API key and `ward-proxy` injects it on the way out. The
//! sandbox sees a base URL on the relay and a placeholder token, never the key.

use std::path::Path;

use ward_events::{CredentialDelivery, NameText, Scope, ServiceId, ShortText, WardEvent};
use ward_proxy::{GatewayRoute, Secret};

use crate::error::{Error, Result};
use crate::sandbox::RELAY_ADDR;

/// Placeholder the agent presents; the proxy strips it before injection.
pub const PLACEHOLDER: &str = "ward-gateway";

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
}

impl Gateway {
    /// Resolve `spec` with a key from the host environment (`key_env`), else from
    /// `vault/<key_env>` under `state`. `None` when neither holds a key.
    pub fn resolve(spec: &GatewaySpec, state: &Path) -> Result<Option<Self>> {
        let vault = state.join("vault").join(spec.key_env);
        let key = std::env::var(spec.key_env)
            .ok()
            .or_else(|| std::fs::read_to_string(vault).ok())
            .map(|k| k.trim().to_owned())
            .filter(|k| !k.is_empty());
        key.map(|key| Self::from_key(spec, &key)).transpose()
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
        let vault = state.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        std::fs::write(vault.join(spec.key_env), "  \n").unwrap();
        assert!(Gateway::resolve(&spec, state.path()).unwrap().is_none());
        std::fs::write(vault.join(spec.key_env), "sk-vault\n").unwrap();
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
