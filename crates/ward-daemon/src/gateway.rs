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
    /// Client headers removed before injection, so the placeholder never leaves.
    pub strip: &'static [&'static str],
    /// Host variable (and vault file name) holding the real key.
    pub key_env: &'static str,
    /// Variable the agent reads its base URL from.
    pub base_url_env: &'static str,
    /// Variable the agent reads its (placeholder) key from.
    pub placeholder_env: &'static str,
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
        let route = GatewayRoute::new(spec.prefix, host, port, spec.header, Secret::from(key))
            .map_err(|e| Error::Sandbox(format!("gateway {}: {e}", spec.service)))?
            .strip_headers(spec.strip);
        Ok(Self::new(spec, route))
    }

    /// Pair `spec` with an already built route.
    #[must_use]
    pub fn new(spec: &GatewaySpec, route: GatewayRoute) -> Self {
        Self {
            service: spec.service.to_owned(),
            route,
            env: vec![
                (
                    spec.base_url_env.to_owned(),
                    format!("http://{RELAY_ADDR}{}", spec.prefix),
                ),
                (spec.placeholder_env.to_owned(), PLACEHOLDER.to_owned()),
            ],
            subject: format!("{}:{}", spec.upstream.0, spec.upstream.1),
        }
    }

    /// The grant as recorded in the log. Its validity is the launch: the route is
    /// torn down with the session proxy when the command exits.
    pub fn granted(&self, expires: core::time::Duration) -> Result<WardEvent> {
        Ok(WardEvent::CredentialGranted {
            service: ServiceId::new(&self.service).map_err(|e| Error::Events(e.to_string()))?,
            scope: Scope {
                subject: ShortText::new(&self.subject),
                permissions: vec![NameText::new("proxy-injected")],
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
