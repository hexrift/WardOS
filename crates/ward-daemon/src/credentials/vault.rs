//! A Vault/OpenBao-compatible [`CredentialProvider`] over the HTTP API (#267).
//! Two engines, both usable without a cloud account:
//!
//! * [`Engine::Kv`] — a KV v2 static secret (`GET /v1/<mount>/data/<path>`,
//!   one field). The provider cannot revoke it; the lease is client-side and
//!   the proxy route stops injecting it at the lease's end.
//! * [`Engine::Token`] — a short-lived token minted for a token role
//!   (`POST /v1/auth/token/create/<role>` with `ttl`, `explicit_max_ttl`,
//!   `policies`, `no_default_policy` and `meta` naming the session, service
//!   and audience), renewed with `auth/token/renew` and revoked with
//!   `auth/token/revoke-accessor`. The provider enforces the TTL and the
//!   maximum itself; the broker's rules hold its answers to them as well.
//!
//! The broker authenticates with its own token (`X-Vault-Token`, read from a
//! 0600 file by [`super::config`]). Every call is bounded by the endpoint's
//! timeout ([`super::http`]). Error details name the step and the status,
//! never a body or a token.

use std::time::{Duration, SystemTime};

use serde_json::{Value, json};

use super::http::{Endpoint, Response};
use super::{
    CredentialProvider, DegradedState, Health, Lease, LeaseRequest, LeaseScope, LeasedSecret,
    ProviderError, Revocation,
};

/// The permission name that opens non-read methods on the proxy route; it is
/// never sent to the provider as a policy.
pub const WRITE: &str = "write";

/// Which secrets engine a service reads from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Engine {
    /// A KV v2 static secret.
    Kv {
        /// The engine's mount (`secret`).
        mount: String,
        /// The secret's path under it (`ci/artifacts`).
        path: String,
        /// The field holding the value (`token`).
        field: String,
    },
    /// A token minted for a token role.
    Token {
        /// The role (`ward-artifacts`).
        role: String,
    },
}

/// One Vault/OpenBao endpoint and engine.
#[derive(Debug)]
pub struct VaultProvider {
    name: String,
    endpoint: Endpoint,
    token: LeasedSecret,
    engine: Engine,
}

impl VaultProvider {
    /// A provider named `name` at `endpoint`, authenticating with `token`,
    /// issuing from `engine`.
    #[must_use]
    pub fn new(name: &str, endpoint: Endpoint, token: LeasedSecret, engine: Engine) -> Self {
        Self {
            name: name.to_owned(),
            endpoint,
            token,
            engine,
        }
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Response, ProviderError> {
        let body = body.map(|b| zeroize::Zeroizing::new(b.to_string().into_bytes()));
        self.endpoint.call(
            method,
            path,
            Some(&self.token),
            body.as_ref().map(|b| b.as_slice()),
        )
    }

    fn issue_kv(
        &self,
        request: &LeaseRequest,
        mount: &str,
        path: &str,
        field: &str,
    ) -> Result<Lease, ProviderError> {
        let response = self.call("GET", &format!("/v1/{mount}/data/{path}"), None)?;
        if response.status == 404 {
            return Err(ProviderError::NotFound(format!("{mount}/{path}")));
        }
        let mut body = expect(&response, 200, "kv read")?;
        let secret = take_string(&mut body["data"]["data"][field])
            .ok_or_else(|| ProviderError::NotFound(format!("{mount}/{path}#{field}")))?;
        Ok(Lease::new(
            &self.name,
            request,
            secret,
            None,
            SystemTime::now(),
            request.ttl,
        ))
    }

    fn issue_token(&self, request: &LeaseRequest, role: &str) -> Result<Lease, ProviderError> {
        let policies: Vec<&String> = request
            .scope
            .permissions
            .iter()
            .filter(|p| *p != WRITE)
            .collect();
        let body = json!({
            "ttl": secs(request.ttl),
            "explicit_max_ttl": secs(request.max_ttl),
            "renewable": true,
            "no_default_policy": true,
            "policies": policies,
            "display_name": format!("ward-{}", request.service),
            "meta": {
                "ward_session": request.session,
                "ward_service": request.service,
                "ward_audience": request.audience,
            },
        });
        let issued_at = SystemTime::now();
        let response = self.call(
            "POST",
            &format!("/v1/auth/token/create/{role}"),
            Some(&body),
        )?;
        let mut body = expect(&response, 200, "token create")?;
        let auth = &mut body["auth"];
        let secret = take_string(&mut auth["client_token"]).ok_or_else(bad_response)?;
        let accessor = take_string(&mut auth["accessor"]).ok_or_else(bad_response)?;
        let ttl = auth["lease_duration"].as_u64().ok_or_else(bad_response)?;
        let scope = granted_scope(&request.scope, auth)?;
        Ok(Lease::new(
            &self.name,
            request,
            secret,
            Some(accessor),
            issued_at,
            Duration::from_secs(ttl),
        )
        .with_scope(scope))
    }
}

/// `600s`.
fn secs(d: Duration) -> String {
    format!("{}s", d.as_secs().max(1))
}

fn bad_response() -> ProviderError {
    ProviderError::degraded(DegradedState::BadResponse, "unexpected answer shape")
}

/// Move a JSON string out into a [`LeasedSecret`] without copying it.
fn take_string(value: &mut Value) -> Option<LeasedSecret> {
    match value.take() {
        Value::String(s) if !s.is_empty() => Some(LeasedSecret::new(s.into_bytes())),
        _ => None,
    }
}

/// The JSON body of a `want` answer; any other status is the degraded state
/// or refusal it means.
fn expect(response: &Response, want: u16, step: &str) -> Result<Value, ProviderError> {
    match response.status {
        s if s == want => serde_json::from_slice(&response.body).map_err(|_| {
            ProviderError::degraded(DegradedState::BadResponse, format!("{step}: not json"))
        }),
        401 | 403 => Err(ProviderError::degraded(
            DegradedState::AuthRejected,
            format!("{step}: {} permission denied", response.status),
        )),
        503 => Err(ProviderError::degraded(
            DegradedState::Sealed,
            format!("{step}: 503 sealed or unavailable"),
        )),
        400 | 404 | 405 => Err(ProviderError::Refused(format!(
            "{step}: {}",
            response.status
        ))),
        other => Err(ProviderError::degraded(
            DegradedState::BadResponse,
            format!("{step}: status {other}"),
        )),
    }
}

/// The scope a token answer actually carries: the requested resources and
/// write flag, and the policies the provider reports (`token_policies`, else
/// `policies`), plus `write` when it was asked for — so [`super::bind_issued`]
/// sees a provider that attached more policies as the widening it is.
fn granted_scope(requested: &LeaseScope, auth: &Value) -> Result<LeaseScope, ProviderError> {
    let list = auth
        .get("token_policies")
        .filter(|v| v.is_array())
        .or_else(|| auth.get("policies"))
        .and_then(Value::as_array)
        .ok_or_else(bad_response)?;
    let mut permissions = list
        .iter()
        .map(|p| p.as_str().map(str::to_owned).ok_or_else(bad_response))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if requested.permissions.contains(WRITE) {
        permissions.insert(WRITE.to_owned());
    }
    Ok(LeaseScope {
        resources: requested.resources.clone(),
        permissions,
        write: requested.write,
    })
}

/// Vault's answer to revoking an accessor whose token no longer exists.
fn invalid_accessor(response: &Response) -> bool {
    response.status == 400
        && serde_json::from_slice::<Value>(&response.body).is_ok_and(|v| {
            v["errors"]
                .as_array()
                .is_some_and(|e| e.iter().any(|m| m.as_str() == Some("invalid accessor")))
        })
}

impl CredentialProvider for VaultProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn issue(&self, request: &LeaseRequest) -> Result<Lease, ProviderError> {
        match &self.engine {
            Engine::Kv { mount, path, field } => self.issue_kv(request, mount, path, field),
            Engine::Token { role } => self.issue_token(request, role),
        }
    }

    fn renew(&self, lease: &Lease, increment: Duration) -> Result<Lease, ProviderError> {
        match &self.engine {
            // A static read has nothing to renew at the source: the lease is
            // client-side, and the rules bound its extension.
            Engine::Kv { .. } => Ok(lease.clone().renewed_until(SystemTime::now() + increment)),
            Engine::Token { .. } => {
                let token =
                    std::str::from_utf8(lease.secret().expose()).map_err(|_| bad_response())?;
                let body = json!({ "token": token, "increment": secs(increment) });
                let now = SystemTime::now();
                let response = self.call("POST", "/v1/auth/token/renew", Some(&body))?;
                let body = expect(&response, 200, "token renew")?;
                let ttl = body["auth"]["lease_duration"]
                    .as_u64()
                    .ok_or_else(bad_response)?;
                let scope = granted_scope(&lease.scope, &body["auth"])?;
                Ok(lease
                    .clone()
                    .renewed_until(now + Duration::from_secs(ttl))
                    .with_scope(scope))
            }
        }
    }

    fn revoke(&self, lease: &Lease) -> Result<Revocation, ProviderError> {
        let Some(accessor) = lease.handle() else {
            return Ok(Revocation::NotRevocable);
        };
        let accessor = std::str::from_utf8(accessor.expose()).map_err(|_| bad_response())?;
        let body = json!({ "accessor": accessor });
        let response = self.call("POST", "/v1/auth/token/revoke-accessor", Some(&body))?;
        // 204 is a confirmed revocation; "invalid accessor" means the token
        // no longer exists at the source (it ran out, or was revoked before),
        // which is the same end state.
        if matches!(response.status, 200 | 204) || invalid_accessor(&response) {
            return Ok(Revocation::Confirmed);
        }
        expect(&response, 204, "token revoke").map(|_| Revocation::Confirmed)
    }

    fn health(&self) -> Health {
        let check = || -> Result<(), ProviderError> {
            let response = self.endpoint.call("GET", "/v1/sys/health", None, None)?;
            match response.status {
                200 | 429 | 472 | 473 => {}
                501 | 503 => {
                    return Err(ProviderError::degraded(DegradedState::Sealed, "sys/health"));
                }
                _ => return Err(bad_response()),
            }
            let response = self.call("GET", "/v1/auth/token/lookup-self", None)?;
            expect(&response, 200, "lookup-self").map(drop)
        };
        match check() {
            Ok(()) => Health::Healthy,
            Err(ProviderError::Degraded { state, .. }) => Health::Degraded(state),
            Err(_) => Health::Degraded(DegradedState::AuthRejected),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn response(status: u16, body: &str) -> Response {
        Response {
            status,
            body: zeroize::Zeroizing::new(body.as_bytes().to_vec()),
        }
    }

    #[test]
    fn statuses_map_to_named_states_and_never_carry_the_body() {
        let secret_body = r#"{"errors":["hvs.not-to-be-repeated"]}"#;
        for (status, name) in [
            (401, "auth-rejected"),
            (403, "auth-rejected"),
            (503, "sealed"),
            (500, "bad-response"),
            (400, "refused"),
        ] {
            let err = expect(&response(status, secret_body), 200, "step").unwrap_err();
            assert_eq!(err.state_name(), name, "{status}");
            assert!(!err.to_string().contains("hvs.not"), "{err}");
        }
        assert_eq!(
            expect(&response(200, "not json"), 200, "step")
                .unwrap_err()
                .state_name(),
            "bad-response"
        );
    }

    #[test]
    fn a_token_answer_reports_the_policies_it_really_carries() {
        let requested = LeaseScope {
            resources: vec!["/r".into()],
            permissions: ["read".to_owned(), WRITE.to_owned()].into(),
            write: true,
        };
        let auth = json!({"token_policies": ["read", "admin"]});
        let scope = granted_scope(&requested, &auth).unwrap();
        assert!(scope.permissions.contains("admin"));
        assert!(scope.permissions.contains(WRITE));
        assert!(!requested.covers(&scope), "the widening is visible");
        let auth = json!({"policies": ["read"]});
        assert!(requested.covers(&granted_scope(&requested, &auth).unwrap()));
        assert!(granted_scope(&requested, &json!({})).is_err());
        assert!(granted_scope(&requested, &json!({"policies": [1]})).is_err());
    }

    #[test]
    fn an_invalid_accessor_is_recognised_as_already_gone() {
        assert!(invalid_accessor(&response(
            400,
            r#"{"errors":["invalid accessor"]}"#
        )));
        assert!(!invalid_accessor(&response(400, r#"{"errors":["other"]}"#)));
        assert!(!invalid_accessor(&response(
            403,
            r#"{"errors":["invalid accessor"]}"#
        )));
        assert_eq!(secs(Duration::from_millis(10)), "1s");
        assert_eq!(secs(Duration::from_secs(600)), "600s");
    }
}
