//! Credentials as node capabilities (#267, ADR-0034; #332 stage 3): the manifest's
//! optional `credentials` grant, additive within protocol 1.3.
//!
//! A grant names a service the node's operator configured, the host the credential is
//! for, and how long its lease may live:
//!
//! ```json
//! {"network":{"custom":["artifacts.example.com"]},
//!  "credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":600}]}
//! ```
//!
//! It never names a provider, a secret or a header: those are the operator's, in the
//! node's own configuration. The grammar holds 1 to [`MAX_CREDENTIAL_GRANTS`] grants, no
//! service twice, each service `[a-z][a-z0-9-]{0,31}`, each host a lowercase DNS name (no
//! wildcard) that one of the manifest's `network.custom` patterns covers, and each
//! `ttl_secs` at least 1. A manifest outside it fails decoding, so a credential can never
//! be granted for a host the attempt may not reach. Whether the node honours a grant (the
//! service is configured, the host is its upstream, the TTL within its ceiling) is the
//! node's decision at `admit`, refused `unsupported_grant` otherwise; a node offers the
//! capability by reporting `credentials.proxy_injection` and `scoped_http_gateway`.

use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::admission::HostAllowlist;

/// Most grants one manifest may carry.
pub const MAX_CREDENTIAL_GRANTS: usize = 4;

/// Most bytes of a service name.
pub const MAX_CREDENTIAL_SERVICE_BYTES: usize = 32;

/// Why a `credentials` grant is outside its grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialError {
    /// No grant, more than [`MAX_CREDENTIAL_GRANTS`], a service named twice, or a zero
    /// TTL.
    InvalidGrant,
    /// A service name outside `[a-z][a-z0-9-]{0,31}`.
    InvalidService,
    /// A host that is not a lowercase DNS name.
    InvalidHost,
    /// A host no `network.custom` pattern of the manifest covers, or a manifest that
    /// grants no network at all.
    HostNotAllowlisted,
}

impl Display for CredentialError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGrant => "credentials grant is invalid",
            Self::InvalidService => "credential service name is invalid",
            Self::InvalidHost => "credential host is not a lowercase DNS name",
            Self::HostNotAllowlisted => "credential host is not in the network allowlist",
        })
    }
}

impl std::error::Error for CredentialError {}

/// One credential the workload's traffic may carry: the configured `service`, injected
/// by the node's proxy into requests for `host` only, under a lease of at most
/// `ttl_secs`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CredentialGrant {
    service: String,
    host: String,
    ttl_secs: u32,
}

impl CredentialGrant {
    /// A grant of `service` for `host`, leased for at most `ttl_secs`.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::InvalidService`], [`CredentialError::InvalidHost`] or
    /// [`CredentialError::InvalidGrant`] for a zero TTL.
    pub fn new(service: String, host: String, ttl_secs: u32) -> Result<Self, CredentialError> {
        if !is_service(&service) {
            return Err(CredentialError::InvalidService);
        }
        if !is_host_name(&host) {
            return Err(CredentialError::InvalidHost);
        }
        if ttl_secs == 0 {
            return Err(CredentialError::InvalidGrant);
        }
        Ok(Self {
            service,
            host,
            ttl_secs,
        })
    }

    /// The configured service the credential comes from.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The only host the credential is injected into.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The longest the lease may live, in seconds.
    #[must_use]
    pub const fn ttl_secs(&self) -> u32 {
        self.ttl_secs
    }
}

/// The manifest's `credentials`: 1 to [`MAX_CREDENTIAL_GRANTS`] grants, no service twice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CredentialGrants(Vec<CredentialGrant>);

impl CredentialGrants {
    /// Validate a list of grants.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::InvalidGrant`] for an empty or oversized list or a
    /// repeated service.
    pub fn new(grants: Vec<CredentialGrant>) -> Result<Self, CredentialError> {
        let repeated = grants.iter().enumerate().any(|(index, grant)| {
            grants[..index]
                .iter()
                .any(|earlier| earlier.service == grant.service)
        });
        if grants.is_empty() || grants.len() > MAX_CREDENTIAL_GRANTS || repeated {
            return Err(CredentialError::InvalidGrant);
        }
        Ok(Self(grants))
    }

    /// The grants, in the order given.
    #[must_use]
    pub fn grants(&self) -> &[CredentialGrant] {
        &self.0
    }

    /// Hold every grant's host to `allowlist`, the manifest's `network.custom`.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::HostNotAllowlisted`] for a host no pattern covers.
    pub fn within(&self, allowlist: Option<&HostAllowlist>) -> Result<(), CredentialError> {
        match allowlist {
            Some(allowlist) if self.0.iter().all(|grant| allowlist.covers(&grant.host)) => Ok(()),
            _ => Err(CredentialError::HostNotAllowlisted),
        }
    }
}

/// `[a-z][a-z0-9-]{0,31}`: the service also names the attempt's proxy route.
fn is_service(service: &str) -> bool {
    let bytes = service.as_bytes();
    (1..=MAX_CREDENTIAL_SERVICE_BYTES).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// A lowercase DNS name in the allowlist's host grammar, without a wildcard, and not an
/// address literal.
fn is_host_name(host: &str) -> bool {
    !host.starts_with("*.")
        && host.parse::<std::net::IpAddr>().is_err()
        && HostAllowlist::new(vec![host.to_owned()]).is_ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CredentialGrantWire {
    service: String,
    host: String,
    ttl_secs: u32,
}

pub(crate) fn grants_from_wire(
    wire: Vec<CredentialGrantWire>,
) -> Result<CredentialGrants, CredentialError> {
    CredentialGrants::new(
        wire.into_iter()
            .map(|grant| CredentialGrant::new(grant.service, grant.host, grant.ttl_secs))
            .collect::<Result<_, _>>()?,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::{CapabilityManifest, CapabilityManifestBytes, NetworkGrant, TaskAdmissionError};

    fn grant(service: &str, host: &str, ttl_secs: u32) -> Result<CredentialGrant, CredentialError> {
        CredentialGrant::new(service.to_owned(), host.to_owned(), ttl_secs)
    }

    fn allowlist(patterns: &[&str]) -> HostAllowlist {
        HostAllowlist::new(patterns.iter().map(|p| (*p).to_owned()).collect()).unwrap()
    }

    fn decode(raw: &str) -> Result<CapabilityManifestBytes, TaskAdmissionError> {
        CapabilityManifestBytes::new(raw.as_bytes().to_vec())
    }

    #[test]
    fn a_credentials_grant_decodes_round_trips_and_names_no_secret() {
        let raw = r#"{"network":{"custom":["artifacts.example.com"]},"credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":600}]}"#;
        let decoded = decode(raw).unwrap();
        let grants = decoded.manifest().credentials().unwrap();
        assert_eq!(grants.grants().len(), 1);
        let only = &grants.grants()[0];
        assert_eq!(only.service(), "artifacts");
        assert_eq!(only.host(), "artifacts.example.com");
        assert_eq!(only.ttl_secs(), 600);

        let built =
            CapabilityManifest::new(NetworkGrant::Custom(allowlist(&["artifacts.example.com"])))
                .with_credentials(
                    CredentialGrants::new(vec![
                        grant("artifacts", "artifacts.example.com", 600).unwrap(),
                    ])
                    .unwrap(),
                )
                .unwrap();
        let encoded = CapabilityManifestBytes::encode(&built).unwrap();
        assert_eq!(encoded.bytes(), raw.as_bytes());
        assert_eq!(encoded.manifest(), decoded.manifest());
        assert!(
            decode(r#"{"network":"offline"}"#)
                .unwrap()
                .manifest()
                .credentials()
                .is_none()
        );
    }

    #[test]
    fn a_wildcard_pattern_covers_a_deeper_host_and_never_its_own_name() {
        let patterns = allowlist(&["*.example.com", "api.other.org"]);
        assert!(patterns.covers("a.example.com"));
        assert!(patterns.covers("b.a.example.com"));
        assert!(!patterns.covers("example.com"));
        assert!(!patterns.covers("xexample.com"));
        assert!(patterns.covers("api.other.org"));
        assert!(!patterns.covers("x.api.other.org"));
        assert!(!patterns.covers("other.org"));
        let grants = CredentialGrants::new(vec![grant("a", "a.example.com", 1).unwrap()]).unwrap();
        assert_eq!(grants.within(Some(&patterns)), Ok(()));
        assert_eq!(
            grants.within(Some(&allowlist(&["example.com"]))),
            Err(CredentialError::HostNotAllowlisted)
        );
        assert_eq!(
            grants.within(None),
            Err(CredentialError::HostNotAllowlisted)
        );
    }

    #[test]
    fn grants_outside_the_grammar_are_refused() {
        assert_eq!(
            grant("a", "h.example", 0),
            Err(CredentialError::InvalidGrant)
        );
        for service in ["", "A", "1a", "-a", "a_b", "a.b", &"a".repeat(33)] {
            assert_eq!(
                grant(service, "h.example", 1),
                Err(CredentialError::InvalidService),
                "{service:?}"
            );
        }
        assert!(grant(&"a".repeat(32), "h.example", 1).is_ok());
        assert!(grant("ci-artifacts2", "h.example", 1).is_ok());
        for host in [
            "",
            "*.h.example",
            "H.example",
            "h example",
            "-h.example",
            "10.0.0.1",
            "10.0.0.1:443",
        ] {
            assert_eq!(
                grant("a", host, 1),
                Err(CredentialError::InvalidHost),
                "{host:?}"
            );
        }
        assert_eq!(
            CredentialGrants::new(Vec::new()),
            Err(CredentialError::InvalidGrant)
        );
        let five = (0..5)
            .map(|n| grant(&format!("s{n}"), "h.example", 1).unwrap())
            .collect();
        assert_eq!(
            CredentialGrants::new(five),
            Err(CredentialError::InvalidGrant)
        );
        let four = (0..4)
            .map(|n| grant(&format!("s{n}"), "h.example", 1).unwrap())
            .collect();
        assert!(CredentialGrants::new(four).is_ok());
        assert_eq!(
            CredentialGrants::new(vec![
                grant("a", "h.example", 1).unwrap(),
                grant("a", "g.example", 1).unwrap(),
            ]),
            Err(CredentialError::InvalidGrant)
        );
    }

    #[test]
    fn a_manifest_outside_the_credentials_grammar_fails_decoding() {
        let refused = [
            r#"{"network":"offline","credentials":[{"service":"a","host":"h.example","ttl_secs":1}]}"#,
            r#"{"network":{"custom":["g.example"]},"credentials":[{"service":"a","host":"h.example","ttl_secs":1}]}"#,
            r#"{"network":{"custom":["h.example"]},"credentials":[]}"#,
            r#"{"network":{"custom":["h.example"]},"credentials":null}"#,
            r#"{"network":{"custom":["h.example"]},"credentials":[{"service":"a","host":"h.example","ttl_secs":0}]}"#,
            r#"{"network":{"custom":["h.example"]},"credentials":[{"service":"a","host":"h.example"}]}"#,
            r#"{"network":{"custom":["h.example"]},"credentials":[{"service":"a","host":"h.example","ttl_secs":1,"header":"authorization"}]}"#,
            r#"{"network":{"custom":["h.example"]},"credentials":[{"service":"a","host":"h.example","ttl_secs":1,"secret":"x"}]}"#,
            r#"{"network":{"custom":["*.example"]},"credentials":[{"service":"a","host":"*.example","ttl_secs":1}]}"#,
            r#"{"network":{"custom":["h.example"]},"credentials":[{"service":"a","host":"h.example","ttl_secs":-1}]}"#,
            r#"{"network":{"custom":["h.example"]},"credentials":{"service":"a","host":"h.example","ttl_secs":1}}"#,
        ];
        for raw in refused {
            assert!(
                matches!(
                    decode(raw),
                    Err(TaskAdmissionError::MalformedManifest
                        | TaskAdmissionError::MalformedCredentialGrant(_))
                ),
                "{raw}"
            );
        }
        assert_eq!(
            decode(refused[1]),
            Err(TaskAdmissionError::MalformedCredentialGrant(
                CredentialError::HostNotAllowlisted
            ))
        );
        assert_eq!(
            CapabilityManifest::new(NetworkGrant::Offline).with_credentials(
                CredentialGrants::new(vec![grant("a", "h.example", 1).unwrap()]).unwrap()
            ),
            Err(CredentialError::HostNotAllowlisted)
        );
        assert!(
            decode(r#"{"network":{"custom":["*.example"]},"credentials":[{"service":"a","host":"h.example","ttl_secs":4294967295}]}"#)
                .is_ok()
        );
    }
}
