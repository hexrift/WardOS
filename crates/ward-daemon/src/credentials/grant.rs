//! Deciding a launch's provider-backed grants (#267): for each service the
//! host configured, the session's manifest rule (the host's rule, narrowed by
//! the project), the user's explicit `--grant`, then a lease issued through
//! the binding rules and turned into a proxy route. Every failure is fail
//! closed and recorded: no gateway, a `CredentialDenied` naming the reason —
//! `credentials.<service>` for policy, `credential-provider:<provider>:<state>`
//! for a provider that is degraded or answered outside the rules — and a note
//! for the user. Nothing falls back to another credential.

use std::path::Path;
use std::sync::Arc;

use ward_events::{DenyReason, NameText, RuleRef, Scope, ServiceId, ShortText, WardEvent};
use ward_policy::{CapabilityManifest, CredentialRule, NetworkCapability};

use super::config::Registry;
use super::issue_bound;
use super::keeper::HeldLease;
use crate::error::{Error, Result};
use crate::gateway::Gateway;

/// What [`provider_grants`] decided for one launch.
#[derive(Debug, Default)]
pub struct ProviderGrants {
    /// A gateway per lease issued.
    pub gateways: Vec<Gateway>,
    /// `CredentialDenied` records for every refusal.
    pub refusals: Vec<WardEvent>,
    /// Lines for the user, one per decision.
    pub notes: Vec<String>,
}

fn denied(service: &str, subject: &str, permissions: &[String], rule: &str) -> Result<WardEvent> {
    let events = |e: ward_events::IdError| Error::Events(e.to_string());
    Ok(WardEvent::CredentialDenied {
        service: ServiceId::new(service).map_err(events)?,
        scope: Scope {
            subject: ShortText::new(subject),
            permissions: permissions.iter().map(|p| NameText::new(p)).collect(),
        },
        reason: DenyReason::PolicyDeny {
            rule: RuleRef::new(rule).map_err(events)?,
        },
    })
}

/// Decide every provider-backed grant of a launch of `session` under
/// `manifest`, the host configuration under `state`, and the services the
/// user asked for with `--grant` (`requested`).
pub fn provider_grants(
    manifest: &CapabilityManifest,
    state: &Path,
    session: &str,
    requested: &[String],
) -> Result<ProviderGrants> {
    let mut out = ProviderGrants::default();
    let registry = match Registry::load(state) {
        Ok(registry) => registry,
        Err(e) => {
            out.notes.push(format!(
                "credential providers: {e}; no provider-backed credential is granted"
            ));
            return Ok(out);
        }
    };
    let offline = matches!(manifest.network, NetworkCapability::Offline);
    for (name, service) in registry.services() {
        let asked = requested.iter().any(|g| g == name);
        let subject = service.upstream.clone();
        let rule = manifest
            .credentials
            .get(&ward_policy::ServiceId(name.to_owned()));
        let scope = match rule {
            None | Some(CredentialRule::Deny) => {
                if asked {
                    out.refusals
                        .push(denied(name, &subject, &[], &format!("credentials.{name}"))?);
                    out.notes.push(format!("{name}: denied by policy"));
                }
                continue;
            }
            Some(CredentialRule::Ask(_)) if !asked => {
                out.notes.push(format!(
                    "{name}: policy says ask; pass --grant {name} for a {} lease",
                    service.provider
                ));
                continue;
            }
            Some(CredentialRule::Ask(scope) | CredentialRule::Allow(scope)) => scope,
        };
        if offline {
            if asked {
                out.notes.push(format!("{name}: session is offline"));
            }
            continue;
        }
        let permissions: Vec<String> = scope.permissions.iter().cloned().collect();
        let issued = registry
            .request_for(name, session, &scope.permissions)
            .and_then(|(provider, request)| {
                issue_bound(&*provider, &request).map(|lease| (provider, lease))
            });
        match issued {
            Ok((provider, lease)) => {
                let ttl = lease.ttl().as_secs();
                let held = HeldLease::new(Arc::clone(&provider), lease, service.renew);
                match Gateway::leased(name, service, Arc::clone(&held), permissions.clone()) {
                    Ok(gateway) => {
                        out.notes.push(format!(
                            "{name}: {} lease for {subject}, {ttl}s; the proxy injects it, the \
                             sandbox never holds it",
                            provider.name()
                        ));
                        out.gateways.push(gateway);
                    }
                    Err(e) => {
                        // Not left alive at the provider for a route never built.
                        let _ = held.withdraw();
                        out.refusals.push(denied(
                            name,
                            &subject,
                            &permissions,
                            &format!("credential-provider:{}:bad-response", service.provider),
                        )?);
                        out.notes
                            .push(format!("{name}: {e}; no credential granted"));
                    }
                }
            }
            Err(e) => {
                let rule = format!(
                    "credential-provider:{}:{}",
                    service.provider,
                    e.state_name()
                );
                out.refusals
                    .push(denied(name, &subject, &permissions, &rule)?);
                out.notes.push(format!(
                    "{name}: provider {} {}; no credential granted (fail closed)",
                    service.provider,
                    e.state_name()
                ));
            }
        }
    }
    Ok(out)
}
