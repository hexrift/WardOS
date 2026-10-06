//! The host vault as a [`CredentialProvider`] (#267): the first implementation
//! behind the interface, and exactly what the gateways always read — the host
//! variable named by the route (`ANTHROPIC_API_KEY`) when it holds a non-empty
//! value, else `$WARD_STATE_DIR/vault/<NAME>` (`ward vault set`), trimmed.
//!
//! The value is static: its lease is client-side only (the proxy route stops
//! injecting it at the lease's end), renewal moves that client-side expiry
//! within the lease's maximum, and there is nothing to revoke at the source —
//! [`Revocation::NotRevocable`] says so rather than claiming otherwise.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::{
    CredentialProvider, Health, Lease, LeaseRequest, LeasedSecret, ProviderError, Revocation,
};
use crate::gateway;

/// The provider name the local vault reports.
pub const NAME: &str = "local-vault";

/// One key of the host vault.
#[derive(Clone, Debug)]
pub struct LocalVault {
    state: PathBuf,
    key_env: String,
}

impl LocalVault {
    /// The key `key_env` under the state root `state`.
    #[must_use]
    pub fn new(state: &Path, key_env: &str) -> Self {
        Self {
            state: state.to_path_buf(),
            key_env: key_env.to_owned(),
        }
    }

    /// The key's current value: the host variable, else the vault file,
    /// trimmed; `None` when neither holds a non-empty value.
    fn current(&self) -> Option<LeasedSecret> {
        std::env::var(&self.key_env)
            .ok()
            .or_else(|| {
                std::fs::read_to_string(gateway::vault_file(&self.state, &self.key_env)).ok()
            })
            .map(|k| k.trim().to_owned())
            .filter(|k| !k.is_empty())
            .map(LeasedSecret::new)
    }
}

impl CredentialProvider for LocalVault {
    fn name(&self) -> &str {
        NAME
    }

    fn issue(&self, request: &LeaseRequest) -> Result<Lease, ProviderError> {
        let secret = self
            .current()
            .ok_or_else(|| ProviderError::NotFound(self.key_env.clone()))?;
        Ok(Lease::new(
            NAME,
            request,
            secret,
            None,
            SystemTime::now(),
            request.ttl,
        ))
    }

    fn renew(&self, lease: &Lease, increment: Duration) -> Result<Lease, ProviderError> {
        Ok(lease.clone().renewed_until(SystemTime::now() + increment))
    }

    fn revoke(&self, _lease: &Lease) -> Result<Revocation, ProviderError> {
        Ok(Revocation::NotRevocable)
    }

    fn health(&self) -> Health {
        Health::Healthy
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::credentials::{LeaseScope, issue_bound, renew_within_bounds};

    fn request() -> LeaseRequest {
        LeaseRequest {
            session: String::new(),
            service: "anthropic".into(),
            scope: LeaseScope::default(),
            ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(120),
            audience: "api.anthropic.com".into(),
        }
    }

    #[test]
    fn the_local_vault_issues_the_file_value_as_a_static_lease() {
        let state = tempfile::tempdir().unwrap();
        let vault = LocalVault::new(state.path(), "WARD_TEST_LOCAL_VAULT_KEY");
        assert_eq!(
            issue_bound(&vault, &request()).unwrap_err(),
            ProviderError::NotFound("WARD_TEST_LOCAL_VAULT_KEY".into())
        );
        std::fs::create_dir_all(gateway::vault_dir(state.path())).unwrap();
        std::fs::write(
            gateway::vault_file(state.path(), "WARD_TEST_LOCAL_VAULT_KEY"),
            "  \n",
        )
        .unwrap();
        assert!(issue_bound(&vault, &request()).is_err(), "blank is absent");
        std::fs::write(
            gateway::vault_file(state.path(), "WARD_TEST_LOCAL_VAULT_KEY"),
            " sk-local \n",
        )
        .unwrap();
        let lease = issue_bound(&vault, &request()).unwrap();
        assert_eq!(lease.secret().expose(), b"sk-local");
        assert_eq!(lease.provider, NAME);
        assert!(!lease.revocable);
        assert_eq!(lease.ttl(), Duration::from_secs(60));
        assert_eq!(vault.revoke(&lease), Ok(Revocation::NotRevocable));
        assert_eq!(vault.health(), Health::Healthy);
        assert_eq!(vault.name(), NAME);
        // Renewal is client-side and stops at the max.
        let renewed = renew_within_bounds(&vault, &lease, SystemTime::now()).unwrap();
        assert!(renewed.expires_at <= lease.max_expires_at);
        assert!(renewed.expires_at >= lease.expires_at);
    }
}
