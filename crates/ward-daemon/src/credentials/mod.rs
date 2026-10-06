//! The credential-provider interface (#267, ADR-0032): where a brokered
//! credential comes from, behind one trait, with the binding rules every
//! provider is held to enforced here rather than trusted to each backend.
//!
//! A [`CredentialProvider`] issues a [`Lease`] for a [`LeaseRequest`] — one
//! session (the task), one service, the resource scope the policy names, a TTL
//! and an audience — and can renew it, revoke it and report its own
//! [`Health`]. Two implementations exist:
//!
//! * [`local::LocalVault`], the host vault the model-API and GitHub gateways
//!   have always read (`$WARD_STATE_DIR/vault/<NAME>`, or the host variable):
//!   a static secret with a client-side lease, nothing to revoke at the source.
//! * [`vault::VaultProvider`], a Vault/OpenBao-compatible HTTP backend: a KV v2
//!   static secret read with a client-side lease, or a short-lived token minted
//!   for a token role (`auth/token/create/<role>` with `ttl` and
//!   `explicit_max_ttl`), renewed and revoked at the provider.
//!
//! The rules ([`issue_bound`], [`renew_within_bounds`]) are the guarantees:
//! a lease is never longer than both the policy's TTL and the provider's
//! ceiling, never wider in scope than requested, bound to the session and
//! audience it was asked for; a renewal never widens scope and never runs
//! past the lease's original maximum. A provider that answers otherwise is
//! refused, never trusted. Any failure is fail-closed: no lease, no grant —
//! never a fallback to a broader credential.
//!
//! The secret itself is a [`LeasedSecret`]: no `Display`, a redacted `Debug`,
//! zeroed on drop, and readable only inside this crate (to build the proxy's
//! injected header and to authenticate to the provider). [`Lease`]'s own
//! `Debug` prints neither the secret nor the provider's revocation handle.

pub mod config;
pub mod grant;
pub mod http;
pub mod keeper;
pub mod local;
pub mod vault;

use std::collections::BTreeSet;
use std::fmt;
use std::time::{Duration, SystemTime};

use zeroize::Zeroizing;

/// A secret value a provider issued: unprintable by type, zeroed on drop.
#[derive(Clone)]
pub struct LeasedSecret(Zeroizing<Vec<u8>>);

impl LeasedSecret {
    /// Wrap `bytes`; the buffer is moved, not copied.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(bytes.into()))
    }

    /// The bytes, for the two places that must have them: the header the
    /// proxy injects, and the provider's own authentication.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` for an empty secret.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for LeasedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LeasedSecret(<redacted>)")
    }
}

/// What a lease may act on: the resource paths at its upstream (empty means
/// every path), the permission names the policy granted, and whether writes
/// are allowed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeaseScope {
    /// Path prefixes at the upstream the credential may be used for.
    pub resources: Vec<String>,
    /// Permission names (for a token role, the provider policies requested).
    pub permissions: BTreeSet<String>,
    /// Whether requests that are not read-only are allowed.
    pub write: bool,
}

impl LeaseScope {
    /// Is `other` no wider than `self`? Every permission of `other` is one of
    /// `self`'s, `other` writes only if `self` does, and every resource of
    /// `other` lies under one of `self`'s (an empty list is every path, so it
    /// covers anything and is covered only by another empty list).
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        let resources = self.resources.is_empty()
            || (!other.resources.is_empty()
                && other
                    .resources
                    .iter()
                    .all(|r| self.resources.iter().any(|mine| under(r, mine))));
        resources && other.permissions.is_subset(&self.permissions) && (self.write || !other.write)
    }
}

/// `path` equals `prefix` or continues it at a `/` boundary.
fn under(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// What a caller asks a provider for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseRequest {
    /// The session (task) the lease is bound to.
    pub session: String,
    /// The service it is for (`artifacts`).
    pub service: String,
    /// What it may act on.
    pub scope: LeaseScope,
    /// How long it should live: the policy's TTL, already bounded by the
    /// provider's ceiling (see [`bound_ttl`]).
    pub ttl: Duration,
    /// The longest any renewal may extend it to, from issue.
    pub max_ttl: Duration,
    /// Who it is for: the upstream host the proxy injects it into.
    pub audience: String,
}

/// A credential a provider issued under a [`LeaseRequest`].
#[derive(Clone)]
pub struct Lease {
    /// The provider's name in the host configuration (`bao`).
    pub provider: String,
    /// The service.
    pub service: String,
    /// The session it is bound to.
    pub session: String,
    /// What it may act on.
    pub scope: LeaseScope,
    /// Who it is for.
    pub audience: String,
    /// When it was issued.
    pub issued_at: SystemTime,
    /// When it runs out unless renewed.
    pub expires_at: SystemTime,
    /// The latest instant any renewal may reach.
    pub max_expires_at: SystemTime,
    /// Whether the provider can revoke it at the source. A static secret
    /// (the local vault, a KV read) cannot: withdrawing the proxy route is
    /// all the revocation there is, and the source value stays valid.
    pub revocable: bool,
    secret: LeasedSecret,
    handle: Option<LeasedSecret>,
}

impl Lease {
    /// A lease for `request` from `provider`, live from `issued_at` for
    /// `ttl`, with at most `request.max_ttl` from issue. `handle` is what the
    /// provider needs to renew or revoke it at the source (a token accessor),
    /// kept as secret as the value itself.
    #[must_use]
    pub fn new(
        provider: &str,
        request: &LeaseRequest,
        secret: LeasedSecret,
        handle: Option<LeasedSecret>,
        issued_at: SystemTime,
        ttl: Duration,
    ) -> Self {
        Self {
            provider: provider.to_owned(),
            service: request.service.clone(),
            session: request.session.clone(),
            scope: request.scope.clone(),
            audience: request.audience.clone(),
            issued_at,
            expires_at: issued_at + ttl,
            max_expires_at: issued_at + request.max_ttl,
            revocable: handle.is_some(),
            secret,
            handle,
        }
    }

    /// The same lease with the scope the provider reports it actually has.
    #[must_use]
    pub fn with_scope(mut self, scope: LeaseScope) -> Self {
        self.scope = scope;
        self
    }

    /// The same lease, now running out at `expires_at`.
    #[must_use]
    pub fn renewed_until(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// The secret value.
    pub(crate) fn secret(&self) -> &LeasedSecret {
        &self.secret
    }

    /// The provider-side handle (a token accessor), when there is one.
    pub(crate) fn handle(&self) -> Option<&LeasedSecret> {
        self.handle.as_ref()
    }

    /// How long it has left at `now` (zero once run out).
    #[must_use]
    pub fn remaining(&self, now: SystemTime) -> Duration {
        self.expires_at.duration_since(now).unwrap_or_default()
    }

    /// The lifetime it was issued or last renewed with, from issue.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.expires_at
            .duration_since(self.issued_at)
            .unwrap_or_default()
    }
}

impl fmt::Debug for Lease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lease")
            .field("provider", &self.provider)
            .field("service", &self.service)
            .field("session", &self.session)
            .field("scope", &self.scope)
            .field("audience", &self.audience)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("max_expires_at", &self.max_expires_at)
            .field("revocable", &self.revocable)
            .finish_non_exhaustive()
    }
}

/// A provider that cannot serve: the named state `ward doctor`, the launch's
/// notes, the `CredentialDenied` record and the grant history all report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DegradedState {
    /// Nothing answered at the address (refused, reset, closed early).
    Unreachable,
    /// A call ran past its timeout.
    TimedOut,
    /// The TLS handshake or certificate verification failed.
    TlsFailed,
    /// The provider refused the broker's own authentication.
    AuthRejected,
    /// The provider is sealed or not initialised.
    Sealed,
    /// The host configuration cannot work (a bad address, an unreadable or
    /// too-open token file, an unknown engine).
    Misconfigured,
    /// The provider answered something this client cannot use.
    BadResponse,
}

impl DegradedState {
    /// The state's name, as every surface prints it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::TimedOut => "timed-out",
            Self::TlsFailed => "tls-failed",
            Self::AuthRejected => "auth-rejected",
            Self::Sealed => "sealed",
            Self::Misconfigured => "misconfigured",
            Self::BadResponse => "bad-response",
        }
    }
}

impl fmt::Display for DegradedState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Whether a provider can serve right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    /// It answered and accepted the broker's authentication.
    Healthy,
    /// It cannot serve; nothing is issued from it until it can.
    Degraded(DegradedState),
}

/// A binding rule a lease or a renewal broke.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingViolation {
    /// A zero TTL was asked for or resulted.
    ZeroTtl,
    /// The provider's answer is wider than what was asked for.
    ScopeWidened,
    /// The lease names another audience.
    AudienceMismatch,
    /// The lease names another session or service.
    SessionMismatch,
    /// The renewal would reach past the lease's original maximum.
    PastMaxTtl,
}

impl fmt::Display for BindingViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroTtl => "zero ttl",
            Self::ScopeWidened => "scope widened",
            Self::AudienceMismatch => "audience mismatch",
            Self::SessionMismatch => "session mismatch",
            Self::PastMaxTtl => "past max ttl",
        })
    }
}

/// Why a provider call produced no usable lease. Every variant is
/// fail-closed: the caller grants nothing.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    /// The provider is in a [`DegradedState`]. `detail` never carries a
    /// secret or a provider response body.
    #[error("provider degraded ({state}): {detail}")]
    Degraded {
        /// The named state.
        state: DegradedState,
        /// What happened.
        detail: String,
    },
    /// The secret the request names does not exist.
    #[error("no such secret: {0}")]
    NotFound(String),
    /// The provider answered, and refused (a permission or role error).
    #[error("refused by the provider: {0}")]
    Refused(String),
    /// The provider's answer broke a binding rule, so it is not used.
    #[error("binding refused: {0}")]
    Binding(BindingViolation),
}

impl ProviderError {
    /// A degraded-state error.
    pub fn degraded(state: DegradedState, detail: impl Into<String>) -> Self {
        Self::Degraded {
            state,
            detail: detail.into(),
        }
    }

    /// The short name every surface prints for this failure: the degraded
    /// state's name, or `not-found`, `refused`, `binding:<rule>`.
    #[must_use]
    pub fn state_name(&self) -> String {
        match self {
            Self::Degraded { state, .. } => state.name().to_owned(),
            Self::NotFound(_) => "not-found".to_owned(),
            Self::Refused(_) => "refused".to_owned(),
            Self::Binding(v) => format!("binding:{}", v.to_string().replace(' ', "-")),
        }
    }
}

/// What revoking a lease achieved at the provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revocation {
    /// The provider confirmed the credential is revoked at the source.
    Confirmed,
    /// A static secret: nothing to revoke at the source. The proxy route's
    /// withdrawal is the whole revocation, and the source value stays valid.
    NotRevocable,
}

/// A source of brokered credentials (#267). Implementations talk to their
/// backend; the binding rules are enforced by [`issue_bound`] and
/// [`renew_within_bounds`], which every caller goes through, not by them.
/// Every method is bounded in time by the implementation: a call that cannot
/// complete returns [`ProviderError::Degraded`] rather than blocking.
pub trait CredentialProvider: Send + Sync {
    /// The provider's name in the host configuration.
    fn name(&self) -> &str;

    /// Issue a lease for `request`.
    fn issue(&self, request: &LeaseRequest) -> Result<Lease, ProviderError>;

    /// Extend `lease` by up to `increment` from now, returning the lease as
    /// the provider now reports it (same secret, its new expiry and scope).
    fn renew(&self, lease: &Lease, increment: Duration) -> Result<Lease, ProviderError>;

    /// Revoke `lease` at the source.
    fn revoke(&self, lease: &Lease) -> Result<Revocation, ProviderError>;

    /// Whether the provider can serve now.
    fn health(&self) -> Health;
}

/// The TTL a lease is asked for: the shortest of what the caller wants, the
/// policy's TTL and the provider's ceiling; zero is refused.
pub fn bound_ttl(
    requested: Duration,
    policy_ttl: Duration,
    provider_max: Duration,
) -> Result<Duration, BindingViolation> {
    let ttl = requested.min(policy_ttl).min(provider_max);
    if ttl.is_zero() {
        Err(BindingViolation::ZeroTtl)
    } else {
        Ok(ttl)
    }
}

/// Hold a freshly issued `lease` to `request`: the same session, service and
/// audience, a scope no wider than asked for, an expiry no later than
/// `request.ttl` from issue and a maximum no later than `request.max_ttl` —
/// clamped down when the provider granted more time, refused when it granted
/// more scope or another binding.
pub fn bind_issued(request: &LeaseRequest, mut lease: Lease) -> Result<Lease, ProviderError> {
    if lease.session != request.session || lease.service != request.service {
        return Err(ProviderError::Binding(BindingViolation::SessionMismatch));
    }
    if lease.audience != request.audience {
        return Err(ProviderError::Binding(BindingViolation::AudienceMismatch));
    }
    if !request.scope.covers(&lease.scope) {
        return Err(ProviderError::Binding(BindingViolation::ScopeWidened));
    }
    lease.max_expires_at = lease.max_expires_at.min(lease.issued_at + request.max_ttl);
    lease.expires_at = lease
        .expires_at
        .min(lease.issued_at + request.ttl)
        .min(lease.max_expires_at);
    if lease.expires_at <= lease.issued_at {
        return Err(ProviderError::Binding(BindingViolation::ZeroTtl));
    }
    Ok(lease)
}

/// Issue through `provider` and hold the answer to `request`
/// ([`bind_issued`]). The one way a lease is issued.
pub fn issue_bound(
    provider: &dyn CredentialProvider,
    request: &LeaseRequest,
) -> Result<Lease, ProviderError> {
    if request.ttl.is_zero() || request.max_ttl < request.ttl {
        return Err(ProviderError::Binding(BindingViolation::ZeroTtl));
    }
    let lease = provider.issue(request)?;
    // A lease the rules refuse is not left alive at the provider either.
    bind_issued(request, lease.clone()).inspect_err(|_| {
        let _ = provider.revoke(&lease);
    })
}

/// Hold a renewal to the lease it renews: the same binding, a scope no wider,
/// the original maximum unchanged, and the new expiry clamped to it.
pub fn bind_renewal(original: &Lease, mut renewed: Lease) -> Result<Lease, ProviderError> {
    if renewed.session != original.session || renewed.service != original.service {
        return Err(ProviderError::Binding(BindingViolation::SessionMismatch));
    }
    if renewed.audience != original.audience {
        return Err(ProviderError::Binding(BindingViolation::AudienceMismatch));
    }
    if !original.scope.covers(&renewed.scope) {
        return Err(ProviderError::Binding(BindingViolation::ScopeWidened));
    }
    renewed.issued_at = original.issued_at;
    renewed.max_expires_at = original.max_expires_at;
    renewed.expires_at = renewed.expires_at.min(original.max_expires_at);
    Ok(renewed)
}

/// Renew `lease` at `now` for up to its original lifetime again, never past
/// its maximum. Refused without asking the provider when the lease is
/// already at (or past) its maximum, or already run out — a lease that has
/// expired is not brought back.
pub fn renew_within_bounds(
    provider: &dyn CredentialProvider,
    lease: &Lease,
    now: SystemTime,
) -> Result<Lease, ProviderError> {
    if lease.expires_at >= lease.max_expires_at || now >= lease.max_expires_at {
        return Err(ProviderError::Binding(BindingViolation::PastMaxTtl));
    }
    if now >= lease.expires_at {
        return Err(ProviderError::Binding(BindingViolation::ZeroTtl));
    }
    let room = lease.max_expires_at.duration_since(now).unwrap_or_default();
    let increment = lease.ttl().min(room);
    let renewed = bind_renewal(lease, provider.renew(lease, increment)?)?;
    Ok(renewed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::sync::Mutex;
    use std::time::UNIX_EPOCH;

    fn scope(resources: &[&str], permissions: &[&str], write: bool) -> LeaseScope {
        LeaseScope {
            resources: resources.iter().map(|s| (*s).to_owned()).collect(),
            permissions: permissions.iter().map(|s| (*s).to_owned()).collect(),
            write,
        }
    }

    fn request(ttl: u64, max: u64) -> LeaseRequest {
        LeaseRequest {
            session: "sess_a".into(),
            service: "artifacts".into(),
            scope: scope(&["/repos/acme"], &["read"], false),
            ttl: Duration::from_secs(ttl),
            max_ttl: Duration::from_secs(max),
            audience: "artifacts.example".into(),
        }
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// A provider whose answers the test scripts: what `issue` and `renew`
    /// return, and every call it saw.
    struct Scripted {
        issued: Mutex<Option<Lease>>,
        renewed: Mutex<Option<Result<Lease, ProviderError>>>,
        calls: Mutex<Vec<String>>,
    }

    impl Scripted {
        fn new(issued: Lease) -> Self {
            Self {
                issued: Mutex::new(Some(issued)),
                renewed: Mutex::new(None),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl CredentialProvider for Scripted {
        fn name(&self) -> &'static str {
            "scripted"
        }
        fn issue(&self, _: &LeaseRequest) -> Result<Lease, ProviderError> {
            self.calls.lock().unwrap().push("issue".into());
            Ok(self.issued.lock().unwrap().clone().unwrap())
        }
        fn renew(&self, _: &Lease, increment: Duration) -> Result<Lease, ProviderError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("renew {}", increment.as_secs()));
            self.renewed.lock().unwrap().clone().unwrap()
        }
        fn revoke(&self, _: &Lease) -> Result<Revocation, ProviderError> {
            self.calls.lock().unwrap().push("revoke".into());
            Ok(Revocation::Confirmed)
        }
        fn health(&self) -> Health {
            Health::Healthy
        }
    }

    fn lease(req: &LeaseRequest, issued: u64, ttl: u64) -> Lease {
        Lease::new(
            "scripted",
            req,
            LeasedSecret::new("tok-secret-1"),
            Some(LeasedSecret::new("acc-secret-1")),
            at(issued),
            Duration::from_secs(ttl),
        )
    }

    #[test]
    fn the_ttl_is_the_shortest_of_the_caller_the_policy_and_the_provider() {
        let s = Duration::from_secs;
        assert_eq!(bound_ttl(s(600), s(300), s(900)), Ok(s(300)));
        assert_eq!(bound_ttl(s(600), s(900), s(120)), Ok(s(120)));
        assert_eq!(bound_ttl(s(60), s(900), s(120)), Ok(s(60)));
        assert_eq!(
            bound_ttl(s(600), Duration::ZERO, s(120)),
            Err(BindingViolation::ZeroTtl)
        );
    }

    #[test]
    fn scope_cover_is_resource_permission_and_write_containment() {
        let wide = scope(&["/repos/acme"], &["read", "list"], true);
        assert!(wide.covers(&scope(&["/repos/acme/one"], &["read"], false)));
        assert!(wide.covers(&scope(&["/repos/acme"], &["read", "list"], true)));
        assert!(!wide.covers(&scope(&["/repos/acmex"], &["read"], false)));
        assert!(!wide.covers(&scope(&["/repos/other"], &["read"], false)));
        assert!(!wide.covers(&scope(&["/repos/acme"], &["admin"], false)));
        assert!(!wide.covers(&scope(&[], &["read"], false)), "every path");
        let ro = scope(&[], &["read"], false);
        assert!(ro.covers(&scope(&["/x"], &["read"], false)));
        assert!(!ro.covers(&scope(&["/x"], &["read"], true)));
    }

    #[test]
    fn an_issued_lease_is_clamped_to_the_requested_ttl_and_max() {
        let req = request(60, 90);
        // The provider granted an hour; the lease is held to the minute asked for.
        let provider = Scripted::new(lease(&req, 1000, 3600));
        let l = issue_bound(&provider, &req).unwrap();
        assert_eq!(l.expires_at, at(1060));
        assert_eq!(l.max_expires_at, at(1090));
        assert_eq!(l.ttl(), Duration::from_secs(60));
        assert_eq!(l.remaining(at(1030)), Duration::from_secs(30));
        assert_eq!(l.remaining(at(2000)), Duration::ZERO);
    }

    #[test]
    fn an_issued_lease_wider_than_asked_or_bound_elsewhere_is_refused() {
        let req = request(60, 90);
        let widened = lease(&req, 0, 60).with_scope(scope(&["/repos/acme"], &["read"], true));
        let provider = Scripted::new(widened);
        assert_eq!(
            issue_bound(&provider, &req).unwrap_err(),
            ProviderError::Binding(BindingViolation::ScopeWidened)
        );
        // Refused, and revoked at the provider rather than left alive there.
        assert_eq!(
            provider.calls.lock().unwrap().as_slice(),
            ["issue", "revoke"]
        );
        let mut other = req.clone();
        other.audience = "elsewhere.example".into();
        assert_eq!(
            issue_bound(&Scripted::new(lease(&other, 0, 60)), &req).unwrap_err(),
            ProviderError::Binding(BindingViolation::AudienceMismatch)
        );
        let mut other = req.clone();
        other.session = "sess_b".into();
        assert_eq!(
            issue_bound(&Scripted::new(lease(&other, 0, 60)), &req).unwrap_err(),
            ProviderError::Binding(BindingViolation::SessionMismatch)
        );
        let mut zero = req.clone();
        zero.ttl = Duration::ZERO;
        assert_eq!(
            issue_bound(&Scripted::new(lease(&req, 0, 60)), &zero).unwrap_err(),
            ProviderError::Binding(BindingViolation::ZeroTtl)
        );
        assert_eq!(
            issue_bound(&Scripted::new(lease(&req, 0, 0)), &req).unwrap_err(),
            ProviderError::Binding(BindingViolation::ZeroTtl)
        );
    }

    #[test]
    fn renewal_extends_within_the_max_and_never_past_it() {
        let req = request(60, 90);
        let original = bind_issued(&req, lease(&req, 1000, 60)).unwrap();
        let provider = Scripted::new(original.clone());
        // The provider offers a full hour; the renewal stops at the max.
        *provider.renewed.lock().unwrap() =
            Some(Ok(original.clone().renewed_until(at(1000 + 3600))));
        let renewed = renew_within_bounds(&provider, &original, at(1040)).unwrap();
        assert_eq!(renewed.expires_at, at(1090));
        assert_eq!(renewed.max_expires_at, at(1090));
        assert_eq!(renewed.issued_at, at(1000));
        // Asked for no more than the room left before the max.
        assert_eq!(provider.calls.lock().unwrap().last().unwrap(), "renew 50");

        // At the max, nothing more is asked of the provider at all.
        let calls = provider.calls.lock().unwrap().len();
        assert_eq!(
            renew_within_bounds(&provider, &renewed, at(1050)).unwrap_err(),
            ProviderError::Binding(BindingViolation::PastMaxTtl)
        );
        assert_eq!(provider.calls.lock().unwrap().len(), calls);
    }

    #[test]
    fn renewal_never_revives_an_expired_lease_or_widens_its_scope() {
        let req = request(60, 600);
        let original = bind_issued(&req, lease(&req, 1000, 60)).unwrap();
        let provider = Scripted::new(original.clone());
        assert_eq!(
            renew_within_bounds(&provider, &original, at(1060)).unwrap_err(),
            ProviderError::Binding(BindingViolation::ZeroTtl)
        );
        *provider.renewed.lock().unwrap() = Some(Ok(original
            .clone()
            .renewed_until(at(1200))
            .with_scope(scope(&["/repos/acme"], &["read", "admin"], false))));
        assert_eq!(
            renew_within_bounds(&provider, &original, at(1030)).unwrap_err(),
            ProviderError::Binding(BindingViolation::ScopeWidened)
        );
        // A degraded provider's renewal fails closed: the caller keeps the
        // old expiry, it never gains one.
        *provider.renewed.lock().unwrap() = Some(Err(ProviderError::degraded(
            DegradedState::Unreachable,
            "connection refused",
        )));
        let err = renew_within_bounds(&provider, &original, at(1030)).unwrap_err();
        assert_eq!(err.state_name(), "unreachable");
    }

    #[test]
    fn neither_the_secret_nor_the_handle_is_ever_formatted() {
        let req = request(60, 90);
        let l = lease(&req, 0, 60);
        let text = format!("{l:?} {:?} {:#?}", l.secret(), l);
        assert!(!text.contains("tok-secret-1"), "{text}");
        assert!(!text.contains("acc-secret-1"), "{text}");
        assert!(text.contains("LeasedSecret(<redacted>)"));
        assert_eq!(l.secret().expose(), b"tok-secret-1");
        assert_eq!(l.secret().len(), 12);
        assert!(!l.secret().is_empty());
        assert!(l.revocable);
        assert_eq!(
            l.handle().map(LeasedSecret::expose),
            Some(&b"acc-secret-1"[..])
        );
    }

    #[test]
    fn every_failure_has_a_short_name() {
        for (e, name) in [
            (
                ProviderError::degraded(DegradedState::TimedOut, "x"),
                "timed-out",
            ),
            (ProviderError::NotFound("k".into()), "not-found"),
            (ProviderError::Refused("403".into()), "refused"),
            (
                ProviderError::Binding(BindingViolation::PastMaxTtl),
                "binding:past-max-ttl",
            ),
        ] {
            assert_eq!(e.state_name(), name);
        }
        for s in [
            DegradedState::Unreachable,
            DegradedState::TimedOut,
            DegradedState::TlsFailed,
            DegradedState::AuthRejected,
            DegradedState::Sealed,
            DegradedState::Misconfigured,
            DegradedState::BadResponse,
        ] {
            assert_eq!(s.to_string(), s.name());
            assert!(!s.name().contains(' '));
        }
    }
}
