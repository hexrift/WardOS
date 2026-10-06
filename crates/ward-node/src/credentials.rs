//! Credentials as node capabilities (#267, ADR-0034; #332 stage 3).
//!
//! A node started with a credentials file ([`NodeCredentials::load`]) honours a manifest's
//! `credentials` grant ([`ward_node_protocol::CredentialGrants`]): for each grant it asks
//! the configured provider for a lease ([`ward_credentials::issue_bound`], the session
//! broker's rules), bound to the attempt, the service and the upstream host, and installs a
//! gateway route on the attempt's own egress proxy ([`crate::egress`]) that injects the
//! leased value into requests for `/<service>/…`, forwarded to that host only. The secret
//! never enters the sandbox: the workload sends an ordinary request to its proxy socket and
//! the proxy adds the header on the way out.
//!
//! The configuration is the operator's, never the envelope's. It names each provider (the
//! `[provider.<name>]` table of [`ward_credentials::provider::ProviderConfig`], the session
//! broker's spelling) and each service: the provider and engine it comes from, the
//! permissions and resource paths its lease is scoped to, the upstream it is injected into,
//! the header, and the longest lease the node grants for it. The file must be the node
//! user's own and writable by no one else, since it decides where the provider token is
//! sent; the token stays in its own private file.
//!
//! A lease lives no longer than the grant's `ttl_secs`, the service's and the provider's
//! ceilings and the attempt's wall-clock budget; a service configured to renew is renewed
//! once a third of its period is left, never past that maximum. When the attempt ends —
//! its own exit, the budget, `stop`, `revoke`, an ambiguous launch, a revoke whose reap is
//! unconfirmed — every route is withdrawn at once and every lease revoked at its provider.
//! A provider that cannot serve is in a named degraded state: the grant gets a route that
//! refuses every request `403` and a `CredentialDenied` record, never a fallback.
//!
//! The attempt's evidence log records every grant without its secret, with the existing
//! credential kinds and origin `node`: `CredentialGranted` when a lease is issued
//! (`issued <host> lease <id>`) or renewed (`renewed <host> lease <id>`), its scope's
//! permissions and its lifetime; `CredentialDenied` with the rule
//! `credential-provider:<provider>:<state>` when none could be issued; `CredentialRevoked`
//! when the route is withdrawn, followed by a `CredentialDenied` with the rule
//! `credential-revoke:<provider>:<state>` when the provider did not confirm the revocation.
//! A lease id is `b3:` and the first 32 hex digits of the `BLAKE3-256` digest of the
//! provider's revocation handle (`static` for a lease the provider cannot revoke): it binds
//! the record to the provider's lease without carrying the handle, and no digest of a
//! secret is ever recorded.
//!
//! The revocation handles of an attempt's live leases are the one thing the node keeps on
//! disk, in a private file beside the workspace (`<task-root>/<task>/<attempt>.credentials/
//! leases.json`, mode 0600 in a 0700 directory), written before the workload starts and
//! removed once the leases are revoked, so a restarted node can revoke at the provider what
//! a node that died left behind ([`NodeCredentials::recover`]). A handle cannot
//! authenticate to the upstream; the leased value is never written anywhere.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ward_credentials::provider::{EngineKind, ProviderConfig, open_private, segment_ok};
use ward_credentials::vault::{Engine, WRITE};
use ward_credentials::{
    CredentialProvider, DegradedState, Lease, LeaseRequest, LeaseScope, LeasedSecret,
    ProviderError, Revocation, issue_bound, renew_within_bounds,
};
use ward_events::{
    Blake3Hash, CredentialDelivery, DenyReason, NameText, RevokeReason, RuleRef, Scope, ServiceId,
    ShortText, WardEvent,
};
use ward_node_protocol::{CredentialGrant, CredentialGrants, TaskBinding};
use ward_proxy::{GatewayRoute, LeaseDeadline, Secret};

/// Suffix of an attempt's credentials directory, beside its workspace.
pub const CREDENTIALS_SUFFIX: &str = ".credentials";

/// File name of the revocation handles inside an attempt's credentials directory.
pub const LEASES_FILE: &str = "leases.json";

/// The longest a provider call may take on a node, so that revoking an attempt's leases
/// fits within the bound `stop` and `revoke` wait for the reap.
pub const MAX_PROVIDER_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest credentials file a node reads.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

const LEASES_FORMAT: u32 = 1;

/// A credentials file the node refuses to start with, and why.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("credentials file: {0}")]
pub struct CredentialConfigError(pub String);

fn invalid(text: impl Into<String>) -> CredentialConfigError {
    CredentialConfigError(text.into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileShape {
    #[serde(default)]
    provider: BTreeMap<String, ProviderConfig>,
    #[serde(default)]
    service: BTreeMap<String, ServiceShape>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceShape {
    provider: String,
    engine: EngineKind,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    mount: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    field: Option<String>,
    #[serde(default)]
    permissions: BTreeSet<String>,
    max_ttl_secs: u64,
    #[serde(default)]
    renew: bool,
    upstream: String,
    #[serde(default = "default_header")]
    header: String,
    #[serde(default)]
    value_prefix: String,
    #[serde(default)]
    paths: Vec<String>,
    #[cfg(feature = "test-loopback")]
    #[serde(default)]
    plain_upstream: bool,
}

fn default_header() -> String {
    "authorization".to_owned()
}

type Connect =
    Arc<dyn Fn(Engine) -> Result<Arc<dyn CredentialProvider>, ProviderError> + Send + Sync>;

#[derive(Clone)]
struct ProviderEntry {
    connect: Connect,
    max_ttl: Duration,
}

#[derive(Clone, Debug)]
struct ServiceEntry {
    id: ServiceId,
    provider: String,
    engine: Engine,
    permissions: BTreeSet<String>,
    max_ttl: Duration,
    renew: bool,
    host: String,
    port: u16,
    header: String,
    value_prefix: String,
    paths: Vec<String>,
    #[cfg(feature = "test-loopback")]
    plain_upstream: bool,
}

/// The providers and services a node's operator configured: what `admit` honours and what
/// `start` leases (see the module docs).
#[derive(Clone, Default)]
pub struct NodeCredentials {
    providers: BTreeMap<String, ProviderEntry>,
    services: BTreeMap<String, ServiceEntry>,
}

impl std::fmt::Debug for NodeCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeCredentials")
            .field("providers", &self.providers.keys().collect::<Vec<_>>())
            .field("services", &self.services)
            .finish()
    }
}

impl NodeCredentials {
    /// Load the credentials file at `path`: a regular file of the node's user, writable by
    /// no one else, at most [`MAX_CONFIG_BYTES`], not a symlink.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialConfigError`] for a missing, unsafe or invalid file.
    pub fn load(path: &Path) -> Result<Self, CredentialConfigError> {
        let bytes = open_private(path, 0o022)
            .map_err(invalid)?
            .ok_or_else(|| invalid(format!("{}: no such file", path.display())))?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(invalid(format!("{}: larger than 64 KiB", path.display())));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("the file is not UTF-8"))?;
        Self::parse(text)
    }

    /// Parse and validate the credentials file's text.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialConfigError`] naming the first provider or service that cannot
    /// be used.
    pub fn parse(text: &str) -> Result<Self, CredentialConfigError> {
        let shape: FileShape = toml::from_str(text).map_err(|e| invalid(e.message().to_owned()))?;
        let mut providers = BTreeMap::new();
        for (name, config) in shape.provider {
            config.check(&name).map_err(invalid)?;
            if Duration::from_millis(config.timeout_ms) > MAX_PROVIDER_TIMEOUT {
                return Err(invalid(format!(
                    "provider {name}: timeout_ms must be at most {} on a node",
                    MAX_PROVIDER_TIMEOUT.as_millis()
                )));
            }
            let max_ttl = Duration::from_secs(config.max_ttl_secs);
            let connect_name = name.clone();
            let connect: Connect = Arc::new(move |engine| {
                config
                    .connect(&connect_name, engine)
                    .map(|provider| Arc::new(provider) as Arc<dyn CredentialProvider>)
            });
            providers.insert(name, ProviderEntry { connect, max_ttl });
        }
        let mut services = BTreeMap::new();
        for (name, shape) in shape.service {
            let entry = service_entry(&name, shape, &providers)
                .map_err(|reason| invalid(format!("service {name}: {reason}")))?;
            services.insert(name, entry);
        }
        if services.is_empty() {
            return Err(invalid("no service is configured"));
        }
        Ok(Self {
            providers,
            services,
        })
    }

    /// Whether `grant` names a configured service, for the host that service is injected
    /// into, with a TTL within the service's and its provider's ceilings.
    #[must_use]
    pub fn honours(&self, grant: &CredentialGrant) -> bool {
        self.services.get(grant.service()).is_some_and(|service| {
            service.host == grant.host()
                && Duration::from_secs(u64::from(grant.ttl_secs())) <= service.max_ttl
        })
    }

    /// Lease every grant of `grants` for the attempt `binding`, killed at `budget`, keeping
    /// the revocation handles in the credentials directory `dir` beside its workspace.
    ///
    /// A grant whose provider cannot serve is denied: its route refuses every request and
    /// its record names the state. Every lease issued is revoked when the returned value is
    /// dropped, whatever else happened.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::Unconfigured`] for a service the file does not configure
    /// (which `admit` never lets through), [`CredentialError::Route`] when a route cannot be
    /// built and [`CredentialError::Unrecorded`] when the handles cannot be kept on disk;
    /// nothing issued is left alive then.
    pub fn issue(
        &self,
        dir: &Path,
        binding: TaskBinding,
        grants: &CredentialGrants,
        budget: Duration,
    ) -> Result<AttemptCredentials, CredentialError> {
        let budget = Duration::from_secs(
            budget
                .as_millis()
                .div_ceil(1000)
                .try_into()
                .unwrap_or(u64::MAX),
        )
        .max(Duration::from_secs(1));
        let mut attempt = AttemptCredentials {
            dir: dir.to_path_buf(),
            leases: Vec::new(),
            routes: Vec::new(),
            records: Mutex::new(Vec::new()),
        };
        for grant in grants.grants() {
            let name = grant.service();
            let service = self
                .services
                .get(name)
                .ok_or(CredentialError::Unconfigured)?;
            match self.lease(name, service, grant, binding, budget) {
                Ok((provider, lease)) => {
                    let issued = HeldLease::new(name, service, provider, lease.clone());
                    let route = route(name, service, Some(&lease), issued.deadline.clone())
                        .map_err(|_| CredentialError::Route)?;
                    attempt.records_mut().push(issued.event("issued", &lease));
                    attempt.routes.push(route);
                    attempt.leases.push(issued);
                }
                Err(error) => {
                    let route = route(name, service, None, LeaseDeadline::at(UNIX_EPOCH))
                        .map_err(|_| CredentialError::Route)?;
                    attempt.routes.push(route);
                    attempt.deny(
                        name,
                        &service.host,
                        &service.permissions,
                        &service.provider,
                        &error.state_name(),
                    );
                }
            }
        }
        attempt.keep()?;
        Ok(attempt)
    }

    fn lease(
        &self,
        name: &str,
        service: &ServiceEntry,
        grant: &CredentialGrant,
        binding: TaskBinding,
        budget: Duration,
    ) -> Result<(Arc<dyn CredentialProvider>, Lease), ProviderError> {
        let ttl = Duration::from_secs(u64::from(grant.ttl_secs()))
            .min(service.max_ttl)
            .min(budget);
        let request = LeaseRequest {
            session: binding.attempt().to_string(),
            service: name.to_owned(),
            scope: LeaseScope {
                resources: service.paths.clone(),
                permissions: service.permissions.clone(),
                write: service.permissions.contains(WRITE),
            },
            ttl,
            max_ttl: service.max_ttl.min(budget).max(ttl),
            audience: service.host.clone(),
        };
        let provider = self.provider(&service.provider, service.engine.clone())?;
        let lease = issue_bound(provider.as_ref(), &request)?;
        Ok((provider, lease))
    }

    fn provider(
        &self,
        name: &str,
        engine: Engine,
    ) -> Result<Arc<dyn CredentialProvider>, ProviderError> {
        let entry = self.providers.get(name).ok_or_else(|| {
            ProviderError::degraded(DegradedState::Misconfigured, format!("no provider {name}"))
        })?;
        (entry.connect)(engine)
    }

    /// Revoke at their providers the leases a node that died left in the credentials
    /// directory `dir`, remove the handles and return the records of what happened, for the
    /// recovered attempt's evidence log. Nothing to revoke returns nothing.
    #[must_use]
    pub fn recover(&self, dir: &Path) -> Vec<WardEvent> {
        let path = dir.join(LEASES_FILE);
        let Ok(Some(bytes)) = open_private(&path, 0o077) else {
            return Vec::new();
        };
        let Ok(kept) = serde_json::from_slice::<KeptLeases>(&bytes) else {
            return Vec::new();
        };
        let records = kept
            .leases
            .into_iter()
            .flat_map(|kept| {
                let handle = LeasedSecret::new(kept.handle.into_bytes());
                let outcome = self
                    .provider(
                        &kept.provider,
                        Engine::Token {
                            role: String::new(),
                        },
                    )
                    .and_then(|provider| {
                        provider.revoke(&recovered_lease(
                            &kept.provider,
                            &kept.service,
                            &kept.host,
                            handle,
                        ))
                    })
                    .map_err(|error| error.state_name());
                Revoked {
                    service: kept.service,
                    host: kept.host,
                    id: kept.lease,
                    provider: kept.provider,
                    outcome,
                }
                .events(RevokeReason::SessionEnded)
            })
            .collect();
        let _ = std::fs::remove_file(&path);
        records
    }

    #[cfg(test)]
    pub(crate) fn with_provider(
        mut self,
        name: &str,
        provider: Arc<dyn CredentialProvider>,
    ) -> Self {
        if let Some(entry) = self.providers.get_mut(name) {
            entry.connect = Arc::new(move |_| Ok(Arc::clone(&provider)));
        }
        self
    }
}

fn service_entry(
    name: &str,
    shape: ServiceShape,
    providers: &BTreeMap<String, ProviderEntry>,
) -> Result<ServiceEntry, String> {
    let provider = providers
        .get(&shape.provider)
        .ok_or_else(|| format!("no provider {:?}", shape.provider))?;
    let engine = ward_credentials::provider::engine(
        shape.engine,
        shape.role.as_deref(),
        shape.mount.as_deref(),
        shape.path.as_deref(),
        shape.field.as_deref(),
    )?;
    let (host, port) = shape
        .upstream
        .rsplit_once(':')
        .and_then(|(host, port)| Some((host, port.parse::<u16>().ok().filter(|p| *p != 0)?)))
        .ok_or_else(|| format!("upstream {:?} is not host:port", shape.upstream))?;
    let id = ServiceId::new(name)
        .ok()
        .filter(|_| CredentialGrant::new(name.to_owned(), host.to_owned(), 1).is_ok())
        .ok_or_else(|| {
            "the name must be [a-z][a-z0-9-]{0,31} and the upstream host a lowercase DNS name"
                .to_owned()
        })?;
    if shape.max_ttl_secs == 0 {
        return Err("max_ttl_secs must be > 0".to_owned());
    }
    if shape.header.is_empty()
        || !shape
            .header
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || shape
            .value_prefix
            .bytes()
            .any(|b| !(b' '..0x7f).contains(&b))
    {
        return Err("header or value_prefix is not a valid header".to_owned());
    }
    if shape
        .paths
        .iter()
        .any(|p| !p.starts_with('/') || p.bytes().any(|b| b <= b' ' || b >= 0x7f))
    {
        return Err("every path must start with `/`".to_owned());
    }
    if shape
        .permissions
        .iter()
        .any(|p| !segment_ok(p) || p.contains('/'))
    {
        return Err("permission names are [A-Za-z0-9._-]".to_owned());
    }
    Ok(ServiceEntry {
        id,
        provider: shape.provider,
        engine,
        permissions: shape.permissions,
        max_ttl: Duration::from_secs(shape.max_ttl_secs).min(provider.max_ttl),
        renew: shape.renew,
        host: host.to_owned(),
        port,
        header: shape.header.to_ascii_lowercase(),
        value_prefix: shape.value_prefix,
        paths: shape.paths,
        #[cfg(feature = "test-loopback")]
        plain_upstream: shape.plain_upstream,
    })
}

/// Why an attempt's credentials could not be prepared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CredentialError {
    /// The revocation handles could not be written beside the workspace.
    #[error("the attempt's credential handles could not be recorded")]
    Unrecorded,
    /// A route for a configured service could not be built.
    #[error("the attempt's credential route could not be built")]
    Route,
    /// A grant names a service the node's file does not configure.
    #[error("a granted credential service is not configured")]
    Unconfigured,
}

/// The credentials directory beside the attempt workspace `workspace`.
#[must_use]
pub fn credentials_dir_beside(workspace: &Path) -> Option<PathBuf> {
    let attempt = workspace.file_name()?.to_str()?;
    Some(workspace.with_file_name(format!("{attempt}{CREDENTIALS_SUFFIX}")))
}

/// The credentials directory of `binding` under the task root `root`.
#[must_use]
pub fn credentials_dir(root: &Path, binding: TaskBinding) -> PathBuf {
    root.join(binding.task().to_string())
        .join(format!("{}{CREDENTIALS_SUFFIX}", binding.attempt()))
}

/// The handles kept beside an attempt's workspace while its leases live.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeptLeases {
    format: u32,
    leases: Vec<KeptLease>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeptLease {
    service: String,
    provider: String,
    host: String,
    lease: String,
    handle: String,
}

/// A lease rebuilt from its kept handle, for nothing but its revocation.
fn recovered_lease(provider: &str, service: &str, host: &str, handle: LeasedSecret) -> Lease {
    let request = LeaseRequest {
        session: String::new(),
        service: service.to_owned(),
        scope: LeaseScope::default(),
        ttl: Duration::from_secs(1),
        max_ttl: Duration::from_secs(1),
        audience: host.to_owned(),
    };
    Lease::new(
        provider,
        &request,
        LeasedSecret::new(Vec::new()),
        Some(handle),
        SystemTime::now(),
        request.ttl,
    )
}

/// The route of `service` under `/<name>`, injecting `lease`'s secret behind the service's
/// value prefix until `deadline`; without a lease, a route that refuses every request.
fn route(
    name: &str,
    service: &ServiceEntry,
    lease: Option<&Lease>,
    deadline: LeaseDeadline,
) -> Result<GatewayRoute, ward_proxy::Error> {
    let value = lease.map_or_else(
        || Secret::new(Vec::new()),
        |lease| {
            let secret = lease.secret().expose();
            let mut value = Vec::with_capacity(service.value_prefix.len() + secret.len());
            value.extend_from_slice(service.value_prefix.as_bytes());
            value.extend_from_slice(secret);
            Secret::new(value)
        },
    );
    let route = GatewayRoute::new(
        format!("/{name}"),
        &service.host,
        service.port,
        service.header.clone(),
        value,
    )?
    .scope(service.paths.clone(), service.permissions.contains(WRITE))
    .until(deadline);
    #[cfg(feature = "test-loopback")]
    let route = route.plain_upstream(service.plain_upstream);
    Ok(route)
}

/// The record id of a lease: `b3:` and 32 hex digits of its handle's digest, or `static`.
fn lease_id(lease: &Lease) -> String {
    lease.handle().map_or_else(
        || "static".to_owned(),
        |handle| format!("b3:{}", &Blake3Hash::hash(handle.expose()).to_hex()[..32]),
    )
}

fn permissions(permissions: &BTreeSet<String>) -> Vec<NameText> {
    permissions.iter().map(|p| NameText::new(p)).collect()
}

fn denial(
    service: &str,
    subject: &str,
    permissions: Vec<NameText>,
    rule: &str,
) -> Option<WardEvent> {
    Some(WardEvent::CredentialDenied {
        service: ServiceId::new(service).ok()?,
        scope: Scope {
            subject: ShortText::new(subject),
            permissions,
        },
        reason: DenyReason::PolicyDeny {
            rule: RuleRef::new(rule).ok()?,
        },
    })
}

/// One lease the node holds for an attempt, and the deadline its route is bound to.
struct HeldLease {
    id_of_service: ServiceId,
    service: String,
    host: String,
    provider_name: String,
    permissions: BTreeSet<String>,
    id: String,
    provider: Arc<dyn CredentialProvider>,
    lease: Mutex<Option<Lease>>,
    deadline: LeaseDeadline,
    renew: AtomicBool,
}

impl HeldLease {
    fn new(
        name: &str,
        service: &ServiceEntry,
        provider: Arc<dyn CredentialProvider>,
        lease: Lease,
    ) -> Self {
        Self {
            id_of_service: service.id.clone(),
            service: name.to_owned(),
            host: service.host.clone(),
            provider_name: service.provider.clone(),
            permissions: service.permissions.clone(),
            id: lease_id(&lease),
            provider,
            deadline: LeaseDeadline::at(lease.expires_at),
            lease: Mutex::new(Some(lease)),
            renew: AtomicBool::new(service.renew),
        }
    }

    fn current(&self) -> Option<Lease> {
        self.lease
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn due(&self, now: SystemTime) -> bool {
        self.renew.load(Ordering::SeqCst)
            && self.current().is_some_and(|lease| {
                lease.expires_at < lease.max_expires_at && lease.remaining(now) <= lease.ttl() / 3
            })
    }

    fn event(&self, verb: &str, lease: &Lease) -> WardEvent {
        WardEvent::CredentialGranted {
            service: self.id_of_service.clone(),
            scope: Scope {
                subject: ShortText::new(&format!("{verb} {} lease {}", self.host, self.id)),
                permissions: permissions(&self.permissions),
            },
            expires: lease.ttl(),
            delivery: CredentialDelivery::ProxyInjected,
        }
    }
}

/// One attempt's leases and the routes that inject them (see the module docs). Dropping it
/// withdraws every route and revokes every lease still held.
pub struct AttemptCredentials {
    dir: PathBuf,
    leases: Vec<HeldLease>,
    routes: Vec<GatewayRoute>,
    records: Mutex<Vec<WardEvent>>,
}

impl std::fmt::Debug for AttemptCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttemptCredentials")
            .field("dir", &self.dir)
            .field("routes", &self.routes.len())
            .field("leases", &self.leases.len())
            .finish_non_exhaustive()
    }
}

impl AttemptCredentials {
    /// The routes the attempt's egress proxy serves, one per grant.
    #[must_use]
    pub fn routes(&self) -> Vec<GatewayRoute> {
        self.routes.clone()
    }

    fn records_mut(&self) -> std::sync::MutexGuard<'_, Vec<WardEvent>> {
        self.records.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn deny(
        &self,
        service: &str,
        host: &str,
        granted: &BTreeSet<String>,
        provider: &str,
        state: &str,
    ) {
        if let Some(event) = denial(
            service,
            host,
            permissions(granted),
            &format!("credential-provider:{provider}:{state}"),
        ) {
            self.records_mut().push(event);
        }
    }

    /// Keep the revocation handles of the live leases in the credentials directory, written
    /// and synced before the workload can use any of them.
    fn keep(&self) -> Result<(), CredentialError> {
        let leases = self
            .leases
            .iter()
            .filter_map(|held| {
                let lease = held.current()?;
                let handle = lease.handle()?;
                Some(
                    String::from_utf8(handle.expose().to_vec())
                        .map(|handle| KeptLease {
                            service: held.service.clone(),
                            provider: held.provider_name.clone(),
                            host: held.host.clone(),
                            lease: held.id.clone(),
                            handle,
                        })
                        .map_err(|_| CredentialError::Unrecorded),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        if leases.is_empty() {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&KeptLeases {
            format: LEASES_FORMAT,
            leases,
        })
        .map_err(|_| CredentialError::Unrecorded)?;
        write_private(&self.dir, &bytes).map_err(|_| CredentialError::Unrecorded)
    }

    /// The records of what was issued and denied, not yet taken; once taken they are
    /// never handed out again.
    pub fn take_records(&self) -> Vec<WardEvent> {
        std::mem::take(&mut *self.records_mut())
    }

    /// Whether a lease is due for renewal at `now`.
    #[must_use]
    pub fn due(&self, now: SystemTime) -> bool {
        self.leases.iter().any(|held| held.due(now))
    }

    /// Renew at their providers the leases due at `now`; each [`Renewal`] takes effect
    /// only once its record is kept ([`Renewal::apply`]). A renewal the provider refuses
    /// or cannot serve stops renewing that lease, which runs out on time.
    #[must_use]
    pub fn renew(&self, now: SystemTime) -> Vec<Renewal<'_>> {
        self.leases
            .iter()
            .filter(|held| held.due(now))
            .filter_map(|held| {
                let lease = held.current()?;
                match renew_within_bounds(held.provider.as_ref(), &lease, now) {
                    Ok(renewed) => Some(Renewal {
                        event: held.event("renewed", &renewed),
                        apply: Some((held, renewed)),
                    }),
                    Err(error) => {
                        held.renew.store(false, Ordering::SeqCst);
                        let event = denial(
                            &held.service,
                            &format!("renew {} lease {}", held.host, held.id),
                            permissions(&held.permissions),
                            &format!(
                                "credential-renew:{}:{}",
                                held.provider_name,
                                error.state_name()
                            ),
                        )?;
                        Some(Renewal { event, apply: None })
                    }
                }
            })
            .collect()
    }

    /// Withdraw every route at once and revoke every lease still held at its provider,
    /// concurrently, then remove the kept handles. Revoking again returns nothing.
    #[must_use]
    pub fn revoke(&self) -> Vec<Revoked> {
        for held in &self.leases {
            held.deadline.set(UNIX_EPOCH);
        }
        let taken: Vec<(&HeldLease, Lease)> = self
            .leases
            .iter()
            .filter_map(|held| {
                let lease = held
                    .lease
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take()?;
                Some((held, lease))
            })
            .collect();
        if taken.is_empty() {
            return Vec::new();
        }
        let outcomes: Vec<Result<Revocation, ProviderError>> = std::thread::scope(|scope| {
            let running: Vec<_> = taken
                .iter()
                .map(|(held, lease)| {
                    std::thread::Builder::new()
                        .name("ward-node-revoke".to_owned())
                        .spawn_scoped(scope, move || held.provider.revoke(lease))
                        .map_err(|_| held.provider.revoke(lease))
                })
                .collect();
            running
                .into_iter()
                .map(|thread| match thread {
                    Ok(thread) => thread.join().unwrap_or_else(|_| {
                        Err(ProviderError::degraded(
                            DegradedState::BadResponse,
                            "revocation panicked",
                        ))
                    }),
                    Err(inline) => inline,
                })
                .collect()
        });
        let _ = std::fs::remove_file(self.dir.join(LEASES_FILE));
        taken
            .iter()
            .zip(outcomes)
            .map(|((held, _), outcome)| Revoked {
                service: held.service.clone(),
                host: held.host.clone(),
                id: held.id.clone(),
                provider: held.provider_name.clone(),
                outcome: outcome.map_err(|error| error.state_name()),
            })
            .collect()
    }

    /// [`Self::revoke`], with the records of the revocation for `reason`, after any issue
    /// or denial record not yet taken.
    #[must_use]
    pub fn finish(&self, reason: RevokeReason) -> Vec<WardEvent> {
        let revoked = self.revoke();
        self.records_of(&revoked, reason)
    }

    /// The records of `revoked` for `reason`, after any issue or denial record not yet
    /// taken.
    #[must_use]
    pub fn records_of(&self, revoked: &[Revoked], reason: RevokeReason) -> Vec<WardEvent> {
        let mut records = self.take_records();
        records.extend(revoked.iter().flat_map(|revoked| revoked.events(reason)));
        records
    }
}

impl Drop for AttemptCredentials {
    fn drop(&mut self) {
        let _ = self.revoke();
    }
}

/// Write `bytes` as the kept handles in the private directory `dir`: a temporary file,
/// synced, renamed into place, and the directory synced.
fn write_private(dir: &Path, bytes: &[u8]) -> std::io::Result<()> {
    DirBuilder::new().mode(0o700).create(dir).or_else(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(error)
        }
    })?;
    let metadata = std::fs::symlink_metadata(dir)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(std::io::Error::other(
            "credentials directory is not private",
        ));
    }
    let temporary = dir.join(format!("{LEASES_FILE}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, dir.join(LEASES_FILE))?;
    File::open(dir)?.sync_all()
}

/// A lease renewed at its provider, not yet in effect, or a renewal that failed.
pub struct Renewal<'a> {
    event: WardEvent,
    apply: Option<(&'a HeldLease, Lease)>,
}

impl std::fmt::Debug for Renewal<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Renewal")
            .field("event", &self.event)
            .finish_non_exhaustive()
    }
}

impl Renewal<'_> {
    /// The record of the renewal, or of its failure.
    #[must_use]
    pub const fn event(&self) -> &WardEvent {
        &self.event
    }

    /// Put the renewal into effect: the route injects until the renewed expiry, unless the
    /// lease was withdrawn meanwhile.
    pub fn apply(self) {
        let Some((held, renewed)) = self.apply else {
            return;
        };
        let mut lease = held.lease.lock().unwrap_or_else(PoisonError::into_inner);
        if lease.is_some() {
            held.deadline.set(renewed.expires_at);
            *lease = Some(renewed);
        }
    }
}

/// What revoking one lease achieved.
#[derive(Clone, Debug)]
pub struct Revoked {
    service: String,
    host: String,
    id: String,
    provider: String,
    outcome: Result<Revocation, String>,
}

impl Revoked {
    /// The records of this revocation for `reason`: `CredentialRevoked`, then a
    /// `CredentialDenied` naming the provider's state when it did not confirm.
    #[must_use]
    pub fn events(&self, reason: RevokeReason) -> Vec<WardEvent> {
        let Ok(service) = ServiceId::new(&self.service) else {
            return Vec::new();
        };
        let mut events = vec![WardEvent::CredentialRevoked { service, reason }];
        if let Err(state) = &self.outcome {
            events.extend(denial(
                &self.service,
                &format!("revoke {} lease {}", self.host, self.id),
                Vec::new(),
                &format!("credential-revoke:{}:{state}", self.provider),
            ));
        }
        events
    }

    /// The service whose lease this was.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// What the provider answered: confirmed, not revocable at the source, or the state
    /// it was in.
    pub const fn outcome(&self) -> &Result<Revocation, String> {
        &self.outcome
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::fs::PermissionsExt as _;

    use ward_events::{ExecutionAttemptId, LeaseId, TaskId};

    use super::*;

    const TOKEN: &str = "fake-leased-token-value";
    const ACCESSOR: &str = "fake-accessor-handle";

    const GOOD: &str = r#"
[provider.bao]
kind = "openbao"
address = "http://127.0.0.1:8200"
token_file = "/nonexistent/bao.token"
insecure_loopback = true
timeout_ms = 500
max_ttl_secs = 300

[service.artifacts]
provider = "bao"
engine = "token"
role = "ward-artifacts"
permissions = ["artifacts-read"]
max_ttl_secs = 900
renew = true
upstream = "artifacts.example.com:443"
value_prefix = "Bearer "
paths = ["/v1/repos/acme"]

[service.registry]
provider = "bao"
engine = "kv"
mount = "secret"
path = "ci/registry"
field = "token"
max_ttl_secs = 60
upstream = "registry.example.com:443"
"#;

    fn binding() -> TaskBinding {
        TaskBinding::new(
            TaskId::from_u128(7),
            ExecutionAttemptId::from_u128(8),
            LeaseId::from_u128(9),
        )
    }

    fn grant(service: &str, host: &str, ttl_secs: u32) -> CredentialGrant {
        CredentialGrant::new(service.to_owned(), host.to_owned(), ttl_secs).unwrap()
    }

    fn grants(list: &[(&str, &str, u32)]) -> CredentialGrants {
        CredentialGrants::new(list.iter().map(|(s, h, t)| grant(s, h, *t)).collect()).unwrap()
    }

    /// A provider that issues one token lease, records every call, and answers as told.
    #[derive(Default)]
    struct Scripted {
        calls: Mutex<Vec<String>>,
        degraded: Mutex<Option<DegradedState>>,
        revoke_fails: AtomicBool,
    }

    impl Scripted {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CredentialProvider for Scripted {
        fn name(&self) -> &'static str {
            "bao"
        }
        fn issue(&self, request: &LeaseRequest) -> Result<Lease, ProviderError> {
            self.calls.lock().unwrap().push(format!(
                "issue {} {} {} {}",
                request.service,
                request.audience,
                request.ttl.as_secs(),
                request.max_ttl.as_secs()
            ));
            if let Some(state) = *self.degraded.lock().unwrap() {
                return Err(ProviderError::degraded(state, "scripted"));
            }
            Ok(Lease::new(
                "bao",
                request,
                LeasedSecret::new(TOKEN.as_bytes().to_vec()),
                Some(LeasedSecret::new(ACCESSOR.as_bytes().to_vec())),
                SystemTime::now(),
                request.ttl,
            ))
        }
        fn renew(&self, lease: &Lease, increment: Duration) -> Result<Lease, ProviderError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("renew {}", increment.as_secs()));
            Ok(lease.clone().renewed_until(lease.expires_at + increment))
        }
        fn revoke(&self, lease: &Lease) -> Result<Revocation, ProviderError> {
            let handle = lease
                .handle()
                .map(|h| String::from_utf8(h.expose().to_vec()).unwrap());
            self.calls
                .lock()
                .unwrap()
                .push(format!("revoke {}", handle.unwrap_or_default()));
            if self.revoke_fails.load(Ordering::SeqCst) {
                return Err(ProviderError::degraded(DegradedState::Unreachable, "down"));
            }
            Ok(Revocation::Confirmed)
        }
        fn health(&self) -> ward_credentials::Health {
            ward_credentials::Health::Healthy
        }
    }

    fn configured(provider: &Arc<Scripted>) -> NodeCredentials {
        NodeCredentials::parse(GOOD)
            .unwrap()
            .with_provider("bao", Arc::clone(provider) as Arc<dyn CredentialProvider>)
    }

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn every_byte_under(dir: &Path) -> Vec<u8> {
        let mut all = Vec::new();
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                all.extend(every_byte_under(&path));
            } else if let Ok(bytes) = std::fs::read(&path) {
                all.extend(bytes);
            }
        }
        all
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }

    #[test]
    fn a_valid_file_configures_services_whose_grants_are_honoured_within_their_ceilings() {
        let credentials = NodeCredentials::parse(GOOD).unwrap();
        assert!(credentials.honours(&grant("artifacts", "artifacts.example.com", 300)));
        assert!(credentials.honours(&grant("registry", "registry.example.com", 60)));
        assert!(!credentials.honours(&grant("artifacts", "artifacts.example.com", 301)));
        assert!(!credentials.honours(&grant("registry", "registry.example.com", 61)));
        assert!(!credentials.honours(&grant("artifacts", "registry.example.com", 60)));
        assert!(!credentials.honours(&grant("unknown", "artifacts.example.com", 60)));
        assert!(!format!("{credentials:?}").contains("token_file"));
    }

    #[test]
    fn a_file_that_cannot_be_used_is_refused_with_the_reason() {
        let cases = [
            (GOOD.replace("timeout_ms = 500", "timeout_ms = 5001"), "timeout_ms"),
            (GOOD.replace("http://127.0.0.1:8200", "http://bao.internal:8200"), "TLS"),
            (GOOD.replace("provider = \"bao\"\nengine = \"token\"", "provider = \"vault\"\nengine = \"token\""), "no provider"),
            (GOOD.replace("role = \"ward-artifacts\"", "role = \"../x\""), "role"),
            (GOOD.replace("artifacts.example.com:443", "artifacts.example.com"), "host:port"),
            (GOOD.replace("artifacts.example.com:443", "10.0.0.1:443"), "DNS name"),
            (GOOD.replace("artifacts.example.com:443", "Artifacts.example.com:443"), "DNS name"),
            (GOOD.replace("[service.artifacts]", "[service.Artifacts]"), "DNS name"),
            (GOOD.replace("max_ttl_secs = 900", "max_ttl_secs = 0"), "max_ttl_secs"),
            (GOOD.replace("value_prefix = \"Bearer \"", "value_prefix = \"Bearer\\n\""), "header"),
            (GOOD.replace("/v1/repos/acme", "v1/repos/acme"), "path"),
            (GOOD.replace("artifacts-read", "artifacts/read"), "permission"),
            (GOOD.replace("renew = true", "renew = true\nsecret = \"x\""), "unknown field"),
            (GOOD.replace("kind = \"openbao\"", "kind = \"openbao\"\nprefix = \"/x\""), "unknown field"),
            ("[provider.bao]\nkind = \"openbao\"\naddress = \"https://b\"\ntoken_file = \"/t\"\n".to_owned(), "no service"),
        ];
        for (text, reason) in cases {
            let error = NodeCredentials::parse(&text).unwrap_err();
            assert!(error.to_string().contains(reason), "{reason}: {error}");
        }
    }

    #[test]
    fn the_file_must_be_the_node_users_own_private_regular_file() {
        let dir = private_dir();
        let path = dir.path().join("credentials.toml");
        assert!(NodeCredentials::load(&path).is_err());
        std::fs::write(&path, GOOD).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            NodeCredentials::load(&path)
                .unwrap_err()
                .to_string()
                .contains("too open")
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(NodeCredentials::load(&path).is_ok());
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(NodeCredentials::load(&link).is_err());
        std::fs::write(&path, format!("{GOOD}\n#{}", "x".repeat(MAX_CONFIG_BYTES))).unwrap();
        assert!(NodeCredentials::load(&path).is_err());
    }

    #[test]
    fn a_lease_is_bound_to_the_attempt_and_its_budget_and_kept_only_as_a_handle() {
        let provider = Arc::new(Scripted::default());
        let root = private_dir();
        let dir = root.path().join("exec.credentials");
        let attempt = configured(&provider)
            .issue(
                &dir,
                binding(),
                &grants(&[("artifacts", "artifacts.example.com", 600)]),
                Duration::from_millis(120_500),
            )
            .unwrap();
        assert_eq!(
            provider.calls(),
            ["issue artifacts artifacts.example.com 121 121"]
        );
        let routes = attempt.routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix(), "/artifacts");
        assert_eq!(routes[0].target().to_string(), "artifacts.example.com:443");
        assert!(!format!("{routes:?}").contains(TOKEN));

        let records = attempt.take_records();
        assert_eq!(records.len(), 1, "{records:?}");
        let WardEvent::CredentialGranted {
            service,
            scope,
            expires,
            delivery,
        } = &records[0]
        else {
            panic!("{records:?}");
        };
        assert_eq!(service.as_str(), "artifacts");
        assert_eq!(*delivery, CredentialDelivery::ProxyInjected);
        assert_eq!(*expires, Duration::from_secs(121));
        let id = &Blake3Hash::hash(ACCESSOR.as_bytes()).to_hex()[..32];
        assert_eq!(
            scope.subject.content(),
            format!("issued artifacts.example.com lease b3:{id}")
        );
        assert_eq!(scope.permissions, [NameText::new("artifacts-read")]);
        assert!(attempt.take_records().is_empty());

        let kept = std::fs::read(dir.join(LEASES_FILE)).unwrap();
        assert!(contains(&kept, ACCESSOR));
        assert!(!contains(&every_byte_under(root.path()), TOKEN));
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(LEASES_FILE)), 0o600);

        let revoked = attempt.revoke();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].outcome(), &Ok(Revocation::Confirmed));
        assert_eq!(
            provider.calls().last().unwrap(),
            &format!("revoke {ACCESSOR}")
        );
        assert!(!dir.join(LEASES_FILE).exists());
        assert!(
            attempt.revoke().is_empty(),
            "revoking twice revokes nothing"
        );
        assert_eq!(
            revoked[0].events(RevokeReason::UserRevoked),
            [WardEvent::CredentialRevoked {
                service: ServiceId::new("artifacts").unwrap(),
                reason: RevokeReason::UserRevoked,
            }]
        );
    }

    #[test]
    fn the_grant_ttl_and_the_service_ceiling_bound_the_lease_below_a_long_budget() {
        let provider = Arc::new(Scripted::default());
        let root = private_dir();
        let attempt = configured(&provider)
            .issue(
                &root.path().join("a.credentials"),
                binding(),
                &grants(&[
                    ("artifacts", "artifacts.example.com", 200),
                    ("registry", "registry.example.com", 60),
                ]),
                Duration::from_secs(3600),
            )
            .unwrap();
        assert_eq!(
            provider.calls(),
            [
                "issue artifacts artifacts.example.com 200 300",
                "issue registry registry.example.com 60 60",
            ]
        );
        assert_eq!(attempt.routes().len(), 2);
        assert_eq!(attempt.finish(RevokeReason::SessionEnded).len(), 4);
    }

    #[test]
    fn an_outage_denies_the_grant_with_a_named_state_and_a_route_that_refuses() {
        let provider = Arc::new(Scripted::default());
        *provider.degraded.lock().unwrap() = Some(DegradedState::Sealed);
        let root = private_dir();
        let dir = root.path().join("o.credentials");
        let attempt = configured(&provider)
            .issue(
                &dir,
                binding(),
                &grants(&[("artifacts", "artifacts.example.com", 60)]),
                Duration::from_secs(60),
            )
            .unwrap();
        assert_eq!(
            attempt.take_records(),
            [WardEvent::CredentialDenied {
                service: ServiceId::new("artifacts").unwrap(),
                scope: Scope {
                    subject: ShortText::new("artifacts.example.com"),
                    permissions: vec![NameText::new("artifacts-read")],
                },
                reason: DenyReason::PolicyDeny {
                    rule: RuleRef::new("credential-provider:bao:sealed").unwrap(),
                },
            }]
        );
        let routes = attempt.routes();
        assert_eq!(routes.len(), 1, "the request gets a refusal, not a 400");
        assert!(!dir.join(LEASES_FILE).exists());
        assert!(attempt.revoke().is_empty());
        assert_eq!(provider.calls().len(), 1);
    }

    #[test]
    fn a_revocation_the_provider_does_not_confirm_is_recorded_with_its_state() {
        let provider = Arc::new(Scripted::default());
        provider.revoke_fails.store(true, Ordering::SeqCst);
        let root = private_dir();
        let dir = root.path().join("u.credentials");
        let attempt = configured(&provider)
            .issue(
                &dir,
                binding(),
                &grants(&[("artifacts", "artifacts.example.com", 60)]),
                Duration::from_secs(60),
            )
            .unwrap();
        let records = attempt.finish(RevokeReason::SessionEnded);
        assert_eq!(records.len(), 3, "{records:?}");
        assert!(matches!(records[0], WardEvent::CredentialGranted { .. }));
        assert_eq!(
            records[1],
            WardEvent::CredentialRevoked {
                service: ServiceId::new("artifacts").unwrap(),
                reason: RevokeReason::SessionEnded,
            }
        );
        let WardEvent::CredentialDenied { reason, scope, .. } = &records[2] else {
            panic!("{records:?}");
        };
        assert_eq!(
            reason,
            &DenyReason::PolicyDeny {
                rule: RuleRef::new("credential-revoke:bao:unreachable").unwrap()
            }
        );
        assert!(
            scope
                .subject
                .content()
                .starts_with("revoke artifacts.example.com lease b3:")
        );
        assert!(!dir.join(LEASES_FILE).exists());
    }

    #[test]
    fn a_renewable_lease_is_renewed_once_a_third_is_left_and_only_once_its_record_is_kept() {
        let provider = Arc::new(Scripted::default());
        let root = private_dir();
        let attempt = configured(&provider)
            .issue(
                &root.path().join("r.credentials"),
                binding(),
                &grants(&[
                    ("artifacts", "artifacts.example.com", 90),
                    ("registry", "registry.example.com", 60),
                ]),
                Duration::from_secs(3600),
            )
            .unwrap();
        let start = SystemTime::now();
        assert!(!attempt.due(start));
        assert!(attempt.renew(start).is_empty());
        let later = start + Duration::from_secs(61);
        assert!(attempt.due(later), "artifacts renews; registry does not");
        let renewals = attempt.renew(later);
        assert_eq!(renewals.len(), 1);
        let WardEvent::CredentialGranted { scope, .. } = renewals[0].event() else {
            panic!("{renewals:?}");
        };
        assert!(
            scope
                .subject
                .content()
                .starts_with("renewed artifacts.example.com lease b3:")
        );
        assert_eq!(provider.calls().last().unwrap(), "renew 90");
        let route = &attempt.routes()[0];
        assert!(!format!("{route:?}").contains(TOKEN));
        drop(renewals);
        assert!(attempt.due(later), "a renewal not applied changes nothing");
        for renewal in attempt.renew(later) {
            renewal.apply();
        }
        assert!(!attempt.due(later));
    }

    #[test]
    fn a_restarted_node_revokes_what_a_dead_node_left_and_removes_the_handles() {
        let provider = Arc::new(Scripted::default());
        let credentials = configured(&provider);
        let root = private_dir();
        let dir = root.path().join("d.credentials");
        let attempt = credentials
            .issue(
                &dir,
                binding(),
                &grants(&[("artifacts", "artifacts.example.com", 60)]),
                Duration::from_secs(60),
            )
            .unwrap();
        std::mem::forget(attempt);
        assert!(dir.join(LEASES_FILE).exists());

        let records = credentials.recover(&dir);
        assert_eq!(
            records,
            [WardEvent::CredentialRevoked {
                service: ServiceId::new("artifacts").unwrap(),
                reason: RevokeReason::SessionEnded,
            }]
        );
        assert_eq!(
            provider.calls().last().unwrap(),
            &format!("revoke {ACCESSOR}")
        );
        assert!(!dir.join(LEASES_FILE).exists());
        assert!(credentials.recover(&dir).is_empty());

        let unconfigured = NodeCredentials::default();
        let again = configured(&provider)
            .issue(
                &dir,
                binding(),
                &grants(&[("artifacts", "artifacts.example.com", 60)]),
                Duration::from_secs(60),
            )
            .unwrap();
        std::mem::forget(again);
        let records = unconfigured.recover(&dir);
        assert_eq!(records.len(), 2, "{records:?}");
        assert!(matches!(
            &records[1],
            WardEvent::CredentialDenied { reason: DenyReason::PolicyDeny { rule }, .. }
                if rule.as_str() == "credential-revoke:bao:misconfigured"
        ));
    }

    #[test]
    fn dropping_an_attempts_credentials_revokes_them() {
        let provider = Arc::new(Scripted::default());
        let root = private_dir();
        let attempt = configured(&provider)
            .issue(
                &root.path().join("x.credentials"),
                binding(),
                &grants(&[("artifacts", "artifacts.example.com", 60)]),
                Duration::from_secs(60),
            )
            .unwrap();
        drop(attempt);
        assert_eq!(
            provider.calls().last().unwrap(),
            &format!("revoke {ACCESSOR}")
        );
        assert!(credentials_dir(root.path(), binding()).ends_with(format!(
            "{}/{}.credentials",
            binding().task(),
            binding().attempt()
        )));
    }
}
