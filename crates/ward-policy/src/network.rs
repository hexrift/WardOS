//! Network modes, their built-in allowlists, and the network narrowing rule.
//!
//! See `docs/architecture.md` §7 and `docs/decisions/ADR-0006-network.md`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hostname::{self, HostPattern, HostSet};
use crate::types::{Layer, PrivateNetworksDenied};

/// Network egress mode.
///
/// The derived order is the *positional* order used for non-`custom` comparisons:
/// `Offline < LocalhostOnly < PackageRegistries < Development < Custom < Unrestricted`.
/// `Custom` is never compared by position during a merge; it is compared by allowlist
/// (see [`NetworkCapability::narrow`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    /// No veth at all.
    Offline,
    /// veth present, only loopback reachable.
    LocalhostOnly,
    /// Built-in package registry hosts.
    PackageRegistries,
    /// Registries plus VCS hosts plus the agent's own model API host.
    Development,
    /// An explicit allowlist.
    Custom,
    /// Everything except private networks. Requires explicit user-layer opt-in and, at
    /// runtime, per-session approval (shown as `NET OPEN`).
    Unrestricted,
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NetworkMode::Offline => "offline",
            NetworkMode::LocalhostOnly => "localhost-only",
            NetworkMode::PackageRegistries => "package-registries",
            NetworkMode::Development => "development",
            NetworkMode::Custom => "custom",
            NetworkMode::Unrestricted => "unrestricted",
        })
    }
}

/// Hosts reachable in `package-registries` mode.
pub const PACKAGE_REGISTRY_HOSTS: &[&str] = &[
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "index.crates.io",
    "static.crates.io",
    "proxy.golang.org",
    "sum.golang.org",
    "rubygems.org",
    "index.rubygems.org",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "plugins.gradle.org",
    "api.nuget.org",
    "packagist.org",
    "repo.packagist.org",
];

/// Hosts added on top of [`PACKAGE_REGISTRY_HOSTS`] in `development` mode: VCS hosts and
/// the agent's model API host.
pub const DEVELOPMENT_EXTRA_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    "api.anthropic.com",
];

fn host_set(names: &[&str]) -> HostSet {
    // Built-in names are validated by a unit test; an invalid entry is dropped, which can
    // only ever make the allowlist smaller.
    names
        .iter()
        .filter_map(|n| HostPattern::parse(n).ok())
        .collect()
}

/// The built-in allowlist for a mode.
///
/// `Offline`, `LocalhostOnly`, `Custom` and `Unrestricted` return an empty set: the first
/// two allow no external host, `Custom` has no built-in list, and `Unrestricted` is not
/// expressed as a list at all.
#[must_use]
pub fn builtin_allowlist(mode: NetworkMode) -> HostSet {
    match mode {
        NetworkMode::PackageRegistries => host_set(PACKAGE_REGISTRY_HOSTS),
        NetworkMode::Development => {
            let mut set = host_set(PACKAGE_REGISTRY_HOSTS);
            set.extend(host_set(DEVELOPMENT_EXTRA_HOSTS));
            set
        }
        NetworkMode::Offline
        | NetworkMode::LocalhostOnly
        | NetworkMode::Custom
        | NetworkMode::Unrestricted => HostSet::new(),
    }
}

/// The effective network capability of a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCapability {
    /// The effective mode.
    pub mode: NetworkMode,
    /// The effective allowlist. Materialised for the built-in modes; empty for
    /// `Offline`, `LocalhostOnly` and `Unrestricted` (enforcers must check `mode`
    /// first).
    pub allow: HostSet,
    /// Private networks are always denied.
    pub deny_private_networks: PrivateNetworksDenied,
    /// The layer whose setting produced the effective value.
    pub decided_by: Layer,
}

/// A layer's network request, as written in policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkRequest<'a> {
    /// The requested mode.
    pub mode: NetworkMode,
    /// The explicit allowlist (only meaningful with `Custom`).
    pub allow: &'a HostSet,
}

impl NetworkCapability {
    /// The capability a single layer's request would grant if it were the only layer.
    #[must_use]
    pub fn standalone(request: NetworkRequest<'_>, layer: Layer) -> Self {
        let allow = match request.mode {
            NetworkMode::Custom => request.allow.clone(),
            other => builtin_allowlist(other),
        };
        Self {
            mode: request.mode,
            allow,
            deny_private_networks: PrivateNetworksDenied,
            decided_by: layer,
        }
    }

    /// The fail-closed floor used when the system layer says nothing about the network.
    #[must_use]
    pub fn floor() -> Self {
        Self {
            mode: NetworkMode::Offline,
            allow: HostSet::new(),
            deny_private_networks: PrivateNetworksDenied,
            decided_by: Layer::System,
        }
    }

    /// Whether `host` may be contacted under this capability.
    ///
    /// Fails closed: `Offline` and `LocalhostOnly` reach nothing external; only
    /// `Unrestricted` reaches hosts outside the allowlist.
    #[must_use]
    pub fn permits_host(&self, host: &str) -> bool {
        match self.mode {
            NetworkMode::Offline | NetworkMode::LocalhostOnly => false,
            NetworkMode::Unrestricted => true,
            NetworkMode::PackageRegistries | NetworkMode::Development | NetworkMode::Custom => {
                hostname::set_matches_host(&self.allow, host)
            }
        }
    }

    /// Partial order: `true` when every destination reachable under `self` is also
    /// reachable under `other`. Ignores `decided_by`.
    #[must_use]
    pub fn is_within(&self, other: &Self) -> bool {
        use NetworkMode::{LocalhostOnly, Offline, Unrestricted};
        match (self.mode, other.mode) {
            (Offline, _) => true,
            (_, Offline) => false,
            (LocalhostOnly, _) | (_, Unrestricted) => true,
            (_, LocalhostOnly) | (Unrestricted, _) => false,
            _ => hostname::is_subset(&self.allow, &other.allow),
        }
    }

    /// Applies a lower layer's request to this (upper) capability.
    ///
    /// Exact rule, where `U` is the upper allowlist and `L` the lower one:
    ///
    /// * `None` (section absent) → inherit the upper capability unchanged, **except**
    ///   that a `User` layer inheriting `Unrestricted` is clamped to `Development`
    ///   (unrestricted requires explicit user opt-in).
    /// * lower `offline` → `offline`.
    /// * lower `localhost-only` → `offline` if upper is `offline`, else `localhost-only`.
    /// * lower `unrestricted` → `unrestricted` only if the layer is `User` **and** the
    ///   upper is `unrestricted`; otherwise the upper capability (a project can never
    ///   obtain it).
    /// * lower `package-registries` / `development` (built-in list `B`):
    ///   * upper `offline` / `localhost-only` → upper;
    ///   * upper `unrestricted` → lower mode with `B`;
    ///   * upper `custom(U)` → `custom(B ∩ U)`;
    ///   * upper built-in → positional minimum of the two modes with its built-in list
    ///     (registries ⊆ development by construction).
    /// * lower `custom(L)`:
    ///   * upper `offline` / `localhost-only` → upper;
    ///   * upper `unrestricted` → `custom(L)`;
    ///   * otherwise → `custom(L ∩ U)`.
    ///
    /// `deny_private_networks` is structurally always denied.
    #[must_use]
    pub fn narrow(&self, lower: Option<NetworkRequest<'_>>, layer: Layer) -> Self {
        use NetworkMode::{
            Custom, Development, LocalhostOnly, Offline, PackageRegistries, Unrestricted,
        };
        let Some(req) = lower else {
            if layer == Layer::User && self.mode == Unrestricted {
                return Self::standalone(
                    NetworkRequest {
                        mode: Development,
                        allow: &HostSet::new(),
                    },
                    layer,
                );
            }
            return self.clone();
        };
        let with = |mode: NetworkMode, allow: HostSet| Self {
            mode,
            allow,
            deny_private_networks: PrivateNetworksDenied,
            decided_by: layer,
        };
        match req.mode {
            Offline => with(Offline, HostSet::new()),
            LocalhostOnly => match self.mode {
                Offline => self.clone(),
                _ => with(LocalhostOnly, HostSet::new()),
            },
            Unrestricted => match (layer, self.mode) {
                (Layer::User, Unrestricted) => with(Unrestricted, HostSet::new()),
                _ => self.clone(),
            },
            PackageRegistries | Development => match self.mode {
                Offline | LocalhostOnly => self.clone(),
                Unrestricted => with(req.mode, builtin_allowlist(req.mode)),
                Custom => with(
                    Custom,
                    hostname::intersect(&builtin_allowlist(req.mode), &self.allow),
                ),
                PackageRegistries | Development => {
                    let mode = req.mode.min(self.mode);
                    if mode == self.mode {
                        self.clone()
                    } else {
                        with(mode, builtin_allowlist(mode))
                    }
                }
            },
            Custom => match self.mode {
                Offline | LocalhostOnly => self.clone(),
                Unrestricted => with(Custom, req.allow.clone()),
                PackageRegistries | Development | Custom => {
                    with(Custom, hostname::intersect(req.allow, &self.allow))
                }
            },
        }
    }
}
