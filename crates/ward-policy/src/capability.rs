//! The capability manifest and its component types.
//!
//! Every capability is a value on a permissiveness lattice. The merge algebra
//! (see [`crate::merge`]) only ever moves down that lattice, so a lower policy
//! layer can narrow a capability but never widen it.

use crate::ids::{Blake3Hash, ImageDigest, ProjectId, ServiceId, SessionId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// A three-valued policy decision. Ordered `Deny > Ask > Allow`, so merging two
/// decisions is `max`: the more restrictive one always wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Silently permitted (logged in Live observer mode).
    Allow,
    /// Routed to the approval surface.
    Ask,
    /// Refused; final for the session and never presented with an override.
    Deny,
}

/// Read/write access level for a mounted path. Ordered `None < ReadOnly < ReadWrite`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    /// Not mounted / no access.
    None,
    /// Mounted read-only.
    #[serde(rename = "ro")]
    ReadOnly,
    /// Mounted read-write.
    #[serde(rename = "rw")]
    ReadWrite,
}

/// Filesystem capability: the fixed sandbox mounts plus any extra paths.
///
/// Paths are always inside the sandbox namespace (`/work`, `/env`, …); host
/// paths never appear here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsCapabilities {
    /// `/work` — the project worktree.
    pub worktree: AccessMode,
    /// `/env` — the persistent project environment (caches, toolchains).
    pub environment: AccessMode,
    /// `$HOME` — sandbox-private, tmpfs-backed.
    pub home: AccessMode,
    /// `/tmp` — tmpfs scratch.
    pub tmp: AccessMode,
    /// Additional in-sandbox mounts and their access level.
    #[serde(default)]
    pub extra: BTreeMap<PathBuf, AccessMode>,
}

/// Egress reachability. The variants form a nested ladder from most to least
/// restrictive; `Custom` is an explicit allowlist ranked just below `Unrestricted`.
///
/// No variant ever permits private, link-local or metadata ranges — that denial
/// is structural (enforced at nftables and the proxy), not a policy field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkCapability {
    /// No network at all.
    Offline,
    /// Loopback only.
    LocalhostOnly,
    /// Loopback plus package registries.
    Registries,
    /// Registries plus VCS hosts plus the agent's own model API.
    Development,
    /// An explicit host allowlist.
    Custom(BTreeSet<String>),
    /// Any public destination (still never private ranges). Requires per-session approval.
    Unrestricted,
}

impl NetworkCapability {
    /// Structural invariant: no mode ever reaches private/link-local/metadata ranges.
    /// Every variant is listed so a new one must consciously decide this.
    #[must_use]
    pub const fn permits_private_ranges(&self) -> bool {
        match self {
            Self::Offline
            | Self::LocalhostOnly
            | Self::Registries
            | Self::Development
            | Self::Custom(_)
            | Self::Unrestricted => false,
        }
    }
}

/// The set of repositories a brokered credential may act on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoSelector {
    /// The repository of the current session only.
    CurrentRepository,
    /// A named repository, `owner/name`.
    Named(String),
}

/// The scope attached to an `Ask` or `Allow` credential rule.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CredentialScope {
    /// Repositories the credential may act on.
    #[serde(default)]
    pub repositories: BTreeSet<RepoSelector>,
    /// Permission strings, e.g. `contents:read`.
    #[serde(default)]
    pub permissions: BTreeSet<String>,
}

/// What the broker does when a service credential is requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRule {
    /// Never issue the credential.
    Deny,
    /// Prompt for approval, bounded by the scope.
    Ask(CredentialScope),
    /// Issue silently, bounded by the scope.
    Allow(CredentialScope),
}

impl CredentialRule {
    /// The decision this rule reduces to, ignoring scope.
    #[must_use]
    pub const fn decision(&self) -> Decision {
        match self {
            Self::Deny => Decision::Deny,
            Self::Ask(_) => Decision::Ask,
            Self::Allow(_) => Decision::Allow,
        }
    }
}

/// Whether the session may run nested containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerCapability {
    /// No container runtime.
    None,
    /// Rootless nested containers permitted.
    NestedRootless,
}

/// The device nodes exposed to the session (usually empty).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceSet(pub BTreeSet<String>);

/// Resource ceilings. Narrower means smaller: merging takes the minimum of each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// cgroup CPU weight.
    pub cpu_weight: u32,
    /// Memory ceiling as a percentage of host RAM.
    pub memory_percent: u8,
    /// Maximum number of processes.
    pub pids: u32,
    /// Disk quota on `/env`, in GiB.
    pub disk_gib: u32,
}

/// Extra pauses imposed in step-through observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StepPolicy {
    /// Pause before each filesystem write.
    #[serde(default)]
    pub pause_before_writes: bool,
    /// Pause before each network request.
    #[serde(default)]
    pub pause_before_network: bool,
}

/// How closely the session is observed. Ordered `Quiet < Live < StepThrough`:
/// merging takes the *most* observed, so a repo can raise oversight but never lower it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverMode {
    /// Allows are silent.
    Quiet,
    /// Allows are logged live.
    Live,
    /// Each mediated action can pause for the operator.
    StepThrough(StepPolicy),
}

/// The effective, session-lifetime description of what an agent may reach.
///
/// Produced by [`crate::merge::merge`] or [`crate::default_manifest`]. Its
/// `policy_hash` is a BLAKE3 digest of the capability fields (identity fields
/// excluded), recorded in the session's genesis event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    /// The session this manifest governs.
    pub session: SessionId,
    /// The project this manifest governs.
    pub project: ProjectId,
    /// BLAKE3 over the canonical serialization of the merged capabilities.
    pub policy_hash: Blake3Hash,
    /// Filesystem mounts and their access levels.
    pub filesystem: FsCapabilities,
    /// Egress reachability.
    pub network: NetworkCapability,
    /// Per-service credential rules.
    pub credentials: BTreeMap<ServiceId, CredentialRule>,
    /// Nested-container capability.
    pub containers: ContainerCapability,
    /// Exposed device nodes.
    pub devices: DeviceSet,
    /// Resource ceilings.
    pub resources: ResourceLimits,
    /// Observation mode.
    pub observer: ObserverMode,
    /// Pinned tool image digests, mounted read-only.
    pub tool_images: Vec<ImageDigest>,
    /// Pinned agent image digest.
    pub agent_image: ImageDigest,
}

impl CapabilityManifest {
    /// Effective decision for a credential request, honouring wildcard (`prefix-*`)
    /// deny classes and defaulting to `Deny` for any unlisted service.
    #[must_use]
    pub fn credential_decision(&self, service: &ServiceId) -> Decision {
        if let Some(rule) = self.credentials.get(service) {
            return rule.decision();
        }
        for (listed, rule) in &self.credentials {
            if let Some(prefix) = listed.0.strip_suffix('*')
                && service.0.starts_with(prefix)
            {
                return rule.decision();
            }
        }
        Decision::Deny
    }
}
