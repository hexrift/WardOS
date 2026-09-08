//! The capability manifest: the effective, strongly typed result of the three-layer
//! merge (`docs/security-model.md` §3).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::network::NetworkCapability;
use crate::schema::{HoldSet, ObserverLevel};
use crate::service::{ScopeItem, ServiceId};
use crate::types::{
    Blake3Hash, ByteSize, CpuWeight, Decision, FsAccess, HostDenied, ImageDigest, Layer, Percent,
    PidsMax, ProjectId, SessionId,
};

/// Everything a session is allowed to do.
///
/// Produced only by [`crate::merge`]; never hand-assembled by enforcement code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    /// The session this manifest governs.
    pub session: SessionId,
    /// The project (repository) the session runs in.
    pub project: ProjectId,
    /// [`crate::policy_hash`] of the three inputs that produced this manifest.
    pub policy_hash: Blake3Hash,
    /// Filesystem capabilities.
    pub filesystem: FsCapabilities,
    /// Network capability.
    pub network: NetworkCapability,
    /// Credential rules keyed by service id or `*` pattern. Use
    /// [`CapabilityManifest::credential`] to evaluate a concrete service; it fails closed
    /// for services not listed.
    pub credentials: BTreeMap<ServiceId, CredentialRule>,
    /// Nested container capability.
    pub containers: ContainerCapability,
    /// Device access; always empty in 0.1.
    pub devices: DeviceSet,
    /// Resource limits.
    pub resources: ResourceLimits,
    /// Observer mode.
    pub observer: ObserverMode,
    /// Pinned digests of tool layers mounted read-only.
    pub tool_images: Vec<ImageDigest>,
    /// Pinned digest of the agent image.
    pub agent_image: ImageDigest,
}

/// Filesystem capabilities. Only the worktree access level is policy-controlled;
/// `/env`, `$HOME` and `/tmp` are always read-write sandbox-private mounts and the host
/// filesystem is structurally denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsCapabilities {
    /// `/work` (the project worktree).
    pub worktree: FsAccess,
    /// `/env` (project environment: caches, toolchain upper layer). Always `Write`.
    pub env: FsAccess,
    /// `$HOME` (sandbox-private, tmpfs-backed). Always `Write`.
    pub home: FsAccess,
    /// `/tmp` (tmpfs). Always `Write`.
    pub tmp: FsAccess,
    /// The host filesystem. Always denied.
    pub host: HostDenied,
    /// The layer whose setting produced `worktree`.
    pub decided_by: Layer,
}

impl FsCapabilities {
    /// Fail-closed floor: read-only worktree.
    #[must_use]
    pub fn floor() -> Self {
        Self::with_worktree(FsAccess::Read, Layer::System)
    }

    /// A capability set with the given worktree access.
    #[must_use]
    pub fn with_worktree(worktree: FsAccess, decided_by: Layer) -> Self {
        Self {
            worktree,
            env: FsAccess::Write,
            home: FsAccess::Write,
            tmp: FsAccess::Write,
            host: HostDenied,
            decided_by,
        }
    }
}

/// The effective rule for one credential service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRule {
    /// The decision.
    pub decision: Decision,
    /// Scope items. Empty means the adapter's minimal read-only scope; broader scopes
    /// must be listed explicitly. Always empty for `Deny`.
    pub scope: BTreeSet<ScopeItem>,
    /// `true` when the denial comes from the system layer (or from the absence of any
    /// system grant) and therefore can never be relaxed by a lower layer.
    pub hard: bool,
    /// The first layer that produced `Deny`, if the decision is `Deny`.
    pub denied_by: Option<Layer>,
}

impl CredentialRule {
    /// The fail-closed rule for a service no layer granted.
    #[must_use]
    pub fn default_deny() -> Self {
        Self {
            decision: Decision::Deny,
            scope: BTreeSet::new(),
            hard: true,
            denied_by: Some(Layer::System),
        }
    }

    /// Combines two rules that both apply to the same concrete service: the more
    /// restrictive decision wins, scopes intersect, and denial provenance is kept.
    #[must_use]
    pub fn combine(&self, other: &Self) -> Self {
        let decision = self.decision.narrow(other.decision);
        let denied_by = match (self.denied_by, other.denied_by) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let scope = if decision.is_deny() {
            BTreeSet::new()
        } else {
            self.scope.intersection(&other.scope).cloned().collect()
        };
        Self {
            decision,
            scope,
            hard: self.hard || other.hard,
            denied_by,
        }
    }

    /// Partial order used by [`CapabilityManifest::is_within`]: `self` grants no more
    /// than `other`. Ignores provenance.
    #[must_use]
    pub fn is_within(&self, other: &Self) -> bool {
        self.decision < other.decision
            || (self.decision == other.decision && self.scope.is_subset(&other.scope))
    }
}

/// Nested container capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ContainerCapability {
    /// No nested containers.
    Denied {
        /// `true` when denied by the system layer.
        hard: bool,
        /// The first layer that denied.
        denied_by: Layer,
    },
    /// Nested rootless containers are permitted.
    NestedRootless,
}

impl ContainerCapability {
    /// `true` for [`ContainerCapability::NestedRootless`].
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, ContainerCapability::NestedRootless)
    }

    /// Partial order: `self` grants no more than `other`.
    #[must_use]
    pub fn is_within(self, other: Self) -> bool {
        !self.is_allowed() || other.is_allowed()
    }
}

/// Device access. Always empty in 0.1; the type exists so the manifest shape matches
/// `docs/security-model.md` §3 and cannot be widened without a schema change.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSet(BTreeSet<String>);

impl DeviceSet {
    /// The empty device set.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// `true` when no device is granted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Partial order: `self` grants no more than `other`.
    #[must_use]
    pub fn is_within(&self, other: &Self) -> bool {
        self.0.is_subset(&other.0)
    }
}

/// A memory ceiling expressed as up to two constraints, both of which apply. The
/// enforcer takes the smaller once host memory is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryMax {
    /// Absolute ceiling in bytes, if any.
    pub bytes: Option<ByteSize>,
    /// Ceiling as a percentage of host memory, if any.
    pub percent_of_host: Option<Percent>,
}

fn min_opt<T: Ord + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    }
}

fn le_opt<T: Ord + Copy>(a: Option<T>, b: Option<T>) -> bool {
    match (a, b) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(x), Some(y)) => x <= y,
    }
}

impl MemoryMax {
    /// Component-wise minimum.
    #[must_use]
    pub fn narrow(self, other: Self) -> Self {
        Self {
            bytes: min_opt(self.bytes, other.bytes),
            percent_of_host: min_opt(self.percent_of_host, other.percent_of_host),
        }
    }

    /// Partial order: `self` is at least as tight as `other` in every component.
    #[must_use]
    pub fn is_within(self, other: Self) -> bool {
        le_opt(self.bytes, other.bytes) && le_opt(self.percent_of_host, other.percent_of_host)
    }
}

/// Resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// cgroup `cpu.weight`.
    pub cpu_weight: CpuWeight,
    /// Memory ceiling.
    pub memory_max: MemoryMax,
    /// cgroup `pids.max`.
    pub pids_max: PidsMax,
    /// Disk quota on `/env`.
    pub disk_quota: ByteSize,
}

impl ResourceLimits {
    /// Field-wise minimum.
    #[must_use]
    pub fn narrow(self, other: Self) -> Self {
        Self {
            cpu_weight: self.cpu_weight.min(other.cpu_weight),
            memory_max: self.memory_max.narrow(other.memory_max),
            pids_max: self.pids_max.min(other.pids_max),
            disk_quota: self.disk_quota.min(other.disk_quota),
        }
    }

    /// Partial order: every limit of `self` is at most the corresponding limit of
    /// `other`.
    #[must_use]
    pub fn is_within(self, other: Self) -> bool {
        self.cpu_weight <= other.cpu_weight
            && self.memory_max.is_within(other.memory_max)
            && self.pids_max <= other.pids_max
            && self.disk_quota <= other.disk_quota
    }
}

/// What step-through mode holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepPolicy {
    /// The hold set.
    pub hold: HoldSet,
}

/// Observer mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum ObserverMode {
    /// Allowed actions are silent.
    Quiet,
    /// Allowed actions are logged.
    Live,
    /// Matching actions are held for approval.
    StepThrough(StepPolicy),
}

impl ObserverMode {
    /// The verbosity level.
    #[must_use]
    pub fn level(&self) -> ObserverLevel {
        match self {
            ObserverMode::Quiet => ObserverLevel::Quiet,
            ObserverMode::Live => ObserverLevel::Live,
            ObserverMode::StepThrough(_) => ObserverLevel::StepThrough,
        }
    }

    /// Combines with a lower layer's request: the more verbose level wins, hold sets
    /// union.
    #[must_use]
    pub fn narrow(&self, level: ObserverLevel, hold: Option<&HoldSet>) -> Self {
        match (self, level) {
            (ObserverMode::StepThrough(current), ObserverLevel::StepThrough) => {
                let hold = hold.map_or_else(|| current.hold.clone(), |h| current.hold.union(h));
                ObserverMode::StepThrough(StepPolicy { hold })
            }
            (ObserverMode::StepThrough(_), _) => self.clone(),
            (_, ObserverLevel::StepThrough) => ObserverMode::StepThrough(StepPolicy {
                hold: hold.cloned().unwrap_or(HoldSet::All),
            }),
            (current, requested) => {
                if requested > current.level() {
                    Self::from_level(requested)
                } else {
                    current.clone()
                }
            }
        }
    }

    fn from_level(level: ObserverLevel) -> Self {
        match level {
            ObserverLevel::Quiet => ObserverMode::Quiet,
            ObserverLevel::Live => ObserverMode::Live,
            ObserverLevel::StepThrough => {
                ObserverMode::StepThrough(StepPolicy { hold: HoldSet::All })
            }
        }
    }

    /// Partial order: `self` is at least as verbose/holding as `other`.
    #[must_use]
    pub fn is_within(&self, other: &Self) -> bool {
        match (self, other) {
            (ObserverMode::StepThrough(a), ObserverMode::StepThrough(b)) => {
                a.hold.is_superset_of(&b.hold)
            }
            _ => self.level() >= other.level(),
        }
    }
}

impl CapabilityManifest {
    /// Evaluates the credential rule for a concrete service name.
    ///
    /// Every listed rule whose pattern matches `service` applies; the most restrictive
    /// decision wins and scopes intersect. A service matched by no rule is denied.
    #[must_use]
    pub fn credential(&self, service: &str) -> CredentialRule {
        let mut result: Option<CredentialRule> = None;
        for (id, rule) in &self.credentials {
            if id.matches(service) {
                result = Some(match result {
                    None => rule.clone(),
                    Some(acc) => acc.combine(rule),
                });
            }
        }
        result.unwrap_or_else(CredentialRule::default_deny)
    }

    /// Partial order over manifests: `true` when `self` grants nothing that `other`
    /// does not also grant. Identity, hashes, images and provenance are ignored.
    ///
    /// This is the invariant the property tests check: a lower layer can only move a
    /// manifest *down* this order.
    #[must_use]
    pub fn is_within(&self, other: &Self) -> bool {
        let services: BTreeSet<&ServiceId> = self
            .credentials
            .keys()
            .chain(other.credentials.keys())
            .collect();
        self.filesystem.worktree <= other.filesystem.worktree
            && self.network.is_within(&other.network)
            && services.iter().all(|s| {
                self.credential(s.as_str())
                    .is_within(&other.credential(s.as_str()))
            })
            && self.containers.is_within(other.containers)
            && self.devices.is_within(&other.devices)
            && self.resources.is_within(other.resources)
            && self.observer.is_within(&other.observer)
    }
}
