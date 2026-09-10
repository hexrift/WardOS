//! The three-layer merge and its narrowing algebra.
//!
//! Each capability type is a [`Lattice`], whose `meet` is the greatest lower
//! bound: the more restrictive combination of two values. Merging walks
//! system → user → project, only ever taking `meet`, so a lower layer can
//! narrow a capability but never widen it. This is the invariant behind
//! guarantee G7 / threat-model ST-007.

use crate::capability::{
    AccessMode, CapabilityManifest, ContainerCapability, CredentialRule, CredentialScope,
    DeviceSet, FsCapabilities, NetworkCapability, ObserverMode, ResourceLimits, StepPolicy,
};
use crate::default_manifest;
use crate::ids::{Blake3Hash, ProjectId, ServiceId, SessionId};
use crate::policy::Policy;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// A capability value that lives on a permissiveness lattice.
pub(crate) trait Lattice: Sized {
    /// The more restrictive combination of `a` and `b` (greatest lower bound).
    fn meet(a: &Self, b: &Self) -> Self;
}

/// Narrow a single field through the three layers, starting from `default`.
fn narrow<T: Lattice + Clone>(default: T, s: Option<&T>, u: Option<&T>, p: Option<&T>) -> T {
    let base = s.cloned().unwrap_or(default);
    let base = u.map_or_else(|| base.clone(), |v| T::meet(&base, v));
    p.map_or_else(|| base.clone(), |v| T::meet(&base, v))
}

/// Merge the system, user and project layers into an effective manifest.
///
/// Absent fields inherit from the layer above (ultimately the default manifest);
/// present fields are clamped so they can only narrow. The result's `policy_hash`
/// is BLAKE3 over the canonical serialization of its capability fields.
#[must_use]
pub fn merge(
    system: &Policy,
    user: &Policy,
    project: &Policy,
    session: SessionId,
    project_id: ProjectId,
) -> CapabilityManifest {
    let base = default_manifest();

    let filesystem = narrow(
        base.filesystem,
        system.filesystem.as_ref(),
        user.filesystem.as_ref(),
        project.filesystem.as_ref(),
    );
    let network = narrow(
        base.network,
        system.network.as_ref(),
        user.network.as_ref(),
        project.network.as_ref(),
    );
    let containers = narrow(
        base.containers,
        system.containers.as_ref(),
        user.containers.as_ref(),
        project.containers.as_ref(),
    );
    let devices = narrow(
        base.devices,
        system.devices.as_ref(),
        user.devices.as_ref(),
        project.devices.as_ref(),
    );
    let resources = narrow(
        base.resources,
        system.resources.as_ref(),
        user.resources.as_ref(),
        project.resources.as_ref(),
    );
    let observer = narrow(
        base.observer,
        system.observer.as_ref(),
        user.observer.as_ref(),
        project.observer.as_ref(),
    );
    let credentials = merge_credentials(&base.credentials, system, user, project);

    let mut manifest = CapabilityManifest {
        session,
        project: project_id,
        policy_hash: Blake3Hash([0u8; 32]),
        filesystem,
        network,
        credentials,
        containers,
        devices,
        resources,
        observer,
        tool_images: base.tool_images,
        agent_image: base.agent_image,
    };
    manifest.policy_hash = policy_hash(&manifest);
    manifest
}

/// Merge credential rules key-by-key. An unlisted service is `Deny` (deny-by-default),
/// so a lower layer can never introduce a service the layer above did not permit.
fn merge_credentials(
    default: &BTreeMap<ServiceId, CredentialRule>,
    system: &Policy,
    user: &Policy,
    project: &Policy,
) -> BTreeMap<ServiceId, CredentialRule> {
    let empty = BTreeMap::new();
    let system_rules = system.credentials.as_ref().unwrap_or(&empty);
    let user_rules = user.credentials.as_ref().unwrap_or(&empty);
    let project_rules = project.credentials.as_ref().unwrap_or(&empty);

    let mut services: BTreeSet<&ServiceId> = default.keys().collect();
    services.extend(system_rules.keys());
    services.extend(user_rules.keys());
    services.extend(project_rules.keys());

    services
        .into_iter()
        .map(|svc| {
            let base = system_rules
                .get(svc)
                .or_else(|| default.get(svc))
                .cloned()
                .unwrap_or(CredentialRule::Deny);
            let rule = narrow(base, None, user_rules.get(svc), project_rules.get(svc));
            (svc.clone(), rule)
        })
        .collect()
}

/// BLAKE3 over the manifest's capability fields (identity fields excluded).
pub(crate) fn policy_hash(m: &CapabilityManifest) -> Blake3Hash {
    #[derive(Serialize)]
    struct HashInput<'a> {
        filesystem: &'a FsCapabilities,
        network: &'a NetworkCapability,
        credentials: &'a BTreeMap<ServiceId, CredentialRule>,
        containers: &'a ContainerCapability,
        devices: &'a DeviceSet,
        resources: &'a ResourceLimits,
        observer: &'a ObserverMode,
        tool_images: &'a [crate::ids::ImageDigest],
        agent_image: &'a crate::ids::ImageDigest,
    }
    let input = HashInput {
        filesystem: &m.filesystem,
        network: &m.network,
        credentials: &m.credentials,
        containers: &m.containers,
        devices: &m.devices,
        resources: &m.resources,
        observer: &m.observer,
        tool_images: &m.tool_images,
        agent_image: &m.agent_image,
    };
    // Deterministic canonical form: struct fields keep declaration order and the only
    // maps/sets are BTree-backed (sorted), so the byte stream is stable across runs.
    let bytes = serde_yaml::to_string(&input).unwrap_or_default();
    Blake3Hash(*blake3::hash(bytes.as_bytes()).as_bytes())
}

// --- Lattice instances -----------------------------------------------------

impl Lattice for AccessMode {
    fn meet(a: &Self, b: &Self) -> Self {
        (*a).min(*b)
    }
}

impl Lattice for ContainerCapability {
    fn meet(a: &Self, b: &Self) -> Self {
        (*a).min(*b)
    }
}

impl NetworkCapability {
    /// Breadth rank on the preset ladder; `Custom` sits just below `Unrestricted`.
    const fn rank(&self) -> u8 {
        match self {
            Self::Offline => 0,
            Self::LocalhostOnly => 1,
            Self::Registries => 2,
            Self::Development => 3,
            Self::Custom(_) => 4,
            Self::Unrestricted => 5,
        }
    }
}

impl Lattice for NetworkCapability {
    fn meet(a: &Self, b: &Self) -> Self {
        match (a, b) {
            // Two explicit allowlists: the hosts permitted by both.
            (Self::Custom(sa), Self::Custom(sb)) => {
                Self::Custom(sa.intersection(sb).cloned().collect())
            }
            // An explicit allowlist against a preset. `Custom` is NOT a scalar rung on
            // the breadth ladder — `["github.com"]` is far narrower than `Development`,
            // not just below `Unrestricted` — so a rank comparison here silently drops
            // the allowlist and returns the preset, which both makes a documented
            // `!custom` narrowing a no-op and lets a lower-trust layer widen a
            // restrictive `Custom` back to the preset (a fail-open, ST-007). Instead keep
            // exactly the allowlist entries that the preset itself already permits, so
            // the result is never broader than either operand.
            (Self::Custom(s), preset) | (preset, Self::Custom(s)) => Self::Custom(
                s.iter()
                    .filter(|pat| preset_covers(preset, pat))
                    .cloned()
                    .collect(),
            ),
            // Two presets: the totally ordered breadth ladder.
            _ if a.rank() <= b.rank() => a.clone(),
            _ => b.clone(),
        }
    }
}

/// Does the preset `preset` permit **every** host that the allowlist pattern `pat`
/// would? Used to intersect a `Custom` allowlist with a preset without widening.
///
/// An exact name is kept when the preset lists it. A wildcard (`*.foo`) is kept only
/// when the whole subtree is within the preset — true for `Unrestricted`, and for the
/// localhost subtree under `LocalhostOnly`, but never for the finite registry/development
/// lists (they cannot cover an entire wildcard subtree). `preset` is assumed non-`Custom`
/// (the `Custom`/`Custom` case is handled by intersection in [`Lattice::meet`]).
fn preset_covers(preset: &NetworkCapability, pat: &str) -> bool {
    match preset {
        NetworkCapability::Unrestricted => true,
        // Offline permits nothing; the `Custom` arm is unreachable (handled by
        // intersection in `meet`) and folded in here only to be exhaustive.
        NetworkCapability::Offline | NetworkCapability::Custom(_) => false,
        NetworkCapability::LocalhostOnly => {
            let base = pat.strip_prefix("*.").unwrap_or(pat);
            base.eq_ignore_ascii_case("localhost")
                || base.to_ascii_lowercase().ends_with(".localhost")
        }
        NetworkCapability::Registries => {
            !pat.contains('*')
                && crate::hosts::any_matches(crate::hosts::REGISTRY_HOSTS.iter().copied(), pat)
        }
        NetworkCapability::Development => {
            !pat.contains('*')
                && crate::hosts::any_matches(
                    crate::hosts::REGISTRY_HOSTS
                        .iter()
                        .chain(crate::hosts::DEVELOPMENT_HOSTS)
                        .copied(),
                    pat,
                )
        }
    }
}

impl Lattice for DeviceSet {
    fn meet(a: &Self, b: &Self) -> Self {
        Self(a.0.intersection(&b.0).cloned().collect())
    }
}

impl Lattice for ResourceLimits {
    fn meet(a: &Self, b: &Self) -> Self {
        Self {
            cpu_weight: a.cpu_weight.min(b.cpu_weight),
            memory_percent: a.memory_percent.min(b.memory_percent),
            pids: a.pids.min(b.pids),
            disk_gib: a.disk_gib.min(b.disk_gib),
        }
    }
}

impl ObserverMode {
    /// Oversight rank: higher means more closely observed (more restrictive on the agent).
    const fn oversight(self) -> u8 {
        match self {
            Self::Quiet => 0,
            Self::Live => 1,
            Self::StepThrough(_) => 2,
        }
    }
}

impl Lattice for ObserverMode {
    fn meet(a: &Self, b: &Self) -> Self {
        match (a, b) {
            (Self::StepThrough(pa), Self::StepThrough(pb)) => Self::StepThrough(StepPolicy {
                pause_before_writes: pa.pause_before_writes || pb.pause_before_writes,
                pause_before_network: pa.pause_before_network || pb.pause_before_network,
            }),
            _ if a.oversight() >= b.oversight() => *a,
            _ => *b,
        }
    }
}

fn scope_meet(a: &CredentialScope, b: &CredentialScope) -> CredentialScope {
    CredentialScope {
        repositories: a
            .repositories
            .intersection(&b.repositories)
            .cloned()
            .collect(),
        permissions: a
            .permissions
            .intersection(&b.permissions)
            .cloned()
            .collect(),
    }
}

impl Lattice for CredentialRule {
    fn meet(a: &Self, b: &Self) -> Self {
        use CredentialRule::{Allow, Ask, Deny};
        match (a, b) {
            (Deny, _) | (_, Deny) => Deny,
            (Ask(sa), Ask(sb) | Allow(sb)) | (Allow(sa), Ask(sb)) => Ask(scope_meet(sa, sb)),
            (Allow(sa), Allow(sb)) => Allow(scope_meet(sa, sb)),
        }
    }
}

impl Lattice for FsCapabilities {
    fn meet(a: &Self, b: &Self) -> Self {
        let extra = a
            .extra
            .iter()
            .filter_map(|(path, mode)| b.extra.get(path).map(|m| (path.clone(), (*mode).min(*m))))
            .collect();
        Self {
            worktree: AccessMode::meet(&a.worktree, &b.worktree),
            environment: AccessMode::meet(&a.environment, &b.environment),
            home: AccessMode::meet(&a.home, &b.home),
            tmp: AccessMode::meet(&a.tmp, &b.tmp),
            extra,
        }
    }
}
