//! The three-layer merge: `system ∩ user ∩ project` (`docs/threat-model.md` §7).
//!
//! # Rules
//!
//! The layers are applied in order `system → user → project`. The system layer is the
//! root of the capability set: anything it does not mention is **not granted** (the
//! fail-closed *floor*). Each lower layer may only move the result *down* the partial
//! order described by [`CapabilityManifest::is_within`]; an absent section in a lower
//! layer means *inherit*.
//!
//! | Section      | System (root)                                  | User / Project (narrowing)                                    |
//! |--------------|------------------------------------------------|---------------------------------------------------------------|
//! | filesystem   | `repo` as written; floor `read`                | `min(upper, lower)`; host is structurally denied              |
//! | network      | mode as written; floor `offline`               | [`NetworkCapability::narrow`] (documented there)              |
//! | secrets      | matching rules, most restrictive; floor `deny` | `min(upper, lower)`; scopes intersect; `deny` records layer   |
//! | containers   | `allow` as written; floor `false`              | logical AND                                                   |
//! | resources    | fields override the built-in defaults          | field-wise minimum                                            |
//! | observer     | level as written; floor `step-through: all`    | more verbose level wins; hold sets union                      |
//!
//! Hard denials: a `deny` produced by the system layer (explicitly or by omission) is
//! marked `hard: true`; no lower layer can relax it, because the merge never raises a
//! decision. `unrestricted` network is never grantable by the project layer and requires
//! the user layer to say `mode: unrestricted` explicitly.

use std::collections::{BTreeMap, BTreeSet};

use crate::defaults::default_resource_limits;
use crate::error::PolicyError;
use crate::hash::policy_hash;
use crate::manifest::{
    CapabilityManifest, ContainerCapability, CredentialRule, DeviceSet, FsCapabilities, MemoryMax,
    ObserverMode, ResourceLimits, StepPolicy,
};
use crate::network::{NetworkCapability, NetworkRequest};
use crate::schema::{HoldSet, Policy, ResourcesPolicy};
use crate::service::{ScopeItem, ServiceId};
use crate::types::{Decision, ImageDigest, Layer, MemoryLimit, ProjectId, SessionId};

/// Session identity recorded in the manifest alongside the merged capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestIdentity {
    /// The session this manifest governs.
    pub session: SessionId,
    /// The project the session runs in.
    pub project: ProjectId,
    /// Pinned digest of the agent image.
    pub agent_image: ImageDigest,
    /// Pinned digests of tool layers mounted read-only.
    pub tool_images: Vec<ImageDigest>,
}

/// Merges the three policy layers into a capability manifest.
///
/// See the module documentation for the exact rules.
///
/// # Errors
/// Returns [`PolicyError::Canonical`] if the inputs cannot be hashed. The merge itself
/// cannot fail: every ambiguity resolves to the more restrictive value.
pub fn merge(
    system: &Policy,
    user: &Policy,
    project: &Policy,
    identity: ManifestIdentity,
) -> Result<CapabilityManifest, PolicyError> {
    let policy_hash = policy_hash(system, user, project)?;
    let lower = [(Layer::User, user), (Layer::Project, project)];
    Ok(CapabilityManifest {
        session: identity.session,
        project: identity.project,
        policy_hash,
        filesystem: merge_filesystem(system, lower),
        network: merge_network(system, lower),
        credentials: merge_credentials(system, lower),
        containers: merge_containers(system, lower),
        devices: DeviceSet::empty(),
        resources: merge_resources(system, lower),
        observer: merge_observer(system, lower),
        tool_images: identity.tool_images,
        agent_image: identity.agent_image,
    })
}

type Lower<'a> = [(Layer, &'a Policy); 2];

fn merge_filesystem(system: &Policy, lower: Lower<'_>) -> FsCapabilities {
    let mut fs = system
        .agent
        .filesystem
        .as_ref()
        .and_then(|f| f.repo)
        .map_or_else(FsCapabilities::floor, |a| {
            FsCapabilities::with_worktree(a, Layer::System)
        });
    for (layer, policy) in lower {
        if let Some(repo) = policy.agent.filesystem.as_ref().and_then(|f| f.repo)
            && repo < fs.worktree
        {
            fs = FsCapabilities::with_worktree(repo, layer);
        }
    }
    fs
}

fn request(policy: &Policy) -> Option<NetworkRequest<'_>> {
    policy.agent.network.as_ref().map(|n| NetworkRequest {
        mode: n.mode,
        allow: &n.allow,
    })
}

fn merge_network(system: &Policy, lower: Lower<'_>) -> NetworkCapability {
    let mut net = request(system).map_or_else(NetworkCapability::floor, |r| {
        NetworkCapability::standalone(r, Layer::System)
    });
    for (layer, policy) in lower {
        net = net.narrow(request(policy), layer);
    }
    net
}

/// A layer's combined verdict for one service: the most restrictive matching rule and
/// the intersection of the matching rules' scopes (`None` if no rule gives a scope).
struct LayerVerdict {
    decision: Decision,
    scope: Option<BTreeSet<ScopeItem>>,
}

fn layer_verdict(policy: &Policy, service: &ServiceId) -> Option<LayerVerdict> {
    let secrets = policy.agent.secrets.as_ref()?;
    let mut verdict: Option<LayerVerdict> = None;
    for (pattern, rule) in secrets {
        if !pattern.matches(service.as_str()) {
            continue;
        }
        verdict = Some(match verdict {
            None => LayerVerdict {
                decision: rule.decision,
                scope: rule.scope.clone(),
            },
            Some(v) => LayerVerdict {
                decision: v.decision.narrow(rule.decision),
                scope: intersect_scopes(v.scope, rule.scope.as_ref()),
            },
        });
    }
    verdict
}

fn intersect_scopes(
    a: Option<BTreeSet<ScopeItem>>,
    b: Option<&BTreeSet<ScopeItem>>,
) -> Option<BTreeSet<ScopeItem>> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.intersection(b).cloned().collect()),
        (a, b) => a.or_else(|| b.cloned()),
    }
}

fn system_rule(verdict: Option<LayerVerdict>) -> CredentialRule {
    match verdict {
        Some(LayerVerdict { decision, scope }) if !decision.is_deny() => CredentialRule {
            decision,
            scope: scope.unwrap_or_default(),
            hard: false,
            denied_by: None,
        },
        _ => CredentialRule::default_deny(),
    }
}

fn narrow_rule(rule: &mut CredentialRule, verdict: LayerVerdict, layer: Layer) {
    let decision = rule.decision.narrow(verdict.decision);
    if decision.is_deny() {
        if !rule.decision.is_deny() {
            rule.denied_by = Some(layer);
        }
        rule.scope.clear();
    } else if let Some(scope) = verdict.scope {
        rule.scope = rule.scope.intersection(&scope).cloned().collect();
    }
    rule.decision = decision;
}

fn merge_credentials(system: &Policy, lower: Lower<'_>) -> BTreeMap<ServiceId, CredentialRule> {
    let keys: BTreeSet<&ServiceId> = std::iter::once(system)
        .chain(lower.iter().map(|(_, p)| *p))
        .filter_map(|p| p.agent.secrets.as_ref())
        .flat_map(BTreeMap::keys)
        .collect();
    keys.into_iter()
        .map(|key| {
            let mut rule = system_rule(layer_verdict(system, key));
            for (layer, policy) in lower {
                if let Some(verdict) = layer_verdict(policy, key) {
                    narrow_rule(&mut rule, verdict, layer);
                }
            }
            (key.clone(), rule)
        })
        .collect()
}

fn merge_containers(system: &Policy, lower: Lower<'_>) -> ContainerCapability {
    let mut containers = match system.agent.containers {
        Some(c) if c.allow => ContainerCapability::NestedRootless,
        _ => ContainerCapability::Denied {
            hard: true,
            denied_by: Layer::System,
        },
    };
    for (layer, policy) in lower {
        if let Some(c) = policy.agent.containers
            && !c.allow
            && containers.is_allowed()
        {
            containers = ContainerCapability::Denied {
                hard: false,
                denied_by: layer,
            };
        }
    }
    containers
}

fn memory_max(limit: MemoryLimit) -> MemoryMax {
    match limit {
        MemoryLimit::Percent(p) => MemoryMax {
            bytes: None,
            percent_of_host: Some(p),
        },
        MemoryLimit::Bytes(b) => MemoryMax {
            bytes: Some(b),
            percent_of_host: None,
        },
    }
}

/// The limits a layer asks for, with unspecified fields taken from `current`.
fn requested_limits(res: &ResourcesPolicy, current: ResourceLimits) -> ResourceLimits {
    ResourceLimits {
        cpu_weight: res.cpu_weight.unwrap_or(current.cpu_weight),
        memory_max: res.memory_max.map_or(current.memory_max, memory_max),
        pids_max: res.pids_max.unwrap_or(current.pids_max),
        disk_quota: res.disk_quota.unwrap_or(current.disk_quota),
    }
}

fn merge_resources(system: &Policy, lower: Lower<'_>) -> ResourceLimits {
    // The system layer overrides the built-in defaults; lower layers only tighten.
    let mut limits = system
        .agent
        .resources
        .as_ref()
        .map_or_else(default_resource_limits, |r| {
            requested_limits(r, default_resource_limits())
        });
    for (_, policy) in lower {
        if let Some(res) = &policy.agent.resources {
            limits = limits.narrow(requested_limits(res, limits));
        }
    }
    limits
}

fn merge_observer(system: &Policy, lower: Lower<'_>) -> ObserverMode {
    let mut observer = match system.observer.default {
        Some(level) => ObserverMode::Quiet.narrow(level, system.observer.step.as_ref()),
        None => ObserverMode::StepThrough(StepPolicy { hold: HoldSet::All }),
    };
    for (_, policy) in lower {
        if let Some(level) = policy.observer.default {
            observer = observer.narrow(level, policy.observer.step.as_ref());
        }
    }
    observer
}

/// Convenience for callers that only need to know whether a lower layer would be
/// accepted as a pure narrowing of an upper manifest: `true` when `narrower` grants
/// nothing that `wider` does not.
#[must_use]
pub fn is_narrowing(narrower: &CapabilityManifest, wider: &CapabilityManifest) -> bool {
    narrower.is_within(wider)
}
