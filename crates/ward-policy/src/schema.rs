//! The `.ward/policy.yaml` schema, shared by the system, user and project layers.
//!
//! A document is parsed into private raw structures with `deny_unknown_fields` and then
//! validated into the typed [`Policy`], so a `Policy` value can only exist in a valid
//! state. Every section is optional: an absent section in a lower layer means *inherit*,
//! and an absent section in the system layer means *nothing granted* (see
//! [`crate::merge`]).
//!
//! ```yaml
//! agent:
//!   filesystem:
//!     repo: write            # write | read
//!     host: deny             # the only accepted value
//!   network:
//!     mode: development      # offline | localhost-only | package-registries |
//!                            # development | custom | unrestricted
//!     allow: []              # hostnames or `*.suffix`; only with mode: custom
//!     deny_private_networks: true   # the only accepted value
//!   secrets:
//!     github: ask            # deny | ask | allow
//!     npm-publish:
//!       decision: deny
//!       scope: []            # optional; adapter-defined items
//!   containers:
//!     allow: true
//!   resources:
//!     cpu_weight: 100
//!     memory_max: 50%        # or a byte size such as 8GiB
//!     pids_max: 4096
//!     disk_quota: 20GiB
//! observer:
//!   default: live            # quiet | live | step-through
//!   step: all                # or a list of globs; requires default: step-through
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::PolicyError;
use crate::hostname::{HostPattern, HostSet};
use crate::network::NetworkMode;
use crate::service::{ScopeItem, ServiceId, StepPattern};
use crate::types::{
    ByteSize, CpuWeight, Decision, FsAccess, HostDenied, MemoryLimit, PidsMax,
    PrivateNetworksDenied,
};

// ---------------------------------------------------------------------------
// Public, validated schema
// ---------------------------------------------------------------------------

/// One policy layer, parsed and validated.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawPolicy")]
pub struct Policy {
    /// Capabilities granted to the agent sandbox.
    pub agent: AgentPolicy,
    /// Observer configuration.
    pub observer: ObserverPolicy,
}

/// The `agent:` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AgentPolicy {
    /// `agent.filesystem`.
    pub filesystem: Option<FilesystemPolicy>,
    /// `agent.network`.
    pub network: Option<NetworkPolicy>,
    /// `agent.secrets`: service (or `*` pattern) → rule.
    pub secrets: Option<BTreeMap<ServiceId, SecretRule>>,
    /// `agent.containers`.
    pub containers: Option<ContainersPolicy>,
    /// `agent.resources`.
    pub resources: Option<ResourcesPolicy>,
}

/// The `agent.filesystem` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FilesystemPolicy {
    /// Access to the project worktree.
    pub repo: Option<FsAccess>,
    /// Host filesystem access. Structurally always denied; present only so a document
    /// may state `host: deny` explicitly.
    pub host: Option<HostDenied>,
}

/// The `agent.network` section. `mode` is required when the section is present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkPolicy {
    /// Requested mode.
    pub mode: NetworkMode,
    /// Explicit allowlist; non-empty only with [`NetworkMode::Custom`].
    pub allow: HostSet,
    /// Structurally always denied.
    pub deny_private_networks: PrivateNetworksDenied,
}

/// A credential rule for one service or service pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretRule {
    /// The decision.
    pub decision: Decision,
    /// Scope items; `None` means *inherit* (lower layers) or *adapter minimum*
    /// (system layer).
    pub scope: Option<BTreeSet<ScopeItem>>,
}

/// The `agent.containers` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ContainersPolicy {
    /// Whether nested rootless containers are allowed.
    pub allow: bool,
}

/// The `agent.resources` section.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ResourcesPolicy {
    /// cgroup `cpu.weight`.
    pub cpu_weight: Option<CpuWeight>,
    /// Memory ceiling.
    pub memory_max: Option<MemoryLimit>,
    /// cgroup `pids.max`.
    pub pids_max: Option<PidsMax>,
    /// Disk quota on `/env`.
    pub disk_quota: Option<ByteSize>,
}

/// Observer verbosity level. Ordered by verbosity: `Quiet < Live < StepThrough`.
///
/// A lower layer may only pick a *more* verbose level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObserverLevel {
    /// Allowed actions are silent.
    Quiet,
    /// Allowed actions are logged.
    Live,
    /// Matching actions are held for approval.
    StepThrough,
}

impl fmt::Display for ObserverLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ObserverLevel::Quiet => "quiet",
            ObserverLevel::Live => "live",
            ObserverLevel::StepThrough => "step-through",
        })
    }
}

/// Which actions step-through mode holds.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HoldSet {
    /// Hold every action.
    All,
    /// Hold actions matching any of these globs.
    Patterns(BTreeSet<StepPattern>),
}

impl HoldSet {
    /// Union of two hold sets (more holds = more restrictive).
    #[must_use]
    pub fn union(&self, other: &HoldSet) -> HoldSet {
        match (self, other) {
            (HoldSet::All, _) | (_, HoldSet::All) => HoldSet::All,
            (HoldSet::Patterns(a), HoldSet::Patterns(b)) => {
                HoldSet::Patterns(a.union(b).cloned().collect())
            }
        }
    }

    /// Whether `self` holds at least everything `other` holds.
    #[must_use]
    pub fn is_superset_of(&self, other: &HoldSet) -> bool {
        match (self, other) {
            (HoldSet::All, _) => true,
            (HoldSet::Patterns(_), HoldSet::All) => false,
            (HoldSet::Patterns(a), HoldSet::Patterns(b)) => a.is_superset(b),
        }
    }

    /// Whether an action named `candidate` is held. Fails closed on `All`.
    #[must_use]
    pub fn holds(&self, candidate: &str) -> bool {
        match self {
            HoldSet::All => true,
            HoldSet::Patterns(set) => set.iter().any(|p| p.matches(candidate)),
        }
    }
}

impl Serialize for HoldSet {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            HoldSet::All => s.serialize_str("all"),
            HoldSet::Patterns(set) => set.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for HoldSet {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        RawHold::deserialize(d)?
            .validate()
            .map_err(serde::de::Error::custom)
    }
}

/// The `observer:` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ObserverPolicy {
    /// Default verbosity.
    pub default: Option<ObserverLevel>,
    /// Hold set; requires `default: step-through` in the same document.
    pub step: Option<HoldSet>,
}

impl Policy {
    /// Parses and validates one YAML document. An empty document is an empty policy.
    ///
    /// # Errors
    /// Returns [`PolicyError`] for YAML syntax errors, unknown fields, type mismatches,
    /// or any semantic violation (for example `host: allow`).
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let raw: Option<RawPolicy> = serde_yaml::from_str(yaml)?;
        raw.map_or_else(|| Ok(Self::default()), Self::try_from)
    }

    /// Serialises the policy as YAML.
    ///
    /// # Errors
    /// Returns [`PolicyError::Yaml`] if serialisation fails.
    pub fn to_yaml(&self) -> Result<String, PolicyError> {
        Ok(serde_yaml::to_string(self)?)
    }

    /// `true` when no section is present (the policy inherits everything).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Overlays `other` onto `self` with *later wins* semantics.
    ///
    /// This is how the files of `/etc/ward/policy.d` combine **within** the system layer
    /// (it is not the cross-layer merge, which only ever narrows). Granularity:
    /// `filesystem.repo`, `filesystem.host`, `containers`, each `resources.*` field,
    /// `observer.default` and `observer.step` override individually; `network` overrides
    /// as a whole (mode and allowlist belong together); `secrets` merges per key.
    pub fn overlay(&mut self, other: &Policy) {
        if let Some(fs) = &other.agent.filesystem {
            let mine = self
                .agent
                .filesystem
                .get_or_insert_with(FilesystemPolicy::default);
            if fs.repo.is_some() {
                mine.repo = fs.repo;
            }
            if fs.host.is_some() {
                mine.host = fs.host;
            }
        }
        if let Some(net) = &other.agent.network {
            self.agent.network = Some(net.clone());
        }
        if let Some(secrets) = &other.agent.secrets {
            let mine = self.agent.secrets.get_or_insert_with(BTreeMap::new);
            for (k, v) in secrets {
                mine.insert(k.clone(), v.clone());
            }
        }
        if let Some(c) = other.agent.containers {
            self.agent.containers = Some(c);
        }
        if let Some(res) = &other.agent.resources {
            let mine = self
                .agent
                .resources
                .get_or_insert_with(ResourcesPolicy::default);
            if res.cpu_weight.is_some() {
                mine.cpu_weight = res.cpu_weight;
            }
            if res.memory_max.is_some() {
                mine.memory_max = res.memory_max;
            }
            if res.pids_max.is_some() {
                mine.pids_max = res.pids_max;
            }
            if res.disk_quota.is_some() {
                mine.disk_quota = res.disk_quota;
            }
        }
        if other.observer.default.is_some() {
            self.observer.default = other.observer.default;
        }
        if other.observer.step.is_some() {
            self.observer.step.clone_from(&other.observer.step);
        }
    }
}

// ---------------------------------------------------------------------------
// Raw (lenient) schema and validation
// ---------------------------------------------------------------------------

/// Accepts either an integer or a string scalar.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawScalar {
    Int(u64),
    Str(String),
}

impl RawScalar {
    fn into_string(self) -> String {
        match self {
            RawScalar::Int(n) => n.to_string(),
            RawScalar::Str(s) => s,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    agent: Option<RawAgent>,
    observer: Option<RawObserver>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgent {
    filesystem: Option<RawFilesystem>,
    network: Option<RawNetwork>,
    secrets: Option<BTreeMap<String, RawSecretRule>>,
    containers: Option<RawContainers>,
    resources: Option<RawResources>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFilesystem {
    repo: Option<FsAccess>,
    host: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetwork {
    mode: Option<NetworkMode>,
    allow: Option<Vec<String>>,
    deny_private_networks: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawSecretRule {
    Short(Decision),
    Full(RawSecretRuleFull),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecretRuleFull {
    decision: Decision,
    scope: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawContainers {
    allow: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResources {
    cpu_weight: Option<u64>,
    memory_max: Option<RawScalar>,
    pids_max: Option<u64>,
    disk_quota: Option<RawScalar>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawObserver {
    default: Option<ObserverLevel>,
    step: Option<RawHold>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawHold {
    Word(String),
    List(Vec<String>),
}

impl RawHold {
    fn validate(self) -> Result<HoldSet, PolicyError> {
        match self {
            RawHold::Word(w) if w == "all" => Ok(HoldSet::All),
            RawHold::Word(w) => Err(PolicyError::InvalidHoldSet(w)),
            // An empty list is ambiguous; resolve to the most restrictive reading.
            RawHold::List(items) if items.is_empty() => Ok(HoldSet::All),
            RawHold::List(items) => items
                .into_iter()
                .map(StepPattern::new)
                .collect::<Result<BTreeSet<_>, _>>()
                .map(HoldSet::Patterns),
        }
    }
}

impl TryFrom<RawPolicy> for Policy {
    type Error = PolicyError;

    fn try_from(raw: RawPolicy) -> Result<Self, Self::Error> {
        let agent = raw
            .agent
            .map_or_else(|| Ok(AgentPolicy::default()), AgentPolicy::try_from)?;
        let observer = raw
            .observer
            .map_or_else(|| Ok(ObserverPolicy::default()), ObserverPolicy::try_from)?;
        Ok(Self { agent, observer })
    }
}

impl TryFrom<RawAgent> for AgentPolicy {
    type Error = PolicyError;

    fn try_from(raw: RawAgent) -> Result<Self, Self::Error> {
        let filesystem = raw.filesystem.map(FilesystemPolicy::try_from).transpose()?;
        let network = raw.network.map(NetworkPolicy::try_from).transpose()?;
        let secrets = raw
            .secrets
            .map(|m| {
                m.into_iter()
                    .map(|(k, v)| Ok((ServiceId::new(k)?, SecretRule::try_from(v)?)))
                    .collect::<Result<BTreeMap<_, _>, PolicyError>>()
            })
            .transpose()?;
        let containers = raw.containers.map(|c| ContainersPolicy { allow: c.allow });
        let resources = raw.resources.map(ResourcesPolicy::try_from).transpose()?;
        Ok(Self {
            filesystem,
            network,
            secrets,
            containers,
            resources,
        })
    }
}

impl TryFrom<RawFilesystem> for FilesystemPolicy {
    type Error = PolicyError;

    fn try_from(raw: RawFilesystem) -> Result<Self, Self::Error> {
        let host = match raw.host {
            None => None,
            Some(s) if s == "deny" => Some(HostDenied),
            Some(s) => return Err(PolicyError::HostFilesystemNotDeny(s)),
        };
        Ok(Self {
            repo: raw.repo,
            host,
        })
    }
}

impl TryFrom<RawNetwork> for NetworkPolicy {
    type Error = PolicyError;

    fn try_from(raw: RawNetwork) -> Result<Self, Self::Error> {
        let mode = raw.mode.ok_or(PolicyError::NetworkModeRequired)?;
        if raw.deny_private_networks == Some(false) {
            return Err(PolicyError::PrivateNetworksMustBeDenied);
        }
        let allow = raw
            .allow
            .unwrap_or_default()
            .iter()
            .map(|h| HostPattern::parse(h))
            .collect::<Result<HostSet, _>>()?;
        if !allow.is_empty() && mode != NetworkMode::Custom {
            return Err(PolicyError::AllowRequiresCustomMode(mode.to_string()));
        }
        Ok(Self {
            mode,
            allow,
            deny_private_networks: PrivateNetworksDenied,
        })
    }
}

impl TryFrom<RawSecretRule> for SecretRule {
    type Error = PolicyError;

    fn try_from(raw: RawSecretRule) -> Result<Self, Self::Error> {
        match raw {
            RawSecretRule::Short(decision) => Ok(Self {
                decision,
                scope: None,
            }),
            RawSecretRule::Full(full) => {
                let scope = full
                    .scope
                    .map(|items| {
                        items
                            .into_iter()
                            .map(ScopeItem::new)
                            .collect::<Result<BTreeSet<_>, _>>()
                    })
                    .transpose()?;
                Ok(Self {
                    decision: full.decision,
                    scope,
                })
            }
        }
    }
}

impl TryFrom<RawResources> for ResourcesPolicy {
    type Error = PolicyError;

    fn try_from(raw: RawResources) -> Result<Self, Self::Error> {
        let cpu_weight = raw.cpu_weight.map(CpuWeight::new).transpose()?;
        let memory_max = raw
            .memory_max
            .map(|v| match v {
                RawScalar::Int(n) => ByteSize::new(n).map(MemoryLimit::Bytes),
                RawScalar::Str(s) => MemoryLimit::parse(&s),
            })
            .transpose()?;
        let pids_max = raw.pids_max.map(PidsMax::new).transpose()?;
        let disk_quota = raw
            .disk_quota
            .map(|v| ByteSize::parse(&v.into_string()))
            .transpose()
            .map_err(|e| match e {
                PolicyError::InvalidResource { value, reason, .. } => {
                    PolicyError::InvalidResource {
                        field: "disk_quota",
                        value,
                        reason,
                    }
                }
                other => other,
            })?;
        Ok(Self {
            cpu_weight,
            memory_max,
            pids_max,
            disk_quota,
        })
    }
}

impl TryFrom<RawObserver> for ObserverPolicy {
    type Error = PolicyError;

    fn try_from(raw: RawObserver) -> Result<Self, Self::Error> {
        let step = raw.step.map(RawHold::validate).transpose()?;
        if step.is_some() && raw.default != Some(ObserverLevel::StepThrough) {
            return Err(PolicyError::StepRequiresStepThrough);
        }
        Ok(Self {
            default: raw.default,
            step,
        })
    }
}
