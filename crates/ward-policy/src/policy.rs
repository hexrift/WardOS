//! A single policy layer, deserialized from one of the three YAML files.

use crate::capability::{
    ContainerCapability, CredentialRule, DeviceSet, FsCapabilities, NetworkCapability,
    ObserverMode, ResourceLimits,
};
use crate::ids::ServiceId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One layer of policy (`system`, `user` or `project`). Every field is optional
/// so a layer may constrain only the capabilities it cares about; absent fields
/// inherit from the layer above.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Filesystem mounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<FsCapabilities>,
    /// Egress reachability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkCapability>,
    /// Per-service credential rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<BTreeMap<ServiceId, CredentialRule>>,
    /// Nested-container capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containers: Option<ContainerCapability>,
    /// Exposed device nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<DeviceSet>,
    /// Resource ceilings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceLimits>,
    /// Observation mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observer: Option<ObserverMode>,
}

/// Failure to load a policy layer.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The YAML was malformed or did not match the schema.
    #[error("invalid policy YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

impl Policy {
    /// Parse a policy layer from YAML. An empty document yields an empty (fully
    /// inheriting) layer.
    ///
    /// # Errors
    /// Returns [`PolicyError::Yaml`] if the document is malformed or contains
    /// unknown fields.
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        if yaml.trim().is_empty() {
            return Ok(Self::default());
        }
        Ok(serde_yaml::from_str(yaml)?)
    }

    /// The commented project policy `ward init` writes (see [`TEMPLATE`]).
    #[must_use]
    pub const fn template() -> &'static str {
        TEMPLATE
    }
}

/// The project policy `ward init` writes: the secure defaults, spelled out with a
/// comment per block so the file reads as a description of what the agent gets.
/// Every value equals the image default, so the file narrows nothing until a line
/// is edited; it exists so the choices are visible and reviewable in the repo.
const TEMPLATE: &str = "\
# .ward/policy.yaml — what an agent may reach in this project (written by `ward init`).
#
# WardOS merges this file with the host's defaults. A line here can only narrow what
# the agent gets, never widen it; remove a line and the default applies again.
# Reference: docs/security-model.md §3.

# Where the agent may go on the network. `development` reaches package registries,
# code hosts (github.com …) and the agent's own model API, nothing else. Narrower:
# `registries`, `localhost_only`, `offline`; or an explicit host list under `!custom`.
network: development

# What the agent may read and write inside the sandbox (rw: read and write, ro: read
# only, none: not mounted). Host paths outside these never appear in the sandbox.
filesystem:
  worktree: rw # this repository, mounted at /work
  environment: rw # its caches and toolchains, at /env, kept between sessions
  home: rw # a private home, empty at every start
  tmp: rw # scratch space

# Credentials the agent may ask for. Keys never enter the sandbox: the session proxy
# injects them on the way out. `ask` means you approve each grant (a desktop
# notification, or `ward claude --grant github`), limited to this repository and to
# the permissions listed. `deny` refuses without asking.
credentials:
  github: !ask
    repositories: [current_repository]
    permissions: [contents:read, issues:read]

# How closely the session is watched. `live` records every action as it happens, which
# the trust bar and `ward watch` show. `!step_through {pause_before_writes: true}`
# holds each file write (or `pause_before_network`, each request) for your approval.
observer: live
";
