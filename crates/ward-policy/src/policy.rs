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
}
