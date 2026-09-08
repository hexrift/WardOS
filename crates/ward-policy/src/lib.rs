//! `ward-policy` — the `WardOS` capability model and three-layer policy merge.
//!
//! A session is described by a [`CapabilityManifest`]. Three policy layers —
//! system, user and project — are merged by [`merge::merge`] into that manifest.
//! The merge is an intersection with `Deny > Ask > Allow`: a lower layer
//! (especially an untrusted project `.ward/policy.yaml`) may deny anything and
//! downgrade allow→ask, but can never widen a capability beyond what the layer
//! above permits. This is guarantee G7 / threat-model ST-007.
//!
//! See `docs/security-model.md` §3 and `docs/threat-model.md` §7.
//!
//! These types are defined locally; integration with `ward-events` comes later.

mod capability;
mod default;
mod ids;
mod merge;
mod policy;

#[cfg(test)]
mod tests;

pub use capability::{
    AccessMode, CapabilityManifest, ContainerCapability, CredentialRule, CredentialScope, Decision,
    DeviceSet, FsCapabilities, NetworkCapability, ObserverMode, RepoSelector, ResourceLimits,
    StepPolicy,
};
pub use default::default_manifest;
pub use ids::{Blake3Hash, ImageDigest, ProjectId, ServiceId, SessionId};
pub use merge::merge;
pub use policy::{Policy, PolicyError};
