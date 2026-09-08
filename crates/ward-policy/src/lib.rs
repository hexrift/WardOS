//! `ward-policy` — policy schema, three-layer merge and capability manifest.
//!
//! See `docs/security-model.md` §3 (capability model), `docs/threat-model.md` §7 (merge
//! rule) and `docs/architecture.md` §7 (network modes).
//!
//! # Overview
//!
//! * [`Policy`] is one parsed and validated layer (`/etc/ward/policy.d/*.yaml`,
//!   `~/.config/ward/policy.yaml`, `<project>/.ward/policy.yaml`). Unknown fields, a
//!   host filesystem `allow`, or `deny_private_networks: false` are hard parse errors.
//! * [`merge`] intersects the three layers into a [`CapabilityManifest`]. A lower layer
//!   may deny anything, may `ask` for anything the upper layer allows, and may `allow`
//!   only what the upper layer allows. The exact per-section rules are documented on
//!   [`merge`](mod@merge) and [`NetworkCapability::narrow`].
//! * [`policy_hash`] and [`manifest_hash`] are BLAKE3 over a canonical, key-sorted
//!   encoding.
//! * [`DEFAULT_POLICY_YAML`] is the built-in system default (`docs/security-model.md`
//!   §3.1); [`load_layers`] overlays it with the system directory and reads the user
//!   and project files with size caps.
//!
//! # Fail-closed guarantees
//!
//! * [`Decision`] has no `Default`; nothing produces `Allow` from missing data.
//! * Anything the system layer does not mention is not granted (the *floor*).
//! * A credential service matched by no rule is denied
//!   ([`CapabilityManifest::credential`]).
//! * Host filesystem access and private-network egress cannot be represented as allowed.

pub mod defaults;
pub mod error;
pub mod hash;
pub mod hostname;
pub mod loader;
pub mod manifest;
pub mod merge;
pub mod network;
pub mod schema;
pub mod service;
pub mod types;

pub use defaults::{DEFAULT_POLICY_YAML, default_policy, default_resource_limits};
pub use error::{LoadError, PolicyError};
pub use hash::{canonical_bytes, manifest_hash, policy_hash};
pub use hostname::{HostPattern, HostSet};
pub use loader::{LayerSources, Layers, MAX_POLICY_FILE_BYTES, load_layers};
pub use manifest::{
    CapabilityManifest, ContainerCapability, CredentialRule, DeviceSet, FsCapabilities, MemoryMax,
    ObserverMode, ResourceLimits, StepPolicy,
};
pub use merge::{ManifestIdentity, is_narrowing, merge};
pub use network::{NetworkCapability, NetworkMode, NetworkRequest, builtin_allowlist};
pub use schema::{
    AgentPolicy, ContainersPolicy, FilesystemPolicy, HoldSet, NetworkPolicy, ObserverLevel,
    ObserverPolicy, Policy, ResourcesPolicy, SecretRule,
};
pub use service::{ScopeItem, ServiceId, StepPattern};
pub use types::{
    Blake3Hash, ByteSize, CpuWeight, Decision, FsAccess, HostDenied, ImageDigest, Layer,
    MemoryLimit, Percent, PidsMax, PrivateNetworksDenied, ProjectId, SessionId, SnapshotId,
};
