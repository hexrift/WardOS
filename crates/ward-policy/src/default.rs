//! The image-shipped default manifest (security-model §3.1).

use crate::capability::{
    AccessMode, CapabilityManifest, ContainerCapability, CredentialRule, CredentialScope,
    DeviceSet, FsCapabilities, NetworkCapability, ObserverMode, RepoSelector, ResourceLimits,
};
use crate::ids::{Blake3Hash, ImageDigest, ProjectId, ServiceId, SessionId};
use crate::merge::policy_hash;
use std::collections::{BTreeMap, BTreeSet};

/// Placeholder identity used before a manifest is bound to a live session.
const PLACEHOLDER: &str = "default";

/// The default capability manifest: the starting point every policy layer narrows.
///
/// Matches security-model §3.1 — worktree/env/home/tmp read-write, development
/// network, GitHub scoped-ask, publish and cloud denied, nested rootless
/// containers, live observer.
#[must_use]
pub fn default_manifest() -> CapabilityManifest {
    let mut manifest = CapabilityManifest {
        session: SessionId(PLACEHOLDER.to_owned()),
        project: ProjectId(PLACEHOLDER.to_owned()),
        policy_hash: Blake3Hash([0u8; 32]),
        filesystem: FsCapabilities {
            worktree: AccessMode::ReadWrite,
            environment: AccessMode::ReadWrite,
            home: AccessMode::ReadWrite,
            tmp: AccessMode::ReadWrite,
            extra: BTreeMap::new(),
        },
        network: NetworkCapability::Development,
        credentials: default_credentials(),
        containers: ContainerCapability::NestedRootless,
        devices: DeviceSet::default(),
        resources: ResourceLimits {
            cpu_weight: 100,
            memory_percent: 50,
            pids: 4096,
            disk_gib: 20,
        },
        observer: ObserverMode::Live,
        tool_images: Vec::new(),
        agent_image: ImageDigest(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        ),
    };
    manifest.policy_hash = policy_hash(&manifest);
    manifest
}

fn default_credentials() -> BTreeMap<ServiceId, CredentialRule> {
    let github = CredentialScope {
        repositories: BTreeSet::from([RepoSelector::CurrentRepository]),
        permissions: BTreeSet::from(["contents:read".to_owned(), "issues:read".to_owned()]),
    };
    BTreeMap::from([
        (ServiceId("github".to_owned()), CredentialRule::Ask(github)),
        (ServiceId("npm-publish".to_owned()), CredentialRule::Deny),
        (ServiceId("pypi-publish".to_owned()), CredentialRule::Deny),
        (ServiceId("cloud-*".to_owned()), CredentialRule::Deny),
        (
            ServiceId("ssh-signing".to_owned()),
            CredentialRule::Ask(CredentialScope::default()),
        ),
    ])
}
