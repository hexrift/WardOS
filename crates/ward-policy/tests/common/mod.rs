//! Shared helpers for the integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ward_policy::{
    CapabilityManifest, ImageDigest, ManifestIdentity, Policy, ProjectId, SessionId, merge,
};

pub const AGENT_IMAGE: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub const TOOL_IMAGE: &str =
    "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

pub fn identity() -> ManifestIdentity {
    ManifestIdentity {
        session: SessionId::new("sess-0001").unwrap(),
        project: ProjectId::new("proj-demo").unwrap(),
        agent_image: ImageDigest::new(AGENT_IMAGE).unwrap(),
        tool_images: vec![ImageDigest::new(TOOL_IMAGE).unwrap()],
    }
}

/// Parses a YAML policy, panicking on error (tests only).
pub fn policy(yaml: &str) -> Policy {
    match Policy::from_yaml(yaml) {
        Ok(p) => p,
        Err(e) => panic!("policy failed to parse: {e}\n---\n{yaml}"),
    }
}

/// The empty (inherit-everything) policy.
pub fn empty() -> Policy {
    Policy::default()
}

/// Merges three YAML documents with the test identity.
pub fn merge_yaml(system: &str, user: &str, project: &str) -> CapabilityManifest {
    merge(&policy(system), &policy(user), &policy(project), identity()).unwrap()
}

/// Merges three policies with the test identity.
pub fn merge_policies(system: &Policy, user: &Policy, project: &Policy) -> CapabilityManifest {
    merge(system, user, project, identity()).unwrap()
}
