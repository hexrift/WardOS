//! A session's capability manifest compiled into what an admission envelope grants
//! (ADR-0040 §4).
//!
//! The node path runs a policy only when the node enforces it as the session would:
//! exactly, or not at all. Every capability the session enforces is either carried into
//! the envelope's manifest or named as a refusal; nothing is dropped and nothing is
//! approximated. The `registries` and `development` presets are the host lists the session
//! proxy matches them with (`ward_policy::hosts`), so they compile to `network.custom` with
//! exactly those hosts, which the node's proxy matches with the same rules. Containers, devices and resource ceilings are not compiled: the
//! session's runtime does not enforce them from the policy either.

use ward_node_protocol::{HostAllowlist, NetworkGrant};
use ward_policy::{
    AccessMode, CapabilityManifest, CredentialRule, NetworkCapability, ObserverMode, hosts,
};

/// The envelope's network grant for `manifest`, or every capability it needs that the
/// node cannot enforce exactly, each naming the policy key.
pub(crate) fn compile(manifest: &CapabilityManifest) -> Result<NetworkGrant, Vec<String>> {
    let mut refused = Vec::new();
    let network = network(&manifest.network).map_err(|reason| refused.push(reason));
    filesystem(manifest, &mut refused);
    for (service, rule) in &manifest.credentials {
        let decision = match rule {
            CredentialRule::Deny => continue,
            CredentialRule::Ask(_) => "ask",
            CredentialRule::Allow(_) => "allow",
        };
        refused.push(format!(
            "credentials.{}: {decision}: the node brokers only the services its operator \
             configures, granted per attempt",
            service.0
        ));
    }
    if let ObserverMode::StepThrough(_) = manifest.observer {
        refused.push(
            "observer: step_through: the node holds no file write or request for a \
             step-through approval"
                .to_owned(),
        );
    }
    match network {
        Ok(network) if refused.is_empty() => Ok(network),
        _ => Err(refused),
    }
}

fn network(network: &NetworkCapability) -> Result<NetworkGrant, String> {
    let (name, hosts): (&str, Vec<String>) = match network {
        NetworkCapability::Offline => return Ok(NetworkGrant::Offline),
        NetworkCapability::Custom(hosts) => ("!custom", hosts.iter().cloned().collect()),
        NetworkCapability::Registries => ("registries", preset(&[hosts::REGISTRY_HOSTS])),
        NetworkCapability::Development => (
            "development",
            preset(&[hosts::REGISTRY_HOSTS, hosts::DEVELOPMENT_HOSTS]),
        ),
        NetworkCapability::LocalhostOnly => return Err(unspelled("localhost_only")),
        NetworkCapability::Unrestricted => return Err(unspelled("unrestricted")),
    };
    HostAllowlist::new(hosts.clone())
        .map(NetworkGrant::Custom)
        .map_err(|e| format!("network: {name} {}: {e}", hosts.join(", ")))
}

fn preset(lists: &[&[&str]]) -> Vec<String> {
    lists
        .iter()
        .flat_map(|list| list.iter().map(|host| (*host).to_owned()))
        .collect()
}

fn unspelled(name: &str) -> String {
    format!(
        "network: {name}: the node's proxy has no rule for it; name the hosts under \
         `network: !custom`, or use `offline`"
    )
}

fn filesystem(manifest: &CapabilityManifest, refused: &mut Vec<String>) {
    let fs = &manifest.filesystem;
    for (key, mode, gives) in [
        (
            "worktree",
            fs.worktree,
            "a writable copy of the project at /work, never the worktree itself",
        ),
        (
            "environment",
            fs.environment,
            "a private, empty, writable /env",
        ),
        ("home", fs.home, "a private, empty, writable home"),
        ("tmp", fs.tmp, "a private, empty, writable /tmp"),
    ] {
        if mode != AccessMode::ReadWrite {
            refused.push(format!(
                "filesystem.{key}: {}: the node gives every attempt {gives}",
                access(mode)
            ));
        }
    }
    if !fs.extra.is_empty() {
        let paths: Vec<String> = fs.extra.keys().map(|p| p.display().to_string()).collect();
        refused.push(format!(
            "filesystem.extra: {}: the node mounts nothing beyond /work, /env, the home and /tmp",
            paths.join(", ")
        ));
    }
}

const fn access(mode: AccessMode) -> &'static str {
    match mode {
        AccessMode::None => "none",
        AccessMode::ReadOnly => "ro",
        AccessMode::ReadWrite => "rw",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use ward_policy::{CredentialScope, ServiceId, StepPolicy, default_manifest};

    use super::*;

    fn runnable() -> CapabilityManifest {
        let mut manifest = default_manifest();
        manifest.network = NetworkCapability::Offline;
        manifest.credentials =
            BTreeMap::from([(ServiceId("github".to_owned()), CredentialRule::Deny)]);
        manifest
    }

    #[test]
    fn an_offline_policy_with_no_brokered_credential_compiles_to_offline() {
        assert_eq!(compile(&runnable()).unwrap(), NetworkGrant::Offline);
    }

    #[test]
    fn a_custom_allowlist_compiles_to_the_same_hosts() {
        let mut manifest = runnable();
        manifest.network = NetworkCapability::Custom(BTreeSet::from([
            "crates.io".to_owned(),
            "*.github.com".to_owned(),
        ]));
        let NetworkGrant::Custom(hosts) = compile(&manifest).unwrap() else {
            panic!("a custom allowlist must stay custom");
        };
        assert_eq!(hosts.patterns(), ["*.github.com", "crates.io"]);
    }

    #[test]
    fn a_host_outside_the_node_grammar_is_refused_by_name() {
        let mut manifest = runnable();
        manifest.network = NetworkCapability::Custom(BTreeSet::from(["Example.COM".to_owned()]));
        let refused = compile(&manifest).unwrap_err();
        assert_eq!(refused.len(), 1);
        assert!(
            refused[0].starts_with("network: !custom Example.COM"),
            "{refused:?}"
        );
    }

    #[test]
    fn the_registry_and_development_presets_compile_to_the_session_proxys_host_lists() {
        let mut manifest = runnable();
        manifest.network = NetworkCapability::Registries;
        let NetworkGrant::Custom(registries) = compile(&manifest).unwrap() else {
            panic!("registries must compile to its hosts");
        };
        assert_eq!(registries.patterns(), hosts::REGISTRY_HOSTS);
        manifest.network = NetworkCapability::Development;
        let NetworkGrant::Custom(development) = compile(&manifest).unwrap() else {
            panic!("development must compile to its hosts");
        };
        let expected: Vec<&str> = hosts::REGISTRY_HOSTS
            .iter()
            .chain(hosts::DEVELOPMENT_HOSTS)
            .copied()
            .collect();
        assert_eq!(development.patterns(), expected);
    }

    #[test]
    fn loopback_only_and_unrestricted_egress_are_refused_by_name_never_narrowed() {
        for (network, name) in [
            (NetworkCapability::LocalhostOnly, "localhost_only"),
            (NetworkCapability::Unrestricted, "unrestricted"),
        ] {
            let mut manifest = runnable();
            manifest.network = network;
            let refused = compile(&manifest).unwrap_err();
            assert_eq!(refused.len(), 1, "{refused:?}");
            assert!(
                refused[0].starts_with(&format!("network: {name}:")),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn the_default_policy_is_refused_for_its_asked_credentials_alone() {
        let refused = compile(&default_manifest()).unwrap_err();
        assert!(
            refused
                .iter()
                .all(|r| r.starts_with("credentials.") && r.contains(": ask: ")),
            "{refused:?}"
        );
        assert!(
            refused
                .iter()
                .any(|r| r.starts_with("credentials.github: ask"))
        );
    }

    #[test]
    fn a_brokered_credential_is_refused_whether_asked_or_allowed() {
        let mut manifest = runnable();
        manifest.credentials = BTreeMap::from([
            (
                ServiceId("anthropic".to_owned()),
                CredentialRule::Allow(CredentialScope::default()),
            ),
            (
                ServiceId("github".to_owned()),
                CredentialRule::Ask(CredentialScope::default()),
            ),
            (ServiceId("npm-publish".to_owned()), CredentialRule::Deny),
        ]);
        assert_eq!(
            compile(&manifest).unwrap_err(),
            [
                "credentials.anthropic: allow: the node brokers only the services its operator \
                 configures, granted per attempt",
                "credentials.github: ask: the node brokers only the services its operator \
                 configures, granted per attempt",
            ]
        );
    }

    #[test]
    fn step_through_observation_is_refused() {
        let mut manifest = runnable();
        manifest.observer = ObserverMode::StepThrough(StepPolicy {
            pause_before_writes: true,
            pause_before_network: false,
        });
        let refused = compile(&manifest).unwrap_err();
        assert_eq!(refused.len(), 1);
        assert!(refused[0].starts_with("observer: step_through"));
        manifest.observer = ObserverMode::Quiet;
        assert!(compile(&manifest).is_ok());
    }

    #[test]
    fn a_narrower_mount_than_the_node_gives_is_refused_by_key() {
        let mut manifest = runnable();
        manifest.filesystem.worktree = AccessMode::ReadOnly;
        manifest.filesystem.environment = AccessMode::None;
        manifest.filesystem.home = AccessMode::ReadOnly;
        manifest.filesystem.tmp = AccessMode::None;
        manifest
            .filesystem
            .extra
            .insert(PathBuf::from("/data"), AccessMode::ReadOnly);
        let refused = compile(&manifest).unwrap_err();
        let keys: Vec<&str> = refused
            .iter()
            .map(|r| r.split(':').next().unwrap())
            .collect();
        assert_eq!(
            keys,
            [
                "filesystem.worktree",
                "filesystem.environment",
                "filesystem.home",
                "filesystem.tmp",
                "filesystem.extra",
            ]
        );
        assert!(refused[0].contains(": ro: "));
        assert!(refused[1].contains(": none: "));
        assert!(refused[4].contains("/data"));
    }
}
