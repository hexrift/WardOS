//! The built-in system default policy matches docs/security-model.md §3.1.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;

use common::{empty, merge_policies};
use ward_policy::hostname::is_subset;
use ward_policy::network::{DEVELOPMENT_EXTRA_HOSTS, PACKAGE_REGISTRY_HOSTS};
use ward_policy::{
    ByteSize, ContainerCapability, CpuWeight, DEFAULT_POLICY_YAML, Decision, FsAccess, HostDenied,
    HostPattern, Layer, MemoryLimit, NetworkMode, ObserverLevel, ObserverMode, Percent, PidsMax,
    Policy, ScopeItem, ServiceId, builtin_allowlist, default_policy, default_resource_limits,
};

fn scope(items: &[&str]) -> BTreeSet<ScopeItem> {
    items.iter().map(|s| ScopeItem::new(*s).unwrap()).collect()
}

#[test]
fn default_policy_parses() {
    default_policy().expect("built-in default policy must parse");
}

#[test]
fn default_policy_matches_documented_values() {
    let p = default_policy().unwrap();
    let fs = p.agent.filesystem.as_ref().unwrap();
    assert_eq!(fs.repo, Some(FsAccess::Write));
    assert_eq!(fs.host, Some(HostDenied));

    let net = p.agent.network.as_ref().unwrap();
    assert_eq!(net.mode, NetworkMode::Development);
    assert!(net.allow.is_empty());

    let secrets = p.agent.secrets.as_ref().unwrap();
    let get = |k: &str| &secrets[&ServiceId::new(k).unwrap()];
    assert_eq!(get("github").decision, Decision::Ask);
    assert_eq!(
        get("github").scope,
        Some(scope(&["repo:current", "contents:read", "issues:read"]))
    );
    assert_eq!(get("npm-publish").decision, Decision::Deny);
    assert_eq!(get("pypi-publish").decision, Decision::Deny);
    assert_eq!(get("cloud-*").decision, Decision::Deny);
    assert_eq!(get("ssh-signing").decision, Decision::Ask);
    assert_eq!(get("ssh-signing").scope, Some(scope(&["per-host"])));
    assert_eq!(secrets.len(), 5);

    assert!(p.agent.containers.unwrap().allow);

    let res = p.agent.resources.unwrap();
    assert_eq!(res.cpu_weight, Some(CpuWeight::new(100).unwrap()));
    assert_eq!(
        res.memory_max,
        Some(MemoryLimit::Percent(Percent::new(50).unwrap()))
    );
    assert_eq!(res.pids_max, Some(PidsMax::new(4096).unwrap()));
    assert_eq!(res.disk_quota, Some(ByteSize::new(20 << 30).unwrap()));

    assert_eq!(p.observer.default, Some(ObserverLevel::Live));
    assert_eq!(p.observer.step, None);
}

#[test]
fn default_resource_limit_constants_match_yaml() {
    let p = default_policy().unwrap();
    let res = p.agent.resources.unwrap();
    let limits = default_resource_limits();
    assert_eq!(Some(limits.cpu_weight), res.cpu_weight);
    assert_eq!(
        limits.memory_max.percent_of_host.map(MemoryLimit::Percent),
        res.memory_max
    );
    assert_eq!(limits.memory_max.bytes, None);
    assert_eq!(Some(limits.pids_max), res.pids_max);
    assert_eq!(Some(limits.disk_quota), res.disk_quota);
}

#[test]
fn default_policy_round_trips() {
    let p = default_policy().unwrap();
    let yaml = p.to_yaml().unwrap();
    assert_eq!(Policy::from_yaml(&yaml).unwrap(), p);
    assert_eq!(Policy::from_yaml(DEFAULT_POLICY_YAML).unwrap(), p);
}

#[test]
fn default_manifest_matches_documented_defaults() {
    let m = merge_policies(&default_policy().unwrap(), &empty(), &empty());
    assert_eq!(m.filesystem.worktree, FsAccess::Write);
    assert_eq!(m.filesystem.env, FsAccess::Write);
    assert_eq!(m.filesystem.home, FsAccess::Write);
    assert_eq!(m.filesystem.tmp, FsAccess::Write);
    assert_eq!(m.filesystem.host, HostDenied);

    assert_eq!(m.network.mode, NetworkMode::Development);
    assert!(m.network.permits_host("github.com"));
    assert!(m.network.permits_host("registry.npmjs.org"));
    assert!(m.network.permits_host("api.anthropic.com"));
    assert!(!m.network.permits_host("example.com"));
    assert!(!m.network.permits_host("10.0.0.1"));

    let github = m.credential("github");
    assert_eq!(github.decision, Decision::Ask);
    assert!(!github.hard);
    assert_eq!(
        github.scope,
        scope(&["repo:current", "contents:read", "issues:read"])
    );
    let npm = m.credential("npm-publish");
    assert_eq!(npm.decision, Decision::Deny);
    assert!(npm.hard);
    assert_eq!(npm.denied_by, Some(Layer::System));
    let cloud = m.credential("cloud-aws-production");
    assert_eq!(cloud.decision, Decision::Deny);
    assert!(cloud.hard);
    let unknown = m.credential("something-unlisted");
    assert_eq!(unknown.decision, Decision::Deny);
    assert!(unknown.hard);

    assert_eq!(m.containers, ContainerCapability::NestedRootless);
    assert!(m.devices.is_empty());
    assert_eq!(m.resources, default_resource_limits());
    assert_eq!(m.observer, ObserverMode::Live);
}

#[test]
fn builtin_host_lists_are_valid_and_nested() {
    for h in PACKAGE_REGISTRY_HOSTS.iter().chain(DEVELOPMENT_EXTRA_HOSTS) {
        HostPattern::parse(h).unwrap_or_else(|e| panic!("{h}: {e}"));
    }
    let registries = builtin_allowlist(NetworkMode::PackageRegistries);
    let development = builtin_allowlist(NetworkMode::Development);
    assert_eq!(registries.len(), PACKAGE_REGISTRY_HOSTS.len());
    assert_eq!(
        development.len(),
        PACKAGE_REGISTRY_HOSTS.len() + DEVELOPMENT_EXTRA_HOSTS.len()
    );
    assert!(is_subset(&registries, &development));
    assert!(!is_subset(&development, &registries));
    for mode in [
        NetworkMode::Offline,
        NetworkMode::LocalhostOnly,
        NetworkMode::Custom,
        NetworkMode::Unrestricted,
    ] {
        assert!(builtin_allowlist(mode).is_empty());
    }
}
