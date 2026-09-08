//! Property tests over random layers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{empty, identity, merge_policies};
use proptest::prelude::*;
use ward_policy::{
    AgentPolicy, ByteSize, CapabilityManifest, ContainersPolicy, CpuWeight, Decision,
    FilesystemPolicy, FsAccess, HoldSet, HostDenied, HostPattern, HostSet, Layer, MemoryLimit,
    NetworkCapability, NetworkMode, NetworkPolicy, NetworkRequest, ObserverLevel, ObserverPolicy,
    Percent, PidsMax, Policy, PrivateNetworksDenied, ResourcesPolicy, ScopeItem, SecretRule,
    ServiceId, StepPattern, merge, policy_hash,
};

const HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "*.github.com",
    "*.githubusercontent.com",
    "registry.npmjs.org",
    "pypi.org",
    "*.example.com",
    "api.example.com",
    "*.sub.example.com",
    "evil.example",
];

const SERVICES: &[&str] = &[
    "github",
    "npm-publish",
    "cloud-*",
    "cloud-dev",
    "ssh-signing",
    "*",
    "svc-a",
    "svc-*",
];
const CONCRETE_SERVICES: &[&str] = &[
    "github",
    "npm-publish",
    "cloud-dev",
    "cloud-prod",
    "ssh-signing",
    "svc-a",
    "svc-b",
    "other",
];
const SCOPES: &[&str] = &[
    "repo:current",
    "contents:read",
    "issues:read",
    "per-host",
    "admin",
];
const STEPS: &[&str] = &["src/**", "tests/**", "*.sh", "Cargo.toml"];

fn decision() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Deny),
        Just(Decision::Ask),
        Just(Decision::Allow)
    ]
}

fn network_mode() -> impl Strategy<Value = NetworkMode> {
    prop_oneof![
        Just(NetworkMode::Offline),
        Just(NetworkMode::LocalhostOnly),
        Just(NetworkMode::PackageRegistries),
        Just(NetworkMode::Development),
        Just(NetworkMode::Custom),
        Just(NetworkMode::Unrestricted),
    ]
}

fn host_set() -> impl Strategy<Value = HostSet> {
    proptest::sample::subsequence(HOSTS, 0..HOSTS.len()).prop_map(|names| {
        names
            .into_iter()
            .map(|n| HostPattern::parse(n).unwrap())
            .collect()
    })
}

fn network() -> impl Strategy<Value = NetworkPolicy> {
    (network_mode(), host_set()).prop_map(|(mode, allow)| NetworkPolicy {
        mode,
        allow: if mode == NetworkMode::Custom {
            allow
        } else {
            HostSet::new()
        },
        deny_private_networks: PrivateNetworksDenied,
    })
}

fn scope() -> impl Strategy<Value = Option<BTreeSet<ScopeItem>>> {
    proptest::option::of(
        proptest::sample::subsequence(SCOPES, 0..SCOPES.len()).prop_map(|items| {
            items
                .into_iter()
                .map(|s| ScopeItem::new(s).unwrap())
                .collect()
        }),
    )
}

fn secrets() -> impl Strategy<Value = BTreeMap<ServiceId, SecretRule>> {
    proptest::collection::btree_map(
        proptest::sample::select(SERVICES).prop_map(|s| ServiceId::new(s).unwrap()),
        (decision(), scope()).prop_map(|(decision, scope)| SecretRule { decision, scope }),
        0..5,
    )
}

fn fs_access() -> impl Strategy<Value = FsAccess> {
    prop_oneof![Just(FsAccess::Read), Just(FsAccess::Write)]
}

fn resources() -> impl Strategy<Value = ResourcesPolicy> {
    (
        proptest::option::of((1u64..=10_000).prop_map(|v| CpuWeight::new(v).unwrap())),
        proptest::option::of(prop_oneof![
            (1u64..=100).prop_map(|p| MemoryLimit::Percent(Percent::new(p).unwrap())),
            (1u64..=64).prop_map(|g| MemoryLimit::Bytes(ByteSize::new(g << 30).unwrap())),
        ]),
        proptest::option::of((1u64..=100_000).prop_map(|v| PidsMax::new(v).unwrap())),
        proptest::option::of((1u64..=100).prop_map(|g| ByteSize::new(g << 30).unwrap())),
    )
        .prop_map(
            |(cpu_weight, memory_max, pids_max, disk_quota)| ResourcesPolicy {
                cpu_weight,
                memory_max,
                pids_max,
                disk_quota,
            },
        )
}

fn observer() -> impl Strategy<Value = ObserverPolicy> {
    let level = prop_oneof![
        Just(ObserverLevel::Quiet),
        Just(ObserverLevel::Live),
        Just(ObserverLevel::StepThrough)
    ];
    let hold = prop_oneof![
        Just(HoldSet::All),
        proptest::sample::subsequence(STEPS, 1..STEPS.len()).prop_map(|s| HoldSet::Patterns(
            s.into_iter()
                .map(|p| StepPattern::new(p).unwrap())
                .collect()
        )),
    ];
    (proptest::option::of(level), proptest::option::of(hold)).prop_map(|(default, step)| {
        ObserverPolicy {
            default,
            step: if default == Some(ObserverLevel::StepThrough) {
                step
            } else {
                None
            },
        }
    })
}

fn policy() -> impl Strategy<Value = Policy> {
    (
        proptest::option::of(fs_access()),
        proptest::option::of(network()),
        proptest::option::of(secrets()),
        proptest::option::of(any::<bool>()),
        proptest::option::of(resources()),
        observer(),
    )
        .prop_map(
            |(repo, network, secrets, containers, resources, observer)| Policy {
                agent: AgentPolicy {
                    filesystem: repo.map(|repo| FilesystemPolicy {
                        repo: Some(repo),
                        host: Some(HostDenied),
                    }),
                    network,
                    secrets,
                    containers: containers.map(|allow| ContainersPolicy { allow }),
                    resources,
                },
                observer,
            },
        )
}

/// A layer's own verdict for a concrete service, if it mentions it.
fn layer_verdict(p: &Policy, service: &str) -> Option<Decision> {
    p.agent
        .secrets
        .as_ref()?
        .iter()
        .filter(|(k, _)| k.matches(service))
        .map(|(_, r)| r.decision)
        .min()
}

/// Every explicit restriction in `layer` is honoured by `m`.
fn layer_restrictions_honoured(p: &Policy, layer: Layer, m: &CapabilityManifest) {
    if let Some(FsAccess::Read) = p.agent.filesystem.as_ref().and_then(|f| f.repo) {
        assert_eq!(m.filesystem.worktree, FsAccess::Read, "{layer}: repo read");
    }
    if let Some(n) = &p.agent.network {
        let standalone = NetworkCapability::standalone(
            NetworkRequest {
                mode: n.mode,
                allow: &n.allow,
            },
            layer,
        );
        assert!(
            m.network.is_within(&standalone),
            "{layer}: network {n:?} vs {:?}",
            m.network
        );
    }
    for service in CONCRETE_SERVICES {
        if let Some(d) = layer_verdict(p, service) {
            assert!(
                m.credential(service).decision <= d,
                "{layer}: secret {service}"
            );
        }
    }
    if let Some(ContainersPolicy { allow: false }) = p.agent.containers {
        assert!(!m.containers.is_allowed(), "{layer}: containers");
    }
    if let Some(r) = &p.agent.resources {
        if let Some(c) = r.cpu_weight {
            assert!(m.resources.cpu_weight <= c, "{layer}: cpu");
        }
        if let Some(pm) = r.pids_max {
            assert!(m.resources.pids_max <= pm, "{layer}: pids");
        }
        if let Some(d) = r.disk_quota {
            assert!(m.resources.disk_quota <= d, "{layer}: disk");
        }
        match r.memory_max {
            Some(MemoryLimit::Bytes(b)) => {
                assert!(m.resources.memory_max.bytes.is_some_and(|x| x <= b));
            }
            Some(MemoryLimit::Percent(p)) => {
                assert!(
                    m.resources
                        .memory_max
                        .percent_of_host
                        .is_some_and(|x| x <= p)
                );
            }
            None => {}
        }
    }
    if let Some(level) = p.observer.default {
        assert!(m.observer.level() >= level, "{layer}: observer");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn merge_never_grants_what_any_layer_restricted(s in policy(), u in policy(), p in policy()) {
        let m = merge_policies(&s, &u, &p);
        // The system layer is the root: its restrictions hold as written.
        layer_restrictions_honoured(&s, Layer::System, &m);
        layer_restrictions_honoured(&u, Layer::User, &m);
        layer_restrictions_honoured(&p, Layer::Project, &m);
    }

    #[test]
    fn merge_is_monotone_in_lower_layers(s in policy(), u in policy(), p in policy()) {
        // The ceiling for the user layer is what the system *grants*. For every section
        // that is merge(s, ∅, ∅), except network when the system grants `unrestricted`:
        // a silent user layer is deliberately clamped to `development`, while an explicit
        // user opt-in (or any explicit narrower mode) is still within the system grant.
        let mut system_grant = merge_policies(&s, &empty(), &empty());
        if let Some(n) = &s.agent.network {
            system_grant.network = NetworkCapability::standalone(
                NetworkRequest { mode: n.mode, allow: &n.allow },
                Layer::System,
            );
        }
        let with_user = merge_policies(&s, &u, &empty());
        let full = merge_policies(&s, &u, &p);
        prop_assert!(with_user.is_within(&system_grant), "user widened: {with_user:#?} vs {system_grant:#?}");
        prop_assert!(full.is_within(&with_user), "project widened: {full:#?} vs {with_user:#?}");
        prop_assert!(full.is_within(&system_grant));
    }

    #[test]
    fn project_cannot_widen_anything(s in policy(), u in policy(), p in policy()) {
        let without = merge_policies(&s, &u, &empty());
        let with = merge_policies(&s, &u, &p);
        prop_assert!(with.filesystem.worktree <= without.filesystem.worktree);
        prop_assert!(with.network.is_within(&without.network));
        for service in CONCRETE_SERVICES {
            prop_assert!(with.credential(service).is_within(&without.credential(service)), "{service}");
        }
        prop_assert!(with.containers.is_within(without.containers));
        prop_assert!(with.resources.is_within(without.resources));
        prop_assert!(with.observer.is_within(&without.observer));
    }

    #[test]
    fn hard_denials_survive_any_lower_layers(s in policy(), u in policy(), p in policy()) {
        let m = merge_policies(&s, &u, &p);
        for service in CONCRETE_SERVICES {
            if layer_verdict(&s, service).is_none_or(Decision::is_deny) {
                let r = m.credential(service);
                prop_assert_eq!(r.decision, Decision::Deny);
                prop_assert!(r.hard, "{}: {:?}", service, r);
                prop_assert_eq!(r.denied_by, Some(Layer::System));
            }
        }
        if !matches!(s.agent.containers, Some(ContainersPolicy { allow: true })) {
            prop_assert_eq!(m.containers, ward_policy::ContainerCapability::Denied { hard: true, denied_by: Layer::System });
        }
    }

    #[test]
    fn unrestricted_requires_user_opt_in_and_project_never_grants_it(s in policy(), u in policy(), p in policy()) {
        let m = merge_policies(&s, &u, &p);
        let user_opted_in = u.agent.network.as_ref().is_some_and(|n| n.mode == NetworkMode::Unrestricted);
        let system_allows = s.agent.network.as_ref().is_some_and(|n| n.mode == NetworkMode::Unrestricted);
        if m.network.mode == NetworkMode::Unrestricted {
            prop_assert!(user_opted_in && system_allows);
        }
        let project_only = merge_policies(&s, &empty(), &p);
        prop_assert_ne!(project_only.network.mode, NetworkMode::Unrestricted);
    }

    #[test]
    fn merge_is_deterministic_and_hash_matches(s in policy(), u in policy(), p in policy()) {
        let a = merge(&s, &u, &p, identity()).unwrap();
        let b = merge(&s, &u, &p, identity()).unwrap();
        prop_assert_eq!(&a, &b);
        prop_assert_eq!(a.policy_hash, policy_hash(&s, &u, &p).unwrap());
        prop_assert_eq!(ward_policy::manifest_hash(&a).unwrap(), ward_policy::manifest_hash(&b).unwrap());
    }

    #[test]
    fn policy_yaml_round_trip(p in policy()) {
        let yaml = p.to_yaml().unwrap();
        let back = Policy::from_yaml(&yaml).unwrap();
        prop_assert_eq!(&back, &p);
        prop_assert_eq!(policy_hash(&back, &empty(), &empty()).unwrap(), policy_hash(&p, &empty(), &empty()).unwrap());
    }

    #[test]
    fn manifest_yaml_round_trip(s in policy(), u in policy(), p in policy()) {
        let m = merge_policies(&s, &u, &p);
        let yaml = serde_yaml::to_string(&m).unwrap();
        let back: CapabilityManifest = serde_yaml::from_str(&yaml).unwrap();
        prop_assert_eq!(back, m);
    }

    #[test]
    fn credential_lookup_is_fail_closed_and_within_listed_rules(s in policy(), u in policy(), p in policy()) {
        let m = merge_policies(&s, &u, &p);
        for service in CONCRETE_SERVICES {
            let r = m.credential(service);
            let listed: Vec<_> = m.credentials.iter().filter(|(k, _)| k.matches(service)).collect();
            if listed.is_empty() {
                prop_assert_eq!(r.decision, Decision::Deny);
                prop_assert!(r.hard);
            } else {
                let min = listed.iter().map(|(_, v)| v.decision).min().unwrap();
                prop_assert_eq!(r.decision, min);
            }
            if r.decision.is_deny() {
                prop_assert!(r.scope.is_empty());
                prop_assert!(r.denied_by.is_some());
            }
        }
    }

    #[test]
    fn host_set_intersection_is_sound(a in host_set(), b in host_set()) {
        let i = ward_policy::hostname::intersect(&a, &b);
        prop_assert!(ward_policy::hostname::is_subset(&i, &a));
        prop_assert!(ward_policy::hostname::is_subset(&i, &b));
        // Every concrete host matched by both is matched by the intersection.
        for host in ["github.com", "api.github.com", "x.y.github.com", "api.example.com", "a.sub.example.com", "evil.example", "pypi.org"] {
            let both = ward_policy::hostname::set_matches_host(&a, host) && ward_policy::hostname::set_matches_host(&b, host);
            prop_assert_eq!(both, ward_policy::hostname::set_matches_host(&i, host), "{}", host);
        }
    }
}
