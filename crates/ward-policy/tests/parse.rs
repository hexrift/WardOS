//! Schema parsing and validation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;

use common::policy;
use ward_policy::{
    ByteSize, CpuWeight, Decision, FsAccess, HoldSet, HostDenied, MemoryLimit, NetworkMode,
    ObserverLevel, Percent, PidsMax, Policy, PolicyError, ScopeItem, ServiceId, StepPattern,
};

const FULL: &str = r"
agent:
  filesystem:
    repo: write
    host: deny
  network:
    mode: custom
    allow: [Registry.NPMJS.org, '*.githubusercontent.com']
    deny_private_networks: true
  secrets:
    github:
      decision: ask
      scope: [repo:current, contents:read]
    npm-publish: deny
    'cloud-*': deny
  containers:
    allow: false
  resources:
    cpu_weight: 50
    memory_max: 8GiB
    pids_max: 1024
    disk_quota: 10GiB
observer:
  default: step-through
  step: ['src/**', 'scripts/*.sh']
";

#[test]
fn parses_full_document() {
    let p = policy(FULL);
    let fs = p.agent.filesystem.unwrap();
    assert_eq!(fs.repo, Some(FsAccess::Write));
    assert_eq!(fs.host, Some(HostDenied));
    let net = p.agent.network.unwrap();
    assert_eq!(net.mode, NetworkMode::Custom);
    let hosts: Vec<String> = net.allow.iter().map(ToString::to_string).collect();
    assert_eq!(hosts, vec!["*.githubusercontent.com", "registry.npmjs.org"]);
    let secrets = p.agent.secrets.unwrap();
    let github = &secrets[&ServiceId::new("github").unwrap()];
    assert_eq!(github.decision, Decision::Ask);
    assert_eq!(
        github.scope.clone().unwrap(),
        ["repo:current", "contents:read"]
            .into_iter()
            .map(|s| ScopeItem::new(s).unwrap())
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        secrets[&ServiceId::new("npm-publish").unwrap()].decision,
        Decision::Deny
    );
    assert!(secrets.contains_key(&ServiceId::new("cloud-*").unwrap()));
    assert!(!p.agent.containers.unwrap().allow);
    let res = p.agent.resources.unwrap();
    assert_eq!(res.cpu_weight, Some(CpuWeight::new(50).unwrap()));
    assert_eq!(
        res.memory_max,
        Some(MemoryLimit::Bytes(ByteSize::new(8 << 30).unwrap()))
    );
    assert_eq!(res.pids_max, Some(PidsMax::new(1024).unwrap()));
    assert_eq!(res.disk_quota, Some(ByteSize::new(10 << 30).unwrap()));
    assert_eq!(p.observer.default, Some(ObserverLevel::StepThrough));
    assert_eq!(
        p.observer.step,
        Some(HoldSet::Patterns(
            ["src/**", "scripts/*.sh"]
                .into_iter()
                .map(|s| StepPattern::new(s).unwrap())
                .collect()
        ))
    );
}

#[test]
fn empty_document_is_empty_policy() {
    assert!(policy("").is_empty());
    assert!(policy("# only a comment\n").is_empty());
    assert!(policy("agent: {}\n").is_empty());
    assert_eq!(policy(""), Policy::default());
}

#[test]
fn unknown_top_level_field_is_error() {
    let err = Policy::from_yaml("agent: {}\nextra: 1\n").unwrap_err();
    assert!(matches!(err, PolicyError::Yaml(_)), "{err}");
    assert!(err.to_string().contains("unknown field"), "{err}");
}

#[test]
fn unknown_nested_field_is_error() {
    for doc in [
        "agent:\n  filesystem:\n    repo: write\n    extra: 1\n",
        "agent:\n  network:\n    mode: offline\n    proxy: x\n",
        "agent:\n  resources:\n    gpu: 1\n",
        "agent:\n  containers:\n    allow: true\n    privileged: true\n",
        "observer:\n  default: live\n  colour: red\n",
        "agent:\n  secrets:\n    github:\n      decision: ask\n      token: abc\n",
    ] {
        let err = Policy::from_yaml(doc).unwrap_err();
        assert!(matches!(err, PolicyError::Yaml(_)), "{doc}: {err}");
    }
}

#[test]
fn host_filesystem_allow_is_hard_error() {
    for value in ["allow", "ask", "read", "write"] {
        let doc = format!("agent:\n  filesystem:\n    host: {value}\n");
        let err = Policy::from_yaml(&doc).unwrap_err();
        assert!(
            matches!(&err, PolicyError::HostFilesystemNotDeny(v) if v == value),
            "{value}: {err}"
        );
    }
    let err = Policy::from_yaml("agent:\n  filesystem:\n    host: true\n").unwrap_err();
    assert!(
        matches!(
            err,
            PolicyError::Yaml(_) | PolicyError::HostFilesystemNotDeny(_)
        ),
        "{err}"
    );
}

#[test]
fn host_filesystem_deny_is_accepted() {
    let p = policy("agent:\n  filesystem:\n    host: deny\n");
    assert_eq!(p.agent.filesystem.unwrap().host, Some(HostDenied));
}

#[test]
fn deny_private_networks_false_is_hard_error() {
    let err = Policy::from_yaml(
        "agent:\n  network:\n    mode: development\n    deny_private_networks: false\n",
    )
    .unwrap_err();
    assert!(
        matches!(err, PolicyError::PrivateNetworksMustBeDenied),
        "{err}"
    );
}

#[test]
fn deny_private_networks_may_be_omitted_or_true() {
    for doc in [
        "agent:\n  network:\n    mode: development\n",
        "agent:\n  network:\n    mode: development\n    deny_private_networks: true\n",
    ] {
        let p = policy(doc);
        assert_eq!(p.agent.network.unwrap().mode, NetworkMode::Development);
    }
}

#[test]
fn network_section_requires_mode() {
    let err =
        Policy::from_yaml("agent:\n  network:\n    deny_private_networks: true\n").unwrap_err();
    assert!(matches!(err, PolicyError::NetworkModeRequired), "{err}");
}

#[test]
fn network_allow_requires_custom_mode() {
    for mode in [
        "offline",
        "localhost-only",
        "package-registries",
        "development",
        "unrestricted",
    ] {
        let doc = format!("agent:\n  network:\n    mode: {mode}\n    allow: [example.com]\n");
        let err = Policy::from_yaml(&doc).unwrap_err();
        assert!(
            matches!(&err, PolicyError::AllowRequiresCustomMode(m) if m == mode),
            "{err}"
        );
        // An empty list is harmless.
        let doc = format!("agent:\n  network:\n    mode: {mode}\n    allow: []\n");
        policy(&doc);
    }
}

#[test]
fn network_modes_all_parse() {
    let expected = [
        ("offline", NetworkMode::Offline),
        ("localhost-only", NetworkMode::LocalhostOnly),
        ("package-registries", NetworkMode::PackageRegistries),
        ("development", NetworkMode::Development),
        ("custom", NetworkMode::Custom),
        ("unrestricted", NetworkMode::Unrestricted),
    ];
    for (name, mode) in expected {
        let p = policy(&format!("agent:\n  network:\n    mode: {name}\n"));
        assert_eq!(p.agent.network.unwrap().mode, mode);
    }
    let err = Policy::from_yaml("agent:\n  network:\n    mode: open\n").unwrap_err();
    assert!(matches!(err, PolicyError::Yaml(_)));
}

#[test]
fn invalid_hostname_in_allowlist_is_error() {
    for bad in [
        "10.0.0.1",
        "-bad.example.com",
        "exa mple.com",
        "foo.*.com",
        "münchen.de",
    ] {
        let doc = format!("agent:\n  network:\n    mode: custom\n    allow: ['{bad}']\n");
        let err = Policy::from_yaml(&doc).unwrap_err();
        assert!(
            matches!(&err, PolicyError::InvalidHostname { value, .. } if value == bad),
            "{bad}: {err}"
        );
    }
}

#[test]
fn secret_rules_short_and_long_forms() {
    let p = policy(
        "agent:\n  secrets:\n    a: allow\n    b: ask\n    c: deny\n    d:\n      decision: allow\n    e:\n      decision: ask\n      scope: []\n",
    );
    let s = p.agent.secrets.unwrap();
    let get = |k: &str| s[&ServiceId::new(k).unwrap()].clone();
    assert_eq!(get("a").decision, Decision::Allow);
    assert_eq!(get("b").decision, Decision::Ask);
    assert_eq!(get("c").decision, Decision::Deny);
    assert_eq!(get("d").decision, Decision::Allow);
    assert_eq!(get("d").scope, None);
    assert_eq!(get("e").scope, Some(BTreeSet::new()));
}

#[test]
fn secret_rule_rejects_unknown_decision_and_bad_ids() {
    let err = Policy::from_yaml("agent:\n  secrets:\n    github: maybe\n").unwrap_err();
    assert!(matches!(err, PolicyError::Yaml(_)), "{err}");
    for bad in ["GitHub", "-x", "a b", ""] {
        let doc = format!("agent:\n  secrets:\n    '{bad}': deny\n");
        let err = Policy::from_yaml(&doc).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidServiceId { .. }),
            "{bad}: {err}"
        );
    }
    let err = Policy::from_yaml(
        "agent:\n  secrets:\n    github:\n      decision: ask\n      scope: ['bad scope']\n",
    )
    .unwrap_err();
    assert!(matches!(err, PolicyError::InvalidScopeItem { .. }), "{err}");
}

#[test]
fn resources_parse_and_validate() {
    let p = policy(
        "agent:\n  resources:\n    cpu_weight: 10000\n    memory_max: 50%\n    pids_max: 1\n    disk_quota: 1048576\n",
    );
    let r = p.agent.resources.unwrap();
    assert_eq!(r.cpu_weight, Some(CpuWeight::new(10_000).unwrap()));
    assert_eq!(
        r.memory_max,
        Some(MemoryLimit::Percent(Percent::new(50).unwrap()))
    );
    assert_eq!(r.pids_max, Some(PidsMax::new(1).unwrap()));
    assert_eq!(r.disk_quota, Some(ByteSize::new(1 << 20).unwrap()));

    let p = policy("agent:\n  resources:\n    memory_max: 4294967296\n    disk_quota: 2TB\n");
    let r = p.agent.resources.unwrap();
    assert_eq!(
        r.memory_max,
        Some(MemoryLimit::Bytes(ByteSize::new(1 << 32).unwrap()))
    );
    assert_eq!(
        r.disk_quota,
        Some(ByteSize::new(2_000_000_000_000).unwrap())
    );

    for bad in [
        "cpu_weight: 0",
        "cpu_weight: 10001",
        "pids_max: 0",
        "memory_max: 0%",
        "memory_max: 101%",
        "memory_max: 0",
        "memory_max: lots",
        "disk_quota: 0",
        "disk_quota: 20 parsecs",
    ] {
        let doc = format!("agent:\n  resources:\n    {bad}\n");
        let err = Policy::from_yaml(&doc).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidResource { .. }),
            "{bad}: {err}"
        );
    }
}

#[test]
fn observer_step_requires_step_through() {
    for doc in [
        "observer:\n  step: all\n",
        "observer:\n  default: live\n  step: all\n",
        "observer:\n  default: quiet\n  step: ['src/**']\n",
    ] {
        let err = Policy::from_yaml(doc).unwrap_err();
        assert!(
            matches!(err, PolicyError::StepRequiresStepThrough),
            "{doc}: {err}"
        );
    }
}

#[test]
fn observer_step_forms() {
    let all = policy("observer:\n  default: step-through\n  step: all\n");
    assert_eq!(all.observer.step, Some(HoldSet::All));
    let empty = policy("observer:\n  default: step-through\n  step: []\n");
    assert_eq!(
        empty.observer.step,
        Some(HoldSet::All),
        "empty list resolves to hold-all"
    );
    let none = policy("observer:\n  default: step-through\n");
    assert_eq!(none.observer.step, None);
    let err = Policy::from_yaml("observer:\n  default: step-through\n  step: some\n").unwrap_err();
    assert!(matches!(err, PolicyError::InvalidHoldSet(_)), "{err}");
    let err = Policy::from_yaml("observer:\n  default: step-through\n  step: ['[unclosed']\n")
        .unwrap_err();
    assert!(
        matches!(err, PolicyError::InvalidStepPattern { .. }),
        "{err}"
    );
}

#[test]
fn observer_levels_parse_in_verbosity_order() {
    assert!(ObserverLevel::Quiet < ObserverLevel::Live);
    assert!(ObserverLevel::Live < ObserverLevel::StepThrough);
    for (name, level) in [
        ("quiet", ObserverLevel::Quiet),
        ("live", ObserverLevel::Live),
        ("step-through", ObserverLevel::StepThrough),
    ] {
        let p = policy(&format!("observer:\n  default: {name}\n"));
        assert_eq!(p.observer.default, Some(level));
    }
}

#[test]
fn decision_order_is_deny_ask_allow() {
    assert!(Decision::Deny < Decision::Ask);
    assert!(Decision::Ask < Decision::Allow);
    assert_eq!(Decision::Allow.narrow(Decision::Ask), Decision::Ask);
    assert_eq!(Decision::Ask.narrow(Decision::Deny), Decision::Deny);
    assert_eq!(Decision::Allow.narrow(Decision::Allow), Decision::Allow);
}

#[test]
fn full_policy_round_trips_through_yaml() {
    let p = policy(FULL);
    let yaml = p.to_yaml().unwrap();
    let again = Policy::from_yaml(&yaml).unwrap();
    assert_eq!(p, again);
}

#[test]
fn yaml_type_mismatch_is_error() {
    let err = Policy::from_yaml("agent:\n  containers:\n    allow: yes-please\n").unwrap_err();
    assert!(matches!(err, PolicyError::Yaml(_)), "{err}");
    let err = Policy::from_yaml("agent:\n  filesystem:\n    repo: execute\n").unwrap_err();
    assert!(matches!(err, PolicyError::Yaml(_)), "{err}");
    let err = Policy::from_yaml("agent: [1, 2]\n").unwrap_err();
    assert!(matches!(err, PolicyError::Yaml(_)), "{err}");
}

#[test]
fn overlay_later_wins_per_field_and_per_key() {
    let mut base = policy(
        "agent:\n  filesystem:\n    repo: write\n  network:\n    mode: development\n  secrets:\n    a: allow\n    b: allow\n  resources:\n    cpu_weight: 100\n    pids_max: 4096\nobserver:\n  default: live\n",
    );
    let over = policy(
        "agent:\n  filesystem:\n    repo: read\n  network:\n    mode: custom\n    allow: [example.com]\n  secrets:\n    b: deny\n    c: ask\n  resources:\n    pids_max: 10\n",
    );
    base.overlay(&over);
    assert_eq!(base.agent.filesystem.unwrap().repo, Some(FsAccess::Read));
    let net = base.agent.network.unwrap();
    assert_eq!(net.mode, NetworkMode::Custom);
    assert_eq!(net.allow.len(), 1);
    let s = base.agent.secrets.unwrap();
    assert_eq!(s[&ServiceId::new("a").unwrap()].decision, Decision::Allow);
    assert_eq!(s[&ServiceId::new("b").unwrap()].decision, Decision::Deny);
    assert_eq!(s[&ServiceId::new("c").unwrap()].decision, Decision::Ask);
    let r = base.agent.resources.unwrap();
    assert_eq!(r.cpu_weight, Some(CpuWeight::new(100).unwrap()));
    assert_eq!(r.pids_max, Some(PidsMax::new(10).unwrap()));
    assert_eq!(base.observer.default, Some(ObserverLevel::Live));
}
