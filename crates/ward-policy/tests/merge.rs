//! Three-layer merge rules, section by section.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::collections::BTreeSet;

use common::{empty, merge_policies, merge_yaml, policy};
use ward_policy::{
    ByteSize, ContainerCapability, CpuWeight, Decision, FsAccess, HoldSet, HostPattern, Layer,
    NetworkMode, ObserverMode, Percent, PidsMax, ScopeItem, StepPattern, default_policy,
    default_resource_limits, is_narrowing, policy_hash,
};

const SYS: &str = ward_policy::DEFAULT_POLICY_YAML;

fn net(mode: &str) -> String {
    format!("agent:\n  network:\n    mode: {mode}\n")
}

fn custom(hosts: &[&str]) -> String {
    let list = hosts
        .iter()
        .map(|h| format!("'{h}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("agent:\n  network:\n    mode: custom\n    allow: [{list}]\n")
}

fn hosts(names: &[&str]) -> BTreeSet<HostPattern> {
    names
        .iter()
        .map(|n| HostPattern::parse(n).unwrap())
        .collect()
}

fn scope(items: &[&str]) -> BTreeSet<ScopeItem> {
    items.iter().map(|s| ScopeItem::new(*s).unwrap()).collect()
}

// ---------------------------------------------------------------------------
// Floors: an empty system layer grants nothing.
// ---------------------------------------------------------------------------

#[test]
fn empty_system_layer_grants_nothing() {
    let m = merge_policies(&empty(), &empty(), &empty());
    assert_eq!(m.filesystem.worktree, FsAccess::Read);
    assert_eq!(m.network.mode, NetworkMode::Offline);
    assert!(m.network.allow.is_empty());
    assert!(m.credentials.is_empty());
    assert_eq!(m.credential("github").decision, Decision::Deny);
    assert!(m.credential("github").hard);
    assert_eq!(
        m.containers,
        ContainerCapability::Denied {
            hard: true,
            denied_by: Layer::System
        }
    );
    assert_eq!(m.resources, default_resource_limits());
    assert_eq!(
        m.observer,
        ObserverMode::StepThrough(ward_policy::StepPolicy { hold: HoldSet::All })
    );
}

#[test]
fn lower_layers_cannot_widen_an_empty_system_layer() {
    let wide = policy(
        "agent:\n  filesystem:\n    repo: write\n  network:\n    mode: unrestricted\n  secrets:\n    github: allow\n  containers:\n    allow: true\n  resources:\n    cpu_weight: 10000\n    pids_max: 100000\n    disk_quota: 1TiB\n    memory_max: 100%\nobserver:\n  default: quiet\n",
    );
    let base = merge_policies(&empty(), &empty(), &empty());
    let m = merge_policies(&empty(), &wide, &wide);
    assert!(is_narrowing(&m, &base));
    assert!(is_narrowing(&base, &m));
    assert_eq!(m.filesystem, base.filesystem);
    assert_eq!(m.network, base.network);
    assert_eq!(m.containers, base.containers);
    assert_eq!(m.resources, base.resources);
    assert_eq!(m.observer, base.observer);
    let github = m.credential("github");
    assert_eq!(github.decision, Decision::Deny);
    assert!(github.hard);
    assert_eq!(github.denied_by, Some(Layer::System));
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

#[test]
fn filesystem_project_can_narrow_to_read() {
    let m = merge_yaml(SYS, "", "agent:\n  filesystem:\n    repo: read\n");
    assert_eq!(m.filesystem.worktree, FsAccess::Read);
    assert_eq!(m.filesystem.decided_by, Layer::Project);
}

#[test]
fn filesystem_project_cannot_widen_user_read() {
    let m = merge_yaml(
        SYS,
        "agent:\n  filesystem:\n    repo: read\n",
        "agent:\n  filesystem:\n    repo: write\n",
    );
    assert_eq!(m.filesystem.worktree, FsAccess::Read);
    assert_eq!(m.filesystem.decided_by, Layer::User);
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

#[test]
fn network_offline_anywhere_wins() {
    for (u, p) in [
        (net("offline"), String::new()),
        (String::new(), net("offline")),
    ] {
        let m = merge_yaml(SYS, &u, &p);
        assert_eq!(m.network.mode, NetworkMode::Offline);
        assert!(!m.network.permits_host("github.com"));
    }
}

#[test]
fn network_localhost_only_narrows_everything_but_offline() {
    let m = merge_yaml(SYS, "", &net("localhost-only"));
    assert_eq!(m.network.mode, NetworkMode::LocalhostOnly);
    let m = merge_yaml(SYS, &net("offline"), &net("localhost-only"));
    assert_eq!(m.network.mode, NetworkMode::Offline);
}

#[test]
fn network_project_never_gets_unrestricted() {
    let m = merge_yaml(SYS, "", &net("unrestricted"));
    assert_eq!(m.network.mode, NetworkMode::Development);
    let sys_open = SYS.replace("mode: development", "mode: unrestricted");
    let m = merge_yaml(&sys_open, "", &net("unrestricted"));
    assert_eq!(m.network.mode, NetworkMode::Development);
    let m = merge_yaml(&sys_open, &net("development"), &net("unrestricted"));
    assert_eq!(m.network.mode, NetworkMode::Development);
}

#[test]
fn network_unrestricted_requires_explicit_user_opt_in() {
    let sys_open = SYS.replace("mode: development", "mode: unrestricted");
    // System allows it, user silent: clamped to development.
    let m = merge_yaml(&sys_open, "", "");
    assert_eq!(m.network.mode, NetworkMode::Development);
    assert_eq!(m.network.decided_by, Layer::User);
    // User opts in explicitly: granted.
    let m = merge_yaml(&sys_open, &net("unrestricted"), "");
    assert_eq!(m.network.mode, NetworkMode::Unrestricted);
    assert!(m.network.permits_host("anything.example"));
    // Project inherits the user's opt-in but cannot add it itself.
    let m = merge_yaml(&sys_open, &net("unrestricted"), "");
    assert_eq!(m.network.mode, NetworkMode::Unrestricted);
    let m = merge_yaml(&sys_open, "", &net("unrestricted"));
    assert_eq!(m.network.mode, NetworkMode::Development);
    // User asks for it when the system does not allow it: clamped to the system value.
    let m = merge_yaml(SYS, &net("unrestricted"), "");
    assert_eq!(m.network.mode, NetworkMode::Development);
}

#[test]
fn network_custom_under_builtin_is_intersection() {
    let m = merge_yaml(
        SYS,
        "",
        &custom(&["github.com", "evil.example", "*.github.com"]),
    );
    assert_eq!(m.network.mode, NetworkMode::Custom);
    assert_eq!(
        m.network.allow,
        hosts(&["github.com", "api.github.com", "codeload.github.com"])
    );
    assert!(m.network.permits_host("github.com"));
    assert!(!m.network.permits_host("evil.example"));
    assert!(!m.network.permits_host("registry.npmjs.org"));
}

#[test]
fn network_custom_under_custom_is_intersection() {
    let m = merge_yaml(
        &custom(&["*.example.com", "github.com", "gitlab.com"]),
        &custom(&["*.example.com", "github.com"]),
        &custom(&["api.example.com", "*.sub.example.com", "gitlab.com"]),
    );
    assert_eq!(m.network.mode, NetworkMode::Custom);
    assert_eq!(
        m.network.allow,
        hosts(&["api.example.com", "*.sub.example.com"])
    );
    assert_eq!(m.network.decided_by, Layer::Project);
}

#[test]
fn network_builtin_under_custom_is_intersection() {
    let m = merge_yaml(
        SYS,
        &custom(&["github.com", "pypi.org", "evil.example"]),
        &net("package-registries"),
    );
    assert_eq!(m.network.mode, NetworkMode::Custom);
    assert_eq!(m.network.allow, hosts(&["pypi.org"]));
    let m = merge_yaml(
        SYS,
        &custom(&["github.com", "pypi.org", "evil.example"]),
        &net("development"),
    );
    assert_eq!(m.network.allow, hosts(&["github.com", "pypi.org"]));
}

#[test]
fn network_builtin_modes_compare_positionally() {
    let m = merge_yaml(SYS, "", &net("package-registries"));
    assert_eq!(m.network.mode, NetworkMode::PackageRegistries);
    assert!(m.network.permits_host("pypi.org"));
    assert!(!m.network.permits_host("github.com"));
    let m = merge_yaml(SYS, &net("package-registries"), &net("development"));
    assert_eq!(m.network.mode, NetworkMode::PackageRegistries);
    assert_eq!(m.network.decided_by, Layer::User);
}

#[test]
fn network_custom_under_offline_or_localhost_stays_closed() {
    let m = merge_yaml(SYS, &net("offline"), &custom(&["github.com"]));
    assert_eq!(m.network.mode, NetworkMode::Offline);
    let m = merge_yaml(SYS, &net("localhost-only"), &custom(&["github.com"]));
    assert_eq!(m.network.mode, NetworkMode::LocalhostOnly);
    let m = merge_yaml(SYS, &net("localhost-only"), &net("development"));
    assert_eq!(m.network.mode, NetworkMode::LocalhostOnly);
}

#[test]
fn network_custom_under_unrestricted_is_taken_verbatim() {
    let sys_open = SYS.replace("mode: development", "mode: unrestricted");
    let m = merge_yaml(&sys_open, &net("unrestricted"), &custom(&["evil.example"]));
    assert_eq!(m.network.mode, NetworkMode::Custom);
    assert_eq!(m.network.allow, hosts(&["evil.example"]));
    let m = merge_yaml(&sys_open, &net("unrestricted"), &net("package-registries"));
    assert_eq!(m.network.mode, NetworkMode::PackageRegistries);
}

#[test]
fn network_mode_positional_order() {
    let modes = [
        NetworkMode::Offline,
        NetworkMode::LocalhostOnly,
        NetworkMode::PackageRegistries,
        NetworkMode::Development,
        NetworkMode::Custom,
        NetworkMode::Unrestricted,
    ];
    for w in modes.windows(2) {
        assert!(w[0] < w[1]);
    }
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

#[test]
fn secrets_lower_layer_may_ask_for_what_upper_allows() {
    let m = merge_yaml(
        "agent:\n  secrets:\n    svc: allow\n",
        "agent:\n  secrets:\n    svc: ask\n",
        "",
    );
    assert_eq!(m.credential("svc").decision, Decision::Ask);
    assert!(!m.credential("svc").hard);
}

#[test]
fn secrets_lower_layer_cannot_allow_what_upper_asks() {
    let m = merge_yaml(
        "agent:\n  secrets:\n    svc: ask\n",
        "",
        "agent:\n  secrets:\n    svc: allow\n",
    );
    assert_eq!(m.credential("svc").decision, Decision::Ask);
    let m = merge_yaml(
        "agent:\n  secrets:\n    svc: allow\n",
        "agent:\n  secrets:\n    svc: ask\n",
        "agent:\n  secrets:\n    svc: allow\n",
    );
    assert_eq!(m.credential("svc").decision, Decision::Ask);
}

#[test]
fn secrets_project_deny_is_final_but_not_hard() {
    let m = merge_yaml(
        "agent:\n  secrets:\n    svc: allow\n",
        "",
        "agent:\n  secrets:\n    svc: deny\n",
    );
    let r = m.credential("svc");
    assert_eq!(r.decision, Decision::Deny);
    assert!(!r.hard);
    assert_eq!(r.denied_by, Some(Layer::Project));
    assert!(r.scope.is_empty());
}

#[test]
fn secrets_system_deny_is_hard_and_survives() {
    let m = merge_yaml(
        "agent:\n  secrets:\n    svc: deny\n",
        "agent:\n  secrets:\n    svc: allow\n",
        "agent:\n  secrets:\n    svc: allow\n",
    );
    let r = m.credential("svc");
    assert_eq!(r.decision, Decision::Deny);
    assert!(r.hard);
    assert_eq!(r.denied_by, Some(Layer::System));
}

#[test]
fn secrets_unlisted_service_is_hard_denied() {
    let m = merge_yaml(SYS, "agent:\n  secrets:\n    my-thing: allow\n", "");
    let r = m.credential("my-thing");
    assert_eq!(r.decision, Decision::Deny);
    assert!(r.hard);
    assert_eq!(r.denied_by, Some(Layer::System));
    assert!(m.credentials.contains_key(&"my-thing".parse().unwrap()));
}

#[test]
fn secrets_pattern_deny_beats_specific_allow_below() {
    let m = merge_yaml(SYS, "agent:\n  secrets:\n    cloud-dev: allow\n", "");
    let r = m.credential("cloud-dev");
    assert_eq!(r.decision, Decision::Deny);
    assert!(r.hard);
    assert_eq!(
        m.credentials[&"cloud-dev".parse().unwrap()].decision,
        Decision::Deny
    );
}

#[test]
fn secrets_within_layer_most_restrictive_pattern_wins() {
    let m = merge_yaml(
        "agent:\n  secrets:\n    'cloud-*': deny\n    cloud-dev: allow\n",
        "",
        "",
    );
    assert_eq!(m.credential("cloud-dev").decision, Decision::Deny);
    let m = merge_yaml(
        "agent:\n  secrets:\n    'cloud-*': ask\n    cloud-dev: allow\n",
        "",
        "",
    );
    assert_eq!(m.credential("cloud-dev").decision, Decision::Ask);
    assert_eq!(m.credential("cloud-prod").decision, Decision::Ask);
}

#[test]
fn secrets_scopes_intersect_and_inherit() {
    let sys = "agent:\n  secrets:\n    gh:\n      decision: allow\n      scope: [a, b, c]\n";
    let m = merge_yaml(
        sys,
        "agent:\n  secrets:\n    gh:\n      decision: allow\n      scope: [b, c, d]\n",
        "",
    );
    assert_eq!(m.credential("gh").scope, scope(&["b", "c"]));
    let m = merge_yaml(sys, "agent:\n  secrets:\n    gh: ask\n", "");
    assert_eq!(m.credential("gh").decision, Decision::Ask);
    assert_eq!(
        m.credential("gh").scope,
        scope(&["a", "b", "c"]),
        "scope inherited"
    );
    let m = merge_yaml(
        sys,
        "",
        "agent:\n  secrets:\n    gh:\n      decision: allow\n      scope: [z]\n",
    );
    assert!(m.credential("gh").scope.is_empty());
    let m = merge_yaml(
        "agent:\n  secrets:\n    gh: allow\n",
        "agent:\n  secrets:\n    gh:\n      decision: allow\n      scope: [a]\n",
        "",
    );
    assert!(
        m.credential("gh").scope.is_empty(),
        "system minimal scope cannot be widened"
    );
}

#[test]
fn secrets_lookup_combines_all_matching_rules() {
    let m = merge_yaml(
        "agent:\n  secrets:\n    'a-*': allow\n    '*-b': ask\n    a-b-c: allow\n",
        "",
        "",
    );
    assert_eq!(m.credential("a-b").decision, Decision::Ask);
    assert_eq!(m.credential("a-x").decision, Decision::Allow);
    assert_eq!(m.credential("a-b-c").decision, Decision::Allow);
    assert_eq!(m.credential("x-b").decision, Decision::Ask);
    assert_eq!(m.credential("zzz").decision, Decision::Deny);
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

#[test]
fn containers_are_anded() {
    let m = merge_yaml(SYS, "", "agent:\n  containers:\n    allow: false\n");
    assert_eq!(
        m.containers,
        ContainerCapability::Denied {
            hard: false,
            denied_by: Layer::Project
        }
    );
    let m = merge_yaml(
        SYS,
        "agent:\n  containers:\n    allow: false\n",
        "agent:\n  containers:\n    allow: true\n",
    );
    assert_eq!(
        m.containers,
        ContainerCapability::Denied {
            hard: false,
            denied_by: Layer::User
        }
    );
    let m = merge_yaml(
        SYS,
        "agent:\n  containers:\n    allow: true\n",
        "agent:\n  containers:\n    allow: true\n",
    );
    assert_eq!(m.containers, ContainerCapability::NestedRootless);
}

#[test]
fn containers_system_deny_is_hard() {
    let m = merge_yaml(
        "agent:\n  containers:\n    allow: false\n",
        "agent:\n  containers:\n    allow: true\n",
        "",
    );
    assert_eq!(
        m.containers,
        ContainerCapability::Denied {
            hard: true,
            denied_by: Layer::System
        }
    );
    let m = merge_yaml("", "agent:\n  containers:\n    allow: true\n", "");
    assert_eq!(
        m.containers,
        ContainerCapability::Denied {
            hard: true,
            denied_by: Layer::System
        }
    );
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

#[test]
fn resources_take_minimum_of_each_field() {
    let m = merge_yaml(
        SYS,
        "agent:\n  resources:\n    cpu_weight: 200\n    pids_max: 100\n",
        "agent:\n  resources:\n    cpu_weight: 50\n    pids_max: 500\n    disk_quota: 1GiB\n    memory_max: 1GiB\n",
    );
    assert_eq!(m.resources.cpu_weight, CpuWeight::new(50).unwrap());
    assert_eq!(m.resources.pids_max, PidsMax::new(100).unwrap());
    assert_eq!(m.resources.disk_quota, ByteSize::new(1 << 30).unwrap());
    assert_eq!(
        m.resources.memory_max.bytes,
        Some(ByteSize::new(1 << 30).unwrap())
    );
    assert_eq!(
        m.resources.memory_max.percent_of_host,
        Some(Percent::new(50).unwrap())
    );
}

#[test]
fn resources_system_overrides_builtin_defaults() {
    let m = merge_yaml(
        "agent:\n  resources:\n    cpu_weight: 500\n    memory_max: 4GiB\n",
        "",
        "",
    );
    assert_eq!(m.resources.cpu_weight, CpuWeight::new(500).unwrap());
    assert_eq!(
        m.resources.memory_max.bytes,
        Some(ByteSize::new(4 << 30).unwrap())
    );
    assert_eq!(m.resources.memory_max.percent_of_host, None);
    assert_eq!(m.resources.pids_max, default_resource_limits().pids_max);
    assert_eq!(m.resources.disk_quota, default_resource_limits().disk_quota);
}

#[test]
fn resources_memory_percent_below_bytes_keeps_both() {
    let m = merge_yaml(
        "agent:\n  resources:\n    memory_max: 8GiB\n",
        "agent:\n  resources:\n    memory_max: 25%\n",
        "",
    );
    assert_eq!(
        m.resources.memory_max.bytes,
        Some(ByteSize::new(8 << 30).unwrap())
    );
    assert_eq!(
        m.resources.memory_max.percent_of_host,
        Some(Percent::new(25).unwrap())
    );
}

// ---------------------------------------------------------------------------
// Observer
// ---------------------------------------------------------------------------

#[test]
fn observer_project_may_only_become_more_verbose() {
    let m = merge_yaml(SYS, "", "observer:\n  default: quiet\n");
    assert_eq!(m.observer, ObserverMode::Live);
    let m = merge_yaml(SYS, "", "observer:\n  default: step-through\n");
    assert_eq!(
        m.observer,
        ObserverMode::StepThrough(ward_policy::StepPolicy { hold: HoldSet::All })
    );
    let m = merge_yaml(
        SYS,
        "observer:\n  default: quiet\n",
        "observer:\n  default: live\n",
    );
    assert_eq!(m.observer, ObserverMode::Live);
    let m = merge_yaml("observer:\n  default: quiet\n", "", "");
    assert_eq!(m.observer, ObserverMode::Quiet);
}

#[test]
fn observer_hold_sets_union() {
    let m = merge_yaml(
        SYS,
        "observer:\n  default: step-through\n  step: ['src/**']\n",
        "observer:\n  default: step-through\n  step: ['tests/**']\n",
    );
    let expected: BTreeSet<StepPattern> = ["src/**", "tests/**"]
        .into_iter()
        .map(|s| StepPattern::new(s).unwrap())
        .collect();
    assert_eq!(
        m.observer,
        ObserverMode::StepThrough(ward_policy::StepPolicy {
            hold: HoldSet::Patterns(expected)
        })
    );
    let m = merge_yaml(
        SYS,
        "observer:\n  default: step-through\n  step: all\n",
        "observer:\n  default: step-through\n  step: ['tests/**']\n",
    );
    assert_eq!(
        m.observer,
        ObserverMode::StepThrough(ward_policy::StepPolicy { hold: HoldSet::All })
    );
    let m = merge_yaml(
        SYS,
        "observer:\n  default: step-through\n  step: ['src/**']\n",
        "observer:\n  default: live\n",
    );
    assert!(matches!(m.observer, ObserverMode::StepThrough(_)));
}

#[test]
fn hold_set_matching_fails_closed_on_all() {
    let all = HoldSet::All;
    assert!(all.holds("anything"));
    let some = HoldSet::Patterns([StepPattern::new("src/**").unwrap()].into_iter().collect());
    assert!(some.holds("src/main.rs"));
    assert!(!some.holds("README.md"));
}

// ---------------------------------------------------------------------------
// Manifest bookkeeping
// ---------------------------------------------------------------------------

#[test]
fn manifest_records_identity_and_policy_hash() {
    let sys = default_policy().unwrap();
    let user = policy("agent:\n  filesystem:\n    repo: read\n");
    let m = merge_policies(&sys, &user, &empty());
    assert_eq!(m.session.as_str(), "sess-0001");
    assert_eq!(m.project.as_str(), "proj-demo");
    assert_eq!(m.agent_image.as_str(), common::AGENT_IMAGE);
    assert_eq!(m.tool_images.len(), 1);
    assert_eq!(m.policy_hash, policy_hash(&sys, &user, &empty()).unwrap());
}

#[test]
fn manifest_is_within_is_reflexive_and_detects_widening() {
    let base = merge_yaml(SYS, "", "");
    let narrower = merge_yaml(
        SYS,
        "",
        "agent:\n  filesystem:\n    repo: read\n  network:\n    mode: offline\n",
    );
    assert!(is_narrowing(&base, &base));
    assert!(is_narrowing(&narrower, &base));
    assert!(!is_narrowing(&base, &narrower));
}

#[test]
fn manifest_serde_round_trip() {
    let m = merge_yaml(
        SYS,
        "observer:\n  default: step-through\n  step: ['src/**']\n",
        "agent:\n  containers:\n    allow: false\n  network:\n    mode: custom\n    allow: [github.com]\n",
    );
    let yaml = serde_yaml::to_string(&m).unwrap();
    let back: ward_policy::CapabilityManifest = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(back, m);
}
