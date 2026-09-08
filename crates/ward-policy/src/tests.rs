//! Tests for the capability model and the narrowing merge.
//!
//! The property tests cross-check [`crate::merge::Lattice::meet`] against an
//! independently written permissiveness order ([`PermitsAtMost`]): if `meet`
//! ever produced something broader than an input, the invariant assertions fail.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::capability::{
    AccessMode, ContainerCapability, CredentialRule, CredentialScope, DeviceSet, FsCapabilities,
    NetworkCapability, ObserverMode, RepoSelector, ResourceLimits, StepPolicy,
};
use crate::ids::{ProjectId, ServiceId, SessionId};
use crate::merge::{Lattice, merge};
use crate::policy::Policy;
use crate::{Decision, default_manifest};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

/// Independently defined permissiveness order: `self` grants nothing beyond `ceiling`.
trait PermitsAtMost {
    fn permits_at_most(&self, ceiling: &Self) -> bool;
}

impl PermitsAtMost for AccessMode {
    fn permits_at_most(&self, c: &Self) -> bool {
        self <= c
    }
}
impl PermitsAtMost for ContainerCapability {
    fn permits_at_most(&self, c: &Self) -> bool {
        self <= c
    }
}
impl PermitsAtMost for DeviceSet {
    fn permits_at_most(&self, c: &Self) -> bool {
        self.0.is_subset(&c.0)
    }
}
impl PermitsAtMost for ResourceLimits {
    fn permits_at_most(&self, c: &Self) -> bool {
        self.cpu_weight <= c.cpu_weight
            && self.memory_percent <= c.memory_percent
            && self.pids <= c.pids
            && self.disk_gib <= c.disk_gib
    }
}
impl PermitsAtMost for NetworkCapability {
    fn permits_at_most(&self, c: &Self) -> bool {
        fn rank(n: &NetworkCapability) -> u8 {
            match n {
                NetworkCapability::Offline => 0,
                NetworkCapability::LocalhostOnly => 1,
                NetworkCapability::Registries => 2,
                NetworkCapability::Development => 3,
                NetworkCapability::Custom(_) => 4,
                NetworkCapability::Unrestricted => 5,
            }
        }
        match (self, c) {
            (NetworkCapability::Custom(a), NetworkCapability::Custom(b)) => a.is_subset(b),
            _ => rank(self) <= rank(c),
        }
    }
}
impl PermitsAtMost for ObserverMode {
    fn permits_at_most(&self, c: &Self) -> bool {
        // more oversight = less permissive, so "at most" means "observed at least as closely".
        fn over(o: ObserverMode) -> u8 {
            match o {
                ObserverMode::Quiet => 0,
                ObserverMode::Live => 1,
                ObserverMode::StepThrough(_) => 2,
            }
        }
        match (self, c) {
            (ObserverMode::StepThrough(a), ObserverMode::StepThrough(b)) => {
                (a.pause_before_writes || !b.pause_before_writes)
                    && (a.pause_before_network || !b.pause_before_network)
            }
            _ => over(*self) >= over(*c),
        }
    }
}
impl PermitsAtMost for CredentialRule {
    fn permits_at_most(&self, c: &Self) -> bool {
        use CredentialRule::{Allow, Ask, Deny};
        let subset = |a: &CredentialScope, b: &CredentialScope| {
            a.repositories.is_subset(&b.repositories) && a.permissions.is_subset(&b.permissions)
        };
        match (self, c) {
            (Deny, _) => true,
            (Ask(a), Ask(b) | Allow(b)) | (Allow(a), Allow(b)) => subset(a, b),
            (_, Deny) | (Allow(_), Ask(_)) => false,
        }
    }
}
impl PermitsAtMost for FsCapabilities {
    fn permits_at_most(&self, c: &Self) -> bool {
        self.worktree <= c.worktree
            && self.environment <= c.environment
            && self.home <= c.home
            && self.tmp <= c.tmp
            && self
                .extra
                .iter()
                .all(|(p, m)| c.extra.get(p).is_some_and(|cm| m <= cm))
    }
}

// --- strategies ------------------------------------------------------------

fn access() -> impl Strategy<Value = AccessMode> {
    prop_oneof![
        Just(AccessMode::None),
        Just(AccessMode::ReadOnly),
        Just(AccessMode::ReadWrite),
    ]
}

fn hosts() -> impl Strategy<Value = BTreeSet<String>> {
    prop::collection::btree_set(
        prop::sample::select(vec!["a", "b", "c"]).prop_map(String::from),
        0..3,
    )
}

fn network() -> impl Strategy<Value = NetworkCapability> {
    prop_oneof![
        Just(NetworkCapability::Offline),
        Just(NetworkCapability::LocalhostOnly),
        Just(NetworkCapability::Registries),
        Just(NetworkCapability::Development),
        hosts().prop_map(NetworkCapability::Custom),
        Just(NetworkCapability::Unrestricted),
    ]
}

fn scope() -> impl Strategy<Value = CredentialScope> {
    let repos = prop::collection::btree_set(
        prop_oneof![
            Just(RepoSelector::CurrentRepository),
            prop::sample::select(vec!["x", "y"]).prop_map(|s| RepoSelector::Named(s.to_owned())),
        ],
        0..3,
    );
    let perms = prop::collection::btree_set(
        prop::sample::select(vec!["contents:read", "issues:read", "contents:write"])
            .prop_map(String::from),
        0..3,
    );
    (repos, perms).prop_map(|(repositories, permissions)| CredentialScope {
        repositories,
        permissions,
    })
}

fn credential() -> impl Strategy<Value = CredentialRule> {
    prop_oneof![
        Just(CredentialRule::Deny),
        scope().prop_map(CredentialRule::Ask),
        scope().prop_map(CredentialRule::Allow),
    ]
}

fn container() -> impl Strategy<Value = ContainerCapability> {
    prop_oneof![
        Just(ContainerCapability::None),
        Just(ContainerCapability::NestedRootless),
    ]
}

fn resources() -> impl Strategy<Value = ResourceLimits> {
    (1u32..200, 0u8..100, 1u32..8192, 1u32..64).prop_map(
        |(cpu_weight, memory_percent, pids, disk_gib)| ResourceLimits {
            cpu_weight,
            memory_percent,
            pids,
            disk_gib,
        },
    )
}

fn observer() -> impl Strategy<Value = ObserverMode> {
    prop_oneof![
        Just(ObserverMode::Quiet),
        Just(ObserverMode::Live),
        (any::<bool>(), any::<bool>()).prop_map(|(w, n)| ObserverMode::StepThrough(StepPolicy {
            pause_before_writes: w,
            pause_before_network: n,
        })),
    ]
}

fn filesystem() -> impl Strategy<Value = FsCapabilities> {
    (access(), access(), access(), access()).prop_map(|(worktree, environment, home, tmp)| {
        FsCapabilities {
            worktree,
            environment,
            home,
            tmp,
            extra: BTreeMap::new(),
        }
    })
}

fn policy() -> impl Strategy<Value = Policy> {
    let creds = prop::collection::btree_map(
        prop::sample::select(vec!["github", "cloud-aws", "npm-publish", "svc"])
            .prop_map(|s| ServiceId(s.to_owned())),
        credential(),
        0..4,
    );
    (
        prop::option::of(filesystem()),
        prop::option::of(network()),
        prop::option::of(creds),
        prop::option::of(container()),
        prop::option::of(resources()),
        prop::option::of(observer()),
    )
        .prop_map(
            |(filesystem, network, credentials, containers, resources, observer)| Policy {
                filesystem,
                network,
                credentials,
                containers,
                devices: None,
                resources,
                observer,
            },
        )
}

// --- helpers ---------------------------------------------------------------

fn merged(system: &Policy, user: &Policy, project: &Policy) -> crate::CapabilityManifest {
    merge(
        system,
        user,
        project,
        SessionId("s".into()),
        ProjectId("p".into()),
    )
}

fn with_network(n: NetworkCapability) -> Policy {
    Policy {
        network: Some(n),
        ..Policy::default()
    }
}

fn with_credential(service: &str, rule: CredentialRule) -> Policy {
    Policy {
        credentials: Some(BTreeMap::from([(ServiceId(service.into()), rule)])),
        ..Policy::default()
    }
}

// --- lattice property tests ------------------------------------------------

/// `meet(a, b)` must be a lower bound of both operands for every capability type.
fn meet_is_lower_bound<T>(a: &T, b: &T)
where
    T: Lattice + PermitsAtMost,
{
    let m = T::meet(a, b);
    assert!(m.permits_at_most(a), "meet widened past the left operand");
    assert!(m.permits_at_most(b), "meet widened past the right operand");
}

proptest! {
    #[test]
    fn meet_never_widens(
        an in network(), bn in network(),
        ac in credential(), bc in credential(),
        af in filesystem(), bf in filesystem(),
        ar in resources(), br in resources(),
        ao in observer(), bo in observer(),
    ) {
        meet_is_lower_bound(&an, &bn);
        meet_is_lower_bound(&ac, &bc);
        meet_is_lower_bound(&af, &bf);
        meet_is_lower_bound(&ar, &br);
        meet_is_lower_bound(&ao, &bo);
    }

    /// The whole point of the crate: the merged manifest is never more permissive
    /// than any layer that constrained a field. The trusted system layer sets the
    /// ceiling (falling back to the default); user and project can only narrow it.
    #[test]
    fn merge_only_narrows(system in policy(), user in policy(), project in policy()) {
        let base = default_manifest();
        let m = merged(&system, &user, &project);

        // Ceiling = the system layer if it constrains the field, else the default.
        let net_ceiling = system.network.clone().unwrap_or(base.network);
        let fs_ceiling = system.filesystem.clone().unwrap_or(base.filesystem);
        let res_ceiling = system.resources.unwrap_or(base.resources);
        let obs_ceiling = system.observer.unwrap_or(base.observer);
        prop_assert!(m.network.permits_at_most(&net_ceiling));
        prop_assert!(m.filesystem.permits_at_most(&fs_ceiling));
        prop_assert!(m.resources.permits_at_most(&res_ceiling));
        prop_assert!(m.observer.permits_at_most(&obs_ceiling));

        for layer in [&user, &project] {
            if let Some(n) = &layer.network {
                prop_assert!(m.network.permits_at_most(n));
            }
            if let Some(f) = &layer.filesystem {
                prop_assert!(m.filesystem.permits_at_most(f));
            }
            if let Some(r) = &layer.resources {
                prop_assert!(m.resources.permits_at_most(r));
            }
        }
    }

    /// A hard `Deny` in any layer survives the merge for that service.
    #[test]
    fn hard_deny_persists(system in policy(), user in policy(), project in policy()) {
        let svc = ServiceId("svc".into());
        let denied_somewhere = [&system, &user, &project].iter().any(|p| {
            p.credentials.as_ref().and_then(|c| c.get(&svc)) == Some(&CredentialRule::Deny)
        });
        let m = merged(&system, &user, &project);
        if denied_somewhere {
            prop_assert_eq!(m.credential_decision(&svc), Decision::Deny);
        }
    }

    /// A project layer can never widen the credential decision above the layer above it.
    #[test]
    fn project_cannot_widen_credentials(system in policy(), user in policy(), rule in credential()) {
        let svc = ServiceId("github".into());
        let above = merged(&system, &user, &Policy::default());
        let below = merged(&system, &user, &with_credential("github", rule));
        // decision ordering is Deny > Ask > Allow, so "no more permissive" is `>=`.
        prop_assert!(below.credential_decision(&svc) >= above.credential_decision(&svc));
    }
}

// --- ST-007: hostile project policy ---------------------------------------

#[test]
fn st007_project_cannot_open_network() {
    let project = with_network(NetworkCapability::Unrestricted);
    let m = merged(&Policy::default(), &Policy::default(), &project);
    // default network is Development; a project asking for Unrestricted is clamped to it.
    assert_eq!(m.network, NetworkCapability::Development);
}

#[test]
fn st007_project_cannot_grant_denied_credential() {
    let project = with_credential(
        "cloud-aws",
        CredentialRule::Allow(CredentialScope::default()),
    );
    let m = merged(&Policy::default(), &Policy::default(), &project);
    // cloud-* is a hard deny in the default manifest; the wildcard still governs.
    assert_eq!(
        m.credential_decision(&ServiceId("cloud-aws".into())),
        Decision::Deny
    );
}

#[test]
fn project_may_downgrade_allow_to_ask() {
    // The trusted system layer grants svc=Allow (within the ceiling); the project
    // narrows it to Ask. A lower layer downgrading allow→ask is exactly permitted.
    let system = with_credential("svc", CredentialRule::Allow(CredentialScope::default()));
    let project = with_credential("svc", CredentialRule::Ask(CredentialScope::default()));
    let m = merged(&system, &Policy::default(), &project);
    assert_eq!(
        m.credential_decision(&ServiceId("svc".into())),
        Decision::Ask
    );
}

#[test]
fn lower_layer_cannot_introduce_service_above_ceiling() {
    // A user layer cannot grant a service the system/default never permitted.
    let user = with_credential("svc", CredentialRule::Allow(CredentialScope::default()));
    let m = merged(&Policy::default(), &user, &Policy::default());
    assert_eq!(
        m.credential_decision(&ServiceId("svc".into())),
        Decision::Deny
    );
}

// --- default manifest ------------------------------------------------------

#[test]
fn default_matches_spec() {
    let m = default_manifest();
    assert_eq!(m.network, NetworkCapability::Development);
    assert_eq!(m.filesystem.worktree, AccessMode::ReadWrite);
    assert_eq!(m.filesystem.environment, AccessMode::ReadWrite);
    assert_eq!(m.containers, ContainerCapability::NestedRootless);
    assert_eq!(m.observer, ObserverMode::Live);
    assert_eq!(m.resources.cpu_weight, 100);
    assert_eq!(m.resources.memory_percent, 50);
    assert_eq!(m.resources.pids, 4096);
    assert_eq!(m.resources.disk_gib, 20);

    assert_eq!(
        m.credential_decision(&ServiceId("github".into())),
        Decision::Ask
    );
    assert_eq!(
        m.credential_decision(&ServiceId("npm-publish".into())),
        Decision::Deny
    );
    assert_eq!(
        m.credential_decision(&ServiceId("pypi-publish".into())),
        Decision::Deny
    );
    assert_eq!(
        m.credential_decision(&ServiceId("cloud-gcp".into())),
        Decision::Deny
    );
    // unknown services are deny-by-default.
    assert_eq!(
        m.credential_decision(&ServiceId("mystery".into())),
        Decision::Deny
    );
}

#[test]
fn no_network_mode_permits_private_ranges() {
    for n in [
        NetworkCapability::Offline,
        NetworkCapability::LocalhostOnly,
        NetworkCapability::Registries,
        NetworkCapability::Development,
        NetworkCapability::Custom(BTreeSet::new()),
        NetworkCapability::Unrestricted,
    ] {
        assert!(!n.permits_private_ranges());
    }
}

#[test]
fn policy_hash_is_deterministic_and_reflects_narrowing() {
    let a = merged(&Policy::default(), &Policy::default(), &Policy::default());
    let b = merge(
        &Policy::default(),
        &Policy::default(),
        &Policy::default(),
        SessionId("other".into()),
        ProjectId("other".into()),
    );
    // identity fields are excluded from the hash.
    assert_eq!(a.policy_hash, b.policy_hash);

    let c = merged(
        &Policy::default(),
        &Policy::default(),
        &with_network(NetworkCapability::Offline),
    );
    assert_ne!(a.policy_hash, c.policy_hash);
}

// --- YAML ------------------------------------------------------------------

#[test]
fn yaml_round_trips() {
    let yaml = r"
network: !custom
  - github.com
  - registry.npmjs.org
filesystem:
  worktree: rw
  environment: rw
  home: rw
  tmp: rw
credentials:
  github: !ask
    repositories: [current_repository]
    permissions: [contents:read, issues:read]
  cloud-aws: deny
containers: nested_rootless
observer: live
";
    let parsed = Policy::from_yaml(yaml).expect("valid policy");
    assert_eq!(
        parsed.network,
        Some(NetworkCapability::Custom(BTreeSet::from([
            "github.com".to_owned(),
            "registry.npmjs.org".to_owned(),
        ])))
    );
    let back = serde_yaml::to_string(&parsed).expect("serialize");
    let reparsed = Policy::from_yaml(&back).expect("re-parse");
    assert_eq!(parsed, reparsed);
}

// --- The `ward init` template ---------------------------------------------

#[test]
fn the_template_parses_to_the_documented_defaults() {
    let p = Policy::from_yaml(Policy::template()).expect("the template is valid policy");
    assert_eq!(p.network, Some(NetworkCapability::Development));
    let fs = p.filesystem.expect("filesystem block");
    assert_eq!(fs.worktree, AccessMode::ReadWrite);
    assert_eq!(fs.environment, AccessMode::ReadWrite);
    let creds = p.credentials.expect("credentials block");
    assert!(matches!(
        creds.get(&ServiceId("github".into())),
        Some(CredentialRule::Ask(scope))
            if scope.repositories.contains(&RepoSelector::CurrentRepository)
    ));
    assert_eq!(p.observer, Some(ObserverMode::Live));
    assert!(p.containers.is_none() && p.devices.is_none() && p.resources.is_none());
}

#[test]
fn the_template_narrows_nothing_against_the_defaults() {
    let p = Policy::from_yaml(Policy::template()).expect("valid");
    let base = default_manifest();
    let merged = merge(
        &Policy::default(),
        &Policy::default(),
        &p,
        SessionId("s".into()),
        ProjectId("p".into()),
    );
    assert_eq!(merged.network, base.network);
    assert_eq!(merged.filesystem, base.filesystem);
    assert_eq!(merged.credentials, base.credentials);
    assert_eq!(merged.observer, base.observer);
}

#[test]
fn empty_yaml_is_fully_inheriting() {
    let p = Policy::from_yaml("").expect("empty policy");
    assert_eq!(p, Policy::default());
    let m = merged(&Policy::default(), &p, &p);
    assert_eq!(m.network, NetworkCapability::Development);
}

#[test]
fn unknown_field_is_rejected() {
    assert!(Policy::from_yaml("bogus: true").is_err());
}
