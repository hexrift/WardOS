//! Hash stability and the golden fixtures.
//!
//! `tests/golden/` is a protected path (`.tamperward.yml`: `crates/**/tests/**` and
//! `**/*.golden`). Changing a golden hash means the canonical encoding or the hashed
//! structure changed; that requires bumping the domain version in `hash.rs` and review.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use common::{empty, identity, merge_policies, policy};
use serde::Serialize;
use ward_policy::{Blake3Hash, Policy, canonical_bytes, manifest_hash, merge, policy_hash};

fn golden(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn golden_policy(name: &str) -> Policy {
    Policy::from_yaml(&golden(name)).unwrap()
}

#[test]
fn policy_hash_is_deterministic() {
    let sys = golden_policy("system.yaml");
    let user = golden_policy("user.yaml");
    let project = golden_policy("project.yaml");
    let a = policy_hash(&sys, &user, &project).unwrap();
    let b = policy_hash(&sys.clone(), &user.clone(), &project.clone()).unwrap();
    assert_eq!(a, b);
}

#[test]
fn policy_hash_ignores_yaml_formatting_and_key_order() {
    let a =
        policy("agent:\n  secrets:\n    b: deny\n    a: allow\n  containers:\n    allow: true\n");
    let b = policy("agent:\n  containers: {allow: true}\n  secrets: {a: allow, b: deny}\n");
    assert_eq!(a, b);
    assert_eq!(
        policy_hash(&a, &empty(), &empty()).unwrap(),
        policy_hash(&b, &empty(), &empty()).unwrap()
    );
}

#[test]
fn policy_hash_is_sensitive_to_content_and_layer() {
    let a = policy("agent:\n  containers:\n    allow: true\n");
    let b = policy("agent:\n  containers:\n    allow: false\n");
    assert_ne!(
        policy_hash(&a, &empty(), &empty()).unwrap(),
        policy_hash(&b, &empty(), &empty()).unwrap()
    );
    // The same document in a different layer hashes differently.
    assert_ne!(
        policy_hash(&a, &empty(), &empty()).unwrap(),
        policy_hash(&empty(), &a, &empty()).unwrap()
    );
}

#[test]
fn golden_policy_hash() {
    let sys = golden_policy("system.yaml");
    let user = golden_policy("user.yaml");
    let project = golden_policy("project.yaml");
    let expected = Blake3Hash::from_hex(golden("policy_hash.golden").trim()).unwrap();
    assert_eq!(policy_hash(&sys, &user, &project).unwrap(), expected);
}

#[test]
fn golden_manifest_hash() {
    let sys = golden_policy("system.yaml");
    let user = golden_policy("user.yaml");
    let project = golden_policy("project.yaml");
    let manifest = merge(&sys, &user, &project, identity()).unwrap();
    let expected = Blake3Hash::from_hex(golden("manifest_hash.golden").trim()).unwrap();
    assert_eq!(manifest_hash(&manifest).unwrap(), expected);
}

#[test]
fn manifest_hash_is_stable_across_serde_round_trip() {
    let m = merge_policies(
        &golden_policy("system.yaml"),
        &golden_policy("user.yaml"),
        &empty(),
    );
    let yaml = serde_yaml::to_string(&m).unwrap();
    let back: ward_policy::CapabilityManifest = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(manifest_hash(&m).unwrap(), manifest_hash(&back).unwrap());
}

#[test]
fn canonical_encoding_sorts_map_keys() {
    #[derive(Serialize)]
    struct Unsorted {
        zeta: u32,
        alpha: &'static str,
        mid: bool,
    }
    let s = Unsorted {
        zeta: 7,
        alpha: "x",
        mid: true,
    };
    let mut map: BTreeMap<&str, serde_yaml::Value> = BTreeMap::new();
    map.insert("alpha", "x".into());
    map.insert("mid", true.into());
    map.insert("zeta", 7.into());
    assert_eq!(canonical_bytes(&s).unwrap(), canonical_bytes(&map).unwrap());
    assert_eq!(
        canonical_bytes(&s).unwrap(),
        b"{s5:alphas1:xs3:midts4:zetau7;}".to_vec()
    );
}

#[test]
fn canonical_encoding_rejects_floats() {
    assert!(canonical_bytes(&1.5f64).is_err());
}

#[test]
fn blake3_hash_hex_round_trip() {
    let h = Blake3Hash::from_bytes([0xab; 32]);
    let hex = h.to_hex();
    assert_eq!(hex.len(), 64);
    assert_eq!(Blake3Hash::from_hex(&hex).unwrap(), h);
    assert!(Blake3Hash::from_hex(&hex.to_uppercase()).is_err());
    assert!(Blake3Hash::from_hex("abc").is_err());
}
