//! Built-in host allowlists and hostname matching.
//!
//! The definitions live in `ward-policy` ([`ward_policy::hosts`]) so the merge
//! lattice that decides egress breadth and the proxy that enforces it share one
//! source of truth. Re-exported here so existing `crate::hosts::…` call sites in
//! this crate keep working.

pub use ward_policy::hosts::{
    DEVELOPMENT_HOSTS, REGISTRY_HOSTS, any_matches, is_localhost_name, matches,
};
