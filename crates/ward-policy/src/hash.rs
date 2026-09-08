//! Canonical serialisation and BLAKE3 hashing of policies and manifests.
//!
//! Values are serialised through serde into a generic tree and then encoded with a
//! small, fully specified byte format so the hash does not depend on YAML/JSON
//! formatting details or on field order:
//!
//! ```text
//! null            n
//! bool            t | f
//! unsigned int    u<decimal>;
//! signed int      i<decimal>;
//! string          s<len>:<utf-8 bytes>
//! sequence        [ <item>* ]
//! mapping         { (<key><value>)* }     entries sorted by raw key bytes
//! tagged          !<len>:<tag bytes><value>
//! ```
//!
//! Floating point values are rejected (nothing in the schema produces them). Each hash
//! is domain-separated by a versioned prefix; bump the version if the encoding or the
//! hashed structure changes.

use serde::Serialize;
use serde_yaml::Value;

use crate::error::PolicyError;
use crate::manifest::CapabilityManifest;
use crate::schema::Policy;
use crate::types::Blake3Hash;

/// Domain prefix for [`policy_hash`].
pub const POLICY_HASH_DOMAIN: &str = "wardos/policy-hash/v1";

/// Domain prefix for [`manifest_hash`].
pub const MANIFEST_HASH_DOMAIN: &str = "wardos/manifest-hash/v1";

fn push_len_prefixed(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
    out.push(tag);
    out.extend_from_slice(bytes.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(bytes);
}

fn encode_into(value: &Value, out: &mut Vec<u8>) -> Result<(), PolicyError> {
    match value {
        Value::Null => out.push(b'n'),
        Value::Bool(true) => out.push(b't'),
        Value::Bool(false) => out.push(b'f'),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                out.push(b'u');
                out.extend_from_slice(u.to_string().as_bytes());
            } else if let Some(i) = n.as_i64() {
                out.push(b'i');
                out.extend_from_slice(i.to_string().as_bytes());
            } else {
                return Err(PolicyError::Canonical(
                    "floating point values cannot be canonicalised".to_owned(),
                ));
            }
            out.push(b';');
        }
        Value::String(s) => push_len_prefixed(out, b's', s.as_bytes()),
        Value::Sequence(items) => {
            out.push(b'[');
            for item in items {
                encode_into(item, out)?;
            }
            out.push(b']');
        }
        Value::Mapping(map) => {
            let mut entries = Vec::with_capacity(map.len());
            for (k, v) in map {
                let mut key = Vec::new();
                encode_into(k, &mut key)?;
                let mut val = Vec::new();
                encode_into(v, &mut val)?;
                // String keys (the only kind the schema produces) sort by their raw
                // bytes; anything else falls back to its encoding.
                let sort_key = match k {
                    Value::String(s) => s.as_bytes().to_vec(),
                    _ => key.clone(),
                };
                entries.push((sort_key, key, val));
            }
            entries.sort();
            out.push(b'{');
            for (_, k, v) in entries {
                out.extend_from_slice(&k);
                out.extend_from_slice(&v);
            }
            out.push(b'}');
        }
        Value::Tagged(tagged) => {
            push_len_prefixed(out, b'!', tagged.tag.to_string().as_bytes());
            encode_into(&tagged.value, out)?;
        }
    }
    Ok(())
}

/// The canonical byte encoding of any serialisable value.
///
/// # Errors
/// Returns [`PolicyError::Canonical`] if the value contains floating point numbers or
/// cannot be serialised.
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, PolicyError> {
    let tree = serde_yaml::to_value(value).map_err(|e| PolicyError::Canonical(e.to_string()))?;
    let mut out = Vec::new();
    encode_into(&tree, &mut out)?;
    Ok(out)
}

fn hash_with_domain(domain: &str, bytes: &[u8]) -> Blake3Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\0");
    hasher.update(bytes);
    hasher.finalize().into()
}

/// The three inputs of a merge, in the shape that is hashed.
#[derive(Serialize)]
struct PolicyInputs<'a> {
    system: &'a Policy,
    user: &'a Policy,
    project: &'a Policy,
}

/// BLAKE3 over the canonical encoding of the three policy layers.
///
/// # Errors
/// Returns [`PolicyError::Canonical`] if a layer cannot be canonicalised.
pub fn policy_hash(
    system: &Policy,
    user: &Policy,
    project: &Policy,
) -> Result<Blake3Hash, PolicyError> {
    let bytes = canonical_bytes(&PolicyInputs {
        system,
        user,
        project,
    })?;
    Ok(hash_with_domain(POLICY_HASH_DOMAIN, &bytes))
}

/// BLAKE3 over the canonical encoding of a manifest.
///
/// # Errors
/// Returns [`PolicyError::Canonical`] if the manifest cannot be canonicalised.
pub fn manifest_hash(manifest: &CapabilityManifest) -> Result<Blake3Hash, PolicyError> {
    let bytes = canonical_bytes(manifest)?;
    Ok(hash_with_domain(MANIFEST_HASH_DOMAIN, &bytes))
}
