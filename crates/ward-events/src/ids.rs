//! Identifier newtypes. These name trusted, `wardd`-assigned entities, so they are thin
//! wrappers rather than sanitisers.

use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// Define an opaque string-backed identifier with a `new`/`as_str` pair.
macro_rules! string_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Wrap a raw ", stringify!($name), " string.")]
            pub fn new(id: impl Into<String>) -> Self {
                Self(id.into())
            }

            /// The underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

string_id!(
    /// Per-session identifier assigned by `wardd`, e.g. `sess_01J…`.
    SessionId
);
string_id!(
    /// Project identifier, keying policy and the persistent project environment.
    ProjectId
);
string_id!(
    /// Credential-broker service identifier, e.g. `github`.
    ServiceId
);
string_id!(
    /// OCI image digest string, e.g. `sha256:…`.
    ImageDigest
);

/// Content-addressed snapshot identifier: a BLAKE3 Merkle root over the worktree manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotId(pub Blake3Hash);

/// A Linux process id (`pid_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Pid(pub i32);
