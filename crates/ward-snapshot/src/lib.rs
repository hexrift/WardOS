//! `ward-snapshot` — content-addressed Ward Snapshots.
//!
//! A Ward Snapshot is an immutable, content-addressed capture of a project worktree
//! taken by `wardd` from Zone 0 (see `docs/snapshots-and-git.md` and ADR-0010). This
//! crate provides the building blocks; the daemon owns the policy of *when* to snapshot
//! and *which* cgroup to freeze.
//!
//! ```text
//!  worktree ──capture──▶ Manifest ──id()──▶ SnapshotId
//!      │                    │
//!      └──ingest──▶ Store (CAS) ◀──put_manifest
//!                     │
//!                     └──materialise──▶ fresh directory for the verifier
//! ```
//!
//! * [`manifest`] — the canonical manifest (`<type> <mode> <size> <hash> <path>` entries,
//!   NUL-separated, bytewise sorted) and the two-level BLAKE3 Merkle identity.
//! * [`capture`] — the frozen-copy capture engine (walk, `.gitignore`, parallel hashing,
//!   limits, optional [`TreeCache`]).
//! * [`freezer`] — the [`Freezer`] trait and the `cgroup.freeze` implementation.
//! * [`store`] — the content-addressed store with atomic blob writes, references and GC.
//! * [`materialise`] — safe reconstruction of a snapshot into a fresh directory.
//! * [`diff`] — manifest-to-manifest differences.
//! * [`meta`] — snapshot metadata (role, session, informational git context, policy).
//!
//! # Trust boundaries
//!
//! Nothing in this crate trusts the contents of `.git`; it is captured as bytes like any
//! other directory. [`meta::GitContext`] is *informational only*. The [`TreeCache`] is an
//! optimisation whose correctness depends on filesystem metadata the agent can influence;
//! see [`cache`] for the exact limitation and the rule `wardd` must follow.
//!
//! This crate is Linux/Unix only (raw-byte paths, `cgroup.freeze`, reflink ioctls).

#![forbid(unsafe_code)]

pub mod cache;
pub mod capture;
pub mod diff;
pub mod error;
pub mod freezer;
pub mod hash;
pub mod manifest;
pub mod materialise;
pub mod meta;
pub mod path;
pub mod store;

pub use cache::TreeCache;
pub use capture::{Capture, CapturePolicy, CaptureStats, capture_with_freezer};
pub use diff::{ManifestDiff, diff};
pub use error::{Error, Result};
pub use freezer::{CgroupV2Freezer, Freezer, NoopFreezer};
pub use hash::{ContentHash, SnapshotId};
pub use manifest::{Entry, EntryKind, Manifest};
pub use materialise::{MaterialiseReport, materialise, materialise_manifest};
pub use meta::{CaptureMode, GitContext, Role, SnapshotMeta};
pub use path::RelPath;
pub use store::{GcReport, IngestOptions, IngestReport, Store};
