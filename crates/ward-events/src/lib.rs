//! `ward-events` — the typed, hash-chained event model for WardOS.
//!
//! See [`docs/event-model.md`](../../../docs/event-model.md). One append-only event
//! stream per session serves the observer, TamperWard, replay and evidence export. Every
//! record carries an [`Origin`]: only kernel/proxy/`wardd`/verifier/TamperWard/user records
//! are enforcement facts, agent records are claims (threat-model row 14).
//!
//! The crate provides four things:
//!
//! * the [`WardEvent`] catalogue and its typed payloads ([`event`]),
//! * the [`EventRecord`] envelope and the BLAKE3 [`Chain`] that seals it ([`record`]),
//! * ingest sanitisers that make terminal-escape and Unicode spoofing unrepresentable —
//!   [`BoundedText`], [`BoundedArgv`], [`SandboxPath`], [`HostName`] ([`sanitise`],
//!   threat-model row 19),
//! * a versioned, size-bounded [`wire`] format (`postcard`) for the Zone 3 → Zone 0 decoder.

// Pedantic lints that only add ceremony to this crate's shape; the security-relevant
// pedantic lints stay on. `doc_markdown` fires on the product nouns (TamperWard, WardOS)
// that pervade these docs as prose.
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::doc_markdown
)]

pub mod event;
pub mod hash;
pub mod ids;
pub mod record;
pub mod sanitise;
pub mod wire;

pub use event::{
    AgentClaimKind, AgentIdentity, AgentState, CapabilityKind, CapabilityRequest, CaptureMode,
    CredentialDelivery, Decision, DecisionSource, DeniedDst, DenyReason, EndReason, ExitStatus,
    FileChange, GrantScope, Origin, PolicySubject, ProcessRef, RequestSource, RevokeReason,
    RuleRef, Scope, SnapshotRole, TamperWardSig, VerifyStatus, VerifySummary, WardEvent,
};
pub use hash::Blake3Hash;
pub use ids::{ImageDigest, Pid, ProjectId, ServiceId, SessionId, SnapshotId};
pub use record::{Chain, EventRecord, VerifyError};
pub use sanitise::{BoundedArgv, BoundedText, HostName, PathError, PathRoot, SandboxPath};
pub use wire::{FORMAT_VERSION, MAX_WIRE_BYTES, WireError, from_bytes, to_bytes};
