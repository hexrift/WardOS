//! `ward-events`: typed events, the hash-chained record envelope, the wire format, and the
//! append-only session log for `WardOS`.
//!
//! Design references: `docs/event-model.md`, `docs/security-model.md` §5,
//! `docs/architecture.md` §3.7, ADR-0011, ADR-0012.
//!
//! # Layout
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`ids`] | Strong identifier newtypes (`SessionId`, `SnapshotId`, `Blake3Hash`, ...) |
//! | [`text`] | Bounded, sanitised text: `BoundedText`, `BoundedArgv`, `SandboxPath`, `HostName` |
//! | [`origin`] | `Origin` and `OriginSet`; enforcement facts vs. agent claims |
//! | [`event`] | The `WardEvent` catalogue and its supporting types |
//! | [`chain`] | `EventRecord`, `Chain`, `ChainVerifier`, `verify` |
//! | [`wire`] | Versioned, length-prefixed frames; `Subscribe` and `Filter` |
//! | [`log`] | `LogWriter` / `LogReader` over an `O_APPEND` file with fsync policy hooks |
//!
//! # Guarantees
//!
//! * Every value of a type in this crate is well-formed: validation runs at construction
//!   **and** at deserialisation, so untrusted bytes from the subscription socket or a log
//!   file cannot smuggle unsanitised text, absolute paths, or oversized frames past the
//!   decoder.
//! * No type here carries secret material. `CredentialGranted` records scope and expiry
//!   only.
//! * Agent-origin records are never enforcement facts ([`Origin::is_enforcement_fact`]).

#![forbid(unsafe_code)]

pub mod chain;
pub mod event;
pub mod ids;
pub mod log;
pub mod origin;
pub mod text;
pub mod wire;

pub use chain::{Chain, ChainError, ChainHead, ChainVerifier, EventRecord, Timestamp, verify};
pub use event::{
    Acceptor, AgentIdentity, AgentKind, AgentState, CapabilityKind, CapabilityRequest, CaptureMode,
    ClaimKind, CredentialDelivery, Decision, DecisionSource, DeniedDst, DenyReason, DetailText,
    EndReason, EventKind, EventKindSet, ExitStatus, FileChangeKind, GrantScope, NameText,
    PauseMethod, PayloadText, PolicySubject, ProcessRef, RevokeReason, Scope, ShortText,
    SignatureBytes, SnapshotRole, StepStatus, TamperWardSig, VerifyRequester, VerifySummary,
    WardEvent,
};
pub use ids::{
    Blake3Hash, IdError, ImageDigest, Pid, ProjectId, RuleRef, ServiceId, SessionId, SnapshotId,
};
pub use log::{FsyncDecider, FsyncPolicy, LogError, LogReader, LogWriter};
pub use origin::{Origin, OriginSet};
pub use text::{
    Arg, BoundedArgv, BoundedText, HostError, HostName, PathError, SandboxPath, SandboxRoot,
    TextError,
};
pub use wire::{
    Filter, FrameHeader, FrameKind, MAX_FRAME_LEN, MAX_PAYLOAD_LEN, Subscribe, WireError,
    decode_record, decode_subscribe, encode_record, encode_subscribe,
};
