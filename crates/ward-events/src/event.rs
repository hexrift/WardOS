//! The [`WardEvent`] catalogue and its typed payloads (event-model §3).
//!
//! By construction no payload can carry token material: the credential events carry only a
//! service, scope, expiry and delivery mode, never a secret.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;
use crate::ids::{ImageDigest, Pid, ProjectId, ServiceId, SnapshotId};
use crate::sanitise::{BoundedArgv, BoundedText, HostName, SandboxPath};

/// The producer of a record and the single most important trust signal (event-model §2,
/// threat-model row 14). Only non-[`Origin::Agent`] records are enforcement facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Origin {
    /// Kernel telemetry (eBPF, fanotify, nftables).
    Kernel = 0,
    /// The egress proxy.
    Proxy = 1,
    /// The `wardd` supervisor.
    Wardd = 2,
    /// The verifier runner.
    Verifier = 3,
    /// TamperWard policy engine.
    TamperWard = 4,
    /// Agent hooks and `ward-request` — claims, never enforcement facts.
    Agent = 5,
    /// A human decision.
    User = 6,
}

impl Origin {
    /// Stable one-byte code mixed into the record hash.
    pub fn code(self) -> u8 {
        self as u8
    }
}

/// Coarse agent lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentState {
    /// Idle.
    Idle,
    /// Actively working.
    Working,
    /// Waiting on input or a decision.
    Waiting,
    /// Blocked on a held request.
    Blocked,
    /// Verification in progress.
    Verifying,
    /// Finished.
    Finished,
}

/// An allow/deny/ask decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Permit.
    Allow,
    /// Refuse.
    Deny,
    /// Hold for an approval decision.
    Ask,
}

/// Who or what produced a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionSource {
    /// A human.
    User,
    /// The capability manifest / policy merge.
    Policy,
    /// An automatic default.
    Auto,
    /// TamperWard.
    TamperWard,
}

/// Origin of a verification or state-acceptance request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestSource {
    /// The agent asked.
    Agent,
    /// A human asked.
    User,
    /// TamperWard triggered it.
    TamperWard,
}

/// Why a session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndReason {
    /// The agent completed normally.
    Completed,
    /// The user stopped the session.
    Stopped,
    /// The session failed.
    Failed,
    /// The agent process crashed.
    Crashed,
    /// A resource or wall-clock limit was hit.
    TimedOut,
}

/// The kind of a filesystem modification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileChange {
    /// A file was created.
    Create,
    /// Contents were written.
    Write,
    /// A file was deleted.
    Delete,
    /// A file was renamed or moved.
    Rename,
    /// Mode/attributes changed.
    Chmod,
    /// A symlink was created.
    Symlink,
}

/// Why a network or credential request was denied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyReason {
    /// No allow rule matched.
    NoRule,
    /// An explicit deny rule matched.
    ExplicitDeny,
    /// Destination is in a private/link-local range.
    PrivateRange,
    /// A connection attempt bypassing the proxy.
    NonProxy,
    /// The grant or lease had expired.
    Expired,
    /// The requested scope exceeds what is permitted.
    ScopeExceeded,
    /// Rate limited.
    RateLimited,
    /// Unclassified.
    Unknown,
}

/// Why a credential was revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevokeReason {
    /// The lease expired.
    Expired,
    /// A human revoked it.
    UserRevoked,
    /// The session ended.
    SessionEnded,
    /// Policy changed.
    PolicyChanged,
    /// Replaced by a newer grant.
    Superseded,
}

/// How a granted credential is delivered — never the secret itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialDelivery {
    /// The proxy injects `Authorization`; the agent never holds a token.
    ProxyInjected,
    /// A short-lived token was minted and delivered over the control socket.
    MintedToken,
}

/// The role a snapshot plays in the session (event-model §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotRole {
    /// Session start.
    Entry,
    /// A verification candidate.
    Candidate,
    /// Accepted post-verification.
    Accepted,
    /// Session end.
    Final,
}

/// How a snapshot was captured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureMode {
    /// A full capture.
    Full,
    /// An incremental capture against a base.
    Incremental,
}

/// Progress status of a verification step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyStatus {
    /// The step is running.
    Running,
    /// The step passed.
    Pass,
    /// The step failed.
    Fail,
}

/// The kind of an agent claim (never an enforcement fact).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentClaimKind {
    /// A tool invocation.
    ToolUse,
    /// A free-text note.
    Note,
    /// A plan step.
    Plan,
}

/// A broad class of capability being requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityKind {
    /// Network egress.
    Network,
    /// Reading files.
    FileRead,
    /// Writing files.
    FileWrite,
    /// Executing a command.
    Exec,
    /// A credential.
    Credential,
    /// Taking a snapshot.
    Snapshot,
    /// Running verification.
    Verify,
    /// Anything else.
    Other,
}

/// Identity of the agent driving a session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Agent name, e.g. `claude-code`.
    pub name: BoundedText,
    /// Agent version string.
    pub version: BoundedText,
}

/// A reference to a process that caused an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessRef {
    /// The process id.
    pub pid: Pid,
    /// BLAKE3 digest of the executable image, when known.
    pub exe_digest: Option<Blake3Hash>,
}

/// The exit result of a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitStatus {
    /// Exit code, if the process exited normally.
    pub code: Option<i32>,
    /// Terminating signal number, if killed by a signal.
    pub signal: Option<i32>,
}

/// A requested capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRequest {
    /// The class of capability.
    pub kind: CapabilityKind,
    /// A human-readable target/description.
    pub target: Option<BoundedText>,
}

/// The scope attached to a granted capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantScope {
    /// Human-readable grant detail.
    pub detail: BoundedText,
    /// Expiry, relative to grant time, if the grant is time-bounded.
    pub expires: Option<Duration>,
}

/// A credential scope such as `contents:read`. Carries no secret material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope(pub BoundedText);

impl Scope {
    /// Build a scope from a scope string.
    pub fn new(raw: &str) -> Self {
        Self(BoundedText::new(raw))
    }
}

/// A reference to a policy rule (opaque identifier).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRef(pub String);

/// A countersignature over an anchor from TamperWard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TamperWardSig(pub Vec<u8>);

/// A destination that was denied before a host name could be established.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeniedDst {
    /// Host or textual address that was targeted.
    pub addr: BoundedText,
    /// Destination port.
    pub port: u16,
}

/// The subject a policy decision applies to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicySubject {
    /// A process.
    Process(ProcessRef),
    /// A filesystem path.
    Path(SandboxPath),
    /// A network host.
    Host(HostName),
    /// A capability request.
    Capability(CapabilityRequest),
    /// A snapshot.
    Snapshot(SnapshotId),
    /// The session as a whole.
    Session,
    /// Anything else, described textually.
    Other(BoundedText),
}

/// Summary of a verification run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifySummary {
    /// Total steps run.
    pub steps: u32,
    /// Steps that passed.
    pub passed: u32,
    /// Steps that failed.
    pub failed: u32,
    /// Human-readable summary.
    pub detail: BoundedText,
}

/// The typed WardOS event catalogue (event-model §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WardEvent {
    /// A session started.
    SessionStarted {
        /// The project.
        project: ProjectId,
        /// The agent identity.
        agent: AgentIdentity,
        /// Hash of the capability manifest.
        manifest_hash: Blake3Hash,
        /// The entry snapshot.
        entry_snapshot: SnapshotId,
        /// Hash of the merged policy.
        policy_hash: Blake3Hash,
        /// Digests of the mounted tool images.
        tool_images: Vec<ImageDigest>,
    },
    /// A session ended.
    SessionEnded {
        /// Why it ended.
        reason: EndReason,
        /// The final snapshot, if one was taken.
        final_snapshot: Option<SnapshotId>,
    },
    /// The agent's coarse state changed.
    AgentStateChanged {
        /// The new state.
        state: AgentState,
    },

    /// A file under `/work` or `/env` was read.
    FileRead {
        /// The path.
        path: SandboxPath,
        /// The reader.
        by: ProcessRef,
    },
    /// A file under `/work` or `/env` was modified.
    FileModified {
        /// The path.
        path: SandboxPath,
        /// The modifier.
        by: ProcessRef,
        /// The kind of change.
        kind: FileChange,
    },

    /// A command started.
    CommandStarted {
        /// The new process id.
        pid: Pid,
        /// The parent process id.
        parent: Pid,
        /// The sanitised argv.
        argv: BoundedArgv,
        /// The working directory.
        cwd: SandboxPath,
        /// Digest of the executable image, when known.
        exe_digest: Option<Blake3Hash>,
    },
    /// A command finished.
    CommandFinished {
        /// The process id.
        pid: Pid,
        /// The exit result.
        exit: ExitStatus,
        /// Wall-clock duration.
        duration: Duration,
    },

    /// The proxy made an egress decision.
    NetworkRequested {
        /// The target host.
        host: HostName,
        /// The target port.
        port: u16,
        /// The decision.
        decision: Decision,
        /// The rule that decided it.
        rule: RuleRef,
        /// The requesting process.
        by: ProcessRef,
    },
    /// An egress attempt was denied before a host was established.
    NetworkDenied {
        /// The denied destination.
        dst: DeniedDst,
        /// Why it was denied.
        reason: DenyReason,
    },

    /// A capability was requested.
    CapabilityRequested {
        /// The capability.
        cap: CapabilityRequest,
        /// Optional stated reason.
        reason: Option<BoundedText>,
    },
    /// A capability request was decided.
    CapabilityDecided {
        /// The capability.
        cap: CapabilityRequest,
        /// The decision.
        decision: Decision,
        /// Who decided.
        by: DecisionSource,
        /// The granted scope, if allowed.
        grant: Option<GrantScope>,
    },
    /// A credential was requested.
    CredentialRequested {
        /// The service.
        service: ServiceId,
        /// The requested scope.
        scope: Scope,
    },
    /// A credential was granted — scope and expiry only, never the token.
    CredentialGranted {
        /// The service.
        service: ServiceId,
        /// The granted scope.
        scope: Scope,
        /// Time until expiry.
        expires: Duration,
        /// How it is delivered.
        delivery: CredentialDelivery,
    },
    /// A credential was denied.
    CredentialDenied {
        /// The service.
        service: ServiceId,
        /// The requested scope.
        scope: Scope,
        /// Why it was denied.
        reason: DenyReason,
    },
    /// A credential was revoked.
    CredentialRevoked {
        /// The service.
        service: ServiceId,
        /// Why it was revoked.
        reason: RevokeReason,
    },

    /// A snapshot was created.
    SnapshotCreated {
        /// The snapshot role.
        role: SnapshotRole,
        /// The snapshot id.
        id: SnapshotId,
        /// Number of manifest entries.
        entries: u64,
        /// Total bytes captured.
        bytes: u64,
        /// The capture mode.
        capture: CaptureMode,
        /// Freeze stall incurred.
        stall: Duration,
    },

    /// TamperWard made a policy decision.
    PolicyDecision {
        /// The subject.
        subject: PolicySubject,
        /// The decision.
        decision: Decision,
        /// The deciding rule.
        rule: RuleRef,
        /// Human-readable detail.
        detail: BoundedText,
    },
    /// A policy denial (convenience projection of a deny decision).
    PolicyDenied {
        /// The subject.
        subject: PolicySubject,
        /// The deciding rule.
        rule: RuleRef,
        /// Human-readable detail.
        detail: BoundedText,
    },
    /// Tampering was detected.
    TamperDetected {
        /// The subject.
        subject: PolicySubject,
        /// Human-readable detail.
        detail: BoundedText,
    },

    /// Verification was requested.
    VerificationRequested {
        /// The candidate snapshot.
        candidate: SnapshotId,
        /// Who requested it.
        requested_by: RequestSource,
    },
    /// Verification started.
    VerificationStarted {
        /// The candidate snapshot.
        candidate: SnapshotId,
        /// The pristine baseline snapshot.
        pristine: SnapshotId,
        /// The verifier image digest.
        verifier_image: ImageDigest,
        /// Hash of the verification manifest.
        manifest_hash: Blake3Hash,
    },
    /// A verification step reported progress.
    VerificationProgress {
        /// The step description.
        step: BoundedText,
        /// The step status.
        status: VerifyStatus,
    },
    /// Verification passed.
    VerificationPassed {
        /// The candidate snapshot.
        candidate: SnapshotId,
        /// The result summary.
        summary: VerifySummary,
        /// Hash of the signed result.
        result_hash: Blake3Hash,
    },
    /// Verification failed.
    VerificationFailed {
        /// The candidate snapshot.
        candidate: SnapshotId,
        /// The result summary.
        summary: VerifySummary,
        /// Hash of the signed result.
        result_hash: Blake3Hash,
    },
    /// TamperWard accepted a verified state.
    StateAccepted {
        /// The accepted snapshot.
        snapshot: SnapshotId,
        /// Who accepted it.
        by: RequestSource,
    },

    /// An agent claim. Never an enforcement fact (threat-model row 14).
    AgentClaim {
        /// The claim kind.
        kind: AgentClaimKind,
        /// The claim payload.
        payload: BoundedText,
    },

    /// A chain anchor, optionally countersigned by TamperWard.
    Anchor {
        /// The chain head at this point.
        chain_head: Blake3Hash,
        /// The sequence number the head covers.
        seq: u64,
        /// A TamperWard countersignature, when present.
        countersigned_by: Option<TamperWardSig>,
    },
}
