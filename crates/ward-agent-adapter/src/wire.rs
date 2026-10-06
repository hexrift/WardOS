//! The run-time half of the contract: what crosses the hook socket, what a host answers,
//! and what it records.
//!
//! * [`SemanticEventLine`] is one request line an adapter writes to `$WARD_SOCKET`
//!   (`/run/ward/hooks.sock`); [`ApprovalAnswer`] is the one line it reads back. This is
//!   exactly what `ward-agent hook` speaks for Claude Code, so a custom agent that writes
//!   these lines gets the same claims and the same approval holds.
//! * [`CapabilityRequest`] and [`CancelRequest`] are the shapes of two features a
//!   contract-1.0 host does not serve yet (see [`crate::contract::SERVED_FEATURES`]).
//! * [`TaskResult`] is the outcome of a launch, decided by the host from the exit status.
//! * [`AdapterBinding`] is the evidence record of which adapter a launch used.
//!
//! None of these carries authority. A line on the hook socket is a claim; an answer is
//! steering the agent may ignore; the binding is metadata.

use std::fmt::{Display, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::contract::{ContractVersion, HookSupport, SemanticEvent, SemanticEvents};
use crate::launch::ProviderId;
use crate::{AdapterId, RuntimeMetadata, valid_metadata_text};

/// Largest `summary` on a hook line, in bytes (`ward-agent hook`'s cap).
pub const SUMMARY_MAX: usize = 256;
/// Largest tool name on a hook line, in bytes.
pub const TOOL_MAX: usize = 128;
/// Largest free-text reason, in bytes.
pub const REASON_MAX: usize = 256;

/// One semantic event, as an adapter writes it to the hook socket.
///
/// `{"hook":"PreToolUse","tool":"Write","summary":"/work/src/lib.rs"}`. A tool event
/// (`PreToolUse`, `PostToolUse`, `PermissionRequest`) names its tool; `SessionStart` and
/// `Stop` carry neither tool nor summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SemanticEventLine {
    hook: SemanticEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
}

impl SemanticEventLine {
    /// Construct a validated line.
    ///
    /// # Errors
    ///
    /// See [`SemanticEventLineError`].
    pub fn new(
        hook: SemanticEvent,
        tool: Option<&str>,
        summary: Option<&str>,
    ) -> Result<Self, SemanticEventLineError> {
        match (hook.names_a_tool(), tool) {
            (true, None) => return Err(SemanticEventLineError::MissingTool),
            (false, Some(_)) => return Err(SemanticEventLineError::UnexpectedTool),
            (false, None) if summary.is_some() => {
                return Err(SemanticEventLineError::UnexpectedSummary);
            }
            _ => {}
        }
        if let Some(tool) = tool {
            let valid = !tool.is_empty()
                && tool.len() <= TOOL_MAX
                && tool
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'));
            if !valid {
                return Err(SemanticEventLineError::InvalidTool);
            }
        }
        if let Some(summary) = summary
            && (summary.len() > SUMMARY_MAX || summary.chars().any(char::is_control))
        {
            return Err(SemanticEventLineError::InvalidSummary);
        }
        Ok(Self {
            hook,
            tool: tool.map(str::to_owned),
            summary: summary.map(str::to_owned),
        })
    }

    /// The event.
    #[must_use]
    pub const fn hook(&self) -> SemanticEvent {
        self.hook
    }

    /// The tool, for tool events.
    #[must_use]
    pub fn tool(&self) -> Option<&str> {
        self.tool.as_deref()
    }

    /// The sanitised description of the tool's input.
    #[must_use]
    pub fn summary(&self) -> Option<&str> {
        self.summary.as_deref()
    }
}

/// Invalid semantic event line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticEventLineError {
    /// A tool event without a tool.
    MissingTool,
    /// A tool on `SessionStart` or `Stop`.
    UnexpectedTool,
    /// A summary on `SessionStart` or `Stop`.
    UnexpectedSummary,
    /// Empty, oversized or outside `A-Z a-z 0-9 _ - . :`.
    InvalidTool,
    /// Oversized or containing control characters.
    InvalidSummary,
}

impl Display for SemanticEventLineError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MissingTool => "a tool event must name its tool",
            Self::UnexpectedTool => "only tool events name a tool",
            Self::UnexpectedSummary => "only tool events carry a summary",
            Self::InvalidTool => "tool name is invalid",
            Self::InvalidSummary => "summary is invalid",
        })
    }
}

impl std::error::Error for SemanticEventLineError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticEventLineWire {
    hook: SemanticEvent,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    summary: Option<String>,
}

impl<'de> Deserialize<'de> for SemanticEventLine {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = SemanticEventLineWire::deserialize(deserializer)?;
        Self::new(wire.hook, wire.tool.as_deref(), wire.summary.as_deref())
            .map_err(D::Error::custom)
    }
}

/// The host's answer to a semantic event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalDecision {
    /// Proceed.
    Allow,
    /// Refuse the tool call.
    Deny,
    /// Hold for the user (answered by the host's approval surface, or by the agent's own
    /// prompt when no host daemon serves the session).
    Ask,
}

/// One answer line: `{"decision":"ask","reason":"step-through: pause before writes"}`.
///
/// Honouring it is the adapter's job and is steering, not enforcement: an adapter that
/// ignores a `deny` has still not gained anything the sandbox, proxy or broker refuse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalAnswer {
    /// The verdict.
    pub decision: ApprovalDecision,
    /// Short human-readable reason.
    pub reason: String,
}

/// What a bounded capability request asks for (contract shape; unserved in 1.0).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestedCapability {
    /// Egress to one host the session allowlist does not already permit.
    Network {
        /// Lowercase DNS name.
        host: String,
    },
    /// A brokered credential for one configured service.
    Credential {
        /// Service name as policy names it (`github`).
        service: String,
    },
}

/// A capability request an adapter would send (contract shape; unserved in 1.0).
///
/// When served, it is a *request*: the host decides it under the session's policy and
/// the approval flow, exactly as for a user's `--grant`, and records both sides.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapabilityRequest {
    capability: RequestedCapability,
    reason: String,
}

impl CapabilityRequest {
    /// Construct a validated request.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityRequestError`] for a malformed host or service, or a reason
    /// that is empty, oversized or contains control characters.
    pub fn new(
        capability: RequestedCapability,
        reason: &str,
    ) -> Result<Self, CapabilityRequestError> {
        let target_ok = match &capability {
            RequestedCapability::Network { host } => valid_host(host),
            RequestedCapability::Credential { service } => ProviderId::new(service).is_ok(),
        };
        if !target_ok {
            return Err(CapabilityRequestError::InvalidTarget);
        }
        if !valid_metadata_text(reason, REASON_MAX) {
            return Err(CapabilityRequestError::InvalidReason);
        }
        Ok(Self {
            capability,
            reason: reason.to_owned(),
        })
    }

    /// What is requested.
    #[must_use]
    pub const fn capability(&self) -> &RequestedCapability {
        &self.capability
    }

    /// Why, in the agent's words (a claim).
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Invalid capability request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityRequestError {
    /// The host or service is malformed.
    InvalidTarget,
    /// The reason is empty, oversized or contains control characters.
    InvalidReason,
}

impl Display for CapabilityRequestError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTarget => "capability request target is invalid",
            Self::InvalidReason => "capability request reason is invalid",
        })
    }
}

impl std::error::Error for CapabilityRequestError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityRequestWire {
    capability: RequestedCapability,
    reason: String,
}

impl<'de> Deserialize<'de> for CapabilityRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = CapabilityRequestWire::deserialize(deserializer)?;
        Self::new(wire.capability, &wire.reason).map_err(D::Error::custom)
    }
}

/// Why a task is cancelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelReason {
    /// The user stopped it (`ward stop`).
    User,
    /// Its budget ran out.
    Deadline,
    /// Its authority was revoked (a node `revoke`, a lease withdrawn).
    Revoked,
}

/// A cancellation of an adapter's task.
///
/// The host carries it out by stopping the sandbox's whole process tree and confirming
/// it gone, for every adapter, whatever its document says: cancellation never depends on
/// the agent's cooperation. An adapter claiming the `cancellation` feature would also be
/// asked to stop cooperatively first; contract-1.0 hosts do not do that yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    /// Why.
    pub reason: CancelReason,
}

/// How a task ended, as the host saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskOutcome {
    /// The program exited 0.
    Completed,
    /// The program exited non-zero or was killed by a signal.
    Failed,
    /// No exit was observed (the launch never got that far).
    Unknown,
}

/// The result of one adapter launch.
///
/// The outcome is the host's, from the exit status; an adapter's structured result (the
/// `structured_task_result` feature) would only ever be attached as a claim and can
/// never turn a failed task into a completed one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskResult {
    /// Outcome.
    pub outcome: TaskOutcome,
    /// Exit code, when the program exited normally.
    pub exit_code: Option<i32>,
}

impl TaskResult {
    /// The result for an exit `code` (`None`: killed by a signal) of a launch that ran.
    #[must_use]
    pub const fn from_exit(code: Option<i32>) -> Self {
        Self {
            outcome: match code {
                Some(0) => TaskOutcome::Completed,
                _ => TaskOutcome::Failed,
            },
            exit_code: code,
        }
    }

    /// The result of a launch that never ran to an exit.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            outcome: TaskOutcome::Unknown,
            exit_code: None,
        }
    }
}

/// Which adapter a launch used: recorded in the session's evidence as an agent-origin
/// claim (`AgentClaim { Note }`), so it can never be read as an enforcement fact.
///
/// Every field is metadata: the runtime is what the adapter declares, the model is what
/// the command line requested (`None` when the runtime picks its own default), and
/// neither is verified. No identity, authority or policy is derived from it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdapterBinding {
    contract: ContractVersion,
    adapter: AdapterId,
    runtime: RuntimeMetadata,
    hooks: HookSupport,
    events: SemanticEvents,
    provider: Option<ProviderId>,
    model: Option<String>,
}

impl AdapterBinding {
    /// Largest model name, in bytes.
    pub const MAX_MODEL_BYTES: usize = 128;

    /// Construct a binding.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterBindingError::InvalidModel`] for an empty, oversized or
    /// control-character-containing model. The hook coverage is derived from `events`;
    /// a wire binding whose `hooks` contradicts its `events` fails to decode with
    /// [`AdapterBindingError::HookCoverageMismatch`].
    pub fn new(
        adapter: AdapterId,
        runtime: RuntimeMetadata,
        events: SemanticEvents,
        provider: Option<ProviderId>,
        model: Option<&str>,
    ) -> Result<Self, AdapterBindingError> {
        if let Some(model) = model
            && !valid_metadata_text(model, Self::MAX_MODEL_BYTES)
        {
            return Err(AdapterBindingError::InvalidModel);
        }
        Ok(Self {
            contract: ContractVersion::CURRENT,
            adapter,
            runtime,
            hooks: events.coverage(),
            events,
            provider,
            model: model.map(str::to_owned),
        })
    }

    /// The adapter.
    #[must_use]
    pub const fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    /// Declared runtime metadata.
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeMetadata {
        &self.runtime
    }

    /// Hook coverage.
    #[must_use]
    pub const fn hooks(&self) -> HookSupport {
        self.hooks
    }

    /// Declared semantic events.
    #[must_use]
    pub const fn events(&self) -> &SemanticEvents {
        &self.events
    }

    /// Provider gateway, if any.
    #[must_use]
    pub const fn provider(&self) -> Option<&ProviderId> {
        self.provider.as_ref()
    }

    /// Model as requested on the command line.
    #[must_use]
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }
}

/// Invalid adapter binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterBindingError {
    /// The model is empty, oversized or contains control characters.
    InvalidModel,
    /// `hooks` contradicts `events`.
    HookCoverageMismatch,
}

impl Display for AdapterBindingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidModel => "model metadata is invalid",
            Self::HookCoverageMismatch => "binding hook coverage contradicts its events",
        })
    }
}

impl std::error::Error for AdapterBindingError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterBindingWire {
    contract: ContractVersion,
    adapter: AdapterId,
    runtime: RuntimeMetadata,
    hooks: HookSupport,
    events: SemanticEvents,
    provider: Option<ProviderId>,
    model: Option<String>,
}

impl<'de> Deserialize<'de> for AdapterBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = AdapterBindingWire::deserialize(deserializer)?;
        if wire.events.coverage() != wire.hooks {
            return Err(D::Error::custom(AdapterBindingError::HookCoverageMismatch));
        }
        let mut binding = Self::new(
            wire.adapter,
            wire.runtime,
            wire.events,
            wire.provider,
            wire.model.as_deref(),
        )
        .map_err(D::Error::custom)?;
        binding.contract = wire.contract;
        Ok(binding)
    }
}

/// The payload of the binding's evidence record: `{"agent_adapter":{…}}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingClaim {
    /// The binding.
    pub agent_adapter: AdapterBinding,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn event_lines_match_the_hook_socket_protocol() {
        let line =
            SemanticEventLine::new(SemanticEvent::PreToolUse, Some("Write"), Some("/work/a.rs"))
                .unwrap();
        assert_eq!(
            serde_json::to_string(&line).unwrap(),
            r#"{"hook":"PreToolUse","tool":"Write","summary":"/work/a.rs"}"#
        );
        let stop = SemanticEventLine::new(SemanticEvent::Stop, None, None).unwrap();
        assert_eq!(serde_json::to_string(&stop).unwrap(), r#"{"hook":"Stop"}"#);
        assert_eq!(
            serde_json::from_str::<SemanticEventLine>(
                r#"{"hook":"PostToolUse","tool":"mcp__git__status"}"#
            )
            .unwrap()
            .tool(),
            Some("mcp__git__status")
        );
    }

    #[test]
    fn malformed_event_lines_fail_closed() {
        use SemanticEventLineError as E;
        assert_eq!(
            SemanticEventLine::new(SemanticEvent::PreToolUse, None, None),
            Err(E::MissingTool)
        );
        assert_eq!(
            SemanticEventLine::new(SemanticEvent::Stop, Some("Write"), None),
            Err(E::UnexpectedTool)
        );
        assert_eq!(
            SemanticEventLine::new(SemanticEvent::SessionStart, None, Some("x")),
            Err(E::UnexpectedSummary)
        );
        for tool in ["", "has space", "a/b", &"t".repeat(TOOL_MAX + 1)] {
            assert_eq!(
                SemanticEventLine::new(SemanticEvent::PostToolUse, Some(tool), None),
                Err(E::InvalidTool),
                "{tool:?}"
            );
        }
        for summary in ["a\nb", &"s".repeat(SUMMARY_MAX + 1)] {
            assert_eq!(
                SemanticEventLine::new(SemanticEvent::PostToolUse, Some("Bash"), Some(summary)),
                Err(E::InvalidSummary)
            );
        }
        for raw in [
            r#"{"hook":"Notification"}"#,
            r#"{"hook":"PreToolUse"}"#,
            r#"{"hook":"Stop","grant":"network"}"#,
            r#"{"hook":"PreToolUse","tool":"Bash","summary":"ls","decision":"allow"}"#,
        ] {
            assert!(
                serde_json::from_str::<SemanticEventLine>(raw).is_err(),
                "{raw}"
            );
        }
    }

    #[test]
    fn approval_answers_are_the_three_hook_decisions() {
        let answer: ApprovalAnswer = serde_json::from_str(
            r#"{"decision":"ask","reason":"step-through: pause before writes"}"#,
        )
        .unwrap();
        assert_eq!(answer.decision, ApprovalDecision::Ask);
        for raw in [
            r#"{"decision":"Allow","reason":""}"#,
            r#"{"decision":"grant","reason":""}"#,
            r#"{"decision":"allow","reason":"","scope":"session"}"#,
        ] {
            assert!(
                serde_json::from_str::<ApprovalAnswer>(raw).is_err(),
                "{raw}"
            );
        }
    }

    #[test]
    fn capability_requests_are_bounded_requests() {
        let request = CapabilityRequest::new(
            RequestedCapability::Network {
                host: "registry.npmjs.org".into(),
            },
            "install the lockfile",
        )
        .unwrap();
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"capability":{"network":{"host":"registry.npmjs.org"}},"reason":"install the lockfile"}"#
        );
        assert_eq!(
            serde_json::from_str::<CapabilityRequest>(&serde_json::to_string(&request).unwrap())
                .unwrap(),
            request
        );
        for host in [
            "",
            "*.example.com",
            "Example.com",
            "a..b",
            "-a.b",
            "10.0.0.1:80",
        ] {
            assert_eq!(
                CapabilityRequest::new(RequestedCapability::Network { host: host.into() }, "x"),
                Err(CapabilityRequestError::InvalidTarget),
                "{host:?}"
            );
        }
        assert_eq!(
            CapabilityRequest::new(
                RequestedCapability::Credential {
                    service: "GitHub".into()
                },
                "x"
            ),
            Err(CapabilityRequestError::InvalidTarget)
        );
        assert_eq!(
            CapabilityRequest::new(
                RequestedCapability::Credential {
                    service: "github".into()
                },
                ""
            ),
            Err(CapabilityRequestError::InvalidReason)
        );
        for raw in [
            r#"{"capability":{"network":{"host":"a.b"}},"reason":"x","granted":true}"#,
            r#"{"capability":{"unrestricted":{}},"reason":"x"}"#,
        ] {
            assert!(
                serde_json::from_str::<CapabilityRequest>(raw).is_err(),
                "{raw}"
            );
        }
    }

    #[test]
    fn the_outcome_is_the_hosts_from_the_exit_status() {
        assert_eq!(
            TaskResult::from_exit(Some(0)).outcome,
            TaskOutcome::Completed
        );
        assert_eq!(TaskResult::from_exit(Some(3)).outcome, TaskOutcome::Failed);
        assert_eq!(TaskResult::from_exit(None).outcome, TaskOutcome::Failed);
        assert_eq!(TaskResult::unknown().outcome, TaskOutcome::Unknown);
        assert_eq!(
            serde_json::to_string(&TaskResult::from_exit(Some(0))).unwrap(),
            r#"{"outcome":"completed","exit_code":0}"#
        );
        assert!(
            serde_json::from_str::<TaskResult>(
                r#"{"outcome":"completed","exit_code":1,"claimed":"done"}"#
            )
            .is_err()
        );
        assert_eq!(
            serde_json::to_string(&CancelRequest {
                reason: CancelReason::Revoked
            })
            .unwrap(),
            r#"{"reason":"revoked"}"#
        );
    }

    #[test]
    fn the_binding_is_metadata_with_a_stable_shape() {
        let binding = AdapterBinding::new(
            AdapterId::new("claude-code").unwrap(),
            RuntimeMetadata::new("Claude Code", Some("2.1.263")).unwrap(),
            SemanticEvents::all(),
            Some(ProviderId::new("anthropic").unwrap()),
            Some("claude-sonnet-4-5"),
        )
        .unwrap();
        assert_eq!(binding.hooks(), HookSupport::Full);
        let claim = BindingClaim {
            agent_adapter: binding,
        };
        let json = serde_json::to_string(&claim).unwrap();
        assert_eq!(
            json,
            r#"{"agent_adapter":{"contract":"1.0","adapter":"claude-code","runtime":{"product":"Claude Code","version":"2.1.263"},"hooks":"full","events":["SessionStart","PreToolUse","PostToolUse","PermissionRequest","Stop"],"provider":"anthropic","model":"claude-sonnet-4-5"}}"#
        );
        assert_eq!(serde_json::from_str::<BindingClaim>(&json).unwrap(), claim);

        assert_eq!(
            AdapterBinding::new(
                AdapterId::new("process").unwrap(),
                RuntimeMetadata::new("agent", None).unwrap(),
                SemanticEvents::none(),
                None,
                Some("bad\nmodel"),
            ),
            Err(AdapterBindingError::InvalidModel)
        );
        for raw in [
            r#"{"agent_adapter":{"contract":"1.0","adapter":"process","runtime":{"product":"a","version":null},"hooks":"full","events":[],"provider":null,"model":null}}"#,
            r#"{"agent_adapter":{"contract":"1.0","adapter":"process","runtime":{"product":"a","version":null},"hooks":"none","events":[],"provider":null,"model":null,"principal":"root"}}"#,
            r#"{"agent_adapter":{"contract":"3.0","adapter":"process","runtime":{"product":"a","version":null},"hooks":"none","events":[],"provider":null,"model":null}}"#,
        ] {
            assert!(serde_json::from_str::<BindingClaim>(raw).is_err(), "{raw}");
        }
    }
}
