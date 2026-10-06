//! The versioned adapter contract and its capability-discovery document.
//!
//! A [`CapabilityDocument`] says, for one adapter, which parts of the contract it
//! supports: how much of the hook layer it wires ([`HookSupport`]), which semantic
//! events it emits ([`SemanticEvents`]) and which integration features it claims
//! (the [`AgentAdapterDescriptor`]'s [`AdapterFeatures`]). Everything in it describes
//! *semantic visibility*. Nothing in it is, or can be turned into, sandbox, network or
//! credential authority: those come from the session's capability manifest and are
//! enforced by the host for every adapter alike, whatever its document says.

use std::fmt::{Display, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{AdapterFeature, AdapterFeatures, AgentAdapterDescriptor};

/// Version of the adapter contract, `major.minor`.
///
/// A reader accepts a document of its own major version and a minor version no newer
/// than its own; anything else fails closed, because a newer minor may carry claims
/// the reader cannot check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContractVersion {
    major: u16,
    minor: u16,
}

impl ContractVersion {
    /// Contract 1.0: launch, the five semantic events, approvals on the decision hooks,
    /// the capability-request, cancellation and task-result shapes, and the binding
    /// record.
    pub const V1_0: Self = Self { major: 1, minor: 0 };
    /// The version this build speaks.
    pub const CURRENT: Self = Self::V1_0;

    /// Major version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Minor version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }

    /// Whether a reader of [`CURRENT`](Self::CURRENT) can trust a document of this
    /// version: same major, minor no newer.
    #[must_use]
    // While the current minor is 0 the minor comparison is an equality; it is spelled
    // as the rule so the next minor changes one constant, not the rule.
    #[allow(clippy::absurd_extreme_comparisons)]
    pub const fn is_supported(self) -> bool {
        self.major == Self::CURRENT.major && self.minor <= Self::CURRENT.minor
    }

    /// Parse `major.minor` (decimal, no sign, no leading zeros, no whitespace).
    ///
    /// # Errors
    ///
    /// Returns [`ContractVersionError::Malformed`] for anything else.
    pub fn parse(text: &str) -> Result<Self, ContractVersionError> {
        let number = |part: &str| {
            let canonical = !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part == "0" || !part.starts_with('0'));
            canonical
                .then(|| part.parse::<u16>().ok())
                .flatten()
                .ok_or(ContractVersionError::Malformed)
        };
        let (major, minor) = text
            .split_once('.')
            .ok_or(ContractVersionError::Malformed)?;
        Ok(Self {
            major: number(major)?,
            minor: number(minor)?,
        })
    }
}

impl Display for ContractVersion {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}", self.major, self.minor)
    }
}

/// Invalid or unsupported contract version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractVersionError {
    /// Not `major.minor`.
    Malformed,
    /// Another major version, or a newer minor than this reader speaks.
    Unsupported(ContractVersion),
}

impl Display for ContractVersionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => formatter.write_str("adapter contract version is malformed"),
            Self::Unsupported(version) => write!(
                formatter,
                "adapter contract {version} is not supported (this reader speaks {})",
                ContractVersion::CURRENT
            ),
        }
    }
}

impl std::error::Error for ContractVersionError {}

impl Serialize for ContractVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ContractVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let version = Self::parse(&text).map_err(D::Error::custom)?;
        if !version.is_supported() {
            return Err(D::Error::custom(ContractVersionError::Unsupported(version)));
        }
        Ok(version)
    }
}

/// How much of the contract's hook layer an adapter wires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookSupport {
    /// Every [`SemanticEvent`] of the contract.
    Full,
    /// Some, not all, of them.
    Partial,
    /// None: the adapter is observed from the host only (exec, files, network).
    None,
}

impl HookSupport {
    /// Wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::None => "none",
        }
    }
}

/// One semantic event an adapter can report over the session's hook socket.
///
/// The spelling is the `hook` field of the wire line ([`crate::wire::SemanticEventLine`]),
/// the same everywhere it appears. Every event is a *claim* (`Origin::Agent`): it
/// steers the step-through UX and feeds the observer, and is never used to decide what
/// the sandbox, the proxy or the broker allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticEvent {
    /// The agent session started.
    SessionStart,
    /// A tool is about to run; the answer may be `allow`, `deny` or `ask` (an approval).
    PreToolUse,
    /// A tool ran.
    PostToolUse,
    /// The agent is about to show its own permission prompt; the answer may deny it.
    PermissionRequest,
    /// The agent finished its turn.
    Stop,
}

impl SemanticEvent {
    /// Every event of the contract, in canonical order.
    pub const ALL: [Self; 5] = [
        Self::SessionStart,
        Self::PreToolUse,
        Self::PostToolUse,
        Self::PermissionRequest,
        Self::Stop,
    ];

    /// Wire spelling (the `hook` field).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionStart => "SessionStart",
            Self::PreToolUse => "PreToolUse",
            Self::PostToolUse => "PostToolUse",
            Self::PermissionRequest => "PermissionRequest",
            Self::Stop => "Stop",
        }
    }

    /// The event for a wire spelling, if it is one of the contract's.
    #[must_use]
    pub fn from_wire(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|event| event.as_str() == name)
    }

    /// Whether the event names a tool (and so carries `tool` on the wire).
    #[must_use]
    pub const fn names_a_tool(self) -> bool {
        matches!(
            self,
            Self::PreToolUse | Self::PostToolUse | Self::PermissionRequest
        )
    }

    /// Whether the event reports tool use (the `semantic_tool_events` feature).
    #[must_use]
    pub const fn is_tool_event(self) -> bool {
        matches!(self, Self::PreToolUse | Self::PostToolUse)
    }

    /// Whether the host's answer to the event is a decision the agent honours (the
    /// points an approval can be held at).
    #[must_use]
    pub const fn is_decision_point(self) -> bool {
        matches!(self, Self::PreToolUse | Self::PermissionRequest)
    }
}

/// Canonical, duplicate-free set of semantic events.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct SemanticEvents(Vec<SemanticEvent>);

impl SemanticEvents {
    /// Construct a canonical set; input order is normalised to [`SemanticEvent::ALL`]'s.
    ///
    /// # Errors
    ///
    /// Returns [`SemanticEventsError::Duplicate`] when an event is given twice.
    pub fn new(
        events: impl IntoIterator<Item = SemanticEvent>,
    ) -> Result<Self, SemanticEventsError> {
        let mut values: Vec<_> = events.into_iter().collect();
        values.sort_unstable();
        if let Some(event) = values
            .windows(2)
            .find_map(|pair| (pair[0] == pair[1]).then_some(pair[0]))
        {
            return Err(SemanticEventsError::Duplicate(event));
        }
        Ok(Self(values))
    }

    /// No events.
    #[must_use]
    pub const fn none() -> Self {
        Self(Vec::new())
    }

    /// Every event of the contract.
    #[must_use]
    pub fn all() -> Self {
        Self(SemanticEvent::ALL.to_vec())
    }

    /// Canonical ordered slice.
    #[must_use]
    pub fn as_slice(&self) -> &[SemanticEvent] {
        &self.0
    }

    /// Whether the set holds `event`.
    #[must_use]
    pub fn contains(&self, event: SemanticEvent) -> bool {
        self.0.binary_search(&event).is_ok()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The hook coverage this set amounts to.
    #[must_use]
    pub fn coverage(&self) -> HookSupport {
        if self.0.is_empty() {
            HookSupport::None
        } else if self.0.len() == SemanticEvent::ALL.len() {
            HookSupport::Full
        } else {
            HookSupport::Partial
        }
    }
}

/// Invalid semantic event set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticEventsError {
    /// An event appeared more than once.
    Duplicate(SemanticEvent),
    /// Wire events were not in canonical order.
    NonCanonicalOrder,
}

impl Display for SemanticEventsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Duplicate(event) => write!(formatter, "duplicate semantic event: {event:?}"),
            Self::NonCanonicalOrder => formatter.write_str("semantic events are not canonical"),
        }
    }
}

impl std::error::Error for SemanticEventsError {}

impl<'de> Deserialize<'de> for SemanticEvents {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = Vec::<SemanticEvent>::deserialize(deserializer)?;
        let canonical = Self::new(wire.iter().copied()).map_err(D::Error::custom)?;
        if canonical.0 != wire {
            return Err(D::Error::custom(SemanticEventsError::NonCanonicalOrder));
        }
        Ok(canonical)
    }
}

/// The capability-discovery document of one adapter (contract 1.0).
///
/// Wire shape:
/// `{"contract":"1.0","adapter":{…descriptor…},"hooks":"full","events":["SessionStart",…]}`.
/// Unknown fields, an unsupported contract version and every inconsistency listed on
/// [`CapabilityDocumentError`] fail closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapabilityDocument {
    pub(crate) contract: ContractVersion,
    pub(crate) adapter: AgentAdapterDescriptor,
    pub(crate) hooks: HookSupport,
    pub(crate) events: SemanticEvents,
}

impl CapabilityDocument {
    /// Construct a validated document.
    ///
    /// # Errors
    ///
    /// See [`CapabilityDocumentError`].
    pub fn new(
        contract: ContractVersion,
        adapter: AgentAdapterDescriptor,
        hooks: HookSupport,
        events: SemanticEvents,
    ) -> Result<Self, CapabilityDocumentError> {
        if !contract.is_supported() {
            return Err(CapabilityDocumentError::UnsupportedContract(contract));
        }
        let features = adapter.features();
        if !features.contains(AdapterFeature::Launch) {
            return Err(CapabilityDocumentError::LaunchRequired);
        }
        if events.coverage() != hooks {
            return Err(CapabilityDocumentError::HookCoverageMismatch);
        }
        let tool_events = events.as_slice().iter().any(|e| e.is_tool_event());
        if features.contains(AdapterFeature::SemanticToolEvents) != tool_events {
            return Err(CapabilityDocumentError::ToolEventsMismatch);
        }
        let decision_points = events.as_slice().iter().any(|e| e.is_decision_point());
        if features.contains(AdapterFeature::ApprovalRequests) && !decision_points {
            return Err(CapabilityDocumentError::ApprovalsWithoutDecisionPoint);
        }
        Ok(Self {
            contract,
            adapter,
            hooks,
            events,
        })
    }

    /// Contract version the document is written against.
    #[must_use]
    pub const fn contract(&self) -> ContractVersion {
        self.contract
    }

    /// The adapter's descriptor: id, runtime metadata, visibility, features.
    #[must_use]
    pub const fn adapter(&self) -> &AgentAdapterDescriptor {
        &self.adapter
    }

    /// Hook coverage.
    #[must_use]
    pub const fn hooks(&self) -> HookSupport {
        self.hooks
    }

    /// Semantic events the adapter emits.
    #[must_use]
    pub const fn events(&self) -> &SemanticEvents {
        &self.events
    }

    /// What a host speaking [`ContractVersion::CURRENT`] actually serves of the
    /// adapter's claims (see [`SERVED_FEATURES`]).
    #[must_use]
    pub fn coverage(&self) -> Coverage {
        let (served, unserved): (Vec<_>, Vec<_>) = self
            .adapter
            .features()
            .as_slice()
            .iter()
            .copied()
            .partition(|feature| SERVED_FEATURES.contains(feature));
        Coverage {
            served: AdapterFeatures(served),
            unserved: AdapterFeatures(unserved),
            hooks: self.hooks,
            events: self.events.clone(),
        }
    }
}

/// Inconsistent capability document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityDocumentError {
    /// The contract version is not one this reader speaks.
    UnsupportedContract(ContractVersion),
    /// Every adapter is launched by the host: that is what puts it inside the sandbox.
    /// An adapter without `launch` would be an agent the host does not contain.
    LaunchRequired,
    /// `hooks` does not match the events (`none` ⇔ no events, `full` ⇔ all of them).
    HookCoverageMismatch,
    /// `semantic_tool_events` is claimed without a tool event, or a tool event is listed
    /// without the feature.
    ToolEventsMismatch,
    /// `approval_requests` is claimed without a decision point (`PreToolUse` or
    /// `PermissionRequest`) to hold an approval at.
    ApprovalsWithoutDecisionPoint,
}

impl Display for CapabilityDocumentError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedContract(version) => {
                write!(formatter, "adapter contract {version} is not supported")
            }
            Self::LaunchRequired => {
                formatter.write_str("an adapter must be launchable by the host (launch)")
            }
            Self::HookCoverageMismatch => {
                formatter.write_str("hook coverage contradicts the listed semantic events")
            }
            Self::ToolEventsMismatch => {
                formatter.write_str("semantic_tool_events contradicts the listed tool events")
            }
            Self::ApprovalsWithoutDecisionPoint => {
                formatter.write_str("approval_requests needs PreToolUse or PermissionRequest")
            }
        }
    }
}

impl std::error::Error for CapabilityDocumentError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityDocumentWire {
    contract: ContractVersion,
    adapter: AgentAdapterDescriptor,
    hooks: HookSupport,
    events: SemanticEvents,
}

impl<'de> Deserialize<'de> for CapabilityDocument {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = CapabilityDocumentWire::deserialize(deserializer)?;
        Self::new(wire.contract, wire.adapter, wire.hooks, wire.events).map_err(D::Error::custom)
    }
}

/// The adapter features a contract-1.0 host serves.
///
/// `capability_requests`, `cancellation` (cooperative) and `structured_task_result`
/// have contract shapes ([`crate::wire`]) but no host path yet: an adapter may claim
/// them, and [`CapabilityDocument::coverage`] reports them as unserved rather than
/// pretending they are wired.
pub const SERVED_FEATURES: [AdapterFeature; 3] = [
    AdapterFeature::Launch,
    AdapterFeature::SemanticToolEvents,
    AdapterFeature::ApprovalRequests,
];

/// What a host serves of one adapter's document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Coverage {
    /// Claimed features the host serves.
    pub served: AdapterFeatures,
    /// Claimed features the host has no path for yet.
    pub unserved: AdapterFeatures,
    /// Hook coverage as claimed.
    pub hooks: HookSupport,
    /// Semantic events as claimed.
    pub events: SemanticEvents,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::{AdapterId, RuntimeMetadata, SemanticVisibility};

    fn descriptor(features: &[AdapterFeature]) -> AgentAdapterDescriptor {
        let semantic = features.contains(&AdapterFeature::SemanticToolEvents);
        AgentAdapterDescriptor::new(
            AdapterId::new("custom.acme-agent").unwrap(),
            RuntimeMetadata::new("Acme Agent", Some("7.4")).unwrap(),
            if semantic {
                SemanticVisibility::AdapterClaims
            } else {
                SemanticVisibility::HostObservationsOnly
            },
            AdapterFeatures::new(features.iter().copied()).unwrap(),
        )
        .unwrap()
    }

    fn events(list: &[SemanticEvent]) -> SemanticEvents {
        SemanticEvents::new(list.iter().copied()).unwrap()
    }

    #[test]
    fn contract_versions_parse_canonically_and_unknown_ones_fail_closed() {
        assert_eq!(ContractVersion::parse("1.0"), Ok(ContractVersion::V1_0));
        assert_eq!(ContractVersion::CURRENT.to_string(), "1.0");
        for bad in [
            "", "1", "1.", ".0", "01.0", "1.00", "+1.0", " 1.0", "1.0.0", "a.b", "70000.0",
        ] {
            assert_eq!(
                ContractVersion::parse(bad),
                Err(ContractVersionError::Malformed),
                "{bad:?}"
            );
        }
        assert!(ContractVersion::V1_0.is_supported());
        assert!(!ContractVersion::parse("1.1").unwrap().is_supported());
        assert!(!ContractVersion::parse("2.0").unwrap().is_supported());
        assert!(!ContractVersion::parse("0.9").unwrap().is_supported());

        assert_eq!(
            serde_json::from_str::<ContractVersion>(r#""1.0""#).unwrap(),
            ContractVersion::V1_0
        );
        for raw in [r#""1.1""#, r#""2.0""#, r#""1.0.0""#, "1.0", "1"] {
            assert!(
                serde_json::from_str::<ContractVersion>(raw).is_err(),
                "{raw}"
            );
        }
    }

    #[test]
    fn semantic_events_are_canonical_and_spelled_as_on_the_wire() {
        let set = events(&[SemanticEvent::Stop, SemanticEvent::PreToolUse]);
        assert_eq!(
            set.as_slice(),
            &[SemanticEvent::PreToolUse, SemanticEvent::Stop]
        );
        assert_eq!(
            serde_json::to_string(&set).unwrap(),
            r#"["PreToolUse","Stop"]"#
        );
        assert_eq!(
            SemanticEvents::new([SemanticEvent::Stop, SemanticEvent::Stop]),
            Err(SemanticEventsError::Duplicate(SemanticEvent::Stop))
        );
        for raw in [
            r#"["Stop","PreToolUse"]"#,
            r#"["Stop","Stop"]"#,
            r#"["pre_tool_use"]"#,
            r#"["Notification"]"#,
        ] {
            assert!(
                serde_json::from_str::<SemanticEvents>(raw).is_err(),
                "{raw}"
            );
        }
        for event in SemanticEvent::ALL {
            assert_eq!(SemanticEvent::from_wire(event.as_str()), Some(event));
            assert_eq!(
                serde_json::to_string(&event).unwrap(),
                format!("\"{}\"", event.as_str())
            );
        }
        assert_eq!(SemanticEvent::from_wire("Notification"), None);
        assert_eq!(SemanticEvents::none().coverage(), HookSupport::None);
        assert_eq!(SemanticEvents::all().coverage(), HookSupport::Full);
        assert_eq!(set.coverage(), HookSupport::Partial);
    }

    #[test]
    fn hook_coverage_must_match_the_listed_events() {
        let hookless = descriptor(&[AdapterFeature::Launch]);
        assert!(
            CapabilityDocument::new(
                ContractVersion::V1_0,
                hookless.clone(),
                HookSupport::None,
                SemanticEvents::none()
            )
            .is_ok()
        );
        for (hooks, list) in [
            (HookSupport::Full, vec![SemanticEvent::SessionStart]),
            (HookSupport::Partial, vec![]),
            (HookSupport::Partial, SemanticEvent::ALL.to_vec()),
            (HookSupport::None, vec![SemanticEvent::Stop]),
        ] {
            assert_eq!(
                CapabilityDocument::new(
                    ContractVersion::V1_0,
                    hookless.clone(),
                    hooks,
                    events(&list)
                ),
                Err(CapabilityDocumentError::HookCoverageMismatch),
                "{hooks:?} {list:?}"
            );
        }
    }

    #[test]
    fn tool_event_and_approval_claims_need_matching_events() {
        // Claims tool events, lists none.
        let claims_tools =
            descriptor(&[AdapterFeature::Launch, AdapterFeature::SemanticToolEvents]);
        assert_eq!(
            CapabilityDocument::new(
                ContractVersion::V1_0,
                claims_tools.clone(),
                HookSupport::Partial,
                events(&[SemanticEvent::SessionStart, SemanticEvent::Stop])
            ),
            Err(CapabilityDocumentError::ToolEventsMismatch)
        );
        // Lists a tool event, does not claim the feature.
        assert_eq!(
            CapabilityDocument::new(
                ContractVersion::V1_0,
                descriptor(&[AdapterFeature::Launch]),
                HookSupport::Partial,
                events(&[SemanticEvent::PostToolUse])
            ),
            Err(CapabilityDocumentError::ToolEventsMismatch)
        );
        // Observes tools after the fact only: no point to hold an approval at.
        assert_eq!(
            CapabilityDocument::new(
                ContractVersion::V1_0,
                descriptor(&[
                    AdapterFeature::Launch,
                    AdapterFeature::SemanticToolEvents,
                    AdapterFeature::ApprovalRequests
                ]),
                HookSupport::Partial,
                events(&[SemanticEvent::PostToolUse])
            ),
            Err(CapabilityDocumentError::ApprovalsWithoutDecisionPoint)
        );
        // Partial and honest: tool events observed, no approvals claimed.
        let partial = CapabilityDocument::new(
            ContractVersion::V1_0,
            claims_tools,
            HookSupport::Partial,
            events(&[SemanticEvent::PostToolUse]),
        )
        .unwrap();
        assert_eq!(partial.hooks(), HookSupport::Partial);
    }

    #[test]
    fn every_adapter_is_launched_by_the_host() {
        // Valid as a descriptor (the pre-contract type allows it), refused as a contract
        // document: an agent the host does not launch is an agent it does not contain.
        let unlaunched = AgentAdapterDescriptor::new(
            AdapterId::new("attached").unwrap(),
            RuntimeMetadata::new("Attached Agent", None).unwrap(),
            SemanticVisibility::HostObservationsOnly,
            AdapterFeatures::new([AdapterFeature::Cancellation]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            CapabilityDocument::new(
                ContractVersion::V1_0,
                unlaunched,
                HookSupport::None,
                SemanticEvents::none()
            ),
            Err(CapabilityDocumentError::LaunchRequired)
        );
    }

    #[test]
    fn coverage_reports_unserved_claims_instead_of_pretending() {
        let document = CapabilityDocument::new(
            ContractVersion::V1_0,
            descriptor(&[
                AdapterFeature::Launch,
                AdapterFeature::SemanticToolEvents,
                AdapterFeature::ApprovalRequests,
                AdapterFeature::CapabilityRequests,
                AdapterFeature::Cancellation,
                AdapterFeature::StructuredTaskResult,
            ]),
            HookSupport::Full,
            SemanticEvents::all(),
        )
        .unwrap();
        let coverage = document.coverage();
        assert_eq!(coverage.served.as_slice(), &SERVED_FEATURES);
        assert_eq!(
            coverage.unserved.as_slice(),
            &[
                AdapterFeature::CapabilityRequests,
                AdapterFeature::Cancellation,
                AdapterFeature::StructuredTaskResult,
            ]
        );
        assert_eq!(
            serde_json::to_string(&coverage).unwrap(),
            r#"{"served":["launch","semantic_tool_events","approval_requests"],"unserved":["capability_requests","cancellation","structured_task_result"],"hooks":"full","events":["SessionStart","PreToolUse","PostToolUse","PermissionRequest","Stop"]}"#
        );
    }

    #[test]
    fn document_wire_shape_is_stable_and_authority_fields_fail_closed() {
        let document = CapabilityDocument::new(
            ContractVersion::V1_0,
            descriptor(&[AdapterFeature::Launch]),
            HookSupport::None,
            SemanticEvents::none(),
        )
        .unwrap();
        let json = serde_json::to_string(&document).unwrap();
        assert_eq!(
            json,
            r#"{"contract":"1.0","adapter":{"id":"custom.acme-agent","runtime":{"product":"Acme Agent","version":"7.4"},"visibility":"host_observations_only","features":["launch"]},"hooks":"none","events":[]}"#
        );
        assert_eq!(
            serde_json::from_str::<CapabilityDocument>(&json).unwrap(),
            document
        );

        let adapter = r#"{"id":"custom.acme-agent","runtime":{"product":"Acme Agent","version":"7.4"},"visibility":"host_observations_only","features":["launch"]}"#;
        for extra in [
            r#","network":"unrestricted""#,
            r#","credentials":["github"]"#,
            r#","sandbox":"none""#,
            r#","enforcement":"adapter""#,
        ] {
            let raw = format!(
                r#"{{"contract":"1.0","adapter":{adapter},"hooks":"none","events":[]{extra}}}"#
            );
            assert!(
                serde_json::from_str::<CapabilityDocument>(&raw).is_err(),
                "{raw}"
            );
        }
        for raw in [
            format!(r#"{{"contract":"1.1","adapter":{adapter},"hooks":"none","events":[]}}"#),
            format!(r#"{{"contract":"2.0","adapter":{adapter},"hooks":"none","events":[]}}"#),
            format!(r#"{{"adapter":{adapter},"hooks":"none","events":[]}}"#),
            format!(r#"{{"contract":"1.0","adapter":{adapter},"hooks":"some","events":[]}}"#),
            format!(r#"{{"contract":"1.0","adapter":{adapter},"hooks":"full","events":[]}}"#),
        ] {
            assert!(
                serde_json::from_str::<CapabilityDocument>(&raw).is_err(),
                "{raw}"
            );
        }
    }
}
