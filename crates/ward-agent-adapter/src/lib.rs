//! Provider-neutral agent adapter contracts.
//!
//! Adapter metadata describes integration affordances only. It is never identity,
//! authority, policy or an OS-enforcement fact.
//!
//! The versioned contract (`docs/agent-integration.md` §10, ADR-0033) is spread over
//! four modules: [`contract`] (version, hook coverage, semantic events and the
//! capability-discovery document), [`launch`] (what an adapter may ask of a launch),
//! [`wire`] (the hook-socket lines, approvals, capability requests, cancellation, task
//! result and the evidence binding) and [`catalogue`] (the documents and launches `WardOS`
//! ships).

#![forbid(unsafe_code)]

pub mod catalogue;
pub mod contract;
pub mod launch;
pub mod wire;

use std::fmt::{Display, Formatter};

pub use catalogue::{AdapterLaunch, AdapterLaunchError};
pub use contract::{
    CapabilityDocument, CapabilityDocumentError, ContractVersion, ContractVersionError, Coverage,
    HookSupport, SERVED_FEATURES, SemanticEvent, SemanticEvents, SemanticEventsError,
};
pub use launch::{
    EnvVar, LaunchSpec, LaunchSpecError, ProviderId, ProviderIdError, SettingsFile, requested_model,
};
pub use wire::{
    AdapterBinding, AdapterBindingError, ApprovalAnswer, ApprovalDecision, BindingClaim,
    CancelReason, CancelRequest, CapabilityRequest, CapabilityRequestError, RequestedCapability,
    SemanticEventLine, SemanticEventLineError, TaskOutcome, TaskResult,
};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

/// Stable provider-neutral adapter identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct AdapterId(String);

impl AdapterId {
    /// Maximum UTF-8 bytes in an adapter identifier.
    pub const MAX_BYTES: usize = 64;

    /// Construct a validated adapter identifier.
    ///
    /// # Errors
    ///
    /// Returns `AdapterIdError` when the identifier is empty, oversized, or contains
    /// characters outside lowercase ASCII letters, digits, dot, underscore and hyphen.
    pub fn new(value: &str) -> Result<Self, AdapterIdError> {
        if value.is_empty()
            || value.len() > Self::MAX_BYTES
            || !value
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(AdapterIdError);
        }

        Ok(Self(value.to_owned()))
    }

    /// Identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Invalid adapter identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterIdError;

impl Display for AdapterIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("agent adapter id is invalid")
    }
}

impl std::error::Error for AdapterIdError {}

impl<'de> Deserialize<'de> for AdapterId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(&value).map_err(D::Error::custom)
    }
}

/// Runtime/product metadata emitted as evidence metadata, never authority identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuntimeMetadata {
    product: String,
    version: Option<String>,
}

impl RuntimeMetadata {
    /// Maximum UTF-8 bytes in a runtime product name.
    pub const MAX_PRODUCT_BYTES: usize = 128;
    /// Maximum UTF-8 bytes in a runtime version string.
    pub const MAX_VERSION_BYTES: usize = 64;

    /// Construct validated runtime metadata.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, control-character-containing, or surrounding-whitespace
    /// product/version values.
    pub fn new(product: &str, version: Option<&str>) -> Result<Self, RuntimeMetadataError> {
        if !valid_metadata_text(product, Self::MAX_PRODUCT_BYTES) {
            return Err(RuntimeMetadataError::InvalidProduct);
        }

        let version = match version {
            Some(value) if valid_metadata_text(value, Self::MAX_VERSION_BYTES) => {
                Some(value.to_owned())
            }
            Some(_) => return Err(RuntimeMetadataError::InvalidVersion),
            None => None,
        };

        Ok(Self {
            product: product.to_owned(),
            version,
        })
    }

    /// Human-readable runtime/product name.
    #[must_use]
    pub fn product(&self) -> &str {
        &self.product
    }

    /// Optional runtime version metadata.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

fn valid_metadata_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

/// Invalid runtime metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeMetadataError {
    /// Runtime product metadata is invalid.
    InvalidProduct,
    /// Runtime version metadata is invalid.
    InvalidVersion,
}

impl Display for RuntimeMetadataError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProduct => formatter.write_str("runtime product metadata is invalid"),
            Self::InvalidVersion => formatter.write_str("runtime version metadata is invalid"),
        }
    }
}

impl std::error::Error for RuntimeMetadataError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeMetadataWire {
    product: String,
    version: Option<String>,
}

impl<'de> Deserialize<'de> for RuntimeMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RuntimeMetadataWire::deserialize(deserializer)?;
        Self::new(&wire.product, wire.version.as_deref()).map_err(D::Error::custom)
    }
}

/// Semantic visibility supplied by an adapter.
///
/// These values describe observability only. Host/kernel/proxy enforcement remains
/// authoritative regardless of adapter visibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticVisibility {
    /// Semantic intent is unavailable; `WardOS` relies on host observations.
    HostObservationsOnly,
    /// The adapter supplies untrusted semantic claims such as tool events.
    AdapterClaims,
}

/// Optional integration features an agent adapter can provide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterFeature {
    /// `WardOS` can launch the runtime through this adapter.
    Launch,
    /// The adapter emits semantic tool-use events.
    SemanticToolEvents,
    /// The adapter can surface approval requests to `WardOS`.
    ApprovalRequests,
    /// The adapter can request bounded capabilities.
    CapabilityRequests,
    /// The adapter supports cancellation.
    Cancellation,
    /// The adapter can return a structured task result.
    StructuredTaskResult,
}

/// Canonical closed feature set for an adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct AdapterFeatures(Vec<AdapterFeature>);

impl AdapterFeatures {
    /// Construct a canonical feature set.
    ///
    /// Input order is normalized to the stable enum order.
    ///
    /// # Errors
    ///
    /// Returns `DuplicateFeature` when the same feature is supplied more than once.
    pub fn new(
        features: impl IntoIterator<Item = AdapterFeature>,
    ) -> Result<Self, AdapterFeaturesError> {
        let mut values: Vec<_> = features.into_iter().collect();
        values.sort_unstable();

        if let Some(feature) = values
            .windows(2)
            .find_map(|pair| (pair[0] == pair[1]).then_some(pair[0]))
        {
            return Err(AdapterFeaturesError::DuplicateFeature(feature));
        }

        Ok(Self(values))
    }

    /// Canonical ordered feature slice.
    #[must_use]
    pub fn as_slice(&self) -> &[AdapterFeature] {
        &self.0
    }

    /// Whether this adapter claims one integration feature.
    #[must_use]
    pub fn contains(&self, feature: AdapterFeature) -> bool {
        self.0.binary_search(&feature).is_ok()
    }
}

/// Invalid adapter feature set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterFeaturesError {
    /// A closed feature appeared more than once.
    DuplicateFeature(AdapterFeature),
    /// Wire features were not encoded in canonical order.
    NonCanonicalOrder,
}

impl Display for AdapterFeaturesError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateFeature(feature) => {
                write!(formatter, "duplicate adapter feature: {feature:?}")
            }
            Self::NonCanonicalOrder => formatter.write_str("adapter features are not canonical"),
        }
    }
}

impl std::error::Error for AdapterFeaturesError {}

impl<'de> Deserialize<'de> for AdapterFeatures {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = Vec::<AdapterFeature>::deserialize(deserializer)?;
        let canonical = Self::new(wire.iter().copied()).map_err(D::Error::custom)?;
        if canonical.0 != wire {
            return Err(D::Error::custom(AdapterFeaturesError::NonCanonicalOrder));
        }
        Ok(canonical)
    }
}

/// Provider-neutral adapter descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AgentAdapterDescriptor {
    id: AdapterId,
    runtime: RuntimeMetadata,
    visibility: SemanticVisibility,
    features: AdapterFeatures,
}

impl AgentAdapterDescriptor {
    /// Construct a validated adapter descriptor.
    ///
    /// # Errors
    ///
    /// Returns `SemanticVisibilityMismatch` when semantic feature claims contradict the
    /// declared degraded/full semantic visibility.
    pub fn new(
        id: AdapterId,
        runtime: RuntimeMetadata,
        visibility: SemanticVisibility,
        features: AdapterFeatures,
    ) -> Result<Self, AgentAdapterDescriptorError> {
        let semantic_events = features.contains(AdapterFeature::SemanticToolEvents);
        let semantic_integrations = semantic_events
            || features.contains(AdapterFeature::ApprovalRequests)
            || features.contains(AdapterFeature::CapabilityRequests);

        match visibility {
            SemanticVisibility::AdapterClaims if !semantic_events => {
                return Err(AgentAdapterDescriptorError::SemanticVisibilityMismatch);
            }
            SemanticVisibility::HostObservationsOnly if semantic_integrations => {
                return Err(AgentAdapterDescriptorError::SemanticVisibilityMismatch);
            }
            SemanticVisibility::AdapterClaims | SemanticVisibility::HostObservationsOnly => {}
        }

        Ok(Self {
            id,
            runtime,
            visibility,
            features,
        })
    }

    /// Stable provider-neutral adapter identifier.
    #[must_use]
    pub fn id(&self) -> &AdapterId {
        &self.id
    }

    /// Runtime/product evidence metadata.
    #[must_use]
    pub fn runtime(&self) -> &RuntimeMetadata {
        &self.runtime
    }

    /// Semantic visibility level.
    #[must_use]
    pub const fn visibility(&self) -> SemanticVisibility {
        self.visibility
    }

    /// Claimed adapter integration features.
    #[must_use]
    pub fn features(&self) -> &AdapterFeatures {
        &self.features
    }
}

/// Invalid adapter descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentAdapterDescriptorError {
    /// Semantic visibility contradicts claimed semantic integration features.
    SemanticVisibilityMismatch,
}

impl Display for AgentAdapterDescriptorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SemanticVisibilityMismatch => {
                formatter.write_str("adapter semantic visibility contradicts feature claims")
            }
        }
    }
}

impl std::error::Error for AgentAdapterDescriptorError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentAdapterDescriptorWire {
    id: AdapterId,
    runtime: RuntimeMetadata,
    visibility: SemanticVisibility,
    features: AdapterFeatures,
}

impl<'de> Deserialize<'de> for AgentAdapterDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentAdapterDescriptorWire::deserialize(deserializer)?;
        Self::new(wire.id, wire.runtime, wire.visibility, wire.features).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn claude_descriptor() -> AgentAdapterDescriptor {
        AgentAdapterDescriptor::new(
            AdapterId::new("claude-code").unwrap(),
            RuntimeMetadata::new("Claude Code", Some("2.1.263")).unwrap(),
            SemanticVisibility::AdapterClaims,
            AdapterFeatures::new([
                AdapterFeature::Launch,
                AdapterFeature::SemanticToolEvents,
                AdapterFeature::ApprovalRequests,
            ])
            .unwrap(),
        )
        .unwrap()
    }

    fn codex_descriptor() -> AgentAdapterDescriptor {
        AgentAdapterDescriptor::new(
            AdapterId::new("codex").unwrap(),
            RuntimeMetadata::new("OpenAI Codex CLI", Some("0.153.4")).unwrap(),
            SemanticVisibility::HostObservationsOnly,
            AdapterFeatures::new([AdapterFeature::Launch]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn adapter_ids_are_provider_neutral_and_bounded() {
        assert_eq!(
            AdapterId::new("claude-code").unwrap().as_str(),
            "claude-code"
        );
        assert_eq!(
            AdapterId::new("custom.acme-agent").unwrap().as_str(),
            "custom.acme-agent"
        );

        for invalid in ["", "Claude", "has space", "/absolute", "a/b"] {
            assert!(AdapterId::new(invalid).is_err(), "{invalid:?} must fail");
        }
        assert!(AdapterId::new(&"a".repeat(AdapterId::MAX_BYTES + 1)).is_err());
    }

    #[test]
    fn runtime_metadata_is_bounded_metadata_not_identity() {
        let runtime = RuntimeMetadata::new("Custom Agent", None).unwrap();
        assert_eq!(runtime.product(), "Custom Agent");
        assert_eq!(runtime.version(), None);

        assert!(RuntimeMetadata::new("", None).is_err());
        assert!(RuntimeMetadata::new("bad\nproduct", None).is_err());
        assert!(RuntimeMetadata::new("Custom Agent", Some("bad\nversion")).is_err());
    }

    #[test]
    fn feature_sets_are_canonical_and_reject_duplicates() {
        let features = AdapterFeatures::new([
            AdapterFeature::StructuredTaskResult,
            AdapterFeature::Launch,
            AdapterFeature::Cancellation,
        ])
        .unwrap();

        assert_eq!(
            features.as_slice(),
            &[
                AdapterFeature::Launch,
                AdapterFeature::Cancellation,
                AdapterFeature::StructuredTaskResult,
            ]
        );
        assert_eq!(
            AdapterFeatures::new([AdapterFeature::Launch, AdapterFeature::Launch]),
            Err(AdapterFeaturesError::DuplicateFeature(
                AdapterFeature::Launch
            ))
        );

        assert!(
            serde_json::from_str::<AdapterFeatures>(
                r#"["structured_task_result","launch","cancellation"]"#
            )
            .is_err()
        );
    }

    #[test]
    fn claude_and_codex_can_use_one_contract_with_explicit_visibility_difference() {
        let claude = claude_descriptor();
        let codex = codex_descriptor();

        assert_eq!(claude.visibility(), SemanticVisibility::AdapterClaims);
        assert!(
            claude
                .features()
                .contains(AdapterFeature::SemanticToolEvents)
        );
        assert!(claude.features().contains(AdapterFeature::ApprovalRequests));

        assert_eq!(codex.visibility(), SemanticVisibility::HostObservationsOnly);
        assert!(
            !codex
                .features()
                .contains(AdapterFeature::SemanticToolEvents)
        );
        assert!(!codex.features().contains(AdapterFeature::ApprovalRequests));
        assert!(codex.features().contains(AdapterFeature::Launch));
    }

    #[test]
    fn generic_adapter_can_express_all_supported_integration_features() {
        let descriptor = AgentAdapterDescriptor::new(
            AdapterId::new("custom.acme-agent").unwrap(),
            RuntimeMetadata::new("Acme Agent", Some("7.4")).unwrap(),
            SemanticVisibility::AdapterClaims,
            AdapterFeatures::new([
                AdapterFeature::Launch,
                AdapterFeature::SemanticToolEvents,
                AdapterFeature::ApprovalRequests,
                AdapterFeature::CapabilityRequests,
                AdapterFeature::Cancellation,
                AdapterFeature::StructuredTaskResult,
            ])
            .unwrap(),
        )
        .unwrap();

        assert!(
            descriptor
                .features()
                .contains(AdapterFeature::CapabilityRequests)
        );
        assert!(descriptor.features().contains(AdapterFeature::Cancellation));
        assert!(
            descriptor
                .features()
                .contains(AdapterFeature::StructuredTaskResult)
        );
    }

    #[test]
    fn semantic_visibility_and_feature_claims_cannot_contradict_each_other() {
        let runtime = RuntimeMetadata::new("Agent", None).unwrap();
        let adapter = AdapterId::new("agent").unwrap();

        assert_eq!(
            AgentAdapterDescriptor::new(
                adapter.clone(),
                runtime.clone(),
                SemanticVisibility::AdapterClaims,
                AdapterFeatures::new([AdapterFeature::Launch]).unwrap(),
            ),
            Err(AgentAdapterDescriptorError::SemanticVisibilityMismatch)
        );

        assert_eq!(
            AgentAdapterDescriptor::new(
                adapter,
                runtime,
                SemanticVisibility::HostObservationsOnly,
                AdapterFeatures::new([AdapterFeature::Launch, AdapterFeature::SemanticToolEvents,])
                    .unwrap(),
            ),
            Err(AgentAdapterDescriptorError::SemanticVisibilityMismatch)
        );
    }

    #[test]
    fn descriptor_wire_shape_is_stable_and_unknown_values_fail_closed() {
        let descriptor = claude_descriptor();
        let json = serde_json::to_string(&descriptor).unwrap();
        assert_eq!(
            json,
            r#"{"id":"claude-code","runtime":{"product":"Claude Code","version":"2.1.263"},"visibility":"adapter_claims","features":["launch","semantic_tool_events","approval_requests"]}"#
        );
        assert_eq!(
            serde_json::from_str::<AgentAdapterDescriptor>(&json).unwrap(),
            descriptor
        );

        for raw in [
            r#"{"id":"claude-code","runtime":{"product":"Claude Code","version":"2.1.263"},"visibility":"trusted_enforcement","features":["launch"]}"#,
            r#"{"id":"claude-code","runtime":{"product":"Claude Code","version":"2.1.263"},"visibility":"host_observations_only","features":["unknown_feature"]}"#,
            r#"{"id":"claude-code","runtime":{"product":"Claude Code","version":"2.1.263"},"visibility":"host_observations_only","features":["launch"],"authority":"admin"}"#,
            r#"{"id":"claude-code","runtime":{"product":"Claude Code","version":"2.1.263","principal":"admin"},"visibility":"host_observations_only","features":["launch"]}"#,
        ] {
            assert!(
                serde_json::from_str::<AgentAdapterDescriptor>(raw).is_err(),
                "{raw} must fail closed"
            );
        }
    }

    #[test]
    fn noncanonical_or_inconsistent_wire_descriptors_fail_closed() {
        for raw in [
            r#"{"id":"agent","runtime":{"product":"Agent","version":null},"visibility":"host_observations_only","features":["launch","launch"]}"#,
            r#"{"id":"agent","runtime":{"product":"Agent","version":null},"visibility":"adapter_claims","features":["launch"]}"#,
            r#"{"id":"agent","runtime":{"product":"Agent","version":null},"visibility":"host_observations_only","features":["semantic_tool_events"]}"#,
            r#"{"id":"agent","runtime":{"product":"Agent","version":null},"visibility":"host_observations_only","features":["cancellation","launch"]}"#,
        ] {
            assert!(
                serde_json::from_str::<AgentAdapterDescriptor>(raw).is_err(),
                "{raw} must fail closed"
            );
        }
    }
}
