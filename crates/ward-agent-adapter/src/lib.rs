//! Provider-neutral agent adapter contracts.
//!
//! Adapter metadata describes integration affordances only. It is never identity,
//! authority, policy or an OS-enforcement fact.

#![forbid(unsafe_code)]

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
        assert_eq!(AdapterId::new("claude-code").unwrap().as_str(), "claude-code");
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
            Err(AdapterFeaturesError::DuplicateFeature(AdapterFeature::Launch))
        );
    }

    #[test]
    fn claude_and_codex_can_use_one_contract_with_explicit_visibility_difference() {
        let claude = claude_descriptor();
        let codex = codex_descriptor();

        assert_eq!(claude.visibility(), SemanticVisibility::AdapterClaims);
        assert!(claude.features().contains(AdapterFeature::SemanticToolEvents));
        assert!(claude.features().contains(AdapterFeature::ApprovalRequests));

        assert_eq!(codex.visibility(), SemanticVisibility::HostObservationsOnly);
        assert!(!codex.features().contains(AdapterFeature::SemanticToolEvents));
        assert!(!codex.features().contains(AdapterFeature::ApprovalRequests));
        assert!(codex.features().contains(AdapterFeature::Launch));
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
                AdapterFeatures::new([
                    AdapterFeature::Launch,
                    AdapterFeature::SemanticToolEvents,
                ])
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
        ] {
            assert!(
                serde_json::from_str::<AgentAdapterDescriptor>(raw).is_err(),
                "{raw} must fail closed"
            );
        }
    }
}
