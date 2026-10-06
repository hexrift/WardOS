//! The capability documents of the adapters `WardOS` ships.
//!
//! * **Claude Code** (`claude-code`, `ward claude`): every hook of the contract is
//!   wired through `ward-agent hook`; tool events and approvals on `PreToolUse` /
//!   `PermissionRequest`.
//! * **Codex** (`codex`, `ward codex`): no hook is wired; the host observes it.
//! * **The generic process adapter** (`process`, `ward agent`): any program, no hooks.
//!
//! The runtime versions are the ones the image pins (`image/agents/package.json`) and
//! the project tests against: declared metadata, not a check of what is installed.
//! Copilot, `OpenCode` and other agents have no first-party document; they run through
//! the generic process adapter, or through a document of their own.

use crate::contract::{CapabilityDocument, ContractVersion, HookSupport, SemanticEvents};
use crate::{
    AdapterFeature, AdapterFeatures, AdapterId, AgentAdapterDescriptor, RuntimeMetadata,
    SemanticVisibility,
};

/// Adapter id of Claude Code.
pub const CLAUDE_CODE: &str = "claude-code";
/// Adapter id of the `OpenAI` Codex CLI.
pub const CODEX: &str = "codex";
/// Adapter id of the generic process adapter.
pub const PROCESS: &str = "process";

/// Claude Code version the project pins and tests.
pub const CLAUDE_CODE_VERSION: &str = "2.1.263";
/// Codex CLI version the project pins and tests.
pub const CODEX_VERSION: &str = "0.153.4";

fn id(value: &str) -> AdapterId {
    AdapterId(value.to_owned())
}

fn runtime(product: &str, version: Option<&str>) -> RuntimeMetadata {
    RuntimeMetadata {
        product: product.to_owned(),
        version: version.map(str::to_owned),
    }
}

/// Claude Code: hooks `full`.
#[must_use]
pub fn claude_code() -> CapabilityDocument {
    CapabilityDocument {
        contract: ContractVersion::CURRENT,
        adapter: AgentAdapterDescriptor {
            id: id(CLAUDE_CODE),
            runtime: runtime("Claude Code", Some(CLAUDE_CODE_VERSION)),
            visibility: SemanticVisibility::AdapterClaims,
            features: AdapterFeatures(vec![
                AdapterFeature::Launch,
                AdapterFeature::SemanticToolEvents,
                AdapterFeature::ApprovalRequests,
            ]),
        },
        hooks: HookSupport::Full,
        events: SemanticEvents::all(),
    }
}

/// The `OpenAI` Codex CLI: hooks `none`.
#[must_use]
pub fn codex() -> CapabilityDocument {
    hookless(id(CODEX), runtime("OpenAI Codex CLI", Some(CODEX_VERSION)))
}

/// The generic process adapter for `runtime` (the product name is the user's or the
/// program's name; it is metadata only): hooks `none`.
#[must_use]
pub fn process(runtime: RuntimeMetadata) -> CapabilityDocument {
    hookless(id(PROCESS), runtime)
}

/// Every first-party document, Claude Code first.
#[must_use]
pub fn first_party() -> [CapabilityDocument; 2] {
    [claude_code(), codex()]
}

fn hookless(id: AdapterId, runtime: RuntimeMetadata) -> CapabilityDocument {
    CapabilityDocument {
        contract: ContractVersion::CURRENT,
        adapter: AgentAdapterDescriptor {
            id,
            runtime,
            visibility: SemanticVisibility::HostObservationsOnly,
            features: AdapterFeatures(vec![AdapterFeature::Launch]),
        },
        hooks: HookSupport::None,
        events: SemanticEvents::none(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::contract::SemanticEvent;

    /// The documents are built without their constructors' checks; prove they would
    /// pass them, and survive the wire.
    fn revalidated(document: &CapabilityDocument) -> CapabilityDocument {
        let adapter = AgentAdapterDescriptor::new(
            AdapterId::new(document.adapter().id().as_str()).unwrap(),
            RuntimeMetadata::new(
                document.adapter().runtime().product(),
                document.adapter().runtime().version(),
            )
            .unwrap(),
            document.adapter().visibility(),
            AdapterFeatures::new(document.adapter().features().as_slice().iter().copied()).unwrap(),
        )
        .unwrap();
        let checked = CapabilityDocument::new(
            document.contract(),
            adapter,
            document.hooks(),
            SemanticEvents::new(document.events().as_slice().iter().copied()).unwrap(),
        )
        .unwrap();
        let json = serde_json::to_string(document).unwrap();
        assert_eq!(
            serde_json::from_str::<CapabilityDocument>(&json).unwrap(),
            checked
        );
        checked
    }

    #[test]
    fn shipped_documents_satisfy_the_contract() {
        for document in first_party()
            .into_iter()
            .chain([process(RuntimeMetadata::new("my-agent", None).unwrap())])
        {
            assert_eq!(revalidated(&document), document);
            assert_eq!(document.contract(), ContractVersion::CURRENT);
        }
    }

    #[test]
    fn claude_code_wires_every_hook_and_codex_and_process_none() {
        let claude = claude_code();
        assert_eq!(claude.hooks(), HookSupport::Full);
        assert_eq!(claude.events().as_slice(), &SemanticEvent::ALL);
        assert!(
            claude
                .adapter()
                .features()
                .contains(AdapterFeature::ApprovalRequests)
        );
        assert!(claude.coverage().unserved.as_slice().is_empty());

        for document in [
            codex(),
            process(RuntimeMetadata::new("opencode", None).unwrap()),
        ] {
            assert_eq!(document.hooks(), HookSupport::None);
            assert!(document.events().is_empty());
            assert_eq!(
                document.adapter().visibility(),
                SemanticVisibility::HostObservationsOnly
            );
            assert_eq!(
                document.adapter().features().as_slice(),
                &[AdapterFeature::Launch]
            );
        }
        assert_eq!(codex().adapter().id().as_str(), CODEX);
        assert_eq!(
            process(RuntimeMetadata::new("opencode", None).unwrap())
                .adapter()
                .id()
                .as_str(),
            PROCESS
        );
    }

    #[test]
    fn shipped_document_wire_shapes_are_stable() {
        assert_eq!(
            serde_json::to_string(&claude_code()).unwrap(),
            r#"{"contract":"1.0","adapter":{"id":"claude-code","runtime":{"product":"Claude Code","version":"2.1.263"},"visibility":"adapter_claims","features":["launch","semantic_tool_events","approval_requests"]},"hooks":"full","events":["SessionStart","PreToolUse","PostToolUse","PermissionRequest","Stop"]}"#
        );
        assert_eq!(
            serde_json::to_string(&codex()).unwrap(),
            r#"{"contract":"1.0","adapter":{"id":"codex","runtime":{"product":"OpenAI Codex CLI","version":"0.153.4"},"visibility":"host_observations_only","features":["launch"]},"hooks":"none","events":[]}"#
        );
    }
}
