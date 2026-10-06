//! The capability documents and launches of the adapters `WardOS` ships, and
//! [`launch`], which builds an adapter's launch by its id: the one builder `ward-daemon`'s
//! sessions and `ward-node`'s hosted adapters (ADR-0036) both use.
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

use std::fmt::{Display, Formatter};

use crate::contract::{CapabilityDocument, ContractVersion, HookSupport, SemanticEvents};
use crate::launch::{
    EnvVar, LaunchSpec, LaunchSpecError, ProviderId, SANDBOX_HOME, SettingsFile, requested_model,
};
use crate::wire::{AdapterBinding, AdapterBindingError};
use crate::{
    AdapterFeature, AdapterFeatures, AdapterId, AgentAdapterDescriptor, RuntimeMetadata,
    RuntimeMetadataError, SemanticVisibility,
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

/// Every adapter a host launches by its id alone: the first-party ones, then the generic
/// process adapter.
pub const LAUNCHABLE: [&str; 3] = [CLAUDE_CODE, CODEX, PROCESS];

/// The command every Claude Code hook runs: the `ward-agent` shim's hook client, at the
/// path the host binds the shim inside the sandbox.
pub const HOOK_COMMAND: &str = "/run/ward/ward-agent hook";

/// Flags with which Claude Code and Codex take a model on their command line.
pub const MODEL_FLAGS: &[&str] = &["--model", "-m"];

/// Claude Code's configuration directory inside the sandbox.
const CLAUDE_CONFIG_DIR: &str = "/home/agent/.claude";

/// Claude Code's non-secret environment: its configuration under the sandbox home, and
/// no traffic beyond the model API.
const CLAUDE_CODE_ENV: &[(&str, &str)] = &[
    ("CLAUDE_CONFIG_DIR", CLAUDE_CONFIG_DIR),
    ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
    ("DISABLE_TELEMETRY", "1"),
    ("DISABLE_ERROR_REPORTING", "1"),
    ("ENABLE_CLAUDEAI_MCP_SERVERS", "false"),
    ("CLAUDE_CODE_DISABLE_ARTIFACT", "1"),
];

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

/// Claude Code's settings file: every event its document declares runs [`HOOK_COMMAND`],
/// in the spelling the session has always seeded (keys sorted, compact).
#[must_use]
pub fn claude_code_settings() -> String {
    let mut events: Vec<&str> = claude_code()
        .events()
        .as_slice()
        .iter()
        .map(|event| event.as_str())
        .collect();
    events.sort_unstable();
    let hooks: Vec<String> = events
        .iter()
        .map(|event| {
            format!(r#""{event}":[{{"hooks":[{{"command":"{HOOK_COMMAND}","type":"command"}}]}}]"#)
        })
        .collect();
    format!(r#"{{"hooks":{{{}}}}}"#, hooks.join(","))
}

/// Claude Code's launch: `claude` on the sandbox `PATH`, its configuration and settings
/// under the sandbox home, the `anthropic` provider.
#[must_use]
pub fn claude_code_launch() -> LaunchSpec {
    let env = CLAUDE_CODE_ENV
        .iter()
        .map(|(name, value)| EnvVar {
            name: (*name).to_owned(),
            value: (*value).to_owned(),
        })
        .collect();
    let settings = vec![SettingsFile {
        path: format!("{CLAUDE_CONFIG_DIR}/settings.json"),
        content: claude_code_settings(),
    }];
    LaunchSpec {
        program: "claude".to_owned(),
        args: Vec::new(),
        env,
        workdir: crate::launch::WORKSPACE.to_owned(),
        settings,
        provider: Some(ProviderId("anthropic".to_owned())),
    }
}

/// Codex's launch: `codex` on the sandbox `PATH`, its home under the sandbox home, the
/// `openai` provider.
#[must_use]
pub fn codex_launch() -> LaunchSpec {
    LaunchSpec {
        program: "codex".to_owned(),
        args: Vec::new(),
        env: vec![EnvVar {
            name: "CODEX_HOME".to_owned(),
            value: format!("{SANDBOX_HOME}/.codex"),
        }],
        workdir: crate::launch::WORKSPACE.to_owned(),
        settings: Vec::new(),
        provider: Some(ProviderId("openai".to_owned())),
    }
}

/// One launch of an adapter named by its id: its capability document, its launch spec
/// running the command's program, the command line and the evidence binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterLaunch {
    document: CapabilityDocument,
    spec: LaunchSpec,
    argv: Vec<String>,
    binding: AdapterBinding,
}

impl AdapterLaunch {
    /// The capability-discovery document.
    #[must_use]
    pub const fn document(&self) -> &CapabilityDocument {
        &self.document
    }

    /// The launch spec, running the command's program.
    #[must_use]
    pub const fn spec(&self) -> &LaunchSpec {
        &self.spec
    }

    /// The command line: the program, the adapter's fixed arguments, then the command's.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// The evidence binding: metadata, never authority.
    #[must_use]
    pub const fn binding(&self) -> &AdapterBinding {
        &self.binding
    }
}

/// Why an adapter cannot be launched by id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterLaunchError {
    /// Not one of [`LAUNCHABLE`].
    Unknown,
    /// The command has no program.
    NoProgram,
    /// The program is not a launch program.
    Launch(LaunchSpecError),
    /// The generic adapter's runtime, named after the program, is not valid metadata.
    Runtime(RuntimeMetadataError),
    /// The model the command line requests is not valid metadata.
    Binding(AdapterBindingError),
}

impl Display for AdapterLaunchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => formatter.write_str("no such adapter"),
            Self::NoProgram => formatter.write_str("the command names no program"),
            Self::Launch(error) => error.fmt(formatter),
            Self::Runtime(error) => error.fmt(formatter),
            Self::Binding(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AdapterLaunchError {}

/// The launch of adapter `id` for `command`, whose first entry is the program (a name on
/// the sandbox `PATH` or an absolute path) and the rest its arguments. A first-party
/// adapter keeps its document, environment, settings and provider whatever program runs
/// it; the generic process adapter's runtime is named after the program's file name and it
/// has no hooks, settings, provider or model.
///
/// # Errors
///
/// See [`AdapterLaunchError`].
pub fn launch(id: &str, command: &[String]) -> Result<AdapterLaunch, AdapterLaunchError> {
    let (program, args) = command.split_first().ok_or(AdapterLaunchError::NoProgram)?;
    let (document, spec, model_flags) = match id {
        CLAUDE_CODE => (claude_code(), claude_code_launch(), MODEL_FLAGS),
        CODEX => (codex(), codex_launch(), MODEL_FLAGS),
        PROCESS => {
            let spec = LaunchSpec::new(program, Vec::new(), Vec::new(), Vec::new(), None)
                .map_err(AdapterLaunchError::Launch)?;
            let name = program.rsplit('/').next().unwrap_or(program);
            let runtime = RuntimeMetadata::new(name, None).map_err(AdapterLaunchError::Runtime)?;
            (process(runtime), spec, &[][..])
        }
        _ => return Err(AdapterLaunchError::Unknown),
    };
    let spec = spec
        .with_program(program)
        .map_err(AdapterLaunchError::Launch)?;
    let descriptor = document.adapter();
    let binding = AdapterBinding::new(
        descriptor.id().clone(),
        descriptor.runtime().clone(),
        document.events().clone(),
        spec.provider().cloned(),
        requested_model(args, model_flags).as_deref(),
    )
    .map_err(AdapterLaunchError::Binding)?;
    Ok(AdapterLaunch {
        argv: spec.argv(args),
        document,
        spec,
        binding,
    })
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

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn first_party_launches_wire_exactly_their_documents_hooks() {
        let claude = claude_code_launch();
        assert_eq!(claude.program(), "claude");
        assert_eq!(claude.provider().map(ProviderId::as_str), Some("anthropic"));
        let [settings] = claude.settings() else {
            panic!("one settings file")
        };
        assert_eq!(settings.path, "/home/agent/.claude/settings.json");
        assert_eq!(settings.content, claude_code_settings());
        let value: serde_json::Value = serde_json::from_str(&settings.content).unwrap();
        let wired: Vec<&str> = value["hooks"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut declared: Vec<&str> = claude_code()
            .events()
            .as_slice()
            .iter()
            .map(|e| e.as_str())
            .collect();
        declared.sort_unstable();
        assert_eq!(wired, declared);
        for event in wired {
            assert_eq!(
                value["hooks"][event][0]["hooks"][0]["command"],
                HOOK_COMMAND
            );
        }
        assert!(
            claude
                .env()
                .iter()
                .any(|v| v.name == "CLAUDE_CONFIG_DIR" && v.value == "/home/agent/.claude")
        );

        let codex = codex_launch();
        assert_eq!(codex.program(), "codex");
        assert_eq!(codex.provider().map(ProviderId::as_str), Some("openai"));
        assert!(codex.settings().is_empty());
        assert_eq!(
            codex.env(),
            &[EnvVar {
                name: "CODEX_HOME".into(),
                value: "/home/agent/.codex".into()
            }]
        );
    }

    #[test]
    fn a_launch_by_id_is_the_document_the_spec_the_command_and_the_binding() {
        let claude = launch(
            CLAUDE_CODE,
            &s(&["/opt/claude/bin/claude", "-p", "--model", "opus", "fix it"]),
        )
        .unwrap();
        assert_eq!(claude.document(), &claude_code());
        assert_eq!(
            claude.spec(),
            &claude_code_launch()
                .with_program("/opt/claude/bin/claude")
                .unwrap()
        );
        assert_eq!(
            claude.argv(),
            s(&["/opt/claude/bin/claude", "-p", "--model", "opus", "fix it"])
        );
        let binding = claude.binding();
        assert_eq!(binding.adapter().as_str(), CLAUDE_CODE);
        assert_eq!(binding.model(), Some("opus"));
        assert_eq!(
            binding.provider().map(ProviderId::as_str),
            Some("anthropic")
        );
        assert_eq!(binding.events(), claude_code().events());

        let hookless = launch(CODEX, &s(&["codex", "exec", "-m", "o4"])).unwrap();
        assert_eq!(hookless.document(), &codex());
        assert_eq!(hookless.binding().model(), Some("o4"));
        assert_eq!(hookless.binding().hooks(), HookSupport::None);

        let generic = launch(PROCESS, &s(&["/work/bin/acme-agent", "--model", "x"])).unwrap();
        assert_eq!(
            generic.document().adapter().runtime().product(),
            "acme-agent"
        );
        assert_eq!(generic.document().adapter().runtime().version(), None);
        assert_eq!(
            generic.spec(),
            &LaunchSpec::new("/work/bin/acme-agent", vec![], vec![], vec![], None).unwrap()
        );
        assert_eq!(
            generic.binding().model(),
            None,
            "the generic adapter knows no model flag"
        );
        assert_eq!(generic.binding().provider(), None);
        assert_eq!(
            launch(PROCESS, &s(&["python3"]))
                .unwrap()
                .document()
                .adapter()
                .runtime()
                .product(),
            "python3"
        );
    }

    #[test]
    fn a_launch_by_id_fails_closed() {
        assert_eq!(
            launch("gemini-cli", &s(&["gemini"])).unwrap_err(),
            AdapterLaunchError::Unknown
        );
        assert_eq!(
            launch(CODEX, &[]).unwrap_err(),
            AdapterLaunchError::NoProgram
        );
        assert_eq!(
            launch(CODEX, &s(&["bin/codex"])).unwrap_err(),
            AdapterLaunchError::Launch(LaunchSpecError::InvalidProgram)
        );
        assert_eq!(
            launch(CLAUDE_CODE, &s(&["claude", "--model", "a\nb"])).unwrap_err(),
            AdapterLaunchError::Binding(crate::AdapterBindingError::InvalidModel)
        );
        assert_eq!(
            launch(PROCESS, &s(&["/work/ bad"])).unwrap_err(),
            AdapterLaunchError::Runtime(crate::RuntimeMetadataError::InvalidProduct)
        );
        assert_eq!(LAUNCHABLE, [CLAUDE_CODE, CODEX, PROCESS]);
        for id in LAUNCHABLE {
            assert!(launch(id, &s(&["agent"])).is_ok(), "{id}");
        }
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
