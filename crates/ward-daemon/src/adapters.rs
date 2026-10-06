//! Agent adapters (contract 1.0, ADR-0033, `docs/agent-integration.md` §10).
//!
//! An [`Adapter`] pairs a capability document ([`ward_agent_adapter::catalogue`]) with
//! the [`LaunchSpec`] the host launches it from. Every adapter — Claude Code, Codex and
//! the generic process adapter alike — goes through the one launch path
//! ([`Session::adapter_launch`](crate::Session::adapter_launch) then
//! [`Session::launch`](crate::Session::launch)): the sandbox, the network allowlist, the
//! credential broker and the evidence log are built from the session's capability
//! manifest and nothing in an adapter can change them. What an adapter adds is
//! semantic visibility (its hooks), the non-secret environment and settings files its
//! runtime needs, and the provider whose gateway it talks to; a missing hook lowers the
//! first and nothing else.

use ward_agent_adapter::catalogue;
use ward_agent_adapter::{
    AdapterBinding, CapabilityDocument, EnvVar, LaunchSpec, ProviderId, RuntimeMetadata,
    SettingsFile, TaskResult,
};

use crate::agents::{self, AgentProfile};
use crate::error::{Error, Result};
use crate::gateway::GatewaySpec;
use crate::session::RunReport;

/// The first-party adapter names, as `ward <name>` spells them.
pub const FIRST_PARTY: [&str; 2] = ["claude", "codex"];

/// Flags with which Claude Code and Codex take a model on their command line.
const MODEL_FLAGS: &[&str] = &["--model", "-m"];

/// One adapter: its capability document and its launch.
#[derive(Clone, Debug)]
pub struct Adapter {
    document: CapabilityDocument,
    launch: LaunchSpec,
    model_flags: &'static [&'static str],
}

impl Adapter {
    /// A first-party adapter by its `ward` name (`claude`, `codex`).
    #[must_use]
    pub fn first_party(name: &str) -> Option<Self> {
        let document = match name {
            "claude" => catalogue::claude_code(),
            "codex" => catalogue::codex(),
            _ => return None,
        };
        let launch = launch_spec(&agents::profile(name)?).ok()?;
        Some(Self {
            document,
            launch,
            model_flags: MODEL_FLAGS,
        })
    }

    /// The generic process adapter for `program` (hooks `none`): `product` defaults to
    /// the program's file name; `version` and `provider` are optional. The provider
    /// must be one the host has a gateway for (`anthropic`, `openai`).
    pub fn process(
        program: &str,
        product: Option<&str>,
        version: Option<&str>,
        provider: Option<&str>,
    ) -> Result<Self> {
        let invalid = |what: &str, e: &dyn std::fmt::Display| {
            Error::Project(format!("generic adapter: {what}: {e}"))
        };
        let name = product.unwrap_or_else(|| program.rsplit('/').next().unwrap_or(program));
        let runtime =
            RuntimeMetadata::new(name, version).map_err(|e| invalid("runtime metadata", &e))?;
        let provider = provider
            .map(|p| {
                let id = ProviderId::new(p).map_err(|e| invalid("provider", &e))?;
                if gateway_spec(&id).is_none() {
                    return Err(Error::Project(format!(
                        "generic adapter: no gateway for provider `{p}` (known: {})",
                        agents::PROVIDERS.join(", ")
                    )));
                }
                Ok(id)
            })
            .transpose()?;
        let launch = LaunchSpec::new(program, Vec::new(), Vec::new(), Vec::new(), provider)
            .map_err(|e| invalid("launch", &e))?;
        Ok(Self {
            document: catalogue::process(runtime),
            launch,
            model_flags: &[],
        })
    }

    /// The same adapter launching `program` (another install of the same runtime).
    pub fn with_program(mut self, program: &str) -> Result<Self> {
        self.launch = self
            .launch
            .with_program(program)
            .map_err(|e| Error::Project(format!("adapter program: {e}")))?;
        Ok(self)
    }

    /// The capability-discovery document.
    #[must_use]
    pub const fn document(&self) -> &CapabilityDocument {
        &self.document
    }

    /// The launch spec.
    #[must_use]
    pub const fn launch_spec(&self) -> &LaunchSpec {
        &self.launch
    }

    /// The gateway of the adapter's provider, if it has one.
    #[must_use]
    pub fn gateway(&self) -> Option<GatewaySpec> {
        self.launch.provider().and_then(gateway_spec)
    }

    /// The evidence binding of a launch with the user's `args`: the document's id,
    /// runtime and events, the provider, and the model the command line requests.
    pub fn binding(&self, args: &[String]) -> Result<AdapterBinding> {
        let descriptor = self.document.adapter();
        AdapterBinding::new(
            descriptor.id().clone(),
            descriptor.runtime().clone(),
            self.document.events().clone(),
            self.launch.provider().cloned(),
            requested_model(args, self.model_flags).as_deref(),
        )
        .map_err(|e| Error::Project(format!("adapter binding: {e}")))
    }
}

/// The launch spec of a first-party profile.
fn launch_spec(
    profile: &AgentProfile,
) -> std::result::Result<LaunchSpec, ward_agent_adapter::LaunchSpecError> {
    let env = profile
        .env
        .iter()
        .map(|(name, value)| EnvVar {
            name: (*name).to_owned(),
            value: (*value).to_owned(),
        })
        .collect();
    let settings = profile
        .settings
        .iter()
        .map(|s| SettingsFile {
            path: s.path.to_owned(),
            content: (s.content)(),
        })
        .collect();
    let provider = profile
        .gateway
        .as_ref()
        .and_then(|g| ProviderId::new(g.service).ok());
    LaunchSpec::new(profile.binary, Vec::new(), env, settings, provider)
}

/// The host's gateway for `provider`.
#[must_use]
pub fn gateway_spec(provider: &ProviderId) -> Option<GatewaySpec> {
    agents::gateway(provider.as_str())
}

/// The model a command line requests with one of `flags` (`--model x`, `--model=x`),
/// the last one winning as it does for the runtimes; `None` when it names none.
#[must_use]
pub fn requested_model(args: &[String], flags: &[&str]) -> Option<String> {
    let mut model = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            break;
        }
        for flag in flags {
            if arg == flag {
                model = iter.next().cloned();
            } else if let Some(value) = arg
                .strip_prefix(flag)
                .and_then(|rest| rest.strip_prefix('='))
            {
                model = Some(value.to_owned());
            }
        }
    }
    model.filter(|m| !m.is_empty())
}

/// The task result of a finished launch: the host's outcome from the exit status.
#[must_use]
pub fn task_result(report: &RunReport) -> TaskResult {
    TaskResult::from_exit(report.code)
}

/// Every capability document this host ships: the first-party ones, then the generic
/// process adapter's (for a program named `<program>`).
#[must_use]
pub fn catalogue() -> Vec<CapabilityDocument> {
    let mut documents: Vec<_> = catalogue::first_party().into_iter().collect();
    if let Ok(runtime) = RuntimeMetadata::new("<program>", None) {
        documents.push(catalogue::process(runtime));
    }
    documents
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use ward_agent_adapter::{HookSupport, SemanticEvent, TaskOutcome};

    use super::*;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn first_party_adapters_are_their_profiles_plus_a_document() {
        for name in FIRST_PARTY {
            let adapter = Adapter::first_party(name).expect(name);
            let profile = agents::profile(name).unwrap();
            let spec = adapter.launch_spec();
            assert_eq!(spec.program(), profile.binary);
            assert_eq!(spec.workdir(), "/work");
            let env: Vec<(&str, &str)> = spec
                .env()
                .iter()
                .map(|v| (v.name.as_str(), v.value.as_str()))
                .collect();
            assert_eq!(env, profile.env);
            assert_eq!(
                adapter.gateway().map(|g| g.service),
                profile.gateway.map(|g| g.service)
            );
        }
        assert!(Adapter::first_party("gemini").is_none());
        assert_eq!(
            Adapter::first_party("claude")
                .unwrap()
                .document()
                .adapter()
                .id()
                .as_str(),
            "claude-code"
        );
    }

    /// The document's hooks are what the launch actually wires: Claude Code's seeded
    /// settings route exactly its declared events through `ward-agent hook`; an adapter
    /// that declares none seeds nothing that could.
    #[test]
    fn declared_hooks_are_the_wired_hooks() {
        let claude = Adapter::first_party("claude").unwrap();
        let [settings] = claude.launch_spec().settings() else {
            panic!("one settings file")
        };
        let value: serde_json::Value = serde_json::from_str(&settings.content).unwrap();
        let wired: Vec<String> = value["hooks"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let mut declared: Vec<String> = claude
            .document()
            .events()
            .as_slice()
            .iter()
            .map(|e| e.as_str().to_owned())
            .collect();
        declared.sort();
        let mut wired = wired;
        wired.sort();
        assert_eq!(wired, declared);
        assert_eq!(claude.document().hooks(), HookSupport::Full);

        for adapter in [
            Adapter::first_party("codex").unwrap(),
            Adapter::process("/opt/opencode/bin/opencode", None, None, None).unwrap(),
        ] {
            assert_eq!(adapter.document().hooks(), HookSupport::None);
            assert!(adapter.launch_spec().settings().is_empty());
        }
    }

    #[test]
    fn declared_runtime_versions_are_the_image_pins() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../image/agents/package.json"
        );
        let pins: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        for (name, package) in [
            ("claude", "@anthropic-ai/claude-code"),
            ("codex", "@openai/codex"),
        ] {
            let adapter = Adapter::first_party(name).unwrap();
            assert_eq!(
                adapter.document().adapter().runtime().version(),
                pins["dependencies"][package].as_str(),
                "{name}: the declared version must be the one the image ships"
            );
        }
    }

    #[test]
    fn the_generic_adapter_is_any_program_with_no_hooks() {
        let adapter = Adapter::process("/work/bin/acme", None, None, None).unwrap();
        let document = adapter.document();
        assert_eq!(document.adapter().id().as_str(), "process");
        assert_eq!(document.adapter().runtime().product(), "acme");
        assert!(document.events().is_empty());
        let spec = adapter.launch_spec();
        assert!(spec.env().is_empty() && spec.settings().is_empty());
        assert!(adapter.gateway().is_none());
        assert_eq!(
            spec.argv(&s(&["--task", "x"])),
            ["/work/bin/acme", "--task", "x"]
        );

        let named =
            Adapter::process("opencode", Some("OpenCode"), Some("0.9"), Some("anthropic")).unwrap();
        assert_eq!(named.document().adapter().runtime().version(), Some("0.9"));
        assert_eq!(named.gateway().map(|g| g.service), Some("anthropic"));

        assert!(Adapter::process("opencode", None, None, Some("acme-ai")).is_err());
        assert!(Adapter::process("opencode", None, None, Some("Anthropic")).is_err());
        assert!(Adapter::process("rel/agent", None, None, None).is_err());
        assert!(Adapter::process("agent", Some("bad\nname"), None, None).is_err());
    }

    #[test]
    fn the_binding_records_metadata_from_document_and_command_line() {
        let claude = Adapter::first_party("claude").unwrap();
        let binding = claude
            .binding(&s(&["--model", "claude-opus-4-1", "-p", "x"]))
            .unwrap();
        assert_eq!(binding.adapter().as_str(), "claude-code");
        assert_eq!(binding.model(), Some("claude-opus-4-1"));
        assert_eq!(
            binding.provider().map(ProviderId::as_str),
            Some("anthropic")
        );
        assert_eq!(binding.events().as_slice(), &SemanticEvent::ALL);

        let codex = Adapter::first_party("codex").unwrap();
        assert_eq!(codex.binding(&[]).unwrap().model(), None);
        assert_eq!(codex.binding(&[]).unwrap().hooks(), HookSupport::None);

        // The generic adapter does not know its program's flags: no model is claimed.
        let generic = Adapter::process("agent", None, None, None).unwrap();
        assert_eq!(
            generic.binding(&s(&["--model", "x"])).unwrap().model(),
            None
        );
    }

    #[test]
    fn requested_model_reads_the_last_flag_before_a_double_dash() {
        let flags = MODEL_FLAGS;
        assert_eq!(
            requested_model(&s(&["--model", "a"]), flags).as_deref(),
            Some("a")
        );
        assert_eq!(
            requested_model(&s(&["--model=b"]), flags).as_deref(),
            Some("b")
        );
        assert_eq!(
            requested_model(&s(&["-m", "c", "--model", "d"]), flags).as_deref(),
            Some("d")
        );
        assert_eq!(requested_model(&s(&["-m=e"]), flags).as_deref(), Some("e"));
        assert_eq!(requested_model(&s(&["--", "--model", "f"]), flags), None);
        assert_eq!(requested_model(&s(&["--model"]), flags), None);
        assert_eq!(requested_model(&s(&["--model="]), flags), None);
        assert_eq!(requested_model(&s(&["--models", "g"]), flags), None);
        assert_eq!(requested_model(&s(&["--model", "h"]), &[]), None);
    }

    #[test]
    fn the_task_result_is_the_exit_status() {
        let report = |code| RunReport {
            argv: Vec::new(),
            code,
            files_changed: 0,
            duration: std::time::Duration::ZERO,
            capture: crate::watch::CaptureMode::Scan,
            observer_degraded: false,
            stdout: String::new(),
            stderr: String::new(),
        };
        assert_eq!(
            task_result(&report(Some(0))).outcome,
            TaskOutcome::Completed
        );
        assert_eq!(task_result(&report(Some(2))).outcome, TaskOutcome::Failed);
        assert_eq!(task_result(&report(None)).outcome, TaskOutcome::Failed);
    }

    #[test]
    fn the_catalogue_lists_every_shipped_document() {
        let ids: Vec<String> = catalogue()
            .iter()
            .map(|d| d.adapter().id().as_str().to_owned())
            .collect();
        assert_eq!(ids, ["claude-code", "codex", "process"]);
    }
}
