//! Agent adapters a node hosts (#279, ADR-0036), additive within protocol 1.3.
//!
//! A workload may name the agent adapter of `ward-agent-adapter`'s contract its argv runs
//! as, beside the argv in the envelope's `workload`:
//!
//! ```json
//! {"argv":["/opt/claude/bin/claude","-p","fix the build"],"capability_manifest":{…},
//!  "snapshot":"…","wall_clock_budget_ms":600000,"adapter":{"id":"claude-code"}}
//! ```
//!
//! The field ([`WorkloadAdapter`]) is optional, absent from the wire when the workload
//! names none, and outside the capability manifest: the adapter is what runs, never
//! authority, so the same manifest bytes serve every adapter. Its `id` is in the contract's
//! id grammar and is the only field; with an adapter, `argv[0]` must be a launch program
//! (a name on the sandbox `PATH` or an absolute path). A workload outside this grammar
//! fails envelope decoding. Which ids a node hosts is the node's to say, in its capability
//! document's `adapters` section ([`AdapterCapabilities`]); a workload naming any other id
//! is refused at `admit`.

use std::fmt::{Display, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ward_agent_adapter::catalogue::{CLAUDE_CODE, CODEX, PROCESS};
use ward_agent_adapter::{AdapterId, ContractVersion};

/// An adapter a node can host: the first-party adapters and the generic process adapter
/// of `ward-agent-adapter`'s catalogue.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostedAdapter {
    /// Claude Code (`claude-code`), hooks `full`.
    ClaudeCode,
    /// The `OpenAI` Codex CLI (`codex`), hooks `none`.
    Codex,
    /// The generic process adapter (`process`), hooks `none`.
    Process,
}

impl HostedAdapter {
    /// Every adapter, in the order the capability document lists them.
    pub const ALL: [Self; 3] = [Self::ClaudeCode, Self::Codex, Self::Process];

    /// The adapter's id.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::ClaudeCode => CLAUDE_CODE,
            Self::Codex => CODEX,
            Self::Process => PROCESS,
        }
    }

    /// The adapter with this id, if a node can host it.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|adapter| adapter.id() == id)
    }
}

impl Display for HostedAdapter {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.id())
    }
}

/// The adapter a workload names: `{"id": …}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadAdapter {
    id: AdapterId,
}

impl WorkloadAdapter {
    /// The adapter `id`.
    #[must_use]
    pub const fn new(id: AdapterId) -> Self {
        Self { id }
    }

    /// The adapter's id.
    #[must_use]
    pub const fn id(&self) -> &AdapterId {
        &self.id
    }
}

/// The capability document's `adapters` section: the adapter contract the node speaks and
/// the adapters its operator hosts, `{"contract":"1.0","hosted":["claude-code","codex"]}`.
/// Present only on a node that hosts at least one; the list is in [`HostedAdapter::ALL`]
/// order with no repeat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one flag per adapter the operator may host
pub struct AdapterCapabilities {
    claude_code: bool,
    codex: bool,
    process: bool,
}

impl AdapterCapabilities {
    /// The adapter contract a node hosts adapters under.
    pub const CONTRACT: ContractVersion = ContractVersion::CURRENT;

    /// The section of a node hosting `adapters`; `None` when it hosts none.
    #[must_use]
    pub fn hosting(adapters: impl IntoIterator<Item = HostedAdapter>) -> Option<Self> {
        let mut section = Self {
            claude_code: false,
            codex: false,
            process: false,
        };
        for adapter in adapters {
            match adapter {
                HostedAdapter::ClaudeCode => section.claude_code = true,
                HostedAdapter::Codex => section.codex = true,
                HostedAdapter::Process => section.process = true,
            }
        }
        (!section.hosted().is_empty()).then_some(section)
    }

    /// Whether the node hosts `adapter`.
    #[must_use]
    pub const fn hosts(self, adapter: HostedAdapter) -> bool {
        match adapter {
            HostedAdapter::ClaudeCode => self.claude_code,
            HostedAdapter::Codex => self.codex,
            HostedAdapter::Process => self.process,
        }
    }

    /// Whether the node hosts the adapter with id `id`.
    #[must_use]
    pub fn hosts_id(self, id: &str) -> bool {
        HostedAdapter::from_id(id).is_some_and(|adapter| self.hosts(adapter))
    }

    /// The hosted adapters, in [`HostedAdapter::ALL`] order.
    #[must_use]
    pub fn hosted(self) -> Vec<HostedAdapter> {
        HostedAdapter::ALL
            .into_iter()
            .filter(|adapter| self.hosts(*adapter))
            .collect()
    }
}

/// Invalid `adapters` section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterCapabilitiesError {
    /// No adapter, an unknown one, a repeat, or not in [`HostedAdapter::ALL`] order.
    InvalidHosted,
}

impl Display for AdapterCapabilitiesError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("hosted adapters are invalid")
    }
}

impl std::error::Error for AdapterCapabilitiesError {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterCapabilitiesWire {
    contract: ContractVersion,
    hosted: Vec<String>,
}

impl Serialize for AdapterCapabilities {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        AdapterCapabilitiesWire {
            contract: Self::CONTRACT,
            hosted: self
                .hosted()
                .into_iter()
                .map(|adapter| adapter.id().to_owned())
                .collect(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AdapterCapabilities {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = AdapterCapabilitiesWire::deserialize(deserializer)?;
        let invalid = || D::Error::custom(AdapterCapabilitiesError::InvalidHosted);
        let hosted = wire
            .hosted
            .iter()
            .map(|id| HostedAdapter::from_id(id).ok_or_else(invalid))
            .collect::<Result<Vec<_>, _>>()?;
        let section = Self::hosting(hosted.iter().copied()).ok_or_else(invalid)?;
        if section.hosted() != hosted {
            return Err(invalid());
        }
        Ok(section)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_workload_adapter_is_an_id_and_nothing_else() {
        let adapter: WorkloadAdapter = serde_json::from_str(r#"{"id":"claude-code"}"#).unwrap();
        assert_eq!(adapter.id().as_str(), "claude-code");
        assert_eq!(
            serde_json::to_string(&adapter).unwrap(),
            r#"{"id":"claude-code"}"#
        );
        assert_eq!(
            serde_json::from_str::<WorkloadAdapter>(r#"{"id":"gemini-cli"}"#)
                .unwrap()
                .id()
                .as_str(),
            "gemini-cli",
            "an id no node hosts is the node's to refuse"
        );
        for bad in [
            r"{}",
            r#"{"id":null}"#,
            r#"{"id":""}"#,
            r#"{"id":"Claude Code"}"#,
            r#"{"id":"-codex"}"#,
            r#"{"id":"codex","program":"/bin/sh"}"#,
            r#"{"id":"codex","env":[{"name":"HTTPS_PROXY","value":"http://evil"}]}"#,
            r#""codex""#,
        ] {
            assert!(
                serde_json::from_str::<WorkloadAdapter>(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn hosted_adapters_are_the_catalogues_launchable_ones() {
        let ids: Vec<&str> = HostedAdapter::ALL.iter().map(|a| a.id()).collect();
        assert_eq!(ids, ward_agent_adapter::catalogue::LAUNCHABLE);
        assert_eq!(HostedAdapter::from_id("codex"), Some(HostedAdapter::Codex));
        assert_eq!(HostedAdapter::from_id("gemini-cli"), None);
        assert_eq!(HostedAdapter::Process.to_string(), "process");
    }

    #[test]
    fn the_adapters_section_lists_what_the_operator_hosts_in_one_spelling() {
        assert_eq!(AdapterCapabilities::hosting([]), None);
        let section =
            AdapterCapabilities::hosting([HostedAdapter::Process, HostedAdapter::ClaudeCode])
                .unwrap();
        assert_eq!(
            serde_json::to_string(&section).unwrap(),
            r#"{"contract":"1.0","hosted":["claude-code","process"]}"#
        );
        assert!(section.hosts_id("claude-code") && section.hosts_id("process"));
        assert!(!section.hosts_id("codex") && !section.hosts_id("gemini-cli"));
        assert_eq!(AdapterCapabilities::CONTRACT, ContractVersion::CURRENT);
        let decoded: AdapterCapabilities =
            serde_json::from_str(r#"{"contract":"1.0","hosted":["claude-code","process"]}"#)
                .unwrap();
        assert_eq!(decoded, section);
        for bad in [
            r#"{"contract":"1.0","hosted":[]}"#,
            r#"{"contract":"1.0","hosted":["process","claude-code"]}"#,
            r#"{"contract":"1.0","hosted":["codex","codex"]}"#,
            r#"{"contract":"1.0","hosted":["gemini-cli"]}"#,
            r#"{"contract":"2.0","hosted":["codex"]}"#,
            r#"{"contract":"1.1","hosted":["codex"]}"#,
            r#"{"hosted":["codex"]}"#,
            r#"{"contract":"1.0","hosted":["codex"],"hooks":"full"}"#,
        ] {
            assert!(
                serde_json::from_str::<AdapterCapabilities>(bad).is_err(),
                "{bad}"
            );
        }
    }
}
