//! `ward session describe`: the immutable facts of a session as one record
//! (`docs/tamperward-integration.md` §2, `SessionDescription`).
//!
//! Everything here is fixed at session start and never changes for its lifetime:
//! the ids, the worktree, the entry snapshot, the policy hash and the effective
//! capability manifest. Nothing is read from the worktree.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use ward_events::{AgentIdentity, AgentKind};
use ward_policy::CapabilityManifest;

/// The agent identity recorded in the session's `SessionStarted` event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDescription {
    /// Product family (`claude_code`, `codex`, `other`).
    pub kind: String,
    /// Product name as reported.
    pub name: String,
    /// Product version as reported.
    pub version: String,
    /// Digest of the agent image (`sha256:…`), when the agent runs from an image.
    pub image: Option<String>,
}

impl From<&AgentIdentity> for AgentDescription {
    fn from(a: &AgentIdentity) -> Self {
        Self {
            kind: match a.kind {
                AgentKind::ClaudeCode => "claude_code",
                AgentKind::Codex => "codex",
                AgentKind::Other => "other",
            }
            .to_owned(),
            name: a.name.as_str().to_owned(),
            version: a.version.as_str().to_owned(),
            image: a.image.map(|d| d.to_string()),
        }
    }
}

/// The immutable facts of one session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDescription {
    /// Session id (`sess_…`).
    pub session: String,
    /// Stable project id (`proj_…`).
    pub project: String,
    /// Canonical project worktree on the host.
    pub worktree: PathBuf,
    /// Session start, milliseconds since the Unix epoch.
    pub started_unix_ms: u64,
    /// The agent identity, when one was recorded.
    pub agent: Option<AgentDescription>,
    /// Entry snapshot id (`blake3:…`).
    pub entry_snapshot: String,
    /// BLAKE3 of the capability fields of the manifest (lowercase hex); the chain
    /// genesis of the session log.
    pub policy_hash: String,
    /// The effective capability manifest.
    pub manifest: CapabilityManifest,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use ward_events::NameText;
    use ward_policy::{Policy, merge};

    fn sample() -> SessionDescription {
        let manifest = merge(
            &Policy::default(),
            &Policy::default(),
            &Policy::default(),
            ward_policy::SessionId("sess_desc".to_owned()),
            ward_policy::ProjectId("proj_desc".to_owned()),
        );
        SessionDescription {
            session: "sess_desc".to_owned(),
            project: "proj_desc".to_owned(),
            worktree: PathBuf::from("/tmp/demo"),
            started_unix_ms: 1_700_000_000_000,
            agent: Some(AgentDescription::from(&AgentIdentity {
                kind: AgentKind::ClaudeCode,
                name: NameText::new("claude"),
                version: NameText::new("1.2.3"),
                image: None,
            })),
            entry_snapshot: format!("blake3:{}", "ab".repeat(32)),
            policy_hash: manifest.policy_hash.to_hex(),
            manifest,
        }
    }

    #[test]
    fn serialises_the_immutable_facts_as_stable_json() {
        let d = sample();
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["session"], "sess_desc");
        assert_eq!(json["project"], "proj_desc");
        assert_eq!(json["worktree"], "/tmp/demo");
        assert_eq!(json["started_unix_ms"], 1_700_000_000_000_u64);
        assert_eq!(json["agent"]["kind"], "claude_code");
        assert_eq!(json["agent"]["name"], "claude");
        assert_eq!(json["agent"]["image"], serde_json::Value::Null);
        assert_eq!(
            json["entry_snapshot"],
            format!("blake3:{}", "ab".repeat(32))
        );
        assert_eq!(json["policy_hash"], d.manifest.policy_hash.to_hex());
        assert_eq!(json["policy_hash"].as_str().unwrap().len(), 64);
        // The manifest travels whole, so every capability fact is in the record.
        assert_eq!(json["manifest"]["policy_hash"], json["policy_hash"]);
        assert_eq!(json["manifest"]["network"], "development");
        assert!(json["manifest"]["credentials"].is_object());
        assert!(json["manifest"]["filesystem"]["worktree"].is_string());
    }

    #[test]
    fn round_trips_through_json() {
        let d = sample();
        let back: SessionDescription =
            serde_json::from_slice(&serde_json::to_vec(&d).unwrap()).unwrap();
        assert_eq!(back, d);
    }
}
