//! Launch profiles for supported coding agents (`docs/agent-integration.md`).

/// How to launch one agent inside the sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentProfile {
    /// Executable name looked up on the sandbox `PATH`.
    pub binary: &'static str,
    /// Environment set inside the sandbox: private config dir, non-essential traffic off.
    pub env: &'static [(&'static str, &'static str)],
}

/// Profile for a known agent name, if any.
pub fn profile(name: &str) -> Option<AgentProfile> {
    match name {
        "claude" => Some(AgentProfile {
            binary: "claude",
            env: &[
                ("CLAUDE_CONFIG_DIR", "/home/agent/.claude"),
                ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
                ("DISABLE_TELEMETRY", "1"),
                ("DISABLE_ERROR_REPORTING", "1"),
                ("ENABLE_CLAUDEAI_MCP_SERVERS", "false"),
                ("CLAUDE_CODE_DISABLE_ARTIFACT", "1"),
            ],
        }),
        "codex" => Some(AgentProfile {
            binary: "codex",
            env: &[("CODEX_HOME", "/home/agent/.codex")],
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn claude_profile_uses_private_config_and_no_telemetry() {
        let p = profile("claude").expect("claude");
        assert_eq!(p.binary, "claude");
        assert!(
            p.env
                .contains(&("CLAUDE_CONFIG_DIR", "/home/agent/.claude"))
        );
        assert!(
            p.env
                .contains(&("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"))
        );
        assert!(profile("nope").is_none());
    }
}
