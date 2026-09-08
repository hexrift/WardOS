//! Launch profiles for supported coding agents (`docs/agent-integration.md`).

use crate::gateway::GatewaySpec;

/// How to launch one agent inside the sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentProfile {
    /// Executable name looked up on the sandbox `PATH`.
    pub binary: &'static str,
    /// Environment set inside the sandbox: private config dir, non-essential traffic off.
    pub env: &'static [(&'static str, &'static str)],
    /// Model-API gateway, when the agent's key can be kept on the host.
    pub gateway: Option<GatewaySpec>,
}

/// Anthropic's Messages API behind `/anthropic` on the relay.
const ANTHROPIC: GatewaySpec = GatewaySpec {
    service: "anthropic",
    prefix: "/anthropic",
    upstream: ("api.anthropic.com", 443),
    header: "x-api-key",
    strip: &["x-api-key", "authorization"],
    key_env: "ANTHROPIC_API_KEY",
    base_url_env: "ANTHROPIC_BASE_URL",
    placeholder_env: "ANTHROPIC_API_KEY",
};

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
            gateway: Some(ANTHROPIC),
        }),
        "codex" => Some(AgentProfile {
            binary: "codex",
            env: &[("CODEX_HOME", "/home/agent/.codex")],
            gateway: None,
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
        assert_eq!(p.gateway.map(|g| g.service), Some("anthropic"));
        assert!(profile("codex").unwrap().gateway.is_none());
        assert!(profile("nope").is_none());
    }
}
