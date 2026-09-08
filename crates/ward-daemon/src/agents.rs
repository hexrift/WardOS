//! Launch profiles for supported coding agents (`docs/agent-integration.md`).

use crate::gateway::GatewaySpec;
use crate::sandbox::AGENT_SHIM;

/// Claude Code hooks that report to `wardd` (`docs/agent-integration.md` §4).
const CLAUDE_HOOKS: &[&str] = &[
    "PreToolUse",
    "PostToolUse",
    "PermissionRequest",
    "SessionStart",
    "Stop",
];

/// How to launch one agent inside the sandbox.
#[derive(Clone, Debug)]
pub struct AgentProfile {
    /// Executable name looked up on the sandbox `PATH`.
    pub binary: &'static str,
    /// Environment set inside the sandbox: private config dir, non-essential traffic off.
    pub env: &'static [(&'static str, &'static str)],
    /// Model-API gateway, when the agent's key can be kept on the host.
    pub gateway: Option<GatewaySpec>,
    /// Settings file seeded read-only into the sandbox.
    pub settings: Option<Settings>,
}

/// A settings file the daemon writes for the agent.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Path inside the sandbox.
    pub path: &'static str,
    /// Produces the file content.
    pub content: fn() -> String,
}

/// Claude Code settings: every hook runs `ward-agent hook`, which reports the
/// call to `wardd` over the session's hook socket and relays its decision.
pub fn claude_settings() -> String {
    let hook = serde_json::json!([{ "hooks": [{ "type": "command", "command": format!("{AGENT_SHIM} hook") }] }]);
    let hooks: serde_json::Map<String, serde_json::Value> = CLAUDE_HOOKS
        .iter()
        .map(|h| ((*h).to_owned(), hook.clone()))
        .collect();
    serde_json::json!({ "hooks": hooks }).to_string()
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
            settings: Some(Settings {
                path: "/home/agent/.claude/settings.json",
                content: claude_settings,
            }),
        }),
        "codex" => Some(AgentProfile {
            binary: "codex",
            env: &[("CODEX_HOME", "/home/agent/.codex")],
            gateway: None,
            settings: None,
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

    #[test]
    fn claude_settings_route_every_hook_through_the_shim() {
        let v: serde_json::Value = serde_json::from_str(&claude_settings()).unwrap();
        for hook in CLAUDE_HOOKS {
            assert_eq!(
                v["hooks"][hook][0]["hooks"][0]["command"], "/run/ward/ward-agent hook",
                "{hook}"
            );
        }
        let settings = profile("claude").unwrap().settings.unwrap();
        assert!(settings.path.starts_with("/home/agent/.claude/"));
    }
}
