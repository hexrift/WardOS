//! Agent hook adapter: a Unix socket the sandbox's `ward-agent hook` shim talks to,
//! answering one JSON request per connection and recording each as an agent claim
//! (`docs/agent-integration.md` §4, `docs/event-model.md` §2). Claims are never
//! enforcement; the decision only feeds step-through UX.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use ward_events::{ClaimKind, PayloadText, WardEvent};
use ward_policy::ObserverMode;

use crate::error::{Error, Result};

/// Longest a client may take to send its request line.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// One hook request from the sandbox (`hook-protocol.md`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookRequest {
    /// The Claude Code `hook_event_name`, verbatim.
    pub hook: String,
    /// `tool_name`, for hooks that carry one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Short sanitised description of `tool_input`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

/// The daemon's answer to a hook request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookResponse {
    /// What the client should tell the agent.
    pub decision: HookDecision,
    /// Short human-readable reason.
    pub reason: String,
}

/// Outcome of a hook decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HookDecision {
    /// Let the action proceed.
    Allow,
    /// Refuse the action (reserved; never emitted today).
    Deny,
    /// Pause and ask the operator.
    Ask,
}

impl HookDecision {
    const fn as_str(self) -> &'static str {
        match self {
            HookDecision::Allow => "allow",
            HookDecision::Deny => "deny",
            HookDecision::Ask => "ask",
        }
    }
}

/// Apply the observer mode's decision rule to a request.
// The by-reference signature is the module's contract with the session code.
#[allow(clippy::trivially_copy_pass_by_ref)]
pub fn decide(observer: &ObserverMode, req: &HookRequest) -> HookResponse {
    let (decision, reason) = match observer {
        ObserverMode::Live => (HookDecision::Allow, "observer: live"),
        ObserverMode::Quiet => (HookDecision::Allow, "observer: quiet"),
        ObserverMode::StepThrough(step) => {
            let tool = req.tool.as_deref().unwrap_or_default();
            let pre = req.hook == "PreToolUse";
            if pre && step.pause_before_writes && is_write_tool(tool) {
                (HookDecision::Ask, "step-through: pause before writes")
            } else if pre && step.pause_before_network && is_network_tool(tool) {
                (HookDecision::Ask, "step-through: pause before network")
            } else {
                (HookDecision::Allow, "step-through")
            }
        }
    };
    HookResponse {
        decision,
        reason: reason.to_owned(),
    }
}

fn is_write_tool(tool: &str) -> bool {
    matches!(tool, "Write" | "Edit" | "MultiEdit" | "NotebookEdit")
}

fn is_network_tool(tool: &str) -> bool {
    matches!(tool, "WebFetch" | "WebSearch")
}

/// A request and the decision it received, kept until the session drains it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// The request as received.
    pub request: HookRequest,
    /// The decision returned.
    pub decision: HookDecision,
}

/// Map a claim to its `Origin::Agent` log event.
pub fn to_event(claim: &Claim) -> WardEvent {
    let req = &claim.request;
    let hook = req.hook.as_str();
    let tool_hook = matches!(hook, "PreToolUse" | "PostToolUse" | "PermissionRequest");
    let (kind, text) = match &req.tool {
        Some(tool) if tool_hook => {
            let summary = req.summary.as_deref().unwrap_or_default();
            let text = if hook == "PostToolUse" {
                format!("{hook} {tool} {summary}")
            } else {
                format!("{hook} {tool} {summary} → {}", claim.decision.as_str())
            };
            (ClaimKind::ToolUse, text)
        }
        _ => (ClaimKind::Note, hook.to_owned()),
    };
    WardEvent::AgentClaim {
        kind,
        payload: PayloadText::new(&text),
    }
}

/// A running hook listener bound to a Unix socket.
pub struct Hooks {
    socket: PathBuf,
    claims: Arc<Mutex<Vec<Claim>>>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Hooks {
    /// Start answering hook requests under `observer`, listening at `dir/hooks.sock`.
    pub fn start(dir: &Path, observer: ObserverMode) -> Result<Self> {
        let socket = dir.join("hooks.sock");
        let listener = UnixListener::bind(&socket)
            .map_err(|e| Error::Sandbox(format!("hook socket {}: {e}", socket.display())))?;
        let claims = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread = {
            let (claims, shutdown) = (claims.clone(), shutdown.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    serve(stream, observer, &claims);
                }
            })
        };
        Ok(Self {
            socket,
            claims,
            shutdown,
            thread: Some(thread),
        })
    }

    /// Host path of the socket to bind into the sandbox.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Claims recorded since the last drain, as log events, in arrival order.
    pub fn drain_events(&self) -> Vec<WardEvent> {
        self.claims
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default()
            .iter()
            .map(to_event)
            .collect()
    }

    /// Stop the listener and remove the socket.
    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Unblock the accept loop; it sees the flag and exits.
        drop(UnixStream::connect(&self.socket));
        if let Some(thread) = self.thread.take() {
            drop(thread.join());
        }
        drop(std::fs::remove_file(&self.socket));
    }
}

/// Handle one connection: read a line, decide, record, reply. Malformed input
/// closes the connection silently.
fn serve(mut stream: UnixStream, observer: ObserverMode, claims: &Mutex<Vec<Claim>>) {
    drop(stream.set_read_timeout(Some(READ_TIMEOUT)));
    let mut line = String::new();
    let Ok(Some(req)) = BufReader::new(&stream)
        .read_line(&mut line)
        .map(|_| serde_json::from_str::<HookRequest>(&line).ok())
    else {
        return;
    };
    let response = decide(&observer, &req);
    if let Ok(mut v) = claims.lock() {
        v.push(Claim {
            request: req,
            decision: response.decision,
        });
    }
    if let Ok(mut json) = serde_json::to_vec(&response) {
        json.push(b'\n');
        drop(stream.write_all(&json));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use ward_policy::StepPolicy;

    fn req(hook: &str, tool: Option<&str>, summary: Option<&str>) -> HookRequest {
        HookRequest {
            hook: hook.into(),
            tool: tool.map(Into::into),
            summary: summary.map(Into::into),
        }
    }

    fn step(pause_before_writes: bool, pause_before_network: bool) -> ObserverMode {
        ObserverMode::StepThrough(StepPolicy {
            pause_before_writes,
            pause_before_network,
        })
    }

    fn pre(tool: &str) -> HookRequest {
        req("PreToolUse", Some(tool), Some("x"))
    }

    fn post(tool: &str) -> HookRequest {
        req("PostToolUse", Some(tool), Some("x"))
    }

    fn assert_decision(observer: ObserverMode, r: &HookRequest, d: HookDecision, reason: &str) {
        let resp = decide(&observer, r);
        assert_eq!(resp.decision, d, "{r:?} under {observer:?}");
        assert_eq!(resp.reason, reason, "{r:?} under {observer:?}");
    }

    #[test]
    fn quiet_and_live_always_allow() {
        for r in [
            pre("Write"),
            pre("WebFetch"),
            post("Write"),
            req("Stop", None, None),
        ] {
            assert_decision(
                ObserverMode::Quiet,
                &r,
                HookDecision::Allow,
                "observer: quiet",
            );
            assert_decision(
                ObserverMode::Live,
                &r,
                HookDecision::Allow,
                "observer: live",
            );
        }
    }

    #[test]
    fn step_through_pauses_before_writes_only_when_flagged() {
        let reason = "step-through: pause before writes";
        for tool in ["Write", "Edit", "MultiEdit", "NotebookEdit"] {
            assert_decision(step(true, false), &pre(tool), HookDecision::Ask, reason);
            assert_decision(step(true, true), &pre(tool), HookDecision::Ask, reason);
            assert_decision(
                step(false, true),
                &pre(tool),
                HookDecision::Allow,
                "step-through",
            );
            assert_decision(
                step(false, false),
                &pre(tool),
                HookDecision::Allow,
                "step-through",
            );
        }
    }

    #[test]
    fn step_through_pauses_before_network_only_when_flagged() {
        let reason = "step-through: pause before network";
        for tool in ["WebFetch", "WebSearch"] {
            assert_decision(step(false, true), &pre(tool), HookDecision::Ask, reason);
            assert_decision(step(true, true), &pre(tool), HookDecision::Ask, reason);
            assert_decision(
                step(true, false),
                &pre(tool),
                HookDecision::Allow,
                "step-through",
            );
            assert_decision(
                step(false, false),
                &pre(tool),
                HookDecision::Allow,
                "step-through",
            );
        }
    }

    #[test]
    fn step_through_allows_post_tool_use_and_other_tools() {
        let all = step(true, true);
        for tool in ["Write", "Edit", "WebFetch", "WebSearch", "Bash", "Read"] {
            assert_decision(all, &post(tool), HookDecision::Allow, "step-through");
        }
        for tool in ["Bash", "Read", "Grep", "Glob"] {
            assert_decision(all, &pre(tool), HookDecision::Allow, "step-through");
        }
        let no_tool = req("PreToolUse", None, None);
        assert_decision(all, &no_tool, HookDecision::Allow, "step-through");
        assert_decision(
            all,
            &req("SessionStart", None, None),
            HookDecision::Allow,
            "step-through",
        );
    }

    #[test]
    fn decision_serialises_lowercase_and_none_fields_are_skipped() {
        let resp = HookResponse {
            decision: HookDecision::Ask,
            reason: "r".into(),
        };
        assert_eq!(
            serde_json::to_string(&resp).unwrap(),
            r#"{"decision":"ask","reason":"r"}"#
        );
        let r = req("Stop", None, None);
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"hook":"Stop"}"#);
        let parsed: HookRequest =
            serde_json::from_str(r#"{"hook":"PreToolUse","tool":"Write","summary":"/w"}"#).unwrap();
        assert_eq!(parsed, req("PreToolUse", Some("Write"), Some("/w")));
    }

    fn claim(r: HookRequest, decision: HookDecision) -> Claim {
        Claim {
            request: r,
            decision,
        }
    }

    fn assert_claim(event: &WardEvent, want_kind: ClaimKind, want: &str) {
        match event {
            WardEvent::AgentClaim { kind, payload } => {
                assert_eq!(*kind, want_kind);
                assert_eq!(payload.content(), want);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn pre_tool_use_ask_renders_with_arrow() {
        let c = claim(
            req("PreToolUse", Some("Write"), Some("/work/src/lib.rs")),
            HookDecision::Ask,
        );
        assert_claim(
            &to_event(&c),
            ClaimKind::ToolUse,
            "PreToolUse Write /work/src/lib.rs → ask",
        );
        let c = claim(
            req("PermissionRequest", Some("Bash"), Some("ls")),
            HookDecision::Allow,
        );
        assert_claim(
            &to_event(&c),
            ClaimKind::ToolUse,
            "PermissionRequest Bash ls → allow",
        );
    }

    #[test]
    fn post_tool_use_renders_without_arrow() {
        let c = claim(
            req("PostToolUse", Some("Write"), Some("/work/src/lib.rs")),
            HookDecision::Allow,
        );
        assert_claim(
            &to_event(&c),
            ClaimKind::ToolUse,
            "PostToolUse Write /work/src/lib.rs",
        );
    }

    #[test]
    fn session_start_and_toolless_hooks_are_notes() {
        let c = claim(req("SessionStart", None, None), HookDecision::Allow);
        assert_claim(&to_event(&c), ClaimKind::Note, "SessionStart");
        let c = claim(req("PreToolUse", None, None), HookDecision::Allow);
        assert_claim(&to_event(&c), ClaimKind::Note, "PreToolUse");
        let c = claim(req("Custom", Some("Write"), None), HookDecision::Allow);
        assert_claim(&to_event(&c), ClaimKind::Note, "Custom");
    }

    fn roundtrip(socket: &Path, line: &str) -> String {
        let mut stream = UnixStream::connect(socket).unwrap();
        stream.write_all(line.as_bytes()).unwrap();
        let mut reply = String::new();
        BufReader::new(&stream).read_line(&mut reply).unwrap();
        reply
    }

    #[test]
    fn listener_answers_records_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let hooks = Hooks::start(dir.path(), step(true, false)).unwrap();
        let socket = hooks.socket().to_path_buf();
        assert_eq!(socket, dir.path().join("hooks.sock"));

        let reply = roundtrip(
            &socket,
            "{\"hook\":\"PreToolUse\",\"tool\":\"Write\",\"summary\":\"/work/src/lib.rs\"}\n",
        );
        let resp: HookResponse = serde_json::from_str(&reply).unwrap();
        assert_eq!(resp.decision, HookDecision::Ask);
        assert_eq!(resp.reason, "step-through: pause before writes");

        assert_eq!(roundtrip(&socket, "not json\n"), "");

        let reply = roundtrip(&socket, "{\"hook\":\"Stop\"}\n");
        let resp: HookResponse = serde_json::from_str(&reply).unwrap();
        assert_eq!(resp.decision, HookDecision::Allow);

        let events = hooks.drain_events();
        assert_eq!(events.len(), 2);
        assert_claim(
            &events[0],
            ClaimKind::ToolUse,
            "PreToolUse Write /work/src/lib.rs → ask",
        );
        assert_claim(&events[1], ClaimKind::Note, "Stop");
        assert!(hooks.drain_events().is_empty());

        hooks.stop();
        assert!(!socket.exists());
    }
}
