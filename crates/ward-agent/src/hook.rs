//! `ward-agent hook`: the in-sandbox client for Claude Code hooks
//! (agent-integration §4).
//!
//! Reads the hook payload on stdin, sends one JSON line to the daemon's Unix
//! socket and prints the decision Claude Code expects. Every failure prints
//! nothing: hook records are claims, never enforcement (event-model §2).

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::cli::note;

/// Socket path used when [`SOCKET_ENV`] is unset.
pub const DEFAULT_SOCKET: &str = "/run/ward/hooks.sock";
/// Environment variable naming the daemon's hook socket.
pub const SOCKET_ENV: &str = "WARD_HOOK_SOCKET";
/// Upper bound of a [`Request::summary`], in bytes.
pub const SUMMARY_MAX: usize = 256;

const TIMEOUT: Duration = Duration::from_secs(5);
/// How long to wait for the decision: the daemon holds an `ask` for the user
/// (ADR-0016, up to `approval.timeout_secs`, 60 s by default) and always
/// answers by then, so a reply that takes minutes is a held approval, not a
/// dead daemon. Beyond this the client gives up and prints nothing.
const DECISION_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_RESPONSE: u64 = 4096;

/// One request line to the daemon, derived from the Claude Code hook input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// `hook_event_name`, verbatim.
    pub hook: String,
    /// `tool_name`, when the hook has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Sanitised description of `tool_input` (see [`summarise`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

impl Request {
    /// Build from the hook input; `None` without a `hook_event_name`.
    pub fn from_hook_input(input: &Value) -> Option<Self> {
        let hook = input.get("hook_event_name")?.as_str()?.to_owned();
        let tool = input
            .get("tool_name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let summary = summarise(tool.as_deref(), input.get("tool_input"));
        Some(Self {
            hook,
            tool,
            summary,
        })
    }
}

/// The daemon's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Proceed.
    Allow,
    /// Refuse the tool call.
    Deny,
    /// Pause for the user.
    Ask,
}

/// One response line from the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// The verdict.
    pub decision: Decision,
    /// Short human text.
    pub reason: String,
}

/// Summarise `tool_input` per the protocol: the tool's path, command, pattern,
/// URL or query, else its compact JSON; control characters stripped and cut
/// to [`SUMMARY_MAX`] bytes on a char boundary.
pub fn summarise(tool: Option<&str>, input: Option<&Value>) -> Option<String> {
    let input = input?;
    let field = |key: &str| input.get(key).and_then(Value::as_str);
    let text = match tool.unwrap_or_default() {
        "Write" | "Edit" | "MultiEdit" => field("file_path"),
        // NotebookEdit carries its path in `notebook_path`, not `file_path`. Without
        // this the summary falls through to the whole tool_input JSON, so the daemon's
        // protected-tests check (which matches a `tests/` path prefix) never fires and
        // an edit to a protected test notebook is not denied — a fail-open.
        "NotebookEdit" => field("notebook_path").or_else(|| field("file_path")),
        "Bash" => field("command"),
        "Read" | "Glob" | "Grep" => field("file_path")
            .or_else(|| field("pattern"))
            .or_else(|| field("path")),
        "WebFetch" => field("url"),
        "WebSearch" => field("query"),
        _ => None,
    }
    .map_or_else(|| input.to_string(), str::to_owned);
    Some(sanitise(&text))
}

fn sanitise(text: &str) -> String {
    let mut out: String = text.chars().filter(|c| !c.is_control()).collect();
    let mut end = SUMMARY_MAX.min(out.len());
    while !out.is_char_boundary(end) {
        end -= 1;
    }
    out.truncate(end);
    out
}

/// The JSON Claude Code reads on stdout, or `None` when nothing is printed.
pub fn output(hook: &str, response: &Response) -> Option<String> {
    let value = match (hook, response.decision) {
        ("PreToolUse", Decision::Deny | Decision::Ask) => json!({
            "hookSpecificOutput": {
                "hookEventName": hook,
                "permissionDecision": response.decision,
                "permissionDecisionReason": response.reason,
            }
        }),
        ("PermissionRequest", Decision::Deny) => json!({
            "hookSpecificOutput": {
                "hookEventName": hook,
                "decision": { "behavior": "deny", "message": response.reason },
            }
        }),
        _ => return None,
    };
    Some(value.to_string())
}

/// One connection, one line each way; any failure or timeout is `None`.
pub fn exchange(socket: &Path, request: &Request) -> Option<Response> {
    let mut stream = UnixStream::connect(socket).ok()?;
    stream.set_read_timeout(Some(DECISION_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(TIMEOUT)).ok()?;
    let mut line = serde_json::to_string(request).ok()?;
    line.push('\n');
    stream.write_all(line.as_bytes()).ok()?;
    let mut reply = String::new();
    BufReader::new(stream.take(MAX_RESPONSE))
        .read_line(&mut reply)
        .ok()?;
    serde_json::from_str(&reply).ok()
}

/// Run the hook client against the socket named by [`SOCKET_ENV`] or
/// [`DEFAULT_SOCKET`].
pub fn run(stdin: impl Read, stdout: impl Write) {
    let socket =
        std::env::var_os(SOCKET_ENV).map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from);
    run_with(stdin, stdout, &socket);
}

/// Parse the hook input from `stdin`, ask the daemon at `socket` and print
/// the decision to `stdout`; on any failure print nothing.
pub fn run_with(stdin: impl Read, mut stdout: impl Write, socket: &Path) {
    let request = serde_json::from_reader(stdin)
        .ok()
        .and_then(|input: Value| Request::from_hook_input(&input));
    let Some(request) = request else {
        note("hook: malformed input, no decision");
        return;
    };
    let Some(response) = exchange(socket, &request) else {
        note(&format!("hook: no decision from {}", socket.display()));
        return;
    };
    if let Some(line) = output(&request.hook, &response) {
        // stdout failures cannot be reported anywhere useful.
        let _ = writeln!(stdout, "{line}");
        let _ = stdout.flush();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    fn summary(tool: &str, input: &Value) -> Option<String> {
        summarise(Some(tool), Some(input))
    }

    #[test]
    fn write_family_uses_file_path() {
        for tool in ["Write", "Edit", "MultiEdit"] {
            let input = json!({"file_path": "/work/src/lib.rs", "content": "x"});
            assert_eq!(summary(tool, &input).as_deref(), Some("/work/src/lib.rs"));
        }
    }

    #[test]
    fn notebook_edit_uses_notebook_path() {
        // NotebookEdit's path is in notebook_path; summarising the wrong field would
        // hide the path from the protected-tests deny (fail-open).
        let input = json!({"notebook_path": "/work/tests/foo.ipynb", "new_source": "x"});
        assert_eq!(
            summary("NotebookEdit", &input).as_deref(),
            Some("/work/tests/foo.ipynb")
        );
        // Falls back to file_path if a caller only supplies that.
        let legacy = json!({"file_path": "/work/tests/bar.ipynb"});
        assert_eq!(
            summary("NotebookEdit", &legacy).as_deref(),
            Some("/work/tests/bar.ipynb")
        );
    }

    #[test]
    fn bash_uses_command() {
        let input = json!({"command": "cargo test", "description": "run tests"});
        assert_eq!(summary("Bash", &input).as_deref(), Some("cargo test"));
    }

    #[test]
    fn read_family_prefers_file_path_then_pattern_then_path() {
        let all = json!({"file_path": "/a", "pattern": "*.rs", "path": "/src"});
        assert_eq!(summary("Read", &all).as_deref(), Some("/a"));
        let no_file = json!({"pattern": "*.rs", "path": "/src"});
        assert_eq!(summary("Glob", &no_file).as_deref(), Some("*.rs"));
        let only_path = json!({"path": "/src"});
        assert_eq!(summary("Grep", &only_path).as_deref(), Some("/src"));
    }

    #[test]
    fn web_tools_use_url_and_query() {
        let fetch = json!({"url": "https://example.org", "prompt": "p"});
        assert_eq!(
            summary("WebFetch", &fetch).as_deref(),
            Some("https://example.org")
        );
        let search = json!({"query": "wardos"});
        assert_eq!(summary("WebSearch", &search).as_deref(), Some("wardos"));
    }

    #[test]
    fn other_tools_and_missing_fields_fall_back_to_compact_json() {
        let input = json!({"b": 1, "a": [true]});
        assert_eq!(
            summary("Task", &input).as_deref(),
            Some(r#"{"a":[true],"b":1}"#)
        );
        assert_eq!(
            summarise(None, Some(&input)).as_deref(),
            Some(r#"{"a":[true],"b":1}"#)
        );
        assert_eq!(
            summary("Write", &json!({"content": "x"})).as_deref(),
            Some(r#"{"content":"x"}"#)
        );
    }

    #[test]
    fn no_tool_input_means_no_summary() {
        assert_eq!(summarise(Some("Write"), None), None);
        assert_eq!(summarise(None, None), None);
    }

    #[test]
    fn control_characters_are_stripped() {
        let input = json!({"command": "ls\n -la\t\u{1b}[0m\u{7f}x"});
        assert_eq!(summary("Bash", &input).as_deref(), Some("ls -la[0mx"));
    }

    #[test]
    fn summary_is_capped_on_a_char_boundary() {
        let text = "é".repeat(200); // 400 bytes, 2 each
        let input = json!({"command": text});
        let out = summary("Bash", &input).unwrap();
        assert_eq!(out.len(), SUMMARY_MAX);
        assert!(out.chars().all(|c| c == 'é'));

        let text = format!("{}€", "a".repeat(255)); // '€' straddles byte 256
        let out = summary("Bash", &json!({"command": text})).unwrap();
        assert_eq!(out.len(), 255);
        assert_eq!(out, "a".repeat(255));
    }

    #[test]
    fn request_from_pre_tool_use_payload() {
        let input = json!({
            "session_id": "abc123",
            "transcript_path": "/home/agent/.claude/projects/x/abc123.jsonl",
            "cwd": "/work",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "/work/src/lib.rs", "content": "pub fn x() {}\n"},
            "tool_use_id": "toolu_01"
        });
        let request = Request::from_hook_input(&input).unwrap();
        assert_eq!(
            request,
            Request {
                hook: "PreToolUse".into(),
                tool: Some("Write".into()),
                summary: Some("/work/src/lib.rs".into()),
            }
        );
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"hook":"PreToolUse","tool":"Write","summary":"/work/src/lib.rs"}"#
        );
    }

    #[test]
    fn request_without_tool_omits_fields() {
        let input = json!({"hook_event_name": "SessionStart", "source": "startup"});
        let request = Request::from_hook_input(&input).unwrap();
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"hook":"SessionStart"}"#
        );
        assert!(Request::from_hook_input(&json!({"tool_name": "Write"})).is_none());
    }

    fn printed(hook: &str, decision: Decision) -> Value {
        let line = output(hook, &response(decision)).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn response(decision: Decision) -> Response {
        Response {
            decision,
            reason: "why".into(),
        }
    }

    #[test]
    fn pre_tool_use_deny_and_ask_are_printed() {
        for (decision, name) in [(Decision::Deny, "deny"), (Decision::Ask, "ask")] {
            assert_eq!(
                printed("PreToolUse", decision),
                json!({"hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": name,
                    "permissionDecisionReason": "why",
                }})
            );
        }
    }

    #[test]
    fn permission_request_deny_is_printed() {
        assert_eq!(
            printed("PermissionRequest", Decision::Deny),
            json!({"hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": "deny", "message": "why"},
            }})
        );
    }

    #[test]
    fn everything_else_prints_nothing() {
        assert_eq!(output("PreToolUse", &response(Decision::Allow)), None);
        assert_eq!(output("PermissionRequest", &response(Decision::Ask)), None);
        assert_eq!(
            output("PermissionRequest", &response(Decision::Allow)),
            None
        );
        assert_eq!(output("PostToolUse", &response(Decision::Deny)), None);
        assert_eq!(output("Stop", &response(Decision::Ask)), None);
    }

    #[test]
    fn response_parses_lowercase_decisions() {
        let parsed: Response =
            serde_json::from_str(r#"{"decision":"ask","reason":"step-through"}"#).unwrap();
        assert_eq!(
            parsed,
            Response {
                decision: Decision::Ask,
                reason: "step-through".into()
            }
        );
        assert!(serde_json::from_str::<Response>(r#"{"decision":"Ask","reason":"x"}"#).is_err());
    }

    #[test]
    fn end_to_end_over_a_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("hooks.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let request: Request = serde_json::from_str(&line).unwrap();
            (&stream)
                .write_all(
                    b"{\"decision\":\"ask\",\"reason\":\"step-through: pause before writes\"}\n",
                )
                .unwrap();
            request
        });

        let stdin = r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/work/a.rs","content":""}}"#;
        let mut stdout = Vec::new();
        run_with(stdin.as_bytes(), &mut stdout, &socket);

        let request = server.join().unwrap();
        assert_eq!(request.hook, "PreToolUse");
        assert_eq!(request.tool.as_deref(), Some("Write"));
        assert_eq!(request.summary.as_deref(), Some("/work/a.rs"));
        let stdout = String::from_utf8(stdout).unwrap();
        assert!(stdout.ends_with('\n'), "{stdout:?}");
        assert_eq!(
            serde_json::from_str::<Value>(&stdout).unwrap(),
            json!({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": "step-through: pause before writes",
            }})
        );
    }

    #[test]
    fn unreachable_socket_prints_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let stdin = r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{}}"#;
        let mut stdout = Vec::new();
        run_with(
            stdin.as_bytes(),
            &mut stdout,
            &dir.path().join("missing.sock"),
        );
        assert!(stdout.is_empty());
    }

    #[test]
    fn malformed_input_prints_nothing_and_does_not_connect() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("hooks.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let mut stdout = Vec::new();
        run_with("not json".as_bytes(), &mut stdout, &socket);
        run_with(r#"{"tool_name":"Write"}"#.as_bytes(), &mut stdout, &socket);
        assert!(stdout.is_empty());
    }
}
