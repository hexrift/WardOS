//! Agent hook adapter: a Unix socket the sandbox's `ward-agent hook` shim talks to,
//! answering one JSON request per connection and recording each as an agent claim
//! (`docs/agent-integration.md` §4, `docs/event-model.md` §2). Claims are never
//! enforcement; the decision feeds step-through UX and refuses edits to paths
//! TamperWard protects (`docs/tamperward-integration.md` §6). That refusal is
//! best-effort steering at the hook layer: only `Write`/`Edit`-style tools are
//! inspected, never `Bash`, and the trusted verifier remains the real guard.
//!
//! An `ask` is held rather than handed to the agent's own prompt when a
//! [`Holder`] is attached (ADR-0016): the session daemon keeps the question,
//! the desktop shows it, and the answer (or the timeout, which denies) is what
//! the agent hears. With no daemon serving the session there is nothing to
//! hold it, and `ask` passes through as before.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use ward_events::{ClaimKind, PayloadText, WardEvent};
use ward_policy::ObserverMode;

use crate::control::{RemoteSink, Request, Response};
use crate::error::{Error, Result};

/// Longest a client may take to send its request line.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How much longer than its own timeout a hold waits for the daemon's answer
/// before treating the daemon as gone.
const HOLD_GRACE: Duration = Duration::from_secs(5);

/// Largest hook request we will buffer before rejecting it (#123). A request is one JSON
/// line of `{hook, tool, summary}`, so this is deliberately far tighter than the control
/// socket's 1 MiB cap (`daemon::MAX_REQUEST_BYTES`): the agent-facing socket needs no
/// megabyte request, and a smaller ceiling bounds the buffer a hostile client can force.
const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Whole-request deadline, enforced in addition to the per-read idle [`READ_TIMEOUT`]: a
/// client that dribbles bytes just often enough never to trip the idle timeout is still
/// cut off here, so a request cannot be stretched without bound (#123).
const REQUEST_DEADLINE: Duration = Duration::from_secs(15);
/// Most connections served concurrently. Past this the accept loop refuses the next
/// connection at once with the overload response ([`overload_reject`]) instead of spawning
/// another handler, so a flood of connections cannot create unbounded host threads and the
/// accept loop is never itself blocked serving one (#123).
const MAX_HANDLERS: usize = 64;
/// Most undrained claims held in memory. Past this a claim is dropped and counted rather
/// than grown without bound; the drop is surfaced on the next drain, never silently folded
/// into the evidence as if it were complete (#123).
const MAX_PENDING_CLAIMS: usize = 4096;

/// Where an `ask` goes to wait for the user.
pub trait Holder: Send + Sync {
    /// Hold `tool` on `summary` for the reason given until it is answered or
    /// times out; `None` when nothing can hold it (the `ask` then passes
    /// through to the agent's own prompt).
    fn hold(&self, tool: &str, summary: &str, reason: &str) -> Option<HookResponse>;
}

/// The session daemon as the holder: one `Request::Hold` per question over
/// its control socket, answered when the user has.
pub struct DaemonHolder {
    socket: PathBuf,
    timeout: Duration,
}

impl DaemonHolder {
    /// Hold through the daemon on `socket`, denying after `timeout`.
    #[must_use]
    pub fn new(socket: PathBuf, timeout: Duration) -> Self {
        Self { socket, timeout }
    }
}

impl Holder for DaemonHolder {
    fn hold(&self, tool: &str, summary: &str, reason: &str) -> Option<HookResponse> {
        let mut sink = RemoteSink::connect(&self.socket)?;
        sink.set_read_timeout(Some(self.timeout + HOLD_GRACE))
            .ok()?;
        let request = Request::Hold {
            tool: tool.to_owned(),
            summary: summary.to_owned(),
            reason: reason.to_owned(),
            timeout_secs: self.timeout.as_secs(),
        };
        // Once the question is with the daemon the answer is final: a lost
        // daemon denies, it never lets the ask through.
        Some(match sink.call(&request) {
            Ok(Response::Decision {
                decision, reason, ..
            }) => HookResponse { decision, reason },
            Ok(Response::Error(e)) => HookResponse {
                decision: HookDecision::Deny,
                reason: format!("approval: {e}"),
            },
            Ok(_) | Err(_) => HookResponse {
                decision: HookDecision::Deny,
                reason: "approval: lost the daemon".to_owned(),
            },
        })
    }
}

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
    /// Refuse the action (a write to a TamperWard-protected path).
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

/// Reason returned when a write targets a TamperWard-protected path.
pub const PROTECTED_REASON: &str = "protected by TamperWard policy: tests";

/// Apply the decision rules to a request: a write to a path in `protected` is
/// denied first; otherwise the observer mode decides.
// The by-reference signature is the module's contract with the session code.
#[allow(clippy::trivially_copy_pass_by_ref)]
pub fn decide(observer: &ObserverMode, protected: &[String], req: &HookRequest) -> HookResponse {
    let permission_hook = matches!(req.hook.as_str(), "PreToolUse" | "PermissionRequest");
    let write = req.tool.as_deref().is_some_and(is_write_tool);
    let target = req.summary.as_deref().unwrap_or_default();
    if permission_hook && write && is_protected(protected, target) {
        return HookResponse {
            decision: HookDecision::Deny,
            reason: PROTECTED_REASON.to_owned(),
        };
    }
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

/// Whether the tool summary (the agent's `file_path`) names a protected path.
///
/// Entries are worktree-relative: a plain path protects that file, and an entry
/// ending in `/` protects everything under that directory. The summary may be
/// absolute under `/work/` or relative with a `./` prefix; both are stripped.
/// A summary with any `..` segment is treated as protected whenever the set is
/// non-empty, so no traversal spelling bypasses the check.
#[must_use]
pub fn is_protected(protected: &[String], summary: &str) -> bool {
    if protected.is_empty() {
        return false;
    }
    if summary == ".."
        || summary.starts_with("../")
        || summary.ends_with("/..")
        || summary.contains("/../")
    {
        return true;
    }
    let mut path = summary.strip_prefix("/work/").unwrap_or(summary);
    while let Some(rest) = path.strip_prefix("./") {
        path = rest;
    }
    // `dir/`, `dir/**` and `dir/*` all mean the directory, as they do for the verifier.
    protected.iter().any(|entry| {
        let dir = entry
            .strip_suffix("/**")
            .or_else(|| entry.strip_suffix("/*"))
            .or_else(|| entry.strip_suffix('/'))
            .map(|d| d.trim_end_matches('/'));
        match dir {
            Some(dir) => !dir.is_empty() && (path == dir || path.starts_with(&format!("{dir}/"))),
            None => path == entry,
        }
    })
}

/// The subset of a TamperWard `config.yml` this module reads.
fn is_network_tool(tool: &str) -> bool {
    matches!(tool, "WebFetch" | "WebSearch")
}

/// A request and the decision it received, kept until the session drains it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// When the request arrived.
    pub at: SystemTime,
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
    /// Claims dropped because the pending buffer was full (#123); surfaced on drain.
    dropped: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Hooks {
    /// Start answering hook requests under `observer`, denying writes to
    /// `protected` paths, listening at `dir/hooks.sock`; an `ask` passes
    /// through to the agent's own prompt.
    pub fn start(dir: &Path, observer: ObserverMode, protected: Vec<String>) -> Result<Self> {
        Self::start_with(dir, observer, protected, None)
    }

    /// [`Hooks::start`] with every `ask` held by `holder` until the user
    /// answers it. Each held question is answered on its own thread so one
    /// pending approval does not stall the agent's other hooks.
    pub fn start_with(
        dir: &Path,
        observer: ObserverMode,
        protected: Vec<String>,
        holder: Option<Arc<dyn Holder>>,
    ) -> Result<Self> {
        Self::start_inner(
            dir,
            observer,
            protected,
            holder,
            MAX_HANDLERS,
            MAX_PENDING_CLAIMS,
            REQUEST_DEADLINE,
        )
    }

    /// [`Hooks::start_with`] with the concurrency cap, pending-claim cap and whole-request
    /// deadline given explicitly (production uses [`MAX_HANDLERS`]/[`MAX_PENDING_CLAIMS`]/
    /// [`REQUEST_DEADLINE`]); the parameters let the overload and slow-drip regressions drive
    /// the bounds at a small, deterministic scale.
    fn start_inner(
        dir: &Path,
        observer: ObserverMode,
        protected: Vec<String>,
        holder: Option<Arc<dyn Holder>>,
        max_handlers: usize,
        max_claims: usize,
        deadline: Duration,
    ) -> Result<Self> {
        let socket = dir.join("hooks.sock");
        let listener = UnixListener::bind(&socket)
            .map_err(|e| Error::Sandbox(format!("hook socket {}: {e}", socket.display())))?;
        let claims = Arc::new(Mutex::new(Vec::new()));
        let dropped = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread = {
            let (claims, dropped, shutdown) = (claims.clone(), dropped.clone(), shutdown.clone());
            std::thread::spawn(move || {
                let protected = Arc::new(protected);
                // Handler threads in flight. The accept loop never serves a connection
                // itself: it spawns a handler up to `max_handlers`, and once that many are
                // live it sends a fast overload reply and closes the connection instead
                // (#123). So the loop is never occupied by a held approval — ordinary
                // requests keep being accepted and answered promptly — the concurrent
                // service count is exactly `max_handlers` (not +1 for the accept thread),
                // and shutdown never joins a handler blocked on a hold.
                let live = Arc::new(AtomicUsize::new(0));
                for stream in listener.incoming().flatten() {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    if live.load(Ordering::SeqCst) >= max_handlers {
                        // Defined overload response: refuse and close at once (never block
                        // the accept loop), counted so the drop is surfaced on the next
                        // drain rather than silently lost.
                        overload_reject(stream, &dropped);
                        continue;
                    }
                    live.fetch_add(1, Ordering::SeqCst);
                    let (protected, claims, dropped, holder, live) = (
                        Arc::clone(&protected),
                        Arc::clone(&claims),
                        Arc::clone(&dropped),
                        holder.clone(),
                        Arc::clone(&live),
                    );
                    std::thread::spawn(move || {
                        serve(
                            stream,
                            &Serve {
                                observer,
                                protected: &protected,
                                claims: &claims,
                                dropped: &dropped,
                                max_claims,
                                deadline,
                                holder: holder.as_deref(),
                            },
                        );
                        live.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            })
        };
        Ok(Self {
            socket,
            claims,
            dropped,
            shutdown,
            thread: Some(thread),
        })
    }

    /// Host path of the socket to bind into the sandbox.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Claims recorded since the last drain, as log events with their arrival
    /// time, in arrival order. If any requests were dropped under overload — the
    /// pending-claim buffer full, or a connection refused at the handler cap — a
    /// final note records how many, so the drained evidence is never presented as
    /// complete when it is not (#123).
    pub fn drain_events(&self) -> Vec<(SystemTime, WardEvent)> {
        let mut events: Vec<(SystemTime, WardEvent)> = self
            .claims
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default()
            .iter()
            .map(|c| (c.at, to_event(c)))
            .collect();
        let dropped = self.dropped.swap(0, Ordering::SeqCst);
        if dropped > 0 {
            events.push((
                SystemTime::now(),
                WardEvent::AgentClaim {
                    kind: ClaimKind::Note,
                    payload: PayloadText::new(&format!(
                        "{dropped} hook request(s) dropped under overload (handler cap reached \
                         or the pending-claim buffer full); this evidence is incomplete"
                    )),
                },
            ));
        }
        events
    }

    /// Stop the listener and remove the socket. Non-blocking: it flags shutdown, unblocks
    /// and joins only the accept thread — which never serves a request itself — so a handler
    /// blocked on a held approval cannot delay shutdown (#123). In-flight handlers finish on
    /// their own; each is bounded by its hold timeout.
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

/// The shared context a connection is served against: the observer mode, the protected
/// set, the claim buffer and its cap, the overflow counter, the whole-request deadline and
/// the optional holder. Bundled so [`serve`] takes one context rather than a long argument
/// list, and cloned cheaply (borrows) per handler.
struct Serve<'a> {
    observer: ObserverMode,
    protected: &'a [String],
    claims: &'a Mutex<Vec<Claim>>,
    dropped: &'a AtomicUsize,
    max_claims: usize,
    deadline: Duration,
    holder: Option<&'a dyn Holder>,
}

/// Handle one connection: read a line, decide, hold an `ask` when there is a
/// holder, record, reply. Malformed input closes the connection silently.
fn serve(mut stream: UnixStream, cx: &Serve) {
    let Some(req) = read_request(&stream, cx.deadline) else {
        return;
    };
    let mut response = decide(&cx.observer, cx.protected, &req);
    if let (HookDecision::Ask, Some(holder)) = (response.decision, cx.holder) {
        let tool = req.tool.as_deref().unwrap_or_default();
        let summary = req.summary.as_deref().unwrap_or_default();
        if let Some(held) = holder.hold(tool, summary, &response.reason) {
            response = held;
        }
    }
    if let Ok(mut v) = cx.claims.lock() {
        // Bound the pending buffer: past the cap the claim is dropped and counted (surfaced
        // on the next drain), so a flood of hook requests cannot grow memory without bound
        // and the drop is never silently presented as complete evidence (#123).
        if v.len() < cx.max_claims {
            v.push(Claim {
                at: SystemTime::now(),
                request: req,
                decision: response.decision,
            });
        } else {
            cx.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
    if let Ok(mut json) = serde_json::to_vec(&response) {
        json.push(b'\n');
        drop(stream.write_all(&json));
    }
}

/// Read one newline-terminated JSON request, bounded in both size and time. Returns
/// `None` — closing the connection silently — on a malformed, oversized, idle-timed-out,
/// slow-dripped or truncated request (#123). The size cap ([`MAX_REQUEST_BYTES`]) stops an
/// unbounded line from growing the buffer; the whole-request `deadline` is enforced
/// *strictly* — each blocking read waits at most the time left (capped at [`READ_TIMEOUT`]
/// for liveness), and the deadline is checked before every block — so a client that keeps
/// the connection just active enough to dodge the idle timeout cannot stretch the request
/// past `deadline`.
fn read_request(stream: &UnixStream, deadline: Duration) -> Option<HookRequest> {
    let end = Instant::now() + deadline;
    let mut reader = BufReader::new(stream);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        // Never block past the whole-request deadline: bound this read to the smaller of the
        // time left and the idle timeout, and give up if the deadline has already arrived.
        let remaining = end.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        if stream
            .set_read_timeout(Some(remaining.min(READ_TIMEOUT)))
            .is_err()
        {
            return None;
        }
        let (found, consumed, over) = {
            let available = match reader.fill_buf() {
                Ok(chunk) if !chunk.is_empty() => chunk,
                // EOF before a newline, a timeout, or a read error: give up.
                _ => return None,
            };
            // The size cap counts the request bytes before the newline, and it is checked
            // even when the newline arrives in the same chunk — otherwise a single oversized
            // read carrying its own newline would slip past it.
            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                let over = buf.len() + pos > MAX_REQUEST_BYTES;
                if !over {
                    buf.extend_from_slice(&available[..pos]);
                }
                (true, pos + 1, over)
            } else {
                let take = available.len();
                let over = buf.len() + take > MAX_REQUEST_BYTES;
                if !over {
                    buf.extend_from_slice(available);
                }
                (false, take, over)
            }
        };
        reader.consume(consumed);
        if over {
            return None; // oversized: request exceeds the byte cap
        }
        if found {
            break;
        }
    }
    serde_json::from_slice::<HookRequest>(&buf).ok()
}

/// The defined overload response (#123): the accept loop is at its handler cap, so refuse
/// this connection at once with a `Deny` and close — never blocking the loop or spawning
/// past the cap. Counted as a dropped request so [`Hooks::drain_events`] surfaces it.
fn overload_reject(mut stream: UnixStream, dropped: &AtomicUsize) {
    dropped.fetch_add(1, Ordering::SeqCst);
    drop(stream.set_write_timeout(Some(READ_TIMEOUT)));
    let response = HookResponse {
        decision: HookDecision::Deny,
        reason: "hook broker overloaded".to_owned(),
    };
    if let Ok(mut json) = serde_json::to_vec(&response) {
        json.push(b'\n');
        drop(stream.write_all(&json));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::approvals::{Approval, ApprovalDecision, Approvals, Outcome};
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
        let resp = decide(&observer, &[], r);
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

    fn protected() -> Vec<String> {
        vec!["tests/security_expiry.rs".into()]
    }

    #[test]
    fn is_protected_matches_exact_and_prefixed_spellings() {
        let p = protected();
        for summary in [
            "tests/security_expiry.rs",
            "/work/tests/security_expiry.rs",
            "./tests/security_expiry.rs",
            "/work/./tests/security_expiry.rs",
        ] {
            assert!(is_protected(&p, summary), "{summary}");
        }
        for summary in [
            "tests/other.rs",
            "/work/tests/other.rs",
            "tests/security_expiry.rs.bak",
            "src/tests/security_expiry.rs",
            "/tests/security_expiry.rs",
            "",
        ] {
            assert!(!is_protected(&p, summary), "{summary}");
        }
        assert!(!is_protected(&[], "tests/security_expiry.rs"));
    }

    #[test]
    fn is_protected_directory_entry_covers_everything_under_it() {
        for spelling in ["tests/", "tests/**", "tests/*"] {
            let p = vec![spelling.to_owned()];
            assert!(is_protected(&p, "tests/deep/nested.rs"), "{spelling}");
            assert!(!is_protected(&p, "tests_helpers/x.rs"), "{spelling}");
        }
        let p = vec!["tests/".to_owned()];
        for summary in [
            "tests/security_expiry.rs",
            "tests/deep/nested.rs",
            "/work/tests/x.rs",
            "./tests/x.rs",
            "tests",
            "tests/",
        ] {
            assert!(is_protected(&p, summary), "{summary}");
        }
        for summary in ["src/tests/x.rs", "tests_helpers/x.rs", "src/lib.rs"] {
            assert!(!is_protected(&p, summary), "{summary}");
        }
    }

    #[test]
    fn is_protected_refuses_any_dot_dot_when_set_is_non_empty() {
        let p = protected();
        for summary in [
            "/work/tests/../tests/security_expiry.rs",
            "/work/src/../tests/security_expiry.rs",
            "../tests/security_expiry.rs",
            "src/../src/lib.rs",
            "tests/..",
            "..",
        ] {
            assert!(is_protected(&p, summary), "{summary}");
            assert!(
                !is_protected(&[], summary),
                "{summary} with nothing protected"
            );
        }
        assert!(
            !is_protected(&p, "src/a..b.rs"),
            "dots inside a name are not traversal"
        );
    }

    #[test]
    fn writes_to_protected_paths_are_denied_in_every_mode() {
        let p = protected();
        let target = Some("/work/tests/security_expiry.rs");
        for observer in [
            ObserverMode::Quiet,
            ObserverMode::Live,
            step(false, false),
            step(true, true),
        ] {
            for hook in ["PreToolUse", "PermissionRequest"] {
                for tool in ["Write", "Edit", "MultiEdit", "NotebookEdit"] {
                    let resp = decide(&observer, &p, &req(hook, Some(tool), target));
                    assert_eq!(
                        resp.decision,
                        HookDecision::Deny,
                        "{hook} {tool} {observer:?}"
                    );
                    assert_eq!(resp.reason, PROTECTED_REASON);
                }
            }
        }
        // Reads, Bash and PostToolUse are not inspected.
        for (hook, tool) in [
            ("PreToolUse", "Read"),
            ("PreToolUse", "Bash"),
            ("PostToolUse", "Write"),
        ] {
            let resp = decide(&ObserverMode::Quiet, &p, &req(hook, Some(tool), target));
            assert_eq!(resp.decision, HookDecision::Allow, "{hook} {tool}");
        }
    }

    #[test]
    fn unprotected_writes_still_follow_step_through() {
        let p = protected();
        let r = req("PreToolUse", Some("Write"), Some("/work/src/lib.rs"));
        let resp = decide(&step(true, false), &p, &r);
        assert_eq!(resp.decision, HookDecision::Ask);
        assert_eq!(resp.reason, "step-through: pause before writes");
        let resp = decide(&step(false, false), &p, &r);
        assert_eq!(resp.decision, HookDecision::Allow);
        assert_eq!(resp.reason, "step-through");
        let resp = decide(&ObserverMode::Live, &p, &r);
        assert_eq!(resp.decision, HookDecision::Allow);
        assert_eq!(resp.reason, "observer: live");
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
            at: SystemTime::now(),
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
        let hooks = Hooks::start(dir.path(), step(true, false), protected()).unwrap();
        let socket = hooks.socket().to_path_buf();
        assert_eq!(socket, dir.path().join("hooks.sock"));

        let reply = roundtrip(
            &socket,
            "{\"hook\":\"PreToolUse\",\"tool\":\"Write\",\"summary\":\"/work/tests/security_expiry.rs\"}\n",
        );
        let resp: HookResponse = serde_json::from_str(&reply).unwrap();
        assert_eq!(resp.decision, HookDecision::Deny);
        assert_eq!(resp.reason, PROTECTED_REASON);

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
        assert_eq!(events.len(), 3);
        assert!(events[0].0 <= events[1].0, "arrival times are kept");
        assert_claim(
            &events[0].1,
            ClaimKind::ToolUse,
            "PreToolUse Write /work/tests/security_expiry.rs → deny",
        );
        assert_claim(
            &events[1].1,
            ClaimKind::ToolUse,
            "PreToolUse Write /work/src/lib.rs → ask",
        );
        assert_claim(&events[2].1, ClaimKind::Note, "Stop");
        assert!(hooks.drain_events().is_empty());

        hooks.stop();
        assert!(!socket.exists());
    }

    /// A holder over an in-process [`Approvals`], ids counted up: the daemon's
    /// hold without the daemon.
    struct LocalHolder {
        approvals: Arc<Approvals>,
        next_id: std::sync::atomic::AtomicU64,
        timeout: Duration,
    }

    impl Holder for LocalHolder {
        fn hold(&self, tool: &str, summary: &str, reason: &str) -> Option<HookResponse> {
            if self.approvals.remembered(tool, summary) {
                return Some(Outcome::Remembered.response());
            }
            let id = self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.approvals
                .register(Approval::new(
                    id,
                    tool,
                    summary,
                    crate::approvals::Authority::none(reason, summary),
                    0,
                ))
                .ok()?;
            Some(self.approvals.wait(id, self.timeout).response())
        }
    }

    fn held_hooks(dir: &Path, timeout: Duration) -> (Hooks, Arc<Approvals>) {
        let approvals = Arc::new(Approvals::new());
        let holder = LocalHolder {
            approvals: Arc::clone(&approvals),
            next_id: std::sync::atomic::AtomicU64::new(1),
            timeout,
        };
        let hooks =
            Hooks::start_with(dir, step(true, true), protected(), Some(Arc::new(holder))).unwrap();
        (hooks, approvals)
    }

    const WRITE: &str =
        "{\"hook\":\"PreToolUse\",\"tool\":\"Write\",\"summary\":\"/work/src/lib.rs\"}\n";

    fn ask_in_background(socket: &Path, line: &'static str) -> std::thread::JoinHandle<String> {
        let socket = socket.to_path_buf();
        std::thread::spawn(move || roundtrip(&socket, line))
    }

    #[test]
    fn a_held_ask_waits_for_the_answer_and_relays_it() {
        let dir = tempfile::tempdir().unwrap();
        let (hooks, approvals) = held_hooks(dir.path(), Duration::from_secs(5));
        let asking = ask_in_background(hooks.socket(), WRITE);
        assert!(
            crate::daemon::wait_until(Duration::from_secs(2), || !approvals.pending().is_empty()),
            "the question is pending while the agent waits"
        );
        let pending = approvals.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tool, "Write");
        assert_eq!(pending[0].summary, "/work/src/lib.rs");
        assert_eq!(
            pending[0].authority.rule,
            "step-through: pause before writes"
        );
        assert_eq!(pending[0].claim, "Write /work/src/lib.rs");
        assert!(!asking.is_finished(), "the hook is held");

        approvals
            .answer(pending[0].id, ApprovalDecision::Allow)
            .unwrap();
        let resp: HookResponse = serde_json::from_str(&asking.join().unwrap()).unwrap();
        assert_eq!(resp.decision, HookDecision::Allow);
        assert_eq!(resp.reason, "approval: allowed once");

        // A denial relays as deny; the claim records what the agent heard.
        let asking = ask_in_background(hooks.socket(), WRITE);
        assert!(crate::daemon::wait_until(Duration::from_secs(2), || {
            !approvals.pending().is_empty()
        }));
        approvals
            .answer(approvals.pending()[0].id, ApprovalDecision::Deny)
            .unwrap();
        let resp: HookResponse = serde_json::from_str(&asking.join().unwrap()).unwrap();
        assert_eq!(resp.decision, HookDecision::Deny);
        assert_eq!(resp.reason, "approval: denied");
        let events = hooks.drain_events();
        assert_claim(
            &events[0].1,
            ClaimKind::ToolUse,
            "PreToolUse Write /work/src/lib.rs → allow",
        );
        assert_claim(
            &events[1].1,
            ClaimKind::ToolUse,
            "PreToolUse Write /work/src/lib.rs → deny",
        );
        hooks.stop();
    }

    #[test]
    fn a_held_ask_nobody_answers_is_denied_when_the_timeout_passes() {
        let dir = tempfile::tempdir().unwrap();
        let (hooks, approvals) = held_hooks(dir.path(), Duration::from_millis(80));
        let started = std::time::Instant::now();
        let reply = roundtrip(hooks.socket(), WRITE);
        assert!(started.elapsed() >= Duration::from_millis(80));
        let resp: HookResponse = serde_json::from_str(&reply).unwrap();
        assert_eq!(resp.decision, HookDecision::Deny);
        assert_eq!(resp.reason, "approval: timed out");
        assert!(approvals.pending().is_empty());
        // Other hooks are not held at all.
        let reply = roundtrip(
            hooks.socket(),
            "{\"hook\":\"PreToolUse\",\"tool\":\"Read\",\"summary\":\"/work/src/lib.rs\"}\n",
        );
        let resp: HookResponse = serde_json::from_str(&reply).unwrap();
        assert_eq!(resp.decision, HookDecision::Allow);
        hooks.stop();
    }

    #[test]
    fn allow_session_answers_the_same_question_without_asking_again() {
        let dir = tempfile::tempdir().unwrap();
        let (hooks, approvals) = held_hooks(dir.path(), Duration::from_secs(5));
        let asking = ask_in_background(hooks.socket(), WRITE);
        assert!(crate::daemon::wait_until(Duration::from_secs(2), || {
            !approvals.pending().is_empty()
        }));
        approvals
            .answer(approvals.pending()[0].id, ApprovalDecision::AllowSession)
            .unwrap();
        let resp: HookResponse = serde_json::from_str(&asking.join().unwrap()).unwrap();
        assert_eq!(resp.decision, HookDecision::Allow);
        assert_eq!(resp.reason, "approval: allowed for the session");

        // The same tool on the same path: allowed at once, nothing pending.
        let started = std::time::Instant::now();
        let resp: HookResponse = serde_json::from_str(&roundtrip(hooks.socket(), WRITE)).unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(resp.decision, HookDecision::Allow);
        assert_eq!(resp.reason, "approval: allowed for the session");
        assert!(approvals.pending().is_empty());
        // Another path is a new question.
        let asking = ask_in_background(
            hooks.socket(),
            "{\"hook\":\"PreToolUse\",\"tool\":\"Write\",\"summary\":\"/work/src/main.rs\"}\n",
        );
        assert!(crate::daemon::wait_until(Duration::from_secs(2), || {
            !approvals.pending().is_empty()
        }));
        approvals.close();
        let resp: HookResponse = serde_json::from_str(&asking.join().unwrap()).unwrap();
        assert_eq!(resp.decision, HookDecision::Deny);
        assert_eq!(resp.reason, "approval: session ended");
        hooks.stop();
    }

    #[test]
    fn without_a_daemon_to_hold_it_the_ask_passes_through() {
        let dir = tempfile::tempdir().unwrap();
        // A socket path nothing listens on: the holder cannot connect.
        let holder: Arc<dyn Holder> = Arc::new(DaemonHolder::new(
            dir.path().join("control.sock"),
            Duration::from_secs(1),
        ));
        let hooks =
            Hooks::start_with(dir.path(), step(true, false), protected(), Some(holder)).unwrap();
        let resp: HookResponse = serde_json::from_str(&roundtrip(hooks.socket(), WRITE)).unwrap();
        assert_eq!(resp.decision, HookDecision::Ask);
        assert_eq!(resp.reason, "step-through: pause before writes");
        hooks.stop();
    }

    /// A daemon stand-in answering `Ping` and one `Hold`.
    fn fake_daemon(dir: &Path, answer: Option<Response>) -> PathBuf {
        let socket = dir.join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut writer = stream.try_clone().unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                    let request: Request = serde_json::from_str(&line).unwrap();
                    let response = match request {
                        Request::Ping => Some(Response::Ok),
                        Request::Hold { .. } => answer.clone(),
                        other => panic!("{other:?}"),
                    };
                    let Some(response) = response else {
                        return;
                    };
                    let mut bytes = serde_json::to_vec(&response).unwrap();
                    bytes.push(b'\n');
                    writer.write_all(&bytes).unwrap();
                    line.clear();
                }
            }
        });
        socket
    }

    #[test]
    fn the_daemon_holder_relays_the_decision_and_denies_a_lost_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let socket = fake_daemon(
            dir.path(),
            Some(Response::Decision {
                id: 4,
                decision: HookDecision::Allow,
                reason: "approval: allowed once".into(),
            }),
        );
        let holder = DaemonHolder::new(socket, Duration::from_secs(1));
        let resp = holder.hold("Write", "/work/a.rs", "r").unwrap();
        assert_eq!(resp.decision, HookDecision::Allow);
        assert_eq!(resp.reason, "approval: allowed once");

        let dir = tempfile::tempdir().unwrap();
        let socket = fake_daemon(dir.path(), None);
        let holder = DaemonHolder::new(socket, Duration::from_secs(1));
        let resp = holder.hold("Write", "/work/a.rs", "r").unwrap();
        assert_eq!(resp.decision, HookDecision::Deny);
        assert_eq!(resp.reason, "approval: lost the daemon");

        let dir = tempfile::tempdir().unwrap();
        let socket = fake_daemon(dir.path(), Some(Response::Error("session ended".into())));
        let holder = DaemonHolder::new(socket, Duration::from_secs(1));
        let resp = holder.hold("Write", "/work/a.rs", "r").unwrap();
        assert_eq!(resp.decision, HookDecision::Deny);
        assert_eq!(resp.reason, "approval: session ended");
    }

    #[test]
    fn a_request_at_the_size_cap_is_answered_and_over_it_is_refused() {
        // #123: the request buffer is bounded. A request whose bytes-before-newline equal
        // the cap is still answered; one byte over is refused with no reply, and the
        // refusal does not wedge the listener.
        let dir = tempfile::tempdir().unwrap();
        let hooks = Hooks::start(dir.path(), step(false, false), protected()).unwrap();
        let socket = hooks.socket().to_path_buf();
        let base = r#"{"hook":"Stop"}"#;
        let pad = MAX_REQUEST_BYTES - base.len();

        let at_cap = format!("{base}{}\n", " ".repeat(pad));
        assert_eq!(at_cap.len() - 1, MAX_REQUEST_BYTES);
        let resp: HookResponse = serde_json::from_str(&roundtrip(&socket, &at_cap)).unwrap();
        assert_eq!(resp.decision, HookDecision::Allow);

        let over = format!("{base}{}\n", " ".repeat(pad + 1));
        assert_eq!(over.len() - 1, MAX_REQUEST_BYTES + 1);
        assert_eq!(
            roundtrip(&socket, &over),
            "",
            "an oversized request is refused"
        );

        // The listener still answers a normal request after refusing the oversized one.
        let resp: HookResponse =
            serde_json::from_str(&roundtrip(&socket, "{\"hook\":\"Stop\"}\n")).unwrap();
        assert_eq!(resp.decision, HookDecision::Allow);
        // Only the two answered requests were recorded; the oversized one left no claim.
        assert_eq!(hooks.drain_events().len(), 2);
        hooks.stop();
    }

    #[test]
    fn a_truncated_request_without_a_newline_is_refused() {
        // #123: partial input that closes before a newline yields no decision and no claim.
        let dir = tempfile::tempdir().unwrap();
        let hooks = Hooks::start(dir.path(), step(false, false), protected()).unwrap();
        let mut stream = UnixStream::connect(hooks.socket()).unwrap();
        stream.write_all(br#"{"hook":"Sto"#).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        BufReader::new(&stream).read_line(&mut reply).unwrap();
        assert_eq!(reply, "", "a truncated request gets no decision");
        assert!(hooks.drain_events().is_empty());
        hooks.stop();
    }

    #[test]
    fn a_claim_flood_is_bounded_and_the_overflow_is_surfaced() {
        // #123: past the pending-claim cap, claims are dropped and counted, and the drop is
        // surfaced on drain as a final note — never silently folded into the evidence.
        let dir = tempfile::tempdir().unwrap();
        let hooks = Hooks::start_inner(
            dir.path(),
            step(false, false),
            protected(),
            None,
            MAX_HANDLERS,
            3,
            REQUEST_DEADLINE,
        )
        .unwrap();
        let socket = hooks.socket().to_path_buf();
        for _ in 0..5 {
            let resp: HookResponse =
                serde_json::from_str(&roundtrip(&socket, "{\"hook\":\"Stop\"}\n")).unwrap();
            assert_eq!(resp.decision, HookDecision::Allow);
        }
        let events = hooks.drain_events();
        assert_eq!(events.len(), 4, "three kept claims plus one overflow note");
        for e in &events[..3] {
            assert_claim(&e.1, ClaimKind::Note, "Stop");
        }
        match &events[3].1 {
            WardEvent::AgentClaim { kind, payload } => {
                assert_eq!(*kind, ClaimKind::Note);
                assert!(
                    payload.content().contains("dropped"),
                    "{}",
                    payload.content()
                );
                assert!(payload.content().starts_with('2'), "{}", payload.content());
            }
            other => panic!("unexpected {other:?}"),
        }
        hooks.stop();
    }

    fn held_hooks_capped(dir: &Path, max_handlers: usize) -> (Hooks, Arc<Approvals>) {
        let approvals = Arc::new(Approvals::new());
        let holder = LocalHolder {
            approvals: Arc::clone(&approvals),
            next_id: std::sync::atomic::AtomicU64::new(1),
            timeout: Duration::from_secs(10),
        };
        let hooks = Hooks::start_inner(
            dir,
            step(true, true),
            protected(),
            Some(Arc::new(holder)),
            max_handlers,
            MAX_PENDING_CLAIMS,
            REQUEST_DEADLINE,
        )
        .unwrap();
        (hooks, approvals)
    }

    #[test]
    fn at_the_handler_cap_excess_connections_get_a_fast_overload_deny() {
        // #123: with all handler slots held by pending approvals, the accept loop is NOT
        // occupied — an excess connection gets a prompt, defined overload Deny (never a
        // hang), the held asks are unaffected, and the rejection is surfaced on drain.
        let dir = tempfile::tempdir().unwrap();
        let (hooks, approvals) = held_hooks_capped(dir.path(), 2);
        let held: Vec<_> = (0..2)
            .map(|_| ask_in_background(hooks.socket(), WRITE))
            .collect();
        assert!(
            crate::daemon::wait_until(Duration::from_secs(2), || approvals.pending().len() == 2),
            "both handler slots are held by pending approvals"
        );

        // An excess connection is refused at once with the overload Deny, not held: the
        // accept loop stays responsive while the two handlers are saturated.
        let started = std::time::Instant::now();
        let reply = roundtrip(hooks.socket(), WRITE);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the overload reply is prompt, not blocked on a held approval"
        );
        let resp: HookResponse = serde_json::from_str(&reply).unwrap();
        assert_eq!(resp.decision, HookDecision::Deny);
        assert_eq!(resp.reason, "hook broker overloaded");

        // The two genuinely held asks are still answerable.
        for p in approvals.pending() {
            let _ = approvals.answer(p.id, ApprovalDecision::Allow);
        }
        for a in held {
            let resp: HookResponse = serde_json::from_str(&a.join().unwrap()).unwrap();
            assert_eq!(resp.decision, HookDecision::Allow);
        }
        // The refused connection is surfaced, not silently lost.
        let events = hooks.drain_events();
        assert!(
            events.iter().any(|(_, e)| matches!(
                e,
                WardEvent::AgentClaim { payload, .. } if payload.content().contains("dropped")
            )),
            "the overload rejection is surfaced on drain: {events:?}"
        );
        hooks.stop();
    }

    #[test]
    fn a_slow_drip_request_is_cut_off_at_the_deadline() {
        // #123: a client that holds the connection open without ever sending a newline is
        // cut off at the whole-request deadline (here 300 ms), strictly — well before the
        // 5 s idle timeout could elapse.
        let dir = tempfile::tempdir().unwrap();
        let hooks = Hooks::start_inner(
            dir.path(),
            step(false, false),
            protected(),
            None,
            MAX_HANDLERS,
            MAX_PENDING_CLAIMS,
            Duration::from_millis(300),
        )
        .unwrap();
        let stream = UnixStream::connect(hooks.socket()).unwrap();
        (&stream).write_all(br#"{"hook":"Sto"#).unwrap(); // a partial line, never terminated
        let started = std::time::Instant::now();
        let mut reply = String::new();
        let _ = BufReader::new(&stream).read_line(&mut reply);
        let elapsed = started.elapsed();
        assert_eq!(reply, "", "a slow-drip request gets no decision");
        assert!(
            elapsed >= Duration::from_millis(200),
            "not cut off before the deadline: {elapsed:?}"
        );
        assert!(
            elapsed < READ_TIMEOUT,
            "cut off at the deadline, well before the idle timeout: {elapsed:?}"
        );
        hooks.stop();
    }

    #[test]
    fn stop_is_prompt_while_handlers_are_saturated() {
        // #123: shutdown must not wait for in-flight handlers blocked on held approvals; the
        // accept thread never serves, so joining it is immediate.
        let dir = tempfile::tempdir().unwrap();
        let (hooks, approvals) = held_hooks_capped(dir.path(), 2);
        let held: Vec<_> = (0..2)
            .map(|_| ask_in_background(hooks.socket(), WRITE))
            .collect();
        assert!(
            crate::daemon::wait_until(Duration::from_secs(2), || approvals.pending().len() == 2),
            "both handler slots are held"
        );
        let started = std::time::Instant::now();
        hooks.stop();
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "stop did not wait for the 10 s holds: {:?}",
            started.elapsed()
        );
        // Release the holds so the lingering handlers exit and the asks complete.
        for p in approvals.pending() {
            let _ = approvals.answer(p.id, ApprovalDecision::Allow);
        }
        for a in held {
            let _ = a.join();
        }
    }
}
