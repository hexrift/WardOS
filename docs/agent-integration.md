# Agent Integration (`ward claude`, `ward codex`)

Status: Phase 2 design. Builds on the Phase 1 runtime (ADR-0013), `ward-agent`
(ADR-0003) and `ward-proxy` (ADR-0006). Facts about Claude Code below come from its
public documentation and are the inputs to experiments E-07 and E-08.

## 1. What `ward claude` does

```text
ward claude [dir] [-- <claude args>]
```

1. Open (or resume) the project session: policy → manifest, entry snapshot, event log.
2. Start `ward-proxy` for the session with the manifest's `NetworkCapability`, plus the
   agent's own hosts (§3) so the agent can reach its model API and nothing else.
3. Build the sandbox: worktree rw at `/work`, `/env` rw, tmpfs `$HOME`, **no host
   home**, netns whose only egress is the proxy, `ward-agent` as PID 1 (Landlock,
   seccomp, `NoNewPrivs`).
4. Provision a **sandbox-private** agent config dir (`CLAUDE_CONFIG_DIR=/home/agent/.claude`)
   containing only: hook wiring (§4), a settings file that disables non-essential
   traffic, and a *short-lived* credential or a gateway pointer (§3). The user's real
   `~/.claude/.credentials.json` is never mounted.
5. Exec the agent with proxy env (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY=localhost`)
   and the observer streaming live.

Nothing above requires the user to know about namespaces or proxies; `ward claude`
is one command.

## 2. Two sandboxes, one trust boundary

Claude Code ships its own Linux sandbox (bubblewrap + socat, optional seccomp),
configurable via `sandbox.*` in its settings. WardOS treats it as **inner, untrusted
defence-in-depth**: it runs inside the WardOS sandbox, may be left enabled, and is never
relied upon (threat-model row 26, ST-025). Its `sandbox.network.allowedDomains` is set to
the same allowlist the outer proxy enforces so the two agree; the outer proxy is the
one that counts.

## 3. Network and credentials

Required for Claude Code to function (allowlisted in `Development` mode):

| Host | Purpose | Notes |
| --- | --- | --- |
| `api.anthropic.com` | model API | required |
| `claude.ai`, `platform.claude.com` | OAuth / token exchange | required for OAuth login; not needed with an API key or gateway |
| `mcp-proxy.anthropic.com` | hosted MCP connectors | optional; `ENABLE_CLAUDEAI_MCP_SERVERS=false` |

Disabled inside the sandbox by default (denied by the proxy, and switched off so the
agent does not retry): telemetry/error reporting (`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`),
auto-update hosts, artifact hosts (`CLAUDE_CODE_DISABLE_ARTIFACT=1`), changelog fetch.

Credential delivery (ADR-0008) prefers **gateway mode**: the sandbox gets
`ANTHROPIC_BASE_URL=http://<proxy>/anthropic` and a placeholder
`ANTHROPIC_AUTH_TOKEN`; `ward-proxy` injects the user's real key on the way out. The
long-lived key never enters Zone 3. If gateway mode proves incompatible with a
provider's OAuth refresh (E-07), the fallback is a per-session short-lived token minted
by the broker into the private config dir.

## 4. Hooks: step-through and semantic events

Claude Code hooks receive JSON on stdin and can allow or deny with a JSON decision:

| Hook | WardOS use | Origin |
| --- | --- | --- |
| `PreToolUse` | Step-through: `ward-request` asks `wardd`; on `Ask`, the observer prompts; deny → `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":…}}` | Agent (claim) |
| `PermissionRequest` | Same decision path for the agent's own permission prompts | Agent |
| `PostToolUse` | `AgentClaim{ToolUse}` for the observer's intent column | Agent |
| `SessionStart` / `Stop` | `AgentStateChanged` bookends | Agent |

Hook-derived records are **claims**, never enforcement facts: the kernel-origin
events from inotify/exec capture and the proxy remain the truth (event-model §2).
Hooks matter for UX (intent, holds) and for TamperWard's steering (`run` envelope),
not for isolation.

## 5. Headless and interactive

Interactive: `claude` with a TTY inside the sandbox (PID 1 forwards signals). Headless:
`claude -p "<task>" --output-format stream-json --permission-mode dontAsk` with tool
allowlists, which is how the security CI drives hostile-agent scenarios. `--bare` is
avoided in WardOS sessions because it skips hooks.

## 6. Codex, Gemini CLI, Aider

Same shape: per-agent module in `ward-cli` supplying (a) required hosts, (b) config-dir
and env conventions, (c) hook/adapter mapping if the agent has one, (d) headless flags.
Codex and Gemini get their API hosts (`api.openai.com`, `generativelanguage.googleapis.com`)
in `Development` mode; agents without hooks get intent only from exec/file capture.

## 7. Acceptance (Phase 2 gate)

* `ward claude` and `ward codex` complete a real task in `examples/ward-demo` with no
  long-lived credential present in the sandbox (ST-012, ST-024).
* The only successful egress in the session log is to the allowlisted hosts; every
  other attempt is a `NetworkDenied` record.
* A full session replays from its sealed log.

## 8. Status (Phase 2, in progress)

Implemented and verified end to end: `ward claude` / `ward codex` launch the agent
interactively inside the session sandbox with the agent profile env (private config
dir, non-essential traffic off). Every run gets a per-session `ward-proxy` on a Unix
socket bound into the isolated network namespace, `ward-agent` relays the sandbox's
loopback `127.0.0.1:3128` to it, and both cases of `http_proxy`/`https_proxy` point
there (ADR-0014). Each proxy decision is a `NetworkRequested` / `NetworkDenied` record
rendered as `NET` / `DENY`. Measured on the demo: under `development`, an HTTPS request
to `registry.npmjs.org` succeeds (`200`, TLS verified against the read-only CA roots
bound into the sandbox) while `10.0.0.1` and `169.254.169.254` get `403`; under
`localhost_only`, `api.github.com` gets `403`. The daemon probes the shim for
`--relay` support and Landlock availability and records degradation rather than
silently weakening. Host credentials enter the sandbox only via an explicit, printed
`--pass-env NAME`; gateway-mode injection (§3) is being implemented in `ward-proxy` so
that even this becomes unnecessary for the model API key.
