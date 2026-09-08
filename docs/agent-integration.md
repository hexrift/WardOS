# Agent Integration (`ward claude`, `ward codex`)

Status: living document; the project's phase is in docs/status.toml and the README.
Builds on the runtime of ADR-0013, `ward-agent`
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

Credential delivery (ADR-0008) is **gateway mode**, implemented: when the host holds
`ANTHROPIC_API_KEY` (environment, else `$WARD_STATE_DIR/vault/ANTHROPIC_API_KEY`), the
sandbox gets `ANTHROPIC_BASE_URL=http://127.0.0.1:3128/anthropic` and the placeholder
`ANTHROPIC_API_KEY=ward-gateway`. `ward-proxy` strips the placeholder (`x-api-key`,
`authorization`) and injects the real key over TLS to `api.anthropic.com`. The
long-lived key never enters Zone 3; the grant is a `CredentialGranted` record (`CRED`
row) with `delivery: proxy-injected`. The gateway upstream is the host's choice, so the
session allowlist does not apply to it (`localhost_only` still reaches the model API);
`offline` still means offline and no grant is made. `--pass-env ANTHROPIC_API_KEY`
opts out: the real key is handed to the agent, printed as such, and no gateway is set
up. GitHub works the same way (`credential-broker.md` §4): with `--grant github` (or an
`allow` rule) the agent's `git push`/`fetch` to `github.com` and its `GITHUB_API_URL`
calls leave through `/github` and `/github-api` routes, scoped to the policy's
repositories and permissions, with the host's `GITHUB_TOKEN` injected by the proxy. If gateway mode proves incompatible with a provider's OAuth refresh (E-07), the
fallback is a per-session short-lived token minted by the broker into the private
config dir.

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

Implemented: `ward claude` seeds `/home/agent/.claude/settings.json` (read-only, from
the daemon) so every hook above runs `/run/ward/ward-agent hook`. That client reads
the hook payload on stdin, sends one JSON line `{hook, tool, summary}` to `wardd` over
the session's hook socket (`/run/ward/hooks.sock`, bound like the egress socket), and
relays the answer: `allow` prints nothing; `ask` or `deny` on `PreToolUse` prints the
`hookSpecificOutput` decision so Claude Code holds for the user or refuses. `wardd`
records each call as `AgentClaim{ToolUse}` (`TOOL` row: `PreToolUse Write
/work/src/lib.rs → ask`) and the bookends as `AgentClaim{Note}`. The decision follows
the manifest's observer mode: `quiet`/`live` always allow; `step_through` answers
`ask` before writes (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`) when
`pause_before_writes` is set and before `WebFetch`/`WebSearch` when
`pause_before_network` is set. Before any of that, a `Write`/`Edit` on a path listed
under `protected.tests` in the entry snapshot's `.tamperward/config.yml` is answered
`deny` with `protected by TamperWard policy: tests` (Bash is not inspected; the
verifier's pristine overlay is the real guard). The hold itself is the agent's own
permission prompt:
the step-through UX rides on Claude Code's terminal, which is why this is best-effort
(event-model §7). An unreachable socket or a malformed answer makes the client print
nothing and exit 0: the outer layers are what hold. Codex has no hook layer; it gets
intent only from exec and file capture (§6). To turn the holds on for a project:

```yaml
# .ward/policy.yaml
observer: !step_through
  pause_before_writes: true
  pause_before_network: true
```

### 4.1 Approvals held by the daemon (ADR-0016)

With a `wardd` serving the session, an `ask` is no longer handed to the agent's own
prompt. The flow, in the order it happens:

```text
agent hook ──► ward-agent hook ──► hooks.sock ──► ward (Hooks) ──► control.sock ──► wardd
  PreToolUse                        {hook,tool,summary}      decide() = ask     Request::Hold
                                                                                    │ appends CapabilityRequested (seq N)
                                                                                    │ pending += {id: N, tool, summary, reason}
      desktop ◄── ward session pending --follow ◄── Subscribe ◄─────────────────────┤
  wardos-approve shows the notification; y / s / n                                  │
      desktop ──► ward session approve N allow|allow-session|deny ──► Request::Approve
                                                                                    │ appends CapabilityDecided
agent ◄── {decision: allow|deny, reason} ◄── Response::Decision ◄───────────────────┘
```

1. `ward` (the process running the sandbox) starts its hook listener with a
   `DaemonHolder` when the session's control socket answers. When `decide` says `ask`,
   the listener sends `Request::Hold { tool, summary, reason, timeout_secs }` over a
   connection of its own and waits for the one answer that connection gets. Each hook
   connection is served on its own thread, so a held write does not stall the agent's
   other hooks.
2. The daemon appends a `CapabilityRequested` record (`event-model.md` §7) and registers
   the approval under that record's sequence number as its id, in one step under the
   log's mutex, so a subscriber that sees the record can already answer it.
   `Request::Pending` lists what is open; `Request::Approve { id, decision }` answers
   it with `allow`, `allow-session` or `deny`. `allow-session` is remembered for the
   same tool on the same target for the rest of the session: the next such `Hold` is
   answered at once, and still recorded as a request and a session-scoped decision.
3. When the answer arrives, or `timeout_secs` pass (`approval.timeout_secs`, the
   session's `WARD_APPROVAL_TIMEOUT_SECS`, default 60), the daemon appends
   `CapabilityDecided` and answers `Response::Decision { id, decision, reason }`. The
   hook relays `allow` or `deny` with the reason (`approval: allowed once`, `approval:
   allowed for the session`, `approval: denied`, `approval: timed out`) and records the
   claim with the decision the agent actually heard (`PreToolUse Write /work/src/lib.rs
   → deny`). A session that ends with a question open releases it as `approval:
   session ended`, denied, and no record follows the seal.
4. Deny is the default: on timeout, on a daemon lost mid-hold (`approval: lost the
   daemon`), and on a sealed log. Only when there is no daemon at all does `ask` pass
   through to the agent's own prompt as before (§4), because there is nothing to hold
   it and nothing to show it. `ward-agent hook` waits up to five minutes for the
   decision, which is what makes a held approval possible: its old five-second read
   timeout would have printed nothing and let the agent's default flow decide.
5. A paused session (ADR-0019 §3, `ward pause`) holds the hold in turn: a question
   that is open stays open with its timeout stopped, `Request::Approve` is refused
   with `paused by ward` until `ward resume`, and a `Hold` that arrives while paused
   waits like the rest. Nothing is denied by the pause itself; the clock simply does
   not run.

The approval record separates the agent's claim from Ward's authority (ADR-0019,
decision 2). What the daemon holds, lists and prints:

```text
Approval {
  id, tool, summary,           the request as the hook sent it (summary: the URL, path or command)
  claim,                       "<tool> <summary>": the agent's words, verbatim, shown labelled as such
  authority: {                 derived by the daemon; never populated from the agent's text
    rule,                      why Ward asks: "step-through: pause before network"
    destination,               sanitised: the URL's host, the path under /work, the command's program
    network,                   the proxy's own verdict: "reachable · restricted (dev)",
                               "refused · host is not on the session allowlist", or "none"
    method,                    "GET" | "read" | "write" | "exec"; "write · refused (protected by
                               TamperWard policy: tests)" or "… refused (/work is read-only)"
    credential,                "GitHub · contents:read, issues:read" once the launch granted it;
                               "… · not granted (--grant github)" for an ask rule; "none"
    repository,                the rule's repositories, current_repository resolved from origin
    lifetime,                  null while open (the answer chooses); once | session in the grant
  },
  requested_at_unix_ms
}
```

`Deriver` (`approvals.rs`) is built once per daemon from the session's manifest, the
worktree's GitHub remote and the entry snapshot's protected paths; `network` is
`ward_proxy::Policy::check_host` on the destination, exactly what the proxy will do,
and `credential` is read from the `CredentialGranted` records the daemon itself
appends (a `--grant github` launch), else from the manifest's rule. A denied write
or an unreachable host is still asked when step-through says so, but the block says
`refused`, so a `y` grants the tool and nothing more.

Temporary authority stays visible while it exists (decision 4): `Request::Grants` /
`ward session grants [--json]` lists every `allow-session` answer (`kind: approval`,
`label: "WebFetch api.github.com"`, `scope`, `lifetime: session`) and every credential
the proxy injects (`kind: credential`, `label: "GitHub"`, `scope: "contents:read,
issues:read · github.com, api.github.com"`, `lifetime: launch`), oldest first; the
shell derives the same list from the stream (`ward-shell-core` `authority.rs`) for
the bar's `NET restricted · github+` and `GRANTS n` and the authority panel.

The desktop side is `wardos-approve` (`desktop.md` §Commands): `--watch` follows
`ward session pending --json --follow` (one JSON object per line: the record above
plus `agent` and `session`) and shows each approval as a mako notification with the
three blocks (`DESTINATION` in the mono face, `REQUESTED BY AGENT` escaped, `WARD WILL
ALLOW` as `Network`, `Method`, `Credential`, `Repository`, `Lifetime` rows) and the
`Allow once` / `Allow session` / `Deny` actions with their keys, relaying the chosen
one as `ward session approve --session <id> <n> <decision>`; without arguments it
lists what is pending, shows the blocks, and takes `y` / `s` / `n` from the keyboard.
`ward session pending` without `--json` prints the same three blocks per approval.
From home, where the listener and the bar run, `ward session pending` and
`ward-shell` mean the newest session a daemon serves (`client::desktop_socket`); a
project directory still means its own session, and `--session` names one outright.

## 5. Headless and interactive

Interactive: `claude` with a TTY inside the sandbox (PID 1 forwards signals). Headless:
`claude -p "<task>" --output-format stream-json --permission-mode dontAsk` with tool
allowlists, which is how the security CI drives hostile-agent scenarios. `--bare` is
avoided in WardOS sessions because it skips hooks.

## 6. Codex, Gemini CLI, Aider

Same shape: per-agent module in `ward-cli` supplying (a) required hosts, (b) config-dir
and env conventions, (c) hook/adapter mapping if the agent has one, (d) headless flags.
Codex gets the same gateway treatment as Claude Code: `OPENAI_API_KEY` stays on the host,
the sandbox sees `OPENAI_BASE_URL=http://127.0.0.1:3128/openai/v1` and a placeholder key,
and the proxy injects `Authorization: Bearer …` on the way to `api.openai.com` (client
`authorization`, `openai-organization` and `openai-project` headers are stripped). Gemini
gets its API host (`generativelanguage.googleapis.com`) in `Development` mode until it has
a gateway spec. Agents without hooks get intent only from exec/file capture.

## 7. Acceptance (Phase 2 gate)

* `ward claude` and `ward codex` complete a real task in `examples/ward-demo` with no
  long-lived credential present in the sandbox (ST-012, ST-024).
* The only successful egress in the session log is to the allowlisted hosts; every
  other attempt is a `NetworkDenied` record.
* A full session replays from its sealed log.

## 8. Status

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
silently weakening. The model-API key stays on the host: `ward claude` configures the
`/anthropic` gateway route (§3) and the log records the grant; verified end to end in
`crates/ward-daemon/tests/e2e.rs` (the sandboxed process holds only the placeholder,
the upstream receives the real key). Other host credentials enter the sandbox only via
an explicit, printed `--pass-env NAME`. Hook adapters (§4) are wired: the daemon
seeds the settings file, answers `/run/ward/hooks.sock`, and records claims; verified
end to end in `crates/ward-daemon/tests/e2e.rs` under a `step_through` policy. Live
run (E-07, `experiments.md` §5): Claude Code 2.1.263 started headless inside the
sandbox from the read-only `/opt` bind, reached `api.anthropic.com` only through the
gateway (the API's `401` for a deliberately invalid host key proves the path), and its
`SessionStart` hook was logged as a claim. Not yet: a full task with a valid key, the
GitHub adapter, nested containers.

## 9. Shipped in the image (ADR-0017)

The WardOS image carries both agents, so `ward claude` and `ward codex` work on a fresh
install without installing anything. [`image/agents/package.json`](../image/agents/package.json)
pins `@anthropic-ai/claude-code` and `@openai/codex` (and `tamperward`) at exact
versions; its lockfile records every tarball with an integrity hash; the image build
runs `npm ci --omit=dev --ignore-scripts` on it under `/usr/lib/wardos/agents` (then
`npm rebuild @anthropic-ai/claude-code`, the one postinstall that places the native
binary) and links `/usr/bin/claude` and `/usr/bin/codex` to the two commands. Node.js
comes from Fedora (`nodejs24`, `nodejs24-npm` in `image/packages.txt`) and the build fails when it
is older than the `engines` floor (22). Versions are bumped by editing `package.json`,
regenerating the lockfile and opening a pull request; the image build's "What the image
holds" step prints `claude --version` and `codex --version` as the proof
([`image/agents/README.md`](../image/agents/README.md)).

How `ward claude` finds them: the sandbox binds `/usr` (and `/opt`) read-only
(`sandbox.rs`, `SYSTEM_RO`) and builds its `PATH` from the host's entries under those
roots plus `/usr/bin`, so `/usr/bin/claude` resolves inside the sandbox through
`/usr/lib/wardos/agents/node_modules/...` the same way it does on the host, root-owned
and unwritable by the agent. Nothing in `~/.local` or `/home` is needed, which is the
point: the agent runs from image content only. `ward doctor` reports the three commands
with their versions (`agents` row), the Node version against the floor (`node`), and
whether `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` are on the host, in the environment or in
`$WARD_STATE_DIR/vault/` (`keys`; presence only, never a value, with `ward vault set
ANTHROPIC_API_KEY` as the fix). On a host that is not the image, the rows say so and
name the `npm install -g` command.
