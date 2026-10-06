# Agent Integration (`ward claude`, `ward codex`, `ward agent`)

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
   seccomp, `NoNewPrivs`). Its Landlock ruleset reads and executes only `/usr`, `/bin`,
   `/sbin`, `/lib`, `/lib64`, `/opt`, `/etc`, `/proc` and the shim itself
   (`/run/ward/ward-agent`, so a command hook can run it): the set a node's hosted
   adapters run under (ADR-0037 §2), one definition for both.
4. Provision a **sandbox-private** agent config dir (`CLAUDE_CONFIG_DIR=/home/agent/.claude`)
   containing only: hook wiring (§4), a settings file that disables non-essential
   traffic, and a *short-lived* credential or a gateway pointer (§3). The user's real
   `~/.claude/.credentials.json` is never mounted.
5. Exec the agent with proxy env (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY=localhost`)
   and the observer streaming live.

Nothing above requires the user to know about namespaces or proxies; `ward claude`
is one command. `ward codex` and `ward agent -- <program>` (any other agent) are the same
command for another adapter: every agent runs through the one launch path of §10, under
the same sandbox, allowlist and credential rules.

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
   session ended`, denied — and (#146) is given its own `CapabilityDecided` record,
   `by: SessionEnded`, appended *before* `SessionEnded` and the seal, so the request
   still has a terminal record rather than silently vanishing at the seal the way it
   did before #146. `Request::Approvals` / `ward session approvals [--json]` lists
   every approval the session has asked, pending or decided (state `pending`,
   `allowed`, `allowed-session`, `denied`, `timed-out` or `session-ended`), unlike
   `Request::Pending` which only ever shows what is still open — so a request that
   missed its notification, or whose notification was dismissed before it was
   answered, is still findable for the rest of the session. The daemon keeps this as
   a bounded in-memory history (oldest dropped first past a cap), not the log itself;
   `ward replay` remains the durable, unbounded account.
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
   not run. Each question has one decision clock (#146 item 4), armed with the
   `Hold`'s `timeout_secs` as it is registered: the timeout is enforced from it, a
   pause holds it where it stands, and resume runs it on from there, so a pause
   neither spends nor refunds decision time. `Request::Pending` and
   `Request::Approvals` report it on every still-open question as `countdown {
   remaining_ms, timeout_ms, held }`, true as of the answer, so the desktop shows the
   daemon's figure rather than working one out from when a request arrived.

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
  requested_at_unix_ms,
  countdown?: {                open questions only, as the daemon answered (#146 item 4); absent otherwise
    remaining_ms,              decision time left before deny-on-timeout; stands still while held
    timeout_ms,                the whole decision time the Hold asked for
    held                       true while the session is paused: the clock does not run
  }
}
```

`Deriver` (`approvals.rs`) is built once per daemon from the session's manifest, the
GitHub remote resolved once from the worktree at session start and persisted in
`SessionMeta::origin_repo` (not re-read from the live worktree at any later point —
issue #196) and the entry snapshot's protected paths; `network` is
`ward_proxy::Policy::check_host` on the destination, exactly what the proxy will do,
and `credential` is read from the `CredentialGranted` records the daemon itself
appends (a `--grant github` launch), else from the manifest's rule. A denied write
or an unreachable host is still asked when step-through says so, but the block says
`refused`, so a `y` grants the tool and nothing more.

Temporary authority stays visible while it exists (decision 4): `Request::Grants` /
`ward session grants [--json]` lists every `allow-session` answer (`kind: approval`,
`label: "WebFetch api.github.com"`, `scope`, `lifetime: session`) and every credential
the proxy injects (`kind: credential`, `label: "GitHub"`, `scope: "contents:read,
issues:read · github.com, api.github.com"`, `lifetime: launch`), oldest first, each
with the daemon-minted `id` it was listed under and a `revoke_state` of `active`,
`revoking` or `unconfirmed` (#245 — see below); the shell derives the same list from
the stream (`ward-shell-core` `authority.rs`) for the bar's `NET restricted · github+`
and `GRANTS n` and the authority panel.

`Request::Revoke` / `ward session revoke <id>` (#140 items 4-6, #245) withdraws one
grant by that id, host-confirmed. An `allow-session` answer is forgotten from
`remembered` at once, so the same tool on the same target asks again — it has no proxy
route to wait on. A credential grant instead instructs the owning proxy to stop
honoring it (the same `GatewayRoute` the credential was injected through, tagged with
this grant's id when it was granted — `Response::Granted`, `GatewayRoute::revocable`)
and waits for that proxy's acknowledgement, up to `crate::revoke::ACK_TIMEOUT` (a
couple of seconds); while it waits, the grant shows `revoke_state: revoking` in
`Request::Grants`, never silently as still-plain-`active` or already gone. Refused
when `id` names no live grant — already revoked, retired when its launch ended, or
never minted. No panel action calls this yet (the layer-shell toolkit blocker #243 and
#210 already noted); it is CLI-only.

The daemon reaches the proxy the same way `ward pause` does (`pause.rs`'s own doc
comment): a file under `sessions/<id>/revoke/`, since `wardd` has no direct handle onto
a proxy that runs inside the client's own `Session::run_launch`, not the daemon. The
answer, `Response::Revoked`, is one of three honest outcomes, never collapsed into a
bare success or a bare error:

- **`Withdrawn`** — the proxy confirmed; no new request may use the credential from now
  on. The grant is removed from `Request::Grants` and `CredentialRevoked` is recorded
  (the shell drops the matching panel row the same moment).
- **`WithdrawnInFlight(n)`** — the proxy confirmed and stopped honoring the credential
  for new requests, but `n` connection(s) that had already passed that check when the
  marker landed are still relaying with it injected; bytes already handed to a socket
  are not recalled (`docs/security-model.md`). Not a failure — the authority itself is
  withdrawn exactly as `Withdrawn` is, the grant is removed the same way, and
  `CredentialRevoked` is recorded — only its already-open use outlives the revoke by
  however long it takes to finish on its own.
- **`Unconfirmed`** — nothing acknowledged within the wait: the owning proxy's launch
  may have crashed, its connection to `wardd` may have died without a terminal record
  (`Lifetime::LaunchUnknown` is the same honest middle ground), or it simply has not
  polled the marker yet. The grant is **not** removed — reporting it gone here would be
  exactly the "UI-only revoke... reported as enforced" #140's acceptance criteria
  forbid — it is instead marked `revoke_state: unconfirmed` and keeps being listed
  until its launch's own terminal record retires it. No `CredentialRevoked` is recorded
  for an outcome nothing confirmed. `ward session revoke`'s own exit code is non-zero
  for this outcome, so a script checking it learns the credential may still be in
  effect.

This closes the gap #243 (which implemented #140 items 4-6's authority-projection half
only) opened issue #245 to track: revoking an *active* credential grant now actually
stops the proxy from honoring new requests using it, not merely the listing.

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

Same shape, now as an adapter (§10): a capability document and a launch spec supplying
(a) the provider whose gateway it uses, (b) config-dir and env conventions, (c) the hooks
it wires, if any, (d) the model flag it takes. Agents without a first-party adapter
(Gemini CLI, Aider, Copilot, `OpenCode`) run through the generic process adapter,
`ward agent [--provider anthropic|openai] -- <program> …`, with no hooks.
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
end to end in `crates/ward-daemon/tests/e2e.rs` under a `step_through` policy, and in
`crates/ward-daemon/tests/session_shim_landlock.rs` with the seeded hook command run
through the bound shim under its enforced ruleset, beside a readable `/opt`. Live
run (E-07, `experiments.md` §5): Claude Code 2.1.263 started headless inside the
sandbox from the read-only `/opt` bind, reached `api.anthropic.com` only through the
gateway (the API's `401` for a deliberately invalid host key proves the path), and its
`SessionStart` hook was logged as a claim. Not yet: a full task with a valid key, the
GitHub adapter, nested containers. Since #279 every launch goes through the adapter
contract of §10 (`ward agent` for any other program), records its adapter binding, and
starts from an empty environment.

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

## 10. The adapter contract (ADR-0033)

Every agent runs through one versioned contract, `ward-agent-adapter` 1.0, and one
launch path. An adapter changes what the session *sees*; nothing in it can change what
the session *allows*. The same holds on `ward-node`, where an admitted workload names its
adapter (§10.9, ADR-0036).

### 10.1 What an adapter is

| Part | Type | What it holds |
| --- | --- | --- |
| Contract version | `ContractVersion` | `"1.0"`. A reader accepts its own major and a minor no newer than its own; anything else fails closed. |
| Capability document | `CapabilityDocument` | The descriptor (id, runtime metadata, semantic visibility, features), `hooks` (`full`, `partial`, `none`) and the semantic events it emits. |
| Launch | `LaunchSpec` | Program, fixed arguments, non-secret environment, settings files under `/home/agent`, provider. The working directory is always `/work`. |
| Semantic events | `SemanticEventLine` | One line on `$WARD_SOCKET`: `{"hook":"PreToolUse","tool":"Write","summary":"/work/src/lib.rs"}`. |
| Approvals | `ApprovalAnswer` | The one line back: `{"decision":"ask","reason":…}`, the decision one of `allow`, `deny`, `ask` (§4, §4.1). |
| Capability requests | `CapabilityRequest` | `{"capability":{"network":{"host":…}},"reason":…}`, or `{"credential":{"service":…}}` as the capability. Shape only: no host serves it yet. |
| Cancellation | `CancelRequest` | `{"reason":"user"}` (or `deadline`, `revoked`), carried out by the host: freeze, kill, confirm gone (`ward stop`). Cooperative cancellation is not served yet. |
| Task result | `TaskResult` | `{"outcome":"completed","exit_code":0}` (or `failed`, `unknown`), the host's, from the exit status. |
| Binding | `AdapterBinding` | Which adapter a launch ran, recorded as evidence (§10.4). |

A capability document is self-consistent or refused: `hooks` matches the events
(`none` ⇔ no events, `full` ⇔ all five), `semantic_tool_events` matches a tool event
(`PreToolUse`, `PostToolUse`), `approval_requests` needs a decision point (`PreToolUse`,
`PermissionRequest`), and `launch` is required, because an agent the host does not
launch is an agent it does not contain. It has no field for a network rule, a
credential, a mount or a policy; one in the JSON fails decoding. A launch spec cannot
set a variable the host owns (proxy settings in any case, `HOME`, `PATH`, `TERM`,
`WARD_*`) or seed a file outside `/home/agent`.

`ward adapters [--json]` prints every document with what this host serves of it
(`coverage`: `served` and `unserved` features).

### 10.2 The adapters WardOS ships

| Adapter | Command | Runtime (declared) | Hooks | Events | Approvals | Capability requests | Provider |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `claude-code` | `ward claude` | Claude Code 2.1.263 | `full` | `SessionStart`, `PreToolUse`, `PostToolUse`, `PermissionRequest`, `Stop` | yes, on `PreToolUse` and `PermissionRequest` | no | `anthropic` |
| `codex` | `ward codex` | OpenAI Codex CLI 0.153.4 | `none` | none | no | no | `openai` |
| `process` | `ward agent -- <program>` | `--product` / `--product-version`, else the program's name | `none` | none | no | no | `--provider`, else none |

The declared versions are the image's pins (`image/agents/package.json`; a test keeps
them equal). They are metadata: nothing checks that the installed binary is that
version.

Unsupported hooks, honestly:

* **Claude Code** wires every event of the contract through `ward-agent hook` (§4).
  Hooks Claude Code has beyond the five (`Notification`, `UserPromptSubmit`,
  `SubagentStop`, `PreCompact`, …) are not wired. `PostToolUse` is recorded, never
  answered. A `Bash` command is summarised, never parsed, so the protected-tests deny of
  §4 cannot see a shell write. It declares no capability requests, cooperative
  cancellation or structured result: `claude -p --output-format json` is not read.
* **Codex** has no hook wired: no tool intent, no approvals, no permission prompts held
  by the daemon. Its activity is what the host observes (exec, files, network).
* **The generic process adapter** knows nothing of its program: no hooks, no model (its
  flags are unknown), no settings file. A program that speaks the hook socket anyway is
  recorded (§10.6), but its document still says `none`.
* **Copilot, `OpenCode`, Gemini CLI, Aider** have no first-party adapter: the project
  does not test them. They run as the generic process adapter, with `--provider` when
  they talk to Anthropic's or OpenAI's API through the gateway.

### 10.3 One launch path, the same authority

`ward claude`, `ward codex` and `ward agent` all call `Session::adapter_launch` and then
`Session::launch`. What the adapter contributes is its command line, its environment and
settings files, and its provider's gateway route (the key stays on the host and the
proxy injects it, §3). Everything else comes from the session's capability manifest and
the user's own `--grant` and `--pass-env`, identically for every adapter:

* the sandbox (worktree at `/work`, tmpfs home, no host home or secrets, `ward-agent`
  hardening when the shim is present);
* the egress proxy and its allowlist; a provider route reaches that provider's API only
  and does not add its host to the allowlist;
* every credential decision (`CredentialGranted` / `CredentialDenied`);
* the environment, which starts empty: no variable of the launching process reaches the
  sandbox, nor the environment of bubblewrap's own init (PID 1 inside, readable by every
  process there), except `LANG`, `LC_ALL`, `USER` and `SHELL` when set
  (`session::FORWARDED_ENV`). Until #279 the whole environment of `ward` was inherited:
  tokens in the user's shell were readable in the sandbox, directly without the shim and
  through `/proc/<pid>/environ` with it.

### 10.4 What evidence records

Right after a launch's `CommandStarted`, the session records one `AgentClaim { Note }`
with origin `agent` whose payload is the binding:

```json
{"agent_adapter":{"contract":"1.0","adapter":"claude-code","runtime":{"product":"Claude Code","version":"2.1.263"},"hooks":"full","events":["SessionStart","PreToolUse","PostToolUse","PermissionRequest","Stop"],"provider":"anthropic","model":"claude-sonnet-4-5"}}
```

`runtime` is what the adapter declares; `model` is what the command line requested
(`--model`/`-m` for Claude Code and Codex, `null` when the runtime picks its default or
the adapter cannot know); `provider` is the adapter's gateway, whether or not a key was
there to grant (the grant itself is the `CredentialGranted` record). None of it is
verified, and none of it is identity, authority or policy: it is recorded as an
agent-origin claim precisely so that nothing can read it as an enforcement fact
(event-model §2). The observer shows it as a `NOTE`.

### 10.5 When a hook is missing

| Missing | What the session loses | What still holds |
| --- | --- | --- |
| `PreToolUse` | Step-through holds, approvals, the protected-tests deny before a write, tool intent in the observer | The write lands only in `/work`; the verifier restores protected tests from the entry snapshot |
| `PermissionRequest` | The daemon cannot refuse the agent's own permission prompt | The prompt grants nothing the sandbox or proxy refuses |
| `PostToolUse` | The `TOOL` rows of what ran | `RUN`, file and `NET`/`DENY` rows from the host |
| `SessionStart` / `Stop` | The bookends in the observer | `CommandStarted` / `CommandFinished` |
| All (`hooks: none`) | Every claim | Every refusal: the conformance suite (§10.7) proves them identical |

Hooks are steering: an adapter that ignores a `deny` has gained nothing the sandbox, the
proxy or the broker refuse.

### 10.6 Integrating a custom agent

1. Run it: `ward agent --product "Acme Agent" --product-version 7.4 -- acme --task …`.
   It gets the session's sandbox, allowlist and credentials, and its launches are
   recorded with the binding of §10.4.
2. If it talks to Anthropic's or OpenAI's API, add `--provider anthropic` (or `openai`):
   it sees `ANTHROPIC_BASE_URL` (or `OPENAI_BASE_URL`) on the relay and a placeholder
   key, never the key.
3. For semantic visibility, have it write one `SemanticEventLine` per event to the Unix
   socket named by `$WARD_SOCKET` and read one `ApprovalAnswer` back (one connection per
   line), honouring `deny` and `ask` before a tool runs. Every line is recorded as a
   claim. Describe what it emits in a `CapabilityDocument` of its own (`hooks: partial`
   with `PostToolUse` only, for an agent that reports after the fact); WardOS does not
   load such a document from a file yet (§10.8).

### 10.7 Conformance

`crates/ward-daemon/tests/adapter_conformance.rs` runs one hostile probe through every
shipped adapter — Claude Code, Codex and the generic process adapter — under the same
project policy, through `Session::adapter_launch` and `Session::launch`. The probe reads
a host secret, the host vault and the host home, writes outside the workspace and into
`/usr`, asks the proxy for an unlisted host, another provider's API and a private
address, connects directly and resolves a name, and reports its environment and that of
the sandbox's PID 1. The suite requires the same refusals line for line, the same
enforcement records, the same manifest, no host variable and no key in the sandbox, the
adapter's own provider as the only credential, one binding per launch, and exactly the
semantic events each document declares. A second test has a hookless agent forge an
approved `PreToolUse` and then try the request: the claim is recorded and the proxy
refuses.

The runtimes are fakes. No real Claude Code or Codex can run a task without a model API,
so the Claude Code fake does what Claude Code does with the settings `ward claude`
seeds — reads `$CLAUDE_CONFIG_DIR/settings.json` and runs each wired hook command with
Claude Code's hook payload on stdin, or writes the line `ward-agent hook` would when the
test build has no shim in the sandbox — and the Codex fake checks the environment
`ward codex` sets.

### 10.8 Not yet

* On `ward-node` (§10.9) a real Claude Code has its command hooks and its provider route
  only on a node whose operator named a `ward-agent` shim (`--agent-shim`); no CI run
  drives a real runtime against a model there either.
* Capability requests, cooperative cancellation and structured task results have
  contract shapes and no host path (`coverage` reports them as unserved for an adapter
  that claims them).
* A custom adapter's document and launch spec cannot be loaded from a file yet; it runs
  as the generic process adapter.
* The verifier's and `ward prepare`'s launches still inherit the host environment.

### 10.9 On `ward-node` (ADR-0036)

A control plane runs an agent on a node by naming its adapter beside the argv in the
signed envelope's workload, `"adapter":{"id":"claude-code"}` (node-integration.md §7.3).
The capability manifest is not involved: the same manifest bytes serve every adapter, so
"the same task manifest" is literal. A node hosts the adapters its operator names
(`ward-node --agent-adapter claude-code --agent-adapter codex`), advertises them in its
capability document (`"adapters":{"contract":"1.0","hosted":[…]}`) and refuses any other
`unsupported_grant` at `admit`.

| | On a node |
| --- | --- |
| Launch | `ward_agent_adapter::catalogue::launch(id, argv)`, the builder sessions take their first-party launches from: `argv[0]` is the program, the adapter adds its fixed arguments, its environment and its settings files (bound read-only under `/home/agent`), nothing else |
| Authority | The manifest's, exactly as for a plain workload: the workspace, no network but the attempt's proxy and its allowlist, leased credentials, holds, the action channel, cgroup limits, an empty environment |
| Provider | The node reads no model key from its environment; a runtime reaches its model API only through a manifest `credentials` grant for a service the operator configured (named after the provider by convention), at `/<service>/…` on `WARD_PROXY_SOCKET` and, on a node with a shim, on its relay |
| Shim and relay | On a node started with `--agent-shim <file>` ([ADR-0037](decisions/ADR-0037-node-agent-shim-and-relay.md)), the operator's `ward-agent`, verified at start, bound read-only at `/run/ward/ward-agent` and run ahead of the adapter as in a session (Landlock, seccomp, no capabilities). Behind an egress proxy it relays `127.0.0.1:3128` to the attempt's proxy, `HTTP_PROXY`/`HTTPS_PROXY` name it, and the provider's base URL (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`) and placeholder key (`ward-gateway`) point at it only when the manifest grants the service named after the provider |
| Hooks | For an adapter with semantic events (Claude Code), a hook socket at `/run/ward/hooks.sock` (`WARD_SOCKET`) speaking §10.1's lines, reached by Claude Code's own `ward-agent hook` on a node with a shim: each is answered `allow` and recorded as an `AgentClaim` with origin `agent`, at most 256 per attempt; a `PermissionRequest` included, never bridged onto the action channel (the hold of node-integration.md §6.9 is the approval). A hookless adapter gets no socket |
| Binding | §10.4's `agent_adapter` claim, right after the node's `NodeAttemptLaunched` |

`crates/ward-node/tests/node_adapter_conformance.rs` is §10.7's suite against the real
`ward-node` binary: the same signed manifest through Claude Code (hooks `full`), Codex and
the generic adapter, the same hostile probe (a host secret, the node's state, the
attempt's own evidence log and leases, writes outside the workspace and into `/usr`, an
unlisted host, a provider's API and a private address through the proxy, direct egress,
DNS) refused identically, identical enforcement records, none of the node's model keys
in the sandbox, the upstream seeing only the node's leased credential on the two routes
the manifest grants, and the semantic events each document declares; a forged approval,
answered `allow` on Claude Code's hook socket or sent by Codex to a socket it does not
have, is refused by the proxy and recorded the same; an adapter the node does not host is
refused before the version is consumed.

`crates/ward-node/tests/node_agent_relay_cli.rs` runs the real node with the real shim and a
runtime that behaves like Claude Code: it reads its base URL from its environment, speaks
HTTP to it, and runs each hook its seeded settings wire as a shell command with Claude
Code's hook input. The model round trip reaches the fake upstream with the node's leased
credential injected by the proxy and never visible to the runtime; its five hooks run the
bound shim and are recorded as agent claims; the relay refuses an unlisted host by
`CONNECT` and by absolute URI; without a grant for its provider (Claude Code under no
`credentials`, Codex under an `anthropic`-only grant) a runtime gets no base URL and its
route is `400`; a held credential is refused through the relay until the control plane
approves the node's request; the workload cannot write, rename, remove, `chmod` or create
beside the shim; nothing of the node's environment reaches the sandbox; and the node
refuses to start with a shim it cannot verify.
