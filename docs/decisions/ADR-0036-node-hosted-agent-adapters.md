# ADR-0036 — Agent adapters on ward-node: the workload names one, the manifest stays the authority

Status: **Proposed; second slice of [#279](https://github.com/hexrift/WardOS/issues/279);
§4's base URL and the deferred shim and relay amended by
[ADR-0037](ADR-0037-node-agent-shim-and-relay.md).**
It applies [ADR-0033](ADR-0033-agent-adapter-contract.md)'s contract to `ward-node`
(its §8 first item) without changing the contract, the node protocol's minor or the
event catalogue.

## Context

ADR-0033 gave every agent one versioned contract (`ward-agent-adapter` 1.0) and one
launch path in the per-session daemon, and proved for local sessions that Claude Code,
Codex and the generic process adapter run under the same enforcement. A `ward-node`
workload was still a bare `argv`: a control plane could run `claude` on a node, but the
node did not know it was an agent, seeded none of its configuration, offered it no hook
socket and recorded nothing of which runtime ran. #279's acceptance — "at least two
materially different agent runtimes execute the same Ward task manifest with equivalent
node-enforced authority; missing adapter hooks reduce semantic visibility but cannot
bypass sandbox, network or credential enforcement" — was proven for sessions only.

## Decision

### 1. The workload names the adapter; the capability manifest does not

The admission envelope's `workload` gains an optional `adapter`, additive within protocol
1.3, beside the argv it describes:

```json
"workload":{"argv":["/opt/claude/bin/claude","-p","fix the build"],
            "capability_manifest":{…},"snapshot":"…","wall_clock_budget_ms":600000,
            "adapter":{"id":"claude-code"}}
```

`id` is in the contract's id grammar (1–64 bytes of `a-z 0-9 . _ -`, starting with a
letter or digit) and is the only field; with an adapter, `argv[0]` must be a launch
program (a name on the sandbox `PATH` or an absolute path). A workload outside this
grammar fails envelope decoding (`authority_denied`). Absent, the field is not on the wire,
so every existing envelope and the §7.4 test vector are byte for byte unchanged.

The adapter is part of *what runs*, as the argv is, and is signed with it; it is not part
of *what is allowed*. Keeping it out of the capability manifest means one manifest — the
same bytes and the same hash — serves every adapter, which is what "the same task manifest
with equivalent authority" requires.

### 2. A node hosts the adapters its operator names, and says so

`ward-node --agent-adapter <id>` (repeatable; `claude-code`, `codex` or `process`, the
ids `ward_agent_adapter::catalogue::LAUNCHABLE` names; it needs `--task-root`; an unknown id
stops the node) hosts that adapter. The capability document then carries, after `actions`,

```json
"adapters":{"contract":"1.0","hosted":["claude-code","codex"]}
```

in catalogue order, and only on such a node: a node without the flag emits exactly the
earlier document. `admit` refuses a workload naming an adapter the node does not host, an
id no node knows, or an argv whose launch the shared catalogue cannot build (a model the
binding cannot record) `unsupported_grant`, after authority is proven and before the
version is consumed (node-integration.md §8.1 step 16).

### 3. The launch is the shared contract's, and cannot widen the attempt

At `start` the node builds the launch with `ward_agent_adapter::catalogue::launch(id, argv)`
— the builder `ward-daemon` now also takes its first-party launch specs from, so a session
and a node launch Claude Code and Codex the same way. `argv[0]` is the program; the
adapter contributes its fixed arguments (none today), its non-secret environment
(`CLAUDE_CONFIG_DIR` and friends, `CODEX_HOME`) and its settings files, written mode 0600
into the attempt's private `<task-root>/<task>/<attempt>.adapter/` and bound read-only at
their path under `/home/agent`. `LaunchSpec`'s rules hold: no mount, network rule,
credential, working directory or host-owned variable (`HOME`, `PATH`, `TERM`, `WARD_*`,
proxy settings) can be expressed. Everything else — the workspace, `--unshare-net`, the
attempt's proxy and allowlist, its leased credentials, its holds, its action channel, its
cgroup limits, the empty environment of ADR-0033 §7 — is built from the manifest exactly
as for any workload, whichever adapter runs.

### 4. The provider is a name the operator's credentials file answers, or nothing

An adapter's provider (`anthropic` for Claude Code, `openai` for Codex) is metadata on the
node: the node never reads a model key from its own environment and sets no base URL or
placeholder (amended by ADR-0037 §4: on a node with a `ward-agent` shim, the base URL on the
attempt's relay and a placeholder, only for a provider the manifest grants). A runtime reaches its model API only through a manifest `credentials` grant
for a service the operator configured (ADR-0034) — by convention named after the
provider, `[service.anthropic]` with `upstream = "api.anthropic.com:443"` and
`header = "x-api-key"` — at `/<service>/…` on `WARD_PROXY_SOCKET`, with the lease injected
by the attempt's proxy, held when the manifest holds it (ADR-0035). The grant is the
manifest's, so it is the same for every adapter: a Codex attempt under a manifest granting
`anthropic` can use that route too, and an adapter naming a provider gains no route the
manifest does not grant.

### 5. Hooks become claims; a hookless adapter just has less to say

For an adapter whose capability document declares semantic events (Claude Code), the
attempt gets a hook socket in its adapter directory, bound at `/run/ward/hooks.sock` and
named by `WARD_SOCKET`, speaking ADR-0033 §6's wire: one `SemanticEventLine` per
connection, read within 4 KiB and 5 seconds, at most 8 connections at once, answered with
one `ApprovalAnswer` `allow` (reason `recorded by ward-node as a claim`). Each line is
recorded in the attempt's evidence log as an `AgentClaim` with origin `agent`, spelled as a
session spells it (`PreToolUse Bash make test → allow`); at most 256 per attempt, the rest
and any that could not be appended counted in one `ObservationsDropped` (source `hook`)
before the end record. A line outside the contract is answered with nothing and recorded
nowhere. The socket closes when the attempt ends and the directory is removed. A hookless
adapter (Codex, the generic adapter) gets no socket at all.

The answer is steering: nothing the node enforces reads a claim, so an agent that claims
an approval, or is answered `allow`, gains nothing the sandbox, the proxy or a hold
refuses. The approval a node enforces is the hold of ADR-0035, opened by the node on the
action channel; bridging a hook's `PermissionRequest` onto that channel is not done here.

### 6. The binding is recorded per attempt, as metadata

Right after `NodeAttemptLaunched` the node appends ADR-0033 §5's binding,
`AgentClaim { Note }` with origin `agent` and payload
`{"agent_adapter":{contract, adapter, runtime, hooks, events, provider, model}}` (the model
from `--model`/`-m` for the first-party adapters, none for the generic one; the generic
adapter's runtime is named after the program's file name). It is part of the launch's
evidence: a launch whose binding cannot be recorded is killed and ends `unknown`, as one
whose launch record cannot be. The node's evidence log now accepts origin `agent` for
`AgentClaim` records only; every other record must still have origin `node`, so a claim can
never be read as an enforcement fact and nothing else can pretend to be a claim.

## Alternatives

* **The adapter in the capability manifest.** One field among the grants, but then two
  adapters never run "the same manifest", and an adapter would sit in the object that
  decides authority while deciding none. Rejected.
* **The node seeds the provider's base URL and a placeholder key, as a session does.**
  The node has no in-sandbox loopback relay yet (node-integration.md §9), and a URL a
  runtime cannot dial is a promise the node cannot keep. Deferred with the relay.
* **Bind the `ward-agent` shim so Claude Code's seeded hook command runs.** It brings the
  relay and Landlock with it and needs its own operator input (where the shim is) and its
  own acceptance. Deferred; until then a real Claude Code's command hooks find no shim, and
  only a runtime that writes the contract's lines itself reaches the socket.
* **Bridge hook approvals onto the action channel.** It would make a hook answer wait for a
  control plane while the node already has an enforced approval, the hold. Deferred.
* **A new `NodeAgentClaim` record kind.** The catalogue is protected and pinned by count;
  `AgentClaim` with origin `agent` already has the right trust class.

## Advantages

* The node runs Claude Code, Codex or any program as an adapter under exactly the authority
  its signed manifest grants, and the conformance suite proves it record for record.
* One launch builder for sessions and nodes: a runtime is launched the same way on both.
* A control plane learns from evidence which runtime and model ran, in a record class that
  cannot be mistaken for authority.

## Disadvantages

* A real Claude Code on a node has its settings but no hook client (no shim) and no model
  route it can dial (no relay): this slice proves the enforcement and the wire with fake
  runtimes, not a real model session.
* The node's evidence log is no longer single-origin; readers that assumed `node` only
  must accept agent claims.

## Security consequences

* Nothing an adapter declares reaches the sandbox's authority: the conformance suite runs
  one hostile probe under one signed manifest through Claude Code, Codex and the generic
  adapter on the real node and requires identical refusals (a host secret, the node's
  state, its own evidence log and leases, writes outside the workspace and into `/usr`, the
  proxy for an unlisted host, a provider's API and a private address, direct egress, DNS),
  identical enforcement records, the node's model keys never in the sandbox or the log,
  nothing in PID 1's environment, and the upstream seeing only the leased credential.
* New surface: one Unix socket per hooked attempt, bounded in lines, bytes, time,
  connections and records, beside the workspace where the workload cannot write; and the
  adapter's settings files, which are the catalogue's, never the envelope's.
* A forged approval — a claim answered `allow`, or a hookless agent's line to a socket that
  does not exist — is refused by the proxy and recorded the same way for both.

## Performance consequences

One settings write and, for a hooked adapter, one listener thread per attempt; one fsynced
append per claim, at most 256. Nothing for a workload naming no adapter.

## Compatibility

Additive within 1.3: a node without `--agent-adapter` answers exactly as before and refuses
a workload naming an adapter `unsupported_grant`; an earlier 1.3 node fails to decode such
an envelope (`authority_denied`); a strict decoder of an earlier 1.3 revision refuses a
capability document carrying `adapters`, so enable the flag once every control plane reads
it (compatibility.md §4). `ward-node`'s inputs change (`ward-agent-adapter` joins its
closure and `ward-node-protocol` changes), so the next release must raise the node version
(CONTRIBUTING.md, #275).

## Why selected

It reaches #279's acceptance on the node with the smallest change that keeps authority a
property of the manifest and the launch path: one optional field, one operator flag, the
shared launch builder, and records the catalogue already has.

## How it will be validated

* `ward-agent-adapter`: the first-party launches wire exactly their documents' hooks, a
  launch by id is the document, spec, command and binding, and fails closed.
* `ward-node-protocol`: the workload field's grammar and spelling, the `adapters` section,
  and that neither appears below 1.3.
* `ward-node`: hosting and refusal (`adapters`), the hook socket's bounds and answers, the
  launch arguments an adapter adds and nothing else (`execution`), agent-origin claims as
  the only non-node records (`evidence`), and `tests/node_adapter_conformance.rs` against
  the real binary as in Security consequences, with a forged approval and the refusals of
  an unhosted adapter.
* `ward-daemon`: the shared first-party launches equal the session's profiles.
* The Node.js reference client's `run --agent-adapter`, by `node --test` and by three cases
  of `scripts/acceptance/node-js.sh` against the shipped node.

## What remains

* Bind the `ward-agent` shim into node attempts for Claude Code's command hooks and an
  in-sandbox loopback relay, so a real runtime reaches its provider route. Done by
  ADR-0037 (`--agent-shim`).
* Bridge a hook's `PermissionRequest` onto the action channel, or say why the hold is
  enough. ADR-0037 §5 says why the hold is enough.
* `ward-node-client` (Rust) and `ward-node-adapter` building an envelope with an adapter
  (both carry one a control plane signed, byte for byte, today).
* A real-runtime conformance run in CI, as ADR-0033 §8.
