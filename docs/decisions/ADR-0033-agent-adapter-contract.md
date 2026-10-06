# ADR-0033 — Agent adapters: one versioned contract, host enforcement for every runtime

Status: **Proposed.** The first slice of
[#279](https://github.com/hexrift/WardOS/issues/279) implements §1–§7 for local
sessions; §8 is what remains. It builds on
[ADR-0011](ADR-0011-event-capture.md) (hooks are claims) and
[ADR-0023](ADR-0023-ward-studio-and-agent-runtime.md) (providers are replaceable brains)
without changing either.

## Context

`ward claude` and `ward codex` were two hand-written launch profiles
(`ward_daemon::agents`). The `ward-agent-adapter` crate (#296) described an adapter's
integration features and semantic visibility, but nothing used it, and there was no way
to run any other agent through the session's launch path, no versioned shape for what
an agent may send the host, and no record of which agent a launch ran. #279 asks for a
stable adapter interface for Claude, Codex, Copilot, `OpenCode` and custom agents whose
missing hooks lower semantic visibility but cannot weaken sandbox, network or credential
enforcement, with the model and runtime recorded as metadata, never as identity or
authority.

## Decision

### 1. One contract, versioned `major.minor`

The contract lives in `ward-agent-adapter` and is version 1.0
(`ContractVersion::CURRENT`). A reader accepts its own major and a minor no newer than
its own; anything else fails closed, because a newer minor may carry claims the reader
cannot check. The existing descriptor types and their invariants are kept unchanged;
the contract adds to them.

### 2. A capability-discovery document per adapter

`CapabilityDocument` = contract version + the existing `AgentAdapterDescriptor` (id,
runtime metadata, semantic visibility, features) + `hooks` (`full`, `partial`, `none`)
+ the semantic events the adapter emits (`SessionStart`, `PreToolUse`, `PostToolUse`,
`PermissionRequest`, `Stop`, spelled as on the hook socket). The document is
self-consistent or refused: `hooks` must match the events, `semantic_tool_events` must
match a tool event, `approval_requests` needs a decision point (`PreToolUse` or
`PermissionRequest`), and every adapter must claim `launch` — an agent the host does
not launch is an agent it does not contain. Unknown fields (`network`, `credentials`,
`sandbox`, …) fail decoding: no field of the document can express authority.
`coverage()` reports which claimed features the host serves; `capability_requests`,
cooperative `cancellation` and `structured_task_result` have contract shapes but no host
path yet and are reported as unserved rather than pretended.

### 3. The launch half is data, and cannot widen the launch

`LaunchSpec` is everything an adapter may ask of a launch: a program (a name on the
sandbox `PATH` or an absolute path), fixed arguments, non-secret environment, settings
files under the sandbox home (`/home/agent`), and the provider whose model-API gateway
it talks to. The working directory is always `/work`. A variable the host owns (the
proxy settings in any case, `HOME`, `PATH`, `TERM`, `WARD_*`) is refused, as is a
settings path outside the sandbox home. Mounts, network rules, credentials and grants
are not in the type: the host builds them from the session's capability manifest.

### 4. One launch path for every adapter

`Session::adapter_launch` turns any adapter into a launch; `agent_launch` (`ward claude`,
`ward codex`) and the new `ward agent` (the generic process adapter, hooks `none`) all
go through it and then `Session::launch`. The sandbox, the egress proxy and its
allowlist, the credential broker and the evidence log are built there from the manifest
and the user's `--grant`/`--pass-env`, exactly as before, for every adapter. The adapter
contributes its command, configuration, settings files and provider route; a hook it
lacks lowers what the observer sees and nothing else. The first-party documents are
Claude Code (hooks `full`, approvals) and Codex (hooks `none`); the declared versions
are the image's pins, checked by a test against `image/agents/package.json`.

### 5. The binding is recorded as a claim

Each adapter launch records, right after its `CommandStarted`, one
`AgentClaim { Note }` with `Origin::Agent` whose payload is
`{"agent_adapter":{contract, adapter, runtime, hooks, events, provider, model}}`. The
runtime is what the adapter declares, the model is what the command line requests
(`--model`/`-m` for the first-party runtimes; none for the generic adapter), and neither
is verified. Recording it as an agent-origin claim puts it in the one record class that
can never be an enforcement fact (`Origin::is_enforcement_fact`). No new event kind is
added: the catalogue is append-only and pinned by its tests, and a claim already has the
right trust class.

### 6. The run-time wire is the hook socket's

`SemanticEventLine` (`{"hook","tool","summary"}`) and `ApprovalAnswer`
(`{"decision","reason"}`) are exactly what `ward-agent hook` exchanges with the
session's hook socket, now typed and bounded: a custom agent that writes those lines
gets the same claims and the same approval holds as Claude Code. A line is a claim; an
answer is steering the agent may ignore. `CancelRequest` is always carried out by the
host (freeze, kill, confirm gone); `TaskResult`'s outcome is the host's, from the exit
status, and a structured result could only ever be attached as a claim.

### 7. Sessions start from an empty environment

The conformance suite found that every session launch inherited the launching `ward`
process's whole environment: bubblewrap ran without `--clearenv`, so tokens and keys in
the user's shell (`GITHUB_TOKEN`, cloud keys) were readable in the sandbox — directly
when no shim filtered them, and through the shim's or bubblewrap's own
`/proc/<pid>/environ` otherwise, since `--clearenv` empties only the sandboxed program's
environment, never that of bubblewrap's init. A session launch now starts from an empty
environment, bubblewrap itself included (`Launch::clear_env` spawns bwrap with none),
forwarding only `LANG`, `LC_ALL`, `USER` and `SHELL` by name. This is part of the
contract's promise: credential enforcement may not depend on the in-sandbox shim, which
is untrusted after start.

## Alternatives

* **A new `AgentAdapterBound` event kind.** Typed and filterable, but the catalogue is
  append-only with its count pinned by its own tests, and a Wardd-origin record would
  read as an enforcement fact. Kept for a later minor if replay needs to filter on it.
* **Adapter-specific launch code per runtime** (the status quo). Every new agent would
  be a new path through the sandbox setup, and equivalence would be a review promise
  instead of a construction.
* **Let an adapter carry its own network or credential needs.** It would make the
  adapter an authority source; the manifest and the user's grants stay the only ones.
  The provider route is the one adapter-declared need, and it is a proxy-injected
  gateway to that provider's API only, recorded as `CredentialGranted`.

## Advantages

* Any agent binary runs under exactly the enforcement Claude Code and Codex get, today,
  with `ward agent`.
* What an adapter can report is declared, checked and discoverable (`ward adapters`).
* Evidence says which runtime and model a launch ran, in a record class that cannot be
  mistaken for authority.

## Disadvantages

* The binding is a JSON note inside a claim, rendered as such by the observer, not a
  typed event.
* Three contract features have shapes but no host path yet.
* Inheriting nothing from the host environment can surprise an agent that relied on a
  host variable; `--pass-env NAME` remains the explicit, printed way in.

## Security consequences

Enforcement no longer depends on which adapter runs or on the shim: the conformance
suite runs the same hostile probe through Claude Code, Codex and the generic adapter
and requires identical refusals (host secret, host vault, host home, writes outside the
workspace, the proxy for an unlisted host, another provider's API and a private
address, direct egress, DNS) and identical enforcement records, with no host variable
and no key in the sandbox, and nothing in the environment of the sandbox's PID 1. A
hookless agent that forges hook lines gets claims recorded and nothing else. The
environment fix also changes `ward-node`'s launches, which already asked for a cleared
environment and now get one in bubblewrap's init as well.

## Performance consequences

None measurable: one extra record per launch, and a `PATH` lookup for bwrap when the
environment is cleared.

## Why selected

It makes enforcement equivalence a property of the code path (one launch function, no
adapter input that can widen it) and of a test, rather than of each adapter's
implementation, while keeping the existing contract crate and event catalogue intact.

## How it will be validated

* `crates/ward-agent-adapter`: the contract's invariants and wire shapes, fail-closed on
  unknown versions, fields and inconsistent claims.
* `crates/ward-daemon/src/adapters.rs`: the documents match what the launches wire, and
  the versions match the image pins.
* `crates/ward-daemon/tests/adapter_conformance.rs`: the enforcement-equivalence suite
  above, against fake runtimes (no real Claude Code or Codex can run a task here).
* `crates/ward-launch`: a cleared launch leaves nothing in `/proc/1/environ`.

## 8. What remains

* Hosting adapters on `ward-node`: decided by [ADR-0036](ADR-0036-node-hosted-agent-adapters.md)
  (the workload names an adapter, the node launches it through this contract and records
  its hook lines as claims), which proves the acceptance "two runtimes execute the same
  Ward task manifest with equivalent node-enforced authority" for the node as well.
* Serving capability requests, cooperative cancellation and structured task results.
* Loading a custom adapter's document and launch spec from a file
  (`ward agent --adapter <file>`), and first-party documents for Copilot, `OpenCode` and
  Gemini once the project tests them; until then they run as the generic adapter.
* A real-runtime conformance run in CI (needs keys or a recorded model API).
* The verifier and `ward prepare` launches still inherit the host environment.
