# ADR-0037 — A real agent runtime on ward-node: the operator's `ward-agent` shim and a loopback relay in hosted-adapter attempts

Status: **Proposed; third slice of [#279](https://github.com/hexrift/WardOS/issues/279),
implemented under [#424](https://github.com/hexrift/WardOS/issues/424).** It amends
[ADR-0036](ADR-0036-node-hosted-agent-adapters.md) §4 ("sets no base URL or placeholder")
and settles two items of its "What remains"; it changes neither the adapter contract, the
node protocol nor the event catalogue.

## Context

ADR-0036 made a `ward-node` attempt host an agent adapter, but a real runtime still cannot
run a model session in one. Claude Code's seeded settings run every hook as the command
`/run/ward/ward-agent hook`, and a node attempt binds no `ward-agent` shim, so the hooks
find nothing to run. A runtime takes its model API as an HTTP base URL
(`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`), and a node attempt's only way out is the
attempt's egress proxy on a Unix socket (`WARD_PROXY_SOCKET`, ADR-0034's `/<service>/…`
routes), which no HTTP client dials. The per-session runtime solved both long ago: the
daemon binds the shim, which hardens the sandbox (ADR-0003) and relays a loopback port to
the session proxy's socket (ADR-0014), and sets the provider's base URL on that relay with a
placeholder key the proxy replaces (ADR-0008). ADR-0036 deferred both for the node because
each needs an operator input, its own security argument and its own acceptance.

## Decision

### 1. The shim is the operator's, named and verified

`ward-node --agent-shim <file>` (it needs `--agent-adapter`) names the shim. At start the
node refuses to serve unless the path is absolute and names a regular file (not a symlink),
executable, owned by root or the node's user and writable by no one else, that answers
`--help` with its `--relay` flag and that once runs `/bin/true` hardened over the task root
(`--rw <task-root> -- /bin/true`): a kernel on which the shim cannot apply Landlock and
seccomp stops the node instead of failing every attempt. The node never looks for a shim
beside its own binary or on any `PATH`, and nothing in the envelope or the workspace names
one. The shim ships in the runtime tarball and in the image (`/usr/bin/ward-agent`); the node
tarball does not carry it (§What remains).

### 2. Every hosted adapter's attempt runs under it, and nothing else does

On such a node an attempt whose workload names an adapter binds the file read-only at
`/run/ward/ward-agent` and runs it ahead of the adapter's command line, as a session runs
it: Landlock (read-write `/work`, `/env`, `/tmp` and the sandbox home; read-only `/usr`,
`/bin`, `/sbin`, `/lib`, `/lib64`, `/opt`, `/etc`, `/proc` and the shim itself, so a command
hook can execute it), the baseline seccomp filter, `no_new_privs` and an empty capability
set, then the adapter's program with only the variables the node names. Claude Code's
`/run/ward/ward-agent hook` then reaches the attempt's hook socket, and its lines are
recorded as agent-origin claims exactly as ADR-0036 §5 says. The workload cannot replace
the shim: the bind is read-only, and under the ruleset nothing in `/run/ward` can be
created, renamed or removed. A workload that names no adapter, and every attempt on a node
without the flag, runs exactly as before.

### 3. The relay is the shim's, on loopback, in front of the attempt's proxy

When the attempt has an egress proxy (`network.custom`), the shim also relays
`127.0.0.1:3128` to the proxy's socket (`--relay 127.0.0.1:3128=/run/ward/proxy.sock`). The
listener is inside the attempt's network namespace, which holds only loopback, so nothing
outside the attempt reaches it, and it copies bytes to a socket the workload could already
dial: every verdict — the allowlist, the structural denies, a route's scope and lease, a
hold, a pause — is still the proxy's, and recorded the same way. The relay runs under the
shim's Landlock domain and seccomp filter like the runtime. The node sets `HTTP_PROXY`,
`HTTPS_PROXY` (both cases) to `http://127.0.0.1:3128` and `NO_PROXY` to
`localhost,127.0.0.1`, as a session does. An offline attempt gets no relay and none of these
variables.

### 4. A provider base URL only for a provider the manifest grants

With the relay running, the node points the adapter's provider at it only when the attempt
has the credential route of the service named after that provider — that is, the signed
manifest grants `credentials` for it (ADR-0036 §4's convention): Claude Code gets
`ANTHROPIC_BASE_URL=http://127.0.0.1:3128/anthropic`, Codex
`OPENAI_BASE_URL=http://127.0.0.1:3128/openai/v1`, and each its key variable set to the
placeholder `ward-gateway`, the session's spelling (both now read from one place,
`ward_agent_adapter::catalogue::{ANTHROPIC, OPENAI}`). The placeholder is not a credential:
the route sets its configured header to the leased value. Without that grant neither
variable is set, and a request for `/<provider>/…` on the relay is the proxy's `400`, not
a route. Because a model API is a `POST`, the operator's service needs `write` among its
`permissions` and the API path among its `paths` (for example `/v1/messages`); the same
service still forwards only to its configured upstream, within its lease.

### 5. A hook's `PermissionRequest` is not bridged: the hold is the approval

A `PermissionRequest` line is answered `allow` and recorded as a claim, like every hook line.
Bridging it onto the action channel was the larger option and is not taken:

* what a node enforces is reached only through the proxy, and ADR-0035's hold covers each
  host and credential there, whatever the runtime asked itself — an action that matters
  waits for the control plane with or without hooks;
* a bridged request would be worded by the agent, and ADR-0035 §3 rejected releasing a
  capability on workload text;
* a tool that acts only inside the sandbox is already bounded by the manifest;
* a bridged answer would hold a hook connection open for minutes against the hook socket's
  5-second read deadline, making the runtime's own prompt the gate instead of the node's.

### 6. Nothing new on the wire or in the log

The flag adds no capability field, protocol revision or record kind: the binding claim, the
hook claims and the proxy's verdicts already say what ran and what passed. A control plane
learns whether a node relays from its operator, or from the attempt's outcome (§What
remains).

## Alternatives

* **The shim beside the node binary, as `wardd` finds it.** A file that happens to sit next
  to the binary would become code run in every adapter's sandbox without the operator
  naming it, and that holds now that the node tarball carries the shim (#427) as much as
  when it did not. Rejected for an explicit, verified flag.
* **A relay in the node process.** A listener on the host is unreachable from a namespace
  that holds only loopback; the node would have to enter each attempt's namespace. Rejected.
* **A relay of the node's own inside the sandbox.** It would duplicate the shim's, and the
  hooks need the shim anyway. Rejected.
* **A base URL for every attempt with a proxy.** A URL to a route the manifest does not
  grant is a promise the node cannot keep. Rejected (§4).
* **Every attempt under the shim.** It would change plain workloads (Landlock, seccomp,
  dropped capabilities) without anything asking for it. Deferred.
* **Bridge `PermissionRequest`.** See §5.

## Advantages

* A runtime that behaves like Claude Code completes a model round trip on a node — base URL
  from its environment, HTTP to it, the credential injected by the node's broker — and its
  command hooks become agent-origin claims, with the same code path a session uses.
* Hosted adapters gain the inner hardening of ADR-0003 on top of the node's sandbox.
* One definition of each provider's base URL, path and key variable for sessions and nodes.

## Disadvantages

* The shim is a second binary the operator installs and keeps at the release's version; the
  node checks that it relays and hardens, not which release built it.
* The runtime sees a placeholder key and a base URL; a runtime that sends the placeholder
  in a header other than the service's configured one forwards it upstream (it is not a
  secret, but it is noise).
* The node does not say in its capability document that it relays.

## Security consequences

* No new authority: the relay is a pipe to the attempt's proxy, the base URL names a route
  the manifest already grants, and the placeholder is not a credential.
  `crates/ward-node/tests/node_agent_relay_cli.rs` runs the real node with the real shim
  and proves a model round trip with the lease injected and never visible to the runtime,
  `CONNECT` and absolute-form requests for an unlisted host refused `403` through the
  relay, no base URL and no route without a grant for the runtime's provider (also for a
  runtime of another provider), a held credential refused until the control plane's
  approval of the node's request, the shim unchanged by a workload that tries to write,
  create beside, rename, remove or `chmod` it, and none of the node's environment in the
  sandbox (PID 1's environment is not even readable under the shim).
* New surface: the operator's shim, run by the node twice at start as the node's user
  (`--help` and the hardened probe) and in every hosted adapter's sandbox; the node trusts
  it as it trusts its own binary, which is why only root or the node's user may own it and
  no one else may write it. One loopback TCP port per relayed attempt, inside its namespace.
* Stronger confinement for hosted adapters: Landlock, seccomp and no capabilities inside the
  bubblewrap sandbox.

## Performance consequences

Two short runs of the shim at start; per hosted-adapter attempt one more exec and the
shim's ruleset and filter; per relayed connection two copying threads in the sandbox.
Nothing for a node without the flag or a workload naming no adapter.

## Compatibility

Additive and operator-enabled: a node without `--agent-shim` is byte for byte what it was,
and nothing a control plane sends or reads changes. `ward-node`'s inputs change (`ward-node`
and `ward-agent-adapter`), so the next release must raise the node version (CONTRIBUTING.md,
#275).

## How it is validated

* `ward-agent-adapter`: every first-party provider has an endpoint outside the reserved
  variables.
* `ward-node` unit tests: the shim's refusals before it runs (relative, missing, a symlink,
  a directory, group- or other-writable, not executable, not a shim), the base URL only for the route of the adapter's provider, the launch under the shim with
  the relay only behind a proxy and a plain workload unchanged, and the flag's parsing.
* `crates/ward-node/tests/node_agent_relay_cli.rs` against the real `ward-node` and
  `ward-agent` binaries, as in Security consequences, and the node's refusal to start with a
  shim it cannot verify.
* `ward-daemon`: the gateway tests, unchanged, over the shared provider endpoints.
* `ward-launch` unit tests: the read-only set, `ward_launch::SHIM_READ_ONLY`, passed to every
  shim a launch binds, a session's as well as a node's (#426).

## What remains

* Ship the shim in the node tarball (it would join the node train's inputs, #275). Done by
  #427: the node tarball carries `ward-agent`, `node-version.sh` counts it among the
  node's inputs, and node-integration-guide.md §1 installs it.
* Say in the capability document that hosted adapters run under a shim with a relay.
* A real-runtime conformance run in CI (ADR-0033 §8).
* A `node-js.sh` case of the shipped node with a shim.
