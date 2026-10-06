# ADR-0037 — A real agent runtime on ward-node: the operator's `ward-agent` shim and a loopback relay in hosted-adapter attempts

Status: **Proposed; third slice of [#279](https://github.com/hexrift/WardOS/issues/279),
implemented under [#424](https://github.com/hexrift/WardOS/issues/424); amended for plain
workloads under [#267](https://github.com/hexrift/WardOS/issues/267) (§7).** It amends
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

`ward-node --agent-shim <file>` (it needs `--agent-adapter`, or since §7
`--network-allowlist`) names the shim. At start the
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
without the flag, runs exactly as before (amended by §7: a workload naming no adapter that
has an egress proxy runs under the shim for its relay).

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

### 7. Amendment (#267): the relay for a plain workload behind an egress proxy

**Context.** A workload naming no adapter reaches its proxy only through
`WARD_PROXY_SOCKET`, a Unix socket that `git`, `curl`, package managers and every other
stock HTTP client cannot dial, so a brokered credential (ADR-0034) was usable only by a
workload that speaks HTTP over a Unix socket itself. ADR-0034's acceptance — a task
receives a short-lived Git, cloud or database capability, uses it, has it revoked and fails
on a later attempt — needs the stock client.

**Decision.** On a node started with `--agent-shim`, every attempt with an egress proxy
runs under the shim, whether or not it names an adapter, exactly as §2 and §3 run a hosted
adapter's: the shim bound read-only at `/run/ward/ward-agent`, its Landlock ruleset,
seccomp filter, `no_new_privs` and empty capability set, its relay of `127.0.0.1:3128` to
`/run/ward/proxy.sock`, and `HTTP_PROXY`, `HTTPS_PROXY` (both cases) and `NO_PROXY`
(`localhost,127.0.0.1`) naming it. A plain workload gets no base URL and no placeholder:
§4 is the adapter's provider's alone. `--agent-shim` therefore needs `--agent-adapter` or
`--network-allowlist`; with neither the shim would have nothing to run and the node still
refuses to start. Unchanged: an offline attempt naming no adapter (nothing to relay, no
hooks) and every attempt on a node without the flag, byte for byte.

**How a stock client uses a credential.** A credential route is a path prefix on the proxy
(ADR-0034 §3), so through the relay it is the URL `http://127.0.0.1:3128/<service>/…`. A
Git workload clones `http://127.0.0.1:3128/<service>/<repo>.git`: `NO_PROXY` sends that
straight to the relay as an origin-form request, the proxy matches the route, strips the
prefix, sets the service's configured header to its value prefix and the leased value
(for Git over smart HTTP, `authorization` with `Bearer `), and forwards it over TLS to the
service's upstream within the service's paths, read-only unless the service grants
`write` (a push, `POST …/git-receive-pack`, needs it). The workload never holds a
credential: no variable, no `.git-credentials`, no `http.extraHeader`, no credential
helper; the remote URL it keeps in `.git/config` names the relay and nothing else. Any
other host goes through `HTTP_PROXY` to the allowlist as before, a `CONNECT` tunnel never
injected into.

**Alternatives.**

* *A node-owned relay without the shim.* The node cannot listen inside the attempt's
  namespace from the host (§Alternatives), so it would need a program of its own in every
  sandbox: a second, unhardened copy of the shim's relay. Rejected.
* *A shim mode that relays without hardening.* A new `ward-agent` flag and a relay outside
  the Landlock domain and seccomp filter the relay now runs under, for a weaker sandbox
  than a hosted adapter gets. Rejected.
* *Every attempt under the shim, offline ones included.* An offline plain workload has
  nothing for the shim to do; hardening it is a separate decision with its own
  compatibility cost. Deferred, as §Alternatives deferred it.
* *A per-attempt opt-in in the manifest.* The envelope would name what the node runs in
  its sandbox, which §1 keeps the operator's. Rejected; the operator's flag decides.

**Security consequences.** No new authority: the relay is the same pipe to the socket the
workload already has, every allow, refuse, inject and hold decision is still the proxy's
and recorded as before, a credential is still injected only on its route to its configured
upstream, and nothing about a credential enters the sandbox. A plain workload behind a
proxy on such a node gains the shim's confinement (writable only under `/work`, `/env`,
`/tmp` and `/home/agent`; seccomp; no capabilities). One loopback port per relayed attempt,
inside its namespace.

**Compatibility.** Operator-enabled and additive for control planes; a node without
`--agent-shim` is unchanged. On a node with it, a plain workload behind a proxy now runs
under Landlock and seccomp: one that writes outside the four writable trees, or makes a
call the baseline filter refuses, fails where it ran before. `ward-node`'s own code changes
(no new crate, no protocol or catalogue change), so the next release raises the node
version (CONTRIBUTING.md, #275).

**Validation.** `ward-node` unit tests (a plain launch behind a proxy under the shim with
the relay and the proxy variables and no base URL, an offline plain launch unchanged, the
flag's parsing) and `crates/ward-node/tests/node_git_capability_cli.rs`, against the real
`ward-node` and `ward-agent` binaries, a fake OpenBao and a `git http-backend` server that
serves only a live leased token: the stock `git` clones and pushes through the relay with
the lease injected; the token is in no byte of the sandbox's workspace and environment, the
evidence log, the state or any node answer; the lease is revoked at the provider when the
attempt ends; the next attempt of the task, whose fresh grant the provider refuses, fails
to clone with the proxy's `403 credential lease expired`, and the revoked token is refused
upstream; a sealed provider fails the clone closed the same way with
`credential-provider:bao:sealed` recorded; a host outside the allowlist is refused `403`
through the relay; a node without the shim and an offline attempt on a node with one run
without relay, proxy variables or seccomp.

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
  dropped capabilities) without anything asking for it. Deferred; §7 takes it for the
  attempts with an egress proxy, which need the relay.
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
* A relay for plain workloads. Done by §7 (#267) for attempts with an egress proxy on a
  node with the shim; an offline plain workload still runs without the shim.
