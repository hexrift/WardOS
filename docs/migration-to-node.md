# Migrating from per-session WardOS to node mode

Status: living document. It states, for the revision on `main`, how the per-session
runtime (`ward up`, one `wardd` per session) and node mode (`ward-node`, a long-lived
service driven by an external control plane) relate: what each runs, where they are
equivalent and where they are not, how they coexist on one host today, the staged path
from one to the other with the exit criterion and the issue for each stage, and the
compatibility statement a user or operator can hold the project to (#278). The target
architecture is [ADR-0029](decisions/ADR-0029-product-split-fleet-trust-boundaries.md),
whose migration map this document makes concrete; the node's contract is
[node-integration.md](node-integration.md) and what it does not do yet is
[node-security-limitations.md](node-security-limitations.md).

Two things this document does not do. It does not promise dates: stages 2 to 4 below are
not scheduled, and where no issue exists it says so. And it converts no data: the two
modes keep separate state and neither rewrites the other's. The one migration there is,
`ward node migrate` ([ADR-0040](decisions/ADR-0040-local-node-mode-migration.md), §3.5),
carries an installation into a local node of its own by importing its retained snapshots
and recording its evidence and policy where they are, never by converting them.

## 1. The two modes, side by side

| | Per-session mode | Node mode |
| --- | --- | --- |
| What starts it | `ward up` in a project directory (or `ward claude`, `ward codex`, `ward run`) | The operator starts `ward-node --socket … --state-dir … --node-id … --trusted-issuers … --task-root …` as a service of the host (node-integration.md §2.1, node-integration-guide.md §3); on an installation `ward node migrate` moved into local node mode, `ward node serve` starts it on the node home's paths (ADR-0040) |
| What runs | One `wardd serve` per session, spawned detached by `ward up`, owning the session's hash chain and control socket ([ADR-0015](decisions/ADR-0015-single-writer-daemon.md)); the bubblewrap sandbox, the egress proxy and the hook listener in the `ward` process that launched them (ADR-0013); the trusted verifier on `ward verify` | One `ward-node` process for the host, serving a Unix socket on protocol 1.0 to 1.3 ([compatibility.md](compatibility.md)); one bubblewrap sandbox per admitted attempt, spawned and reaped by the node through `ward-launch` ([ADR-0030](decisions/ADR-0030-node-task-admission-and-execution-ownership.md) §3) |
| Unit of work | A session: a project worktree, an agent, a policy, from `ward up` to `ward stop` | A task attempt: an argv over an imported snapshot with a wall-clock budget, from `admit` to `seal` |
| Who owns authority | The local user, through policy: `.ward/policy.yaml` merged with the user and system policy into a capability manifest that only narrows (security-model.md G7) | An external control plane, through an issuer key the node's operator put in the trust store; the node admits only a signed, audience-bound, versioned envelope and verifies it before anything is materialised (ADR-0030 §2) |
| Network | The session proxy: the manifest's host allowlist, private ranges denied, credentials injected, a loopback relay for `HTTP_PROXY` clients | Offline by default; with `--network-allowlist` a `network.custom` manifest runs behind a per-attempt proxy with the session proxy's rules, reached through its Unix socket, and on a node started with the operator's `ward-agent` shim (`--agent-shim`) through its loopback relay with `HTTP_PROXY` naming it, and credentials only on the routes of `--credentials` services (node-integration.md §6.8, §9); any other grant is refused `unsupported_grant` at `admit` (§7.5) |
| Credentials | The vault (`ward vault`) and proxy injection; brokered credentials the policy marks `ask` are approved per session | With `--credentials`, leases from the operator's providers for the services a signed manifest grants, injected by the attempt's proxy and revoked when it ends (node-integration.md §6.8); nothing else reaches a workload (node-security-limitations.md §3.2) |
| Approvals | Held by the daemon, answered by the user or the desktop (`agent-integration.md` §4.1) | With `--action-channel` a workload asks the control plane through its attempt's channel and receives a recorded answer (node-integration.md §6.7); with `--approval-hold` as well, a manifest's `hold` makes the node refuse a held host or credential until the control plane approves the request the node opened for it (§6.9); nothing else is held (node-security-limitations.md §3.2) |
| Intervention | `ward pause`, `ward resume`, `ward stop`, `ward stop --restore-entry` ([ADR-0019](decisions/ADR-0019-authority-freshness-intervention.md) §3) | `pause`, `resume`, `stop`, `revoke` over the socket, each confirmed before it is answered (node-integration.md §6) |
| Evidence | One session log, `~/.local/state/ward/sessions/<id>/events.log`, written only by that session's `wardd`, sealed with `HEAD` by `ward stop` | One evidence log per attempt, `<task-root>/<task>/<attempt>.evidence/events.log`, written only by the node, sealed with `HEAD` by `seal` (node-integration.md §6.5) |
| Result | The worktree, the session log, the verifier's verdict | A receipt (`completed`, `failed`, `unknown`) on `inspect`; on a node started with `--output-return`, the bounded output the manifest asked for (the head of stdout and stderr, declared workspace files with digests) on `result` (node-integration.md §6.6); the rest of the workspace stays on the host |
| Who reads it | `ward replay`, `ward watch`, the desktop's trust bar and panels, TamperWard over the control socket | `ward replay --verify` on the host as the node's uid; the control plane through `inspect` and the adapter's attempt report |
| Identity on the host | The login user; everything under `~/.local/state/ward` | A system user of its own (`ward-node` in the guide), with state, task root and socket directory nothing else can read |
| Where it is installed from | The runtime tarball `wardos-<version>-<arch>-linux.tar.gz`, `install.sh`, or the image | The node tarball `ward-node-<node version>-<arch>-linux.tar.gz` (the node train's own version, compatibility.md §6), installed by the operator; present in the image but not started there (node-release-readiness.md §2) |

### 1.1 Equivalents

| Per-session | Node mode | Note |
| --- | --- | --- |
| A session | A task attempt | A session may launch many commands; an attempt runs one argv and ends. A retry is a new attempt under a new envelope, never a re-run (ADR-0030 §6) |
| `ward up` | `create`, then `admit`, then `start` | `ward up` also records the project's current session and takes the entry snapshot; the node materialises a snapshot the operator imported beforehand with `ward-node snapshot import` |
| `ward run` | `ward run --via-node` | In local node mode (ADR-0040 §3): one attempt over a fresh or a migrated snapshot, signed by the local issuer, `create` to `seal`, the project's policy compiled into the manifest or refused by name; the worktree is not written and nothing runs in-process |
| `ward pause` / `ward resume` | `pause` / `resume` | Both freeze the whole process tree and confirm it before answering. The session pause also closes the proxy, suspends credential grants and holds approvals (security-model.md G13); the node has none of those to hold. The node freeze is signal-only and never uses the cgroup freezer |
| `ward stop` | `stop`, then `seal` | `ward stop` terminates, confirms, records `WorkloadsTerminated`, `SessionEnded` and seals in one operation; on the node, `stop` ends the attempt with a `failed` receipt and `seal` is a separate verb |
| No counterpart | `revoke` | Revocation is durable before the kill and refuses every later `admit` or `start` under the lease, across restarts (node-integration.md §2.5). The per-session equivalent is the user's own policy change, which applies to the next session only (G7) |
| The seal at `ward stop` | `seal` | Both write `HEAD` and make the log read-only. The node also accepts `seal` from `exited` and `revoked` |
| Session log | Attempt evidence log | Same `ward-events` format (§4.1). The session log carries the agent's claims, kernel, proxy and verifier facts and the user's decisions; the attempt log carries the seven node records about admission, launch, intervention, output collection, end, recovery and seal, the proxy's verdicts as `NetworkRequested`/`NetworkDenied` with origin `node` when the attempt has egress, and never workload output itself (a returned result is recorded by its counts and digests) |
| Policy manifest (`.ward/policy.yaml` merged into a capability manifest) | Capability manifest in the envelope | The envelope's manifest uses `ward-policy`'s spelling for `network`; `offline` is honoured everywhere and `custom` on a node with `--network-allowlist`. Filesystem, exec, credential and step-through policy have no envelope field yet |
| `ward claude`, `ward codex`, `ward agent` (agent adapters, ADR-0033) | `workload.adapter` on a node started with `--agent-adapter` (ADR-0036) | Both launch through `ward-agent-adapter`'s one builder, so Claude Code and Codex get the same configuration and settings either way, under the session's or the manifest's authority. A session binds the `ward-agent` shim (hook client, relay) and a provider gateway with a placeholder key; a node binds neither yet: its hook socket hears a runtime that writes the contract's lines itself, and a model API is reached only through a manifest `credentials` grant on the proxy socket (node-integration.md §6.10). Both record the binding and hook lines as agent-origin claims |
| Entry snapshot (session CAS) | Imported snapshot (node CAS) | Both are `ward-snapshot` content-addressed stores with 64-hex ids; the stores are separate (`~/.local/state/ward/cas` and `<state-dir>/cas`) |
| `ward replay --verify` | `ward replay --verify` | The same command verifies both logs (§4.1) |
| `ward doctor` | `ward doctor` | One command. Its `ward-node` line is the only place the per-session tooling knows about a node (§2.2) |

### 1.2 What has no equivalent

- **Approvals and credentials.** The node's approval hold covers held hosts and brokered
  credentials only, and its broker takes no per-session `ask` and no project policy: on a
  node started with `--credentials` the control plane's signed manifest grants a service
  the node's operator configured, and the node's proxy injects its lease
  (node-integration.md §6.8, ADR-0034). On a node started with `--action-channel` a
  workload can ask the control plane a bounded question through its attempt's action
  channel and receives a recorded answer (node-integration.md §6.7, ADR-0031, #404); an
  approval it asks for itself is a statement it acts on, while one the node opens for a
  capability the manifest holds is a hold the node applies, on a node started with
  `--approval-hold` (§6.9, ADR-0035, #415). There is no `allow-session` remembered across
  attempts, no step-through on files or commands, and a workload that needs a token in its
  own hands cannot run under the node today
  ([#267](https://github.com/hexrift/WardOS/issues/267) for credentials, §3).
- **Network.** Node workloads are offline. There is no egress proxy on the node path and
  no issue yet for one (§3).
- **Result return.** A session leaves its worktree in place for the user. An attempt's
  workspace stays under the task root, readable only as the node's uid; what comes back
  over the protocol is the bounded result the manifest declared, on a node started with
  `--output-return` (the head of stdout and stderr, exact declared files with digests;
  node-integration.md §6.6), not a worktree or a workspace export (§3).
- **The desktop.** The trust bar, the approval inbox, the session switcher and the
  observer read session descriptions and session logs through the per-session control
  socket (`desktop.md`). None of them reads an attempt evidence log or drives a node.
- **Verification.** `ward verify` and TamperWard act on a session. The node reports what
  it did; certification is the control plane's (ADR-0029 non-goals, node-security-limitations.md §3.3).
- **The local issuer.** ADR-0030 §2 describes a local issuer key the `ward` CLI signs
  with. `ward node migrate` creates it (mode 0600, in the node home) and puts it in the
  node's trust store, and `ward run --via-node` signs with it (ADR-0040); no other `ward`
  command signs or sends anything to a node. Outside local node mode a key is made and
  used with `ward-node-client` or the adapter (node-integration.md §11), whoever runs it.

## 2. Coexistence today

Both modes can run on one host, and the image carries both. Nothing in either mode
changes the other.

### 2.1 What is shared and what is not

| | Shared | Separate |
| --- | --- | --- |
| Code | `ward-launch` (the bubblewrap launch, freeze and kill primitives; `ward-daemon` re-exports them unchanged), `ward-events` (records, chain, wire format, log reader and writer), `ward-snapshot` (content-addressed store), `ward-proxy` (the egress proxy and its policy, which the node runs once per attempt with a network allowlist) | `ward-daemon` is not a dependency of `ward-node` (ADR-0030 §3), and `ward-node-protocol` does not depend on `ward-policy`: the envelope's `network` manifest repeats `ward-policy`'s spelling and host grammar in its own types. The node has no in-sandbox relay, no vault, no hook broker and no verifier |
| Binaries | `ward` (for `ward replay`, `ward doctor`) | `wardd`, `ward-agent` on one side; `ward-node`, `ward-node-adapter` on the other |
| Format | The event log: one catalogue, one frame format, one `HEAD` (§4.1) | The origin: `node` appears only in attempt logs, never in a session log, and no session origin appears in an attempt log |
| State | Nothing | `~/.local/state/ward` (or `$WARD_STATE_DIR`) for sessions; `--state-dir` and `--task-root` (mode 0700) for the node. In local node mode those are `<state>/node/state` and `<state>/node/tasks`, inside the node home `ward node migrate` made, which no session command writes (ADR-0040 §1) |
| Snapshot store | The format | The stores. A session's entry snapshot is not visible to the node unless `ward node migrate` imported it (a copy, verified by digest), and an imported snapshot is not visible to a session |
| Sockets | Nothing | `sessions/<id>/control.sock` (0600, JSON lines, per session); the node's `--socket` (0600, or 0660 with `--client-group`; protocol 1.x framing). Neither speaks the other's protocol and neither falls back to the other (node-integration.md §4, node_readiness.rs) |
| Unix identity | Nothing, by design | The login user for sessions; a system user for the node, with listed client uids where the adapter runs as a second user (#378) |
| Policy files | Nothing is read by both | `.ward/`, `.tamperward/config.yml` and `.tamperward.yml` are read by the per-session tools only, `.ward/policy.yaml` also by `ward run --via-node` to compile the envelope it signs; the node reads its trust store, its state and its task root only |

### 2.2 `ward doctor`

`ward doctor` has one line for the node. It reads `WARD_NODE_SOCKET`, probes the socket
with a `hello` only, and prints one of `binary_absent`, `not_configured`,
`not_running`, `protocol_compatible` (with the negotiated version),
`protocol_incompatible` or `unhealthy`, each with its fix
(`crates/ward-daemon/src/node_readiness.rs`). The line is informational: it starts no
work, requests no capabilities, and an incompatible or absent node never changes what the
per-session commands do. Set the variable to the node's socket to check a node from the
host (node-integration-guide.md §3); leave it unset on a host with no node and the line
reads `not_configured`. A second line, `node mode`, names the installation's mode:
`per-session`, or `local-node` with the node and its home once `ward node migrate` has run
(ADR-0040 §2); `ward node status` re-checks what that migration carried.

### 2.3 Installing both

The runtime tarball installs `ward`, `wardd` and `ward-agent` for a user
([install.md](install.md) §1); the node tarball installs `ward-node`,
`ward-node-adapter` and the node's own `ward-agent` shim for the host's operator
(node-integration-guide.md §1). `install.sh`
never installs the node. Take both tarballs from the same release so that `ward replay`
knows every record kind the node writes (§4.1), and record the release beside the
deployment. On the WardOS image both are at `/usr/bin`, whether the image was built from
a release (the node from the release's node tarball, checksum-checked) or from a checkout
(compiled); the node is not started on the image or on reference hardware
(node-release-readiness.md §2), so an operator who wants it writes the unit of
node-integration-guide.md §3.

## 3. The migration path, in stages

Each stage names what changes for a user or operator, what stays compatible, what breaks,
how to roll back, the exit criterion, and the issue that delivers it. Stage 0 is where
`main` is. Stage 1 is the next step the shipped pieces allow. Stages 2 to 4 are not
scheduled; where a row says "no issue yet", none has been opened at this revision.

| Stage | What moves to the node | Exit criterion | Delivered by |
| --- | --- | --- | --- |
| 0 (today) | Governed tool and verification runs: an argv over a snapshot, offline, with a budget, beside per-session development on the same host | A real node is driven over its socket through `ward-node-client` and `ward-node-adapter`; the acceptance suite proves bounded execution, isolation, interruption, authorization failure, replay safety and recovery (node-acceptance.md) | #332 slices 5 to 10 (done: #354, #356, #358, #359, #361, #362, #363, #366, #367, #368, #371, #373, #374) |
| 1 | Task driving by an external control plane, as a uid of its own on the node's host, through the adapter | A control plane outside WardOS runs attempts end to end from its own identity without sharing the node's uid, reads receipts and verifies evidence logs, following the integration guide alone | The client-uid allowlist (#378, done) and node-integration-guide.md (#374, done); the control plane's side is outside WardOS. A control plane on another host reaches the node over mutual TLS (`--listen-tls`, ADR-0038, done); enrolment, attestation, revocation and key bootstrap remain [#262](https://github.com/hexrift/WardOS/issues/262) |
| 2 | Producer tasks: workloads that fetch a dependency, call a provider or hand a result back | A manifest with `network.custom` is honoured through a node-owned egress proxy with the session proxy's rules; an attempt's output or workspace reaches the control plane in a bounded form the protocol carries; `network.proxy_allowlist` and `snapshots.read` or an output capability read `true` | Both halves by #332: the network half (`--network-allowlist`, node-integration.md §9; done) and the result half (`--output-return`, the manifest's `output` grant, `result` and the `output` capability section, node-integration.md §6.6; done). A workspace export as a snapshot (`snapshots.read`) has no issue yet (node-security-limitations.md §3.2) |
| 3 | A hosted agent runtime: the conversation loop inside the sandbox, with approvals and credentials as node capabilities | A workload can ask the control plane a question and get an answer through a channel relayed by the node; a credential reaches a workload only brokered, scoped and revocable, with `credentials.proxy_injection` or `scoped_http_gateway` `true`; approvals are a node-mediated hold rather than a per-session daemon hold | The channel by [#404](https://github.com/hexrift/WardOS/issues/404) (`--action-channel`, the manifest's `actions` grant, `actions` and `answer`, node-integration.md §6.7, ADR-0031; done); [#267](https://github.com/hexrift/WardOS/issues/267) for credentials (first node slice done, ADR-0034); [#415](https://github.com/hexrift/WardOS/issues/415) for approvals as an enforced node capability (`--approval-hold`, the manifest's `hold`, node-integration.md §6.9, ADR-0035; done) |
| 4 | Local sessions themselves: the desktop reads attempt evidence and drives node tasks, `ward up` is a thin client of a local node, per-session `wardd` is retired | `ward up`, `ward pause`, `ward resume`, `ward stop`, `ward verify`, `ward watch` and the desktop behave as they do today against a local node with no remote control plane; the single evidence writer of a session is the node; no command falls back to an in-process writer | The migration and the first CLI path by [#278](https://github.com/hexrift/WardOS/issues/278) (`ward node migrate`, `ward run --via-node`, `ward node serve`; ADR-0040; first slice done); [#258](https://github.com/hexrift/WardOS/issues/258)'s open slices ("Multi-session ownership and restart recovery", "Preserve current local CLI behaviour through the node boundary"); ADR-0029's migration map rows for the CLI, the per-session writer and the desktop; [#260](https://github.com/hexrift/WardOS/issues/260) for the scheduler several sessions need. The local-and-remote CLI issue (#272) was closed as superseded by #332 |

### 3.1 Stage 0: the node beside per-session development

- **What a user or operator changes.** Nothing for per-session use. An operator who wants
  the node installs the node tarball, creates the node's user and directories, writes the
  trust store and starts the service (node-integration-guide.md §1 to §3), and imports the
  snapshots the workloads need (§4).
- **What stays compatible.** Every `ward` command, every `.ward/` and `.tamperward/`
  file, every session log and every snapshot in the session CAS. `ward replay --verify`
  from the same release reads both kinds of log.
- **What breaks.** Nothing. The node reads nothing of the session state, and a node that
  is absent, stopped or incompatible changes nothing but the `ward doctor` line.
- **Rollback.** Stop and remove the node service and its directories; the per-session
  installation is untouched. Archive the attempt logs first if they are evidence you
  want; the node never deletes them.

### 3.2 Stage 1: an external control plane drives tasks

- **What changes.** The operator creates a second system user for the adapter, a group
  for the socket, and starts the node with `--client-group` and `--client-uid`
  (node-integration-guide.md §3). The control plane keeps its issuer key off the node's
  host and pre-signs envelopes for the adapter (node-integration.md §11.4). A control
  plane on another host instead reaches a node started with `--listen-tls` over mutual
  TLS with a client certificate from the operator's client CA, through the same adapter's
  `--connect-tls` (node-integration-guide.md §3.1, ADR-0038); without it, whatever carries
  the control plane's commands to the host is the control plane's own and unauthenticated
  by the node.
- **What stays compatible.** Everything of stage 0. The protocol window and the upgrade
  order of [compatibility.md](compatibility.md) govern the node and the control plane.
- **What breaks.** Nothing on the per-session side. On the node side, a listed uid can
  speak to the node but cannot read its state, records or evidence logs; a control plane
  that read logs as the node's uid at stage 0 has to read them another way or run as the
  node's uid.
- **Rollback.** Remove the two flags and the group; the socket is 0600 again and only the
  node's uid is served. Remove `--listen-tls` and its files and nothing listens on TCP.
  Nothing durable depends on either.

### 3.3 Stage 2: network grants and result return

- **What changes.** Both halves are in place. The network half: an envelope may name
  `network.custom` and a node started with `--network-allowlist` runs the workload behind
  a node-owned egress proxy with the same rules the session proxy applies today
  (allowlist, private ranges denied, `CONNECT` pinned), reached through its Unix socket;
  the capability document changes only by `network.proxy_allowlist` reading `true`,
  within 1.3 (compatibility.md §1). The result half: an envelope may carry an `output`
  grant (the first `stdio_bytes` of each stream, exact declared workspace files up to
  `files_bytes`), a node started with `--output-return` keeps the stream heads while the
  workload runs, collects the files once it has ended, stores the result beside the
  workspace, records it with every digest in the attempt log and returns it through the
  read-only `result` request; the capability document gains an `output` section only on
  such a node (node-integration.md §6.6). This landed additively within 1.3 rather than
  as a new minor, because the protected node tests pin the negotiated version at 1.3;
  an unchanged control plane keeps negotiating what it did and a node without the flag
  emits exactly the earlier document.
- **What stays compatible.** `{"network":"offline"}` envelopes, every verb, every attempt
  log already written. The node still refuses a grant it cannot enforce rather than
  running with less (node-integration.md §7.5), so a node without `--network-allowlist`
  keeps refusing `custom`.
- **What breaks.** Nothing by protocol. A policy decision: a workload with egress is a
  different risk from an offline one, which is why the allowlist is an operator flag. The
  session proxy's evidence records (`NetworkRequested`, `NetworkDenied`, with
  `ObservationsDropped` for a gap) are reused in the attempt log with origin `node`
  (§4.1): no new catalogue variant, so a `ward` that reads attempt logs reads these too.
- **Rollback.** Roll the node back to a release without the flags; a control plane that
  still sends an `output` grant is then refused `unsupported_grant` (or `authority_denied`
  by a node older than the grammar), never run with less (compatibility.md §4). Attempt
  logs with network records read under any `ward` that reads attempt logs at all, since
  the kinds are the session proxy's; logs with the result half's
  `NodeAttemptOutputCollected` record need a `ward` at least this new (§4.1).
- **Issues.** #332 for both halves (done). A workspace export as a snapshot and streamed
  output have no issue yet (node-security-limitations.md §3.2).

### 3.4 Stage 3: a hosted agent runtime, with approvals and credentials as node capabilities

- **What changes.** The node offers a channel from the sandbox to the control plane that
  the workload can ask through, relayed and recorded by the node, so an agent's
  conversation loop can run inside the sandbox. That part is in place (#404,
  [ADR-0031](decisions/ADR-0031-node-action-channel.md)): a node started with
  `--action-channel` gives an attempt whose manifest carries an `actions` grant a socket
  at `/run/ward/actions.sock` (named by `WARD_ACTION_SOCKET`) on which the workload asks
  bounded `approval` and `decision` requests; the control plane lists them with `actions`
  and answers with `answer`; the node records every request and answer in the attempt's
  evidence log before it shows or relays it, answers `expired` past the grant's wait and
  `cancelled` when the attempt ends, keeps requests pending through a pause, and answers
  a control-protocol line on the channel with nothing (node-integration.md §6.7); the
  capability document carries `actions` only on such a node, additively within 1.3.
  Credentials are brokered, scoped and revocable node capabilities as well (the first node
  slice of #267, [ADR-0034](decisions/ADR-0034-node-brokered-credentials.md)): a node
  started with `--network-allowlist` and `--credentials` (the operator's file of providers
  and services) honours a manifest's `credentials` grant naming a configured service, a host
  its own allowlist covers and a TTL; it leases the credential through the session broker's
  provider interface and rules (now the `ward-credentials` crate both runtimes share), bound
  to the attempt and its budget, has the attempt's egress proxy inject it into requests for
  `/<service>/…` to that host only, never into the sandbox, revokes it at the provider when
  the attempt ends and when a restarted node finds a lease a dead node left, fails closed
  with a named state and a `403`, and records every grant in the evidence log without its
  secret (node-integration.md §6.8); the capability document reports
  `credentials.proxy_injection` only on such a node, with its shape unchanged. Approvals
  are a hold the node applies on the control plane's answer as well (#415,
  [ADR-0035](decisions/ADR-0035-node-approval-hold.md)): a node started with
  `--approval-hold` (with `--action-channel` and `--network-allowlist`) honours a
  manifest's `hold` naming hosts of its own allowlist and services of its own credentials;
  the first request the attempt's proxy sees for a held capability opens an approval
  request on the channel, which the node words and the workload cannot, and the proxy
  refuses that capability with a named `403` until the control plane's approval of exactly
  that request is recorded; a denial, an expiry and the attempt's end keep it refused, a
  pause keeps it held with its clock stopped, and a restart cancels what was still asked
  (node-integration.md §6.9) — the per-session approval hold (`agent-integration.md` §4.1)
  preserved for what the node enforces. The capability document's `actions` section carries
  `hold` only on such a node. Stage 3 is complete with this; what remains is the rest of
  #267 for the node (delivery B, the services advertised) and holds on anything but a host
  or a credential (node-security-limitations.md §3.2). The hosted agent runtime itself is
  named by the workload ([#279](https://github.com/hexrift/WardOS/issues/279),
  [ADR-0036](decisions/ADR-0036-node-hosted-agent-adapters.md)): a node started with
  `--agent-adapter` runs Claude Code, Codex or the generic process adapter through the
  shared adapter contract under exactly the authority its manifest grants, records the
  binding and the hook lines as agent-origin claims, and advertises `adapters`; with the
  operator's `ward-agent` shim (`--agent-shim`,
  [ADR-0037](decisions/ADR-0037-node-agent-shim-and-relay.md)) a real runtime's command
  hooks run and its model route is reached through the shim's loopback relay, as in a
  session (node-integration.md §6.10).
- **What stays compatible.** Stage 2 envelopes and every attempt log. The per-session
  mode, which keeps its own approvals and vault until stage 4; its credential providers are
  the same code, moved behaviour-preserving into `ward-credentials`.
- **What breaks.** The sandbox gains a socket into it. The session mode's security proofs
  for the hook socket (ST-016, ST-027: a control-protocol request on the hook socket gets
  nothing) are the bar the node channel had to meet, and it meets it: a lifecycle request
  or a `hello` on the channel gets zero bytes and a closed connection and is recorded as
  a refusal (node-acceptance.md §2.5); the capability document says whether a node offers
  the channel, so a control plane never assumes it (node-integration.md §5). Brokered
  credentials add no socket and nothing to the sandbox; what they add is a file of the
  operator's naming the providers the node may call, and the revocation handles of live
  leases kept beside each attempt's workspace until they are revoked. Holds add no socket
  either; what they add is a question the node asks on the channel the attempt already
  has, and a `403` the workload must read as a refusal it may retry.
- **Rollback.** As stage 2: drop `--action-channel`, or roll the node back to a release
  without it; a control plane that still grants `actions` is then refused
  `unsupported_grant` (or `authority_denied` by a node older than the grammar) rather than
  run without the channel, and `actions` and `answer` are `unsupported_operation` (or
  unknown, closing the connection). Logs with `NodeAction*` records need a `ward` at least
  this new (§4.1). Drop `--credentials` likewise: a `credentials` grant is then refused
  `unsupported_grant` (`authority_denied` by a node older than the grammar), and leases
  already issued end with their attempts or at their own TTL; the credential records reuse
  kinds every `ward` reads. Drop `--approval-hold` likewise: a manifest with a `hold` is
  then refused `unsupported_grant` (`authority_denied` by a node older than the grammar),
  never run without the hold; the hold's records reuse the action and network kinds.
- **Issues.** [#404](https://github.com/hexrift/WardOS/issues/404) for the channel (done);
  [#267](https://github.com/hexrift/WardOS/issues/267) for credentials (the first node
  slice is in place; what remains is node-security-limitations.md §3.2);
  [#415](https://github.com/hexrift/WardOS/issues/415) for approvals as an enforced node
  capability (done; #269 was closed as superseded by #332).

### 3.5 Stage 4: the desktop and `ward up` on a local node, per-session `wardd` retired

- **What changes.** This is ADR-0029's "CLI/desktop to local node" row and #258's
  "preserve current local CLI behaviour through the node boundary". `ward up` becomes a
  client that asks a local node to admit and start the session, signing as the local
  issuer ADR-0030 §2 describes, with a key created at install and readable only by the
  node's operator account; `ward pause`, `ward resume` and `ward stop` become `pause`,
  `resume`, `stop` and `seal` on the node; the desktop's worker subscribes to the node's
  stream instead of the session socket, and the trust bar, the approval inbox and the
  session switcher read attempt evidence. The node owns one or more sessions at once and
  recovers them across its own restart (#258), which needs the scheduler and the resource
  accounting of #260. The in-process log-writer fallback goes: once the node is the
  authoritative writer there is no command that writes a log itself (#258, "no in-process
  log-writer fallback once the node service is authoritative"; ADR-0029's compatibility
  policy: "no silent fallback from a stronger node-mediated path to a weaker in-process
  path").
- **What stays compatible.** The command names and their semantics (ADR-0029: "Existing
  `ward` commands are not removed merely because an external control plane exists"),
  `.ward/` and `.tamperward/` files, and the evidence already written: every sealed
  session log stays readable by `ward replay` under the append-only rule (§4.1). Local
  mode needs no remote control plane, identity provider or database (ADR-0029).
- **What breaks.** The process model. `ward up` no longer spawns a `wardd`; a host
  without a node cannot start a session, so the node becomes a requirement of the runtime
  install, not an operator option, and `install.sh` or the image has to set it up. The
  session's state moves from `~/.local/state/ward/sessions/<id>/` to the node's task root
  under the node's uid, which is the one place in this path where existing on-disk state
  changes hands. #278's acceptance ("an existing local installation can upgrade into
  local ward-node mode without losing project policy, pinned snapshots or evidence") needs
  an explicit, verified, reversible migration before any of that, and its first slice is
  in place ([ADR-0040](decisions/ADR-0040-local-node-mode-migration.md)): `ward node
  migrate` refuses an unsealed or unverifying session log, imports every snapshot the
  per-session runtime retains into the node's store verified by digest, leaves every
  sealed log and every policy file where it is and records each by BLAKE3, creates the
  local issuer key (0600) and the trust store naming it, and commits all of it with one
  rename of a staging directory, so a failure leaves the prior state byte-identical and
  `--rollback` restores it. The logs are recorded, not imported: an attempt log and a
  session log are verified against their own origin sets (§4.1), and evidence is never
  copied into a second place. `ward run --via-node` then runs one attempt on that node.
  The session log and the attempt log still have to be reconciled into one shape: today a
  session is many launches and an attempt is one, and the single-writer rule of ADR-0015
  moves from the per-session daemon to the node (ADR-0030 §3: "ADR-0015 is unchanged for
  local sessions ... until ownership migrates").
- **Rollback.** Keep the per-session binaries of the previous release installed beside
  the node; a session started by the old `wardd` is still stopped and sealed by the old
  `ward`. A release that retires `wardd` needs a documented release boundary and a
  migration path first (ADR-0029's compatibility policy, compatibility.md §3), and must
  not partially import evidence: an import that fails leaves the prior state as it was
  (#278). For the migration that exists, `ward node migrate --rollback` is that path back:
  it refuses while the node serves, renames the node home aside in one step, and removes it
  unless attempts ran under it, whose evidence it keeps (ADR-0040 §2).
- **Issues.** [#278](https://github.com/hexrift/WardOS/issues/278) for the migration and
  the first CLI path (first slice done, ADR-0040; what remains is ADR-0040's last section);
  [#258](https://github.com/hexrift/WardOS/issues/258)'s two open slices;
  [#260](https://github.com/hexrift/WardOS/issues/260); the desktop and `ward up` work
  has no issue of its own yet beyond #258's slice.

## 4. Compatibility statement

### 4.1 Event logs

- **One format.** Session logs and attempt evidence logs are the same `ward-events`
  format: the same frame header (`WIRE_VERSION` 1), the same record envelope, the same
  hash layout, the same `HEAD` file ([event-model.md](event-model.md) §2, §3.1, §5;
  node-integration.md §6.5). `ward replay --verify` verifies either, and `ward replay
  --json` summarises the node records (`crates/ward-cli/src/replay.rs`,
  `a_node_attempt_evidence_log_verifies_and_summarises`).
- **The node's records are additive.** The eight `NodeAttempt*` kinds are appended at the
  end of the catalogue (the six of admission, launch, intervention, end, recovery and
  seal, then `NodeAttemptOutputCollected` for a returned result and
  `NodeAttemptResourceUsage` for what an attempt run in a cgroup used), followed by the
  three `NodeAction*` kinds of the action channel (`NodeActionRequested`,
  `NodeActionAnswered`, `NodeActionRefused`), and `node` is the eighth
  origin, under the append-only rule of event-model.md §3.1. Adding them changed how no
  earlier record encodes, so every session log sealed by an earlier release still
  verifies under the current `ward`. An attempt with egress also carries the session
  proxy's `NetworkRequested`, `NetworkDenied` and `ObservationsDropped` kinds, with origin
  `node` and no new variant.
- **An older `ward` cannot read an attempt log.** The event body is postcard, which names
  a variant by its declaration index, and the origin is encoded the same way; a `ward`
  built before the node kinds and the `node` origin existed has no variant for them and
  fails to decode the very first record (`NodeAttemptAdmitted`, origin `node`). It reports
  a decode failure for that log and renders nothing from it. It does not skip the unknown
  records, and it does not report a partial verdict. The converse holds for every future
  addition in either log: read a log with a `ward` at least as new as the writer, which
  is why §2.3 says to take both tarballs from one release.
- **Never in the same file.** A session log never contains origin `node`, and an attempt
  log contains nothing else (`ward_node::evidence::verify` checks it). A record with the
  wrong origin for its log is a verification failure, not a merge.

### 4.2 Protocol

The node protocol window, its negotiation, the supported skew between a node and a
control plane, the upgrade order and the major-version rule are
[compatibility.md](compatibility.md), and CI holds its marker equal to
`WARD_NODE_PROTOCOL`. Two consequences for a mixed host:

- The per-session control socket is not a version of the node protocol and never
  negotiates with it. `ward doctor`'s probe and the node both refuse rather than fall back
  (node_readiness.rs: "Protocol incompatibility never triggers a fallback to wardd").
- A WardOS release moves the window only when the pull request that implemented a minor
  moved it (compatibility.md §6). Upgrading the runtime tarball on a host therefore never
  changes what its node serves; upgrading the node tarball may raise `max_minor` and never
  lowers `min_minor` without an ADR.

### 4.3 Policy files and project state

Node mode reads none of a project's files. `.ward/policy.yaml`, `.tamperward/config.yml`
and `.tamperward.yml` keep their meaning and their readers (`ward up`, `ward verify`,
`ward ready`, TamperWard), and `ward init` is unchanged. The envelope's capability
manifest borrows `ward-policy`'s spelling for `network`, and `ward run --via-node` compiles a
project's effective policy into it (ADR-0040 §4): `offline`, `!custom` and the
`registries` and `development` presets (as the very host lists the session proxy matches)
compile; anything the node cannot enforce as a session would (an `ask` or `allow`
credential, step-through observation, a mount narrower than the node gives, loopback-only
or unrestricted egress) is refused by name, never dropped. The node itself still reads no
policy file. The session CAS, the vault and every
`sessions/<id>/` directory are untouched by a node on the same host.

### 4.4 What a per-session user must not do

- **Do not point a node at a per-session state directory**, or at any directory with
  content in it. The node home `ward node migrate` makes (`<state>/node/`) is not one: it
  is a new directory of the node's own, and the node it configures reads nothing outside
  it. `--state-dir` and `--task-root` are the node's own, created mode 0700
  and refused if group- or world-accessible; the node pins its id there and writes its
  records, revocations and snapshot store into it. `~/.local/state/ward` is the session
  tree, mode and layout both wrong for a node, and sharing it would put session logs
  within a node's reach and node state within every `ward` command's.
- **Do not run the node as the login user that runs sessions.** The point of the node's
  system user is that a compromised `ward` client, agent or desktop process cannot read or
  edit node state, records, evidence logs or workspaces, and that a compromised adapter
  is not a compromised node (#378, node-security-limitations.md §3.1). Give the node its
  own uid and list the adapter's uid with `--client-uid`; never list the login user to
  make reading evidence logs convenient, since reading them needs the node's uid anyway
  (node-integration.md §11.1).
- **Do not share a socket directory** between `sessions/<id>/control.sock` and the node's
  socket, and do not set `WARD_NODE_SOCKET` to a session's control socket: the handshake
  fails and the line reads `unhealthy`.
- **Do not copy an attempt log into a session directory**, or the reverse, expecting a
  tool to merge them. Each is verified against its own genesis and origin set (§4.1).
- **Do not expect a node to honour a `.ward/policy.yaml`.** Authority reaches a node only
  in a signed envelope (ADR-0030 §2).

### 4.5 Upgrading a mixed host

- Take the runtime tarball and the node tarball from the same release, each checked with
  `sha256sum -c` against its sidecar from that release, and read the release manifest
  (`wardos-<version>-manifest.json`, [release-manifest.md](release-manifest.md)) for the
  source commit and the `node_protocol_window` the release serves. A release publishes
  both trains or neither (node-release-readiness.md §2).
- **Order.** Stop the node's attempts first: stop admitting, let attempts end, `seal`
  them, then stop the service; a node restart turns every running attempt into
  `exited`/`unknown` and never re-runs it (node-integration.md §6.4). Sessions are
  independent: `ward stop` each one, or leave them, since a running `wardd` keeps its own
  binary and the new `ward` refuses an older daemon only where the protocol says so
  (security-model.md G13: a client sends `Stop` only to a daemon whose capabilities name
  confirmed stop). Install the node binaries, then the runtime binaries, then start the
  node, then check `ward doctor` with `WARD_NODE_SOCKET` set.
- **Across the node's window.** Within the window the node goes first and a control plane
  keeps negotiating what it did; raise a control plane's `min_minor` only once every node
  it drives serves that minor (compatibility.md §4). Rolling a node back below what a
  control plane requires fails closed at the handshake.
- **What a release upgrade never does.** It never converts a session log, a snapshot or a
  policy file; it never moves state between the session tree and the node's directories;
  it never starts a node that was not running. The node is not a released artifact with a
  version of its own yet (#275), so its version is the WardOS version, and releases are
  checksum-only until ADR-0028's workflow and verifier land (#148).

## 5. Against #278's acceptance

#278 asks that an existing local installation can upgrade into local node mode without
losing policy, pinned snapshots or evidence, that a failed migration leaves a recoverable
prior state, and that fleet features can be enabled incrementally. At this revision
([ADR-0040](decisions/ADR-0040-local-node-mode-migration.md)):

- **Policy, snapshots and evidence are not lost.** `ward node migrate` imports every
  snapshot the per-session runtime retains into the node's store, verified by digest, and
  leaves every sealed session log and every policy file in place, recorded by BLAKE3 (the
  logs with their chain heads), so `ward replay --verify` keeps verifying them and `ward
  node status` shows them unchanged. Nothing of the session tree is written.
- **A recoverable prior state.** The migration is staged beside the session tree and
  committed by one rename; a failure before it leaves the prior state byte-identical, and
  `ward node migrate --rollback` returns to per-session mode, removing the node home or,
  when attempts ran under it, keeping it aside with their evidence. For the node itself,
  the rollback column of each stage still holds.
- **Upgrade into local node mode** means, in this first slice, that the node serves the
  installation's own home (`ward node serve`) and `ward run --via-node` runs a session's
  command on it as one attempt signed by the local issuer and sealed by the node. `ward up`
  and the interactive commands stay per-session until #258 (§3.5).
- **Incremental enablement** is the same node's flags: `ward node serve -- …` passes
  mutual TLS, a control plane's issuer beside the local one in the node home's trust store,
  credentials, the action channel and holds, adapters, cgroups, a bound on concurrent
  attempts and containers, each discovered by a control plane through `capabilities`
  (node-integration.md §5) and refused at `admit` when absent (§7.5), none needing the
  installation to migrate again (ADR-0040 §5).
- **Upgrade tests across releases** do not exist: CI tests one commit against itself
  (node-release-readiness.md §3), and the protocol tests cover skew between a node and a
  peer at the same commit (compatibility.md §7). A test that reads a log sealed by a
  previous release, migrates an installation a previous release wrote, or drives a node
  from a previous release's client, is still to be written and has no issue yet.
