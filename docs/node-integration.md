# ward-node integration contract for external control planes

Status: living document. It describes the `ward-node` protocol 1.3 contract as
implemented today (ADR-0030 steps 1–9, 12 and 13: the network allowlist and bounded
result return, both additive within 1.3; the first single-node slice of #260:
cgroup resource limits and accounting, and a bound on attempts executing at once, also
additive within 1.3; and the action channel of
[ADR-0031](decisions/ADR-0031-node-action-channel.md), #404, additive within 1.3 as well;
and credentials as node capabilities of
[ADR-0034](decisions/ADR-0034-node-brokered-credentials.md), the first node slice of #267,
additive within 1.3 too, and approvals as a hold the node enforces of
[ADR-0035](decisions/ADR-0035-node-approval-hold.md), #415, additive within 1.3 as well,
and agent adapters hosted on admitted workloads of
[ADR-0036](decisions/ADR-0036-node-hosted-agent-adapters.md), #279, additive within 1.3
too, with the operator's `ward-agent` shim and its loopback relay in their attempts of
[ADR-0037](decisions/ADR-0037-node-agent-shim-and-relay.md), #424, an operator flag that
changes nothing on the wire), the same protocol over TCP with mutual TLS of
[ADR-0038](decisions/ADR-0038-node-mutual-tls-transport.md), the remote-transport slice of
#262, an operator-enabled second listener that changes nothing in the protocol (§3), and
the client and process adapter that drive it (§11). The cross-system acceptance suite that proves it against a real node (ADR-0030
step 10, #332 slice 9) is [node-acceptance.md](node-acceptance.md). Three companion
documents (ADR-0030 step 11, #332 slice 10): the walk from an empty host to a verified
attempt is [node-integration-guide.md](node-integration-guide.md); what the node does
not enforce yet, with the impact and the issue for each gap, is
[node-security-limitations.md](node-security-limitations.md); what CI proves about all
of this on every change and what a release publishes is
[node-release-readiness.md](node-release-readiness.md). A fourth, for a control plane
written in Node.js or TypeScript, is
[node-integration-from-nodejs.md](node-integration-from-nodejs.md): the control-plane side
of this contract as a dependency-free reference client in `examples/node-control-plane`,
held to the §7.4 vector and proven against a real node.

This is the contract an adapter drives, in any language, to have a local `ward-node`
admit, run, pause, stop, revoke and seal a task. Every protocol message below was
produced by the node's own encoders and decoded back by its strict decoders; the
admission example is a working test vector (§7.4).

## 1. Scope and trust model

- `ward-node` is the enforcement authority on its host
  ([ADR-0029](decisions/ADR-0029-product-split-fleet-trust-boundaries.md)). It decides
  whether a task runs, allocates its workspace, spawns, pauses, reaps, enforces the
  budget, records revocations and records the outcome.
- The control plane is external and not part of WardOS. It only issues bounded,
  expiring authority: an admission envelope signed by an issuer key the node's operator
  configured ([ADR-0030](decisions/ADR-0030-node-task-admission-and-execution-ownership.md)).
  Reaching the socket, or completing a TLS handshake with a certificate the node accepts
  (§3), proves nothing; a signature by a trusted key is required.
- The node reads the capability manifest and honours only what it can enforce: `offline`
  always, a `network.custom` host allowlist only on a node its operator started with
  `--network-allowlist`, which then runs the workload behind a node-owned egress proxy
  allowing exactly those hosts (§7.5, §9), and an `output` grant only on a node started
  with `--output-return`, which then keeps the head of the workload's stdout and stderr,
  collects the declared workspace files once the attempt has ended and returns the bounded
  result through `result` (§6.6, §7.5), a `resources` grant (CPU, memory and pid
  limits) only on a node started with `--cgroup-root`, which then runs every attempt in a
  cgroup of its own, enforces the limits there and records what each attempt used
  (§6.5, §7.5, §9), and an `actions` grant only on a node started with
  `--action-channel`, which then gives the attempt a socket in the sandbox through which
  the workload asks and the control plane answers, every exchange recorded (§6.7, §7.5),
  and a `credentials` grant only on a node started with `--credentials` (and
  `--network-allowlist`), which then leases each granted service's credential from the
  provider its operator configured, has the attempt's egress proxy inject it into requests
  for that service's allowlisted host only, never into the sandbox, and revokes it at the
  provider when the attempt ends (§6.8, §7.5),
  and a `hold` only on a node started with `--approval-hold` (and `--action-channel` and
  `--network-allowlist`), whose attempt proxy then refuses each held host or credential
  service until the control plane approves the request the node opens for it on the
  workload's first use (§6.9, §7.5);
  any other grant is refused `unsupported_grant` at `admit`, never run with less silently.
- Which agent runtime a workload is, is the workload's to say and the operator's to host:
  a workload may name an agent adapter of `ward-agent-adapter`'s contract beside its argv
  (`workload.adapter`, §7.3), and a node started with `--agent-adapter <id>` launches it
  through that contract — the adapter's environment and settings files and, for Claude
  Code, a hook socket whose lines are recorded as agent-origin claims — under exactly the
  authority the manifest grants, which is the same for every adapter (§6.10); any other
  node refuses such a workload `unsupported_grant`. On a node also started with
  `--agent-shim <file>`, the adapter runs under the operator's `ward-agent` shim, so its
  command hooks work, and behind an egress proxy the shim's loopback relay forwards to the
  attempt's proxy, the provider's base URL pointing at it for a provider the manifest
  grants a credential for (§6.10).
- How much the node runs at once is the operator's choice: a node started with
  `--max-running` executes at most that many attempts at once and refuses a `start` past
  it, or below a memory or disk headroom floor, `capacity_exhausted` with the task still
  `ready` (§5, §8.2). The node keeps no queue; the control plane's waiting attempts are its
  `ready` tasks.
- WardOS ships one client for this contract: the `ward-node-client` crate (a transport,
  a typed client, an issuer signer and a fail-closed attempt driver for Rust control
  planes) and its `ward-node-adapter` binary (the same over stdin/stdout for control
  planes in other languages), §11. Both run on the node's host, as the node's uid or as
  a uid the node's operator listed with `--client-uid` (§2.1, §11.1), or anywhere that
  reaches a node started with `--listen-tls`, with a client certificate from the
  operator's client CA (§2.1, §3, ADR-0038).
- Not implemented yet: a loopback relay and `HTTP_PROXY` environment inside the sandbox
  of a workload naming no adapter (the proxy is reached through its Unix socket, §9; a
  hosted adapter on a node with `--agent-shim` has both, §6.10), credentials delivered any other way
  than by proxy injection, or for anything but HTTP to one configured host (#267), a hold
  on anything but an allowlisted host or a brokered credential (an approval the workload
  asks for itself through the action channel is a recorded statement it acts on, §6.7; one
  the node opens for a held capability is enforced, §6.9), a hook's `PermissionRequest`
  bridged onto the action channel (the hold is the approval, §6.10), an event stream
  (`stream`), a workspace export as a snapshot (`snapshots.read` and
  `snapshots.diff` stay `false`; `result` returns declared files only, §6.6), and
  enrolment, attestation, certificate revocation lists or a durable record of TLS
  handshakes (the transport is a local Unix socket and, on a node started with
  `--listen-tls`, TCP with mutual TLS whose certificates the operator provisions and
  whose client keys it can revoke without a restart, §2.1, §3; the rest is #262). The full list, with what each gap means for a control plane, is
  [node-security-limitations.md](node-security-limitations.md) §3.
- The per-session runtime (`ward up`, one `wardd` per session) is a separate mode on the
  same host, with its own state, sockets and uid; how the two compare, coexist and
  converge is [migration-to-node.md](migration-to-node.md).

## 2. Operator setup

### 2.1 Running the node

```text
ward-node --socket <path> --state-dir <dir> --node-id <node_…> \
  [--trusted-issuers <file>] [--task-root <dir>] [--network-allowlist [--credentials <file>]] \
  [--output-return] [--action-channel [--approval-hold]] [--cgroup-root <dir>] \
  [--max-running <n> [--memory-floor <bytes>] [--disk-floor <bytes>]] \
  [--agent-adapter <id>… [--agent-shim <file>]] [--client-uid <uid>]… [--client-group <group>] \
  [--listen-tls <ip:port> --tls-cert <file> --tls-key <file> --tls-client-ca <file> [--tls-client-pin <pin>]… [--tls-client-revoked <file>]]
```

| Flag | Required | Meaning |
| --- | --- | --- |
| `--socket` | yes | Unix socket to serve. Its parent directory must exist and have no group or other permission bits (0700 or stricter); the socket is created mode 0600. With `--client-group` the directory must instead be owned by that group with no group-write and no other bits (0750 or stricter), and the socket is created mode 0660 owned by that group. An existing path is never removed: delete a stale socket before restarting. |
| `--state-dir` | yes | Node-owned state, created mode 0700 if absent and refused if group- or world-accessible. Holds `node-id`, `admission-versions.json`, `revocations.json`, `retired-attempts.json`, the snapshot store `cas/` and `tasks/`, one record per registered task (`<task>.json`, mode 0600, in a directory created mode 0700) from which a restarted node recovers its registry (§6.4). |
| `--node-id` | yes | The node's audience id (`node_` + 26-character ULID). Pinned in `<state-dir>/node-id` at first start; a later start with another id is refused. Envelopes must name exactly this id. |
| `--trusted-issuers` | no | Trust store (§2.2). Without it no issuer is trusted and every `admit` is refused `authority_denied`. |
| `--task-root` | no | Directory under which the node allocates workspaces and keeps each admitted attempt's evidence log (§6.5), created mode 0700 and refused if group- or world-accessible or not a real directory. With it the node executes (`start`, `pause`, `resume`, `stop`, `revoke`, `seal`); the node refuses to start if bubblewrap is unusable. Without it, all six are `unsupported_operation` and no evidence log is kept. |
| `--network-allowlist` | no | Honour a manifest's `network.custom` host allowlist (§7.5): the attempt runs behind a node-owned egress proxy allowing exactly those hosts, with IP literals, private ranges and the metadata endpoint always refused (§9), and the node reports `network.proxy_allowlist` `true` (§5). Needs `--task-root`. Without it every `network.custom` manifest is refused `unsupported_grant`. |
| `--output-return` | no | Honour a manifest's `output` grant (§7.5): the node keeps the first `stdio_bytes` of the workload's stdout and stderr, collects the declared workspace files once the attempt has ended (relative paths only, nothing followed outside the workspace, bounded), stores the result in `<task-root>/<task>/<attempt>.output/` (§6.6) and returns it through `result`; the capability document then carries `output` with `stdio` and `files` `true` (§5). Needs `--task-root`. Without it every manifest with `output` is refused `unsupported_grant` and `result` is `unsupported_operation`. |
| `--action-channel` | no | Honour a manifest's `actions` grant (§7.5): the attempt gets its own action channel, a socket in `<task-root>/<task>/<attempt>.actions/` bound into the sandbox at `/run/ward/actions.sock` and named by `WARD_ACTION_SOCKET`, on which the workload asks bounded questions; the node records every request and answer in the attempt's evidence log, relays them to the control plane (`actions`) and the control plane's answers back (`answer`), and the capability document carries `actions` (§5, §6.7). An approval the workload asks for is a recorded statement, not a capability the node enforces; one the node opens for a held capability is (`--approval-hold`). Needs `--task-root`. Without it every manifest with `actions` is refused `unsupported_grant` and both requests are `unsupported_operation`. |
| `--approval-hold` | no | Honour a manifest's `hold` (§6.9, §7.5): the first request the attempt's egress proxy sees for a held host or credential service opens one approval request on the attempt's action channel, and the proxy refuses that capability `403` with a named body until the control plane's approval of that request is recorded; a denial, an expiry or the attempt's end keep it refused. The capability document's `actions` section carries `hold` `true` (§5). Needs `--action-channel` and `--network-allowlist`. Without it every manifest with `hold` is refused `unsupported_grant`. |
| `--credentials` | no | The operator's credentials file (§6.8): the credential providers (the `[provider.<name>]` tables of credential-broker.md §5.1) and the services they back. A manifest's `credentials` grant for a configured service is then honoured (§7.5): its lease is issued at `start`, bounded by the attempt, injected by the attempt's egress proxy into requests for the service's host, and revoked at the provider when the attempt ends; the capability document reports `credentials` `true` (§5). The file must be the node user's own regular file, not a symlink, writable by no one else, at most 64 KiB; a malformed or unsafe file stops the node. Needs `--network-allowlist`. Without it every manifest with `credentials` is refused `unsupported_grant`. |
| `--cgroup-root` | no | A cgroup v2 directory delegated to the node: writable by the node's uid and holding no process of its own (for systemd, a unit with `Delegate=yes` whose main process sits in a sub-cgroup, `DelegateSubgroup=`). The node refuses to start if it is not on a cgroup v2 filesystem, if one of the `cpu`, `memory` and `pids` controllers it offers cannot be enabled in its `cgroup.subtree_control`, or if no cgroup can be created under it. Every attempt then runs in a cgroup of its own, `<dir>/<attempt>`, created before the spawn and removed once the workload is reaped; a manifest's `resources` limits are written there (§7.5, §9); what the attempt used is read from the kernel's counters and recorded (§6.5); and the node reports `resources` with the controllers it enabled (§5). At start the node also kills and removes every attempt cgroup (`exec_…`) a previous run left under it. Needs `--task-root`. Without it every manifest with `resources` is refused `unsupported_grant` and nothing is measured. |
| `--max-running` | no | At most this many attempts (1 to 1 024) execute at once: from the spawn until the reaper has reaped the workload, paused attempts and attempts whose kill is pending included. A `start` past it is refused `capacity_exhausted` with the task still `ready` and nothing materialised (§8.2); the node reports the bound, the running count and its headroom in `scheduling` (§5). Needs `--task-root`. Without it the node bounds nothing, as before. |
| `--memory-floor`, `--disk-floor` | no | Refuse a `start` `capacity_exhausted` while the host's available memory (`MemAvailable`) or the space available on the task root's filesystem is below this many bytes. A floor the node cannot measure refuses the `start` `resource_unavailable`. Need `--max-running`. |
| `--agent-adapter` | no | Host this agent adapter (`claude-code`, `codex` or `process`; repeatable) on workloads that name it (§6.10, §7.3): the node launches the workload's argv through `ward-agent-adapter`'s contract, adding the adapter's environment and settings files and, for one with hooks, a hook socket whose lines are recorded as agent-origin claims, under exactly the authority the manifest grants; the capability document carries `adapters` (§5). An unknown id stops the node. Needs `--task-root`. Without it every workload naming an adapter is refused `unsupported_grant`. |
| `--agent-shim` | no | The operator's `ward-agent` shim (the node tarball's, the runtime tarball's or the image's `ward-agent`: `/usr/local/bin/ward-agent` as node-integration-guide.md §1 installs it, `/usr/bin/ward-agent` on the image), verified at start: an absolute path to a regular file, not a symlink, executable, owned by root or the node's user and writable by no one else, that names `--relay` in its `--help` and once runs `/bin/true` hardened over the task root (so a kernel without Landlock stops the node). Every attempt of a hosted adapter then runs under it, bound read-only at `/run/ward/ward-agent`: Landlock, seccomp and no capabilities inside the sandbox, the adapter's command hooks reaching its hook socket, and, behind an egress proxy, the shim's relay on `127.0.0.1:3128` forwarding to the attempt's proxy with `HTTP_PROXY`/`HTTPS_PROXY` naming it and the adapter's provider base URL on it for a provider the manifest grants a credential for (§6.10). Nothing in the capability document changes. Needs `--agent-adapter`. Without it no shim is bound and no relay runs. |
| `--client-uid` | no | A uid (decimal) or user name the node serves on its socket besides its own uid; repeatable, resolved once at start (an unknown name or a uid listed twice refuses to start). The node reads every connection's peer credentials before it reads a byte and closes a connection from any other uid without a response (§3). Root is not exempt. Being served grants no authority: `admit` still needs a trusted signature (§8.1). |
| `--client-group` | no | A gid or group name to share the socket with: the socket is created mode 0660 owned by it, and its parent directory must be owned by it with mode 0750 or stricter. Needs at least one `--client-uid`; a member of the group that is not a listed uid can connect but is closed unread. Without it the socket is 0600 and only the node's uid (or root) can connect, whatever `--client-uid` says. The state directory and task root stay 0700 either way: a listed client can speak to the node, not read its state. |
| `--listen-tls` | no | Also serve the protocol on this TCP address (`<ip>:<port>`; port `0` picks a free one) over TLS 1.3 with a mandatory client certificate ([ADR-0038](decisions/ADR-0038-node-mutual-tls-transport.md), §3). At start the node writes `ward-node: serving the node protocol over mutual TLS on <ip>:<port>` to stderr. The socket is served as before. A certificate the node accepts takes the place of `--client-uid` for this listener, never of an issuer signature. With it, `SIGHUP` reloads the TLS files without a restart (below). Needs `--tls-cert`, `--tls-key` and `--tls-client-ca`; an address already in use stops the node. |
| `--tls-cert` | with `--listen-tls` | The node's certificate chain in PEM, leaf first, as the operator's PKI issued it for the names its clients expect (`subjectAltName`); the node user's own regular file, not a symlink, writable by no one else, at most 64 KiB. |
| `--tls-key` | with `--listen-tls` | The private key of `--tls-cert`'s leaf, PEM (PKCS#8, SEC1 or PKCS#1); the node user's own regular file, not a symlink, with no group or other permission bits (0600 or 0400), at most 64 KiB. A key that is not the certificate's stops the node. |
| `--tls-client-ca` | with `--listen-tls` | The CA certificates, PEM, a client's certificate must chain to, for client authentication; the node user's own regular file, not a symlink, writable by no one else, at most 64 KiB, with at least one usable certificate. |
| `--tls-client-pin` | no | Serve only these client keys: `sha256:` and the 64 lowercase hex digits of the SHA-256 of the client certificate's DER `SubjectPublicKeyInfo` (`openssl x509 -in client.pem -pubkey -noout \| openssl pkey -pubin -outform der \| sha256sum`); repeatable, a malformed or repeated pin stops the node. A pin outlives the renewal of a certificate for the same key. Without it every key the client CA certified is served. Needs `--listen-tls`. |
| `--tls-client-revoked` | no | A revocation list: client keys refused even when their certificate chains to `--tls-client-ca` and is pinned, one per line in `--tls-client-pin`'s spelling, with blank lines and `#` comments (to the end of the line) allowed and a key listed twice revoked once. The node user's own regular file, not a symlink, writable by no one else, at most 64 KiB, UTF-8; a line that is anything else stops the node, naming the line. Re-read on every `SIGHUP`, so start with an empty list to revoke without a restart later. Needs `--listen-tls`. |

The node refuses to start on any unsafe or malformed input: a trust store, state file or
task record it cannot parse, wrong permissions, a pinned id mismatch, a TLS file that is
unsafe, empty or inconsistent. It serves until killed. Every file is read once at start,
and changing one is a restart (§6.4), except the TLS files of a node started with
`--listen-tls`: on `SIGHUP` it reads `--tls-cert`, `--tls-key`, `--tls-client-ca` and
`--tls-client-revoked` again under the same checks and, only when all of them are usable,
uses them for every handshake from then on, writing `ward-node: reloaded the TLS
configuration: server key sha256:<pin> (changed|unchanged), client CA certificates <n>
(changed|unchanged), pinned client keys <n>, revoked client keys <n> (+<added>,
-<removed>)` to stderr; otherwise it keeps the previous configuration whole and writes
`ward-node: reloading the TLS configuration failed; still serving the previous one:
<reason>`. The process, its tasks and the socket are untouched either way. The pins
(flags) and the trust store are not reloaded. Without `--listen-tls`, `SIGHUP` keeps its
default effect and ends the node.

The same binary has three operator subcommands over local files; none speaks to the
socket, and each runs as the node's uid:

| Subcommand | Does |
| --- | --- |
| `ward-node issuer-key-id <hex-public-key>` | Prints the key id an issuer proof must name (§2.3). |
| `ward-node snapshot import --state-dir <dir> <project-dir>` | Captures a project into the snapshot store and prints the id an envelope's `workload.snapshot` carries (§2.4). |
| `ward-node audit --state-dir <dir> [--task-root <dir>] [--attempt <exec_…>] [--json] <task_…>` | Answers who delegated what authority to the task and when, from its durable record, and cross-checks the attempt's evidence log (§2.6). |

### 2.2 Trust store

One issuer per line. Each line binds one Ed25519 public key to the one principal
(`prn_…`) it may issue authority as:

```text
line       = [ws] [entry [ws]] ["#" comment]
entry      = public-key ws [key-id ws] principal
public-key = 64 lowercase hex digits: the 32-byte Ed25519 public key
key-id     = 64 lowercase hex digits: the key id of §2.3, which must equal the derived id
principal  = "prn_" + 26-character upper-case Crockford base32 ULID (§7.2)
ws         = one or more spaces or tabs
```

`#` starts a comment that runs to the end of the line; blank and comment-only lines are
ignored. The key id is optional and only checked; the principal is required.

```text
# control-plane issuer (this is the test key of §7.4; never trust it in production)
ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c 0871f3aabc26e4582c508af5c03884e6a96f0989d1dd8cfb49cd17ed25792433 prn_01M1RQ16G00000Y3RF1W7GY3RF
```

A key signs only for its principal: `admit` is refused `authority_denied` unless the
envelope's root lease names, as its `issuer`, the principal the signing key is bound to
(§8.1). Several keys may be bound to the same principal (for rotation); one key is never
bound to two.

The file must be a regular file, not writable by group or others (`mode & 022 == 0`),
at most 64 KiB and UTF-8. A malformed line, a key bound to no principal (including a line
in the earlier `<public-key> [<key-id>]` format), upper-case hex, a mismatched key id or
a duplicate key stops the node. The store is read once at start; a key change needs a
restart.

### 2.3 Issuer key id

A key id is `BLAKE3-256(public_key_bytes)` over the 32 raw public-key bytes (not over
the hex text), written as 64 lowercase hex digits. The node prints it:

```text
$ ward-node issuer-key-id ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c
0871f3aabc26e4582c508af5c03884e6a96f0989d1dd8cfb49cd17ed25792433
```

Input that is not 64 lowercase hex digits exits non-zero.

### 2.4 Importing a project snapshot

```text
$ ward-node snapshot import --state-dir <dir> <project-dir>
c19c769fdd8644df9167a36d0133289c9fa44a8c768cd0aafa1756a13fb3e33b
```

It captures `<project-dir>` (honouring `.gitignore`, including `.git`, at most 2 GiB)
into `<state-dir>/cas` and prints one line: the snapshot id as 64 lowercase hex digits,
with no prefix. That line, without its newline, is exactly the value an envelope's
`workload.snapshot` carries (§7.3); pass it through unchanged. Use the same
`--state-dir` as the node. It is an operator command over local files, not a socket verb.

### 2.5 Revocations

The node reads `<state-dir>/revocations.json` once at start, and adds to it itself when it
serves `revoke` (§6.1):

```json
{"format":1,"revocations":[{"lease":"lease_01M45YYRG00009K6DANAXVQK6C","revoked_at_unix_ms":1791203400000,"reason":"operator"}]}
```

`reason` is one of `operator`, `policy`, `delegation_revoked`, `security`. A lease is
unusable from `revoked_at_unix_ms` on; a revoked ancestor revokes every lease delegated
from it, and two different facts for one lease make it unusable. A `revoke` records the
task's lease with `revoked_at_unix_ms` at the node clock and reason `operator`, rewriting
the whole file from the node's in-memory facts, so an edit made while the node runs is
lost at the next `revoke`. Edit the file only while the node is stopped; a malformed
file, or one over 8 MiB (8 388 608 bytes), stops the node.

The node never removes an entry, and it never writes a state file larger than the 8 MiB
it accepts at start. A `revoke` whose record would make `revocations.json` exceed 8 MiB
(written compactly, about 83 000 records) is refused `resource_unavailable` with nothing
changed: the revocation is not recorded, no older one is dropped, and the workload keeps
running. To make room, stop the node and remove entries you no longer need (only for
leases that can never be presented again, for example expired ones), or stop or revoke
the task by other means. The same bound applies to every state file the node writes; a
refused write is `resource_unavailable` from the verb that needed it.

`admission-versions.json`, `retired-attempts.json`, `tasks/` and `node-id` are
node-owned: deleting the versions file would let old envelopes be replayed, deleting a
retired attempt would let a replaced attempt be registered again (§6.1), deleting a
revocation the node recorded would make that lease usable again, and deleting a task
record forgets the task and the operation ids its attempt applied.

### 2.6 Auditing an attempt: who delegated what

```text
$ ward-node audit --state-dir <dir> --task-root <task-root> task_01M45YYRG00001249248SK6H24
agent agent_01M45YYRG00000000000000003 delegated lease lease_01M45YYRG00009K6DANAXVQK6C (delegation deleg_01M45YYRG000016NWVVWJ6HB70) to agent agent_01M43CJ1G0000DVQFEXVZZY001 for task task_01M45YYRG00001249248SK6H24 at 2026-10-05T12:00:00.000Z, expires 2026-10-05T13:00:00.000Z, under principal prn_01M1RQ16G00000Y3RF1W7GY3RF from lease lease_01M45YYRG00000000000000001
grants: repo.read on repo:example/project
lineage, root first:
  lease lease_01M45YYRG00000000000000001 (delegation deleg_01M45YYRG00000000000000002) from principal prn_01M1RQ16G00000Y3RF1W7GY3RF to agent agent_01M45YYRG00000000000000003, valid 2026-10-05T12:00:00.000Z to 2026-10-05T14:00:00.000Z, grants: repo.read on repo:example/project (delegable)
admitted by key 0871f3aabc26e4582c508af5c03884e6a96f0989d1dd8cfb49cd17ed25792433 as version 1 at 2026-10-05T12:03:12.418Z (operation 2); envelope <64 hex, the BLAKE3 digest of the envelope bytes> valid 2026-10-05T12:00:00.000Z to 2026-10-05T12:15:00.000Z, session sess_01M45YYRG0000FXQ5TK1V58CGG
attempt exec_01M45YYRG00005ANB6CSVQF248: state sealed, receipt completed, evidence <task-root>/task_01M45YYRG00001249248SK6H24/exec_01M45YYRG00005ANB6CSVQF248.evidence/events.log: 4 records, head <64 hex>, sealed
```

The audit reads one file, the task's record in `<state-dir>/tasks/` (§6.4), and answers
from it alone: no socket, no control plane. Since this revision the record keeps, beside
the envelope digest, the authority chain the `admit` that took effect verified: the lease
the binding names (its issuing principal, delegation id, subject agent, parent lease and
delegating agent, grants, validity and version), every ancestor lease in the same terms,
the envelope's validity and version, and the node clock at the admission, with the
`admit` operation id and the issuer key id the record already held. The facts are written
with the rest of the record before `admit` is answered (§6.4); a refused `admit` records
nothing. The output is, line by line:

1. who delegated what: for a root lease `principal prn_… delegated lease … to agent … for
   task …`, for a delegated lease `agent … delegated lease … to agent … for task …, under
   principal prn_… from lease …`, with the lease's validity. The `issuer` is the human or
   service principal whose key signed the envelope (§2.2): a CI runner or other automation
   is a service principal with a key and `prn_` of its own, so the line names it; the
   `subject` is always the agent the authority was delegated to. The node records no
   model or provider identity;
2. the lease's grants, `capability on resource`, `(delegable)` where a child may receive
   the grant;
3. the lineage, root first, each ancestor with the principal or agent that delegated it,
   its subject, validity and grants, so the contraction down the chain is visible; or
   `lineage: none (root lease)`;
4. the admission: the issuer key id, the envelope version, the node clock at the
   admission, the `admit` operation id, the envelope digest and validity, the session;
5. the attempt: its recorded state (§6.4; `launching` is a spawn in flight when the record
   was last written), its receipt outcome (§9) or `none`, and its evidence log.

Times print as UTC with millisecond precision. `--attempt <exec_…>` requires the record
to hold that attempt: the record holds the task's current attempt only, and the node
guesses nothing about a replaced one (its record went with the replacement, §6.1; its
evidence log remains under its own id, §6.5), so another attempt is an error. `--task-root
<dir>` verifies the attempt's evidence log as §6.5 does and then requires its
`NodeAttemptAdmitted` record for the `admit` operation to agree with the record on binding,
session, envelope digest, issuer key id and version; if the log is absent, does not
verify, has no such record or differs, the last line ends `evidence disagrees with the
record: <why>` and the command exits 1. Without `--task-root` the line ends `evidence not
checked`; a never-admitted task with no log reads `absent`.

A record written before this revision has no authority facts and reads `task … attempt …
was admitted before authority facts were recorded (operation …, envelope …, key …,
session …)`; a task that was never admitted reads `task … attempt … was never admitted`;
a `ready` task a restart recovered has forgotten its admission (§6.4) and reads as never
admitted until it is admitted again, while an attempt that was started keeps its chain for
as long as its record exists. The audit fails closed: a state directory without `tasks/`,
a records directory accessible to group or others, and a record that is absent, not a
regular file, over 8 MiB, malformed, not the task's or holding more lineage (16) or
grants than an envelope can carry, are each an error on stderr with exit 1, and nothing is
created or written.

`--json` prints the same facts as one object with `"schema":1`: `task`, `attempt`,
`lease`, `state`, `receipt` (`null` or the outcome), `admitted` (`null`, or `operation`,
`envelope`, `issuer_key`, `session` and `authority`, itself `null` for a pre-change record
or `lease`, `lineage` (nearest parent first, as the envelope carries it), the envelope's
`issued_at_unix_ms`, `expires_at_unix_ms` and `version`, and `admitted_at_unix_ms`; each
lease is `lease`, `delegation`, `issuer`, `subject`, `parent_lease`, `delegated_by`,
`grants`, `issued_at_unix_ms`, `expires_at_unix_ms`, `version`) and `evidence` (`null`
without `--task-root`, else `log`, `verified` (`null`, or `records`, `head`, `sealed`) and
`disagreement` (`null`, or why)). Times are Unix milliseconds, ids carry their prefixes
and hashes are lowercase hex. The exit status is the text form's.

## 3. Transport framing

- Unix stream socket, newline-delimited JSON: each message is one UTF-8 JSON object
  followed by `\n` (a preceding `\r` is tolerated). Responses are one line each. On a
  node started with `--listen-tls` the identical framing runs inside a TLS session over
  TCP (below); everything in this section holds there byte for byte.
- **One request per connection.** A connection carries exactly: the handshake line, its
  response, then at most one request line and its response. The node then closes it.
  Open a new connection per request. Both lines may be written at once.
- A request line is at most 64 KiB (65 536 bytes) excluding the newline; a longer line
  closes the connection. Every answer line fits 64 KiB too, except the answer to `result`
  (§6.6), which carries an attempt's bounded output and is at most 16 MiB
  (16 777 216 bytes): read that one with the larger bound, as the shipped client does.
- **Request deadline.** The handshake line, its response and the request line must all
  complete within 10 seconds of accept. Partial progress does not extend it. If it
  expires the node closes the connection without a response.
- **Answer deadline.** Once a request is read, the verb runs to its own bound, which the
  request deadline does not cut short, and the node then has a further 10 seconds to
  write the answer, counted from when the answer is ready. A verb's answer can therefore
  take longer than 10 seconds to arrive: `stop` and `revoke` wait up to 10 seconds for
  the reap, `start` materialises the snapshot and then waits up to 30 seconds for the
  spawn, `pause` and `resume` wait up to 1 second for the freeze or thaw to settle, and
  every other request is answered at once. Give `start`, `stop` and `revoke` a read
  timeout above those bounds (for example 60 seconds plus the time to copy your largest
  snapshot).
- Connections are served one at a time. Do not hold a connection open; an idle client
  delays every other client by up to 10 seconds, and a `start`, `stop`, `revoke`,
  `pause` or `resume` delays them for as long as it runs.
- **Peer check before any byte.** The node reads each connection's peer credentials
  (`SO_PEERCRED`) before reading from it. A peer whose uid is neither the node's own nor
  listed with `--client-uid` (§2.1) is closed without a response: it sees EOF (or a reset,
  if it had already written) and nothing else, indistinguishable on the wire from the
  fail-closed closes below. The node reports the refusal on stderr with the uid, at most
  once per uid per 10 seconds, with the count of refusals it did not report.
- **Mutual TLS** ([ADR-0038](decisions/ADR-0038-node-mutual-tls-transport.md)). On the
  `--listen-tls` address the node speaks TLS 1.3 only (no 1.2, no early data, no session
  resumption) and requires the application protocol `ward-node` (ALPN) and a client
  certificate that chains to `--tls-client-ca` for client authentication, is within its
  validity window give or take 60 seconds of clock skew, carries a key not on the
  `--tls-client-revoked` list and, with `--tls-client-pin`, carries a pinned key. The
  client checks the node's certificate against the server CA
  it was given, for the name it expects (and, if it pins one, the node's key), with the
  same skew. One connection still carries one request; the handshake must complete within
  10 seconds of accept and then the request deadline applies. A refused handshake (no
  certificate, another CA, expired or not yet valid, revoked, not pinned, no `ward-node`
  ALPN, TLS 1.2, a plaintext client, too slow) ends with a TLS alert or a close and no protocol byte,
  and the node reports it on stderr with the peer's address and the reason, at most once
  per address per 10 seconds with the count it did not report; a served session is
  reported as `served a TLS client sha256:<pin> from <address>`, at most once per client
  key per 10 seconds. Handshakes run on their own threads, at most 32 TCP connections at
  once (one more is closed at accept), and only an authenticated session waits for the
  one-at-a-time lock the socket's connections share, so a TCP peer that never completes a
  handshake delays nobody. After the answer, or after a fail-closed close, the node ends
  the session with `close_notify`; a client reads that as EOF exactly as on the socket. A
  reload on `SIGHUP` (§2.1) applies from the next handshake and does not interrupt a
  session in progress, except that a session whose key a reload revoked while it waited
  for the lock is closed unserved and reported; its client sees EOF without an answer, as
  for any fail-closed close (§10).
- **Fail closed:** anything malformed (invalid JSON, an unknown or missing field, an
  unknown verb, a request whose `protocol` differs from the negotiated version, a value
  out of bounds) gets no response line: the node closes the connection. Only well-formed
  requests get a typed `rejected` response. An adapter must treat EOF without a response
  as "unknown whether a mutating request took effect" and recover by `inspect` and replay
  (§10).

## 4. Handshake and version negotiation

The client sends the range it speaks; the node supports major 1, minors 0–3.

```json
{"request":"hello","protocol":{"major":1,"min_minor":3,"max_minor":3}}
```

The node picks the highest common minor:

```json
{"response":"accepted","protocol":{"major":1,"minor":3}}
```

| Case | Response | Connection |
| --- | --- | --- |
| Different major | `{"response":"rejected","reason":"major_version_mismatch","supported":{"major":1,"min_minor":0,"max_minor":3}}` | closed |
| Same major, no overlapping minor (for example `min_minor` 4) | `{"response":"rejected","reason":"no_common_minor","supported":{"major":1,"min_minor":0,"max_minor":3}}` | closed |
| Accepted at 1.0 | `{"response":"accepted","protocol":{"major":1,"minor":0}}` | closed (1.0 has no requests) |
| `min_minor > max_minor`, unknown field, not a `hello` | none | closed |

All later messages carry `"protocol":{"major":1,"minor":3}`, the exact negotiated
version. An adapter for this contract should offer exactly `min_minor` 3, `max_minor` 3
and refuse anything else: at 1.2 the node has no `admit`, no `exited` and no outcome, and
a 1.2 connection that sends `admit` is closed.

The supported version skew between a node and a control plane, and the upgrade order,
are in [compatibility.md](compatibility.md).

## 5. Capability discovery

At 1.1 and later the one request may be discovery:

```json
{"request":"capabilities","protocol":{"major":1,"minor":3}}
```

A node started with `--trusted-issuers` and `--task-root` answers at 1.3 (capacity is the
host's; the other values are what the node reports today; with `--network-allowlist` as
well, `network.proxy_allowlist` reads `true`):

```json
{"response":"capabilities","capabilities":{"protocol":{"major":1,"minor":3},"architecture":"x86_64","capacity":{"logical_cpus":8,"memory_bytes":17179869184},"isolation":{"namespaces":{"sandbox":true,"user_namespace":true},"backends":{"container":false,"microvm":false,"vm":false}},"network":{"offline":true,"proxy_allowlist":false},"credentials":{"proxy_injection":false,"scoped_http_gateway":false},"snapshots":{"content_addressed":true,"diff":false,"read":false},"verifier":{"isolated":false},"lifecycle":{"pause":true,"stop":true,"revoke":true,"admit":true,"start":true}}}
```

| Flag | Meaning at 1.3 |
| --- | --- |
| `lifecycle.admit` | Present, and `true`, when the node verifies and admits signed envelopes. Absent means `false`. Every `ward-node` binary admits at 1.3; without a trust store every `admit` is still refused. |
| `lifecycle.start` | Present, and `true`, when the node executes admitted tasks (`--task-root` set, bubblewrap usable). Absent means `false`. |
| `lifecycle.stop` | Always present. At 1.3 it equals `start`: the node never offers a way to begin execution without its own way to end it. |
| `lifecycle.pause`, `lifecycle.revoke` | Always present. At 1.3 each is `true` exactly when `lifecycle.start` is: an executing node serves `pause` and `revoke`. The document has no flag for `resume` or `seal`; an executing node serves `resume` with `pause` and `seal` with `start`, and a node that advertises `start` `false` refuses all four `unsupported_operation`. |
| `isolation.namespaces.sandbox`, `isolation.namespaces.user_namespace` | `true` exactly when `lifecycle.start` is: every workload runs in a bubblewrap namespace sandbox inside its own user namespace. |
| `network.offline` | `true` exactly when `lifecycle.start` is: every workload runs with no network but loopback. |
| `network.proxy_allowlist` | `true` exactly when `lifecycle.start` is and the node was started with `--network-allowlist` (§2.1): a manifest asking for a host allowlist (`network.custom`, §7.5) is then honoured through a per-attempt egress proxy (§9). Otherwise `false`, and such a manifest is refused `unsupported_grant` at `admit`. |
| `snapshots.content_addressed` | `true` exactly when `lifecycle.start` is: workspaces are materialised from the node's content-addressed store (§2.4). |
| `credentials.proxy_injection`, `credentials.scoped_http_gateway` | Both `true` exactly when `network.proxy_allowlist` is and the node was started with `--credentials` (§2.1): a manifest's `credentials` grant for a service the operator configured is then honoured, its lease injected by the attempt's egress proxy into a route scoped to that service's host and paths (§6.8). Otherwise both `false`, and such a manifest is refused `unsupported_grant` at `admit`. The section's shape is unchanged, so a strict decoder of any 1.3 revision reads it. Which services a node offers is the operator's to say; the document does not list them. |
| `resources.cpu`, `resources.memory`, `resources.pids` | Present, as `"resources":{"cpu":…,"memory":…,"pids":…}` after `output` (or after `verifier` when `output` is absent), exactly when `lifecycle.start` is and the node was started with `--cgroup-root` (§2.1): every attempt then runs in a cgroup of its own and what it used is recorded (§6.5). Each flag is `true` when the node enabled that controller and enforces the matching limit of a `resources` grant (`cpu_millis`, `memory_bytes`, `pids`, §7.5). Otherwise the section is absent, nothing is measured, and every `resources` grant is refused `unsupported_grant`. New in this revision of 1.3, with the same caveat as `output`: a strict decoder of an earlier revision refuses a document that carries it. |
| `scheduling` | Present, as `"scheduling":{"max_running":…,"running":…,"memory_floor_bytes":…,"memory_available_bytes":…,"disk_floor_bytes":…,"disk_available_bytes":…}` after `resources` (or where `resources` would be), exactly when `lifecycle.start` is and the node was started with `--max-running`. Read when the document is served: `running` counts the attempts executing now (spawned and not yet reaped), the `*_available_bytes` are the host's `MemAvailable` and the task root filesystem's available space (`0` if they cannot be read), and a floor of `0` means none. A `start` is refused `capacity_exhausted` while `running` is at `max_running` or an available amount is below its floor (§8.2). New in this revision of 1.3, with the same caveat as `output`. |
| `output.stdio`, `output.files` | Present, as `"output":{"stdio":true,"files":true}` after `verifier`, exactly when `lifecycle.start` is and the node was started with `--output-return` (§2.1): a manifest's `output` grant (§7.5) is then honoured and `result` returns an ended attempt's bounded stdout, stderr and declared files (§6.6). Otherwise the section is absent, which means both `false`, and such a manifest is refused `unsupported_grant` at `admit`. The section is new in this revision of 1.3: a strict decoder of an earlier 1.3 revision refuses a document that carries it, so start a node with `--output-return` only once every control plane that reads it is at this revision; a node without the flag emits exactly the earlier document. |

| `actions.approval`, `actions.decision`, `actions.max_pending`, `actions.max_total`, `actions.max_wait_secs` | Present, as `"actions":{"approval":true,"decision":true,"max_pending":8,"max_total":64,"max_wait_secs":3600}` after `verifier` (and after `output`, `resources` and `scheduling` when those are present), exactly when `lifecycle.start` is and the node was started with `--action-channel` (§2.1): a manifest's `actions` grant (§7.5) is then honoured within those ceilings, and `actions` and `answer` are served (§6.7). Otherwise the section is absent, which means no channel, and such a manifest is refused `unsupported_grant` at `admit`. Like `output`, the section is new in this revision of 1.3: a strict decoder of an earlier revision refuses a document that carries it, so start a node with `--action-channel` only once every control plane that reads it is at this revision; a node without the flag emits exactly the earlier document. |
| `actions.hold` | Present, and `true`, as the last field of `actions` (`…,"max_wait_secs":3600,"hold":true}`), exactly when the section is and the node was started with `--approval-hold` (§2.1): a manifest's `hold` (§7.5) is then honoured (§6.9). Absent means `false`, and such a manifest is refused `unsupported_grant` at `admit`. New in this revision of 1.3: a strict decoder of an earlier revision refuses a document that carries it, so start a node with `--approval-hold` only once every control plane that reads it is at this revision; a node without the flag emits exactly the earlier document. |

| `adapters.contract`, `adapters.hosted` | Present, as `"adapters":{"contract":"1.0","hosted":["claude-code","codex","process"]}` after `actions` (or where `actions` would be), exactly when `lifecycle.start` is and the node was started with `--agent-adapter` (§2.1): `contract` is the `ward-agent-adapter` contract the node hosts adapters under, `hosted` the adapters its operator named, in that order, none twice. A workload naming one of them is honoured (§6.10); any other adapter is refused `unsupported_grant`. Otherwise the section is absent. New in this revision of 1.3: a strict decoder of an earlier revision refuses a document that carries it, so start a node with `--agent-adapter` only once every control plane that reads it is at this revision; a node without the flag emits exactly the earlier document. |

Everything else (`isolation.backends`, `snapshots.diff`, `snapshots.read`, `verifier`) is
`false`: the node offers none of it yet. 1.1 and 1.2
documents keep their earlier content: they never carry `admit`, `start`, `output`,
`resources`, `scheduling`, `actions` or `adapters`,
report `stop`, `pause` and `revoke` as `false`, and report the execution flags
above as `false`, because a 1.1 or 1.2 connection cannot run anything.

## 6. Lifecycle verbs

Every request names the task by its `binding` (`task`, `attempt`, `lease`). Mutating
verbs carry an `operation_id`: an integer from 1 to 2^64−1 (keep it at or below
2^53−1 if your JSON library uses doubles). The examples use the binding of the §7
envelope; the retry example names a new attempt of the same task.

### 6.1 Requests and responses

`create` registers the binding. Nothing runs and no authority is checked.

```json
{"request":"create","protocol":{"major":1,"minor":3},"operation_id":1,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"}}
{"response":"accepted","protocol":{"major":1,"minor":3},"operation_id":1,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"created"}
```

`admit` carries the signed envelope (§7) and moves `created → ready`:

```json
{"response":"accepted","protocol":{"major":1,"minor":3},"operation_id":2,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"ready"}
```

`start` spawns the admitted workload and answers once the spawn is confirmed:

```json
{"request":"start","protocol":{"major":1,"minor":3},"operation_id":3,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"}}
{"response":"accepted","protocol":{"major":1,"minor":3},"operation_id":3,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"running"}
```

An ambiguous launch is answered `accepted` with state `exited` (its outcome is
`unknown`; never retry it, §10):

```json
{"response":"accepted","protocol":{"major":1,"minor":3},"operation_id":3,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"exited"}
```

On a node started with `--max-running` (§2.1), a `start` that would pass the bound, or
that finds the host's available memory or disk below its floor, is refused and changes
nothing: the task stays `ready`, no workspace is materialised and nothing is recorded, so
the same request (same `operation_id`) may be sent again once an attempt has ended:

```json
{"response":"rejected","protocol":{"major":1,"minor":3},"operation_id":3,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"reason":"capacity_exhausted"}
```

The node keeps no queue of its own: a refused `start` is forgotten, so nothing waits on
the node, nothing can starve there and nothing is lost or reordered by a restart. The
control plane's waiting attempts are its `ready` tasks, which `inspect` shows and the
registry bounds (1 024 tasks, §10); `scheduling` in the capability document (§5) says how
many run and how many may.

`pause` stops the running workload's whole process tree and answers once the freeze is
confirmed; `resume` continues it and answers once nothing is still stopped:

```json
{"request":"pause","protocol":{"major":1,"minor":3},"operation_id":5,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"}}
{"response":"accepted","protocol":{"major":1,"minor":3},"operation_id":5,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"paused"}
{"request":"resume","protocol":{"major":1,"minor":3},"operation_id":6,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"}}
{"response":"accepted","protocol":{"major":1,"minor":3},"operation_id":6,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"running"}
```

A freeze (or thaw) that cannot be confirmed is refused, and the task stays `running` (or
`paused`):

```json
{"response":"rejected","protocol":{"major":1,"minor":3},"operation_id":5,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"reason":"resource_unavailable"}
```

`stop` kills and reaps the workload before it answers:

```json
{"request":"stop","protocol":{"major":1,"minor":3},"operation_id":4,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"}}
{"response":"accepted","protocol":{"major":1,"minor":3},"operation_id":4,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"stopped"}
```

`revoke` durably revokes the task's lease, then kills and reaps a live workload before it
answers (from `ready` it spawns nothing):

```json
{"request":"revoke","protocol":{"major":1,"minor":3},"operation_id":7,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"}}
{"response":"accepted","protocol":{"major":1,"minor":3},"operation_id":7,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"revoked"}
```

`seal` makes an `exited`, `stopped` or `revoked` task terminal:

```json
{"request":"seal","protocol":{"major":1,"minor":3},"operation_id":8,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"}}
{"response":"accepted","protocol":{"major":1,"minor":3},"operation_id":8,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"sealed"}
```

`inspect` is read-only and has no `operation_id`:

```json
{"request":"inspect","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"}}
{"response":"inspected","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"running"}
```

An `exited`, `stopped`, `revoked` or `sealed` task also carries its receipt outcome (§9).
A `created`, `ready`, `running` or `paused` task never does, and neither does any 1.1 or
1.2 response:

```json
{"response":"inspected","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"exited","outcome":"completed"}
{"response":"inspected","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"stopped","outcome":"failed"}
{"response":"inspected","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"revoked","outcome":"failed"}
{"response":"inspected","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"sealed","outcome":"failed"}
{"response":"inspected","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"paused"}
```

`outcome` on a `revoked` or `sealed` task is new in this revision of 1.3: an earlier
1.3 node never sent it there, and a strict 1.3 decoder of that revision refuses it.
Treat `outcome` as optional on `exited`, `stopped`, `revoked` and `sealed`.

A refusal echoes the request's `operation_id`, or `null` for `inspect` and `stream`:

```json
{"response":"rejected","protocol":{"major":1,"minor":3},"operation_id":2,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"reason":"authority_denied"}
{"response":"rejected","protocol":{"major":1,"minor":3},"operation_id":null,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"reason":"task_not_found"}
```

`stream` is decoded but always answered `unsupported_operation`.

A retry is a new execution attempt of the same task (§10). Once the current attempt is
`exited`, `stopped`, `revoked` or `sealed`, a `create` naming the same task under a new
`attempt` id replaces it; the new attempt is then admitted with a new envelope whose
`version` is higher than any accepted before for the task:

```json
{"request":"create","protocol":{"major":1,"minor":3},"operation_id":9,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG0000BJ8XG3K6B2D7Q","lease":"lease_01M45YYRG00009K6DANAXVQK6C"}}
{"response":"accepted","protocol":{"major":1,"minor":3},"operation_id":9,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG0000BJ8XG3K6B2D7Q","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"created"}
```

While the current attempt is `created`, `ready`, `running` or `paused`, the same request is
refused, and after the replacement the old binding is no longer known:

```json
{"response":"rejected","protocol":{"major":1,"minor":3},"operation_id":9,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG0000BJ8XG3K6B2D7Q","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"reason":"attempt_mismatch"}
{"response":"rejected","protocol":{"major":1,"minor":3},"operation_id":null,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"reason":"attempt_mismatch"}
```

A replaced attempt is retired for good. Before the replacement takes effect the node
records the old attempt id durably in `<state-dir>/retired-attempts.json`; from then on a
`create` naming that attempt is refused `stale_operation`, whatever the task's current
attempt is doing, after a node restart and after the task is evicted, so the old attempt
can never be registered, admitted or run again:

```json
{"request":"create","protocol":{"major":1,"minor":3},"operation_id":10,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"}}
{"response":"rejected","protocol":{"major":1,"minor":3},"operation_id":10,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"reason":"stale_operation"}
```

The node retires at most 256 attempts per task and 65 536 in all. It never forgets one:
when recording the old attempt would exceed either bound, or the write fails, the new
attempt is refused `resource_unavailable` and the current attempt stays as it was.

### 6.2 State machine

| From | Event | To | Receipt outcome |
| --- | --- | --- | --- |
| — | `create` | `created` | — |
| `created` | `admit` | `ready` | — |
| `ready` | `start`, spawn confirmed | `running` | — |
| `ready` | `start`, launch ambiguous | `exited` | `unknown` |
| `ready` | `stop` | `stopped` | `failed` (nothing ran) |
| `ready` | `revoke` | `revoked` | `failed` (nothing ran) |
| `running` | `pause`, freeze confirmed | `paused` | — |
| `paused` | `resume`, thaw confirmed | `running` | — |
| `running`, `paused` | workload ends on its own or at its budget | `exited` | `completed`, `failed` or `unknown` |
| `running`, `paused` | `stop` | `stopped` | `failed`, or `unknown` if the reap is unconfirmed |
| `running`, `paused` | `revoke` | `revoked` | `failed`; what the reaper observed if the workload had already ended on its own; `unknown` if the reap is unconfirmed |
| `exited`, `stopped`, `revoked` | `seal` | `sealed` | unchanged (kept and still reported) |
| `exited`, `stopped`, `revoked`, `sealed` | `create` under a new attempt id | `created` (the new attempt) | the old attempt's receipt is discarded; the old attempt id is retired |
| `ready` | node restart | `created` (admit again with a higher `version`, §6.4) | — |
| `running`, `paused`, or a `start` in flight | node restart | `exited` | `unknown` |

`exited`, `stopped` and `revoked` end an attempt: the only transitions out of them are
`seal` and a `create` for a new attempt. `sealed` is terminal; only a new attempt
replaces it. A mutating verb that the task's state does not allow is `invalid_state` with
nothing changed (replays aside, §6.3). A paused workload is still watched by its reaper
and its budget keeps running, so it can end in `exited` while paused (killed at its
budget).

A `stop` or `revoke` of a `paused` task continues the task's whole tree before the kill.
From that moment the task reads `running`, because its processes are running again while
they are killed, and it stays `running` until the reaper records how it ended. If the
reap is not confirmed in time, a `stop` is answered `resource_unavailable` (§8.2) and the
task keeps reading `running` with the kill still pending: `pause` and `resume` are then
refused `invalid_state`, while `inspect`, a replay of the `stop` and a `revoke` are
served. (A `revoke` always ends in `revoked`, §8.2.)

### 6.3 Idempotency and replay

A replay is the same request again, for example after a lost response. The node keeps,
for each attempt and each verb, every `operation_id` that took effect on that attempt, for
as long as the attempt is registered, across node restarts (§6.4): one each for `create`,
`admit`, `start`, `stop`, `revoke` and `seal`, and every `pause` and every `resume`. An
attempt takes at most 128
pauses (and so at most 128 resumes); a further `pause` is refused `resource_unavailable`
with nothing changed, so no id is ever forgotten while its attempt is registered. `stop`
and `revoke` are never held back by that bound. An id is tied to its verb: the same id
under another verb is a new operation of that verb.

One rule covers all eight mutating verbs. When a request's `operation_id` already took
effect for its verb on this attempt:

- if it is the latest operation of that verb on the attempt, the answer is `accepted` with
  the task's current state, however far the task has moved on since (for example
  `sealed`, or `running` again after a `pause` was resumed). Nothing acts again.
- if a later operation of the same verb has taken effect since (only `pause` and `resume`
  can take effect more than once per attempt), the answer is `stale_operation` and nothing
  acts.

Only an operation that took effect is recorded. A refused request records nothing and
may be retried, with the same `operation_id` or another.

| Verb | Replay that is accepted | Anything else |
| --- | --- | --- |
| `create` | Same binding and the `operation_id` of the `create` that registered it: `accepted` with the current state. | Another `operation_id`: `invalid_state`. Same task and attempt, another lease: `lease_mismatch`. Same task, a retired attempt (§6.1): `stale_operation`. Same task, another attempt: a new attempt if the current one is `exited`, `stopped`, `revoked` or `sealed` (§6.1), otherwise `attempt_mismatch`. |
| `admit` | Same `operation_id`, byte-identical `envelope_json` and identical `proof` as the admit that succeeded: `accepted` with the current state. | On a task that is not `created`: `invalid_state`. |
| `start` | The `operation_id` of the `start` that took effect (including an ambiguous one): `accepted` with the current state. | On a task that is not `ready`: `invalid_state`. |
| `stop` | The `operation_id` of the `stop` that took effect: `accepted` with the current state (`stopped`, or `sealed` once sealed). | On a task that is not `ready`, `running` or `paused`, including one stopped by another operation: `invalid_state`. |
| `pause` | The `operation_id` of the latest `pause` that took effect: `accepted` with the current state. An earlier one: `stale_operation`. | On a task that is not `running`, or whose kill is pending: `invalid_state`. On an attempt that already took 128 pauses: `resource_unavailable`. |
| `resume` | The `operation_id` of the latest `resume` that took effect: `accepted` with the current state. An earlier one: `stale_operation`. | On a task that is not `paused`: `invalid_state`. |
| `revoke` | The `operation_id` of the `revoke` that took effect: `accepted` with the current state (`revoked`, or `sealed` once sealed). | On a task that is not `ready`, `running` or `paused`: `invalid_state`. |
| `seal` | The `operation_id` of the `seal` that took effect: `accepted`, `sealed`. | On a task that is not `exited`, `stopped` or `revoked`, including one sealed by another operation: `invalid_state`. |

Replay a `stop` that timed out with the same `operation_id`: a second stop with a new id
while the first is pending also stops the task, but is then answered `invalid_state`
because the first id is recorded as the stopping operation.

The record belongs to the attempt. Once a new attempt replaces it, every request naming
the old attempt is refused (`stale_operation` for `create`, `attempt_mismatch` for the
other verbs, `task_not_found` once the task is evicted); none of them acts.

### 6.4 Restart and recovery

The node keeps one durable record per registered task in `<state-dir>/tasks/`. Every
transition is written to it (temporary file, fsync, rename, directory fsync) before the
node answers the verb; if that write fails, the verb is refused `resource_unavailable`
and nothing changed (a `pause` or `resume` undoes its freeze or thaw first). The record of
an admitted attempt also keeps the authority chain its `admit` verified, which
`ward-node audit` reads (§2.6). On a node started with `--cgroup-root`, the record of
an ended attempt also keeps what it used (`usage`: the limits enforced and the kernel's
counters, as in `NodeAttemptResourceUsage`, §6.5), and keeps it across a restart; a record
without a measurement carries no `usage` field and reads exactly as before. `start`
records that it is about to spawn before it spawns, and the spawned process once the
spawn is confirmed; if that second write fails, the node kills the workload and answers
`accepted` with `exited` (`unknown`), as for an ambiguous launch.

After a restart, killed or clean, the node rebuilds its registry from the records before
it serves its socket, and a control plane observes:

- **`created` tasks** read `created`; replaying their `create` is `accepted`.
- **`ready` tasks** read `created`: the node does not start on an admission it has not
  verified since it started. Replaying the old `admit` is `stale_operation` (its version is
  consumed); `admit` a new envelope with a higher `version`, then `start`.
- **Attempts that may have been executing** — `running` or `paused`, a `start` whose spawn
  was in flight, or a `stop` or `revoke` still waiting for its reap — read `exited` with
  outcome `unknown`, whatever the workload did. Any process of the attempt that survived
  the node is killed: bubblewrap's `--die-with-parent` normally takes the sandbox down
  with the node, and the node also kills the process tree still rooted at the recorded
  host process (matched by pid, start time and boot, so an unrelated process is never
  signalled; a paused tree is killed as it is). The attempt is never started again;
  retry it as a new attempt (§10).
- **`exited`, `stopped`, `revoked` and `sealed` tasks** keep their state and receipt
  outcome.
- **Replays** of every `operation_id` the attempt applied are answered exactly as before
  the restart (§6.3) and never act; replaying the `start` of an attempt recovered as
  `exited` answers `exited` and spawns nothing. A `stop` or `revoke` that was still waiting
  for its reap did not take effect: its replay is `invalid_state` on the `exited` task.
- **Durable facts** stay as they were: admission versions, revocations (a revoked lease is
  still `lease_revoked` at `admit` and `start`) and retired attempt ids.

A malformed, oversized or unexpected entry in `tasks/`, or more records than the registry
holds (1 024), stops the node from starting. The node never writes more records than it
loads: an evicted task's record is removed before the task that needed its room is
recorded. Each recovered attempt's evidence log is also brought in line with its recovered
state before the node serves (§6.5); a log that does not verify stops the node from
starting.

### 6.5 Evidence logs

A node with a `--task-root` is the single writer of one append-only, hash-chained
evidence log per attempt it admits:

```text
<task-root>/<task>/<attempt>.evidence/events.log    the log (mode 0600; 0400 once sealed)
<task-root>/<task>/<attempt>.evidence/HEAD          the sealed head, written by seal (0400)
<task-root>/<task>/<attempt>.output/result.json     the stored result of an output grant (§6.6; mode 0600)
<task-root>/<task>/<attempt>.actions/actions.sock   the action channel's socket while the attempt runs (§6.7)
<task-root>/<task>/<attempt>.credentials/leases.json the revocation handles of the attempt's live leases (§6.8)
<task-root>/<task>/<attempt>.adapter/               a hosted adapter's settings files and hook socket while the attempt runs (§6.10)
```

The directories (mode 0700, like `<task-root>/<task>/`) sit beside the attempt's
workspace `<task-root>/<task>/<attempt>/`, never inside it: the sandbox binds only the
workspace, so the workload cannot reach its log or its stored result. Nothing else writes
them.

The log uses the `ward-events` session-log format unchanged (`event-model.md` §5):
length-prefixed frames, each record hash-chained to the one before. Every record has
origin `node`, except the claims of a hosted agent adapter (§6.10): `AgentClaim` records,
and only those, with origin `agent`, the one origin no reader takes for an enforcement
fact. The chain is bound to the attempt: its session id carries the execution
attempt id's 128-bit value (`sess_` + the attempt's 26-character body), and its genesis
hash is BLAKE3 over the bytes `ward-node attempt evidence v1` and a NUL, followed by the
task, attempt and lease ids as 16 big-endian bytes each. Records, in order:

| Record | Written when | Carries |
| --- | --- | --- |
| `NodeAttemptAdmitted` | An `admit` took effect (again after a restart, under a higher version). | Task, attempt and lease ids, the receipt session, the `admit` operation id, the BLAKE3 digest of the exact envelope bytes, the issuer key id, the envelope version. |
| `NodeAttemptLaunched` | `start` confirmed its spawn. | The `start` operation id and the host pid. |
| `NodeAttemptIntervened` | A `pause` or `resume` took effect. | `pause` or `resume`, and the operation id. |
| `NetworkRequested`, `NetworkDenied` | The attempt's egress proxy (§9: a `network.custom` manifest on a node with `--network-allowlist`) allowed or refused a destination. The node records the proxy's verdicts itself while the attempt runs, in the order they were made, at most 512 per attempt. | The destination host or literal and port; for an allow, the pinned addresses as the rule and the workload's host pid; for a denial, the reason (not allowlisted, private range, or a hold's `PolicyDeny` with the rule `hold:<state>:<n>`, §6.9). Never a request body. |
| `ObservationsDropped` | Verdicts of the attempt's proxy could not be recorded: past the 512 bound, refused by the log's own bound, or still undecided when the attempt ended. One marker, before `NodeAttemptEnded`. | `source` `network`, the count and the bound. |
| `AgentClaim` (origin `agent`) | The workload names an agent adapter the node hosts (§6.10): once right after `NodeAttemptLaunched`, the binding (`Note`, payload `{"agent_adapter":{…}}`); and for an adapter with hooks, one per line its hook socket accepted, appended while the attempt runs, at most 256 per attempt. A launch whose binding cannot be appended is killed and recorded as an ambiguous launch. | The binding: the contract, adapter, declared runtime, hooks, events, provider and requested model, all metadata. A hook line: `ToolUse` `<hook> <tool> <summary> → allow` (`PostToolUse` without the answer) or `Note` `SessionStart` / `Stop`. Claims, never facts. |
| `ObservationsDropped` (source `hook`) | Hook lines past the 256 bound, refused by the log, or arriving at more than 8 connections at once. One marker, before `NodeAttemptEnded`. | `source` `hook`, the count and the bound. |
| `NodeAttemptResourceUsage` | The attempt ran on a node started with `--cgroup-root` (§2.1), its workload ended and was reaped, and the node read its cgroup's counters. One record, before `NodeAttemptOutputCollected` (if any) and `NodeAttemptEnded`; not written for an attempt whose end was recorded before its reap (a `revoke` whose reap was not confirmed) or that never spawned. | The limits enforced (`cpu_millis_limit`, `memory_limit_bytes`, `pids_limit`, absent when not asked for) and what the tree used: `cpu_usage_usec` (`cpu.stat`), `memory_peak_bytes` (`memory.peak`), `pids_peak` (`pids.peak`), `memory_oom_kills` (`memory.events` `oom_kill`) and `pids_max_events` (forks refused at the limit, `pids.events` `max`); a counter the host's kernel or controllers do not provide is absent. |
| `NodeAttemptOutputCollected` | The attempt was admitted with an `output` grant on a node started with `--output-return` (§6.6, §7.5), its workload ended and was reaped, and the node collected the output and stored it. One record, right before `NodeAttemptEnded`; never written for a workload the node lost track of. | For stdout and for stderr, the bytes returned and the bytes dropped past them; for every declared file, in declaration order, its workspace path, size, `BLAKE3-256` digest and status (`returned`, `digest_only`, `missing`, `not_a_regular_file`, `too_large`). Never the bytes. `result` returns exactly what this record digests. |
| `NodeActionRequested` | The workload asked through the attempt's action channel (§6.7: an `actions` grant on a node started with `--action-channel`) and the node accepted the request, or the node opened a request itself for a held capability on its first use (§6.9: a `hold` on a node started with `--approval-hold`; summary `network <pattern>` or `credential <service>`). Appended before the control plane can list or answer it. | The node's request number (from 1), the kind (`approval`, `decision`), and the size and `BLAKE3-256` digest of the summary and of the detail. Never the text. |
| `NodeActionAnswered` | A request was answered: by `answer` (appended before the workload is told), or by the node: `expired` once its wait ran out, `cancelled` when the attempt ended, the workload's connection closed, the channel closed, or a restarted node recovered the attempt. Every pending request is answered before `NodeAttemptEnded` or `NodeAttemptRecovered`. | The request number, the decision (`approved`, `denied`, `expired`, `cancelled`), the `answer`'s operation id (none for the node's own answers), and the size and digest of the note. Never the note. |
| `NodeActionRefused` | The node refused a line on the channel and closed that connection without a reply (§6.7): oversized, malformed, a node-protocol or control-protocol request, a kind not granted, a repeated id, too many pending or in all. At most 16 per attempt: the 16th closes the channel. | The reason and how many bytes of the line the node read. |
| `CredentialGranted` | The attempt was admitted with a `credentials` grant on a node started with `--credentials` (§6.8) and the provider issued a lease for a granted service: before `NodeAttemptLaunched`; or the node renewed one. | The service, the subject `issued <host> lease <id>` or `renewed <host> lease <id>`, the lease's permissions and lifetime, delivery `ProxyInjected`. The lease id is `b3:` and 32 hex digits of the `BLAKE3-256` digest of the provider's revocation handle, or `static`. Never the leased value or the handle. |
| `CredentialDenied` | No lease could be issued for a granted service (before `NodeAttemptLaunched`), a renewal failed, or the provider did not confirm a revocation (after its `CredentialRevoked`). | The service, the host, and the rule `credential-provider:<provider>:<state>`, `credential-renew:<provider>:<state>` or `credential-revoke:<provider>:<state>` with the provider's named state (`unreachable`, `timed-out`, `tls-failed`, `auth-rejected`, `sealed`, `misconfigured`, `bad-response`, `refused`, `not-found` or `binding:<rule>`). |
| `CredentialRevoked` | The attempt ended and its lease's route was withdrawn and the lease revoked at the provider: before `NodeAttemptEnded`; or a restarted node revoked a lease a node that died left behind: before `NodeAttemptRecovered`. | The service and the reason: `UserRevoked` for `revoke`, `SessionEnded` for every other end. |
| `NodeAttemptEnded` | The attempt ended: natural exit, budget kill, a lost child, an ambiguous launch, a `stop` or `revoke` (from `ready`, or with its kill reaped, or a revoke whose reap was not confirmed). | The state (`exited`, `stopped`, `revoked`), the receipt outcome, the cause (exit code, budget, killed, lost, ambiguous, not started, unconfirmed) and the `stop` or `revoke` operation id. |
| `NodeAttemptRecovered` | The state the node holds differs from the state the log last shows: after a restart, before the node serves, and before sealing. | The state and outcome the node holds. |
| `NodeAttemptSealed` | `seal` took effect; the log is then sealed. | The `seal` operation id. |

Every record is metadata; workload output is never logged (an output record carries
counts, sizes and digests, never a byte of the output), and neither is anything a workload
or a control plane said through the action channel (§6.7: sizes and digests only), nor a
leased credential or its revocation handle (§6.8). A record is fsynced before the
node answers its verb. If it cannot be appended, the verb is refused
`resource_unavailable` and nothing changes: the task record written for it is restored,
and a `pause` or `resume` undoes its freeze or thaw first. One exception is `admit`: its
evidence record is written after its version is durably recorded, so an `admit` refused
this way still consumes its version, and the next `admit` needs a higher one. A replayed
operation appends nothing. Events the node observes rather than serves are recorded as
they happen, and a later restart reconciles any it could not append:

- a `start` whose `NodeAttemptLaunched` cannot be appended kills the workload and is
  answered `exited` (`unknown`), as for an ambiguous launch;
- an end the reaper observed but could not append is recorded as `NodeAttemptRecovered`,
  with the state and outcome the node holds, when the node next starts or before the
  attempt is sealed, whichever comes first;
- an attempt that may have been executing when the node died is recorded
  `NodeAttemptRecovered` `exited` (`unknown`) before the restarted node serves.

A crash can only leave a torn final frame that was never acknowledged; the restarted node
cuts it off. Any other damage (a flipped byte, a foreign or reordered record, a `HEAD`
that does not match) refuses every further append with `resource_unavailable` and stops a
restarted node from starting. The log is bounded at 256 KiB; records that do not end an
attempt are refused `resource_unavailable` once it would pass 240 KiB, so the records that
end, recover and seal it always fit; the node's own `expired` and `cancelled` answers to
action-channel requests (§6.7) and the `CredentialDenied` and `CredentialRevoked` records
of a `credentials` grant (§6.8) may use that reserve too, since they are bounded by the
grant and must never be lost.

To verify a log, as an operator or a control plane with access to the host:

```text
ward replay --verify <task-root>/<task>/<attempt>.evidence/events.log
```

or, in Rust, `ward_events::LogReader::open(path)?.verify_all()?` compared with
`ward_events::log::parse_head` of `HEAD`, or `ward_node::evidence::verify(dir, binding)`,
which also checks the genesis, the session id and that every record has origin `node`,
or is an `AgentClaim` with origin `agent`.
`ward replay --json` prints one summary per record. The protocol does not carry the log
or its head: `inspect` and receipts are unchanged. To answer who delegated the authority
the attempt ran under, and to check that the log's `NodeAttemptAdmitted` record agrees
with the task's durable record, use `ward-node audit --task-root` (§2.6).

Retention is the operator's: the node never deletes an evidence log or a stored result.
A sealed task evicted from the registry (§10, capacity) keeps its sealed log and its
result, and a replaced attempt keeps both, sealed or not, under its own attempt id.
Remove `<task-root>/<task>/` only once its logs have been read or archived.

### 6.6 Result return

A node started with `--output-return` (§2.1) honours a manifest's `output` grant (§7.5):
while the workload runs the node keeps exactly the first `stdio_bytes` of its stdout and
of its stderr (a head; everything past it is drained and counted), and once the workload
has ended and been reaped — a natural exit, the budget kill, a `stop` or a `revoke` — the
attempt's reaper collects the declared files from the workspace, stores the bounded
result as `<task-root>/<task>/<attempt>.output/result.json` (§6.5) and records what it
collected in the evidence log (`NodeAttemptOutputCollected`), before the end record.
Nothing of the workspace is read while the attempt executes. The collection happens
before the attempt's end is recorded, so a `stop` or `revoke` waiting for the reap (§3,
§8.2) waits for it too; it is bounded by the grant and the ceilings below (reading and
digesting at most 64 files of at most 64 MiB each), but a workload that leaves very large
declared files can make a `stop` run into its 10-second bound and be answered
`resource_unavailable` once; replay it.

Collection never leaves the workspace and is bounded: each declared path is relative and
in the grammar of §7.5, every component is looked at without following a symlink, and a
symlink, a directory or any other non-regular file anywhere on the path is reported
`not_a_regular_file` with nothing followed or read; a path with nothing at it is
`missing`. A regular file is returned whole, with its size and `BLAKE3-256` digest, while
it fits what is left of `files_bytes` (files are taken in declaration order), digest-only
with `"truncated":true` once it does not, and `too_large` — neither read nor digested —
above 64 MiB (67 108 864 bytes). Every size is the size the node read, every digest is of
exactly the bytes a control plane can compare against the file on the host.

`result` is read-only and has no `operation_id`. It is served for an `exited`, `stopped`,
`revoked` or `sealed` task; `seal` keeps the result:

```json
{"request":"result","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"}}
{"response":"result","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"exited","output":{"stdout":{"bytes":13,"truncated":false,"dropped":0,"content_base64":"aGVsbG8gc3Rkb3V0Cg=="},"stderr":{"bytes":4,"truncated":true,"dropped":4996,"content_base64":"ZWVlZQ=="},"files":[{"path":"out/report.json","size":11,"digest":"<64 hex, BLAKE3-256 of the content>","truncated":false,"content_base64":"eyJvayI6dHJ1ZX0="},{"path":"big.bin","size":3000,"digest":"<64 hex>","truncated":true},{"path":"missing.txt","skipped":"missing"},{"path":"planted","skipped":"not_a_regular_file"}]}}
```

| Field | Meaning |
| --- | --- |
| `state` | The task's state when the result was read: `exited`, `stopped`, `revoked` or `sealed`. |
| `output.stdout`, `output.stderr` | `bytes`: the bytes returned, the length of `content_base64` decoded; `dropped`: the bytes the workload wrote past the returned head; `truncated`: `dropped > 0`; `content_base64`: the first `bytes` of the stream, standard base64 with padding. The head is returned, never the tail. |
| `output.files[]` | One entry per declared path, in declaration order. A returned file: `size`, `digest` (64 lowercase hex, `BLAKE3-256`), `"truncated":false` and `content_base64`. A file past the content budget: `size`, `digest`, `"truncated":true` and no content. Anything else: `skipped`, one of `missing`, `not_a_regular_file`, `too_large`, and nothing else. |

A `result` is refused with a `rejected` response whose `operation_id` is `null` (as for
`inspect`): `unsupported_operation` on a node not started with `--output-return`, or on a
connection below 1.3 (where the verb is unknown and the connection closes without an
answer); `task_not_found`, `attempt_mismatch` and `lease_mismatch` as for every verb;
`invalid_state` while the attempt is `created`, `ready`, `running` or `paused`; and
`resource_unavailable` when no stored result exists for the ended attempt: its manifest
carried no `output` grant, the attempt never ran (`stopped` or `revoked` from `ready`),
the node lost track of its workload (receipt `unknown`; the workspace is left unread),
the node restarted before the output was collected (also `unknown`), the result could
not be stored, or its `NodeAttemptOutputCollected` record could not be appended — a
result the log does not bind is removed rather than served, and a restarted node removes
a stored result its log does not bind before it serves. A refused `result` changes
nothing; the receipt and the evidence log stand.

Reading is repeatable: the same request answers the same bytes until the attempt is
replaced by a new attempt (§6.1), whose result then has its own directory, or the operator
removes the task directory (§10). The stored result survives a node restart (§6.4). Over
the socket a control plane binds what it received to the sealed log by the digests in
`NodeAttemptOutputCollected`: recompute `BLAKE3-256` over each returned file's content and
over the stream heads' lengths and compare them with the record, read as §6.5 says. The
shipped client reads the result after `seal` and puts it in the report (§11.3).

### 6.7 Action channel

A node started with `--action-channel` (§2.1) honours a manifest's `actions` grant (§7.5)
by giving the attempt its own channel ([ADR-0031](decisions/ADR-0031-node-action-channel.md)):
at `start`, before the spawn, the node listens on
`<task-root>/<task>/<attempt>.actions/actions.sock` (the directory mode 0700, beside the
workspace, never inside it), binds that socket into the sandbox at
`/run/ward/actions.sock` and sets `WARD_ACTION_SOCKET=/run/ward/actions.sock` (§9). The
socket is removed when the attempt ends. The channel is a question-and-answer path, not a
route: the network namespace is unchanged.

**What the workload sends and receives.** One JSON request per line, on a connection it
opens to the socket:

```json
{"id":"deploy-1","kind":"approval","summary":"deploy to staging","detail":"plan: rotate 3 services"}
```

| Field | Values |
| --- | --- |
| `id` | 1–64 bytes of `A-Z a-z 0-9 . _ : -`, unique within the attempt. The workload's correlation key. |
| `kind` | `approval` (permission to do what the summary says) or `decision` (a yes-or-no choice made for the workload), and only a kind the grant names. |
| `summary` | 1–512 bytes of UTF-8 text: what the control plane is asked. |
| `detail` | 0–16 KiB (16 384 bytes) of UTF-8 text: the context it needs. |

Every field is required and no other is allowed; a line is at most 128 KiB. The answer
comes back on the same connection, one line per request:

```json
{"id":"deploy-1","decision":"approved","note":"go ahead"}
```

`decision` is `approved` or `denied` from the control plane, `expired` from the node once
the grant's `wait_secs` ran out with no answer, or `cancelled` from the node when the
attempt ended (`stop`, `revoke`, the budget kill, the workload's own exit), the channel
closed, or a restarted node recovered the attempt; `note` is the control plane's, at most
512 bytes, absent without one. A workload must proceed only on `approved` and treat
everything else, an end-of-file without a reply included, as a refusal. Several requests
may wait on one connection, up to `max_pending`; closing the connection withdraws its
waiting requests (answered `cancelled`).

**What gets nothing.** The node answers only well-formed, granted requests. A line longer
than 128 KiB or whose summary or detail is past its bound (`oversized`), a line that is not
one request object of the grammar (`malformed`), one that parses as a node-protocol or
control-protocol request — any object with a `request`, `req` or `response` member, so a
lifecycle request and a `hello` (`control_request`) — a kind the grant does not name
(`kind_not_granted`), a repeated id (`duplicate_id`), and a request past `max_pending`
(`too_many_pending`) or `max_total` (`too_many_requests`) are answered with zero bytes:
the node records `NodeActionRefused` (§6.5) and closes that connection. The 16th refusal
closes the channel for the rest of the attempt (its waiting requests are answered
`cancelled`); at most 8 connections are served at once and a further one is closed unread.
Nothing a workload sends reaches the node's protocol socket or changes what the node
enforces.

**Ordering and records.** The node records before it shows or tells (§6.5): a request is
listed and answerable only once its `NodeActionRequested` is appended, and an answer is
appended before the workload is told. A request whose record cannot be appended is
answered `cancelled` and never listed; an `answer` whose record cannot be appended is
refused `resource_unavailable` and the request stays pending. Records carry sizes and
`BLAKE3-256` digests, never a summary, detail or note: a control plane binds what it saw
to the sealed log by hashing the UTF-8 bytes of what `actions` returned.

**Pause, stop, revoke, the budget and a restart.** While the attempt is paused its requests
stay pending and their wait clocks stop, so a pause never makes one expire; the control
plane may still list and answer, and the reply is read once the workload runs again. When
the attempt ends every pending request is answered `cancelled`, recorded before
`NodeAttemptEnded`. A node restart recovers every attempt that may have been running as
`exited` (§6.4); before it serves, it answers `cancelled` every request the attempt's log
shows unanswered, before `NodeAttemptRecovered`.

**`actions`** is read-only and has no `operation_id`: the attempt's state and its pending
requests, oldest first, each with the node's request number (`action`, what `answer`
names), the workload's `id`, the kind, the summary and detail, and the milliseconds left
before it expires (frozen while paused). It is served for every state; only a `running`
or `paused` attempt has pending requests. Its answer is read within 1 MiB, not the 64 KiB
line bound.

```json
{"request":"actions","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"}}
{"response":"actions","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"running","pending":[{"action":1,"id":"deploy-1","kind":"approval","summary":"deploy to staging","detail":"plan: rotate 3 services","expires_in_ms":298512}]}
```

**`answer`** is mutating and carries an `operation_id`; `decision` is `approved` or
`denied` (a control plane may not answer `expired` or `cancelled`), `note` is optional:

```json
{"request":"answer","protocol":{"major":1,"minor":3},"operation_id":10,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"action":1,"decision":"approved","note":"go ahead"}
{"response":"answered","protocol":{"major":1,"minor":3},"operation_id":10,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"action":1,"decision":"approved"}
```

Both are refused with a `rejected` response spelled like a lifecycle refusal (§6.1), with
`operation_id` `null` for `actions`:

| Reason | When |
| --- | --- |
| `unsupported_operation` | The node was not started with `--action-channel`. Below 1.3 both requests are unknown and the connection closes without an answer. |
| `task_not_found`, `attempt_mismatch`, `lease_mismatch` | As for every verb (§8.3). |
| `invalid_state` | `answer` to an attempt that is not `running` or `paused`. |
| `unknown_request` | `answer` names a request number the attempt never recorded. |
| `already_answered` | `answer` to a request already answered: by an earlier `answer`, or `expired` or `cancelled` by the node. |
| `stale_operation` | `answer` reuses an operation id that applied a different answer. |
| `resource_unavailable` | The answer could not be appended to the evidence log; nothing changed and the request is still pending. |

Replaying an `answer` with the same operation id and the same request, decision and note
is answered `answered` again and appends nothing, also once the attempt has ended. The
applied answer ids live in the node process: after a node restart the attempt has ended
and a replay is `invalid_state`; the log is the durable record of what was answered.

**Authority, and what an approval is.** An `answer` is authorised like every verb: by the
exact binding, on a socket the node serves only to its own uid and its listed client uids
(§2.1, §3). It is not signed per request (#262). The channel grants nothing by itself: an
approval of a workload's own request is a statement the node records and relays, which the
workload acts on because it chose to wait for it, and widens no capability, credential or
network. What the node does enforce is a hold (§6.9): a request it opened itself for a
capability the manifest holds, whose approval is what releases that capability.

### 6.8 Brokered credentials

A node started with `--credentials` (§2.1) honours a manifest's `credentials` grant
(§7.5) by leasing, for the attempt, a credential for each granted service from the
provider its operator configured, and having the attempt's egress proxy inject it
([ADR-0034](decisions/ADR-0034-node-brokered-credentials.md)). The control plane names a
service, never a secret; the secret never enters the sandbox.

**The operator's file.** One TOML file, the node user's own, writable by no one else:

```toml
[provider.bao]
kind = "openbao"                          # or "vault": the same HTTP API
address = "https://bao.internal:8200"     # TLS required
token_file = "/etc/ward-node/bao.token"   # 0600, the node user's; the node's provider token
ca_bundle = "/etc/ward-node/bao-ca.pem"   # optional; the host trust store otherwise
timeout_ms = 2000                         # every provider call; at most 5000 on a node
max_ttl_secs = 3600                       # the longest lease this provider may issue

[service.artifacts]
provider = "bao"
engine = "token"                          # a token role; or "kv" with mount, path, field
role = "ward-artifacts"
permissions = ["artifacts-read"]          # the lease's policies; "write" opens writes
max_ttl_secs = 900                        # the longest `ttl_secs` the node honours for it
renew = false                             # renew the lease while the attempt runs
upstream = "artifacts.example.com:443"    # the only place the credential goes, over TLS
header = "authorization"
value_prefix = "Bearer "
paths = ["/v1/repos/acme"]                # the resource paths the route may reach
```

The provider tables are those of the session broker (credential-broker.md §5.1), with the
same checks on the address and the token file. A service name is `[a-z][a-z0-9-]{0,31}` and
its upstream host a lowercase DNS name; at least one service is required.

**What the workload does.** It sends an ordinary HTTP/1.1 request to the attempt's proxy
socket (`WARD_PROXY_SOCKET`, §9) for the path `/<service>/…`:

```text
GET /artifacts/v1/repos/acme/latest HTTP/1.1
Host: artifacts.example.com
```

The proxy strips `/<service>`, forwards the request over TLS to the service's `upstream`
with the configured header set to `value_prefix` and the leased value (replacing any
header of that name the workload sent), within the service's `paths` and read-only unless
the service's permissions include `write`, and streams the answer back
(credential-broker.md §4, route scope). Nothing is added to the sandbox's environment,
files or sockets; a `CONNECT` tunnel is never injected into, and a request to any other
host carries nothing the proxy added. Each such request is a `NetworkRequested` verdict in
the evidence log (§6.5).

**The lease.** Issued at `start`, before the spawn, bound to the attempt (the provider's
session is the attempt id), the service and the upstream host as its audience; it lives at
most the shortest of the grant's `ttl_secs`, the service's and the provider's maximum, and
the attempt's wall-clock budget. With `renew = true` the node renews it once a third of its
period is left, never past that maximum; a renewal that fails stops renewing it and it runs
out on time. While the attempt is paused its proxy refuses every request (§9), so nothing
is injected. Past its expiry, and as soon as the attempt ends, the route answers `403`
before anything is resolved or connected.

**Revocation.** When the attempt ends — its exit, the budget, `stop`, `revoke`, an
ambiguous launch, a `revoke` whose reap is not confirmed — the node withdraws every route
at once and revokes every lease at its provider, recording each before `NodeAttemptEnded`
(§6.5). The revocation handles of the attempt's live leases (token accessors, never the
leased values) are kept in `<task-root>/<task>/<attempt>.credentials/leases.json` (mode
0600 in a 0700 directory beside the workspace) from before the spawn until they are
revoked; a node restarted after it died revokes every lease it finds there before it
serves, recorded before `NodeAttemptRecovered`. A lease the provider cannot revoke at the
source (a KV read) ends with its route.

**Provider outage.** A provider that cannot serve issues nothing: the attempt still runs,
its request for `/<service>/…` is answered `403 Forbidden` with the body `credential lease
expired` and recorded as a `NetworkDenied` verdict, and the grant's `CredentialDenied`
record names the provider's state. There is no fallback to another credential. A control
plane reads the denial from the evidence log, or from the workload's own outcome.

### 6.9 Approval holds

A node started with `--approval-hold` (§2.1) honours a manifest's `hold` (§7.5): hosts of
its `network.custom` and services of its `credentials` that the node holds until the
control plane approves them ([ADR-0035](decisions/ADR-0035-node-approval-hold.md)). The
manifest needs an `actions` grant naming `approval`, since the node asks through the
attempt's action channel (§6.7).

**What the workload sees.** Nothing new is added to the sandbox. A request through the
attempt's proxy (§9) for a host a held pattern covers — a credential route to that host
included — or on a held service's route is refused `403 Forbidden` before anything is
resolved, connected to or injected, with one of four bodies:

| Body | When |
| --- | --- |
| `held for approval` | The node's request for the capability is waiting for an answer. The workload retries at its own pace. |
| `approval denied` | The control plane answered `denied`. Final for the attempt. |
| `approval expired` | Nobody answered within the grant's `wait_secs`. Final for the attempt. |
| `approval cancelled` | The request was cancelled (the attempt ended, the channel closed, or its record could not be appended). Final for the attempt. |

Once the request is answered `approved`, and the answer recorded, the capability is
released for the rest of the attempt: its requests go through the proxy as any allowlisted
request does. Hosts and services the hold does not name are never refused by it. While the
attempt is paused the proxy refuses everything `503 paused by ward` (§9) and the hold's
wait clock stands still.

**What the control plane sees.** The first request the proxy sees for a held capability
opens one `approval` request on the attempt's channel; a request touching several held
capabilities opens each. It is listed by `actions` like a workload's, once its
`NodeActionRequested` is recorded, with the id `hold:<n>` (the capability's place in the
hold, hosts first, then services, from 1), the summary `network <pattern>` or
`credential <service>`, a fixed detail, and one more field naming the capability:

```json
{"action":3,"id":"hold:1","kind":"approval","summary":"network deploy.example.com","detail":"the node refuses requests to deploy.example.com until this is approved","expires_in_ms":291250,"hold":{"host":"deploy.example.com"}}
```

`hold` is `{"host": pattern}` or `{"service": name}` and appears only on a request the node
opened; a workload's request never carries it, and a workload request under an id
`hold:1`…`hold:<count>` of its attempt is refused `duplicate_id`. The node's requests count
against neither the workload's `max_pending` nor its `max_total`, so a listing holds at
most 8 of the workload's and 8 of the hold's, and their numbers may run past `max_total`.
Answer them with `answer` (§6.7): `approved` releases exactly the capability that request
was opened for, `denied` keeps it refused. Every rule of `answer` holds: a replay applies
nothing new, the same operation id with another answer is `stale_operation`, an answer to
another number releases only that request's capability, and an answer after the request
ended is `already_answered` (or `invalid_state` once the attempt has).

**Evidence.** The request and its answer are `NodeActionRequested` and
`NodeActionAnswered` (§6.5), recorded before the request is listed and before anything is
released; an answer whose record fails is `resource_unavailable` and releases nothing. Each
refusal is a `NetworkDenied` verdict for the destination with the reason `PolicyDeny` and
the rule `hold:<state>:<n>` (`held`, `denied`, `expired` or `cancelled`, and the request
number), or `hold:cancelled` for a capability the closed channel never asked about;
verdicts are drained from the proxy's bounded queue like every verdict (§6.5). A log reader
ties them together by the request number and by hashing the summary.

**Stop, revoke, the budget and a restart.** When the attempt ends, every pending request,
the hold's included, is answered `cancelled` before `NodeAttemptEnded` (§6.7). A restarted
node runs no attempt (§6.4): it answers `cancelled` every request the log shows unanswered
before `NodeAttemptRecovered`, an approval recorded before the crash stays the log's
account of what was released, and a retry is a new attempt whose holds start held.

### 6.10 Hosted agent adapters

A node started with `--agent-adapter <id>` (§2.1) runs a workload whose envelope names
that adapter (`workload.adapter`, §7.3) through `ward-agent-adapter`'s contract 1.0
(agent-integration.md §10, [ADR-0036](decisions/ADR-0036-node-hosted-agent-adapters.md)).
The adapters a node can host are `claude-code` (Claude Code, hooks `full`), `codex` (the
Codex CLI, hooks `none`) and `process` (any program, hooks `none`).

**The launch.** At `start` the node builds the launch with the contract's shared builder
(`ward_agent_adapter::catalogue::launch`, which `ward claude` and `ward codex` use too):
`argv[0]` is the program the adapter runs (a name on the sandbox `PATH` or an absolute
path), followed by the adapter's fixed arguments (none for the shipped adapters) and the
rest of the argv. The adapter adds its non-secret environment (Claude Code:
`CLAUDE_CONFIG_DIR=/home/agent/.claude` and its telemetry switches; Codex:
`CODEX_HOME=/home/agent/.codex`) and its settings files (Claude Code:
`/home/agent/.claude/settings.json`, wiring its hooks), written mode 0600 into
`<task-root>/<task>/<attempt>.adapter/` and bound read-only at their path. Nothing an
adapter declares can name a mount, a network rule, a credential, a working directory or a
variable the node owns (`HOME`, `PATH`, `TERM`, `WARD_*`, proxy settings): the workspace,
the network namespace, the proxy and its allowlist, the leased credentials, the holds,
the action channel, the cgroup and the empty environment are the manifest's, exactly as
for a workload naming no adapter. The capability manifest is not involved in naming the
adapter, so one manifest serves every adapter.

**The provider.** Claude Code's provider is `anthropic`, Codex's `openai`; the node
records it and reads no model key from its own environment. A runtime reaches its model
API only through a manifest `credentials` grant (§6.8) for a service the operator
configured — by convention named after the provider, for example `[service.anthropic]`
with `upstream = "api.anthropic.com:443"`, `header = "x-api-key"`, `value_prefix = ""`,
`paths = ["/v1/messages"]` and `write` among its `permissions` (a model API is a `POST`,
which a read-only route refuses) — at `/<service>/…` on `WARD_PROXY_SOCKET`, the lease
injected by the attempt's proxy and held when the manifest holds it (§6.9). The grant is
the manifest's, so it is the same for every adapter.

**The shim and the relay.** On a node started with `--agent-shim` (§2.1,
[ADR-0037](decisions/ADR-0037-node-agent-shim-and-relay.md)) every attempt of a hosted
adapter runs under the operator's `ward-agent` shim, bound read-only at
`/run/ward/ward-agent`, which hardens the sandbox (Landlock read-write on `/work`, `/env`,
`/tmp` and `/home/agent`, read-only on the system directories and itself; seccomp; no
capabilities; only the variables the node names) before it runs the adapter's command
line. Claude Code's seeded hooks run `/run/ward/ward-agent hook`, which sends the
contract's line to the hook socket below. When the attempt has an egress proxy the shim
also relays `127.0.0.1:3128`, inside the attempt's network namespace, to the proxy's
socket, and the node sets:

| Variable | Value | When |
| --- | --- | --- |
| `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` | `http://127.0.0.1:3128` | the attempt has an egress proxy |
| `NO_PROXY`, `no_proxy` | `localhost,127.0.0.1` | the same |
| `ANTHROPIC_BASE_URL` (Claude Code), `OPENAI_BASE_URL` (Codex) | `http://127.0.0.1:3128/anthropic`, `http://127.0.0.1:3128/openai/v1` | the manifest grants `credentials` for the service named after the adapter's provider |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | `ward-gateway`, a placeholder the route replaces | the same |

The relay is a pipe to the socket the workload already has: every request through it is
the proxy's to allow, refuse, inject or hold, and is recorded as one (§6.5, §9). Without a
grant for its provider the runtime gets no base URL, and a request for `/<provider>/…` is
the proxy's `400` (`proxy requires an absolute http:// URI`). A workload naming no
adapter, and every attempt on a node without the flag, runs without shim and relay.

**Hooks.** For an adapter whose capability document declares semantic events (Claude
Code), the node listens on `<task-root>/<task>/<attempt>.adapter/hooks.sock`, binds it at
`/run/ward/hooks.sock` and sets `WARD_SOCKET=/run/ward/hooks.sock`. One request per
connection, the contract's line (agent-integration.md §10.1):

```json
{"hook":"PreToolUse","tool":"Bash","summary":"make test"}
```

read within 4 KiB and 5 seconds, at most 8 connections at once; the answer is one line,

```json
{"decision":"allow","reason":"recorded by ward-node as a claim"}
```

and the line is recorded as an `AgentClaim` with origin `agent` (§6.5). A line outside the
contract (not one such object, an unknown hook, a tool on `SessionStart`, a field the
contract does not have, past 4 KiB or 5 seconds) gets zero bytes and is recorded nowhere.
The answer is steering: nothing the node enforces reads a claim, and an approval claimed
or answered here releases nothing; the approval the node enforces is a hold (§6.9). A
`PermissionRequest` is answered and recorded like every other line, never bridged onto the
action channel: what the node enforces is reached only through the proxy, where a hold
already gates each host and credential, and a bridged request would be worded by the agent
(ADR-0037 §5). A hookless adapter gets no socket and no `WARD_SOCKET`. The socket closes and the adapter's
directory is removed when the attempt ends.

**Evidence.** Right after `NodeAttemptLaunched` the node records the binding, `AgentClaim
{ Note }` with origin `agent` and payload

```json
{"agent_adapter":{"contract":"1.0","adapter":"codex","runtime":{"product":"OpenAI Codex CLI","version":"0.153.4"},"hooks":"none","events":[],"provider":"openai","model":"o4-mini"}}
```

where `runtime` is what the adapter declares (for `process`, the program's file name and
no version), `model` what `--model`/`-m` requested (first-party adapters only), `provider`
the adapter's. None of it is verified, and none of it is identity or authority.

**Not yet.** Without `--agent-shim` a real Claude Code's command hooks find nothing to run
(only a runtime that writes the contract's lines itself reaches the hook socket) and a
runtime that needs an HTTP base URL has none. The capability document does not say whether
a node relays; no CI run drives a real runtime against a model.

## 7. The admission envelope

### 7.1 Shape

The envelope is a JSON object. Shown pretty-printed; whitespace and key order are free
(§7.4). Every field is required except the lease's `parent_lease_id` and `delegated_by`,
which read as `null` when absent (send them explicitly), and `workload.adapter`, which is
absent for a workload naming no agent adapter (§7.3); unknown or duplicate fields are
refused at every level.

```json
{
  "binding": {
    "task": "task_01M45YYRG00001249248SK6H24",
    "attempt": "exec_01M45YYRG00005ANB6CSVQF248",
    "lease": "lease_01M45YYRG00009K6DANAXVQK6C"
  },
  "agent": "agent_01M43CJ1G0000DVQFEXVZZY001",
  "node": "node_01M3KY5QG0000028T5CY4TQKFF",
  "session": "sess_01M45YYRG0000FXQ5TK1V58CGG",
  "authority": {
    "lease": {
      "id": "lease_01M45YYRG00009K6DANAXVQK6C",
      "delegation_id": "deleg_01M45YYRG000016NWVVWJ6HB70",
      "issuer": "prn_01M1RQ16G00000Y3RF1W7GY3RF",
      "subject": "agent_01M43CJ1G0000DVQFEXVZZY001",
      "task": "task_01M45YYRG00001249248SK6H24",
      "parent_lease_id": null,
      "delegated_by": null,
      "grants": [
        {
          "capability": "repo.read",
          "resource": "repo:example/project",
          "delegable": false
        },
        {
          "capability": "repo.write",
          "resource": "repo:example/project",
          "delegable": false
        }
      ],
      "issued_at_unix_ms": 1791201600000,
      "expires_at_unix_ms": 1791205200000,
      "version": 1
    },
    "lineage": []
  },
  "workload": {
    "argv": [
      "sh",
      "-c",
      "make test"
    ],
    "capability_manifest": {
      "hash": "eb3e889be30ae8dd712a52c33e37aaca72e52ccff1aa770ecbd962d0cdb0d0c3",
      "bytes": "7b226e6574776f726b223a226f66666c696e65227d"
    },
    "snapshot": "c19c769fdd8644df9167a36d0133289c9fa44a8c768cd0aafa1756a13fb3e33b",
    "wall_clock_budget_ms": 600000
  },
  "issued_at_unix_ms": 1791201600000,
  "expires_at_unix_ms": 1791202500000,
  "version": 1
}
```

### 7.2 Identifiers and encodings

| Kind | Form |
| --- | --- |
| Ids | Prefix + 26-character ULID in upper-case Crockford base32 (`0-9`, `A-Z` without `I`, `L`, `O`, `U`; first character `0`–`7`). Prefixes: `task_`, `exec_` (execution attempt), `lease_`, `agent_`, `node_`, `sess_`, `deleg_`, `prn_` (principal). Lower case is refused. |
| Times | Unix milliseconds as JSON integers (`*_unix_ms`). `issued_at` is inclusive and `expires_at` exclusive; `expires_at` must be strictly greater. |
| Hashes | 64 lower-case hex digits, no prefix: `capability_manifest.hash`, `snapshot`, `proof.issuer_key_id`. |
| Byte strings | Lower-case hex: `capability_manifest.bytes` (decoded bytes) and `proof.signature`. There is no base64 anywhere. |
| Hex case | Every hex value, in the envelope, the proof and the trust store (§2.2), is written and accepted in lower case only, so a signed or hashed value has one spelling. An upper-case or mixed-case digit is refused: in the envelope it fails decoding (`authority_denied`), in the proof the request is malformed (no response, §3). |

### 7.3 Fields

| Field | Type and bounds |
| --- | --- |
| `binding` | `{"task","attempt","lease"}`; must equal the `admit` request's `binding`. |
| `agent` | `agent_…`; must equal `authority.lease.subject`. |
| `node` | `node_…`; the audience, must equal the node's `--node-id`. |
| `session` | `sess_…`; recorded in the attempt's receipt, not otherwise checked. |
| `authority.lease` | The lease that authorises this task (below). Its `id` must equal `binding.lease` and its `task` `binding.task`. |
| `authority.lineage` | Array of 0–16 ancestor leases, nearest parent first, ending at the root. Empty when `lease` is itself a root. Always present. |
| `workload.argv` | Array of 1–256 strings; `argv[0]` (the program, resolved on the sandbox `PATH`) non-empty; each entry at most 4 096 bytes, all entries together at most 16 384 bytes; no NUL. Never truncated: anything over a bound is refused. |
| `workload.capability_manifest` | `{"hash","bytes"}`: `bytes` is the hex of 1–8 192 manifest bytes and `hash` is `BLAKE3-256` of those decoded bytes. The decoded bytes must be one manifest in the grammar of §7.5: a manifest outside it fails envelope decoding (`authority_denied`), and one that asks for a grant this node does not honour is refused `unsupported_grant`. |
| `workload.snapshot` | 64 lower-case hex digits: exactly the line `ward-node snapshot import` printed (§2.4). Must be in the node's store at `start`. |
| `workload.wall_clock_budget_ms` | Integer ≥ 1. Mandatory; the workload is killed when it is reached, measured from spawn. |
| `workload.adapter` | Optional (new in this revision of 1.3; a node of an earlier revision fails to decode an envelope that carries it). `{"id": "<adapter>"}`: run the argv as that agent adapter (§6.10). `id` is 1–64 bytes of `a-z 0-9 . _ -`, starting with a letter or digit, and the only field; with it, `argv[0]` must be a name on the sandbox `PATH` or an absolute path. Outside this grammar the envelope fails decoding (`authority_denied`); an id the node does not host is refused `unsupported_grant`. Absent, it is not sent: never `null`. |
| `issued_at_unix_ms`, `expires_at_unix_ms` | Envelope validity at the node clock, checked at `admit` and again at `start`. It does not bound a running workload; the budget does. |
| `version` | Integer ≥ 1, strictly greater than the last version the node durably accepted for this **task** (not attempt), across restarts. |

A lease (`authority.lease` and each `lineage` entry):

| Field | Type and bounds |
| --- | --- |
| `id`, `delegation_id` | `lease_…`, `deleg_…` |
| `issuer` | `prn_…`, the root principal; identical along the lineage. The root lease's `issuer` must be the principal the signing key is bound to in the trust store (§2.2). |
| `subject` | `agent_…`, the agent holding the lease. |
| `task` | `task_…`; identical along the lineage. |
| `parent_lease_id`, `delegated_by` | Both `null` for a root lease; for a delegated lease the parent's `id` and the parent's `subject`. |
| `grants` | Non-empty array of `{"capability","resource","delegable"}`. `capability`: 1–64 bytes of `a-z 0-9 . _ -`, starting with a letter or digit. `resource`: 1–256 printable ASCII bytes, no spaces. Sorted by `capability`, then `resource`, then `delegable` (`false` first), byte-wise, with no two entries for the same capability and resource. |
| `issued_at_unix_ms`, `expires_at_unix_ms` | Lease validity; `expires_at` strictly greater. |
| `version` | Integer ≥ 1. |

A delegated lease must be a contraction of its parent: its grants a subset of the
parent's delegable grants, its lifetime inside the parent's, its `version` greater, its
`id` and `delegation_id` different. Every lease in the chain must be valid at the node
clock. A delegated example (`authority` only):

```json
{
  "lease": {
    "id": "lease_01M45YYRG00009K6DANAXVQK6C",
    "delegation_id": "deleg_01M45YYRG000016NWVVWJ6HB70",
    "issuer": "prn_01M1RQ16G00000Y3RF1W7GY3RF",
    "subject": "agent_01M43CJ1G0000DVQFEXVZZY001",
    "task": "task_01M45YYRG00001249248SK6H24",
    "parent_lease_id": "lease_01M45YYRG00000000000000001",
    "delegated_by": "agent_01M45YYRG00000000000000003",
    "grants": [
      {
        "capability": "repo.read",
        "resource": "repo:example/project",
        "delegable": false
      }
    ],
    "issued_at_unix_ms": 1791201600000,
    "expires_at_unix_ms": 1791205200000,
    "version": 2
  },
  "lineage": [
    {
      "id": "lease_01M45YYRG00000000000000001",
      "delegation_id": "deleg_01M45YYRG00000000000000002",
      "issuer": "prn_01M1RQ16G00000Y3RF1W7GY3RF",
      "subject": "agent_01M45YYRG00000000000000003",
      "task": "task_01M45YYRG00001249248SK6H24",
      "parent_lease_id": null,
      "delegated_by": null,
      "grants": [
        {
          "capability": "repo.read",
          "resource": "repo:example/project",
          "delegable": true
        }
      ],
      "issued_at_unix_ms": 1791201600000,
      "expires_at_unix_ms": 1791208800000,
      "version": 1
    }
  ]
}
```

### 7.4 Signing rule and test vector

The proof is a detached Ed25519 signature (RFC 8032, pure Ed25519) over **the UTF-8
bytes of the `envelope_json` string value as sent**: the string your JSON library places
in the request, before it is escaped into the request line and after the node unescapes
it. There is no canonicalisation. Serialise the envelope once, sign those bytes, and
embed that same string; never re-serialise after signing.

```text
envelope_json = json_encode(envelope)                 # any key order, any whitespace
signed_bytes  = utf8_encode(envelope_json)            # 1..32768 bytes, valid UTF-8
signature     = ed25519_sign(issuer_private_key, signed_bytes)     # 64 bytes
key_id        = blake3_256(issuer_public_key)                       # 32 raw key bytes in
request = {
  "request": "admit",
  "protocol": {"major": 1, "minor": 3},
  "operation_id": op_id,
  "binding": envelope.binding,
  "envelope_json": envelope_json,                     # the same string, as a JSON string
  "proof": {"issuer_key_id": lower_hex(key_id), "signature": lower_hex(signature)}
}
send(connection, json_encode(request) + "\n")         # one line, at most 65536 bytes
```

The envelope is limited to 32 KiB before escaping, and the escaped request line to
64 KiB; an envelope dense in quotes or backslashes can pass the first and fail the
second.

Test vector. **The key is a public test key** (the Ed25519 private seed is 32 bytes of
`0x07`, as in the node's own tests); never put it in a production trust store.

| Item | Value |
| --- | --- |
| Public key | `ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c` |
| Key id | `0871f3aabc26e4582c508af5c03884e6a96f0989d1dd8cfb49cd17ed25792433` |
| Signed bytes | the 1203-byte string below, without a trailing newline |
| Signature | `c2336bf71cc42af7222a4f736ac991c830cb560d1aa1af8241a3356ab58a8f23cb236ef558b113832d81ca3114de958b55c24eb6e45b317db3c05fac5bc26002` |

```json
{"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"agent":"agent_01M43CJ1G0000DVQFEXVZZY001","node":"node_01M3KY5QG0000028T5CY4TQKFF","session":"sess_01M45YYRG0000FXQ5TK1V58CGG","authority":{"lease":{"id":"lease_01M45YYRG00009K6DANAXVQK6C","delegation_id":"deleg_01M45YYRG000016NWVVWJ6HB70","issuer":"prn_01M1RQ16G00000Y3RF1W7GY3RF","subject":"agent_01M43CJ1G0000DVQFEXVZZY001","task":"task_01M45YYRG00001249248SK6H24","parent_lease_id":null,"delegated_by":null,"grants":[{"capability":"repo.read","resource":"repo:example/project","delegable":false},{"capability":"repo.write","resource":"repo:example/project","delegable":false}],"issued_at_unix_ms":1791201600000,"expires_at_unix_ms":1791205200000,"version":1},"lineage":[]},"workload":{"argv":["sh","-c","make test"],"capability_manifest":{"hash":"eb3e889be30ae8dd712a52c33e37aaca72e52ccff1aa770ecbd962d0cdb0d0c3","bytes":"7b226e6574776f726b223a226f66666c696e65227d"},"snapshot":"c19c769fdd8644df9167a36d0133289c9fa44a8c768cd0aafa1756a13fb3e33b","wall_clock_budget_ms":600000},"issued_at_unix_ms":1791201600000,"expires_at_unix_ms":1791202500000,"version":1}
```

The complete `admit` request line:

```json
{"request":"admit","protocol":{"major":1,"minor":3},"operation_id":2,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"envelope_json":"{\"binding\":{\"task\":\"task_01M45YYRG00001249248SK6H24\",\"attempt\":\"exec_01M45YYRG00005ANB6CSVQF248\",\"lease\":\"lease_01M45YYRG00009K6DANAXVQK6C\"},\"agent\":\"agent_01M43CJ1G0000DVQFEXVZZY001\",\"node\":\"node_01M3KY5QG0000028T5CY4TQKFF\",\"session\":\"sess_01M45YYRG0000FXQ5TK1V58CGG\",\"authority\":{\"lease\":{\"id\":\"lease_01M45YYRG00009K6DANAXVQK6C\",\"delegation_id\":\"deleg_01M45YYRG000016NWVVWJ6HB70\",\"issuer\":\"prn_01M1RQ16G00000Y3RF1W7GY3RF\",\"subject\":\"agent_01M43CJ1G0000DVQFEXVZZY001\",\"task\":\"task_01M45YYRG00001249248SK6H24\",\"parent_lease_id\":null,\"delegated_by\":null,\"grants\":[{\"capability\":\"repo.read\",\"resource\":\"repo:example/project\",\"delegable\":false},{\"capability\":\"repo.write\",\"resource\":\"repo:example/project\",\"delegable\":false}],\"issued_at_unix_ms\":1791201600000,\"expires_at_unix_ms\":1791205200000,\"version\":1},\"lineage\":[]},\"workload\":{\"argv\":[\"sh\",\"-c\",\"make test\"],\"capability_manifest\":{\"hash\":\"eb3e889be30ae8dd712a52c33e37aaca72e52ccff1aa770ecbd962d0cdb0d0c3\",\"bytes\":\"7b226e6574776f726b223a226f66666c696e65227d\"},\"snapshot\":\"c19c769fdd8644df9167a36d0133289c9fa44a8c768cd0aafa1756a13fb3e33b\",\"wall_clock_budget_ms\":600000},\"issued_at_unix_ms\":1791201600000,\"expires_at_unix_ms\":1791202500000,\"version\":1}","proof":{"issuer_key_id":"0871f3aabc26e4582c508af5c03884e6a96f0989d1dd8cfb49cd17ed25792433","signature":"c2336bf71cc42af7222a4f736ac991c830cb560d1aa1af8241a3356ab58a8f23cb236ef558b113832d81ca3114de958b55c24eb6e45b317db3c05fac5bc26002"}}
```

Its timestamps are fixed (2026-10-05T12:00:00Z plus 15 minutes), so a live node refuses
it as `lease_expired` after that window; use it to check your encoding and signature,
then sign fresh envelopes. A node with this key bound to
`prn_01M1RQ16G00000Y3RF1W7GY3RF` in its trust store (the line of §2.2) and `--node-id
node_01M3KY5QG0000028T5CY4TQKFF` admits an envelope built the same way with current
timestamps.

### 7.5 Capability manifest

`workload.capability_manifest.bytes` decodes to exactly one JSON object in this grammar,
the manifest grammar of protocol 1.3. Whitespace and key order are free (the hash and the
signature cover the bytes as sent); an unknown or repeated field, a value outside the
grammar, and anything that is not one object fail envelope decoding (`authority_denied`,
§8.1 step 7).

| Field | Values |
| --- | --- |
| `network` | Required. `"offline"`: no network. Or `{"custom": [patterns]}`: egress to the listed hosts only. The spelling is `ward-policy`'s `network` capability (`offline`, `!custom`). |
| `network.custom` | 1–64 host patterns, no repeats, in `ward-policy`'s host grammar: a lowercase DNS name (`github.com`), or `*.` and a name (`*.crates.io`), which covers any name with at least one more label and never the name itself. Labels are 1–63 characters of `a-z 0-9 -`, neither starting nor ending with `-`; a name is at most 253 bytes. Lower case only, so a signed pattern has one spelling. |
| `output` | Optional (new in this revision of 1.3; a node of an earlier revision fails to decode a manifest that carries it). `{"stdio_bytes": N, "files": [paths], "files_bytes": M}`, all three required: return the first `N` bytes of each of stdout and stderr, and the declared `files` with up to `M` bytes of content in all (§6.6). |
| `output.stdio_bytes`, `output.files_bytes` | Integers ≥ 0. The grammar bounds neither; the node honours at most 1 MiB (1 048 576) per stream and 8 MiB (8 388 608) of file content, and refuses a larger grant `unsupported_grant`. `0` is a grant too: the streams come back empty with their dropped counts. |
| `resources` | Optional (new in this revision of 1.3; a node of an earlier revision fails to decode a manifest that carries it). `{"cpu_millis": N, "memory_bytes": M, "pids": P}`, each field optional and at least one present: the limits the node must enforce on the attempt's whole process tree through its cgroup (§9). An absent field is not limited by the grant. |
| `resources.cpu_millis` | Integer ≥ 1: CPU time per second of wall clock, in thousandths of one CPU (`cpu.max`; `1000` is one full CPU). The node honours at most 1 000 per logical CPU it reports in `capacity`. |
| `resources.memory_bytes` | Integer ≥ 1: memory the tree may use, tmpfs writes included (`memory.max`), with no swap where the kernel accounts swap (`memory.swap.max` `0`); a tree that passes it is killed whole (`memory.oom.group`). The node honours at most the `capacity.memory_bytes` it reports. |
| `resources.pids` | Integer ≥ 1: processes and threads that may exist in the tree at once, bubblewrap's own included (`pids.max`); a fork past it fails. The node honours at most 65 536. |
| `actions` | Optional (new in this revision of 1.3, like `output`). `{"kinds": [kinds], "max_pending": P, "max_total": T, "wait_secs": W}`, all four required: give the attempt an action channel for the listed kinds, with at most `P` requests waiting at once, `T` in the attempt's lifetime, each answered `expired` after `W` seconds (§6.7). |
| `actions.kinds` | 1–2 of `approval` and `decision`, no repeats. Any other kind fails envelope decoding. |
| `actions.max_pending`, `actions.max_total`, `actions.wait_secs` | Integers ≥ 1, with `max_pending` ≤ `max_total`. The node honours at most 8 pending, 64 in all and 3600 seconds (its capability document says so, §5), and refuses a larger grant `unsupported_grant`. |
| `credentials` | Optional (new in this revision of 1.3, like `output`). An array of 1–4 grants `{"service": S, "host": H, "ttl_secs": T}`, all three required, no service twice: lease service `S`'s credential for the attempt, for at most `T` seconds, injected by the attempt's egress proxy into requests for `H` only (§6.8). |
| `credentials[].service` | 1–32 bytes, `[a-z][a-z0-9-]*`: a service the node's operator configured. |
| `credentials[].host` | A lowercase DNS name in the `network.custom` host grammar, without a wildcard and not an address literal, that one of the manifest's own `network.custom` patterns covers; so a manifest with `credentials` names `network.custom`. A host outside the allowlist fails decoding. |
| `credentials[].ttl_secs` | Integer ≥ 1. The node honours at most the service's `max_ttl_secs`, and refuses a larger grant `unsupported_grant`; the lease is shorter still when the attempt's budget is. |
| `hold` | Optional (new in this revision of 1.3, like `output`). `{"hosts": [patterns], "services": [names]}`, each list optional but non-empty when present, at least one present: the capabilities the node holds until the control plane approves the request it opens for each (§6.9). The manifest must carry an `actions` grant naming `approval`. |
| `hold.hosts` | Patterns of the manifest's own `network.custom`, each exactly as written there (a name a `*.` pattern covers is not one), no repeats. |
| `hold.services` | Services of the manifest's own `credentials`, no repeats. Together with `hosts`, at most 8 entries. |
| `output.files` | 0–64 paths, no repeats, each 1–255 bytes of `a-z A-Z 0-9 . _ - /`, relative to the workspace root, with no empty, `.` or `..` component, no leading or trailing `/` and no `//`. Exact paths only: no globs, no directories. A path outside the grammar (`../x`, `/etc/passwd`, a space) fails envelope decoding. |

The node honours a decoded grant only if its capability document (§5) says it can
enforce it: `offline` always, `custom` only when `network.proxy_allowlist` is `true`,
which a node started with `--network-allowlist` reports (§2.1), and `output` only when
`output.stdio` and `output.files` are `true`, which a node started with
`--output-return` reports, and only within the ceilings above, `resources` only when
every limit it names has its flag `true` in the document's `resources` section, which a
node started with `--cgroup-root` reports, and only within the ceilings above, and
`actions` only when the document carries an `actions` section offering every listed kind,
which a node started with `--action-channel` reports, and only within its ceilings, and
`credentials` only when `credentials.proxy_injection` is `true`, which a node started with
`--credentials` reports, and only for a service its operator configured, for that service's
host and within its ceiling, and `hold` only when `actions.hold` is `true`, which a node
started with `--approval-hold` reports; the
workload then runs behind the attempt's own egress proxy allowing exactly the listed
patterns (§9), its output is kept and returned as §6.6 says, its process tree is held to
the limits as §9 says, its channel is served as §6.7 says, its credentials are leased
and injected as §6.8 says, and its held capabilities are refused until approved as §6.9
says. A
manifest that asks for a grant the node does not honour is refused `unsupported_grant`
(§8.1 step 16): the node refuses what it cannot enforce
rather than run the workload with less than its manifest says. The refusal comes after
authority is proven and before the version is written, so it consumes no version;
re-admit under the same version with a manifest the node honours.

```json
{"network":"offline"}
```

Hex `7b226e6574776f726b223a226f66666c696e65227d`, `BLAKE3-256`
`eb3e889be30ae8dd712a52c33e37aaca72e52ccff1aa770ecbd962d0cdb0d0c3`: the manifest of the
§7.4 test vector, and the only manifest a node without `--network-allowlist` admits.

```json
{"network":{"custom":["github.com","*.crates.io"]}}
```

Decodes; honoured on a node started with `--network-allowlist`, refused
`unsupported_grant` on any other.

```json
{"network":"offline","output":{"stdio_bytes":4096,"files":["out/report.json","big.bin"],"files_bytes":2048}}
```

Decodes; honoured on a node started with `--output-return`, refused `unsupported_grant`
on any other, as is `{"stdio_bytes":1048577,…}` on every node.

```json
{"network":"offline","resources":{"cpu_millis":500,"memory_bytes":268435456,"pids":64}}
```

Decodes; honoured on a node started with `--cgroup-root` whose `resources` section
reports `cpu`, `memory` and `pids` `true` and whose `capacity` is at least half a CPU and
256 MiB, refused `unsupported_grant` on any other. `{"network":"offline","resources":{}}`,
a limit of `0`, a `null` limit and an unknown limit (`"disk_bytes"`) fail decoding
(`authority_denied`).

```json
{"network":"offline","actions":{"kinds":["approval"],"max_pending":2,"max_total":8,"wait_secs":300}}
```

Decodes; honoured on a node started with `--action-channel`, refused `unsupported_grant`
on any other, as is `{"max_pending":9,…}` on every node.

```json
{"network":{"custom":["artifacts.example.com"]},"credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":600}]}
```

Decodes; honoured on a node started with `--network-allowlist` and `--credentials` whose
file configures `artifacts` with that upstream host and a `max_ttl_secs` of at least 600,
refused `unsupported_grant` on any other.

```json
{"network":{"custom":["deploy.example.com"]},"actions":{"kinds":["approval"],"max_pending":1,"max_total":1,"wait_secs":300},"hold":{"hosts":["deploy.example.com"]}}
```

Decodes; honoured on a node started with `--network-allowlist`, `--action-channel` and
`--approval-hold`, refused `unsupported_grant` on any other.

```json
{"network":"development"}
```

`ward-policy`'s presets are not in the grammar: the envelope fails decoding
(`authority_denied`), as do `{}`, `{"network":{"custom":[]}}`,
`{"network":"offline","output":{"stdio_bytes":1,"files":["../x"],"files_bytes":1}}`,
`{"network":"offline","actions":{"kinds":["credential"],"max_pending":1,"max_total":1,"wait_secs":1}}`,
an `actions` grant with no kind, a zero bound or `max_pending` above `max_total`,
`{"network":"offline","credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":600}]}`
(no allowlist covers the host), a `credentials` grant naming a header, a provider or a
secret, an empty `credentials` list, a zero `ttl_secs` or a wildcard host, a `hold` naming
a host that is not one of the manifest's `network.custom` patterns or a service that is not
one of its `credentials`, a `hold` without an `actions` grant naming `approval`, an empty
`hold` or hold list, and any manifest with a field other than `network`, `output`,
`resources`, `actions`, `credentials` and `hold`.

## 8. Verification order and rejection reasons

### 8.1 `admit`

The node applies these checks in order; the first failure is the answer and nothing
changes (no version is consumed, nothing is materialised).

| # | Check | Refusal |
| --- | --- | --- |
| 1 | The task is registered | `task_not_found` |
| 2 | The request's attempt and lease equal the registered binding | `attempt_mismatch`, `lease_mismatch` |
| 3 | Replay of the admit that succeeded (§6.3) | `accepted`, current state |
| 4 | The task is `created` | `invalid_state` |
| 5 | `proof.issuer_key_id` is in the trust store | `authority_denied` |
| 6 | The signature verifies over the `envelope_json` bytes | `authority_denied` |
| 7 | `envelope_json` decodes strictly (every field, bound and encoding of §7) | `authority_denied` |
| 8 | The root lease's `issuer` (the last `lineage` entry, or `authority.lease` when the lineage is empty) is the principal the signing key is bound to (§2.2) | `authority_denied` |
| 9 | Envelope `binding` equals the request's: task / attempt / lease | `authority_denied` / `attempt_mismatch` / `lease_mismatch` |
| 10 | Envelope `node` is this node | `authority_denied` |
| 11 | `issued_at_unix_ms <= now` / `now < expires_at_unix_ms` | `authority_denied` / `lease_expired` |
| 12 | `version` is greater than the last accepted for the task | `stale_operation` |
| 13 | The lineage promotes from its root: root shape, non-empty grants, every delegation rule of §7.3, each lease valid now | `lease_expired` for an expired lease, otherwise `authority_denied` |
| 14 | Lease `task` / `id` / `subject` equal binding task / binding lease / `agent` | `authority_denied` / `lease_mismatch` / `authority_denied` |
| 15 | No revocation (§2.5) covers the lease or an ancestor | `lease_revoked` |
| 16 | Every grant in the decoded capability manifest is one this node honours (§7.5): `{"network":"offline"}` always, `{"network":{"custom":[…]}}` only when the node reports `network.proxy_allowlist` (§5), an `output` grant only when the node reports `output` and the grant is within the node's ceilings (§6.6), a `resources` grant only when the node reports every limit it names in `resources` and the grant is within the node's ceilings (§7.5), an `actions` grant only when the node reports `actions` and within its ceilings (§6.7), a `credentials` grant only when the node reports `credentials.proxy_injection`, for services its operator configured, their hosts and within their ceilings (§6.8), a `hold` only when the node reports `actions.hold` (§6.9); and a `workload.adapter` only when the node lists it in `adapters.hosted` and can build its launch from the argv (§6.10) | `unsupported_grant` |
| 17 | The version is written durably | `resource_unavailable` (write failed) |

On success the task is `ready` and holds the envelope for `start`.

### 8.2 `start`, `stop`, `pause`, `resume`, `revoke`, `seal` and `create`

Each of the six execution verbs is `unsupported_operation` without `--task-root` (and on a
1.2 connection), before anything else is checked.

`start`: checks 1–2; replay; not
`ready` → `invalid_state`; envelope `issued_at` in the future → `authority_denied`;
envelope or lease expired → `lease_expired`; revoked → `lease_revoked`; on a node started
with `--max-running`, as many attempts executing as the bound, or available memory or
disk below its floor → `capacity_exhausted`, a floor that cannot be measured →
`resource_unavailable`, both with the task still `ready` and nothing materialised;
snapshot missing
from the store, the attempt's workspace already existing (`<task-root>/<task>/<attempt>/`),
the attempt's cgroup not created or its limits not written (`--cgroup-root`), or the
sandbox failing to spawn → `resource_unavailable` with the task still `ready`.

`stop`: checks 1–2; replay; `ready` → `stopped`; `running` or `paused` → kill
(continuing a paused tree first, after which the task reads `running`, §6.2), wait up to
10 seconds for the reap, then `stopped`, or `resource_unavailable` if still running (the
task reads `running` and the kill stays pending), or `invalid_state` if the workload
exited first; any other state → `invalid_state`. The answer is written after the wait,
whatever it took (§3).

`pause`: checks 1–2; replay; not `running`, or a kill of it is pending →
`invalid_state`; 128 pauses already taken by the attempt → `resource_unavailable`; then
the node sends `SIGSTOP` to every process of the workload's tree (rooted at the sandbox's
outer `bwrap`, children first) and waits up to 1 second until each is stopped, ended or
held in vfork wait on a stopped child, freezing anything forked meanwhile. Confirmed → `paused`. Not confirmed in time, or the workload ended → the node
sends `SIGCONT` to everything it stopped and answers `resource_unavailable`, with the task
still `running`. The freeze is by signal only; no cgroup freezer is used.

`resume`: checks 1–2; replay; not `paused`, or a kill of it is pending → `invalid_state`;
then `SIGCONT` to the tree, parents first, and up to 1 second for no process of it to be
left stopped. Confirmed (or the workload already gone) → `running`; otherwise
`resource_unavailable` with the task still `paused`.

`revoke`: checks 1–2; replay; not `ready`, `running` or `paused` → `invalid_state`; then
the revocation of the binding's lease is written to `revocations.json` (§2.5) unless one
already in effect is recorded, and a failed write, or a store that would exceed 8 MiB →
`resource_unavailable` with nothing changed. Only then: `ready` → `revoked`; `running` or
`paused` → kill (continuing a paused tree first, after which the task reads `running`),
wait up to 10 seconds for the reap, then `revoked`. Unlike `stop`, `revoke`
is answered `revoked` even if the reap is not confirmed in time (the receipt is then
`unknown` and the node keeps killing) and even if the workload ends on its own before the
kill lands (the receipt then records what the reaper observed): the authority is gone
either way.

`seal`: checks 1–2; replay; not `exited`, `stopped` or `revoked` → `invalid_state`;
otherwise `sealed`. Nothing is written to disk and the workspace is not removed.

`create`: a retired attempt (§6.1) → `stale_operation`; then check 2 and the replay rule
of §6.3, with a new attempt replacing a finished one (§6.1) once the replaced attempt id is
durably retired (`resource_unavailable` with nothing changed if it cannot be). A new task
when the node already holds 1 024 tasks evicts the task sealed longest ago; with no sealed
task to evict it is refused `resource_unavailable`.

### 8.3 Rejection reasons

| Wire string | Meaning |
| --- | --- |
| `task_not_found` | No task with this `task` id is registered (never created, or evicted after a `seal`). A restart forgets no task (§6.4). |
| `attempt_mismatch` | The task is registered, or the envelope is bound, under another execution attempt; for `create`, the current attempt has not finished yet. |
| `lease_mismatch` | The task is registered, or the envelope is bound, under another lease id, or the envelope's lease `id` is not the binding's lease. |
| `lease_expired` | The envelope or a lease is past its expiry at the node clock. |
| `lease_revoked` | A durable revocation, from `revocations.json` or recorded by `revoke`, covers the lease or an ancestor. |
| `stale_operation` | The request is stale and nothing was done. From `admit`: the envelope `version` is not greater than the last version the node durably accepted for the task (an old or replayed envelope, also after a restart). From `pause` or `resume`: the `operation_id` took effect earlier and a later operation of the same verb has superseded it (§6.3). From `create`: the attempt was replaced by a later attempt of the task and is retired (§6.1). |
| `invalid_state` | The task is not in a state that allows the verb, or another operation already did it. From `result`: the attempt has not ended yet (§6.6). |
| `authority_denied` | Untrusted key, bad signature, malformed envelope (a capability manifest outside the grammar of §7.5 included), a root lease `issuer` that is not the principal bound to the signing key, wrong audience, not yet valid, or authority that does not cover the task or agent. |
| `unsupported_grant` | From `admit` only: the envelope's capability manifest decodes but asks for a grant this node cannot honour (§7.5): a `network.custom` allowlist on a node without `--network-allowlist`, an `output` grant on a node without `--output-return` or above its ceilings (§6.6), a `resources` grant on a node without `--cgroup-root`, naming a limit whose controller the node has not enabled, or above its ceilings, an `actions` grant on a node without `--action-channel` or above its ceilings (§6.7), or a `credentials` grant on a node without `--credentials`, for a service its operator did not configure, a host other than that service's upstream host, or a `ttl_secs` above the service's ceiling (§6.8), or a `hold` on a node without `--approval-hold` (§6.9). The task stays `created` and no version is consumed; re-admit under the same version with a manifest the node honours. Protocol 1.3 and later. |
| `capacity_exhausted` | From `start` only, on a node started with `--max-running` (§2.1): the node already executes as many attempts as its bound, or the host's available memory or the task root's available disk is below the configured floor. Nothing changed: the task stays `ready`, nothing is materialised or recorded; send the same `start` again once an attempt has ended (§6.1). New in this revision of 1.3: a strict decoder of an earlier revision does not know the string, which is why only a node started with `--max-running` sends it. |
| `resource_unavailable` | Registry full with no sealed task to evict, snapshot missing, workspace exists, spawn failed, a state write failed or would exceed its bound (admission version, revocation, retired attempt or task record), an evidence record could not be appended (§6.5), stop not confirmed in time, a pause or resume not confirmed, or an attempt's 128 pauses used up. From `result`: no stored result exists for the ended attempt (§6.6). |
| `unsupported_operation` | The verb is not implemented (`stream`), or not enabled on this node or connection (no `--task-root`, or protocol 1.2; `result` without `--output-return`; `actions` and `answer` without `--action-channel`). |

## 9. Receipts

The node records one receipt per attempt (binding, session and outcome) when the attempt
ends (`exited`, `stopped` or `revoked`) and keeps it in the task's durable record. At 1.3, `inspect` of an
`exited`, `stopped`, `revoked` or `sealed` task reports the outcome; `seal` keeps the
receipt, so a sealed task reports the outcome its attempt ended with. A 1.1 or 1.2
connection never sees an outcome. A receipt survives a node restart (§6.4); it is lost
when a new attempt replaces its attempt and when its sealed task is evicted: read the
outcome before then.
The attempt's evidence log (§6.5) records the same outcome in its `NodeAttemptEnded` or
`NodeAttemptRecovered` record and outlives both. `ward-node audit` (§2.6) prints the
receipt outcome beside the authority chain the attempt was admitted under.

| Outcome | When |
| --- | --- |
| `completed` | `exited`: the sandbox exited with status 0 before the budget, with no stop. `revoked`: the same, observed by the reaper while the revoke was being served, before its kill landed. |
| `failed` | `exited`: non-zero exit status, termination by a signal the node did not send, or killed at the wall-clock budget (also while paused). `stopped`: killed and reaped by `stop`, or stopped from `ready` without running. `revoked`: killed and reaped by `revoke`, revoked from `ready` without running, or a non-zero exit or budget kill observed before the kill landed. |
| `unknown` | `exited`: the launch was ambiguous (the spawn was not confirmed within 30 seconds, a process may have started before the launch failed, or the spawned process could not be recorded), the node lost the child while waiting, or the node restarted while the attempt may have been executing (§6.4). `stopped`: the child was lost while a stop was pending. `revoked`: the reap was not confirmed within 10 seconds, or the child was lost. |

The workload runs in bubblewrap with the workspace bound writable at `/work` (its working
directory), a private `/tmp` and `/home/agent`, read-only system directories, a network
namespace holding only loopback, and only `HOME`, `PATH`, `TERM` and `PWD` set (`PWD` is
bubblewrap's, set to `/work` when it enters the working directory; nothing of the node's
own environment is passed on), plus, for a workload naming an agent adapter, that
adapter's own variables and, for one with hooks, `WARD_SOCKET` (§6.10). Output is drained; without an `output` grant none of it
is kept, and with one (on a node started with `--output-return`) the first `stdio_bytes`
of each stream are kept and returned by `result` with the declared files (§6.6).

Without `--cgroup-root` the node creates no cgroup for a workload: the wall-clock budget
is its only bound and nothing it uses is measured. With it (§2.1), the node creates
`<cgroup-root>/<attempt>` before the spawn, writes the manifest's `resources` limits there
(`cpu.max` as quota and period, a 100 ms period stretched to one second below the
kernel's 1 ms minimum quota; `memory.max`, `memory.swap.max` `0` and `memory.oom.group`
`1` where the kernel has them; `pids.max`), and spawns through a host `/bin/sh` that stops
itself until the node has moved it into that cgroup and only then executes `bwrap`; a move
that fails kills the shell and refuses the `start` `resource_unavailable` with nothing run.
Bubblewrap and every process of the sandbox are therefore created inside the cgroup; the
sandbox has no cgroup filesystem (no `/sys` is bound) and, where the kernel supports one,
a cgroup namespace rooted at that cgroup (bubblewrap's `--unshare-cgroup-try`), so
nothing in it can move itself out.
When the workload has been reaped the node kills whatever is left in the cgroup
(`cgroup.kill`, or `SIGKILL` to each member), reads the counters it records (§6.5) and
removes the cgroup. CPU time, peak memory and peak pids are the kernel's own counters for
the whole tree, including anything the reap killed.

An `offline` manifest (§7.5) binds nothing else: there is no route off the host. A
`network.custom` manifest, on a node started with `--network-allowlist` (§2.1), runs the
attempt behind its own egress proxy: the node starts a `ward-proxy` instance for the
attempt, in the node process and as the node's uid, listening on a Unix socket under
`<task-root>/<task>/<attempt>.egress/` (mode 0700, beside the workspace, never inside
it), binds that socket into the sandbox at `/run/ward/proxy.sock` and sets exactly one
more variable, `WARD_PROXY_SOCKET=/run/ward/proxy.sock`. The proxy speaks `CONNECT
host:port` (an opaque tunnel; TLS is never intercepted) and absolute-URI plain-HTTP
forwarding, with the session proxy's rules
([ADR-0014](decisions/ADR-0014-sandbox-egress-relay.md)): exactly the manifest's host
patterns pass; IP literals, private, link-local, loopback, multicast and reserved ranges
and the cloud metadata endpoint are refused whatever the allowlist says; every address a
name resolves to is checked and the connection goes only to a checked address, so a
rebinding answer gains nothing; a refusal is `403` with a fixed body that names no
allowlist entry. Raw TCP, UDP and DNS still have no path: the network namespace is
unchanged and the proxy is the one way out. Every verdict is recorded in the attempt's
evidence log as `NetworkRequested` or `NetworkDenied` (§6.5). `pause` makes the proxy
answer every new connection `503 paused by ward` and hold established relays until
`resume`; `stop`, `revoke`, the budget kill and the attempt's own exit shut it down and
unlink the socket; a node restart ends it with the node. A workload reaches the proxy
through the socket `WARD_PROXY_SOCKET` names; only a hosted adapter's attempt on a node
with `--agent-shim` also has a loopback relay to it and `HTTP_PROXY` naming that (§6.10). A `credentials` grant, on a node started with `--credentials`,
adds the attempt's credential routes to that proxy (§6.8); nothing else injects a
credential, and nothing about one is bound into the sandbox. A `hold`, on a node started
with `--approval-hold`, has the proxy ask the attempt's action channel about every request
for an allowlisted host or on a credential route before it is resolved, connected to or
injected, and refuse a held one `403` by name until its approval is recorded (§6.9); a
host the policy refuses is refused by the policy first.

An `actions` manifest, on a node started with `--action-channel` (§2.1), binds one more
socket: the attempt's action channel, from `<task-root>/<task>/<attempt>.actions/`
(mode 0700, beside the workspace) at `/run/ward/actions.sock`, and sets
`WARD_ACTION_SOCKET=/run/ward/actions.sock`. It is not a network path: the node reads
only the bounded request lines of §6.7 on it and answers only those, and nothing on it
reaches the node's protocol socket.

## 10. Failure semantics an adapter must handle

- **No response.** EOF without a response line is a fail-closed malformed request, the
  10-second request deadline expiring before the request line arrived, or the answer
  deadline expiring because the client did not read (§3). Any mutating verb (`create`,
  `admit`, `start`, `pause`, `resume`, `stop`, `revoke`, `seal`) may still have taken
  effect. Inspect, then replay with the same `operation_id`.
- **Slow `start`, `stop` and `revoke`.** A slow verb is answered, not cut off: a `start`
  whose spawn is not confirmed within 30 seconds is answered `accepted` with `exited`
  (ambiguous, below); a `stop` whose reap is not confirmed within 10 seconds is answered
  `resource_unavailable` (replay it with the same `operation_id`; a task that was
  `paused` reads `running` meanwhile and refuses `pause` and `resume`, §6.2); a `revoke` whose reap
  is not confirmed within 10 seconds is still answered `accepted` with `revoked`, with an
  `unknown` receipt, while the node keeps killing. Keep the connection open and reading
  until the answer arrives (§3).
- **Pause refused.** `pause` reports `paused` only once the whole process tree is
  confirmed stopped. If the freeze cannot be confirmed within 1 second (or the workload
  ended meanwhile), the node continues everything it stopped and answers
  `resource_unavailable`; the task stays `running` and its workload keeps running. Retry
  with the same `operation_id`, or `stop` or `revoke` it. A refused `resume` leaves the
  task `paused`; retry it, or `stop` or `revoke` it (both continue the tree before the
  kill).
- **Paused is not suspended time.** The wall-clock budget keeps running while a task is
  paused, and the reaper keeps watching it: a paused task whose budget runs out is killed
  and becomes `exited` with `failed`. Pausing never extends a budget.
- **Revoke is durability-first.** `revoke` writes the revocation of the binding's lease
  to `revocations.json` before anything else changes; if that write fails, or the store
  would exceed 8 MiB (§2.5), the answer is `resource_unavailable`, nothing changed and the
  workload keeps running. Once written it
  holds across restarts: no later `admit` or `start` under that lease, or under any lease
  delegated from it, is accepted (`lease_revoked`). Its scope is the named task only: a
  lease is bound to one task, so other tasks, their leases and the lease's ancestors are
  untouched, and nothing else running on the node is stopped. A retry of a revoked task
  therefore needs a lease that neither is the revoked one nor descends from it. A `revoke`
  of a `created`, `exited`, `stopped` or `sealed` task is `invalid_state` and records
  nothing; to revoke such a lease, use `revocations.json` (§2.5).
- **Ambiguous launch.** `accepted` with `exited`, or `inspect` showing `exited` with
  `unknown`, means the attempt may have had effects. It is never re-run: its workspace
  exists, so any later `start` of the same attempt is refused. Retry it as a new attempt
  (below).
- **Retry.** A retry is a new attempt of the same task. Once the current attempt is
  `exited`, `stopped`, `revoked` or `sealed`, `create` the same task under a new attempt
  id, `admit` a new envelope bound to it with a higher `version`, and `start` it; its
  workspace is `<task-root>/<task>/<new-attempt>/`. The new attempt replaces the old one
  in the registry: the old binding then reads `attempt_mismatch` and its state and
  receipt can no longer be inspected, so read the outcome first. The old attempt id is
  retired durably: a late or replayed `create` for it is refused `stale_operation`, also
  after a restart or an eviction (§6.1). While the current attempt is `created`, `ready`,
  `running` or `paused`, the `create` is refused `attempt_mismatch`; stop or revoke it
  first. A task takes at most 256 replacements; after that a new attempt is refused
  `resource_unavailable`. Never reuse an attempt id.
- **Stop or revoke racing exit.** Exactly one terminal state wins. If the workload exited
  on its own before a `stop` took effect, the task is `exited` with its real outcome and
  the `stop` is answered `invalid_state`; inspect to read it. A `revoke` served while the
  task is `running` or `paused` always ends in `revoked`.
- **Node restart.** Tasks, receipts and applied operation ids survive (§6.4). An attempt
  that was `running` or `paused`, or whose `start` was in flight, reads `exited` with
  outcome `unknown` and is never run again; its sandbox died with the node or was killed
  when the node came back. A `ready` task reads `created` and needs a new `admit` with a
  higher `version`. Replays are answered as before the restart and never act. Treat a
  `stop` or `revoke` that got no answer before the restart as not applied: inspect, and
  read the outcome.
- **Versions.** Keep a durable, strictly increasing version per task in the control
  plane. It is per task, not per attempt: a new attempt's envelope needs a version higher
  than every one accepted for the task before, across attempts, evictions and restarts.
  Every successful `admit` consumes one; refused admits (`unsupported_grant` included) do
  not, except one refused `resource_unavailable` because its evidence record could not be
  appended (§6.5).
- **A lost `result` answer.** `result` is read-only: ask again with the same request. It
  answers the same bytes for as long as the attempt is registered, so there is nothing to
  replay and nothing it can have changed. The shipped driver asks once more and otherwise
  ends the run `unknown`, so a control plane that asked for output never records a run as
  complete without it (§11.2).
- **Clocks.** Validity is judged at the node clock at `admit` and at `start`; no other
  verb rechecks it. Leave margin for skew and for the delay between the two.
- **Capacity exhausted.** `capacity_exhausted` from `start` is backpressure, not an
  error: the task is still `ready` and its admission still valid until it expires. Keep
  the attempt in the control plane's own queue and send the same `start` (same
  `operation_id`) again once one of the node's attempts has ended; read `scheduling` in
  the capability document (§5) to see when. A start retried after the envelope expired is
  `lease_expired`; admit a new envelope then.
- **Capacity.** The node holds at most 1 024 tasks. `exited`, `stopped` and `revoked`
  tasks count until they are sealed; seal each finished task once you have read its
  outcome. When a `create` for a new task finds the registry full, the node evicts the
  task sealed longest ago (oldest first); with no sealed task it answers
  `resource_unavailable`. An evicted task reads `task_not_found`; its admission version
  and any revocation stay in the node state, so it can be created again but admitted
  only with a higher version. A new attempt of a known task replaces it in place and
  needs no room.
- **Disk.** The node never removes a workspace that ran (not on `stop`, `revoke`, `seal`,
  eviction or restart), so that an attempt is never started twice, and never removes a
  stored result or an evidence log. Reclaim task-root space out of band, and only for
  attempt ids you will never send again; a stored result is at most about 14 MiB (its
  ceilings, base64-encoded).

## 11. Client and adapter

WardOS ships one implementation of this contract for the control-plane side, in the
`ward-node-client` crate (`crates/ward-node-client`):

- `UnixTransport`: the framing of §3 over the local socket, one connection per request,
  both request lines written at once, both bounds (64 KiB each way) enforced, a `connect`
  timeout (until the node has accepted the connection and answered the handshake) and a
  `request` timeout (until the verb's answer; default 90 seconds, §3). EOF before the
  handshake answer is `ClosedWithoutResponse`; EOF after it is "no response", which the
  client reports for the verb as "unknown whether it took effect" (§10).
- `TlsTransport`: the same over TCP with mutual TLS to a node started with `--listen-tls`
  (§3, ADR-0038), from `TlsSettings`: the node's address, the name its certificate must
  carry, the server CA, this client's certificate and key (mode `0600` or `0400`) and,
  optionally, the node's pinned key. The TLS handshake counts against the `connect`
  timeout. A node whose certificate is not from the server CA, not for the name or not the
  pinned key, and a node that refuses this client's certificate, are
  `TransportError::Tls` with the reason; nothing is sent to a node that is not
  authenticated.
- `Client`: negotiates once, offering 1.3 up to the highest minor this revision
  implements (today 1.3–1.3), and refuses with a typed error a node that offers nothing
  in that window (`HandshakeRejected`) or accepts a version below 1.3 (`ProtocolTooOld`).
  Every later connection must be accepted at exactly the negotiated version. It reads the
  capability document (§5) and sends `create`, `admit`, `start`, `pause`, `resume`,
  `stop`, `revoke`, `seal`, `inspect` (§6), `result` (§6.6, read within the 16 MiB
  result bound rather than the 64 KiB line bound), and `actions` (read within 1 MiB) and
  `answer` (§6.7), decoding each answer strictly and refusing one that names another
  binding, operation id or request number than the request.
- `IssuerKey`: the control plane's Ed25519 issuer key, loaded from a 32-byte seed file
  that must be a regular file of mode `0600` or `0400` (any other mode is refused), or
  from seed bytes. It prints its public key and key id (§2.3) and the trust-store line
  binding it to a principal (§2.2), and signs the exact bytes of a serialised envelope as
  §7.4 prescribes; its unit test reproduces the §7.4 vector byte for byte.
- `EnvelopeInput`: the envelope of §7.1 as the control plane writes it, with the
  capability manifest given as its object (`{"network":"offline"}`, which is also the
  value when it is left out) instead of hash and bytes. Building it refuses every value
  outside §7.3, an envelope that would not fit the wire, and a lease that is not the
  binding's lease, not bound to the binding's task, or not held by the envelope's agent,
  before anything is signed. Nothing else has a default: authority, lease, workspace
  (snapshot) and budget are the control plane's inputs.
- `Driver::run_attempt`: `create` → `admit` → `start` → poll `inspect` → read the receipt
  → `seal` → `result` when the envelope's manifest carried an `output` grant, with the
  rules below, returning an `AttemptReport`.

Beside the crate, `examples/node-control-plane` is a reference implementation of the
control-plane side in plain Node.js (>= 22, no dependencies): ids and their derivation
from a control plane's own ids (§7.2), the issuer key and proof with `node:crypto` (§2.3,
§7.4, reproduced byte for byte in its tests), the envelope (§7), a durable per-task
version (§7.3, §10), the adapter conversation of §11.4 with cancellation, replay and
the outcome mapping, result return (§6.6, §7.5) with every returned digest verified,
and the action channel (§6.7, §7.5): the `actions` grant within the ceilings, `actions`
and `answer`, and an answer loop on a second adapter beside the `run` whose answers take
their operation ids from the run's scheme and are recorded before they are sent;
`scripts/acceptance/node-js.sh` proves it against a real node. It
is the worked example for [node-integration-from-nodejs.md](node-integration-from-nodejs.md).

### 11.1 Operator requirements for a client host

Over mutual TLS (§3) the client runs wherever it reaches the node's `--listen-tls`
address, as any user that can read its own key; the rest of this section is the socket's
case. A remote client cannot read the node's evidence logs (`task_root` in a `run` is then
left out) and cannot run `ward-node snapshot import`: the snapshot is imported on the
node's host, and the id travels to the control plane.

The client runs where the node runs, under the node's own Unix identity or under a uid
the operator listed with `--client-uid`. Without `--client-group` the socket is mode
`0600` in a `0700` directory, so only the node's uid can connect; with it the socket is
`0660` in a `0750` directory owned by that group, so the group's members can connect,
and the node then serves only its own uid and the listed uids, closing every other peer
unread (§2.1, §3). The state directory and task root are `0700` either way: a listed
client can speak to the node but cannot read its state, its records or its evidence
logs, which is the point of running it as a second user. The host needs bubblewrap with
unprivileged user namespaces for the node to execute at all. `ward-node snapshot import` (§2.4) runs as the node's uid
against the node's `--state-dir`; the id it prints is the envelope's `workload.snapshot`.
Give `start`, `stop` and `revoke` a read timeout of 60 seconds or more (`start` waits up
to 30 seconds for the spawn after copying the snapshot, `stop` and `revoke` up to 10
seconds for the reap, §3); the adapter's `--timeout-ms` defaults to 90 000. Reading an
attempt's evidence log (§6.5) needs the node's uid (a listed client uid is not enough)
and the node's `--task-root`.

### 11.2 Fail-closed rules of the driver

- **Operation ids are the caller's.** Every mutating verb takes its id from an
  `OperationIds` scheme the caller supplies. The default scheme is `create` 1, `admit` 2,
  `start` 3, `stop` 4, `revoke` 5, `seal` 6, with `pause`/`resume` counting up from 7;
  `{"start_at": N}` shifts the whole scheme, and every id can be set explicitly.
- **Replay never acts twice.** A control plane that restarts replays the run with the
  same ids and the same signed bytes. The node answers each replayed id with the task's
  current state and acts on nothing (§6.3); the replayed `admit` needs byte-identical
  `envelope_json` and proof, which is why the adapter prints and sends exactly the bytes
  it was given. A replay of a run that already ended sends `create`, `admit` and `seal`
  (each answered `sealed`) and no `start`: there is nothing to start, and the workload
  never runs again.
- **Cancellation is `revoke`, never `stop`.** When the caller's lease or deadline is
  withdrawn (`CancelToken`, or `SIGTERM` to the adapter), the driver revokes the attempt
  (from `ready` without starting it, or killing a live workload) and seals it. The
  revocation is durable: nothing under that lease, or a lease delegated from it, can be
  admitted or started again (§10).
- **The budget is bounded.** The driver polls `inspect` from `start` until an ended state
  (`exited`, `stopped`, `revoked`, `sealed`), with bounded backoff: the interval starts at
  `poll_interval` (default 250 ms) and doubles up to `max_poll_interval` (default 2 s).
  A workload still running past its budget plus a grace (default 60 s) is revoked and the
  report says `deadline_exceeded`.
- **A lost answer is recovered once, as §10 says.** When a connection closes without an
  answer or times out, the driver inspects, then replays the same request with the same
  operation id, once. A second failure, or a connection that cannot be opened at all, ends
  the run: the report has `outcome` `unknown`, `outcome_certain` `false` and the
  `transport_error`; the driver never retries beyond that, never re-admits with another
  envelope and never starts a second attempt (ADR-0030 §6). Replay the run with the same
  ids once the node answers again.
- **A refusal ends the run.** A `rejected` `create`, `admit`, `start` or `inspect` is
  reported as `outcome` `{"refused": {"verb", "reason"}}` with nothing further sent; the
  task stays where the node left it (`created` after a refused `admit`, `ready` after a
  refused `start`), and the control plane decides whether to retry the verb or revoke. A
  refused `revoke` or `seal` is recorded in `operations` with its reason.
- **`unknown` means failed.** `outcome_certain` is `false` exactly when `outcome` is
  `unknown` (the node's receipt was `unknown`, the transport failed, or the attempt never
  ended). A control plane maps it to failed; it never infers success.
- **The result is read once, after the seal, and only when it was granted.** When the
  envelope's manifest carries an `output` grant the driver sends `result` after `seal`
  (also on a replay of a sealed run, which is why a replay reports the same output) and
  puts the answer in the report's `output`; a refused `result` is recorded as a `rejected`
  event with `output` `null` and leaves the receipt and outcome as they were; a lost
  `result` answer is asked for once more and then ends the run `unknown`, like any other
  lost answer (§10). Without the grant the driver never asks.

### 11.3 The attempt report

`done` carries the report; the same struct is `AttemptReport` in Rust. Field by field:

| Field | Meaning |
| --- | --- |
| `binding` | The task, attempt and lease that ran. |
| `final_state` | The last state the node reported, or `null` if no verb was answered. |
| `outcome` | `completed`, `failed`, `unknown`, or `{"refused":{"verb":…,"reason":…}}`. |
| `outcome_certain` | `false` exactly when `outcome` is `unknown`. |
| `receipt` | The node's receipt outcome as inspected (§9), or `null`. |
| `cause` | What ended the attempt, read from the evidence log when `task_root` is given and the log is readable; spelled as `ward-events` spells `NodeAttemptEnd` (`{"Exited":{"code":0}}`, `"BudgetExceeded"`, `"Killed"`, `"Lost"`, `"Ambiguous"`, `"NotStarted"`, `"Unconfirmed"`), else `null`. |
| `sealed` | Whether the node confirmed `seal`. |
| `cancelled` | Whether the run was cancelled and revoked. |
| `deadline_exceeded` | Whether the workload outlived its budget plus the grace and was revoked. |
| `evidence_log` | `<task-root>/<task>/<attempt>.evidence/events.log` when `task_root` is given, else `null`. |
| `evidence_head` | The sealed log's head hash (64 hex digits) when the log is sealed, readable and verifies against its `HEAD`, else `null`. |
| `operations` | Every mutating verb sent, in order, with its `operation_id` and the node's `state` (accepted) or `reason` (rejected); a verb whose answer never arrived has neither. |
| `transport_error` | The transport failure that ended the run, or `null`. |
| `output` | The attempt's bounded output as `result` returned it (§6.6: `stdout`, `stderr`, `files`), when the envelope's manifest carried an `output` grant and the node returned it; `null` otherwise, also after a refused `result`. |

### 11.4 The process adapter

`ward-node-adapter --socket <path> [--timeout-ms 90000] [--connect-timeout-ms 10000]`
reads one JSON command per line on stdin and writes one JSON event per line on stdout.
For a node started with `--listen-tls`, `--connect-tls <host:port> --tls-cert <file>
--tls-key <file> --tls-server-ca <file> --tls-server-name <name> [--tls-server-pin
sha256:<hex>]` takes the place of `--socket` (the two are exclusive) and every command
travels over mutual TLS (§3, §11); TLS files that cannot be used are an `error` event and
exit status 1 before any command is read.
Every output line carries `"schema":1`; stderr is diagnostics only. Commands:

| Command | Answer |
| --- | --- |
| `{"cmd":"capabilities"}` | `{"event":"capabilities","protocol":{"major":1,"minor":3},"capabilities":{…}}` (the §5 document). |
| `{"cmd":"run", …}` | The event stream below, ending in one `done`. |
| `{"cmd":"revoke","operation_id":N,"binding":{…}}` | `{"event":"verb","verb":"revoke","operation_id":N,"result":"accepted","state":…}` or `…,"result":"rejected","reason":…}`. |
| `{"cmd":"inspect","binding":{…}}` | `{"event":"inspected","state":…,"outcome":…}` or `{"event":"rejected","verb":"inspect","operation_id":null,"reason":…}`. |
| `{"cmd":"result","binding":{…}}` | `{"event":"result","state":…,"output":{…}}` (the §6.6 output) or `{"event":"rejected","verb":"result","operation_id":null,"reason":…}`. |
| `{"cmd":"actions","binding":{…}}` | `{"event":"actions","state":…,"pending":[…]}` (the §6.7 listing) or `{"event":"rejected","verb":"actions","operation_id":null,"reason":…}`. |
| `{"cmd":"answer","binding":{…},"request":N,"decision":"approved","operation_id":M}` | `{"event":"answered","operation_id":M,"request":N,"decision":…}` or `{"event":"rejected","verb":"answer","operation_id":M,"reason":…}` (§6.7). `decision` is `approved` or `denied`; an optional `"note"` is relayed to the workload. |
| anything else | `{"event":"error","error":"…"}`. |

`run` takes the attempt in one of two forms, never a mixture:

- **Pre-signed (the path for an external control plane):** `"envelope_json"` is the
  serialised envelope as a JSON string and `"proof"` is `{"issuer_key_id","signature"}`
  (§7.4). The control plane keeps its key and signs with its own library; the adapter
  only transports, sending exactly the bytes it was given. The binding and budget are read
  from those bytes, which must decode as one valid envelope (§7.3) or the command is an
  `error` and nothing is sent.
- **Signed here (a convenience for local use):** `"issuer_seed_file"` names the seed file
  of an `IssuerKey` (mode `0600` or `0400`) and `"envelope"` is an `EnvelopeInput`
  (§7.1 shape, manifest as its object or absent). The adapter builds, bounds and signs it.

Optional fields: `"operation_ids"` (`{"start_at":N}` or every id spelled out, default
the scheme of §11.2), `"poll_ms"`, `"max_poll_ms"`, `"grace_ms"` (defaults 250, 2000,
60000) and `"task_root"` (the node's `--task-root`, to report the evidence log, its
sealed head and the cause).

One run, as the adapter writes it (the envelope string shortened):

```json
{"cmd":"run","envelope_json":"{\"binding\":{\"task\":\"task_01M45YYRG00001249248SK6H24\",…},…}","proof":{"issuer_key_id":"0871f3aa…","signature":"c2336bf7…"},"operation_ids":{"start_at":20},"poll_ms":250,"task_root":"/var/lib/ward-node/tasks"}
```

```json
{"schema":1,"event":"state","verb":"create","operation_id":20,"state":"created"}
{"schema":1,"event":"state","verb":"admit","operation_id":21,"state":"ready"}
{"schema":1,"event":"admitted","envelope_json":"{\"binding\":{…},…}","proof":{"issuer_key_id":"0871f3aa…","signature":"c2336bf7…"}}
{"schema":1,"event":"state","verb":"start","operation_id":22,"state":"running"}
{"schema":1,"event":"receipt","state":"exited","outcome":"completed"}
{"schema":1,"event":"state","verb":"seal","operation_id":25,"state":"sealed"}
{"schema":1,"event":"evidence","path":"/var/lib/ward-node/tasks/task_01M45YYRG00001249248SK6H24/exec_01M45YYRG00005ANB6CSVQF248.evidence/events.log"}
{"schema":1,"event":"done","report":{"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"final_state":"sealed","outcome":"completed","outcome_certain":true,"receipt":"completed","cause":{"Exited":{"code":0}},"sealed":true,"cancelled":false,"deadline_exceeded":false,"evidence_log":"/var/lib/ward-node/tasks/task_01M45YYRG00001249248SK6H24/exec_01M45YYRG00005ANB6CSVQF248.evidence/events.log","evidence_head":"3ac2d55f…","operations":[{"verb":"create","operation_id":20,"state":"created","reason":null},{"verb":"admit","operation_id":21,"state":"ready","reason":null},{"verb":"start","operation_id":22,"state":"running","reason":null},{"verb":"seal","operation_id":25,"state":"sealed","reason":null}],"transport_error":null}}
```

The stream may also carry `{"event":"rejected","verb":…,"operation_id":…,"reason":…}`
for a refused verb, `{"event":"recovering","verb":…,"operation_id":…}` when a lost
answer is being recovered (§11.2), and, when the manifest granted `output`,
`{"event":"output","stdout_bytes":…,"stderr_bytes":…,"files":…,"truncated":…}` once the
result was read; the output itself is in `done`'s report (`output`, §11.3), not repeated
in the stream. The `admitted` event repeats the exact signed bytes
and proof so a caller that signed here can persist them and replay after its own
restart; a caller that pre-signed already holds them.

`SIGTERM` or `SIGINT` during a `run` cancels it: the attempt is revoked and sealed, the
`done` is written, and the adapter exits without reading further commands; while idle it
exits at once. A `run` holds its adapter until the attempt is sealed, so a control plane
whose workload asks through the action channel lists and answers from a second adapter
process (or its own client) while the first runs. The exit status is 0 when every command was well formed and answered (an
attempt that failed, was refused or ended `unknown` is still a clean answer: read `done`),
1 when an `error` event was written (a malformed command, an unreachable node for
`capabilities`, `revoke` or `inspect`, or a `run` refused before anything was sent), 2 for
bad flags. A command line is at most 256 KiB.

### 11.5 What an adapter cannot do yet

- Egress is HTTP(S) through the attempt's proxy socket only, and only on a node started
  with `--network-allowlist` (§7.5, §9): there is no loopback relay or `HTTP_PROXY` in
  the sandbox except for a hosted adapter on a node with `--agent-shim` (§6.10), and
  patterns are host-level. On any other node a manifest with
  `network.custom` is refused `unsupported_grant`.
- A credential reaches a workload only as a header the attempt's proxy injects on the
  route of a service the node's operator configured, on a node started with
  `--credentials` (§6.8); the adapter can grant it, never hand a token to the workload,
  and learns of a provider outage only from the evidence log or the workload (#267).
- Output comes back only as a bounded result on a node started with `--output-return`
  (§6.6): the head of each stream up to 1 MiB and the files the manifest declared by exact
  path, up to 8 MiB of content, with digests for the rest. There is no tail, no streaming
  while the attempt runs, no globs or directories, and no workspace export: what the
  workload wrote beyond the declared files stays under `<task-root>/<task>/<attempt>/`,
  readable only on the host as the node's uid (`snapshots.read` and `snapshots.diff` are
  `false`).
- There is no event stream (`stream`); progress is what `inspect` reports. The action
  channel (§6.7) carries bounded questions out and answers in, on a node started with
  `--action-channel`; an approval of a workload's own request is a recorded statement,
  not something the node enforces, and no credential reaches the workload through it.
  What the node enforces is a hold (§6.9), on a node started with `--approval-hold`, and
  only on an allowlisted host or a brokered credential: anything else the workload does
  (a file it writes, a command it runs) is not held.

The honest integration shape today is therefore running governed tool actions and
verification runs, an `argv` over a snapshot with a budget, through the node, reading the
receipt, the bounded result and the evidence log, and not hosting a whole agent runtime
whose conversation loop needs streamed output or credentials inside the sandbox; a loop
that needs approvals before it reaches a host or uses a credential gets them enforced by a
hold, and one that needs approvals for anything else can ask through the action channel and
must itself hold to the answer. Each of these gaps,
with its impact, the mitigation available today and the issue that closes it, is a row
of [node-security-limitations.md](node-security-limitations.md) §3.
