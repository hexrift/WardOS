# ward-node integration contract for external control planes

Status: living document. It describes the `ward-node` protocol 1.3 contract as
implemented today (ADR-0030 steps 1–9), and the client and process adapter that drive it
(§11). The cross-system acceptance suite that proves it against a real node (ADR-0030
step 10, #332 slice 9) is [node-acceptance.md](node-acceptance.md).

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
  Reaching the socket proves nothing; a signature by a trusted key is required.
- The node reads the capability manifest and honours only what it can enforce: every
  workload runs offline, so a manifest asking for egress is refused `unsupported_grant`
  at `admit` (§7.5) until the proxy-backed allowlist lands, never run offline silently.
- WardOS ships one client for this contract: the `ward-node-client` crate (a transport,
  a typed client, an issuer signer and a fail-closed attempt driver for Rust control
  planes) and its `ward-node-adapter` binary (the same over stdin/stdout for control
  planes in other languages), §11. Both run on the node's host, as the node's uid.
- Not implemented yet: that allowlist, an event stream (`stream`), and any remote
  transport or mTLS. The only transport is a local Unix socket; remote transport and key
  bootstrap are #262.

## 2. Operator setup

### 2.1 Running the node

```text
ward-node --socket <path> --state-dir <dir> --node-id <node_…> \
  [--trusted-issuers <file>] [--task-root <dir>]
```

| Flag | Required | Meaning |
| --- | --- | --- |
| `--socket` | yes | Unix socket to serve. Its parent directory must exist and have no group or other permission bits (0700 or stricter). The socket is created mode 0600. An existing path is never removed: delete a stale socket before restarting. |
| `--state-dir` | yes | Node-owned state, created mode 0700 if absent and refused if group- or world-accessible. Holds `node-id`, `admission-versions.json`, `revocations.json`, `retired-attempts.json`, the snapshot store `cas/` and `tasks/`, one record per registered task (`<task>.json`, mode 0600, in a directory created mode 0700) from which a restarted node recovers its registry (§6.4). |
| `--node-id` | yes | The node's audience id (`node_` + 26-character ULID). Pinned in `<state-dir>/node-id` at first start; a later start with another id is refused. Envelopes must name exactly this id. |
| `--trusted-issuers` | no | Trust store (§2.2). Without it no issuer is trusted and every `admit` is refused `authority_denied`. |
| `--task-root` | no | Directory under which the node allocates workspaces and keeps each admitted attempt's evidence log (§6.5), created mode 0700 and refused if group- or world-accessible or not a real directory. With it the node executes (`start`, `pause`, `resume`, `stop`, `revoke`, `seal`); the node refuses to start if bubblewrap is unusable. Without it, all six are `unsupported_operation` and no evidence log is kept. |

The node refuses to start on any unsafe or malformed input: a trust store, state file or
task record it cannot parse, wrong permissions, a pinned id mismatch. It serves until
killed.

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

## 3. Transport framing

- Unix stream socket, newline-delimited JSON: each message is one UTF-8 JSON object
  followed by `\n` (a preceding `\r` is tolerated). Responses are one line each.
- **One request per connection.** A connection carries exactly: the handshake line, its
  response, then at most one request line and its response. The node then closes it.
  Open a new connection per request. Both lines may be written at once.
- A request line is at most 64 KiB (65 536 bytes) excluding the newline; a longer line
  closes the connection.
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
host's; the other values are what the node reports today):

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
| `network.proxy_allowlist` | `false`: the node cannot enforce a host allowlist, so a manifest asking for one (`network.custom`, §7.5) is refused `unsupported_grant` at `admit`. |
| `snapshots.content_addressed` | `true` exactly when `lifecycle.start` is: workspaces are materialised from the node's content-addressed store (§2.4). |

Everything else (`isolation.backends`, `credentials`, `snapshots.diff`,
`snapshots.read`, `verifier`) is `false`: the node offers none of it yet. 1.1 and 1.2
documents keep their earlier content: they never carry `admit` or
`start`, report `stop`, `pause` and `revoke` as `false`, and report the execution flags
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
and nothing changed (a `pause` or `resume` undoes its freeze or thaw first). `start`
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
```

The directory (mode 0700, like `<task-root>/<task>/`) sits beside the attempt's workspace
`<task-root>/<task>/<attempt>/`, never inside it: the sandbox binds only the workspace,
so the workload cannot reach its log. Nothing else writes it.

The log uses the `ward-events` session-log format unchanged (`event-model.md` §5):
length-prefixed frames, each record hash-chained to the one before. Every record has
origin `node`. The chain is bound to the attempt: its session id carries the execution
attempt id's 128-bit value (`sess_` + the attempt's 26-character body), and its genesis
hash is BLAKE3 over the bytes `ward-node attempt evidence v1` and a NUL, followed by the
task, attempt and lease ids as 16 big-endian bytes each. Records, in order:

| Record | Written when | Carries |
| --- | --- | --- |
| `NodeAttemptAdmitted` | An `admit` took effect (again after a restart, under a higher version). | Task, attempt and lease ids, the receipt session, the `admit` operation id, the BLAKE3 digest of the exact envelope bytes, the issuer key id, the envelope version. |
| `NodeAttemptLaunched` | `start` confirmed its spawn. | The `start` operation id and the host pid. |
| `NodeAttemptIntervened` | A `pause` or `resume` took effect. | `pause` or `resume`, and the operation id. |
| `NodeAttemptEnded` | The attempt ended: natural exit, budget kill, a lost child, an ambiguous launch, a `stop` or `revoke` (from `ready`, or with its kill reaped, or a revoke whose reap was not confirmed). | The state (`exited`, `stopped`, `revoked`), the receipt outcome, the cause (exit code, budget, killed, lost, ambiguous, not started, unconfirmed) and the `stop` or `revoke` operation id. |
| `NodeAttemptRecovered` | The state the node holds differs from the state the log last shows: after a restart, before the node serves, and before sealing. | The state and outcome the node holds. |
| `NodeAttemptSealed` | `seal` took effect; the log is then sealed. | The `seal` operation id. |

Every record is metadata; workload output is never logged. A record is fsynced before the
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
end, recover and seal it always fit.

To verify a log, as an operator or a control plane with access to the host:

```text
ward replay --verify <task-root>/<task>/<attempt>.evidence/events.log
```

or, in Rust, `ward_events::LogReader::open(path)?.verify_all()?` compared with
`ward_events::log::parse_head` of `HEAD`, or `ward_node::evidence::verify(dir, binding)`,
which also checks the genesis, the session id and that every record has origin `node`.
`ward replay --json` prints one summary per record. The protocol does not carry the log
or its head: `inspect` and receipts are unchanged.

Retention is the operator's: the node never deletes an evidence log. A sealed task
evicted from the registry (§10, capacity) keeps its sealed log, and a replaced attempt
keeps its log, sealed or not, under its own attempt id. Remove `<task-root>/<task>/`
only once its logs have been read or archived.

## 7. The admission envelope

### 7.1 Shape

The envelope is a JSON object. Shown pretty-printed; whitespace and key order are free
(§7.4). Every field is required except the lease's `parent_lease_id` and `delegated_by`,
which read as `null` when absent (send them explicitly); unknown or duplicate fields are
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

The node honours a decoded grant only if its capability document (§5) says it can
enforce it: `offline` always, `custom` only when `network.proxy_allowlist` is `true`,
which no node reports yet. A manifest that asks for a grant the node does not honour is
refused `unsupported_grant` (§8.1 step 16): the node refuses what it cannot enforce
rather than run the workload with less than its manifest says. The refusal comes after
authority is proven and before the version is written, so it consumes no version;
re-admit under the same version with a manifest the node honours.

```json
{"network":"offline"}
```

Hex `7b226e6574776f726b223a226f66666c696e65227d`, `BLAKE3-256`
`eb3e889be30ae8dd712a52c33e37aaca72e52ccff1aa770ecbd962d0cdb0d0c3`: the manifest of the
§7.4 test vector, and the only manifest a node admits at this revision.

```json
{"network":{"custom":["github.com","*.crates.io"]}}
```

Decodes, and is refused `unsupported_grant` until the proxy-backed allowlist lands.

```json
{"network":"development"}
```

`ward-policy`'s presets are not in the grammar: the envelope fails decoding
(`authority_denied`), as do `{}`, `{"network":{"custom":[]}}` and any manifest with a
field other than `network`.

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
| 16 | Every grant in the decoded capability manifest is one this node honours (§7.5): at this revision the manifest is `{"network":"offline"}` | `unsupported_grant` |
| 17 | The version is written durably | `resource_unavailable` (write failed) |

On success the task is `ready` and holds the envelope for `start`.

### 8.2 `start`, `stop`, `pause`, `resume`, `revoke`, `seal` and `create`

Each of the six execution verbs is `unsupported_operation` without `--task-root` (and on a
1.2 connection), before anything else is checked.

`start`: checks 1–2; replay; not
`ready` → `invalid_state`; envelope `issued_at` in the future → `authority_denied`;
envelope or lease expired → `lease_expired`; revoked → `lease_revoked`; snapshot missing
from the store, the attempt's workspace already existing (`<task-root>/<task>/<attempt>/`)
or the sandbox failing to spawn → `resource_unavailable` with the task still `ready`.

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
| `invalid_state` | The task is not in a state that allows the verb, or another operation already did it. |
| `authority_denied` | Untrusted key, bad signature, malformed envelope (a capability manifest outside the grammar of §7.5 included), a root lease `issuer` that is not the principal bound to the signing key, wrong audience, not yet valid, or authority that does not cover the task or agent. |
| `unsupported_grant` | From `admit` only: the envelope's capability manifest decodes but asks for a grant this node cannot honour (§7.5), here any `network` other than `offline`. The task stays `created` and no version is consumed; re-admit under the same version with a manifest the node honours. Protocol 1.3 and later. |
| `resource_unavailable` | Registry full with no sealed task to evict, snapshot missing, workspace exists, spawn failed, a state write failed or would exceed its bound (admission version, revocation, retired attempt or task record), an evidence record could not be appended (§6.5), stop not confirmed in time, a pause or resume not confirmed, or an attempt's 128 pauses used up. |
| `unsupported_operation` | The verb is not implemented (`stream`), or not enabled on this node or connection (no `--task-root`, or protocol 1.2). |

## 9. Receipts

The node records one receipt per attempt (binding, session and outcome) when the attempt
ends (`exited`, `stopped` or `revoked`) and keeps it in the task's durable record. At 1.3, `inspect` of an
`exited`, `stopped`, `revoked` or `sealed` task reports the outcome; `seal` keeps the
receipt, so a sealed task reports the outcome its attempt ended with. A 1.1 or 1.2
connection never sees an outcome. A receipt survives a node restart (§6.4); it is lost
when a new attempt replaces its attempt and when its sealed task is evicted: read the
outcome before then.
The attempt's evidence log (§6.5) records the same outcome in its `NodeAttemptEnded` or
`NodeAttemptRecovered` record and outlives both.

| Outcome | When |
| --- | --- |
| `completed` | `exited`: the sandbox exited with status 0 before the budget, with no stop. `revoked`: the same, observed by the reaper while the revoke was being served, before its kill landed. |
| `failed` | `exited`: non-zero exit status, termination by a signal the node did not send, or killed at the wall-clock budget (also while paused). `stopped`: killed and reaped by `stop`, or stopped from `ready` without running. `revoked`: killed and reaped by `revoke`, revoked from `ready` without running, or a non-zero exit or budget kill observed before the kill landed. |
| `unknown` | `exited`: the launch was ambiguous (the spawn was not confirmed within 30 seconds, a process may have started before the launch failed, or the spawned process could not be recorded), the node lost the child while waiting, or the node restarted while the attempt may have been executing (§6.4). `stopped`: the child was lost while a stop was pending. `revoked`: the reap was not confirmed within 10 seconds, or the child was lost. |

The workload runs in bubblewrap with the workspace bound writable at `/work` (its working
directory), a private `/tmp` and `/home/agent`, read-only system directories, no network
but loopback (what its manifest asked for, §7.5), and only `HOME`, `PATH`, `TERM` and
`PWD` set (`PWD` is bubblewrap's, set to `/work` when it enters the working directory;
nothing of the node's own environment is passed on). Output is drained and not
returned.

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
- **Clocks.** Validity is judged at the node clock at `admit` and at `start`; no other
  verb rechecks it. Leave margin for skew and for the delay between the two.
- **Capacity.** The node holds at most 1 024 tasks. `exited`, `stopped` and `revoked`
  tasks count until they are sealed; seal each finished task once you have read its
  outcome. When a `create` for a new task finds the registry full, the node evicts the
  task sealed longest ago (oldest first); with no sealed task it answers
  `resource_unavailable`. An evicted task reads `task_not_found`; its admission version
  and any revocation stay in the node state, so it can be created again but admitted
  only with a higher version. A new attempt of a known task replaces it in place and
  needs no room.
- **Disk.** The node never removes a workspace that ran (not on `stop`, `revoke`, `seal`,
  eviction or restart), so that an attempt is never started twice. Reclaim task-root
  space out of band, and only for attempt ids you will never send again.

## 11. Client and adapter

WardOS ships one implementation of this contract for the control-plane side, in the
`ward-node-client` crate (`crates/ward-node-client`):

- `UnixTransport`: the framing of §3 over the local socket, one connection per request,
  both request lines written at once, both bounds (64 KiB each way) enforced, a `connect`
  timeout (until the node has accepted the connection and answered the handshake) and a
  `request` timeout (until the verb's answer; default 90 seconds, §3). EOF before the
  handshake answer is `ClosedWithoutResponse`; EOF after it is "no response", which the
  client reports for the verb as "unknown whether it took effect" (§10).
- `Client`: negotiates once, offering 1.3 up to the highest minor this revision
  implements (today 1.3–1.3), and refuses with a typed error a node that offers nothing
  in that window (`HandshakeRejected`) or accepts a version below 1.3 (`ProtocolTooOld`).
  Every later connection must be accepted at exactly the negotiated version. It reads the
  capability document (§5) and sends `create`, `admit`, `start`, `pause`, `resume`,
  `stop`, `revoke`, `seal` and `inspect` (§6), decoding each answer strictly and refusing
  one that names another binding or operation id than the request.
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
  → `seal`, with the rules below, returning an `AttemptReport`.

### 11.1 Operator requirements for a client host

The client runs where the node runs, under the same Unix identity: the socket is mode
`0600` in a `0700` directory and the state directory is `0700` (§2.1), so another uid
cannot connect or read. The host needs bubblewrap with unprivileged user namespaces for
the node to execute at all. `ward-node snapshot import` (§2.4) runs as the node's uid
against the node's `--state-dir`; the id it prints is the envelope's `workload.snapshot`.
Give `start`, `stop` and `revoke` a read timeout of 60 seconds or more (`start` waits up
to 30 seconds for the spawn after copying the snapshot, `stop` and `revoke` up to 10
seconds for the reap, §3); the adapter's `--timeout-ms` defaults to 90 000. Reading an
attempt's evidence log (§6.5) needs the same uid and the node's `--task-root`.

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

### 11.4 The process adapter

`ward-node-adapter --socket <path> [--timeout-ms 90000] [--connect-timeout-ms 10000]`
reads one JSON command per line on stdin and writes one JSON event per line on stdout.
Every output line carries `"schema":1`; stderr is diagnostics only. Commands:

| Command | Answer |
| --- | --- |
| `{"cmd":"capabilities"}` | `{"event":"capabilities","protocol":{"major":1,"minor":3},"capabilities":{…}}` (the §5 document). |
| `{"cmd":"run", …}` | The event stream below, ending in one `done`. |
| `{"cmd":"revoke","operation_id":N,"binding":{…}}` | `{"event":"verb","verb":"revoke","operation_id":N,"result":"accepted","state":…}` or `…,"result":"rejected","reason":…}`. |
| `{"cmd":"inspect","binding":{…}}` | `{"event":"inspected","state":…,"outcome":…}` or `{"event":"rejected","verb":"inspect","operation_id":null,"reason":…}`. |
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
for a refused verb and `{"event":"recovering","verb":…,"operation_id":…}` when a lost
answer is being recovered (§11.2). The `admitted` event repeats the exact signed bytes
and proof so a caller that signed here can persist them and replay after its own
restart; a caller that pre-signed already holds them.

`SIGTERM` or `SIGINT` during a `run` cancels it: the attempt is revoked and sealed, the
`done` is written, and the adapter exits without reading further commands; while idle it
exits at once. The exit status is 0 when every command was well formed and answered (an
attempt that failed, was refused or ended `unknown` is still a clean answer: read `done`),
1 when an `error` event was written (a malformed command, an unreachable node for
`capabilities`, `revoke` or `inspect`, or a `run` refused before anything was sent), 2 for
bad flags. A command line is at most 256 KiB.

### 11.5 What an adapter cannot do yet

- Workloads run offline: a manifest with `network.custom` is refused `unsupported_grant`
  (§7.5), so nothing in the sandbox can reach a network service.
- The workload's stdout and stderr are drained and not returned (§9); the protocol carries
  no output.
- The workspace is not exported: what the workload wrote stays under
  `<task-root>/<task>/<attempt>/`, readable only on the host as the node's uid.
- There is no event stream (`stream`) and no callback channel into the sandbox; progress
  is what `inspect` reports.

The honest integration shape today is therefore running governed tool actions and
verification runs, an `argv` over a snapshot with a budget, through the node, reading the
receipt and the evidence log, and not hosting a whole agent runtime whose conversation
loop needs output, network or callbacks from inside the sandbox.
