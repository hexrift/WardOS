# ward-node integration contract for external control planes

Status: living document. It describes the `ward-node` protocol 1.3 contract as
implemented today (ADR-0030 steps 1–4).

This is the contract an adapter drives, in any language, to have a local `ward-node`
admit, run and stop a task. Every protocol message below was produced by the node's own
encoders and decoded back by its strict decoders; the admission example is a working
test vector (§7.4).

## 1. Scope and trust model

- `ward-node` is the enforcement authority on its host
  ([ADR-0029](decisions/ADR-0029-product-split-fleet-trust-boundaries.md)). It decides
  whether a task runs, allocates its workspace, spawns, reaps, enforces the budget and
  records the outcome.
- The control plane is external and not part of WardOS. It only issues bounded,
  expiring authority: an admission envelope signed by an issuer key the node's operator
  configured ([ADR-0030](decisions/ADR-0030-node-task-admission-and-execution-ownership.md)).
  Reaching the socket proves nothing; a signature by a trusted key is required.
- Not implemented yet: network grants from the capability manifest (every workload runs
  offline), `pause`/`resume`/`revoke`/`seal`, an event stream, per-attempt evidence logs,
  durable task recovery across a node restart, and any remote transport or mTLS. The
  only transport is a local Unix socket; remote transport and key bootstrap are #262.

## 2. Operator setup

### 2.1 Running the node

```text
ward-node --socket <path> --state-dir <dir> --node-id <node_…> \
  [--trusted-issuers <file>] [--task-root <dir>]
```

| Flag | Required | Meaning |
| --- | --- | --- |
| `--socket` | yes | Unix socket to serve. Its parent directory must exist and have no group or other permission bits (0700 or stricter). The socket is created mode 0600. An existing path is never removed: delete a stale socket before restarting. |
| `--state-dir` | yes | Node-owned state, created mode 0700 if absent and refused if group- or world-accessible. Holds `node-id`, `admission-versions.json`, `revocations.json` and the snapshot store `cas/`. |
| `--node-id` | yes | The node's audience id (`node_` + 26-character ULID). Pinned in `<state-dir>/node-id` at first start; a later start with another id is refused. Envelopes must name exactly this id. |
| `--trusted-issuers` | no | Trust store (§2.2). Without it no issuer is trusted and every `admit` is refused `authority_denied`. |
| `--task-root` | no | Directory under which the node allocates workspaces, created mode 0700 and refused if group- or world-accessible or not a real directory. With it the node executes (`start`/`stop`); the node refuses to start if bubblewrap is unusable. Without it, `start` and `stop` are `unsupported_operation`. |

The node refuses to start on any unsafe or malformed input: a trust store or state file
it cannot parse, wrong permissions, a pinned id mismatch. It serves until killed.

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

There is no revocation verb. The node reads `<state-dir>/revocations.json` once at start:

```json
{"format":1,"revocations":[{"lease":"lease_01M45YYRG00009K6DANAXVQK6C","revoked_at_unix_ms":1791203400000,"reason":"operator"}]}
```

`reason` is one of `operator`, `policy`, `delegation_revoked`, `security`. A lease is
unusable from `revoked_at_unix_ms` on; a revoked ancestor revokes every lease delegated
from it, and two different facts for one lease make it unusable. Write the file while the
node is stopped; a malformed file stops the node. `admission-versions.json` and `node-id`
are node-owned: deleting the versions file would let old envelopes be replayed.

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
  take longer than 10 seconds to arrive: `stop` waits up to 10 seconds for the reap,
  `start` materialises the snapshot and then waits up to 30 seconds for the spawn, and
  every other request is answered at once. Give `start` and `stop` a read timeout above
  those bounds (for example 60 seconds plus the time to copy your largest snapshot).
- Connections are served one at a time. Do not hold a connection open; an idle client
  delays every other client by up to 10 seconds, and a `start` or `stop` delays them for
  as long as it runs.
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

## 5. Capability discovery

At 1.1 and later the one request may be discovery:

```json
{"request":"capabilities","protocol":{"major":1,"minor":3}}
```

A node started with `--trusted-issuers` and `--task-root` answers at 1.3 (capacity is the
host's; the other values are what the node reports today):

```json
{"response":"capabilities","capabilities":{"protocol":{"major":1,"minor":3},"architecture":"x86_64","capacity":{"logical_cpus":8,"memory_bytes":17179869184},"isolation":{"namespaces":{"sandbox":true,"user_namespace":true},"backends":{"container":false,"microvm":false,"vm":false}},"network":{"offline":true,"proxy_allowlist":false},"credentials":{"proxy_injection":false,"scoped_http_gateway":false},"snapshots":{"content_addressed":true,"diff":false,"read":false},"verifier":{"isolated":false},"lifecycle":{"pause":false,"stop":true,"revoke":false,"admit":true,"start":true}}}
```

| Flag | Meaning at 1.3 |
| --- | --- |
| `lifecycle.admit` | Present, and `true`, when the node verifies and admits signed envelopes. Absent means `false`. Every `ward-node` binary admits at 1.3; without a trust store every `admit` is still refused. |
| `lifecycle.start` | Present, and `true`, when the node executes admitted tasks (`--task-root` set, bubblewrap usable). Absent means `false`. |
| `lifecycle.stop` | Always present. At 1.3 it equals `start`: the node never offers a way to begin execution without its own way to end it. |
| `lifecycle.pause`, `lifecycle.revoke` | Always `false`; the verbs are not implemented. |
| `isolation.namespaces.sandbox`, `isolation.namespaces.user_namespace` | `true` exactly when `lifecycle.start` is: every workload runs in a bubblewrap namespace sandbox inside its own user namespace. |
| `network.offline` | `true` exactly when `lifecycle.start` is: every workload runs with no network but loopback. |
| `snapshots.content_addressed` | `true` exactly when `lifecycle.start` is: workspaces are materialised from the node's content-addressed store (§2.4). |

Everything else (`isolation.backends`, `network.proxy_allowlist`, `credentials`,
`snapshots.diff`, `snapshots.read`, `verifier`) is `false`: the node offers none of it
yet. 1.1 and 1.2 documents keep their earlier content: they never carry `admit` or
`start`, report `stop` as `false`, and report the execution flags above as `false`,
because a 1.1 or 1.2 connection cannot run anything.

## 6. Lifecycle verbs

Every request names the task by its `binding` (`task`, `attempt`, `lease`). Mutating
verbs carry an `operation_id`: an integer from 1 to 2^64−1 (keep it at or below
2^53−1 if your JSON library uses doubles). The examples use the binding of the §7
envelope.

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

`stop` kills and reaps the workload before it answers:

```json
{"request":"stop","protocol":{"major":1,"minor":3},"operation_id":4,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"}}
{"response":"accepted","protocol":{"major":1,"minor":3},"operation_id":4,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"stopped"}
```

`inspect` is read-only and has no `operation_id`:

```json
{"request":"inspect","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"}}
{"response":"inspected","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"running"}
```

An `exited` or `stopped` task also carries its receipt outcome (§9):

```json
{"response":"inspected","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"exited","outcome":"completed"}
{"response":"inspected","protocol":{"major":1,"minor":3},"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"state":"stopped","outcome":"failed"}
```

A refusal echoes the request's `operation_id`, or `null` for `inspect`:

```json
{"response":"rejected","protocol":{"major":1,"minor":3},"operation_id":2,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"reason":"authority_denied"}
{"response":"rejected","protocol":{"major":1,"minor":3},"operation_id":null,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"reason":"task_not_found"}
```

`pause`, `resume`, `revoke` and `seal` (same shape as `stop`) and `stream` are decoded
but always answered `unsupported_operation`.

### 6.2 State machine

| From | Event | To | Receipt outcome |
| --- | --- | --- | --- |
| — | `create` | `created` | — |
| `created` | `admit` | `ready` | — |
| `ready` | `start`, spawn confirmed | `running` | — |
| `ready` | `start`, launch ambiguous | `exited` | `unknown` |
| `ready` | `stop` | `stopped` | `failed` (nothing ran) |
| `running` | workload ends on its own or at its budget | `exited` | `completed`, `failed` or `unknown` |
| `running` | `stop` | `stopped` | `failed`, or `unknown` if the reap is unconfirmed |

`exited` and `stopped` are terminal today. `paused`, `revoked` and `sealed` exist in the
protocol but no node reaches them.

### 6.3 Idempotency and replay

Operation ids are recorded per task and per verb. A replay is the same request again,
for example after a lost response.

| Verb | Replay that is accepted | Anything else |
| --- | --- | --- |
| `create` | Same binding and the `operation_id` of the `create` that registered it: `accepted` with the current state. | Another `operation_id`: `invalid_state`. Same task, another attempt or lease: `attempt_mismatch` / `lease_mismatch`. |
| `admit` | Same `operation_id`, byte-identical `envelope_json` and identical `proof` as the admit that succeeded: `accepted` with the current state (which may be past `ready`). | On a task that is not `created`: `invalid_state`. A refused admit records nothing and may be retried with any `operation_id`. |
| `start` | The `operation_id` of the `start` that took effect (including an ambiguous one): `accepted` with the current state. | On a task that is not `ready`: `invalid_state`. A refused start records nothing. |
| `stop` | The `operation_id` of the `stop` that took effect: `accepted`, `stopped`. | On a task that is `created`, `exited`, or stopped by another operation: `invalid_state`. |

Replay a `stop` that timed out with the same `operation_id`: a second stop with a new id
while the first is pending also stops the task, but is then answered `invalid_state`
because the first id is recorded as the stopping operation.

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
| `workload.capability_manifest` | `{"hash","bytes"}`: `bytes` is the hex of 1–8 192 manifest bytes and `hash` is `BLAKE3-256` of those decoded bytes. Required and hash-checked, but not interpreted yet: no grant in it is honoured. |
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
| 16 | The version is written durably | `resource_unavailable` (write failed) |

On success the task is `ready` and holds the envelope for `start`.

### 8.2 `start`, `stop` and `create`

`start`: `unsupported_operation` without `--task-root`; then checks 1–2; replay; not
`ready` → `invalid_state`; envelope `issued_at` in the future → `authority_denied`;
envelope or lease expired → `lease_expired`; revoked → `lease_revoked`; snapshot missing
from the store, the attempt's workspace already existing (`<task-root>/<task>/<attempt>/`)
or the sandbox failing to spawn → `resource_unavailable` with the task still `ready`.

`stop`: `unsupported_operation` without `--task-root`; then checks 1–2; replay; `ready`
→ `stopped`; `running` → kill, wait up to 10 seconds for the reap, then `stopped`, or
`resource_unavailable` if still running, or `invalid_state` if the workload exited first;
any other state → `invalid_state`. The answer is written after the wait, whatever it
took (§3).

`create`: checks 2 and the replay rule of §6.3; a node holding 1 024 tasks refuses a new
one with `resource_unavailable`.

### 8.3 Rejection reasons

| Wire string | Meaning |
| --- | --- |
| `task_not_found` | No task with this `task` id is registered (never created, or forgotten by a restart). |
| `attempt_mismatch` | The task is registered, or the envelope is bound, under another execution attempt. |
| `lease_mismatch` | The task is registered, or the envelope is bound, under another lease id, or the envelope's lease `id` is not the binding's lease. |
| `lease_expired` | The envelope or a lease is past its expiry at the node clock. |
| `lease_revoked` | A durable revocation covers the lease or an ancestor. |
| `stale_operation` | The request is stale. From `admit`: the envelope `version` is not greater than the last version the node durably accepted for the task (an old or replayed envelope, also after a restart). The protocol also reserves it for a mutating request whose `operation_id` was superseded by a later operation on the task; `ward-node` does not return it for that today. |
| `invalid_state` | The task is not in a state that allows the verb, or another operation already did it. |
| `authority_denied` | Untrusted key, bad signature, malformed envelope, a root lease `issuer` that is not the principal bound to the signing key, wrong audience, not yet valid, or authority that does not cover the task or agent. |
| `resource_unavailable` | Registry full, snapshot missing, workspace exists, spawn failed, state write failed, or stop not confirmed in time. |
| `unsupported_operation` | The verb is not implemented, or not enabled on this node. |

## 9. Receipts

The node records one receipt per attempt (binding, session and outcome) when the attempt
ends, keeps it in memory, and reports its outcome on `inspect` of an `exited` or
`stopped` task. It is lost on restart.

| Outcome | When |
| --- | --- |
| `completed` | `exited`: the sandbox exited with status 0 before the budget, with no stop. |
| `failed` | `exited`: non-zero exit status, termination by a signal the node did not send, or killed at the wall-clock budget. `stopped`: killed and reaped by `stop`, or stopped from `ready` without running. |
| `unknown` | `exited`: the launch was ambiguous (the spawn was not confirmed within 30 seconds, or a process may have started before the launch failed), or the node lost the child while waiting. `stopped`: the child was lost while a stop was pending. |

The workload runs in bubblewrap with the workspace bound writable at `/work` (its working
directory), a private `/tmp` and `/home/agent`, read-only system directories, no network
but loopback, and only `HOME`, `PATH` and `TERM` set. Output is drained and not
returned.

## 10. Failure semantics an adapter must handle

- **No response.** EOF without a response line is a fail-closed malformed request, the
  10-second request deadline expiring before the request line arrived, or the answer
  deadline expiring because the client did not read (§3). A `create`, `admit`, `start`
  or `stop` may still have taken effect. Inspect, then replay with the same
  `operation_id`.
- **Slow `start` and `stop`.** A slow verb is answered, not cut off: a `start` whose
  spawn is not confirmed within 30 seconds is answered `accepted` with `exited`
  (ambiguous, below), and a `stop` whose reap is not confirmed within 10 seconds is
  answered `resource_unavailable` (replay it with the same `operation_id`). Keep the
  connection open and reading until the answer arrives (§3).
- **Ambiguous launch.** `accepted` with `exited`, or `inspect` showing `exited` with
  `unknown`, means the attempt may have had effects. It is never re-run: its workspace
  exists, so any later `start` of the same attempt is refused. Retrying needs a new
  attempt id and a new envelope with a higher version. The running node keeps one
  binding per task and refuses a `create` for another attempt of the same task
  (`attempt_mismatch`) until it restarts, so today a retry on the same node uses a new
  task id or waits for a restart.
- **Stop racing exit.** Exactly one terminal state wins. If the workload exited on its
  own first, the task is `exited` with its real outcome and the `stop` is answered
  `invalid_state`; inspect to read it.
- **Node restart.** The registry is in memory: every task is forgotten (`inspect` →
  `task_not_found`), receipts are lost, and running sandboxes die with the node through
  bubblewrap's `--die-with-parent` (except in the few milliseconds after a spawn). Treat
  an attempt that was `running` and is now `task_not_found` as outcome unknown. Its
  workspace survives, so the attempt cannot be started again; the admission version
  survives, so the old envelope is refused `stale_operation`.
- **Versions.** Keep a durable, strictly increasing version per task in the control
  plane. Every successful `admit` consumes one; refused admits do not.
- **Clocks.** Validity is judged at the node clock at `admit` and at `start`. Leave
  margin for skew and for the delay between the two.
- **Capacity.** The registry never frees a task (there is no `seal` yet), so a node
  accepts 1 024 `create`s per process lifetime and then answers `resource_unavailable`
  until restarted.
