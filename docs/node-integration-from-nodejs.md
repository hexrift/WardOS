# Integrating `ward-node` from a Node.js control plane

Status: living document. It is the guide for a control plane written in Node.js or
TypeScript — concretely, the worker execution boundary of
[hexrift/ai-institution](https://github.com/hexrift/ai-institution) (its issue #490) —
that wants `ward-node` to run its bounded workloads. It says what to install, what to
keep where, how to derive the ids and the version, how to build and sign the envelope with
`node:crypto`, how to spawn `ward-node-adapter` and speak its JSON lines, how to read the
outcome, how to cancel and how to recover after a restart on either side. Every rule
here is the contract's, [node-integration.md](node-integration.md), cited by section;
nothing here adds to it. The reference implementation of everything below is
[`examples/node-control-plane`](../examples/node-control-plane/README.md): a
dependency-free client (`ward-node.mjs`, with `ward-node.d.ts` for TypeScript) and a
command line (`control-plane.mjs`), held to the contract's §7.4 test vector byte for byte
by `node --test` and proven against a real node by
[`scripts/acceptance/node-js.sh`](../scripts/acceptance/node-js.sh), which CI runs on every
change after the Rust acceptance suite ([node-acceptance.md](node-acceptance.md)).

The shape of the integration is the one of node-integration.md §11.5: the control plane
keeps its agent loop and its authority on its own side, and hands the node one bounded,
offline action at a time — an `argv` over a snapshot with a wall-clock budget — reading
back the receipt and, on the host, the evidence log. What the node cannot do yet for
such a control plane is §11 below; read it before deciding which actions go through the
node.

## 1. Prerequisites

Operator steps, in the words of [node-integration-guide.md](node-integration-guide.md) §1
to §4, with what the Node.js side adds:

1. **The node tarball.** Install `ward-node` and `ward-node-adapter` from the release's
   `ward-node-<node version>-<arch>-linux.tar.gz` (guide §1); both must be on the host
   where the control plane's adapter process will run. `ward-node --version` and
   `ward-node-adapter --version` print the node version you deployed.
2. **A system user for the node, and one for the control plane's client.** The node runs
   as `ward-node` with its state directory and task root mode 0700 (guide §1). The
   control plane's process runs as a user of its own (`ward-adapter` in guide §3) that
   the node is told to serve: start the node with `--client-uid <that user>` and
   `--client-group <a group both share>`, with the socket directory `0750` owned by that
   group (node-integration.md §2.1). The client can then speak to the node and cannot
   read its state, records or evidence logs. Reading an evidence log back (§6.5) needs the
   node's uid; `ward-node audit --task-root` (§2.6) is how the control plane's operator
   verifies one.
3. **The socket.** The adapter takes `--socket <path>`; the path is the node's `--socket`.
   One request per connection, served one at a time (§3): the adapter opens a connection
   per verb, and a control plane drives one node from one place.
4. **bubblewrap with unprivileged user namespaces** on the host (guide §1), or the node
   refuses to start with a task root and `lifecycle.start` is absent from its capability
   document (§5). The acceptance script probes this exactly as the Rust suites do and
   skips loudly without it.
5. **Node.js >= 22** on the host for the client; the reference client uses nothing
   outside the standard library (`node:crypto`, `node:child_process`, `node:readline`,
   `node:fs`).
6. **A snapshot.** The workload runs over a project snapshot the node already holds:
   `ward-node snapshot import --state-dir <dir> <project>` as the node's user prints the
   64-hex id the envelope's `workload.snapshot` carries (§2.4, guide §4). Everything the
   workload needs is in the snapshot: the workload is offline.

Check the host from the control plane's user before anything else:

```text
$ node examples/node-control-plane/control-plane.mjs capabilities --socket /run/ward-node/node.sock
{"protocol":{"major":1,"minor":3},…,"lifecycle":{"pause":true,"stop":true,"revoke":true,"admit":true,"start":true}}
```

`lifecycle.start` must be `true` (§5).

## 2. Key custody

The control plane is the issuer. It holds one Ed25519 key per issuing principal and
signs every envelope itself; the node holds the public key in its trust store and sees
signatures only (§2.2, §7.4). In Node.js:

```js
import { generateKeyPairSync, createPrivateKey, sign } from "node:crypto";

const { privateKey } = generateKeyPairSync("ed25519");
const pem = privateKey.export({ type: "pkcs8", format: "pem" });   // write it mode 0600
// later: createPrivateKey({ key: pem, format: "pem" })
// proof: sign(null, Buffer.from(envelopeJson, "utf8"), privateKey)   // 64 bytes, Ed25519 (RFC 8032)
```

The reference client wraps this as `createIssuerKey(path)` (PKCS#8 PEM, mode 0600, never
overwriting), `loadIssuerKey(path)` (refuses any mode but 0600 or 0400, as the Rust
`IssuerKey` does) and `Issuer.prove(envelopeJson)`. The trust-store line the operator
needs is `<public-key hex> <key id> <prn_…>` (§2.2); the key id is BLAKE3-256 over the 32
raw public-key bytes (§2.3). Node's `crypto` has no BLAKE3, so the client ships one in
plain JavaScript (`blake3.mjs`, held to the reference vectors); `ward-node issuer-key-id
<public-key hex>` prints the same id from the node's side, and the acceptance script
checks the two agree.

```text
$ node examples/node-control-plane/control-plane.mjs keygen --key /etc/ai-institution/ward-issuer.pem --principal institution-a
ea4a…d22c 0871…2433 prn_27KBYD82NBZWEK7ZA0Q1HDF3XS
```

Rules:

- The key lives where the control plane runs, on a filesystem only its user can read.
  It never goes to the node's host unless the control plane runs there; even then the
  node's user cannot read it.
- The principal the key is bound to (`prn_…`) is the control plane's issuing identity:
  one per institution (or per issuing service, such as a CI runner). The root lease's
  `issuer` must be that principal or `admit` is `authority_denied` (§8.1 step 8).
- Rotation is "add the new line, restart the node, retire the old line, restart again"
  (node-security-limitations.md §3.1). Several keys may be bound to one principal.
- The §7.4 test key (seed 32 × `0x07`) is for checking an encoder and signer, never for a
  trust store.

## 3. Id derivation

Every WardOS id is a prefix and a 128-bit value rendered as 26 upper-case Crockford base32
characters, first character `0`–`7` (§7.2). The node does not care how the control plane
chooses the value, only that it is well formed and used consistently: a task id names one
task for ever, an attempt id is never reused (§10), a lease id is one lease.

ai-institution's ids are strings (work item ids, lease ids with a numeric generation,
worker ids, run-scoped ids). The reference client derives a WardOS id from any such string
deterministically, so no mapping table has to be stored:

```text
deriveId(prefix, callerId) = encodeId(prefix, first 16 bytes of
    SHA-256("ward-node id v1" ‖ 0x00 ‖ prefix ‖ 0x00 ‖ utf8(callerId)), big-endian)
```

The same caller id always gives the same WardOS id; two prefixes never share a value; the
rendered form always has a first character `0`–`7` because 128 bits fill 25⅗ characters.
`control-plane.mjs derive-id <prefix> <caller-id>` prints one. The mapping for #490:

| ai-institution | WardOS id | Derived from |
| --- | --- | --- |
| The work item / Task being executed | `task_…` | the work item id (or `missionId/taskId`): one WardOS task per unit of governed work, across all its attempts |
| One execution of it under one lease generation | `exec_…` | `<work item id>#<lease generation>` or the runtime invocation id: a new attempt every time the work is dispatched again (§10: never reuse an attempt id) |
| The authority the attempt runs under | `lease_…` | the institution work lease id and generation: a retry after a cancel needs a lease that is neither the revoked one nor delegated from it (§10), and a new generation gives one |
| The worker (producer or verifier) | `agent_…` | the worker id |
| The institution as issuer | `prn_…` | the institution id (what the key is bound to in the trust store) |
| The run | `sess_…` | the run scope id; recorded in the receipt, not checked (§7.3) |
| The host | `node_…` | chosen by the operator once per host (`--node-id`) and configured, not derived from anything that could change |
| The delegation record | `deleg_…` | the same string as the lease |

A control plane that already issues ULIDs can use them as the 128-bit value directly
(`encodeId`); a random one is `randomId(prefix)`. Lower case is refused everywhere (§7.2).

## 4. The version counter

Every envelope carries a `version` that must be strictly greater than the last version the
node durably accepted **for the task**, across attempts, control-plane restarts, node
restarts and evictions (§7.3, §10). The node keeps its side in
`<state-dir>/admission-versions.json`; the control plane must keep a durable counter per
task of its own, or its second attempt of a task is refused `stale_operation` (§8.3).

The reference client's `VersionStore` is one JSON file,
`{"format":1,"versions":{"task_…":N}}`; every `next(task)` re-reads the file, increments
the task's entry and writes the file back durably (temporary file, `fsync`, `rename`)
before returning the version. In a control plane with a database, the counter is a column
on the task row, incremented in the same transaction that records the attempt. Rules:

- Allocate the version **before** `admit` and record it with the signed bytes (§5 below).
  A refused `admit` leaves a gap; the node does not mind gaps, only non-increase.
  (Exactly one refusal consumes a version on the node's side: `resource_unavailable`
  because the evidence record could not be appended, §6.5. The next envelope needs a
  higher one either way, which a monotonic counter gives.)
- Never derive the version from the attempt or from a clock. A node that restarted while
  a task was `ready` reads the task as `created` and needs a *new* `admit` with a higher
  version (§6.4): that is a new version for the same attempt.
- A counter that is lost or reset is refused by the node: the acceptance case
  `version_is_held_strictly_increasing` deletes the client's counter for a task, watches
  the node answer `stale_operation` for the reissued version 1, restores it and watches
  version 2 admit.

## 5. The envelope and its signature

Build the envelope of §7.1 from the control plane's facts, bound-check it, serialise it
once, sign those bytes, and keep them. With the reference client:

```js
import { buildEnvelope, rootLease, signEnvelope, loadIssuerKey, deriveId, VersionStore } from "./ward-node.mjs";

const issuer = loadIssuerKey("/etc/ai-institution/ward-issuer.pem");
const principal = deriveId("prn", "institution-a");
const task = deriveId("task", workItem.id);
const attempt = deriveId("exec", `${workItem.id}#${lease.generation}`);
const leaseId = deriveId("lease", `${lease.id}#${lease.generation}`);
const agent = deriveId("agent", lease.workerId);
const binding = { task, attempt, lease: leaseId };
const now = Date.now();
const version = new VersionStore(stateDir + "/admission-versions.json").next(task);

const envelope = buildEnvelope({
  binding,
  agent,
  node: NODE_ID,                                   // the host's --node-id, configured
  session: deriveId("sess", runScope.runId),
  lease: rootLease({
    id: leaseId,
    delegationId: deriveId("deleg", `${lease.id}#${lease.generation}`),
    issuer: principal,
    subject: agent,
    task,
    grants: [{ capability: "workload.run", resource: `task:${task}`, delegable: false }],
    issuedAtUnixMs: now - 60_000,
    expiresAtUnixMs: lease.expiresAt,
  }),
  workload: { argv: ["sh", "-c", "make test"], snapshot, wallClockBudgetMs: deadlineAt - now },
  issuedAtUnixMs: now - 60_000,
  expiresAtUnixMs: now + 15 * 60_000,
  version,
});
const signed = signEnvelope(issuer, envelope);    // { envelope_json, proof, binding }
```

`buildEnvelope` refuses, before anything is signed, every value §7.3 bounds: a malformed
or lower-case id, a lease that is not the binding's lease or task or whose subject is not
`agent`, an empty or oversized `argv`, a NUL, unsorted or duplicate grants, a budget below
1, a snapshot that is not 64 lowercase hex digits, `expires_at <= issued_at`, a version
below 1, a manifest outside §7.5's grammar, or an envelope over 32 KiB. It writes the keys
in the order the §7.4 vector has them; `serialiseEnvelope` is `JSON.stringify`, compact,
which is also what the node's own encoder produces.

The one rule that matters for the signature (§7.4): **the proof is over the exact UTF-8
bytes of the `envelope_json` string as sent**. Serialise once, sign that string, embed
that same string in the `run` command, persist that same string for replay, and never
re-serialise: `JSON.parse` followed by `JSON.stringify` is not guaranteed to give the same
bytes, and a replayed `admit` must be byte-identical (§6.3). The reference client's
`signEnvelope` returns the string it signed; the test `the envelope serialises to the
§7.4 bytes and signs to the §7.4 signature` holds it to the vector, and `the complete
admit request line is the §7.4 line` holds the wire line too.

Grants: the node checks their shape and order (§7.3) and that a delegated lease contracts
its parent; it does not interpret the capability names. Name what the control plane's
own policy granted (its action policy decision), so that `ward-node audit` (§2.6) later
answers "who delegated what" in the institution's own vocabulary.

## 6. Spawning the adapter and the JSON-lines protocol

`ward-node-adapter` is the language-neutral path (§11.4): a process that reads one JSON
command per line on stdin and writes one JSON event per line on stdout, each with
`"schema":1`; stderr is diagnostics. ai-institution already spawns TamperWard this way
(`execFile` / `spawn` with `shell: false`, piped stdio, a timeout); the adapter is spawned
the same way, with the socket on its command line:

```js
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const child = spawn("ward-node-adapter", ["--socket", socket, "--timeout-ms", "90000"], { stdio: ["pipe", "pipe", "inherit"] });
const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
lines.on("line", (line) => handle(JSON.parse(line)));          // one event per line
child.stdin.write(JSON.stringify({ cmd: "run", envelope_json: signed.envelope_json, proof: signed.proof, operation_ids: { start_at: 1 }, task_root }) + "\n");
```

Rules of the conversation:

- **One command, one answer stream.** `capabilities`, `inspect` and `revoke` answer with
  one event each; `run` answers with a stream that ends in exactly one `done`. Do not send
  the next command before the stream ended: during a `run` the adapter is driving the
  node and reads stdin only afterwards.
- **Pre-signed only.** Send `envelope_json` (the signed string) and `proof`; never
  `issuer_seed_file` and `envelope`, which would put the key on the node's host. The
  adapter forwards the bytes unchanged.
- **Operation ids are yours** (`operation_ids`, §11.2): the scheme `create` N, `admit`
  N+1, `start` N+2, `stop` N+3, `revoke` N+4, `seal` N+5. Keep N with the signed bytes
  (§9); the reference client uses N = 1 for every attempt, since the node keeps ids per
  attempt.
- **`task_root`** (the node's `--task-root`) makes the report carry the evidence log path,
  its sealed head and the cause (exit code, budget, kill). Give it even when the client
  cannot read the log: the path is what the operator verifies.
- **Timeouts.** Leave the adapter's `--timeout-ms` at 90 000 or above: `start` waits up
  to 30 s for the spawn after copying the snapshot, `stop` and `revoke` up to 10 s for the
  reap (§3, §11.1). The control plane's own timeout on the adapter process is the budget
  plus the driver's grace (default 60 s) plus those bounds, not less.
- **Exit status** (§11.4): 0 when every command was well formed and answered — a failed
  attempt is still a clean answer, read `done`; 1 when an `error` event was written
  (malformed command, unreachable node for `capabilities`/`inspect`/`revoke`, a `run`
  refused before anything was sent); 2 for bad flags.

One complete run, as the reference client logged it with `--trace` against a real node
(`>>` sent, `<<` received; the `envelope_json` string shortened, paths shortened):

```text
>> {"cmd":"run","envelope_json":"{\"binding\":{\"task\":\"task_4YBS6ZBCXPTX25C5VRKXK4F44Y\",\"attempt\":\"exec_1WE6Z4RMRXBWY6B9XH1W6280WT\",\"lease\":\"lease_29BAZWG8TW6GN66FZFT44QGBPT\"},\"agent\":\"agent_747PGG7555YW8W6MCJB53SXASE\",\"node\":\"node_3JATJNDSA0TMAHPZMM3PH3ZJTJ\",\"session\":\"sess_51H1YEGXJZ469Q6TR36R54R2CJ\",\"authority\":{\"lease\":{\"id\":\"lease_29BAZWG8TW6GN66FZFT44QGBPT\",\"delegation_id\":\"deleg_61NQK3053E888XHNPEMAPA9WRC\",\"issuer\":\"prn_27KBYD82NBZWEK7ZA0Q1HDF3XS\",\"subject\":\"agent_747PGG7555YW8W6MCJB53SXASE\",\"task\":\"task_4YBS6ZBCXPTX25C5VRKXK4F44Y\",\"parent_lease_id\":null,\"delegated_by\":null,\"grants\":[{\"capability\":\"workload.run\",\"resource\":\"task:task_4YBS6ZBCXPTX25C5VRKXK4F44Y\",\"delegable\":false}],\"issued_at_unix_ms\":1791238641818,\"expires_at_unix_ms\":1791239661818,\"version\":1},\"lineage\":[]},\"workload\":{\"argv\":[\"sh\",\"-c\",\"echo hello > out.txt\"],\"capability_manifest\":{\"hash\":\"eb3e889be30ae8dd712a52c33e37aaca72e52ccff1aa770ecbd962d0cdb0d0c3\",\"bytes\":\"7b226e6574776f726b223a226f66666c696e65227d\"},\"snapshot\":\"42d16368…e3fba\",\"wall_clock_budget_ms\":60000},\"issued_at_unix_ms\":1791238641818,\"expires_at_unix_ms\":1791239601818,\"version\":1}","proof":{"issuer_key_id":"1f7d5e110dcef9199c159dd9f82652612eb7e18a6610badf70f7e62ee5200509","signature":"92eb3489…5702"},"operation_ids":{"start_at":1},"task_root":"/var/lib/ward-node/tasks"}
<< {"event":"state","operation_id":1,"schema":1,"state":"created","verb":"create"}
<< {"event":"state","operation_id":2,"schema":1,"state":"ready","verb":"admit"}
<< {"envelope_json":"{\"binding\":{\"task\":\"task_4YBS6ZBCXPTX25C5VRKXK4F44Y\",…}","event":"admitted","proof":{"issuer_key_id":"1f7d5e11…0509","signature":"92eb3489…5702"},"schema":1}
<< {"event":"state","operation_id":3,"schema":1,"state":"running","verb":"start"}
<< {"event":"receipt","outcome":"completed","schema":1,"state":"exited"}
<< {"event":"state","operation_id":6,"schema":1,"state":"sealed","verb":"seal"}
<< {"event":"evidence","path":"/var/lib/ward-node/tasks/task_4YBS6ZBCXPTX25C5VRKXK4F44Y/exec_1WE6Z4RMRXBWY6B9XH1W6280WT.evidence/events.log","schema":1}
<< {"event":"done","report":{"binding":{"attempt":"exec_1WE6Z4RMRXBWY6B9XH1W6280WT","lease":"lease_29BAZWG8TW6GN66FZFT44QGBPT","task":"task_4YBS6ZBCXPTX25C5VRKXK4F44Y"},"cancelled":false,"cause":{"Exited":{"code":0}},"deadline_exceeded":false,"evidence_head":"15590b379cc8b8c1d76c754d9a1b4488667e88a631586dcdfbc92e48cd85cf21","evidence_log":"/var/lib/ward-node/tasks/task_4YBS6ZBCXPTX25C5VRKXK4F44Y/exec_1WE6Z4RMRXBWY6B9XH1W6280WT.evidence/events.log","final_state":"sealed","operations":[{"operation_id":1,"reason":null,"state":"created","verb":"create"},{"operation_id":2,"reason":null,"state":"ready","verb":"admit"},{"operation_id":3,"reason":null,"state":"running","verb":"start"},{"operation_id":6,"reason":null,"state":"sealed","verb":"seal"}],"outcome":"completed","outcome_certain":true,"receipt":"completed","sealed":true,"transport_error":null},"schema":1}
```

The stream may also carry `rejected` (a refused verb, with its reason), `recovering` (a
lost answer being recovered by `inspect` and one replay, §11.2) and, for a cancelled or
budget-killed attempt, a `receipt` with `revoked`/`failed` or `exited`/`failed`. The
reference client's `Adapter` class is this conversation with a promise per command and an
`onEvent` hook; `--trace` on the command line prints every line as above.

## 7. Outcomes and their mapping

The `done` event's `report` is the attempt report of §11.3. Read it in this order, and
map it as the table says; the reference client's `outcomeOf(report)` does exactly this
and returns `{outcome, certain, exitStatus, receipt, cause, finalState, sealed, cancelled,
deadlineExceeded, evidenceLog, evidenceHead, refused, transportError, binding}`:

| Report | Means | For ai-institution's execution receipt |
| --- | --- | --- |
| `outcome` `completed`, `outcome_certain` `true` | The sandbox exited 0 within its budget (§9); `cause` is `{"Exited":{"code":0}}` | A successful governed execution: `exitStatus` 0. The receipt's binding is the WardOS `binding`; keep `evidence_head` (the sealed log's head) and `evidence_log` as the adapter receipt id and the provenance pointer. |
| `outcome` `failed`, `cause` `{"Exited":{"code":N}}` | Non-zero exit | A failed execution with `exitStatus` N. |
| `outcome` `failed`, `cause` `"BudgetExceeded"` | Killed at `wall_clock_budget_ms`, also while paused (§10) | A failed execution by deadline; no exit status. |
| `outcome` `failed`, `cancelled` `true`, `cause` `"Killed"` or `"NotStarted"` | Revoked by the control plane (§8 below) | Cancelled; no exit status. The lease is revoked for good on this node. |
| `outcome` `unknown`, `outcome_certain` `false` | Ambiguous launch, lost child, node restart mid-run, or a transport failure the driver could not recover (§11.2, §9) | **Failed, never success.** The attempt may have had effects (§10, "ambiguous launch"); retry as a new attempt (§9 below), never the same one. |
| `outcome` `{"refused":{"verb","reason"}}` | The node refused `create`, `admit`, `start` or `inspect` and nothing further was sent (§11.2) | Not an execution. Map the reason (§8.3): `authority_denied` and `unsupported_grant` are configuration errors to fix before re-admitting under the same version; `stale_operation` at `admit` means the version counter is behind (§4); `lease_expired` and `lease_revoked` need a new lease; `resource_unavailable` at `start` means the snapshot is missing or the spawn failed, retry `start` with the same id. |
| `deadline_exceeded` `true` | The workload outlived its budget plus the driver's grace and was revoked | Failed; the node's budget enforcement did not end it in time, which is worth an alert. |
| `sealed` `false` | `seal` was refused or never answered | The task still counts against the node's 1 024 (§10); seal it from a later `inspect`/replay, or it is evicted when the registry fills. |

Two things the report does not carry: the workload's output and its files (§11 below),
and the receipt bound to the evidence head over the socket (node-security-limitations.md
§3.3) — the binding exists on the host, which is why `evidence_head` from a run with
`task_root` and `ward-node audit --task-root` are what close it.

The command line prints the outcome object as one JSON line and exits 0 only for
`completed` and not cancelled, 1 for everything else, 2 for its own failure.

## 8. Cancel

Cancellation is `revoke`, never `stop` (§11.2): the lease is durably revoked first, then
the workload is killed and reaped, then the attempt is sealed. Two ways, both proven by
the acceptance (`cancel_is_revoke_then_seal`) and the Rust tests:

- **The adapter is yours:** send it `SIGTERM` (or `SIGINT`). The adapter revokes and
  seals the running attempt, writes `done` with `cancelled: true`, and exits 0 (§11.4).
  The reference client's `Adapter.cancel()` is this, wired to the process's own `SIGINT`
  and `SIGTERM` and to `--cancel-after <ms>` on the command line.
- **The run is driven elsewhere:** from another adapter process send
  `{"cmd":"revoke","operation_id":N+4,"binding":{…}}`. The driving adapter sees
  `revoked` on its next `inspect`, reads the receipt and seals.

Afterwards: `revocations.json` on the node holds the lease; no `admit` or `start` under
that lease or any lease delegated from it is accepted again (`lease_revoked`, §10). A
retry of the work therefore needs a new lease id — in #490's terms, a new lease
generation (§3) — and a new attempt id. ai-institution's `cancellationRequested` flag and
`deadlineAt` on the worker execution binding map onto this directly: when the flag turns
true, cancel the adapter; `deadlineAt - now` is the envelope's budget, so the node ends
the attempt by itself at the deadline whether or not the control plane is there to cancel.

## 9. Recovery after a control-plane restart

The node is the source of truth for what happened; the control plane only has to be able
to ask again without acting twice (§6.3, §6.4, §11.2). Persist, **before the first byte is
sent**: the binding, the signed `envelope_json` string and `proof`, the operation-id
scheme, the version and the task root. The reference client writes this as
`<state-dir>/runs/<exec_…>.json` (`saveRunRecord`) and `control-plane.mjs replay
--attempt <exec_…>` resends it.

After the restart, replay the recorded run through a fresh adapter: same bytes, same
proof, same ids. The node answers each replayed id with the task's **current** state and
acts on nothing:

| The task is | `create` answers | then |
| --- | --- | --- |
| still `created` (the earlier `admit` was refused or never arrived) | `accepted`, `created` (same id); a *different* id is `invalid_state` | `admit` is verified anew and takes effect once; the run continues normally |
| `ready` | `accepted`, `ready` | `admit` replays `accepted`, `ready`; `start` takes effect |
| `running` or `paused` | `accepted`, `running` | `admit` and `start` replay; the driver polls to the end and seals |
| `exited`, `stopped` or `revoked` | `accepted` with that state | `admit` replays; **no `start` is sent** (there is nothing to start, §11.2); the receipt is read and `seal` takes effect |
| `sealed` | `accepted`, `sealed` | `admit` and `seal` replay `sealed`; no `start`; the report has the same outcome, cause and evidence head as the first run |
| known under a *newer* attempt (someone retried) | `stale_operation` (the attempt is retired, §6.1) | the run ends `refused`; read the newer attempt instead |
| evicted (`task_not_found`) | a new task is registered | its `admit` needs a version above the one the node still holds for the task (§10): the counter of §4 gives one |

The acceptance case `replay_acts_on_nothing` runs the sealed row from a new process and
checks that create, admit and seal each answer `sealed`, that no `start` was sent and
that the workload's output and the evidence head are unchanged. The node-restart side is
§6.4: a task that was `running` reads `exited`/`unknown` (retry as a new attempt), a
`ready` task reads `created` and needs a new `admit` with a higher version.

Rules that follow for #490's runtime: treat a lease the control plane cannot see the
outcome of as *unknown*, never as succeeded; a retry is a new attempt under a new lease
generation, with the new attempt's `create` sent only once the old attempt is `exited`,
`stopped`, `revoked` or `sealed` (otherwise `attempt_mismatch`, §6.1); read `inspect`
before replacing an attempt, because a new attempt discards the old receipt (§9).

## 10. The proof

```bash
cd examples/node-control-plane && node --test       # 22 cases, no node, no sandbox
scripts/acceptance/node-js.sh                        # 5 cases against a real node; skips loudly without bubblewrap
WARD_REQUIRE_ISOLATION=1 scripts/acceptance/node-js.sh   # fail instead of skipping, as CI does
```

The unit suite proves the §7.4 vector (the serialised bytes, the key id, the signature
and the complete `admit` line), the id rendering and derivation, the version counter
across a process restart, and the JSON-lines framing against a fake adapter that records
every line. The acceptance starts a real node with the client's generated key in its
trust store and proves `completes_and_seals`, `fails_with_exit_status`,
`cancel_is_revoke_then_seal`, `replay_acts_on_nothing` and
`version_is_held_strictly_increasing`, verifying every evidence log with `ward-node
audit --task-root` (and `ward replay --verify` when a `ward` binary is at hand). It runs
as part of `scripts/acceptance/node.sh` in CI, so the table in the verify job's summary
ends with its verdicts; it passes as root and as an unprivileged user, which is how a
control plane's user runs it.

## 11. What is not available yet

Each of these is a row of [node-security-limitations.md](node-security-limitations.md) §3
with its impact, the mitigation and the issue; this is the list for a Node.js control
plane deciding what to put through the node today:

- **Result return.** The workload's stdout and stderr are drained and not returned, and
  the workspace is not exported (§9, §11.5). What a workload wrote is in
  `<task-root>/<task>/<attempt>/` on the host, readable only as the node's uid. Bounded
  output and a workspace export on `inspect`/`seal` are landing as protocol 1.4 in a
  parallel pull request; until it merges, design workloads whose exit status is the
  verdict (a verification run), and read artifacts on the host out of band.
- **In-sandbox callbacks.** There is no channel from the workload to the control plane:
  no `stream`, no socket into the sandbox (§6.1, §11.5). An agent loop that needs tool
  results, model calls or approvals from outside the sandbox stays on the control plane;
  the node runs the bounded actions it delegates.
- **Approvals.** The node has no approval step of its own; governance is the control
  plane's (ai-institution's action policy and approval resolution) and happens before
  `admit`. The grants the envelope carries record the decision; the node checks their
  shape and lineage, not their meaning.
- **Credentials.** Nothing is injected into the sandbox (#267); the only egress is an
  HTTP(S) proxy over a Unix socket on a node started with `--network-allowlist` (§9).
- **Remote transport.** The adapter runs on the node's host (#262); a control plane
  elsewhere brings its own channel to that host and ships pre-signed bytes over it.

## 12. Checklist for #490

Operator side:

- [ ] `ward-node` and `ward-node-adapter` installed from the release's node tarball on
      every execution host; node version recorded.
- [ ] A `ward-node` system user; a `ward-adapter` user for the institution's client; the
      node started with `--trusted-issuers`, `--task-root`, `--client-uid ward-adapter`,
      `--client-group`; `lifecycle.start` reads `true` from the client's user.
- [ ] The institution's issuer key generated on the control plane (PKCS#8 PEM, 0600), its
      trust-store line installed, `ward-node issuer-key-id` agreeing with the client.
- [ ] Snapshots imported for every project a workload may run over; the id stored with the
      work item.

ai-institution side, as an `InstitutionWorkerExecutionPort` (or an action execution port)
behind an adapter:

- [ ] Id derivation as §3: work item → `task_`, lease id + generation → `exec_` and
      `lease_`, worker → `agent_`, institution → `prn_`, run scope → `sess_`; the host's
      `node_` from configuration.
- [ ] A durable, strictly increasing admission version per WardOS task (§4), allocated
      before `admit` in the same transaction that records the attempt.
- [ ] The envelope built from the lease (grants from the policy decision, lifetime inside
      the work lease's, budget `deadlineAt - now`) and signed over the exact bytes (§5);
      the §7.4 vector in the adapter's own tests.
- [ ] The adapter spawned like TamperWard (§6): pre-signed `run`, `task_root`, a timeout
      above budget + grace + 90 s; one command at a time; `done` parsed into the outcome
      (§7); `unknown` mapped to failure.
- [ ] The signed bytes, proof, ids and version persisted before the first send; replay on
      restart with the same adapter conversation (§9); no second attempt until the first is
      ended.
- [ ] Cancellation wired to `SIGTERM` on the adapter (or a `revoke` command), and the
      retry path issuing a new lease generation and attempt (§8).
- [ ] The execution receipt carrying the WardOS binding, the receipt outcome, the exit
      status, the evidence log path and sealed head, so the verifier evidence package can
      bind the claim to it; `ward-node audit --json` as the operator's cross-check.
- [ ] The limitations of §11 reflected in which actions are routed to the node: exit
      status as verdict until result return lands; agent loops stay on the control plane.
