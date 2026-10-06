# Integrating `ward-node` from a Node.js control plane

Status: living document. It is the guide for a control plane written in Node.js or
TypeScript — concretely, the worker execution boundary of
[hexrift/ai-institution](https://github.com/hexrift/ai-institution) (its issue #490) —
that wants `ward-node` to run its bounded workloads. It says what to install, what to
keep where, how to derive the ids and the version, how to build and sign the envelope with
`node:crypto`, how to spawn `ward-node-adapter` and speak its JSON lines, how to read the
outcome, how to ask for and read back a bounded result, how to grant the action channel
and answer the workload's requests while it runs, how to grant a workload a credential the
node brokers without the secret ever reaching it, how to run the workload as an agent
adapter the node hosts, how to cancel and how to recover after a restart on either side. Every rule
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
back the receipt, the bounded output the manifest declared (§7.1 below) and, on the host, the
evidence log, and answering on its own side the approvals and decisions the workload asks
for through the action channel (§7.2 below). Where an action needs a service's credential,
the control plane grants it by name and the node leases and injects it, so the workload
reaches only that service's host and never holds the secret (§7.3 below). Where an action
must not reach a host or use a credential before a human says yes, the control plane holds
that capability in the manifest and the node refuses it until the control plane approves
the request the node opens for it (§7.4 below). Where the action is an agent runtime —
Claude Code, Codex or any program — the workload names its adapter and the node launches
it through the adapter contract under the same manifest (§7.5 below). What the node
cannot do yet for such a control plane is §11 below; read it before deciding which actions
go through the node.

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
   workload needs is in the snapshot: the workload is offline, unless its manifest grants
   a brokered credential and with it the credential's host (§7.3 below).

Check the host from the control plane's user before anything else:

```text
$ node examples/node-control-plane/control-plane.mjs capabilities --socket /run/ward-node/node.sock
{"protocol":{"major":1,"minor":3},…,"lifecycle":{"pause":true,"stop":true,"revoke":true,"admit":true,"start":true}}
```

`lifecycle.start` must be `true` (§5). For result return (§7.1 below) start the node with
`--output-return` as well; its document then also carries
`"output":{"stdio":true,"files":true}`. For the action channel (§7.2 below) start it with
`--action-channel`; its document then carries
`"actions":{"approval":true,"decision":true,"max_pending":8,"max_total":64,"max_wait_secs":3600}`.
For brokered credentials (§7.3 below) start it with `--network-allowlist` and
`--credentials <file>`; its document then reads
`"network":{"offline":true,"proxy_allowlist":true}` and
`"credentials":{"proxy_injection":true,"scoped_http_gateway":true}`. For approval holds
(§7.4 below) start it with `--network-allowlist`, `--action-channel` and
`--approval-hold`; its `actions` section then ends `…,"max_wait_secs":3600,"hold":true}`
(the adapter prints the document's keys in sorted order, so read it as an object).

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
below 1, a manifest outside §7.5's grammar or with an `output` or `actions` grant above
the node's ceilings (§7.1 and §7.2 below) or a `credentials` grant for a host its own
`network.custom` does not cover (§7.3 below), or an envelope over 32 KiB. It writes the keys
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

- **One command, one answer stream.** `capabilities`, `inspect`, `result`, `revoke`,
  `actions` and `answer` answer with one event each; `run` answers with a stream that ends
  in exactly one `done`. Do not send the next command before the stream ended: during a
  `run` the adapter is driving the node and reads stdin only afterwards, which is why the
  action channel is answered from a second adapter (§7.2 below).
- **Pre-signed only.** Send `envelope_json` (the signed string) and `proof`; never
  `issuer_seed_file` and `envelope`, which would put the key on the node's host. The
  adapter forwards the bytes unchanged.
- **Operation ids are yours** (`operation_ids`, §11.2): the scheme `create` N, `admit`
  N+1, `start` N+2, `stop` N+3, `revoke` N+4, `seal` N+5, `pause` and `resume` counting up
  from N+6 (at most 128 of each, §6.3). The reference client puts the answers of the
  action channel after them: the answer to request number R is N+261+R (`first_answer` is
  N+262; R is at most 64). Keep N with the signed bytes (§9); the reference client uses
  N = 1 for every attempt, since the node keeps ids per attempt.
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
lost answer being recovered by `inspect` and one replay, §11.2), `output` (the counts of
a result read after `seal` when the manifest granted one; the bytes are in `done`, §7.1
below) and, for a cancelled or budget-killed attempt, a `receipt` with `revoked`/`failed`
or `exited`/`failed`. The reference client's `Adapter` class is this conversation with a
promise per command and an `onEvent` hook; `--trace` on the command line prints every line
as above.

## 7. Outcomes and their mapping

The `done` event's `report` is the attempt report of §11.3. Read it in this order, and
map it as the table says; the reference client's `outcomeOf(report)` does exactly this
and returns `{outcome, certain, exitStatus, receipt, cause, finalState, sealed, cancelled,
deadlineExceeded, evidenceLog, evidenceHead, refused, transportError, output,
outputMissing, binding}` (`output` and `outputMissing`: §7.1 below):

| Report | Means | For ai-institution's execution receipt |
| --- | --- | --- |
| `outcome` `completed`, `outcome_certain` `true` | The sandbox exited 0 within its budget (§9); `cause` is `{"Exited":{"code":0}}` | A successful governed execution: `exitStatus` 0. The receipt's binding is the WardOS `binding`; keep `evidence_head` (the sealed log's head) and `evidence_log` as the adapter receipt id and the provenance pointer. |
| `outcome` `completed`, the manifest granted `output`, `output` `null` (`outputMissing` `true`) | The workload exited 0, but its granted result did not come back: `result` was refused or its answer lost (§6.6) | **Not a success:** what the action ran to produce cannot be read. Retry as a new attempt (§9 below), or read the workspace on the host out of band. |
| `outcome` `failed`, `cause` `{"Exited":{"code":N}}` | Non-zero exit | A failed execution with `exitStatus` N. |
| `outcome` `failed`, `cause` `"BudgetExceeded"` | Killed at `wall_clock_budget_ms`, also while paused (§10) | A failed execution by deadline; no exit status. |
| `outcome` `failed`, `cancelled` `true`, `cause` `"Killed"` or `"NotStarted"` | Revoked by the control plane (§8 below) | Cancelled; no exit status. The lease is revoked for good on this node. |
| `outcome` `unknown`, `outcome_certain` `false` | Ambiguous launch, lost child, node restart mid-run, or a transport failure the driver could not recover (§11.2, §9) | **Failed, never success.** The attempt may have had effects (§10, "ambiguous launch"); retry as a new attempt (§9 below), never the same one. |
| `outcome` `{"refused":{"verb","reason"}}` | The node refused `create`, `admit`, `start` or `inspect` and nothing further was sent (§11.2) | Not an execution. Map the reason (§8.3): `authority_denied` and `unsupported_grant` are configuration errors to fix before re-admitting under the same version; `stale_operation` at `admit` means the version counter is behind (§4); `lease_expired` and `lease_revoked` need a new lease; `resource_unavailable` at `start` means the snapshot is missing or the spawn failed, retry `start` with the same id. |
| `deadline_exceeded` `true` | The workload outlived its budget plus the driver's grace and was revoked | Failed; the node's budget enforcement did not end it in time, which is worth an alert. |
| `sealed` `false` | `seal` was refused or never answered | The task still counts against the node's 1 024 (§10); seal it from a later `inspect`/replay, or it is evicted when the registry fills. |

What the report does not carry: anything of the workload's output beyond what the
manifest declared (§7.1 and §11 below), and the receipt bound to the evidence head over the
socket (node-security-limitations.md §3.3) — the binding exists on the host, which is why
`evidence_head` from a run with `task_root` and `ward-node audit --task-root` are what
close it.

The command line prints the outcome object as one JSON line and exits 0 only for
`completed`, not cancelled and, when the manifest granted output, with the output back; 1
for everything else; 2 for its own failure, a returned result that fails verification
included.

### 7.1 Result return

A node started with `--output-return` (node-integration.md §2.1) returns a bounded result
of an ended attempt when, and only when, the envelope's manifest asked for it (§6.6,
§7.5). The capability document says whether it can: `output.stdio` and `output.files`
both `true`; without them the section is absent and a manifest with an `output` grant is
refused `unsupported_grant` at `admit`, with nothing run.

**The grant** is part of the signed manifest, next to `network`:

```json
{"network":"offline","output":{"stdio_bytes":4096,"files":["out/report.json","coverage/summary.json"],"files_bytes":65536}}
```

`stdio_bytes` is how much of the *head* of each of stdout and stderr to keep;
`files` are exact workspace paths (0–64, each 1–255 bytes of `a-z A-Z 0-9 . _ - /`,
relative, no `.` or `..` component, no globs, no directories); `files_bytes` is the
content budget for all of them together, taken in declaration order. The node honours at
most 1 MiB (1 048 576) per stream and 8 MiB (8 388 608) of file content and refuses a
larger grant `unsupported_grant`; `0` is a grant too (counts and digests only). With the
reference client, `workload.manifest` takes the object, `outputGrant({stdioBytes, files,
filesBytes})` builds it, and both refuse a path outside the grammar or a budget above the
ceilings before anything is signed (`OUTPUT_CEILINGS` holds them); the command line takes
`--stdio-bytes`, `--files` (repeatable, comma-separated) and `--files-bytes`.

**What comes back.** After `seal` the adapter asks `result` once and `done`'s report
carries `output` (§11.3), the §6.6 object: `stdout` and `stderr` as `{bytes, truncated,
dropped, content_base64}` and one `files` entry per declared path, in declaration order.
`{"cmd":"result","binding":{…}}` reads the same bytes again later, as often as needed,
until the attempt is replaced (`Adapter.result(binding)`, `control-plane.mjs result`).
Each file entry is one of three shapes:

| Entry | Means |
| --- | --- |
| `{path, size, digest, truncated: false, content_base64}` | Returned whole: `size` bytes, `digest` the BLAKE3-256 of exactly those bytes. |
| `{path, size, digest, truncated: true}` | Digest-only: the file was there and regular, but its content did not fit what was left of `files_bytes`; `size` and `digest` are still of the whole file. |
| `{path, skipped}` | Not read: `missing` (nothing at the path), `not_a_regular_file` (a directory, a symlink or anything else, on the path or at it; nothing is followed) or `too_large` (above 64 MiB, neither read nor digested). |

`truncated` on a stream means the workload wrote more than `stdio_bytes`: the first
`bytes` are returned and `dropped` counts the rest, which is gone (no tail is kept).
`truncated` on a file means digest-only. Neither is an error of the attempt; both say the
grant was smaller than what the workload produced. Size the grant to the verdict the
control plane needs (a JSON report, a summary), not to the workload's whole log.

**Verify before use.** `decodeOutput` (and `outcomeOf`, which calls it) decodes the base64,
checks that every count, flag and shape agrees with §6.6, recomputes BLAKE3-256 over each
returned file's content and compares it with `digest`; a mismatch is refused (a
`ContractError`, exit status 2 on the command line), never reported as the file. Given the
grant the attempt was admitted under (`outcomeOf(report, {grant: outputGrantOf(signed.envelope_json)})`),
it also holds the result to it: exactly the declared paths in order, no stream head above
`stdio_bytes`, no more returned content than `files_bytes`. The same digests are recorded,
without the bytes, in the sealed evidence log's `NodeAttemptOutputCollected` record
(§6.5), so a check on the host that reads the log binds what the control plane received
to what the node collected; the acceptance finds each returned digest in the sealed log. `writeReturnedFiles(dir, files)`
(`--out-dir` on the command line) writes the returned files under one directory at their
declared paths, mode 0600, refusing before anything is written a path that would leave the
directory, cross a symlink in it or overwrite a file.

**A missing or unknown output is not success.** When the grant asked for a result and
`output` is `null` — the node refused `result` (`resource_unavailable`: the node lost
track of the workload, restarted before collecting it, or could not store it), the answer
was lost, or the attempt was refused or never ran — `outcomeOf` sets `outputMissing`, and
the command line exits 1 even for a `completed` attempt: whatever the control plane ran
the workload to learn cannot be read. An `unknown` outcome stays unknown whatever output it
has. A file entry `skipped` or digest-only is a fact about the workspace, reported
truthfully; whether a verdict file that came back `missing` fails the action is the
control plane's policy, and the conservative reading is that it does.

### 7.2 The action channel

A node started with `--action-channel` gives an attempt whose manifest grants `actions` a
channel from the workload to the control plane (node-integration.md §6.7,
[ADR-0031](decisions/ADR-0031-node-action-channel.md)): the workload connects to the Unix
socket named by `WARD_ACTION_SOCKET` (`/run/ward/actions.sock`), writes one request per
line, `{"id","kind","summary","detail"}`, and waits for one line back,
`{"id","decision","note"?}`. The control plane lists the pending requests with `actions`
and answers each with `answer`. Without the flag the capability document has no
`actions` section and a manifest with the grant is refused `unsupported_grant` at
`admit`, with nothing run.

**The grant** is part of the signed manifest, next to `network` (and `output`):

```json
{"network":"offline","actions":{"kinds":["approval"],"max_pending":2,"max_total":8,"wait_secs":300}}
```

`kinds` are the requests the workload may send, `approval` (permission to do what the
summary says) and `decision` (a yes-or-no choice made for it), one or both, without
repeats; `max_pending` is how many may wait at once, `max_total` how many in the attempt's
lifetime, `wait_secs` how long each waits before the node answers it `expired`. All three
are integers of at least 1, with `max_pending` ≤ `max_total`; the node honours at most 8
pending, 64 in all and 3600 seconds (`ACTION_CEILINGS`) and refuses a larger grant
`unsupported_grant`. `workload.manifest` takes the object, `actionsGrant({kinds,
maxPending, maxTotal, waitSecs})` builds it, and both refuse a kind outside the two, a
repeat, a zero or a non-integer bound, `max_pending` above `max_total` and a bound above a
ceiling before anything is signed; `actionsGrantOf(envelope_json)` reads the grant back
from the signed bytes. The command line takes `--actions <kind>[,<kind>]` with
`--actions-max-pending` (default 2), `--actions-max-total` (default 8) and
`--actions-wait-secs` (default 300).

**Reading.** `Adapter.actions(binding)` sends `{"cmd":"actions","binding":{…}}` and
resolves with `{state, pending}`: the attempt's lifecycle state and its pending requests,
oldest first, each `{action, id, kind, summary, detail, expires_in_ms}`. `action` is the
node's request number, the one `answer` names; `id` is the workload's; `expires_in_ms` is
frozen while the attempt is paused. `decodeActions` holds the listing to the contract
before anything acts on it (ids of 1–64 bytes of `A-Z a-z 0-9 . _ : -`, unique; a summary
of 1–512 bytes; a detail of at most 16 KiB; strictly increasing numbers; at most 8, and
none unless the attempt is `running` or `paused`) and, given the grant, to it (only
granted kinds, at most `max_pending`, numbers up to `max_total`, no longer wait than
`wait_secs`); a listing outside them is refused, not answered. A refusal resolves
`{rejected: reason}`: `unsupported_operation` from a node without the flag,
`task_not_found` or `attempt_mismatch` before the run's `create` has registered the
attempt, `lease_mismatch`.

**Answering.** `Adapter.answer(binding, request, decision, operationId, note?)` sends
`{"cmd":"answer","binding":{…},"request":R,"decision":"approved"|"denied","operation_id":M,"note"?}`
and resolves with `{result: "answered", request, decision, operation_id}` or
`{result: "rejected", reason, operation_id}`. A control plane answers `approved` or
`denied` only (`expired` and `cancelled` are the node's) and the note is at most 512 bytes;
anything else is refused before it is sent. An answer event that names another request,
decision or operation id than the one sent, or a reason outside §6.7, is refused. The
reasons, and what the reference loop does with each:

| Reason | Means | The loop |
| --- | --- | --- |
| `already_answered` | Answered already: by another `answer`, or `expired` or `cancelled` by the node | Final for the request. |
| `stale_operation` | This operation id already applied a different answer | Final; never resent under another id. |
| `unknown_request` | The attempt never recorded that number | Final. |
| `invalid_state` | The attempt is no longer `running` or `paused` | Final; the next listing reads the end. |
| `resource_unavailable` | The node could not record the answer; the request is still pending | Sent again at the next poll, same id and answer. |

**The second process.** The adapter's `run` holds its process until the attempt is sealed
(§6 above), so the answers come from a second `ward-node-adapter` beside it.
`Adapter.answerLoop(binding, policy, {pollMs, signal, runDir})` is that loop: on its own
adapter it polls `actions` every `pollMs` (default 250), asks `policy(request)` once per
request (`"approved"`, `"denied"`, `{decision, note}`, or `null` to leave it to someone
else), answers, and resolves `{state, answers}` once a listing reads an ended state, or
with state `null` when `signal` aborts. Before the run's `create` it waits through
`task_not_found`; a node that cannot serve the channel, or a listing outside the grant,
ends it with an error. `control-plane.mjs run` starts it beside the run when given a
policy, aborts it when `done` arrives, prints each request and its answer on stderr and
lists the answers in the outcome's `actions`:

```text
$ node control-plane.mjs run … --actions approval --approve-all --note "ok by policy" -- python3 agent.py
control-plane: request 1 (approval, id deploy-1): deploy to staging
control-plane:   plan: rotate 3 services
control-plane:   expires in 300 s unless answered
control-plane: request 1 answered approved (operation 263) with note "ok by policy"
{"outcome":"completed",…,"actions":[{"request":1,"id":"deploy-1","kind":"approval","summary":"deploy to staging","decision":"approved","note":"ok by policy","operation_id":263,"result":"answered","replayed":false}]}
```

`--deny-all` answers every request `denied`; `--ask` shows each one on stderr and reads
`y [note]` or `n [note]` from stdin (anything but `y` or `yes` denies; the end of stdin
denies with the note `no answer on stdin`). Without a policy nobody in that process
answers: a run driven elsewhere is answered with `control-plane.mjs actions` and
`control-plane.mjs answer --state-dir <dir> --attempt <exec_…> --request R --decision
approved|denied [--note …]`, or with an explicit binding and `--operation-id`.

**Idempotent answers.** An answer is a mutating request with an operation id, and the
node applies an id once: the same id with the same request, decision and note is
answered `answered` again and appends nothing, also once the attempt has ended; the same
id with anything else is `stale_operation` (§6.7). The reference client takes the id from
the run record's scheme, one per request number (`answerOperationId(ids, R)`, N+261+R),
and writes the answer into the run record (`recordAnswer`, the record's `answers`)
**before** sending it. A control plane that restarts after deciding but before the node
answered finds the answer in its record and sends exactly that answer again, under the
same id, without asking its policy again; one that restarts after the node applied it
finds the request no longer pending, or, replaying anyway, gets `answered` again. Either
way the request is answered once, as the record says. `control-plane.mjs answer` with
`--state-dir` does the same and refuses a different answer to a recorded request before
sending it. Keep one answerer per run record at a time: the record is rewritten whole.
The applied ids live in the node process: after a node restart the attempt has ended
(recovered `exited`, its pending requests answered `cancelled`) and a replay is
`invalid_state`; the evidence log is the durable record of what was answered.

**What the evidence log says.** Every request is recorded `NodeActionRequested` (its
number, kind, and the size and BLAKE3-256 of the summary and of the detail) before it is
listed, and every answer `NodeActionAnswered` (the number, the decision, the `answer`'s
operation id or none for `expired` and `cancelled`, and the size and digest of the note)
before the workload is told; never the text. A check on the host binds what the control
plane saw to the sealed log by hashing the UTF-8 bytes of the summary, detail and note
with `blake3Hex`; the acceptance decodes the log's action records from its raw bytes and
finds exactly the digests and operation ids the client used. When the attempt ends (the
workload exits, it is cancelled, its budget runs out) every pending request is answered
`cancelled` before `NodeAttemptEnded`.

**What an approval is.** A recorded statement, relayed. The workload proceeds because it
chose to wait for the answer, and must treat everything but `approved` (`denied`,
`expired`, `cancelled`, an end of file without a reply) as "do not proceed". The node
enforces nothing on an approval the workload asked for: it widens no capability,
credential or network, and is not signed per answer; it is authorised by the exact binding
on the node's socket (node-security-limitations.md §3.2). What the node does enforce is a
hold (§7.4 below): an approval of a request the node opened itself for a held host or
credential. Governance that must hold whatever the workload does stays where it is today:
in the control plane's policy, before `admit`, in the grants, the hold and the manifest it
signs.

### 7.3 Brokered credentials

A node started with `--network-allowlist` and `--credentials <file>` leases, for an
attempt whose manifest grants it, a credential from a provider its operator configured,
and the attempt's egress proxy injects it into the workload's requests for that service
(node-integration.md §6.8, [ADR-0034](decisions/ADR-0034-node-brokered-credentials.md)).
The control plane names a service, a host and a lifetime, never a provider, a header or a
secret: those are the operator's, and the secret never reaches the sandbox, the evidence
log or any answer the control plane reads.

**The grant** is part of the signed manifest, last, after `network` (and `output` and
`actions`):

```json
{"network":{"custom":["artifacts.example.com"]},"credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":600}]}
```

1 to 4 grants, no service twice. `service` is `[a-z][a-z0-9-]{0,31}`, the name of a service
the node's operator configured; `host` a lowercase DNS name, without a wildcard and not an
address literal, that one of the manifest's own `network.custom` patterns covers
(`*.example.com` covers `a.example.com`, never `example.com`), so an offline manifest grants
no credential; `ttl_secs` an integer of at least 1 (and at most 2^32 − 1, `CREDENTIAL_LIMITS`),
the longest the lease may live; nothing else. `workload.manifest` takes the object and
`credentialsGrant([{service, host, ttlSecs}])` builds the list; both refuse anything outside
that grammar before anything is signed, and `manifest` refuses a host its `network.custom`
does not cover. `credentialsGrantOf(envelope_json)` reads the grant back from the signed
bytes.

**The node's offer.** The capability document says whether a node brokers at all, not
which services: `credentials.proxy_injection` and `credentials.scoped_http_gateway` are both
`true` exactly on a node started with `--network-allowlist` and `--credentials` (§5). Any
other node refuses the grant `unsupported_grant` at `admit`, so the client reads the
document first: `brokersCredentials(capabilities)` says whether, and
`requireCredentialBroker(capabilities)` refuses, naming `unsupported_grant`, before a
version is allocated or anything is signed. Which services a node offers, for which host
and up to which `ttl_secs`, the operator tells the control plane; a grant for a service the
file does not configure, for a host other than that service's upstream or above its
`max_ttl_secs` is refused `unsupported_grant` by the node itself: the outcome is `refused`
and certain, nothing ran, no provider was asked and no version was consumed (§7.5).

**The command line.** `control-plane.mjs run --credential <service>=<host>[:<ttl-secs>]`,
repeatable, puts the grant in the manifest with a `network.custom` of exactly the granted
hosts; without a TTL the lease may live as long as the budget, rounded up to whole seconds.
It reads the node's capability document before anything else and exits 2, naming
`unsupported_grant`, on a node that does not broker credentials; the outcome lists the
grants in `credentials`, and `replay` lists them from the run record and resends the same
bytes (an attempt that ended is not started again, so nothing is leased again):

```text
$ node control-plane.mjs run … --credential artifacts=artifacts.example.com:600 -- python3 fetch.py
{"outcome":"completed",…,"credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":600}]}
```

**What the workload does.** It sends an ordinary HTTP/1.1 request to the attempt's proxy
socket (`WARD_PROXY_SOCKET`) for `/<service>/…`. The proxy strips `/<service>`, forwards the
request to the service's upstream over TLS with the configured header set to the leased
value, replacing any header of that name the workload sent, within the service's paths and
read-only unless the operator granted writes, and streams the answer back. Nothing else
changes in the sandbox: no variable, file or socket carries the credential, a `CONNECT`
tunnel is never injected into, and a request to any other host carries nothing the proxy
added. A tool that only speaks `HTTP_PROXY` cannot use the route unless it runs as a hosted
agent adapter on a node with a `ward-agent` shim, whose relay and base URL reach it (§7.5
below).

**The lease and its end.** The node leases at `start`, before the spawn, bound to the
attempt (the provider's session is the attempt id), the service and the host, for at most
the shortest of the grant's `ttl_secs`, the service's and the provider's ceilings and the
attempt's budget. When the attempt ends — its exit, its budget, `stop`, or a cancel
(`revoke`, §8 below) — every route is withdrawn and every lease revoked at its provider
before the end is recorded; a node restarted after it died revokes what it left before it
serves. A provider that cannot serve fails closed: the attempt still runs, its request is
answered `403` (`credential lease expired`), and the log names the provider's state. There
is no fallback to another credential; the workload's exit status carries the rest.

**What the evidence log says.** Every grant is recorded `CredentialGranted` (the subject
`issued <host> lease b3:<32 hex>`, the lease's permissions and lifetime, delivery
`ProxyInjected`) before `NodeAttemptLaunched`, each injected request a `NetworkRequested`
verdict, and the route's end `CredentialRevoked` (`UserRevoked` after a cancel,
`SessionEnded` otherwise) before `NodeAttemptEnded`; `CredentialDenied` names the rule
`credential-provider:<provider>:<state>` when no lease could be issued. Never the leased
value, its digest or the provider's revocation handle. The acceptance decodes these
records from the sealed log's raw bytes, and finds neither the leased token nor the
provider token in the log, the workload's output, the task root, the node's state or
anything the client wrote.

### 7.4 Approval holds

A node started with `--network-allowlist`, `--action-channel` and `--approval-hold` holds
the hosts and credential services a manifest's `hold` names until the control plane
approves them (node-integration.md §6.9,
[ADR-0035](decisions/ADR-0035-node-approval-hold.md)). It is the per-session approval hold
for what the node enforces: the question is the node's, not the agent's claim, deny is the
default, and the record precedes the release.

**The hold** is part of the signed manifest, last, after `credentials`:

```json
{"network":{"custom":["deploy.example.com","artifacts.example.com"]},"actions":{"kinds":["approval"],"max_pending":1,"max_total":4,"wait_secs":300},"credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":600}],"hold":{"hosts":["deploy.example.com"],"services":["artifacts"]}}
```

`hosts` are patterns of the manifest's own `network.custom`, exactly as written there;
`services` services of its own `credentials`; each list non-empty when present, at least
one present, nothing twice, at most 8 in all (`HOLD_LIMITS`), and the manifest must grant
`actions` naming `approval`. `holdGrant({hosts, services})` builds it, `manifest` refuses a
hold outside that grammar or naming what the manifest does not grant before anything is
signed, and `holdGrantOf(envelope_json)` reads it back. `offersApprovalHold(capabilities)`
says whether a node honours holds (`actions.hold` is `true`), and
`requireApprovalHold(capabilities)` refuses, naming `unsupported_grant`, before a version is
allocated; any other node refuses the manifest `unsupported_grant` itself.

**What happens.** The first request the attempt's proxy sees for a held capability — a
request to a host a held pattern covers, a credential route to it included, or on a held
service's route — opens one `approval` request on the channel and is refused `403` with
the body `held for approval`. The listing shows it with its `hold` (§7.2 above): id
`hold:<n>` (the capability's place, hosts first, then services), summary
`network <pattern>` or `credential <service>`, and `"hold":{"host":…}` or
`"hold":{"service":…}`. `heldCapabilities(hold)` gives the ids and summaries to expect, and
`decodeActions(listing, grant, hold)` (which `answerLoop` and the command line apply with
the run record's grant and hold) refuses a listing whose node-opened requests do not match
them. Answering it `approved` releases that capability for the rest of the attempt; `denied`,
an expiry or the attempt's end keep it refused (`approval denied`, `approval expired`,
`approval cancelled`). The node's requests take numbers past the workload's (up to 72 in
all), and `answerOperationId` gives their answers operation ids of the run's scheme like
any other. The workload sees only `403`s until the release: it should retry at its own pace
and treat a named refusal as final.

**The command line.** `control-plane.mjs run --hold host=<pattern>` or
`--hold service=<name>`, repeatable, with `--actions approval` and the `--credential` flags
whose hosts and services it holds, signs the hold; the policy flags answer the node-opened
requests like the workload's, and each is printed as opened by the node for its hold:

```text
$ node control-plane.mjs run … --actions approval --credential artifacts=localhost:60 --hold service=artifacts --approve-all -- python3 held.py
control-plane: request 1 (approval, id hold:1, opened by the node for its hold on artifacts): credential artifacts
control-plane: request 1 answered approved (operation 263)
{"outcome":"completed",…,"actions":[{"request":1,"id":"hold:1","kind":"approval","hold":{"service":"artifacts"},"summary":"credential artifacts","decision":"approved",…}],"hold":{"services":["artifacts"]}}
```

It reads the node's capability document first and exits 2, naming `unsupported_grant`, on a
node without `--approval-hold`; a hold outside the grammar or its manifest exits 2 before
the node is asked.

**What the evidence log says.** The node's request is `NodeActionRequested` and its answer
`NodeActionAnswered`, as for any request; each refusal is a `NetworkDenied` for the
destination with the reason `PolicyDeny` and the rule `hold:<state>:<n>`. The acceptance
decodes all three from the sealed log's bytes and checks the request's summary digest
against `blake3Hex("credential artifacts")`.

### 7.5 Agent adapters

A node started with `--agent-adapter <id>` hosts that agent adapter on workloads that name
it (node-integration.md §6.10, §7.3,
[ADR-0036](decisions/ADR-0036-node-hosted-agent-adapters.md)): `claude-code`, `codex` or
`process`. The adapter is named in the workload, beside the argv, not in the manifest, so
the same manifest bytes serve every adapter:

```json
"workload":{"argv":["claude","-p","fix the build"],"capability_manifest":{…},"snapshot":"…","wall_clock_budget_ms":600000,"adapter":{"id":"claude-code"}}
```

`buildEnvelope` takes it as `workload.adapter` (an id) and spells it last in the workload,
and not at all without one; `workloadAdapter(id, argv)` refuses an id outside the grammar
(1–64 bytes of `a-z 0-9 . _ -`) or an `argv[0]` the adapter cannot launch (a relative path
with a `/`) before anything is signed, and `agentAdapterOf(envelope_json)` reads it back.
`hostsAgentAdapter(capabilities, id)` says whether a node lists it in `adapters.hosted`, and
`requireAgentAdapter(capabilities, id)` refuses, naming `unsupported_grant`, before a version
is allocated; any other node refuses the envelope `unsupported_grant` itself. `AGENT_ADAPTERS`
lists the ids a node can host.

**What the node does with it.** It launches `argv[0]` with the adapter's environment and
settings files (Claude Code's `CLAUDE_CONFIG_DIR` and settings, Codex's `CODEX_HOME`) and,
for Claude Code, a hook socket at `/run/ward/hooks.sock` whose lines are answered `allow`
and recorded as agent-origin claims; everything else is the manifest's, exactly as for any
workload. The provider is metadata: a runtime reaches its model API only through a
`credentials` grant (§7.3 above) for a service the operator configured, named after the
provider by convention, on `WARD_PROXY_SOCKET`. On a node whose operator named a
`ward-agent` shim (`--agent-shim`, node-integration.md §6.10, ADR-0037) the runtime runs
under it: Claude Code's command hooks reach the hook socket, and behind the attempt's proxy
the shim relays `127.0.0.1:3128` to it, with `HTTPS_PROXY` naming the relay and the
provider's base URL (`ANTHROPIC_BASE_URL=http://127.0.0.1:3128/anthropic`,
`OPENAI_BASE_URL=http://127.0.0.1:3128/openai/v1`) and a placeholder key set only when the
manifest grants the service named after the provider. Nothing the client sends changes. The
sealed log holds the binding (`{"agent_adapter":{…}}`, origin `agent`) right after the
launch record.

**The command line.** `control-plane.mjs run --agent-adapter <id> -- <argv>` (`--adapter`
stays the `ward-node-adapter` binary) reads the node's capability document first and exits
2, naming `unsupported_grant`, on a node that does not host the adapter; an id or a program
outside the grammar exits 2 before the node is asked. The outcome names it:

```text
$ node control-plane.mjs run … --agent-adapter codex -- codex exec "fix the build"
{"outcome":"completed",…,"agent_adapter":"codex"}
```

`replay` names the recorded adapter the same way.

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
--attempt <exec_…>` resends it. With an action channel the record also holds every answer
given, written before it was sent (§7.2 above); `replay` with a policy answers the
attempt's requests through the same loop and sends a recorded answer again, under its
id, instead of deciding anew.

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
cd examples/node-control-plane && node --test       # 93 cases, no node, no sandbox
scripts/acceptance/node-js.sh                        # 25 cases against real nodes; skips loudly without bubblewrap
WARD_REQUIRE_ISOLATION=1 scripts/acceptance/node-js.sh   # fail instead of skipping, as CI does
```

The unit suite proves the §7.4 vector (the serialised bytes, the key id, the signature
and the complete `admit` line), the id rendering and derivation, the version counter
across a process restart, the JSON-lines framing against a fake adapter that records
every line, and result return: the `output` grant's grammar and ceilings, decoding with
every digest recomputed (a mismatch refused), the result held to its grant, a granted
output that did not come back reported missing, writing returned files without
escaping their directory, and the action channel: the `actions` grant's grammar and
ceilings, listings and answers held to the contract, the answer loop against a fake
adapter scripted with requests (each answered once by the policy, persisted before it is
sent, the loop stopping at the attempt's end), a restarted loop replaying the recorded
answer under the same operation id without asking again, each refusal handled by what it
means, and `run --approve-all`, `--deny-all` and `--ask` and the standalone `actions` and
`answer` commands end to end, and brokered credentials: the `credentials` grant's grammar
held to `ward-node-protocol`'s (the same accepted and refused services, hosts and TTLs),
its hosts held to the manifest's `network.custom`, its place last in the signed bytes, the
capability document's two flags read before signing, and `run --credential` refused on a
node that does not broker before a version is allocated, signed and listed in the outcome
on one that does, and replayed, and approval holds: the `hold`'s grammar held to
`ward-node-protocol`'s (the same signed bytes for the same hold), its hosts and services
held to the manifest's, a listing's node-opened requests held to the hold, `actions.hold`
read before signing, and `run --hold` with `--approve-all` and `--deny-all` and its refusals,
and agent adapters: the workload's `adapter` spelled last and absent without one, the
manifest the same bytes with or without it, the id and program grammar, `adapters.hosted`
read before signing, and `run --agent-adapter` signed, named in the outcome, replayed and
refused on a node that does not host it.
The acceptance starts a real node with the client's generated
key in its trust store, `--output-return` and `--action-channel` and proves `completes_and_seals`,
`fails_with_exit_status`, `cancel_is_revoke_then_seal`, `replay_acts_on_nothing`,
`version_is_held_strictly_increasing`,
`output_returns_declared_content_with_matching_digests` (both streams and two declared
files back byte for byte, each digest equal to BLAKE3-256 of the file on the host and in
the sealed log, `--out-dir` holding them),
`output_marks_truncation_past_the_budgets` (the heads with `truncated` and the dropped
counts, a file past the budget digest-only with the host file's digest) and, against a
second node without the flag, `output_grant_is_refused_without_the_flag`
(`unsupported_grant`, reported `refused` and certain, not `unknown`); and, with a Python
workload in the sandbox that asks through `/run/ward/actions.sock` and proceeds only on
`approved`, `actions_approval_lets_the_workload_proceed` (`--approve-all`: the workload
exits 0 and the sealed log records the request's digests and the approval under operation
263 with the note's digest before the end), `actions_denial_stops_the_workload`
(`--deny-all`: exit 3, the run fails), `actions_unanswered_request_expires` (`wait_secs`
2: the node answers `expired`, recorded with no operation id; a late answer is
`invalid_state`), `actions_cancel_while_pending_answers_cancelled` (cancelling the run
while the request is listed answers it `cancelled` before the end),
`actions_answered_from_a_second_process` (the standalone `actions` and `answer`: a replay
answered again, `stale_operation`, `already_answered` and `unknown_request` from the real
node, exactly two answers in the log) and, against the node without the flag,
`actions_grant_is_refused_without_the_flag_or_outside_the_grammar`; and, against a node
started with `--network-allowlist` and `--credentials`, a fake OpenBao and a fake upstream on
127.0.0.1 (`fixtures/fake-credential-services.mjs`) and a Python workload that sends one
request with a placeholder `Authorization` header through `WARD_PROXY_SOCKET`,
`credentials_injected_by_the_proxy_never_seen_and_revoked` (the upstream receives the leased
token in place of the placeholder; the lease is bound to the attempt, the service and the
host for the grant's TTL and revoked at the provider when the attempt ends; neither the
leased token nor the provider token is in the workload's returned output and environment,
the sealed log, the task root, the node's state or the client's files; the log's
`CredentialGranted` and `CredentialRevoked` records decoded from its bytes),
`credentials_replay_leases_nothing`, `credentials_cancel_revokes_the_lease` (`UserRevoked`
and the provider's revocation on cancel) and, against a node with `--network-allowlist` and
without `--credentials`, `credentials_grant_is_refused_without_the_flag_or_outside_the_grammar`
(the client's refusal before signing, the node's own `unsupported_grant` for the same signed
grant, and the credentials node's for a TTL above the ceiling and an unconfigured service);
and, against a node started with `--network-allowlist`, `--credentials`, `--action-channel`
and `--approval-hold` and a Python workload that retries the held route until it is answered
with anything but `held for approval`, `hold_approval_releases_the_held_credential` (the
node's request `hold:1` approved by `--approve-all`, the next request reaching the fake
upstream with the lease injected; the request recorded before the approval, the approval
before the released request, and the hold's refusal under its rule), `hold_denial_keeps_it_refused` (`approval denied`, exit 3, nothing
upstream), `hold_expiry_keeps_it_refused` (`approval expired` after a 2 s wait) and,
against a node without `--approval-hold`, `hold_is_refused_without_the_flag_or_outside_its_manifest`;
and, against a node started with `--agent-adapter claude-code` and `--agent-adapter codex`
(the shipped build) whose own environment holds model keys, with a Claude Code fake that
writes its hook lines to `$WARD_SOCKET` and a Codex fake that checks its home,
`agent_adapters_run_one_manifest` (both complete under byte-identical signed manifests,
none of the node's keys in either sandbox, one `agent_adapter` binding in each sealed log),
`claude_code_hooks_are_claims` (every hook line answered `allow` and recorded as a claim,
none in Codex's log, the adapter's directory gone with the attempt) and
`agent_adapter_refused_where_not_hosted` (the client's refusal of `process` before signing,
and the plain node's own `unsupported_grant` for the signed Codex run),
verifying every evidence log with `ward-node audit --task-root` (and `ward replay --verify`
when a `ward` binary is at hand). The shipped `ward-node` never connects to a loopback
address and speaks only TLS upstream, so the credentials and hold nodes, alone, are
`ward-node` built with its `test-loopback` feature, as ward-node's own
`tests/node_credentials_cli.rs` and `tests/node_hold_cli.rs` run it; the script builds it into a target directory of its own (or takes
`WARD_NODE_LOOPBACK_BIN`), and every other node runs the shipped build, `WARD_NODE_BIN`,
which it builds without the feature into a target directory of its own as well, never
reusing the `test-loopback` build a `cargo test` leaves in `target/debug`. A build with the
feature says so in its `--version`, and the script refuses a `WARD_NODE_BIN` that does (and
a `WARD_NODE_LOOPBACK_BIN` that does not) before any node starts. It runs
as part of `scripts/acceptance/node.sh` in CI, so the table in the verify job's summary
ends with its verdicts; it passes as root and as an unprivileged user, which is how a
control plane's user runs it.

## 11. What is not available yet

Each of these is a row of [node-security-limitations.md](node-security-limitations.md) §3
with its impact, the mitigation and the issue; this is the list for a Node.js control
plane deciding what to put through the node today:

- **Output beyond the bounded result.** A result is the head of each stream up to 1 MiB
  and the files the manifest declared by exact path, up to 8 MiB of content, read once
  the attempt has ended (§7.1 above; node-integration.md §6.6). There is no tail, no streaming while the attempt
  runs, no globs or directories and no workspace export (§11.5): what the workload wrote
  beyond the declared files stays in `<task-root>/<task>/<attempt>/` on the host,
  readable only as the node's uid. Design workloads to leave their verdict in a small
  declared file (a JSON report) and their exit status, and read anything larger on the
  host out of band.
- **In-sandbox callbacks beyond questions.** The action channel (§7.2 above) carries
  bounded `approval` and `decision` requests out of the sandbox and a yes or no, with an
  optional note of at most 512 bytes, back in; nothing else. There is no `stream` (§6.1,
  §11.5), and no tool results, model calls or credentials reach the workload through the
  channel, so an agent loop that needs them stays on the control plane; the node runs the
  bounded actions it delegates.
- **Approvals beyond a hold on a host or a credential.** Governance is the control plane's
  (ai-institution's action policy and approval resolution) and happens before `admit`. The
  node enforces an approval only as a hold (§7.4 above) on a host or a brokered
  credential the manifest names; an approval a workload asks for through the action channel
  (§7.2 above) is a recorded statement it acts on, nothing gates a file it writes or a
  command it runs, a release lasts for the rest of the attempt, and no answer is signed per
  answer (node-security-limitations.md §3.2). The grants the envelope carries record the
  decision; the node checks their shape and lineage, not their meaning.
- **Credentials beyond a proxy-injected header.** A credential reaches a workload's traffic
  only as a header the attempt's proxy injects into plain HTTP/1.1 requests for
  `/<service>/…` on `WARD_PROXY_SOCKET` (§7.3 above); nothing is injected into a `CONNECT`
  tunnel, there is no in-sandbox relay for a tool that only speaks `HTTP_PROXY` outside a
  hosted adapter on a node with a shim (§7.5 above), the
  capability document does not list the services a node offers (the operator says) (#267);
  a credential is held for an approval only by a hold (§7.4 above).
- **A real agent runtime on a node without a shim.** A hosted adapter (§7.5 above) gets
  its command hooks and an HTTP base URL for its model only on a node whose operator named
  a `ward-agent` shim (`--agent-shim`, ADR-0037), which the capability document does not
  show; elsewhere Claude Code's command hooks find nothing to run and a runtime that needs
  a base URL has none. Hook answers are `allow` everywhere and a `PermissionRequest` is not
  bridged onto the action channel: hold the hosts and credentials that matter (§7.4 above)
  (#279, #424).
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
- [ ] Where a workload needs a service's credential: the node started with
      `--network-allowlist` and `--credentials <file>` (the node user's own file, writable
      by no one else, its provider token in a 0600 file), each service configured with its
      upstream, paths, permissions and `max_ttl_secs` (node-integration.md §6.8); the
      services, their hosts and ceilings recorded in the institution's configuration;
      `credentials.proxy_injection` and `scoped_http_gateway` read `true` from the
      client's user.
- [ ] Where a host or credential must wait for a human: the node started with
      `--approval-hold` as well (with `--action-channel` and `--network-allowlist`);
      `actions.hold` reads `true` from the client's user.
- [ ] Where an agent runtime runs on the node: the node started with `--agent-adapter`
      for each runtime the institution routes there (`claude-code`, `codex`, `process`);
      `adapters.hosted` lists them from the client's user; the model provider's service
      (`anthropic`, `openai`) configured in `--credentials` with its upstream, header,
      the API path in `paths` and `write` among its `permissions` (a model API is a
      `POST`).
- [ ] Where a real Claude Code or Codex runs there: the node started with
      `--agent-shim <file>` naming the release's `ward-agent` (from the runtime tarball or
      the image, owned by root or the node user, writable by no one else) and
      `--network-allowlist`; the node refuses to start with a shim it cannot verify, and the
      operator records that it relays, since the capability document does not say.

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
- [ ] Nodes started with `--output-return`, and each action's verdict file and stream
      budget declared in its manifest's `output` grant within the ceilings (§7.1 above); every
      returned file's digest verified before use; a granted output that is missing treated
      as failure, never success.
- [ ] Where a workload must ask before an irreversible step: nodes started with
      `--action-channel`, the kinds it may ask and its bounds in the manifest's `actions`
      grant within the ceilings (§7.2 above), its requests answered by the institution's
      approval resolution from a second adapter (`answerLoop`), each answer recorded with
      its operation id of the attempt's scheme before it is sent and replayed, never
      re-decided, after a restart; the workload proceeding only on `approved`, and the
      answer understood as a recorded statement, not a hold the node enforces.
- [ ] Where an action needs a credential: the `credentials` grant in its manifest (§7.3
      above), naming the configured service, its host (also in `network.custom`) and a TTL
      within the operator's ceiling, signed only after `requireCredentialBroker` accepted the
      node's capability document; never a secret in an envelope, argv, snapshot or
      environment; the workload's requests sent to `/<service>/…` on `WARD_PROXY_SOCKET`;
      a `403` from the route or a `CredentialDenied` record read as the credential being
      unavailable, never answered with another credential; `CredentialRevoked` in the
      sealed log as the end of the lease.
- [ ] Where an irreversible step reaches a host or uses a credential: that host or service
      in the manifest's `hold` (§7.4 above), with an `actions` grant naming `approval`,
      signed only after `requireApprovalHold` accepted the node's capability document; the
      node-opened requests (`hold` in the listing, ids `hold:<n>`) routed to the
      institution's approval resolution through `answerLoop` with the run record's grant and
      hold, each answer recorded before it is sent and replayed, never re-decided; the
      workload written to retry a `403 held for approval` and to stop on `approval denied`,
      `approval expired` or `approval cancelled`.
- [ ] Where a work item runs an agent runtime: the runtime named in the envelope's
      `workload.adapter` (§7.5 above), signed only after `requireAgentAdapter` accepted the
      node's capability document, under the same manifest whichever runtime it is; its
      model reached through a `credentials` grant, never a key in the argv, snapshot or
      environment, the base URL (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`) set by a node with
      a shim only for the provider the manifest grants; the sealed log's `agent_adapter`
      binding and hook claims read as the agent's account, never as authority.
- [ ] The signed bytes, proof, ids and version persisted before the first send; replay on
      restart with the same adapter conversation (§9); no second attempt until the first is
      ended.
- [ ] Cancellation wired to `SIGTERM` on the adapter (or a `revoke` command), and the
      retry path issuing a new lease generation and attempt (§8).
- [ ] The execution receipt carrying the WardOS binding, the receipt outcome, the exit
      status, the evidence log path and sealed head, so the verifier evidence package can
      bind the claim to it; `ward-node audit --json` as the operator's cross-check.
- [ ] The limitations of §11 reflected in which actions are routed to the node: exit
      status plus bounded declared outputs as the verdict; agent loops stay on the control
      plane.
