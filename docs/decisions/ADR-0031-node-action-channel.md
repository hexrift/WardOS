# ADR-0031 — The node action channel: workload requests relayed, recorded and answered

Status: **Proposed; implemented under #404 (stage 3 of [migration-to-node.md](../migration-to-node.md)
§3.4, #332).** Approvals as an enforced node capability and brokered credentials (#267) are
not part of this decision; what the channel does not do yet is a row of
[node-security-limitations.md](../node-security-limitations.md) §3.

[ADR-0030](ADR-0030-node-task-admission-and-execution-ownership.md) gives `ward-node`
ownership of what it admits: spawn, budget, reaping and the attempt's evidence log. Its
security consequences list "no callback channel": a workload in an admitted attempt can
run, write its workspace and, with a grant, reach an allowlisted host or hand back a
bounded result, but it cannot ask the control plane anything while it runs. An agent's
conversation loop needs exactly that (an approval before an irreversible step, a choice it
should not make itself), and the authority to answer has to stay outside the sandbox. This
records how the node offers that question-and-answer path without giving the sandbox a
path to the node's own control surface.

## Decision

### 1. A per-attempt Unix socket, bound at a fixed path, named by one variable

A node started with `--action-channel` (needs `--task-root`, like `--network-allowlist`
and `--output-return`) gives each attempt whose manifest carries an `actions` grant its own
listening socket, `<task-root>/<task>/<attempt>.actions/actions.sock`. The directory is
created mode 0700 beside the workspace, never inside it, as the evidence and egress
directories are, so the workload cannot replace, remove or read anything there; the node
binds the socket through a held directory descriptor, so a deep task root never meets the
108-byte socket path limit. The sandbox binds it at `/run/ward/actions.sock` and the node
sets exactly one more variable, `WARD_ACTION_SOCKET=/run/ward/actions.sock`. The network
namespace is unchanged (loopback only): the channel is not a route anywhere. The socket
exists exactly while the attempt can use it: it is created at `start`, before the spawn,
and removed when the attempt ends; a node restart leaves an inert file at most.

The node listens on threads of its own process. Nothing in the sandbox speaks to the node's
protocol socket, and the node never reads the channel as node protocol: the two surfaces
share no parser state.

### 2. A JSON-lines grammar with bounds, and a closed set of kinds

The workload writes one request per line on a connection:

```json
{"id":"deploy-1","kind":"approval","summary":"deploy to staging","detail":"plan: rotate 3 services"}
```

- `id`: 1–64 bytes of `A-Z a-z 0-9 . _ : -`, chosen by the workload, unique within the
  attempt;
- `kind`: one of a closed set, `approval` (permission to do what the summary says) or
  `decision` (a yes-or-no choice made for the workload); anything else fails decoding;
- `summary`: 1–512 bytes; `detail`: 0–16 KiB; both UTF-8 text;
- every field required, no other field; a line is at most 128 KiB (room for the bounds
  even fully escaped).

The manifest grants the channel per attempt:
`"actions":{"kinds":["approval"],"max_pending":2,"max_total":8,"wait_secs":300}` — the
kinds the workload may send, how many may wait at once, how many in the attempt's
lifetime, and how long each waits. The grammar requires at least one kind, no repeats,
non-zero bounds and `max_pending ≤ max_total`; the node's ceilings are 8 pending, 64 in
all and 3600 seconds. A grant above a ceiling, or any grant on a node without the flag, is
refused `unsupported_grant` at `admit`, after authority is proven and before the version
is consumed, like every other grant the node cannot honour. The capability document
carries an `actions` section (the kinds offered and the three ceilings) only on a node
started with the flag; every other node emits exactly the earlier document. All of this
is additive within protocol 1.3 (§6 below).

### 3. What the workload receives, and what it waits for

Each accepted request is answered on the connection it was asked on, with one line:

```json
{"id":"deploy-1","decision":"approved","note":"go ahead"}
```

`decision` is `approved` or `denied` (the control plane's), or `expired` or `cancelled`
(the node's); `note` is the control plane's optional note, at most 512 bytes. A workload
fails closed on anything but `approved`: a denial, an expiry, a cancellation, and an
end-of-file without a reply all mean "do not proceed". The wait bound is the grant's
`wait_secs`: a request nobody answers is answered `expired` by the node when it runs out.
A workload may pipeline several requests on one connection, up to `max_pending`.

### 4. The node records first, and refuses with nothing

The node is the attempt evidence log's single writer (ADR-0030 §3). The channel's threads
never write it: they queue records, and the task registry appends them under its lock, in
order — from the attempt's reaper while it waits, and before every `actions` and `answer`
is served. Three record kinds are appended at the end of the event catalogue, all origin
`node`, all critical:

- `NodeActionRequested`: the node's request number (from 1), the kind, and the size and
  `BLAKE3-256` digest of the summary and of the detail;
- `NodeActionAnswered`: the request number, the decision, the `answer`'s operation id
  (none for the node's own `expired` and `cancelled`), and the size and digest of the note;
- `NodeActionRefused`: why a line was refused, and how many bytes of it the node read.

Never the text: a summary, detail or note may carry what the control plane must see but a
log reader need not, and digests bind what the control plane saw to the sealed log. A
request becomes visible to the control plane, and answerable, only once its
`NodeActionRequested` is appended; one whose record cannot be appended is answered
`cancelled` and never listed. An answer is appended before the workload is told; one that
cannot be appended is refused `resource_unavailable` and the request stays pending.

A line that is not a request of the grammar gets nothing: the node records
`NodeActionRefused` and closes that connection without writing a byte. That covers an
oversized line, a malformed one, a kind the grant does not name, a repeated id, a request
past `max_pending` or `max_total`, and — the bar of the session mode's hook socket, ST-016
and ST-027 — anything that parses as a node-protocol or control-protocol request: an
object with a `request`, `req` or `response` member, so a lifecycle request and a `hello`
are refused `control_request`. After 16 refusals the channel closes for the rest of the
attempt, so a hostile workload cannot grow its log without bound; at most 8 connections
are served at once and a further one is closed unread. Replies are written without
blocking: a workload that does not read its socket loses its reply, never the node's
progress.

### 5. Pause, stop, revoke, the budget, the workload's exit, and a node restart

- **Pause.** The workload is frozen anyway; its requests stay pending. The wait clocks stop
  while the attempt is paused and resume with it, so a pause never turns a pending request
  into `expired`. The control plane may still list and answer; the reply waits in the
  socket until the workload runs again.
- **Stop, revoke, the budget kill, the workload's own exit.** When the attempt ends, every
  pending request is answered `cancelled`, recorded before `NodeAttemptEnded`, and the
  channel closes. A revoke whose reap is not confirmed in time does the same before its
  `unconfirmed` end.
- **A connection closed while its request waits** withdraws it: answered `cancelled`.
- **A node restart.** The restarted node holds no attempt running (ADR-0030 §6: every
  attempt that may have been executing is recovered `exited` with an `unknown` receipt), so
  no pending request can be answered any more: before it serves, the node answers
  `cancelled` every request its log shows unanswered, before the `NodeAttemptRecovered`
  record.

### 6. How the control plane reads and answers

Two requests on the node's protocol socket, protocol 1.3, on a node started with the flag:

- `actions` (read-only, no operation id): the attempt's state and its pending requests,
  oldest first, each with its number, id, kind, summary, detail and the milliseconds left
  before it expires (frozen while paused). Answered within a 1 MiB line bound, since up to
  8 details of 16 KiB travel in it.
- `answer` (mutating, with an `operation_id`): `{"action":N,"decision":"approved"|"denied",
  "note"?}`. Replaying the same operation id with the same answer is answered as before and
  appends nothing, also once the attempt has ended; the same operation id with another
  answer is `stale_operation`; another answer to a request already answered — by the
  control plane, or `expired` or `cancelled` by the node — is `already_answered`; a number
  the attempt never recorded is `unknown_request`; an answer to an attempt that is not
  `running` or `paused` is `invalid_state`; and `task_not_found`, `attempt_mismatch`,
  `lease_mismatch` as for every verb. Both are `unsupported_operation` on a node without
  the flag, and unknown (the connection closes) below 1.3.

Both are separate request and response types (`TaskActionsRequest`,
`TaskActionsResponse`), not variants of the lifecycle request: the lifecycle enum is
matched exhaustively by protected tests and by every existing client, and an added variant
would break them where an added type does not — the shape #395 chose for `result`. The
action's number field is `action`, since `request` is the wire's tag.

### 7. Authority, and what an approval is

The answer is authorised the way every verb is: by the exact binding (task, attempt and
lease) on the node's socket, which serves only the node's uid and the operator's listed
client uids. The issuer proved its authority at `admit`, the node rechecked it at `start`,
and a revocation ends the attempt and with it every pending request. An answer is not
signed per request; per-request issuer proofs belong with the authenticated remote
transport (#262).

The channel grants nothing by itself. An approval is a statement the node records and
relays: the workload proceeds because it chose to wait for it, and the node enforces
nothing on it in this slice — no capability, no credential, no widened network. Approvals
as a hold the node applies, and credentials brokered as node capabilities (#267), are the
rest of stage 3 and need their own decisions.

## Alternatives

- **HTTP over the egress proxy.** Rejected. It would make the channel depend on
  `--network-allowlist` and on a network grant, mix control traffic into the egress
  evidence (`NetworkRequested`), and put an HTTP parser between the sandbox and the
  decision; the proxy's job is to refuse, not to carry questions. An offline attempt would
  have no channel at all.
- **Markers on stdout.** Rejected. Output is drained and, without an output grant, never
  read; with one it is read once the attempt has ended. A marker cannot be answered, a
  workload's own output can forge one, and any byte the workload prints would become
  protocol.
- **A shared file in the workspace.** Rejected. The workspace is the workload's: it can
  write, truncate or replace any file there, so the node would read attacker-controlled
  state, need polling and locking, and could never tell a request from a forged answer.
  Records beside the workspace are exactly what the workload must not reach.
- **The node protocol socket bound into the sandbox.** Rejected. It hands the sandbox the
  verbs that govern it (`stop`, `answer`, `seal`), which is precisely what ST-027 proves
  the session mode never does.
- **One channel per node instead of per attempt.** Rejected. The socket would have to say
  which attempt a request belongs to, which the workload could lie about; a socket per
  attempt makes the binding a fact of where the request arrived.

## Advantages

- The same shape as the egress proxy: one socket, one variable, a private directory beside
  the workspace, owned and recorded by the node.
- Every exchange is in the sealed evidence log with sizes and digests, in order, and the
  record always precedes what it describes.
- A control plane drives it with two requests and the client and adapter it already uses;
  a node without the flag is byte-for-byte what it was.

## Disadvantages

- The sandbox gains a socket into it; its parser is new attack surface on the node.
- Answers are authorised by the binding, not by a per-answer issuer signature, until #262.
- The applied answer ids live in the node process: after a node restart a replay is
  `invalid_state`, and the log is the durable record of what was answered.
- The adapter's `run` blocks, so a process-adapter control plane answers from a second
  adapter process (or its own client).

## Security consequences

- No request from the sandbox reaches a node decision: the channel shares no parser with
  the protocol socket, a control-protocol line gets zero bytes and a closed connection and
  is recorded, and nothing the workload sends changes what the node enforces.
- Bounded everywhere: line, summary, detail, note, id, pending, total, wait, connections,
  refusals; the evidence log's own bound keeps its reserve for the end records, which the
  node's own `expired` and `cancelled` answers may use.
- Fail closed: anything but an `approved` reply, including silence and a closed
  connection, means the workload does not proceed; a record that cannot be written refuses
  rather than relays.
- An approval is recorded, not enforced; credentials are not brokered; answers are not
  signed per request. Each is a row of node-security-limitations.md §3.

## Performance consequences

One listener thread per attempt with a grant and one thread per open connection (at most
8); records are fsynced as every evidence record is. Nothing changes for an attempt
without a grant or a node without the flag.

## Why selected

It meets the session mode's hook-socket bar with the egress proxy's proven shape, keeps
the node the single writer, and is additive within 1.3 like #388 and #395, so nothing an
existing control plane does changes.

## How it will be validated

- Unit tests of the grammar and wire (`ward-node-protocol`), of the channel (refusals,
  bounds, ordering, expiry, pause, withdrawal, closing) and of the registry over the
  node's socket (`ward-node`), and of the client and adapter against a scripted node.
- The cross-system acceptance suite against a real node started with `--action-channel`
  ([node-acceptance.md](../node-acceptance.md), `acceptance_actions.rs`): approve and
  deny, expiry, stop and revoke while pending, pause while pending, a node restart while
  pending, the hostile lines, replay of an answer, and a node without the flag that refuses
  the grant and advertises nothing.
