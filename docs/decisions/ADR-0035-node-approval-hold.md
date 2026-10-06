# ADR-0035 — Approvals as a hold the node enforces: held capabilities released only by a recorded approval

Status: **Proposed; implemented under [#415](https://github.com/hexrift/WardOS/issues/415),
the last item of stage 3 of [migration-to-node.md](../migration-to-node.md) §3.4 (#332).**

## Context

[ADR-0031](ADR-0031-node-action-channel.md) gave a `ward-node` workload a channel to ask the
control plane, every request and answer recorded by the node, but an approval there is a
statement the node relays: nothing the node enforces depends on it (ADR-0031 §7,
node-security-limitations.md §3.2). [ADR-0034](ADR-0034-node-brokered-credentials.md) made
credentials node capabilities, injected by the attempt's egress proxy, beside the
proxy-backed host allowlist of the network grant. A control plane running an agent needs
the per-session mode's hold for both (agent-integration.md §4.1): an action that reaches an
irreversible host or uses a credential waits for a human, and is refused, not merely
discouraged, until one says yes. What the per-session mode keeps: the question is asked by
the runtime, not claimed by the agent; deny is the default (on timeout, on the end of the
session, on a lost daemon); a pause holds the hold with its clock stopped; the record of
the request and of the decision precedes their effect.

## Decision

### 1. The manifest marks granted capabilities as held

The capability manifest gains an optional `hold` field, additive within protocol 1.3 like
`actions` and `credentials`:

```json
{"network":{"custom":["deploy.example.com","artifacts.example.com"]},
 "actions":{"kinds":["approval"],"max_pending":1,"max_total":4,"wait_secs":300},
 "credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":600}],
 "hold":{"hosts":["deploy.example.com"],"services":["artifacts"]}}
```

`hosts` names patterns of the manifest's own `network.custom`, exactly as written there;
`services` names services of its own `credentials`. Each list is optional but non-empty
when present, at least one is present, nothing twice, at most 8 entries in all, and the
manifest must carry an `actions` grant naming `approval`, since the node asks through the
attempt's action channel. A manifest outside this grammar fails decoding
(`authority_denied`), so a hold can only narrow what the same signed manifest grants,
never add to it. A hold on a host covers every request the
proxy sees for a name that pattern covers, a credential route to that host included; a hold
on a service covers its credential route.

### 2. The node honours it only when its operator enabled it

`ward-node --approval-hold` (it needs `--action-channel` and `--network-allowlist`)
honours a `hold`; any other node refuses such a manifest `unsupported_grant` at `admit`,
after authority is proven and before the version is consumed, as every grant it cannot
honour (node-integration.md §8.1 step 16). A node without `--action-channel` already
refuses the `actions` grant the hold needs; a node of an earlier revision fails to decode
the manifest (`authority_denied`). The capability document's `actions` section carries
`"hold":true` exactly on a node started with the flag; every other node emits exactly the
earlier document, so an operator who does not enable it changes nothing a control plane
reads.

### 3. The node opens the request, on first use

The first request the attempt's egress proxy sees for a held capability — a request the
allowlist or the matched credential route would let through, before anything is resolved,
connected to or injected — opens one `approval` request on the attempt's channel for that
capability, and the proxy refuses the request `403 Forbidden` with the body
`held for approval`. The request carries the id `hold:<n>` (the capability's place in the
hold, hosts first, then services, from 1), the summary `network <pattern>` or
`credential <service>` and a fixed detail, and the `actions` listing shows it with a `hold`
field naming the capability (`{"host":…}` or `{"service":…}`), which no workload request
can carry. The ids `hold:1`…`hold:<count>` are the node's: a workload request under one is
refused `duplicate_id`. A request touching several held capabilities opens each of them at
once. The node's requests count against neither the workload's `max_pending` nor its
`max_total`; they are bounded by the hold itself.

Matching is therefore by construction: the approval that releases a capability is the
answer to the one request the node opened for it, named by its request number on the
control plane's `answer`. The alternative — the workload names the held capability in a
field of its own request — was rejected: the workload would choose what the control plane
sees asked, could word a request for one capability to look like another, and the node
would have to parse workload text to decide what to release.

### 4. Release, refusal and their ends

- **Approved** (the control plane's `answer` with `approved`, recorded): the capability is
  released for the rest of the attempt; the next request for it goes through the proxy as
  any allowlisted request does. A release is per attempt, not one-shot: an agent's single
  step (a push, a fetch of several objects) is several requests, and the attempt is
  already bounded by its budget. A retry is another attempt, whose holds start held.
- **Denied, expired** (the grant's `wait_secs` ran out unanswered) **or cancelled** (the
  attempt ended, the channel closed, or the request's record could not be appended): the
  capability stays refused for the rest of the attempt, `403` with the body
  `approval denied`, `approval expired` or `approval cancelled`; nothing reopens it, so a
  workload cannot turn a denial into a stream of new questions.
- **Pending**: `403 held for approval`. The workload retries at its own pace; the proxy
  never blocks a connection waiting for an answer.
- **Pause**: the paused proxy answers every request `503 paused by ward` before the hold is
  asked (ADR-0019 §3, ADR-0034 §4); the pending request's wait clock stops (ADR-0031 §5)
  and the control plane may still answer. After resume, an approval given while paused
  releases.
- **Stop, revoke, the budget, the workload's exit**: the attempt ends, every pending
  request — the node's included — is answered `cancelled` before the end record, and the
  proxy is shut down with the attempt.
- **A node restart**: the restarted node runs no attempt (ADR-0030 §6). Recovery answers
  `cancelled` every request the attempt's log shows unanswered, before
  `NodeAttemptRecovered`; an approval recorded before the crash stays in the log as the
  account of what was released, and nothing is released after the restart.

### 5. Authority and replay

Only the control plane answers: an `answer` is served on the node's protocol socket, by
the exact binding, to the node's uid and its listed client uids (ADR-0031 §7). Nothing the
workload writes on its channel is an answer: a line shaped as one is refused
`control_request` with zero bytes. The hold is released only by a successful `answer` to
the request the node opened: a replay of an applied operation id applies nothing new, the
same id with another answer is `stale_operation`, an answer to another request number
releases that request's capability only (or nothing), an unknown number is
`unknown_request`, and an answer after a denial, an expiry or a cancellation is
`already_answered` — or `invalid_state` once the attempt has ended. A forged answer from
anyone not served by the socket never reaches the node.

### 6. Evidence, with the existing record kinds

The event catalogue is protected and asserted by count
(`crates/ward-events/tests/roundtrip.rs`); the existing kinds carry everything the hold
needs, so the catalogue is unchanged:

- the hold's request is `NodeActionRequested` (origin `node`, kind `approval`, the sizes
  and `BLAKE3-256` digests of its summary and detail); it is listed, and answerable, only
  once that record is appended (ADR-0031 §4), and one whose record cannot be appended is
  answered `cancelled` and its capability stays refused;
- its answer is `NodeActionAnswered`, with the `answer`'s operation id, or none for the
  node's `expired` and `cancelled`; the capability is released only once an `approved`
  answer is appended — an answer whose record fails is refused `resource_unavailable` and
  releases nothing;
- each refusal is the proxy's verdict, a `NetworkDenied` for the destination with the
  reason `PolicyDeny` and the rule `hold:<state>:<n>` (`held`, `denied`, `expired`,
  `cancelled`, and the request number), or `hold:cancelled` for a capability the closed
  channel never asked about. Verdicts travel the proxy's bounded queue as every verdict
  does (node-integration.md §6.5): a refusal is answered to the workload when it is made
  and appended by the attempt's reaper, a queue overflow counted as `ObservationsDropped`.
  What the node releases and what it shows the control plane is always recorded first; a
  refusal releases nothing, so its record may follow it.

A log reader ties the three together by the request number and by hashing the summary.

## Alternatives

- **The workload names the capability in its request.** Rejected (§3): the workload would
  choose the wording the control plane approves, and the node would release on workload
  text.
- **Hold the connection open until the answer.** Rejected: a proxy thread per waiting
  request for up to an hour, bounded only by the proxy's connection cap; and an HTTP client
  that times out sees nothing named. A named `403` is the session proxy's refusal shape and
  the workload's retry is its own.
- **One-shot releases.** Rejected (§4): one approval per HTTP request is unusable for any
  real step, and a control plane that wants single use grants a short budget.
- **Reopen a denied or expired hold on the next use.** Rejected: denial is the default; a
  workload could otherwise ask again without bound. A new attempt asks again.
- **Gate without an operator flag.** Rejected: the `actions` section would change for every
  node with `--action-channel` and `--network-allowlist`, which a strict decoder of an
  earlier 1.3 revision refuses; the flag keeps node-first upgrades safe
  (compatibility.md §4).
- **A new `NodeHold*` record kind.** Deferred: the catalogue is protected and asserted by
  count, and the action and network kinds already say what was asked, answered and refused.

## Security consequences

- The approval is now authority: a held host or credential is unreachable from the sandbox
  until a control-plane answer to the node's own request is recorded, and stays unreachable
  after any other outcome. Nothing the workload sends can open, word, answer or replay the
  request that releases it.
- A host is held by name, as the allowlist allows by name: a request naming another
  allowlisted host is not held even if that name resolves to the same address. Hold the
  pattern the manifest allows (`*.example.com`), not one name under a wider pattern, when
  every name under it must wait.
- Everything else is unchanged: an ungated host or credential behaves exactly as before,
  structural denies still apply to a released host, a released credential is still scoped
  to its route's paths and lease, and the hold never widens what the manifest grants.
- New surface: the proxy asks the hold on each request for an allowlisted destination; the
  hold's state is in the node process and bounded by the manifest (at most 8 requests).
- Answers are still authorised by the binding, not signed per answer (#262).

## Performance consequences

One lock and a pattern match per allowlisted request on an attempt with a hold; nothing
for an attempt without one or a node without the flag.

## Compatibility

Additive within 1.3: the manifest's `hold`, the flag `actions.hold` (only with
`--approval-hold`) and the listing's `hold` field (only on a request a hold opened, so only
for a control plane that signed a hold) are new; a node without the flag is byte for byte
what it was. The listing may hold the workload's 8 requests and the hold's 8. `ward-node`'s
inputs change (`ward-node-protocol` and `ward-proxy`), so the next release must raise the
node version (CONTRIBUTING.md, #275).

## How it is validated

`ward-node-protocol` unit tests of the grammar, the listing's `hold` field and the flag;
`ward-proxy` tests of the hold seam (`tests/hold.rs`: a held host or route is refused before
anything is resolved, connected or injected, the policy refuses first, a paused proxy never
asks); `ward-node` unit tests of the channel's holds (opened on first use, recorded before
listed, released only by a recorded approval of its own request, denied, expired and
cancelled by name, held across a pause, ids reserved, both of two holds opened at once),
of the proxy verdict's record, of `admit` and of the capability document; and
`tests/node_hold_cli.rs`, a real node with a real sandbox, proxy, fake OpenBao and fake
upstream: approval releases the host and the credential route (the upstream sees the
injected lease), approving one of two holds releases nothing, denial, expiry and stop keep
it refused, a pause keeps it held past its wait, a forged, replayed or misdirected answer
releases nothing, and a node killed after one approval recovers with that approval kept and
the other request cancelled. The Node.js reference client's `run --hold` is proven against a
real node by `scripts/acceptance/node-js.sh` (approve, deny, expiry, refusal).
