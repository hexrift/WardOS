# node-control-plane: a reference `ward-node` control plane in Node.js

The control-plane side of [`docs/node-integration.md`](../../docs/node-integration.md)
written in plain Node.js (>= 22, ESM, no npm dependencies), for a control plane such as
[hexrift/ai-institution](https://github.com/hexrift/ai-institution) that is written in
TypeScript and spawns external tools as processes. The guide that walks an adapter author
through it is [`docs/node-integration-from-nodejs.md`](../../docs/node-integration-from-nodejs.md).

| File | What it is |
| --- | --- |
| `ward-node.mjs` | The library: ids (§7.2) and their derivation from caller ids, the issuer key and proof (§2.3, §7.4), the envelope (§7), the durable per-task version (§10), run records for replay, the `ward-node-adapter` conversation (§11.4), the receipt-to-outcome mapping (§9, §11.3), result return: the manifest's `output` grant within the node's ceilings (§7.5), the returned output decoded with every digest recomputed and held to its grant, and returned files written under one directory (§6.6), and the action channel: the manifest's `actions` grant within ADR-0031's grammar and the node's ceilings (§7.5), `actions` and `answer` with every listing and answer held to the contract, and `answerLoop`, which answers a running attempt's requests by a policy from a second adapter, recording each answer with its operation id in the run record before sending it (§6.7), and brokered credentials: the manifest's `credentials` grant within ADR-0034's grammar, its hosts covered by the manifest's own `network.custom`, and the capability document's `credentials` flags read before a grant is signed (§6.8), and approval holds: the manifest's `hold` within ADR-0035's grammar, naming only hosts and services the same manifest grants, signed last, `actions.hold` read before it is signed, and the node-opened requests of a listing held to it (§6.9), and agent adapters: the workload's `adapter` within the grammar, signed last in the workload and never in the manifest, and the capability document's `adapters.hosted` read before it is signed (§6.10, §7.3), and resource limits: the manifest's `resources` grant within ward-node-protocol's grammar, signed after `output`, and the capability document's `resources` flags and `capacity` read before it is signed (§7.5, §9), and capacity: a `start` refused `capacity_exhausted` sent again as the same run, with the same operation ids, with backoff within a bounded wait, the node's `scheduling` read before each wait (§8.2), and the adapter's node: its socket, or a node serving `--listen-tls` reached over mutual TLS with this client's certificate, refusing a node whose key `tls.serverRevoked` lists even when pinned (`new Adapter({tls})`, `adapterNodeArgs`; §3, ADR-0038). |
| `ward-node.d.ts` | Hand-written TypeScript declarations for it. |
| `blake3.mjs` | BLAKE3-256 in plain JavaScript, for key ids and manifest hashes; held to the reference vectors. |
| `control-plane.mjs` | The command line: `keygen`, `derive-id`, `capabilities`, `run` (with `--stdio-bytes`, `--files`, `--files-bytes` for an output grant and `--out-dir` for the returned files; `--actions` with `--actions-max-pending`, `--actions-max-total`, `--actions-wait-secs` for an actions grant and `--approve-all`, `--deny-all` or `--ask` to answer it; `--credential <service>=<host>[:<ttl-secs>]` for a credentials grant, refused before signing on a node that does not broker credentials and listed in the outcome; `--hold host=<pattern>` or `--hold service=<name>` for a hold, refused before signing on a node without `--approval-hold`, its node-opened requests answered by the policy and listed in the outcome; `--agent-adapter <id>` to run the argv as a hosted agent adapter, refused before signing on a node that does not host it and named in the outcome; `--cpu-millis`, `--memory-bytes`, `--pids` for a resources grant, refused before signing on a node that does not enforce it and listed in the outcome; `--capacity-wait-secs` (default 30, 0 disables) to wait out a node at capacity with the same start, each wait listed in the outcome), `replay` (once, never waiting), `inspect`, `result`, `revoke`, `actions`, `answer`; each that speaks to the node takes `--socket`, or `--connect-tls` with `--tls-cert`, `--tls-key`, `--tls-server-ca`, `--tls-server-name`, an optional `--tls-server-pin` and an optional `--tls-server-revoked` list of revoked node keys for a node over mutual TLS. |
| `fixtures/` | `fake-adapter.mjs`, a scripted stand-in for `ward-node-adapter` for the unit suite; `fake-credential-services.mjs`, a fake OpenBao and a fake upstream on 127.0.0.1 for the acceptance's credentials cases. |
| `test/` | `node --test` cases (120) that need no node and no sandbox: the §7.4 vector byte for byte, ids, the version counter across a restart, the JSON-lines framing against `fixtures/fake-adapter.mjs`, the output grant's grammar and ceilings, result decoding and digest verification, writing returned files without escaping their directory, the actions grant's grammar and ceilings, the answer loop against a scripted channel (answers persisted before sending, replayed after a restart under the same id, each refusal, the end of the attempt), the command line's `--approve-all`, `--deny-all`, `--ask`, `actions` and `answer`, and the credentials grant's grammar and allowlist coverage, the broker flags read before signing, and `run --credential` and its replay, and the hold's grammar and its manifest, its signed bytes, listings held to it, `actions.hold` read before signing, and `run --hold` with each policy and its refusals, and the agent adapter's grammar, its place in the signed workload, `adapters.hosted` read before signing, and `run --agent-adapter` and its replay and refusals, and the resources grant's grammar, its signed bytes, the node's `resources` and `capacity` read before signing, and `run --cpu-millis/--memory-bytes/--pids`, and the capacity wait: the same run sent again until the node starts it, given up once the wait is spent, a cancel while waiting revoking and sealing, and `replay` never waiting, and the TLS settings, revoked node keys included, mapped onto the adapter's flags and their refusals. |

```bash
cd examples/node-control-plane && node --test          # the unit suite
scripts/acceptance/node-js.sh                           # the same client against a real ward-node
```

The acceptance (`scripts/acceptance/node-js.sh`) starts a real node with the client's own
key in its trust store and proves, with nothing mocked, that a workload completes, fails
with its exit status, is cancelled by revoke-then-seal, replays without acting twice,
that the node holds the version strictly increasing, on a node started with
`--output-return`, that a declared result comes back byte for byte with digests equal to
the files on the host, is marked truncated past its budgets, and is refused
`unsupported_grant` by a node without the flag, and, on a node started with
`--action-channel`, that a workload asking through the channel proceeds on
`--approve-all`, stops on `--deny-all`, fails closed when its request expires or the run is
cancelled while it waits, is answered idempotently from a second process, and that a node
without the flag refuses the grant, and, on a node started with `--network-allowlist` and
`--credentials` against a fake OpenBao and a fake upstream on loopback, that the upstream
receives the leased token the node's proxy injected while the workload's output, the
sealed log, the task root and the node's state never hold it, that the lease is revoked at
the provider when the attempt ends or is cancelled, that a replay leases nothing, and that a
node without `--credentials` (and the client before it) refuses the grant, and, on a node
started with `--action-channel` and `--approval-hold` as well, that a held credential route
is refused by name until the client's policy approves the request the node opened for it
(and then reaches the upstream with the lease injected), stays refused on a denial or an
expiry, and that a node without `--approval-hold` (and the client before it) refuses the
hold, and, on a node started with `--agent-adapter claude-code` and `--agent-adapter codex`,
that both runtimes run under the same signed manifest with none of the node's keys,
Claude Code's hook lines recorded as claims and Codex with no hook socket, and that an
adapter the node does not host is refused, and, on a node started with `--listen-tls` and
certificates made at run time with `openssl`, that the same client over mutual TLS reads the
socket's capability document and runs an attempt to a verifying sealed log, accepts the
node's key pinned the operator's way and refuses another, and that a client of another CA
is refused, and, on a node started with `--max-running 1`
and without `--cgroup-root`, that a start refused `capacity_exhausted` is waited out with
the same start (or, once the wait is spent, left ready for a replay that sends it), and
that a resources grant is refused by the client and by the node; its evidence logs are verified with the node's
own audit, and the action, credential and network records in them are decoded from the
raw bytes and checked against what the client used (28 cases). The credentials and hold nodes are `ward-node` built with its
`test-loopback` feature, since the shipped build never connects to a loopback upstream or
speaks plain HTTP to one; the script builds it into a target directory of its own, or takes
`WARD_NODE_LOOPBACK_BIN`. Every other node is the shipped build, `WARD_NODE_BIN`, built
without the feature into another target directory of its own; a build with the feature
says so in its `--version`, and the script refuses it as `WARD_NODE_BIN` before any node
starts.

The signing key is a PKCS#8 PEM file (mode 0600) that never leaves the control plane's
process; the node sees signatures only. Everything the client builds is checked against
the contract's bounds before it is signed, and neither an `unknown` outcome nor a
granted output that did not come back is ever success. An approval through the action
channel is a statement the node records and relays to a workload that chose to wait for
it; what the node enforces is a hold, on a held host or credential, released only by an
approval of the request the node itself opened. A credentials grant names a service, never
a secret: the node leases the credential and its proxy injects it, so the workload never
holds it.
