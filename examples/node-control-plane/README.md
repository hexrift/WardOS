# node-control-plane: a reference `ward-node` control plane in Node.js

The control-plane side of [`docs/node-integration.md`](../../docs/node-integration.md)
written in plain Node.js (>= 22, ESM, no npm dependencies), for a control plane such as
[hexrift/ai-institution](https://github.com/hexrift/ai-institution) that is written in
TypeScript and spawns external tools as processes. The guide that walks an adapter author
through it is [`docs/node-integration-from-nodejs.md`](../../docs/node-integration-from-nodejs.md).

| File | What it is |
| --- | --- |
| `ward-node.mjs` | The library: ids (§7.2) and their derivation from caller ids, the issuer key and proof (§2.3, §7.4), the envelope (§7), the durable per-task version (§10), run records for replay, the `ward-node-adapter` conversation (§11.4) and the receipt-to-outcome mapping (§9, §11.3). |
| `ward-node.d.ts` | Hand-written TypeScript declarations for it. |
| `blake3.mjs` | BLAKE3-256 in plain JavaScript, for key ids and manifest hashes; held to the reference vectors. |
| `control-plane.mjs` | The command line: `keygen`, `derive-id`, `capabilities`, `run`, `replay`, `inspect`, `revoke`. |
| `test/` | `node --test` cases that need no node and no sandbox: the §7.4 vector byte for byte, ids, the version counter across a restart, the JSON-lines framing against `fixtures/fake-adapter.mjs`. |

```bash
cd examples/node-control-plane && node --test          # the unit suite
scripts/acceptance/node-js.sh                           # the same client against a real ward-node
```

The acceptance (`scripts/acceptance/node-js.sh`) starts a real node with the client's own
key in its trust store and proves, with nothing mocked, that a workload completes, fails
with its exit status, is cancelled by revoke-then-seal, replays without acting twice, and
that the node holds the version strictly increasing; its evidence logs are verified with
the node's own audit.

The signing key is a PKCS#8 PEM file (mode 0600) that never leaves the control plane's
process; the node sees signatures only. Everything the client builds is checked against
the contract's bounds before it is signed, and an `unknown` outcome is never success.
