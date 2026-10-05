# node-control-plane: a reference `ward-node` control plane in Node.js

The control-plane side of [`docs/node-integration.md`](../../docs/node-integration.md)
written in plain Node.js (>= 22, ESM, no npm dependencies), for a control plane such as
[hexrift/ai-institution](https://github.com/hexrift/ai-institution) that is written in
TypeScript and spawns external tools as processes. The guide that walks an adapter author
through it is [`docs/node-integration-from-nodejs.md`](../../docs/node-integration-from-nodejs.md).

| File | What it is |
| --- | --- |
| `ward-node.mjs` | The library: ids (§7.2) and their derivation from caller ids, the issuer key and proof (§2.3, §7.4), the envelope (§7), the durable per-task version (§10), run records for replay, the `ward-node-adapter` conversation (§11.4), the receipt-to-outcome mapping (§9, §11.3), and result return: the manifest's `output` grant within the node's ceilings (§7.5), the returned output decoded with every digest recomputed and held to its grant, and returned files written under one directory (§6.6). |
| `ward-node.d.ts` | Hand-written TypeScript declarations for it. |
| `blake3.mjs` | BLAKE3-256 in plain JavaScript, for key ids and manifest hashes; held to the reference vectors. |
| `control-plane.mjs` | The command line: `keygen`, `derive-id`, `capabilities`, `run` (with `--stdio-bytes`, `--files`, `--files-bytes` for an output grant and `--out-dir` for the returned files), `replay`, `inspect`, `result`, `revoke`. |
| `test/` | `node --test` cases that need no node and no sandbox: the §7.4 vector byte for byte, ids, the version counter across a restart, the JSON-lines framing against `fixtures/fake-adapter.mjs`, the output grant's grammar and ceilings, result decoding and digest verification, and writing returned files without escaping their directory. |

```bash
cd examples/node-control-plane && node --test          # the unit suite
scripts/acceptance/node-js.sh                           # the same client against a real ward-node
```

The acceptance (`scripts/acceptance/node-js.sh`) starts a real node with the client's own
key in its trust store and proves, with nothing mocked, that a workload completes, fails
with its exit status, is cancelled by revoke-then-seal, replays without acting twice,
that the node holds the version strictly increasing, and, on a node started with
`--output-return`, that a declared result comes back byte for byte with digests equal to
the files on the host, is marked truncated past its budgets, and is refused
`unsupported_grant` by a node without the flag; its evidence logs are verified with the
node's own audit.

The signing key is a PKCS#8 PEM file (mode 0600) that never leaves the control plane's
process; the node sees signatures only. Everything the client builds is checked against
the contract's bounds before it is signed, and neither an `unknown` outcome nor a
granted output that did not come back is ever success.
