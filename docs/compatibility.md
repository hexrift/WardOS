# Node protocol compatibility and skew policy

Status: living document. It states the `ward-node` protocol window this revision serves
and the version skew a node and an external control plane
([ADR-0029](decisions/ADR-0029-product-split-fleet-trust-boundaries.md)) may run with.
The wire contract itself is [node-integration.md](node-integration.md).

<!-- protocol-window: 1.0-1.3 -->

## 1. The window

This revision of `ward-node` serves protocol **major 1, minors 0 through 3**. The
single source of that range is `WARD_NODE_PROTOCOL` in
[`crates/ward-node-protocol/src/lib.rs`](../crates/ward-node-protocol/src/lib.rs); the
marker at the top of this file restates it, and
[`scripts/security-check/protocol-window.py`](../scripts/security-check/protocol-window.py)
fails CI when the two differ.

| Minor | Adds | Gate in code |
| --- | --- | --- |
| 1.0 | The `hello` handshake and version negotiation. No requests. | — |
| 1.1 | Read-only capability discovery (`capabilities`). | `CAPABILITY_DISCOVERY_PROTOCOL` |
| 1.2 | Identity-only task lifecycle: `create` and `inspect`. The execution verbs decode but are refused `unsupported_operation`; `admit` closes the connection. | `TASK_LIFECYCLE_PROTOCOL` |
| 1.3 | Signed admission (`admit`) with its typed capability manifest, the `exited` state, the receipt outcome on `inspect`, and the execution verbs `start`, `stop`, `pause`, `resume`, `revoke`, `seal` ([ADR-0030](decisions/ADR-0030-node-task-admission-and-execution-ownership.md)). Additive within 1.3: the `unsupported_grant` rejection reason of an `admit` whose manifest the node cannot honour (node-integration.md §7.5), and `network.proxy_allowlist` reading `true` on a node started with `--network-allowlist`, which then admits a `network.custom` manifest (§5, §9); the flag has been in the document since 1.1 and the manifest grammar is unchanged. Additive within 1.3 at this revision, for result return (§6.6): the manifest's optional `output` grant (a node of an earlier revision fails to decode a manifest that carries it, `authority_denied`, and a node without `--output-return` refuses it `unsupported_grant`), the capability document's `output` section, which only a node started with `--output-return` emits (a strict 1.3 decoder of an earlier revision refuses a document that carries it, so enable the flag once the control planes are at this revision), the read-only `result` request (unknown to an earlier 1.3 node, which closes the connection without an answer, as for any unknown verb) and the `NodeAttemptOutputCollected` evidence record (appended at the end of the catalogue; a `ward` of an earlier release cannot read a log that carries it, migration-to-node.md §4.1). Additive within 1.3 at this revision, for single-node capacity and resource limits (#260, node-integration.md §2.1, §5, §7.5, §8.2): the manifest's optional `resources` grant (a node of an earlier revision fails to decode a manifest that carries it, `authority_denied`; a node without `--cgroup-root`, or without the controller a limit needs, refuses it `unsupported_grant`, so no earlier or less capable node ever runs a workload without the limits it asked for); the capability document's `resources` and `scheduling` sections, which only a node started with `--cgroup-root` or `--max-running` emits (a strict 1.3 decoder of an earlier revision refuses a document that carries either, so enable those flags once the control planes are at this revision; a node without them emits exactly the earlier document); the `capacity_exhausted` rejection reason, which only a node started with `--max-running` sends, from `start` only (an earlier strict decoder fails to decode the answer and must treat it as a lost answer: `inspect` then shows the task still `ready`, and nothing was applied); the `NodeAttemptResourceUsage` evidence record, written only by a node started with `--cgroup-root` (appended at the end of the catalogue; a `ward` of an earlier release cannot read a log that carries it); and the optional `usage` field of a task record, written only for an attempt measured under `--cgroup-root` (a node rolled back to an earlier revision refuses to start on a record that carries it, as on any record it cannot parse: seal and evict those tasks, or move their records out of `<state-dir>/tasks/`, before rolling back). Additive within 1.3 at this revision, for the action channel (§6.7, [ADR-0031](decisions/ADR-0031-node-action-channel.md)): the manifest's optional `actions` grant (a node of an earlier revision fails to decode a manifest that carries it, `authority_denied`, and a node without `--action-channel` refuses it `unsupported_grant`), the capability document's `actions` section, which only a node started with `--action-channel` emits (a strict 1.3 decoder of an earlier revision refuses a document that carries it, so enable the flag once the control planes are at this revision), the `actions` and `answer` requests (unknown to an earlier 1.3 node, which closes the connection without an answer) with their own response type and rejection reasons `unknown_request` and `already_answered`, the workload's request and reply lines on the channel, and the `NodeActionRequested`, `NodeActionAnswered` and `NodeActionRefused` evidence records (appended at the end of the catalogue, with the same consequence for an earlier `ward`). Additive within 1.3 at this revision, for brokered credentials (§6.8, [ADR-0034](decisions/ADR-0034-node-brokered-credentials.md)): the manifest's optional `credentials` grant (a node of an earlier revision fails to decode a manifest that carries it, `authority_denied`, and a node without `--credentials` refuses it `unsupported_grant`), and `credentials.proxy_injection` and `scoped_http_gateway` reading `true` on a node started with `--credentials` (the flags have been in the document since 1.1, so its shape is unchanged); the evidence records are the existing `CredentialGranted`, `CredentialDenied` and `CredentialRevoked` kinds, which every `ward` reads. Additive within 1.3 at this revision, for approval holds (§6.9, [ADR-0035](decisions/ADR-0035-node-approval-hold.md)): the manifest's optional `hold` (a node of an earlier revision fails to decode a manifest that carries it, `authority_denied`, and a node without `--approval-hold` refuses it `unsupported_grant`), the `actions` section's `hold` flag, which only a node started with `--approval-hold` emits (a strict 1.3 decoder of an earlier revision refuses a document that carries it, so enable the flag once the control planes are at this revision), and the `actions` listing's `hold` field, which appears only on a request a hold opened (so only to a control plane that signed one); the evidence records are the existing `NodeActionRequested`, `NodeActionAnswered` and `NetworkDenied` kinds. | `TASK_ADMISSION_PROTOCOL` |

Each feature is gated on the **negotiated** version, not on what the node could serve:
a 1.2 connection to a 1.3 node gets only the 1.2 features.

## 2. Negotiation

`negotiate` in `ward-node-protocol` does exactly this with the peer's offered range
`{major, min_minor, max_minor}`:

1. If the majors differ, reject with `major_version_mismatch`.
2. Otherwise take the overlap `[max(min_minors), min(max_minors)]`. If it is empty,
   reject with `no_common_minor`.
3. Otherwise accept at the **highest common minor**, `min(max_minors)`.

A rejection carries the node's own `supported` range and the node then closes the
connection without reading another line. There is no fallback, to a lower major or to
the per-session `ward-daemon` protocol. A malformed `hello` (inverted range, unknown
field) gets no response at all (node-integration.md §4).

## 3. Supported skew

- **Node.** A node serves every minor of its major from 1.0 up to its maximum. A minor
  is retired (the window's lower bound raised) only by an ADR that names the release
  boundary and migration path, as ADR-0029's compatibility policy requires; a peer that
  offers only retired minors gets `no_common_minor`.
- **Control plane.** To admit and execute tasks a control plane must negotiate **1.3 or
  later**. Offer exactly the minors you implement, and act only on the version in the
  `accepted` response: if a node accepts a lower minor than you need, treat it as
  unusable rather than sending verbs it will refuse. node-integration.md §4 recommends
  offering exactly 1.3–1.3 against this revision. Within 1.3, read the capability
  document before relying on an addition of a later revision: ask for `result` only on
  a node whose document carries `output` (§5), as the shipped driver does, sign a
  `resources` grant only for a node whose document carries `resources` with every limit
  the grant names `true`, grant `actions` or send `actions` and `answer` only to a
  node whose document carries `actions`, and sign a `hold` only for a node whose `actions`
  section carries `hold` `true`.
- **Supported combinations.** Any node and control plane whose ranges share a major and
  overlap at a minor that has every feature the control plane uses. Everything else is
  refused at the handshake, before any authority is presented.

## 4. Upgrade order

- **Node first** is safe within the window. A node that gains a minor raises only its
  `max_minor`; an unchanged control plane still negotiates the same version it did
  before, because the highest common minor cannot rise above the control plane's own
  maximum.
- **Control plane newer than the node.** If its range still includes the node's
  maximum, the node accepts at its own maximum and the control plane must limit itself
  to that minor. If its `min_minor` is above the node's maximum, the node rejects with
  `no_common_minor` and its `supported` range: upgrade the node, then raise the control
  plane's `min_minor` only once every node it drives serves that minor.
- **Rollback.** Rolling a node back below the minor a control plane requires fails the
  same way, closed, at the handshake. Rolling a control plane back is safe while its
  range still reaches a minor the node serves.

## 5. Major versions

A major bump is a breaking change: a node serves one major and rejects every other one
with `major_version_mismatch`, so there is no cross-major negotiation. It needs an ADR
with a migration path and release boundary (ADR-0029). A control plane that must drive
nodes of both majors during a migration opens a new connection offering the other
major after a `major_version_mismatch`; the node never downgrades on its own.

## 6. Protocol version and WardOS releases

The node protocol version and the WardOS release version are independent:

- WardOS releases (the workspace SemVer, bumped only in a dedicated release PR; see
  [CONTRIBUTING.md](../CONTRIBUTING.md#versioning)) version the image and binaries. A
  release changes the protocol window only if `WARD_NODE_PROTOCOL` changed since the
  previous release, so an image or runtime release does not by itself require a
  control-plane upgrade.
- `WARD_NODE_PROTOCOL` changes in the pull request that implements the new or retired
  minor, together with this document (the check above enforces that pairing). It
  never changes as a side effect of a release PR.
- `ward-node` ships in every release as its own tarball,
  `ward-node-<node version>-<arch>-linux.tar.gz`
  ([node-release-readiness.md](node-release-readiness.md) §2), under the **node
  version**: the literal `version` of `crates/ward-node` and `crates/ward-node-client`,
  which `ward-node --version` prints, independent of the WardOS version
  ([#275](https://github.com/hexrift/WardOS/issues/275)). It moves exactly when the
  node's inputs move: `scripts/release/node-version.sh` refuses a release whose node
  changed since the previous release without a higher node version, and one whose
  node version changed although nothing the node is built from did, so one node
  version names one node source across releases. The protocol version is a third
  thing: a node version may rise without a protocol change (a fix), and a protocol
  minor arrives with a node version bump at the next release. Every release carries
  its protocol window in the release manifest
  ([release-manifest.md](release-manifest.md)), as `node_protocol_window`, read from
  the marker at the top of this document at the release commit, and both trains'
  versions under `components`, so a control plane can read the window and the node
  version of a release without the tarball or the source.

## 7. What CI checks

- `scripts/security-check/protocol-window.py` (with its regression suite
  `protocol-window.test.sh`), in the `docs links` job: this document's window equals
  `WARD_NODE_PROTOCOL`.
- `ward-node-protocol` unit tests: `negotiate` accepts the highest common minor and
  rejects a major mismatch and disjoint minors with their stable reasons.
- `ward-node` unit tests over a real socket: a peer above the node's maximum minor, a
  peer of another major, and a peer offering only minors the node does not serve are
  each rejected with the node's `supported` range, nothing after the handshake is
  served and no task is registered; a newer peer that still offers the node's maximum
  negotiates down to it.
