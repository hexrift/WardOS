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
| 1.3 | Signed admission (`admit`), the `exited` state, the receipt outcome on `inspect`, and the execution verbs `start`, `stop`, `pause`, `resume`, `revoke`, `seal` ([ADR-0030](decisions/ADR-0030-node-task-admission-and-execution-ownership.md)). | `TASK_ADMISSION_PROTOCOL` |

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
  offering exactly 1.3–1.3 against this revision.
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
- `ward-node` is not yet released as an independently versioned artifact, and the
  release manifest ([release-manifest.md](release-manifest.md)) does not record the
  protocol window; the window of a release is the one in its source commit.

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
