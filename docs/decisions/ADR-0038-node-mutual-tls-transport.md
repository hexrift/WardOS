# ADR-0038 — ward-node over mutual TLS: an authenticated remote transport for the same protocol

Status: **Proposed; the remote-transport slice of
[#262](https://github.com/hexrift/WardOS/issues/262).** It amends
[ADR-0030](ADR-0030-node-task-admission-and-execution-ownership.md) ("no remote transport
or mTLS") and the transport of node-integration.md §3; it changes neither the protocol
grammar, the capability document, the admission envelope nor the event catalogue.

## Context

`ward-node` speaks its protocol on a local Unix socket only. Who may connect is decided by
the filesystem (the socket's mode and group) and, since the first slice of #262 (#378), by
a peer-credential check against the node's own uid and the operator's `--client-uid` list.
A control plane on another host therefore cannot reach a node at all except through
something of its own on the node's host (an SSH session, an agent), which the node neither
sees nor authenticates. A uid is a host-local identity: across a network there is none to
check.

Authority is already independent of the transport: `admit` verifies a detached Ed25519
signature by a trusted issuer over the exact envelope bytes, bound to the node's audience
id, to a strictly increasing per-task version and to unexpired, unrevoked leases
(ADR-0030 §2), and every mutating verb carries an operation id that replays without acting
twice (node-integration.md §6.3). What is missing is an authenticated channel: one on which
the node knows which control plane it serves, the control plane knows which node it
reaches, nobody between them reads or changes a byte, and no static secret shared by a fleet
is involved.

## Decision

### 1. The same protocol, over TLS 1.3, beside the socket

`ward-node --listen-tls <ip>:<port>` (with `--tls-cert`, `--tls-key` and `--tls-client-ca`)
binds a TCP listener and serves on it exactly the JSON-lines protocol of the socket: one
handshake line and one request per connection, the same line bounds, request and answer
deadlines and fail-closed closes, the same `NodeService` and the same task registry. The
Unix socket is unchanged and always served; `--listen-tls` is optional and off by default.
Only TLS 1.3 is offered (no TLS 1.2 or earlier, no early data, no session resumption, so
every connection verifies its certificate afresh), and a client must negotiate the
application protocol `ward-node` (ALPN): a TLS client of some other service that happens to
share a CA is closed before a protocol byte. A plaintext client is a malformed TLS record
and is closed the same way.

### 2. The node's identity is the operator's files, never the envelope's

`--tls-cert` is the node's certificate chain (leaf first) and `--tls-key` its private key,
both PEM, provisioned by the operator from whatever PKI the deployment uses (ADR-0029: WardOS
does not become its own PKI). At start the node reads every TLS file once, refusing to serve
unless each is the node user's own regular file, not a symlink, at most 64 KiB, the key
with no group or other permission bits and the certificates and CA writable by no one else
(the rule of the credentials file, ADR-0034), the key parses and is the certificate's key,
and the CA file holds at least one usable certificate. Nothing in the envelope, the
workspace or the protocol names a certificate or a key. The node's server identity proves
to a control plane which node it reached; the envelope's audience id (ADR-0030 §2) still
decides what that node admits.

### 3. A client is a certificate from the operator's client CA, optionally pinned

`--tls-client-ca` names the CA certificates a client's certificate must chain to, for
client authentication (a certificate whose extended key usage excludes `clientAuth` is
refused). `--tls-client-pin sha256:<hex>`, repeatable, narrows that to the client keys
listed: the SHA-256 of the certificate's DER `SubjectPublicKeyInfo`, the value
`openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | sha256sum` prints, so a
key pinned once survives the renewal of its certificate. Without pins, every key the client
CA certified is served. There is no shared secret: each node and each control plane holds
its own key, and nothing a node holds lets it impersonate another node or a client.

The CA alone was preferred over a pin list alone because rotation and expiry are the CA's
job and a pin list alone has neither; pins exist for a CA shared beyond the control plane.

### 4. What a TLS identity authorises

A served TLS client is exactly a served socket peer: it may send every verb. Its
certificate replaces the peer-credential gate of `--client-uid` for that listener and
nothing else. `admit` still needs a trusted issuer signature over the exact bytes, and the
operation ids, versions and revocations still fence every mutation, so a stolen client key
lets an attacker `create`, `inspect`, `stop`, `revoke` and replay what it already saw, not
admit new authority. A replayed or superseded operation is answered as on the socket
(`stale_operation`, the current state, or `invalid_state`), and a control plane that loses
the node keeps no authority on it that could widen.

### 5. Validity and clock skew

A client certificate (and, on the shipped client, the node's certificate) must be within its
validity window at the verifier's clock, stretched by `CLOCK_SKEW` (60 seconds) on either
side; outside it the handshake fails `certificate expired` or `certificate not valid yet`.
The allowance is fixed, not configurable: an operator whose clocks disagree by more runs
NTP. The node does not check its own certificate's dates at start; a client refuses an
expired node certificate, which is what the operator sees.

### 6. Handshakes cannot hold the socket

Each accepted TCP connection is handshaken on a thread of its own, at most 32 at once (one
past it is closed at accept and reported), within 10 seconds of accept. Only a completed,
authenticated session then takes the node's one-at-a-time serving lock, which the socket's
connections take too. So a slow or hostile TCP peer can occupy handshake threads but never
the protocol, and requests from both listeners are still served one at a time, exactly as
before.

### 7. Audit: reported, rate-limited, not yet durable

At start the node writes `ward-node: serving the node protocol over mutual TLS on
<addr>` to stderr. Every refused connection is reported on stderr with the peer's address and
the reason (no certificate, unknown issuer, expired, not valid yet, not pinned, no `ward-node`
protocol, TLS version, handshake timeout, too many connections), at most once per address per
10 seconds, with the count of the refusals it did not report; every served session is
reported as `served a TLS client sha256:<pin> from <address>`, at most once per client key
per 10 seconds, with the same count. Under a service manager stderr is the journal. This is
not a durable, hash-chained node record: handshakes are not task events, the event
catalogue has no kind for them, and adding one is the audit slice of #262 (§What remains).

### 8. Rotation is a restart

The files are read once. Rotating the node's certificate, the client CA or the pins is
replacing the files and restarting the node, which recovers every task from its records
(node-integration.md §6.4); an attempt in flight ends `exited`/`unknown` as for any restart.
Reloading without a restart is deferred (§What remains). Removing a compromised client is
removing its pin or issuing from a new client CA and restarting; until certificate
revocation lists or short-lived certificates exist (§What remains), a compromised client
certificate that is neither pinned out nor rotated away stays valid until it expires.

### 9. Clients

`ward-node-client` gains `TlsTransport` (`TlsSettings`: address, expected server name,
server CA, client certificate and key, optional server pin), with the Unix transport's
framing, bounds and EOF semantics; it refuses a node whose certificate does not chain to the
server CA, is not valid for the expected name or is not the pinned key, and a TLS failure is
`TransportError::Tls`. The client's key file must be mode 0600 or 0400, like the issuer seed.
`ward-node-adapter --connect-tls <host:port> --tls-cert … --tls-key … --tls-server-ca …
--tls-server-name … [--tls-server-pin …]` uses it in place of `--socket`, and the Node.js
reference client passes those flags through (`new Adapter({tls: …})`, `--connect-tls` on its
CLI), so the protocol code stays in one place.

## Alternatives

* **A shared bearer token or a fleet-wide pre-shared key.** One stolen copy impersonates every
  client to every node, and rotation touches the whole fleet. Rejected by #262.
* **TLS with server authentication only, the client authenticated by the envelope.** Reads
  (`inspect`, `actions`, `result`) and every verb but `admit` carry no signature; anyone who
  can reach the port could inspect, stop and revoke. Rejected.
* **Per-request signatures instead of TLS.** It would authenticate the requests but neither
  encrypt the answers (output, action-channel text) nor authenticate the node to the control
  plane, and it changes the protocol. Deferred as per-answer signing (§What remains), on top
  of this, not instead of it.
* **An SSH tunnel or a reverse proxy the operator runs.** It works today and stays possible,
  but the node cannot see who connected, and every deployment invents its own. Rejected as the
  contract, kept as a deployment choice.
* **Accept TLS 1.2.** Every supported client speaks 1.3; offering 1.2 adds downgrade surface
  for nothing. Rejected.
* **Hot reload on `SIGHUP`.** Small, but it needs a reload path for the trust store too to be
  coherent, and a restart is already safe. Deferred.

## Advantages

* A control plane on another host reaches a node with mutual authentication, confidentiality
  and integrity, and no secret shared beyond one key pair per party.
* Nothing in the protocol, the capability document or the envelope changes: every client,
  test vector and acceptance case of the socket holds over TLS.
* The issuer signature stays the only source of authority; the transport adds who-may-speak.

## Disadvantages

* The operator runs a PKI (or at least two CAs) and provisions files per node.
* Rotation and client removal need a restart; there is no revocation list.
* Handshakes are reported on stderr, not recorded durably.
* Two more crates in the node's closure as direct dependencies (`rustls` and `rustls-webpki`,
  both already in the lock file and the node's closure through `ward-proxy`).

## Security consequences

* New network surface: a TCP port that speaks TLS 1.3 before anything else. Before a client
  is authenticated the node parses only TLS records (rustls, the library `ward-proxy` and the
  credential broker already use), on a bounded number of threads with a bounded deadline.
* A client's key is as powerful as a listed uid on the socket, and no more: it never mints
  authority, because `admit` still verifies the issuer signature.
* `crates/ward-node/tests/node_mtls_cli.rs` runs the real node and proves: a valid client is
  served exactly what the socket serves; no client certificate, a certificate from another
  CA, an expired one, one not yet valid, a server-only certificate, an unpinned key, TLS 1.2,
  a client without the `ward-node` ALPN and a plaintext client are closed without a protocol
  byte and reported; a served TLS client is refused `authority_denied` for an untrusted
  signature and a replayed `admit` acts once; a stalled TCP peer does not hold the socket;
  unsafe or inconsistent files stop the node before it binds; a rotated client CA takes
  effect on restart with the task registry intact.
* `crates/ward-node-client/tests/tls_transport.rs` proves the client side: a node whose
  certificate is from another CA, for another name or not the pinned key is refused; a whole
  attempt runs, seals and replays over TLS without running twice, and a superseded `pause`
  replays `stale_operation`; the adapter speaks over `--connect-tls`.

## Performance consequences

One TLS 1.3 handshake (ECDHE and certificate verification on both sides) per request, since
the protocol opens a connection per request and resumption is off; one short-lived thread per
TCP connection. Nothing for a node without `--listen-tls`.

## Compatibility

Additive and operator-enabled: a node without `--listen-tls` serves exactly what it served,
and `ward-node-adapter --socket` is unchanged. `ward-node`'s and `ward-node-client`'s inputs
change (new code, `rustls` and `rustls-webpki` as direct dependencies), so the next release
must raise the node version (CONTRIBUTING.md, #275).

## How it is validated

* `ward-node` unit tests: pin parsing and duplicates, the skew arithmetic, the bound on
  connections in progress, the refusal reasons, the flags' parsing and requirements.
* `ward-node-client` unit tests: the client's file checks, pin parsing, skew, the TLS error
  inside an I/O error.
* The two end-to-end suites of Security consequences, against the real binaries, with every
  certificate generated at test time (rcgen); none is committed.
* `scripts/acceptance/node-js.sh` case `mutual_tls_transport`: the Node.js reference client
  through the shipped adapter over TLS against the shipped node, certificates made with
  `openssl` at run time, the node's pin computed the operator's way.

## What remains (the rest of #262)

* Enrolment: a node bootstrapping its own key and a short-lived certificate from the control
  plane, instead of operator-provisioned files.
* Attestation: nothing about the node's software or hardware is attested; the certificate
  says which key, not what runs behind it.
* Revocation: certificate revocation lists or short-lived certificates for clients and
  nodes, and remote revocation propagation of leases with acknowledgement.
* Reload without restart (certificates, CA, pins and the trust store together).
* A durable node audit record of every handshake, enrolment, renewal, revocation and
  trust-root change.
* Per-answer signing of the node's answers, so a record of an answer proves which node
  gave it beyond the session it came on.
