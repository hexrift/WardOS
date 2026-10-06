# ADR-0038 — ward-node over mutual TLS: an authenticated remote transport for the same protocol

Status: **Proposed; the remote-transport slice of
[#262](https://github.com/hexrift/WardOS/issues/262).** It amends
[ADR-0030](ADR-0030-node-task-admission-and-execution-ownership.md) ("no remote transport
or mTLS") and the transport of node-integration.md §3; it changes neither the protocol
grammar, the capability document, the admission envelope nor the event catalogue. §8
(client-key revocation and reload without a restart) was decided in a later slice of
#262, and §9's revocation of node keys on the client in another.

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
does not become its own PKI). At start the node reads every TLS file, refusing to serve
unless each is the node user's own regular file, not a symlink, at most 64 KiB, the key
with no group or other permission bits and the certificates and CA writable by no one else
(the rule of the credentials file, ADR-0034), the key parses and is the certificate's key,
and the CA file holds at least one usable certificate; a reload (§8) applies the same
checks and keeps the previous configuration when any fails. Nothing in the envelope, the
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

`--tls-client-revoked <file>` names a revocation list: one pin per line, spelled as
`--tls-client-pin` spells it, with blank lines and `#` comments. After the chain is
validated, a key on the list is refused even when it is pinned, and the refusal is
reported like any other (`the client key sha256:<hex> is revoked by
--tls-client-revoked`). The list is held to the rule of the certificates (the node user's
own regular file, not a symlink, writable by no one else, at most 64 KiB); a line that is
not a pin, blank or a comment stops the node at start, naming the line. A key listed twice
is revoked once.

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
the reason (no certificate, unknown issuer, expired, not valid yet, revoked, not pinned, no
`ward-node` protocol, TLS version, handshake timeout, too many connections), at most once per
address per 10 seconds, with the count of the refusals it did not report; every served session is
reported as `served a TLS client sha256:<pin> from <address>`, at most once per client key
per 10 seconds, with the same count. Every reload (§8) is reported once, as `reloaded the
TLS configuration: server key sha256:<pin> (changed|unchanged), client CA certificates <n>
(changed|unchanged), pinned client keys <n>, revoked client keys <n> (+<added>,
-<removed>)` or as `reloading the TLS configuration failed; still serving the previous
one: <reason>`. Under a service manager stderr is the journal. This is
not a durable, hash-chained node record: handshakes are not task events, the event
catalogue has no kind for them, and adding one is the audit slice of #262 (§What remains).

### 8. Revocation and rotation without a restart: `SIGHUP`

On a node started with `--listen-tls`, `SIGHUP` reloads the TLS configuration: the node
reads and checks the certificate, the key, the client CA and the revocation list again,
with the pins it was started with (they are flags, so changing them is still a restart),
and assembles a new configuration. Only when all of it is usable does it replace the old
one, in one swap, for every handshake from then on; on any failure (a malformed or unsafe
file, a key that does not match a half-rotated certificate, a missing revocation list) the
node keeps serving exactly the previous configuration and says why. Either outcome is
reported on stderr (§7). The process keeps running, so the task registry, running
attempts and the Unix socket are untouched. The node blocks `SIGHUP` before it starts any
thread and takes it on a thread of its own, so a signal never interrupts a handshake or a
verb; the processes it starts get the default signal mask back. Only the node's uid and
root can send it, the same principals that can replace its files. Without `--listen-tls`,
`SIGHUP` keeps its default effect and ends the node.

Established sessions are not interrupted. A session carries one request, bounded by the
request and answer deadlines (node-integration.md §3), so the exposure is one request
already in progress. The one exception is revocation: a session whose handshake completed
before a reload but whose request is still waiting for the one-at-a-time lock is checked
again against the revocation list when it gets the lock, and a revoked key is closed
unserved and reported (`was revoked by --tls-client-revoked after its handshake`).
Closing a session in the middle of its verb was rejected: it would turn an answered,
recorded transition into an `unknown` for the control plane without taking back anything
the verb already did.

Removing a compromised client is therefore adding its pin to the revocation list and
sending `SIGHUP`; the next handshake with that key is refused. Rotating the node's
certificate or the client CA is replacing the files and sending `SIGHUP`. Revocation is by
key, not by certificate: every certificate for a revoked key is refused, renewals
included. Certificate revocation lists, OCSP and short-lived certificates remain
(§What remains).

### 9. Clients

`ward-node-client` gains `TlsTransport` (`TlsSettings`: address, expected server name,
server CA, client certificate and key, optional server pin), with the Unix transport's
framing, bounds and EOF semantics; it refuses a node whose certificate does not chain to the
server CA, is not valid for the expected name or is not the pinned key, and a TLS failure is
`TransportError::Tls`. The client's key file must be mode 0600 or 0400, like the issuer seed.
`ward-node-adapter --connect-tls <host:port> --tls-cert … --tls-key … --tls-server-ca …
--tls-server-name … [--tls-server-pin …] [--tls-server-revoked …]` uses it in place of
`--socket`, and the Node.js reference client passes those flags through (`new
Adapter({tls: …})`, `--connect-tls` on its CLI), so the protocol code stays in one place.

**Revoked node keys.** A node key that leaked still chains to the server CA, and a pin
names the key a client expects, not the keys it must never accept again. The client
therefore takes a revocation list of node keys (`RevokedNodeKeys`, given to
`TlsTransport::with_revoked`; `--tls-server-revoked <file>` on the adapter;
`tls.serverRevoked` in the Node.js client), spelled and read exactly as the node's
`--tls-client-revoked` (§3): one pin per line, blank lines and `#` comments, a regular file
writable by no one else, at most 64 KiB, a malformed line refused with its number before
anything is sent. After the chain is validated, a node whose key is on the list is refused
at the handshake, before the pin is compared and so even when it is the pinned key, as
`TransportError::Tls` with `invalid peer certificate: the node's key sha256:<hex> is
revoked`. Every certificate for that key is refused, renewals included. The list is read
when the transport is built, so a new list takes effect at the next adapter process. The
parser is a copy of the node's rather than a shared one: the only crate both depend on is
`ward-node-protocol`, which holds the protocol's types and not a transport's files, and the
client never depends on `ward-node` (architecture.md); a unit test of the client reads a
corpus of lists with both parsers and requires the same keys or the same error.
`TlsSettings` keeps its fields, so existing callers are unchanged.

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
* **Rotation and revocation by restart only.** Safe, but a restart ends every attempt in
  flight (`exited`/`unknown`), so removing a stolen client key cost the node's running
  work. Replaced by §8.
* **Watching the files (inotify) instead of a signal.** A rotation writes several files;
  a watcher would reload between the certificate and its key and report a failure the
  operator did not cause. `SIGHUP` is the operator's own commit point, and the
  convention of service managers (`ExecReload=`). Rejected.
* **A reload verb on the protocol.** A client's key would then reconfigure who may be a
  client; the TLS identities are the operator's. Rejected.
* **X.509 CRLs instead of a key list.** They revoke a certificate, need the client CA to
  sign and publish them, and leave a renewed certificate for a stolen key valid; the
  node already names clients by key. Deferred as an addition (§What remains).
* **Closing every established session on reload.** It cuts verbs off mid-way and buys
  nothing the next handshake does not already give (§8). Rejected.

## Advantages

* A control plane on another host reaches a node with mutual authentication, confidentiality
  and integrity, and no secret shared beyond one key pair per party.
* Nothing in the protocol, the capability document or the envelope changes: every client,
  test vector and acceptance case of the socket holds over TLS.
* The issuer signature stays the only source of authority; the transport adds who-may-speak.
* A stolen client key is refused at its next handshake, and the node's certificate or the
  client CA is rotated, without a restart: no attempt in flight is lost to it.
* A node whose key leaked is refused by every client given its key in a revocation list,
  even where that key is pinned, and the node is reached again once its operator rotates
  it to a fresh key.

## Disadvantages

* The operator runs a PKI (or at least two CAs) and provisions files per node.
* Revocation is a key list the operator distributes to each node and signals, and a list of
  node keys each client host is given; there is no CRL, no OCSP and no propagation across
  nodes or clients. Changing the pins, or the trust store,
  still needs a restart.
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
* `crates/ward-node/tests/node_mtls_revocation_cli.rs` runs the real node and proves
  §3's revocation list and §8's reload: a revoked key is refused even when pinned while
  another key from the same CA is served; revoking a key and sending `SIGHUP` refuses it
  at its next handshake without a restart, the task registry intact, and removing it
  serves it again; a session authenticated before the revocation is closed unserved when
  its request comes up; a malformed, unsafe or missing revocation list and a certificate
  without its key on `SIGHUP` keep the whole previous configuration (the revocation beside
  them is not applied) and are reported; a rotated server key and client CA are served
  after `SIGHUP`, the client seeing the new key; a malformed, unsafe, symlinked,
  oversized or non-UTF-8 list stops the node at start.
* `crates/ward-node-client/tests/tls_transport.rs` proves the client side: a node whose
  certificate is from another CA, for another name or not the pinned key is refused; a whole
  attempt runs, seals and replays over TLS without running twice, and a superseded `pause`
  replays `stale_operation`; the adapter speaks over `--connect-tls`.
* `crates/ward-node-client/tests/tls_node_revocation.rs` proves §9's node-key revocation
  against the real node: a node whose key the client's list names is refused even when it
  is pinned and chains to the server CA, a list that does not name it changes nothing, a
  node rotated to a fresh key from the same CA and reloaded with `SIGHUP` is reached again
  by the same client with the same list, the adapter refuses the revoked node with
  `--tls-server-revoked` and an unusable list before anything is sent.

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

* `ward-node` unit tests: pin parsing and duplicates, revocation-list parsing and its
  line-numbered errors, the reload report, the skew arithmetic, the bound on connections
  in progress, the refusal reasons, the flags' parsing and requirements.
* `ward-node-client` unit tests: the client's file checks, pin parsing, skew, the TLS error
  inside an I/O error, the node-key revocation list's parsing, its line-numbered errors,
  its file rules and its agreement with the node's parser.
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
* Revocation beyond the key lists of §8 and §9: certificate revocation lists or
  short-lived certificates for clients and nodes, propagation of a revoked key to every
  node and every client (each list is the operator's file, per host), and remote
  revocation propagation of leases with acknowledgement.
* Reloading the pins (a file in place of the flags) and the trust store without a
  restart.
* A durable node audit record of every handshake, enrolment, renewal, revocation and
  trust-root change.
* Per-answer signing of the node's answers, so a record of an answer proves which node
  gave it beyond the session it came on.
