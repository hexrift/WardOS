# ward-node integration guide: from zero to a verified attempt

Status: living document. It walks an operator and a control-plane author from an empty
host to one admitted, executed, sealed and verified attempt on `ward-node`, in the order
the work happens. Every command, flag and value here is the one the contract defines;
the contract itself is [node-integration.md](node-integration.md), cited by section, and
nothing here adds to it. What the node does not do yet is
[node-security-limitations.md](node-security-limitations.md); read it before deciding
what to put through the node. A control plane written in Node.js or TypeScript has its
own walk through the control-plane side, with a reference client and its acceptance:
[node-integration-from-nodejs.md](node-integration-from-nodejs.md).

The walk has two sides. The **operator** owns the host: the node binary, its user, its
directories, its trust store and its snapshots. The **control plane** owns authority: the
issuer key, the envelopes it signs and the attempt it drives. At this revision both run
on the same host, as the node's uid or as a uid the node is told to serve
(node-integration.md §11.1); the control plane proper
may be elsewhere, but whatever it uses to reach the node runs here.

### Docker Engine containers

Docker Engine containers are not currently a qualified deployment for `ward-node`.
On macOS, Docker Desktop supplies a Linux Engine in a managed VM; a headless Docker
Engine is available on Linux, but the Linux Engine/container path still needs its own
acceptance. The `docker` CLI alone does not run Linux containers natively on macOS.

On Apple Silicon with Docker Desktop's Linux Engine 27.4.0, the default container
`/proc` masks prevent Bubblewrap from mounting a private `/proc`. A focused follow-up
confirmed that removing those outer masks and reapplying the sensitive paths inside
Bubblewrap lets the private proc mount work. However, that run used the Engine's
reported unconfined seccomp default. Explicitly selecting Docker's built-in seccomp
profile causes `unshare --user` to fail with `Operation not permitted`, so Bubblewrap
cannot create the namespaces the node requires. The proc-path change alone does not
qualify Docker, and no supported configuration that preserves the default seccomp
boundary has been demonstrated.

Do not work around this by omitting the private proc mount, using `seccomp=unconfined`,
or granting privileged container access; the node must refuse to run when its sandbox
cannot be created. The failure is reproducible with
[`node-docker-preflight.sh`](../scripts/acceptance/node-docker-preflight.sh). Until the
proc and namespace acceptance passes with a supported Engine security profile, use a
supported Linux host or the WardOS image instead.

## 1. Operator: install the node

Every release attaches a node tarball per architecture with its checksum,
`ward-node-<node version>-<arch>-linux.tar.gz` and `.sha256`, next to the runtime
tarball ([node-release-readiness.md](node-release-readiness.md) §2). `<node version>`
is the node train's own version, not the release's: the release manifest
`wardos-<version>-manifest.json` names it under `components["ward-node"].version`, and
it stays the same across releases that change nothing the node is built from
([compatibility.md](compatibility.md) §6). `<arch>` is what
`uname -m` prints on the host, `x86_64` or `aarch64`. It carries `ward-node`,
`ward-node-adapter`, `ward-agent` (the shim a node runs hosted agent adapters under,
below), `LICENSE` and the documents, built from the release commit with
the pinned toolchain and `--locked`. Download both files from the
[release](https://github.com/hexrift/WardOS/releases) you deploy, check the tarball
before unpacking it, and install the three binaries:

```bash
arch="$(uname -m)"
version="$(jq -r '.components["ward-node"].version' wardos-0.19.0-manifest.json)"  # the release you deploy
sha256sum -c "ward-node-${version}-${arch}-linux.tar.gz.sha256"   # "OK", or stop here
tar -xzf "ward-node-${version}-${arch}-linux.tar.gz"
install -m 0755 "ward-node-${version}-${arch}-linux"/{ward-node,ward-node-adapter,ward-agent} /usr/local/bin/
ward-node --version                                            # "ward-node <node version>"
```

**The shim.** `ward-agent` lands beside `ward-node`. A node started with
`--agent-shim /usr/local/bin/ward-agent` (on the image, `--agent-shim /usr/bin/ward-agent`)
runs every hosted adapter's attempt (`--agent-adapter`) and every attempt behind an egress
proxy (`--network-allowlist`) under it, so command hooks work and stock HTTP clients reach
the proxy through its loopback relay (node-integration.md §2.1, §6.8 and §6.10,
[ADR-0037](decisions/ADR-0037-node-agent-shim-and-relay.md)). The node never looks for a
shim on its own, so without the flag none is bound. It verifies the file when it starts
and refuses to start unless the path is absolute and names a regular file (not a symlink),
the file is executable by its owner, owned by root or by the node's user and writable by
neither group nor others, its `--help` names `--relay`, and one run of `/bin/true`
hardened over the task root succeeds (a kernel without Landlock stops the node here). The
`install` above, run as root, gives the file exactly that shape: `root:root`, mode 0755.
Name the installed copy, not the one in the unpacked tarball: `tar` run as root keeps the
archive's owner, the release builder's uid, which the node refuses.
The node checks the file and not the directory it is in, so keep it in a directory only
root can write, as `/usr/local/bin` and `/usr/bin` are; a shim in a directory the node's
user or anyone else can write could be swapped after the check. `ward-agent --version`
prints the release version, not the node version: it is the same build as the runtime
tarball's, and a change to it raises the node version all the same
([compatibility.md](compatibility.md) §6).

The checksum proves the tarball is the one CI attached to the release; releases are not
signed or provenance-verified yet (node-security-limitations.md §3.3, ADR-0028).
Releases cut before this revision carry no node tarball. `install.sh`, the runtime's
installer, does not install the node: it is a per-user install of the session layer,
and the node is a service of the host. On a WardOS host the three binaries are already in
the image, at `/usr/bin/ward-node`, `/usr/bin/ward-node-adapter` and `/usr/bin/ward-agent`,
whether the image
was built from a release (`image/Containerfile`'s release stage installs the node
tarball, checksum-checked) or from a checkout (the images CI publishes;
[node-release-readiness.md](node-release-readiness.md) §2): skip the install above,
and point the unit of §3 at `/usr/bin/ward-node`.

Without a release for the commit you deploy, build the same three binaries from it with
the pinned toolchain (`rust-toolchain.toml`), as the release does:

```bash
git clone https://github.com/hexrift/WardOS && cd WardOS && git checkout <commit>   # the commit you deploy
cargo build --release --locked -p ward-node -p ward-node-client -p ward-agent
install -m 0755 target/release/ward-node target/release/ward-node-adapter target/release/ward-agent /usr/local/bin/
```

Either way, record what you installed, the release or the commit; the protocol window a
node serves is the one in its source commit ([compatibility.md](compatibility.md) §6).
The host needs bubblewrap with unprivileged user namespaces ([install.md](install.md)
§2); `bwrap --unshare-all` must work for the node's user, or the node refuses to start
with a task root.

Give the node its own user and three private directories: the node's state, its task
root and the directory that holds its socket. The node creates the first two mode 0700
and refuses them if group- or world-accessible; the socket's parent directory must
already exist with no group or other bits (§2.1). If the adapter is to run as a user of
its own rather than as `ward-node`, §3 names the two flags and the group that allow it:

```bash
useradd --system --home-dir /var/lib/ward-node --shell /usr/sbin/nologin ward-node
install -d -m 0700 -o ward-node -g ward-node /var/lib/ward-node /run/ward-node
```

Choose the node's identity: `node_` followed by a 26-character ULID in upper-case
Crockford base32 (§7.2), one per host, never reused. Any ULID library produces one; the
examples below use the contract's `node_01M3KY5QG0000028T5CY4TQKFF`. The node pins it in
`<state-dir>/node-id` at first start and refuses a later start with another id.

## 2. Control plane: an issuer key and its trust-store line

The control plane generates one Ed25519 key per issuing principal and keeps the 32-byte
seed to itself. The node never sees it: an envelope is signed where the key is and
arrives pre-signed (§11.4). Two ways to produce the trust-store line the operator needs:

- **In Rust**, with the shipped client: `IssuerKey::from_seed_file(path)` reads a seed
  file that must be a regular file of mode `0600` or `0400`, and
  `trust_store_line(principal)` returns `<public-key> <key-id> <prn_…>` (§11).
- **In any language**, with your own Ed25519 library: the public key as 64 lowercase hex
  digits, then the key id the node derives for it, then the principal:

```text
$ ward-node issuer-key-id ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c
0871f3aabc26e4582c508af5c03884e6a96f0989d1dd8cfb49cd17ed25792433
```

The key id is `BLAKE3-256` over the 32 raw public-key bytes (§2.3). The line binds the
key to exactly one principal, the `prn_…` the control plane issues leases as; a root
lease signed by this key must name that principal as its `issuer` or the admit is
`authority_denied` (§2.2, §8.1 step 8).

The key above is the **public test key** of §7.4 (its seed is 32 bytes of `0x07`). It
is in this guide so the values line up with the contract's worked example; never put it
in a production trust store.

## 3. Operator: the trust store and the service

Write the trust store, one issuer per line, `#` comments allowed. The file must be a
regular file, UTF-8, at most 64 KiB and not writable by group or others (§2.2):

```bash
install -m 0644 -o root -g root /dev/null /etc/ward-node/trusted-issuers
cat >> /etc/ward-node/trusted-issuers <<'EOF'
# control-plane issuer A
ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c 0871f3aabc26e4582c508af5c03884e6a96f0989d1dd8cfb49cd17ed25792433 prn_01M1RQ16G00000Y3RF1W7GY3RF
EOF
```

A malformed line, upper-case hex, a key id that does not match, a duplicate key or a key
bound to no principal stops the node. The store is read once at start; to rotate, add
the new key's line, restart, retire the old line, restart again (§2.2;
node-security-limitations.md §3.1).

Start the node as its user. The repository ships no unit file; this is the shape of one
an operator writes, with the flags of §2.1 and nothing else:

```ini
[Unit]
Description=ward-node
After=network.target

[Service]
User=ward-node
Group=ward-node
RuntimeDirectory=ward-node
RuntimeDirectoryMode=0700
ExecStart=/usr/local/bin/ward-node \
  --socket /run/ward-node/node.sock \
  --state-dir /var/lib/ward-node/state \
  --node-id node_01M3KY5QG0000028T5CY4TQKFF \
  --trusted-issuers /etc/ward-node/trusted-issuers \
  --task-root /var/lib/ward-node/tasks
KillMode=control-group
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

To run the adapter as a user of its own, so that a compromised adapter cannot read the
node's state, records or evidence logs, create a group for the socket, put the adapter's
user in it, give the socket directory to that group and name the user to the node. The
node then serves its own uid and `ward-adapter` and closes every other connection unread
(node-integration.md §2.1, §3); the state directory and task root stay 0700:

```bash
groupadd --system ward-clients
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin --groups ward-clients ward-adapter
```

```ini
[Service]
User=ward-node
Group=ward-clients
RuntimeDirectory=ward-node
RuntimeDirectoryMode=0750
ExecStart=/usr/local/bin/ward-node \
  --socket /run/ward-node/node.sock \
  --state-dir /var/lib/ward-node/state \
  --node-id node_01M3KY5QG0000028T5CY4TQKFF \
  --trusted-issuers /etc/ward-node/trusted-issuers \
  --task-root /var/lib/ward-node/tasks \
  --client-group ward-clients \
  --client-uid ward-adapter
```

`Group=` makes `RuntimeDirectory=` create `/run/ward-node` as `ward-node:ward-clients`,
which with `RuntimeDirectoryMode=0750` is exactly what `--client-group` requires; the
socket comes up `0660 ward-node:ward-clients`. Listing a uid grants it no authority:
`admit` still needs a signature from the trust store.

`KillMode=control-group` is what closes the die-with-parent window on a unit restart
(node-security-limitations.md §3.2); add `MemoryMax=` and `TasksMax=` to bound what the
node's workloads can take from the host, since the node sets no resource limit of its
own. The node never removes an existing socket path: delete a stale one before a
restart, or let `RuntimeDirectory=` recreate the directory.

Check it from the host, as the node's user (or as a listed client user):

```text
$ WARD_NODE_SOCKET=/run/ward-node/node.sock ward doctor      # the ward-node line reads protocol_compatible
$ echo '{"cmd":"capabilities"}' | ward-node-adapter --socket /run/ward-node/node.sock
{"schema":1,"event":"capabilities","protocol":{"major":1,"minor":3},"capabilities":{…,"lifecycle":{"pause":true,"stop":true,"revoke":true,"admit":true,"start":true}}}
```

`lifecycle.start` must be `true` (§5). If it is absent the node is running without a
task root or bubblewrap is unusable, and every execution verb will be
`unsupported_operation`.

### 3.1 Reaching the node from another host: mutual TLS

A control plane that does not run on the node's host reaches it over TCP with mutual TLS
(node-integration.md §2.1, §3;
[ADR-0038](decisions/ADR-0038-node-mutual-tls-transport.md)). The node never makes its own
certificates: the operator's PKI issues one for each node and one for each control-plane
client, from two CAs (or one CA for nodes and one for clients). Anything that issues X.509
works; with plain `openssl`, on a machine that is neither the node nor the control plane:

```bash
# Once: a CA for node certificates and a CA for client certificates (keys stay on this machine).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=ward node CA" \
  -keyout node-ca-key.pem -out node-ca.pem -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=ward client CA" \
  -keyout client-ca-key.pem -out client-ca.pem -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

# Per node: a key and a certificate for the name the control plane dials.
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=node-7.exec.internal" -keyout node-key.pem -out node.csr
openssl x509 -req -in node.csr -CA node-ca.pem -CAkey node-ca-key.pem -CAcreateserial -days 90 -out node.pem \
  -extfile <(printf 'subjectAltName=DNS:node-7.exec.internal\nextendedKeyUsage=serverAuth\n')

# Per control-plane client: a key and a client certificate.
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=institution-worker" -keyout client-key.pem -out client.csr
openssl x509 -req -in client.csr -CA client-ca.pem -CAkey client-ca-key.pem -CAcreateserial -days 90 -out client.pem \
  -extfile <(printf 'extendedKeyUsage=clientAuth\n')
```

Better still, generate each key where it is used and send only the certificate request to
the CA, so no key travels. On the node, install the node's certificate and key and the
**client** CA, all owned by the node's user; the key readable by no one else, the others
writable by no one else (the node refuses to start otherwise):

```bash
install -d -m 0700 -o ward-node -g ward-node /etc/ward-node/tls
install -m 0644 -o ward-node -g ward-node node.pem      /etc/ward-node/tls/node.pem
install -m 0600 -o ward-node -g ward-node node-key.pem  /etc/ward-node/tls/node-key.pem
install -m 0644 -o ward-node -g ward-node client-ca.pem /etc/ward-node/tls/client-ca.pem
printf '# client keys this node refuses, one sha256:<hex> per line\n' > revoked-clients
install -m 0644 -o ward-node -g ward-node revoked-clients /etc/ward-node/tls/revoked-clients
```

Add the listener to the unit's `ExecStart=`, and let `systemctl reload` reach the node:

```ini
  --listen-tls 10.0.4.7:7443 \
  --tls-cert /etc/ward-node/tls/node.pem \
  --tls-key /etc/ward-node/tls/node-key.pem \
  --tls-client-ca /etc/ward-node/tls/client-ca.pem \
  --tls-client-revoked /etc/ward-node/tls/revoked-clients
ExecReload=/bin/kill -HUP $MAINPID
```

The revocation list starts empty; it is there so that revoking a key later needs no
restart.

Listen on the address the control plane reaches and open the port to the control plane's
network only: authentication is the certificate, but nothing is gained by letting anyone
else complete a handshake. If the client CA certifies more than this control plane, pin
the control plane's keys too, with the value the node reports for a served client or the
one `openssl` computes:

```bash
openssl x509 -in client.pem -pubkey -noout | openssl pkey -pubin -outform der | sha256sum
# → add --tls-client-pin sha256:<that hex> (repeatable)
```

On the control plane, install the client's certificate and key (mode 0600, the worker's
user), the **node** CA and a list of revoked node keys, empty for now and writable by no
one but its owner, and check from there:

```text
$ printf '# node keys this client refuses, one sha256:<hex> per line\n' > revoked-nodes
$ echo '{"cmd":"capabilities"}' | ward-node-adapter --connect-tls node-7.exec.internal:7443 \
    --tls-cert client.pem --tls-key client-key.pem --tls-server-ca node-ca.pem --tls-server-name node-7.exec.internal \
    --tls-server-revoked revoked-nodes
{"schema":1,"event":"capabilities","protocol":{"major":1,"minor":3},"capabilities":{…}}
```

Every adapter process reads the list when it starts, so a revoked node key needs no
restart of anything on the control plane: the next adapter refuses it.

The node's journal says what happened at the edge: `serving the node protocol over mutual
TLS on 10.0.4.7:7443` at start, `served a TLS client sha256:<pin> from <address>` and
`refused a TLS connection from <address>: <reason>` (each at most once per client key or
address per 10 seconds, with a count of the ones in between). These lines are the only
record of handshakes; keep the journal.

**Reload, rotation and revocation.** On `SIGHUP` (`systemctl reload ward-node`) the node
reads the certificate, key, client CA and revocation list again and checks them as at
start. Only when all of them are usable does it switch to them, for every handshake from
then on; otherwise it keeps serving the previous configuration whole. Either way it says
so in the journal, and checking that line is part of every procedure below:

```text
ward-node: reloaded the TLS configuration: server key sha256:<pin> (changed), client CA certificates 1 (unchanged), pinned client keys 0, revoked client keys 1 (+1, -0)
ward-node: reloading the TLS configuration failed; still serving the previous one: <file>, line 2: malformed revoked key "sha256:00" (…)
```

The process stays up, so tasks, running attempts and the socket are untouched. Sessions
already in progress finish their one request; a session whose key you just revoked and
whose request has not started yet is closed unanswered. Write each file in full before
signalling (write a temporary file in the same directory and `mv` it into place; keep the
owner and modes of the install step), because the node reads whatever is there when the
signal arrives; if it catches a certificate without its key, it refuses the reload and
keeps the old pair, and the next `SIGHUP` after the key is in place succeeds.

- *A compromised client key:* append its pin (the value the journal reported for it in
  `served a TLS client sha256:<pin>`, or the one `openssl` computes from its certificate)
  to `revoked-clients` and reload. The journal shows `revoked client keys <n> (+1, -0)`;
  the next handshake with that key is refused, as `refused a TLS connection from
  <address>: invalid peer certificate: the client key sha256:<pin> is revoked by
  --tls-client-revoked`, even if the key is pinned. Every certificate for that key is
  refused, renewals included. A revoked key still could not admit anything: that needs
  the issuer key (§2). Remove the line and reload to serve the key again.
- *Node certificate:* issue a new one (same or new key), replace `node.pem` and
  `node-key.pem`, reload, and check that the journal reports the new `server key`. Clients
  that pin the node's key need the new pin first if the key changed.
- *A compromised node key:* whoever holds it can pose as the node to every client that
  trusts the node CA, pins or not. First generate a fresh key on the node and have the CA
  certify it (never reuse the old key). Then, on **every** client host, append the old
  key's pin (the `server key sha256:<pin>` the node's journal reported, or the one
  `openssl` computes from `node.pem`) to `revoked-nodes`; from the next adapter process on,
  a handshake with that key is refused before anything is sent, as an `error` event
  `TLS: … invalid peer certificate: the node's key sha256:<pin> is revoked`, even where
  the key is pinned, and every certificate for it, renewals included. Then install the new
  certificate and key on the node and reload; the journal reports `server key
  sha256:<new pin> (changed)`. Clients that pin the node move their pin to the new key.
  Between the revocation and the reload the clients refuse the real node too, which is the
  safe side: an attempt in flight keeps running on the node, and its `run` ends `unknown`
  if an answer is lost (§7). Keep the old pin in the list for as long as any certificate
  for it is unexpired.
- *Client certificates:* issue the new one before the old expires; nothing changes on the
  node unless it pins keys. Pins are flags, so adding or removing one is still a restart
  (§8; an attempt running at that moment ends `exited`/`unknown`, so drain first): add
  the new pin, restart, switch the client, remove the old pin, restart. Revoking the old
  key instead of unpinning it needs no restart.
- *Client CA:* put both CAs in `client-ca.pem` (the file holds several), reload, move the
  clients to the new CA, remove the old CA, reload. A client of a CA no longer in the file
  is refused at its next handshake after the reload.

`crates/ward-node/tests/node_mtls_revocation_cli.rs` exercises these procedures against
the real node: a revocation and its removal, a broken list and a half-rotated certificate
kept out, and a rotated node key and client CA, each by `SIGHUP` without a restart.
`crates/ward-node-client/tests/tls_node_revocation.rs` exercises the compromised node key:
the client refuses the revoked key, pinned or not, through the library and the adapter, and
reaches the node again once it is rotated to a fresh key and reloaded.

## 4. Operator: import a snapshot

A workload runs over a project snapshot the node already holds. Import it as the node's
user, against the node's `--state-dir`; the one line printed is exactly the envelope's
`workload.snapshot` value (§2.4):

```text
$ ward-node snapshot import --state-dir /var/lib/ward-node/state /srv/projects/example
c19c769fdd8644df9167a36d0133289c9fa44a8c768cd0aafa1756a13fb3e33b
```

It honours `.gitignore` (and includes `.git`), is bounded at 2 GiB, and is an operator
command over local files, not a socket verb. Everything the workload needs must be in
the snapshot: workloads run offline unless the node was started with
`--network-allowlist` and the manifest names the hosts to fetch from (§7.5, §9), so a
dependency that is neither there nor reachable through the proxy is not fetched.

## 5. Control plane: build, sign and run one attempt

Build the envelope of §7.1 with your own ids and current timestamps. The parts that go
wrong most often:

- `node` is the node's `--node-id`, exactly; `binding` names a task, a new attempt and
  the lease; `authority.lease.issuer` is the principal your key is bound to;
  `authority.lease.subject` equals `agent`; `authority.lease.id` equals `binding.lease`
  and `authority.lease.task` equals `binding.task` (§7.3).
- `workload.snapshot` is the line of §4 unchanged; `workload.argv` is what runs, resolved
  on the sandbox `PATH`; `workload.wall_clock_budget_ms` is mandatory and is the only
  limit the node enforces unless the node runs attempts in cgroups (below).
- `workload.capability_manifest.bytes` is the hex of `{"network":"offline"}` and `hash`
  its `BLAKE3-256`: `7b226e6574776f726b223a226f66666c696e65227d` and
  `eb3e889be30ae8dd712a52c33e37aaca72e52ccff1aa770ecbd962d0cdb0d0c3`. It is the only
  manifest a node without `--network-allowlist` admits; with the flag,
  `{"network":{"custom":[hosts]}}` is admitted too and the workload reaches those hosts
  through the proxy socket `WARD_PROXY_SOCKET` names (§7.5, §9). On a node started with
  `--output-return`, a manifest may also carry
  `"output":{"stdio_bytes":N,"files":["out/report.json",…],"files_bytes":M}` (at most
  1 MiB per stream, 8 MiB of files, 64 exact relative paths): the report's `output` then
  carries the first `N` bytes of stdout and stderr and the declared files with their
  digests (§6.6, §7.5). On a node started with `--cgroup-root`, a manifest may also carry
  `"resources":{"cpu_millis":N,"memory_bytes":M,"pids":P}` (any of the three): the
  kernel then holds the workload's whole process tree to those limits, and the attempt's
  evidence log records what it used (`NodeAttemptResourceUsage`). Ask only for limits the
  capability document's `resources` section reports `true` (§5, §7.5).
- `version` is `1` for a task's first envelope and strictly higher than every version
  the node accepted for that task before, across attempts and restarts (§10).
- `issued_at_unix_ms <= now < expires_at_unix_ms` at the node's clock, with margin.

Serialise once, sign those exact bytes with the issuer key (RFC 8032 Ed25519, no
canonicalisation), and never re-serialise (§7.4). The §7.4 test vector, with its fixed
timestamps, is what you check your encoder and signer against before signing a live
envelope. In Node.js, `examples/node-control-plane/ward-node.mjs` does all of this with
`node:crypto` alone and reproduces the vector in its tests
([node-integration-from-nodejs.md](node-integration-from-nodejs.md) §5).

Run it through the adapter in its pre-signed form, which sends your bytes unchanged and
leaves key custody with you (§11.4). Give `task_root` so the report can read the evidence
log:

```json
{"cmd":"run","envelope_json":"{\"binding\":{\"task\":\"task_01M45YYRG00001249248SK6H24\",…},…}","proof":{"issuer_key_id":"0871f3aa…","signature":"c2336bf7…"},"operation_ids":{"start_at":20},"task_root":"/var/lib/ward-node/tasks"}
```

```text
ward-node-adapter --socket /run/ward-node/node.sock < run.jsonl
```

The adapter drives `create → admit → start → inspect… → seal` and writes one event per
line, ending in `done` (§11.4). Operation ids are yours: persist the scheme you chose
(`{"start_at":20}` above) with the signed bytes before you send them, so that a restart
of your side can replay the same run (§6). The default read timeout of 90 s covers the
contract's own bounds (`start` up to 30 s after the snapshot copy, `stop` and `revoke` up
to 10 s, §3); do not lower it below 60 s.

## 6. Read the receipt and verify the evidence

The last line is the report (§11.3). Read these fields, in this order:

| Field | What to do with it |
| --- | --- |
| `outcome_certain` | `false` means `outcome` is `unknown`: treat the attempt as failed, never as success (§11.2). |
| `outcome` | `completed`, `failed`, `unknown`, or `{"refused":{"verb","reason"}}`; a refusal says which verb the node rejected and why (§8.3). |
| `receipt`, `cause` | The node's receipt and, from the evidence log, what ended the attempt (`{"Exited":{"code":0}}`, `"BudgetExceeded"`, `"Killed"`, …). |
| `sealed`, `evidence_head` | `true` and a 64-hex head mean the driver sealed the task and verified the log against its `HEAD`. Keep the head with the report. |
| `operations` | Every verb sent, its operation id and the node's answer: your audit trail of the run. |
| `output` | On a node started with `--output-return` and an envelope whose manifest carried an `output` grant (§7.5): the first `stdio_bytes` of stdout and stderr with their dropped counts, and each declared workspace file's content and `BLAKE3` digest, or digest only past `files_bytes`, or why it was skipped (§6.6). Recompute the digests over what you received and compare them with the log's `NodeAttemptOutputCollected` record. `null` otherwise. |

Then verify the log yourself, as the node's user, with the path the report gave:

```text
$ ward replay --verify /var/lib/ward-node/tasks/task_01M45YYRG00001249248SK6H24/exec_01M45YYRG00005ANB6CSVQF248.evidence/events.log
```

The log is the `ward-events` session-log format; its records are `NodeAttemptAdmitted`,
`NodeAttemptLaunched`, any `NodeAttemptIntervened`, `NodeAttemptOutputCollected` when
output was granted, `NodeAttemptEnded` (or `NodeAttemptRecovered`) and
`NodeAttemptSealed`, all with origin `node` (§6.5). The
receipt is not carried over the socket together with the head
(node-security-limitations.md §3.3), so the report's `evidence_head` and this
verification are how a control plane binds the two. What the workload wrote beyond the
files the manifest declared is in `<task-root>/<task>/<attempt>/` on the host and
nowhere else (§11.5); the declared files and the stream heads come back in the report's
`output` when the node was started with `--output-return` (§6.6).

### 6.1 Answering who delegated what

The record the node keeps for the task answers, from the host alone, who delegated what
authority to the attempt and when. As the node's user:

```text
$ ward-node audit --state-dir /var/lib/ward-node/state --task-root /var/lib/ward-node/tasks task_01M45YYRG00001249248SK6H24
```

The first line names the principal (`prn_…`: the principal your issuer key is bound to,
§2; a CI runner is a service principal with a key and principal of its own) or, for a
delegated lease, the agent that delegated it; the lease and delegation ids; the agent that
holds the lease; the task; and the lease's validity. Then come its grants, its lineage root
first with each ancestor's grants, the key id, version, node time and operation of the
`admit`, and the attempt's state, receipt outcome and evidence log. With `--task-root` the
log is verified and its `NodeAttemptAdmitted` record must agree with the task record, or
the last line ends `evidence disagrees with the record` and the command exits 1. `--json`
prints the same as one object (`"schema":1`). Keep the output with the report and the
head: together they say what ran, under whose authority, and with what result
(node-integration.md §2.6).

## 7. Handle failure the way the contract says

Node-integration.md §10 is the full list; these are the cases every control plane meets.

| What you see | What it means | What to do |
| --- | --- | --- |
| `rejected` at `admit` with `authority_denied` | Untrusted key, bad signature, malformed envelope, wrong audience, wrong issuer principal, or not yet valid (§8.1). Nothing changed, no version consumed. | Fix the envelope or the trust store; re-admit under the same version. |
| `lease_expired`, `lease_revoked` | Validity or revocation, at the node clock (§8.3). | Issue a fresh lease (a revoked one, and anything delegated from it, is gone for good on that node). |
| `stale_operation` at `admit` | The version is not above the last accepted for the task (§8.3). | Raise `version`; your per-task counter is behind the node's. |
| `unsupported_grant` | The manifest asks for a grant this node does not honour (§7.5): a network allowlist on a node without `--network-allowlist`, an `output` grant on a node without `--output-return` or above its ceilings, a `resources` grant on a node without `--cgroup-root`, naming a limit the node has no controller for, or above its ceilings, an `actions` grant on a node without `--action-channel` or above its ceilings, a `credentials` grant on a node without `--credentials`, for a service its operator did not configure, another host or above the service's ceiling, a `hold` on a node without `--approval-hold`. No version consumed. | Re-admit with `{"network":"offline"}` and no `output`, `actions`, `credentials` or `hold`, start the node with `--network-allowlist` if the workload needs egress, `--output-return` if you need its output back, `--action-channel` if it asks you questions (§6.7), `--credentials` with the service configured if it calls an authenticated service (§6.8) or `--approval-hold` if a host or credential must wait for your approval (§6.9), or do not run this workload here. |
| `rejected` at `result` with `resource_unavailable` | No stored result for the ended attempt: the manifest carried no `output` grant, the attempt never ran or was lost, or the node restarted before collecting (§6.6). | Nothing to recover: read the workspace on the host if you need it, and declare the files next time. |
| `capacity_exhausted` at `start` | The node was started with `--max-running` and already runs that many attempts, or the host's available memory or disk is below the node's floor (§8.2). Nothing changed; the task stays `ready`. | Keep the attempt queued on your side and send the same `start` (same id) again once one of the node's attempts has ended; `scheduling` in the capability document says how many run (§5). |
| `resource_unavailable` at `start` | Snapshot missing from the store, workspace already exists, or the spawn failed; the task stays `ready`. | Import the snapshot (§4), or retry `start` with the same id; never reuse an attempt id. |
| `done` with `outcome` `unknown` | Ambiguous launch, lost child, node restart mid-run, or a transport failure the driver could not recover (§11.2). | Treat as failed. Retry as a **new attempt**: `create` the same task under a new attempt id, `admit` a new envelope with a higher `version`, `start`. The old attempt never runs again. |
| `recovering` events, then `done` | A lost answer was recovered by `inspect` and one replay of the same id (§11.2). | Nothing; this is the contract working. |
| `rejected` at `create` with `attempt_mismatch` | The task's current attempt is still `created`, `ready`, `running` or `paused` (§6.1). | Stop or revoke it first, or wait for it to end. |
| The adapter exits 1 with an `error` event | A malformed command, or the node unreachable for `capabilities`, `revoke` or `inspect` (§11.4). | Nothing took effect on the node for that command; fix and resend. |

Cancellation is `revoke`, never `stop`: send `SIGTERM` to a running adapter, or
`{"cmd":"revoke",…}` for a run you drive elsewhere, and the lease is durably revoked
before the workload is killed (§11.2, §10). A later attempt of that task needs a lease
that is neither the revoked one nor delegated from it.

## 8. Restarts, on either side

**The node restarts** (§6.4). Tasks, receipts and applied operation ids survive. An
attempt that was running, paused or starting reads `exited` with outcome `unknown` and
its surviving processes are killed; retry it as a new attempt (§7 above). A `ready` task
reads `created` and needs a new `admit` with a higher version. Replays of anything that
took effect are answered as before and act on nothing.

**Your side restarts** (§11.2). Replay the run: the same operation ids, the same signed
bytes, the same `proof`, through a new adapter process. The node answers each replayed
id with the task's current state and runs nothing twice; a run that had already ended
replays as `create`, `admit` and `seal`, each answered `sealed`, with no `start`. This is
why the signed bytes and the id scheme are persisted before the first send (§5). The
acceptance case `replay_after_a_client_restart_runs_nothing_twice` is exactly this path
(node-acceptance.md §2).

**Your side is gone for a while** (node-integration.md §6.4). The node carries on without
you and never on more than you signed: a running attempt ends at its budget, an
unanswered action-channel request expires and a held capability stays refused, and an
admission whose envelope expired meanwhile is refused at `start`. Nothing you did not send
happens, and nothing waits for you either: issue envelopes and budgets you are prepared
to let run out unattended.

**Reading the outcome before it is gone.** A new attempt replaces the old one's receipt
and an evicted sealed task reads `task_not_found` (§9, §10); read `inspect` or the
report first, and keep the evidence log, which outlives both.

## 9. Versions and compatibility

Offer exactly protocol `1.3` to `1.3` in the handshake and act only on the version the
node accepts (§4); the shipped client does this. The window a node serves, the skew a
node and a control plane may run with, and the upgrade order are in
[compatibility.md](compatibility.md): upgrade the node first within the window, raise
the control plane's minimum only once every node it drives serves that minor, and
expect a handshake refusal, before any authority is presented, for anything outside the
window. The protocol version is independent of the WardOS release version
(compatibility.md §6); CI fails a change that moves one without the other
(node-release-readiness.md §1).

## 10. Day two

- **Capacity.** The node holds 1 024 tasks; ended tasks count until sealed. Seal each
  finished task once its outcome is read (§10).
- **Disk.** The node never removes a workspace or an evidence log. Archive the logs,
  then reclaim `<task-root>/<task>/` out of band, only for attempt ids you will never send
  again (§6.5, §10).
- **State files.** Edit `revocations.json` only while the node is stopped; never edit
  `admission-versions.json`, `retired-attempts.json`, `tasks/` or `node-id` (§2.5).
- **Rotation and compromise.** Add before you remove; drain before you restart
  (node-security-limitations.md §3.1). For TLS certificates, CAs and pins, §3.1 above.
- **What to read when something is odd.** `ward replay --json` on the attempt's log
  (§6.5), the node's stderr, and `inspect` through the adapter, which never acts.
