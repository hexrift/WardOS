# ward-node integration guide: from zero to a verified attempt

Status: living document. It walks an operator and a control-plane author from an empty
host to one admitted, executed, sealed and verified attempt on `ward-node`, in the order
the work happens. Every command, flag and value here is the one the contract defines;
the contract itself is [node-integration.md](node-integration.md), cited by section, and
nothing here adds to it. What the node does not do yet is
[node-security-limitations.md](node-security-limitations.md); read it before deciding
what to put through the node.

The walk has two sides. The **operator** owns the host: the node binary, its user, its
directories, its trust store and its snapshots. The **control plane** owns authority: the
issuer key, the envelopes it signs and the attempt it drives. At this revision both run
on the same host, as the node's uid or as a uid the node is told to serve
(node-integration.md §11.1); the control plane proper
may be elsewhere, but whatever it uses to reach the node runs here.

## 1. Operator: install the node

Every release attaches a node tarball per architecture with its checksum,
`ward-node-<node version>-<arch>-linux.tar.gz` and `.sha256`, next to the runtime
tarball ([node-release-readiness.md](node-release-readiness.md) §2). `<node version>`
is the node train's own version, not the release's: the release manifest
`wardos-<version>-manifest.json` names it under `components["ward-node"].version`, and
it stays the same across releases that change nothing the node is built from
([compatibility.md](compatibility.md) §6). `<arch>` is what
`uname -m` prints on the host, `x86_64` or `aarch64`. It carries `ward-node`,
`ward-node-adapter`, `LICENSE` and the documents, built from the release commit with
the pinned toolchain and `--locked`. Download both files from the
[release](https://github.com/hexrift/WardOS/releases) you deploy, check the tarball
before unpacking it, and install the two binaries:

```bash
arch="$(uname -m)"
version="$(jq -r '.components["ward-node"].version' wardos-0.19.0-manifest.json)"  # the release you deploy
sha256sum -c "ward-node-${version}-${arch}-linux.tar.gz.sha256"   # "OK", or stop here
tar -xzf "ward-node-${version}-${arch}-linux.tar.gz"
install -m 0755 "ward-node-${version}-${arch}-linux"/{ward-node,ward-node-adapter} /usr/local/bin/
ward-node --version                                            # "ward-node <node version>"
```

The checksum proves the tarball is the one CI attached to the release; releases are not
signed or provenance-verified yet (node-security-limitations.md §3.3, ADR-0028).
Releases cut before this revision carry no node tarball. `install.sh`, the runtime's
installer, does not install the node: it is a per-user install of the session layer,
and the node is a service of the host. On a WardOS host the two binaries are already in
the image, at `/usr/bin/ward-node` and `/usr/bin/ward-node-adapter`, whether the image
was built from a release (`image/Containerfile`'s release stage installs the node
tarball, checksum-checked) or from a checkout (the images CI publishes;
[node-release-readiness.md](node-release-readiness.md) §2): skip the install above,
and point the unit of §3 at `/usr/bin/ward-node`.

Without a release for the commit you deploy, build the same two binaries from it with
the pinned toolchain (`rust-toolchain.toml`), as the release does:

```bash
git clone https://github.com/hexrift/WardOS && cd WardOS && git checkout <commit>   # the commit you deploy
cargo build --release --locked -p ward-node -p ward-node-client
install -m 0755 target/release/ward-node target/release/ward-node-adapter /usr/local/bin/
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
  limit the node enforces.
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
  digests (§6.6, §7.5).
- `version` is `1` for a task's first envelope and strictly higher than every version
  the node accepted for that task before, across attempts and restarts (§10).
- `issued_at_unix_ms <= now < expires_at_unix_ms` at the node's clock, with margin.

Serialise once, sign those exact bytes with the issuer key (RFC 8032 Ed25519, no
canonicalisation), and never re-serialise (§7.4). The §7.4 test vector, with its fixed
timestamps, is what you check your encoder and signer against before signing a live
envelope.

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
| `unsupported_grant` | The manifest asks for a grant this node does not honour (§7.5): a network allowlist on a node without `--network-allowlist`, an `output` grant on a node without `--output-return` or above its ceilings. No version consumed. | Re-admit with `{"network":"offline"}` and no `output`, start the node with `--network-allowlist` if the workload needs egress or `--output-return` if you need its output back, or do not run this workload here. |
| `rejected` at `result` with `resource_unavailable` | No stored result for the ended attempt: the manifest carried no `output` grant, the attempt never ran or was lost, or the node restarted before collecting (§6.6). | Nothing to recover: read the workspace on the host if you need it, and declare the files next time. |
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
  (node-security-limitations.md §3.1).
- **What to read when something is odd.** `ward replay --json` on the attempt's log
  (§6.5), the node's stderr, and `inspect` through the adapter, which never acts.
