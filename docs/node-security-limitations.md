# ward-node security limitations

Status: living document. It is the security statement for the `ward-node` substrate as
shipped at this revision (protocol 1.3, ADR-0030 steps 1–11, #332 slices 5–10): what the
node enforces, what it does not, and what each gap means for an external control plane.
The contract is [node-integration.md](node-integration.md), the proof of what is claimed
here is [node-acceptance.md](node-acceptance.md), and what CI checks on every change is
[node-release-readiness.md](node-release-readiness.md). The project-wide statements this
document refines are [threat-model.md](threat-model.md) (§3.1, fleet trust) and
[security-model.md](security-model.md) (§2, non-guarantees).

A limitation listed here is not a bug. It is a boundary of the current implementation
that a control-plane author has to design around, stated so that nobody has to read the
code to find it.

## 1. Trust model in one page

- **The node is the enforcement authority on its host**
  ([ADR-0029](decisions/ADR-0029-product-split-fleet-trust-boundaries.md)). It decides
  whether a task runs and owns its workspace, spawn, budget, interventions, records and
  evidence. Nothing the control plane sends is executed on the control plane's word
  alone.
- **The control plane signs; the node verifies.** Authority reaches the node as one
  admission envelope (binding, agent, node audience, session, lease and lineage, argv,
  capability manifest, snapshot id, mandatory wall-clock budget, validity window,
  per-task version) with a detached Ed25519 signature over the exact bytes sent
  (node-integration.md §7). The node accepts a signature only from a key in its trust
  store, and only for the one principal that key is bound to (§2.2); it then checks
  audience, validity, version, lineage contraction, revocation and the manifest, in the
  order of §8.1, before anything is materialised.
- **The socket proves nothing.** Reaching the Unix socket gives a peer the ability to
  `create`, `inspect` and send verbs; it gives no authority to run anything. Every
  execution verb needs an admitted envelope, and `admit` needs a trusted signature.
  Conversely, the socket is mode 0600 in a 0700 directory, so by default only the
  node's own uid can reach it at all; an operator who shares it with a group
  (`--client-group`, mode 0660) names the uids it serves (`--client-uid`), and the node
  checks every connection's peer credentials before it reads a byte, closing any other
  peer without a response (§2.1, §3, §11.1). Being served is not authority either.
- **The workload is hostile.** It runs in a bubblewrap sandbox with its workspace as the
  only writable host path, no network but loopback, and an environment the node
  constructs from nothing (§9). The node's state, trust store, evidence logs and socket
  are never visible to it.
- **Evidence is the node's.** One append-only, hash-chained `ward-events` log per
  attempt, written by the node alone, outside the sandbox's reach (§6.5). It records
  what the node did and observed, never workload output.

## 2. What is enforced

Each row names the mechanism and where it is proven. "Acceptance" is a case of
[node-acceptance.md](node-acceptance.md) §2; "unit" means `ward-node`'s own tests, run
under the merge gate.

| Property | Mechanism | Proven by |
| --- | --- | --- |
| Authority is verified before effect | Trust store of Ed25519 keys bound to principals; signature over the exact envelope bytes; audience, validity, version, lineage and revocation checks in a fixed order with nothing materialised on failure (§8.1) | acceptance `authorization_failures_are_refused_with_nothing_materialised`; unit |
| Namespace isolation | bubblewrap with `--unshare-all` inside an unprivileged user namespace: own mount, pid, ipc, uts and network namespaces; `/usr`, `/bin`, `/lib` read-only; the workspace bound at `/work`; private tmpfs for `/tmp`, `/home`, `/run` | acceptance `isolation_holds_against_an_in_sandbox_probe` (host secret, state dir, evidence log and task root unreadable; writes outside `/work` never reach the host; the test's pid invisible) |
| Offline | `--unshare-net` with no egress socket: loopback only, no route off the host; a manifest asking for network is refused `unsupported_grant` at `admit` (§7.5) rather than run with less | acceptance (isolation probe `net.*` rows; authorization case) |
| Empty environment | `--clearenv`, then exactly `HOME=/home/agent`, `PATH`, `TERM=xterm`; bubblewrap adds `PWD=/work` when it enters the working directory. Nothing of the node's environment is passed on | acceptance (probe `env.*` rows, including a canary set in the node's environment) |
| Bounded execution | The envelope's `wall_clock_budget_ms` is mandatory; the node's reaper kills the workload at the budget, also while paused, and records `failed` with cause `BudgetExceeded` | acceptance `bounded_execution_kills_at_the_budget_and_completes_within_bounds` |
| Confirmed interventions | `pause` answers `paused` only once the whole tree is confirmed stopped, and an unconfirmed freeze is undone and refused; `stop` answers `stopped` only once the kill is reaped, else `resource_unavailable`; `revoke` writes the revocation durably before anything else and answers `revoked` even when the reap is unconfirmed, then with an `unknown` receipt (§8.2) | acceptance `interruption_pause_and_resume_leave_the_workload_alive`, `interruption_revoke_ends_the_workload_and_seals_its_evidence`; unit (the full transition matrix) |
| Durable records | Every transition is written to the task's record (temporary file, fsync, rename) before the verb is answered; a failed write refuses the verb with nothing changed; admission versions, revocations and retired attempts are durable and never removed by the node (§2.5, §6.4) | acceptance `durable_records_survive_a_node_restart`; unit |
| Fail-closed recovery | After a restart an attempt that may have been executing is `exited`/`unknown`, its surviving tree is killed, and it is never re-run; `ready` tasks need a fresh `admit` under a higher version; a log or record that does not verify stops the node | acceptance `interruption_node_kill_recovers_exited_unknown_and_never_reruns`, `durable_records_survive_a_node_restart` |
| Replay safety | Every applied `operation_id` is kept per attempt across restarts; a replay answers the current state and acts on nothing; a replaced attempt id is retired for good (§6.3) | acceptance `replay_after_a_client_restart_runs_nothing_twice`, `durable_records_survive_a_node_restart` |
| Evidence logs | One hash-chained log per attempt, node-written, fsynced before the verb is answered, bounded at 256 KiB, sealed with `HEAD` by `seal`, verifiable with `ward replay --verify` (§6.5) | acceptance (every case verifies its log and `HEAD`); unit |
| Manifest refusal | The capability manifest is one typed, bounded object; outside the grammar it fails decoding (`authority_denied`); inside it, any grant the node cannot enforce is `unsupported_grant` before the version is consumed (§7.5) | acceptance (authorization case); unit |
| Peer-credential gate | Every accepted connection's `SO_PEERCRED` uid is read before a byte of it; only the node's own uid and the `--client-uid` list are served, any other peer (root included) is closed unread, with the refusal reported on stderr at most once per uid per 10 s. The filesystem gates who can connect (socket 0600, or 0660 with `--client-group` in a 0750 group-owned directory), the credential check gates who is served (§2.1, §3) | unit (`peer`); `node_peer_uids_cli` (the second-uid cases run as root and skip unprivileged, with the reason) |
| Bounded protocol surface | One request per connection, 64 KiB lines, 10 s request and answer deadlines, strict decoders that close the connection on anything malformed, bounded state files (8 MiB), bounded registry (1 024 tasks), bounded pauses (128) and retirements (256 per task) (§3, §6) | unit |
| Fail-closed client | The shipped client and adapter never guess at a lost answer (inspect, replay once, then `unknown`), never re-admit or start a second attempt on their own, revoke rather than stop on cancellation, and transport a pre-signed envelope byte for byte (§11.2) | `ward-node-client` tests against a real node; acceptance (replay case through a new adapter process) |

## 3. What is not enforced

Each limitation names its impact for an external control plane, what an operator can do
today, and the issue that closes it. "No issue yet" means exactly that: the gap is
known and recorded here, and no child issue has been opened for it at this revision.

### 3.1 Transport and trust bootstrap

| Limitation | Impact | Mitigation today | Closed by |
| --- | --- | --- | --- |
| **Only a local Unix socket.** There is no remote transport and no mTLS. The client and the adapter run on the node's host, as the node's uid (§11.1). | A control plane on another host cannot reach the node directly. Whatever carries its commands to the host (SSH, an agent of the control plane's own) is outside this contract and unauthenticated by the node. | Run the adapter on the node's host under the node's uid and let the control plane drive it over a channel it already trusts. Pre-sign envelopes on the control plane so the issuer key never lives on the node's host (§11.4). | [#262](https://github.com/hexrift/WardOS/issues/262) |
| **Same-uid co-location by default.** The socket (0600), state directory (0700) and task root (0700) are reachable only by the node's uid unless the operator lists the uids the node serves (`--client-uid`) and the group that may connect (`--client-group`: socket 0660 in a 0750 group-owned directory); the node then checks every connection's peer credentials before reading a byte (§2.1, §3, §11.1). | With the default, a process that can talk to the node can also read and edit the node's state files, evidence logs and workspaces: a compromised client on the host is a compromised node on that host. With listed client uids, a compromised client can still `create`, `inspect` and send every verb, but cannot read or edit the node's state, records, logs or workspaces, and the issuer key still gates admission: the allowlist decides who may speak, the trust store decides whose authority counts. | Give the node its own system user with nothing else in it; run the adapter as a second user, listed with `--client-uid` and a member of the `--client-group` group (node-integration-guide.md §3); keep the issuer key elsewhere so the host cannot mint authority for any node. | The local peer-credential check is in place at this revision (the first slice of [#262](https://github.com/hexrift/WardOS/issues/262)); the remote path, where no uid exists to check, is the rest of [#262](https://github.com/hexrift/WardOS/issues/262) |
| **Manual trust-store bootstrap.** The operator writes `--trusted-issuers` by hand (§2.2). There is no enrolment, no attestation of the node and no node identity beyond the `--node-id` the operator chose. | The control plane cannot verify which node it is talking to beyond the audience id the envelope names and the socket it reached. A node id is a label, not a credential. | Treat the host's own identity (its SSH host key, its image) as the node's identity for now; keep one `node_…` per host and never reuse it. | [#262](https://github.com/hexrift/WardOS/issues/262) |
| **Key rotation needs a restart.** The trust store is read once at start; a key change is a node restart (§2.2), which turns every running attempt into `exited`/`unknown` (§6.4). | Rotating an issuer key, or removing a compromised one, costs every attempt in flight on that node. | Bind the new key before the old one is retired (several keys per principal are allowed), drain the node (stop admitting, wait for attempts to end, seal), then restart with the old key removed. | [#262](https://github.com/hexrift/WardOS/issues/262) |
| **Revocation is local.** `revoke` and `revocations.json` are per node; there is no propagation to other nodes or acknowledgement to the control plane beyond the verb's answer (§2.5). | A lease revoked on one node is still admissible on another node that trusts the same key until it expires or is revoked there too. | Keep lease lifetimes short (expiry is the fallback bound), and revoke on every node a lease could reach. | [#262](https://github.com/hexrift/WardOS/issues/262) |
| **No clock-skew policy.** Validity is judged at the node clock at `admit` and `start` (§10); the contract says to leave margin, and nothing measures or bounds the skew. | A node whose clock is wrong refuses valid envelopes (`authority_denied`, `lease_expired`) or accepts ones the control plane considers expired. | Run NTP on the node host; issue envelopes with a margin on both ends and short lifetimes; treat a refusal as a signal to check clocks. | [#262](https://github.com/hexrift/WardOS/issues/262) names the policy; no test of skew exists (node-acceptance.md §4) |

### 3.2 What a workload can and cannot do

| Limitation | Impact | Mitigation today | Closed by |
| --- | --- | --- | --- |
| **No network grants.** Every workload is offline; `network.custom` is refused `unsupported_grant`, and the node reports `network.proxy_allowlist: false` (§5, §7.5). There is no egress proxy on the node path. | Nothing in the sandbox can fetch a dependency, call an API or push a result. The honest integration shape is governed tool actions and verification runs over a snapshot that already holds what the workload needs (§11.5). | Put dependencies into the snapshot (`ward-node snapshot import`, §2.4); do network work on the control plane's side before and after the attempt. | No issue yet (a proxy-backed allowlist for `ward-node`, reusing `ward-proxy`) |
| **No result return.** Stdout and stderr are drained and not returned; the workspace is not exported; the protocol carries neither (§9, §11.5). `snapshots.read` and `snapshots.diff` are `false` (§5). | A control plane learns only the receipt (`completed`, `failed`, `unknown`) and, on the host, the evidence log. What the workload produced stays in `<task-root>/<task>/<attempt>/`, readable only as the node's uid. | Read the workspace on the host as the node's uid (the acceptance suite does exactly this); design workloads whose exit status is the verdict, as the isolation probe does. | No issue yet (bounded output on `inspect`, or a workspace export as a content-addressed snapshot) |
| **No in-sandbox callback channel.** `stream` is decoded but always `unsupported_operation`; there is no socket into the sandbox and no way for the workload to ask the control plane anything (§6.1, §11.5). | An agent runtime whose loop needs approvals, tool results or credentials from outside the sandbox cannot be hosted under the node yet. Progress is what `inspect` reports. | Run the agent loop on the control plane's side and use the node for the bounded, offline actions it delegates. | No issue yet (an action channel relayed to the control plane) |
| **No credential injection.** `credentials.proxy_injection` and `scoped_http_gateway` are `false` (§5); no credential reaches a node workload by any route. | A workload cannot authenticate to anything, which with the offline rule is consistent but limiting. | None inside the sandbox. | [#267](https://github.com/hexrift/WardOS/issues/267), after the network allowlist |
| **Only a wall-clock budget.** There is no CPU, memory, pid or disk limit on a workload; the node creates no cgroup for it (architecture.md §3.11). The sandbox root, `/tmp`, `/home` and `/run` are RAM-backed tmpfs whose size the node does not bound. | A workload can exhaust the host's memory (through tmpfs writes or allocation), pids or disk under the task root for the length of its budget. Isolation holds; availability does not. | Run the node under a service manager with resource limits on its unit (for systemd, `MemoryMax=`, `TasksMax=`), which bound every workload the node spawns collectively; keep budgets short; put the task root on its own filesystem. | [#260](https://github.com/hexrift/WardOS/issues/260) |
| **Sandbox-private writable root.** The sandbox's `/` and the mount-point directories bubblewrap creates (`/etc`) are writable tmpfs inside the sandbox; the bound system directories are read-only (node-acceptance.md §5). Nothing written there reaches the host. | None for the host. A workload that assumes `/` is read-only (as a hardening check) will find it is not. | None needed for confidentiality or integrity; the memory impact is the row above. | No issue yet (an observation, not a hole; a read-only root would be a `ward-launch` change) |
| **The die-with-parent window.** bubblewrap's `--die-with-parent` takes a sandbox down with the node, except in the brief window between the spawn and the moment the just-spawned `bwrap` arms it; the node's restart recovery kills the tree rooted at the recorded host process only once that pid is recorded (§6.4). | A node killed in that window can leave a workload running with no budget enforcement, because the reaper died with the node. The attempt still recovers as `exited`/`unknown` and is never re-run. | Run the node under a service manager whose unit kills its whole cgroup on stop (systemd's default `KillMode=control-group`), so no orphan survives a unit restart; a node-owned cgroup per attempt would close the window for a crash as well. | No issue yet for the window itself; the per-attempt cgroup is what [#260](https://github.com/hexrift/WardOS/issues/260) needs anyway |
| **Not an escape suite.** The isolation case is a contract check of what the sandbox denies to an ordinary workload (node-acceptance.md §4). Kernel privilege escalation from an unprivileged user namespace is a residual risk the project states publicly (threat-model.md §9). | A working kernel exploit defeats the boundary. | What the project does for every sandbox: a current kernel, no capabilities, no devices; `ward selftest`'s hostile probes on the session path. | [#263](https://github.com/hexrift/WardOS/issues/263) for a microVM tier |

### 3.3 Receipts, evidence and operations

| Limitation | Impact | Mitigation today | Closed by |
| --- | --- | --- | --- |
| **The receipt is not bound to the evidence head.** `inspect` reports the outcome; the protocol carries neither the log nor its sealed head (§6.5, §9). | Over the socket alone a control plane cannot tie the outcome it reads to the evidence that backs it; the binding exists only on the host. | Give the adapter `task_root` (§11.4): the report's `evidence_head` is the sealed `HEAD` the driver verified against the log, and `cause` is read from the log. Archive the log with the report. | No issue yet (an `inspect` or `seal` answer carrying the sealed head) |
| **Receipts are lost on replacement and eviction.** A new attempt replaces the old one's receipt; an evicted sealed task reads `task_not_found` (§9, §10). | Read the outcome before you retry or before the registry fills; after that, only the evidence log holds it. | Seal each finished task once its outcome is read; keep the logs (the node never deletes them). | Working as designed; no change planned |
| **Retention is the operator's.** Workspaces and evidence logs are never removed by the node (§6.5, §10). | Disk under the task root grows with every attempt until the operator reclaims it. | Reclaim out of band, only for attempt ids that will never be sent again, after the logs are archived. | Working as designed; no change planned |
| **One node, one process, one request at a time.** Connections are served serially; a slow `start` delays every other client for as long as it runs (§3). There is no scheduler, no queue and no admission control for load. | Throughput is bounded by the slowest verb in flight; a control plane needs its own queue and must not treat a slow answer as a lost one. | Give verbs the timeouts §11.1 names; drive one node from one place. | [#260](https://github.com/hexrift/WardOS/issues/260) |
| **No load, capacity or concurrency testing.** The acceptance suite runs one workload at a time; the registry, pause and state-file bounds are unit-tested (node-acceptance.md §4). | How the node behaves with hundreds of tasks or many concurrent attempts is not measured. | Keep the registry well under 1 024 tasks by sealing promptly; measure on your own hardware before relying on a figure. | [#260](https://github.com/hexrift/WardOS/issues/260) (its acceptance is 25 concurrent sandboxes) |
| **No TamperWard verdict.** The node says what it did; whether a result is certified is the control plane's decision (ADR-0029). | A `completed` receipt is a report that the workload exited 0 within its budget, not a verification. | Run verification as its own attempt whose exit status is the verdict, and certify on the control plane. | Working as designed (ADR-0029 non-goals) |
| **The node artifact is not signed itself; it is checksum-bound to the signed release manifest.** `ward-node` and `ward-node-adapter` ship in every release's node tarball, `ward-node-<node version>-<arch>-linux.tar.gz` with its `.sha256` ([node-release-readiness.md](node-release-readiness.md) §2). The release manifest records the tarball's digest and is signed keyless by the release workflow on the release tag ([release-manifest.md](release-manifest.md)), so a verified manifest proves which workflow, on which tag of which repository, recorded that digest — but the tarball carries no signature of its own, the node's install path (an operator's; `install.sh` installs the runtime only, and does run the verifier — [install.md](install.md) §1) runs the verifier only by hand, releases before the signing step (v0.4.1 and earlier) have no bundle, and the image takes the node from the tarball by checksum when built from a release (`image/Containerfile`'s release stage) and compiles it, unsigned, when built from a checkout. | A deployment that verifies the manifest by hand gets the node's publisher/workflow identity; one that only checks the `.sha256` gets integrity alone. The protocol window it gets is the one in the release's source commit (compatibility.md §6). | Download the tarball, its `.sha256`, and the release's manifest with its `.sha256` and `.sigstore.json`; run `scripts/release/verify-manifest.sh <manifest> <bundle> --tag <tag>` beside them and proceed only on `state=provenance-verified`; check that `ward-node --version` prints the release version, and record the release beside the deployment (node-integration-guide.md §1). | [#148](https://github.com/hexrift/WardOS/issues/148) (ADR-0028: tarball signing, install-path verification); a node version of its own is [#275](https://github.com/hexrift/WardOS/issues/275) |

## 4. What this means for a control plane

Read together, the rows above give the honest integration shape of node-integration.md
§11.5: bounded, offline, snapshot-based actions and verification runs, driven from the
node's host by a client the control plane trusts, with the receipt read from `inspect`
and the proof read from the evidence log on the host. A control plane that needs more
(network, output, a conversation with the workload, a remote transport) is waiting on
the issues named here, and should fail closed rather than approximate them: do not grant
what the node cannot enforce, do not infer success from `unknown`, and do not carry a
result the node never returned.
