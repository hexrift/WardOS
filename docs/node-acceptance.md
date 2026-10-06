# ward-node cross-system acceptance

Status: living document. It records the acceptance suite of #332 slice 9 for the
`ward-node` contract ([node-integration.md](node-integration.md),
[ADR-0030](decisions/ADR-0030-node-task-admission-and-execution-ownership.md)): what each
case proves, how to run it, what it needs, and what it does not prove.

## 1. What it is

A real `ward-node` (the shipped binary, with a trust store and a task root) is driven over
its real Unix socket by the shipped control-plane client, `ward-node-client`, and for one
replay path by the `ward-node-adapter` process. Nothing is mocked: the sandbox is
bubblewrap, the workloads are real processes, the evidence logs are the node's own files.

The suite is [`crates/ward-node-client/tests/acceptance.rs`](../crates/ward-node-client/tests/acceptance.rs)
and, for the network allowlist (§2.2), result return (§2.3), capacity (§2.4) and the
action channel (§2.5),
[`crates/ward-node-client/tests/acceptance_network.rs`](../crates/ward-node-client/tests/acceptance_network.rs),
[`crates/ward-node-client/tests/acceptance_output.rs`](../crates/ward-node-client/tests/acceptance_output.rs),
[`crates/ward-node-client/tests/acceptance_capacity.rs`](../crates/ward-node-client/tests/acceptance_capacity.rs)
and [`crates/ward-node-client/tests/acceptance_actions.rs`](../crates/ward-node-client/tests/acceptance_actions.rs):
one `#[test]` per case, named exactly as in the tables below. The pass criterion of each
case is written in the test file's `CASES` table and repeated here word for word; the
tests `every_acceptance_case_is_documented`, `every_network_acceptance_case_is_documented`,
`every_output_acceptance_case_is_documented`, `every_capacity_acceptance_case_is_documented`
and `every_action_acceptance_case_is_documented`
fail when the two drift apart. A case that passes prints one verdict line:

```text
acceptance <case>: PASS in <ms> ms -- <criterion>
```

One case has an optional host prerequisite (§2.4: a cgroup v2 directory delegated to the
test). Without it the case prints, and the runner's table shows, a skip with its reason
instead of a verdict; it neither passes nor fails the run:

```text
acceptance <case>: SKIP -- <reason>
```

[`scripts/acceptance/node.sh`](../scripts/acceptance/node.sh) runs exactly these cases,
from all five files, with isolation required (`WARD_REQUIRE_ISOLATION=1`, so a host without a working
bubblewrap fails instead of skipping), one case at a time so the verdict lines stay
whole, and prints the verdicts (with the rest of the `cargo test` output, on stderr) and
a summary table (on stdout, so it can be captured alone):

```text
scripts/acceptance/node.sh
```

After the table, `node.sh` runs [`scripts/acceptance/node-js.sh`](../scripts/acceptance/node-js.sh),
the acceptance of the Node.js reference control plane
([node-integration-from-nodejs.md](node-integration-from-nodejs.md) §10) against a second
real node started with `--output-return` and `--action-channel` (and a third without
either, a fourth with `--network-allowlist` and `--credentials`, a fifth with
`--network-allowlist` alone, a sixth with `--network-allowlist`, `--credentials`,
`--action-channel` and `--approval-hold`, a seventh with all of those but
`--approval-hold`, and an eighth with `--agent-adapter claude-code` and
`--agent-adapter codex`), under the same isolation requirement; its twenty-five verdicts
(five of the attempt's lifecycle; three of result return: declared content with digests the host
agrees with, truncation past the budgets, and the refusal of a grant by a node without
the flag; six of the action channel, with a workload in the sandbox that proceeds only on
an approval: `--approve-all` lets it proceed, `--deny-all` stops it, an unanswered request
expires, cancelling the run answers a pending request `cancelled`, a second process
answers idempotently and meets each refusal, and a node without the flag or a grant
outside the grammar is refused, each checked against the sealed log's action records;
four of brokered credentials, against a fake OpenBao and a fake upstream on 127.0.0.1: the
upstream receives the token the proxy injected while the workload's output, the sealed log,
the task root and the node's state never hold it and the lease is revoked at the provider
at the attempt's end, a replay leases nothing, a cancel revokes the lease, and a node
without `--credentials` and the client before it refuse the grant, each checked against
the sealed log's credential records; four of approval holds, against the same fakes with a
workload that retries a held credential route: `--approve-all` approves the request the
node opened and the next request reaches the upstream with the lease injected, `--deny-all`
and an unanswered request keep the route refused by name with nothing sent upstream, and a
node without `--approval-hold` and the client before it refuse the hold, each checked
against the sealed log's action and network records; three of hosted agent adapters
(ADR-0036), with a Claude Code fake that writes its hook lines and a Codex fake that checks
its home, on the shipped build whose environment holds model keys: both run under
byte-identical signed manifests with none of the node's keys in either sandbox and one
`agent_adapter` binding in each sealed log, Claude Code's hook lines are answered `allow`
and recorded as claims while Codex has no hook socket, and an adapter the node does not
host is refused by the client and by a node without `--agent-adapter`) follow the table
and a failure of either fails the run. The credentials and hold nodes are `ward-node` built with its
`test-loopback` feature (the
shipped build never connects to a loopback upstream or speaks plain HTTP to one), which
`node-js.sh` builds into a target directory of its own or takes from
`WARD_NODE_LOOPBACK_BIN`; every other node it starts, and every node of the Rust suite
when `node.sh` runs it, is the shipped build, `WARD_NODE_BIN`, built without the feature
(§3). The cases below are the Rust suite's.

The cases also run, in parallel with the rest of the workspace, under the merge gate
(`scripts/verify/tamperward.sh`, which CI runs with `WARD_REQUIRE_ISOLATION=1` and a
working bubblewrap), so a pull request cannot merge with one of them red.

## 2. The cases

| Case | Pass criterion |
| --- | --- |
| `bounded_execution_kills_at_the_budget_and_completes_within_bounds` | a workload past its wall-clock budget ends exited/failed with cause BudgetExceeded in its evidence log within budget + 30 s and leaves no process; a completing one ends exited/completed with cause Exited 0 within 60 s; both seal with a verifying log |
| `isolation_holds_against_an_in_sandbox_probe` | one attempt runs every isolation probe and exits 0 only if no hole was found: no route off the host (loopback works), no read of a host secret, the node state dir or the evidence log, no write into a bound host directory, nothing written to /tmp or HOME reaches the host, the environment is exactly what the contract names and the node's own environment never leaks |
| `interruption_revoke_ends_the_workload_and_seals_its_evidence` | revoke mid-run is answered revoked within 15 s, every workload process is gone, inspect reports revoked with a receipt, the evidence log seals with the revoke's NodeAttemptEnded record, the lease is in revocations.json, and a replayed revoke acts again on nothing |
| `interruption_pause_and_resume_leave_the_workload_alive` | pause stops the workload's output for a 400 ms observation window with its whole process tree still present, resume lets the output continue, and the evidence log records both interventions in order |
| `interruption_node_kill_recovers_exited_unknown_and_never_reruns` | after SIGKILL of the node mid-run and a restart the attempt reads exited/unknown, the workload is gone and its output stops, a replayed start answers exited and a new start is invalid_state, the workload's run marker was written once, and a full client replay seals it with outcome unknown |
| `authorization_failures_are_refused_with_nothing_materialised` | an untrusted key, an expired lease, a wrong node audience and a manifest asking for network are each refused at admit with authority_denied, lease_expired, authority_denied and unsupported_grant and no task directory exists; a stale version is stale_operation and a revoked lease is lease_revoked with no workspace and no evidence log for the refused attempt |
| `replay_after_a_client_restart_runs_nothing_twice` | the same operation ids replayed in process and from a new ward-node-adapter process with the pre-signed bytes answer sealed/completed with the same receipt, cause and evidence head, the workload's marker has one line and the log is unchanged; a retired attempt is refused stale_operation by create |
| `durable_records_survive_a_node_restart` | after SIGKILL and restart a sealed attempt reads sealed/completed, its evidence log and HEAD verify to the same head, every replayed operation id answers sealed, a client replay reports the same outcome, and a retired attempt stays stale_operation across a further restart |

Together they cover the epic's completion gate: bounded execution (case 1), recovery
(cases 5 and 8), authorization failure (case 6) and replay safety (cases 7 and 8), with
isolation (case 2) and interruption (cases 3 to 5) as the cross-system properties the
slice is named for. The network allowlist cases of §2.2 extend isolation and interruption
to an attempt with egress; the result return cases of §2.3 prove the bounded result a
control plane receives against the files on the host; the action channel cases of §2.5
prove the question-and-answer path from a workload to the control plane, its records and
its refusals.

### 2.1 How each case reads its result

The main suite's workloads are admitted without an `output` grant, so the protocol
carries none of their output and does not export the workspace (node-integration.md
§11.5); the cases read outcomes the way a control plane on the node's host can:

- the receipt and state from `inspect` through the client, and the client's
  `AttemptReport` (`outcome`, `receipt`, `cause`, `evidence_head`, `operations`);
- the attempt's evidence log, verified with `ward_node::evidence::verify` and the
  `ward-events` log verifier against its `HEAD`;
- the node's own files under its state dir and task root, which the test runs as the
  node's uid and may read: `revocations.json`, each attempt's workspace, each evidence
  directory;
- `/proc`, to count the workload's processes by a marker unique to the test run.

The isolation case puts the probe in the project snapshot and makes its verdict the
workload's exit status: `0` when every probe found isolation holding, `1` when any found
a hole, `2` when the probe itself could not run. The receipt (`completed` only for exit
0) and the evidence log's `NodeAttemptEnded` cause (`Exited { code }`) carry that status
to the test, which then reads the probe's per-check rows from the workspace on the host
for the diagnostics. The probes, each a hole if it fails:

| Probe | Checks |
| --- | --- |
| `net.private`, `net.external` | A TCP connect to `10.255.255.1:9` and to `1.1.1.1:80` fails (the sandbox's network namespace has no route off the host). |
| `net.loopback`, `net.interfaces` | A connect to a listener the probe opened on `127.0.0.1` succeeds, and `/proc/net/dev` lists only `lo`: loopback is kept, as node-integration.md §9 says, and nothing else exists. |
| `fs.secret` | A file the test wrote next to the node's directories on the host cannot be read. |
| `fs.state_dir`, `fs.evidence_log`, `fs.task_root` | `<state-dir>/node-id`, the attempt's own `events.log` and the task root do not exist for the workload. |
| `fs.work_read` | `src/input.txt` from the snapshot is readable at `/work` (a positive control). |
| `fs.write.*` | Creating a file under `/usr`, `/usr/bin`, `/etc/ssl`, the state dir and the evidence directory fails. |
| `fs.private.*` | Writes to `/tmp`, `$HOME` and `/` succeed inside the sandbox; the test then asserts none of them exists on the host, so they landed in sandbox-private tmpfs. |
| `env.keys`, `env.home`, `env.term`, `env.canary` | The environment the workload was exec'd with (`/proc/self/environ`) has no key outside `HOME`, `PATH`, `TERM` and `PWD`, with `HOME=/home/agent` and `TERM=xterm`; a canary variable set in the node's own environment is absent. |
| `pid.host` | The test process's pid is not visible in the workload's `/proc`. |
| `cwd` | The working directory is `/work`. |

### 2.2 The network allowlist cases

The cases of `acceptance_network.rs` start the node with `--network-allowlist`
(node-integration.md §2.1) and admit a manifest `{"network":{"custom":["example.com"]}}`
(§7.5). The workload then runs behind the attempt's own egress proxy (§9), bound at
`/run/ward/proxy.sock` and named by `WARD_PROXY_SOCKET`.

| Case | Pass criterion |
| --- | --- |
| `network_allowlist_lets_only_listed_hosts_out_through_the_proxy` | a workload admitted with network.custom reaches the allowlisted host through the proxy socket at /run/ward/proxy.sock named by WARD_PROXY_SOCKET, and is refused 403 for a non-listed host, a private literal, a loopback literal and the metadata endpoint by CONNECT and by forward; raw TCP, UDP and DNS have no path and the sandbox has only lo; the environment is exactly the contract's plus WARD_PROXY_SOCKET; the attempt completes and its sealed log records one NetworkRequested allow and five NetworkDenied with origin node and no ObservationsDropped |
| `network_allowlist_proxy_pauses_resumes_and_stops_with_the_attempt` | while the attempt is paused its proxy answers 503 paused by ward and records nothing, after resume it decides and records again, and after stop the proxy socket is gone, nothing accepts on it and no workload process is left; the sealed log shows the verdicts around the two interventions in order |
| `network_allowlist_is_advertised_and_honoured_only_when_enabled` | a node started without --network-allowlist reports network.proxy_allowlist false and refuses a network.custom manifest unsupported_grant with nothing materialised; the same node started with it reports network.offline and network.proxy_allowlist true at 1.3 |

The first case's probe runs inside the sandbox and makes its verdict the workload's exit
status, as the isolation probe does; the test then reads its rows from the workspace. The
probes, each a hole if it fails:

| Probe | Checks |
| --- | --- |
| `env.socket`, `env.keys`, `proxy.socket` | `WARD_PROXY_SOCKET` is `/run/ward/proxy.sock`, a socket; the environment has no key outside `HOME`, `PATH`, `TERM`, `PWD` and `WARD_PROXY_SOCKET`. |
| `proxy.allowed` | `CONNECT example.com:443` through the socket is answered `200` (the tunnel opened) or `502` (the proxy allowed it and the upstream was unreachable): allowed by policy either way, never `403`. The proxy's verdict, recorded as `NetworkRequested`, is what the case proves; a reply from the host is not required. |
| `proxy.denied.host`, `proxy.denied.private`, `proxy.denied.loopback`, `proxy.denied.metadata`, `proxy.denied.metadata_forward` | `CONNECT` to `denied.example:443`, `10.255.255.1:80`, `127.0.0.1:80` and `169.254.169.254:80`, and a forwarded `GET http://169.254.169.254/latest/meta-data/`, are each answered `403`. |
| `net.raw_tcp`, `net.raw_udp`, `net.dns` | A raw TCP connect to `1.1.1.1:80` fails, a UDP datagram to `1.1.1.1:53` cannot be sent, and `example.com` does not resolve inside the sandbox: the proxy is the only path out. |
| `net.interfaces` | `/proc/net/dev` lists only `lo`. |

The second case drives the proxy from the host, as the node's uid, through the attempt's
socket under `<task-root>/<task>/<attempt>.egress/`: `403` before the pause, `503 paused by
ward` while paused with nothing recorded, `403` after resume, and no socket at all after
`stop`. The third needs no workload.

### 2.3 The result return cases

The cases of `acceptance_output.rs` start the node with `--output-return`
(node-integration.md §2.1) and admit manifests carrying an `output` grant (§7.5). The
workloads are shell one-liners that print to both streams and write files into the
workspace; the control plane reads the result through the driver's report and through
`result` (§6.6), and the test compares it with the files in the workspace on the host and
with the `NodeAttemptOutputCollected` record of the sealed log.

| Case | Pass criterion |
| --- | --- |
| `output_return_delivers_bounded_stdio_and_files_with_matching_digests` | a workload admitted with an output grant on a node started with --output-return prints to both streams and writes files; the report carries exactly what it printed with dropped 0, each declared file's content and BLAKE3 digest equal to the file in the workspace on the host, a file past files_bytes digest-only with its true size, a missing path and a planted symlink skipped unread; the sealed log records NodeAttemptOutputCollected with the same digests right before NodeAttemptEnded; the result is stored mode 0600 in a 0700 directory beside the workspace and nothing is written into the workspace |
| `output_return_marks_truncation_and_keeps_digests_right_past_the_budgets` | a workload writing past stdio_bytes on both streams and a file past files_bytes gets exactly the first stdio_bytes of each stream, truncated true and the exact dropped count, the file digest-only with its true size and digest, the evidence record agreeing on every count and digest, and result answering the same bytes after seal |
| `output_return_refuses_escaping_paths_at_admit_and_follows_nothing` | a signed envelope whose manifest declares ../x or an absolute path is refused authority_denied at admit with no task directory created; a workload that plants a symlink to a host secret at one declared path and a symlink to a directory on another is reported not_a_regular_file for both, the host secret appears nowhere in the result or the log, and the attempt still completes |
| `output_return_is_advertised_and_honoured_only_when_enabled` | a node started without --output-return carries no output section in its 1.3 capability document, refuses an output grant unsupported_grant with nothing materialised and answers result unsupported_operation; the same node started with it reports output.stdio and output.files true, and an attempt it admitted without the grant has no result (resource_unavailable) while its receipt is unchanged |
| `output_return_survives_a_node_restart_and_seal` | after SIGKILL of the node and a restart with the flag, result answers the sealed attempt's output byte for byte as before the kill, the evidence log and HEAD still verify with the NodeAttemptOutputCollected record in place, and a client replay of the run with the same operation ids reports the same output without running anything |

The escaping-path part of the third case cannot be built through the shipped client,
whose manifest type refuses the path at construction; the test hand-crafts the envelope
bytes (the valid manifest's hex and hash replaced by the escaping one's) and signs them,
so what is proven is the node's own refusal of a signed envelope outside the grammar. The
planted symlink names the host secret by its absolute host path, which the workload
cannot read; the case proves the node never follows it when it collects.

### 2.4 The capacity cases

The cases of `acceptance_capacity.rs` start the node with `--max-running`, and with
`--cgroup-root` where a cgroup is delegated (node-integration.md §2.1), and drive many
attempts at once (#260). They run one at a time even within their own binary, so no case
measures another's load.

| Case | Pass criterion |
| --- | --- |
| `capacity_runs_twenty_five_concurrent_sandboxes_within_the_running_bound` | a node started with --max-running 25 runs 25 CPU-burning sandboxes at once, every one inspected running with its process tree present, and reports scheduling.max_running 25 and running 25; while all 25 burn, every inspect and capability request is answered within 2 s; a 26th start is refused capacity_exhausted with the task still ready and no workspace, and the same start is accepted running once one attempt is stopped; every attempt then stops, seals with a verifying log and leaves no process, and running reads 0 |
| `capacity_refuses_a_start_below_the_memory_or_disk_floor` | a node whose --memory-floor or --disk-floor is above what the host has available refuses start capacity_exhausted with the task still ready, nothing materialised and no evidence of a launch, and reports the floor above the available bytes in its scheduling section |
| `capacity_resource_limits_are_refused_without_a_cgroup_root` | a node started without --cgroup-root carries no resources section in its 1.3 capability document and refuses a manifest with a resources grant unsupported_grant at admit with nothing materialised, while the same node admits and runs an offline manifest |
| `capacity_cgroup_limits_hold_and_usage_is_recorded` | on a node started with --cgroup-root every attempt's sealed log records NodeAttemptResourceUsage with its CPU time right before NodeAttemptEnded and its task record carries the same usage; with the pids controller a workload forking past pids 8 is held at it (peak at most 8, forks refused counted); with the memory controller a workload allocating past memory_bytes is killed by the limit (outcome failed, oom kills counted, peak at most the limit); with the cpu controller a busy loop limited to 100 cpu_millis uses at most 0.3 s of CPU in 2 s; a limit the node has no controller for is refused unsupported_grant |

The first case's workloads are shell busy loops (`while :; do :; done`), 25 of them on
however many CPUs the host has (four on CI's runner); it prints how many requests it
sent while they burned and the slowest answer, and asserts each `inspect` and
capability request within 2 s. Each attempt's process tree (the outer `bwrap`, its
namespace init and the shell) is counted in `/proc` by a marker unique to the run.

The last case needs a cgroup v2 directory in which the test can create a child it then
hands to the node as `--cgroup-root`: `WARD_NODE_CGROUP_ROOT`, or the host's cgroup2 mount
when the test runs as root. Without one it prints `SKIP` with the reason. With one whose
controllers include neither `pids` nor `memory` it still checks the accounting and the
refusals, then prints `SKIP`, because no limit could be proven held. With
`WARD_REQUIRE_CGROUP=1` either skip is a failure instead. Each limit is proven only where its
controller is present, and the case prints which limits the kernel held: pids by a
workload forking 32 sleeps under `pids` 8, memory by `dd` with a 256 MiB buffer under
`memory_bytes` 32 MiB, CPU by a two-second busy loop under `cpu_millis` 100. CI's runner
delegates no cgroup to the tests, so on CI this case is a `SKIP` row (§4).

### 2.5 The action channel cases

The cases of `acceptance_actions.rs` start the node with `--action-channel`
(node-integration.md §2.1) and admit manifests carrying an `actions` grant (§7.5). The
workload is a small Python agent from the imported snapshot that connects to the socket
`WARD_ACTION_SOCKET` names (`/run/ward/actions.sock`), asks for approval, writes the reply
it received into the workspace and exits 0 only on `approved` (non-zero on `denied`,
`expired`, `cancelled` or no reply); the hostile case first sends four hostile lines, each
on its own connection, and records how many bytes came back. The control plane lists
pending requests with `actions` and answers with `answer` (§6.7) through the shipped
client; the test compares what the workload received with what was answered and with the
`NodeActionRequested`, `NodeActionAnswered` and `NodeActionRefused` records of the log.

| Case | Pass criterion |
| --- | --- |
| `action_channel_approval_lets_the_workload_proceed_and_a_denial_stops_it` | a workload admitted with an actions grant on a node started with --action-channel finds WARD_ACTION_SOCKET=/run/ward/actions.sock, asks for approval and waits; the control plane lists the request with its id, kind, summary and detail and approves it, the workload receives approved with the note and exits 0, and a second attempt that is denied receives denied and exits non-zero without proceeding; each sealed log records NodeActionRequested with the summary and detail digests and NodeActionAnswered with the answer's operation id before NodeAttemptEnded, never the text; the socket lives in a 0700 directory beside the workspace and is gone once the attempt ends |
| `action_channel_unanswered_request_expires_after_its_wait` | a request nobody answers is answered expired by the node once the grant's wait_secs ran out, the workload fails closed with a non-zero exit, the log records NodeActionAnswered expired with no operation id, and a late answer once the attempt has ended is refused invalid_state |
| `action_channel_stop_and_revoke_cancel_a_pending_request` | a stop and a revoke while a request is pending each end the attempt (stopped, revoked) with no workload left, answer the request cancelled and record NodeActionAnswered cancelled before NodeAttemptEnded; a later answer is refused invalid_state and the listing is empty |
| `action_channel_pause_keeps_a_request_pending_until_answered_after_resume` | a pause while a request is pending keeps it pending past its wait (the listing reads paused with the request in it, nothing is answered expired), and an approval given after resume is delivered: the workload proceeds and exits 0, and the log shows the pause and resume around the request and its answer |
| `action_channel_hostile_lines_get_nothing_and_are_recorded` | an oversized line, a malformed line, a node lifecycle request and a hello sent on the channel, each on its own connection, are each answered with zero bytes and a closed connection and recorded as NodeActionRefused oversized, malformed, control_request and control_request; nothing of them reaches the control plane's listing, and a well-formed request afterwards is still listed and approved |
| `action_channel_replayed_answer_is_idempotent_and_a_second_answer_is_refused` | replaying an answer with the same operation id and the same decision is answered answered again and appends nothing, a different answer to the same request is refused already_answered, the same operation id with another decision is refused stale_operation, an unknown request number is refused unknown_request, and the log holds exactly one NodeActionAnswered for the request |
| `action_channel_pending_request_is_cancelled_when_a_restarted_node_recovers_the_attempt` | after SIGKILL of the node while a request is pending and a restart with the flag, the attempt is exited with an unknown receipt, its log records NodeActionAnswered cancelled for the request before NodeAttemptRecovered and still verifies, the listing is empty and the attempt seals |
| `action_channel_is_advertised_and_honoured_only_when_enabled` | a node started without --action-channel carries no actions section in its 1.3 capability document, refuses an actions grant unsupported_grant with nothing materialised and answers actions and answer unsupported_operation; the same node started with it reports actions with approval and decision and its ceilings, and refuses a grant above them unsupported_grant |

The pause case holds the pause for six seconds against a five-second wait: the time the
listing says the request has left is the same before and after, and nothing is answered
`expired`; that sleep is the passage of time the case is about, not a synchronisation.
Every other wait in these cases polls a condition (the listing, `inspect`) with a bound.

## 3. Running it

```text
scripts/acceptance/node.sh                      # the suite, isolation required, then node-js.sh
scripts/acceptance/node-js.sh                   # the Node.js reference control plane alone (node-integration-from-nodejs.md §10)
cargo test -p ward-node-client --test acceptance # the same cases, skipping without bubblewrap
scripts/acceptance/node.test.sh                 # the runner's own rendering regressions
```

The runner's table has one row per case with its result and wall time; its exit status
is 0 only when every case passed and at least one ran. A run as an unprivileged user is
part of the slice's verification: build first, then run the test binary from a directory
that user can read, with `WARD_REQUIRE_ISOLATION=1`, `HOME` and `TMPDIR` pointing at a
writable directory.

Which `ward-node` each case runs:

| Cases | Build | Where it comes from |
| --- | --- | --- |
| The Rust suite's (§2), run by `node.sh` | shipped, without `test-loopback` | `WARD_NODE_BIN`, or built by `node.sh` into `${CARGO_TARGET_DIR:-target}/node-shipped` and passed on to the suite and to `node-js.sh` as `WARD_NODE_BIN` |
| `node-js.sh`'s lifecycle, result return and action channel cases, its node with `--network-allowlist` and without `--credentials`, and every `snapshot import`, `issuer-key-id` and `audit` | shipped, without `test-loopback` | `WARD_NODE_BIN`, or built into the same `node-shipped` directory |
| `node-js.sh`'s credentials node, hold node and node without `--approval-hold` | `test-loopback` | `WARD_NODE_LOOPBACK_BIN`, or built into `${CARGO_TARGET_DIR:-target}/node-js-test-loopback` |

Neither runner takes `ward-node` from `${CARGO_TARGET_DIR:-target}/debug`: a `cargo test`
of `ward-node` or of the workspace (the merge gate runs it with `--all-features`) leaves the
`test-loopback` build there, since `ward-node`'s own tests enable the feature. A
`test-loopback` build says so in its `--version` (`ward-node 0.1.0 (test-loopback)`; the
shipped build prints `ward-node 0.1.0`), and both runners refuse a `WARD_NODE_BIN` that
does, as `node-js.sh` refuses a `WARD_NODE_LOOPBACK_BIN` that does not, before anything is
started. The Rust suite's own helper does the same: run on its own, or under the merge
gate (§1), `cargo test -p ward-node-client` uses `WARD_NODE_BIN` when it is set and
otherwise builds the shipped `ward-node` into the same `node-shipped` directory, never the
`ward-node` beside its test binaries, and it refuses a `test-loopback` build either way
(#422). Every run of the cases therefore proves the shipped build.

### 3.1 What the host needs

- Linux with bubblewrap and unprivileged user namespaces (`bwrap --unshare-all` must
  work for the user running the tests). The suite skips without them unless
  `WARD_REQUIRE_ISOLATION=1`, exactly as every other bubblewrap-backed test in the
  workspace; the runner always sets it.
- `sh` and `python3` resolvable from a bound system directory (`/usr`, `/bin`, with
  `/etc/alternatives` for a Debian-style `python3` symlink): the workloads are shell
  one-liners and the beating and probing workloads are Python programs with no
  dependencies beyond the standard library.
- A readable `/proc`: the cases count workload processes by marker there.
- For the cgroup case of §2.4 only: a cgroup v2 directory the test may create a child in,
  named by `WARD_NODE_CGROUP_ROOT` (or the cgroup2 mount when running as root), with the
  `pids`, `memory` and `cpu` controllers enabled in its `cgroup.subtree_control` for the
  limits to be proven; without it the case skips.
- No network is needed by the main suite; its network probes expect connects to fail. The
  network allowlist's allowed-host case (§2.2) needs the host to resolve `example.com`
  (the proxy resolves the allowlisted name on the host before it decides); without name
  resolution that one case skips, or fails under `WARD_REQUIRE_ISOLATION=1`. Whether the
  host can then reach `example.com` does not matter: the case accepts the proxy's `200`
  and its `502` alike, because the verdict, not the reply, is what it proves.

### 3.2 Time bounds

Every bound in the suite is generous against the contract's own (node-integration.md §3:
`start` waits up to 30 s for the spawn, `stop` and `revoke` up to 10 s for the reap) and
is asserted in code: a completing run ends within 60 s, a budget kill lands within the
budget plus 30 s, a `revoke` answers within 15 s, a pause is observed for 400 ms, and
wait-on-condition loops give up after 20 s. A whole run of the suite takes well under a
minute on a developer machine; each case prints its own time.

## 4. What it does not prove

- **No remote transport here.** This suite drives the local Unix socket only. The
  mutual-TLS listener of ADR-0038 is proven by `ward-node`'s `tests/node_mtls_cli.rs`,
  `ward-node-client`'s `tests/tls_transport.rs` and `node-js.sh`'s `mutual_tls_transport`;
  enrolment, attestation and revocation of transport identities have nothing to test yet
  (#262).
- **No loopback relay, and credentials outside this suite.** The network cases prove the
  proxy's verdicts, its recording and its lifecycle through the Unix socket the sandbox is
  handed; they do not prove a workload tool that only speaks `HTTP_PROXY` can use it (only
  a hosted adapter on a node with `--agent-shim` has an in-sandbox relay, proven by
  `ward-node`'s own `tests/node_agent_relay_cli.rs`, node-integration.md §6.10). Brokered credentials
  (node-integration.md §6.8) are proven against a real node by `ward-node`'s own
  `tests/node_credentials_cli.rs` and, driven through `ward-node-adapter`, by the four
  credentials cases of `node-js.sh`, both against a fake OpenBao and a plain-HTTP fake
  upstream on loopback with the `test-loopback` build; not by a case of the Rust suite
  here, and never against a real provider or a TLS upstream (#267). Approval holds
  (node-integration.md §6.9) likewise: by `ward-node`'s own `tests/node_hold_cli.rs`
  (approve, deny, expiry, stop, pause, a node restart, forged, replayed and misdirected
  answers) and by the four hold cases of `node-js.sh`, against the same fakes; a held host
  is proven released only on a credential route to it, since the shipped proxy never
  connects to a loopback upstream.
- **Hosted agent adapters outside this suite.** A workload naming an agent adapter
  (node-integration.md §6.10, ADR-0036) is proven by `ward-node`'s own
  `tests/node_adapter_conformance.rs` (the same signed manifest through Claude Code, Codex
  and the generic adapter, with identical refusals and enforcement records),
  `tests/node_agent_relay_cli.rs` (the operator's `ward-agent` shim and its relay,
  ADR-0037: a model round trip with the lease injected by the node's broker, command hooks
  recorded as claims, no base URL without a grant, a held credential refused until
  approved) and by the three agent-adapter cases of `node-js.sh`, with fake runtimes;
  never with a real runtime against a real model.
- **No workspace export, no streamed output.** The result return cases prove the bounded
  result of §2.3 (declared files, stream heads); what a workload wrote beyond the files it
  declared is still read on the host as the node's uid, which a remote control plane
  cannot do, and nothing is carried while the attempt runs.
- **Approvals are enforced only as holds, outside this suite.** The action channel cases
  (§2.5) prove that a workload that asks holds on the answer, and that the node records,
  relays, expires and cancels as the contract says; nothing proves, or could, that a
  workload which never asks is stopped, because the node enforces nothing on an approval a
  workload asks for itself. What the node enforces, a hold on a host or a credential, is
  proven by the tests named in the bullet above. The hostile case sends four kinds of
  lines, not a fuzzer's corpus; the channel's parser is unit-tested for the rest.
- **No escape attempt beyond the probes.** The isolation case is a contract check of what
  the sandbox denies to an ordinary workload, not an adversarial escape suite; the
  kernel-level boundary tests of [experiments.md](experiments.md) E-01 and the
  `ward-daemon` namespace, verifier and egress regressions are separate.
- **Concurrency at 25, not at scale; limits only where a cgroup is delegated.** The
  capacity cases run 25 sandboxes at once under CPU pressure; hundreds of attempts, host
  memory pressure and single-attempt latency are not measured, and the 1 024-task
  registry, the 128-pause bound and the 8 MiB state files are unit-tested in `ward-node`,
  not here. On CI's runner no cgroup is delegated, so the kernel's enforcement of pids,
  memory and CPU limits is not proven there (the case skips, visibly); it is proven on a
  host that delegates one.
- **No clock skew.** Envelopes are signed at the node's own clock.
- **No TamperWard verdicts.** The suite says what the node did; whether a result is
  certified is the external control plane's decision (ADR-0029).

Each of these, with its impact for a control plane and the issue that closes it, is a
row of [node-security-limitations.md](node-security-limitations.md) §3; where this suite
runs in CI and what else CI proves is [node-release-readiness.md](node-release-readiness.md).

## 5. Findings recorded by the suite

- The environment a workload is exec'd with carries `PWD=/work` beside `HOME`, `PATH`
  and `TERM`: bubblewrap sets it when it changes into `/work`. The contract's wording in
  node-integration.md §9 names it; the probe's `env.keys` row prints the exact key set
  on every run.
- The sandbox root (`/`) and the mount-point directories bubblewrap creates (`/etc`) are
  writable tmpfs inside the sandbox. They are sandbox-private and nothing written there
  reaches the host, which the `fs.private.*` rows and the host-side assertions show; the
  bound system directories themselves are read-only (`fs.write.*`).
