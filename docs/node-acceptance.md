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

The suite is [`crates/ward-node-client/tests/acceptance.rs`](../crates/ward-node-client/tests/acceptance.rs):
one `#[test]` per case, named exactly as in the table below. The pass criterion of each
case is written in the test file's `CASES` table and repeated here word for word; the
test `every_acceptance_case_is_documented` fails when the two drift apart. A case that
passes prints one verdict line:

```text
acceptance <case>: PASS in <ms> ms -- <criterion>
```

[`scripts/acceptance/node.sh`](../scripts/acceptance/node.sh) runs exactly these cases
with isolation required (`WARD_REQUIRE_ISOLATION=1`, so a host without a working
bubblewrap fails instead of skipping), one case at a time so the verdict lines stay
whole, and prints the verdicts (with the rest of the `cargo test` output, on stderr) and
a summary table (on stdout, so it can be captured alone):

```text
scripts/acceptance/node.sh
```

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
slice is named for.

### 2.1 How each case reads its result

The protocol carries no workload output and does not export the workspace
(node-integration.md §11.5), so the cases read outcomes the way a control plane on the
node's host can:

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

## 3. Running it

```text
scripts/acceptance/node.sh                      # the suite, isolation required
cargo test -p ward-node-client --test acceptance # the same cases, skipping without bubblewrap
scripts/acceptance/node.test.sh                 # the runner's own rendering regressions
```

The runner's table has one row per case with its result and wall time; its exit status
is 0 only when every case passed and at least one ran. A run as an unprivileged user is
part of the slice's verification: build first, then run the test binary from a directory
that user can read, with `WARD_REQUIRE_ISOLATION=1`, `HOME` and `TMPDIR` pointing at a
writable directory.

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
- No network is needed; the network probes expect connects to fail.

### 3.2 Time bounds

Every bound in the suite is generous against the contract's own (node-integration.md §3:
`start` waits up to 30 s for the spawn, `stop` and `revoke` up to 10 s for the reap) and
is asserted in code: a completing run ends within 60 s, a budget kill lands within the
budget plus 30 s, a `revoke` answers within 15 s, a pause is observed for 400 ms, and
wait-on-condition loops give up after 20 s. A whole run of the suite takes well under a
minute on a developer machine; each case prints its own time.

## 4. What it does not prove

- **No remote transport.** The only transport is the local Unix socket; nothing here
  exercises mTLS, key bootstrap or a control plane on another host (#262).
- **No network grants.** Every workload runs offline. The suite proves a manifest asking
  for network is refused and that an offline workload has no route off the host; it does
  not prove an allowlist, because the node enforces none yet (node-integration.md §7.5).
- **No workspace export and no output.** What the workload wrote is read on the host as
  the node's uid, which a remote control plane cannot do; the protocol carries neither.
- **No escape attempt beyond the probes.** The isolation case is a contract check of what
  the sandbox denies to an ordinary workload, not an adversarial escape suite; the
  kernel-level boundary tests of [experiments.md](experiments.md) E-01 and the
  `ward-daemon` namespace, verifier and egress regressions are separate.
- **No load, capacity or concurrency.** One workload at a time; the 1 024-task registry,
  the 128-pause bound and the 8 MiB state files are unit-tested in `ward-node`, not here.
- **No clock skew.** Envelopes are signed at the node's own clock.
- **No TamperWard verdicts.** The suite says what the node did; whether a result is
  certified is the external control plane's decision (ADR-0029).

## 5. Findings recorded by the suite

- The environment a workload is exec'd with carries `PWD=/work` beside `HOME`, `PATH`
  and `TERM`: bubblewrap sets it when it changes into `/work`. The contract's wording in
  node-integration.md §9 names it; the probe's `env.keys` row prints the exact key set
  on every run.
- The sandbox root (`/`) and the mount-point directories bubblewrap creates (`/etc`) are
  writable tmpfs inside the sandbox. They are sandbox-private and nothing written there
  reaches the host, which the `fs.private.*` rows and the host-side assertions show; the
  bound system directories themselves are read-only (`fs.write.*`).
