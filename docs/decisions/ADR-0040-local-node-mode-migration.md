# ADR-0040 — Local node mode: a reversible migration of one installation into a `ward-node` of its own

Status: **Proposed; first slice of [#278](https://github.com/hexrift/WardOS/issues/278),
toward stage 4 of [migration-to-node.md](../migration-to-node.md) §3.5.**

## Context

#278 asks that an existing local installation can upgrade into local `ward-node` mode
without losing project policy, pinned snapshots or evidence, that a failure during the
migration leaves a recoverable prior state, and that fleet features can then be enabled
incrementally. Until this slice the two modes kept separate state and neither read the
other's (migration-to-node.md §2.1): no importer existed, and the `ward` CLI never signed
or sent anything to a node, although ADR-0030 §2 already decided that in local mode the
CLI signs as a *local issuer* whose key is readable only by the node's operator account
and is held to exactly the checks any issuer is.

Stage 4 in full is larger than one change: `ward up`, `pause`, `resume` and `stop` on a
node, the desktop reading attempt evidence, one node owning several sessions and
recovering them (#258), the scheduler several sessions need (#260), the session log and
the attempt log reconciled into one shape, and `wardd` retired. None of that is needed to
meet the acceptance, and each of it is unsafe to start before a migration exists that
moves an installation's state into a node's reach without losing or rewriting it. What
the acceptance does need, beyond the migration itself, is a working way to run through the
node once migrated; otherwise "local node mode" names a state nothing uses.

## Decision

### 1. Local node mode is a node home beside the session tree

A migrated installation has one more directory under its session state root
(`$WARD_STATE_DIR`, else `~/.local/state/ward`): `node/`, mode 0700, which the local node
owns and no session command writes.

| Path under `<state>/node/` | What it is |
| --- | --- |
| `migration.json` | The migration record, and the mode marker: while it exists the installation is in local node mode |
| `issuer.seed` | The local issuer's Ed25519 seed, 32 bytes, mode 0600 |
| `trusted-issuers` | The node's trust store (`--trusted-issuers`), mode 0600: the local issuer bound to a fresh local principal |
| `state/` | The node's `--state-dir` (mode 0700), with the imported snapshots in `state/cas` |
| `tasks/` | The node's `--task-root` (mode 0700): each attempt's workspace and evidence log |
| `node.sock` | The node's socket, while `ward node serve` runs it |

The node home is inside the state root so that one rename can create it or remove it, which
is what makes the migration a transaction (§2). It is the node's own directory: the node is
never pointed at the session tree, reads nothing outside its home, and nothing in the
session tree moves into it. The account that owns it is the node's operator account
(ADR-0030 §2); on a single-user installation, which is what local mode is, that is the
login user who ran `ward node migrate` (§6 states what this does and does not protect).

### 2. `ward node migrate` is one transaction over a read-only plan

**The plan reads and writes nothing.** For every session directory with a log it verifies
the log exactly as `ward replay --verify` does and refuses the migration, naming the
session, if a log is not sealed (`ward stop --session <id>` seals it) or does not verify:
a migration carries only sealed evidence that verifies, never a log something may still
append to. It lists the snapshots the per-session runtime retains, exactly the root set
`ward snapshot gc` keeps (`ward_daemon::retention::roots`: active entries and candidates,
in-flight verification candidates, `StateAccepted` evidence and `ward snapshot keep`
marks), and the policy layers sessions read: each recorded project's `.ward/policy.yaml`
and the host's system layer, `credentials.toml` (the user layer is empty today). It refuses
an installation that is already in local node mode. `--dry-run` prints the plan and stops.

**What the migration does with each.**

- (a) **The local issuer.** A fresh 32-byte seed from the OS entropy source, written with
  `create_new` and mode 0600, read back through `IssuerKey::from_seed_file`, the same check
  every signer applies; a trust-store line binds its public key to a fresh principal
  (`prn_…`), one key for one principal (node-integration.md §2.2).
- (b) **Snapshots** are copied from the session CAS into the node's store, each blob and
  the manifest read through the CAS's integrity checks and written under the same digest,
  the manifest last, and the copy then verified whole. A snapshot that fails fails the
  migration: nothing is imported partially.
- (c) **Policy** is referenced, never rewritten: each file's path and BLAKE3 (or its
  absence) go in the record. The project's policy keeps living in the project.
- (d) **Evidence** stays where it is, byte for byte. The record lists each log's path
  relative to the state root, its length, the BLAKE3 of its bytes, the chain head its
  sealed `HEAD` names and its record count, so `ward replay --verify` keeps verifying it
  where it always was and `ward node status` can show it unchanged.
- (e) **The mode marker** is the record itself, with the node's identity (`--node-id`,
  fresh unless given), the local principal and key id, the source state root and the
  time.

**The transaction.** Everything is built in a staging directory beside the session tree,
`<state>/node.staging`, and flushed; then one `renameat2(RENAME_NOREPLACE)` makes it
`<state>/node` (on a filesystem without that flag, a plain rename once the target is
seen absent). Before the rename the installation is in per-session mode with its session
tree unchanged; after it, in local node mode. Any failure before the rename removes the
staging directory, so the prior state is byte-identical; a crash leaves the staging
directory, inert (nothing reads it as a node home or as a marker), and the next run
removes it first. A rename that finds a node home already there fails as "already
migrated".

**Rollback.** `ward node migrate --rollback` refuses while the node's socket answers, then
renames the node home aside (`<state>/node.rolled-back-<ms>`) in one step, which is the
return to per-session mode. If no attempt ever ran under it the aside directory is
removed, and the state is exactly what it was before the migration; if attempts ran, it is
kept, because their evidence logs are evidence and a rollback never deletes evidence.

**Checks.** `ward node status` prints the mode, the node, the local principal and whether
the socket answers, and re-checks the record: each carried log unchanged and still
verifying, each imported snapshot whole in the node's store, each policy file unchanged or
changed (policy stays the user's to edit, so a change is reported, not failed). It exits
non-zero when evidence or a snapshot does not check. `ward doctor` gains a `node mode` row:
`per-session`, `local-node` with the node and its home, or a failure for a record it cannot
read (never "per-session" for a damaged marker).

### 3. The CLI path: `ward run --via-node`, one attempt, never in-process

A node attempt runs one argv over a snapshot to its end; a session is a project worktree
opened by `ward up` that many launches, pauses, resumes and the desktop share until `ward
stop`. `ward run` is the command whose semantics an attempt already has, so it is the
command that gains the node path in this slice; `ward up` on a node is #258's
"preserve current local CLI behaviour through the node boundary", which needs one node
owning a long-lived session, and stays per-session (§7).

`ward run --via-node [--snapshot <hex>] [--budget <secs>] -- <argv>` in local node mode:

1. merges the project's effective policy exactly as a session would
   (`ward_daemon::session::effective_manifest`) and compiles it (§4), refusing by name
   before anything else happens;
2. connects to the node's socket and reads its capabilities;
3. captures the project into the node's store (or takes a snapshot already there, for
   instance a migrated one, checked whole);
4. builds the envelope: a fresh task, attempt and lease, a fresh agent as the lease's
   subject, a root lease issued by the local principal with one grant (`project.run` on the
   project's id), valid for the budget plus two minutes, version 1; the compiled network
   grant, and the head of stdout and stderr (256 KiB each) as an `output` grant when the
   node returns output;
5. signs it with the local issuer and runs it with `ward-node-client`'s fail-closed driver,
   `create` to `seal`, printing the returned output, the receipt and the sealed evidence
   log's path and head.

The exit status is success only for a `completed` receipt. The worktree is never written;
the attempt's workspace and evidence stay under the task root. There is no fallback,
following ADR-0029's compatibility policy: outside local node mode the command refuses and
names `ward node migrate`; with no node serving it refuses and names `ward node serve`; a
refusal from the node, or an `unknown` outcome, is reported as such, and nothing runs
in-process instead. `ward run` without `--via-node`, `ward up` and every other command keep
their per-session behaviour in either mode.

`ward node serve` replaces itself with `ward-node` (found beside `ward` or on `PATH`) on the
home's paths: `--socket`, `--state-dir`, `--node-id`, `--trusted-issuers`, `--task-root`,
`--network-allowlist` and `--output-return`. The last two are on because the node honours
them only for an envelope that asks, and the CLI asks only for what the compiled policy
grants; any further flags after `--` are passed to `ward-node` (§5).

### 4. Policy compiles exactly, or is refused by name

The node path runs a policy only when the node enforces it as a session would. Every
capability the session enforces is carried into the manifest or named as a refusal;
nothing is dropped, narrowed or approximated.

| Policy | Compiles to | Refused |
| --- | --- | --- |
| `network: offline` | `"offline"` | |
| `network: !custom [hosts]` | `{"custom": hosts}` (on a node advertising `network.proxy_allowlist`) | a host outside the envelope's lowercase pattern grammar |
| `network: registries`, `development` | `{"custom": …}` with exactly the hosts the session proxy matches the preset with (`ward_policy::hosts`) | |
| `network: localhost_only`, `unrestricted` | | the node's proxy has no rule for either |
| `filesystem.worktree`, `environment`, `home`, `tmp`: `rw` | the node's private writable `/work` (a copy of the project), `/env`, home and `/tmp` | `ro` or `none`: the node gives every attempt each of them writable |
| `filesystem.extra` | | any entry: the node mounts nothing else |
| `credentials.<service>: deny` | nothing brokered | `ask` or `allow`: the node brokers only services its operator configured (ADR-0034) |
| `observer: quiet`, `live` | the node's own evidence | `step_through`: the node holds no write or request for an approval |

`containers`, `devices` and `resources` are not compiled: the per-session runtime does not
enforce them from the policy either, so running without them weakens nothing. The default
policy is refused for its `ask` credentials alone; a project that denies them runs.

### 5. Fleet features are the same node's flags, enabled without migrating again

The node home is a node like any other, so every remote and fleet feature is a `ward-node`
flag on it, passed through `ward node serve -- …`, and a capability the control plane
discovers before it relies on it (node-integration.md §5):

- a control plane on another host reaches it over mutual TLS: `--listen-tls`,
  `--tls-cert`, `--tls-key`, `--tls-client-ca` (ADR-0038, node-integration-guide.md §3.1);
- the control plane's issuer is one more line in `<state>/node/trusted-issuers`, bound to
  its own principal; the local issuer keeps working beside it;
- brokered credentials, the action channel and approval holds, hosted agent adapters,
  cgroup limits, a bound on concurrent attempts and container placement are
  `--credentials`, `--action-channel`, `--approval-hold`, `--agent-adapter`,
  `--cgroup-root`, `--max-running` and `--container-runtime` (ADR-0034 to ADR-0039).

Each is added, and removed, by restarting the node with or without its flag; the record,
the key and the stores do not change, and a node without a flag refuses a manifest that
needs it (`unsupported_grant`) rather than running with less. Local mode needs none of
them and no remote service.

## Alternatives

- **Moving the session tree into the node, or converting session logs into attempt logs.**
  Rejected. It rewrites or relocates evidence; a session log and an attempt log have
  different origin sets and are verified against their own genesis (migration-to-node.md
  §4.1), and copying would leave two copies with one reader. Recording the logs in place
  keeps every `ward replay` verdict exactly what it was.
- **A node home outside the state root (`/var/lib/ward-node`, another user).** Not one
  rename, so not a transaction, and it needs root. A node under a system user of its own is
  stage 1's deployment (node-integration-guide.md §1); moving a session tree to another uid
  is part of what remains (§7).
- **A mode marker in the session tree beside the node home.** Two renames, and a window
  in which the marker and the home disagree. The record is the marker.
- **`ward up --via-node`.** Deferred, not rejected: `ward up` is a long-lived, many-launch
  session the desktop reads, which a node cannot yet own (§7). A flag that started one
  attempt and called it a session would change the command's semantics.
- **Falling back to the per-session path when the node is absent, or narrowing a policy the
  node cannot express.** Rejected by ADR-0029: no silent fallback from a node-mediated path
  to an in-process one, and the node refuses a grant it cannot enforce rather than run with
  less (node-integration.md §7.5).
- **Importing snapshots through the node's protocol.** No verb exists, and adding one is a
  protocol change; the node's store is a `ward-snapshot` CAS that `ward-node snapshot
  import` already writes offline, so the migration writes it the same way.

## Advantages

- The acceptance is met on the real binaries: nothing of the session tree is rewritten, a
  failed migration leaves it byte-identical, a rollback restores it.
- The local issuer is held to ADR-0030 §2's checks unchanged; the node admits a local run
  exactly as it admits a control plane's.
- One policy merge serves both runtimes, and every capability the node cannot enforce is
  named.

## Disadvantages

- In local node mode only `ward run --via-node` uses the node; the interactive session
  commands stay per-session until #258.
- A run's writes stay in its workspace under the task root; the worktree does not see them.
- The default project policy is refused on the node path until the project denies its
  asked credentials.

## Security consequences

- **The local issuer key** is created 0600 with `create_new`, read back through the
  signer's own mode check, never printed, and bound to one fresh principal. A rollback that
  removes the home removes it; one that keeps the home for its evidence keeps it there, 0600
  and trusted by nothing that serves.
- **The operator account.** In local node mode the node, its state and the key belong to
  the login user who migrated, as the session tree already does: the node's state is as
  reachable from that user's own processes as session logs are today, no more. The
  workload is narrower than in a session: a sandbox over a copy, no worktree write, and the
  node as the single writer of its evidence. A node under a system user of its own, the
  separation migration-to-node.md §4.4 asks for when sessions and a node coexist, is not
  what this migration sets up (§7).
- **Authority.** Every run passes the node's admission checks; the lease is a root lease of
  the local principal bound to one fresh task, attempt and agent, expiring with the budget.
- **Evidence** is never moved, rewritten or partially imported; the record lets `ward node
  status` detect a later change to a carried log (detection, not prevention: the logs stay
  the user's files, as before).
- **Snapshots** are verified by digest on the way out of the session CAS and once in the
  node's store; a corrupt source fails the whole migration.
- **No fallback.** Nothing in the node path runs in-process, and nothing outside it changes.

## Performance consequences

The migration reads every session log once and copies every retained snapshot once; it is
an explicit, one-off command. A `ward run --via-node` captures the project into the node's
store (incremental by content) and polls the node every 250 ms to 2 s.

## Compatibility

No protocol, envelope, manifest or event-catalogue change: the node is unchanged and the
CLI is one more issuer. Per-session mode and every existing command behave as before, and a
migration never rewrites existing state. The record is versioned (`format: 1`); a record of
another format is refused, never read as per-session mode. `ward-snapshot`, one of the
node's inputs, gains `open_existing`, `copy_from` and `verify`, so the next release raises
the node version (CONTRIBUTING.md, #275).

## How it is validated

`ward-snapshot` unit tests (a copy keeps id, content and metadata; a corrupt blob fails
the copy and never lands; opening an existing store creates nothing; a damaged snapshot
does not verify). `ward-cli` unit tests of the plan (names every sealed log, retained
snapshot and policy layer and writes nothing; refuses an unsealed or unverifying log), of
the transaction (a failure injected after each step leaves the state byte-identical and a
re-run succeeds; a corrupt snapshot fails it; a leftover staging directory is removed; a
second migration is refused), of rollback (exact without attempts, kept with them, refused
while serving), of the status check, of the policy compilation (every row of §4) and of
the run's refusals and envelope. `crates/ward-cli/tests/node_migration.rs` drives the real
`ward` and `ward-node`: a populated installation migrates with its session tree
byte-identical, its logs verifying and its pinned snapshot's manifest equal in the node's
store; through `ward node serve` a run over a fresh snapshot and one over the migrated
snapshot complete and seal and verify with `ward replay`, a failing command fails, a policy
the node cannot enforce is refused by name and a rollback is refused while the node serves;
a migration that fails at a corrupt snapshot leaves the state byte-identical, a re-run
succeeds, and a rollback restores the prior state exactly.

## What remains for #278 and stage 4

- `ward up`, `ward pause`, `ward resume`, `ward stop`, `ward verify` and `ward watch` on the
  node, with one node owning a session's many launches and recovering it (#258), and the
  scheduler several sessions need (#260).
- The desktop's worker reading the node's stream and attempt evidence.
- The session log and the attempt log reconciled into one shape, `wardd` and the
  in-process writer retired behind a documented release boundary.
- A node under a system user of its own as the local default, with the key created at
  install by `install.sh` and the image, and the session tree's ownership moved with it.
- Tests that read a log sealed by a previous release and migrate an installation a previous
  release wrote (no issue yet).
