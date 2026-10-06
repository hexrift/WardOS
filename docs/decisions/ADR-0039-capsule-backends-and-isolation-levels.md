# ADR-0039 — Capsule backends: one execution-backend contract, ordered isolation levels, a manifest floor

Status: **Proposed; first and second slices of [#263](https://github.com/hexrift/WardOS/issues/263).**
The second slice amends it (§1's `container` row, §2.1, §5, §8 and the validation): an OCI
container backend driven by `runc`, the operator's flag for stronger placement and its
advertisement, and a conformance suite holding both backends to the same authority. It
makes [ADR-0022](ADR-0022-capsules.md)'s backend ladder concrete for `ward-node`: the
contract every backend serves, the isolation levels it is ordered by, how an attempt is
placed on one, and what is recorded. It adds one optional manifest field within protocol
1.3; it changes neither the capability document's shape, the lifecycle, nor the event
catalogue.

## Context

ADR-0022 names a ladder of boundaries (sandbox, container, microVM, VM) behind a policy
that picks the lightest one appropriate to the risk, and leaves the API open. `ward-node`
runs every admitted attempt the same way: a bubblewrap sandbox over the attempt's
workspace (`ward-launch`, ADR-0013), behind the launch port of ADR-0030 §3
(`TaskLauncher`, `RunningWorkload`, `WorkloadFreezer`). Its capability document has
carried an `isolation.backends` section (`container`, `microvm`, `vm`) since protocol 1.1,
always `false`, with nothing that defines what each would guarantee, and a control plane
has no way to say that a task needs more than the sandbox. A task that runs unknown code
must be able to require a stronger boundary and be sure it never gets a weaker one.

## Decision

### 1. Four isolation levels, ordered by what they guarantee

| Level | Kernel boundary | Guarantees | Does not guarantee |
| --- | --- | --- | --- |
| `sandbox` | The host kernel, shared. | Its own user, PID, IPC, UTS, network (loopback only) and, where the kernel allows, cgroup namespaces; the attempt's workspace is the only writable host path, system directories are bound read-only and the host home, the node's state and every other attempt are not mounted; a minimal `/dev`; the process tree dies with the node (`--die-with-parent`). | Any defence against a host-kernel vulnerability reachable through the system calls it may make. A seccomp filter, Landlock and `no_new_privs` (only when the attempt runs under the operator's `ward-agent` shim, ADR-0037). Its own root filesystem. Resource limits (only with `--cgroup-root`). |
| `container` | The host kernel, shared. | Everything `sandbox` does, and always: a seccomp filter, no capabilities in any set, `no_new_privs`, a read-only root filesystem of its own (an empty directory into which the sandbox's read-only system directories are bound), and masked and read-only `/proc` paths. | Any defence against a host-kernel vulnerability reachable through the system calls the filter allows. A root filesystem from an image the node verified (the host's system directories are bound, as for `sandbox`). A cgroup of its own, so a freezer and resource limits, when the node runs rootless. |
| `microvm` | A guest kernel of its own behind hardware virtualisation (KVM). | Everything `container` guarantees about what the workload can reach, inside a guest whose kernel is not the host's; the host is reachable only through KVM and the virtual machine monitor's minimal set of virtio devices. | Any defence against a vulnerability in KVM or the monitor, or against microarchitectural side channels the host does not mitigate. |
| `vm` | A guest kernel of its own behind hardware virtualisation, on a full emulated machine. | Everything `microvm` does, and a whole machine the workload may administer (its own firmware and kernel, root in the guest, kernel modules) without that weakening the boundary. | The same as `microvm`, over a larger device model. |

The order (`sandbox` < `container` < `microvm` < `vm`) is an order of guarantees: each
level guarantees everything the levels below it do. It is not a ranking of attack surface
(a full VM's device model is larger than a microVM's); this ADR claims only that a `vm`
satisfies anything a `microvm` was required for. The wire spellings are exactly the names
in the table, the same names the capability document has always used.

### 2. One backend contract, expressed in the node's existing ports

A `CapsuleBackend` (`ward-node`, `crate::capsule`) is one mechanism at one level. It
describes itself (`CapsuleBackendDescriptor`: its backend id, its level and the operations
it serves) and serves the contract's operations through the ports the node already owns:

| Operation | Served by | `bubblewrap` |
| --- | --- | --- |
| `prepare` | The registry, before the backend is asked for anything: the workspace materialised from the snapshot under the task root, the egress, credential, action and adapter parts built from the manifest into one `LaunchRequest`. | served |
| `start` | `TaskLauncher::launch`, on the attempt's reaper thread. | served |
| `exec` | A second command in a running capsule. No verb asks for it. | **not served** |
| `pause`, `resume` | `WorkloadFreezer::freeze` and `thaw`, confirmed or refused. | served |
| `stop` | `RunningWorkload::wait` once its `StopSignal` is requested, or at the budget: kill and reap. | served |
| `snapshot` | Capturing a running capsule's state. No verb asks for it. | **not served** |
| `destroy` | Dropping the `RunningWorkload` (kills and reaps) and, after a restart, `TaskLauncher::end_survivor`; the registry then removes what it prepared. | served |
| `inspect` | `RunningWorkload::pid` and `process`: the host process the capsule runs as. | served |

A backend that does not serve an operation says so in its descriptor; the registry never
asks it to. The first backend is the existing bubblewrap launch, unchanged: `bubblewrap`
at level `sandbox`, whether or not the node runs attempts in cgroups. It is an adapter
over the existing launchers, not a rewrite: the launch, freeze, kill and survivor paths
are byte for byte the ones ADR-0030 §3 validated.

Every backend binds the attempt's authority explicitly, from the `LaunchRequest`, never
from its own defaults. For `bubblewrap`: storage is the workspace at `/work` and system
directories read-only; network is a loopback-only namespace and, only for a granted
allowlist, the attempt's proxy socket; devices are bubblewrap's minimal `/dev`;
credentials never enter the sandbox (the proxy injects them, ADR-0034); the verifier is
not reachable. Every later backend states the same five bindings for itself (§2.1), and
the conformance suite holds every backend to the same observable result.

### 2.1 The `runc` backend at `container`

An operator who starts the node with `--container-runtime <file>` names the host's `runc`
(ADR-0002 chose an OCI runtime; `runc` is the one Debian, Ubuntu and GitHub's runners
install). The node verifies it at start as it verifies `--agent-shim`: an absolute path to
a regular file, owned by root or the node's user, writable by no one else, executable,
whose `--version` begins `runc version`, with `/usr/bin/setpriv` (util-linux) present; it
then runs one container built exactly as an attempt's would be over a scratch directory of
the task root, and any refusal stops the node. A node without the flag has no `container`
backend and refuses that floor.

**One launch, two mechanisms.** The backend turns the attempt's `LaunchRequest` into the
very `ward_launch::Launch` the bubblewrap backend would run, and that launch's
`SandboxPlan` (`ward-launch`: the environment, the mounts, the working directory, the
hostname and the command line that `Launch::args` hands bubblewrap, tested to agree with
it) into an OCI bundle at `<task-root>/<task>/<attempt>.capsule/` (mode 0700): an empty
`rootfs/` mounted read-only and a `config.json`. Nothing about the attempt is decided by
the container backend itself, so the bindings are bubblewrap's by construction:

| Binding | `runc` |
| --- | --- |
| Storage | The workspace bound writable at `/work`; `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/opt` and the trust roots bound read-only; private writable `/tmp`, `/home`, `/run`, `/home/agent` and `/env`; the root filesystem read-only. The host home, the node's state, the evidence logs and every other attempt are not mounted. |
| Network | A network namespace of its own with only loopback; for a manifest naming an allowlist, the attempt's egress proxy socket bound at `/run/ward/proxy.sock` and named by `WARD_PROXY_SOCKET`, and under the shim its relay on `127.0.0.1:3128`. |
| Devices | `runc`'s minimal `/dev` (`null`, `zero`, `full`, `random`, `urandom`, `tty`, a private `devpts` and `shm`); no `/sys`. |
| Credentials | Never inside: the attempt's proxy injects them (ADR-0034), exactly as for bubblewrap. |
| Verifier | Not reachable. |

The hook and action sockets, an adapter's settings files and the operator's shim are bound
as bubblewrap binds them, and the environment is bubblewrap's (bubblewrap's own `PWD`
included). On top the container always has no capability in any set, `no_new_privs`, the
baseline seccomp profile of `ward_sandbox::seccomp` (default-allow, the mount, `ptrace`,
`bpf`, keyring, module, `userfaultfd` and `io_uring` families refused, `kexec` and
`reboot` killed), masked and read-only `/proc` paths and the user, mount, PID, IPC, UTS,
network and cgroup namespaces.

**Rootless.** The container's user namespace maps exactly one id, the node's own user, to
root inside. A node run as root therefore runs the container as the host's root without a
capability; a node run as another user runs `runc` rootless, which needs the same
unprivileged user namespaces bubblewrap does. The workload sees itself as uid 0 where
bubblewrap shows it the node's uid; either way what it writes to the workspace is the
node user's.

**Operations.** `start` spawns `setpriv --pdeathsig KILL -- runc run` on the attempt's
reaper thread and the container's first process is `setpriv --pdeathsig KILL` from the
bound `/usr`, so the container dies with `runc` and `runc` with the node, as bubblewrap's
`--die-with-parent` does (with the same few-instruction window before the first process
arms it). The stdio, the output capture and the reaper are the bubblewrap launch's
(`Launch::spawn_runtime`). `stop` and the budget kill `runc` and every process of the
container (`runc kill --all … KILL` as root, which freezes, signals and thaws the cgroup so
a paused container dies without running again; `runc kill … KILL` rootless, which ends the
PID namespace); the reaper then deletes the container (`runc delete --force`) and removes
its bundle, whatever ended it. As root `runc` gives the container cgroups of its own and
`pause`/`resume` are `runc pause`/`runc resume`, confirmed by `runc state`, with the egress
proxy paused for as long as the container is: descriptor `runc` serving everything but
`exec` and `snapshot`. Rootless there is no cgroup and no freezer, so the descriptor
declares `pause` and `resume` unserved and the registry refuses them `unsupported_operation`
for its attempts without asking. A node that restarts ends a survivor by its recorded host
process, as for bubblewrap, and deletes a container and bundle its predecessor left beside
the workspace. The backend records `"capsule":{"backend":"runc","isolation":"container"}`.

**What it does not guarantee next to bubblewrap with the shim.** The shim adds Landlock
(read-only on the system directories, writable only on the workspace and the private
trees) inside the sandbox; the container has no Landlock of its own, though under
`--agent-shim` the shim runs inside it as it does in bubblewrap. Both filters are
deny-lists over default-allow, so neither is a kernel boundary. The container's root
filesystem is not an image the node verified. Rootless, the container has no cgroup, so
no freezer and no limits; with or without root, a manifest's `resources` limits are not
enforced in it, so such a manifest is never placed on it (`admit` refuses it
`unsupported_grant` there, and `start` checks again).

Promotion stays the node's existing rule: nothing is copied back from a capsule; only a
manifest's declared, bounded output is collected after the workload is reaped
(ADR-0030 step 13), whichever backend ran it.

### 3. Capability discovery is the existing `isolation` section, given a meaning

A 1.3 document's `isolation.namespaces.sandbox` is `true` exactly when the node offers a
`sandbox` backend, and `isolation.backends.container`, `.microvm` and `.vm` exactly when it
offers one at that level. Nothing is added to the document: a node with only the
bubblewrap backend emits byte for byte what it did, and a strict decoder of every earlier
1.3 revision keeps reading it. Which mechanism serves a level (bubblewrap, an OCI runtime,
a monitor) is the node's, not the document's.

### 4. The manifest may name a minimum; absent is `sandbox`

The capability manifest gains an optional field, additive within 1.3:

```json
{"network":"offline","isolation":{"minimum":"microvm"}}
```

`minimum` is one of `container`, `microvm`, `vm`, and is the only field. Absent, the
minimum is `sandbox`, today's behaviour, and `{"minimum":"sandbox"}` fails decoding, so a
floor has one spelling and every existing manifest and its hash are unchanged. An unknown
level, a `null`, an array, an unknown or repeated field fail decoding
(`authority_denied`). A node of an earlier revision fails to decode a manifest that
carries the field, so it can never run such an attempt with less.

### 5. Placement: never weaker, stronger only by the operator's policy

An attempt runs only on a backend whose level is at least its manifest's minimum. The node
places it on a backend at exactly that level; it places it on a stronger backend (the
weakest one above the minimum) only when its operator's policy says so explicitly, and
never on a weaker one. A node with no backend the rule allows refuses the manifest
`unsupported_grant` at `admit`, after authority is proven and before the version is
consumed, with nothing materialised (node-integration.md §8.1 step 16); `start` applies
the same rule again before it prepares anything. Fallback is therefore explicit:
a control plane that wants a weaker boundary must sign a manifest with a lower floor,
and a node that would run stronger says so by its operator's flag, never by itself.

The flag is `--place-stronger` (it needs `--container-runtime`): the node then places an
attempt on the weakest backend whose level is above the floor, when it has one, and at the
floor otherwise, so with bubblewrap and `runc` an unmarked manifest runs in a container.
Without it every attempt runs at exactly its floor and an unmarked manifest stays on
bubblewrap. The document advertises the policy additively: `isolation.stronger_placement`
`true`, present only on such a node (a node without the flag emits the document it did;
a strict decoder of an earlier revision refuses one carrying it, as it does `output`). A
manifest with `resources` limits is placed only on a backend that enforces them.

### 6. The backend that ran an attempt is recorded

The `start` that places an attempt writes the backend and its level into the attempt's
durable task record, in the launch intent before the spawn:
`"capsule":{"backend":"bubblewrap","isolation":"sandbox"}`. A record that names no
capsule (an attempt never started, or a record written before this revision) reads as
before. The per-attempt evidence log is unchanged: every existing record kind is already
backend-neutral (`NodeAttemptLaunched` names the host process the backend runs the capsule
as), and the catalogue gains no kind in this slice; a hash-chained placement record is a
follow-up (§8).

### 7. Where the contract lives

The level and the manifest floor are protocol (`ward-node-protocol`, `IsolationLevel`,
`IsolationGrant`); the backend contract, placement and the bubblewrap backend are
`ward-node`'s (`crate::capsule`). The per-session daemon keeps its own sandbox until
execution ownership migrates to the node (ADR-0029); it then runs on the same contract.

### 8. What the next slices add

* Done in the second slice: the `runc` backend at `container` (§2.1), `--place-stronger`
  and `isolation.stronger_placement` (§5), and the conformance suite (below).
* A root filesystem for `container` from an image the node verified, `resources` limits
  in the container's cgroup, and a freezer for rootless containers (a delegated cgroup).
* A microVM backend (KVM, ADR-0022) and the `exec` and `snapshot` operations.
* A hash-chained placement record in the attempt's evidence log, appended at the end of
  the catalogue, and `ward-node audit` reporting it.

## Alternatives

* **A new capability-document section listing backends by name.** A strict decoder of
  an earlier 1.3 revision refuses a document carrying it, on every executing node, for
  no information the existing `isolation` flags do not already carry; and naming the
  mechanism invites control planes to depend on it. Rejected for this slice.
* **Any level may run on any node, recorded after the fact.** A task that requires a
  microVM would silently run in a sandbox. That is the failure the issue forbids.
* **Always place on the strongest backend a node has.** Silent and slow: the operator,
  not the node, decides whether stronger isolation's cost and its different devices are
  acceptable for weaker-required work.
* **The floor outside the manifest, beside the adapter.** The floor is authority, not
  what runs: the manifest is what the issuer signs as authority and what a node refuses
  as a whole, so it belongs there.
* **`crun` rather than `runc`.** ADR-0002 prefers `crun` on the production host; `runc`
  is what Debian, Ubuntu and GitHub's runners install, and the bundle is plain OCI, so a
  `crun` backend is the same bundle behind another verified binary.
* **A container built from its own defaults** (a runtime's spec template, an image's
  environment). It would decide bindings the manifest never granted; building the bundle
  from the bubblewrap launch's plan makes the authority equal by construction and the
  conformance suite proves it.
* **The signal freezer for rootless containers.** It would serve `pause`, but not with
  the freezer the container level is about; the descriptor says the operation is unserved
  and the node refuses it instead.
* **Rewrite the launch path around the trait first.** The launch, freeze and survivor
  code carries ADR-0030's guarantees and its tests; wrapping it is the smaller, safe
  change.

## Advantages

* A control plane can require a boundary and be certain it is never given a weaker one.
* Nothing changes for an attempt whose manifest names no floor, on the wire or on the
  node.
* Each backend has one contract to meet and one table of what it does not guarantee.

## Disadvantages

* A node honours `container` only with `--container-runtime`; `microvm` and `vm` are
  refused everywhere until their backends land.
* A rootless container cannot be paused, and no container enforces `resources` limits.
* The record of which backend ran an attempt is in the task record, not yet in the
  hash-chained evidence log.

## Security consequences

* The decision fails closed: a floor the node cannot meet is refused before anything is
  materialised, and an older node fails to decode it.
* The level guarantees are stated with what they do not cover, so a `sandbox` is never
  read as a kernel boundary it is not.
* No backend can widen an attempt: every binding comes from the admitted manifest through
  the `LaunchRequest`, and the container's bundle is built from the same launch plan as
  the sandbox.
* The operator's `runc` is trusted like the shim: verified at start, never named by an
  envelope, never looked up on a path an attempt controls.

## Performance consequences

Placement is a comparison over the node's backends at `admit` and `start`; the record
gains a few bytes. A container attempt adds the bundle write, `runc`'s own setup and a
few `runc` invocations at its end (tens of milliseconds); a bubblewrap attempt is
unchanged.

## Compatibility

Additive within 1.3, like the `output`, `resources`, `actions`, `credentials` and `hold`
grants: a manifest without `isolation` and the capability document of a sandbox-only node
are byte for byte what they were. A node of an earlier revision refuses a manifest that
carries `isolation` (`authority_denied`), so it fails closed.

## How it is validated

* Protocol unit tests: the level order and spelling, the floor's grammar and every
  refusal, the manifest round trip, and the capability document unchanged for a
  sandbox-only node.
* Node unit tests: placement never weaker and stronger only when allowed, the bubblewrap
  backend's descriptor, `admit` refusing a floor above the node with no version consumed,
  and the record naming the backend.
* A real node (`crates/ward-node/tests/node_isolation_floor_cli.rs`): a manifest requiring
  `container`, `microvm` or `vm` is refused `unsupported_grant` with nothing under the task
  root, and an unmarked manifest runs as before, its record naming `bubblewrap` at
  `sandbox`.
* Conformance against a real node with both backends
  (`crates/ward-node/tests/node_capsule_conformance_cli.rs`): one manifest run without a
  floor on bubblewrap and with `container` on `runc` gives the same probe results (the
  workspace the only writable host path, `/usr` and the trust roots read-only, a host
  secret and the node's state unreadable, no direct network, no name resolution, the
  proxy's refusals of an unlisted and an unresolvable host and of loopback, the brokered
  credential reaching the upstream through the proxy only), the same environment, the
  same returned output and the same evidence records but for ids, digests and pids, under
  the shim too; a budget kill and a stop are recorded alike and leave nothing running; the
  container has no capability, `no_new_privs` and a seccomp filter; a node killed outright
  takes its container with it and its successor deletes what is left; `pause` works as
  root and is refused rootless; a `container` floor is refused without a runtime; an
  unmarked manifest runs on `runc` only under `--place-stronger`; a runtime that is not a
  trustworthy `runc` stops the node. The container cases need `runc` able to run a
  container as the test's user; they skip, named, without it, and fail instead under
  `WARD_REQUIRE_CONTAINER=1`, which CI does not set yet (its required job sets
  `WARD_REQUIRE_ISOLATION=1` only).
* Unit tests: the plan agreeing with bubblewrap's arguments (`ward-launch`), the bundle's
  configuration, the runtime's refusals, placement under both policies, the registry
  launching on the placed backend and refusing `pause` where it is unserved, and
  `resources` never placed on a backend that does not enforce them.
* The Node.js reference client refuses a floor before signing unless the node's document
  offers that level, or one above it with `isolation.stronger_placement`.
