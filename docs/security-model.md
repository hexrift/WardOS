# WardOS Security Model

Status: living document; the project's phase is in docs/status.toml and the README.
Human-review-only file (see
[`development-under-tamperward.md`](development-under-tamperward.md)).

This document states what WardOS guarantees, what it does not, and the capability model
that produces those guarantees. Every guarantee references the threat-model rows and tests
that back it. If a guarantee here has no test, it is a **goal**, labelled as such.

---

## 1. Guarantees (WardOS on WardOS hardware image)

| G | Guarantee | Threat-model rows | Tests | Status |
| --- | --- | --- | --- | --- |
| G1 | An agent session cannot read or write host paths outside its worktree, project environment, sandbox home and tmp | 1, 2, 3 | ST-001..003, 015 | Proven by `ward selftest` (ST-001..004, 013..015 DENIED on a real sandbox) |
| G2 | An agent session never receives a long-lived credential; every credential it can use is scoped, short-lived, session-bound and logged | 11, 25 | ST-012, 024 | Model-API key: proven by `ward selftest` (canary key on the host never appears in Zone 3; the injected key cannot leave its route). Other services: Phase 3 |
| G3 | An agent session can reach only the network destinations in its effective manifest, and never private/link-local/metadata ranges | 10, 21 | ST-011, 022, 026, 028 | Proven by `ward selftest` and the proxy tests: ST-011 (private, link-local and metadata ranges 403 in every mode), ST-022 (a tunnel is opaque and pinned to its `CONNECT` target; the agent's TLS ends at the destination even with a sandbox-writable CA), ST-026 (raw TCP, IPv6, SOCKS5 and UDP have no path out), ST-028 (an allowlisted name that resolves to a private address gets the private literal's 403; a tunnel keeps the address it was pinned to). Rows and proofs in §6.1 |
| G4 | An agent session cannot observe, signal, trace, or share writable filesystem state with `wardd`, TamperWard, or any verifier | 5, 6 | ST-005, 006, 027 | Proven by `ward selftest` for the namespace form: ST-005 (the supervisor cannot be signalled), ST-006 (the launch's host run directory, where verifier trees live, is invisible), ST-027 (the host's loopback, abstract sockets and run-directory sockets are in another namespace; a control-protocol request on the hook socket gets nothing); the distinct verifier uid is ahead |
| G5 | Entry, candidate and accepted snapshots are immutable and unreachable from the sandbox; their IDs are content-derived | 8, 16 | ST-008, 018 | ST-008 proven by `ward selftest` (the CAS is unreachable) and by content addressing (`ward snapshot diff`); ST-018 (freeze before capture) proven by the integration test `candidate_capture_is_atomic_while_the_agent_writes` (`crates/ward-daemon/tests/st018_freeze_before_capture.rs`), reproduced by CI: the daemon freezes the session's sandbox for the length of a candidate/final capture (`pause::CaptureFreeze`, built on the ADR-0019 pause primitive) so no agent write interleaves with the walk, and the test shows an agent that changes a file's size on every write tears an unfrozen capture but never a frozen one (each frozen snapshot's blobs hash to their content ids and its `materialize` re-digests to its id) |
| G6 | Evidence is append-only, hash-chained, unreachable from the sandbox, and agent-originated records are distinguishable from enforcement records | 9, 14 | ST-009, 010, 016, 027 | Proven: ST-009/010 and ST-017 by `ward selftest` (log, state root and control socket unreachable), ST-027 `hook-socket-forgery` (a control-protocol `approve` on the hook socket is answered with nothing and recorded as nothing), ST-016 end to end (hook-socket input stays `Origin::Agent`), plus `ward replay --verify` on the chain |
| G7 | The effective capability manifest is fixed for the life of a session and repository policy can only narrow it | 7, 18 | ST-007 | Proven: ST-007 end to end (a policy rewritten mid-session does not widen the network) and the merge property tests in `ward-policy` |
| G8 | The host container engine is never exposed to an agent session | 4 | ST-004, 027 | Proven by `ward selftest` (ST-004: no Docker socket; ST-027 `host-run-sockets`: `/run/docker.sock`, `/run/podman/podman.sock` and `/run/user/*` are absent) |
| G9 | Verification runs the trusted test set from Zone 1 against exactly the snapshot IDs in evidence, in an environment the agent cannot influence beyond repository content | 6, 16, 17 | ST-006, 018, 019, 029 | Partly proven: ST-006 by `ward selftest`, ST-019 end to end (a hostile verify command gets no network, no host path and no persistence); the trusted test set comes from the entry snapshot today, TamperWard's bundle; ST-018 is proven (the candidate is captured with the sandbox frozen, `candidate_capture_is_atomic_while_the_agent_writes`, see G5), ST-029 (hostile verifier corpus) is ahead (§6). Freshness (ADR-0019): a verdict is shown as `VERIFY ✓` only while the worktree digests to the candidate id the `VerificationPassed` record names, computed by the shell with the snapshot crate's digest-only walk, so a green mark never outlives the state it verified |
| G10 | Hard-denied capabilities are never presented with an override | 18 | UI test | Phase 5 target |
| G11 | Data at rest is encrypted and unlockable only by the measured boot chain or the recovery key | 23 | RT-001 | Phase 7 target |
| G12 | A failed update rolls back automatically or via `ward system rollback` | 24 | RT-002 | Phase 7 target |
| G13 | `ward pause` holds a session as one host operation, in this order: every process of its sandboxes is frozen (a cgroup v2 freezer when the daemon can create a delegated cgroup, else `SIGSTOP` to the whole `bwrap` tree, children first), the session proxy refuses every new connection and every unresolved request with `503 paused by ward` and injects no credential, held approvals stay held with their timeouts stopped and new ones wait, and `SessionPaused { method, reason }` is appended; `ward resume` reverses it and appends `SessionResumed`. Not frozen: bytes already handed to a socket before the pause (an in-flight TLS record past the proxy reaches its peer; the relay itself moves nothing more), the `ward` client process that owns the proxy and the hook listener, and the host. A tunnel idle longer than the proxy's idle timeout while paused closes on resume. Stop from paused ends the frozen tree and keeps the worktree; `--restore-entry` writes the entry snapshot over it and keeps what it replaced in `.ward/restore-<ts>/` (`EntryRestored`) | 13, 19 | pause e2e | Proven end to end on bubblewrap (`pause_freezes_the_sandbox_closes_the_proxy_and_resume_lets_it_finish`: the shell's `State: T`, the proxy's 503 where it answered 403, the command finishing after resume) and by unit tests of the freeze path selection, the paused proxy and the held approvals; the cgroup path is selected only where `cgroup.freeze` appears, and CI has none |

## 2. Non-guarantees (state these everywhere the guarantees are stated)

* No protection against kernel privilege-escalation exploits from inside the sandbox.
* No protection against hostile firmware, DMA, cold-boot, evil-maid or speculative
  side-channel attacks.
* No protection against a compromised `wardd`, TamperWard, host root, or the user.
* No guarantee that verification is *meaningful*; only that it is *independent*. Meaning
  is TamperWard's domain.
* No prevention of exfiltration through allowlisted destinations; only scoping and logging.
* No guarantee about the agent's *inner* sandbox (e.g. Claude Code's bubblewrap layer).
  It is welcome defence-in-depth and is not relied on.
* On the portable (docker compose) runtime: G11, G12 do not apply; G1–G10 hold only to the
  extent the host container engine and VM enforce them.

---

## 3. Capability model

A session is described by a **capability manifest**. Capabilities are strongly typed; no
free-form strings are interpreted at enforcement time.

```rust
// ward-policy (concept)
pub struct CapabilityManifest {
    pub session: SessionId,
    pub project: ProjectId,
    pub policy_hash: Blake3Hash,           // hash of the merged policy that produced this
    pub filesystem: FsCapabilities,        // worktree rw, env rw, extra ro/rw paths (never host)
    pub network: NetworkCapability,        // Offline | LocalhostOnly | Registries | Development | Custom(Allowlist) | Unrestricted
    pub credentials: BTreeMap<ServiceId, CredentialRule>, // Deny | Ask | Allow(scope)
    pub containers: ContainerCapability,   // None | NestedRootless
    pub devices: DeviceSet,                // usually empty
    pub resources: ResourceLimits,         // cpu weight, memory, pids, disk
    pub observer: ObserverMode,            // Quiet | Live | StepThrough(StepPolicy)
    pub tool_images: Vec<ImageDigest>,     // pinned digests of layers mounted ro
    pub agent_image: ImageDigest,
}

pub enum Decision { Allow, Ask, Deny }
```

### 3.1 Default manifest

```text
filesystem
  /work        rw   (project worktree)
  /env         rw   (project environment: caches, toolchain upper layer)
  $HOME        rw   (sandbox-private, tmpfs-backed, discarded unless policy persists it)
  /tmp         rw   (tmpfs)
  everything else: absent or ro tool layers

network          development  (VCS hosts, package registries, the agent's own API host)
private networks deny (hard)

credentials
  github         ask, scope = current repository, contents:read issues:read
  npm publish    deny
  pypi publish   deny
  cloud-*        deny (hard)
  ssh-signing    ask, per-host

containers       nested rootless allowed
devices          none
resources        cpu weight 100, memory 50% of host, pids 4096, disk quota 20 GiB on /env
observer         live
```

### 3.2 Three-layer policy

```text
/etc/ward/policy.d/*.yaml        system   (root-owned, image-shipped defaults + admin)
~/.config/ward/policy.yaml       user
<project>/.ward/policy.yaml      project  (untrusted: may only narrow)
```

Merge is intersection with `Deny > Ask > Allow`. See threat model §7.

### 3.3 Decision semantics

* `Deny` at any layer is final for the session. Rendered as `DENIED` with the reason and
  the layer that denied. No override.
* `Ask` routes to the approval surface. Grants are `once` or `session`. Never persistent
  across sessions in 0.1 (a persistent grant is a *policy edit*, done in settings, not in a
  prompt).
* `Allow` is silent in Quiet mode, logged in Live mode.

---

## 4. Division of responsibility with TamperWard

```text
WardOS answers:   "Can the agent reach X at all?"    (capability, isolation)
TamperWard answers: "May the agent do Y to Z, and is the result acceptable?"
                                                     (behaviour, invariants, verification)
```

Concretely:

| Concern | WardOS | TamperWard |
| --- | --- | --- |
| Agent reads `~/.ssh` | Impossible (not mounted) | n/a |
| Agent edits `tests/auth.test.ts` | Allowed (it is in `/work`) | Denied if protected → WardOS receives the decision and reports it; the file write itself is reverted by TamperWard's mechanism or rejected at verification, per TamperWard's spec |
| Agent runs `npm test` | Allowed, logged | Observed; may be an input to decisions |
| Agent asks for GitHub token | Broker: scope/ask/deny | May veto by policy |
| Result acceptable? | Provides snapshot IDs, spawns verifier, records result | Decides |

WardOS never implements semantic rules ("no assertion weakening"). TamperWard never
implements isolation.

---

## 5. Security-relevant engineering rules

These are enforced by CI once code exists (Phase 1) and are listed here so the security
model is complete:

* `#![deny(unsafe_code)]` in every crate except those listed in an `UNSAFE.md` with a
  justification per block.
* `wardd` decodes agent-originated bytes only through length-bounded, typed decoders
  (no `serde_json::from_slice` on unbounded input; use a schema with size limits).
* Every path from Zone 3 is validated to be **within** `/work` or `/env` after
  canonicalisation *inside the sandbox mount namespace*, never on host paths.
* No security decision has a "fallback to allow" branch. Unknown → deny, logged.
* No shell in the enforcement path. Shell is permitted only in `scripts/` (build glue) and
  provisioning prototypes.
* All identifiers (`SessionId`, `SnapshotId`, `ImageDigest`, `ServiceId`) are newtypes.
* Logging never includes credential material; the broker's log type has no `Display` for
  secrets.

---

## 6. Next security work: the proof backlog

[ADR-0019](decisions/ADR-0019-authority-freshness-intervention.md) decision 6: the
remaining proofs come before more desktop polish. Each row below is a guarantee above
that is stated but not yet backed by a probe, in the order the work is taken. A row
leaves this list when it is a `ward selftest` row or an end-to-end test with a hostile
workload, reproduced by CI on every pull request, and the guarantee's Status column
says so. Numbering continues the threat model's §8 list; ST-023..025 are taken there.

| Test | Guarantee | What the probe does | Passes when |
| --- | --- | --- | --- |
| ST-029 `hostile-verifier-corpus` | G9 | Runs the verifier over a corpus of hostile repositories: build scripts that reach for the network, the host and the CAS; test harnesses that rewrite their own results; symlinks, submodules and hooks pointing out of the tree | Every repository gets a verdict; nothing touches the host, the network or the next run; the verdicts are what the trusted test set says, not what the repository says |

The probes are implemented as `ward selftest` groups or `security-tests/` workloads,
not here; this section is the contract for what they must show.

ST-018 `candidate-snapshot-toctou` (G5, G9) left this list: it is proven by the
integration test `candidate_capture_is_atomic_while_the_agent_writes`
(`crates/ward-daemon/tests/st018_freeze_before_capture.rs`), reproduced by CI on every
pull request. The daemon freezes the session's sandbox for the length of a candidate or
final capture (`pause::CaptureFreeze`, the ADR-0019 pause primitive held only for the
walk and released after, with no marker, record, or change to the proxy or credentials)
so no agent write can interleave with it. The test spawns an agent — discovered and
frozen exactly as `ward pause` finds a session's `bwrap` tree — that changes a file's
size on every write, shows an unfrozen capture tears (a snapshot whose recorded size and
stored bytes disagree, so it no longer `materialize`s back to its id), and shows that
with the freeze held every capture is internally consistent. A candidate captured while
the session is already paused by the user is captured against the tree the user's freeze
already holds still, and the guard leaves that pause for `ward resume` to lift.

### 6.1 Delivered: the `egress and surfaces` group of `ward selftest`

ST-022, ST-026, ST-027 and ST-028 left the backlog as thirteen rows of one
`ward selftest` group, reproduced by CI on every pull request
(`egress_and_surface_probes_never_reach` in `crates/ward-daemon/tests/e2e.rs`). The
probes run inside the real bubblewrap sandbox, handed a proxy socket and a hook socket
exactly as a session launch is; the proxy is the real `ward-proxy` in `localhost_only`
mode with a resolver the self-test stages, so an allowlisted `*.localhost` name can be
made to answer with a private address or to change its answer between two requests,
and the self-test's own loopback servers (two plain HTTP servers that sign their
answers, one TLS server with a certificate made for the run) stand in for allowed
destinations. Each probe prints facts; the verdict is reached on the host by comparing
them with what those servers, the resolver and the proxy's decision record saw. A row
this host cannot measure says `CANNOT-MEASURE-HERE` with the reason and is never
counted as a pass (E-06's convention); the summary line counts them separately.

| Row | What the sandbox does | Proof (`DENIED` when) |
| --- | --- | --- |
| ST-022 `tunnel-host-switch` | `CONNECT`s to allowed server A, then sends a request with `Host:` server B inside the tunnel | The answer carries A's signature and B saw no request: a tunnel is bytes to its `CONNECT` target, nothing re-reads the `Host` |
| ST-022 `tls-end-to-end` | Writes its own CA file under `/tmp`, names it in `SSL_CERT_FILE`, `SSL_CERT_DIR` and `NODE_EXTRA_CA_CERTS`, then speaks TLS through a `CONNECT` to the TLS server | The peer certificate is byte for byte the server's and the response is byte for byte what the server wrote: the proxy never terminated TLS, so it could not read the plaintext or inject a header. A verify failure or a differing certificate is `REACHED` |
| ST-022 `proxy-inside-tunnel` | Inside a `CONNECT` to A, sends `GET http://denied.example:B/` (what `curl --proxy` sends to a proxy) for a name outside the allowlist that resolves to loopback | Server A answers with its signature and B saw nothing: a tunnel is not a second proxy |
| ST-026 `raw-tcp-ipv4` | `connect(2)` to `8.8.8.8:53` and `10.0.0.1:80` | `ENETUNREACH`, `ECONNREFUSED` or `EHOSTUNREACH` (or `EPERM` from a filter): the namespace has loopback only |
| ST-026 `raw-tcp-ipv6` | `connect(2)` to `[2001:4860:4860::8888]:53` | The same, or `CANNOT-MEASURE-HERE` on a kernel without IPv6 sockets (`EAFNOSUPPORT`) |
| ST-026 `socks5-on-proxy` | A SOCKS5 greeting (`05 01 00`) on the proxy socket | An HTTP `400` or a closed connection, never a `05` reply: the relay speaks HTTP `CONNECT` and forwarding only |
| ST-026 `udp-egress` | A DNS query over UDP to `1.1.1.1:53` | `sendto` fails with no route; a datagram that leaves but is not answered is `CANNOT-MEASURE-HERE`, a reply is `REACHED` |
| ST-027 `host-run-sockets` | Looks for `/run/user/*`, `/run/docker.sock`, `/var/run/docker.sock`, `/run/podman/podman.sock` and the session's control socket path | None exists: `/run` is a private tmpfs holding only the two sockets the session binds |
| ST-027 `host-loopback` | Connects to a port the host is listening on, binds that same port, binds a port the host verified free and asks the proxy to `CONNECT` to it | The host's port is refused inside and free to bind inside (separate port space), and the proxy's connect from the host side is a `502`: a port bound inside is invisible to the host |
| ST-027 `host-abstract-socket` | Connects to an abstract Unix socket the host bound for the run (`@ward-selftest-<nonce>`) and to `@/tmp/.X11-unix/X0` | `ECONNREFUSED`: abstract sockets are per network namespace |
| ST-027 `hook-socket-forgery` | Sends a control-protocol `{"req":"approve",…}` line on the hook socket | The hook listener answers with nothing and records nothing; the hook socket has no path to the control protocol, and the control socket itself is absent (ST-017), so there is no daemon secret to steal because no request from the sandbox can reach a `wardd` decision |
| ST-028 `rebind-to-private` | `CONNECT`s to allowlisted names staged to resolve to `10.0.0.1`, `169.254.169.254`, `::ffff:192.168.0.1` and `[127.0.0.1, 10.0.0.1]`, and to the literal `10.0.0.1` | Every name gets byte for byte the literal's `403` and the proxy's record says `private range` or `cloud metadata endpoint`; a `200` or `502` (an attempted connect) is `REACHED` |
| ST-028 `pinned-tunnel` | `CONNECT`s to `pin.localhost`, whose answer is loopback once and `10.0.0.1` ever after; sends a request inside the first tunnel; `CONNECT`s again | The first tunnel reaches server A, the proxy resolved the name exactly once per request (twice in all: a third resolution would mean the data path re-resolves), and the second `CONNECT` is a `403` recorded as `private range` |

`ward-proxy` already checked every resolved address against the structural deny
ranges and connected only to a checked address (`policy.rs`); the ST-028 rows and the
two proxy integration tests (`allowlisted_name_resolving_to_a_private_address_is_the_literal_403`,
`an_established_tunnel_is_pinned_and_a_rebinding_answer_refuses_the_next`) state that
as a contract rather than an implementation detail.
