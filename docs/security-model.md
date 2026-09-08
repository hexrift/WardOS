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
| G3 | An agent session can reach only the network destinations in its effective manifest, and never private/link-local/metadata ranges | 10, 21 | ST-011, 022, 026, 028 | ST-011 proven by `ward selftest` and the proxy tests (private, link-local and metadata ranges 403 in every mode); ST-022 (TLS interception), ST-026 (raw TCP and SOCKS) and ST-028 (DNS rebinding and pinning) are the backlog of §6 |
| G4 | An agent session cannot observe, signal, trace, or share writable filesystem state with `wardd`, TamperWard, or any verifier | 5, 6 | ST-005, 006, 027 | Proven by `ward selftest` for the namespace form: ST-005 (the supervisor cannot be signalled), ST-006 (the launch's host run directory, where verifier trees live, is invisible); the distinct verifier uid and ST-027 (loopback and control-socket surfaces, §6) are ahead |
| G5 | Entry, candidate and accepted snapshots are immutable and unreachable from the sandbox; their IDs are content-derived | 8, 16 | ST-008, 018 | ST-008 proven by `ward selftest` (the CAS is unreachable) and by content addressing (`ward snapshot diff`); ST-018 (freeze before capture) is ahead |
| G6 | Evidence is append-only, hash-chained, unreachable from the sandbox, and agent-originated records are distinguishable from enforcement records | 9, 14 | ST-009, 010, 016 | Proven: ST-009/010 and ST-017 by `ward selftest` (log, state root and control socket unreachable), ST-016 end to end (hook-socket input stays `Origin::Agent`), plus `ward replay --verify` on the chain |
| G7 | The effective capability manifest is fixed for the life of a session and repository policy can only narrow it | 7, 18 | ST-007 | Proven: ST-007 end to end (a policy rewritten mid-session does not widen the network) and the merge property tests in `ward-policy` |
| G8 | The host container engine is never exposed to an agent session | 4 | ST-004 | Proven by `ward selftest` (ST-004: no Docker socket) |
| G9 | Verification runs the trusted test set from Zone 1 against exactly the snapshot IDs in evidence, in an environment the agent cannot influence beyond repository content | 6, 16, 17 | ST-006, 018, 019, 029 | Partly proven: ST-006 by `ward selftest`, ST-019 end to end (a hostile verify command gets no network, no host path and no persistence); the trusted test set comes from the entry snapshot today, TamperWard's bundle, ST-018 and ST-029 (hostile verifier corpus) are ahead (§6). Freshness (ADR-0019): a verdict is shown as `VERIFY ✓` only while the worktree digests to the candidate id the `VerificationPassed` record names, computed by the shell with the snapshot crate's digest-only walk, so a green mark never outlives the state it verified |
| G10 | Hard-denied capabilities are never presented with an override | 18 | UI test | Phase 5 target |
| G11 | Data at rest is encrypted and unlockable only by the measured boot chain or the recovery key | 23 | RT-001 | Phase 7 target |
| G12 | A failed update rolls back automatically or via `ward system rollback` | 24 | RT-002 | Phase 7 target |

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
| ST-018 `candidate-snapshot-toctou` | G5, G9 | Writes to the worktree from a background process and from a nested container while a candidate is being captured | The candidate's manifest is what the freeze saw; the writes land after it or are recorded as the session being paused (built on the pause primitive of ADR-0019) |
| ST-022 `tls-interception-attempt` | G3 | Installs a CA into the sandbox's trust store, points the agent's proxy variables at a sandbox-side listener, and asks for an injected host through it | The gateway terminates TLS only for the hosts it injects, with system trust; the sandbox listener sees a CONNECT it cannot complete, and the log shows the attempt |
| ST-026 `raw-tcp-socks-bypass` | G3 | Opens a raw TCP connection, a SOCKS4/5 handshake and a non-HTTP protocol on the relay port and on every other address the sandbox can name | Nothing leaves except through the proxy's HTTP grammar; each attempt is a `NetworkDenied` record with the reason |
| ST-027 `loopback-control-surface` | G4, G6 | Scans the sandbox's loopback and abstract Unix namespace for the control socket, the hook socket of another session, and any host service | Only the session's own relay and hook socket answer; the control socket is unreachable (ST-017 already proves it cannot be abused when found) |
| ST-028 `dns-rebinding-pinning` | G3 | Serves an allowlisted name whose answer flips to a private address between resolution and connect, and a name with mixed public and private answers | The proxy connects to the address it resolved and refused the private one; the flip is a `NetworkDenied` record, not a connection |
| ST-029 `hostile-verifier-corpus` | G9 | Runs the verifier over a corpus of hostile repositories: build scripts that reach for the network, the host and the CAS; test harnesses that rewrite their own results; symlinks, submodules and hooks pointing out of the tree | Every repository gets a verdict; nothing touches the host, the network or the next run; the verdicts are what the trusted test set says, not what the repository says |

The probes are implemented as `ward selftest` groups or `security-tests/` workloads,
not here; this section is the contract for what they must show.
