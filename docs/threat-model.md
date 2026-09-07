# WardOS Threat Model

Status: Phase 0. This document is the basis for every security claim in
[`security-model.md`](security-model.md). A claim that is not traceable to a row in §6 and
a test in §8 is not a claim WardOS makes.

Under the repository's TamperWard/CODEOWNERS split
([`development-under-tamperward.md`](development-under-tamperward.md)) this file is
**human-review-only**: agents may propose edits, a human security reviewer must approve them.

---

## 1. Assets

| ID | Asset | Zone | Why it matters |
| --- | --- | --- | --- |
| A1 | Host filesystem and OS image | 0 | Integrity of everything else |
| A2 | User's real home directory | 0 | Personal data, other projects, editor configs |
| A3 | Long-lived credentials (`~/.ssh`, `~/.aws`, PATs, npm tokens, cloud keys, the agent's own model-API OAuth token) | 0 | Lateral movement, exfiltration, financial loss |
| A4 | WardOS policy store and per-session capability manifests | 0 | Defines the sandbox boundary |
| A5 | TamperWard policy, state and decision channel | 1 | Defines acceptable behaviour |
| A6 | Snapshot store (CAS): entry, candidate, accepted snapshots | 0 | Ground truth for "what did the agent start from / produce" |
| A7 | Evidence log (event chain) | 0 | Audit, replay, TamperWard evidence |
| A8 | Trusted verifier runtime, trusted tests, verifier scratch state | 2 | Independence of verification |
| A9 | Other projects' worktrees and environments | 0 | Cross-project contamination |
| A10 | Host container engine (Docker/Podman socket) | 0 | Root-equivalent on host |
| A11 | Private network (LAN, VPN, cloud metadata endpoints, other containers) | 0/4 | Pivot, SSRF |
| A12 | The project worktree itself | 3 | The thing the agent is *supposed* to change; integrity of the *accepted* result is A6+A8's job |
| A13 | Control channels (`wardd` socket, TamperWard socket, proxy, event subscription) | 0 | Confused-deputy and injection surface |
| A14 | Boot chain, disk encryption keys, TPM state | 0 | Physical/offline integrity |

---

## 2. Adversaries

| ID | Adversary | Capability assumed | Position |
| --- | --- | --- | --- |
| T1 | Malicious coding agent | Arbitrary code execution as the sandbox user; full control of everything in Zone 3; can send arbitrary bytes on every Zone 3 → Zone 0 channel; can spend unlimited time | Zone 3 |
| T2 | Compromised / prompt-injected agent | Same as T1 (indistinguishable from outside) | Zone 3 |
| T3 | Malicious repository (hostile code, hooks, `.ward/`, `.tamperward/`, `.claude/`, symlinks, submodules, giant files) | Controls all file content the agent and the verifier read from the project | Zone 3 + inputs to Zone 2 |
| T4 | Malicious dependency / install script | Arbitrary code at `npm install`/`pip install`/`cargo build` time inside the sandbox **and inside the verifier** | Zone 3, Zone 2 |
| T5 | Compromised developer tool image (compiler, linter, agent binary) | Arbitrary code in Zone 3 from session start | Zone 3 |
| T6 | Network attacker | Controls Zone 4; can serve hostile responses to allowlisted hosts if TLS is defeated (it must not be) | Zone 4 |
| T7 | Local unprivileged user account (multi-user host, rare) | Ordinary Unix user on the host | Zone 0 (unprivileged) |
| T8 | Thief with powered-off device | Physical access, no running session | Offline |

**Not modelled (explicitly out of scope for 0.1):** kernel exploitation from Zone 3 (we
reduce attack surface but do not claim to stop a working kernel LPE), hostile firmware,
evil-maid attacks on a running/suspended machine, DMA attacks, speculative-execution side
channels, a compromised `wardd`/TamperWard/host root, a malicious *user*, supply-chain
compromise of the WardOS image itself (mitigated by signing, not modelled as an attacker
here), and denial of service by the agent against its own sandbox (bounded by cgroups, not
prevented).

---

## 3. Trust assumptions

WardOS assumes:

1. The Linux kernel enforces namespaces, seccomp, Landlock, cgroups, nftables and file
   permissions correctly.
2. `wardd`, TamperWard's control plane and the Ward Shell are not compromised.
3. The user is honest with respect to their own machine (approvals are the user's).
4. TLS to allowlisted hosts is intact (system trust store; no MITM CA in the sandbox unless
   the user configures one, which is surfaced in the bar).
5. The host image is the signed image it claims to be (Secure Boot + measured boot from
   Phase 7; before that, this assumption is unenforced and documented as such).
6. Zone 3 is **fully compromised** at all times. Every design decision is checked against
   this.

---

## 4. Attack surfaces

Enumerated from the perspective of T1 (everything else is a subset).

| S | Surface | What T1 can do with it |
| --- | --- | --- |
| S1 | Project worktree bind mount | Write arbitrary content, symlinks, hardlinks, FIFOs, huge files, deep trees, `.git` rewrites, hooks |
| S2 | Project environment (rw upper layer) | Plant binaries that later sessions execute; fill disk |
| S3 | `ward-agent` control socket | Send malformed/oversized/flooding messages; forge event content; request capabilities repeatedly; race approvals |
| S4 | Egress proxy | Attempt non-allowlisted hosts, IP literals, DNS rebinding, CONNECT to private IPs, SNI/Host mismatch, HTTP smuggling, credential extraction via reflected requests |
| S5 | Nested container runtime | Attempt userns/overlay escapes, device access, cgroup escape |
| S6 | Agent hooks / semantic events | Lie (emit false "read" events, suppress events) |
| S7 | Verification request | Request verification of a manipulated candidate; race the snapshot; time-of-check/time-of-use on files |
| S8 | Verifier inputs (via repo content) | Test code, build scripts, `Cargo.toml` build.rs, `package.json` lifecycle scripts run *inside the verifier* |
| S9 | Snapshot engine inputs | Pathological trees to make snapshotting slow, non-canonical names, symlink loops, files changing during capture |
| S10 | Kernel syscall surface | Exploits (out of scope) and resource abuse (in scope: bounded) |
| S11 | Observer/Shell rendering | Terminal escape sequences, Unicode direction overrides, oversized strings in event payloads |
| S12 | Credentials delivered in-sandbox | Persist beyond session, exfiltrate, replay |
| S13 | `.ward/` policy in repo | Attempt to grant itself capabilities |
| S14 | Signals/ptrace/`/proc` | Attack sibling processes |

---

## 5. Security objectives

| O | Objective | Enforced by |
| --- | --- | --- |
| O1 | Agent cannot read or write any host path outside `/work`, `/env`, sandbox `$HOME`, `/tmp` | mount ns + Landlock + userns (unmapped uids) |
| O2 | Agent cannot obtain any long-lived credential | Vault outside Zone 3; broker mints scoped/short-lived; proxy injection preferred; agent's own API auth via broker gateway |
| O3 | Agent cannot reach non-allowlisted network destinations or any private network | netns + nftables (fail closed) + proxy allowlist + RFC1918/link-local/ULA deny + DNS stub |
| O4 | Agent cannot see, signal, ptrace, or share writable state with the verifier, TamperWard, or `wardd` | PID ns, distinct uids, no shared mounts, socket permissions, seccomp `ptrace` restriction |
| O5 | Agent cannot alter the entry snapshot, candidate snapshot, or accepted snapshot after capture | CAS owned by `ward` uid, not mounted in Zone 3; content addressing; capture under cgroup freeze |
| O6 | Agent cannot alter, truncate, reorder, or forge evidence | Append-only log owned by `ward`; hash chain; agent-originated events tagged `origin=agent` and never treated as enforcement facts |
| O7 | Agent cannot change its own capability manifest or TamperWard policy during a session | Manifest fixed at session open from policy hash; repo `.ward/` can only *narrow* capabilities relative to user/system policy (§7) |
| O8 | Agent cannot obtain host container-engine authority | Socket never mounted; nested rootless runtime inside userns only |
| O9 | The verifier's inputs are exactly the pristine and candidate snapshot IDs recorded in evidence, and the trusted test set from Zone 1 | Verifier materialises from CAS; manifest signed by `wardd`; result binds to IDs |
| O10 | Hostile code executing *inside the verifier* cannot affect Zone 0, Zone 1, Zone 3, later verifications, or the evidence beyond its own result | Verifier is disposable, no network, no persistent writable state, distinct uid; result written by `wardd` from a pipe, not by verifier to shared storage |
| O11 | Denials are visible and non-overridable where policy is hard | Approval router distinguishes `ask` from `deny`; UI never renders an override for `deny` |
| O12 | Resource abuse in Zone 3 does not take down Zone 0/1/2 | cgroup memory/pids/io limits; disk quota on project environment; snapshot size caps |
| O13 | Data at rest is protected when the device is off | LUKS2 + TPM2-bound unlock with PCR policy + recovery key (Phase 7) |
| O14 | A broken update never leaves the machine unbootable | bootc atomic deployments, automatic boot-counting rollback + `ward system rollback` (Phase 7) |

---

## 6. Threat → mitigation matrix

Format: threat (adversary, surface) → primary control → secondary control → residual risk
→ test ID(s) from §8.

| # | Threat | Primary control | Secondary | Residual | Tests |
| --- | --- | --- | --- | --- | --- |
| 1 | Read `~/.ssh`, `~/.aws`, home (T1, S1) | Home not mounted; uids unmapped | Landlock ro-deny; seccomp | Kernel bug | ST-001, ST-002 |
| 2 | Write host file (T1, S1) | Mount ns rootfs ro layers; only listed rw paths | Landlock; userns | Kernel bug | ST-003 |
| 3 | Symlink/hardlink out of worktree (T1, S1) | Bind mount boundary: symlinks resolve inside the ns; hardlinks to unmapped inodes fail | Snapshot engine refuses to follow symlinks out of tree; verifier materialises symlinks as symlinks | None known | ST-015 |
| 4 | Access Docker socket (T1, S5) | Not mounted; not in `/run` | Nested runtime is rootless-in-userns | Nested runtime escape → still inside outer userns | ST-004 |
| 5 | Kill/signal verifier or wardd (T1, S14) | PID ns: invisible | Distinct uid; `CAP_KILL` absent | None known | ST-005 |
| 6 | Write verifier state (T1, S1/S7) | Verifier has no mount from Zone 3; materialises from CAS | Verifier uid distinct; no shared tmpfs | None known | ST-006 |
| 7 | Rewrite policy (T1, S13) | Manifest computed at session open; repo policy can only narrow | Policy hash in evidence; changes mid-session ignored until `ward stop`/`up` | User applies hostile repo policy manually | ST-007 |
| 8 | Modify entry snapshot (T1, S9) | Captured under freeze; stored in CAS unreachable from Zone 3 | Content-addressed: mutation changes ID | Freeze bypass via nested containers in other cgroup → prevented by nesting under session cgroup | ST-008 |
| 9 | Read/rewrite evidence (T1, S3) | Log owned by `ward`, not mounted | Hash chain; periodic anchor to TamperWard | Wardd compromise | ST-009, ST-010 |
| 10 | Private network / metadata SSRF (T1, S4) | nftables DROP non-proxy egress; proxy denies private ranges incl. DNS-resolved | DNS stub returns only allowlisted A/AAAA; DNS rebinding defeated by proxy re-resolving and pinning | IPv6 misconfiguration | ST-011 |
| 11 | Credential persistence/replay (T1, S12) | Proxy injection: no token in Zone 3 | Minted tokens ≤10 min, session-bound, revoked at stop; audit | Token used within its window for out-of-scope action if scope too broad | ST-012 |
| 12 | Namespace escape (T1, S10) | Rootless userns; no caps; seccomp denies `unshare` of userns beyond nesting depth 1, `mount`, `setns` to foreign, `bpf`, `keyctl` | Landlock | Kernel LPE (out of scope) | ST-013 |
| 13 | cgroup escape / fork bomb (T1, S10) | cgroup ns; `pids.max`; `memory.max`; `cgroup.kill` | Nested runtime constrained under session cgroup | DoS of own session only | ST-014 |
| 14 | Forge semantic events (T1, S6) | Events carry `origin`; enforcement uses only `origin=kernel|proxy|wardd` events | UI labels agent-origin events distinctly | User misreads a forged "read" event as fact | ST-016 |
| 15 | Flood/malform control socket (T1, S3) | Length-prefixed, bounded, typed decoding; per-session rate limit; backpressure | Socket is per-session; wardd worker isolation | Slow-loris on own session | ST-017 |
| 16 | TOCTOU on candidate snapshot (T1, S7) | Freeze entire session cgroup incl. nested containers before capture | Btrfs snapshot when available (atomic) | Writes from outside the cgroup — none exist | ST-018 |
| 17 | Hostile build script in verifier (T3/T4, S8) | Verifier is disposable, no network, no secrets, distinct uid | cgroup limits; time budget; result only via wardd pipe | Verifier "passes" a hostile test set — this is TamperWard's protected-tests problem, not WardOS's | ST-019 |
| 18 | Hostile `.ward/` requests broad capabilities (T3, S13) | Merge is deny-by-default; repo may only narrow | UI shows effective capabilities before first session on a new repo | User approves blindly | ST-007 |
| 19 | Terminal escape / Unicode injection in UI (T1, S11) | Event strings sanitised at ingest (control chars stripped, bidi isolates), length-capped | Observer renders in cells, never raw | Homoglyph confusion | ST-020 |
| 20 | Compromised tool image (T5) | Image digests pinned in capability manifest and recorded in evidence | Approved-image allowlist (enterprise hook) | Hostile image is still inside Zone 3 → same as T1 | ST-021 |
| 21 | MITM of allowlisted host (T6) | TLS terminates in the sandbox (proxy is CONNECT, not interception) for non-injected hosts; for injected hosts proxy terminates TLS itself with system trust | No custom CAs in sandbox by default | Compromised CA | ST-022 |
| 22 | Other local user reads session data (T7) | `/var/lib/ward` mode 0700 `ward:ward`; sockets `0660` with group per user | Per-user session ownership | Root user | ST-023 |
| 23 | Device theft (T8) | LUKS2 + TPM2 PCR-bound unlock; recovery passphrase | Secure Boot prevents unsigned boot | Evil maid on suspended device (out of scope) | RT-001 (rollback/boot suite) |
| 24 | Broken update (build defect) | Atomic deployment, boot counting, automatic fallback | `ward system rollback` | Firmware update breaks PCRs → recovery key path | RT-002 |
| 25 | Agent runs `git push --force`/rewrites history (T1, S1) | Not prevented in the worktree (it is the agent's copy) | Push requires broker credential with `contents:write`; policy default is `ask`; evidence records | Accepted by design | ST-024 |
| 26 | Agent tampers with the *agent's own* inner sandbox (e.g. Claude Code bubblewrap settings) (T1) | Inner sandbox is treated as untrusted defence-in-depth; WardOS never relies on it | — | None: outer boundary is the claim | ST-025 |

---

## 7. Policy merge rule (referenced by #7, #18)

```text
effective = system_policy ∩ user_policy ∩ project_policy
```

* Each layer may **deny** anything, **ask** for anything the layer above allows, and
  **allow** only what the layer above allows.
* A repository's `.ward/policy.yaml` therefore cannot grant more than the user's default.
* Hard denials (`aws-production: deny` in system policy) cannot be relaxed by any lower
  layer and never render an override control.
* The effective manifest is hashed and recorded in the session's genesis event.

---

## 8. Security test catalogue (initial)

Each test is executed by a hostile workload inside a real sandbox on a real WardOS image
(QEMU in CI, hardware in the certification suite) and must **fail to achieve** its goal.
Executed by `ward selftest` on-device and by the WardOS Security CI on every PR.

```text
ST-001  read-host-home                  ST-014  cgroup-escape
ST-002  read-ssh-key                    ST-015  symlink-boundary-escape
ST-003  write-host-file                 ST-016  forge-semantic-event
ST-004  access-docker-socket            ST-017  control-socket-abuse
ST-005  kill-verifier                   ST-018  candidate-snapshot-toctou
ST-006  write-verifier-state            ST-019  hostile-build-script-in-verifier
ST-007  rewrite-policy                  ST-020  ui-injection
ST-008  modify-entry-snapshot           ST-021  tool-image-substitution
ST-009  read-evidence                   ST-022  tls-interception-attempt
ST-010  rewrite-evidence                ST-023  cross-user-session-read
ST-011  private-network-bypass          ST-024  credential-scope-overreach
ST-012  credential-persistence          ST-025  inner-sandbox-disable
ST-013  namespace-escape
RT-001  boot-chain-integrity            RT-002  broken-update-rollback
```

Numbering ST-001..015 matches the original engineering brief; ST-016..025 were added by
this threat model.

---

## 9. Residual risks to state publicly

1. **Kernel exploits.** A working local privilege escalation from an unprivileged userns
   defeats Zone 3 isolation. WardOS reduces surface (seccomp, no caps, no devices, no
   io_uring/userfaultfd/bpf) and will evaluate a microVM tier for the verifier
   (E-03), but does not claim kernel-exploit resistance in 0.1.
2. **Hostile tests inside the verifier.** WardOS guarantees the verifier ran *the trusted
   test set* against *the recorded snapshots* in isolation. Whether those tests are
   meaningful is TamperWard's protected-surface problem.
3. **User approvals.** `ask` capabilities depend on the user reading the prompt.
4. **Allowlisted hosts are trusted.** If `github.com` is allowlisted, data can leave via
   GitHub. Exfiltration through allowed channels is bounded by scope, not prevented.
5. **Portable (non-WardOS) deployments** inherit their container host's boundary. No
   boot-chain or host-image claims apply there.
