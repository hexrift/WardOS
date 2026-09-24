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
| G9 | Verification runs the trusted test set from Zone 1 against exactly the snapshot IDs in evidence, in an environment the agent cannot influence beyond repository content | 6, 16, 17 | ST-006, 018, 019, 029 | Partly proven: ST-006 by `ward selftest`, ST-019 end to end (a hostile verify command gets no network, no host path and no persistence); the trusted test set comes from the entry snapshot today, TamperWard's bundle; ST-018 is proven (the candidate is captured with the sandbox frozen, `candidate_capture_is_atomic_while_the_agent_writes`, see G5), and ST-029 (hostile verifier corpus) is proven by the `verifier corpus` group of `ward selftest` (nine hostile repositories run through the real verifier, §6.2), reproduced by CI. Freshness (ADR-0019): a verdict is shown as `VERIFY ✓` only while the worktree digests to the candidate id the `VerificationPassed` record names, computed by the shell with the snapshot crate's digest-only walk, so a green mark never outlives the state it verified |
| G10 | Hard-denied capabilities are never presented with an override | 18 | UI test | Phase 5 target |
| G11 | Data at rest is encrypted and unlockable only by the measured boot chain or the recovery key | 23 | RT-001 | Phase 7 target |
| G12 | A failed update rolls back automatically or via `ward system rollback` | 24 | RT-002 | Phase 7 target |
| G13 | `ward pause` holds a session as one host operation, in this order: every process of its sandboxes is frozen (a cgroup v2 freezer when the daemon can create a delegated cgroup, else `SIGSTOP` to the whole `bwrap` tree, children first), the session proxy refuses every new connection and every unresolved request with `503 paused by ward` and injects no credential, held approvals stay held with their timeouts stopped and new ones wait — and only *then* does the daemon decide whether the freeze actually settled and append exactly one terminal record for it: `SessionPaused { method, reason }` when confirmed, or `SessionPauseUnsettled { method, reason, pending }` when it could not confirm every process stopped within the bound — never both, and never the confirmed record first (PR #207 review finding 1): deciding the outcome before publishing anything means no subscriber, the CLI, `ward-cli`'s replay, or the desktop's own trust bar (`ward-shell-core::AgentState::PauseUnsettled`, distinct from `AgentState::Paused` and rendered as its own `PAUSED?` word/glyph/tone) can ever observe a confirmed pause that a moment later turns out to have been unsettled all along. `SIGSTOP` delivery is asynchronous (the cgroup freezer path is not: it already blocks on `cgroup.events` reporting `frozen 1`), so on the signal path the daemon waits up to `pause::FREEZE_SETTLE` (1s) for every process to actually stop before deciding; a recount that finds nothing pending after a timeout is normalized to settled, never a self-contradictory "unsettled: 0 pending" (`pause::settle_outcome`, PR #207 review finding 3). The marker, the held approvals and the SIGSTOPs already sent all still stand regardless of the outcome (the pause is never undone for it), only shown as unconfirmed rather than as the same unqualified success a confirmed pause gets (#145 items 3-4). If the terminal record's own append fails on the unsettled path (e.g. storage exhaustion), that failure is folded into the error returned to the caller — never silently discarded — while the marker/approvals/frozen tree still stand and remain releasable by a later `ward resume` (PR #207 review finding 2); the settled path's own append failure keeps its pre-existing behaviour of rolling the whole attempt back. `ward resume` reverses a pause (settled or not) and appends `SessionResumed`. Not frozen: bytes already handed to a socket before the pause (an in-flight TLS record past the proxy reaches its peer; the relay itself moves nothing more), the `ward` client process that owns the proxy and the hook listener, and the host. A tunnel idle longer than the proxy's idle timeout while paused closes on resume. `ward stop` (#145 item 5), from running or from paused, is termination followed by sealing: under the session lock, the stop marker is written (no later launch is admitted), the session's sandbox trees are frozen (or the pause's freeze kept), the freeze is confirmed stable before anything is killed (every held process stopped and a rescan — by `bwrap` tree and by the sandbox's pid namespace — finding nothing new, so a child forked in the scan-to-`SIGSTOP` window cannot be orphaned out of reach), every process is killed and confirmed gone within `pause::STOP_SETTLE` (2s), `WorkloadsTerminated { ended, pending: 0 }` is appended when there was anything to end, and only then is the agent recorded `Finished`, approvals closed, `SessionEnded` appended and the log sealed — a sealed log therefore no longer coexists with a sandbox of that session still running. Launch admission is part of the same serialized operation: every launch re-checks the pause and stop markers under that lock immediately before its `bwrap` spawn and holds the lock across the spawn (`pause::admit_launch`), so a launch that stalled past the early check can neither slip past a stop's scan nor spawn after it. A client sends `Stop` only to a daemon whose `Request::Capabilities` names `stop-terminates-workloads`, and treats a `Sealed` without a termination acknowledgement as a failure: a 0.18 daemon, whose `Stop` only seals, is refused with nothing sent. A stop that cannot confirm termination (a process stuck in uninterruptible sleep) is refused, not reported done: the log stays unsealed, no `Finished` is recorded, the session is held for the stop over what is left and `WorkloadsTerminated { pending > 0 }` says so — an incomplete stop, not a pause: `ward resume` refuses it (its processes may already have taken `SIGKILL`), and `ward stop` retries. `Request::Seal` remains the separate log-only closure and does not touch a running sandbox. The worktree is kept; `--restore-entry` is one daemon-owned hold (`Request::HoldForStop`): the daemon freezes the sandboxes itself — never trusting a pause marker a restarted daemon did not write — or takes over its own pause, writes the stop marker, and keeps the hold, which no `ward resume` can release, until the stop; only once the hold is confirmed stable does the entry snapshot get written over the worktree (what it replaced kept in `.ward/restore-<ts>/`, `EntryRestored`), then the stop ends the held tree. Not ended by a stop: the `ward` client process that launched the sandbox (it sees its child killed and exits). Not covered: a process that never takes `SIGSTOP` within `pause::FREEZE_SETTLE` (killable-only waits) is killed without a confirmed barrier (`Termination::barrier_confirmed`), and a child it forks outside the sandbox's pid namespace is not found — only possible for a tree sharing the host's namespace, which `bwrap --unshare-pid` does not; a daemon restarted mid-stop refuses `resume` (stop marker) but does not rebuild the stop hold's freeze until the next `stop` | 13, 19 | pause e2e | Proven end to end on bubblewrap (`pause_freezes_the_sandbox_closes_the_proxy_and_resume_lets_it_finish`: the shell's `State: T`, the proxy's 503 where it answered 403, the command finishing after resume) and by unit tests of the freeze path selection, the paused proxy and the held approvals; the cgroup path is selected only where `cgroup.freeze` appears, and CI has none. The unsettled path (#145 items 3-4) is proven by daemon-level unit tests with an injected settle outcome (`an_unsettled_freeze_still_pauses_but_is_never_reported_as_a_clean_success`), the append-failure fold by `an_unsettled_pauses_append_failure_is_surfaced_not_discarded`, the `Some(0)` normalization by `a_timeout_whose_immediate_recount_finds_nothing_pending_normalizes_to_settled`/`a_timeout_with_a_genuinely_nonzero_recount_reports_it`, and the desktop's distinct state by `ward-shell-core`'s `an_unsettled_pause_is_distinct_from_a_confirmed_one_and_resume_restores_the_prior_state` and `every_agent_state_has_a_glyph_a_word_and_a_tone` — none of it end to end: `SIGSTOP` cannot be caught, blocked or ignored by user space, so there is no real process a test could make resist it for a bubblewrap-backed test to race against, and `bwrap` itself is still not installable in the environment these were verified in (see PR #207's own verification section). Stop's termination (#145 item 5) is proven against real process trees the daemon's scan recognises as a session sandbox (`pause::tests::terminate_ends_a_real_sandbox_shaped_tree`, `daemon::tests::stop_ends_a_running_sandbox_before_sealing`, `session::tests::a_daemonless_stop_ends_a_running_sandbox_before_sealing`, e2e `stop_restore_entry_through_the_daemon_pauses_restores_then_terminates` through a real daemon), on bubblewrap by e2e `stop_ends_a_running_sandbox_before_the_log_is_sealed` where it is installed, and the refused path with an injected termination outcome (`a_stop_that_cannot_confirm_termination_is_refused_and_held_paused_until_a_retry`). PR #253 review: protocol negotiation by `control::tests::a_new_client_refuses_to_stop_through_a_daemon_that_predates_confirmed_stop` (a 0.18 stand-in daemon; no `stop` is ever sent) and `a_seal_without_a_termination_acknowledgement_is_not_a_successful_stop`; launch/stop serialization by `daemon::tests::a_launch_admitted_before_a_stop_spawns_before_the_stops_scan` (recorded order) and `a_launch_that_stalls_past_a_stop_is_refused_before_it_spawns` (the reviewer's ordering, held on channels); the one-operation restore by `daemon::tests::hold_for_stop_freezes_for_itself_even_with_a_stale_marker_from_before_a_restart`, `a_stop_hold_cannot_be_released_by_resume_or_bypassed_by_a_launch` and e2e `stop_restore_entry_does_not_trust_a_stale_pause_marker`; the fork barrier by `pause::tests::a_child_forked_in_the_scan_to_stop_window_is_frozen_before_the_freeze_is_stable` (injected), `an_orphan_in_the_sandboxs_pid_namespace_is_still_found` and, on real processes, `terminate_leaves_no_orphan_of_a_tree_that_forks_during_the_stop` (fails 5 in 6 runs with the barrier disabled); `Finished` only after confirmed termination and the incomplete stop by `daemon::tests::working_then_a_refused_stop_then_resume_is_refused_and_only_the_retry_finishes` and e2e `a_stop_through_the_daemon_records_finished_only_after_the_termination`. The delegated cgroup-freezer/`cgroup.kill` path remains unverified here: CI has no delegated cgroup |
| G14 | Recording an observation never gates enforcement, and a gap in the record is never silent. The file watch, the session proxy's decision recorder and the agent hook broker hand their observations to the session's single log writer through bounded per-source queues; the writer drains them *while the command runs* (every 250 ms or every 256 observations, whichever comes first) and flushes the remaining tail exactly once before `CommandFinished`. Each record keeps its source's observation time, and a later drain never reorders or rewrites what an earlier one appended. Each producer is quiesced before its own final drain — stopped from accepting new work and waited on, for a bounded time, until what it already had in flight has reached its queue — so a decision or claim completed across that cutover is flushed rather than discarded with the producer, and a producer that cannot be quiesced in time is itself recorded as a gap. Giving up on it is one atomic step rather than two racing ones: the session proxy and the hook broker close their cutovers with the same queue primitive, which seals the queue and counts whatever is still in flight under the one lock a producer has to take to hand its observation over, so each in-flight producer is classified exactly once — accepted into the final batch, or counted in the gap marker, never both. *In flight* is the window in which an observation may still be produced and has not been handed over yet, never the producer's whole lifetime: the session proxy announces each connection it accepts before it serves it and retires it at its verdict, so a tunnel still relaying is not a decision outstanding (it was recorded when the connection was allowed) while a connection that has not decided yet is. Nothing can join that set once the cutover has begun, because announcing a connection and stopping the proxy are mutually exclusive: once the call that stops the proxy has returned, an acceptor still parked on the listening socket can no longer announce anything, so it cannot serve anything either — a guarantee that holds however the acceptor is scheduled and whether or not it was woken out of its blocking accept. So the count the seal takes is complete, and the single terminal drain that immediately follows it carries every gap rather than leaving one for a drain that never happens. A queue that is full refuses the new observation rather than evicting one already accepted, counts the refusal under the same lock that saw the queue full (so the observations and their refusals are one atomic drain epoch), and the next drain appends `ObservationsDropped { source, dropped, capacity }` right after the batch it accompanies — so an incomplete window is bounded by its neighbours and visible in every observer mode, for every bounded source including the agent hook broker. A proxy thread's decision call does one lock, one length comparison and returns, so allow/deny is decided and answered in real time however far behind the log writer or a UI consumer has fallen. Every producer is owned by one RAII value: a launch that fails before or during the child still stops the threads, removes the run directory and its sockets, and appends what was already recorded | 9, 14 | live-observation e2e | Proven end to end on bubblewrap by `file_and_network_observations_reach_the_log_before_the_command_exits` (`crates/ward-daemon/tests/live_observations.rs`: a sandboxed command writes a file and makes an approved loopback request, then blocks on a barrier only the test can release; both records are asserted on the log, and `CommandFinished` asserted absent, before the barrier is released — and the terminal flush is then shown to append neither of them a second time) and by `a_launch_that_cannot_run_still_shuts_its_producers_down`; the bound and its marker by `observe::tests` and `egress::tests::a_full_recorder_records_an_overflow_marker_instead_of_losing_decisions`; the cutover by `observe::tests::a_hook_claim_completed_across_the_cutover_is_still_flushed` and `observe::tests::a_producer_that_cannot_be_quiesced_is_marked_as_a_gap_not_ignored`; the exactly-once classification *at* the cutover's own boundary — a producer released only after the seal, which must not be both flushed and marked — by `observe::tests::a_hook_claim_that_lands_after_the_seal_is_counted_once_not_twice`, `egress::tests::a_proxy_decision_that_lands_after_the_seal_is_counted_once_not_twice` and `observe::tests::every_producer_racing_the_seal_is_accounted_for_exactly_once`; the gap being in the batch the *single* terminal drain already took — sealed, drained, and only then released, which is the order the session itself uses — by `egress::tests::a_decision_still_in_flight_at_the_seal_is_a_gap_in_the_batch_the_drain_already_took` and `egress::tests::the_terminal_flush_returns_the_network_gap_for_a_decision_it_gave_up_on`; the set being closed by stopping the proxy whatever happens to the connection that wakes its acceptor — an acceptor parked at its announcement while the socket file is unlinked, so the wake provably fails — by `egress::tests::a_connection_announced_while_the_wake_fails_is_accounted_for_exactly_once`; the boundary being the verdict and not the connection, so a live relay is never a false gap, by `egress::tests::a_connection_leaves_the_pending_set_at_its_verdict_not_at_the_end_of_its_relay` and `ward-proxy`'s `every_accepted_connection_is_announced_before_it_is_served_and_retired_once`; the single drain epoch by `observe::tests::a_refusal_is_never_counted_into_a_drain_that_did_not_take_the_batch`; and the hook broker's gap being visible in Quiet by `hooks::tests::a_dropped_hook_claim_is_visible_in_quiet` |

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

## 6. Security proofs: the backlog, now cleared

[ADR-0019](decisions/ADR-0019-authority-freshness-intervention.md) decision 6: the
remaining proofs came before more desktop polish, and the list is now empty. Every
guarantee above that was stated but not yet backed by a probe now is one — a
`ward selftest` row or an end-to-end test with a hostile workload, reproduced by CI
on every pull request, and named in the guarantee's Status column. The probes live as
`ward selftest` groups or `security-tests/` workloads, not here; this section records
what the last two showed. Numbering continues the threat model's §8 list; ST-023..025
are taken there.

ST-029 `hostile-verifier-corpus` (G9) left this list: it is proven by the `verifier
corpus` group of `ward selftest` (§6.2), reproduced by CI on every pull request. It
runs the verifier over nine hostile repositories — a build/test command that reaches
for the network, the host and the CAS; a test overwritten in the worktree; output that
forges a passing summary; a runaway workload; a symlink pointing out of the tree — and
each is contained, its verdict what the trusted test set says rather than what the
repository says.

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

### 6.2 Delivered: the `verifier corpus` group of `ward selftest`

ST-029 left the backlog as nine rows of one `ward selftest` group, reproduced by CI on
every pull request (`hostile_verifier_corpus_is_contained` in
`crates/ward-daemon/tests/e2e.rs`; the group and its judges are
`crates/ward-daemon/src/selftest/verifier_corpus.rs`). Each row is a hostile
*verifier* repository — a `.tamperward/config.yml` whose `verify.command`, and any
planted files, attempt one attack — built under a private temp base with its own
content-addressed store, then run through the real verifier (`ward_daemon::verify`:
snapshot the worktree as the candidate, overlay every protected path from the trusted
entry snapshot, run the command in the disposable bubblewrap sandbox with *no egress
socket* and the host toolchains bound read-only, kill it past its `budget_secs`). The
command stands in for hostile repository content the trusted command happens to run (a
build script, a test harness). Verdicts use the same vocabulary as every other group:
`DENIED` when the sandbox contained the attack, `REACHED` when it escaped (none does),
`CANNOT-MEASURE-HERE` when this host cannot enforce the guarantee, never a false pass.
Where feasible a row also demonstrates the attack would succeed without the guard: the
host canary is a real file the harness reads directly, and the overlay restores the
strict test over the weakened one the fixture wrote.

| Row | What the hostile repository does | Proof (`DENIED` when) |
| --- | --- | --- |
| ST-029 `network-egress` | Its command opens a raw TCP socket to `8.8.8.8:53` | The connect has no route: the verify sandbox is `--unshare-net` with loopback only and, unlike a session launch, is given no egress socket at all. No bash to open the socket is `CANNOT-MEASURE-HERE` |
| ST-029 `read-host-path` | Reads the host canary file, the CAS, `/etc/shadow` and `$HOME` by absolute path | None is readable: they are never mounted into the sandbox. The harness reads the canary directly, so its absence inside is containment, not a bad target |
| ST-029 `write-outside-scratch` | Writes to a read-only system bind (`/usr`) and to real host paths outside the scratch tree | The system bind rejects the write and no host path outside the disposable scratch is created (writes to the sandbox's own ephemeral tmpfs root vanish with it and do not count) |
| ST-029 `no-persistence` | Writes `PWNED` and mutates a tracked file inside the run | The user's worktree and the immutable entry snapshot are byte-for-byte unchanged (the run is over a materialised copy), and a second verify's freshly materialised tree carries no trace of the first |
| ST-029 `runaway-budget` | Runs an infinite loop under a one-second budget | The wall-clock budget kills it (`budget of 1s exceeded`) and the run fails: the host is not hung |
| ST-029 `resource-cgroup` | Reads the memory and pid cgroup limits in force | A finite `memory.max`/`pids.max` would be `DENIED`; the 0.1 bubblewrap backend applies no cgroup limit (ADR-0002 selects `crun` for the production host, which does), so this host reports `CANNOT-MEASURE-HERE` with the observed values rather than running a destructive fork bomb |
| ST-029 `protected-test-overlay` | Weakens a protected test in the worktree so it would pass, and runs it | The verifier overlaid the trusted bytes from the entry snapshot, so the strict test runs and still fails: the weakened test never granted a pass (the scratch copy is the strict bytes, not the weakened ones the fixture wrote) |
| ST-029 `exit-code-authority` | Prints a fake `test result: ok. 999 passed` then exits non-zero | The verdict is the command's exit code, not text it printed: the summary parser reads the 999 yet the run fails. Only a non-zero exit or a timeout can fail, and no printed line can forge a pass |
| ST-029 `symlink-host-escape` | Plants a worktree symlink at a host path and follows it | The snapshot captures it as a symlink and `materialize` writes it as a symlink (never following it or copying the target's content); inside the mount namespace the absolute target resolves to nothing, so the canary is unreachable and its secret never appears in the output |
