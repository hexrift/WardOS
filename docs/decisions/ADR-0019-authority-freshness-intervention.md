# ADR-0019 — Authority, freshness, intervention, evidence: the next leap is legibility, not decoration

## Decision
The architecture stays as it is (capability manifest, host-side credential broker,
content-addressed snapshots, offline verifier, single-writer hash-chained evidence, the
WardOS/TamperWard split, measured performance). The visual language stays as it is.
What changes is what a human can *read* from the desktop at a glance, in this order:

1. **Verification is snapshot-bound and its freshness is shown.** `VERIFY` has five
   states and the bar shows exactly one: `—` never verified, `◐` verifying candidate
   `7c01…`, `✓` candidate `7c01…`, `~ STALE` the worktree has changed since `7c01…`,
   `✗` the candidate failed. Green disappears the moment the tree differs from the
   verified candidate. Freshness is decided by content, not heuristics: the shell
   digests the worktree with the snapshot crate's incremental hash cache and compares
   it with the candidate id in the last `VerificationPassed` record. Clicking the
   segment shows the verified candidate, the time, the current digest, the change
   count, the TamperWard, tests and integrity results.
2. **Approvals separate the agent's claim from Ward's authority.** An approval shows
   three blocks: the *destination* (sanitised by the daemon), *requested by agent*
   (the reason, verbatim, labelled as the agent's words), and *Ward will allow* (what
   the policy and the credential rules actually grant if the user says yes: network
   destination, method, credential and its scope, repository, lifetime). Anything Ward
   derives looks authoritative; anything the agent says is visibly the agent's.
3. **Pause is a host primitive.** `ward pause` (and one key on the desktop) freezes the
   session's processes, closes the proxy to new traffic, suspends credential
   injection, holds queued approvals, and records the enforcement in the log, as one
   operation. Its exits are `resume`, `stop` keeping the workspace, and `stop`
   restoring the entry state. Interruption belongs to the host, not to the agent.
4. **Temporary authority stays visible while it exists.** A session-scoped grant
   changes the bar (`NET restricted · github+`, `GRANTS 1`) until the session ends;
   clicking it lists the current authority: filesystem, network, every temporary grant
   with its scope and lifetime, and the standing denials.
5. **Approval load is a security metric.** E-13 measures approvals per agent-hour,
   approve and deny rates, decision time, allow-once followed by the same request,
   allow-session rate, requests contained by the sandbox, requests caused by missing
   policy, switches to unrestricted network and launches outside `ward`. E-14 puts
   ten to twenty real tasks through the agent bare and through WardOS and measures
   completion, time, interruptions, prompts, legitimate work blocked, retries,
   time to `✓ VERIFIED`, and whether the user can then say what the agent could reach,
   which credentials it used, what it changed and whether the current state is
   verified. No targets until the data exists.
6. **The remaining security proofs come before more desktop polish**: ST-018 freeze
   before capture (built on the pause primitive), ST-022 TLS interception, raw TCP and
   SOCKS paths, loopback and control-socket surfaces, DNS rebinding and pinning, a
   hostile verifier repository corpus.
7. **One source of truth for the project's status**, checked in CI, so no document
   claims a phase of its own; and the primary install path is a release binary with a
   checksum (a signature when the signing key exists), with the shell bootstrap
   labelled as the convenient development installer.

Deferred, with a trigger: a semantic observer view (task, changes, activity,
security, important events; the raw stream one click away) when sessions or agents
multiply; task-shaped network profiles (`offline`, `test`, `develop`, `github`,
`packages`, `cloud-read`) derived from E-08's observed requirements, not from
intuition.

## Context
An outside review of the repository, taken seriously because it read the code and
the documents rather than the screenshots, concluded that the architecture and the
visual language are right and that the next gap is legibility: a `✓ VERIFIED` that can
outlive the state it verified, an approval whose most prominent line is the agent's
own claim, no host-owned way to stop everything at once, grants that vanish from view
the moment they are given, and an observer that is a prettier `tail -f`. It also
pointed at drift: twelve documents still say "Phase 0" under a README that says
Phase 6, and a README that offers `curl | bash` a few lines above the claim that
nothing is fetched by `curl | sh`. The evidence it cited matches ours: Anthropic
reports its sandboxing cut permission prompts by 84 % and that users approve about
93 % of prompts; usable-security research finds repeated warnings habituate; OWASP's
AI secure-coding guidance asks for tests of raw TCP, SOCKS, loopback and metadata
paths, not only HTTPS egress. The four comprehension questions of E-14 are the
product's real acceptance test.

## Consequences
* `ward-shell-core` gains a verify state machine and an authority model; the bar and
  the panels render them; `ward-snapshot` exposes a digest-only capture.
* The daemon's approval carries a derived `authority` block; `ward session pending`
  and `wardos-approve` show it; the design language's §10 is rewritten to match.
* The daemon gains `pause`/`resume`, the proxy a paused state, the events crate
  `SessionPaused`/`SessionResumed`; the desktop a `wardos-pause` command and a key.
* `docs/experiments.md` gains E-13 and E-14; `docs/security-model.md` and the roadmap
  carry the proof backlog as the next security work.
* `docs/status.toml` is the one status; a CI check fails any document that states a
  phase itself.
* The image-size issues (#67 to #70) proceed in parallel: they are not polish, they
  are the reason a first pull takes ten minutes.

## Amendment — stop is termination, then sealing (#145 item 5)
Decision 3 names `stop` as one of pause's exits; it did not say what `stop` does to a
session that is *not* paused. Until #145 item 5 it sealed the log and left a running
sandbox running, unobserved: a log-only closure presented as a stop. Now:

* `ward stop` (`Request::Stop`) is termination of the session's workloads followed by
  evidence sealing, from running or from paused. The daemon freezes the session's
  sandbox trees (or keeps the pause's freeze), confirms the freeze stable, kills every
  process, and confirms each is gone within a bound (`pause::STOP_SETTLE`), rescanning
  for anything forked meanwhile. `WorkloadsTerminated { ended, pending,
  barrier_confirmed }` is the durable stop result: completion requires
  `pending == 0 && barrier_confirmed`; only then is the agent recorded `Finished`,
  the approvals closed, `SessionEnded` appended and the log sealed. A confirmed retry
  after an earlier incomplete stop records this result even when it ends zero additional
  processes, so replay can see `STOP?` clear before the seal.
* **Launch admission and stop are one serialized lifecycle operation** (#145 item 2 as
  it bears on stop). Every sandbox launch re-checks admission under the session lock
  the pause/stop path takes (`pause::admit_launch`) and holds it across the `bwrap`
  spawn; a stop writes a permanent stop marker under that lock before it scans. A
  launch either exists before the scan (and is ended by it) or is refused.
* **The fork barrier.** Nothing is killed until the freeze is confirmed stable: every
  held process stopped, and a rescan taken after that finding nothing new
  (`pause::stabilize`), so a child forked in the scan-to-`SIGSTOP` window cannot be
  orphaned by its parent's kill. Membership is the tree of the session's `bwrap` roots
  *and* the sandbox's own pid namespace, which still holds a reparented child.
* A stop that cannot confirm termination is refused, never reported as done (#145
  item 4): the log stays unsealed, no `Finished` is recorded, and the session is held
  **for the stop**. This includes both known survivors (`pending > 0`) and the
  membership-barrier case where all currently-known PIDs later disappear but
  `barrier_confirmed == false`; the latter is still recorded durably rather than
  normalized into success. That is an incomplete stop, not a pause: its processes may
  already have taken `SIGKILL`, so `ward resume` refuses it; `ward stop` retries.
* Log-only closure stays available as its own, explicit operation: `Request::Seal`.
* `ward stop --restore-entry` is one daemon-owned pause→restore→stop operation
  (`Request::HoldForStop`): the daemon freezes the sandboxes itself — never trusting a
  pause marker a restarted daemon did not write — or takes over its own pause, writes
  the stop marker, and keeps the hold until the stop; no other client can resume it in
  between. The restore runs only once the hold is confirmed stable.
* **Protocol negotiation.** `Request::Stop` exists on 0.18 daemons too, where it only
  seals. A client asks `Request::Capabilities` first and sends `Stop` (or `HoldForStop`)
  only to a daemon that names the feature; the answer must also positively acknowledge
  the termination (`Sealed { ended: Some(n) }`). An older daemon is refused with
  nothing sent, and the user is told to end it so the client can stop the session
  itself.

Still open under #145: the persisted `Pausing`/`Stopping`/`Incomplete` lifecycle (the
stop marker and the in-memory stop hold are its stop-side precursors, not that state
machine), reconciliation of an interrupted stop across a daemon restart (a restarted
daemon refuses `resume` once the stop marker exists, but does not rebuild the hold's
freeze until the next `stop`), and per-component acknowledgement from the proxy. The
fork barrier is confirmed only when every known process is frozen and a stable
rescan closes the membership set within `pause::FREEZE_SETTLE`. A failed late cgroup
migration invalidates that barrier and falls back to `SIGSTOP`; a timeout remains a
durable incomplete stop even if every currently-known PID is later killed. A child that
somehow escapes both the tracked tree and the sandbox's PID namespace remains outside
this membership proof; real `bwrap --unshare-pid` sandboxes are specifically structured
so descendants stay in that namespace.

## What does not change
No more colour, no shields, no closer resemblance to Omarchy, no custom kernel, no
departure from the terminal-first workflow, no replacement of the Rust shell model,
no blurring of WardOS isolation and TamperWard semantic enforcement.
