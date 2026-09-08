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

## What does not change
No more colour, no shields, no closer resemblance to Omarchy, no custom kernel, no
departure from the terminal-first workflow, no replacement of the Rust shell model,
no blurring of WardOS isolation and TamperWard semantic enforcement.
