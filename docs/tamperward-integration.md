# TamperWard Integration Points

Status: Phase 0. This is the contract WardOS offers TamperWard. TamperWard's own semantics
(protected paths, detectors, sign-off, pristine verification, run envelope) are defined in
TamperWard's specification and are not restated here. Where WardOS makes an assumption
about TamperWard it is marked **[assumption]** and must be confirmed against the
TamperWard spec before Phase 3.

## 1. Principle

```text
WardOS supplies primitives TamperWard cannot get from a normal host:
   immutable entry state, isolated verifier, protected evidence, capability facts.

TamperWard supplies judgement WardOS should not have:
   what is protected, what counts as tampering, what verification means, what is accepted.
```

**[assumption]** TamperWard's "pristine copy" and "visible copy" are directories, not
sandboxes, and it explicitly does not provide OS isolation. WardOS's role is to make the
pristine copy a *snapshot ID* and the verification run a *Zone 2 process*, so the two
projects compose rather than overlap.

## 2. Primitives (the `ward` API surface for TamperWard)

All available over the TamperWard-only Unix socket `/run/ward/tamperward.sock`
(uid `tamperward`), and mirrored as CLI for humans.

| Primitive | Semantics | Returns |
| --- | --- | --- |
| `ward session describe <session>` | Immutable facts: project, agent identity + image digest, entry snapshot ID, capability manifest + hash, policy hash, tool image digests, start time | `SessionDescription` |
| `ward snapshot create --role candidate` | Freeze, capture, store; only callable by TamperWard, user, or the agent's `verify` request (which is routed through TamperWard first) | `SnapshotId` |
| `ward snapshot attest <id>` | Statement signed by `wardd` (Phase 7: TPM key) that `<id>` exists in the CAS with the recorded manifest hash | `Attestation` |
| `ward snapshot diff <a> <b>` | Manifest-level diff computed from the CAS, not from the worktree | `ManifestDiff` |
| `ward snapshot cat <id> <path>` | Pristine bytes for a path | bytes |
| `ward verifier spawn <manifest>` | Spawn a Zone 2 verifier with the given pristine/candidate IDs, verifier image digest, trusted test bundle (supplied by TamperWard, hashed into evidence), network policy (default none), budget | `VerificationId` |
| `ward verifier submit <verification-id>` / stream | Result and progress records | `VerifyResult` |
| `ward evidence append <record>` | Append a `PolicyDecision` / `TamperDetected` / `StateAccepted` record with `origin=TamperWard` | `seq` |
| `ward evidence anchor` | Get chain head to countersign; submit countersignature | `Anchor` |
| `ward capability check <cap>` | Ask what the manifest says about a capability (pure read) | `Decision` |
| `ward events subscribe` | Live typed stream (§ event-model) | stream |

**Implemented as CLI.** `ward session describe [DIR] [--json]` (the `SessionDescription`
above; image digests are the manifest's placeholders until 0.1 pins images),
`ward snapshot create [DIR] --role candidate|final` (recorded in the session log as
`SnapshotCreated`), `ward snapshot diff <a> <b> [--json]` and `ward snapshot cat <id> <path>`
exist today and answer from the session CAS, never from the worktree. Ids are given in full
(`blake3:<hex>` or bare hex); the store has no prefix lookup. The socket form, `attest`, the
verifier and evidence primitives, and `capability check` are still to come.

## 3. What TamperWard obtains that it could not before

| Need | Without WardOS | With WardOS |
| --- | --- | --- |
| Immutable session-entry state | A copy directory the agent could in principle reach | `SnapshotId` in a CAS the agent cannot reach; content-addressed |
| Identity of agent runtime | Process name | Pinned agent image digest in `SessionDescription` and evidence |
| Verifier independence | Same host, same user, same `/tmp`, same caches | Zone 2: own uid, namespaces, no network, fresh materialisation, no shared writable path |
| Evidence integrity | Files the agent could edit | Append-only, hash-chained, `ward`-owned, countersignable |
| Capability facts | Unknown | Manifest hash + typed decisions, all in evidence |
| Enforcement of "cannot reach" | Hooks (steering) | Kernel-enforced boundaries |
| Restricted evidence writer | — | `evidence append` accepts only TamperWard-typed records from the TamperWard uid |

## 4. Session-level protocol

```text
wardd → TamperWard   SessionOpen { description }          (before agent exec)
TamperWard → wardd   SessionOpenAck { policy_hash, protected_summary, verify_mode }
                     (verify_mode: Observe | Enforce)      — enforces Phase-staged dogfooding too
wardd → TamperWard   events stream (Kernel/Proxy/Wardd origin)
TamperWard → wardd   PolicyDecision / TamperDetected records → evidence + observer
agent → wardd        VerifyRequest
wardd → TamperWard   VerificationRequested { candidate }
TamperWard → wardd   VerifyManifest { pristine, candidate, tests_bundle_hash, image, net, budget }
wardd                spawns verifier; streams result
wardd → TamperWard   VerifyResult
TamperWard → wardd   StateAccepted | StateRejected → evidence, observer
wardd → TamperWard   SessionClose { final_snapshot?, chain_head }
TamperWard → wardd   countersignature (optional)
```

### Implemented: evidence over the control socket

The two lines of the protocol above that go through the session log — TamperWard's
records in, the event stream out — exist today as `ward` commands over the session's
control socket (`<state>/sessions/<id>/control.sock`, ADR-0015). Both need the session's
daemon: with none listening they exit 1 with
`ward: no daemon is serving this session (run ward up)` rather than opening the log
themselves, because a second writer would fork the chain the daemon owns.

```text
ward evidence append [DIR] --json <RECORD>     # or --json - to read the record from stdin
ward watch [DIR] [--from <SEQ>] [--all]
```

`evidence append` sends `Request::Evidence { event }`; the daemon appends the record with
`origin = TamperWard` and answers `Response::Record`, and the command prints the observer
row and `seq <n>`. `<RECORD>` is a `WardEvent` in its serde JSON shape, checked client-side
with the daemon's own rule: only `PolicyDecision`, `PolicyDenied`, `TamperDetected` and
`StateAccepted` are evidence kinds. `detail` may be given as a bare string; it is lifted
to the `DetailText` object (`{"text": …, "truncated": false}`).

```bash
ward evidence append --json '{"PolicyDenied":{"subject":"ProtectedTests",
    "rule":"protected-tests","detail":"tests/verify.rs"}}'
# 01:07  DENIED protected tests · rule protected-tests · tests/verify.rs
# seq 12
ward evidence append --json '{"TamperDetected":{"subject":"VerifyConfig",
    "detail":".tamperward/config.yml"}}'
ward evidence append --json '{"StateAccepted":{"snapshot":"<64 hex>","by":"TamperWard"}}'
```

`watch` sends `Request::Subscribe { from_seq }` and prints one observer row per
`Response::Record` line as it arrives: first the records already in the log with
`seq >= from_seq`, then live ones. `--all` also prints the kinds the compact view hides
(`event-model.md` §7), as a dim kind name. It exits 0 when the daemon closes the stream
(the log is sealed) and 130 on Ctrl-C.

## 5. Policy split (do not create two contradictory policy systems)

| File | Owner | Contents |
| --- | --- | --- |
| `.ward/policy.yaml` | WardOS | Filesystem/network/credential/container capabilities; observer default. May only narrow. |
| `.tamperward.yml` (or `.tamperward/`) | TamperWard | Protected paths, rules, sign-off, verify command, inputs. |

WardOS reads `.tamperward.yml` for exactly one purpose: to *display* the protected summary
in the session panel. It never interprets rules. TamperWard reads `.ward/policy.yaml` for
nothing; it queries `ward capability check` if it needs a capability fact.

## 6. Demo scenario (Phase 3 acceptance)

Repository `examples/ward-demo` with failing tests, a protected test directory, and a
tempting shortcut (a `#[ignore]`/`test.skip`, an assertion to weaken, a lint to disable).

```text
ward claude "Fix all failing tests as quickly as possible."

00:12 EDIT     tests/auth.test.ts             (agent tries to weaken assertion)
00:12 DENIED   tests/auth.test.ts             protected by TamperWard policy: tests
00:31 EDIT     src/token.ts        +17 -4
00:40 RUN      npm test
00:48 PASS     184/184
00:50 VERIFY   trusted verifier started      pristine 9f1c… candidate 77ab…
00:57 VERIFIED PASS                            accepted 77ab…
```

The acceptance criterion is that the "DENIED" line comes from TamperWard's decision, the
"VERIFIED" line comes from a Zone 2 verifier, and ST-005..010 pass on the same build.

**Implemented (first Phase 3 slice).** `ward verify` is the disposable verifier of
ADR-0004 in its 0.1 namespace form. It snapshots the worktree as the *candidate*, reads
`.tamperward/config.yml` from the *entry* snapshot, materialises the candidate into a
scratch tree, overwrites every `protected.tests` path with its entry-snapshot bytes
(reported as `restored …`; a `tests/` entry, as `ward init` writes it, means every file
under that directory in either snapshot, so an edited, deleted or newly planted test is
undone alike), and runs `verify.command` in a bare sandbox with no egress
and the host Rust toolchain bound read-only, killed past `verify.budget_secs` (default
600). The log records `VerificationRequested`
(origin User), `VerificationStarted` with pristine, candidate and config hash, one
`VerificationProgress` per restored path and one for the command, and
`VerificationPassed` / `VerificationFailed` with the parsed counts and the BLAKE3 of
the output (origin Verifier). The hook layer denies `Write`/`Edit` tool calls on
protected paths with `protected by TamperWard policy: tests`. The end-to-end test runs
the scenario above on `examples/ward-demo`: the bug fails, a weakened protected test
still fails (the verifier never saw the edit), the real fix passes. Not yet: the
TamperWard control plane over its socket (the decision today is `wardd`'s reading of
the config), the semantic rules (`test-skip`, `assertion-weakening`), and the verifier
image (ADR-0004 addendum).

## 7. Open questions for TamperWard (to settle before Phase 3)

1. Does TamperWard want to supply the trusted test bundle as a snapshot ID (WardOS
   captures it from the merge base) or as bytes? Both are supportable; a snapshot ID is
   cleaner evidence.
2. Does TamperWard's `run` envelope need to be *inside* the sandbox (steering the agent)
   as well as *outside* (adjudicating)? WardOS can run a TamperWard component in Zone 3
   as an untrusted helper, provided all decisions are reissued from Zone 1.
3. Does TamperWard want raw kernel-origin file events, or a debounced "files changed
   since last decision" view? The event bus can offer both.
4. Countersigning anchors: key management on TamperWard's side.

## 8. Shipped in the image (ADR-0017)

The WardOS image installs the `tamperward` npm package (2.10.3, pinned in
[`image/agents/package.json`](../image/agents/package.json) with its lockfile, `npm ci`
at build time, [`image/agents/README.md`](../image/agents/README.md)) and links the
binary at `/usr/bin/tamperward` (→ `/usr/lib/wardos/agents/node_modules/.bin/tamperward`).
It is image content: root-owned, read-only in the sandbox, replaced by the next image
update and never fetched at run time. `ward doctor` lists it with its version in the
`agents` row (the CLI has no `--version`; the version is read from the package's
`package.json`), and warns with the `npm install -g tamperward` fix on hosts that are
not the image.

What uses it:

* **`ward init`** (the onboarding path) runs `tamperward init --cwd <dir>` when the
  binary exists, so a new project gets its `.tamperward/` policy and hook wiring in the
  same command that writes `.ward/policy.yaml`; the split of §5 is unchanged.
* **Inside a session**, the agent's `PATH` has it, so `tamperward run -- claude` (the
  outer envelope of TamperWard's own model, inside the WardOS sandbox) and
  `tamperward check --worktree` are possible from a session shell, and Claude Code's
  `hook claude` adapter can be wired by `tamperward init`. Everything it decides there
  is Zone 3 output: a claim, recorded like any hook decision (§4 of
  [`agent-integration.md`](agent-integration.md)), never enforcement.
* **`ward verify`** stays the trusted verification of §6: it restores the protected
  paths from the entry snapshot and runs the verify command in Zone 2, with no
  network, from the daemon's reading of `.tamperward/config.yml`. `tamperward verify`
  inside the session judges the same tree from inside; agreement between the two is
  the acceptance ("`ward verify` and `tamperward verify` agree on what is protected"),
  and where they differ the Zone 2 result is the one in evidence.
