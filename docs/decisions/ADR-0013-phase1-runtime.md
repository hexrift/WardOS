# ADR-0013 — Phase 1 runtime: in-process session, bridged ids

## Decision
The Phase 1 `ward` CLI drives the session lifecycle **in-process** through the
`ward-daemon` library rather than over a control socket to a long-running `wardd`.
The daemon/socket split (ADR-0009) is deferred to Phase 2. Cross-crate id
duplication is bridged in one place (`ward-daemon::ids`).

## Alternatives
1. In-process library behind the CLI (selected for Phase 1).
2. Full `wardd` daemon + Unix control socket from day one.
3. A single crate holding all shared id/types that every other crate depends on.

## Advantages
- Fastest path to a runnable, demonstrable product with real isolation and a real
  event log, with no IPC on the warm path.
- Module boundaries (`session`, `sandbox`, `render`, `ids`) are drawn so the Phase 2
  socket split is mechanical: `Session` becomes the daemon's per-session actor.

## Disadvantages
- No cross-invocation session state yet: each `ward` command is a self-contained
  mini-session (it opens, acts, seals its log). A persistent supervisor arrives in
  Phase 2.
- Each Phase 1 crate defines its own id newtypes (`SessionId`, `SnapshotId`,
  `Blake3Hash`, …) so it could be built and tested independently by parallel work.
  They meet only in `ward-daemon`, which converts between them by string/bytes. This
  is safe but is friction; Phase 2 should promote the id types into a single shared
  crate (candidate: `ward-events`) that the others depend on.

## Security consequences
- The in-process model does not weaken any Phase 1 guarantee: isolation is enforced
  by the sandbox (namespaces, unmounted host paths), not by process separation
  between the CLI and the session logic. Zone separation for the verifier and
  TamperWard (Phases 3–4) still requires separate processes and is unaffected.

## Performance consequences
- No socket round-trips; `ward status` and `ward run` start a session directly.

## How it will be validated
- `ward-daemon` unit tests plus a bubblewrap-guarded end-to-end test
  (`session_runs_and_seals_a_log`, `selftest_blocks_every_probe`), and the ST-*
  probes run by `ward selftest`.
