# ADR-0015 — `wardd` as the single log writer; `ward` commands as producers

## Decision
A session's hash-chained log has exactly one writer: a per-session `wardd` process
that owns the chain and the `LogWriter`, listens on the session's control socket
(`<state>/sessions/<id>/control.sock`, mode 0600) and serves a small JSON-lines
protocol. `ward` commands keep running sandboxes, proxies and hook listeners **in
their own process** (ADR-0013: stdio and the terminal stay local) but they no longer
append to the log themselves: every event goes through a `Sink`, which is the local
chain when no daemon is running (today's behaviour, the fallback) or the control
socket when one is. TamperWard and the observer use the same socket: evidence records
with `origin = TamperWard` are appended by the daemon on TamperWard's behalf, and a
subscriber receives records as they are written.

## Alternatives
1. Keep every `ward` invocation an independent writer that re-opens the log
   (Phase 1). Two concurrent writers fork the chain; nothing external can append.
2. File locks plus head re-sync on every append. Serialises writers but still gives
   TamperWard no live stream and no process that outlives a command.
3. Move launches themselves into the daemon (full ADR-0009). Requires pty forwarding
   for interactive agents; deferred, and not needed for a single writer.

## Advantages
- One chain head in one process: no forks, no lock dance, a place to anchor.
- The control socket is the TamperWard primitive surface (`tamperward-integration.md`
  §2) and the observer's subscription API (`event-model.md` §6) at once.
- The fallback keeps every command working with no daemon at all, so the CLI and
  the tests do not depend on process lifecycle.

## Disadvantages
- One more process per session, spawned by `ward up` and reaped by `ward stop`; a
  crashed daemon means the next command falls back to the local chain, which is safe
  (the log is the truth) but loses the live stream until `ward up` runs again.
- JSON on the socket is roomier than the binary wire format; records still go to
  disk in the bounded wire encoding, and the socket carries the same typed values.

## Security consequences
- The socket is uid-owned; `origin = TamperWard` records are accepted only from the
  `Evidence` request, which is limited to the evidence kinds (`PolicyDecision`,
  `PolicyDenied`, `TamperDetected`, `StateAccepted`). A producer cannot claim a
  kernel origin for an event it did not observe any more than before: the origin
  set a `ward` command may append is the one it appends today, and the sandbox
  never sees the socket (it lives outside every bind).
- Peer-uid checks for a distinct `tamperward` uid arrive with Phase 4 privilege
  separation; in 0.1 all peers are the session owner.

## Performance consequences
- One Unix-socket round trip per event on the warm path, well inside the observer
  latency budget; producers keep no chain state and never re-read the log.

## How it will be validated
- Unit tests for the protocol and both sinks; an end-to-end test that runs a command
  through a live daemon, appends evidence from a second process and reads it back
  in order from the sealed log; `ST-016` and `ST-009/010` unchanged.
