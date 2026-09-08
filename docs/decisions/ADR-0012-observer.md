# ADR-0012 — Observer: TUI first, one event API, Ward Shell panel later

## Decision
The observer is implemented first as a Rust TUI (`ward watch`, `ward replay`) in
Phases 1–5, consuming the `wardd` event subscription API. The Ward Shell's agent activity
panel (Phase 5–6) consumes the *same* API and shares view-model code from
`ward-observer`. Modes Quiet/Live/Step-through are `wardd` behaviour (holds and filters),
not UI behaviour; the UI only renders and answers approvals.

## Alternatives
- GUI first.
- Web-based observer.
- Observer with direct read access to session directories.

## Advantages
- A TUI is usable over SSH, in the portable runtime, and before the desktop exists;
  the design language's activity rows are text-native anyway.
- Step-through in `wardd` means approvals are enforced even if no UI is attached
  (request times out → deny).

## Disadvantages
- Two renderers to maintain (mitigated by shared view models).

## Security consequences
- Read-only by construction: the observer socket has no mutating operations except
  `Approve/Deny`, which requires the user's uid and is itself an event.
- Rendering sanitisation (ST-020) lives in `ward-events` ingest, not in each UI.

## Performance consequences
- TUI redraw budget one frame per event batch; subscription latency budget in
  `event-model.md`.

## Why selected
It de-risks the event model early with real users and keeps the desktop work focused on
identity rather than plumbing.

## How it will be validated
Latency CI; usability review at Phase 2 with two external developers.

## Implemented

`ward watch` is the observer's first renderer, a client of the session daemon's
subscription (ADR-0015). It has two modes over one data path
(`client::watch_records`, one `EventRecord` per message):

- **Line mode** (`--plain`, or whenever stdout is not a terminal): one observer row
  per record on stdout until the log is sealed (exit 0) or Ctrl-C (exit 130). Pipes
  and `| head` work as before.
- **TUI** (`--tui`, or the default on a terminal): a full-screen view built with
  `ratatui` over `crossterm`. A trust bar on top carries the session's state in its
  colour (marker and state words: verified green for `offline`, restricted amber for
  every limited mode, red for `open`, dim once the log is sealed) and names the
  session, project, network mode, credentials granted, observer mode and daemon
  state (`LIVE` / `SEALED`). The main pane is the activity stream with the same
  columns and verb colours as line mode, newest at the bottom; `j`/`k`, the arrows,
  `PageUp`/`PageDown` scroll and pause following, `End` re-follows. The status line
  carries `files changed · commands · network allowed / denied · claims`, derived
  from records rather than rendered rows, and the key hints. `q`, `Esc` and Ctrl-C
  quit with exit 0. When the daemon closes the stream the bar shows `SEALED` and the
  view stays until `q`. A missing daemon is reported before the terminal is touched;
  raw mode and the alternate screen are undone on every exit path by a guard.

`--from <seq>` and `--all` apply in both modes. The view model (`ward-cli/src/tui.rs`:
`Model`, `Counters`, `Header`, `Action`, `trust_tone`) is pure and tested off-screen
against ratatui's `TestBackend`; the row columns and colour roles come from
`ward_daemon::render::{observer_cells, kind_cells, Tone}`, which line mode also uses,
so the two renderers cannot drift.

Not yet there: the replay timeline strip of `event-model.md` §8, step-through
prompts (approvals are answered in the agent's own prompt today, `agent-integration.md`
§4), a Quiet/Live filter switch in the UI (the mode is the manifest's), and the
shared `ward-observer` view-model crate the Ward Shell panel will consume; the model
lives in `ward-cli` until a second consumer exists.
