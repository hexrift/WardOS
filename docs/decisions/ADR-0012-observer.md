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
