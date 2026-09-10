# ADR-0021 — The Ward Field: a design language for an agentic desktop

## Decision
WardOS adopts a single, recognisable visual system — **Ward Field** — and makes the rest
of the interface subordinate to it. The desktop is designed *around* the loop **human
intent → constrained agent action → verifiable outcome**, not as a themed Hyprland with a
security panel bolted on. Five things are now the identity, in order:

1. **The Ward Field** — the desktop environment itself. Almost-black topography (flowing
   contour lines) that is nearly invisible at rest and reveals relationships between
   intent, files and verification when an agent works. There is no stock wallpaper; the
   field is the ground, so a screenshot is recognisable as WardOS with the logo removed.
2. **Spatial behaviour** — surfaces emerge from where they belong. Command Weave grows
   from the user's locus; a Decision Receipt blooms from the file it concerns; the Proof
   Rail progresses through the operation.
3. **Semantic colour, absolute** — graphite at rest; **violet = agent intent/action**;
   **green = verified outcome**; **amber = review/attention** (the trust states of
   ADR-0019). These colours never become general accents; at rest there is no violet and
   no green anywhere.
4. **Typography and restraint** — Inter (UI) and JetBrains Mono (code), the faces the
   image already ships; quiet until something matters.
5. **The interaction vocabulary** — Command Weave (one intent-reading surface replacing
   launcher/search/terminal/prompt), the Proof Rail (an ignorable step spine, 2–4 px at
   rest), the Decision Receipt (risk made legible, attached to the action), and Workspace
   Rooms as words on a lifecycle — **BUILD · VERIFY · SHIP** — with a `WARD / VERIFIED ↔
   REVIEW` trust pill.

One governing rule constrains all of it: **nothing appears merely to show WardOS is
clever; it appears only because the user needs it now.** Security creates confidence
without demanding attention — TamperWard is invisible infrastructure whose evidence
appears only when useful (e.g. denying an agent's shortcut, with the reason shown).

Coordinate system is **1440×900 (16:10, laptop-native)**; 16:9 is a cinematic crop, not
the design target. Motion is part of the identity and bounded by speed: ~150 ms micro,
~220 ms surfaces, ~260 ms room transitions, always interruptible, opacity-only under
`prefers-reduced-motion`.

This refines — it does not discard — [ADR-0007](ADR-0007-desktop-and-shell.md) (Hyprland +
Ward Shell), [ADR-0016](ADR-0016-desktop-feature-set.md) (feature set) and
[ADR-0019](ADR-0019-authority-freshness-intervention.md) (legibility over decoration), and
it is the visual target [`design-language.md`](../design-language.md) now describes.

## Context
E-09 (first hardware boot) and the "UI isn't intuitive" feedback showed the current
desktop — a competent but generic Hyprland/Waybar arrangement — did not *express* what
makes WardOS different: that agents are visible, constrained and verifiable. It looked
like a rice, and the agent felt bolted on. A design exploration produced a coherent
alternative with a real thesis and one recognisable motif (the field), rather than a
collection of fashionable UI pieces. Locking that thesis now, before more shell work,
stops the desktop drifting into either a generic Linux look or an "AI-operating-system
dashboard".

The direction was prototyped and proven before adoption: the field animation and its
relationship to agent activity were built first (`docs/design/storyboard/ward-field.html`),
because the identity collapses if the field is mediocre; then the full flow
(`docs/design/storyboard/wardos.html`, and an earlier ten-scene cut `index.html`).

## Consequences
* [`docs/design-language.md`](../design-language.md) gains a "Ward Field" section and
  points here; the interaction vocabulary (Weave, Proof Rail, Receipt, Rooms) is the
  target the `ward-shell` surfaces render toward, replacing decorative chrome.
* Rooms become named lifecycle contexts (**BUILD · VERIFY · SHIP**) rather than numbers;
  the trust pill (`WARD / VERIFIED ↔ REVIEW`) is the one status source (ADR-0019).
* Prototypes live under `docs/design/storyboard/` with `DESIGN.md` (tokens, timings,
  components, rationale) and per-scene screenshots; they are the reference, not shipped
  code.
* No stock wallpaper is the default identity; a wallpaper becomes optional, layered under
  a field that stays the signature.
* Implementation is incremental and does not block the reliability→onboarding→
  discoverability work: the field can arrive first as the background (`hyprpaper`/a small
  renderer), then Command Weave replaces the launcher, then the Proof Rail and Decision
  Receipt replace terminal-watching and Allow/Deny modals. E-10 (the shell toolkit)
  remains the gate for native surfaces.

## Alternatives considered
* **Keep the current themed Hyprland and only tidy discoverability.** Cheaper, but leaves
  WardOS visually indistinguishable from any rice and the agent bolted on — the exact
  failure E-09 surfaced.
* **A security-dashboard aesthetic** (panels, meters, always-on monitoring). Rejected by
  ADR-0019 and by the product thesis: it makes the user feel monitored, not in control.
* **Adopt an existing look** (macOS/GNOME/Omarchy conventions). Rejected: none of them are
  built around the intent→action→proof loop, and imitation forfeits identity.
* **Defer any visual decision until E-10.** Rejected: the direction is cheap to prove in a
  web prototype now, and locking it lets every subsequent shell decision serve one thesis
  instead of re-litigating the look each time.

## How it will be validated
* A screenshot of stock WardOS is identifiable as WardOS with the logo removed (the field).
* A novice can, with a mouse, get online, invoke an agent and read its proof; an expert is
  materially faster with the keyboard (Command Weave).
* Security reads as confidence, not alarm: the TamperWard-denied moment is understood
  without a manual, and no permanent monitoring surface is required.
* The field holds 60 fps on the E-09 hardware once GPU acceleration is real (linux-firmware
  / mesa), and degrades to a static field under reduced motion or software rendering.
