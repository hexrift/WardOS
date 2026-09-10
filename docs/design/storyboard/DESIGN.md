# WardOS storyboard — DESIGN.md

An interactive preview of the WardOS product idea:

> **Human intent → constrained agent action → visible proof.**

> **`wardos.html` is the definitive realization** of the refined art direction: the
> `BUILD · VERIFY · SHIP` rooms, the `WARD / VERIFIED`↔`WARD / REVIEW` trust pill, the Y ward
> glyph, WARD GATE ("unlock the room, not the whole machine"), CALIBRATE (Navigation / Agent
> autonomy / Motion), and the signature **TamperWard-denied moment** — an agent's shortcut
> (delete a failing test) is blocked, and it corrects course. Eight screens over the proven
> Ward Field. `index.html` is the earlier ten-scene cut; `ward-field.html` is the field
> proving ground. All three share the same tokens and field engine.

Live artifact: published from `index.html`. Screen-recordable demo route: append `#demo`
to the URL (hides the dev controller, autoplays ~60 s). Screenshots of every scene are in
`screens/`.

This is built as a **believable preview of the real product**, not marketing art. Every
scene is a *state of one desktop*, not ten separate mockups — the transitions between
states carry as much of the idea as the states themselves.

---

## Why these choices exist

The brief's hardest constraint is emotional: the user must feel **calm, capable, fast, in
control** — never *monitored, overwhelmed, or trapped in a security console*. Security is
present but must never dominate. Three product decisions follow from that and shape
everything below:

1. **Chrome fades; work is the centre of gravity.** The desktop is nearly empty at rest.
   Status is a single quiet line. There is no dock, no Start menu, no widget sea. (Focus
   Canvas)
2. **One surface does everything.** Launcher, search, terminal, files, settings and the
   agent prompt collapse into Command Weave, which reads *intent*, not keywords.
3. **Proof replaces surveillance.** Agent activity is a narrow, ignorable rail and, for
   consequential actions, a receipt attached to the thing being changed — not a terminal
   to watch or a modal to fear.

---

## Visual tokens

Committed single dark world (an OS surface), every colour painted explicitly so it holds
on any host ground.

| Token | Hex | Role |
|-------|-----|------|
| `--ground` | `#0B0D10` | mineral black, faint blue-graphite bias — the field |
| `--ground-2` | `#141821` | raised graphite (weave, rail panel) |
| `--ground-3` | `#181C25` | windows, receipts |
| `--ink` | `#ECE7DE` | warm off-white — primary type |
| `--ink-dim` | `#8A8780` | muted warm grey — secondary type |
| `--verify` | `#6FB08A` | **restrained** verification green — proof, done states |
| `--intent` | `#8E7CF0` | muted electric violet — **agent intent only** |
| `--cool` | `#5E7CA6` | occasional cool neutral blue — focus ring, PR tags (a lighter `#8FA8CC` for small code keywords to hold contrast) |
| `--edge` | `rgba(236,231,222,.09)` | hairlines |

**Colour discipline.** Violet means *agent intent* and nothing else; green means *verified*
and nothing else. Neutrals do the rest. No gradients, no glass everywhere, no neon
borders, no huge rounded rectangles. Depth comes from luminance, one soft shadow spent by
role, and the Ward Field — not from chrome.

### The Ward Field
A `<canvas>` behind everything renders ~22 slow contour lines (layered sines) plus, during
agent scenes, bezier **threads** connecting an *intent* node to the *files* it touches and
to *verification*. At rest it is ~5% opacity and almost invisible; on agent intent it lifts
to ~22% and shifts graphite → violet; on verification it shifts violet → green. This is the
motif you would recognise with the logo removed. `prefers-reduced-motion` freezes it to a
faint static layer.

## Typography

Grounded in WardOS's *actual* shipped faces (`rsms-inter-fonts`, `jetbrains-mono-fonts`):

- **Inter** — all UI. Hierarchy from weight (300–600) and tracking, not size alone; display
  text is tight (`-.02em`), uppercase labels are loose (`.14–.2em`).
- **JetBrains Mono** — code, terminal, paths, deltas, keycaps, tabular data.

No decorative or "hacker" type. Nothing below ~11px is load-bearing.

## Components

| Component | What it is | Signature detail |
|-----------|------------|------------------|
| **Rooms rail** | workspaces as words (`BUILD · VERIFY · SHIP`), top edge | current room lit, siblings recede; never numbers, never tabs |
| **Status** | one quiet line, top-right | a single state pulse: green ready / violet working |
| **Focus Canvas** | the active window, centred, inset | fades in with a small spring; everything else recedes |
| **Command Weave** | one universal input | expands from the locus; shows a few *intent* interpretations + context/capability chips; ↵ launches |
| **Proof Rail** | ultra-thin step spine hugging the window | collapsed = a column of dots; expands to a legible floating panel; done=green, active=violet |
| **Decision Receipt** | a receipt attached to the file | `+/−` delta, Why, Verification, Inspect / Allow once — makes risk legible, not scary |
| **Diff** | compact inspect popover | grows from the receipt |
| **Verified chit** | collapses all proof to one seal | click reveals TamperWard evidence (progressive disclosure) |
| **Result** | outcome + Review / Commit / **Undo** | Undo is first-class — powerful actions stay reversible |
| **Next-up** | "what should I work on next?" | real repo signals: PR #98, failed CI, agent result |

## Animation timings

Motion always explains a spatial or state change; nothing animates just because it can.

| Class | Duration | Easing | Used for |
|-------|----------|--------|----------|
| micro | 150 ms | `cubic-bezier(.22,.61,.36,1)` | hovers, selection, hint fades |
| surface | 210 ms | ease / spring | weave, receipt, diff, rail expand |
| spatial | 300 ms | `cubic-bezier(.34,1.36,.5,1)` (spring) | window entry, room underline, result |

Objects move from where they logically originate: Command Weave scales up from the locus;
the Decision Receipt grows from the affected file (with a short violet tether); the Proof
Rail progresses top-down through the operation; rooms slide by spatial relationship. All
transitions are interruptible (scrubbing/next cancels timers). `prefers-reduced-motion`
(and the in-app toggle) drop spatial travel for opacity-only.

## Interaction principles

- **Power-user core, beginner-safe surface.** Keyboard is fastest (`Space` play/pause,
  `←/→` scenes; in the product, `Super` holds reveal shortcuts, `Super+Space` is Weave) but
  every important thing is visible and mouse-operable: rooms are clickable, the weave rows
  are clickable, Inspect/Allow/Undo are buttons.
- **Progressive disclosure.** The Verified chit is one line until you ask for the evidence;
  the Proof Rail is dots until you look. Nothing shouts.
- **Optimistic, immediate feedback.** Every action acknowledges instantly; the OS is never
  locked by agent activity — you can move while the agent works.
- **Reversibility builds trust.** Undo is a first-class action on the result, not buried.

## Modes

- **Auto** — plays the 10-scene, ~60 s sequence (durations sum to 60).
- **Manual** — dev controller (Prev / Play / Pause / Next / scene selector / Restart /
  reduced-motion), plus real interactions inside scenes.
- **Reduced motion** — OS setting or the toggle; opacity-only, field frozen.
- **Responsive** — a fixed 1440×810 stage scaled + letterboxed to any viewport (works at
  1440×900, 1920×1080, 2560×1440).
- **`#demo`** — hides the controller and autoplays, for screen recording.

## Scene map (≈60 s)

`01` Boot 3s · `02` First-run 7s · `03` Login 3s · `04` Focus Canvas 5s ·
`05` Command Weave 7s · `06` Agent work 9s · `07` Decision Receipt 6s ·
`08` Verification 6s · `09` Result 5s · `10` Flow 9s.

## From prototype to product

Built as one self-contained page (vanilla state machine + CSS transitions + a canvas
field) rather than a framework, because the Artifact sandbox forbids remote assets and
this keeps it at 60 fps with zero load cost. The architecture maps 1:1 to the production
target (React + TypeScript + a spring library): each scene is a desktop *state*, each
component a view fed by the same tokens — exactly how `ward-shell` renders the real bar,
menu and panels from shared TOML tokens today.

## Prove the field first — `ward-field.html`

Because the whole identity collapses if the Ward Field is mediocre, it is prototyped on its
own — `ward-field.html`, a proving ground — before any launcher, settings, onboarding or
window chrome. It renders real **marching-squares topography** over an evolving scalar field
that swells and ripples *around the work locus*, driven by a live agent-activity state
machine (idle → intent → acting → verifying → verified) with tuning knobs (density / flow /
energy) so the identity can be dialled in. Field states in `screens/field-*.png`.

Refinements now treated as rules (from art direction, applied here and binding on the
product):

- **Identity hierarchy:** (1) Ward Field — the environmental signature; (2) spatial
  behaviour — things emerge from where they belong; (3) semantic colour; (4) typography and
  restraint; (5) the interaction vocabulary (Command Weave / Proof Rail / Receipts).
- **Semantic colour is absolute.** At rest there is *no* violet and *no* green anywhere —
  pure graphite. Violet means agent intent/action and nothing else; green means verified
  outcome and nothing else. Even the status dot obeys this (neutral → violet working →
  green verified); Rooms use ink only.
- **The field is the desktop.** No stock wallpaper — almost-black topography reacting to
  work is the ground, so stock WardOS is recognisable by the field alone. A wallpaper is
  optional, not the identity.
- **Gradients live only inside the canvas** (energy falloff, edge light-attenuation) so the
  field reads spatial, never diagrammatic — never in UI chrome, buttons or panels.
- **Spatial causality.** Threads and the Decision Receipt originate from the work locus and
  the affected file — the receipt *blooms from the file* with a tether — not from the centre.
- **Rooms are locations, not tabs.** The current room is lit with `{ }` braces and full ink;
  inactive rooms almost disappear. No selected-button underline.
- **Proof Rail is 2–4 px at rest.** A structural hairline that blooms only when there is
  something worth showing; if it ever reads as a permanent sidebar, the concept has failed.
- **Speed is identity.** ~150 ms micro, ~220 ms Command Weave, ~250 ms Rooms; everything
  interruptible; nothing "floats in beautifully" over half a second.
- **Coordinate system is 1440×900 (16:10, laptop-native).** 16:9 is a cinematic *crop* for
  the demo film, not the design target — a ThinkPad/MacBook-class display must not feel
  cramped vertically.
- **The governing rule:** *nothing appears merely to show WardOS is clever; it appears only
  because the user needs it now.* This is what keeps the design out of the
  "AI-operating-system dashboard" trap.

## Invariants & enforcement

These are treated as invariants, not aesthetics, and are checked by
`check-invariants.sh` (run it from anywhere; it greps all three prototypes):

- **Semantic colour is absolute.** `--intent` (violet) appears only for agent intent/action
  (the weave input + selected route, the acting line, the acting proof-rail node); `--verify`
  (green) only for a genuinely verified outcome (passed tests, the outcome seal, done rail
  nodes, the verified trust pill). `--amber` is review/attention (the trust pill in VERIFY,
  the Decision Receipt, the denied node). At rest the desktop is graphite + warm off-white:
  the glyph, syntax strings and decorators, route markers, idle status dot and the resting
  Proof Rail carry **no** violet or green. State is never colour-only — every coloured state
  also carries text.
- **No glass, no chrome gradients, no remote fonts.** No `backdrop-filter`; no CSS
  `linear-/radial-gradient` in UI chrome (the Ward Field's `ctx.createRadialGradient` energy
  falloff/attenuation is the sole, deliberate exception, inside the canvas); Inter and
  JetBrains Mono are named (the faces WardOS ships) with fallbacks — never fetched.
- **Command Weave originates from the locus.** JS measures the focused line and blooms the
  weave from it (`transform-origin` at the caret), with a centred fallback only if no locus
  exists — never a hard-coded centre.
- **Decision Receipt is anchored to its cause.** JS anchors it to the affected line with a
  tether; it is not a fixed-coordinate card.
- **Proof Rail is a 2 px graphite trace at rest**, blooming into the panel only while the
  agent works, settling back toward neutral after.
- **Rooms are locations** (`{ BUILD }` lit, VERIFY/SHIP receded) — no tabs, no underline, no
  `ROOM 01`. `BUILD · VERIFY · SHIP` is the one vocabulary across all files.

Coordinate system is 1440×900 (16:10); motion budget ~150 ms micro / ~220 ms surfaces /
~260 ms rooms, interruptible, opacity-only under reduced motion (also driven by the CALIBRATE
Motion choice). Field drift scales with agent activity — near-still at rest.

> CI wiring of `check-invariants.sh` is a follow-up: `verify.yml` is the TamperWard-protected
> merge authority and is intentionally not modified from a design PR.

## Quality bar (self-check)

- **Recognisable with the logo removed?** Yes — the Ward Field + words-not-numbers rooms +
  spatially-attached receipts are the identity, not any panel style.
- **AI embedded in the OS, not a chatbot panel?** Yes — intent enters through Command Weave
  and surfaces as a rail and receipts in the workspace; there is no chat sidebar.
- **Confidence without demanding attention?** Yes — proof is a chit and a rail; TamperWard
  evidence appears only when asked for.
- **Novice with a mouse, expert faster with the keyboard?** Both paths exist for every
  important action.
- **Still modern in 2030?** No trend chrome (glass/neon/gradient) to date it — restraint and
  motion instead.
