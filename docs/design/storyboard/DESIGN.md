# WardOS storyboard — DESIGN.md

An interactive preview of the WardOS product idea:

> **Human intent → constrained agent action → visible proof.**

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
| `--ground-2` | `#12151C` | raised graphite (weave, rail panel) |
| `--ground-3` | `#181C25` | windows, receipts |
| `--ink` | `#ECE7DE` | warm off-white — primary type |
| `--ink-dim` | `#8A8780` | muted warm grey — secondary type |
| `--verify` | `#6FB08A` | **restrained** verification green — proof, done states |
| `--intent` | `#8E7CF0` | muted electric violet — **agent intent only** |
| `--cool` | `#6E88AE` | occasional cool neutral blue — keywords, PR tags |
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
| **Rooms rail** | workspaces as words (`BUILD · RESEARCH · REVIEW`), top edge | sliding spring underline; never numbers |
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
