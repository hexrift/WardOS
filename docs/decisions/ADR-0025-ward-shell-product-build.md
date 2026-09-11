# ADR-0025 — Building the real Ward Field / Ward Shell (the product), in phases

## Decision
WardOS commits to building the Ward Field / Ward Shell described in ADR-0021 and
`docs/design-language.md` as the shipped product — a desktop that *is* WardOS rather than
a themed stock Hyprland — and to getting there in ordered, shippable phases so every
release boots, is on-brand, and moves the live desktop closer to the storyboard
(`docs/design/storyboard/wardos.html`). Two product properties the user named explicitly
are first-class here: **one terminal command surface (`ward …`)** and **end-to-end
first-run onboarding** (timezone, keyboard, locale, account, network), neither of which
needs the native-surface toolkit and both of which land early.

This does not supersede ADR-0016 (the interim stock-desktop composition) or ADR-0021 (the
Ward Field design) — it sequences their completion. ADR-0016's third-party renderers
(Waybar, fuzzel, mako) stay until each is *replaced* (not re-themed) by a native surface,
which remains gated on **E-10** (the layer-shell toolkit choice).

### Phases

- **Phase A — one command surface (`ward …`).** `ward <verb>` runs the desktop command
  `wardos-<verb>` when it is on `PATH`, so the terminal has a single verb namespace: the
  secure session core (`ward init/up/verify/doctor/claude/…`) and the desktop verbs
  (`ward theme`, `ward setup`, `ward install`, `ward update`, …) are one `ward`. The
  `wardos-*` scripts remain the implementations and keep working under their own names;
  `ward` is the front door. *This ADR ships Phase A.*
- **Phase B — first-run system onboarding.** A calm, on-brand, keyboard-first first-boot
  flow that sets timezone, keyboard layout, locale, and (where the image was built without
  one) the user account, plus network — the gap identified on E-09 (today these are baked
  at build time or defaulted to `wardos`/UTC/us/en_US). Runs once, before or as the first
  thing after the greeter, styled to the host palette; idempotent, skippable, re-runnable.
  Does not need E-10.
- **Phase C — the Ward Field ground.** Replace the static wallpaper with the living
  near-black topography (§2a): almost invisible at rest, lifting to show intent ↔ files ↔
  verification while an agent works, settling green when verified; static under reduced
  motion or software rendering; 60 fps target on E-09. Begins as a background renderer
  (per ADR-0021's "field-as-background first"), not yet a full compositor surface.
- **Phase D — the Command Weave.** Replace the fuzzel launcher with the single
  intent-reading surface on `Super` (projects, agents, verify, apps, search, the
  agent prompt).
- **Phase E — Proof Rail, Decision Receipt, Workspace Rooms (native shell, E-10).** The
  proof spine that blooms into an inspectable timeline instead of terminal-watching; the
  risk-legible receipt attached to the affected file (where TamperWard evidence surfaces);
  the BUILD · VERIFY · SHIP rooms with the one trust pill. These are the native
  layer-shell surfaces of `ward-shell`'s own making and land only once E-10 picks the
  toolkit.

## Context
E-09 (the first hardware boot) confirmed what ADR-0021 anticipated: the shipped desktop is
"a competent but generic Hyprland/Waybar arrangement… looked like a rice, and the agent
felt bolted on." The security core (`ward` CLI, daemon, sandbox, proxy, verifier) and the
shell *view models* (`ward-shell-core`) are real and tested; the *pixels* of the Ward
Field, Command Weave, Proof Rail, Decision Receipt and Rooms exist only as storyboards,
and there is no on-device first-run system configuration. The user's direction was to
"begin the real Ward Field / Ward Shell build as the next focus… the final product with
all bells and whistles, end-to-end onboarding (timezone, keyboard, …), the theme entirely
WardOS, and terminal commands under `ward …`." Phasing keeps that ambition shippable:
each phase is independently useful and independently reversible, and the two phases that
do not need the E-10 toolkit (A, B) come first so the product feels unified and
self-configuring long before the native surfaces exist.

The one architecturally significant, expensive-to-reverse decision is the **E-10 toolkit**
for the native surfaces of Phases C–E (a wgpu/Smithay layer-shell client, a GTK4 +
gtk4-layer-shell surface, an iced/Slint app, …). It is deliberately **left open here** and
owned by a future ADR, informed by what Phases C and D learn; nothing in Phases A–B
depends on it.

## Consequences
- **Phase A (this ADR).** `ward` gains an external-subcommand bridge: any non-built-in
  verb runs `wardos-<verb>` on `PATH`, replacing the process (its exit status, signals and
  terminal are the caller's). The verb must be a bare word (no `/`, no leading `-`) so
  `ward` can only reach the `wardos-*` family. `ward --help` documents the passthrough;
  `ward <verb> --help` reaches the desktop command's own help. Unknown verbs get a clear
  error naming `wardos-<verb>`. The `wardos-*` names keep working unchanged, so nothing
  that calls them (autostart, menus, `.desktop` files, tests) has to move. Unit tests
  cover the verb validation, the `PATH` resolution, and the clap capture; `docs/desktop.md`
  gains a "`ward` as the command surface" note. Feature → MINOR: `0.4.x` → `0.5.0`.
- **Later phases** each land as their own PR(s) with their own ADR where a decision is
  made (notably the E-10 toolkit before Phase E). Phase B introduces first-run system
  units/flow; Phase C a field renderer; Phases D–E the native surfaces.
- The interim renderers (ADR-0016) and the design language (ADR-0021) remain authoritative
  until each surface is replaced; semantic colour stays absolute (violet = intent, green =
  verified, amber = review) across every phase.
