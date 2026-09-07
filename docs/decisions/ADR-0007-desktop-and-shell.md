# ADR-0007 — Desktop: Hyprland; Ward Shell in Rust

## Decision
Compositor: **Hyprland** on Wayland. Ward Shell (bar, command centre, session panel,
agent activity panel, approvals, verification display, settings) is written in **Rust**
using a layer-shell-capable toolkit selected by measurement in E-10 (candidates:
`iced` + `iced_layershell`; GTK4-rs + `gtk4-layer-shell`). No Electron, no browser
runtime, no Qt/QML unless E-10 shows the Rust candidates cannot meet budgets. Visual and
interaction identity per [`../design-language.md`](../design-language.md).

## Alternatives
- Sway (wlroots, stable, fewer effects).
- niri (scrollable tiling, Rust).
- A WardOS-owned compositor on smithay (Rust).
- GNOME/KDE with extensions.
- Existing bars/launchers (waybar, wofi, rofi) configured with a theme.

## Advantages
- Hyprland: fast, keyboard-first, mature IPC for workspace/bar integration, active
  ecosystem, in Fedora repos.
- Rust shell components share `ward-events` types with `wardd` and the TUI; one event
  API, no privileged access in the UI.
- Owning the bar/launcher is what makes the identity ("the desktop understands agents")
  possible; reusing waybar/wofi would make WardOS look derivative.

## Disadvantages
- Hyprland's own C++ codebase and release cadence are outside WardOS control; API changes
  (hyprland-ipc) need tracking.
- Building a bar/launcher/panel set is real work; scope is limited to the components that
  carry the identity, with terminal/browser/editor being third-party.
- niri's model is interesting for agent+editor layouts but its ecosystem is smaller;
  revisit after 0.1.

## Security consequences
- Ward Shell never receives privileged filesystem access; approvals are events. The shell
  is in Zone 0 like any user process.
- The Wayland socket is never mounted into Zone 3.

## Performance consequences
- Budgets: launcher < 16 ms, workspace < 8 ms, idle shell < 0.5 % CPU. Rust layer-shell
  apps with wgpu or tiny-skia backends are expected to meet these; E-10 confirms.

## Why selected
Hyprland satisfies keyboard-first and polish with the least compositor work. A custom
smithay compositor is the long-term option if Hyprland becomes a constraint, but is not a
0.1 goal (non-goal: rebuilding Linux components). The shell must be WardOS-owned because
it *is* the product's visible identity.

## How it will be validated
E-10 prototypes; performance CI on shell latency; design review against
`design-language.md` at the Phase 5 and Phase 6 gates.
