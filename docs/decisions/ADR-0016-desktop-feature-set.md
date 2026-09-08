# ADR-0016 — Desktop feature set: everything Omarchy does, on Fedora, the WardOS way

## Decision
WardOS ships a complete, opinionated Hyprland desktop, feature-equivalent to Omarchy and
then some, before the Ward Shell's own layer-shell toolkit (E-10) exists. Until E-10, the
Ward Shell's view models (`ward-shell-core`) are **rendered by third-party components**
that read what the shell emits: Waybar draws the trust bar from `ward-shell bar --waybar`
(one JSON module per segment), fuzzel draws the command centre and every menu from
`ward-shell launcher --lines` and `wardos-menu`, mako draws notifications and approvals.
The identity stays WardOS's: what is shown, its order, words, glyphs and colours come
from the shell and the theme files; the components are pixel renderers, replaced, not
re-themed, when E-10 lands.

The desktop is one tree, [`desktop/`](../desktop.md), installed by the image into
`/usr/share/wardos` and `/etc/xdg`, and by `desktop/install.sh` onto an existing Fedora.
Its user-facing commands form one family, `wardos-*`, listed in
[`docs/desktop.md`](../desktop.md); every feature is reachable from the keyboard, from
the command centre and from the menu.

Feature parity is measured in [`docs/desktop.md` §Parity](../desktop.md#parity): each
Omarchy capability names the WardOS command, key, package and test that delivers it.
"Then some" is the agent layer: session state in the bar, approvals as desktop
notifications answered from the keyboard, verification in the menu, credential grants
from the command centre, a sandboxed browser profile per project, and an image built and
package-checked by CI.

## Alternatives
- Wait for E-10 and the Rust shell before shipping any desktop. Rejected: the shell's
  surfaces are already decided and tested as view models; the pixels are the last step,
  not the first, and users can install the OS today.
- Copy Omarchy's configuration (waybar, walker, its themes and menu tree) and reskin it.
  Rejected by `design-language.md` §15: the components can be shared, the presentation
  cannot, and Omarchy targets Arch (pacman, AUR, yay), not an immutable Fedora host.
- A GNOME or KDE session with extensions. Rejected in ADR-0007.

## Advantages
- Every Omarchy feature is available on a Fedora bootc host with the WardOS agent layer
  on top, from one command family with one theme model.
- Rendering through Waybar/fuzzel/mako today costs no shell code that E-10 will throw
  away: the shell emits models, the components draw them, the toolkit replaces them.
- Fedora packages come from the distribution repositories (checked by CI against a
  `fedora:42` container) and Flathub, never `curl | sh`, never an AUR helper.

## Disadvantages
- Three third-party components carry the shell's look until E-10; their theming is
  generated from the theme TOML by `wardos-theme render`, so a token change is one edit,
  but the components' own limits (Waybar CSS, fuzzel INI) bound what can be expressed.
- Omarchy's Arch-only pieces (yay, pacman hooks, Limine + snapper snapshots) map onto
  bootc equivalents (`bootc upgrade`, image rollback) with different semantics; the
  parity table says which.
- The desktop tree is large and mostly shell; it is kept honest by shellcheck, a
  bash test harness with mocked commands, and a CI job that runs both.

## Security consequences
- No desktop component gains privileged access. `wardos-*` commands run as the user;
  the ones that need root (`wardos-update`, `wardos-setup fingerprint`) call `pkexec` or
  `sudo` explicitly and say so. Nothing in `desktop/` reads a session's worktree.
- Approvals (`design-language.md` §10) become real: the daemon holds an `ask` decision,
  the desktop shows it, and only a keyboard answer (or timeout) releases it. Deny is the
  default on timeout.
- Web apps run in a browser profile per app under `~/.local/share/wardos/webapps`,
  isolated from the user's main browser profile.
- Theme install from a git URL is a clone into the user's theme directory plus a
  render; the TOML is data, no theme ships executable code.

## Performance consequences
- Budgets stand (ADR-0007): menu visible < 16 ms warm (fuzzel is measured at ~10 ms),
  idle shell < 0.5 % CPU (Waybar polling intervals ≥ 5 s, the ward modules event-driven
  from `ward-shell bar --waybar --follow`).

## Why selected
Users asked for the Omarchy experience on WardOS; the shell already knows what to show;
Fedora's repositories carry the whole Hyprland stack. Rendering through existing
components now, with the toolkit replacing them later, is the shortest path that keeps
the identity intact and the code base honest.

## How it will be validated
CI: shellcheck on every script, the bash harness in `desktop/tests`, Rust tests for the
theme renderer and the shell's Waybar output, a `fedora:42` package existence check for
`image/packages.txt`, and a full `docker build` of the image on `main`. Manually, at the
Phase 6 gate: boot the image in QEMU and on the reference hardware and walk the parity
table.
