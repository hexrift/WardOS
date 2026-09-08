# The WardOS desktop

Status: specification and build plan for ADR-0016. Identity and rules:
[`design-language.md`](design-language.md). Compositor decision:
[ADR-0007](decisions/ADR-0007-desktop-and-shell.md). Feature set decision:
[ADR-0016](decisions/ADR-0016-desktop-feature-set.md).

The desktop is Hyprland plus the Ward Shell. Until the shell has its own toolkit (E-10),
its surfaces are rendered by Waybar (the trust bar), fuzzel (the command centre and every
menu) and mako (notifications and approvals), all fed by `ward-shell` and themed from the
same TOML token files. Everything a user can do has a key, a menu entry and a `wardos-*`
command. This document is the contract the `desktop/` tree implements.

## Layout

```text
desktop/
  bin/          wardos-* commands (bash, `set -euo pipefail`, shellcheck-clean) → /usr/bin
  lib/          wardos.sh: shared functions (paths, menu backend, notify, theme, launch)
  hyprland/     hyprland.conf + the files it sources (bindings, input, monitors, envs,
                autostart, windows, looknfeel) → /usr/share/wardos/hypr, /etc/xdg/hypr
  config/       one directory per component: waybar, mako, fuzzel, hyprlock, hypridle,
                hyprsunset, swayosd, foot, alacritty, btop, fastfetch, nvim, xcompose,
                gtk, chromium, bash → /usr/share/wardos/config (copied to ~/.config on
                first login by wardos-first-run; re-applied by wardos-refresh)
  themes/       <id>.toml token files (+ optional <id>/backgrounds/) → /usr/share/wardos/themes
  theme/        Rust crate `wardos-theme`: renders a theme into every component's format
  webapps/      default web apps (name, url, icon)     tuis/  default terminal apps
  systemd/      user units (battery monitor, screensaver, bar) and the autologin drop-in
  tests/        run.sh (shellcheck + every *.test.sh with a mocked PATH)
  install.sh    apply the desktop on an existing Fedora (Workstation, Silverblue, Kinoite)
  shell/        the ward-shell binary (already present)
```

User state: `~/.config/wardos/` (theme choice, rendered theme in `theme/current/`, user
overrides), `~/.local/share/wardos/` (web app profiles, installed themes, fonts),
`~/.local/state/wardos/` (toggles, last screenshot, record pid). Image-owned defaults
under `/usr/share/wardos/`; user files always win.

## Commands

One family, one help convention (`wardos-<name> --help` prints the usage block at the top
of the script). Menu-facing commands take their choices from arguments too, so every
menu path is scriptable and testable.

| Command | Does |
| --- | --- |
| `wardos-menu [path…]` | The menu tree (below), fuzzel-rendered; `wardos-menu style theme` jumps in |
| `wardos-menu-select` | dmenu-style picker used by everything; backend `WARDOS_MENU_BACKEND=fuzzel\|stdin` |
| `wardos-keys` | Key bindings viewer: parses `hyprland/*.conf`, searchable, one line per bind |
| `wardos-launch <what>` | `terminal`, `browser [url]`, `editor [file]`, `files`, `tui <name>`, `webapp <name>`, `or-focus <class> <cmd…>` |
| `wardos-capture <what>` | `screenshot [region\|window\|output]` (grim+slurp, satty to annotate), `record [region\|output]` toggle (wf-recorder), `color` (hyprpicker) |
| `wardos-toggle <what>` | `nightlight` (hyprsunset), `idle` (hypridle), `bar` (waybar), `screensaver`, `notifications` (mako dnd) |
| `wardos-power <what>` | `lock`, `suspend`, `relaunch` (Hyprland), `restart`, `shutdown`, `menu` |
| `wardos-theme <verb>` | `list`, `current`, `set <id>`, `next`, `install <git-url>`, `remove <id>`, `render [id]`, `bg next` |
| `wardos-font <verb>` | `list`, `current`, `set <name>` (mono for terminals, sans for UI) |
| `wardos-webapp <verb>` | `install <name> <url> [icon-url]`, `remove <name>`, `list`; chromium `--app`, one profile each |
| `wardos-tui <verb>` | `install <name> <cmd>`, `remove <name>`, `list`; a `.desktop` that opens the terminal with a class |
| `wardos-install <what>` | `app <flatpak-id>`, `package <rpm>` (bootc layering, says so), `webapp`, `tui`, `theme`, `font`, `dev <lang>` (mise), `service <name>` |
| `wardos-remove <what>` | the inverse of every install |
| `wardos-setup <what>` | `wifi` (nmtui), `bluetooth` (bluetui or bluetoothctl), `audio` (pulsemixer), `power` (power profile), `monitors`, `input`, `keys`, `fingerprint` (fprintd), `fido2` (pam-u2f), `printers`, `dns`, `timezone`, `config <component>` |
| `wardos-update [what]` | `bootc upgrade` + `flatpak update` + `wardos-refresh`; `--check` for the bar indicator |
| `wardos-refresh [component]` | re-copy a component's default config into `~/.config`, keeping a backup |
| `wardos-notify <title> [body]` | notification with the WardOS defaults; `--done` for "finished" toasts |
| `wardos-approve` | shows a pending approval from `wardd` and answers it (`y`/`s`/`n`) |
| `wardos-battery-monitor` | low-battery notifications (timer unit) |
| `wardos-screensaver` | terminal text effects on idle, any key exits |
| `wardos-share <file>` | serve a file on the LAN with a QR code (python http.server + qrencode) |
| `wardos-first-run` | first login: copy configs, pick a theme, `ward doctor`, show the keys |
| `wardos-version` | image and tool versions (`bootc status`, `ward --version`) |
| `wardos-about` | the About surface (fastfetch with the WardOS logo) |

Rules: a command never edits a file it did not create without a backup next to it
(`<file>.bak`); root is asked for with `pkexec` (desktop) or `sudo` (terminal) and only
by `wardos-update`, `wardos-install package`, `wardos-setup fingerprint|fido2|dns|timezone`.

## Menu

`Super + Space` is the command centre (`design-language.md` §13) and `Super + Alt + Space`
the full menu, which is the command centre's SYSTEM section expanded. One tree:

```text
PROJECTS   …            (ward-shell)
AGENTS     Start Claude · Start Codex · Resume session · Sessions…
SECURITY   Verify current project · Review permissions · Replay last session ·
           Evidence · Snapshots · Grant credential…
SYSTEM     Apps · Capture · Appearance · Connect · Install · Remove · Update ·
           Toggle · Power · Help
  Apps        every .desktop, web apps and terminal apps included
  Capture     Screenshot region / window / output · Record region / output · Colour
  Appearance  Theme · Background · Font · Light or dark
  Connect     Wi-Fi · Bluetooth · Audio · Monitors · Input · Printers · DNS · Power profile
  Install     App (Flathub) · Package · Web app · Terminal app · Theme · Font ·
              Development (ruby, node, bun, go, python, rust, java, elixir, php) ·
              Service (tailscale, dropbox, syncthing)
  Remove      App · Web app · Terminal app · Theme · Font
  Update      System · Configs · Themes
  Toggle      Night light · Idle lock · Bar · Screensaver · Notifications
  Power       Lock · Suspend · Relaunch · Restart · Shutdown
  Help        Keys · Manual · Hyprland wiki · About
```

## Keys

The existing set (`desktop/hyprland/keybindings.conf`) stays. Added, in one file per
group so `wardos-keys` can title them:

| Key | Does |
| --- | --- |
| `Super + Space` / `Super + Alt + Space` | command centre / full menu |
| `Super + K` | keys viewer |
| `Super + Return` / `Super + B` / `Super + E` / `Super + N` | terminal / browser / files / editor |
| `Super + M` / `Super + G` / `Super + D` / `Super + T` / `Super + /` | music / messages / containers / activity / passwords |
| `Print` / `Shift + Print` / `Ctrl + Print` | screenshot region / window / output |
| `Alt + Print` / `Super + Print` | screen record toggle / colour picker |
| `Super + Escape` / `Super + Shift + Escape` | lock / power menu |
| `Super + Ctrl + N` / `I` / `B` / `S` | toggle night light / idle lock / bar / screensaver |
| `Super + Ctrl + V` / `Super + Ctrl + E` | clipboard history / emoji |
| `Super + Shift + T` / `Super + Shift + B` | next theme / next background |
| `XF86*` keys | volume, brightness, media, with swayosd |
| `Super + scroll`, `Super + [` `]` | previous / next workspace |

## Themes

A theme is one TOML file (the existing token model). `wardos-theme render <id>` writes
`~/.config/wardos/theme/current/` with one file per component: `hyprland.conf` (borders,
ground), `waybar.css`, `mako.conf`, `fuzzel.ini`, `foot.ini`, `alacritty.toml`,
`btop.theme`, `hyprlock.conf`, `swayosd.css`, `nvim.lua` (a colorscheme from the tokens),
`chromium.json` (theme colour), `gtk.css` and `colors.env` (every token as `WARDOS_*`),
plus `background` (a path, or `solid:<hex>` for swaybg `-c`). Every component's config
`include`s its fragment; `wardos-theme set` re-renders and signals each running
component (hyprctl reload, `killall -SIGUSR2 waybar`, `makoctl reload`, ...).

Shipped: the four official variants, plus palette themes mapped onto the nine tokens
(Tokyo Night, Catppuccin, Nord, Gruvbox, Everforest, Kanagawa, Rosé Pine, Matte Black,
Flexoki), each marked `source = "palette"` and observing §3's rules (no gradients,
state colour only on glyphs and markers). Themes from `wardos-theme install <git-url>`
live in `~/.local/share/wardos/themes/`.

## Packages

`image/packages.txt` lists every package the desktop needs, one per line with a comment
naming what it is for. The `Containerfile` installs from it; CI checks every name exists
in Fedora 42 (`dnf repoquery` in a `fedora:42` container) and builds the whole image
with `docker build` on `main`. Applications that are not in Fedora come from Flathub via
`wardos-install app` and the defaults in `desktop/flatpaks.txt`; nothing is downloaded
by `curl | sh`.

## Tests

`desktop/tests/run.sh` shellchecks `desktop/bin/*`, `desktop/lib/*`, `desktop/install.sh`
and runs every `desktop/tests/*.test.sh`. A test puts a directory of mock commands
first on `PATH` (each mock appends its arguments to `$MOCK_LOG`), sets
`WARDOS_MENU_BACKEND=stdin` with `WARDOS_MENU_CHOICE=<answer>`, points `HOME` and `XDG_*`
at a temp dir, and asserts on the log and the files written. Rust parts (the theme
renderer, `ward-shell bar --waybar`) are tested with `cargo test`.

## Parity

Each Omarchy capability, and how WardOS delivers it. ✔ in the last column once the
command, key and test exist on `main`.

| Omarchy | WardOS | Delivered |
| --- | --- | --- |
| Hyprland with tiling, gaps, keybindings | `desktop/hyprland/` | ✔ scaffold |
| Waybar top bar | trust bar rendered by Waybar from `ward-shell bar --waybar` | |
| Walker launcher, clipboard history, emoji | fuzzel + cliphist, `wardos-menu-select` | |
| omarchy-menu tree | `wardos-menu` (SYSTEM section above) | |
| Keybindings viewer | `wardos-keys` | |
| Themes (set, next, install, remove, backgrounds) | `wardos-theme`, TOML tokens rendered per component | |
| Font switching | `wardos-font` | |
| Web apps in Chromium app mode | `wardos-webapp` | |
| TUI apps as windows | `wardos-tui` | |
| Screenshots (hyprshot + satty) | `wardos-capture screenshot` (grim, slurp, satty) | |
| Screen recording | `wardos-capture record` (wf-recorder) | |
| Colour picker | `wardos-capture color` (hyprpicker) | |
| Lock screen, idle, suspend | hyprlock, hypridle, `wardos-power` | |
| Night light | hyprsunset via `wardos-toggle nightlight` | |
| On-screen volume/brightness | swayosd | |
| Notifications | mako | |
| Power menu | `wardos-power menu` | |
| Screensaver | `wardos-screensaver` | |
| Battery monitor | `wardos-battery-monitor` | |
| Wi-Fi, Bluetooth, audio TUIs | `wardos-setup wifi\|bluetooth\|audio` | |
| Power profiles | `wardos-setup power` | |
| Fingerprint, FIDO2 | `wardos-setup fingerprint\|fido2` | |
| Printers, DNS, timezone | `wardos-setup printers\|dns\|timezone` | |
| Install packages / AUR | `wardos-install app` (Flathub), `package` (bootc layer) | |
| Dev environments (mise) | `wardos-install dev <lang>` | |
| Docker + lazydocker | podman, podman-compose, podman-tui | |
| Terminal (Alacritty/Ghostty), bash, prompt, aliases | foot default, alacritty shipped, `config/bash` | |
| Neovim (LazyVim) | neovim with a WardOS config and per-theme colours | |
| btop, fastfetch, lazygit, fzf, ripgrep, fd, bat, eza, zoxide | shipped, configured, themed | |
| Chromium default browser, theme colour | chromium, `chromium.json` fragment | |
| Nautilus | nautilus | |
| Plymouth boot splash | WardOS Plymouth theme | |
| Autologin into Hyprland | getty autologin + uwsm | |
| Full-disk encryption at install | `image/disk.sh --luks` (bootc-image-builder) | |
| omarchy-update, migrations | `wardos-update` (bootc upgrade, flatpak, refresh) | |
| Snapshots and rollback (Limine + snapper) | bootc deployments, `bootc rollback` | |
| Install on an existing Arch | `desktop/install.sh` on an existing Fedora | |
| Share a file over LAN | `wardos-share` | |
| XCompose special characters | `config/xcompose` | |
| Apple display brightness | `wardos-setup monitors` (ddcutil, asdcontrol when present) | |

Then some (WardOS only):

| Feature | Delivers |
| --- | --- |
| Agent state, network, TamperWard and verification in the bar | `ward-shell bar --waybar` |
| Approvals as notifications, answered from the keyboard | `wardos-approve`, daemon hold on `ask` |
| Verify, replay, evidence, snapshots, grants in the menu | `wardos-menu` SECURITY |
| Sandboxed browser profile per project | `wardos-launch browser --project` |
| Package names and the whole image checked by CI | `image/packages.txt`, image build job |
