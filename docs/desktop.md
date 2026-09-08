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
  systemd/      user units (battery monitor, approval listener, swayosd) and the autologin drop-in
  flatpaks.txt  default Flathub applications, one id per line with its purpose
  tests/        run.sh (shellcheck + every *.test.sh with a mocked PATH)
  install.sh    apply the desktop on an existing Fedora (Workstation, Silverblue, Kinoite)
  shell/        the ward-shell binary (already present)
```

`config/` maps onto `~/.config` one directory per component, with the exceptions the
tools impose: `hyprlock`, `hypridle` and `hyprsunset` go to `~/.config/hypr/`, `gtk` to
both `~/.config/gtk-3.0/` and `~/.config/gtk-4.0/`, `xcompose/XCompose` to `~/.XCompose`,
`chromium/chromium-flags.conf` to `~/.config/chromium-flags.conf`, and
`bash/profile.d-wardos.sh` is the image's `/etc/profile.d/wardos.sh` (the other `bash/`
files are sourced from `/usr/share/wardos/config/bash` unless `~/.config/bash/` overrides
them; `~/.config/wardos/bash-override` opts out entirely). `hyprland/hyprland.conf` only
sources: `envs`, `monitors`, `input`, `looknfeel`, `windows`, `autostart`, `bindings`, then
the theme fragment last so the theme's colours win.

On the image, and on an existing Fedora through `desktop/install.sh`, the tree is placed
by [`image/install-desktop.sh`](../image/install-desktop.sh) (table in
[`image/README.md`](../image/README.md#the-desktop-in-the-image)): `bin/` → `/usr/bin`,
`lib/` → `/usr/lib/wardos`, `hyprland/` → `/usr/share/wardos/hypr` with `/etc/xdg/hypr`
a link to that directory (so `source = ./envs.conf` resolves), `config/` →
`/usr/share/wardos/config` with `/etc/xdg/<component>` links for the ones that read
`XDG_CONFIG_DIRS` (waybar, foot, mako, fuzzel, btop, fastfetch) and
`gtk/settings.ini` copied to `/etc/xdg/gtk-3.0` and `gtk-4.0`, `bash/profile.d-wardos.sh`
→ `/etc/profile.d/wardos.sh`, `themes/`, `webapps/`, `tuis/`, `flatpaks.txt` →
`/usr/share/wardos/`, `systemd/user/` → `/usr/lib/systemd/user` with
`/usr/lib/systemd/user-preset/90-wardos.preset` enabling every unit that has `[Install]`,
the getty drop-in → `/etc/systemd/system/getty@tty1.service.d/` (the image; an existing
Fedora only with `install.sh --autologin`). `shell/`, `theme/` and `tests/` never land on
the host. Every row is asserted by `desktop/tests/install.test.sh` against a temp root.

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
| `wardos-theme <verb>` | `list`, `current`, `set <id>`, `next`, `install <git-url>`, `remove <id>`, `render [id]`, `reload`, `bg next` |
| `wardos-font <verb>` | `list`, `current`, `set [mono\|sans] <name>` (mono for terminals, sans for UI; a sans candidate sets sans, anything else mono) |
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

The configurations rely on these details of the commands: `wardos-launch webapp` gives
its Chromium window the class `wardos-webapp-<name>` and `wardos-launch tui` its terminal
the class `wardos-tui-<name>` (the window rules tile the first on the web workspace and
float the second at 1000×700); `or-focus` matches the class case-insensitively;
`wardos-setup` opens its TUI in a terminal window when it is not already in one (the
bar clicks call it directly); `wardos-update --check` prints one Waybar JSON line
(`text`, `tooltip`, `class` `available` or empty); `wardos-screensaver` returns at once
when `wardos-toggle screensaver` has switched it off (hypridle calls it at 2.5 min);
`wardos-approve --watch` is the long-running listener behind `wardos-approve.service`;
`wardos-battery-monitor` runs once per call, from its timer every 2 min;
`wardos-setup audio` opens `pulsemixer` when it is installed and `pavucontrol` otherwise
(the image ships pavucontrol; pulsemixer is not packaged in Fedora).

Rules: a command never edits a file it did not create without a backup next to it
(`<file>.bak`); root is asked for with `pkexec` (desktop) or `sudo` (terminal) and only
by `wardos-update`, `wardos-install package`, `wardos-setup fingerprint|fido2|dns|timezone`.

How the family is built (`desktop/lib/wardos.sh` and the scripts): every script finds
the library through `$WARDOS_LIB`, then `../lib/wardos.sh`, then
`/usr/lib/wardos/wardos.sh`, so it runs from the checkout and from `/usr/bin`;
`wardos_usage` prints the comment block under the shebang, which is the `--help` text.
`wardos-menu-select`'s stdin backend takes several newline-separated answers in
`WARDOS_MENU_CHOICE`, one per successive menu, so a walk through the tree is one test;
an answer that matches nothing is returned as typed, which is how names and URLs are
asked for. `wardos-menu` implies SYSTEM when the first word is not a section
(`wardos-menu capture`), accepts `style` for Appearance, and runs leaves that need a
terminal (installs, the system update, DNS, About) through `wardos-launch run
<app-id> <cmd…>`, a terminal window that stays open when the command ends. Web and
terminal app definitions are `name=`/`url=`/`icon=` and `name=`/`cmd=`/`icon=` files,
the user's in `~/.config/wardos/webapps|tuis/` over the shipped ones in
`/usr/share/wardos/`; `install <name>` alone installs a shipped default and
`install --defaults` all of them (what `wardos-first-run` does). Toggles keep their
state in `$XDG_STATE_HOME/wardos/<what>` and answer `--status` for the bar, except
`idle` (pgrep hypridle) and `notifications` (`makoctl mode`), whose state something else
may have changed. Detached processes (wf-recorder, hyprsunset, hypridle) start through
`wardos_daemon`, which restores SIGINT (a script's background jobs ignore it) and gives
them their own session. `wardos-refresh` copies `config/<component>` with the
exceptions of §Layout and treats `hypr` as the Hyprland tree; `wardos-update` with no
argument does system, flatpaks and themes, never configs, which replace the user's
copies and are refreshed only on request. `wardos-install font` copies `.ttf`/`.otf`
files into `~/.local/share/fonts` (choosing one is `wardos-font set`), `service
tailscale` only enables an installed `tailscaled` because Tailscale is not in Fedora,
and `package` says that a layered RPM belongs in `image/packages.txt`.

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

The command centre's PROJECTS, AGENTS and SECURITY rows come from the shell:
`ward-shell launcher --lines [--query q]` prints one `SECTION<TAB>label<TAB>command`
line per entry of `design-language.md` §13, in section order, with the session's state
in the label (`payments-api   ● working`, `Resume session   payments-api · ● working`)
and the command the shell chose for it (`foot -D <worktree> -- ward claude`, `ward
watch`, `ward verify` and `ward-shell settings` in a terminal that stays open, `ward
replay <events.log>`, `foot`, `chromium`, `wardos-menu system`; paths are shell-quoted).
`wardos-menu` shows the first two columns through fuzzel `--dmenu` and runs the third;
fuzzel does the matching, so `--query` is for scripts and tests. Without a session the
fixed rows remain and the given directory is the project.

## Keys

The existing set (`desktop/hyprland/keybindings.conf`) stays. Added, in one file per
group so `wardos-keys` can title them:

| Key | Does |
| --- | --- |
| `Super + Space` / `Super + Alt + Space` | command centre / full menu |
| `Super + K` | keys viewer (focus moves with `Super + arrows`, and `Super + H` / `J` / `L`) |
| `Super + Return` / `Super + B` / `Super + E` / `Super + N` | terminal / browser / files / editor |
| `Super + M` / `Super + G` / `Super + D` / `Super + T` / `Super + /` | music / messages / containers / activity / passwords |
| `Print` / `Shift + Print` / `Ctrl + Print` | screenshot region / window / output |
| `Alt + Print` / `Super + Print` | screen record toggle / colour picker |
| `Super + Escape` / `Super + Shift + Escape` | lock / power menu |
| `Super + Ctrl + N` / `I` / `B` / `S` / `D` | toggle night light / idle lock / bar / screensaver / notifications |
| `Super + Ctrl + V` / `Super + Ctrl + E` | clipboard history / emoji |
| `Super + Shift + T` / `Super + Shift + B` | next theme / next background |
| `XF86*` keys | volume, brightness, media, with swayosd |
| `Super + scroll`, `Super + [` `]` | previous / next workspace |
| `Super + Alt + T` | split direction (was `Super + T`, now activity) |
| `Super + Alt + arrows` | resize the window (also `Super + Ctrl + H` / `J` / `K` / `L`) |

Every bind carries a `# description` line above it; that line is what `wardos-keys`
shows. `Super + Space` runs `wardos-menu`, `Super + Alt + Space` `wardos-menu system`.
Volume and brightness keys are `bindel` (repeat, work when locked), media keys `bindl`.
`desktop/tests/configs.test.sh` checks that every key in this table has a bind, that no
two binds share a chord, and that every `exec` is a `wardos-*` command, a defined
`$variable` or one of a short allowlist (`swayosd-client`, `playerctl`, `cliphist`, …).

## Themes

A theme is one TOML file (the existing token model). `wardos-theme render <id>` writes
`~/.config/wardos/theme/current/` with one file per component: `hyprland.conf` (borders,
ground), `waybar.css`, `mako.conf`, `fuzzel.ini`, `foot.ini`, `alacritty.toml`,
`btop.theme`, `hyprlock.conf`, `swayosd.css`, `nvim.lua` (a colorscheme from the tokens),
`chromium.json` (theme colour), `gtk.css` and `colors.env` (every token as `WARDOS_*`),
plus `background` (a path, or `solid:<hex>` for swaybg `-c`) and `theme.toml` (the theme
itself, for the shell). Every component's config `include`s its fragment; `wardos-theme
set` re-renders and signals each running component (`hyprctl reload`, `pkill -SIGUSR2 -x
waybar`, `pkill -SIGUSR1 -x nvim`, `makoctl reload`, swaybg restarted, `systemctl --user
restart swayosd.service`, `gsettings … color-scheme prefer-dark|light`, the btop symlink
below), then notifies `Theme · <name>`. `wardos-theme reload` is that signalling alone,
which `wardos-font set` uses after writing `~/.config/wardos/fonts.conf` and re-rendering.
The renderer is the Rust crate `desktop/theme` (`wardos-theme-render <id-or-path> --out
<dir>`); what each fragment carries and how the terminal cells are derived is in
`desktop/themes/README.md`.

What the shipped configurations expect of each fragment: `hyprland.conf` sets
`general:col.active_border`, `general:col.inactive_border` and `misc:background_color`
(`looknfeel.conf` carries no colour); `waybar.css` and `gtk.css` `@define-color` the nine
tokens by name (`ground`, `panel`, `separator`, `text`, `text_muted`, `accent`, `verified`,
`restricted`, `denied`); `hyprlock.conf` defines the same nine as `$ground` … `$denied` in
`rgb(RRGGBB)` plus `$font`; `mako.conf`, `fuzzel.ini`, `foot.ini` and `alacritty.toml` carry
the colour keys and the font of their format; `nvim.lua` returns a table of highlight
groups for `nvim_set_hl` and `wardos-theme set` sends `SIGUSR1` to running editors;
`colors.env` is sourced by the bash prompt on every prompt. btop only loads themes from
its own directory, so `wardos-theme set` symlinks `~/.config/btop/themes/wardos.theme`
to `theme/current/btop.theme` and `config/btop` names `color_theme = "wardos"`. swayosd
takes its style on the command line, so `wardos-theme set` restarts `swayosd.service`.

Shipped: the four official variants, plus palette themes mapped onto the nine tokens
(Tokyo Night, Catppuccin, Nord, Gruvbox, Everforest, Kanagawa, Rosé Pine, Matte Black,
Flexoki), each marked `source = "palette"` and observing §3's rules (no gradients,
state colour only on glyphs and markers). Themes from `wardos-theme install <git-url>`
live in `~/.local/share/wardos/themes/`.

## Packages

[`image/packages.txt`](../image/packages.txt) lists every package the desktop needs, one
per line with a comment naming what it is for, exact Fedora package names (`fd-find`,
`pipewire-pulseaudio`). What Fedora does not carry (the Hyprland ecosystem beyond the
compositor, lazygit) comes from the COPRs of [`image/coprs.txt`](../image/coprs.txt),
part of the image's trust set (`image/README.md`, "COPRs"). The `Containerfile` enables
the COPRs and installs from the manifest, and `desktop/install.sh` layers the same with
`dnf` or `rpm-ostree`; CI checks every name exists in the Fedora release the image pins
(44; `image/check-packages.sh`: `dnf repoquery` in a `fedora:44` container, job "image
packages" on every pull request) and builds the whole image with `docker build`
(`image.yml`, job "image build", on `main` and on pull requests that touch `image/`,
`desktop/` or the crates). A name the check has not confirmed yet carries
`# unverified` until it has (none today); the check, not the file, decides. Applications that are not in Fedora
come from Flathub via `wardos-install app` and the defaults in `desktop/flatpaks.txt`,
installed once by `wardos-flathub.service` after the first boot with a network; nothing
is downloaded by `curl | sh`. `mise` is not in Fedora and not in the image.

## Tests

`image/check-hyprland.sh` (CI job `hyprland config`) parses `desktop/hyprland/` with the
Hyprland the image ships, so a removed or renamed option fails a pull request instead of
showing in a booted desktop's error bar. `desktop/tests/run.sh` shellchecks `desktop/bin/*`, `desktop/lib/*`, `desktop/install.sh`
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
| Hyprland with tiling, gaps, keybindings | `desktop/hyprland/` | ✔ `hyprland.conf` + 7 sourced files, §Keys complete, `configs.test.sh` |
| Waybar top bar | trust bar rendered by Waybar from `ward-shell bar --waybar` | ✔ config: `config/waybar`, `configs.test.sh` |
| Walker launcher, clipboard history, emoji | fuzzel + cliphist, `wardos-menu-select` | ✔ config: `config/fuzzel` (+ `emoji.txt`), `Super + Ctrl + V` / `E` |
| omarchy-menu tree | `wardos-menu` (SYSTEM section above) | ✔ `wardos-menu [path…]`, `wardos-menu-select` (fuzzel and stdin backends), `Super + Space` / `Super + Alt + Space`; `menu.test.sh`, `menu-select.test.sh` |
| Keybindings viewer | `wardos-keys` | ✔ `wardos-keys [--list]`, `Super + K`; `keys.test.sh` |
| Themes (set, next, install, remove, backgrounds) | `wardos-theme`, TOML tokens rendered per component | ✔ `wardos-theme list\|current\|set\|next\|install\|remove\|render\|reload\|bg next`, `wardos-theme-render` (crate `desktop/theme`, `cargo test -p wardos-theme`), 14 themes; `desktop/tests/theme.test.sh`. Keys `Super + Shift + T` / `B` belong to the keys slice |
| Font switching | `wardos-font` | ✔ `wardos-font list\|current\|set`; `desktop/tests/font.test.sh` |
| Web apps in Chromium app mode | `wardos-webapp` | ✔ `wardos-webapp install\|remove\|list` (+ `install --defaults`), `wardos-launch webapp`, 13 defaults in `desktop/webapps/`; `webapp.test.sh`, `launch.test.sh` |
| TUI apps as windows | `wardos-tui` | ✔ `wardos-tui install\|remove\|list` (+ `install --defaults`), `wardos-launch tui`, 7 defaults in `desktop/tuis/`, `Super + D` / `T`; `tui.test.sh`, `launch.test.sh` |
| Screenshots (hyprshot + satty) | `wardos-capture screenshot` (grim, slurp, satty) | ✔ `wardos-capture screenshot region\|window\|output`, `Print` / `Shift + Print` / `Ctrl + Print`; `capture.test.sh` |
| Screen recording | `wardos-capture record` (wf-recorder) | ✔ `wardos-capture record region\|output` (toggle, pid in `$XDG_STATE_HOME/wardos/record.pid`), `Alt + Print`; `capture.test.sh` |
| Colour picker | `wardos-capture color` (hyprpicker) | ✔ `wardos-capture color`, `Super + Print`; `capture.test.sh` |
| Lock screen, idle, suspend | hyprlock, hypridle, `wardos-power` | ✔ config: `config/hyprlock`, `config/hypridle`, `Super + Escape`; `wardos-power lock\|suspend`, `wardos-toggle idle` (`Super + Ctrl + I`); `power.test.sh`, `toggle.test.sh` |
| Night light | hyprsunset via `wardos-toggle nightlight` | ✔ config: `config/hyprsunset`, `Super + Ctrl + N`; `wardos-toggle nightlight [on\|off\|--status]`; `toggle.test.sh` |
| On-screen volume/brightness | swayosd | ✔ config: `swayosd.service`, `XF86*` binds |
| Notifications | mako | ✔ config: `config/mako` (approval and done categories, dnd mode); `wardos-notify [--done]`, `wardos-toggle notifications` (`Super + Ctrl + D`); `notify.test.sh`, `toggle.test.sh` |
| Power menu | `wardos-power menu` | ✔ `wardos-power lock\|suspend\|relaunch\|restart\|shutdown\|menu`, `Super + Shift + Escape`; `power.test.sh` |
| Screensaver | `wardos-screensaver` | ✔ `wardos-screensaver` (tte, tput fallback), `wardos-toggle screensaver` (`Super + Ctrl + S`), hypridle at 2.5 min; `screensaver.test.sh`, `toggle.test.sh` |
| Battery monitor | `wardos-battery-monitor` | ✔ units: `wardos-battery-monitor.service` + `.timer` (2 min); `wardos-battery-monitor` (20/10/5 %, once each); `battery-monitor.test.sh` |
| Wi-Fi, Bluetooth, audio TUIs | `wardos-setup wifi\|bluetooth\|audio` | ✔ nmtui, bluetui or bluetoothctl, pulsemixer or pavucontrol, in a `wardos-tui-*` window from the bar; `setup.test.sh` |
| Power profiles | `wardos-setup power` | ✔ `wardos-setup power [profile]` (powerprofilesctl); `setup.test.sh` |
| Fingerprint, FIDO2 | `wardos-setup fingerprint\|fido2` | ✔ fprintd-enroll / pamu2fcfg, then `sudo authselect enable-feature`; `setup.test.sh` |
| Printers, DNS, timezone | `wardos-setup printers\|dns\|timezone` | ✔ system-config-printer or CUPS in the browser; nmcli on the active connection; timedatectl; `setup.test.sh` |
| Install packages / AUR | `wardos-install app` (Flathub), `package` (bootc layer) | ✔ `wardos-install app\|package\|webapp\|tui\|theme\|font\|dev\|service`, `wardos-remove` the same; `install.test.sh`, `remove.test.sh` |
| Dev environments (mise) | `wardos-install dev <lang>` | ✔ `mise use -g <lang>@latest`, a clear message without mise; `install.test.sh` |
| Docker + lazydocker | podman, podman-compose, podman-tui | |
| Terminal (Alacritty/Ghostty), bash, prompt, aliases | foot default, alacritty shipped, `config/bash` | ✔ `config/foot`, `config/alacritty`, `config/bash` (prompt tested in `configs.test.sh`) |
| Neovim (LazyVim) | neovim with a WardOS config and per-theme colours | ✔ config: `config/nvim` (self-contained, `lua/plugins.lua` hook) |
| btop, fastfetch, lazygit, fzf, ripgrep, fd, bat, eza, zoxide | shipped, configured, themed | ✔ config: `config/btop`, `config/fastfetch`, aliases and fzf/zoxide hooks in `config/bash` |
| Chromium default browser, theme colour | chromium, `chromium.json` fragment | ✔ config: `config/chromium/chromium-flags.conf`, `BROWSER=chromium` |
| Nautilus | nautilus | |
| Plymouth boot splash | WardOS Plymouth theme | ✔ `image/rootfs/usr/share/plymouth/themes/wardos/` (WARD on the ground, 2 px progress, passphrase prompt), selected in the `Containerfile` and in the initramfs (the image build proves it); its look at boot is E-09's |
| Autologin into Hyprland | getty autologin + uwsm | ✔ `systemd/system/getty@tty1.service.d/autologin.conf`, `config/bash/profile.d-wardos.sh` (tested); placed by `image/install-desktop.sh` (`--no-autologin` for existing Fedoras), the user from `image/disk.sh --user wardos` (`install.test.sh`) |
| Full-disk encryption at install | `image/disk.sh --luks` (Anaconda kickstart on the ISO; bootc-image-builder has no LUKS) | ✔ `image/disk.sh --type iso --luks`, `install.test.sh`; passphrase prompt unverified until E-09 |
| omarchy-update, migrations | `wardos-update` (bootc upgrade, flatpak, refresh) | ✔ `wardos-update [system\|flatpaks\|themes\|configs\|--check]`, `wardos-refresh <component>\|--all`; `update.test.sh`, `refresh.test.sh`; image side: `bootc upgrade`, `image/boot/README.md` |
| Snapshots and rollback (Limine + snapper) | bootc deployments, `bootc rollback` | ✔ every upgrade keeps the previous deployment; `bootc rollback` (`image/boot/README.md`) |
| Install on an existing Arch | `desktop/install.sh` on an existing Fedora | ✔ `desktop/install.sh` (dnf or rpm-ostree, `--dry-run`), `install.test.sh` |
| Share a file over LAN | `wardos-share` | ✔ `wardos-share [--port N] <file>` (python3 http.server, qrencode); `share.test.sh` |
| XCompose special characters | `config/xcompose` | ✔ `config/xcompose/XCompose`, compose on Right Alt |
| Apple display brightness | `wardos-setup monitors` (ddcutil, asdcontrol when present) | |

Then some (WardOS only):

| Feature | Delivers | Delivered |
| --- | --- | --- |
| Agent state, network, TamperWard and verification in the bar | `ward-shell bar --waybar [--segment mark\|session\|project\|agent\|network\|credentials\|observer\|tamperward\|verify\|daemon] [--follow]`, one JSON module per segment with the tone name and the agent state word as classes; `launcher --lines` for the command centre | ✔ `ward-shell-core` `waybar::tests::every_segment_is_a_module_in_the_{live,sealed}_state`, `every_segment_is_the_empty_module_with_no_session_except_the_mark`, `trust::tests::every_segment_is_addressable_by_name_live_and_sealed`, `launcher::tests::lines_are_section_label_and_shell_command_for_a_described_session`; `ward-shell` `waybar_flags_parse_and_need_waybar` |
| Approvals as notifications, answered from the keyboard | `wardos-approve`, daemon hold on `ask` (`agent-integration.md` §4.1: `Request::Hold`/`Approve`/`Pending`, `ward session pending --follow`, `ward session approve`); `wardos-approve.service` is the listener | ✔ `ward-daemon` `approvals::tests::*`, `hooks::tests::a_held_ask_{waits_for_the_answer_and_relays_it,nobody_answers_is_denied_when_the_timeout_passes}`, `hooks::tests::allow_session_answers_the_same_question_without_asking_again`, `daemon::tests::a_held_approval_is_recorded_listed_answered_and_recorded_again`, `client::tests::{pending_and_approve_go_through_the_daemon,follow_pending_emits_what_is_pending_after_the_backlog_then_on_each_request}`; `desktop/tests/approve.test.sh` |
| Verify, replay, evidence, snapshots, grants in the menu | `wardos-menu` SECURITY | ✔ from `ward-shell launcher --lines`, static `ward` list without it; `menu.test.sh` |
| Sandboxed browser profile per project | `wardos-launch browser --project` | ✔ chromium profile under `~/.local/share/wardos/browser/<hash>`; `launch.test.sh` |
| Package names and the whole image checked by CI | `image/packages.txt`, image build job | ✔ `image/check-packages.sh` ("image packages"), `image.yml` ("image build") |
