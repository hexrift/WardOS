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
  systemd/      user units (battery monitor, approval listener, bar worker, the
                empty-workspace hint, swayosd)
  flatpaks.txt  default Flathub applications, one id per line with its purpose
  tests/        run.sh (shellcheck + every *.test.sh with a mocked PATH)
  capture/      the README capture: capture.sh, ci-run.sh, scenes.tsv, assemble.py,
                refresh.sh and the packages it installs (CI only, "The README animation")
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
`/usr/lib/systemd/user-preset/90-wardos.preset` enabling every unit that has `[Install]`.
Login is greetd, set up by the image itself (`image/rootfs/etc/greetd`), not by this
step. `shell/`, `theme/`, `tests/` and `capture/` never land on the host. Every row is asserted by
`desktop/tests/install.test.sh` against a temp root.

**First-boot provisioning ([ADR-0027](decisions/ADR-0027-first-boot-provisioning.md)).**
The image ships unprovisioned — no human account. greetd runs `wardos-greetd-session`,
which while `/var/lib/wardos/provisioned` is absent starts the provisioning UI
(`wardos-provision-ui`) under cage instead of the greeter: an unprivileged foot-hosted terminal
UI (cage speaks xdg-shell only, so a layer-shell client like fuzzel aborts under it — hence a
self-contained TUI, not fuzzel) that asks the keyboard FIRST and re-establishes the compositor's
live layout before password entry, then collects language, timezone, name, username and a masked
password, then asks the
root broker (`wardos-provisiond`, socket-activated on `/run/wardos/provision.sock`, group
`greeter`, mode 0660) to apply them and create the real user. The broker writes the marker
on success; from then on the selector runs the normal greeter and the broker refuses. A
build-time `WARDOS_DEV_SEED_USER` bakes a dev *username* only (no baked password) so
`wardos-dev-seed.service` can seed that account at first boot and skip provisioning on CI/hardware
images. The seed is transactional and mirrors the broker: **with** the first-boot systemd
credential `wardos-dev-seed.password` it creates the `wheel` user, sets the password and commits
the marker as one journalled/rolled-back transaction; **without** a credential it creates no
account and no marker, so the machine stays unprovisioned and first-boot provisioning runs (no
locked-account dead end). It runs before greetd and the broker socket, reconciling any orphan from
an interrupted prior seed before canonical provisioning could start. Production images ship
without the flag, unprovisioned.
`greetd`'s `config.toml` runs `wardos-greetd-session`, so the selector is live; on a
provisioned machine its greeter path is byte-for-byte the #116 login.

User state: `~/.config/wardos/` (theme choice, rendered theme in `theme/current/`, user
overrides), `~/.local/share/wardos/` (web app profiles, installed themes, fonts),
`~/.local/state/wardos/` (toggles, last screenshot, record pid). Image-owned defaults
under `/usr/share/wardos/`; user files always win.

## Commands

One family, one help convention (`wardos-<name> --help` prints the usage block at the top
of the script). Menu-facing commands take their choices from arguments too, so every
menu path is scriptable and testable.

**`ward` is the command surface (ADR-0025).** In the terminal you type one verb, `ward`:
the secure session core (`ward init`, `ward up`, `ward verify`, `ward doctor`, `ward
claude`, …) and the desktop verbs below, which `ward` reaches by running `wardos-<verb>`.
So `ward theme set ward-dark` runs `wardos-theme set ward-dark`, `ward setup wifi` runs
`wardos-setup wifi`, and `ward <verb> --help` shows that command's own help. Any verb that
is neither a built-in nor an installed `wardos-<verb>` is an error naming what is missing.
The `wardos-*` names keep working unchanged (autostart, menus and `.desktop` entries still
use them); `ward` is the front door for people.

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
| `wardos-update [what]` | `bootc upgrade` (stage-only; ADR-0028 §5's states and the anti-rollback floor first, "Update states" below; `--allow-rollback`, `--require-provenance`) + `flatpak update` + `wardos-refresh`; `--status` the states alone; `--check` for the bar indicator |
| `wardos-refresh [component]` | re-copy a component's default config into `~/.config`, keeping a backup |
| `wardos-notify <title> [body]` | notification with the WardOS defaults; `--done` for "finished" toasts |
| `wardos-hint [--force] <workspace>` / `wardos-hint --watch` | the empty-workspace hint (#99, §Discoverability): for `1\|code`, `2\|agent` or `3\|web` with no window on it, one notification saying what starts there and how, once per workspace per login (a marker under `$XDG_RUNTIME_DIR/wardos/`); nothing for a workspace with a window or for 4–9; `--force` shows it anyway. `--watch` follows Hyprland's event socket (`socat`, `workspacev2>>ID,NAME`) and is the long-running listener behind `wardos-hint.service`; `hint.test.sh` |
| `wardos-approve` | shows a pending approval from `wardd` as its three blocks (destination · requested by agent · Ward will allow; `design-language.md` §10) and answers it (`y`/`s`/`n`); `--watch` multiplexes every live session's approvals (#141), titling each notification with its agent and project, and relays the answer to the session it was asked from; a still-showing notification is replaced with the outcome the moment its approval becomes terminal elsewhere, and its live workers are bounded (`WARDOS_APPROVE_MAX_NOTIFIERS`, #146 items 2-3) |
| `wardos-approve-inbox` | the persistent approval inbox (#146 items 2-3): every approval `ward session approvals --all` knows across every live session, pending first, fuzzel-dmenu style, each pending row ending with the decision time the daemon reports (`42 s left, then denied`, or `held while paused · …` while its session is paused, #146 item 4); a pending choice opens `wardos-approve <id>` pinned to its own session in a terminal that stays open on the outcome (the daemon's own confirmation, or its refusal: answered elsewhere, timed out, unreachable), a decided one shows a read-only summary, and a live session whose approvals could not be listed is an `unreachable` row naming the error, never a pending one — reachable even when a notification was missed, dismissed, or never shown at all; a listing that fails outright is a critical notification, not a silent exit |
| `wardos-pause [pause\|resume\|menu\|pause-all\|--status]` | pause the agent session (`WARDOS_SESSION`'s if set, an immutable pinned id — else `WARDOS_PROJECT`'s) as one host operation (ADR-0019 §3: processes frozen, network closed, credential grants suspended, approvals held, recorded) through `ward pause`, with the one notification; paused, the exits: Resume / Stop & preserve workspace / Stop & restore entry state / Inspect activity; `pause-all` (#141 item 5) is the distinct, explicit "pause every live session" scope, one result line each; `--status` prints `paused`, `unconfirmed` (a pause or stop began and its outcome is not recorded yet — the daemon is still at it, or died mid-way and none has reconciled the session since), `running` or `none`; a pause a component did not acknowledge (#145 item 3: `ward pause` prints `paused, but unconfirmed: egress proxy (…)`) gets the same critical `AGENTS PAUSING` notification an unsettled freeze gets, naming the component; a resume that releases the user's pause while a snapshot capture still holds the session (#145 item 6) notifies `Agents still held for capture`, never `Agents resumed` |
| `wardos-session-switch` | the keyboard-first session switcher (#141 item 3, `Super + Alt + S`): every live session — project, agent state (PAUSED included), pending approvals, verification freshness — from `ward-shell switcher --lines`; choosing one runs `ward session select <id>`, the desktop's shared selection every other surface with no session of its own then agrees on |
| `wardos-battery-monitor` | low-battery notifications (timer unit) |
| `wardos-screensaver` | terminal text effects on idle, any key exits |
| `wardos-share <file>` | serve a file on the LAN with a QR code (python http.server + qrencode) |
| `wardos-calibrate [--force] [step…]` | first-boot system setup, CALIBRATE ([ADR-0026](decisions/ADR-0026-first-run-calibrate.md)): `locale` (`localectl set-locale`), `keyboard` (Hyprland `kb_layout` live + persisted, and `localectl set-x11-keymap`), `timezone` (region → city, `timedatectl set-timezone`), `password` (one terminal running `passwd`, off the default path); no arguments runs the guided flow with a review that changes any choice. Offered every login until it **completes**: the marker (`~/.config/wardos/calibrate-done`) is written only when the applies succeed or you choose *Skip the rest*; a cancelled review or a failed apply leaves it unset, so an unconfigured machine is re-offered next login rather than recorded as done. A step with a value applies it non-interactively. Keyboard-first, offline, polkit not `sudo` |
| `wardos-first-run` | first login: copy configs (once, guarded by `~/.config/wardos/first-run-done` — never re-copied, so a resumed login can't clobber the user's config backups), the default theme, `ward doctor`, the default apps, show the keys, then one pointer (#99: `Super + Space`, `Super + Shift + Escape` / the bar's POWER cell, the trust bar — never the walkthrough's "Welcome to WardOS" greeting); then the resumable stages `wardos-calibrate` and `wardos-welcome`, offered each login until each records its own completion |
| `wardos-greetd-session` | greetd's session selector ([ADR-0027](decisions/ADR-0027-first-boot-provisioning.md)): `/var/lib/wardos/provisioned` absent → the provisioning UI under cage; present → the normal `gtkgreet` greeter (byte-for-byte the provisioned-machine login) |
| `wardos-provision-ui` | first-boot provisioning UI (CALIBRATE provisioning form): unprivileged foot-hosted TUI under cage (xdg-shell, not fuzzel) — keyboard first (re-established as the live layout before password entry), then language, timezone, name, username, masked password — that asks the broker to apply them and create the first user. No privileged operation itself |
| `wardos-provisiond` | the root provisioning broker (socket-activated, one instance per connection): validated verbs `LOCALE`/`KEYMAP`/`TIMEZONE`/`ACCOUNT`/`STATUS`; refuses once provisioned; the password is fed to `chpasswd` on stdin, never logged; `ACCOUNT` is the transactional commit that writes the marker |
| `wardos-welcome [--again] [step…]` | the first-login walkthrough ([`onboarding.md`](onboarding.md) §1): `theme` (from `wardos-theme list`), `keys` (a terminal running `ward vault set NAME`, never a menu), `project` (a directory picker over `~` or a URL to clone, then `ward init`), `agent` (`ward ready` first — a blocking gap shows its report and asks before continuing, #147 item 7; `Fix it first` opens `ward init` in a terminal, where a verification boundary `ward ready` showed as proposed but not accepted is accepted by the user, never by the script, #147 item 2 — then `ward claude` there, the trust bar in one line), `done` (the card; writes `~/.config/wardos/welcome-done`); one step by name any time, `--again` the whole; `clone URL DIR` is the project step's terminal command |
| `wardos-version` | image and tool versions (`bootc status`, `ward --version`) |
| `wardos-about` | the About surface (fastfetch with the WardOS logo) |
| `wardos-baseline [file]` | one-file hardware/diagnostics bundle (`ward doctor` + boot, GPU, network, power facts) for reference-hardware acceptance and support; prints the path (`baseline.test.sh`) |

The configurations rely on these details of the commands: `wardos-launch webapp` gives
its Chromium window the class `wardos-webapp-<name>` and `wardos-launch tui` its terminal
the class `wardos-tui-<name>` (the window rules tile the first on the web workspace and
float the second at 1000×700); `or-focus` matches the class case-insensitively;
`wardos-setup` opens its TUI in a terminal window when it is not already in one (the
bar clicks call it directly); `wardos-update --check` prints one Waybar JSON line
(`text`, `tooltip`, `class` `available`, `unavailable` when bootc could not ask — the
tooltip says why — or empty); `wardos-screensaver` returns at once
when `wardos-toggle screensaver` has switched it off (hypridle calls it at 2.5 min);
`wardos-approve --watch` is the long-running listener behind `wardos-approve.service`;
`ward-shell worker` is the long-running shared bar projection behind
`wardos-shell-worker.service` (#138 item 2); `wardos-battery-monitor` runs once per call,
from its timer every 2 min;
`wardos-setup audio` opens `pulsemixer` when it is installed and `pavucontrol` otherwise
(the image ships pavucontrol; pulsemixer is not packaged in Fedora). The image's firewall
admits nothing inbound (`image/README.md` "Security posture"), so `wardos-share` is
expected to open its port for the duration of the run and no longer, with
`firewall-cmd --add-port=<port>/tcp` (never `--permanent`) before serving and
`--remove-port` on exit.

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
<app-id> <cmd…>`, a terminal window that stays open when the command ends and exits with
that command's own status — `[done]` or `[failed, exit N]` — never the close prompt's, so a
caller that checks it (`wardos-welcome`, `wardos-calibrate`'s password step) can tell a
failed step from a successful one. Web and
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
`dev rust` installs a Rust toolchain into `~/.rustup` and `~/.cargo` with the image's
`rustup-init` (the host has no compiler, ADR-0001; the verifier binds this one, and
`ward doctor` names the command until it has run; repeating it only sets the default
channel), and `package` says that a layered RPM belongs in `image/packages.txt`.

### Update states

`wardos-update --status`, and `wardos-update system` before it stages anything, print
ADR-0028 §5's states one per line, each its own fact (#148 item 5):

| Line | Shows |
| --- | --- |
| `booted` | the running deployment as `reference@digest`, its WardOS version and `ward --version`. The version is the image's `org.wardos.version` label (`image/Containerfile`), read from the registry with `skopeo inspect` by digest; when skopeo cannot answer, bootc's own `version` field — the Fedora base image's label today — said as `(bootc version; <why>)` |
| `staged` | the deployment the next boot runs (digest, version), or `none` |
| `available` | the newest image bootc finds for the configured reference (`bootc upgrade --check`, then the `cachedUpdate` of `bootc status --json`): digest and version; `up to date`; or why it could not ask — `network-unavailable: …; retry when the machine is online`, `registry-auth-failed: …`, `bootc-error: …` |
| `verified` | how far the candidate got: `digest-resolved` (bootc resolved the digest; the layers are downloaded and digest-checked at staging), or `downloaded, digest-checked` once staged — then `provenance-missing`, since no signed manifest covers the image yet ([`release-manifest.md`](release-manifest.md)) |
| `manifest` | the release manifest of the candidate's version, fetched from that release and verified with [`scripts/release/verify-manifest.sh`](../scripts/release/verify-manifest.sh) (a copy beside the checkout, `/usr/lib/wardos/verify-manifest.sh`, `$WARDOS_VERIFY_MANIFEST`, else the repository's at the tag): `provenance-verified`, `verification-failed (<cause>)`, `provenance-missing`, `verifier-unavailable (<cause>)`, `network-unavailable`, or `not looked up` (the version is unknown, or not a release tag — a build between releases is `v0.4.1-15-g…`). Evidence about that release's tarballs, never about the image; the line says so |
| `rollback` | the deployment `bootc rollback` would boot (digest, version), or `none` |
| `anti-rollback` | `allowed`, `refused: candidate X is lower than booted Y; pass --allow-rollback to stage it anyway`, `allowed by --allow-rollback`, or `not evaluated` (a version unknown, or not a version). The shell mirrors `check_anti_rollback` of [`crates/ward-release-verify`](../crates/ward-release-verify) over its version grammar (`[vV]?X.Y.Z(-pre)?(+build)?`, SemVer precedence); the crate is the reference. Both sides come from one source — two labels, else two bootc fields, said as `(bootc versions)` — never one of each |
| `compatibility` | the node protocol window the release serves: from the verified manifest (`node_protocol_window`, with `rollback_supported`), else from [`compatibility.md`](compatibility.md)'s marker when this host has the document, else `unknown` |

`system` stages only (`sudo bootc upgrade`; the booted deployment is unchanged until a
reboot you choose) and prints the compatibility and rollback lines before it does. It
refuses, with its own exit code and no `sudo bootc upgrade`: a lower version (5, unless
`--allow-rollback`), a release manifest that fails verification (6), and a missing
manifest or an unavailable verifier under `--require-provenance` (6; without the flag
both are said and the image is staged checksum-only, as `install.sh` does); a network
(3), registry (4) or bootc (1) failure stops it before a candidate is known. Without an
argument the toast carries the same outcome: `✓ Update` with the staged version and the
rollback, or a critical notice with the failure state. A failure is never "no update".
`update-states.test.sh` holds every row and refusal against mocked `bootc`, `skopeo`
and `curl` and the fake `cosign` of `scripts/release/verify-manifest.test.sh`, with the
real verifier.

## Menu

`Super + Space` is the command centre (`design-language.md` §13) and `Super + Alt + Space`
the full menu, which is the command centre's SYSTEM section expanded. One tree:

```text
PROJECTS   …            (ward-shell)
AGENTS     Start Claude · Start Codex · Resume session · Sessions…
SECURITY   Verify current project · Review permissions · Approval inbox ·
           Pause all sessions · Replay last session · Evidence · Snapshots ·
           Grant credential…
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
  Help        Welcome · Keys · Manual · Hyprland wiki · About
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
fixed rows remain and the given directory is the project; the shell's text surfaces
then say `No agent session. Super + Space → Start Claude, or ward init then ward
claude in a terminal.` while `bar --waybar` stays the dim mark. Until
`~/.config/wardos/welcome-done` exists, a command centre with no live session (no
PROJECTS row) opens on `WELCOME  Start here`, which runs `wardos-welcome`.

The bar's verify segment is bound to the snapshot it judged (ADR-0019 decision 1,
`design-language.md` §11). Before rendering `bar` (text or `--waybar`) the shell digests
the worktree with `ward-snapshot`'s digest-only walk and incremental hash cache, using
the capture options `ward verify` captures a candidate with, and compares the id with the
candidate the last `VerificationPassed` record names: `VERIFY —` never, `VERIFY ◐
7c01a2b3` verifying, `VERIFY ✓ 7c01a2b3` the tree is that candidate, `VERIFY ~ STALE` it
no longer is, `VERIFY ✗` it failed — but only when what is being rendered actually shows
that state (`SegmentName::needs_freshness`, true only for the whole bar and `--segment
verify`; #138 item 3). Six of the seven `ward-shell bar --waybar --segment … --follow`
processes `config/waybar/config.jsonc` launches — `project`, `agent`, `network`,
`grants`, `tamperward` and `daemon` — never touch the worktree at all; their text and
tone come from the event stream alone. Only the seventh, `--segment verify`, does. The
`daemon` segment is the explicit connection-state module (#138 item 5): `LIVE` /
`UNKNOWN` / `SEALED`, and every segment module — this one included — carries its own
`unknown` CSS class distinct from its ordinary tone whenever the daemon connection is
lost without a confirmed seal (`waybar.css`'s `.unknown` rule), not only the whole-bar
module a real desktop does not actually run. In `--follow`
mode, for a segment that does need it, the digest
still runs unconditionally on every quiet tick (`--tick-ms`, 2000 by default), since an
edit made outside the sandbox is a change the stream never reports — but a record no
longer re-digests immediately every time: record-triggered digests are debounced to at
most one per 250 ms (`DIGEST_DEBOUNCE`), so a burst of records collapses into a bounded
number of scans instead of one per record, while `DigestGate` guarantees a change that
lands is still always either covered by the scan running when it lands or picked up by a
follow-up scan — never silently dropped. A record withdraws `VERIFY ✓`'s green the
instant it lands, before its (possibly still-debounced) digest ever runs, so the bar
never keeps asserting a confirmed match against a tree that already has evidence against
it; the daemon socket is itself polled at least as often as `DIGEST_DEBOUNCE` while a
segment needs freshness, so the debounce deadline is serviced on its own rather than
only when the next record happens to arrive or the much longer quiet tick elapses. Cost
on `examples/ward-demo` (9 files), measured
by `ward-shell`'s
`a_warm_digest_of_the_demo_is_within_the_bar_budget` (release build, 4-vCPU host): cold
0.24 ms, warm 0.05 ms; on this repository's own checkout (364 files, `WARD_DIGEST_DIR`)
cold 8.9 ms, warm 2.1 ms. The test fails above 50 ms warm. `ward-shell verify-panel` prints the segment's click panel (the
verified candidate, its time, the current digest, the number of manifest entries that
differ from the stored candidate, TamperWard's evidence, the test counts, and integrity
as the number of protected files the verifier restored from the entry snapshot), and
`custom/ward-verify`'s `on-click` opens it in a `ward-session` foot window like the
session panel. The change count needs the session CAS (`~/.local/state/ward/cas`); the
state itself needs only the digest, so it is decided even without one.

The six `ward-shell bar --waybar --segment … --follow` processes above are what
`config/waybar/config.jsonc` launches, but while `wardos-shell-worker.service` is running
none of them actually subscribes to the daemon or digests the worktree itself (#138 item
2): each first asks that service's own socket (`ward-shell worker`, one request line
naming its segment, or `bar` for the whole row) and, once it answers, just copies the
`Module` JSON lines it sends to stdout — the worker is the one process that keeps the one
`Snapshot`, the one daemon subscription and the one digest schedule (unconditional, since
it cannot know in advance which of the six will connect) all six used to keep on their
own, and a segment that connects mid-session gets the worker's current cached module at
once, then only the lines that actually change afterwards. A process falls back to
subscribing and digesting for itself — exactly the behaviour described above, unchanged —
when nothing answers the worker within a handful of quick, bounded connect retries (the
cold-start race between the unit starting, per `autostart.conf`'s ordering below, and a
process's very first ask before the worker has bound its socket) followed by a short
handshake timeout on a connection that did accept but never answered (wedged): the unit
still not installed or restarting past that budget, or a caller that named an explicit
`--dir` (the desktop-wide worker does not parameterise by one) or an explicit `--tick-ms`
(the worker runs one fixed cadence for every segment, so it cannot honour a caller-chosen
one — asking it anyway would silently turn that documented, tested option into a no-op).
`desktop/hyprland/autostart.conf`'s `systemctl --user start` line names
`wardos-shell-worker.service` alongside `wardos-approve.service` and the rest, before
`waybar` execs, so the worker has as much of a head start on binding as that file can give
it on the plain-`Hyprland` path (the systemd preset alone only reaches units through
`graphical-session.target`, which a `uwsm start hyprland.desktop` session pulls in but a
plain one does not) — the bounded connect retry above is what actually closes the
remaining race, since a `systemctl start` that has returned only means the unit's process
was forked, not that it has bound its socket yet. While the desktop has no session at all
(a headless run, a machine before its first `ward up`, the gap after the last session
sealed) the worker stays up with its socket bound, answers every segment the empty
module, and looks for a session again every 2s — the same pause it takes after a session
ends before looking for the next, and the `RestartSec` the unit would pace a worker that
exited by — saying `no session for . and no live session anywhere` once, and again only
when the reason changes, never once per poll. It waits rather than exits because the
unit's `Restart=on-failure` is pacing for a crash, not for an idle loop: a worker that
exited to borrow it would spin, unpaced, wherever it is run without systemd
(`desktop/shell/tests/worker_idle.rs` runs it that way with no session and asserts one
line and a live process over several polls).

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
| `Super + Escape` / `Super + Shift + Escape` | lock / power menu (`wardos-power menu`: Lock · Suspend · Relaunch · Restart · Shutdown — also the bar's POWER cell and SYSTEM ▸ Power in the command centre, §Discoverability) |
| `Super + Shift + P` | pause the agents (`wardos-pause`); paused, the exits menu |
| `Super + Alt + S` | session switcher (#141): every live session, keyboard-first (`wardos-session-switch`) |
| `Super + Alt + A` | approval inbox (`wardos-approve-inbox`, #146 items 2-3) |
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

## Discoverability

The first boot on the reference laptop (#99, E-09) could not find a way to shut down,
clicked `code`, `agent` and `web` in the bar and landed on empty workspaces with nothing
to say what starts there, and found tool dialogs left floating on the wrong workspace.
Each has one answer, and the first-run pointer names them:

**A visible way out.** The bar's right group ends in a `POWER` cell (`custom/ward-power`,
after the clock, the one cell without a right border): a click opens `wardos-power menu`,
the same five choices `Super + Shift + Escape` opens, with `wardos-power`'s semantics
unchanged (no confirmation — the menu is the confirmation, and every action is undone by
logging in again). Its tooltip names the key and the command centre's SYSTEM ▸ Power. The
first-run pointer and the walkthrough's closing card name both. `Relaunch` is "leave
Hyprland"; with autologin it comes straight back, so whether it should read `Log out` is
part of the autologin decision #99 leaves to the owner.

**Workspace labels are workspaces.** The three named workspaces (`looknfeel.conf`:
`defaultName:code`, `agent`, `web`) were rendered by their word alone, and three lowercase
words in the centre of a bar whose other cells are clickable actions read as three apps to
launch — which is what the first boot did. The bar now renders them as `1 code`, `2 agent`,
`3 web` and a free workspace as its number (`hyprland/workspaces` `format` `{id} {icon}`,
with `format-icons` mapping each name to itself and `default` to nothing): the number is
the `Super + 1/2/3` key, the word says what the place is for, and the Hyprland names stay
what they were, so `hyprctl` and the window rules are unchanged. The labels stay
clickable (they switch workspaces), which is what a numbered tab suggests.

**The empty-workspace hint.** Nothing auto-starts on a workspace by design (an agent
starts when asked), so `wardos-hint` says how. `wardos-hint.service` runs `wardos-hint
--watch` for the session (started on `autostart.conf`'s `systemctl --user start` line like
the other units, after `import-environment` has handed `HYPRLAND_INSTANCE_SIGNATURE` to the
user manager); it follows the compositor's `socket2` with `socat` and, on a `workspacev2`
event for 1, 2 or 3, waits a short settle (`WARDOS_HINT_SETTLE`, 0.3 s, so a browser the
rules send to 3 has mapped), reads the window count from `hyprctl workspaces -j`, and when
it is zero sends one notification through the desktop's own path (`wardos_notify` → mako,
10 s, calm words): `Workspace 2 · agent — No agent is running yet. Super + Space → Start
Claude, or ward claude in a terminal (Super + Return). The observer (Super + O) lands
here.`; `1 · code` names the editor (`Super + N`) and the terminal; `3 · web` the browser
(`Super + B`) and web apps. Once per workspace per login: the marker is under
`$XDG_RUNTIME_DIR/wardos/`, which is this login's and gone at logout, so the hint is a
first-visit card, not a nag. No hint for 4–9, none for a workspace with a window, and no
new surface or daemon beyond the one listener. The bar's workspace buttons keep Waybar's
own `activate` click; the hint reacts to the resulting workspace change, so a click, a
key, a scroll and a swipe all get it.

**Tool dialogs open where they were asked for.** `windows.conf`'s utilities section
(`configs.test.sh` enforces it): the audio mixer (`pavucontrol`), the network and
Bluetooth editors, the portal pickers and the terminals `wardos-menu` and
`wardos-calibrate` open for an install, an update, a setup step, About or `passwd`
(`wardos-launch run <app-id>`, classes `wardos-install|remove|update|setup|about|passwd`)
are floating, sized (800×560, or 1000×700 like the terminal apps) and centred, on the
current workspace; every `float on` match also places its window (`center on` or `move`),
and no dialog match carries a `workspace` effect that would send it elsewhere. A dialog
left open when the user moves on stays on its workspace — a window belongs to one — and
is closed there with `Super + Q`; the numbered labels and the hint say which workspace is
which.

## Themes

A theme is one TOML file (the existing token model). `wardos-theme render <id>` writes
`~/.config/wardos/theme/current/` with one file per component: `hyprland.conf` (borders,
ground), `waybar.css`, `mako.conf`, `fuzzel.ini`, `foot.ini`, `alacritty.toml`,
`btop.theme`, `hyprlock.conf`, `swayosd.css`, `nvim.lua` (a colorscheme from the tokens),
`chromium.json` (theme colour), `gtk.css` and `colors.env` (every token as `WARDOS_*`),
plus `background.png` (the wallpaper drawn from the tokens, below), `background` (the
path swaybg and hyprlock show; `solid:<hex>` is still understood for swaybg `-c` when a
hand-written file says so) and `theme.toml` (the theme itself, for the shell). Every
component's config `include`s its fragment; `wardos-theme
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
`rgb(RRGGBB)` plus `$veil` (the panel colour at 70 %, `rgba(RRGGBBAA)`), `$font`,
`$radius` and `$wallpaper` (the path `background` names); `mako.conf`, `fuzzel.ini`,
`foot.ini` and `alacritty.toml` carry the colour keys and the font of their format
(fuzzel's `match` and `selection-match` are the accent and the text, so a match reads
on the accent selection); `nvim.lua` returns a table of highlight
groups for `nvim_set_hl` and `wardos-theme set` sends `SIGUSR1` to running editors;
`colors.env` is sourced by the bash prompt on every prompt. btop only loads themes from
its own directory, so `wardos-theme set` symlinks `~/.config/btop/themes/wardos.theme`
to `theme/current/btop.theme` and `config/btop` names `color_theme = "wardos"`. swayosd
takes its style on the command line, so `wardos-theme set` restarts `swayosd.service`.

Wallpapers: every render writes `background.png`, a 1920×1200 wallpaper drawn from the
tokens by the renderer's own rasteriser (rectangles on the 8 px grid, no vector library):
the ground colour, one 1 px rule in the separator tone 64 px in from either edge, and
the WARD mark set small (14 px, 5×7 bitmap glyphs of 2 px cells) in the lower left in
`text_muted`. No gradient, no photo, three tones, so the file is a two-bit indexed PNG
of about 6 KB and the render takes milliseconds; the composition is the same for every
theme and only its tones change, which keeps the host layer identical under every
palette (`design-language.md` §2). Precedence: when the theme ships
`<id>/backgrounds/` (or an installed clone `backgrounds/`), its first file by name is
the background and `background.png` is only written; otherwise `background` points at
`background.png` (an absolute path, so swaybg and hyprlock read it from anywhere).
`wardos-theme bg next` cycles the theme's own directory and rewrites the hyprlock
fragment's `$wallpaper` line so the lock screen follows; a theme without a directory
has nothing to cycle and says so. The lock screen (`config/hyprlock`) shows the same
file under `$veil`, the ground alone when the file cannot be read. Tests:
`cargo test -p wardos-theme` (`every_theme_draws_a_small_wallpaper_…`: dimensions, the
corner pixel is the ground, the mark pixel is `text_muted`, three tones, < 200 KB, the
time budget) and `desktop/tests/theme.test.sh` (swaybg is given the rendered file, `bg
next` reaches hyprlock).

Shipped: the four official variants, plus palette themes mapped onto the nine tokens
(Tokyo Night, Catppuccin, Nord, Gruvbox, Everforest, Kanagawa, Rosé Pine, Matte Black,
Flexoki), each marked `source = "palette"` and observing §3's rules (no gradients,
state colour only on glyphs and markers). Themes from `wardos-theme install <git-url>`
live in `~/.local/share/wardos/themes/`.

## Packages

[`image/packages.txt`](../image/packages.txt) lists every package the desktop needs, one
per line with a comment naming what it is for, exact Fedora package names (`fd-find`,
`pipewire-pulseaudio`). What Fedora does not carry (the Hyprland ecosystem beyond the
compositor) comes from the COPRs of [`image/coprs.txt`](../image/coprs.txt),
part of the image's trust set (`image/README.md`, "COPRs"). The `Containerfile` enables
the COPRs and installs from the manifest, and `desktop/install.sh` layers the same with
`dnf` or `rpm-ostree`; CI checks every name exists in the Fedora release the image pins
(44; `image/check-packages.sh`: `dnf repoquery` in a `fedora:44` container, job "image
packages" on every pull request) and builds the whole image with `docker build`
(`image.yml`, job "image build", on `main` and on pull requests that touch `image/`,
`desktop/` or the crates). A name the check has not confirmed yet carries
`# unverified` until it has; the check, not the file, decides. Applications that are not in Fedora
come from Flathub via `wardos-install app` and the defaults in `desktop/flatpaks.txt`,
installed once by `wardos-flathub.service` after the first boot with a network; nothing
is downloaded by `curl | sh`. `mise` is not in Fedora and not in the image. The list is
kept to what the desktop renders (`image/README.md` "Size"): one browser, Chromium,
which is also the web-app engine (Firefox is `wardos-install app org.mozilla.firefox`
and its window lands on the web workspace like Chromium's); no compiler (`rustup` ships
the installer, `wardos-install dev rust` runs it); the fonts every component names,
Inter and JetBrains Mono, with DejaVu, one CJK variable font and one colour emoji font
as fallbacks; and the `en_US` locale.

## Tests

`image/check-hyprland.sh` (CI job `hyprland config`) parses `desktop/hyprland/` with the
Hyprland the image ships, so a removed or renamed option fails a pull request instead of
showing in a booted desktop's error bar. `desktop/tests/run.sh` shellchecks `desktop/bin/*`, `desktop/lib/*`, `desktop/install.sh`,
`desktop/capture/*.sh` and runs every `desktop/tests/*.test.sh`. A test puts a directory of mock commands
first on `PATH` (each mock appends its arguments to `$MOCK_LOG`), sets
`WARDOS_MENU_BACKEND=stdin` with `WARDOS_MENU_CHOICE=<answer>`, points `HOME` and `XDG_*`
at a temp dir, and asserts on the log and the files written. Rust parts (the theme
renderer, `ward-shell bar --waybar`, the worktree digest behind the verify segment) are
tested with `cargo test`; `desktop/shell/tests/` holds the `ward-shell` integration tests
that spawn the built binary itself (`worker_idle.rs`: the worker with no session).

## The README animation

`assets/wardos-desktop.gif` is a capture of the shipped desktop: Hyprland, Waybar,
mako, fuzzel, foot and hyprlock running on a virtual output in CI, with this checkout's
`ward`, `wardd` and `ward-shell`, walked from the first login to the lock screen (twelve
scenes, 1280x720, about 24 s; the current GIF is 386 KB). Every pixel is the
compositor's; nothing is drawn afterwards, and nothing in it can drift from the product
without the capture noticing first. It replaced a storyboard rendered from the shipped
material in a browser (issue #84), which went with it.

The capture is the workflow `desktop capture` (`.github/workflows/desktop-capture.yml`):
weekly on `main`, by hand, and on pull requests that touch `desktop/` or `image/`. The
runner has no GPU, and aquamarine gets its buffer allocator from its DRM backend, which
needs a KMS device opened through a seat (`HYPRLAND_HEADLESS_ONLY` does not help: the
headless backend has no allocator of its own). So the job runs on the host, loads the
`vkms` kernel module (a virtual KMS device with a `Virtual-1` connector) and hands
`/dev/dri` with `--device` to a container of the Fedora release the image pins. There
[`desktop/capture/ci-run.sh`](../desktop/capture/ci-run.sh) enables the COPRs of
`image/coprs.txt`, installs `desktop/capture/packages.txt` (the image's own packages for
everything on screen, plus `seatd`), places the tree with `image/install-desktop.sh`,
puts the checkout's `ward` binaries in `/usr/bin`, starts `seatd` as the seat (no VT, the
socket owned by the session user; the image has logind for this), and runs
[`desktop/capture/capture.sh`](../desktop/capture/capture.sh) as an unprivileged user
with `LIBSEAT_BACKEND=seatd`. The card the `modprobe` added is handed down as
`CAPTURE_DRM_CARD` (sysfs may call its driver `faux_driver` rather than `vkms`, so the
workflow compares the card list before and after); without it capture.sh picks the card
that is vkms's by driver name, device path or uevent, never the runner's own adapter.
That card is `AQ_DRM_DEVICES`. capture.sh sets the user up as a first login leaves
it (every output at 1920x1080@60, Hyprland's debug log on, checked by
`Hyprland --verify-config`), starts a session bus and the shipped Hyprland (Mesa's
software rasteriser for EGL and, through `kms_swrast` on the card's dumb buffers, for
GBM; `AQ_TRACE`/`HYPRLAND_TRACE` on), waits for the vkms output and creates a headless
one only when none appears. The clients start as on the image, from the user's copy of
`autostart.conf`: `exec-once = waybar`, `exec-once = mako`, the `wl-paste … cliphist
store` watchers, the theme re-apply that starts swaybg, `wardos-first-run`; the capture
sends each line's output to its own `logs/<command>.log` with `exited <status>` after it
when the command ends, runs Waybar with `-l debug`, and makes hypridle's line a no-op
(its idle timer would lock the screen; the package is not installed there). There is no
systemd user session in the container, so the `systemctl --user` line fails and logs
that, and the units it would start do not run: the bar's segments subscribe to the
daemon themselves, as they do whenever `wardos-shell-worker.service` is down, and the
approval listener, the polkit agent and swayosd are not needed for the scenes. ci-run.sh
runs a system bus with nothing on it (the classic `dbus-daemon --system`; dbus-broker's
under systemd on the image), so Waybar's bluetooth, network and battery modules and GTK
get "no such service" answers rather than no bus. Then it walks
[`desktop/capture/scenes.tsv`](../desktop/capture/scenes.tsv). Each scene is started
through `hyprctl dispatch exec` (the welcome steps, `wardos-launch run`, `wardos-menu`,
`wardos-theme`, `wardos-power`), waited for in `hyprctl layers` and `hyprctl clients`
rather than slept on, shot with `grim`, and closed again (a menu is cancelled the way
Escape would). Before every shot Hyprland's own notifications are dismissed
(`hyprctl dismissnotify`): on 0.56 two overlay toasts appear at login, that
`hyprland-guiutils` is not installed (the repositories' answer is in the job's
`versions.txt`) and that the `.conf` config format goes in 0.57 (the Lua migration, left
for then; `hyprland-guiutils` is in the image now); a user clicks them away and they
are not the desktop. The Tokyo Night scene waits for the switch itself, not the toast:
the wallpaper re-drawn (its digest before and after is logged), swaybg replaced after
that, the bar strip showing the new ground in a probe shot (the same `assemble.py
check --region --dominant` the frame gets; Waybar re-creates its surface on `SIGUSR2`,
but the new surface may take the old one's address, so the addresses are logged and
not waited on), then a second for the re-render, and its shot's bar strip (the top
32 px, `window#waybar { background: @ground }`) must be dominated by the new theme's
ground as the render has it (`assemble.py check --region --dominant`). The whole frame cannot be the measure: the terminals of the `ward up` and
`ward watch` scenes still cover most of it in Ward Dark, as open terminals do on any
desktop (foot reads its colours once, at start), and the wallpaper shows only in the
gaps. `assemble.py` makes the GIF from
the shots with each scene's milliseconds, 1280x720 and 128 colours. Every shot is described in
the job log (size, how many colours, the dominant one), and a required scene that does
not come up fails the job with a shot of what was on screen instead, every client's log,
`hyprctl` monitors, layers and clients, the processes, Hyprland's log without its trace
lines (plus the last forty of them), the DRM nodes, the EGL vendor, seatd's log and any
crash report; the lock screen is optional and is left out, with a warning,
when hyprlock cannot draw there. The GIF and the shots are the artifact
`wardos-desktop-capture`, the logs on failure `wardos-desktop-capture-logs`.

What it does not show, and why: the boot splash (Plymouth is not a compositor surface),
anything an agent does (CI has no model key: the agent at work, an approval), `ward
verify` and its `STALE` (the verifier runs ward-demo's `cargo test` in a user namespace;
the container has neither), and typed input (the capture presses no keys: the key
prompt, a cloned repository). The session is `ward up` on a copy of `examples/ward-demo`,
which needs no sandbox. Every pixel is the compositor's; nothing is drawn afterwards.

No workflow writes to the repository. A maintainer brings a run's GIF into
`assets/wardos-desktop.gif`, from the newest green run on `main` or from a release tag
captured with `gh workflow run desktop-capture.yml --ref vX.Y.Z`, and commits it in a
pull request:

```sh
desktop/capture/refresh.sh [--ref vX.Y.Z | --run ID]
```

For a host that cannot reach the artifact store (GitHub keeps artifacts on Azure blob
storage), a run started by hand with `gh workflow run desktop-capture.yml -f
inline_gif=true` also prints the GIF into the job log as one base64 line between
`-----BEGIN WARDOS-DESKTOP-GIF-----` and `-----END WARDOS-DESKTOP-GIF-----`, with
`size=<bytes> sha256=<hex>` on the line before to check the decode against; a GIF over
2 MiB is left to the artifact and the step says so. Pull-request runs never inline.

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
| Themes (set, next, install, remove, backgrounds) | `wardos-theme`, TOML tokens rendered per component | ✔ `wardos-theme list\|current\|set\|next\|install\|remove\|render\|reload\|bg next`, `wardos-theme-render` (crate `desktop/theme`, `cargo test -p wardos-theme`), 14 themes, each with a wallpaper drawn from its tokens (`background.png`); `desktop/tests/theme.test.sh`. Keys `Super + Shift + T` / `B` belong to the keys slice |
| Font switching | `wardos-font` | ✔ `wardos-font list\|current\|set`; `desktop/tests/font.test.sh` |
| Web apps in Chromium app mode | `wardos-webapp` | ✔ `wardos-webapp install\|remove\|list` (+ `install --defaults`), `wardos-launch webapp`, 13 defaults in `desktop/webapps/`; `webapp.test.sh`, `launch.test.sh` |
| TUI apps as windows | `wardos-tui` | ✔ `wardos-tui install\|remove\|list` (+ `install --defaults`), `wardos-launch tui`, 7 defaults in `desktop/tuis/`, `Super + D` / `T`; `tui.test.sh`, `launch.test.sh` |
| Screenshots (hyprshot + satty) | `wardos-capture screenshot` (grim, slurp, satty) | ✔ `wardos-capture screenshot region\|window\|output`, `Print` / `Shift + Print` / `Ctrl + Print`; `capture.test.sh` |
| Screen recording | `wardos-capture record` (wf-recorder) | ✔ `wardos-capture record region\|output` (toggle, pid in `$XDG_STATE_HOME/wardos/record.pid`), `Alt + Print`; `capture.test.sh` |
| Colour picker | `wardos-capture color` (hyprpicker) | ✔ `wardos-capture color`, `Super + Print`; `capture.test.sh` |
| Lock screen, idle, suspend | hyprlock, hypridle, `wardos-power` | ✔ config: `config/hyprlock` (the theme's wallpaper under a panel veil, the clock, the accent-bordered input, the WARD mark; `configs.test.sh`), `config/hypridle`, `Super + Escape`; `wardos-power lock\|suspend`, `wardos-toggle idle` (`Super + Ctrl + I`); `power.test.sh`, `toggle.test.sh` |
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
| Install packages / AUR | `wardos-install app` (Flathub), `package` (bootc layer) | ✔ `wardos-install app\|package\|webapp\|tui\|theme\|font\|dev\|service` (`dev rust` = rustup into the home, the verifier's toolchain), `wardos-remove` the same; `wardos-install.test.sh`, `remove.test.sh` |
| Dev environments (mise) | `wardos-install dev <lang>` | ✔ `mise use -g <lang>@latest`, a clear message without mise; `install.test.sh` |
| Docker + lazydocker | podman, podman-compose, podman-tui | |
| Terminal (Alacritty/Ghostty), bash, prompt, aliases | foot default, alacritty shipped, `config/bash` | ✔ `config/foot`, `config/alacritty`, `config/bash` (prompt tested in `configs.test.sh`) |
| Neovim (LazyVim) | neovim with a WardOS config and per-theme colours | ✔ config: `config/nvim` (self-contained, `lua/plugins.lua` hook) |
| btop, fastfetch, fzf, ripgrep, fd, bat, eza, zoxide | shipped, configured, themed | ✔ config: `config/btop`, `config/fastfetch`, aliases and fzf/zoxide hooks in `config/bash` |
| Chromium default browser, theme colour | chromium, `chromium.json` fragment | ✔ config: `config/chromium/chromium-flags.conf`, `BROWSER=chromium` |
| Nautilus | nautilus | |
| Plymouth boot splash | WardOS Plymouth theme | ✔ `image/rootfs/usr/share/plymouth/themes/wardos/` (WARD on the ground, 2 px progress, passphrase prompt), selected in the `Containerfile` and in the initramfs (the image build proves it); its look at boot is E-09's |
| Login screen into Hyprland | greetd greeter (graphical, Ward Dark) → uwsm | ✔ `image/rootfs/etc/greetd/` (`config.toml`, `wardos-greeter.css`, the `greeter` sysusers), `image/rootfs/usr/libexec/wardos-session` (uwsm + fallback), enabled in the `Containerfile`; `greeter.test.sh`. A real login screen, not autologin (ADR-0024); the user is created by first-boot provisioning (ADR-0027), not baked into the disk |
| Full-disk encryption at install | `image/disk.sh` (Anaconda kickstart on the ISO, on by default; bootc-image-builder has no LUKS) | ✔ `image/disk.sh --type iso` encrypts unless `--no-luks` (ADR-0017), `install.test.sh`; passphrase prompt unverified until E-09 |
| omarchy-update, migrations | `wardos-update` (bootc upgrade, flatpak, refresh) | ✔ `wardos-update [system\|flatpaks\|themes\|configs\|--status\|--check] [--allow-rollback] [--require-provenance]` (ADR-0028 §5's states one per line, the anti-rollback floor, failures as states; "Update states"), `wardos-refresh <component>\|--all`; `update.test.sh`, `update-states.test.sh`, `refresh.test.sh`; image side: `bootc upgrade`, `image/boot/README.md` |
| Snapshots and rollback (Limine + snapper) | bootc deployments, `bootc rollback` | ✔ every upgrade keeps the previous deployment; `bootc rollback` (`image/boot/README.md`) |
| Install on an existing Arch | `desktop/install.sh` on an existing Fedora | ✔ `desktop/install.sh` (dnf or rpm-ostree, `--dry-run`), `install.test.sh` |
| Share a file over LAN | `wardos-share` | ✔ `wardos-share [--port N] <file>` (python3 http.server, qrencode); `share.test.sh` |
| XCompose special characters | `config/xcompose` | ✔ `config/xcompose/XCompose`, compose on Right Alt |
| Apple display brightness | `wardos-setup monitors` (ddcutil, asdcontrol when present) | |

Then some (WardOS only):

| Feature | Delivers | Delivered |
| --- | --- | --- |
| Agent state, network, TamperWard and verification in the bar | `ward-shell bar --waybar [--segment mark\|session\|project\|agent\|network\|grants\|credentials\|observer\|tamperward\|verify\|daemon] [--follow [--tick-ms N]]`, one JSON module per segment with the tone name and the agent or verify state word as classes; `launcher --lines` for the command centre. One shared per-session projection and subscription across the six segments (#138 item 2): `wardos-shell-worker.service` runs `ward-shell worker`, started before `waybar` on the plain-`Hyprland` path too (`autostart.conf`); it keeps the one `Snapshot`, the one daemon subscription and the one (unconditional) digest schedule; each `bar --waybar --follow` process asks it first (`relay_from_worker`, a request line naming its segment or `bar`, then the worker's own `Module` JSON lines copied straight to stdout), retrying a few times, quickly, before giving up on a cold-start race (the worker not bound yet) — and only subscribes and digests for itself, exactly as before this item, when nothing answers even after those retries, or answers but goes quiet (wedged, its own handshake timeout), or an explicit `--dir` (the worker does not serve one) or `--tick-ms` (the worker runs one fixed cadence for every segment, so honouring a caller's own would mean every other connected segment gets it too — asking anyway would silently turn that option into a no-op) was named | ✔ `ward-shell-core` `waybar::tests::every_segment_is_a_module_in_the_{live,sealed}_state`, `every_segment_is_the_empty_module_with_no_session_except_the_mark`, `trust::tests::every_segment_is_addressable_by_name_live_and_sealed`, `launcher::tests::lines_are_section_label_and_shell_command_for_a_described_session`; `ward-shell` `{waybar_flags_parse_and_need_waybar,the_worker_is_asked_only_with_no_explicit_dir_and_no_explicit_tick}`; `ward-shell` `worker::tests::{a_new_session_serves_the_cached_module_immediately_and_only_pushes_real_changes,every_segment_of_one_publish_shares_one_instant_and_one_snapshot,a_session_ending_closes_every_subscriber_and_a_later_one_gets_none,two_relay_clients_for_different_segments_each_get_only_their_own_updates,serve_session_publishes_every_segment_from_one_real_subscription,a_cold_start_race_still_converges_every_relay_client_onto_the_worker,relay_falls_back_when_{nothing_is_listening,the_worker_accepts_but_never_answers},waiting_for_a_session_pauses_one_interval_per_empty_look_and_logs_the_reason_once,a_changed_reason_or_error_while_waiting_is_logged_once_per_change}`, `desktop/shell/tests/worker_idle.rs` (`a_worker_with_no_session_waits_quietly_and_stays_alive`: the spawned worker, no session, one line and still alive after 5.5s); `configs.test.sh` (`wardos-shell-worker.service`, and that `autostart.conf` starts it before `waybar`) |
| Verification bound to the snapshot it judged (ADR-0019 decision 1) | the eight-state `VERIFY` segment (`—` `◐` `✓` `~ STALE` `✗` `! ERROR` `! CANCELLED` `! INTERRUPTED`, #139) decided by digesting the worktree and comparing with the verified candidate; `ward-shell verify-panel` and the segment's click | ✔ `ward-snapshot` `digest_worktree`/`digest_manifest` (`tests/digest.rs`: `the_digest_is_the_id_a_capture_would_store_and_writes_nothing`, `the_hash_cache_makes_the_second_digest_cheap`); `ward-shell-core` `trust::tests::the_verify_segment_is_an_eight_state_machine_over_the_stream_and_the_worktree`, `panel::tests::the_verify_panel_holds_the_verdict_against_the_worktree`, `waybar::tests::the_verify_module_goes_stale_with_the_worktree_and_says_how_far`; `ward-shell` `the_verify_segment_follows_the_worktree_by_content`, `a_warm_digest_of_the_demo_is_within_the_bar_budget`; `ward-daemon` `verify_ignores_a_weakened_protected_test_and_passes_the_real_fix` (the record's candidate is the worktree's digest); `configs.test.sh` (the click) |
| Approvals that separate the agent's claim from Ward's authority (ADR-0019) | `wardos-approve`, daemon hold on `ask` (`agent-integration.md` §4.1: `Request::Hold`/`Approve`/`Pending`, `ward session pending [--json] [--follow]`, `ward session approve`); the daemon derives `authority` (destination, network, method, credential, repository, lifetime) from the manifest, never from the agent's text; the notification is the three blocks of `design-language.md` §10 with the target in `<tt>`; `wardos-approve.service` is the listener | ✔ `ward-daemon` `approvals::tests::a_fetch_to_a_host_{with_a_credential_rule_derives_the_rule_and_the_grant_state,without_a_credential_rule_reports_the_proxys_verdict_and_no_credential}`, `approvals::tests::a_write_to_a_protected_path_is_refused_in_the_authority_and_a_plain_write_is_not`, `approvals::tests::a_command_shows_the_program_the_proxy_and_every_granted_credential`, `hooks::tests::a_held_ask_{waits_for_the_answer_and_relays_it,nobody_answers_is_denied_when_the_timeout_passes}`, `daemon::tests::a_held_approval_is_recorded_listed_answered_and_recorded_again`, `client::tests::{pending_and_approve_go_through_the_daemon,follow_pending_emits_what_is_pending_after_the_backlog_then_on_each_request}`; `desktop/tests/approve.test.sh` |
| Every approval given a terminal record and a persistent, queryable lifecycle (#146 item 1; daemon slice, see the next row for the desktop-facing half) | a still-open approval released by the session ending now gets its own `CapabilityDecided` record (`by: SessionEnded`) appended *before* `SessionEnded` and the seal, instead of silently vanishing at the seal; `Request::Approvals` / `ward session approvals [--follow] [--all] [--json]` lists every approval the session has asked, pending or decided (`pending`\|`allowed`\|`allowed-session`\|`denied`\|`timed-out`\|`session-ended`), not only what is still open — a bounded in-memory history (`Approvals::HISTORY_CAP`, oldest dropped first), so a request survives a client missing or dismissing whatever first announced it, for the rest of the session | ✔ `ward-daemon` `approvals::tests::{closing_releases_every_open_question_and_refuses_new_ones,closing_leaves_an_uncollected_answer_alone,the_approvals_view_lists_pending_and_bounded_history_by_request_order,the_decided_history_is_bounded_oldest_dropped_first,outcomes_become_hook_responses_and_log_records}`, `daemon::tests::{a_held_approval_is_recorded_listed_answered_and_recorded_again,request_approvals_lists_pending_and_decided_oldest_asked_first}`, `control::tests::approval_requests_and_responses_round_trip_with_their_words`, `client::tests::pending_and_approve_go_through_the_daemon`; `ward-cli` `session_pending_and_grants_take_json_and_print_the_three_blocks` |
| A persistent approval inbox, and notifications that update or close themselves (#146 items 2-3) | `wardos-approve-inbox` (`Super + Alt + A`, SECURITY ▸ Approval inbox in the command centre): every approval `ward session approvals --json --all` knows across every live session, pending first, fuzzel-dmenu style; a pending choice opens `wardos-approve <id>` in a terminal pinned to that approval's own session (`WARDOS_SESSION`, mirroring `wardos-pause`'s own pinned target), a decided one shows a read-only summary, so a request whose notification was missed, dismissed, or never shown at all (past the worker bound below) is never unreachable. The inbox does not misstate a failure either (#146 item 5 and its daemon-disconnect/expiry-before-click acceptance): the pending choice's terminal is opened through `wardos-launch run`, so it stays open on how the answer ended — `ward session approve`'s own `approval <id> <decision>` once the daemon has taken it, or the daemon's refusal (`not pending`, `timed out`) or connection error with `[failed, exit N]` — and an approval gone by the time that terminal asks for it (answered elsewhere, or expired before the click) is `wardos-approve: approval <id> is not pending`, a failure, rather than `no pending approvals`; a session `ward session approvals --all` could not ask (`{"session", "error"}`, #141 finding 5) is its own read-only `unreachable` row after the pending ones, never read as a pending approval with empty fields; and a listing that fails outright is a critical `Approval inbox unavailable` notification carrying the error, not a silent exit from a keybinding. `wardos-approve --watch` follows each live session that has an open notification with its own `ward session approvals --json --follow --session <id>` (`client::follow_approvals`): when an approval it is still showing a notification for becomes terminal elsewhere (answered from another terminal, timed out, or the session ended with it open), the popup is replaced in place (`notify-send -r`, low urgency, no actions) rather than left offering an action nothing will honour. Live `notify-send --wait` workers are bounded (`WARDOS_APPROVE_MAX_NOTIFIERS`, default 10 — past it a new approval is left to the inbox); every one started is reaped the moment its approval resolves — given a bounded grace window, in parallel, to settle on its own first, so an answer already in flight is never raced against the round's own end — or in a final sweep, so many approvals across many live sessions, or one nobody dismissed, cannot keep this listener from moving on to the next round of live sessions. `--all` has no `--follow` counterpart: a live, multiplexed decided-feed across every session is not needed, since each session with an open notification is already followed individually. Remaining decision time and pause holding it came after (#146 item 4, row below). Duplicate-notice grouping came after too (#146 item 7, row below); the persistent inbox itself is this row's own non-notification fallback | ✔ `ward-daemon` `client::tests::{follow_approvals_emits_pending_once_then_its_outcome_once,approvals_all_reports_a_per_session_outcome_and_never_hides_an_unreachable_one}`; `ward-cli` `tests::{session_pending_and_grants_take_json_and_print_the_three_blocks,session_pending_all_and_select_parse}` (the `--follow`/`--all` parses); `desktop/tests/approve.test.sh` (worker bound, resolve-elsewhere, no-notify-send, `WARDOS_SESSION`, an explicit id with nothing pending), `desktop/tests/approve-inbox.test.sh` (unreachable row, failed listing, the held terminal's accepted/refused/gone outcomes) |
| Remaining decision time, held while paused (#146 item 4) | The daemon keeps one decision clock per open approval (`approvals.rs` `Clock`, armed with the `Hold`'s own `timeout_secs` as it is registered): `Approvals::wait` times out on it, `ward pause` holds it where it stands and `ward resume` runs it on from there — so a pause neither spends nor refunds decision time (before this, `wait` kept its own count and a pause/resume handed back whatever had run since its last wake) — and `Request::Pending`/`Request::Approvals` report it on each open question as `countdown { remaining_ms, timeout_ms, held }` (`ward session pending|approvals --json`; absent for a decided question, and read as absent from an older daemon). The desktop shows that figure and never derives one from when a request arrived: `wardos-approve --watch` sends it as mako's progress line (`-h int:value:<percent left>`, §10: not a number) and adds a `DECISION TIME` block reading `held while paused · resume the session to answer` for a held one; the terminal path (`wardos-approve [<id>]`), `ward session pending` and each pending inbox row give it in words (`42 s left, then denied`, `held while paused · 45 s left once resumed`). The deny-on-timeout itself is unchanged, and an answer that reaches the daemon once the clock has run out is refused (`timed out`) rather than overtaking the timeout. Every one of these figures is a snapshot of the daemon's clock as the surface is rendered. Not in this change: redrawing a notification that is already showing, whether as its clock runs down or when its session is later paused or resumed (the popup's line and held block are fixed as it opens; the inbox and the terminal re-read the daemon each time they open) | ✔ `ward-daemon` `approvals::tests::{a_countdown_runs_down_is_held_while_paused_and_runs_on_from_where_it_stood,a_pause_neither_spends_nor_refunds_the_time_wait_enforces,only_an_open_question_with_an_armed_clock_carries_a_countdown,a_countdown_travels_as_json_only_when_there_is_one_and_reads_as_words,a_paused_hold_stops_the_clock_refuses_answers_and_keeps_questions,an_answer_to_a_question_whose_clock_ran_out_before_wait_is_refused,an_answer_racing_the_timeout_at_the_deadline_cannot_win}`, `daemon::tests::{a_held_approval_is_recorded_listed_answered_and_recorded_again,pause_holds_approvals_writes_the_marker_and_records_until_resume_or_stop}`; `ward-cli` `tests::session_pending_text_shows_the_daemons_decision_time_when_it_has_one`; `desktop/tests/approve.test.sh` (progress hint, held block, terminal words), `desktop/tests/approve-inbox.test.sh` (row words) |
| Duplicate-notice grouping, and a non-notification fallback (#146 item 7) | `wardos-approve --watch` folds two or more pending approvals into one notification only when they are exact duplicates — same session, agent, project, claim and the authority the daemon derived (`group_key`: a hash of the rendered title and body, never the id) — so an agent that fires the same tool call more than once before the first is answered opens one popup, not several; the title carries a count (`×N`) as a snapshot taken shortly after the first of the group is reserved, not a live figure (mirrors item 4's own snapshot semantics: a duplicate arriving after that window still joins the group and is still answered with it, just without growing the shown count). One action answers every id gathered under the key and nothing else — never a broader grant than what is shown — and grouping never crosses sessions, even when two different sessions' titles and bodies would otherwise read identically. Keyboard navigation and readable text labels beyond fuzzel's own (the inbox's `wardos-approve-inbox`, `Super + Alt + A`) remain out of scope: the notification popup itself is still mouse/notify-send-action driven, and the inbox — reachable independently of whether any notification was ever shown — is this feature's own answer to "keyboard-first and not dependent on a popup at all" | ✔ `desktop/tests/approve.test.sh` (`(×N)` in the title, one popup for two duplicates and both answered, no grouping across sessions, a partially-externally-resolved group stays open for what is left) |
| Temporary authority visible while it exists (ADR-0019) | `ward session grants [--json]` (`Request::Grants`: `allow-session` answers and `--grant` credentials with scope and lifetime); the bar's `network` module reads `NET restricted · github+` and keeps opening the read-only `ward-shell authority-panel`; the `grants` module reads `GRANTS n` and opens `wardos-grants`, an on-demand picker bound to the desktop's selected session exactly once. Choosing a listed daemon-minted grant id asks for confirmation, then runs the existing host-confirmed `ward session revoke <id> --session <session>` path and surfaces its exact three-way result: revoked, revoked with already-open connections still draining, or could not be confirmed (non-zero, visibly critical). A selection change while the picker is open cannot retarget the revoke because both listing and mutation use the same pinned session | ✔ `ward-daemon` `approvals::tests::grants_list_the_credentials_injected_and_the_allow_session_answers`, `daemon::tests::a_granted_credential_is_temporary_authority_the_daemon_lists_and_derives_from`; `ward-shell-core` `authority::tests::*`, `waybar::tests::a_live_grant_changes_the_network_module_and_shows_the_grants_module`; `desktop/tests/grants.test.sh`, `configs.test.sh` |
| Pause as a host primitive (ADR-0019 §3) | `wardos-pause` on `Super + Shift + P`; `ward pause [--reason] [--status]`, `ward resume`, `ward stop [--session <id>] [--restore-entry]`; the daemon's `Request::Pause`/`Resume` freeze the sandbox tree (cgroup v2 freezer when a delegated cgroup can be made, else `SIGSTOP` children first), write the marker every session proxy refuses on (`503 paused by ward`, no credential injected), hold the approvals, and append `SessionPaused`/`SessionResumed`; `ward stop` ends every sandboxed process and confirms both the pre-kill membership barrier and termination before sealing (`WorkloadsTerminated`; `pending > 0` **or** `barrier_confirmed: false` is a refused/incomplete stop, durably retained even when zero PIDs are still known, so replay and the bar keep reading `STOP?` until a confirmed retry; `ward resume` and `wardos-pause`'s Resume are refused with a critical `RESUME REFUSED` notification), and `--restore-entry` has the daemon hold the session frozen for the stop first; `ward stop --session <id>` stops that session itself (`Session::open_live`), never re-resolved, refused with nothing stopped when it is not live, and every stop prints the same `resolved-session:` line pause and resume print; `wardos-pause`'s Stop exits pass `WARDOS_SESSION` as that pin; the bar's agent segment reads `PAUSED` in the denied tone; `EntryRestored` records a restore. **Restart reconciliation (#145 item 7):** every pause and stop writes its intent (`sessions/<id>/intent.json`: operation id, verb, reason, start time) durably before anything is signalled and removes it once its outcome is on the log; a `wardd` started on the session finishes the operation before serving — an interrupted stop is ended, recorded with the real counts and sealed (or held with `WorkloadsTerminated { pending }` when termination cannot be confirmed, as a refused stop is), an interrupted pause is frozen from what `/proc` shows and recorded as `SessionPaused` only when confirmed, and a hold that had completed is adopted so Resume and Stop act on it; `ward pause --status` / `wardos-pause --status` read `unconfirmed` while an intent has no outcome, so the bar never shows `paused` on the strength of a marker whose pause never finished. **Per-component acknowledgement (#145 item 3):** after the freeze settles the daemon collects a bounded acknowledgement from every egress of the session (each registers under `sessions/<id>/proxies/` and rewrites its state as the marker flips it, `ward_daemon::acks`), from the approvals and from credential mediation, in that order; `SessionPaused` is recorded only when the freeze and every component confirmed, otherwise `SessionPauseUnsettled` names the first unconfirmed component in its `reason` and the bar reads `PAUSED?` with the component on the agent segment's hover; `ward resume` releases in the reverse order and is refused, with the session kept paused, when a release is not confirmed; `ward stop` requires the same acknowledgements before `WorkloadsTerminated`; `ward pause --status --json` carries `unconfirmed`. **Capture holds and hold ownership (#145 item 6):** a snapshot capture (`ward snapshot create`, `ward verify`'s candidate, the restore's capture) proceeds only from confirmed quiescence — the freeze settled and every component acknowledged — under a hold of its own (`Request::HoldForCapture`/`ReleaseCapture`; `pause::LocalCaptureHold` without a daemon), recorded as `SessionPaused` with a `ward capture: …` reason when nothing held the session before, and refused with nothing held or recorded otherwise; every hold has owners (`held_by.json`: user, capture, stop) and `ward resume` releases only the user's layer — refusing a hold only a capture owns (`RESUME REFUSED`), and, over a capture, leaving the session held for it (`wardos-pause` notifies `Agents still held for capture`); the bar reads `PAUSED (capture)` while a capture is the only owner and `ward pause --status --json` carries `held_by` | ✔ `wardos-pause [pause\|resume\|menu\|--status]`, `Super + Shift + P`; `pause.test.sh`; `ward-daemon` `pause::tests::*`, `approvals::tests::a_paused_hold_stops_the_clock_refuses_answers_and_keeps_questions`, `daemon::tests::pause_holds_approvals_writes_the_marker_and_records_until_resume_or_stop`, `egress::tests::the_marker_pauses_and_resumes_the_proxy`, e2e `pause_freezes_the_sandbox_closes_the_proxy_and_resume_lets_it_finish`, `restore_entry_materialises_the_snapshot_and_keeps_what_it_replaced`, `stop_ends_a_running_sandbox_before_the_log_is_sealed` and `stop_restore_entry_through_the_daemon_pauses_restores_then_terminates`; `daemon::tests::a_stop_that_cannot_confirm_termination_is_refused_and_held_paused_until_a_retry`, `daemon::tests::an_unconfirmed_stop_barrier_with_zero_known_pids_is_durable_until_retry`, `daemon::tests::working_then_a_refused_stop_then_resume_is_refused_and_only_the_retry_finishes`; `daemon::tests::{a_pause_records_its_intent_before_the_freeze_and_clears_it_with_its_record,a_stop_records_its_intent_before_terminating_and_clears_it_at_the_seal,a_refused_stop_clears_its_intent_once_the_hold_is_recorded,a_restart_during_a_pause_before_the_freeze_finishes_the_pause,a_restart_during_a_pause_after_the_freeze_records_what_it_cannot_confirm,a_restart_during_a_stop_before_the_kill_finishes_the_stop,a_restart_after_the_termination_record_but_before_the_seal_only_seals,a_restart_whose_stop_cannot_confirm_termination_holds_the_session_until_a_retry,a_restart_after_a_completed_pause_adopts_the_hold_without_a_second_record,a_restart_after_a_refused_stop_adopts_the_hold_for_the_stop,a_restart_with_nothing_in_flight_changes_nothing,an_unreadable_intent_refuses_to_serve}`, `session::tests::a_daemonless_stop_records_its_intent_before_terminating_and_clears_it_with_its_outcome`, `restart_reconciliation::{a_restarted_wardd_finishes_a_stop_interrupted_on_a_running_sandbox,a_restarted_wardd_finishes_a_stop_interrupted_before_anything_ran,a_restarted_wardd_finishes_an_interrupted_pause_and_serves_the_hold}`; `ward-cli` `tests::pause_status_word_is_unconfirmed_while_an_intent_has_no_outcome`; `ward-daemon` `acks::tests::*`, `daemon::tests::{a_pause_whose_proxy_does_not_acknowledge_is_unsettled_naming_it,a_pause_whose_approvals_do_not_confirm_is_unsettled_naming_them,resume_releases_the_components_in_reverse_order_and_confirms_each,a_resume_whose_proxy_does_not_confirm_release_keeps_the_session_paused,a_stop_waits_for_every_component_before_recording_termination,a_hold_for_stop_whose_component_does_not_confirm_is_refused_but_stands,reconciliation_re_collects_the_acknowledgements}`, `egress::tests::the_marker_pauses_and_resumes_the_proxy` (the registration), `component_acks::*` (a real daemon driven through the real file protocol by a stand-in egress); `ward-cli` `tests::{pause_status_json_names_what_the_hold_could_not_confirm,pause_uncertainty_lines_name_the_freeze_and_the_component}`; `ward-shell-core` `feed::tests::an_unconfirmed_component_is_named_until_the_hold_is_confirmed_or_released`, `waybar::tests::the_agent_segment_explains_an_unconfirmed_component_on_hover`; `ward-shell-core` `feed::tests::a_refused_stop_is_an_incomplete_stop_until_the_retry_confirms_it`; `ward-daemon` `daemon::tests::{a_capture_hold_proceeds_from_a_settled_and_acknowledged_freeze,a_capture_from_an_unconfirmed_freeze_is_refused_with_nothing_held_or_recorded,a_capture_over_a_user_pause_that_cannot_be_reconfirmed_is_refused_leaving_the_pause,resume_refuses_a_hold_owned_only_by_a_capture,resume_releases_only_the_users_layer_over_a_capture,a_captures_release_leaves_the_users_pause_in_place,a_stop_hold_takes_over_a_captures_hold,reconciliation_releases_an_orphaned_capture_hold_but_not_a_user_hold,resume_releases_a_capture_hold_whose_capturer_is_gone}`, `pause::tests::{holders_name_their_owners_in_order_round_trip_and_forget_dead_capturers,a_local_capture_hold_freezes_marks_records_and_releases,a_local_capture_that_cannot_confirm_quiescence_is_refused_and_leaves_nothing}`, `session::tests::a_daemonless_snapshot_holds_the_sandbox_for_the_capture_and_records_it`, `control::tests::capture_hold_requests_round_trip_and_are_not_served_on_a_log_connection`, `capture_hold::*` (a real daemon, a writer found as the session's sandbox, a stand-in egress acknowledging); `ward-cli` `tests::{pause_status_json_lists_who_holds_the_session,resume_explains_a_hold_that_stays_for_a_capture}`; `ward-shell-core` `feed::tests::a_capture_hold_is_paused_for_capture_until_a_user_pause_or_the_release`, `trust::tests::the_agent_segment_names_a_hold_that_is_only_a_captures`; `ward-daemon` `session::tests::open_live_reaches_only_the_pinned_live_session`; `ward-cli` `tests::{stop_session_parses,stop_pinned_to_a_session_never_re_resolves_and_fails_closed,resolved_session_line_for_an_id_matches_the_socket_form}`; `ward-proxy` `proxy::tests::a_paused_proxy_refuses_new_requests_and_resumes_cleanly`; `ward-shell-core` `trust::tests::every_agent_state_has_a_glyph_a_word_and_a_tone` |
| Explicit session targeting with multiple live sessions (#141) | A shared, host-owned selection (`ward_daemon::selection`, `<state>/desktop-selection.json`: session id + generation, bumped on every change) `client::desktop_socket` falls back to instead of each caller independently recomputing "newest live" — the bar, `wardos-approve`, `wardos-pause` and `ward session select` all agree; `ward session pending --all [--follow]` and `wardos-approve --watch` multiplex every live session's approvals (`client::follow_pending_all`), each line naming its `session` and `project`; `ward pause --session <id>` / `--all` and `wardos-pause`'s `WARDOS_SESSION` / `pause-all` give "pause this session" (an immutable id, never re-resolved) and "pause all sessions" (`client::pause_all`, one result per session) as distinct, explicit scopes; `ward-shell switcher [--lines]` and `wardos-session-switch` (`Super + Alt + S`) are the keyboard-first switcher of item 3, each line bound to its own session's id. An id already in hand (an approval's `--session`, a pinned pause) never consults the selection, so switching it cannot retarget an action already bound to a session (item 6). **Registry (item 1):** `ward_daemon::registry::snapshot(state, settle)` reads every live session's project, agent, running/paused state and pending-approval count fresh on each call — from the same `describe`/`pending`/`Subscribe` a session's own socket already answers, not a second persisted copy — plus the last verification attempt's outcome (`VerificationState`), bundled with the current `Selection` in one `Registry`; this is the shared data structure `ward-shell`'s bar/panels and the switcher are meant to bind to instead of each re-deriving it, and the switcher below is the first of those to actually do so. **Bound into the switcher (item 2, partial):** `ward-shell switcher` now reads the desktop's shared selection and each line's pending-approval count from that one `registry::snapshot` call, replacing its former separate `selection::current` read and a second per-session `Pending` request; the live-session list itself still comes straight from `live_sessions` (a session whose *own*, separate registry-side probe hit a disconnect must not flicker out of a switcher that otherwise still reaches it, so list membership deliberately does not move to `registry.entries` — see the `switcher` doc comment), and its per-line agent/verify text still needs its own `load_from` subscription for the tone-aware bar text and worktree-freshness digest the registry's coarser facts don't carry. The bar's single-session surfaces and other panels (item 2's remaining scope) are not bound to the registry yet. **Item 3, unpinned-toggle gap:** an explicit id already in hand was always immune to a selection change (above), but an *unpinned* `wardos-pause`/`ward pause`/`ward resume` (no `WARDOS_SESSION`, run from a directory with no session of its own) could resolve through `desktop_socket`'s fallback to the desktop's shared selection or the newest live session — a different project than the one named on the command line — while its confirmation said only "AGENTS PAUSED"/"Agents resumed" with no project named, letting the acknowledgement read as confirmation of whatever directory the caller happened to be in. `ward pause`/`ward resume` now print a `resolved-session: {"id":…,"project":…}` line naming the session `desktop_socket` actually resolved to, and `wardos-pause`'s one notification for a keybind press includes that project path, unpinned or not. JSON-encoded rather than plain text: a project path is an arbitrary Unix path and may itself contain a newline, which a line-oriented record can't carry without truncating the path or splitting the record across two physical lines — `jq` decodes the escaped value exactly, whatever it holds. An unpinned raw hotkey with no display-time value to bind to (no switcher line, no panel row) still resolves the current selection at keypress time — fail-closed live behavior, not staleness — so this closes the acknowledgement gap rather than inventing a "previously displayed" binding that does not exist for a bare hotkey; Waybar's `on-click` handlers are unaffected since each already opens an interactive panel rather than firing a destructive action directly | ✔ `ward-daemon` `client::tests::{desktop_socket_shares_a_registry_backed_selection_across_calls,desktop_socket_replaces_a_selection_whose_session_is_no_longer_live,pause_all_reports_a_per_session_outcome_ok_or_error,follow_pending_all_multiplexes_every_live_sessions_approvals}`, `selection::tests::*`, `registry::tests::*` (project/agent/pending, pause and pause-unsettled both report not-running, resume restores the pre-pause state, a passed/in-flight verification is reported, an unreachable session is skipped rather than failing the snapshot, concurrent snapshots agree), `daemon::tests::the_newest_served_session_is_the_desktops_session`; `ward-cli` `tests::{session_pending_all_and_select_parse,pause_resume_and_restore_entry_parse,resolved_session_line_names_the_session_actually_behind_the_socket,resolved_session_line_is_none_for_an_unknown_session,resolved_session_line_carries_a_newline_in_the_project_path_intact}`; `ward-shell` `tests::{the_cli_parses_and_defaults_to_the_bar,switcher_label_names_the_project_agent_state_pending_count_and_marks_the_selection,switcher_binding_joins_by_session_id_not_position}`; `ward-shell-core` `launcher::tests::the_launcher_lists_the_four_sections_in_order_with_session_rows` (`Pause all sessions`); `approve.test.sh` (multiplexed `--watch`), `pause.test.sh` (`pause-all`, `WARDOS_SESSION`, the unpinned-fallback resolved-session notification, an embedded newline and a trailing newline in the resolved project both surviving intact, a line that only substring-matches the record marker being ignored), `configs.test.sh` (`Super + Alt + S`) |
| Verify, replay, evidence, snapshots, grants in the menu | `wardos-menu` SECURITY | ✔ from `ward-shell launcher --lines`, static `ward` list without it; `menu.test.sh` |
| Sandboxed browser profile per project | `wardos-launch browser --project` | ✔ chromium profile under `~/.local/share/wardos/browser/<hash>`; `launch.test.sh` |
| The first five minutes (ADR-0017) | `wardos-welcome` from `wardos-first-run`, Help ▸ Welcome and the command centre's `Start here` row; `ward init` (policy template, verifier config, `.gitignore`, TamperWard wiring), `ward vault set\|list\|rm\|path`; the shell's no-session line | ✔ `wardos-welcome [--again] [theme\|keys\|project\|agent\|done]`; `welcome.test.sh`, `welcome-ready.test.sh`, `first-run.test.sh`, `menu.test.sh`; `ward-cli` `init::tests::*`, `vault::tests::*`, `tests/ready_proposals.rs`, `ward-daemon` `verify_proposal::tests::*`, `readiness::tests::{an_unaccepted_proposal_is_setup_required_with_the_proposal_shown,nothing_to_propose_is_unavailable_and_says_why}`, `ward-policy` `tests::the_template_*`, `ward-daemon` `gateway::tests::key_comes_from_the_vault_when_the_host_env_is_unset`, `ward-shell` `a_project_without_a_session_gets_the_next_step_not_an_error`; [`onboarding.md`](onboarding.md) |
| Package names and the whole image checked by CI | `image/packages.txt`, image build job | ✔ `image/check-packages.sh` ("image packages"), `image.yml` ("image build") |
| Claude Code, Codex and TamperWard in the image (ADR-0017) | `image/agents/package.json` + lockfile, `npm ci` at build time, `/usr/bin/{claude,codex,tamperward}` | ✔ `image/agents/`, Containerfile agents step, "What the image holds" prints the three versions; `ward doctor` rows `agents`, `node`, `keys` (`ward-daemon` `doctor::tests::{agents_lists_versions_and_names_what_is_missing_with_its_package,node_is_checked_against_the_agents_floor,keys_reports_where_a_key_is_and_never_its_value}`) |
| Host firewall, nothing inbound | firewalld enabled, default zone `wardos` (`image/rootfs/etc/firewalld/zones/wardos.xml`) | ✔ `image/rootfs/usr/lib/systemd/system-preset/90-wardos.preset`, Containerfile; `ward doctor` row `firewall` (`doctor::tests::firewall_wants_firewalld_running_with_a_closed_default_zone`) |
| A way out, workspace labels and an empty-workspace hint the first boot can find (#99, §Discoverability) | the bar's `POWER` cell (`wardos-power menu`, `Super + Shift + Escape`, SYSTEM ▸ Power), numbered workspace labels (`1 code` · `2 agent` · `3 web`), `wardos-hint` + `wardos-hint.service` (one notification per empty named workspace per login), the first-run pointer and the walkthrough's closing card, tool dialogs floating and centred where they were asked for | ✔ `hint.test.sh`; `configs.test.sh` (the power cell and its click, the label format, the unit and its autostart line, every floating dialog placed and none sent to another workspace); `first-run.test.sh` (the pointer, once, after the keys viewer); `welcome.test.sh`. Hardware confirmation on the T480s still open |
| Timed image updates, rollback kept | `bootc-fetch-apply-updates.timer` (stage only; the next boot applies), `bootc rollback` | ✔ preset + drop-in `bootc-fetch-apply-updates.service.d/wardos.conf`; "What the image holds" checks `is-enabled`; `wardos-update` stays the manual path |
