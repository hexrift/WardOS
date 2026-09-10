# ADR-0024 — A real login screen (greetd), and a boot that never stalls

## Decision
WardOS logs in through a **greetd** greeter, not a tty1 autologin, and every WardOS boot
unit is bounded so the login screen is the first thing the user sees, in seconds.

* **greetd on VT 1** (the VT Plymouth hands off to) runs a graphical greeter — `cage`, a
  single-window Wayland kiosk compositor, hosting `gtkgreet` — styled to the Ward Dark
  host-layer palette (`/etc/greetd/wardos-greeter.css`) so the login screen is visually
  continuous with the Plymouth splash before it: the same near-black ground (`#0E0F11`),
  warm off-white type (`#D9D9D6`), the WardOS mark, one violet focus accent, a denied-red
  error. It never shouts (design-language.md §2, the HOST layer).
* greetd authenticates the real user through PAM; on success `gtkgreet` runs
  `/usr/libexec/wardos-session`, which starts Hyprland under `uwsm` (so
  `graphical-session.target` and the WardOS user units come up as at any login), with a
  fallback to bare `Hyprland`. The greeter runs unprivileged as a dedicated `greeter`
  system user; `cage -s` keeps Ctrl+Alt+F2…F6 reaching a text console, so a greeter or
  session failure can never lock the machine out.
* **No boot unit may stall the path to login.** `wardos-usb-guard` no longer pulls in the
  deprecated, unbounded `systemd-udev-settle.service` (a wait for the whole udev queue,
  ordered before `sysinit.target`, that stalled the first hardware boot for minutes); it
  uses a short bounded `udevadm settle` and a `TimeoutStartSec`, ordered after udev
  coldplug and before the greeter. `wardos-firstboot` (`ward doctor`) is ordered *after*
  greetd, so the report is written once the login screen is already up and never delays
  it. Speed is a product property, not an afterthought (design-language.md §1: "Calm.
  Precise. … "; the Ward Field's "speed as identity").

This supersedes the tty1-autologin login of ADR-0007/ADR-0017 and amends the
`wardos-usb-guard` unit of ADR-0020 (the guard's purpose and safety properties are
unchanged; only its boot ordering and its removal of the udev-settle dependency are).

## Context
On the reference laptop (Hardware Baseline 1, E-09) the first hardware boot took ~331 s
to reach userspace and dropped the user into a bare tty1 autologin — no login screen, and
a startup slow enough to read as broken. Two things were wrong. First, login: an
autologin is neither the "real login screen" the product needs nor on-brand; the design
agreement (ADR-0021, design-language.md) calls for a calm, trusted HOST surface, and the
login screen is the first one a user meets. Second, speed: a default-Fedora boot chain
plus WardOS units with no timeouts let a single slow unit hold the whole boot — and
`systemd-udev-settle.service`, which WardOS pulled in early and which upstream systemd
deprecates precisely because it waits unboundedly for the entire udev queue, is the
classic offender. "Speed should be part of the product" was an explicit instruction.

## Consequences
* `greetd`, `gtkgreet`, `cage` and `librsvg2` (the SVG loader the greeter CSS needs) join
  `image/packages.txt`; CI's "image packages" job resolves the names against Fedora 44 and
  the COPRs before any image build.
* `image/rootfs/etc/greetd/{config.toml,wardos-greeter.css,wardos-mark.svg}`,
  `image/rootfs/usr/libexec/wardos-session` and
  `image/rootfs/usr/lib/sysusers.d/wardos-greeter.conf` are the login surface; the
  Containerfile enables `greetd.service` and sets `graphical.target` as default.
* The tty1 autologin drop-in is gone (`desktop/systemd/system/…/autologin.conf` removed;
  `install-desktop.sh` and `desktop/install.sh` lose their `--autologin`/`--no-autologin`
  flags), and `profile.d-wardos.sh` no longer starts a session — it only sets shell
  defaults now. A dev install on an existing Fedora keeps whatever display manager the
  host has; the WardOS greeter ships on the image.
* `wardos-usb-guard.service` and `wardos-firstboot.service` are re-ordered and bounded as
  above.
* `greeter.test.sh` asserts the greetd config, the Ward Dark theme, the greeter user, and
  the session launcher's foreground/fallback behaviour; `configs.test.sh` and
  `install.test.sh` assert the autologin path is gone.
* `systemd-analyze blame` from the reference laptop (a USB-stick boot) named the three
  heavy units, and this change addresses them: `systemd-udev-settle.service` (67 s — WardOS
  was its only puller, so it is gone), `wardos-firstboot.service` (`ward doctor`, 71 s — now
  ordered after greetd, capped, and idle-priority, so it is off the path to the login
  screen), and `ldconfig.service` (78 s — see below). Slow USB flash I/O amplified all of
  them; on the installed SSD each is a fraction of that, and every one is a *one-time*
  first-boot cost — the second boot of a deployment skips `ldconfig` (ConditionNeedsUpdate),
  `ward doctor` (its marker) and the settle wait, so it is dramatically faster.
* `ldconfig.service` (the stock glibc "rebuild dynamic linker cache") is deliberately left
  untouched. It is `ConditionNeedsUpdate`-gated (fires once per deployment, before
  `sysinit.target`) and its safe elimination is not something that can be validated without
  a hardware boot: masking risks an unbootable image if the baked cache is ever wrong, and
  reordering/stamp tricks risk a dependency cycle or, worse, suppressing the sibling
  `systemd-sysusers` run that creates the `greeter` user. A slow *first* boot is recoverable;
  an unbootable image is not. It is tracked as a follow-up pending a tested change and a
  confirmed second-boot time on E-09.
* E-09 greeter boot (first flash) exposed two greeter faults, both fixed: `gtkgreet` was
  launched with `-l` (layer-shell), but `cage` implements no `wlr-layer-shell`, so the
  greeter committed a 0×0 surface, cage dropped it and greetd relaunched it — a flicker
  loop; `-l` is dropped (cage fullscreens a plain window). And the `greeter` home
  `/var/lib/greeter` was never created, so cage had no working directory and no writable
  shader cache; a tmpfiles.d entry now creates it before greetd starts. Only a real boot
  surfaces these — CI builds the image but does not run the compositor.
* A second round of E-09 hardware findings, once the greeter rendered and the desktop
  came up, is addressed alongside the login work so the reference laptop is reflashed
  once:
  - **Wi-Fi was dead.** Fedora 44 split `linux-firmware` into per-device subpackages that
    are *weak* dependencies, and the image builds with `--setopt=install_weak_deps=False`,
    so the Intel 8265's `iwlwifi-8265-*` ucode (in `iwlwifi-mvm-firmware`) was never
    installed — `dmesg` showed "no suitable firmware found" and `nmtui` listed no wireless
    device. `iwlwifi-mvm-firmware` and `iwlwifi-dvm-firmware` are now named explicitly in
    `image/packages.txt`.
  - **Onboarding stalled behind `ward doctor`.** `wardos-first-run` ran `ward doctor`
    synchronously; the same probe run that took ~70 s at boot (it cold-starts every agent
    to read its version) also blocked the welcome, the keys and the walkthrough on the
    first login. It is now detached — the `wardos-firstboot` service still writes the full
    report — so onboarding is responsive on slow media.
  - **Two duplicate toasts.** The theme was applied (and announced) by *both* the desktop
    autostart and `wardos-first-run`, and the "Welcome to WardOS" greeting was sent by both
    `wardos-first-run` and the walkthrough. The per-login theme re-apply is now quiet
    (`wardos-theme set -q`, the login re-apply is not a *change*), and the walkthrough is
    the single sender of the greeting.
* Still to verify on hardware (E-09): a *second* boot's time (should be far below 331 s);
  that the greeter renders and authenticates (the first-round fix); and, from this round,
  that Wi-Fi associates, the duplicate toasts are gone, and onboarding is responsive.
  The blue-gradient wallpaper (Ward Dark ground not painting) is still under live
  diagnosis and is deliberately not guessed at here.
