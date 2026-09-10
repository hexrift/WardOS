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
* Still to verify on hardware (E-09): the exact 331 s culprit against
  `systemd-analyze blame`/`critical-chain`, and that the greeter renders and authenticates
  on the reference laptop. The unit timeouts bound the worst case regardless of the
  specific culprit; the blame data closes the boot-P0 investigation.
