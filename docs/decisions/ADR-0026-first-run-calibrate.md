# ADR-0026 — First-run system onboarding (CALIBRATE)

## Decision
WardOS gains a first-boot system-setup step, **CALIBRATE** (`wardos-calibrate`), that lets
the user choose **language/locale, keyboard layout, and timezone** on first login, in the
WardOS design language, before the walkthrough (`wardos-welcome`). It is the Phase B slice
of the Ward Shell build (ADR-0025). It runs **in the user's Hyprland session** using the
desktop's existing surface — keyboard-first `wardos-menu` (fuzzel) pickers — so it needs no
new toolkit (E-10 stays deferred) and does not touch the image boot path or the greeter.

`wardos-first-run` calls `wardos-calibrate` **before** `wardos-welcome`: the machine is made
usable (right language, keys, clock) first, then the agent walkthrough runs. CALIBRATE has
its own marker (`~/.config/wardos/calibrate-done`), and `wardos-welcome` is unaffected by
whether it ran.

**Resume until complete (not merely "once").** `wardos-first-run` separates the one-time
default copy (guarded by `first-run-done`, never repeated, so a later login can't re-run
`wardos-refresh` and overwrite the user's config backups) from the resumable stages
(CALIBRATE, then the walkthrough), which it invokes on **every** login. CALIBRATE writes its
marker only when the flow reaches a confirmed terminal state whose applies succeeded, or when
the user deliberately chooses **Skip the rest** (do-not-ask-again). A **cancelled** review or
a **failed** apply (e.g. `localectl`/`timedatectl` refuses a value) leaves the marker unset,
so the next login offers CALIBRATE again — an unconfigured machine is never silently recorded
as complete. Best-effort still means every selected setting is attempted; the result is only
aggregated to decide whether to record completion.

### What CALIBRATE does, and how it applies
- **Language / locale** — from `localectl list-locales` (UTF-8 only), applied with
  `localectl set-locale LANG=…`. Effective at the next login.
- **Keyboard layout** — from `localectl list-x11-keymap-layouts`, applied three ways so it
  is right everywhere: the running Hyprland session (`hyprctl keyword input:kb_layout`), the
  persisted Hyprland config (the `kb_layout` line in the user's `~/.config/hypr/input.conf`,
  backed up first), and the console/greeter (`localectl set-x11-keymap`).
- **Timezone** — a two-level region → city picker over `timedatectl list-timezones` (so no
  400-item flat menu), applied with `timedatectl set-timezone`. Immediate.
- **Login password (optional, off the default path)** — an explicit menu action that opens
  **one** terminal window running `passwd` for the current user. This is the same pattern
  `wardos-welcome` already uses for secret entry (`ward vault set`): selection/navigation is
  graphical, only secret entry uses a terminal.

Every system change is applied through **polkit** (the `localectl`/`timedatectl` D-Bus
calls authorize against the running `hyprpolkitagent`), never `sudo` in a terminal — so the
normal path never drops to a shell. Each apply is **best-effort**: a failure is reported
with a notification and the flow continues, exactly like `wardos-first-run`'s other steps.

### Requirements met
Keyboard **and** mouse (fuzzel), fully offline (all lists are local — `localectl`,
`timedatectl`, `xkeyboard-config`), **no terminal on the normal path**, back/edit (a review
screen changes any choice), a "Keep current" option per step (nothing is forced),
validation and error recovery (invalid values are rejected by `localectl`/`timedatectl`;
failures notify and continue), and — because the surface is a centred fuzzel list — it is
motion-free and responsive at every aspect ratio by construction (16:10, 16:9, phone).

## Context
The first hardware boot (E-09) confirmed the gap ADR-0025 anticipated: timezone, keyboard
and locale were baked to build defaults (UTC / `us` / `en_US.UTF-8`) with no way for the
user to choose them on first boot short of editing config by hand. `input.conf` even says
so: "the layout is `us` until the installer asks". Making WardOS genuinely usable as an OS
means completing this first-run path before the more visual Ward Field work (Phase C), which
is much easier to judge once a fresh machine can complete a coherent first-run flow.

### The one architectural decision: account creation stays with the installer
Net-new **user-account creation** is **not** in CALIBRATE. The install paths already collect
it: `image/disk.sh --user NAME` writes the account (in `wheel`) and its password into the
bootc-image-builder customization or the Anaconda kickstart, and the ISO installer asks at
install time. Doing account *creation* on first boot would require a graphical **pre-login**
surface (before any user session exists), which is exactly the native-toolkit surface E-10
defers — and duplicating the installer's job. So:

- **Real installs** (ISO / qcow2): the account and password come from the installer; CALIBRATE
  refines locale/keyboard/timezone in-session.
- **The raw test image** (no installer): CALIBRATE's optional password step lets the seeded
  default account set a real password from the desktop.
- A full graphical **pre-login** first-boot (net-new account + these settings before the
  greeter) is left to a later slice, once the E-10 native surface exists; it is recorded here
  as the known follow-up, not built now.

This keeps Phase B in-session, image-stable, and shippable, and keeps the security-sensitive
account-creation path where it already works.

## Consequences
- New `desktop/bin/wardos-calibrate` (bash, `set -euo pipefail`, shellcheck-clean) with
  per-step subcommands (`locale`, `keyboard`, `timezone`, `password`, `run`) so every path
  is scriptable and testable; `wardos-first-run` calls it before `wardos-welcome`.
  `desktop/tests/calibrate.test.sh` drives the whole flow with mocked
  `localectl`/`timedatectl`/`hyprctl`/`wardos-menu-select`, and `first-run.test.sh` gains the
  ordering assertion (calibrate before welcome). `docs/desktop.md` and `docs/onboarding.md`
  document it.
- No image package changes: `localectl`, `timedatectl` (systemd) and `passwd`
  (shadow-utils) are in the base; keymap/locale data ships with `xkeyboard-config`/glibc.
- No new toolkit, no compositor change, no greeter change; the greeter and image boot path
  are untouched, so this cannot regress the E-09 reliability fixes (#116).
- Friendly language **names** (rather than locale codes) and a graphical pre-login flow are
  named follow-ups; neither blocks this slice.
- User-visible feature → its own MINOR bump in this PR (`0.4.0` → `0.5.0`, workspace version
  + inter-crate pins + lockfile); merge-order collisions on the workspace version against the
  other stacked PRs are resolved at merge. No protected surface, CODEOWNERS path, or
  `docs/security-model.md` guarantee changes.
