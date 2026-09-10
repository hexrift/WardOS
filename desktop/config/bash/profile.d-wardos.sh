#!/usr/bin/env bash
# WardOS — /etc/profile.d/wardos.sh (installed there by the image and by
# desktop/install.sh from desktop/config/bash/profile.d-wardos.sh).
#
# Sourced by every login shell, so it must stay harmless: no `set -e`, no output,
# nothing for non-bash shells. Two jobs:
#   1. Interactive bash gets the WardOS shell defaults (config/bash/bashrc) unless the
#      user has opted out by creating ~/.config/wardos/bash-override, in which case
#      their own ~/.bashrc is all there is.
#   2. On tty1 with no Wayland session yet, the autologin (desktop/systemd/system)
#      lands here and the session starts: `uwsm start hyprland.desktop` when uwsm is
#      installed (systemd-managed session, graphical-session.target for the units),
#      plain `Hyprland` otherwise. A clean exit (logging out of a real session) ends
#      the login shell, so the autologin starts a fresh session — the old `exec`
#      behaviour. But a compositor that FAILS to come up must not do that silently:
#      `exec`-ing straight back into the autologin is an invisible crash-loop with no
#      shell and no error to read (E-09 follow-up: the T480s booted to exactly this).
#      So the start is wrapped — its output is captured to a log, `uwsm` failure falls
#      back to launching Hyprland directly, and if the session still cannot start the
#      shell drops to an interactive prompt on tty1 with the error in view.
# $WARDOS_CONFIG points at the config tree (a test sets it to the checkout).

[ -n "$BASH_VERSION" ] || return 0 2>/dev/null || exit 0

: "${WARDOS_CONFIG:=/usr/share/wardos/config}"
export WARDOS_CONFIG

if [ -n "$PS1" ] && [ ! -e "${XDG_CONFIG_HOME:-$HOME/.config}/wardos/bash-override" ] \
  && [ -r "$WARDOS_CONFIG/bash/bashrc" ]; then
  # shellcheck source=desktop/config/bash/bashrc
  . "$WARDOS_CONFIG/bash/bashrc"
fi

if [ -z "$WAYLAND_DISPLAY" ] && [ -z "$HYPRLAND_INSTANCE_SIGNATURE" ] && [ "$(tty 2>/dev/null)" = /dev/tty1 ]; then
  _wardos_log="${XDG_STATE_HOME:-$HOME/.local/state}/wardos"
  mkdir -p "$_wardos_log" 2>/dev/null || true
  _wardos_log="$_wardos_log/session-start.log"
  : >"$_wardos_log" 2>/dev/null || true
  # Run the session; a clean exit ends the login shell (fresh session next time).
  _wardos_try() { "$@" >>"$_wardos_log" 2>&1; }
  if command -v uwsm >/dev/null 2>&1; then
    _wardos_try uwsm start hyprland.desktop && exit 0
    # uwsm could not start the session (e.g. a missing/broken session entry): try the
    # compositor directly before giving up, so a working Hyprland still comes up.
    command -v Hyprland >/dev/null 2>&1 && { _wardos_try Hyprland && exit 0; }
  elif command -v Hyprland >/dev/null 2>&1; then
    _wardos_try Hyprland && exit 0
  fi
  # The session could not start. Do NOT re-exec into the autologin (that crash-loops
  # with nothing to read): surface the reason and stay on a usable shell on tty1.
  echo
  echo "WardOS: the graphical session did not start — leaving you at a shell on tty1."
  echo "WardOS: the compositor's output is in $_wardos_log —"
  tail -n 20 "$_wardos_log" 2>/dev/null | sed 's/^/    /'
  echo
  echo "WardOS: 'ward doctor' checks the GPU and hardware, 'wardos-baseline' writes a"
  echo "        full diagnostic bundle, 'uwsm start hyprland.desktop' retries the session."
  unset -f _wardos_try 2>/dev/null || true
  unset _wardos_log 2>/dev/null || true
fi
