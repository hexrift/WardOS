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
#      plain `Hyprland` otherwise. `exec` replaces the login shell, so logging out of
#      Hyprland returns to the login prompt.
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
  if command -v uwsm >/dev/null 2>&1; then
    exec uwsm start hyprland.desktop
  elif command -v Hyprland >/dev/null 2>&1; then
    exec Hyprland
  fi
fi
