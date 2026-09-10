#!/usr/bin/env bash
# WardOS — /etc/profile.d/wardos.sh (installed there by the image and by
# desktop/install.sh from desktop/config/bash/profile.d-wardos.sh).
#
# Sourced by every login shell, so it must stay harmless: no `set -e`, no output,
# nothing for non-bash shells. One job now:
#   Interactive bash gets the WardOS shell defaults (config/bash/bashrc) unless the
#   user has opted out by creating ~/.config/wardos/bash-override, in which case their
#   own ~/.bashrc is all there is.
#
# Starting the graphical session is no longer this file's job: WardOS logs in through
# greetd (image/rootfs/etc/greetd), which authenticates the user and runs the session
# via /usr/libexec/wardos-session. There is no tty1 autologin to land here any more.
# $WARDOS_CONFIG points at the config tree (a test sets it to the checkout).

[ -n "$BASH_VERSION" ] || return 0 2>/dev/null || exit 0

: "${WARDOS_CONFIG:=/usr/share/wardos/config}"
export WARDOS_CONFIG

if [ -n "$PS1" ] && [ ! -e "${XDG_CONFIG_HOME:-$HOME/.config}/wardos/bash-override" ] \
  && [ -r "$WARDOS_CONFIG/bash/bashrc" ]; then
  # shellcheck source=desktop/config/bash/bashrc
  . "$WARDOS_CONFIG/bash/bashrc"
fi
