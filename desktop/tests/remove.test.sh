#!/usr/bin/env bash
# wardos-remove: the inverse of every wardos-install.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
exec >"$TMP/out"
for c in sudo notify-send wardos-webapp wardos-tui wardos-theme fc-cache mise systemctl; do mock "$c"; done
mock flatpak 'case "$*" in list*) printf "org.signal.Signal\tSignal\ncom.spotify.Client\tSpotify\n" ;; esac'

wardos-remove --help | grep -q '^Usage' || fail "--help prints the usage block"

wardos-remove app org.signal.Signal
assert_logged '^flatpak uninstall -y org.signal.Signal$'
# Without an id: pick from the installed flatpaks.
export WARDOS_MENU_CHOICE=com.spotify
wardos-remove app
assert_logged '^flatpak list --app --columns=application,name$'
assert_logged '^flatpak uninstall -y com.spotify.Client$'

wardos-remove package htop
assert_logged '^sudo rpm-ostree uninstall htop$'
wardos-remove webapp mine
assert_logged '^wardos-webapp remove mine$'
wardos-remove tui disk
assert_logged '^wardos-tui remove disk$'
wardos-remove theme nord
assert_logged '^wardos-theme remove nord$'

# font: the files of that family under ~/.local/share/fonts go, the cache is rebuilt.
mkdir -p "$XDG_DATA_HOME/fonts"
: >"$XDG_DATA_HOME/fonts/Mono-Regular.ttf"
: >"$XDG_DATA_HOME/fonts/Other.ttf"
mock fc-list "printf '%s\n' \"$XDG_DATA_HOME/fonts/Mono-Regular.ttf: Mono\" \"$XDG_DATA_HOME/fonts/Other.ttf: Other\""
wardos-remove font Mono
[[ ! -e "$XDG_DATA_HOME/fonts/Mono-Regular.ttf" ]] || fail "the family's file is removed"
assert_file "$XDG_DATA_HOME/fonts/Other.ttf"
assert_logged '^fc-cache -f$'

wardos-remove dev ruby
assert_logged '^mise unuse -g ruby$'

wardos-remove service syncthing
assert_logged '^systemctl --user disable --now syncthing$'
assert_logged '^flatpak uninstall -y com.github.zocker_160.SyncThingy$'
wardos-remove service dropbox
assert_logged '^flatpak uninstall -y com.dropbox.Client$'
wardos-remove service tailscale
assert_logged '^sudo systemctl disable --now tailscaled$'

wardos-remove nothing 2>/dev/null && fail "unknown kind"
exit 0
