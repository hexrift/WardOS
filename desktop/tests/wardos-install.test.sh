#!/usr/bin/env bash
# wardos-install: Flathub apps, bootc-layered packages (with the notice), web and terminal
# apps, themes, fonts, mise languages, services.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
exec >"$TMP/out"
for c in flatpak sudo notify-send wardos-webapp wardos-tui wardos-theme fc-cache mise systemctl; do mock "$c"; done

wardos-install --help | grep -q '^Usage' || fail "--help prints the usage block"

wardos-install app org.signal.Signal
assert_logged '^flatpak install -y flathub org.signal.Signal$'
assert_logged '^notify-send -a WardOS .*org.signal.Signal'
# Without an id the picker asks (free text).
export WARDOS_MENU_CHOICE=com.spotify.Client
wardos-install app
assert_logged '^flatpak install -y flathub com.spotify.Client$'

# package: rpm-ostree layering through sudo, and it says what that means.
wardos-install package htop 2>"$TMP/err"
assert_logged '^sudo rpm-ostree install htop$'
grep -qi 'reboot' "$TMP/err" || fail "the package notice mentions the reboot"
grep -q 'image/packages.txt' "$TMP/err" || fail "the notice points at the image's package list"

# webapp, tui, theme delegate to their commands.
wardos-install webapp Mine https://mine.example
assert_logged '^wardos-webapp install Mine https://mine.example$'
wardos-install tui Disk "ncdu /"
assert_logged '^wardos-tui install Disk ncdu /$'
wardos-install theme https://github.com/x/theme
assert_logged '^wardos-theme install https://github.com/x/theme$'

# font: files land in ~/.local/share/fonts and the cache is rebuilt.
mkdir -p "$TMP/fonts"
: >"$TMP/fonts/Mono-Regular.ttf"
: >"$TMP/fonts/README"
wardos-install font "$TMP/fonts"
assert_file "$XDG_DATA_HOME/fonts/Mono-Regular.ttf"
[[ ! -e "$XDG_DATA_HOME/fonts/README" ]] || fail "only font files are installed"
assert_logged '^fc-cache -f$'
wardos-install font "$TMP/fonts/Mono-Regular.ttf"
assert_file "$XDG_DATA_HOME/fonts/Mono-Regular.ttf"

# dev: mise, or a clear message without it.
wardos-install dev ruby
assert_logged '^mise use -g ruby@latest$'
rm "$MOCK_DIR/mise"
wardos-install dev node 2>"$TMP/err" && fail "no mise, no install"
grep -q mise "$TMP/err" || fail "the message names mise"

# service: dropbox from Flathub; syncthing as a user unit when installed, else Flathub;
# tailscale enabled when installed, else a message.
wardos-install service dropbox
assert_logged '^flatpak install -y flathub com.dropbox.Client$'
wardos-install service syncthing
assert_logged '^flatpak install -y flathub com.github.zocker_160.SyncThingy$'
mock syncthing
wardos-install service syncthing
assert_logged '^systemctl --user enable --now syncthing$'
wardos-install service tailscale 2>"$TMP/err" && fail "tailscale is not in Fedora"
grep -q tailscale "$TMP/err" || fail "the message names tailscale"
mock tailscale
wardos-install service tailscale
assert_logged '^sudo systemctl enable --now tailscaled$'

wardos-install nothing 2>/dev/null && fail "unknown kind"
exit 0
