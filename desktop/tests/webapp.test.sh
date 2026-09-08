#!/usr/bin/env bash
# wardos-webapp: install writes a .desktop and a conf, remove takes them away, list shows
# what is installed and what ships.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
# shellcheck disable=SC2016  # the mock's body is expanded when the mock runs
mock curl 'for a; do case "$a" in -o) shift; : >"$1" ;; esac; done'
mock notify-send
apps="$XDG_DATA_HOME/applications"
exec >/dev/null # the commands' own output; failures go to stderr

wardos-webapp --help | grep -q '^Usage' || fail "--help prints the usage block"

# A custom web app with an icon url: the icon is downloaded once.
wardos-webapp install "My App" https://my.example https://my.example/icon.png
assert_logged '^curl .*https://my.example/icon.png'
assert_file "$apps/wardos-my-app.desktop"
grep -q '^Exec=wardos-launch webapp my-app$' "$apps/wardos-my-app.desktop" || fail "Exec"
grep -q '^Name=My App$' "$apps/wardos-my-app.desktop" || fail "Name"
grep -q '^StartupWMClass=wardos-my-app$' "$apps/wardos-my-app.desktop" || fail "WMClass"
grep -q "^Icon=$XDG_DATA_HOME/wardos/webapps/icons/my-app.png$" "$apps/wardos-my-app.desktop" || fail "Icon path"
assert_file "$XDG_CONFIG_HOME/wardos/webapps/my-app.conf"
grep -q '^url=https://my.example$' "$XDG_CONFIG_HOME/wardos/webapps/my-app.conf" || fail "conf url"
grep -q '^name=My App$' "$XDG_CONFIG_HOME/wardos/webapps/my-app.conf" || fail "conf name"

# Without an icon url nothing is downloaded and the icon is a theme name.
wardos-webapp install Plain https://plain.example
[[ $(grep -c '^curl' "$MOCK_LOG") -eq 1 ]] || fail "no download without an icon url"
grep -q '^Icon=web-browser$' "$apps/wardos-plain.desktop" || fail "fallback icon"

# A shipped default installs by name alone.
wardos-webapp install github
grep -q '^Exec=wardos-launch webapp github$' "$apps/wardos-github.desktop" || fail "default installed"
assert_logged 'dashboard-icons/png/github.png'
wardos-webapp install nothing-here 2>/dev/null && fail "unknown name without a url fails"

# list: installed ones are marked, shipped ones listed.
list=$(wardos-webapp list)
grep -q "^my-app	My App	https://my.example	installed$" <<<"$list" || fail "installed row; got: $list"
grep -q "^youtube	YouTube	https://youtube.com	default$" <<<"$list" || fail "default row"
grep -q "^github	GitHub	https://github.com	installed$" <<<"$list" || fail "an installed default"

# --defaults installs every shipped one that is not installed yet.
wardos-webapp install --defaults
assert_file "$apps/wardos-youtube.desktop"
assert_file "$apps/wardos-google-photos.desktop"

# remove: the entry, the conf, the icon and the profile go.
mkdir -p "$XDG_DATA_HOME/wardos/webapps/my-app"
wardos-webapp remove my-app
[[ ! -e "$apps/wardos-my-app.desktop" ]] || fail ".desktop removed"
[[ ! -e "$XDG_CONFIG_HOME/wardos/webapps/my-app.conf" ]] || fail "conf removed"
[[ ! -e "$XDG_DATA_HOME/wardos/webapps/my-app" ]] || fail "profile removed"
# remove without a name asks.
export WARDOS_MENU_CHOICE=plain
wardos-webapp remove
[[ ! -e "$apps/wardos-plain.desktop" ]] || fail "removed the chosen one"
wardos-webapp remove nothing-here 2>/dev/null && fail "removing an unknown app fails"
exit 0
