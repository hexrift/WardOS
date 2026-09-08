#!/usr/bin/env bash
# wardos-launch: terminal, browser (plain and per-project profile), editor, files, tui,
# webapp, or-focus, run.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
for c in foot alacritty chromium firefox nautilus nvim code hyprctl; do mock "$c"; done
unset TERMINAL BROWSER EDITOR VISUAL

wardos-launch --help | grep -q '^Usage' || fail "--help prints the usage block"

wardos-launch terminal
assert_logged '^foot $'
wardos-launch terminal ward claude
assert_logged '^foot -e ward claude$'
TERMINAL=alacritty wardos-launch run wardos-about wardos-about
assert_logged "^alacritty --class wardos-about -e sh -c .* wardos-about$"

wardos-launch browser
assert_logged '^chromium $'
wardos-launch browser https://example.com
assert_logged '^chromium https://example.com$'
BROWSER=firefox wardos-launch browser https://example.com
assert_logged '^firefox https://example.com$'
# A project's browser profile lives under ~/.local/share/wardos/browser/<hash>.
mkdir -p "$TMP/proj"
wardos-launch browser --project "$TMP/proj" https://example.com
assert_logged "^chromium --user-data-dir=$XDG_DATA_HOME/wardos/browser/[0-9a-f]{12} --class=wardos-browser-[0-9a-f]{12} https://example.com$"
[[ -d "$XDG_DATA_HOME/wardos/browser" ]] || fail "the profile directory is created"

# A terminal editor opens inside the terminal; a GUI editor as itself.
wardos-launch editor "$TMP/file.txt"
assert_logged "^foot --app-id wardos-editor -e nvim $TMP/file.txt$"
EDITOR=code wardos-launch editor "$TMP/file.txt"
assert_logged "^code $TMP/file.txt$"

wardos-launch files "$TMP"
assert_logged "^nautilus $TMP$"

# tui and webapp resolve the shipped defaults and the user's own definitions.
wardos-launch tui btop
assert_logged '^foot --app-id wardos-btop -e btop$'
wardos-launch webapp github
assert_logged "^chromium --app=https://github.com --user-data-dir=$XDG_DATA_HOME/wardos/webapps/github --class=wardos-github$"
mkdir -p "$XDG_CONFIG_HOME/wardos/tuis" "$XDG_CONFIG_HOME/wardos/webapps"
printf 'name=Mine\ncmd=htop -d 5\n' >"$XDG_CONFIG_HOME/wardos/tuis/mine.conf"
printf 'name=Mine\nurl=https://mine.example\n' >"$XDG_CONFIG_HOME/wardos/webapps/mine.conf"
wardos-launch tui mine
assert_logged '^foot --app-id wardos-mine -e htop -d 5$'
wardos-launch webapp mine
assert_logged '^chromium --app=https://mine.example '
wardos-launch tui nothing 2>/dev/null && fail "unknown tui"

# or-focus: focus the window with that class when it exists, else start the command.
mock hyprctl "case \"\$*\" in 'clients -j') printf '[{\"class\": \"wardos-btop\"}]\n' ;; esac"
wardos-launch or-focus wardos-btop wardos-launch tui btop
assert_logged '^hyprctl dispatch focuswindow class:wardos-btop$'
[[ $(grep -c '^foot --app-id wardos-btop' "$MOCK_LOG") -eq 1 ]] || fail "a focused window is not started again"
wardos-launch or-focus wardos-mine wardos-launch tui mine
assert_not_logged '^hyprctl dispatch focuswindow class:wardos-mine$'
[[ $(grep -c '^foot --app-id wardos-mine' "$MOCK_LOG") -eq 2 ]] || fail "or-focus starts a missing window"
exit 0
