#!/usr/bin/env bash
# wardos-menu-select: the stdin backend answers from the env, fuzzel gets the theme ini.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

wardos-menu-select --help | grep -q '^Usage' || fail "--help prints the usage block"

# stdin backend: exact match, then prefix match, then the text itself (a free-text answer).
export WARDOS_MENU_CHOICE="Suspend"
assert_eq "$(printf 'Lock\nSuspend\nShutdown\n' | wardos-menu-select --prompt Power)" "Suspend"
export WARDOS_MENU_CHOICE="Shut"
assert_eq "$(printf 'Lock\nSuspend\nShutdown\n' | wardos-menu-select)" "Shutdown"
export WARDOS_MENU_CHOICE="https://example.com"
assert_eq "$(printf 'Lock\n' | wardos-menu-select)" "https://example.com"
# Cancelled: no answer, non-zero exit, nothing printed.
export WARDOS_MENU_CHOICE=""
if out=$(printf 'Lock\n' | wardos-menu-select); then fail "an empty choice is a cancel"; fi
assert_eq "$out" ""

# A newline-separated answer list feeds successive menus (a walk through a tree).
export WARDOS_MENU_CHOICE=$'Capture\nScreenshot region'
assert_eq "$(printf 'Apps\nCapture\n' | wardos-menu-select)" "Capture"
assert_eq "$(printf 'Screenshot region\nScreenshot window\n' | wardos-menu-select)" "Screenshot region"

# fuzzel backend: --dmenu, the prompt, and the rendered theme ini when it exists.
mock fuzzel 'cat >/dev/null; echo Lock'
export WARDOS_MENU_BACKEND=fuzzel
assert_eq "$(printf 'Lock\n' | wardos-menu-select --prompt Power)" "Lock"
assert_logged '^fuzzel --dmenu --prompt Power $'
assert_not_logged 'config'
mkdir -p "$XDG_CONFIG_HOME/wardos/theme/current"
: >"$XDG_CONFIG_HOME/wardos/theme/current/fuzzel.ini"
printf 'Lock\n' | wardos-menu-select --prompt Power --lines 5 >/dev/null
assert_logged "^fuzzel --dmenu --prompt Power  --config $XDG_CONFIG_HOME/wardos/theme/current/fuzzel.ini --lines 5$"
