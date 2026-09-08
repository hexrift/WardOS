#!/usr/bin/env bash
# wardos-power: lock, suspend, relaunch, restart, shutdown, and the menu of the five.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
for c in hyprlock systemctl hyprctl; do mock "$c"; done

wardos-power --help | grep -q '^Usage' || fail "--help prints the usage block"

wardos-power lock
assert_logged '^hyprlock $'
wardos-power suspend
assert_logged '^systemctl suspend$'
wardos-power relaunch
assert_logged '^hyprctl dispatch exit$'
wardos-power restart
assert_logged '^systemctl reboot$'
wardos-power shutdown
assert_logged '^systemctl poweroff$'

# The menu runs the chosen one; a cancelled menu does nothing.
: >"$MOCK_LOG"
export WARDOS_MENU_CHOICE=Suspend
wardos-power menu
assert_logged '^systemctl suspend$'
export WARDOS_MENU_CHOICE=""
: >"$MOCK_LOG"
wardos-power menu
[[ ! -s "$MOCK_LOG" ]] || fail "a cancelled menu runs nothing"

wardos-power nothing 2>/dev/null && fail "unknown action"
exit 0
