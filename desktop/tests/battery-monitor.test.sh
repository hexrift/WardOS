#!/usr/bin/env bash
# wardos-battery-monitor: one notification per level (20, 10, 5) while discharging.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
mock notify-send
export WARDOS_POWER_SUPPLY_DIR="$TMP/power"
bat="$WARDOS_POWER_SUPPLY_DIR/BAT0"
mkdir -p "$bat"
set_battery() {
  echo "$1" >"$bat/capacity"
  echo "$2" >"$bat/status"
}
notified() { grep -c '^notify-send' "$MOCK_LOG"; }

wardos-battery-monitor --help | grep -q '^Usage' || fail "--help prints the usage block"

set_battery 50 Discharging
wardos-battery-monitor
assert_eq "$(notified)" 0
set_battery 20 Discharging
wardos-battery-monitor
assert_eq "$(notified)" 1
assert_logged '^notify-send -a WardOS .*20 %'
wardos-battery-monitor
set_battery 15 Discharging
wardos-battery-monitor
assert_eq "$(notified)" 1
set_battery 10 Discharging
wardos-battery-monitor
assert_eq "$(notified)" 2
set_battery 5 Discharging
wardos-battery-monitor
assert_eq "$(notified)" 3
assert_logged '^notify-send -a WardOS -u critical .*5 %'
# Charging resets: the next discharge announces again.
set_battery 6 Charging
wardos-battery-monitor
assert_eq "$(notified)" 3
set_battery 9 Discharging
wardos-battery-monitor
assert_eq "$(notified)" 4
# No exclamation marks anywhere.
grep -q '!' "$MOCK_LOG" && fail "no exclamation marks"
# No battery: nothing to do, no error.
rm -r "$bat"
wardos-battery-monitor || fail "no battery is fine"
exit 0
