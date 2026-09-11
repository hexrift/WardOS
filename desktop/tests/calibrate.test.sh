#!/usr/bin/env bash
# wardos-calibrate (CALIBRATE, ADR-0026): language, keyboard, timezone, optional password.
# The system changes go through localectl/timedatectl (mocked here); the pickers are the
# stdin menu backend driven by WARDOS_MENU_CHOICE.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

# localectl answers the lists CALIBRATE reads and logs the applies; timedatectl the same.
# The bodies are single-quoted on purpose: $1/$* must expand when the mock runs, not now.
# shellcheck disable=SC2016
mock localectl 'case "${1:-}" in
  status) printf "System Locale: LANG=en_US.UTF-8\n   X11 Layout: us\n" ;;
  list-locales) printf "%s\n" en_US.UTF-8 de_DE.UTF-8 fr_FR.UTF-8 C.UTF-8 ;;
  list-x11-keymap-layouts) printf "%s\n" us de fr gb ;;
esac'
# shellcheck disable=SC2016
mock timedatectl 'case "${1:-}" in
  list-timezones) printf "%s\n" Europe/Paris Europe/London America/New_York UTC ;;
  show) printf "UTC\n" ;;
esac'
mock hyprctl
mock notify-send
mock wardos-launch
marker="$XDG_CONFIG_HOME/wardos/calibrate-done"
cursor="$XDG_RUNTIME_DIR/wardos-menu-select.cursor"

# reset_menu ANSWERS…: fresh cursor + the successive menu answers for the next flow.
reset_menu() {
  rm -f "$cursor"
  local IFS=$'\n'
  export WARDOS_MENU_CHOICE="$*"
}

wardos-calibrate --help | grep -q '^Usage' || fail "--help prints the usage block"

# --- non-interactive steps (scriptable, ADR-0026) ---------------------------------------
: >"$MOCK_LOG"
wardos-calibrate timezone Europe/Paris
assert_logged '^timedatectl set-timezone Europe/Paris$'

: >"$MOCK_LOG"
wardos-calibrate locale de_DE.UTF-8
assert_logged '^localectl set-locale LANG=de_DE.UTF-8$'

: >"$MOCK_LOG"
wardos-calibrate keyboard fr
assert_logged '^hyprctl keyword input:kb_layout fr$'
assert_logged '^localectl set-x11-keymap fr$'
input_conf="$XDG_CONFIG_HOME/hypr/input.conf"
assert_file "$input_conf"
grep -Eq '^[[:space:]]*kb_layout[[:space:]]*=[[:space:]]*fr$' "$input_conf" ||
  fail "keyboard step rewrites kb_layout to fr; got: $(grep kb_layout "$input_conf")"

# --- the guided flow: pick each, then "Apply and continue" ------------------------------
: >"$MOCK_LOG"
reset_menu "de_DE.UTF-8" "de" "Europe" "Paris" "Apply and continue"
wardos-calibrate
assert_logged '^localectl set-locale LANG=de_DE.UTF-8$'
assert_logged '^localectl set-x11-keymap de$'
assert_logged '^timedatectl set-timezone Europe/Paris$'
assert_file "$marker"

# Done once: a second run with the marker present does nothing.
: >"$MOCK_LOG"
reset_menu "de_DE.UTF-8" "de" "Europe" "Paris" "Apply and continue"
wardos-calibrate
assert_not_logged '^timedatectl set-timezone'
# --force runs again despite the marker.
: >"$MOCK_LOG"
reset_menu "en_US.UTF-8" "us" "UTC" "Apply and continue"
wardos-calibrate --force
assert_logged '^timedatectl set-timezone UTC$'

# --- "keep current" applies nothing for that step ---------------------------------------
rm -f "$marker"
: >"$MOCK_LOG"
reset_menu "· keep current (en_US.UTF-8)" "· keep current (us)" "· keep current (UTC)" "Apply and continue"
wardos-calibrate
assert_not_logged '^localectl set-locale'
assert_not_logged '^localectl set-x11-keymap'
assert_not_logged '^timedatectl set-timezone'
assert_file "$marker"

# --- "Skip the rest" writes the marker but applies nothing ------------------------------
rm -f "$marker"
: >"$MOCK_LOG"
reset_menu "de_DE.UTF-8" "de" "Europe" "Paris" "Skip the rest"
wardos-calibrate
assert_not_logged '^timedatectl set-timezone'
assert_file "$marker"

# --- review can change a choice, and timezone "‹ back" returns to the region ------------
rm -f "$marker"
: >"$MOCK_LOG"
# locale, keyboard, timezone(region Europe → city ‹ back → region UTC),
# then review: change Timezone → region America → city New_York, then Apply.
reset_menu "en_US.UTF-8" "us" "Europe" "‹ back" "UTC" \
  "Timezone · UTC" "America" "New_York" "Apply and continue"
wardos-calibrate
assert_logged '^timedatectl set-timezone America/New_York$'
assert_file "$marker"

# --- the optional password step opens one terminal (never on the default path) ----------
: >"$MOCK_LOG"
wardos-calibrate password
assert_logged '^wardos-launch run wardos-passwd passwd$'

echo "ok   calibrate.test.sh internal assertions"
