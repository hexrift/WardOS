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

# --- a cancelled review writes NO marker (unfinished setup is not recorded as complete) --
rm -f "$marker"
: >"$MOCK_LOG"
# Empty answers: every picker and the review menu are cancelled (dismissed with Escape).
reset_menu ""
wardos-calibrate
[[ ! -e "$marker" ]] || fail "a cancelled review must not write the completion marker"
assert_not_logged '^localectl set-locale'
assert_not_logged '^timedatectl set-timezone'

# --- an invalid non-interactive keyboard value mutates nothing and exits non-zero --------
# Seed a known-good layout first, then confirm a bogus value leaves it untouched.
: >"$MOCK_LOG"
wardos-calibrate keyboard de
grep -Eq '^[[:space:]]*kb_layout[[:space:]]*=[[:space:]]*de$' "$input_conf" || fail "seed de"
: >"$MOCK_LOG"
if wardos-calibrate keyboard boguslayout 2>/dev/null; then fail "invalid keyboard must exit non-zero"; fi
assert_not_logged 'set-x11-keymap boguslayout'
assert_not_logged '^hyprctl keyword input:kb_layout boguslayout'
grep -Eq '^[[:space:]]*kb_layout[[:space:]]*=[[:space:]]*de$' "$input_conf" ||
  fail "invalid keyboard must not change input.conf; got: $(grep kb_layout "$input_conf")"

# --- a FAILED apply is NOT recorded as complete, and is retried next login (#125) -------
# Distinct from a cancelled review (no marker) and a deliberate "Skip the rest" (marker):
# every selected setting is still attempted, but if any requested apply fails the marker is
# withheld, so the machine is not left stranded with an unapplied setting and CALIBRATE is
# offered again next login until it succeeds.
rm -f "$marker"
# shellcheck disable=SC2016
mock timedatectl 'case "${1:-}" in
  list-timezones) printf "%s\n" Europe/Paris Europe/London America/New_York UTC ;;
  show) printf "UTC\n" ;;
  set-timezone) exit 1 ;;
esac'
: >"$MOCK_LOG"
reset_menu "de_DE.UTF-8" "de" "Europe" "Paris" "Apply and continue"
wardos-calibrate
assert_logged '^localectl set-locale LANG=de_DE.UTF-8$' # the others are still attempted
[[ ! -e "$marker" ]] || fail "a failed apply must not record completion"
# Next login: the marker is still absent, so CALIBRATE runs again (retry).
: >"$MOCK_LOG"
reset_menu "de_DE.UTF-8" "de" "Europe" "Paris" "Apply and continue"
wardos-calibrate
[[ ! -e "$marker" ]] || fail "an unresolved failed apply is retried, not recorded"
assert_logged '^localectl set-locale LANG=de_DE.UTF-8$'
# The apply now succeeds: completion is recorded and the flow stops re-offering.
# shellcheck disable=SC2016
mock timedatectl 'case "${1:-}" in
  list-timezones) printf "%s\n" Europe/Paris Europe/London America/New_York UTC ;;
  show) printf "UTC\n" ;;
esac'
: >"$MOCK_LOG"
reset_menu "de_DE.UTF-8" "de" "Europe" "Paris" "Apply and continue"
wardos-calibrate
assert_logged '^timedatectl set-timezone Europe/Paris$'
assert_file "$marker"

echo "ok   calibrate.test.sh internal assertions"
