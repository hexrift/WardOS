#!/usr/bin/env bash
# wardos-pause (ADR-0019 §3): one key pauses the session through `ward pause`, shows the
# one notification, and offers the exits; each exit is the ward command it names, and a
# cancelled menu leaves the session paused.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

pause=$WARDOS_ROOT/bin/wardos-pause
export WARDOS_PROJECT=/home/dev/payments-api
export WARD_STATE_FILE="$TMP/ward-state"
echo running >"$WARD_STATE_FILE"

# --- --help --------------------------------------------------------------------
"$pause" --help | grep -q '^Usage:' || fail "--help prints the usage block"
"$pause" --help | grep -q 'Stop & restore entry state' || fail "--help names the exits"

# A `ward` whose pause state lives in a file, so the toggle can be walked through.
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "pause --status "*) cat "$WARD_STATE_FILE" ;;
  "pause "*) echo paused >"$WARD_STATE_FILE" ;;
  "resume "*) echo running >"$WARD_STATE_FILE" ;;
  "stop "*) echo none >"$WARD_STATE_FILE" ;;
  "watch "*) : ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send
mock foot
export TERMINAL=foot

# --- toggle from running: pause, the notification, then Resume from the menu ---
WARDOS_MENU_CHOICE=Resume "$pause"
assert_logged '^ward pause --status /home/dev/payments-api$'
assert_logged '^ward pause /home/dev/payments-api$'
assert_logged '^notify-send -a WardOS -u critical AGENTS PAUSED network closed · credential grants suspended · processes frozen · workspace retained$'
assert_logged '^ward resume /home/dev/payments-api$'
assert_logged '^notify-send -a WardOS -t 2000 Agents resumed $'
assert_eq "$(cat "$WARD_STATE_FILE")" running

# --- already paused: the menu alone; Stop & preserve keeps the workspace -------
: >"$MOCK_LOG"
echo paused >"$WARD_STATE_FILE"
WARDOS_MENU_CHOICE='Stop & preserve workspace' "$pause"
assert_not_logged '^ward pause /home'
assert_not_logged 'AGENTS PAUSED'
assert_logged '^ward stop /home/dev/payments-api$'
assert_not_logged 'restore-entry'
assert_eq "$(cat "$WARD_STATE_FILE")" none

# --- Stop & restore entry state is `ward stop --restore-entry` --------------------
: >"$MOCK_LOG"
echo paused >"$WARD_STATE_FILE"
WARDOS_MENU_CHOICE='Stop & restore entry state' "$pause"
assert_logged '^ward stop --restore-entry /home/dev/payments-api$'
assert_logged '^notify-send .*entry state restored'

# --- Inspect activity opens the observer in a terminal; the session stays paused -
: >"$MOCK_LOG"
echo paused >"$WARD_STATE_FILE"
WARDOS_MENU_CHOICE='Inspect activity' "$pause"
assert_logged '^foot --app-id ward-observer -e ward watch /home/dev/payments-api$'
assert_not_logged '^ward resume'
assert_eq "$(cat "$WARD_STATE_FILE")" paused

# --- a cancelled menu changes nothing: paused stays paused -----------------------
: >"$MOCK_LOG"
echo running >"$WARD_STATE_FILE"
WARDOS_MENU_CHOICE='' "$pause"
assert_logged '^ward pause /home/dev/payments-api$'
assert_not_logged '^ward resume'
assert_not_logged '^ward stop'
assert_eq "$(cat "$WARD_STATE_FILE")" paused

# --- the verbs and --status ------------------------------------------------------
: >"$MOCK_LOG"
"$pause" resume
assert_logged '^ward resume /home/dev/payments-api$'
assert_eq "$("$pause" --status)" running
echo paused >"$WARD_STATE_FILE"
assert_eq "$("$pause" --status)" paused
: >"$MOCK_LOG"
WARDOS_MENU_CHOICE=Resume "$pause" pause
assert_logged '^ward pause /home/dev/payments-api$'
assert_logged '^ward resume /home/dev/payments-api$'
: >"$MOCK_LOG"
WARDOS_MENU_CHOICE=Resume "$pause" menu
assert_not_logged '^ward pause /home'
assert_logged '^ward resume /home/dev/payments-api$'

# --- no session: a plain refusal, nothing run ------------------------------------
: >"$MOCK_LOG"
echo none >"$WARD_STATE_FILE"
"$pause" 2>/dev/null && fail "no session is an error"
assert_not_logged '^ward pause /home'
"$pause" bogus 2>/dev/null && fail "an unknown verb is an error"

# --- shellcheck-clean, usage block, strict mode ----------------------------------
head -1 "$pause" | grep -q '^#!/usr/bin/env bash$' || fail "shebang"
grep -q '^set -euo pipefail$' "$pause" || fail "strict mode"
