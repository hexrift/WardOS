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
"$pause" --help | grep -q 'pause-all' || fail "--help names pause-all (#141 item 5)"

# A `ward` whose pause state lives in a file, so the toggle can be walked through.
# "pause --all" fails (exit 1, `sess_b` short) unless $TMP/pause-all-ok exists, the same
# way the real `ward pause --all` exits non-zero on a partial failure (#141 finding 4).
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "pause --status "*) cat "$WARD_STATE_FILE" ;;
  "pause --all --reason "*)
    if [[ -f "$TMP/pause-all-ok" ]]; then
      printf "  sess_a · paused\n  sess_b · paused\n"
    else
      printf "  sess_a · paused\n  sess_b · not paused: already paused\n"
      exit 1
    fi
    ;;
  "pause --session "*)
    echo paused >"$WARD_STATE_FILE"
    if [[ -f "$TMP/pause-unsettled" ]]; then
      printf "  paused, but 2 processes had not confirmed stopped within 1s — the marker is held and approvals stay frozen regardless\n"
    fi
    ;;
  "pause "*)
    echo paused >"$WARD_STATE_FILE"
    if [[ -f "$TMP/pause-unsettled" ]]; then
      printf "  paused, but 2 processes had not confirmed stopped within 1s — the marker is held and approvals stay frozen regardless\n"
    fi
    ;;
  "resume --session "*) echo running >"$WARD_STATE_FILE" ;;
  "resume "*)
    if [[ -f "$TMP/resume-refused" ]]; then
      echo "ward: daemon: a stop of session sess_a has begun and not completed: its sandboxed processes are held for that stop (some may already have been killed), so \`ward resume\` cannot release them. Run \`ward stop\` to finish it" >&2
      exit 1
    fi
    echo running >"$WARD_STATE_FILE"
    ;;
  "stop "*)
    if [[ -f "$TMP/stop-refused" ]]; then
      echo "ward: daemon: stop could not confirm every sandboxed process of session sess_a ended: 2 ended, 1 still present after 2s" >&2
      exit 1
    fi
    echo none >"$WARD_STATE_FILE"
    ;;
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

# --- an unsettled freeze gets a distinct, still-critical notification (#233): the
# fixed "processes frozen" text must not be shown when `ward pause` itself reports
# some processes not yet confirmed stopped ---
: >"$MOCK_LOG"
echo running >"$WARD_STATE_FILE"
touch "$TMP/pause-unsettled"
WARDOS_MENU_CHOICE=Resume "$pause"
assert_logged '^ward pause /home/dev/payments-api$'
assert_logged '^notify-send -a WardOS -u critical AGENTS PAUSING network closed · credential grants suspended · 2 processes not yet confirmed stopped · workspace retained$'
assert_not_logged 'AGENTS PAUSED network closed'
rm -f "$TMP/pause-unsettled"
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

# --- a stop the daemon refuses (#145 item 5: termination not confirmed) is never
# announced as "Session stopped": its own critical notification carries ward's words ---
: >"$MOCK_LOG"
echo paused >"$WARD_STATE_FILE"
touch "$TMP/stop-refused"
WARDOS_MENU_CHOICE='Stop & preserve workspace' "$pause" 2>/dev/null && fail "a refused stop is an error"
assert_logged '^ward stop /home/dev/payments-api$'
assert_logged '^notify-send -a WardOS -u critical STOP NOT CONFIRMED ward: daemon: stop could not confirm .* 1 still present after 2s$'
assert_not_logged 'Session stopped'
assert_eq "$(cat "$WARD_STATE_FILE")" paused
: >"$MOCK_LOG"
WARDOS_MENU_CHOICE='Stop & restore entry state' "$pause" 2>/dev/null && fail "a refused stop is an error"
assert_logged '^ward stop --restore-entry /home/dev/payments-api$'
assert_logged 'STOP NOT CONFIRMED'
assert_not_logged 'entry state restored'
rm -f "$TMP/stop-refused"

# --- after a refused stop, Resume is refused too (PR #253 review finding 5: an
# incomplete stop is not an ordinary pause): never "Agents resumed", and ward's words
# say to finish the stop ---
: >"$MOCK_LOG"
echo paused >"$WARD_STATE_FILE"
touch "$TMP/resume-refused"
WARDOS_MENU_CHOICE=Resume "$pause" 2>/dev/null && fail "a refused resume is an error"
assert_logged '^ward resume /home/dev/payments-api$'
# shellcheck disable=SC2016
assert_logged '^notify-send -a WardOS -u critical RESUME REFUSED ward: daemon: a stop of session sess_a has begun and not completed.*Run `ward stop` to finish it$'
assert_not_logged 'Agents resumed'
assert_eq "$(cat "$WARD_STATE_FILE")" paused
rm -f "$TMP/resume-refused"

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

# --- pause-all: a partial failure reports it accurately, not as full success (#141
# finding 4 — the title used to read "ALL SESSIONS PAUSED" even here) ---
: >"$MOCK_LOG"
rm -f "$TMP/pause-all-ok"
"$pause" pause-all
assert_logged '^ward pause --all --reason host requested: pause all$'
assert_logged 'SOME SESSIONS NOT PAUSED   sess_a · paused$'
assert_logged 'sess_b · not paused: already paused$'
assert_not_logged 'ALL SESSIONS PAUSED'
assert_not_logged '^ward pause /home'

# --- pause-all: every session actually paused gets the success title ------------
: >"$MOCK_LOG"
touch "$TMP/pause-all-ok"
"$pause" pause-all
assert_logged '^ward pause --all --reason host requested: pause all$'
assert_logged 'ALL SESSIONS PAUSED   sess_a · paused$'
assert_logged 'sess_b · paused$'
assert_not_logged 'SOME SESSIONS NOT PAUSED'
rm -f "$TMP/pause-all-ok"

# --- WARDOS_SESSION pins an immutable target (#141 item 2): it is never re-resolved
# from the directory, so a stale or superseded project session cannot be reached instead ---
: >"$MOCK_LOG"
echo running >"$WARD_STATE_FILE"
WARDOS_SESSION=sess_pinned WARDOS_MENU_CHOICE=Resume "$pause"
assert_logged '^ward pause --session sess_pinned /home/dev/payments-api$'
assert_logged '^ward resume --session sess_pinned /home/dev/payments-api$'

# --- --status honours WARDOS_SESSION too (#141 finding 3): the toggle's status read
# is pinned exactly like pause and resume already are, not silently left to inspect
# the project's current session instead ---
: >"$MOCK_LOG"
WARDOS_SESSION=sess_pinned "$pause" --status >/dev/null
assert_logged '^ward pause --status --session sess_pinned /home/dev/payments-api$'

# --- no session: a plain refusal, nothing run ------------------------------------
: >"$MOCK_LOG"
echo none >"$WARD_STATE_FILE"
"$pause" 2>/dev/null && fail "no session is an error"
assert_not_logged '^ward pause /home'
"$pause" bogus 2>/dev/null && fail "an unknown verb is an error"

# --- shellcheck-clean, usage block, strict mode ----------------------------------
head -1 "$pause" | grep -q '^#!/usr/bin/env bash$' || fail "shebang"
grep -q '^set -euo pipefail$' "$pause" || fail "strict mode"
