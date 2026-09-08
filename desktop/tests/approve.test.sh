#!/usr/bin/env bash
# wardos-approve (docs/design-language.md §10, ADR-0016): the watch path turns each
# pending approval into a mako notification with actions and relays the chosen action;
# the interactive path picks an approval and answers it with y / s / n.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

approve=$WARDOS_ROOT/bin/wardos-approve
line12='{"id":12,"tool":"Write","summary":"/work/src/lib.rs","reason":"step-through: pause before writes","requested_at_unix_ms":1,"agent":"claude","session":"sess_a"}'
line13='{"id":13,"tool":"WebFetch","summary":"api.github.com","reason":"step-through: pause before network","requested_at_unix_ms":2,"agent":"claude","session":"sess_a"}'
export LINE12=$line12 LINE13=$line13

# --- --help --------------------------------------------------------------------
"$approve" --help | grep -q '^Usage:' || fail "--help prints the usage block"
"$approve" --help | grep -q 'wardos-approve --watch' || fail "--help names --watch"

# --- --watch: one notification per pending approval, the action relayed --------
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --follow "*) printf "%s\n%s\n" "$LINE12" "$LINE13" ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# The first notification is answered with "Allow session", the second is dismissed.
# shellcheck disable=SC2016
mock notify-send 'case "$*" in *"/work/src/lib.rs"*) echo session ;; *) exit 0 ;; esac'
WARDOS_PROJECT=/home/dev/payments-api "$approve" --watch --once
assert_logged '^ward session pending --follow /home/dev/payments-api$'
assert_logged '^notify-send -a WardOS -c ward-approval -u critical --wait -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests /work/src/lib.rs$'
assert_logged '^Reason  step-through: pause before writes$'
assert_logged '^Scope   Write$'
assert_logged '^notify-send .* Claude requests api.github.com$'
assert_logged '^ward session approve --session sess_a 12 allow-session$'
assert_not_logged '^ward session approve --session sess_a 13'

# A denial relays as deny; an unknown action is left to the daemon's timeout.
: >"$MOCK_LOG"
mock notify-send 'case "$*" in *"/work/src/lib.rs"*) echo deny ;; *) echo bogus ;; esac'
WARDOS_PROJECT=/home/dev/payments-api "$approve" --watch --once
assert_logged '^ward session approve --session sess_a 12 deny$'
assert_not_logged '^ward session approve --session sess_a 13'

# --- interactive: one pending approval is picked, the menu answers y / s / n ---
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending "*) printf "%s\n" "$LINE12" ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
WARDOS_MENU_CHOICE=y "$approve"
assert_logged '^ward session pending '"$PWD"'$'
assert_logged '^ward session approve --session sess_a 12 allow$'
assert_not_logged '^wardos-menu-select'

# The menu is wardos-menu-select when it exists; s is the session grant.
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock wardos-menu-select 'grep -m1 "^${WARDOS_MENU_CHOICE}$(printf "\t")"'
WARDOS_MENU_CHOICE=s "$approve"
assert_logged '^wardos-menu-select --prompt Approve$'
assert_logged '^ward session approve --session sess_a 12 allow-session$'

# A cancelled menu answers nothing (the daemon's timeout denies).
: >"$MOCK_LOG"
WARDOS_MENU_CHOICE='' "$approve" && fail "a cancelled menu is not success"
assert_not_logged '^ward session approve'

# --- interactive: several pending, the approval is picked first --------------------
: >"$MOCK_LOG"
rm -f "$MOCK_DIR/wardos-menu-select"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending "*) printf "%s\n%s\n" "$LINE12" "$LINE13" ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
WARDOS_MENU_CHOICE=13 "$approve" 13 n
assert_logged '^ward session approve --session sess_a 13 deny$'
: >"$MOCK_LOG"
"$approve" 99 y && fail "an id that is not pending is an error"
assert_not_logged '^ward session approve'
: >"$MOCK_LOG"
# With no id the first menu picks the approval by its id line, then the answer.
# Both menus read the same choice with the stdin backend, so pick 13 and give n.
WARDOS_MENU_CHOICE=13 "$approve" "" n 2>/dev/null || true
assert_logged '^ward session approve --session sess_a 13 deny$'

# --- nothing pending -------------------------------------------------------------
: >"$MOCK_LOG"
mock ward 'case "$*" in "session pending "*) : ;; *) exit 1 ;; esac'
out=$("$approve")
assert_eq "$out" "  no pending approvals"
assert_not_logged '^ward session approve'

# --- shellcheck-clean, usage block, strict mode -----------------------------------
head -1 "$approve" | grep -q '^#!/usr/bin/env bash$' || fail "shebang"
grep -q '^set -euo pipefail$' "$approve" || fail "strict mode"
