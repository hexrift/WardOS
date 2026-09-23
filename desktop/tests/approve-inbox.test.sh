#!/usr/bin/env bash
# wardos-approve-inbox (#146 items 2-3, #141): the persistent inbox reads `ward session
# approvals --json --all` — every live session, pending and decided alike — lists it
# fuzzel-dmenu style with pending first, opens a terminal running `wardos-approve <id>`
# pinned to that approval's own session (WARDOS_SESSION) for a pending choice, and
# shows a read-only summary for a decided one. Nothing pending anywhere gets a
# notification instead of an empty menu.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

inbox=$WARDOS_ROOT/bin/wardos-approve-inbox
export TERMINAL=foot
mock foot

pending12='{"approval":{"id":12,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"r","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":null},"requested_at_unix_ms":1},"outcome":null,"decided_at_unix_ms":null,"agent":"claude","session":"sess_a","project":"payments-api"}'
decided7='{"approval":{"id":7,"tool":"WebFetch","summary":"api.github.com","claim":"WebFetch api.github.com","authority":{"rule":"r","destination":"api.github.com","network":"reachable","method":"GET","credential":"none","repository":null,"lifetime":"once"},"requested_at_unix_ms":0},"outcome":"timed-out","decided_at_unix_ms":9,"agent":"claude","session":"sess_a","project":"payments-api"}'
# A second, unrelated live session (#141): its approval must surface too.
pending20='{"approval":{"id":20,"tool":"Write","summary":"/work/other/db.rs","claim":"Write /work/other/db.rs","authority":{"rule":"r","destination":"/work/other/db.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":null},"requested_at_unix_ms":2},"outcome":null,"decided_at_unix_ms":null,"agent":"codex","session":"sess_b","project":"other-service"}'
export PENDING12=$pending12 DECIDED7=$decided7 PENDING20=$pending20

# --- --help --------------------------------------------------------------------
"$inbox" --help | grep -q '^Usage:' || fail "--help prints the usage block"
"$inbox" --help | grep -q 'wardos-approve-inbox' || fail "--help names itself"
"$inbox" --help | grep -q 'Super + Alt + A' || fail "--help names its keybinding"

# --- nothing pending or decided anywhere: a notification, no menu ----------------
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session approvals --json --all") : ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send
mock wardos-menu-select 'echo "wardos-menu-select must not run here" >&2; exit 1'
"$inbox"
assert_logged '^notify-send -a WardOS -t 2500 No approvals nothing pending or recently decided, in any live session$'
assert_not_logged '^wardos-menu-select'

# --- listing: pending before decided, across every live session ------------------
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session approvals --json --all") printf "%s\n%s\n%s\n" "$DECIDED7" "$PENDING12" "$PENDING20" ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# shellcheck disable=SC2016
mock wardos-menu-select 'grep -m1 "^${WARDOS_MENU_CHOICE}$(printf "\t")"'
WARDOS_MENU_CHOICE=12 "$inbox"
assert_logged '^ward session approvals --json --all$'
assert_logged '^wardos-menu-select --prompt Approvals$'
# Choosing a pending one (12) opens a terminal running wardos-approve 12 pinned to
# its own session, WARDOS_SESSION=sess_a — never $project's/the desktop's selection.
assert_logged '^foot --app-id ward-approval -e wardos-approve 12$'

# The other live session's pending approval (20, sess_b) is reachable too, pinned to
# its own session.
: >"$MOCK_LOG"
WARDOS_MENU_CHOICE=20 "$inbox"
assert_logged '^foot --app-id ward-approval -e wardos-approve 20$'

# --- a decided choice shows a read-only summary, no terminal ----------------------
: >"$MOCK_LOG"
: >"$TMP/info.txt"
# shellcheck disable=SC2016
mock wardos-menu-select 'if [[ $1 == --prompt && $2 == Approvals ]]; then
  grep -m1 "^${WARDOS_MENU_CHOICE}$(printf "\t")"
else
  cat >"$TMP/info.txt"
fi'
WARDOS_MENU_CHOICE=7 "$inbox"
assert_not_logged '^foot'
grep -q '^State        timed-out$' "$TMP/info.txt" || fail "the summary names the state: $(cat "$TMP/info.txt")"
grep -q '^Project      payments-api$' "$TMP/info.txt" || fail "the summary names the project: $(cat "$TMP/info.txt")"
grep -q '^Destination  api.github.com$' "$TMP/info.txt" || fail "the summary names the destination: $(cat "$TMP/info.txt")"
grep -q '^Tool         WebFetch$' "$TMP/info.txt" || fail "the summary names the tool: $(cat "$TMP/info.txt")"

# --- two live sessions sharing the same numeric approval id (#222 review):
# Approval::id is only that session's own sequence number, so both can legitimately
# show id 12 in this same listing at once. Recovering the chosen row with a second
# `awk '$1 == id'` lookup would return both of them; selecting either row must
# still open wardos-approve 12 pinned to that row's own WARDOS_SESSION -------------
: >"$MOCK_LOG"
dup12_a='{"approval":{"id":12,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"r","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":null},"requested_at_unix_ms":1},"outcome":null,"decided_at_unix_ms":null,"agent":"claude","session":"sess_a","project":"payments-api"}'
dup12_c='{"approval":{"id":12,"tool":"Write","summary":"/work/other/db.rs","claim":"Write /work/other/db.rs","authority":{"rule":"r","destination":"/work/other/db.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":null},"requested_at_unix_ms":2},"outcome":null,"decided_at_unix_ms":null,"agent":"codex","session":"sess_c","project":"other-service"}'
export DUP12_A=$dup12_a DUP12_C=$dup12_c
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session approvals --json --all") printf "%s\n%s\n" "$DUP12_A" "$DUP12_C" ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# The mock foot records the WARDOS_SESSION it was actually opened with, so a row
# picked by session, not by the (here, shared) id, can be checked precisely.
# shellcheck disable=SC2016
mock foot 'printf "%s\n" "${WARDOS_SESSION:-}" >>"$TMP/opened_sessions"'
: >"$TMP/opened_sessions"
# Selecting by a substring unique to one row (its session), never by the shared
# id "12" — a lookup keyed on bare id would match both of these lines.
# shellcheck disable=SC2016
mock wardos-menu-select 'grep -m1 -F -- "$WARDOS_MENU_CHOICE"'
WARDOS_MENU_CHOICE=sess_a "$inbox"
assert_logged '^foot --app-id ward-approval -e wardos-approve 12$'
assert_eq "$(cat "$TMP/opened_sessions")" "sess_a"

: >"$MOCK_LOG"
: >"$TMP/opened_sessions"
WARDOS_MENU_CHOICE=sess_c "$inbox"
assert_logged '^foot --app-id ward-approval -e wardos-approve 12$'
assert_eq "$(cat "$TMP/opened_sessions")" "sess_c"
mock foot

# --- a cancelled listing does nothing, quietly ------------------------------------
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock wardos-menu-select 'grep -m1 "^${WARDOS_MENU_CHOICE}$(printf "\t")"'
WARDOS_MENU_CHOICE='' "$inbox"
assert_not_logged '^foot'
assert_not_logged '^ward session approve'

# --- shellcheck-clean, usage block, strict mode -----------------------------------
head -1 "$inbox" | grep -q '^#!/usr/bin/env bash$' || fail "shebang"
grep -q '^set -euo pipefail$' "$inbox" || fail "strict mode"
