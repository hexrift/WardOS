#!/usr/bin/env bash
# wardos-grants (#317): the grants segment offers an on-demand, session-pinned
# revoke action over the daemon's authoritative `ward session grants` list. The
# chosen id is always revoked against the same explicit session that produced the
# list, and the CLI's exact host-confirmed result is surfaced without reinterpretation.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

grants=$WARDOS_ROOT/bin/wardos-grants
mock notify-send

credential='{"id":7,"kind":"credential","label":"GitHub","scope":"contents:read / api.github.com","lifetime":"launch","granted_at_unix_ms":1,"revoke_state":"active"}'
approval='{"id":8,"kind":"approval","label":"WebFetch example.org","scope":"network","lifetime":"session","granted_at_unix_ms":2,"revoke_state":"suspended"}'
export CREDENTIAL=$credential APPROVAL=$approval

# --- --help --------------------------------------------------------------------
"$grants" --help | grep -q '^Usage:' || fail "--help prints the usage block"
"$grants" --help | grep -q 'wardos-grants' || fail "--help names itself"

# --- no selected session: no list and no menu ----------------------------------
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session select --show") echo "(none)" ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock wardos-menu-select 'echo "menu must not open" >&2; exit 1'
"$grants"
assert_logged '^ward session select --show$'
assert_not_logged '^ward session grants'
assert_not_logged '^wardos-menu-select'
assert_logged '^notify-send -a WardOS -t 2500 No active session select or start a Ward session first$'

# --- selected session with no grants: empty-state notification ------------------
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session select --show") echo "sess_a" ;;
  "session grants --session sess_a --json") : ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
"$grants"
assert_logged '^ward session grants --session sess_a --json$'
assert_not_logged '^wardos-menu-select'
assert_logged '^notify-send -a WardOS -t 2500 No temporary grants sess_a holds no temporary authority$'

# --- choose one row, confirm, and revoke against the exact listed session --------
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session select --show") echo "sess_a" ;;
  "session grants --session sess_a --json") printf "%s\n%s\n" "$CREDENTIAL" "$APPROVAL" ;;
  "session revoke 7 --session sess_a") echo "  grant 7 revoked" ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# shellcheck disable=SC2016
mock wardos-menu-select 'case "$2" in
  Grants) grep -m1 "^${WARDOS_MENU_CHOICE}$(printf "\t")" ;;
  "Revoke grant 7?") printf "%s\n" "${WARDOS_CONFIRM:-Cancel}" ;;
  *) echo "unexpected prompt: $*" >&2; exit 1 ;;
esac'
WARDOS_MENU_CHOICE=7 WARDOS_CONFIRM=Revoke "$grants"
assert_logged '^ward session select --show$'
assert_logged '^ward session grants --session sess_a --json$'
assert_logged '^ward session revoke 7 --session sess_a$'
assert_logged '^notify-send -a WardOS -t 6000 Grant revoke result   grant 7 revoked$'

# The second row is visible with its daemon state. The menu receives the original
# id/session-safe fields before the display text; state is not silently discarded.
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock wardos-menu-select 'case "$2" in
  Grants) tee -a "$MOCK_LOG" | grep -m1 "^${WARDOS_MENU_CHOICE}$(printf "\t")" ;;
  "Revoke grant 8?") printf "%s\n" Cancel ;;
  *) exit 1 ;;
esac'
WARDOS_MENU_CHOICE=8 "$grants"
assert_logged '8.*approval.*WebFetch example.org.*session.*suspended'
assert_not_logged '^ward session revoke 8 '

# --- cancellation never mutates authority --------------------------------------
: >"$MOCK_LOG"
WARDOS_MENU_CHOICE=7 WARDOS_CONFIRM=Cancel "$grants"
assert_not_logged '^ward session revoke '

# --- unconfirmed is visibly failure, with the CLI's exact warning preserved ----
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session select --show") echo "sess_a" ;;
  "session grants --session sess_a --json") printf "%s\n" "$CREDENTIAL" ;;
  "session revoke 7 --session sess_a")
    echo "  grant 7 could not be confirmed revoked; it may still be in effect - see \`ward session grants\`"
    exit 1
    ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# shellcheck disable=SC2016
mock wardos-menu-select 'case "$2" in
  Grants) grep -m1 "^7$(printf "\t")" ;;
  "Revoke grant 7?") printf "%s\n" Revoke ;;
  *) exit 1 ;;
esac'
set +e
"$grants"
status=$?
set -e
[[ $status -ne 0 ]] || fail "an unconfirmed revoke must fail"
assert_logged '^ward session revoke 7 --session sess_a$'
assert_logged 'notify-send -a WardOS -u critical -t 8000 Grant revoke result .*could not be confirmed revoked; it may still be in effect'

# --- an in-flight success remains a success and keeps the warning ----------------
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session select --show") echo "sess_a" ;;
  "session grants --session sess_a --json") printf "%s\n" "$CREDENTIAL" ;;
  "session revoke 7 --session sess_a")
    echo "  grant 7 revoked - 2 connections already using it will finish on their own"
    ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
"$grants"
assert_logged 'notify-send -a WardOS -t 6000 Grant revoke result .*2 connections already using it will finish on their own$'

head -1 "$grants" | grep -q '^#!/usr/bin/env bash$' || fail "shebang"
grep -q '^set -euo pipefail$' "$grants" || fail "strict mode"
