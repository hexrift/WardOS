#!/usr/bin/env bash
# wardos-session-switch (#141 item 3, finding 6): every live session, digested by
# `ward-shell switcher --lines`, picked through the menu and made the desktop's
# selection. Two sessions whose displayed line happens to render byte-identical must
# still resolve to their own, distinct session — never whichever of the two happens
# to be listed first.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

switch=$WARDOS_ROOT/bin/wardos-session-switch

# --- --help --------------------------------------------------------------------
"$switch" --help | grep -q '^Usage:' || fail "--help prints the usage block"

# --- no live sessions: a notice, no menu, exit 0 --------------------------------
mock ward-shell 'printf ""'
mock notify-send
"$switch"
assert_logged 'No live sessions'
rm "$MOCK_DIR/ward-shell"

# --- two rows with byte-identical labels still select their own session (#141
# finding 6): `ward-shell switcher --lines` is free to emit the same project/agent/
# pending/verify text for two different live sessions (same worktree basename, same
# state), so the fixture below deliberately makes both rows' label field identical
# and only their session id differs.
mock ward-shell 'printf "SESSIONS\t  payments-api  running  no approvals pending  verified\tward session select sess_a\nSESSIONS\t  payments-api  running  no approvals pending  verified\tward session select sess_b\n"'
mock ward

: >"$MOCK_LOG"
WARDOS_MENU_CHOICE='1)' "$switch"
assert_logged '^ward session select sess_a$'
assert_not_logged '^ward session select sess_b$'

: >"$MOCK_LOG"
WARDOS_MENU_CHOICE='2)' "$switch"
assert_logged '^ward session select sess_b$'
assert_not_logged '^ward session select sess_a$'

# --- a cancelled menu selects nothing ------------------------------------------
: >"$MOCK_LOG"
WARDOS_MENU_CHOICE='' "$switch"
assert_not_logged '^ward session select'

# --- shellcheck-clean, usage block, strict mode ----------------------------------
head -1 "$switch" | grep -q '^#!/usr/bin/env bash$' || fail "shebang"
grep -q '^set -euo pipefail$' "$switch" || fail "strict mode"
