#!/usr/bin/env bash
# wardos-grants (#317): lists the current session's temporary grants
# (`ward session grants --json`) fuzzel-dmenu style, confirms, then runs
# `ward session revoke <id>` and relays its exact, host-confirmed three-way
# answer (#140, #245) verbatim — never reworded, never collapsed to a plain
# "done". On demand only: no notifier, no polling, one dmenu, one confirm,
# one revoke call.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

grants=$WARDOS_ROOT/bin/wardos-grants
export WARDOS_PROJECT=/work/payments-api

# --- --help ------------------------------------------------------------------
"$grants" --help | grep -q '^Usage:' || fail "--help prints the usage block"
"$grants" --help | grep -q 'wardos-grants' || fail "--help names itself"

# --- nothing to revoke: a notification, no menu -------------------------------
mock notify-send
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session grants --json /work/payments-api") : ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock wardos-menu-select 'echo "wardos-menu-select must not run here" >&2; exit 1'
"$grants"
assert_logged '^notify-send -a WardOS -t 2500 No temporary grants nothing to revoke in this session$'
assert_not_logged '^wardos-menu-select'

# --- listing, choosing, confirming, and each outcome the daemon can answer ---
github='{"id":1,"kind":"credential","label":"GitHub","scope":"contents:read · github.com","lifetime":"launch","granted_at_unix_ms":1,"revoke_state":"active"}'
write='{"id":2,"kind":"approval","label":"Write /work/src/lib.rs","scope":"write","lifetime":"session","granted_at_unix_ms":2,"revoke_state":"active"}'
export GITHUB_GRANT=$github WRITE_GRANT=$write

confirm_menu() {
  # shellcheck disable=SC2016
  mock wardos-menu-select 'case "$*" in
    "--prompt Temporary grants") grep -m1 "^${WARDOS_MENU_CHOICE}$(printf "\t")" ;;
    "--prompt Revoke "*) grep -m1 "^${WARDOS_CONFIRM_CHOICE}$" ;;
    *) echo "unexpected wardos-menu-select call: $*" >&2; exit 1 ;;
  esac'
}

# An `allow-session` answer: revoked outright, exit 0, ordinary urgency.
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session grants --json /work/payments-api") printf "%s\n%s\n" "$GITHUB_GRANT" "$WRITE_GRANT" ;;
  "session revoke 2 /work/payments-api") printf "  grant 2 revoked\n" ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
confirm_menu
WARDOS_MENU_CHOICE=2 WARDOS_CONFIRM_CHOICE=Revoke "$grants"
assert_logged '^ward session grants --json /work/payments-api$'
assert_logged '^ward session revoke 2 /work/payments-api$'
assert_logged '^notify-send -a WardOS -t 3000 Grant revoked grant 2 revoked$'

# A credential grant whose owning proxy confirmed but had connections already
# open: exit 0, critical urgency all the same — never read as a plain,
# unqualified "revoked".
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session grants --json /work/payments-api") printf "%s\n" "$GITHUB_GRANT" ;;
  "session revoke 1 /work/payments-api") printf "  grant 1 revoked — 2 connections already using it will finish on their own\n" ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
confirm_menu
WARDOS_MENU_CHOICE=1 WARDOS_CONFIRM_CHOICE=Revoke "$grants"
assert_logged '^ward session revoke 1 /work/payments-api$'
assert_logged '^notify-send -a WardOS -u critical Grant revoked — still in flight grant 1 revoked — 2 connections already using it will finish on their own$'

# Nothing acknowledged the withdrawal in time: exit 1, and the grant is not
# reported gone — critical urgency, and the exit status this script itself
# ends with is non-zero too, matching `ward session revoke`'s own exit code
# (#245's "no UI-only revoke is reported as enforced" extended to the exit
# status).
: >"$MOCK_LOG"
cat >"$MOCK_DIR/ward" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "ward $*" >>"$MOCK_LOG"
case "$*" in
  "session grants --json /work/payments-api") printf '%s\n' "$GITHUB_GRANT" ;;
  "session revoke 1 /work/payments-api")
    echo "  grant 1 could not be confirmed revoked; it may still be in effect — see \`ward session grants\`"
    exit 1
    ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac
EOF
chmod +x "$MOCK_DIR/ward"
confirm_menu
WARDOS_MENU_CHOICE=1 WARDOS_CONFIRM_CHOICE=Revoke "$grants" && fail "an unconfirmed revoke must exit non-zero"
# The backtick pair below is the daemon's own literal text, not a command
# substitution — it is inside single quotes, so it never expands.
# shellcheck disable=SC2016
assert_logged '^notify-send -a WardOS -u critical Revoke failed grant 1 could not be confirmed revoked; it may still be in effect — see `ward session grants`$'

# A hard refusal (the grant is no longer live) is reported the same honest
# way — critical, verbatim, never silently swallowed.
: >"$MOCK_LOG"
cat >"$MOCK_DIR/ward" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "ward $*" >>"$MOCK_LOG"
case "$*" in
  "session grants --json /work/payments-api") printf '%s\n' "$GITHUB_GRANT" ;;
  "session revoke 1 /work/payments-api")
    # A hard `Err` reaches the terminal double-wrapped — `Error::Daemon`'s own
    # "daemon: …" plus `main`'s top-level "ward: …" — exactly what a real
    # `ward session revoke` on an id that is no longer live prints; relayed
    # verbatim, not reworded.
    echo "ward: daemon: revoke: grant 1 not found" >&2
    exit 1
    ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac
EOF
chmod +x "$MOCK_DIR/ward"
confirm_menu
WARDOS_MENU_CHOICE=1 WARDOS_CONFIRM_CHOICE=Revoke "$grants" && fail "a refused revoke must exit non-zero"
assert_logged '^notify-send -a WardOS -u critical Revoke failed ward: daemon: revoke: grant 1 not found$'

# --- cancelling the confirmation changes nothing ------------------------------
: >"$MOCK_LOG"
cat >"$MOCK_DIR/ward" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "ward $*" >>"$MOCK_LOG"
case "$*" in
  "session grants --json /work/payments-api") printf '%s\n%s\n' "$GITHUB_GRANT" "$WRITE_GRANT" ;;
  "session revoke "*) echo "revoke must not run when the confirmation is cancelled" >&2; exit 1 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac
EOF
chmod +x "$MOCK_DIR/ward"
confirm_menu
WARDOS_MENU_CHOICE=2 WARDOS_CONFIRM_CHOICE=Cancel "$grants"
assert_not_logged '^ward session revoke'

# --- cancelling the initial listing changes nothing ---------------------------
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock wardos-menu-select 'grep -m1 "^${WARDOS_MENU_CHOICE}$(printf "\t")"'
WARDOS_MENU_CHOICE='' "$grants"
assert_not_logged '^ward session revoke'

# --- a non-active grant shows its own state, mirroring Grant::line() ---------
: >"$MOCK_LOG"
suspended='{"id":3,"kind":"credential","label":"AWS","scope":"read · s3.amazonaws.com","lifetime":"launch","granted_at_unix_ms":1,"revoke_state":"suspended"}'
export SUSPENDED_GRANT=$suspended
cat >"$MOCK_DIR/ward" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "ward $*" >>"$MOCK_LOG"
case "$*" in
  "session grants --json /work/payments-api") printf '%s\n' "$SUSPENDED_GRANT" ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac
EOF
chmod +x "$MOCK_DIR/ward"
# shellcheck disable=SC2016
mock wardos-menu-select 'tee -a "$MOCK_LOG"'
"$grants" </dev/null || true
assert_logged '   3  AWS *read · s3\.amazonaws\.com · launch · suspended$'

# --- WARDOS_SESSION pins the target session, like wardos-pause ---------------
: >"$MOCK_LOG"
cat >"$MOCK_DIR/ward" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "ward $*" >>"$MOCK_LOG"
case "$*" in
  "session grants --json --session sess_pinned /work/payments-api") printf '%s\n' "$WRITE_GRANT" ;;
  "session revoke 2 /work/payments-api --session sess_pinned") printf '  grant 2 revoked\n' ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac
EOF
chmod +x "$MOCK_DIR/ward"
confirm_menu
WARDOS_SESSION=sess_pinned WARDOS_MENU_CHOICE=2 WARDOS_CONFIRM_CHOICE=Revoke "$grants"
assert_logged '^ward session grants --json --session sess_pinned /work/payments-api$'
assert_logged '^ward session revoke 2 /work/payments-api --session sess_pinned$'

# --- shellcheck-clean, usage block, strict mode ------------------------------
head -1 "$grants" | grep -q '^#!/usr/bin/env bash$' || fail "shebang"
grep -q '^set -euo pipefail$' "$grants" || fail "strict mode"
