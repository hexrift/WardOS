#!/usr/bin/env bash
# wardos-provision-ui (ADR-0027): the unprivileged first-boot provisioning UI, now a
# self-contained terminal UI (foot-hosted under cage — NOT fuzzel/menu-select, which aborts
# under cage's xdg-shell-only compositor). The flow is driven through the REAL TUI code path by
# feeding scripted lines on stdin (E3), and the broker transport (socat) is mocked so the
# requests the UI sends can be inspected. The password must never leak anywhere but the single
# socket request.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

export WARDOS_PROVISIONED_MARKER="$TMP/provisioned"
export WARDOS_PROVISION_SOCK="$TMP/sock"
export WARDOS_PROVISION_STAGE="$TMP/provision.stage"
socat_in="$TMP/socat.in"

# The broker transport: capture the request, reply OK (happy path).
# shellcheck disable=SC2016
mock socat 'req=$(cat); printf "%s\n" "$req" >>"'"$socat_in"'"; printf "OK\n"'
# shellcheck disable=SC2016
mock localectl 'case "${1:-}" in
  status) printf "System Locale: LANG=en_US.UTF-8\n   X11 Layout: us\n" ;;
  list-locales) printf "%s\n" en_US.UTF-8 de_DE.UTF-8 ;;
  list-x11-keymap-layouts) printf "%s\n" us de fr ;;
esac'
# shellcheck disable=SC2016
mock timedatectl 'case "${1:-}" in
  list-timezones) printf "%s\n" Europe/Paris UTC ;;
  show) printf "UTC\n" ;;
esac'

# run_ui LINES… : feed each argument as one input line to the TUI, capturing the exit status.
run_ui() {
  local rc=0
  printf '%s\n' "$@" | wardos-provision-ui || rc=$?
  return "$rc"
}

wardos-provision-ui --help | grep -q '^Usage' || fail "--help prints the usage block"

# --- happy path: keep the three settings, then name/username/password, then create --------
# Each picker is filter-line + choice-line; choice 0 keeps current. XKB_DEFAULT_LAYOUT is unset,
# so "keep current" for the keyboard means no restage — the whole flow runs in one process.
: >"$socat_in"
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_STAGE"
run_ui \
  "" 0 \
  "" 0 \
  "" 0 \
  "Ada Lovelace" \
  "alice" \
  "hunter2secret" "hunter2secret" \
  "1" || fail "provision-ui should succeed on the happy path"
grep -q '^ACCOUNT$' "$socat_in" || fail "an ACCOUNT request was sent; got: $(cat "$socat_in")"
grep -q '^alice$' "$socat_in" || fail "username in the ACCOUNT request"
grep -q '^Ada Lovelace$' "$socat_in" || fail "full name in the ACCOUNT request"
grep -q '^hunter2secret$' "$socat_in" || fail "password crosses the socket once"
# Settings were kept, so no LOCALE/KEYMAP/TIMEZONE request was sent.
if grep -q '^LOCALE$' "$socat_in"; then fail "kept language must send no LOCALE request"; fi
if grep -q '^KEYMAP$' "$socat_in"; then fail "kept keyboard must send no KEYMAP request"; fi
if grep -q '^TIMEZONE$' "$socat_in"; then fail "kept timezone must send no TIMEZONE request"; fi
# The password must not be written to any file the UI created under HOME/state, nor left in the
# stage carry-over (which is removed on success and never holds the password in the first place).
if grep -rIq 'hunter2secret' "$HOME" 2>/dev/null; then fail "password leaked into a file under HOME"; fi
[[ ! -e "$WARDOS_PROVISION_STAGE" ]] || fail "the stage carry-over must be cleared on success"

# --- E3: free-text/password integration through the real TUI (retries) -------------------
# An invalid username re-asks; an empty then a mismatched-then-matching password re-asks. All of
# it flows through the real read/read -rs code, not a stdin-menu fake.
: >"$socat_in"
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_STAGE"
run_ui \
  "" 0 \
  "" 0 \
  "" 0 \
  "Ada" \
  "Bad Name" "alice2" \
  "" "sekret" "sekret" \
  "1" || fail "provision-ui should recover from an invalid username and a password retry"
grep -q '^ACCOUNT$' "$socat_in" || fail "E3: an ACCOUNT request was sent after the retries"
grep -q '^alice2$' "$socat_in" || fail "E3: the second (valid) username reached the broker"
grep -q '^sekret$' "$socat_in" || fail "E3: the confirmed password reached the broker"
if grep -rIq 'sekret' "$HOME" 2>/dev/null; then fail "E3: password leaked into a file under HOME"; fi

# --- E5: failure-transaction — a failed setting apply must NOT proceed to ACCOUNT/marker ---
# The broker replies ERR to LOCALE; the UI applies the chosen locale first, sees it fail, and
# returns to the review WITHOUT ever sending ACCOUNT, so no provisioned marker is written.
: >"$socat_in"
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_STAGE"
# shellcheck disable=SC2016
mock socat 'req=$(cat); printf "%s\n" "$req" >>"'"$socat_in"'"; case "$req" in LOCALE*) printf "ERR could not set locale\n" ;; *) printf "OK\n" ;; esac'
run_ui \
  "" 0 \
  "de" 1 \
  "" 0 \
  "X" \
  "bob" \
  "pw" "pw" \
  "1" && fail "E5: the flow must not succeed when a chosen setting fails to apply"
grep -q '^LOCALE$' "$socat_in" || fail "E5: the chosen locale apply was attempted"
if grep -q '^ACCOUNT$' "$socat_in"; then fail "E5: ACCOUNT must NOT be sent after a failed apply"; fi
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "E5: no provisioned marker on a failed apply"
# Restore the happy-path broker for the remaining checks.
# shellcheck disable=SC2016
mock socat 'req=$(cat); printf "%s\n" "$req" >>"'"$socat_in"'"; printf "OK\n"'

# --- E4: live-keymap staging plumbing — choosing a layout different from the compositor's live
#     layout (XKB_DEFAULT_LAYOUT) records it and asks the bootstrap session to relaunch cage
#     (exit 75) BEFORE any password is entered. See greetd-session.test.sh for the relaunch. ---
: >"$socat_in"
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_STAGE"
unset XKB_DEFAULT_LAYOUT
rc=0
printf '%s\n' "de" 1 | wardos-provision-ui || rc=$?
[[ "$rc" -eq 75 ]] || fail "E4: a keyboard differing from the live layout must exit 75 (restage); got $rc"
grep -q '^KEYMAP=de$' "$WARDOS_PROVISION_STAGE" || fail "E4: the chosen layout is recorded for the restage; got: $(cat "$WARDOS_PROVISION_STAGE" 2>/dev/null)"
[[ ! -s "$socat_in" ]] || fail "E4: no broker traffic before the restage (password not yet entered); got: $(cat "$socat_in")"
# Idempotency: once the layout is live (XKB_DEFAULT_LAYOUT matches the choice), the UI does NOT
# restage again — it proceeds to collect the rest and create the account.
: >"$socat_in"
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_STAGE"
export XKB_DEFAULT_LAYOUT=de
run_ui \
  "de" 1 \
  "" 0 \
  "" 0 \
  "Ada" \
  "carol" \
  "pw2" "pw2" \
  "1" || fail "E4: with the layout already live the UI proceeds without restaging"
unset XKB_DEFAULT_LAYOUT
grep -q '^KEYMAP$' "$socat_in" || fail "E4: the chosen keyboard is applied via the broker at create time"
grep -q '^ACCOUNT$' "$socat_in" || fail "E4: the account is created once the layout is live"

# --- already provisioned: the UI does nothing and does not touch the broker ---------------
: >"$socat_in"
rm -f "$WARDOS_PROVISION_STAGE"
touch "$WARDOS_PROVISIONED_MARKER"
run_ui "" || fail "provision-ui exits 0 when already provisioned"
[[ ! -s "$socat_in" ]] || fail "no broker traffic when already provisioned; got: $(cat "$socat_in")"

echo "ok   provision-ui.test.sh internal assertions"
