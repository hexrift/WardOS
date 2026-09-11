#!/usr/bin/env bash
# wardos-provisiond (ADR-0027): the first-boot provisioning broker. Reads one request on
# stdin, performs one narrow operation, writes one reply line, refuses once provisioned.
# The privileged tools (localectl/timedatectl/useradd/usermod/chpasswd/userdel/id) are mocked.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

export WARDOS_PROVISIONED_MARKER="$TMP/provisioned"
export WARDOS_PROVISION_LOCK="$TMP/provisiond.lock"
export WARDOS_KEYBOARD_STATE="$TMP/keyboard-layout"
for c in localectl timedatectl useradd usermod chpasswd userdel getent; do mock "$c"; done

# ask VERB-AND-LINES… : feed the lines as one request, print the reply.
ask() { printf '%s\n' "$@" | wardos-provisiond; }

wardos-provisiond --help >/dev/null 2>&1 || true # no --help; must at least not hang

# STATUS reflects the marker.
[[ "$(ask STATUS)" == "OK unprovisioned" ]] || fail "STATUS unprovisioned"

# Valid settings apply and reply OK.
: >"$MOCK_LOG"
[[ "$(ask LOCALE de_DE.UTF-8)" == OK ]] || fail "LOCALE ok"
assert_logged '^localectl set-locale LANG=de_DE.UTF-8$'
[[ "$(ask KEYMAP fr)" == OK ]] || fail "KEYMAP ok"
assert_logged '^localectl set-x11-keymap fr$'
# The keyboard choice is recorded so the new user's Hyprland config can adopt it.
[[ "$(cat "$WARDOS_KEYBOARD_STATE" 2>/dev/null)" == fr ]] || fail "KEYMAP records the layout for the desktop"
[[ "$(ask TIMEZONE Europe/Paris)" == OK ]] || fail "TIMEZONE ok"
assert_logged '^timedatectl set-timezone Europe/Paris$'

# Invalid input is rejected before any tool runs.
: >"$MOCK_LOG"
[[ "$(ask LOCALE 'en_US; rm -rf /')" == ERR* ]] || fail "LOCALE rejects junk"
[[ "$(ask KEYMAP 'us && reboot')" == ERR* ]] || fail "KEYMAP rejects junk"
[[ "$(ask TIMEZONE '../../etc')" == ERR* ]] || fail "TIMEZONE rejects traversal"
assert_not_logged 'set-locale'
assert_not_logged 'set-x11-keymap'
assert_not_logged 'set-timezone'

# ACCOUNT: a new user is created, the password is set, the marker committed. The password
# is fed to chpasswd on stdin, so it must appear in NO argument log.
: >"$MOCK_LOG"
mock id 'exit 1' # the user does not exist yet
[[ "$(printf 'ACCOUNT\nalice\nAda Lovelace\nhunter2secret\n' | wardos-provisiond)" == OK ]] ||
  fail "ACCOUNT ok"
assert_logged '^useradd -m -c Ada Lovelace -G wheel -s /bin/bash alice$'
assert_logged '^chpasswd'
assert_not_logged 'hunter2secret'
assert_file "$WARDOS_PROVISIONED_MARKER"

# Once provisioned, every mutating verb is refused.
[[ "$(ask STATUS)" == "OK provisioned" ]] || fail "STATUS provisioned"
[[ "$(ask LOCALE en_US.UTF-8)" == "ERR already provisioned" ]] || fail "LOCALE refused when provisioned"
[[ "$(printf 'ACCOUNT\nbob\nBob\npw\n' | wardos-provisiond)" == "ERR already provisioned" ]] ||
  fail "ACCOUNT refused when provisioned"

# Invalid username is rejected (fresh marker).
rm -f "$WARDOS_PROVISIONED_MARKER"
: >"$MOCK_LOG"
mock id 'exit 1'
[[ "$(printf 'ACCOUNT\n1nvalid Name\nx\npw\n' | wardos-provisiond)" == ERR* ]] || fail "bad username rejected"
assert_not_logged '^useradd'

# A reserved name is refused by the blocklist (before any lookup).
: >"$MOCK_LOG"
mock id 'echo 0'
[[ "$(printf 'ACCOUNT\nroot\nr\npw\n' | wardos-provisiond)" == "ERR name is reserved" ]] ||
  fail "reserved name refused"
assert_not_logged '^useradd'
assert_not_logged '^usermod'

# Any name already in use is refused, never adopted/elevated — including nobody=65534 (the
# exact defect: UID 65534 must not be added to wheel). No usermod, no useradd.
: >"$MOCK_LOG"
mock id 'echo 65534' # the name resolves to an existing (system) account
[[ "$(printf 'ACCOUNT\nsvcacct\nS\npw\n' | wardos-provisiond)" == "ERR name already in use" ]] ||
  fail "an existing account (uid 65534) must be refused, not adopted"
assert_not_logged '^usermod'
assert_not_logged '^useradd'
# An existing in-range account is likewise refused (no adoption of any kind).
: >"$MOCK_LOG"
mock id 'echo 1500'
[[ "$(printf 'ACCOUNT\nsvc2\nS\npw\n' | wardos-provisiond)" == "ERR name already in use" ]] ||
  fail "an existing account must be refused"
assert_not_logged '^useradd'

# chpasswd failure on a freshly created user rolls the user back and does not mark provisioned.
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_LOCK"
: >"$MOCK_LOG"
mock id 'exit 1'
mock chpasswd 'exit 1'
[[ "$(printf 'ACCOUNT\ncarol\nCarol\npw\n' | wardos-provisiond)" == ERR* ]] || fail "chpasswd failure reported"
assert_logged '^userdel -r carol$'
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "marker must not exist after a failed account"

# Marker-commit failure ALSO rolls the newly created user back (the cited defect: a marker
# write/rename failure must not leave a password-set wheel user behind).
mock chpasswd # succeeds again
: >"$MOCK_LOG"
mock id 'exit 1'
: >"$TMP/blocker" # a regular file, so a marker path *under* it cannot be created
out=$(printf 'ACCOUNT\nerin\nErin\npw\n' |
  WARDOS_PROVISIONED_MARKER="$TMP/blocker/nope/provisioned" WARDOS_PROVISION_LOCK="$TMP/lock2" wardos-provisiond)
[[ "$out" == ERR* ]] || fail "marker-commit failure must be reported; got: $out"
assert_logged '^useradd -m -c Erin -G wheel -s /bin/bash erin$'
assert_logged '^userdel -r erin$'

# An empty password is refused.
mock chpasswd
: >"$MOCK_LOG"
mock id 'exit 1'
[[ "$(printf 'ACCOUNT\ndave\nDave\n\n' | wardos-provisiond)" == "ERR empty password" ]] || fail "empty password refused"

# Two concurrent ACCOUNT requests must create exactly one administrator: the exclusive lock
# serializes them, and the loser re-checks state after the lock and is refused.
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_LOCK"
: >"$MOCK_LOG"
mock id 'exit 1'
mock chpasswd
(printf 'ACCOUNT\nalice\nAlice\npw\n' | wardos-provisiond >"$TMP/c1" 2>/dev/null) &
(printf 'ACCOUNT\nbob\nBob\npw\n' | wardos-provisiond >"$TMP/c2" 2>/dev/null) &
wait
n=$(grep -c '^useradd' "$MOCK_LOG" || true)
[[ "$n" -eq 1 ]] || fail "concurrent ACCOUNT created $n accounts, expected exactly 1"
results="$(cat "$TMP/c1" "$TMP/c2")"
[[ "$(grep -c '^OK$' <<<"$results")" -eq 1 ]] || fail "exactly one ACCOUNT should win; got: $results"
grep -q 'already provisioned' <<<"$results" || fail "the losing ACCOUNT must be refused; got: $results"

echo "ok   provisiond.test.sh internal assertions"
