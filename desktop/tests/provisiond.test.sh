#!/usr/bin/env bash
# wardos-provisiond (ADR-0027): the first-boot provisioning broker. Reads one request on
# stdin, performs one narrow operation, writes one reply line, refuses once provisioned.
# The privileged tools (localectl/timedatectl/useradd/usermod/chpasswd/userdel/id) are mocked.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

export WARDOS_PROVISIONED_MARKER="$TMP/provisioned"
export WARDOS_PROVISION_LOCK="$TMP/provisiond.lock"
export WARDOS_PROVISION_JOURNAL="$TMP/provision.journal"
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

# --- #127: an unresolved transaction (failed rollback) refuses a second admin, then recovers
# Stateful account mocks share an on-disk account set, so a failed userdel really leaves the
# account behind and the next request must reconcile it — never add a second administrator.
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_LOCK" "$WARDOS_PROVISION_JOURNAL"
acct_dir="$TMP/accounts"
rm -rf "$acct_dir"
mkdir -p "$acct_dir"
export ACCT_DIR="$acct_dir"
# shellcheck disable=SC2016
mock useradd 'u="${@: -1}"; : >"$ACCT_DIR/$u"'
# shellcheck disable=SC2016
mock id 'for a in "$@"; do case "$a" in -*) ;; *) if [[ -e "$ACCT_DIR/$a" ]]; then echo 1000; exit 0; else exit 1; fi ;; esac; done; exit 1'
# shellcheck disable=SC2016
mock userdel '[[ -n "${USERDEL_FAIL:-}" ]] && exit 1; u="${@: -1}"; rm -f "$ACCT_DIR/$u"; exit 0'
mock chpasswd 'exit 1' # force a mid-transaction failure so rollback runs

# ACCOUNT alice: chpasswd fails AND userdel fails → alice remains, the transaction is left
# unresolved (its journal persists), and no marker is written.
out=$(printf 'ACCOUNT\nalice\nAlice\npw\n' | USERDEL_FAIL=1 wardos-provisiond)
[[ "$out" == ERR* ]] || fail "a failed apply must report ERR; got: $out"
[[ -e "$acct_dir/alice" ]] || fail "a failed userdel leaves the account (stateful mock)"
[[ -e "$WARDOS_PROVISION_JOURNAL" ]] || fail "an unresolved transaction keeps its journal"
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "a failed transaction must not mark provisioned"

# A DIFFERENT username is now REFUSED while alice is unresolved and cannot be cleaned up
# (this is the reproduced bug: two residual administrators).
out=$(printf 'ACCOUNT\nbob\nBob\npw\n' | USERDEL_FAIL=1 wardos-provisiond)
[[ "$out" == ERR*unresolved* ]] || fail "a second admin must be refused while unresolved; got: $out"
[[ ! -e "$acct_dir/bob" ]] || fail "no second account is created while unresolved"
[[ "$(find "$acct_dir" -maxdepth 1 -type f | wc -l)" -eq 1 ]] ||
  fail "must not accumulate administrators: $(ls "$acct_dir")"

# Recovery: once userdel can succeed and the password applies, the next attempt reconciles
# (removes alice), creates the new admin, and commits — exactly one administrator results.
mock chpasswd # succeeds now
out=$(printf 'ACCOUNT\nbob\nBob\npw\n' | wardos-provisiond) # USERDEL_FAIL unset → userdel ok
[[ "$out" == OK ]] || fail "recovery must create the admin once cleanup succeeds; got: $out"
[[ ! -e "$acct_dir/alice" ]] || fail "the unresolved account is removed on recovery"
[[ -e "$acct_dir/bob" ]] || fail "the new admin is created on recovery"
[[ ! -e "$WARDOS_PROVISION_JOURNAL" ]] || fail "the journal is cleared after a committed recovery"
assert_file "$WARDOS_PROVISIONED_MARKER"

# --- #127: a crash mid-transaction (journal + orphan account, no marker) reconciles on the
# next attempt — the deterministic restart case.
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_LOCK"
rm -rf "$acct_dir"
mkdir -p "$acct_dir"
: >"$acct_dir/ghost"                            # an orphan a crashed attempt left behind
printf 'ghost\n' >"$WARDOS_PROVISION_JOURNAL"   # its durable transaction record
out=$(printf 'ACCOUNT\nnewadmin\nNew Admin\npw\n' | wardos-provisiond)
[[ "$out" == OK ]] || fail "a restart must reconcile the orphan and proceed; got: $out"
[[ ! -e "$acct_dir/ghost" ]] || fail "the orphan from the interrupted attempt is removed"
[[ -e "$acct_dir/newadmin" ]] || fail "the new admin is created after reconciliation"
assert_file "$WARDOS_PROVISIONED_MARKER"

# --- durability fault injection (#127 review): a failed fsync must fail the write CLOSED,
# never be swallowed with `|| true`. `sync <path>` (coreutils) fsyncs that path and exits
# non-zero on a flush error; the broker's write_durable checks both the file flush and the
# directory flush. Mocking `sync` lets us fail each independently.
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_LOCK" "$WARDOS_PROVISION_JOURNAL"
mock useradd
mock chpasswd
mock userdel
mock id 'exit 1'

# File-flush failure: the fsync of the journal's temp file fails, so the very first durable
# write in the transaction fails and the account is never created, no marker is written.
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock sync 'case "$1" in *.tmp.*) exit 1 ;; esac; exit 0'
out=$(printf 'ACCOUNT\nfaye\nFaye\npw\n' | wardos-provisiond)
[[ "$out" == ERR* ]] || fail "a file-flush (fsync) failure must fail the durable write closed; got: $out"
assert_not_logged '^useradd'
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "no marker after a failed file flush"
[[ ! -e "$WARDOS_PROVISION_JOURNAL" ]] || fail "the temp is cleaned up after a failed file flush"

# Directory-flush failure: the file flush succeeds but the fsync of the containing directory
# fails, so write_durable still returns non-zero and the transaction fails closed.
: >"$MOCK_LOG"
rm -f "$WARDOS_PROVISION_JOURNAL"
# shellcheck disable=SC2016
mock sync 'case "$1" in *.tmp.*) exit 0 ;; *) exit 1 ;; esac'
out=$(printf 'ACCOUNT\ngwen\nGwen\npw\n' | wardos-provisiond)
[[ "$out" == ERR* ]] || fail "a directory-flush (fsync) failure must fail the durable write closed; got: $out"
assert_not_logged '^useradd'
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "no marker after a failed directory flush"

# KEYMAP persistence failure (#127 review item 2): if the chosen layout cannot be recorded
# durably for the new user's Hyprland session, the broker must report an error, not OK — the
# earlier "provisioning says success, first desktop gets a different layout" failure mode.
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_KEYBOARD_STATE"
: >"$MOCK_LOG"
mock sync 'exit 1' # any flush of the keyboard-layout record fails
out=$(printf 'KEYMAP\ngb\n' | wardos-provisiond)
[[ "$out" == ERR* ]] || fail "KEYMAP must report an error when the layout cannot be persisted; got: $out"
assert_logged '^localectl set-x11-keymap gb$' # the system keymap step still ran
[[ ! -e "$WARDOS_KEYBOARD_STATE" ]] || fail "a failed persist leaves no half-written layout record"
mock sync 'exit 0' # restore a succeeding flush for any later use

echo "ok   provisiond.test.sh internal assertions"
