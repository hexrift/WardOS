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

# --- blocker 4: EVERY mutating verb re-checks the marker AFTER the lock, not only ACCOUNT.
# A KEYMAP (or LOCALE/TIMEZONE) request can pass its cheap pre-lock check while the machine is
# still unprovisioned, block on the lock, and reach the front of the queue only AFTER an ACCOUNT
# committed the marker. Before the fix it mutated the just-finalized machine; now the
# post-acquisition re-check refuses it and it mutates NOTHING. Deterministic: we hold the lock
# from outside so the KEYMAP request blocks after its pre-lock check, commit the marker while it
# is blocked (as a winning ACCOUNT would), then release — the re-check is guaranteed to see the
# committed marker regardless of scheduling.
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_LOCK" "$WARDOS_PROVISION_JOURNAL" "$WARDOS_KEYBOARD_STATE"
: >"$MOCK_LOG"
mock localectl # if the verb reaches its mutation, set-x11-keymap would be logged (the bug)
exec {holdfd}>"$WARDOS_PROVISION_LOCK"
flock -x "$holdfd" # hold the exclusive lock so the broker's flock blocks
printf 'KEYMAP\nfr\n' | wardos-provisiond >"$TMP/late.out" 2>/dev/null &
latepid=$!
sleep 0.3                          # let KEYMAP pass its pre-lock check and block on the lock
: >"$WARDOS_PROVISIONED_MARKER"    # a concurrent ACCOUNT commits the marker while KEYMAP waits
flock -u "$holdfd"                 # release: KEYMAP now acquires the lock and re-checks
exec {holdfd}>&-
wait "$latepid"
[[ "$(cat "$TMP/late.out")" == "ERR already provisioned" ]] ||
  fail "blocker 4: a KEYMAP that locks after ACCOUNT committed must be refused; got: $(cat "$TMP/late.out")"
assert_not_logged 'set-x11-keymap' # the finalized machine must NOT be mutated
[[ ! -e "$WARDOS_KEYBOARD_STATE" ]] || fail "blocker 4: the refused KEYMAP must not record a layout"

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

# Marker directory-flush failure AFTER the marker was renamed into place (#119 review): the
# marker file DID land on disk (temp write + temp fsync + rename all succeeded) but the fsync
# of its directory — the barrier that proves the rename survives a power cut — fails, AND the
# single retry of that flush fails too. The rename is NOT proven durable, so the broker must
# NOT acknowledge OK: it treats the transaction as INDETERMINATE, keeps the journal (naming
# this account) for reconcile, and replies recovery-required. The freshly created account is
# NOT rolled back — the invariant that a failed durability sync never leaves the marker
# present with the account removed still holds. Put the marker in its own directory (MK_DIR)
# so only that directory's fsync can be failed, leaving the journal's directory flush intact.
export MK_DIR="$TMP/mk"
export WARDOS_PROVISIONED_MARKER="$MK_DIR/provisioned"
rm -rf "$MK_DIR"
rm -f "$WARDOS_PROVISION_LOCK" "$WARDOS_PROVISION_JOURNAL"
: >"$MOCK_LOG"
mock useradd
mock chpasswd
mock userdel
mock id 'exit 1'
# Fail EVERY fsync of the marker directory (the initial commit flush AND the single retry);
# every temp-file fsync, the journal directory fsync, and the keyboard-state fsync still
# succeed. So the marker temp is written, fsynced and renamed, and only fsync_path "$MK_DIR"
# (the trailing directory flush and its retry) fails.
# shellcheck disable=SC2016
mock sync 'case "$1" in "$MK_DIR") exit 1 ;; esac; exit 0'
out=$(printf 'ACCOUNT\nheidi\nHeidi\npw\n' | wardos-provisiond)
[[ "$out" == ERR*unresolved* ]] ||
  fail "an unconfirmable marker durability barrier must report recovery-required, not OK; got: $out"
assert_not_logged '^userdel'                             # never roll the account back
assert_file "$WARDOS_PROVISIONED_MARKER"                 # the marker is present (renamed into place)
[[ -e "$WARDOS_PROVISION_JOURNAL" ]] ||
  fail "an indeterminate transaction must keep its journal for reconcile"

# Power loss after the indeterminate state (#119 review): the not-yet-durable marker is
# dropped by the crash while the journalled orphan account survives. On the next boot the
# machine is unprovisioned; reconcile_pending MUST remove that orphan before creating any new
# account, so a user picking a DIFFERENT name cannot end up as a second administrator. Use the
# stateful ACCT_DIR mocks so the removal is observable.
mk_acct_dir="$TMP/mk-accounts"
rm -rf "$mk_acct_dir"
mkdir -p "$mk_acct_dir"
export ACCT_DIR="$mk_acct_dir"
# shellcheck disable=SC2016
mock useradd 'u="${@: -1}"; : >"$ACCT_DIR/$u"'
# shellcheck disable=SC2016
mock id 'for a in "$@"; do case "$a" in -*) ;; *) if [[ -e "$ACCT_DIR/$a" ]]; then echo 1000; exit 0; else exit 1; fi ;; esac; done; exit 1'
# shellcheck disable=SC2016
mock userdel 'u="${@: -1}"; rm -f "$ACCT_DIR/$u"; exit 0'
mock chpasswd
: >"$ACCT_DIR/heidi"                          # the orphan account the indeterminate txn created
printf 'heidi\n' >"$WARDOS_PROVISION_JOURNAL" # its journal still names it
rm -f "$WARDOS_PROVISIONED_MARKER"            # the crash dropped the not-yet-durable marker
rm -f "$WARDOS_PROVISION_LOCK"
mock sync 'exit 0'                            # storage recovered: flushes succeed again
out=$(printf 'ACCOUNT\nolga\nOlga\npw\n' | wardos-provisiond)
[[ "$out" == OK ]] || fail "recovery after an indeterminate crash must create the admin once; got: $out"
[[ ! -e "$mk_acct_dir/heidi" ]] || fail "the orphan from the indeterminate transaction must be reconciled away"
[[ -e "$mk_acct_dir/olga" ]] || fail "the new admin is created after reconciliation"
[[ "$(find "$mk_acct_dir" -maxdepth 1 -type f | wc -l)" -eq 1 ]] ||
  fail "a power loss after the indeterminate state must not yield two administrators: $(ls "$mk_acct_dir")"
assert_file "$WARDOS_PROVISIONED_MARKER"
[[ ! -e "$WARDOS_PROVISION_JOURNAL" ]] || fail "the journal is cleared after a committed recovery"

# Restore simple mocks and a succeeding flush for the tests that follow.
mock useradd
mock chpasswd
mock userdel
mock id 'exit 1'
mock sync 'exit 0'

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

# --- #119 review item 5: bounded request/field sizes, and control-char/length rejection of the
# free-form full name. A hostile client on the socket must not be able to send unbounded data,
# and the GECOS full name (the one free-form account field) must reject ANY control character
# and stay within a length cap — the old check rejected only ':' and a literal newline.
export WARDOS_PROVISIONED_MARKER="$TMP/provisioned" # back to a clean marker path after MK_DIR
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_LOCK" "$WARDOS_PROVISION_JOURNAL"
mock useradd
mock chpasswd
mock userdel
mock id 'exit 1'
mock localectl
mock sync 'exit 0'

# An over-long field line is DENIED before the verb acts (bounded read, cap 64 for a locale).
: >"$MOCK_LOG"
long_locale=$(printf 'a%.0s' {1..100})
out=$(printf 'LOCALE\n%s\n' "$long_locale" | wardos-provisiond)
[[ "$out" == ERR* ]] || fail "an over-long locale line must be denied; got: $out"
assert_not_logged 'set-locale' # rejected before (and instead of) acting on it

# A full name with a TAB is denied (control char), and nothing is created.
: >"$MOCK_LOG"
rm -f "$WARDOS_PROVISIONED_MARKER"
out=$(printf 'ACCOUNT\nalice\nAda\tLovelace\npw\n' | wardos-provisiond)
[[ "$out" == ERR* ]] || fail "a full name containing a TAB must be denied; got: $out"
assert_not_logged '^useradd'
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "a rejected full name must not mark provisioned"

# A full name with a carriage return is denied.
: >"$MOCK_LOG"
out=$(printf 'ACCOUNT\nalice\nAda\rLovelace\npw\n' | wardos-provisiond)
[[ "$out" == ERR* ]] || fail "a full name containing a CR must be denied; got: $out"
assert_not_logged '^useradd'

# A full name with an embedded control byte (0x01) is denied.
: >"$MOCK_LOG"
out=$(printf 'ACCOUNT\nalice\nAda\x01Lovelace\npw\n' | wardos-provisiond)
[[ "$out" == ERR* ]] || fail "a full name containing a control byte must be denied; got: $out"
assert_not_logged '^useradd'

# A full name OVER the length cap (65 chars, cap is 64) is denied, and nothing is created.
: >"$MOCK_LOG"
long_name=$(printf 'A%.0s' {1..65})
out=$(printf 'ACCOUNT\nalice\n%s\npw\n' "$long_name" | wardos-provisiond)
[[ "$out" == ERR* ]] || fail "a full name over the length cap must be denied; got: $out"
assert_not_logged '^useradd'

# A valid full name UNDER the cap (63 chars, no control chars) is ACCEPTED: the account is
# created and the marker committed. This proves the tightened check did not reject legitimate
# names near the cap.
: >"$MOCK_LOG"
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_LOCK" "$WARDOS_PROVISION_JOURNAL"
mock id 'exit 1'
ok_name=$(printf 'A%.0s' {1..63})
out=$(printf 'ACCOUNT\nalice\n%s\npw\n' "$ok_name" | wardos-provisiond)
[[ "$out" == OK ]] || fail "a valid full name near the cap must be accepted; got: $out"
assert_logged "^useradd -m -c $ok_name -G wheel -s /bin/bash alice\$"
assert_file "$WARDOS_PROVISIONED_MARKER"

echo "ok   provisiond.test.sh internal assertions"
