#!/usr/bin/env bash
# wardos-dev-seed (ADR-0027 §Dev escape hatch, E7): the ONE development account mechanism.
# At first boot, on a dev-seed image (flag file present) that is still unprovisioned, it
# seeds the named account and marks the machine provisioned — but ONLY with a usable
# credential and ONLY for a valid, non-reserved, not-already-existing name. With no
# credential it mutates nothing and writes no marker (the machine falls back to canonical
# first-boot provisioning). The privileged tools (useradd/usermod/passwd/chpasswd/id and
# systemd-creds) are mocked and the flag/marker/credential paths are isolated in $TMP.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

# The script under test lives in the image rootfs, not desktop/bin.
seed="$test_root/image/rootfs/usr/libexec/wardos-dev-seed"
assert_file "$seed"

export WARDOS_DEV_SEED_FLAG="$TMP/dev-seed-user"
export WARDOS_PROVISIONED_MARKER="$TMP/provisioned"
# The seed's durable transaction journal (its own path, distinct from the broker's), isolated
# in $TMP so the transactional/reconcile regressions can drive it without touching real /var.
export WARDOS_DEV_SEED_JOURNAL="$TMP/dev-seed.journal"
export CREDENTIALS_DIRECTORY="$TMP/creds"
credfile="$CREDENTIALS_DIRECTORY/wardos-dev-seed.password"
mkdir -p "$CREDENTIALS_DIRECTORY"

# None of these should ever run except useradd/chpasswd on the happy path; mocking usermod
# and passwd lets the no-mutation cases PROVE the account is never locked or altered. userdel
# (rollback/reconcile) and sync (fsync_path in the durable writes) are mocked to succeed by
# default; the transactional regressions below override them to force failures deterministically.
for c in useradd usermod passwd chpasswd systemd-creds id userdel sync; do mock "$c"; done

# run_seed: run the script, capturing its exit status without tripping errexit.
run_seed() { rc=0; bash "$seed" || rc=$?; }

reset_state() {
  rm -f "$WARDOS_PROVISIONED_MARKER" "$credfile" "$WARDOS_DEV_SEED_JOURNAL"
  : >"$MOCK_LOG"
}

cred_on() { printf 'hunter2secret\n' >"$credfile"; }

# --- 1. Credential present → the dev account is created, usable, and provisioned. ---------
reset_state
printf 'devuser\n' >"$WARDOS_DEV_SEED_FLAG"
cred_on
mock id 'exit 1' # the seed user does not exist yet
run_seed
[[ $rc -eq 0 ]] || fail "credentialed seed should succeed; rc=$rc"
assert_logged '^useradd -m -c WardOS dev -G wheel -s /bin/bash devuser$'
assert_logged '^chpasswd'
assert_not_logged 'hunter2secret'          # password is fed on stdin, never an argument
assert_not_logged '^usermod'               # a usable account is never locked
assert_not_logged '^passwd'
assert_file "$WARDOS_PROVISIONED_MARKER"

# --- 2. Credential absent → NO locked user, NO marker; fall back to provisioning. ---------
# This is the core E7 fix: "no credential" must NOT yield "locked user + provisioned marker".
reset_state
printf 'devuser\n' >"$WARDOS_DEV_SEED_FLAG"
mock id 'exit 1'
run_seed
[[ $rc -eq 0 ]] || fail "no-credential seed should exit 0 (fall back), not error; rc=$rc"
assert_not_logged '^useradd'               # no account created
assert_not_logged '^usermod'               # no account locked
assert_not_logged '^passwd'                # no passwd -l
assert_not_logged '^chpasswd'
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "no credential must NOT write the provisioned marker"

# --- 3. Reserved seed name (root) → refused, nothing mutated, no marker. -------------------
# Even WITH a credential, a reserved name is refused before any mutation — never lock/alter
# root (or any reserved identity) and then mark provisioned.
reset_state
printf 'root\n' >"$WARDOS_DEV_SEED_FLAG"
cred_on
mock id 'echo 0' # root exists
run_seed
[[ $rc -ne 0 ]] || fail "a reserved seed name must be refused"
assert_not_logged '^useradd'
assert_not_logged '^usermod'
assert_not_logged '^passwd'
assert_not_logged '^chpasswd'
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "a reserved seed name must not mark provisioned"

# Every name on the broker's blocklist is refused (kept in lockstep with wardos-provisiond).
for reserved in daemon bin sys adm nobody nogroup greeter ward-provision; do
  reset_state
  printf '%s\n' "$reserved" >"$WARDOS_DEV_SEED_FLAG"
  cred_on
  mock id 'echo 1' # resolves to some existing account
  run_seed
  [[ $rc -ne 0 ]] || fail "reserved name '$reserved' must be refused"
  assert_not_logged '^useradd'
  [[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "reserved '$reserved' must not mark provisioned"
done

# --- 4. Already-existing seed name → refused (NO adoption), no marker. ---------------------
reset_state
printf 'existinguser\n' >"$WARDOS_DEV_SEED_FLAG"
cred_on
mock id 'echo 1000' # the name already resolves to an account
run_seed
[[ $rc -ne 0 ]] || fail "an existing seed name must be refused (no adoption)"
assert_not_logged '^useradd'
assert_not_logged '^usermod'               # never elevate/alter the existing account
assert_not_logged '^chpasswd'              # never reset an existing account's password
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "adopting an existing account must not happen, no marker"

# --- 4b. An invalid seed username is refused before any mutation. --------------------------
reset_state
printf 'Bad Name\n' >"$WARDOS_DEV_SEED_FLAG"
cred_on
mock id 'exit 1'
run_seed
[[ $rc -ne 0 ]] || fail "an invalid seed username must be refused"
assert_not_logged '^useradd'
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "an invalid seed username must not mark provisioned"

# --- 5. Reboot idempotency. ----------------------------------------------------------------
# 5a. Once provisioned (marker present), a re-run is an immediate no-op: no second account.
reset_state
printf 'devuser\n' >"$WARDOS_DEV_SEED_FLAG"
cred_on
mock id 'exit 1'
run_seed # first boot: seeds and marks provisioned
[[ $rc -eq 0 ]] || fail "first seed should succeed; rc=$rc"
assert_file "$WARDOS_PROVISIONED_MARKER"
: >"$MOCK_LOG"
run_seed # second boot: marker present → gated out at the top
[[ $rc -eq 0 ]] || fail "a re-run on a provisioned machine should be a clean no-op; rc=$rc"
assert_not_logged '^useradd'               # never double-create the account
assert_not_logged '^chpasswd'

# 5b. No-credential is idempotent too: running twice never mutates and never leaves a marker.
reset_state
printf 'devuser\n' >"$WARDOS_DEV_SEED_FLAG"
mock id 'exit 1'
run_seed
run_seed
assert_not_logged '^useradd'
assert_not_logged '^usermod'
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "repeated no-credential boots must stay unprovisioned"

# --- 6. Not a dev-seed image (no flag file) → nothing happens at all. -----------------------
reset_state
rm -f "$WARDOS_DEV_SEED_FLAG"
cred_on
mock id 'exit 1'
run_seed
[[ $rc -eq 0 ]] || fail "with no flag file the seed must be a clean no-op; rc=$rc"
assert_not_logged '^useradd'
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "no flag file must not mark provisioned"

# === Transactional discipline (#119 review): the seed establishes account + password + marker
# as ONE transaction, mirroring wardos-provisiond's ACCOUNT verb — durable journal before any
# mutation, checked rollback on any failure (including a failed rollback), and reconcile-on-entry
# of an interrupted prior attempt. Stateful account mocks share an on-disk account set so a
# userdel really removes (or, when forced to fail, really leaves) the account, and forced
# failures come from env/sentinels, never timing. ==============================================
acct_dir="$TMP/accounts"
seed_stateful_mocks() {
  rm -rf "$acct_dir"
  mkdir -p "$acct_dir"
  export ACCT_DIR="$acct_dir"
  # shellcheck disable=SC2016  # $ACCT_DIR/$@ expand in the mock at run time, not now
  mock useradd 'u="${@: -1}"; : >"$ACCT_DIR/$u"'
  # shellcheck disable=SC2016
  mock id 'for a in "$@"; do case "$a" in -*) ;; *) if [[ -e "$ACCT_DIR/$a" ]]; then echo 1000; exit 0; else exit 1; fi ;; esac; done; exit 1'
  # shellcheck disable=SC2016  # USERDEL_FAIL sentinel forces a rollback failure deterministically
  mock userdel '[[ -n "${USERDEL_FAIL:-}" ]] && exit 1; u="${@: -1}"; rm -f "$ACCT_DIR/$u"; exit 0'
  mock chpasswd
  mock sync 'exit 0'
}
acct_count() { find "$acct_dir" -maxdepth 1 -type f | wc -l; }

# --- T1. chpasswd fails → NO residual account, NO marker, journal reconcilable; next boot recovers.
seed_stateful_mocks
reset_state
printf 'devuser\n' >"$WARDOS_DEV_SEED_FLAG"
cred_on
mock chpasswd 'exit 1' # the password cannot be set → the transaction must roll back
run_seed
[[ $rc -ne 0 ]] || fail "a chpasswd failure must fail the seed"
assert_logged '^useradd -m -c WardOS dev -G wheel -s /bin/bash devuser$'
assert_logged '^userdel -r devuser$'                 # the freshly created account is rolled back
[[ "$(acct_count)" -eq 0 ]] || fail "a chpasswd failure must leave NO residual account: $(ls "$acct_dir")"
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "a chpasswd failure must not mark provisioned"
[[ ! -e "$WARDOS_DEV_SEED_JOURNAL" ]] || fail "a succeeded rollback clears the journal (clean state)"
# Simulated next boot: chpasswd works now → a clean seed with exactly one admin.
mock chpasswd
: >"$MOCK_LOG"
run_seed
[[ $rc -eq 0 ]] || fail "the next boot must seed cleanly after a rolled-back chpasswd failure; rc=$rc"
[[ "$(acct_count)" -eq 1 ]] || fail "recovery must yield exactly one admin: $(ls "$acct_dir")"
assert_file "$WARDOS_PROVISIONED_MARKER"
[[ ! -e "$WARDOS_DEV_SEED_JOURNAL" ]] || fail "a committed seed clears the journal"

# --- T2. Marker creation fails (mkdir / temp file) → account rolled back, no marker. ----------
# Point the marker under a regular file so its parent directory cannot be created: the marker
# never lands, so this is a true commit failure and the freshly created account is rolled back.
seed_stateful_mocks
reset_state
printf 'devuser\n' >"$WARDOS_DEV_SEED_FLAG"
cred_on
: >"$TMP/blocker"
rc=0
WARDOS_PROVISIONED_MARKER="$TMP/blocker/nope/provisioned" bash "$seed" || rc=$?
[[ $rc -ne 0 ]] || fail "a marker-creation failure must fail the seed"
assert_logged '^useradd -m -c WardOS dev -G wheel -s /bin/bash devuser$'
assert_logged '^userdel -r devuser$'
[[ "$(acct_count)" -eq 0 ]] || fail "a marker-creation failure must roll the account back: $(ls "$acct_dir")"
[[ ! -e "$TMP/blocker/nope/provisioned" ]] || fail "no marker after a marker-creation failure"
[[ ! -e "$WARDOS_DEV_SEED_JOURNAL" ]] || fail "a succeeded rollback clears the journal"
rm -f "$TMP/blocker"

# --- T3. Marker RENAME fails → account rolled back, no marker. --------------------------------
# The marker temp is written and fsynced, but the atomic rename into place fails: still a commit
# failure (the marker never lands), so the account is rolled back. Mock mv to fail ONLY for the
# marker destination; for every other path (the journal) it performs a real file move so the
# transaction reaches the marker step.
seed_stateful_mocks
reset_state
printf 'devuser\n' >"$WARDOS_DEV_SEED_FLAG"
cred_on
# shellcheck disable=SC2016  # $WARDOS_PROVISIONED_MARKER / positional args expand in the mock
mock mv 'dst="${@: -1}"; src="${@: -2:1}"; if [[ "$dst" == "$WARDOS_PROVISIONED_MARKER" ]]; then exit 1; fi; cat "$src" >"$dst" && rm -f "$src"'
run_seed
[[ $rc -ne 0 ]] || fail "a marker-rename failure must fail the seed"
assert_logged '^userdel -r devuser$'
[[ "$(acct_count)" -eq 0 ]] || fail "a marker-rename failure must roll the account back: $(ls "$acct_dir")"
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "no marker after a failed rename"
[[ ! -e "$WARDOS_DEV_SEED_JOURNAL" ]] || fail "a succeeded rollback clears the journal"
rm -f "$MOCK_DIR/mv" # restore the real mv for the remaining tests

# --- T4. Rollback (userdel) ITSELF fails → journal kept, seed refuses; a later boot with userdel
#         working reconciles (removes the orphan) BEFORE re-seeding → proves NO second admin. ---
seed_stateful_mocks
reset_state
printf 'devuser\n' >"$WARDOS_DEV_SEED_FLAG"
cred_on
mock chpasswd 'exit 1'          # force a mid-transaction failure so rollback runs
rc=0
USERDEL_FAIL=1 bash "$seed" || rc=$? # …and the rollback userdel fails too
[[ $rc -ne 0 ]] || fail "a failed rollback must make the seed refuse (recovery required)"
[[ -e "$acct_dir/devuser" ]] || fail "a failed userdel leaves the account (stateful mock)"
[[ -e "$WARDOS_DEV_SEED_JOURNAL" ]] || fail "a failed rollback KEEPS the journal for reconcile"
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "an unresolved transaction must not mark provisioned"
# A later boot: userdel works and the password applies. reconcile_pending removes the orphan
# BEFORE creating anything, then the seed proceeds — exactly ONE administrator results.
mock chpasswd
: >"$MOCK_LOG"
run_seed # USERDEL_FAIL unset → userdel succeeds
[[ $rc -eq 0 ]] || fail "recovery must seed once the orphan can be removed; rc=$rc"
assert_logged '^userdel -r devuser$'                 # the orphan was reconciled away first
[[ -e "$acct_dir/devuser" ]] || fail "the admin exists after recovery"
[[ "$(acct_count)" -eq 1 ]] || fail "recovery must NOT yield a second admin: $(ls "$acct_dir")"
assert_file "$WARDOS_PROVISIONED_MARKER"
[[ ! -e "$WARDOS_DEV_SEED_JOURNAL" ]] || fail "the journal is cleared after a committed recovery"

# --- T5. Interruption between each mutation → the next boot reconciles to a single-admin
#         provisioned OR a cleanly-unprovisioned state, NEVER two usable admins. ---------------

# T5a. journal-but-no-account (crashed after the journal write, before useradd). Next boot:
# reconcile finds no orphan, clears the journal, and the seed proceeds cleanly.
seed_stateful_mocks
reset_state
printf 'devuser\n' >"$WARDOS_DEV_SEED_FLAG"
cred_on
printf 'devuser\n' >"$WARDOS_DEV_SEED_JOURNAL" # a durable record, but useradd never ran
run_seed
[[ $rc -eq 0 ]] || fail "T5a: a journal with no account must reconcile and seed cleanly; rc=$rc"
[[ "$(acct_count)" -eq 1 ]] || fail "T5a: exactly one admin after reconcile: $(ls "$acct_dir")"
assert_file "$WARDOS_PROVISIONED_MARKER"
[[ ! -e "$WARDOS_DEV_SEED_JOURNAL" ]] || fail "T5a: the journal is cleared after committing"

# T5b. account-but-no-password (crashed after useradd, before chpasswd). Next boot: reconcile
# removes the orphan the journal names, then the seed re-creates it — exactly one admin.
seed_stateful_mocks
reset_state
printf 'devuser\n' >"$WARDOS_DEV_SEED_FLAG"
cred_on
printf 'devuser\n' >"$WARDOS_DEV_SEED_JOURNAL"
: >"$acct_dir/devuser"                        # the orphan the interrupted useradd left
run_seed
[[ $rc -eq 0 ]] || fail "T5b: an orphan account must be reconciled and re-seeded; rc=$rc"
assert_logged '^userdel -r devuser$'          # the orphan is removed before re-creating
[[ "$(acct_count)" -eq 1 ]] || fail "T5b: must not accumulate admins: $(ls "$acct_dir")"
assert_file "$WARDOS_PROVISIONED_MARKER"
[[ ! -e "$WARDOS_DEV_SEED_JOURNAL" ]] || fail "T5b: the journal is cleared after committing"

# T5c. account+password-but-no-marker (crashed after chpasswd, before the marker). On this boot
# the credential is GONE: reconcile still removes the orphan, then the no-credential fall-back
# leaves the machine cleanly UNPROVISIONED — no account, no marker, never a second admin.
seed_stateful_mocks
reset_state
printf 'devuser\n' >"$WARDOS_DEV_SEED_FLAG"
# no cred_on → the credential is absent on this boot
printf 'devuser\n' >"$WARDOS_DEV_SEED_JOURNAL"
: >"$acct_dir/devuser"                        # orphan with a password set, but no marker committed
run_seed
[[ $rc -eq 0 ]] || fail "T5c: a no-credential recovery boot must fall back cleanly; rc=$rc"
assert_logged '^userdel -r devuser$'          # the orphan is reconciled away first
[[ "$(acct_count)" -eq 0 ]] || fail "T5c: the orphan must be removed, leaving no admin: $(ls "$acct_dir")"
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "T5c: no credential must leave the machine unprovisioned"
[[ ! -e "$WARDOS_DEV_SEED_JOURNAL" ]] || fail "T5c: reconcile clears the journal even on the fall-back path"

echo "ok   dev-seed.test.sh internal assertions"
