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
export CREDENTIALS_DIRECTORY="$TMP/creds"
credfile="$CREDENTIALS_DIRECTORY/wardos-dev-seed.password"
mkdir -p "$CREDENTIALS_DIRECTORY"

# None of these should ever run except useradd/chpasswd on the happy path; mocking usermod
# and passwd lets the no-mutation cases PROVE the account is never locked or altered.
for c in useradd usermod passwd chpasswd systemd-creds id; do mock "$c"; done

# run_seed: run the script, capturing its exit status without tripping errexit.
run_seed() { rc=0; bash "$seed" || rc=$?; }

reset_state() {
  rm -f "$WARDOS_PROVISIONED_MARKER" "$credfile"
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

echo "ok   dev-seed.test.sh internal assertions"
