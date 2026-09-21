#!/usr/bin/env bash
# E8 disk-dev integration (ADR-0027): prove the supported dev-account path cannot yield the
# "pre-created wheel user + unprovisioned marker" hazard. There is ONE dev escape hatch — the
# WARDOS_DEV_SEED_USER build-arg, which wardos-dev-seed turns into (account + provisioned
# marker) TOGETHER at first boot — and image/disk.sh no longer creates any first user, so a
# disk can never establish a wheel account without the marker. A true end-to-end bootc build
# cannot run in CI (it needs privileged podman + bootc-image-builder and never boots the
# compositor), so this asserts the WIRING and dry-run config generation instead; the real
# first-boot behaviour is covered by dev-seed.test.sh, and hardware boot is the final gate.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

disk_sh="$test_root/image/disk.sh"
build_sh="$test_root/image/build.sh"
disk_yml="$test_root/.github/workflows/disk.yml"
release_yml="$test_root/.github/workflows/release.yml"
for f in "$disk_sh" "$build_sh" "$disk_yml" "$release_yml"; do assert_file "$f"; done

# A pinned image name so disk.sh never needs `git describe`, and an isolated output dir.
img="localhost/wardos:test"
out="$TMP/out"

# run_cmd: run a command, capture combined output in $OUT and status in $rc (errexit off
# around the capture so a non-zero exit — an intended rejection — does not abort the test).
run_cmd() {
  set +e
  OUT=$("$@" 2>&1)
  rc=$?
  set -e
}

# --- 1. disk.sh generates NO account-creation config on any type. --------------------------
# qcow2 (no --luks): no config is generated at all, so certainly no user.
run_cmd bash "$disk_sh" --type qcow2 --image "$img" --output "$out" --dry-run
[[ $rc -eq 0 ]] || fail "qcow2 dry-run should succeed; rc=$rc; out: $OUT"
grep -qi 'customizations.user' <<<"$OUT" && fail "qcow2 disk.sh must not create a user"
grep -qE '^\s*user --name' <<<"$OUT" && fail "qcow2 disk.sh must not emit a kickstart user line"

# iso --luks: a kickstart IS generated (full-disk encryption), but it locks root and creates
# NO user — the disk boots unprovisioned and provisioning creates the first user.
run_cmd bash "$disk_sh" --type iso --luks --image "$img" --output "$out" --dry-run
[[ $rc -eq 0 ]] || fail "iso --luks dry-run should succeed; rc=$rc; out: $OUT"
grep -q 'rootpw --lock' <<<"$OUT" || fail "the LUKS kickstart must lock root"
grep -qi 'customizations.user' <<<"$OUT" && fail "the LUKS kickstart must not create a user"
grep -qE 'user --name' <<<"$OUT" && fail "the LUKS kickstart must not emit a user line"
# The generated config carries no marker coupling because it carries no account: there is no
# way for disk.sh to produce "account present, marker absent".
true

# --- 2. disk.sh REJECTS the removed --user/--password/--ssh-key flags. ---------------------
for flag in --user --password --ssh-key; do
  run_cmd bash "$disk_sh" --type qcow2 --image "$img" "$flag" x --dry-run
  [[ $rc -ne 0 ]] || fail "disk.sh must reject the removed $flag flag"
  grep -q 'first boot' <<<"$OUT" || fail "disk.sh $flag rejection should point at first-boot provisioning"
done

# --- 3. build.sh routes --dev-seed-user to the WARDOS_DEV_SEED_USER build-arg. -------------
run_cmd bash "$build_sh" --source checkout --dev-seed-user devx --dry-run
[[ $rc -eq 0 ]] || fail "build.sh --dev-seed-user dry-run should succeed; rc=$rc; out: $OUT"
grep -q 'build-arg WARDOS_DEV_SEED_USER=devx' <<<"$OUT" ||
  fail "build.sh must pass --build-arg WARDOS_DEV_SEED_USER; out: $OUT"
# A reserved / invalid seed name is refused at build time.
run_cmd bash "$build_sh" --dev-seed-user root --dry-run
[[ $rc -ne 0 ]] || fail "build.sh must refuse a reserved --dev-seed-user"
run_cmd bash "$build_sh" --dev-seed-user 'Bad Name' --dry-run
[[ $rc -ne 0 ]] || fail "build.sh must refuse an invalid --dev-seed-user"

# --- 4. disk.yml never passes --user to disk.sh; the dev account goes through the build-arg.
# Inspect the actual disk.sh invocation lines (ignore comments), so a re-added --user is caught.
disk_calls=$(grep -E '\./image/disk\.sh' "$disk_yml" || true)
[[ -n "$disk_calls" ]] || fail "expected disk.sh invocations in disk.yml"
grep -qE '\-\-user' <<<"$disk_calls" && fail "disk.yml must not pass --user to disk.sh (ADR-0027)"
# The build step wires the dev account to the build-arg instead.
grep -qE '\-\-dev-seed-user' "$disk_yml" || fail "disk.yml must route the dev account to build.sh --dev-seed-user"
# And it never bakes a password into the disk anymore (delivered at boot as a credential).
grep -qE 'WARDOS_PASSWORD' "$disk_yml" && fail "disk.yml must not bake a build-time password"

# --- 5. release.yml still dispatches an UNPROVISIONED disk (no user), via the guard. -------
# Inspect only non-comment lines (a comment like "No -f user=... here" must not trip this).
release_code=$(grep -vE '^[[:space:]]*#' "$release_yml" || true)
grep -qE '\-f +user=' <<<"$release_code" && fail "release.yml must not dispatch a non-blank user (unprovisioned release disks)"
grep -q 'guard-release-dispatch' <<<"$release_code" || fail "release.yml must still run guard-release-dispatch"

echo "ok   disk-dev.test.sh internal assertions"
