#!/usr/bin/env bash
# Regressions for check-assets.sh (issue #126): an idempotent retry accepts
# byte-identical published assets (no-op) and refuses to clobber differing bytes.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/check-assets.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# fresh_case NAME -> makes $work/NAME/{local,published} and echoes the case dir.
fresh_case() {
  local dir="$work/$1"
  mkdir -p "$dir/local" "$dir/published"
  printf '%s' "$dir"
}

tarball="wardos-1.2.3-x86_64-linux.tar.gz"
checksum="$tarball.sha256"

# Identical retry: both artifacts published byte-identical -> exit 0 (skip upload).
c="$(fresh_case identical)"
printf 'BINARY-BYTES\n' >"$c/local/$tarball";  cp "$c/local/$tarball"  "$c/published/$tarball"
printf 'CHECKSUM\n'      >"$c/local/$checksum"; cp "$c/local/$checksum" "$c/published/$checksum"
expect_status 0 "identical retry is a no-op" bash "$sut" "$c/local" "$c/published"

# Conflicting retry: the published tarball differs in bytes -> exit 1 (refuse).
c="$(fresh_case conflict-tarball)"
printf 'REBUILT-BYTES\n' >"$c/local/$tarball";  printf 'OLD-BYTES\n' >"$c/published/$tarball"
printf 'CHECKSUM\n'       >"$c/local/$checksum"; cp "$c/local/$checksum" "$c/published/$checksum"
expect_status 1 "conflicting tarball rejected before upload" bash "$sut" "$c/local" "$c/published"

# Conflicting checksum only: still refused (the .sha256 asset is compared too).
c="$(fresh_case conflict-checksum)"
printf 'BYTES\n' >"$c/local/$tarball";  cp "$c/local/$tarball" "$c/published/$tarball"
printf 'NEW-SUM\n' >"$c/local/$checksum"; printf 'OLD-SUM\n' >"$c/published/$checksum"
expect_status 1 "conflicting checksum rejected" bash "$sut" "$c/local" "$c/published"

# Brand-new: nothing published yet -> exit 10 (caller uploads).
c="$(fresh_case new)"
printf 'BYTES\n' >"$c/local/$tarball"; printf 'SUM\n' >"$c/local/$checksum"
expect_status 10 "unpublished assets signal upload" bash "$sut" "$c/local" "$c/published"

# Partial: one artifact identical, its checksum not yet published -> exit 10.
c="$(fresh_case partial)"
printf 'BYTES\n' >"$c/local/$tarball"; cp "$c/local/$tarball" "$c/published/$tarball"
printf 'SUM\n'   >"$c/local/$checksum"
expect_status 10 "partial publish signals upload of the rest" bash "$sut" "$c/local" "$c/published"

# Unrelated published assets (a second arch, a disk image) are left untouched:
# only the artifacts this run rebuilt are compared.
c="$(fresh_case unrelated)"
printf 'BYTES\n' >"$c/local/$tarball"; cp "$c/local/$tarball" "$c/published/$tarball"
printf 'SUM\n'   >"$c/local/$checksum"; cp "$c/local/$checksum" "$c/published/$checksum"
printf 'AARCH\n' >"$c/published/wardos-1.2.3-aarch64-linux.tar.gz"
expect_status 0 "unrelated published assets ignored" bash "$sut" "$c/local" "$c/published"

# The release manifest and its sidecar (generate-manifest.sh, issue #275) are
# reconciled like the tarballs: a published manifest that differs is refused,
# one not yet published signals an upload, an identical one is a no-op.
manifest="wardos-1.2.3-manifest.json"
c="$(fresh_case manifest-conflict)"
printf 'BYTES\n' >"$c/local/$tarball";  cp "$c/local/$tarball"  "$c/published/$tarball"
printf 'SUM\n'   >"$c/local/$checksum"; cp "$c/local/$checksum" "$c/published/$checksum"
printf '{"a":1}\n' >"$c/local/$manifest"; printf '{"a":2}\n' >"$c/published/$manifest"
expect_status 1 "conflicting manifest rejected before upload" bash "$sut" "$c/local" "$c/published"
c="$(fresh_case manifest-sidecar-conflict)"
printf 'BYTES\n' >"$c/local/$tarball";  cp "$c/local/$tarball"  "$c/published/$tarball"
printf '{"a":1}\n' >"$c/local/$manifest"; cp "$c/local/$manifest" "$c/published/$manifest"
printf 'NEW\n' >"$c/local/$manifest.sha256"; printf 'OLD\n' >"$c/published/$manifest.sha256"
expect_status 1 "conflicting manifest checksum rejected" bash "$sut" "$c/local" "$c/published"
c="$(fresh_case manifest-new)"
printf 'BYTES\n' >"$c/local/$tarball";  cp "$c/local/$tarball"  "$c/published/$tarball"
printf '{"a":1}\n' >"$c/local/$manifest"; printf 'SUM\n' >"$c/local/$manifest.sha256"
expect_status 10 "an unpublished manifest signals upload" bash "$sut" "$c/local" "$c/published"
c="$(fresh_case manifest-identical)"
printf 'BYTES\n' >"$c/local/$tarball";  cp "$c/local/$tarball"  "$c/published/$tarball"
printf '{"a":1}\n' >"$c/local/$manifest"; cp "$c/local/$manifest" "$c/published/$manifest"
printf 'SUM\n' >"$c/local/$manifest.sha256"; cp "$c/local/$manifest.sha256" "$c/published/$manifest.sha256"
expect_status 0 "an identical published manifest is a no-op" bash "$sut" "$c/local" "$c/published"

# Guardrails: empty local dir and missing dirs are errors, not silent passes.
c="$(fresh_case empty)"
expect_status 1 "empty local dir rejected" bash "$sut" "$c/local" "$c/published"
expect_status 1 "missing published dir rejected" bash "$sut" "$c/local" "$work/does-not-exist"

echo "PASS check-assets.test.sh"
