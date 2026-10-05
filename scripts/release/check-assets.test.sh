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

# The manifest's Sigstore bundle (issue #148) is never byte-compared: a keyless
# signature differs on every run that signs. A local bundle counts as "to
# upload" whenever its manifest is identical or new -- so a retry that re-signs
# an otherwise identical set exits 10, not 0 -- and a published bundle that
# differs is not a conflict; but a manifest whose bytes differ refuses the run,
# bundle included, and a bundle without its manifest beside it is an error. A
# published bundle with no local counterpart (a run that did not sign) is left
# alone like any other asset the run is not replacing.
bundle="$manifest.sigstore.json"
identical_set() { # DIR -> tarball, checksum, manifest and sidecar, all published byte-identical
  printf 'BYTES\n' >"$1/local/$tarball";  cp "$1/local/$tarball"  "$1/published/$tarball"
  printf 'SUM\n'   >"$1/local/$checksum"; cp "$1/local/$checksum" "$1/published/$checksum"
  printf '{"a":1}\n' >"$1/local/$manifest"; cp "$1/local/$manifest" "$1/published/$manifest"
  printf 'MSUM\n' >"$1/local/$manifest.sha256"; cp "$1/local/$manifest.sha256" "$1/published/$manifest.sha256"
}
c="$(fresh_case bundle-resigned-identical)"
identical_set "$c"
printf '{"rekor":"run-2"}\n' >"$c/local/$bundle"
expect_status 10 "a re-signed bundle over an identical set signals upload" bash "$sut" "$c/local" "$c/published"
c="$(fresh_case bundle-differs-from-published)"
identical_set "$c"
printf '{"rekor":"run-2"}\n' >"$c/local/$bundle"; printf '{"rekor":"run-1"}\n' >"$c/published/$bundle"
expect_status 10 "a published bundle with different bytes is not a conflict" bash "$sut" "$c/local" "$c/published"
out="$(bash "$sut" "$c/local" "$c/published" 2>&1 || true)"
grep -q "never byte-compared" <<<"$out" ||
  fail "bundle-differs: the output should say the bundle is never byte-compared"
c="$(fresh_case bundle-with-new-manifest)"
printf 'BYTES\n' >"$c/local/$tarball";  cp "$c/local/$tarball"  "$c/published/$tarball"
printf '{"a":1}\n' >"$c/local/$manifest"; printf 'MSUM\n' >"$c/local/$manifest.sha256"
printf '{"rekor":"run-1"}\n' >"$c/local/$bundle"
expect_status 10 "a bundle with a not-yet-published manifest signals upload" bash "$sut" "$c/local" "$c/published"
c="$(fresh_case bundle-with-conflicting-manifest)"
identical_set "$c"
printf '{"a":2}\n' >"$c/published/$manifest"
printf '{"rekor":"run-2"}\n' >"$c/local/$bundle"
expect_status 1 "a bundle whose manifest conflicts is refused with it" bash "$sut" "$c/local" "$c/published"
c="$(fresh_case bundle-without-manifest)"
printf 'BYTES\n' >"$c/local/$tarball"; printf 'SUM\n' >"$c/local/$checksum"
printf '{"rekor":"run-1"}\n' >"$c/local/$bundle"
expect_status 1 "a bundle without its manifest beside it is an error" bash "$sut" "$c/local" "$c/published"
c="$(fresh_case published-bundle-not-resigned)"
identical_set "$c"
printf '{"rekor":"run-1"}\n' >"$c/published/$bundle"
expect_status 0 "a published bundle is left alone when this run did not sign" bash "$sut" "$c/local" "$c/published"

# Guardrails: empty local dir and missing dirs are errors, not silent passes.
c="$(fresh_case empty)"
expect_status 1 "empty local dir rejected" bash "$sut" "$c/local" "$c/published"
expect_status 1 "missing published dir rejected" bash "$sut" "$c/local" "$work/does-not-exist"

echo "PASS check-assets.test.sh"
