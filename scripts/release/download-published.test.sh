#!/usr/bin/env bash
# Regressions for download-published.sh (issue #126): a failed READ of the
# existing release must never look like "no assets exist" and authorize a
# clobber. Enumeration or download failure fails closed (non-zero); only a
# release that genuinely lists no matching asset yields the "new, upload" path.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/download-published.sh"
check_assets="$RELEASE_DIR/check-assets.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

tarball="wardos-1.2.3-x86_64-linux.tar.gz"
checksum="$tarball.sha256"

# A fake `gh` whose two subcommands are steered by env vars, so enumeration and
# download failures can be simulated without a network:
#   FAKE_VIEW_RC       exit status of `gh release view` (default 0)
#   FAKE_ASSETS        newline-separated asset names it prints (default: none)
#   FAKE_DOWNLOAD_RC   exit status of `gh release download` (default 0)
#   FAKE_SRC           dir the "download" copies the requested asset out of
fake_gh() {
  local path="$work/gh"
  cat >"$path" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  "release view")
    printf '%s' "${FAKE_ASSETS:-}" | sed '/^$/d'
    exit "${FAKE_VIEW_RC:-0}"
    ;;
  "release download")
    dir="" ; pattern=""
    shift 2
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --dir) dir="$2"; shift 2 ;;
        --pattern) pattern="$2"; shift 2 ;;
        --clobber) shift ;;
        *) shift ;;
      esac
    done
    rc="${FAKE_DOWNLOAD_RC:-0}"
    if [[ "$rc" -eq 0 && -n "${FAKE_SRC:-}" && -e "$FAKE_SRC/$pattern" ]]; then
      cp "$FAKE_SRC/$pattern" "$dir/$pattern"
    fi
    exit "$rc"
    ;;
  *)
    echo "fake gh: unexpected: $*" >&2; exit 99 ;;
esac
EOF
  chmod +x "$path"
  printf '%s' "$path"
}
GH="$(fake_gh)"
export GH

# fresh_case NAME: a $work/NAME with {local,remote}, local holding both built
# artifacts and remote holding the published fixtures a download would pull.
fresh_case() {
  local dir="$work/$1"
  mkdir -p "$dir/local" "$dir/remote" "$dir/published"
  printf 'TARBALL-BYTES\n'  >"$dir/local/$tarball"
  printf 'CHECKSUM-BYTES\n' >"$dir/local/$checksum"
  cp "$dir/local/$tarball"  "$dir/remote/$tarball"
  cp "$dir/local/$checksum" "$dir/remote/$checksum"
  printf '%s' "$dir"
}

# --- Blocker 1 regressions: an unreadable existing release fails closed. -------

# Enumeration fails (auth/API/network): must exit non-zero, never fall through.
c="$(fresh_case enum-fail)"
expect_status 1 "enumeration failure fails closed" \
  env GH="$GH" FAKE_VIEW_RC=1 FAKE_ASSETS="$tarball
$checksum" FAKE_SRC="$c/remote" \
  bash "$sut" v1.2.3 "$c/local" "$c/published"

# A remote-listed asset whose download fails: must exit non-zero, not "new".
c="$(fresh_case download-fail)"
expect_status 1 "download failure of a listed asset fails closed" \
  env GH="$GH" FAKE_VIEW_RC=0 FAKE_ASSETS="$tarball
$checksum" FAKE_DOWNLOAD_RC=1 FAKE_SRC="$c/remote" \
  bash "$sut" v1.2.3 "$c/local" "$c/published"

# A listed asset that "succeeds" but never lands is treated as a failure, not new.
c="$(fresh_case silent-nodownload)"
expect_status 1 "listed asset that does not land fails closed" \
  env GH="$GH" FAKE_VIEW_RC=0 FAKE_ASSETS="$tarball
$checksum" FAKE_DOWNLOAD_RC=0 FAKE_SRC="$work/no-such-src" \
  bash "$sut" v1.2.3 "$c/local" "$c/published"

# The failure path must never reach check-assets' exit 10 (upload): a failed read
# stops at download-published, so the reconcile (download THEN compare) fails
# closed rather than authorizing a clobber.
reconcile() { # <local> <published> ; mirrors the workflow: download then compare
  bash "$sut" v1.2.3 "$1" "$2" || return $?
  bash "$check_assets" "$1" "$2"
}
c="$(fresh_case enum-fail-not-upload)"
export FAKE_VIEW_RC=1 FAKE_ASSETS="$tarball
$checksum" FAKE_SRC="$c/remote"
expect_status 1 "unreadable release never becomes an upload (exit 10)" \
  reconcile "$c/local" "$c/published"
unset FAKE_VIEW_RC FAKE_ASSETS FAKE_SRC

# --- Positive paths: the genuine states still work. ---------------------------

# Both assets published and downloadable: exit 0, published dir gets the bytes,
# and check-assets then sees a byte-identical no-op (exit 0).
c="$(fresh_case identical)"
export FAKE_VIEW_RC=0 FAKE_ASSETS="$tarball
$checksum" FAKE_SRC="$c/remote"
expect_status 0 "both assets enumerated and downloaded" \
  reconcile "$c/local" "$c/published"
unset FAKE_VIEW_RC FAKE_ASSETS FAKE_SRC

# Release genuinely has no matching asset: enumeration succeeds but is empty ->
# exit 0, published stays empty, and check-assets then signals upload (exit 10).
c="$(fresh_case genuinely-new)"
export FAKE_VIEW_RC=0 FAKE_ASSETS="" FAKE_SRC="$c/remote"
expect_status 10 "a release with no matching asset signals upload" \
  reconcile "$c/local" "$c/published"
unset FAKE_VIEW_RC FAKE_ASSETS FAKE_SRC

# The release manifest (generate-manifest.sh, issue #275) is pulled for
# comparison like a tarball: listed, it must download; its download failing
# fails closed.
manifest="wardos-1.2.3-manifest.json"
c="$(fresh_case manifest-published)"
printf '{"schema_version":1}\n' >"$c/local/$manifest"; cp "$c/local/$manifest" "$c/remote/$manifest"
printf 'MANIFEST-SUM\n' >"$c/local/$manifest.sha256"; cp "$c/local/$manifest.sha256" "$c/remote/$manifest.sha256"
export FAKE_VIEW_RC=0 FAKE_ASSETS="$tarball
$checksum
$manifest
$manifest.sha256" FAKE_SRC="$c/remote"
expect_status 0 "a published manifest and its sidecar are pulled and compare identical" \
  reconcile "$c/local" "$c/published"
[[ -e "$c/published/$manifest" && -e "$c/published/$manifest.sha256" ]] ||
  fail "manifest case: the published manifest and sidecar were not pulled for comparison"
unset FAKE_VIEW_RC FAKE_ASSETS FAKE_SRC
c="$(fresh_case manifest-download-fail)"
printf '{"schema_version":1}\n' >"$c/local/$manifest"; cp "$c/local/$manifest" "$c/remote/$manifest"
expect_status 1 "download failure of a listed manifest fails closed" \
  env GH="$GH" FAKE_VIEW_RC=0 FAKE_ASSETS="$manifest" FAKE_DOWNLOAD_RC=1 FAKE_SRC="$c/remote" \
  bash "$sut" v1.2.3 "$c/local" "$c/published"

# The manifest's Sigstore bundle (issue #148) is never pulled: a keyless
# signature differs on every run that signs, so there is nothing to compare,
# and check-assets then counts the local bundle as an upload (exit 10) over an
# otherwise identical set.
bundle="$manifest.sigstore.json"
c="$(fresh_case bundle-not-pulled)"
printf '{"schema_version":1}\n' >"$c/local/$manifest"; cp "$c/local/$manifest" "$c/remote/$manifest"
printf 'MANIFEST-SUM\n' >"$c/local/$manifest.sha256"; cp "$c/local/$manifest.sha256" "$c/remote/$manifest.sha256"
printf '{"rekor":"run-2"}\n' >"$c/local/$bundle"; printf '{"rekor":"run-1"}\n' >"$c/remote/$bundle"
export FAKE_VIEW_RC=0 FAKE_ASSETS="$tarball
$checksum
$manifest
$manifest.sha256
$bundle" FAKE_SRC="$c/remote"
expect_status 10 "a published bundle is not pulled and the re-signed one signals upload" \
  reconcile "$c/local" "$c/published"
[[ ! -e "$c/published/$bundle" ]] || fail "bundle case: the published bundle must not be downloaded for comparison"
[[ -e "$c/published/$manifest" ]] || fail "bundle case: the manifest itself must still be pulled"
unset FAKE_VIEW_RC FAKE_ASSETS FAKE_SRC

# Missing local dir is an error, not a silent empty pass.
expect_status 1 "missing local dir rejected" \
  env GH="$GH" FAKE_ASSETS="" bash "$sut" v1.2.3 "$work/does-not-exist" "$work/pub"

echo "PASS download-published.test.sh"
