#!/usr/bin/env bash
# Regressions for install.sh's verification of a downloaded release (ADR-0028 §5,
# issue #148), against a fake `curl` serving a fixture release and the fake
# `cosign` of verify-manifest.test.sh: a signed release installs as
# provenance-verified; a host without cosign, a verifier that cannot be fetched,
# a stale trusted root and a release without a manifest or bundle install
# checksum-only, loudly, and are refused under --require-provenance; a wrong
# identity or issuer, altered manifest bytes, a tarball that disagrees with the
# manifest or with its sidecar, and another release's manifest install nothing,
# each under its own exit code. The pre-existing behaviour -- no tarball for this
# architecture, the flags, a local install from an unpacked tarball -- holds.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

repo="$(cd "$RELEASE_DIR/../.." && pwd)"
sut="$repo/install.sh"
generate="$RELEASE_DIR/generate-manifest.sh"
verifier="$RELEASE_DIR/verify-manifest.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

arch="$(uname -m)"
tag="v1.2.3"
version="1.2.3"
commit="0123456789abcdef0123456789abcdef01234567"
pinned_issuer="https://token.actions.githubusercontent.com"
identity_for() { printf 'https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/tags/%s' "$1"; }
tarball="wardos-${version}-${arch}-linux.tar.gz"
manifest="wardos-${version}-manifest.json"

mkdir -p "$work/bin"

# The fake cosign of verify-manifest.test.sh: `cosign verify-blob --bundle` over a
# certificate whose claims the test chooses (FAKE_COSIGN_IDENTITY, _ISSUER,
# _BLOB_SHA256, _MODE=tuf-fail, _LOG).
cat >"$work/bin/cosign" <<'COSIGN'
#!/usr/bin/env bash
set -euo pipefail
[[ -n "${FAKE_COSIGN_LOG:-}" ]] && printf '%s\n' "$*" >>"$FAKE_COSIGN_LOG"
[[ "${1:-}" == "verify-blob" ]] || { echo "fake cosign: unexpected subcommand $*" >&2; exit 99; }
shift
bundle=""; identity=""; identity_re=""; issuer=""; issuer_re=""; blob=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle) bundle="$2"; shift 2 ;;
    --certificate-identity) identity="$2"; shift 2 ;;
    --certificate-identity-regexp) identity_re="$2"; shift 2 ;;
    --certificate-oidc-issuer) issuer="$2"; shift 2 ;;
    --certificate-oidc-issuer-regexp) issuer_re="$2"; shift 2 ;;
    --trusted-root) shift 2 ;;
    -*) echo "fake cosign: unexpected flag $1" >&2; exit 99 ;;
    *) blob="$1"; shift ;;
  esac
done
if [[ "${FAKE_COSIGN_MODE:-}" == "tuf-fail" ]]; then
  echo "Error: getting trusted root: updating TUF metadata: no cached root" >&2
  exit 1
fi
[[ -f "$bundle" ]] || { echo "Error: bundle not found" >&2; exit 1; }
actual="$(sha256sum "$blob" | awk '{print $1}')"
[[ "$actual" == "${FAKE_COSIGN_BLOB_SHA256:-}" ]] || { echo "Error: verifying blob: invalid signature" >&2; exit 1; }
cert_identity="${FAKE_COSIGN_IDENTITY:-}"
cert_issuer="${FAKE_COSIGN_ISSUER:-}"
if [[ -n "$identity" ]]; then
  [[ "$identity" == "$cert_identity" ]] || { echo "Error: none of the expected identities matched" >&2; exit 1; }
elif [[ -n "$identity_re" ]]; then
  [[ "$cert_identity" =~ $identity_re ]] || { echo "Error: none of the expected identities matched" >&2; exit 1; }
else
  echo "Error: --certificate-identity or --certificate-identity-regexp required" >&2; exit 1
fi
if [[ -n "$issuer" ]]; then
  [[ "$issuer" == "$cert_issuer" ]] || { echo "Error: expected oidc issuer not found" >&2; exit 1; }
elif [[ -n "$issuer_re" ]]; then
  [[ "$cert_issuer" =~ $issuer_re ]] || { echo "Error: expected oidc issuer not found" >&2; exit 1; }
else
  echo "Error: --certificate-oidc-issuer or --certificate-oidc-issuer-regexp required" >&2; exit 1
fi
echo "Verified OK"
COSIGN

# A fake curl serving one release out of $FAKE_CURL_ROOT, the way install.sh
# talks to GitHub: the release JSON for /releases/latest and /releases/tags/<tag>,
# an asset's bytes for /releases/assets/<id> (by-id/<id> in the root), and the
# verifier for raw.githubusercontent.com/<repo>/<tag>/scripts/release/verify-manifest.sh
# or, with a token, the contents API's ?ref=<tag> (both from verifier-at/<tag>).
# -f semantics: a file the root lacks is exit 22, the way a 404 is.
cat >"$work/bin/curl" <<'CURL'
#!/usr/bin/env bash
set -euo pipefail
[[ -n "${FAKE_CURL_LOG:-}" ]] && printf '%s\n' "$*" >>"$FAKE_CURL_LOG"
out=""; url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|-H) [[ "$1" == -o ]] && out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  https://api.github.com/repos/hexrift/WardOS/releases/latest) file="$FAKE_CURL_ROOT/release.json" ;;
  https://api.github.com/repos/hexrift/WardOS/releases/tags/*) file="$FAKE_CURL_ROOT/tags/${url##*/}" ;;
  https://api.github.com/repos/hexrift/WardOS/releases/assets/*) file="$FAKE_CURL_ROOT/by-id/${url##*/}" ;;
  https://raw.githubusercontent.com/hexrift/WardOS/*/scripts/release/verify-manifest.sh)
    ref="${url#https://raw.githubusercontent.com/hexrift/WardOS/}"
    file="$FAKE_CURL_ROOT/verifier-at/${ref%%/*}" ;;
  "https://api.github.com/repos/hexrift/WardOS/contents/scripts/release/verify-manifest.sh?ref="*)
    file="$FAKE_CURL_ROOT/verifier-at/${url##*=}" ;;
  *) echo "fake curl: unexpected url $url" >&2; exit 99 ;;
esac
[[ -f "$file" ]] || { echo "fake curl: 404 $url" >&2; exit 22; }
if [[ -n "$out" ]]; then cp "$file" "$out"; else cat "$file"; fi
CURL
chmod +x "$work/bin/cosign" "$work/bin/curl"
export PATH="$work/bin:$PATH"

# fresh_release NAME -> $work/NAME: a fixture release for this machine's arch.
# assets/ holds what the release attaches (the runtime tarball with its
# sidecar, the manifest generate-manifest.sh produces for it, the manifest's
# sidecar and a fake bundle); the verifier is served at the release tag. Edit
# assets/, then `publish` writes the release JSON and the by-id table.
fresh_release() {
  local dir="$work/$1" stage
  mkdir -p "$dir/assets" "$dir/verifier-at" "$dir/tags"
  stage="$dir/stage/wardos-${version}-${arch}-linux"
  mkdir -p "$stage"
  local bin
  for bin in ward wardd ward-agent; do
    # shellcheck disable=SC2016  # $1 is the fixture binary's own argument
    printf '#!/bin/sh\n[ "$1" != doctor ] || echo "doctor: fixture ok"\necho %s %s\n' "$bin" "$version" >"$stage/$bin"
    chmod +x "$stage/$bin"
  done
  tar -C "$dir/stage" -czf "$dir/assets/$tarball" "wardos-${version}-${arch}-linux"
  (cd "$dir/assets" && sha256sum "$tarball" >"$tarball.sha256")
  GENERATE_MANIFEST_NOW=2026-01-01T00:00:00Z bash "$generate" "$tag" "$commit" "$dir/assets" >"$dir/assets/$manifest"
  (cd "$dir/assets" && sha256sum "$manifest" >"$manifest.sha256")
  printf '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n' >"$dir/assets/$manifest.sigstore.json"
  cp "$verifier" "$dir/verifier-at/$tag"
  publish "$dir"
  printf '%s' "$dir"
}
# publish DIR -> DIR/release.json names every file in DIR/assets, with the API
# asset url install.sh fetches by; the same JSON answers /releases/tags/<tag>.
publish() {
  local dir="$1" id=0 f entries=""
  rm -rf "$dir/by-id" && mkdir -p "$dir/by-id"
  for f in "$dir"/assets/*; do
    id=$((id + 1))
    ln -s "$f" "$dir/by-id/$id"
    entries+="$(printf '    {\n      "url": "https://api.github.com/repos/hexrift/WardOS/releases/assets/%s",\n      "name": "%s",\n      "state": "uploaded"\n    },\n' "$id" "$(basename "$f")")"$'\n'
  done
  printf '{\n  "tag_name": "%s",\n  "name": "%s",\n  "assets": [\n%s  ]\n}\n' "$tag" "$tag" "${entries%,*}"$'\n' >"$dir/release.json"
  cp "$dir/release.json" "$dir/tags/$tag"
}
manifest_of() { printf '%s/assets/%s' "$1" "$manifest"; }
signed_digest() { sha256sum "$(manifest_of "$1")" 2>/dev/null | awk '{print $1}'; }
# resign DIR: after editing the manifest, its sidecar follows (the signed-digest
# the fake cosign expects is read fresh by run_sut).
resign() { (cd "$1/assets" && sha256sum "$manifest" >"$manifest.sha256"); }

# run_sut RELEASE ARGS... -> install.sh against that release with the fake
# cosign presenting the pinned claims unless overridden, into a fresh prefix,
# with no GitHub token unless the case sets SUT_TOKEN (the host's is
# hidden so the public download path is what runs); stdout+stderr land in $out,
# the status in $rc, the prefix in $prefix.
out=""
rc=0
prefix=""
run_sut() {
  local dir="$1"
  shift
  prefix="$(mktemp -d "$work/prefix.XXXXXX")"
  rc=0
  out="$(
    GITHUB_TOKEN="${SUT_TOKEN:-}" GH_TOKEN='' FAKE_CURL_ROOT="$dir" \
      FAKE_COSIGN_IDENTITY="${FAKE_COSIGN_IDENTITY:-$(identity_for "$tag")}" \
      FAKE_COSIGN_ISSUER="${FAKE_COSIGN_ISSUER:-$pinned_issuer}" \
      FAKE_COSIGN_BLOB_SHA256="${FAKE_COSIGN_BLOB_SHA256:-$(signed_digest "$dir")}" \
      bash "$sut" --prefix "$prefix" "$@" 2>&1
  )" || rc=$?
}
# expect RC TEXT DESC -> the last run exited RC and its output contains TEXT.
expect() {
  local want_rc="$1" want_text="$2" desc="$3"
  [[ "$rc" == "$want_rc" ]] || fail "$desc: expected exit $want_rc, got $rc; output: $out"
  grep -q -F -- "$want_text" <<<"$out" || fail "$desc: output lacks '$want_text'; output: $out"
  echo "ok   $desc"
}
# last_line TEXT DESC -> the last line of the output is exactly TEXT.
last_line() {
  [[ "$(tail -n1 <<<"$out")" == "$1" ]] || fail "$2: last line is '$(tail -n1 <<<"$out")', not '$1'"
}
installed() { [[ -x "$prefix/bin/ward" && -x "$prefix/bin/wardd" && -x "$prefix/bin/ward-agent" ]]; }
assert_installed() { installed || fail "$1: the three binaries should be in $prefix/bin"; }
assert_nothing_installed() {
  if installed || [[ -n "$(ls -A "$prefix/bin" 2>/dev/null)" ]]; then
    fail "$1: nothing should have been installed; $(ls -A "$prefix/bin")"
  fi
}

### An untouched, signed release: every state, then provenance-verified. ########

c="$(fresh_release valid)"
log="$work/valid.cosign.log"
FAKE_COSIGN_LOG="$log" run_sut "$c"
expect 0 "provenance-verified" "a signed release installs as provenance-verified"
assert_installed "valid"
last_line "install: provenance-verified" "valid"
for state in "downloaded $manifest, its .sha256 and its Sigstore bundle" \
  "digest-checked (manifest): $manifest.sha256 agrees" \
  "digest-checked (tarball): $tarball.sha256 agrees" \
  "digest-checked (tarball): $manifest agrees" \
  "verify-manifest: state=provenance-verified"; do
  grep -q -F -- "$state" <<<"$out" || fail "valid: output lacks the state line '$state'; output: $out"
done
# The states come in ADR-0028's order, and the verifier covered the tarball.
[[ "$(grep -n -F 'digest-checked (manifest)' <<<"$out" | head -1 | cut -d: -f1)" -lt \
  "$(grep -n -F 'provenance-verified' <<<"$out" | head -1 | cut -d: -f1)" ]] || fail "valid: digest-checked should precede provenance-verified"
grep -q -F "artifact OK: '$tarball'" <<<"$out" || fail "valid: the verifier should have digest-checked the tarball; output: $out"
! grep -q -i 'checksum-only' <<<"$out" || fail "valid: a verified install must not say checksum-only"
# cosign was asked for the exact identity of the release tag, once.
grep -q -F -- "--certificate-identity $(identity_for "$tag") --certificate-oidc-issuer $pinned_issuer" "$log" ||
  fail "valid: cosign was not asked for the pinned identity; log: $(cat "$log")"
[[ "$(wc -l <"$log")" == "1" ]] || fail "valid: cosign should be called once; log: $(cat "$log")"
# The installed binaries are the tarball's, and ward doctor ran.
[[ "$("$prefix/bin/ward" --version)" == "ward $version" ]] || fail "valid: installed ward is not the tarball's"
grep -q -F "doctor: fixture ok" <<<"$out" || fail "valid: ward doctor should have run"
echo "ok   the states are printed in order, cosign is asked for the exact identity once, the binaries are the tarball's"

# --version pins the tag; --require-provenance is satisfied by a verified release;
# --trusted-root reaches cosign through the verifier.
root="$work/trusted-root.json"
echo '{}' >"$root"
log="$work/pinned.cosign.log"
FAKE_COSIGN_LOG="$log" run_sut "$c" --version "$tag" --require-provenance --trusted-root "$root"
expect 0 "install: provenance-verified" "--version, --require-provenance and --trusted-root on a verified release"
grep -q -F -- "--trusted-root $root" "$log" || fail "--trusted-root did not reach cosign; log: $(cat "$log")"
# A relative root resolves although the verifier runs inside the download dir.
log="$work/relroot.cosign.log"
pushd "$work" >/dev/null
FAKE_COSIGN_LOG="$log" run_sut "$c" --trusted-root trusted-root.json
popd >/dev/null
expect 0 "install: provenance-verified" "a relative --trusted-root is resolved before the verifier runs"
grep -q -F -- "--trusted-root $root" "$log" || fail "relative --trusted-root was not made absolute; log: $(cat "$log")"
run_sut "$c" --trusted-root "$work/no-such-root"
expect 2 "not a readable file" "an unreadable --trusted-root is a usage error"
assert_nothing_installed "bad trusted root"
# With a token (a private fork) the assets and the verifier come through the API,
# authenticated, and the release verifies the same.
log="$work/token.curl.log"
SUT_TOKEN=secret-token FAKE_CURL_LOG="$log" run_sut "$c"
expect 0 "install: provenance-verified" "with a token the verifier is fetched through the contents API"
grep -q -F -- "-H Authorization: Bearer secret-token -H Accept: application/vnd.github.raw+json -o " "$log" ||
  fail "token: the verifier should be fetched with the token; log: $(cat "$log")"
grep -q -F -- "contents/scripts/release/verify-manifest.sh?ref=$tag" "$log" || fail "token: contents API not used; log: $(cat "$log")"

### No cosign, no verifier, no trusted root: checksum-only, loudly, or refused. ##

c="$(fresh_release no-cosign)"
COSIGN=no-such-cosign run_sut "$c"
expect 0 "verifier-unavailable (cosign-missing)" "without cosign the install goes on checksum-only"
grep -q -F "provenance NOT verified, proceeding checksum-only" <<<"$out" || fail "no-cosign: the checksum-only line must be loud; output: $out"
last_line "install: checksum-only (verifier-unavailable: cosign-missing)" "no-cosign"
! grep -q -F "provenance-verified" <<<"$out" || fail "no-cosign: must not claim provenance-verified"
assert_installed "no-cosign"
# The tarball was still held against the manifest's digest, and the sidecar.
grep -q -F "digest-checked (tarball): $manifest agrees" <<<"$out" || fail "no-cosign: the manifest digest check must still run; output: $out"
COSIGN=no-such-cosign run_sut "$c" --require-provenance
expect 3 "refusing to install (--require-provenance)" "--require-provenance refuses a host without cosign"
assert_nothing_installed "no-cosign --require-provenance"

c="$(fresh_release no-verifier)"
rm "$c/verifier-at/$tag"
run_sut "$c"
expect 0 "verifier-unavailable (verifier-not-fetched)" "a verifier that cannot be fetched means checksum-only"
last_line "install: checksum-only (verifier-unavailable: verifier-not-fetched)" "no-verifier"
assert_installed "no-verifier"
run_sut "$c" --require-provenance
expect 3 "verifier-unavailable (verifier-not-fetched)" "--require-provenance refuses when the verifier cannot be fetched"
assert_nothing_installed "no-verifier --require-provenance"

c="$(fresh_release stale-root)"
FAKE_COSIGN_MODE=tuf-fail run_sut "$c"
expect 0 "verifier-unavailable (trusted-root-unavailable)" "a stale Sigstore trusted root means checksum-only, not a pass"
last_line "install: checksum-only (verifier-unavailable: trusted-root-unavailable)" "stale-root"
FAKE_COSIGN_MODE=tuf-fail run_sut "$c" --require-provenance
expect 11 "trusted-root-unavailable" "--require-provenance refuses on a stale trusted root, under the verifier's code"
assert_nothing_installed "stale-root --require-provenance"

### A release without a manifest, or without a bundle: provenance-missing. ######

c="$(fresh_release old-release)"
rm "$c/assets/$manifest" "$c/assets/$manifest.sha256" "$c/assets/$manifest.sigstore.json"
publish "$c"
run_sut "$c"
expect 0 "provenance-missing (no-manifest)" "a release without a manifest installs checksum-only"
grep -q -F "predates the signing step" <<<"$out" || fail "old-release: should say the release predates the signed manifest; output: $out"
grep -q -F "digest-checked (tarball): $tarball.sha256 agrees" <<<"$out" || fail "old-release: the sidecar check must still run; output: $out"
last_line "install: checksum-only (provenance-missing: no-manifest)" "old-release"
assert_installed "old-release"
run_sut "$c" --require-provenance
expect 4 "refusing to install (--require-provenance)" "--require-provenance refuses a release without a manifest"
assert_nothing_installed "old-release --require-provenance"

c="$(fresh_release unsigned)"
rm "$c/assets/$manifest.sigstore.json"
publish "$c"
run_sut "$c"
expect 0 "provenance-missing (no-bundle)" "a manifest without a bundle installs checksum-only"
last_line "install: checksum-only (provenance-missing: no-bundle)" "unsigned"
run_sut "$c" --require-provenance
expect 4 "provenance-missing (no-bundle)" "--require-provenance refuses an unsigned manifest"
assert_nothing_installed "unsigned --require-provenance"

### Verification failures install nothing, under the verifier's codes. ###########

c="$(fresh_release wrong-identity)"
FAKE_COSIGN_IDENTITY="https://github.com/someone-else/WardOS/.github/workflows/release.yml@refs/tags/$tag" run_sut "$c"
expect 6 "verification-failed (identity-mismatch)" "a valid signature from another repository is refused"
assert_nothing_installed "wrong-identity"
grep -q -F "cause=identity-mismatch" <<<"$out" || fail "wrong-identity: the verifier's cause should be shown; output: $out"
FAKE_COSIGN_IDENTITY="$(identity_for v1.2.2)" run_sut "$c" --require-provenance
expect 6 "identity-mismatch" "a valid signature for another tag is refused"
assert_nothing_installed "other-tag"

FAKE_COSIGN_ISSUER="https://accounts.google.com" run_sut "$c"
expect 5 "verification-failed (issuer-mismatch)" "a certificate from another issuer is refused"
assert_nothing_installed "wrong-issuer"

FAKE_COSIGN_BLOB_SHA256="$(printf 'other' | sha256sum | awk '{print $1}')" run_sut "$c"
expect 7 "verification-failed (manifest-altered)" "a manifest the bundle does not cover is refused"
assert_nothing_installed "altered"

# One byte of the tarball changed, sidecar re-made to match: the (unverified)
# manifest disagrees, before and without the verifier.
c="$(fresh_release altered-tarball)"
printf 'x' >>"$c/assets/$tarball"
(cd "$c/assets" && sha256sum "$tarball" >"$tarball.sha256")
run_sut "$c"
expect 8 "verification-failed (digest-mismatch)" "a tarball whose digest is not the manifest's is refused"
grep -q -F "$manifest records" <<<"$out" || fail "altered-tarball: should name the manifest's digest; output: $out"
assert_nothing_installed "altered-tarball"
COSIGN=no-such-cosign run_sut "$c"
expect 8 "verification-failed (digest-mismatch)" "...also without cosign: checksum-only never means manifest-unchecked"
assert_nothing_installed "altered-tarball no-cosign"

# One byte changed, sidecar left alone: the sidecar is the second line of defence.
c="$(fresh_release altered-sidecar)"
printf 'x' >>"$c/assets/$tarball"
run_sut "$c"
expect 8 "$tarball.sha256 does not match" "a tarball its own sidecar disagrees with is refused"
assert_nothing_installed "altered-sidecar"
c="$(fresh_release altered-manifest-sidecar)"
printf '%064d  %s\n' 0 "$manifest" >"$c/assets/$manifest.sha256"
run_sut "$c"
expect 8 "$manifest.sha256 does not match" "a manifest its own sidecar disagrees with is refused"
assert_nothing_installed "altered-manifest-sidecar"

# Another release's manifest under this release's name: it does not name this
# tarball.
c="$(fresh_release wrong-release)"
mkdir -p "$c/other"
printf 'payload' >"$c/other/wardos-9.9.9-${arch}-linux.tar.gz"
(cd "$c/other" && sha256sum "wardos-9.9.9-${arch}-linux.tar.gz" >"wardos-9.9.9-${arch}-linux.tar.gz.sha256")
GENERATE_MANIFEST_NOW=2026-01-01T00:00:00Z bash "$generate" v9.9.9 "$commit" "$c/other" >"$c/assets/$manifest"
resign "$c"
run_sut "$c"
expect 10 "verification-failed (wrong-release)" "another release's manifest is refused"
assert_nothing_installed "wrong-release"

# A manifest the verifier cannot read (tag and version disagree): malformed.
c="$(fresh_release malformed)"
sed -i 's/"version": "1.2.3"/"version": "1.2.4"/' "$(manifest_of "$c")"
resign "$c"
run_sut "$c"
expect 12 "verification-failed (malformed-manifest)" "a manifest the verifier cannot read is refused"
assert_nothing_installed "malformed"

### What held before: the arch guard, the flags, the local install. ##############

c="$(fresh_release other-arch)"
rm "$c/assets/$tarball" "$c/assets/$tarball.sha256"
publish "$c"
run_sut "$c"
expect 1 "has no $arch tarball" "a release without this architecture's tarball is refused before any download"
assert_nothing_installed "other-arch"

c="$(fresh_release flags)"
run_sut "$c" --bogus
expect 2 "unknown option --bogus" "an unknown flag is a usage error"
run_sut "$c" --help
expect 0 "--require-provenance" "--help names --require-provenance"
grep -q -F -- "--trusted-root" <<<"$out" || fail "--help should name --trusted-root"
run_sut "$c" --version v0.0.1
expect 1 "could not fetch release v0.0.1" "an unknown --version is an actionable failure, not curl's exit code"
assert_nothing_installed "unknown version"

# From an unpacked tarball install.sh installs the files beside it, fetches
# nothing, and says so: the user verified the tarball (docs/install.md §1).
c="$(fresh_release local)"
cp "$sut" "$c/stage/wardos-${version}-${arch}-linux/install.sh"
log="$work/local.curl.log"
prefix="$(mktemp -d "$work/prefix.XXXXXX")"
rc=0
out="$(GITHUB_TOKEN='' GH_TOKEN='' FAKE_CURL_LOG="$log" FAKE_CURL_ROOT="$c" bash "$c/stage/wardos-${version}-${arch}-linux/install.sh" --prefix "$prefix" 2>&1)" || rc=$?
expect 0 "install: unverified" "a local install from an unpacked tarball is never called verified"
assert_installed "local"
[[ ! -s "$log" ]] || fail "local: nothing should be fetched; curl log: $(cat "$log")"

echo "PASS install.test.sh"
