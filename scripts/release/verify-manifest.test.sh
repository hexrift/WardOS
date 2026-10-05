#!/usr/bin/env bash
# Regressions for verify-manifest.sh (ADR-0028 §2/§3, issue #148), run against a
# fake `cosign` on PATH: the verifier passes a manifest signed by the pinned
# identity for its own tag, and refuses -- with the documented cause and exit
# code -- a wrong identity, a wrong issuer, altered manifest bytes, a missing
# bundle, an altered artifact, an incomplete set, the wrong release, a manifest
# whose tag is not a release tag, and a machine without cosign (which must be
# "verifier unavailable", never a pass). The rows of ADR-0028's acceptance table
# this covers: untouched release / one byte changed / valid signature from
# another repository or workflow / missing bundle / incomplete artifact set /
# stale or absent trusted root.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/verify-manifest.sh"
generate="$RELEASE_DIR/generate-manifest.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

tag="v1.2.3"
version="1.2.3"
commit="0123456789abcdef0123456789abcdef01234567"
pinned_issuer="https://token.actions.githubusercontent.com"
identity_for() { printf 'https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/tags/%s' "$1"; }

# A fake cosign that behaves like `cosign verify-blob --bundle` over a
# certificate whose claims the test chooses:
#   FAKE_COSIGN_IDENTITY     the SAN "in the certificate"
#   FAKE_COSIGN_ISSUER       the OIDC issuer "in the certificate"
#   FAKE_COSIGN_BLOB_SHA256  the digest the "signature" covers
#   FAKE_COSIGN_MODE         "" | tuf-fail (cannot load the trusted root)
#   FAKE_COSIGN_LOG          a file every invocation appends its arguments to
# It fails when the blob's bytes are not the signed ones, when the exact or
# regexp identity/issuer the verifier asks for does not match the certificate,
# or when the bundle file is missing -- the three outcomes real cosign has.
mkdir -p "$work/bin"
cat >"$work/bin/cosign" <<'EOF'
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
EOF
chmod +x "$work/bin/cosign"
export PATH="$work/bin:$PATH"

# fresh_release NAME -> a $work/NAME holding a complete fixture release: two
# runtime tarballs with sidecars, the manifest generate-manifest.sh produces for
# them, its .sha256 sidecar and a (fake) bundle. The fake cosign is told the
# manifest's digest is the signed one; callers set the certificate claims.
fresh_release() {
  local dir="$work/$1"
  mkdir -p "$dir"
  local arch name
  for arch in x86_64 aarch64; do
    name="wardos-${version}-${arch}-linux.tar.gz"
    printf 'payload-%s' "$arch" >"$dir/$name"
    (cd "$dir" && sha256sum "$name" >"$name.sha256")
  done
  GENERATE_MANIFEST_NOW=2026-01-01T00:00:00Z bash "$generate" "$tag" "$commit" "$dir" >"$dir/wardos-${version}-manifest.json"
  (cd "$dir" && sha256sum "wardos-${version}-manifest.json" >"wardos-${version}-manifest.json.sha256")
  printf '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n' >"$dir/wardos-${version}-manifest.json.sigstore.json"
  printf '%s' "$dir"
}
manifest_of() { printf '%s/wardos-%s-manifest.json' "$1" "$version"; }
bundle_of() { printf '%s/wardos-%s-manifest.json.sigstore.json' "$1" "$version"; }
signed_digest() { sha256sum "$(manifest_of "$1")" | awk '{print $1}'; }

# run_sut RELEASE ARGS... -> runs the verifier on that release's manifest and
# bundle with the fake cosign presenting the pinned claims unless overridden;
# stdout+stderr land in $out, the status in $rc.
out=""
rc=0
run_sut() {
  local dir="$1"
  shift
  rc=0
  out="$(
    FAKE_COSIGN_IDENTITY="${FAKE_COSIGN_IDENTITY:-$(identity_for "$tag")}" \
      FAKE_COSIGN_ISSUER="${FAKE_COSIGN_ISSUER:-$pinned_issuer}" \
      FAKE_COSIGN_BLOB_SHA256="${FAKE_COSIGN_BLOB_SHA256:-$(signed_digest "$dir")}" \
      bash "$sut" "$(manifest_of "$dir")" "$(bundle_of "$dir")" "$@" 2>&1
  )" || rc=$?
}
# expect RC CAUSE DESC -> the last run_sut exited RC and reported CAUSE (or, for
# 0, the provenance-verified state).
expect() {
  local want_rc="$1" want_text="$2" desc="$3"
  [[ "$rc" == "$want_rc" ]] || fail "$desc: expected exit $want_rc, got $rc; output: $out"
  grep -q -F -- "$want_text" <<<"$out" || fail "$desc: output lacks '$want_text'; output: $out"
  echo "ok   $desc"
}

### Untouched release, pinned identity for its own tag: provenance-verified. ####

c="$(fresh_release valid)"
run_sut "$c"
expect 0 "state=provenance-verified" "valid release verifies"
grep -q -F "2 artifact(s) digest-checked, 0 absent" <<<"$out" || fail "valid: both artifacts should be digest-checked; output: $out"
grep -q -F "sidecar OK" <<<"$out" || fail "valid: the manifest sidecar should be checked; output: $out"
run_sut "$c" --tag "$tag" --require-artifacts
expect 0 "state=provenance-verified" "valid release verifies with --tag and --require-artifacts"

# The exact identity is derived from the manifest's tag and passed as
# --certificate-identity, never as a pattern: cosign must have been asked for
# exactly release.yml@refs/tags/v1.2.3 with the pinned issuer.
log="$work/valid.log"
FAKE_COSIGN_LOG="$log" run_sut "$c"
expect 0 "state=provenance-verified" "valid release verifies (logged)"
grep -q -F -- "--certificate-identity $(identity_for "$tag") --certificate-oidc-issuer $pinned_issuer" "$log" ||
  fail "cosign was not asked for the exact pinned identity of the manifest's tag; log: $(cat "$log")"
[[ "$(wc -l <"$log")" == "1" ]] || fail "a passing verification should call cosign exactly once; log: $(cat "$log")"

# A prerelease tag derives a prerelease identity.
pre="$work/prerelease"
mkdir -p "$pre"
name="wardos-1.2.3-rc.1-x86_64-linux.tar.gz"
printf 'rc' >"$pre/$name"; (cd "$pre" && sha256sum "$name" >"$name.sha256")
GENERATE_MANIFEST_NOW=2026-01-01T00:00:00Z bash "$generate" v1.2.3-rc.1 "$commit" "$pre" >"$pre/wardos-1.2.3-rc.1-manifest.json"
printf '{}\n' >"$pre/wardos-1.2.3-rc.1-manifest.json.sigstore.json"
rc=0
out="$(FAKE_COSIGN_IDENTITY="$(identity_for v1.2.3-rc.1)" FAKE_COSIGN_ISSUER="$pinned_issuer" \
  FAKE_COSIGN_BLOB_SHA256="$(sha256sum "$pre/wardos-1.2.3-rc.1-manifest.json" | awk '{print $1}')" \
  bash "$sut" "$pre/wardos-1.2.3-rc.1-manifest.json" "$pre/wardos-1.2.3-rc.1-manifest.json.sigstore.json" 2>&1)" || rc=$?
expect 0 "state=provenance-verified" "a prerelease manifest derives its own identity"

# --trusted-root is handed to cosign as given; one that is not a file is an
# input error, not a verdict.
c="$(fresh_release trusted-root)"
printf '{"mediaType":"application/vnd.dev.sigstore.trustedroot+json"}\n' >"$c/trusted_root.json"
log="$work/trusted-root.log"
FAKE_COSIGN_LOG="$log" run_sut "$c" --trusted-root "$c/trusted_root.json"
expect 0 "state=provenance-verified" "a trusted root is forwarded to cosign"
grep -q -F -- "--trusted-root $c/trusted_root.json" "$log" || fail "trusted-root: cosign was not given the trusted root; log: $(cat "$log")"
run_sut "$c" --trusted-root "$c/does-not-exist.json"
expect 2 "cause=usage" "a trusted root that is not a file is a usage error"

### Wrong identity / wrong issuer: valid signature, refused by policy. ##########

# Another repository's release workflow signed it (the acceptance table's
# "valid signature from another repository/workflow").
c="$(fresh_release other-repo)"
FAKE_COSIGN_IDENTITY="https://github.com/attacker/WardOS/.github/workflows/release.yml@refs/tags/$tag" run_sut "$c"
expect 6 "cause=identity-mismatch" "another repository's identity is refused"

# The same repository, another workflow.
c="$(fresh_release other-workflow)"
FAKE_COSIGN_IDENTITY="https://github.com/hexrift/WardOS/.github/workflows/deploy.yml@refs/tags/$tag" run_sut "$c"
expect 6 "cause=identity-mismatch" "another workflow's identity is refused"

# The release workflow, but run on a branch, not the tag.
c="$(fresh_release branch-ref)"
FAKE_COSIGN_IDENTITY="https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/heads/main" run_sut "$c"
expect 6 "cause=identity-mismatch" "a branch-ref identity is refused"

# The release workflow on another tag than the manifest names.
c="$(fresh_release other-tag)"
FAKE_COSIGN_IDENTITY="$(identity_for v9.9.9)" run_sut "$c"
expect 6 "cause=identity-mismatch" "an identity for another tag is refused"

# A literal `v*` in the certificate is not a wildcard that matches.
c="$(fresh_release literal-wildcard)"
FAKE_COSIGN_IDENTITY="$(identity_for 'v*')" run_sut "$c"
expect 6 "cause=identity-mismatch" "a literal v* identity does not match"

# Right identity string, wrong OIDC issuer: its own cause and exit code.
c="$(fresh_release other-issuer)"
FAKE_COSIGN_ISSUER="https://attacker.example/oidc" run_sut "$c"
expect 5 "cause=issuer-mismatch" "another OIDC issuer is refused"

# The policy override is honoured (a fork verifying its own release) and still
# derives an exact identity for the manifest's tag.
c="$(fresh_release fork)"
FAKE_COSIGN_IDENTITY="https://github.com/fork/WardOS/.github/workflows/release.yml@refs/tags/$tag" \
  run_sut "$c" --identity-policy repository=fork/WardOS
expect 0 "state=provenance-verified" "a fork's policy override verifies the fork's identity"
run_sut "$c" --identity-policy repository=fork/WardOS
expect 6 "cause=identity-mismatch" "with a fork's policy, WardOS's own identity is refused"
run_sut "$c" --identity-policy owner=fork
expect 2 "cause=usage" "an unknown identity-policy key is a usage error"

### Altered bytes. ###############################################################

# One byte changed in the manifest after signing: the bundle no longer verifies
# the bytes under any identity.
c="$(fresh_release altered-manifest)"
signed="$(signed_digest "$c")"
printf ' \n' >>"$(manifest_of "$c")"
FAKE_COSIGN_BLOB_SHA256="$signed" run_sut "$c"
expect 7 "cause=manifest-altered" "an altered manifest is refused"

# The manifest is intact but its sidecar is not its own.
c="$(fresh_release sidecar-mismatch)"
printf '%064d  wardos-%s-manifest.json\n' 0 "$version" >"$(manifest_of "$c").sha256"
run_sut "$c"
expect 8 "cause=digest-mismatch" "a sidecar that disagrees with the signed manifest is refused"

# No sidecar at all: the signature covers the bytes; verified, with a note.
c="$(fresh_release no-sidecar)"
rm "$(manifest_of "$c").sha256"
run_sut "$c"
expect 0 "state=provenance-verified" "a manifest without a sidecar still verifies"
grep -q -F "no 'wardos-${version}-manifest.json.sha256' beside the manifest" <<<"$out" || fail "no-sidecar: expected a note; output: $out"

# One byte changed in a tarball after download.
c="$(fresh_release altered-artifact)"
printf 'x' >>"$c/wardos-${version}-x86_64-linux.tar.gz"
run_sut "$c"
expect 8 "cause=digest-mismatch" "an altered artifact is refused"
grep -q -F "wardos-${version}-x86_64-linux.tar.gz" <<<"$out" || fail "altered-artifact: the cause should name the artifact; output: $out"

# A tarball's own sidecar disagrees with the signed manifest.
c="$(fresh_release artifact-sidecar-mismatch)"
printf '%064d  wardos-%s-aarch64-linux.tar.gz\n' 1 "$version" >"$c/wardos-${version}-aarch64-linux.tar.gz.sha256"
run_sut "$c"
expect 8 "cause=digest-mismatch" "an artifact sidecar that disagrees with the signed manifest is refused"

### Missing provenance, incomplete set, wrong release. ##########################

c="$(fresh_release missing-bundle)"
rm "$(bundle_of "$c")"
log="$work/missing-bundle.log"
FAKE_COSIGN_LOG="$log" run_sut "$c"
expect 4 "cause=provenance-missing" "a missing bundle is refused"
[[ ! -e "$log" ]] || fail "missing-bundle: cosign must not be invoked without a bundle; log: $(cat "$log")"

c="$(fresh_release unreadable-bundle)"
printf 'not json' >"$(bundle_of "$c")"
run_sut "$c"
expect 4 "cause=provenance-missing" "a non-JSON bundle is refused as missing provenance"

# An artifact the manifest names is absent: skipped by default, refused with
# --require-artifacts.
c="$(fresh_release absent-artifact)"
rm "$c/wardos-${version}-aarch64-linux.tar.gz" "$c/wardos-${version}-aarch64-linux.tar.gz.sha256"
run_sut "$c"
expect 0 "state=provenance-verified" "an absent artifact is skipped by default"
grep -q -F "1 artifact(s) digest-checked, 1 absent" <<<"$out" || fail "absent-artifact: expected 1 checked, 1 absent; output: $out"
run_sut "$c" --require-artifacts
expect 9 "cause=incomplete-set" "an absent artifact is refused with --require-artifacts"

# The wrong release: a validly signed manifest of another release than asked for.
c="$(fresh_release wrong-tag)"
run_sut "$c" --tag v1.2.4
expect 10 "cause=wrong-release" "a manifest for another release than --tag is refused"

# The file name says one version, the manifest another: substituted or mixed up.
c="$(fresh_release misnamed)"
mv "$(manifest_of "$c")" "$c/wardos-9.9.9-manifest.json"
rc=0
out="$(FAKE_COSIGN_IDENTITY="$(identity_for "$tag")" FAKE_COSIGN_ISSUER="$pinned_issuer" \
  FAKE_COSIGN_BLOB_SHA256="$(sha256sum "$c/wardos-9.9.9-manifest.json" | awk '{print $1}')" \
  bash "$sut" "$c/wardos-9.9.9-manifest.json" "$(bundle_of "$c")" 2>&1)" || rc=$?
expect 10 "cause=wrong-release" "a manifest whose file name names another version is refused"

### Malformed manifests never reach cosign. ####################################

# A manifest whose tag is a literal `v*`: refused before any identity is derived.
c="$(fresh_release wildcard-tag)"
jq '.tag = "v*" | .version = "*"' "$(manifest_of "$c")" >"$c/m.json" && mv "$c/m.json" "$(manifest_of "$c")"
log="$work/wildcard-tag.log"
FAKE_COSIGN_LOG="$log" FAKE_COSIGN_BLOB_SHA256="$(signed_digest "$c")" run_sut "$c"
expect 2 "cause=malformed-manifest" "a v* tag is refused as malformed"
[[ ! -e "$log" ]] || fail "wildcard-tag: cosign must not be invoked for a malformed tag; log: $(cat "$log")"

c="$(fresh_release branch-tag)"
jq '.tag = "main" | .version = "main"' "$(manifest_of "$c")" >"$c/m.json" && mv "$c/m.json" "$(manifest_of "$c")"
FAKE_COSIGN_BLOB_SHA256="$(signed_digest "$c")" run_sut "$c"
expect 2 "cause=malformed-manifest" "a branch name as tag is refused as malformed"

c="$(fresh_release version-mismatch)"
jq '.version = "1.2.4"' "$(manifest_of "$c")" >"$c/m.json" && mv "$c/m.json" "$(manifest_of "$c")"
FAKE_COSIGN_BLOB_SHA256="$(signed_digest "$c")" run_sut "$c"
expect 2 "cause=malformed-manifest" "a version that disagrees with the tag is refused"

c="$(fresh_release bad-digest-field)"
jq '.artifacts[0].digest = "md5:abc"' "$(manifest_of "$c")" >"$c/m.json" && mv "$c/m.json" "$(manifest_of "$c")"
FAKE_COSIGN_BLOB_SHA256="$(signed_digest "$c")" run_sut "$c"
expect 2 "cause=malformed-manifest" "an artifact without a sha256 digest is refused"

c="$(fresh_release not-json)"
printf 'not json' >"$(manifest_of "$c")"
run_sut "$c"
expect 2 "cause=malformed-manifest" "a manifest that is not JSON is refused"

rc=0
out="$(bash "$sut" "$work/does-not-exist.json" "$work/x.sigstore.json" 2>&1)" || rc=$?
expect 2 "cause=malformed-manifest" "a missing manifest file is an input error"

rc=0
out="$(bash "$sut" 2>&1)" || rc=$?
expect 2 "cause=usage" "no arguments is a usage error"

### The verifier itself. ########################################################

# cosign cannot load the Sigstore trusted root: distinct, not a verdict.
c="$(fresh_release tuf)"
FAKE_COSIGN_MODE=tuf-fail run_sut "$c"
expect 11 "cause=trusted-root-unavailable" "a trusted root cosign cannot load is its own failure"

# No cosign on PATH: "verifier unavailable", exit 3, never a pass -- with a PATH
# that still has every other tool the verifier needs, so this is what is tested.
tools="$work/toolsonly"
mkdir -p "$tools"
for t in bash jq sha256sum awk sed grep tr basename dirname mktemp rm cat; do
  ln -s "$(command -v "$t")" "$tools/$t"
done
c="$(fresh_release no-cosign)"
rc=0
out="$(PATH="$tools" bash "$sut" "$(manifest_of "$c")" "$(bundle_of "$c")" 2>&1)" || rc=$?
expect 3 "cause=cosign-missing" "without cosign the verifier is unavailable, not passing"
grep -q -F "state=verifier-unavailable" <<<"$out" || fail "no-cosign: expected the verifier-unavailable state; output: $out"
grep -q -F "Nothing has been verified" <<<"$out" || fail "no-cosign: the message must say nothing was verified; output: $out"

# COSIGN names a binary that does not exist: the same state.
rc=0
out="$(COSIGN=/nonexistent/cosign bash "$sut" "$(manifest_of "$c")" "$(bundle_of "$c")" 2>&1)" || rc=$?
expect 3 "cause=cosign-missing" "a COSIGN override that does not exist is unavailable"

echo "PASS verify-manifest.test.sh"
