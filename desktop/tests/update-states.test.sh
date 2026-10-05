#!/usr/bin/env bash
# wardos-update --status and system (ADR-0028 §5, #148 item 5): booted, staged, available,
# verified, manifest, rollback, anti-rollback and compatibility are separate lines; a
# network, registry, verifier or bootc failure is an actionable state and never "no
# update"; a lower candidate version is refused unless --allow-rollback is given.
#
# Mocks: `bootc` answers `status --json` from $BOOTC_STATUS and `upgrade --check` with
# $BOOTC_CHECK (or fails with $BOOTC_CHECK_FAIL); `skopeo inspect` answers the image's
# org.wardos.version label from $SKOPEO_LABELS ("<digest>=<label> …"); `curl` serves the
# release assets of $CURL_DIR by file name (404 otherwise, offline with $CURL_FAIL); and
# the fake `cosign` of scripts/release/verify-manifest.test.sh signs the fixture manifest
# with the claims the test chooses. The verifier itself is the real
# scripts/release/verify-manifest.sh of this checkout.
# shellcheck disable=SC2016  # mock bodies are shell text, expanded when the mock runs
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
for c in sudo flatpak wardos-refresh wardos-theme git notify-send; do mock "$c"; done
mock ward 'echo "ward 0.4.1"'

mock bootc 'case "$*" in
  "status --json")
    [[ -n "${BOOTC_STATUS_FAIL:-}" ]] && { echo "$BOOTC_STATUS_FAIL" >&2; exit 1; }
    cat "$BOOTC_STATUS" ;;
  "upgrade --check")
    [[ -n "${BOOTC_CHECK_FAIL:-}" ]] && { echo "$BOOTC_CHECK_FAIL" >&2; exit 1; }
    printf "%s\n" "$BOOTC_CHECK" ;;
esac'
mock skopeo '[[ -n "${SKOPEO_FAIL:-}" ]] && { echo "$SKOPEO_FAIL" >&2; exit 1; }
ref="${*##* }"; d="${ref##*@}"
for kv in ${SKOPEO_LABELS:-}; do
  [[ "${kv%%=*}" == "$d" ]] && { printf "{\"Labels\": {\"org.wardos.version\": \"%s\"}}\n" "${kv#*=}"; exit 0; }
done
printf "{\"Labels\": {}}\n"'
mock curl 'dest=""; url=""
while [[ $# -gt 0 ]]; do case "$1" in -o) dest=$2; shift 2 ;; -w | -H) shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac; done
[[ -n "${CURL_FAIL:-}" ]] && { echo "curl: (6) Could not resolve host: github.com" >&2; exit 6; }
f="${CURL_DIR:-/nonexistent}/$(basename "$url")"
if [[ -f "$f" ]]; then cp "$f" "$dest"; printf 200; else printf 404; fi'

# The fake cosign of scripts/release/verify-manifest.test.sh (FAKE_COSIGN_IDENTITY,
# _ISSUER, _BLOB_SHA256 choose the certificate's claims and the signed bytes).
cat >"$MOCK_DIR/cosign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
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
[[ -f "$bundle" ]] || { echo "Error: bundle not found" >&2; exit 1; }
actual="$(sha256sum "$blob" | awk '{print $1}')"
[[ "$actual" == "${FAKE_COSIGN_BLOB_SHA256:-}" ]] || { echo "Error: verifying blob: invalid signature" >&2; exit 1; }
if [[ -n "$identity" ]]; then
  [[ "$identity" == "${FAKE_COSIGN_IDENTITY:-}" ]] || { echo "Error: none of the expected identities matched" >&2; exit 1; }
elif [[ -n "$identity_re" ]]; then
  [[ "${FAKE_COSIGN_IDENTITY:-}" =~ $identity_re ]] || { echo "Error: none of the expected identities matched" >&2; exit 1; }
fi
if [[ -n "$issuer" ]]; then
  [[ "$issuer" == "${FAKE_COSIGN_ISSUER:-}" ]] || { echo "Error: expected oidc issuer not found" >&2; exit 1; }
elif [[ -n "$issuer_re" ]]; then
  [[ "${FAKE_COSIGN_ISSUER:-}" =~ $issuer_re ]] || { echo "Error: expected oidc issuer not found" >&2; exit 1; }
fi
echo "Verified OK"
EOF
chmod +x "$MOCK_DIR/cosign"

# A fixture release v0.4.2 with a manifest, its sidecar and a (fake) bundle, the way
# the release workflow publishes them; the fake cosign is told the manifest's bytes
# are the signed ones and presents the pinned identity for that tag unless a case
# overrides it.
release="$TMP/release"
mkdir -p "$release"
for arch in x86_64 aarch64; do
  name="wardos-0.4.2-${arch}-linux.tar.gz"
  printf 'payload-%s' "$arch" >"$release/$name"
  (cd "$release" && sha256sum "$name" >"$name.sha256")
done
GENERATE_MANIFEST_NOW=2026-01-01T00:00:00Z bash "$WARDOS_ROOT/../scripts/release/generate-manifest.sh" \
  v0.4.2 0123456789abcdef0123456789abcdef01234567 "$release" >"$release/wardos-0.4.2-manifest.json"
(cd "$release" && sha256sum wardos-0.4.2-manifest.json >wardos-0.4.2-manifest.json.sha256)
printf '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n' >"$release/wardos-0.4.2-manifest.json.sigstore.json"
rm "$release"/*.tar.gz*
export FAKE_COSIGN_ISSUER="https://token.actions.githubusercontent.com"
export FAKE_COSIGN_IDENTITY="https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/tags/v0.4.2"
FAKE_COSIGN_BLOB_SHA256=$(sha256sum "$release/wardos-0.4.2-manifest.json" | awk '{print $1}')
export FAKE_COSIGN_BLOB_SHA256
export CURL_DIR="$release"
export COSIGN="$MOCK_DIR/cosign" # the verifier's cosign, whether or not the host has one

ref="quay.io/hexrift/wardos:latest"
booted_digest="sha256:aaaa000000000000000000000000000000000000000000000000000000000001"
cand_digest="sha256:bbbb000000000000000000000000000000000000000000000000000000000002"
rollback_digest="sha256:cccc000000000000000000000000000000000000000000000000000000000003"

# deployment DIGEST VERSION [CACHED-JSON] -> one bootc deployment object (bootc's
# `version` is the image's version label, Fedora's own for today's WardOS images).
deployment() {
  printf '{"image": {"image": {"image": "%s", "transport": "registry"}, "version": "%s", "timestamp": null, "imageDigest": "%s"}, "cachedUpdate": %s, "incompatible": false, "pinned": false, "store": "ostreeContainer", "ostree": {"checksum": "x", "deploySerial": 0}}' \
    "$ref" "$2" "$1" "${3:-null}"
}
cached() { printf '{"image": {"image": "%s", "transport": "registry"}, "version": "%s", "timestamp": null, "imageDigest": "%s"}' "$ref" "$2" "$1"; }
# write_status BOOTED STAGED ROLLBACK -> $BOOTC_STATUS (each a deployment object or null)
write_status() {
  printf '{"apiVersion": "org.containers.bootc/v1", "kind": "BootcHost", "metadata": {"name": "host"}, "spec": {"image": {"image": "%s", "transport": "registry"}, "bootOrder": "default"}, "status": {"staged": %s, "booted": %s, "rollback": %s, "rollbackQueued": false, "type": "bootcHost"}}\n' \
    "$ref" "$2" "$1" "$3" >"$BOOTC_STATUS"
}
export BOOTC_STATUS="$TMP/bootc-status.json"

out=""
rc=0
run() {
  rc=0
  out=$(wardos-update "$@" 2>&1) || rc=$?
}
assert_line() { grep -Eq -- "$1" <<<"$out" || fail "expected a line matching '$1'; output:
$out"; }
assert_no_line() { ! grep -Eiq -- "$1" <<<"$out" || fail "unexpected '$1' in output:
$out"; }
assert_rc() { [[ $rc == "$1" ]] || fail "expected exit $1, got $rc; output:
$out"; }

wardos-update --help | grep -q -- '--status' || fail "--help names --status"
wardos-update --help | grep -q -- '--allow-rollback' || fail "--help names --allow-rollback"

### --status: an update available, a rollback deployment, the manifest verifies. ####
write_status "$(deployment "$booted_digest" 44.20260901.0 "$(cached "$cand_digest" 44.20260908.0)")" null "$(deployment "$rollback_digest" 44.20260825.0)"
export BOOTC_CHECK="Update available for: $ref"
export SKOPEO_LABELS="$booted_digest=v0.4.1 $cand_digest=v0.4.2 $rollback_digest=v0.4.0"
run --status
assert_rc 0
assert_line "^booted +$ref@$booted_digest +v0.4.1 .*ward 0.4.1"
assert_line "^staged +none"
assert_line "^available +$cand_digest +v0.4.2 "
assert_line "^verified +digest-resolved \(bootc\), downloaded and digest-checked at staging; provenance-missing: the image is not covered by the release manifest"
assert_line "^manifest +v0.4.2: provenance-verified .*release v0.4.2.*not (of|about) the image"
assert_line "^rollback +available: $rollback_digest +v0.4.0"
assert_line "^anti-rollback +allowed: candidate v0.4.2 is not lower than booted v0.4.1"
assert_line "^compatibility +node protocol window 1\.0-1\.3 \(release manifest v0.4.2\); rollback supported: true"
assert_no_line "no update"
# The verifier was asked for the release's own tag and ran the fake cosign.
assert_logged "^skopeo inspect --no-tags docker://quay.io/hexrift/wardos@$cand_digest$"
assert_logged "^curl .*releases/download/v0.4.2/wardos-0.4.2-manifest.json.sigstore.json"

### --status: already staged, nothing newer, no rollback deployment. ###############
write_status "$(deployment "$booted_digest" 44.20260901.0)" "$(deployment "$cand_digest" 44.20260908.0)" null
export BOOTC_CHECK="No changes in: $ref"
run --status
assert_rc 0
assert_line "^staged +$cand_digest +v0.4.2$"
assert_line "^verified +downloaded, digest-checked \(bootc\); provenance-missing: the image is not covered by the release manifest"
assert_line "^available +up to date \(bootc: No changes in: $ref\)"
assert_line "^rollback +none"
assert_line "^anti-rollback +allowed: candidate v0.4.2 is not lower than booted v0.4.1"
assert_line "^compatibility +node protocol window 1\.0-1\.3 \(release manifest v0.4.2\)"
assert_no_line "no update"

### system: stage-only, the compatibility and rollback notes before the reboot note. ##
write_status "$(deployment "$booted_digest" 44.20260901.0 "$(cached "$cand_digest" 44.20260908.0)")" null "$(deployment "$rollback_digest" 44.20260825.0)"
export BOOTC_CHECK="Update available for: $ref"
: >"$MOCK_LOG"
run system
assert_rc 0
assert_logged '^sudo bootc upgrade$'
assert_line "^anti-rollback +allowed"
assert_line "^manifest +v0.4.2: provenance-verified"
assert_line "^rollback +available: $rollback_digest"
assert_line "reboot you choose"
assert_no_line "no update"

### The manifest is missing: loud, checksum-only, staging goes on; refused with
### --require-provenance. #########################################################
export CURL_DIR="$TMP/empty"
mkdir -p "$CURL_DIR"
: >"$MOCK_LOG"
run system
assert_rc 0
assert_line "^manifest +v0.4.2: provenance-missing \(release v0.4.2 publishes no manifest\)"
assert_logged '^sudo bootc upgrade$'
: >"$MOCK_LOG"
run system --require-provenance
assert_rc 6
assert_line "^manifest +v0.4.2: provenance-missing"
assert_line "refusing to stage \(--require-provenance\)"
assert_not_logged '^sudo bootc upgrade$'
export CURL_DIR="$release"

### Network failures are states, never "no update". ###############################
export CURL_FAIL=1
run --status
assert_rc 0
assert_line "^manifest +network-unavailable: .*; retry"
assert_no_line "no update"
unset CURL_FAIL

export BOOTC_CHECK_FAIL="ERROR Fetching manifest: dial tcp: lookup quay.io: no such host"
: >"$MOCK_LOG"
run system
assert_rc 3
assert_line "^available +network-unavailable: .*no such host.*; retry"
assert_not_logged '^sudo bootc upgrade$'
assert_no_line "no update"
run --status
assert_rc 0
assert_line "^available +network-unavailable: "
run --check
assert_rc 0
assert_eq "$out" '{"text": "update?", "tooltip": "network-unavailable: ERROR Fetching manifest: dial tcp: lookup quay.io: no such host; retry when the machine is online", "class": "unavailable"}'

export BOOTC_CHECK_FAIL="ERROR Fetching manifest: unauthorized: authentication required"
run system
assert_rc 4
assert_line "^available +registry-auth-failed: .*authentication required"
assert_no_line "no update"

export BOOTC_CHECK_FAIL="ERROR something else broke"
run system
assert_rc 1
assert_line "^available +bootc-error: ERROR something else broke"
assert_no_line "no update"
unset BOOTC_CHECK_FAIL

### bootc itself failing is bootc-error, never "no update". ########################
export BOOTC_STATUS_FAIL="ERROR could not read the deployments"
run --status
assert_line "^booted +bootc-error: ERROR could not read the deployments"
assert_no_line "no update"
run system
assert_rc 1
assert_line "bootc-error"
unset BOOTC_STATUS_FAIL
printf 'not json\n' >"$BOOTC_STATUS"
run --status
assert_line "^booted +bootc-error: unreadable bootc status"
write_status "$(deployment "$booted_digest" 44.20260901.0 "$(cached "$cand_digest" 44.20260908.0)")" null null

### The verifier failing is verification-failed and blocks staging. ###############
export FAKE_COSIGN_IDENTITY="https://github.com/attacker/WardOS/.github/workflows/release.yml@refs/tags/v0.4.2"
: >"$MOCK_LOG"
run system
assert_rc 6
assert_line "^manifest +v0.4.2: verification-failed \(identity-mismatch\)"
assert_not_logged '^sudo bootc upgrade$'
assert_no_line "no update"
export FAKE_COSIGN_IDENTITY="https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/tags/v0.4.2"

# No cosign on the host: the verifier is unavailable, which is said, not passed.
mv "$MOCK_DIR/cosign" "$TMP/cosign.away"
run --status
assert_line "^manifest +v0.4.2: verifier-unavailable \(cosign-missing\)"
mv "$TMP/cosign.away" "$MOCK_DIR/cosign"

### The anti-rollback floor (ADR-0028 §5; the shell mirror of
### ward-release-verify's check_anti_rollback). ####################################
export SKOPEO_LABELS="$booted_digest=v0.4.1 $cand_digest=v0.4.0"
: >"$MOCK_LOG"
run system
assert_rc 5
assert_line "^anti-rollback +refused: candidate v0.4.0 is lower than booted v0.4.1; pass --allow-rollback to stage it anyway"
assert_not_logged '^sudo bootc upgrade$'
assert_no_line "no update"
run --status
assert_rc 0
assert_line "^anti-rollback +refused: candidate v0.4.0 is lower than booted v0.4.1"
: >"$MOCK_LOG"
run system --allow-rollback
assert_rc 0
assert_line "^anti-rollback +allowed by --allow-rollback: candidate v0.4.0 is lower than booted v0.4.1"
assert_logged '^sudo bootc upgrade$'
# A manifest lookup for the older release still happens (v0.4.0 has none here).
assert_line "^manifest +v0.4.0: provenance-missing"

# Equal is not a downgrade; a pre-release of the booted release is.
export SKOPEO_LABELS="$booted_digest=v0.4.1 $cand_digest=v0.4.1"
run --status
assert_line "^anti-rollback +allowed: candidate v0.4.1 is not lower than booted v0.4.1"
export SKOPEO_LABELS="$booted_digest=v0.4.1 $cand_digest=v0.4.1-rc.1"
run system
assert_rc 5
assert_line "^anti-rollback +refused: candidate v0.4.1-rc.1 is lower than booted v0.4.1"
assert_line "^manifest +v0.4.1-rc.1: provenance-missing"
# A build between releases (git describe) is a pre-release of the tag it follows and
# is not a release: the floor compares it, the manifest is not looked up.
export SKOPEO_LABELS="$booted_digest=v0.4.1-12-gabc1234 $cand_digest=v0.4.1-15-gdef5678"
: >"$MOCK_LOG"
run --status
assert_line "^anti-rollback +allowed: candidate v0.4.1-15-gdef5678 is not lower than booted v0.4.1-12-gabc1234"
assert_line "^manifest +not looked up: v0.4.1-15-gdef5678 is not a release tag"
assert_line "^compatibility +node protocol window 1\.0-1\.3 \(docs/compatibility.md\)"
assert_not_logged '^curl '

# A label that is not a version cannot be compared: said, and not a refusal.
export SKOPEO_LABELS="$booted_digest=v0.4.1 $cand_digest=abc1234"
run --status
assert_line "^anti-rollback +not evaluated: candidate version 'abc1234' is not a valid version"
assert_line "^manifest +not looked up: abc1234 is not a release tag"

### Without skopeo, bootc's own version fields are compared, and said to be. ########
mv "$MOCK_DIR/skopeo" "$TMP/skopeo.away"
export SKOPEO_LABELS=""
run --status
assert_line "^booted +$ref@$booted_digest +44.20260901.0 \(bootc version; skopeo not installed\)"
assert_line "^available +$cand_digest +44.20260908.0 "
assert_line "^anti-rollback +allowed: candidate 44.20260908.0 is not lower than booted 44.20260901.0 \(bootc versions\)"
assert_line "^manifest +not looked up: the candidate's WardOS version is unknown \(skopeo not installed\)"
mv "$TMP/skopeo.away" "$MOCK_DIR/skopeo"
export SKOPEO_FAIL="FATA[0000] pinging container registry quay.io: dial tcp: no such host"
run --status
assert_line "^anti-rollback +allowed: candidate 44.20260908.0 is not lower than booted 44.20260901.0 \(bootc versions\)"
assert_line "^manifest +network-unavailable: .*no such host.*; retry"
unset SKOPEO_FAIL
export SKOPEO_LABELS="$booted_digest=v0.4.1 $cand_digest=v0.4.2"

### The whole run: the toast carries the states; a failure is a critical notice. ####
write_status "$(deployment "$booted_digest" 44.20260901.0 "$(cached "$cand_digest" 44.20260908.0)")" null "$(deployment "$rollback_digest" 44.20260825.0)"
export BOOTC_CHECK="Update available for: $ref"
: >"$MOCK_LOG"
run
assert_rc 0
assert_logged '^sudo bootc upgrade$'
assert_logged '^flatpak update -y$'
assert_logged '^notify-send -a WardOS .*✓ Update.*reboot you choose'
assert_not_logged 'notify-send .*-u critical'
export BOOTC_CHECK_FAIL="ERROR Fetching manifest: dial tcp: lookup quay.io: no such host"
: >"$MOCK_LOG"
run
assert_rc 3
assert_logged '^notify-send -a WardOS -u critical Update network-unavailable: '
assert_not_logged '✓ Update'
assert_logged '^flatpak update -y$'
assert_no_line "no update"
unset BOOTC_CHECK_FAIL

# --check is unchanged when bootc answers.
run --check
assert_eq "$out" '{"text": "update", "tooltip": "Update available for: quay.io/hexrift/wardos:latest", "class": "available"}'
exit 0
