#!/usr/bin/env bash
# Verify a published release manifest offline against WardOS's pinned release
# identity (ADR-0028 §2/§3, issue #148).
#
# Usage: verify-manifest.sh <manifest> <bundle> [options]
#
#   <manifest>   the downloaded wardos-<version>-manifest.json.
#   <bundle>     its Sigstore bundle, wardos-<version>-manifest.json.sigstore.json,
#                written by `cosign sign-blob --bundle` in the release workflow.
#
#   --tag <vX.Y.Z>          the release the caller meant to download; a manifest
#                           that names another release is refused (a validly
#                           signed manifest of an older release is still the
#                           wrong manifest for this one).
#   --require-artifacts     every artifact the manifest names must be present
#                           beside it; by default an absent artifact is reported
#                           and skipped, and only the present ones are checked.
#   --identity-policy k=v   override one pinned policy value for a fork that
#                           verifies its own releases: issuer=, repository= or
#                           workflow=. Repeatable. The default is WardOS's own
#                           pinned policy below; do not override it to make a
#                           WardOS release "verify".
#   --trusted-root <file>   a Sigstore trusted root (cosign --trusted-root) for
#                           a machine that cannot refresh cosign's TUF cache.
#
# What a pass proves: the manifest bytes were signed by the release workflow
# (.github/workflows/release.yml) of the pinned repository, running on the
# release tag the manifest itself names, with a certificate issued for GitHub
# Actions' OIDC issuer; and every artifact present beside the manifest has the
# digest the signed manifest records. It does not prove the tarballs were built
# reproducibly, and it says nothing about the boot chain (ADR-0028 §6).
#
# The expected signing identity is derived from the manifest's own `tag`:
#   https://github.com/<repository>/.github/workflows/<workflow>@refs/tags/<tag>
# and passed to cosign as an exact --certificate-identity, never a pattern, so a
# certificate for another tag, a branch, a pull request, another workflow or a
# literal `v*` cannot match the way a wildcard would (the same reconstruction
# crates/ward-release-verify/src/identity.rs performs; its unit tests hold the
# three pinned values below equal to the crate's constants). The tag is checked
# against the release tag grammar before the identity is derived from it.
#
# Why the signature failure is classified by re-running cosign rather than by
# reading its message: cosign's error text is not a contract. A first run with
# the pinned issuer and the exact identity decides pass/fail; on failure the
# bundle is re-checked against any identity and any issuer. If that also fails
# the signature does not cover these bytes (altered manifest, or a bundle that is
# not this manifest's); if it passes, the bytes are intact and only the identity
# or the issuer is wrong, and a third run with the pinned issuer alone tells which.
# Every cosign run here is a bundle verification: no Rekor or Fulcio call, only
# cosign's cached Sigstore trusted root (refreshed through TUF by cosign itself).
#
# Checks run in this order, stopping at the first failure:
#   1. the tools (cosign, jq, sha256sum) are installed;
#   2. the manifest parses and names a release tag (and the expected one);
#   3. the bundle exists;
#   4. the signature verifies for the pinned issuer and derived identity;
#   5. the manifest's own .sha256 sidecar, when present beside it, agrees;
#   6. every artifact present beside the manifest hashes to the digest the signed
#      manifest records (and its .sha256 sidecar, when present, agrees too).
#
# Output: one `verify-manifest: state=<state> ...` line on the final result, with
# ADR-0028's states -- `provenance-verified` on success, otherwise
# `verification-failed cause=<cause>` or `verifier-unavailable cause=<cause>` --
# and an actionable explanation. A verifier that cannot run never passes.
#
# Exit codes (one per cause, so a caller can act on them without parsing):
#   0   provenance-verified.
#   2   usage error, or the manifest is unreadable or malformed.
#   3   verifier-unavailable: cosign (or jq, sha256sum) is not installed.
#   4   provenance-missing: the bundle is absent or unreadable.
#   5   issuer-mismatch: the certificate was issued by another OIDC issuer.
#   6   identity-mismatch: the signer is not the pinned workflow on this tag.
#   7   manifest-altered: the bundle does not verify these manifest bytes.
#   8   digest-mismatch: the .sha256 sidecar or an artifact disagrees with the
#       signed manifest.
#   9   incomplete-set: --require-artifacts and a named artifact is absent.
#   10  wrong-release: the manifest names another release than --tag, or than
#       its own file name.
#   11  trusted-root-unavailable: cosign could not load the Sigstore trusted root.
set -euo pipefail

# ADR-0028 §2's pinned identity policy. These three literals are held equal to
# PINNED_ISSUER, PINNED_REPOSITORY and PINNED_WORKFLOW in
# crates/ward-release-verify/src/identity.rs by that crate's tests.
PINNED_ISSUER="https://token.actions.githubusercontent.com"
PINNED_REPOSITORY="hexrift/WardOS"
PINNED_WORKFLOW="release.yml"

COSIGN="${COSIGN:-cosign}"

usage="usage: verify-manifest.sh <manifest> <bundle> [--tag vX.Y.Z] [--require-artifacts] [--identity-policy k=v]... [--trusted-root file]"

# fail STATE EXIT CAUSE MESSAGE
fail() {
  local state="$1" code="$2" cause="$3"
  shift 3
  echo "verify-manifest: state=$state cause=$cause: $*" >&2
  exit "$code"
}
refuse() { fail verification-failed "$@"; }
unavailable() { fail verifier-unavailable "$@"; }
note() { echo "verify-manifest: $*"; }

manifest=""
bundle=""
expected_tag=""
require_artifacts=false
trusted_root=""
issuer="$PINNED_ISSUER"
repository="$PINNED_REPOSITORY"
workflow="$PINNED_WORKFLOW"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      [[ $# -ge 2 ]] || fail verification-failed 2 usage "--tag needs a value; $usage"
      expected_tag="$2"
      shift 2
      ;;
    --require-artifacts)
      require_artifacts=true
      shift
      ;;
    --identity-policy)
      [[ $# -ge 2 ]] || fail verification-failed 2 usage "--identity-policy needs key=value; $usage"
      case "$2" in
        issuer=*) issuer="${2#issuer=}" ;;
        repository=*) repository="${2#repository=}" ;;
        workflow=*) workflow="${2#workflow=}" ;;
        *) fail verification-failed 2 usage "--identity-policy takes issuer=, repository= or workflow=, not '$2'" ;;
      esac
      shift 2
      ;;
    --trusted-root)
      [[ $# -ge 2 ]] || fail verification-failed 2 usage "--trusted-root needs a file; $usage"
      trusted_root="$2"
      shift 2
      ;;
    -*)
      fail verification-failed 2 usage "unknown option '$1'; $usage"
      ;;
    *)
      if [[ -z "$manifest" ]]; then
        manifest="$1"
      elif [[ -z "$bundle" ]]; then
        bundle="$1"
      else
        fail verification-failed 2 usage "unexpected argument '$1'; $usage"
      fi
      shift
      ;;
  esac
done
[[ -n "$manifest" && -n "$bundle" ]] || fail verification-failed 2 usage "$usage"
for value in "$issuer" "$repository" "$workflow"; do
  [[ -n "$value" && ! "$value" =~ [[:space:]] ]] ||
    fail verification-failed 2 usage "an identity-policy value must be non-empty and contain no whitespace: '$value'"
done

# 1. The verifier itself. A missing cosign is the "verifier unavailable" state of
#    ADR-0028, never a pass: there is nothing a checksum alone could stand in for.
command -v jq >/dev/null 2>&1 || unavailable 3 jq-missing "jq is required to read the manifest"
command -v sha256sum >/dev/null 2>&1 || unavailable 3 sha256sum-missing "sha256sum is required to check digests"
command -v "$COSIGN" >/dev/null 2>&1 ||
  unavailable 3 cosign-missing "cosign is not installed (looked for '$COSIGN'); install it (https://github.com/sigstore/cosign) or set COSIGN, then verify again. Nothing has been verified."

# 2. The manifest: readable, valid JSON, a release tag, consistent with itself and
#    with what the caller asked for. All of this is read from still-unverified
#    bytes, so nothing is trusted yet; the tag only decides which exact identity
#    the signature must have been made under.
[[ -f "$manifest" && -r "$manifest" ]] || fail verification-failed 2 malformed-manifest "manifest '$manifest' is not a readable file"
jq -e . "$manifest" >/dev/null 2>&1 || fail verification-failed 2 malformed-manifest "manifest '$manifest' is not valid JSON"
tag="$(jq -r '.tag // empty' "$manifest")"
version="$(jq -r '.version // empty' "$manifest")"
[[ -n "$tag" ]] || fail verification-failed 2 malformed-manifest "manifest '$manifest' has no tag"
# The release tag grammar of check-version.sh and generate-manifest.sh, anchored
# end to end: anything else -- `v*`, a branch name, a bare version -- is refused
# here, before an identity is derived from it.
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  fail verification-failed 2 malformed-manifest "manifest tag '$tag' is not a v<semver> release tag"
fi
[[ "$version" == "${tag#v}" ]] ||
  fail verification-failed 2 malformed-manifest "manifest version '$version' does not match its tag '$tag'"
jq -e '.artifacts | type == "array"' "$manifest" >/dev/null 2>&1 ||
  fail verification-failed 2 malformed-manifest "manifest '$manifest' has no artifacts array"
if ! jq -e '.artifacts | all(.name | type == "string" and length > 0 and (contains("/") | not))
                       and all(.digest | type == "string" and test("^sha256:[0-9a-f]{64}$"))' \
  "$manifest" >/dev/null 2>&1; then
  fail verification-failed 2 malformed-manifest "manifest '$manifest' names an artifact without a plain file name or a sha256:<hex> digest"
fi

if [[ -n "$expected_tag" && "$tag" != "$expected_tag" ]]; then
  refuse 10 wrong-release "manifest names release '$tag', not the expected '$expected_tag'; download the manifest and bundle of the release you meant"
fi
manifest_name="$(basename "$manifest")"
if [[ "$manifest_name" == wardos-*-manifest.json ]]; then
  file_version="${manifest_name#wardos-}"
  file_version="${file_version%-manifest.json}"
  [[ "$file_version" == "$version" ]] ||
    refuse 10 wrong-release "file name '$manifest_name' says version '$file_version' but the manifest inside names '$version'; the two assets were mixed up or the manifest was substituted"
fi

# 3. The bundle. Absent or unreadable provenance is its own failure, distinct from
#    a signature that does not verify.
[[ -f "$bundle" && -r "$bundle" ]] ||
  refuse 4 provenance-missing "bundle '$bundle' is not a readable file; download '$manifest_name.sigstore.json' from the same release (a release without one was published before the manifest was signed, or by a run that was not on its tag -- see docs/release-manifest.md)"
jq -e . "$bundle" >/dev/null 2>&1 ||
  refuse 4 provenance-missing "bundle '$bundle' is not a JSON Sigstore bundle"
if [[ -n "$trusted_root" && ! -r "$trusted_root" ]]; then
  fail verification-failed 2 usage "trusted root '$trusted_root' is not a readable file"
fi

# 4. The signature, against the exact identity for this manifest's tag.
expected_identity="https://github.com/${repository}/.github/workflows/${workflow}@refs/tags/${tag}"

cosign_log="$(mktemp)"
trap 'rm -f "$cosign_log"' EXIT

# cosign_verify ARGS... -> runs `cosign verify-blob --bundle <bundle> ARGS... <manifest>`
# quietly, keeping stderr in $cosign_log for the trusted-root check.
cosign_verify() {
  local args=(verify-blob --bundle "$bundle")
  [[ -n "$trusted_root" ]] && args+=(--trusted-root "$trusted_root")
  "$COSIGN" "${args[@]}" "$@" "$manifest" >/dev/null 2>"$cosign_log"
}

if ! cosign_verify --certificate-identity "$expected_identity" --certificate-oidc-issuer "$issuer"; then
  # A trusted root cosign could not load is not a verdict about the manifest.
  # Best effort, from cosign's message: it only ever reclassifies a failure,
  # never turns one into a pass.
  if grep -q -E '(^|[^A-Za-z])(TUF|tuf)([^A-Za-z]|$)|trusted[ _-]?root' "$cosign_log"; then
    unavailable 11 trusted-root-unavailable "cosign could not load the Sigstore trusted root ($(tr '\n' ' ' <"$cosign_log" | sed -E 's/[[:space:]]+$//')); refresh it (cosign initialize) or pass --trusted-root, then verify again. Nothing has been verified."
  fi
  if ! cosign_verify --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*'; then
    refuse 7 manifest-altered "the bundle does not verify these manifest bytes under any identity: '$manifest' was altered after it was signed, or '$bundle' is not its bundle; download both again from the release"
  fi
  if cosign_verify --certificate-identity-regexp '.*' --certificate-oidc-issuer "$issuer"; then
    refuse 6 identity-mismatch "the signature is valid but was not made by '$expected_identity' (issuer '$issuer'): the manifest was signed by another repository, workflow, ref or tag; do not install from it"
  fi
  refuse 5 issuer-mismatch "the signature is valid but its certificate was not issued by '$issuer': the manifest was not signed from GitHub Actions' OIDC issuer; do not install from it"
fi
note "signature OK: '$manifest_name' was signed by $expected_identity (issuer $issuer)"

# 5. The manifest's own sidecar. The signature already covers the bytes; the
#    sidecar is checked so `sha256sum -c` next to it cannot disagree with this
#    verifier about the same file.
manifest_digest="$(sha256sum "$manifest" | awk '{print $1}')"
if [[ -f "$manifest.sha256" ]]; then
  sidecar_digest="$(awk '{print $1; exit}' "$manifest.sha256")"
  [[ "$sidecar_digest" == "$manifest_digest" ]] ||
    refuse 8 digest-mismatch "'$manifest_name.sha256' records $sidecar_digest but the signed manifest hashes to $manifest_digest; the sidecar is not this manifest's"
  note "sidecar OK: '$manifest_name.sha256' agrees"
else
  note "no '$manifest_name.sha256' beside the manifest; the signature covers its bytes"
fi

# 6. The artifacts beside the manifest, against the digests the signed manifest
#    records. Only the manifest is signed; a tarball is trusted exactly as far as
#    its digest is in it.
dir="$(dirname "$manifest")"
checked=0
absent=()
while IFS=$'\t' read -r name digest; do
  path="$dir/$name"
  hex="${digest#sha256:}"
  if [[ ! -f "$path" ]]; then
    absent+=("$name")
    continue
  fi
  actual="$(sha256sum "$path" | awk '{print $1}')"
  [[ "$actual" == "$hex" ]] ||
    refuse 8 digest-mismatch "'$name' hashes to $actual but the signed manifest records $hex; the artifact was altered or is from another release"
  if [[ -f "$path.sha256" ]]; then
    recorded="$(awk '{print $1; exit}' "$path.sha256")"
    [[ "$recorded" == "$hex" ]] ||
      refuse 8 digest-mismatch "'$name.sha256' records $recorded but the signed manifest records $hex; the sidecar is not this artifact's"
  fi
  note "artifact OK: '$name'"
  checked=$((checked + 1))
done < <(jq -r '.artifacts[] | [.name, .digest] | @tsv' "$manifest")

if [[ ${#absent[@]} -gt 0 ]]; then
  if [[ "$require_artifacts" == true ]]; then
    refuse 9 incomplete-set "${#absent[@]} artifact(s) the signed manifest names are not beside it: ${absent[*]}; download the complete set before installing"
  fi
  note "${#absent[@]} artifact(s) not present beside the manifest, not checked: ${absent[*]}"
fi

note "state=provenance-verified: '$manifest_name' ($tag) was signed by $expected_identity; $checked artifact(s) digest-checked, ${#absent[@]} absent"
