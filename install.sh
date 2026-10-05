#!/usr/bin/env bash
# WardOS installer for an existing Linux host.
#
#   curl -fsSL https://raw.githubusercontent.com/hexrift/WardOS/main/install.sh | bash
#   ./install.sh                      # from an unpacked release tarball
#   ./install.sh --prefix /usr/local  # system-wide (needs write access)
#   ./install.sh --require-provenance # refuse anything short of a verified release
#
# Installs ward, wardd and ward-agent, checks for bubblewrap, and runs
# `ward doctor`. Nothing is written outside the prefix and ~/.local/state/ward.
# The release tarball is the one for this machine's architecture (`uname -m`):
# x86_64, or aarch64 from v0.3.
#
# Before it installs a downloaded release it verifies the release against its
# signed manifest (ADR-0028 §5, docs/release-manifest.md) and prints each state
# it reaches, in the ADR's words, so a log shows what was proven:
#
#   downloaded            the manifest, its .sha256 and its Sigstore bundle, then
#                         the tarball and its .sha256
#   digest-checked        the .sha256 sidecars agree with the bytes, and the
#                         tarball hashes to the digest the manifest records for it
#   provenance-verified   scripts/release/verify-manifest.sh of the release's own
#                         tag passed: the manifest was signed by the release
#                         workflow on this tag, and the tarball is in it
#   provenance-missing    the release has no manifest (every release up to
#                         v0.4.1) or no bundle (published from a branch); the
#                         install goes on checksum-only, said out loud
#   verifier-unavailable  cosign is not installed, the verifier could not be
#                         fetched, or cosign has no Sigstore trusted root; the
#                         install goes on checksum-only, said out loud
#   verification-failed   the manifest or the tarball does not hold up; nothing
#                         is installed
#
# The last line is `install: <state reached>`. A checksum-only install is never
# called verified; --require-provenance turns both checksum-only states into
# refusals. The verifier is fetched from the repository at the release tag, the
# same channel this script arrives through, not from the tarball it checks.
#
# Exit codes (one per cause, so a caller can act on them without parsing):
#   0   installed.
#   1   no such release, no tarball for this architecture, a download failed, or
#       the host cannot run WardOS.
#   2   usage error.
#   3   verifier-unavailable, refused by --require-provenance.
#   4   provenance-missing, refused by --require-provenance.
#   5   issuer-mismatch, 6 identity-mismatch, 7 manifest-altered, 10 wrong-release,
#       11 trusted-root-unavailable (with --require-provenance): the verifier's
#       verdicts, under its own exit codes (scripts/release/verify-manifest.sh).
#   8   digest-mismatch: a .sha256 sidecar, or the tarball against the manifest.
#   12  malformed-manifest: the verifier could not read the manifest.
set -euo pipefail

REPO="hexrift/WardOS"
PREFIX="${HOME}/.local"
VERSION="latest"
REQUIRE_PROVENANCE=false
TRUSTED_ROOT=""
COSIGN="${COSIGN:-cosign}"
ARCH="$(uname -m)"
# Some kernels report arm64 for aarch64; the tarballs use the Fedora and rustc name.
[ "$ARCH" != "arm64" ] || ARCH="aarch64"

usage() {
  cat <<USAGE
usage: install.sh [--prefix DIR] [--version vX.Y.Z] [--require-provenance] [--trusted-root FILE]
  --prefix              install binaries under DIR/bin (default: ~/.local)
  --version             release tag to install (default: latest)
  --require-provenance  refuse to install unless the release verifies as
                        provenance-verified (default: a release without a signed
                        manifest, or a host without cosign, installs checksum-only)
  --trusted-root        a Sigstore trusted root for cosign, for a machine that
                        cannot refresh its TUF cache (passed to the verifier)
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --require-provenance) REQUIRE_PROVENANCE=true; shift ;;
    --trusted-root) TRUSTED_ROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "install.sh: unknown option $1" >&2; usage; exit 2 ;;
  esac
done

if [ "$(uname -s)" != "Linux" ]; then
  echo "install.sh: WardOS runs on Linux only (macOS: use a Linux VM)" >&2
  exit 1
fi
case "$ARCH" in
  x86_64 | aarch64) ;;
  *) echo "install.sh: no release binaries for $ARCH (x86_64 and aarch64 only); build from source with cargo" >&2; exit 1 ;;
esac
if [ -n "$TRUSTED_ROOT" ]; then
  [ -r "$TRUSTED_ROOT" ] || { echo "install.sh: --trusted-root $TRUSTED_ROOT is not a readable file" >&2; exit 2; }
  # The verifier runs inside the download directory; the root must still resolve.
  TRUSTED_ROOT="$(readlink -f "$TRUSTED_ROOT")"
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
bindir="${PREFIX}/bin"
mkdir -p "$bindir"

# The state the install reached, for the last line.
outcome=""

install_from() {
  local dir="$1"
  for bin in ward wardd ward-agent; do
    install -m 0755 "${dir}/${bin}" "${bindir}/${bin}"
  done
  echo "installed ward, wardd, ward-agent -> ${bindir}"
}

# refuse CODE CAUSE MESSAGE: a verification failure. Nothing has been installed.
refuse() {
  local code="$1" cause="$2"
  shift 2
  echo "install.sh: verification-failed ($cause): $*; nothing was installed" >&2
  exit "$code"
}
# checksum_only STATE CODE CAUSE MESSAGE: provenance could not be verified. Loud,
# and a refusal under --require-provenance; otherwise the install goes on with
# the checksums alone, and the last line says so.
checksum_only() {
  local state="$1" code="$2" cause="$3"
  shift 3
  if [ "$REQUIRE_PROVENANCE" = true ]; then
    echo "install.sh: $state ($cause): $*; refusing to install (--require-provenance)" >&2
    exit "$code"
  fi
  echo "install.sh: $state ($cause): $*; provenance NOT verified, proceeding checksum-only" >&2
  outcome="checksum-only ($state: $cause)"
}

if [ -x "${here}/ward" ] && [ -x "${here}/wardd" ] && [ -x "${here}/ward-agent" ]; then
  install_from "$here"
  outcome="unverified (the files beside install.sh; check the tarball first, docs/install.md §1)"
else
  command -v curl >/dev/null || { echo "install.sh: curl is required to download a release" >&2; exit 1; }
  # A private repository needs a token (GITHUB_TOKEN or GH_TOKEN) with contents:read;
  # with one, assets are fetched through the API, which works for public repos too.
  token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
  auth=()
  [ -n "$token" ] && auth=(-H "Authorization: Bearer ${token}")
  api="https://api.github.com/repos/${REPO}/releases"
  if [ "$VERSION" = "latest" ]; then
    release="$(curl -fsSL "${auth[@]}" "${api}/latest")" || release=""
  else
    release="$(curl -fsSL "${auth[@]}" "${api}/tags/${VERSION}")" || release=""
  fi
  [ -n "$release" ] || { echo "install.sh: could not fetch release ${VERSION} from GitHub (no such release, no network, or a private repository: set GITHUB_TOKEN)" >&2; exit 1; }
  VERSION="$(printf '%s' "$release" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$VERSION" ] || { echo "install.sh: could not resolve release ${VERSION:-latest} (private repository? set GITHUB_TOKEN)" >&2; exit 1; }
  name="wardos-${VERSION#v}-${ARCH}-linux"
  has_asset() { printf '%s' "$release" | grep -q "\"name\": *\"$1\""; }
  if ! has_asset "${name}.tar.gz"; then
    echo "install.sh: release ${VERSION} has no ${ARCH} tarball (aarch64 ships from v0.3); build from source with cargo" >&2
    exit 1
  fi
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  fetch_asset() {
    # $1 asset file name, $2 destination; by API id so private assets download too.
    local id
    id="$(printf '%s' "$release" | tr -d '\n' | sed -n "s/.*\"url\": *\"[^\"]*\/releases\/assets\/\([0-9]*\)\",[^}]*\"name\": *\"$1\".*/\1/p" | head -1)"
    if [ -n "$id" ]; then
      curl -fsSL "${auth[@]}" -H "Accept: application/octet-stream" -o "$2" "${api}/assets/${id}"
    else
      curl -fsSL "${auth[@]}" -o "$2" "https://github.com/${REPO}/releases/download/${VERSION}/$1"
    fi
  }

  # The manifest first, with its sidecar and its bundle, when the release has them
  # (docs/release-manifest.md). Nothing in it is trusted until the verifier has
  # passed; until then it only says which bytes the tarball should have.
  manifest="wardos-${VERSION#v}-manifest.json"
  bundle="${manifest}.sigstore.json"
  have_manifest=false
  have_bundle=false
  if has_asset "$manifest"; then
    have_manifest=true
    fetch_asset "$manifest" "${tmp}/${manifest}"
    fetch_asset "${manifest}.sha256" "${tmp}/${manifest}.sha256"
    if has_asset "$bundle"; then
      have_bundle=true
      fetch_asset "$bundle" "${tmp}/${bundle}"
      echo "downloaded ${manifest}, its .sha256 and its Sigstore bundle from release ${VERSION}"
    else
      echo "downloaded ${manifest} and its .sha256 from release ${VERSION} (no Sigstore bundle)"
    fi
    (cd "$tmp" && sha256sum -c "${manifest}.sha256" >/dev/null 2>&1) ||
      refuse 8 digest-mismatch "${manifest}.sha256 does not match ${manifest}"
    echo "digest-checked (manifest): ${manifest}.sha256 agrees"
  fi

  echo "downloading ${name}.tar.gz from release ${VERSION}"
  fetch_asset "${name}.tar.gz" "${tmp}/${name}.tar.gz"
  fetch_asset "${name}.tar.gz.sha256" "${tmp}/${name}.tar.gz.sha256"
  (cd "$tmp" && sha256sum -c "${name}.tar.gz.sha256" >/dev/null 2>&1) ||
    refuse 8 digest-mismatch "${name}.tar.gz.sha256 does not match ${name}.tar.gz"
  echo "digest-checked (tarball): ${name}.tar.gz.sha256 agrees"

  # The tarball against the digest the manifest records for it, by name. The
  # manifest (schema 1, docs/release-manifest.md) writes each artifact's name
  # before its digest, so no jq is needed; the verifier re-checks the same bytes
  # with jq when it runs, and this check is the only one when it cannot.
  if [ "$have_manifest" = true ]; then
    recorded="$(tr -d '\n' <"${tmp}/${manifest}" | sed -n "s/.*\"name\": *\"${name}.tar.gz\"[^}]*\"digest\": *\"sha256:\([0-9a-f]\{64\}\)\".*/\1/p")"
    [ -n "$recorded" ] || refuse 10 wrong-release "${manifest} does not name ${name}.tar.gz; it is another release's manifest, or the release set is incomplete"
    actual="$(sha256sum "${tmp}/${name}.tar.gz" | awk '{print $1}')"
    [ "$actual" = "$recorded" ] || refuse 8 digest-mismatch "${name}.tar.gz hashes to ${actual} but ${manifest} records ${recorded}"
    echo "digest-checked (tarball): ${manifest} agrees"
  fi

  # Provenance: the verifier of the release's own tag, against the pinned identity.
  # Its verdicts keep their causes and exit codes; "unavailable" is never a pass.
  fetch_verifier() {
    # $1 destination. From the repository at the release tag: the channel this
    # script arrives through, not the tarball it is about to check.
    local path="scripts/release/verify-manifest.sh"
    if [ -n "$token" ]; then
      curl -fsSL "${auth[@]}" -H "Accept: application/vnd.github.raw+json" -o "$1" \
        "https://api.github.com/repos/${REPO}/contents/${path}?ref=${VERSION}"
    else
      curl -fsSL -o "$1" "https://raw.githubusercontent.com/${REPO}/${VERSION}/${path}"
    fi
  }
  if [ "$have_manifest" = false ]; then
    checksum_only provenance-missing 4 no-manifest "release ${VERSION} has no signed manifest; it predates the signing step (v0.4.1 and earlier)"
  elif [ "$have_bundle" = false ]; then
    checksum_only provenance-missing 4 no-bundle "release ${VERSION} has a manifest but no Sigstore bundle; it was published by a run that was not on its tag (docs/release-manifest.md)"
  elif ! command -v "$COSIGN" >/dev/null; then
    checksum_only verifier-unavailable 3 cosign-missing "cosign is not installed (looked for '$COSIGN'); install it (https://github.com/sigstore/cosign) to verify the release"
  elif ! fetch_verifier "${tmp}/verify-manifest.sh"; then
    checksum_only verifier-unavailable 3 verifier-not-fetched "could not fetch scripts/release/verify-manifest.sh at ${VERSION} from the repository"
  else
    verifier_args=(--tag "$VERSION")
    [ -z "$TRUSTED_ROOT" ] || verifier_args+=(--trusted-root "$TRUSTED_ROOT")
    verdict=0
    (cd "$tmp" && COSIGN="$COSIGN" bash verify-manifest.sh "$manifest" "$bundle" "${verifier_args[@]}") || verdict=$?
    case "$verdict" in
      0)
        echo "provenance-verified: ${manifest} was signed by the release workflow on ${VERSION}, and ${name}.tar.gz is in it"
        outcome="provenance-verified"
        ;;
      2) refuse 12 malformed-manifest "the verifier could not read ${manifest} (see above)" ;;
      3) checksum_only verifier-unavailable 3 tools-missing "the verifier needs jq and sha256sum (see above)" ;;
      4) checksum_only provenance-missing 4 no-bundle "the verifier found no usable bundle (see above)" ;;
      5) refuse 5 issuer-mismatch "the signature's certificate was not issued for GitHub Actions (see above)" ;;
      6) refuse 6 identity-mismatch "the manifest was not signed by ${REPO}'s release workflow on ${VERSION} (see above)" ;;
      7) refuse 7 manifest-altered "the bundle does not verify these manifest bytes (see above)" ;;
      8) refuse 8 digest-mismatch "the tarball or a sidecar disagrees with the signed manifest (see above)" ;;
      10) refuse 10 wrong-release "the manifest is not release ${VERSION}'s (see above)" ;;
      11) checksum_only verifier-unavailable 11 trusted-root-unavailable "cosign could not load the Sigstore trusted root (cosign initialize, or --trusted-root)" ;;
      *) refuse 1 verifier-failed "the verifier exited ${verdict} (see above)" ;;
    esac
  fi

  tar -C "$tmp" -xzf "${tmp}/${name}.tar.gz"
  install_from "${tmp}/${name}"
fi

case ":$PATH:" in
  *":${bindir}:"*) ;;
  *) echo "note: add ${bindir} to your PATH" ;;
esac

if ! command -v bwrap >/dev/null; then
  echo
  echo "bubblewrap is not installed. Install it with one of:"
  echo "  sudo apt install bubblewrap        # Debian, Ubuntu"
  echo "  sudo dnf install bubblewrap        # Fedora"
  echo "  sudo pacman -S bubblewrap          # Arch"
fi

echo
"${bindir}/ward" doctor || true
echo "install: ${outcome}"
