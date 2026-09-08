#!/usr/bin/env bash
# WardOS installer for an existing Linux host.
#
#   curl -fsSL https://raw.githubusercontent.com/hexrift/WardOS/main/install.sh | bash
#   ./install.sh                      # from an unpacked release tarball
#   ./install.sh --prefix /usr/local  # system-wide (needs write access)
#
# Installs ward, wardd and ward-agent, checks for bubblewrap, and runs
# `ward doctor`. Nothing is written outside the prefix and ~/.local/state/ward.
set -euo pipefail

REPO="hexrift/WardOS"
PREFIX="${HOME}/.local"
VERSION="latest"
ARCH="$(uname -m)"

usage() {
  cat <<USAGE
usage: install.sh [--prefix DIR] [--version vX.Y.Z]
  --prefix   install binaries under DIR/bin (default: ~/.local)
  --version  release tag to install (default: latest)
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "install.sh: unknown option $1" >&2; usage; exit 2 ;;
  esac
done

if [ "$(uname -s)" != "Linux" ]; then
  echo "install.sh: WardOS runs on Linux only (macOS: use a Linux VM)" >&2
  exit 1
fi
if [ "$ARCH" != "x86_64" ]; then
  echo "install.sh: no release binaries for $ARCH yet; build from source with cargo" >&2
  exit 1
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
bindir="${PREFIX}/bin"
mkdir -p "$bindir"

install_from() {
  local dir="$1"
  for bin in ward wardd ward-agent; do
    install -m 0755 "${dir}/${bin}" "${bindir}/${bin}"
  done
  echo "installed ward, wardd, ward-agent -> ${bindir}"
}

if [ -x "${here}/ward" ] && [ -x "${here}/wardd" ] && [ -x "${here}/ward-agent" ]; then
  install_from "$here"
else
  command -v curl >/dev/null || { echo "install.sh: curl is required to download a release" >&2; exit 1; }
  # A private repository needs a token (GITHUB_TOKEN or GH_TOKEN) with contents:read;
  # with one, assets are fetched through the API, which works for public repos too.
  token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
  auth=()
  [ -n "$token" ] && auth=(-H "Authorization: Bearer ${token}")
  api="https://api.github.com/repos/${REPO}/releases"
  if [ "$VERSION" = "latest" ]; then
    release="$(curl -fsSL "${auth[@]}" "${api}/latest")"
  else
    release="$(curl -fsSL "${auth[@]}" "${api}/tags/${VERSION}")"
  fi
  VERSION="$(printf '%s' "$release" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$VERSION" ] || { echo "install.sh: could not resolve release ${VERSION:-latest} (private repository? set GITHUB_TOKEN)" >&2; exit 1; }
  name="wardos-${VERSION#v}-x86_64-linux"
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
  echo "downloading ${name}.tar.gz from release ${VERSION}"
  fetch_asset "${name}.tar.gz" "${tmp}/${name}.tar.gz"
  fetch_asset "${name}.tar.gz.sha256" "${tmp}/${name}.tar.gz.sha256"
  (cd "$tmp" && sha256sum -c "${name}.tar.gz.sha256" >/dev/null) || { echo "install.sh: checksum mismatch" >&2; exit 1; }
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
