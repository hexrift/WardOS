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
  if [ "$VERSION" = "latest" ]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$VERSION" ] || { echo "install.sh: could not resolve the latest release" >&2; exit 1; }
  fi
  name="wardos-${VERSION#v}-x86_64-linux"
  url="https://github.com/${REPO}/releases/download/${VERSION}/${name}.tar.gz"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  echo "downloading ${url}"
  curl -fsSL -o "${tmp}/${name}.tar.gz" "$url"
  curl -fsSL -o "${tmp}/${name}.tar.gz.sha256" "${url}.sha256"
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
