#!/usr/bin/env bash
# The Fedora half of the desktop capture (.github/workflows/desktop-capture.yml), run as
# root in a fedora:<release> container that docker gave the host's virtual DRM node
# (--device /dev/dri; vgem or vkms, loaded on the runner): the COPRs of image/coprs.txt
# and the packages of desktop/capture/packages.txt, the tree placed by
# image/install-desktop.sh, the checkout's ward binaries in /usr/bin, the unprivileged
# user `wardos` with access to the node, then capture.sh as that user.
#
#   desktop/capture/ci-run.sh BINARIES OUT
#
# BINARIES holds ward, wardd, ward-shell and wardos-theme-render; OUT receives what
# capture.sh writes. OUT is handed back to HOST_UID:HOST_GID (the runner's user) and made
# readable on the way out, failed or not, so the host can upload it.
set -euo pipefail

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; }
die() {
  echo "ci-run.sh: $*" >&2
  exit 1
}
case "${1:-}" in
  -h | --help) usage; exit 0 ;;
esac
[[ $# -eq 2 ]] || { usage >&2; exit 2; }
[[ $(id -u) -eq 0 ]] || die "runs as root in the capture container"

root=$(cd "$(dirname "$0")/../.." && pwd)
bins=$(cd "$1" && pwd)
mkdir -p "$2"
out=$(cd "$2" && pwd)

hand_back() {
  chown -R "${HOST_UID:-0}:${HOST_GID:-0}" "$out" 2>/dev/null || true
  chmod -R a+rX "$out" 2>/dev/null || true
}
trap hand_back EXIT

shopt -s nullglob
nodes=(/dev/dri/*)
shopt -u nullglob
[[ ${#nodes[@]} -gt 0 ]] || die "no /dev/dri in the container; docker run needs --device /dev/dri"

# shellcheck source=image/dnf-retry.sh disable=SC1091
source "$root/image/dnf-retry.sh"
retry 3 5 dnf -y -q install dnf5-plugins
while read -r copr; do
  retry 3 5 dnf -y -q copr enable "$copr"
done < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$root/image/coprs.txt")
mapfile -t pkgs < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$root/desktop/capture/packages.txt")
retry 3 5 dnf -y --setopt=install_weak_deps=False install "${pkgs[@]}"
# eglinfo for capture.sh's failure output only; its absence costs a diagnostic, not the run.
retry 3 5 dnf -y -q --setopt=install_weak_deps=False install egl-utils ||
  echo "ci-run.sh: egl-utils not installed; the failure output goes without eglinfo" >&2
rpm -q hyprland aquamarine hyprlock waybar fuzzel mako foot grim mesa-dri-drivers | tee "$out/versions.txt"

"$root/image/install-desktop.sh" "$root/desktop" /
install -m 0755 "$bins"/ward "$bins"/wardd "$bins"/ward-shell "$bins"/wardos-theme-render /usr/bin/
id wardos >/dev/null 2>&1 || useradd -m -s /bin/bash wardos
# docker passes the nodes with the host's owner and mode (root:render, 0660 on Ubuntu);
# the session user opens them through the container's own copy of the node.
chmod 0666 "${nodes[@]}"
ls -l /dev/dri
chown wardos:wardos "$out"

runuser -u wardos -- env HOME=/home/wardos USER=wardos LANG=en_US.UTF-8 \
  GITHUB_ACTIONS="${GITHUB_ACTIONS:-}" "$root/desktop/capture/capture.sh" "$out"
