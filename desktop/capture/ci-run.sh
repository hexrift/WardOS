#!/usr/bin/env bash
# The Fedora half of the desktop capture (.github/workflows/desktop-capture.yml), run as
# root in a fedora:<release> container that docker gave the host's DRM nodes (--device
# /dev/dri, the vkms card among them, loaded on the runner): the COPRs of image/coprs.txt
# and the packages of desktop/capture/packages.txt, the tree placed by
# image/install-desktop.sh, the checkout's ward binaries in /usr/bin, the unprivileged
# user `wardos`, a seat for it (seatd, no VT, the socket owned by that user: aquamarine
# opens the card through libseat, and there is no logind here), a system bus (the
# classic dbus-daemon; dbus-broker's under systemd on the image), then capture.sh as
# that user, with the card the workflow chose (CAPTURE_DRM_CARD) or picking the vkms
# card itself.
#
#   desktop/capture/ci-run.sh BINARIES OUT
#
# BINARIES holds ward, wardd, ward-shell and wardos-theme-render; OUT receives what
# capture.sh writes and the logs of seatd and the system bus. OUT is handed back to
# HOST_UID:HOST_GID (the runner's user) and made readable on the way out, failed or
# not, so the host can upload it; seatd and the bus are stopped on the way out too.
set -euo pipefail

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; }
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

seatd_pid=""
dbus_pid=""
hand_back() {
  if [[ -n $seatd_pid ]]; then kill "$seatd_pid" 2>/dev/null || true; fi
  if [[ -n $dbus_pid ]]; then kill "$dbus_pid" 2>/dev/null || true; fi
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
rpm -q hyprland aquamarine hyprlock waybar fuzzel mako foot grim mesa-dri-drivers seatd | tee "$out/versions.txt"

"$root/image/install-desktop.sh" "$root/desktop" /
install -m 0755 "$bins"/ward "$bins"/wardd "$bins"/ward-shell "$bins"/wardos-theme-render /usr/bin/
id wardos >/dev/null 2>&1 || useradd -m -s /bin/bash wardos
# docker passes the nodes with the host's owner and mode (root:render, 0660 on Ubuntu);
# seatd opens the card for the session as root, and the open nodes let grim and Mesa
# at them directly.
chmod 0666 "${nodes[@]}"
ls -l /dev/dri
for card in /sys/class/drm/card*; do
  [[ -e $card/device ]] || continue
  echo "$(basename "$card"): $(basename "$(readlink -f "$card/device/driver" 2>/dev/null)" 2>/dev/null || echo '?') ($(readlink -f "$card/device"))"
done
echo "CAPTURE_DRM_CARD=${CAPTURE_DRM_CARD:-} (unset: capture.sh picks the ${CAPTURE_DRM_DRIVER:-vkms} card itself)"
chown wardos:wardos "$out"

# The system bus, at its default address (/run/dbus/system_bus_socket), with nothing on
# it: GTK and Waybar's bluetooth, network and battery modules ask it for BlueZ,
# NetworkManager and UPower and get "no such service" answers, as on a machine without
# them, instead of no bus at all (run 6: Waybar's last complaint before it went away was
# `Unable to connect to the SYSTEM Bus!`). The classic daemon's system.conf runs it as
# the `dbus` user, which the package's scriptlet creates; the machine id is its
# dbus-uuidgen's.
id dbus >/dev/null 2>&1 || useradd -r -s /sbin/nologin dbus
dbus-uuidgen --ensure
mkdir -p /run/dbus
rm -f /run/dbus/system_bus_socket /run/dbus/pid
dbus-daemon --system --nofork --nopidfile >"$out/dbus-system.log" 2>&1 &
dbus_pid=$!
for _ in $(seq 1 50); do
  [[ -S /run/dbus/system_bus_socket ]] && break
  kill -0 "$dbus_pid" 2>/dev/null || break
  sleep 0.2
done
[[ -S /run/dbus/system_bus_socket ]] || {
  cat "$out/dbus-system.log" >&2 || true
  die "the system bus did not open /run/dbus/system_bus_socket"
}
runuser -u wardos -- test -r /run/dbus/system_bus_socket -a -w /run/dbus/system_bus_socket || die "wardos cannot use the system bus socket"

# The seat: seatd as root, not bound to a VT (SEATD_VTBOUND=0; the container has no
# /dev/tty0 and nothing to switch), its socket owned by the session user. libseat in
# Hyprland is pointed at it (LIBSEAT_BACKEND=seatd) since there is no logind session.
sock=${SEATD_SOCK:-/run/seatd.sock}
rm -f "$sock"
SEATD_VTBOUND=0 seatd -u wardos -g wardos -l info >"$out/seatd.log" 2>&1 &
seatd_pid=$!
for _ in $(seq 1 50); do
  [[ -S $sock ]] && break
  kill -0 "$seatd_pid" 2>/dev/null || break
  sleep 0.2
done
[[ -S $sock ]] || {
  cat "$out/seatd.log" >&2 || true
  die "seatd did not open $sock"
}
ls -l "$sock"
runuser -u wardos -- test -r "$sock" -a -w "$sock" || die "wardos cannot use $sock"

runuser -u wardos -- env HOME=/home/wardos USER=wardos LANG=en_US.UTF-8 \
  LIBSEAT_BACKEND=seatd SEATD_SOCK="$sock" CAPTURE_DRM_DRIVER="${CAPTURE_DRM_DRIVER:-vkms}" \
  CAPTURE_DRM_CARD="${CAPTURE_DRM_CARD:-}" \
  GITHUB_ACTIONS="${GITHUB_ACTIONS:-}" \
  "$root/desktop/capture/capture.sh" "$out"
