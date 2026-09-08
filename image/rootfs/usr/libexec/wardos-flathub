#!/usr/bin/env bash
# Add Flathub and install the desktop's default applications (image/README.md, "Flathub").
#
#   wardos-flathub [LIST]
#
# LIST is a file of Flatpak application ids, one per line, `#` comments and blank lines
# allowed; default /usr/share/wardos/flatpaks.txt (desktop/flatpaks.txt in the
# checkout). Missing list: only the remote is added. Ships as /usr/libexec/wardos-flathub
# and runs once from wardos-flathub.service after the first boot with a network.
set -euo pipefail

usage() {
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
}
case "${1:-}" in
  -h | --help) usage; exit 0 ;;
esac
list=${1:-/usr/share/wardos/flatpaks.txt}

flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo

if [[ ! -f "$list" ]]; then
  echo "wardos-flathub: no list at $list; Flathub added, nothing installed"
  exit 0
fi
mapfile -t ids < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$list")
if [[ ${#ids[@]} -eq 0 ]]; then
  echo "wardos-flathub: $list names no applications"
  exit 0
fi
echo "wardos-flathub: installing ${#ids[@]} applications from $list"
flatpak install -y --noninteractive flathub "${ids[@]}"
