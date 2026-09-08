#!/usr/bin/env bash
# Apply the WardOS desktop to an existing Fedora (docs/desktop.md §Layout, ADR-0016).
#
#   desktop/install.sh [--autologin] [--no-flatpaks] [--destdir DIR] [--dry-run]
#
# Steps, each printed before it runs: enable the COPRs of image/coprs.txt (dnf5-plugins
# and `dnf copr enable`, or their .repo files into /etc/yum.repos.d on rpm-ostree) and
# install image/packages.txt with dnf (Workstation) or rpm-ostree (Silverblue, Kinoite,
# bootc: layered, takes effect after a reboot);
# place the desktop tree with image/install-desktop.sh (sudo); enable the user units;
# add Flathub and install desktop/flatpaks.txt (--no-flatpaks skips); then say how to
# start Hyprland. --autologin also installs the tty1 autologin drop-in for the user
# `wardos`, which the image has and a Fedora with a display manager should not.
# --destdir installs the tree somewhere other than / (staging, tests). --dry-run prints
# every command and runs none. Root is asked for with sudo, per step, never for the
# whole script.
set -euo pipefail

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
}

repo_root=$(cd "$(dirname "$0")/.." && pwd)
packages_file=$repo_root/image/packages.txt
coprs_file=$repo_root/image/coprs.txt
flatpaks_file=$repo_root/desktop/flatpaks.txt
# The file that marks an rpm-ostree/bootc host; overridable for tests.
ostree_marker=${WARDOS_OSTREE_MARKER:-/run/ostree-booted}

autologin=0
flatpaks=1
destdir=/
dry_run=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --autologin) autologin=1; shift ;;
    --no-flatpaks) flatpaks=0; shift ;;
    --destdir) destdir=$2; shift 2 ;;
    --destdir=*) destdir=${1#--destdir=}; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "install.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  if [[ $dry_run -eq 0 ]]; then "$@"; fi
}

# --- 1. packages ----------------------------------------------------------------------
if [[ ! -f "$packages_file" ]]; then
  echo "install.sh: $packages_file not found; run from a WardOS checkout" >&2
  exit 1
fi
mapfile -t packages < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$packages_file")
coprs=()
if [[ -f "$coprs_file" ]]; then
  mapfile -t coprs < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$coprs_file")
fi
# The Fedora release the COPR repository files are for; 42 when not on Fedora (tests).
fedora_release=42
if grep -qs '^ID=fedora$' /etc/os-release; then
  fedora_release=$(sed -n 's/^VERSION_ID=//p' /etc/os-release)
fi

if command -v rpm-ostree >/dev/null 2>&1 && [[ -e "$ostree_marker" ]]; then
  flavour=ostree
  # rpm-ostree has no `copr` verb: the repository file is what `dnf copr enable` would
  # write, fetched from COPR itself (a .repo file, not a script).
  for c in "${coprs[@]}"; do
    run sudo curl -fsSL -o "/etc/yum.repos.d/_copr_${c//\//-}.repo" \
      "https://copr.fedorainfracloud.org/coprs/${c}/repo/fedora-${fedora_release}/${c//\//-}-fedora-${fedora_release}.repo"
  done
  echo "install.sh: rpm-ostree host: layering ${#packages[@]} packages (a reboot applies them)"
  run sudo rpm-ostree install --idempotent "${packages[@]}"
elif command -v dnf >/dev/null 2>&1; then
  flavour=dnf
  if [[ ${#coprs[@]} -gt 0 ]]; then
    run sudo dnf -y install dnf5-plugins
    for c in "${coprs[@]}"; do
      run sudo dnf -y copr enable "$c"
    done
  fi
  echo "install.sh: installing ${#packages[@]} packages with dnf"
  run sudo dnf install -y "${packages[@]}"
else
  echo "install.sh: neither dnf nor rpm-ostree found; the desktop targets Fedora 42 (Workstation, Silverblue, Kinoite)" >&2
  exit 1
fi

# --- 2. the desktop tree --------------------------------------------------------------
install_args=()
[[ $autologin -eq 1 ]] || install_args+=(--no-autologin)
run sudo "$repo_root/image/install-desktop.sh" "${install_args[@]}" "$repo_root/desktop" "$destdir"

# --- 3. user units (the preset written by install-desktop.sh) -------------------------
units=()
for u in "$repo_root"/desktop/systemd/user/*; do
  [[ -f "$u" ]] && grep -q '^\[Install\]' "$u" && units+=("$(basename "$u")")
done
run systemctl --user daemon-reload
if [[ ${#units[@]} -gt 0 ]]; then
  run systemctl --user preset "${units[@]}"
fi

# --- 4. Flathub ----------------------------------------------------------------------
run sudo flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
if [[ $flatpaks -eq 1 && -f "$flatpaks_file" ]]; then
  mapfile -t ids < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$flatpaks_file")
  if [[ ${#ids[@]} -gt 0 ]]; then
    run sudo flatpak install -y --noninteractive flathub "${ids[@]}"
  fi
fi

# --- 5. how to log in -----------------------------------------------------------------
cat <<EOF

install.sh: done. To start the desktop:
  - at a display manager (GDM, SDDM): pick "Hyprland (uwsm)" in the session menu
  - from a text console:               uwsm start hyprland.desktop
  - first login runs wardos-first-run (configs, theme, keys); later: wardos-refresh
EOF
if [[ $flavour == ostree ]]; then
  echo "  - the layered packages are in the next deployment: reboot first (systemctl reboot)"
fi
