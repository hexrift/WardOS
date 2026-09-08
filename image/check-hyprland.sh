#!/usr/bin/env bash
# Parse desktop/hyprland/*.conf with the Hyprland the image ships (docs/desktop.md):
# inside a quay.io/fedora/fedora:<release> container with the COPRs of image/coprs.txt,
# install hyprland and run `Hyprland --verify-config` on the tree, with a rendered
# theme fragment in place so the last `source` resolves. Fails on any config error,
# which is what a booted image would show in its red error bar. The release comes from
# the Containerfile's FROM line, like check-packages.sh. --dry-run prints the command.
#
#   image/check-hyprland.sh [--dry-run]
set -euo pipefail

usage() {
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
}

repo_root=$(cd "$(dirname "$0")/.." && pwd)
release=$(sed -n 's|^FROM quay.io/fedora/fedora-bootc:\([0-9][0-9]*\)$|\1|p' "$repo_root/image/Containerfile" | head -n 1)
dry_run=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "check-hyprland.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
if [[ ! "$release" =~ ^[0-9]+$ ]]; then
  echo "check-hyprland.sh: no fedora-bootc:<release> FROM line in image/Containerfile" >&2
  exit 1
fi

runtime=${CONTAINER_RUNTIME:-}
if [[ -z "$runtime" ]]; then
  if command -v docker >/dev/null 2>&1; then runtime=docker; else runtime=podman; fi
fi
mapfile -t coprs < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$repo_root/image/coprs.txt")

# What runs inside the container: enable the COPRs, install hyprland, lay the tree out
# as the image does (/etc/xdg/hypr → the tree), render the theme fragment the last
# `source` line wants (the fragment's shape is what matters, so a stand-in with the
# same keys is enough), then verify.
# shellcheck disable=SC2016  # $@ and $HOME expand inside the container's bash
inner='set -e
dnf -y -q install dnf5-plugins >/dev/null
for c in "$@"; do dnf -y -q copr enable "$c" >/dev/null; done
dnf -y -q --setopt=install_weak_deps=False install hyprland >/dev/null
export XDG_RUNTIME_DIR=/tmp/xdg && mkdir -m 700 -p "$XDG_RUNTIME_DIR"
Hyprland --version | head -n 1
mkdir -p /etc/xdg && ln -sfn /desktop/hyprland /etc/xdg/hypr
mkdir -p "$HOME/.config/wardos/theme/current"
printf "general {\n  col.active_border = rgb(7FA1C3)\n  col.inactive_border = rgb(24272B)\n}\nmisc {\n  background_color = rgb(0E0F11)\n}\n" \
  > "$HOME/.config/wardos/theme/current/hyprland.conf"
Hyprland --verify-config -c /etc/xdg/hypr/hyprland.conf'
cmd=("$runtime" run --rm
  --volume "$repo_root/desktop:/desktop:ro"
  --env HOME=/root
  "quay.io/fedora/fedora:${release}"
  bash -c "$inner" -- "${coprs[@]}")

echo "check-hyprland.sh: Fedora ${release}, COPRs: ${coprs[*]:-none}; would run:"
printf '  %q' "${cmd[@]}"; printf '\n'
if [[ $dry_run -eq 1 ]]; then exit 0; fi
exec "${cmd[@]}"
