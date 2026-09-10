#!/usr/bin/env bash
# Place the desktop tree (desktop/) into a root filesystem (docs/desktop.md §Layout).
#
#   image/install-desktop.sh SRC DESTDIR
#
# SRC is a checkout's desktop/ directory, DESTDIR the root to install into: "/" in the
# image build (Containerfile), "/" again from desktop/install.sh on an existing Fedora,
# a temp directory in desktop/tests/install.test.sh. Every part is optional: what SRC
# does not contain is skipped, so the script works while the tree is still being filled
# in. Login is greetd, set up by the image itself (image/rootfs/etc/greetd and the
# Containerfile), not here. Sources (shell/, theme/), tests/ and install.sh never land.
set -euo pipefail

usage() {
  sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
}

args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    -*) echo "install-desktop.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
if [[ ${#args[@]} -ne 2 ]]; then
  echo "install-desktop.sh: SRC and DESTDIR are required" >&2
  usage >&2
  exit 2
fi
src=${args[0]}
dest=${args[1]}
if [[ ! -d "$src" ]]; then
  echo "install-desktop.sh: $src is not a directory" >&2
  exit 1
fi
src=$(cd "$src" && pwd)
mkdir -p "$dest"
dest=$(cd "$dest" && pwd)

# Where each part goes (docs/desktop.md §Layout). Image-owned defaults live under
# /usr/share/wardos; /etc/xdg only carries links for the components that read
# XDG_CONFIG_DIRS themselves, so there is exactly one copy of every file.
share=/usr/share/wardos
xdg_components=(waybar foot mako fuzzel btop fastfetch)

say() { printf 'install-desktop: %s\n' "$*"; }

copy_tree() { # copy_tree SRC_DIR DEST_DIR
  mkdir -p "$dest$2"
  cp -R "$1/." "$dest$2/"
  say "$(basename "$1") → $2 ($(find "$1" -type f | wc -l) files)"
}

# link_or_fill NAME TARGET: make $dest/etc/xdg/NAME a link to TARGET (an absolute path
# on the installed system). An existing real directory, as on a Fedora that already
# ships a default there, is filled instead of replaced, so nothing of the host is lost.
link_or_fill() {
  local link="$dest/etc/xdg/$1"
  if [[ -d "$link" && ! -L "$link" ]]; then
    cp -R "$dest$2/." "$link/"
    say "/etc/xdg/$1 exists: filled from $2"
  else
    mkdir -p "$dest/etc/xdg"
    ln -sfn "$2" "$link"
    say "/etc/xdg/$1 → $2"
  fi
}

if [[ -d "$src/bin" ]]; then
  mkdir -p "$dest/usr/bin"
  n=0
  for f in "$src"/bin/*; do
    [[ -f "$f" ]] || continue
    install -m 0755 "$f" "$dest/usr/bin/$(basename "$f")"
    n=$((n + 1))
  done
  say "bin → /usr/bin ($n commands)"
fi

[[ -d "$src/lib" ]] && copy_tree "$src/lib" /usr/lib/wardos

if [[ -d "$src/hyprland" ]]; then
  copy_tree "$src/hyprland" "$share/hypr"
  # The directory, not the file: hyprland.conf sources ./keybindings.conf relative to
  # the path it was read from, which must therefore contain the siblings too.
  link_or_fill hypr "$share/hypr"
fi

if [[ -d "$src/config" ]]; then
  copy_tree "$src/config" "$share/config"
  for c in "${xdg_components[@]}"; do
    [[ -d "$src/config/$c" ]] && link_or_fill "$c" "$share/config/$c"
  done
  # GTK reads settings.ini from XDG_CONFIG_DIRS/gtk-3.0 and gtk-4.0 (gtk.css only from
  # the user's own directory, which wardos-first-run fills): one file, two real
  # directories, because the source directory serves both versions.
  if [[ -f "$src/config/gtk/settings.ini" ]]; then
    for v in gtk-3.0 gtk-4.0; do
      install -D -m 0644 "$src/config/gtk/settings.ini" "$dest/etc/xdg/$v/settings.ini"
    done
    say "config/gtk/settings.ini → /etc/xdg/gtk-3.0/, /etc/xdg/gtk-4.0/"
  fi
  if [[ -f "$src/config/bash/profile.d-wardos.sh" ]]; then
    install -D -m 0644 "$src/config/bash/profile.d-wardos.sh" "$dest/etc/profile.d/wardos.sh"
    say "config/bash/profile.d-wardos.sh → /etc/profile.d/wardos.sh"
  fi
fi

[[ -d "$src/themes" ]] && copy_tree "$src/themes" "$share/themes"
[[ -d "$src/webapps" ]] && copy_tree "$src/webapps" "$share/webapps"
[[ -d "$src/tuis" ]] && copy_tree "$src/tuis" "$share/tuis"
if [[ -f "$src/flatpaks.txt" ]]; then
  install -D -m 0644 "$src/flatpaks.txt" "$dest$share/flatpaks.txt"
  say "flatpaks.txt → $share/flatpaks.txt"
fi

if [[ -d "$src/systemd/user" ]]; then
  copy_tree "$src/systemd/user" /usr/lib/systemd/user
  # Units with an [Install] section are enabled for every user through a preset;
  # the rest (a timer's service, for instance) are pulled in by what installs them.
  preset="$dest/usr/lib/systemd/user-preset/90-wardos.preset"
  mkdir -p "$(dirname "$preset")"
  {
    echo "# WardOS desktop user units (image/install-desktop.sh); applied by systemd --user"
    echo "# on first login and by desktop/install.sh (systemctl --user preset)."
    for u in "$src"/systemd/user/*; do
      [[ -f "$u" ]] || continue
      grep -q '^\[Install\]' "$u" && echo "enable $(basename "$u")"
    done
  } >"$preset"
  say "systemd/user → /usr/lib/systemd/user (preset: $(grep -c '^enable' "$preset") units)"
fi

