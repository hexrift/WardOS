#!/usr/bin/env bash
# Regenerate assets/wardos-desktop.gif: the desktop storyboard in the README.
#
#   assets/storyboard/render.sh [WORKDIR]
#
# Needs: the workspace built (wardos-theme-render), python3 with Pillow, node with
# the playwright package (PLAYWRIGHT=/path/to/playwright/index.mjs when it is not in
# node_modules here) and a Chromium it can launch (CHROME=/path overrides).
# Every frame is HTML built from the theme fragments wardos-theme-render writes, the
# Waybar layout, ward-shell's launcher and bar lines and real ward output; see
# README.md in this directory and docs/desktop.md, "The README animation".
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
work=${1:-$(mktemp -d)}
for theme in ward-dark tokyo-night; do
  "$root/target/release/wardos-theme-render" --out "$work/themes/$theme" "$root/desktop/themes/$theme.toml"
done
python3 "$here/story.py" "$work"
node "$here/shot.mjs" "$work/frames"
python3 "$here/assemble.py" "$work" "$root/assets/wardos-desktop.gif"
