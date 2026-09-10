#!/usr/bin/env bash
# wardos-theme: list, current, set (render + reload), next, install, remove, render, bg next.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

current_dir="$XDG_CONFIG_HOME/wardos/theme/current"
user_themes="$XDG_DATA_HOME/wardos/themes"

# The renderer mock writes what the script reads back: colors.env (variant and
# name from the theme file), background.png (the wallpaper drawn from the
# tokens), background (its path, as the real one does when the theme has no
# backgrounds/) and the hyprlock fragment's $wallpaper line.
# shellcheck disable=SC2016  # the mock bodies expand when the mock runs
mock wardos-theme-render '
id=$1; out=$3
mkdir -p "$out"
toml=""
for d in "$WARDOS_THEMES" "$XDG_DATA_HOME/wardos/themes" "$WARDOS_ROOT/themes"; do
  for c in "$d/$id.toml" "$d/$id/$id.toml" "$d/$id/theme.toml"; do
    [[ -f $c ]] && toml=$c && break 2
  done
done
[[ -n $toml ]] || { echo "no theme $id" >&2; exit 1; }
name=$(sed -n "s/^name = \"\(.*\)\"/\1/p" "$toml")
variant=$(sed -n "s/^variant = \"\(.*\)\"/\1/p" "$toml")
printf "WARDOS_THEME_ID=\"%s\"\nWARDOS_THEME_NAME=\"%s\"\nWARDOS_VARIANT=\"%s\"\nWARDOS_GROUND=\"#0E0F11\"\n" "$id" "$name" "$variant" >"$out/colors.env"
for f in hyprland.conf waybar.css mako.conf fuzzel.ini foot.ini alacritty.toml btop.theme swayosd.css nvim.lua chromium.json gtk.css theme.toml; do : >"$out/$f"; done
printf "PNG" >"$out/background.png"
echo "$out/background.png" >"$out/background"
printf "\$ground     = rgb(0E0F11)\n\$wallpaper  = %s/background.png\n" "$out" >"$out/hyprlock.conf"'
mock hyprctl
mock pkill
mock makoctl
mock swaybg
mock gsettings
mock systemctl
mock notify-send
# shellcheck disable=SC2016
mock git '
# git clone --depth 1 <url> <dir>: a theme repo carries theme.toml, unless the URL says "empty"
dir=${*: -1}
mkdir -p "$dir"
case $* in *empty*) ;; *) printf "[meta]\nname = \"Ocean\"\nid = \"ocean\"\nvariant = \"dark\"\n" >"$dir/theme.toml" ;; esac'
export WARDOS_THEMES=""

# Wait for a backgrounded mock (swaybg) to have logged.
wait_logged() {
  for _ in $(seq 1 40); do
    grep -Eq -- "$1" "$MOCK_LOG" && return 0
    sleep 0.05
  done
  fail "expected a call matching '$1' within 2 s; log:
$(cat "$MOCK_LOG")"
}

# --help prints the usage block.
wardos-theme --help | grep -q '^wardos-theme' || fail "--help should print usage"

# list: every shipped theme, sorted.
listed=$(wardos-theme list)
assert_eq "$(echo "$listed" | head -1)" "catppuccin-latte"
assert_eq "$(echo "$listed" | wc -l)" "14"
echo "$listed" | grep -qx 'ward-dark' || fail "list lacks ward-dark"
echo "$listed" | grep -qx 'tokyo-night' || fail "list lacks tokyo-night"

# current: Ward Dark until something is set.
assert_eq "$(wardos-theme current)" "ward-dark"

# set: render, id, and every reload the components need.
wardos-theme set nord
assert_logged "^wardos-theme-render nord --out $current_dir$"
assert_eq "$(cat "$current_dir/id")" "nord"
assert_eq "$(wardos-theme current)" "nord"
assert_file "$current_dir/hyprland.conf"
assert_file "$current_dir/chromium.json"
assert_logged '^hyprctl reload$'
assert_logged '^pkill -SIGUSR2 -x waybar$'
assert_logged '^pkill -SIGUSR1 -x nvim$'
assert_logged '^makoctl reload$'
assert_logged '^pkill -x swaybg$'
# The wallpaper the render drew is what swaybg shows (docs/desktop.md §Themes).
wait_logged "^swaybg -i $current_dir/background.png -m fill$"
assert_logged '^systemctl --user restart swayosd.service$'
assert_logged '^gsettings set org.gnome.desktop.interface color-scheme prefer-dark$'
assert_logged '^notify-send .*Theme · Nord$'
# btop only loads themes from its own directory: a symlink to the render.
assert_eq "$(readlink "$XDG_CONFIG_HOME/btop/themes/wardos.theme")" "$current_dir/btop.theme"

# A light theme asks GNOME apps for the light scheme.
wardos-theme set catppuccin-latte
assert_logged 'color-scheme prefer-light$'

# set -q renders and reloads exactly like set, but sends no notification: it is the
# routine per-login re-apply (autostart, wardos-first-run), not a theme change, so a
# toast each login would be noise (E-09 duplicate-toast fix).
: >"$MOCK_LOG"
wardos-theme set -q nord
assert_logged "^wardos-theme-render nord --out $current_dir$"
assert_logged '^hyprctl reload$'
assert_eq "$(cat "$current_dir/id")" "nord"
assert_not_logged '^notify-send'
# --quiet is the long form; an id is still required.
: >"$MOCK_LOG"
wardos-theme set --quiet ward-dark
assert_eq "$(cat "$current_dir/id")" "ward-dark"
assert_not_logged '^notify-send'
if wardos-theme set -q 2>/dev/null; then fail "set -q still needs an id"; fi

# set refuses an unknown id and leaves the current theme alone.
if wardos-theme set no-such-theme 2>/dev/null; then fail "set no-such-theme should fail"; fi
assert_eq "$(wardos-theme current)" "ward-dark"

# next: alphabetical, wrapping.
wardos-theme set nord
wardos-theme next
assert_eq "$(wardos-theme current)" "rose-pine"
wardos-theme set ward-light
wardos-theme next
assert_eq "$(wardos-theme current)" "catppuccin-latte"

# render: only the render and the id, no reload.
: >"$MOCK_LOG"
wardos-theme render ward-graphite
assert_logged "^wardos-theme-render ward-graphite --out $current_dir$"
assert_eq "$(wardos-theme current)" "ward-graphite"
assert_not_logged '^hyprctl'
assert_not_logged '^notify-send'
: >"$MOCK_LOG"
wardos-theme render
assert_logged "^wardos-theme-render ward-graphite --out $current_dir$"

# reload alone signals the components without rendering.
: >"$MOCK_LOG"
wardos-theme reload
assert_not_logged '^wardos-theme-render'
assert_logged '^hyprctl reload$'
assert_logged '^makoctl reload$'

# A hand-written `solid:<hex>` background still means swaybg -c.
echo "solid:#101010" >"$current_dir/background"
: >"$MOCK_LOG"
wardos-theme reload
wait_logged '^swaybg -c #101010$'

# install: a shallow clone under the user's themes, named after the URL, then set.
: >"$MOCK_LOG"
wardos-theme install https://example.invalid/someone/wardos-theme-ocean.git
assert_logged "^git clone --depth 1 https://example.invalid/someone/wardos-theme-ocean.git $user_themes/ocean$"
assert_file "$user_themes/ocean/theme.toml"
assert_eq "$(wardos-theme current)" "ocean"
wardos-theme list | grep -qx 'ocean' || fail "installed theme not listed"
assert_logged '^notify-send .*Theme · Ocean$'

# A clone without a theme file is not a theme: refused and removed.
if wardos-theme install https://example.invalid/someone/empty.git 2>/dev/null; then fail "install of a non-theme should fail"; fi
[[ ! -e "$user_themes/empty" ]] || fail "a failed install should leave nothing behind"

# remove: installed themes go (falling back to Ward Dark); shipped ones are refused.
wardos-theme remove ocean
[[ ! -e "$user_themes/ocean" ]] || fail "remove should delete the clone"
assert_eq "$(wardos-theme current)" "ward-dark"
if wardos-theme remove nord 2>/dev/null; then fail "remove of a shipped theme should be refused"; fi
assert_file "$WARDOS_ROOT/themes/nord.toml"

# bg next: cycles the theme's backgrounds, restarting swaybg each time.
mkdir -p "$user_themes/dune/backgrounds"
printf '[meta]\nname = "Dune"\nid = "dune"\nvariant = "dark"\n' >"$user_themes/dune/dune.toml"
: >"$user_themes/dune/backgrounds/b.png"
: >"$user_themes/dune/backgrounds/a.png"
wardos-theme set dune
: >"$MOCK_LOG"
wardos-theme bg next
wait_logged "^swaybg -i $user_themes/dune/backgrounds/a.png -m fill$"
assert_eq "$(cat "$current_dir/background")" "$user_themes/dune/backgrounds/a.png"
# The lock screen follows: the fragment's $wallpaper line is the pick, the rest stays.
assert_eq "$(grep '^[$]wallpaper' "$current_dir/hyprlock.conf")" "\$wallpaper  = $user_themes/dune/backgrounds/a.png"
assert_eq "$(grep -c '' "$current_dir/hyprlock.conf")" "2"
grep -q '^[$]ground     = rgb(0E0F11)$' "$current_dir/hyprlock.conf" || fail "bg next must leave the other hyprlock variables alone"
: >"$MOCK_LOG"
wardos-theme bg next
wait_logged "^swaybg -i $user_themes/dune/backgrounds/b.png -m fill$"
assert_eq "$(grep '^[$]wallpaper' "$current_dir/hyprlock.conf")" "\$wallpaper  = $user_themes/dune/backgrounds/b.png"
: >"$MOCK_LOG"
wardos-theme bg next
wait_logged "^swaybg -i $user_themes/dune/backgrounds/a.png -m fill$"

# A theme without backgrounds says so and changes nothing.
wardos-theme set ward-dark
: >"$MOCK_LOG"
if wardos-theme bg next 2>/dev/null; then fail "bg next without backgrounds should fail"; fi
assert_not_logged '^swaybg'

# Unknown verbs fail with usage.
if wardos-theme frobnicate 2>/dev/null; then fail "unknown verb should fail"; fi
