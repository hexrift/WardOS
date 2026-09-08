#!/usr/bin/env bash
# wardos-refresh: a component's default configuration copied into ~/.config, the previous
# one kept as <component>.bak; the exceptions of docs/desktop.md §Layout.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
exec >/dev/null
export WARDOS_ROOT="$TMP/root"
mkdir -p "$WARDOS_ROOT/config/waybar" "$WARDOS_ROOT/config/hyprlock" "$WARDOS_ROOT/config/gtk" \
  "$WARDOS_ROOT/config/xcompose" "$WARDOS_ROOT/config/chromium" "$WARDOS_ROOT/config/bash" "$WARDOS_ROOT/hyprland"
echo default >"$WARDOS_ROOT/config/waybar/config.jsonc"
echo default >"$WARDOS_ROOT/config/hyprlock/hyprlock.conf"
echo default >"$WARDOS_ROOT/config/gtk/settings.ini"
echo default >"$WARDOS_ROOT/config/xcompose/XCompose"
echo default >"$WARDOS_ROOT/config/chromium/chromium-flags.conf"
echo default >"$WARDOS_ROOT/config/bash/bashrc"
echo profile >"$WARDOS_ROOT/config/bash/profile.d-wardos.sh"
echo default >"$WARDOS_ROOT/hyprland/hyprland.conf"
echo default >"$WARDOS_ROOT/hyprland/bindings.conf"
c="$XDG_CONFIG_HOME"

wardos-refresh --help | grep -q '^Usage' || fail "--help prints the usage block"

# A plain component: the directory is copied; an existing one is backed up first.
wardos-refresh waybar
assert_eq "$(cat "$c/waybar/config.jsonc")" default
[[ ! -e "$c/waybar.bak" ]] || fail "nothing to back up the first time"
echo mine >"$c/waybar/config.jsonc"
echo extra >"$c/waybar/extra.css"
wardos-refresh waybar
assert_eq "$(cat "$c/waybar/config.jsonc")" default
assert_eq "$(cat "$c/waybar.bak/config.jsonc")" mine
assert_file "$c/waybar/extra.css"

# The exceptions: hypr-family files into ~/.config/hypr, gtk into both gtk dirs,
# XCompose and chromium-flags.conf as files.
mkdir -p "$c/hypr"
echo mine >"$c/hypr/hyprlock.conf"
wardos-refresh hyprlock
assert_eq "$(cat "$c/hypr/hyprlock.conf")" default
assert_eq "$(cat "$c/hypr/hyprlock.conf.bak")" mine
wardos-refresh gtk
assert_eq "$(cat "$c/gtk-3.0/settings.ini")" default
assert_eq "$(cat "$c/gtk-4.0/settings.ini")" default
wardos-refresh xcompose
assert_eq "$(cat "$HOME/.XCompose")" default
wardos-refresh chromium
assert_eq "$(cat "$c/chromium-flags.conf")" default
# bash: the pieces, not the image's profile.d file.
wardos-refresh bash
assert_eq "$(cat "$c/bash/bashrc")" default
[[ ! -e "$c/bash/profile.d-wardos.sh" ]] || fail "profile.d-wardos.sh belongs to the image"
# hypr: the Hyprland tree, the user's copy backed up whole.
echo mine >"$c/hypr/hyprland.conf"
wardos-refresh hypr
assert_eq "$(cat "$c/hypr/hyprland.conf")" default
assert_eq "$(cat "$c/hypr/bindings.conf")" default
assert_eq "$(cat "$c/hypr.bak/hyprland.conf")" mine

# --all does every component that ships; --list names them.
rm -rf "$c"
wardos-refresh --all
assert_file "$c/waybar/config.jsonc"
assert_file "$c/hypr/hyprlock.conf"
assert_file "$c/hypr/hyprland.conf"
assert_file "$c/gtk-4.0/settings.ini"
grep -qx hypr <<<"$(wardos-refresh --list)" || fail "--list includes hypr"
grep -qx waybar <<<"$(wardos-refresh --list)" || fail "--list includes waybar"
wardos-refresh nothing 2>/dev/null && fail "unknown component"
exit 0
