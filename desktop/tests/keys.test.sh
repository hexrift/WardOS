#!/usr/bin/env bash
# wardos-keys: bind lines from the shipped and the user's Hyprland files, one line per key.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

wardos-keys --help | grep -q '^Usage' || fail "--help prints the usage block"

# A private tree so the assertions do not depend on the shipped bindings.
export WARDOS_ROOT="$TMP/root"
mkdir -p "$WARDOS_ROOT/hyprland" "$XDG_CONFIG_HOME/hypr"
cat >"$WARDOS_ROOT/hyprland/keybindings.conf" <<'EOF'
# WardOS — key bindings
$mod = SUPER
$terminal = foot

# ---------------------------------------------------------------------------
# Programs
# ---------------------------------------------------------------------------
# Review permissions (§14).
bind = $mod SHIFT, S, exec, $settings
bind = $mod, RETURN, exec, $terminal
bind = $mod, B, exec, $browser # Browser
bind = $mod, 1, workspace, 1
bindm = $mod, mouse:272, movewindow
bindel = , XF86AudioRaiseVolume, exec, wpctl set-volume @DEFAULT_AUDIO_SINK@ 5%+
EOF
cat >"$XDG_CONFIG_HOME/hypr/bindings.conf" <<'EOF'
$mod = SUPER
# Keys viewer
bind = $mod, K, exec, wardos-keys
# My own terminal
bind = $mod, RETURN, exec, alacritty
EOF

out=$(wardos-keys --list)
grep -q '^Super + Shift + S  *Review permissions (§14).$' <<<"$out" || fail "comment above is the description; got:
$out"
grep -q '^Super + B  *Browser$' <<<"$out" || fail "trailing comment is the description"
grep -q '^Super + 1  *workspace 1$' <<<"$out" || fail "no comment: the dispatcher and its argument"
grep -q '^Super + mouse:272  *movewindow$' <<<"$out" || fail "bindm lines are listed"
grep -q '^XF86AudioRaiseVolume  *exec wpctl' <<<"$out" || fail "bindel lines without a modifier"
grep -q '^Super + K  *Keys viewer$' <<<"$out" || fail "user files are read"
grep -q '^Super + Return  *My own terminal$' <<<"$out" || fail "the user file wins for the same key"
[[ $(grep -c '^Super + Return' <<<"$out") -eq 1 ]] || fail "one line per key combination"
grep -q 'Programs' <<<"$out" && fail "separator comments are not descriptions"

# The default shows the lines through the picker and prints the chosen one.
export WARDOS_MENU_CHOICE="Super + K"
sel=$(wardos-keys)
grep -q '^Super + K  *Keys viewer$' <<<"$sel" || fail "the picker shows the lines; got: $sel"
