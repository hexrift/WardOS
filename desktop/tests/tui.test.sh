#!/usr/bin/env bash
# wardos-tui: terminal apps as windows, a .desktop with Exec=wardos-launch tui <name>.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
apps="$XDG_DATA_HOME/applications"

wardos-tui --help | grep -q '^Usage' || fail "--help prints the usage block"

wardos-tui install "Disk usage" "ncdu /" >/dev/null
assert_file "$apps/wardos-disk-usage.desktop"
grep -q '^Exec=wardos-launch tui disk-usage$' "$apps/wardos-disk-usage.desktop" || fail "Exec"
grep -q '^Name=Disk usage$' "$apps/wardos-disk-usage.desktop" || fail "Name"
grep -q '^StartupWMClass=wardos-disk-usage$' "$apps/wardos-disk-usage.desktop" || fail "WMClass"
grep -q '^Terminal=false$' "$apps/wardos-disk-usage.desktop" || fail "the terminal is ours, not the launcher's"
grep -q '^cmd=ncdu /$' "$XDG_CONFIG_HOME/wardos/tuis/disk-usage.conf" || fail "conf cmd"
grep -q '^icon=utilities-terminal$' "$XDG_CONFIG_HOME/wardos/tuis/disk-usage.conf" || fail "default icon"

# Shipped defaults: by name, and all at once.
wardos-tui install btop >/dev/null
grep -q '^Icon=utilities-system-monitor$' "$apps/wardos-btop.desktop" || fail "the default's icon"
wardos-tui install --defaults >/dev/null
for t in lazygit podman-tui pulsemixer nmtui bluetoothctl nvim; do assert_file "$apps/wardos-$t.desktop"; done
wardos-tui install nothing-here 2>/dev/null && fail "unknown name without a command fails"

list=$(wardos-tui list)
grep -q "^disk-usage	Disk usage	ncdu /	installed$" <<<"$list" || fail "installed row; got: $list"
grep -q "^btop	btop	btop	installed$" <<<"$list" || fail "installed default"

wardos-tui remove disk-usage >/dev/null
[[ ! -e "$apps/wardos-disk-usage.desktop" ]] || fail ".desktop removed"
[[ ! -e "$XDG_CONFIG_HOME/wardos/tuis/disk-usage.conf" ]] || fail "conf removed"
export WARDOS_MENU_CHOICE=btop
wardos-tui remove >/dev/null
[[ ! -e "$apps/wardos-btop.desktop" ]] || fail "removed the chosen one"
grep -q "^btop	btop	btop	default$" <<<"$(wardos-tui list)" || fail "a removed default is still listed as default"
exit 0
