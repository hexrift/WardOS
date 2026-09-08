#!/usr/bin/env bash
# wardos-setup: the TUIs in a terminal window, power profiles, config files in the editor,
# fingerprint, FIDO2, printers, DNS, timezone.
# shellcheck disable=SC2016  # mock bodies are shell text, expanded when the mock runs
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
exec >"$TMP/out" </dev/null # not a terminal: the TUIs open one
for c in foot nmtui bluetoothctl pulsemixer powerprofilesctl wardos-keys wardos-launch wardos-refresh \
  fprintd-enroll sudo pamu2fcfg nmcli timedatectl notify-send system-config-printer; do mock "$c"; done
unset TERMINAL

wardos-setup --help | grep -q '^Usage' || fail "--help prints the usage block"

wardos-setup wifi
assert_logged '^foot --app-id wardos-tui-nmtui -e nmtui$'
wardos-setup bluetooth
assert_logged '^foot --app-id wardos-tui-bluetoothctl -e bluetoothctl$'
mock bluetui
wardos-setup bluetooth
assert_logged '^foot --app-id wardos-tui-bluetui -e bluetui$'
wardos-setup audio
assert_logged '^foot --app-id wardos-tui-pulsemixer -e pulsemixer$'
rm "$MOCK_DIR/pulsemixer"
mock pavucontrol
wardos-setup audio
assert_logged '^pavucontrol $'

# power: pick a profile from powerprofilesctl's list.
mock powerprofilesctl 'case "$1" in list) printf "  performance:\n* balanced:\n  power-saver:\n" ;; esac'
wardos-setup power performance
assert_logged '^powerprofilesctl set performance$'
export WARDOS_MENU_CHOICE=power-saver
wardos-setup power
assert_logged '^powerprofilesctl set power-saver$'

# monitors / input: the user's hypr file in the editor, seeded from the shipped one.
wardos-setup monitors
assert_file "$XDG_CONFIG_HOME/hypr/monitors.conf"
assert_logged "^wardos-launch editor $XDG_CONFIG_HOME/hypr/monitors.conf$"
wardos-setup input
assert_logged "^wardos-launch editor $XDG_CONFIG_HOME/hypr/input.conf$"
wardos-setup keys
assert_logged '^wardos-keys $'

# The sudo steps need a terminal: outside one they re-run themselves in a window that
# stays open; inside one (a pty from util-linux script) they run here.
wardos-setup timezone Europe/Berlin
assert_logged "^wardos-launch run wardos-tui-timezone .*wardos-setup timezone Europe/Berlin$"
assert_not_logged '^sudo'
in_tty() { script -qec "$*" /dev/null >/dev/null; }
if ! command -v script >/dev/null; then
  echo "setup.test.sh: no util-linux script; the in-terminal steps are not exercised" >&2
  exit 0
fi

# In a terminal already, a TUI runs right here.
: >"$MOCK_LOG"
in_tty wardos-setup wifi
assert_logged '^nmtui $'
assert_not_logged '^foot'

# fingerprint and fido2 enrol, then turn the PAM feature on through sudo.
in_tty wardos-setup fingerprint
assert_logged '^fprintd-enroll $'
assert_logged '^sudo authselect enable-feature with-fingerprint$'
mock pamu2fcfg 'echo "user:key"'
in_tty wardos-setup fido2
assert_file "$XDG_CONFIG_HOME/Yubico/u2f_keys"
assert_logged '^sudo authselect enable-feature with-pam-u2f$'
in_tty wardos-setup fido2
assert_file "$XDG_CONFIG_HOME/Yubico/u2f_keys.bak"
assert_logged '^pamu2fcfg -n$'

# printers: system-config-printer when present, else CUPS in the browser.
wardos-setup printers
assert_logged '^system-config-printer $'
rm "$MOCK_DIR/system-config-printer"
wardos-setup printers
assert_logged '^wardos-launch browser http://localhost:631$'

# dns: the active connection gets the provider's servers.
mock nmcli 'case "$*" in *"show --active"*) printf "Wired 1:eth0\n" ;; esac'
in_tty wardos-setup dns Quad9
assert_logged '^sudo nmcli connection modify Wired 1 ipv4.dns 9.9.9.9 149.112.112.112 ipv4.ignore-auto-dns yes$'
assert_logged '^sudo nmcli connection up Wired 1$'
export WARDOS_MENU_CHOICE=Cloudflare
in_tty wardos-setup dns
assert_logged '^sudo nmcli connection modify Wired 1 ipv4.dns 1.1.1.1 1.0.0.1'
in_tty wardos-setup dns Automatic
assert_logged '^sudo nmcli connection modify Wired 1 ipv4.dns  ipv4.ignore-auto-dns no$'

# timezone: from timedatectl's list.
mock timedatectl 'case "$1" in list-timezones) printf "Europe/London\nEurope/Berlin\n" ;; esac'
in_tty wardos-setup timezone Europe/Berlin
assert_logged '^sudo timedatectl set-timezone Europe/Berlin$'
export WARDOS_MENU_CHOICE=Europe/Lon
in_tty wardos-setup timezone
assert_logged '^sudo timedatectl set-timezone Europe/London$'

# config <component>: the component's main file in the editor, refreshed first when missing.
wardos-setup config waybar
assert_logged '^wardos-refresh waybar$'
assert_logged "^wardos-launch editor $XDG_CONFIG_HOME/waybar/config.jsonc$"
mkdir -p "$XDG_CONFIG_HOME/mako"
: >"$XDG_CONFIG_HOME/mako/config"
wardos-setup config mako
assert_not_logged '^wardos-refresh mako$'
assert_logged "^wardos-launch editor $XDG_CONFIG_HOME/mako/config$"

wardos-setup nothing 2>/dev/null && fail "unknown thing"
exit 0
