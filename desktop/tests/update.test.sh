#!/usr/bin/env bash
# wardos-update: bootc upgrade, Flatpak updates, configs, themes; --check for the bar.
# shellcheck disable=SC2016  # mock bodies are shell text, expanded when the mock runs
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
for c in sudo flatpak wardos-refresh wardos-theme git notify-send; do mock "$c"; done
mock bootc 'case "$*" in "upgrade --check") printf "%s\n" "$BOOTC_CHECK" ;; esac'

wardos-update --help | grep -q '^Usage' || fail "--help prints the usage block"

# --check: one Waybar JSON line; class "available" when bootc reports an update.
export BOOTC_CHECK="Update available for: quay.io/hexrift/wardos:latest"
assert_eq "$(wardos-update --check)" '{"text": "update", "tooltip": "Update available for: quay.io/hexrift/wardos:latest", "class": "available"}'
export BOOTC_CHECK="No changes in: quay.io/hexrift/wardos:latest"
assert_eq "$(wardos-update --check)" '{"text": "", "tooltip": "No changes in: quay.io/hexrift/wardos:latest", "class": ""}'
rm "$MOCK_DIR/bootc"
assert_eq "$(wardos-update --check)" '{"text": "", "tooltip": "bootc is not installed", "class": ""}'
mock bootc 'case "$*" in "upgrade --check") echo "a \"quoted\" line" ;; esac'
assert_eq "$(wardos-update --check)" '{"text": "", "tooltip": "a \"quoted\" line", "class": ""}'

# The parts, one at a time.
wardos-update system >/dev/null
assert_logged '^sudo bootc upgrade$'
wardos-update flatpaks >/dev/null
assert_logged '^flatpak update -y$'
wardos-update configs >/dev/null
assert_logged '^wardos-refresh --all$'
mkdir -p "$XDG_DATA_HOME/wardos/themes/nord/.git"
wardos-update themes >/dev/null
assert_logged "^git -C $XDG_DATA_HOME/wardos/themes/nord pull --ff-only$"
assert_logged '^wardos-theme render$'

# No argument: system, flatpaks and themes, then a done toast (configs only on request).
: >"$MOCK_LOG"
wardos-update >/dev/null
assert_logged '^sudo bootc upgrade$'
assert_logged '^flatpak update -y$'
assert_logged '^wardos-theme render$'
assert_not_logged '^wardos-refresh'
assert_logged '^notify-send -a WardOS .*✓ Update'
wardos-update nothing 2>/dev/null && fail "unknown part"
exit 0
