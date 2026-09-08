#!/usr/bin/env bash
# wardos-toggle: night light, idle lock, bar, screensaver, notifications; state files.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
exec >/dev/null
for c in hyprsunset hypridle pkill notify-send makoctl; do mock "$c"; done
mock pgrep 'exit 1'
state="$XDG_STATE_HOME/wardos"
# Daemons start in the background; give their mock a moment to log.
wait_count() {
  for _ in $(seq 40); do
    [[ $(grep -c -- "$1" "$MOCK_LOG") -ge "$2" ]] && return 0
    sleep 0.05
  done
  fail "expected $2 calls matching '$1'; log:
$(cat "$MOCK_LOG")"
}

wardos-toggle --help | grep -q '^Usage' || fail "--help prints the usage block"

# nightlight: on starts hyprsunset with a temperature, off kills it; the state file says which.
wardos-toggle nightlight
wait_count '^hyprsunset --temperature [0-9]*$' 1
assert_eq "$(cat "$state/nightlight")" on
assert_eq "$(wardos-toggle nightlight --status)" on
wardos-toggle nightlight
assert_logged '^pkill -x hyprsunset$'
assert_eq "$(cat "$state/nightlight")" off
wardos-toggle nightlight on
wait_count '^hyprsunset' 2
wardos-toggle nightlight on
sleep 0.2
[[ $(grep -c '^hyprsunset' "$MOCK_LOG") -eq 2 ]] || fail "on when already on does nothing"

# idle: hypridle running (pgrep) means on; toggling stops or starts it.
mock pgrep 'exit 0'
assert_eq "$(wardos-toggle idle --status)" on
wardos-toggle idle
assert_logged '^pkill -x hypridle$'
mock pgrep 'exit 1'
wardos-toggle idle
wait_count '^hypridle $' 1

# bar: waybar toggles on SIGUSR1.
wardos-toggle bar
assert_logged '^pkill -SIGUSR1 waybar$'
assert_eq "$(wardos-toggle bar --status)" off
wardos-toggle bar
assert_eq "$(wardos-toggle bar --status)" on

# screensaver: a state file wardos-screensaver reads; nothing to signal.
assert_eq "$(wardos-toggle screensaver --status)" on
wardos-toggle screensaver
assert_eq "$(cat "$state/screensaver")" off
wardos-toggle screensaver
assert_eq "$(cat "$state/screensaver")" on

# notifications: mako's do-not-disturb mode; "on" means notifications are shown. The
# state is what `makoctl mode` reports after the toggle.
# shellcheck disable=SC2016
mock makoctl 'f=$TMP/dnd; case "$*" in "mode -t do-not-disturb") if [[ -e $f ]]; then rm "$f"; else : >"$f"; fi ;; mode) if [[ -e $f ]]; then echo do-not-disturb; else echo default; fi ;; esac'
assert_eq "$(wardos-toggle notifications --status)" on
wardos-toggle notifications
assert_logged '^makoctl mode -t do-not-disturb$'
assert_eq "$(cat "$state/notifications")" off
assert_not_logged 'Notifications off'
wardos-toggle notifications
assert_eq "$(cat "$state/notifications")" on
assert_logged '^notify-send -a WardOS .*Notifications on'

wardos-toggle nothing 2>/dev/null && fail "unknown toggle"
exit 0
