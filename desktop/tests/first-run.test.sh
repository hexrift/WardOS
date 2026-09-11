#!/usr/bin/env bash
# wardos-first-run: configs, the default theme, ward doctor, the default apps, the keys,
# once (a marker), unless --force.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
for c in wardos-refresh wardos-theme ward wardos-keys wardos-webapp wardos-tui notify-send wardos-welcome; do mock "$c"; done
marker="$XDG_CONFIG_HOME/wardos/first-run-done"

wardos-first-run --help | grep -q '^Usage' || fail "--help prints the usage block"

wardos-first-run
assert_logged '^wardos-refresh --all$'
# The login re-apply is quiet (-q): the desktop autostart re-applies every login, so a
# toast here would be the duplicate the reference laptop showed (E-09).
assert_logged '^wardos-theme set -q ward-dark$'
# `ward doctor` is detached so its run (tens of seconds on a USB boot) never blocks the
# rest of onboarding; wait_logged gives the detached mock a moment to record the call.
wait_logged '^ward doctor$'
assert_logged '^wardos-webapp install --defaults$'
assert_logged '^wardos-tui install --defaults$'
assert_logged '^wardos-keys $'
assert_file "$marker"
# first-run does not send the "Welcome to WardOS" greeting: the walkthrough (wardos-welcome)
# is its single sender, so the reference laptop's duplicate toast cannot recur (E-09).
assert_not_logged 'Welcome to WardOS'
# The walkthrough comes after the keys, once the marker is written. (The detached
# `ward doctor` above may land anywhere in the log, so assert order against the keys line,
# not that wardos-welcome is the very last line.)
assert_logged '^wardos-welcome $'
keys_at=$(grep -n '^wardos-keys $' "$MOCK_LOG" | head -1 | cut -d: -f1)
welcome_at=$(grep -n '^wardos-welcome $' "$MOCK_LOG" | head -1 | cut -d: -f1)
[[ -n "$keys_at" && -n "$welcome_at" && "$welcome_at" -gt "$keys_at" ]] ||
  fail "wardos-welcome must run after wardos-keys; log: $(cat "$MOCK_LOG")"

# Done once: the second login does nothing.
: >"$MOCK_LOG"
wardos-first-run
[[ ! -s "$MOCK_LOG" ]] || fail "nothing runs after the marker; log: $(cat "$MOCK_LOG")"
wardos-first-run --force
assert_logged '^wardos-refresh --all$'
wait_logged '^ward doctor$'  # let the detached doctor finish before the log is reused

# A missing ward is skipped and a failing theme set reported, neither is fatal.
rm "$MOCK_DIR/ward" "$marker"
mock wardos-theme "exit 1"
: >"$MOCK_LOG"
wardos-first-run
assert_logged '^wardos-keys $'
assert_file "$marker"
assert_logged '^notify-send -a WardOS .*Theme not applied'

# A failing setup step is non-fatal AND the marker is still written, so a re-login does
# not run first-run again (which would re-copy the defaults and clobber the user's real
# config backup). Onboarding continues to wardos-welcome despite the failure.
for c in wardos-refresh wardos-theme ward wardos-webapp wardos-tui; do mock "$c"; done
rm -f "$marker"
mock wardos-refresh "exit 1"
: >"$MOCK_LOG"
wardos-first-run
assert_file "$marker"
assert_logged '^notify-send -a WardOS .*Defaults not applied'
assert_logged '^wardos-keys $'
assert_logged '^wardos-welcome $'
wait_logged '^ward doctor$'  # let the detached doctor finish before the log is reused
# The next login is a no-op: the marker survived the failed step, so nothing re-runs.
: >"$MOCK_LOG"
wardos-first-run
[[ ! -s "$MOCK_LOG" ]] || fail "first-run re-ran after a failed step; log: $(cat "$MOCK_LOG")"
