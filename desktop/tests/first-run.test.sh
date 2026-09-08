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
assert_logged '^wardos-theme set ward-dark$'
assert_logged '^ward doctor$'
assert_logged '^wardos-webapp install --defaults$'
assert_logged '^wardos-tui install --defaults$'
assert_logged '^wardos-keys $'
assert_logged '^notify-send -a WardOS .*Welcome'
assert_file "$marker"
# The walkthrough comes last, after the keys, once the marker is written.
assert_logged '^wardos-welcome $'
[[ "$(tail -n1 "$MOCK_LOG")" == "wardos-welcome " ]] || fail "wardos-welcome is the last step; log: $(cat "$MOCK_LOG")"

# Done once: the second login does nothing.
: >"$MOCK_LOG"
wardos-first-run
[[ ! -s "$MOCK_LOG" ]] || fail "nothing runs after the marker; log: $(cat "$MOCK_LOG")"
wardos-first-run --force
assert_logged '^wardos-refresh --all$'

# A missing ward is skipped and a failing theme set reported, neither is fatal.
rm "$MOCK_DIR/ward" "$marker"
mock wardos-theme "exit 1"
: >"$MOCK_LOG"
wardos-first-run
assert_logged '^wardos-keys $'
assert_file "$marker"
assert_logged '^notify-send -a WardOS .*Theme not applied'
