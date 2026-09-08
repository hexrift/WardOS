#!/usr/bin/env bash
# wardos-screensaver: tte with the wordmark, a tput fallback, any key exits, off means off.
# shellcheck disable=SC2016  # mock bodies are shell text, expanded when the mock runs
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
mock tte 'cat >/dev/null'
mock tput 'case "$1" in cols) echo 80 ;; lines) echo 24 ;; esac'

wardos-screensaver --help | grep -q '^Usage' || fail "--help prints the usage block"

# Switched off by wardos-toggle: returns at once, runs nothing.
mkdir -p "$XDG_STATE_HOME/wardos"
echo off >"$XDG_STATE_HOME/wardos/screensaver"
wardos-screensaver </dev/null >/dev/null
assert_not_logged '^tte'
echo on >"$XDG_STATE_HOME/wardos/screensaver"

# With tte: the wordmark through an effect; a key press ends it.
printf x | wardos-screensaver >/dev/null
assert_logged '^tte .*(beams|decrypt|slide|wipe|expand|print)'
# End of input counts as a key too, so a run without a terminal never hangs.
wardos-screensaver </dev/null >/dev/null

# Without tte: the tput fallback draws the wordmark itself.
rm "$MOCK_DIR/tte"
: >"$MOCK_LOG"
out=$(printf x | wardos-screensaver)
assert_logged '^tput'
grep -q WARDOS <<<"$out" || fail "the fallback prints the wordmark"
exit 0
