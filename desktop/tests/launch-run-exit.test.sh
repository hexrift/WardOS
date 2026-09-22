#!/usr/bin/env bash
# wardos-launch run's exit contract (#142): the terminal window's own exit status is always
# the child command's real exit status ("$@"'s), never the close prompt's `read`.
#
# launch.test.sh's `run` assertion only checks the constructed command line — its terminal
# mock (foot/alacritty) just logs the call and returns, so the inner `sh -c '...'` payload it
# builds never actually runs, and could not have caught this bug. This test does not mock
# that part away: a small shim stands in for the terminal binary and actually execs the `-e`
# command, the way a real terminal opens its child — reproducing the issue's own repro
# ("a harmless local terminal shim executed the real wardos-launch run wrapper with a child
# that exits 23, then supplied Enter to close the window") with a real child process and real
# stdin, both for Enter and for EOF (Ctrl-D) at the close prompt.
# shellcheck disable=SC2016  # the mock body's $@/$#/$1 expand when the mock runs, not now
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
export TERMINAL=foot
# The shim: find "-e" among its own arguments and exec everything after it, instead of just
# logging the call like this suite's plain `mock` bodies do.
mock foot '
while [[ $# -gt 0 && "$1" != "-e" ]]; do shift; done
shift
exec "$@"
'

# run_wrapper CHILD_STATUS enter|eof: runs the real wardos-launch run wrapper with a child
# that exits CHILD_STATUS, feeding it Enter or EOF at the close prompt. Sets LAST_RC to the
# wrapper's own exit status and LAST_OUTPUT to what it printed, without tripping this script's
# own `set -e` on the (often deliberately nonzero) result.
run_wrapper() {
  local child_status=$1 stdin=$2
  set +e
  if [[ "$stdin" == enter ]]; then
    LAST_OUTPUT=$(printf '\n' | wardos-launch run wardos-test-app sh -c "exit $child_status")
  else
    LAST_OUTPUT=$(wardos-launch run wardos-test-app sh -c "exit $child_status" </dev/null)
  fi
  LAST_RC=$?
  set -e
}

# The #142 reproduction: a child that exits 23, closed with Enter. Before the fix this
# reported 0 (read's status), not 23 (the child's).
run_wrapper 23 enter
[[ $LAST_RC -eq 23 ]] || fail "expected the wrapper to exit 23 (the child's status) after Enter, got $LAST_RC"
grep -q '\[failed, exit 23\]' <<<"$LAST_OUTPUT" || fail "expected a [failed, exit 23] message; got: $LAST_OUTPUT"

# The same failing child, but closed with EOF (Ctrl-D) instead of Enter: still 23 — `read`
# failing on EOF must not be confused with, or override, the child's own exit code.
run_wrapper 23 eof
[[ $LAST_RC -eq 23 ]] || fail "expected exit 23 after an EOF close, got $LAST_RC"

# A successful child, closed with Enter: 0.
run_wrapper 0 enter
[[ $LAST_RC -eq 0 ]] || fail "expected exit 0 for a successful child after Enter, got $LAST_RC"
grep -q '\[done\]' <<<"$LAST_OUTPUT" || fail "expected a [done] message; got: $LAST_OUTPUT"

# A successful child, closed with EOF instead of Enter: still 0 (no regression) — EOF at the
# close prompt must never turn a successful command into a failure.
run_wrapper 0 eof
[[ $LAST_RC -eq 0 ]] || fail "expected exit 0 for a successful child after an EOF close (no regression), got $LAST_RC"

echo "ok   launch-run-exit.test.sh internal assertions"
