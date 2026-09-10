#!/usr/bin/env bash
# wardos-baseline: writes a one-file diagnostics bundle (ward doctor + raw hardware/boot
# facts) and prints its path; missing tools are noted, never fatal.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
mock ward

wardos-baseline --help | grep -q '^Usage' || fail "--help prints the usage block"

# Explicit path: the bundle lands there and its path is the last line printed.
out=$(wardos-baseline "$TMP/b.txt" | tail -1)
[[ "$out" == "$TMP/b.txt" ]] || fail "must print the bundle path, got: $out"
assert_file "$TMP/b.txt"
grep -q '^WardOS hardware baseline bundle$' "$TMP/b.txt" || fail "header missing"
grep -q '^===== ward doctor =====$' "$TMP/b.txt" || fail "ward doctor section missing"
assert_logged '^ward doctor$'
# A tool that is not installed is noted, not fatal.
grep -q 'not installed' "$TMP/b.txt" || fail "absent tools should be noted"

# Default path lands under the state dir and exists.
p=$(wardos-baseline | tail -1)
assert_file "$p"
case "$p" in
  */wardos/baseline-*.txt) ;;
  *) fail "default bundle not under the wardos state dir: $p" ;;
esac
