#!/usr/bin/env bash
# Shared test helpers (docs/desktop.md §Tests). Source this from a *.test.sh.
#
#   setup_env          temp HOME/XDG dirs, WARDOS_MENU_BACKEND=stdin, mock dir on PATH
#   mock NAME [BODY]   create a mock command that logs "$NAME $*" to $MOCK_LOG, then runs BODY
#   assert_logged STR  fail unless $MOCK_LOG contains a line matching the regex STR
#   assert_not_logged STR
#   wait_logged STR    assert_logged after giving a detached mock up to 2 s
#   assert_file PATH   fail unless PATH exists
#   fail MSG
set -euo pipefail

test_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export WARDOS_ROOT="$test_root/desktop"

fail() { echo "FAIL: $*" >&2; exit 1; }

setup_env() {
  TMP=$(mktemp -d)
  export TMP
  export HOME="$TMP/home"
  export XDG_CONFIG_HOME="$HOME/.config"
  export XDG_DATA_HOME="$HOME/.local/share"
  export XDG_STATE_HOME="$HOME/.local/state"
  export XDG_RUNTIME_DIR="$TMP/run"
  mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR"
  export MOCK_DIR="$TMP/mock"
  export MOCK_LOG="$TMP/mock.log"
  mkdir -p "$MOCK_DIR"
  : >"$MOCK_LOG"
  export PATH="$MOCK_DIR:$test_root/desktop/bin:$PATH"
  export WARDOS_MENU_BACKEND=stdin
  export WARDOS_MENU_CHOICE=""
  trap 'rm -rf "$TMP"' EXIT
}

mock() {
  local name=$1
  local body=${2:-true}
  # shellcheck disable=SC2016  # the $* and $MOCK_LOG are for the mock, expanded when it runs
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "%s $*" >>"$MOCK_LOG"\n%s\n' "$name" "$body" >"$MOCK_DIR/$name"
  chmod +x "$MOCK_DIR/$name"
}

assert_logged() { grep -Eq -- "$1" "$MOCK_LOG" || fail "expected a call matching '$1'; log:
$(cat "$MOCK_LOG")"; }
assert_not_logged() { ! grep -Eq -- "$1" "$MOCK_LOG" || fail "unexpected call matching '$1'"; }
# wait_logged STR: like assert_logged, but gives a detached mock up to 2 s to log.
wait_logged() {
  local i
  for ((i = 0; i < 40; i++)); do
    grep -Eq -- "$1" "$MOCK_LOG" && return 0
    sleep 0.05
  done
  assert_logged "$1"
}
assert_file() { [[ -e "$1" ]] || fail "expected file $1"; }
assert_eq() { [[ "$1" == "$2" ]] || fail "expected '$2', got '$1'"; }
