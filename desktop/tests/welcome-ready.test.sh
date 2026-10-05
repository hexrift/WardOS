#!/usr/bin/env bash
# wardos-welcome, the agent step's readiness gate: when `ward ready` blocks, "Fix it first"
# opens `ward init` in a terminal (where the proposed verification boundary is accepted,
# #147 item 2) and never starts the agent; "Start anyway" starts it without `ward init`;
# a cancelled question does neither.
# shellcheck disable=SC2016  # mock bodies are shell text, expanded when the mock runs
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
for c in wardos-launch notify-send; do mock "$c"; done
mock ward 'case "$*" in
  ready\ *) exit "${WARD_READY_EXIT:-0}" ;;
esac'
project_file="$XDG_STATE_HOME/wardos/welcome-project"
mkdir -p "$HOME/work/app" "$(dirname "$project_file")"
printf '%s\n' "$HOME/work/app" >"$project_file"
export WARD_READY_EXIT=1

# Fix it first: the report in a terminal, then `ward init` in a terminal, no agent.
export WARDOS_MENU_CHOICE=$'Start Claude\nFix it first'
wardos-welcome agent
assert_logged "^ward ready $HOME/work/app --agent claude$"
assert_logged "^wardos-launch run wardos-ready ward ready $HOME/work/app --agent claude$"
assert_logged "^wardos-launch run wardos-init ward init $HOME/work/app$"
assert_not_logged '^wardos-launch run wardos-agent'
grep -q -- '--accept-verify' "$MOCK_LOG" && fail "the script never accepts the boundary itself"

# Start anyway: the agent, and no `ward init`.
: >"$MOCK_LOG"
export WARDOS_MENU_CHOICE=$'Start Codex\nStart anyway'
wardos-welcome agent
assert_not_logged 'ward init'
assert_logged "^wardos-launch run wardos-agent ward codex $HOME/work/app$"

# A cancelled question: neither.
: >"$MOCK_LOG"
export WARDOS_MENU_CHOICE=$'Start Claude'
wardos-welcome agent
assert_logged '^wardos-launch run wardos-ready'
assert_not_logged 'ward init'
assert_not_logged '^wardos-launch run wardos-agent'

# A failing `ward init` terminal does not crash the step either.
mock wardos-launch 'case "$*" in *wardos-init*) exit 17 ;; esac'
: >"$MOCK_LOG"
export WARDOS_MENU_CHOICE=$'Start Claude\nFix it first'
wardos-welcome agent || fail "a failed ward init must not crash wardos-welcome"
assert_logged "^wardos-launch run wardos-init ward init $HOME/work/app$"
assert_not_logged '^wardos-launch run wardos-agent'
exit 0
