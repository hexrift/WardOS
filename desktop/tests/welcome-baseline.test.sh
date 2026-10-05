#!/usr/bin/env bash
# wardos-welcome and #147's last two parts. The agent step offers the baseline only when
# `ward ready` (non-blocking) shows none recorded, or a stale one, and runs it only on a
# yes, in a terminal (`ward ready … --baseline`), never silently; a current baseline, or a
# blocking report, asks nothing about it. The done step closes with the four E-14 answers
# from `ward ready --answers --json` when the remembered project has a session, and shows
# no such card without one.
# shellcheck disable=SC2016  # mock bodies are shell text, expanded when the mock runs
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
for c in wardos-launch notify-send; do mock "$c"; done
mock ward 'case "$*" in
  *--answers\ --json) [[ -n "${WARD_ANSWERS:-}" ]] && cat "$WARD_ANSWERS"; exit 0 ;;
  ready\ *) printf "%s\n" "${WARD_READY_OUT:-}"; exit "${WARD_READY_EXIT:-0}" ;;
esac'
# Every menu's items are logged too, so the cards can be read back.
mock wardos-menu-select 'items=$(cat); printf "%s\n" "$items" >>"$MOCK_LOG"
printf "%s\n" "$items" | "$WARDOS_ROOT/bin/wardos-menu-select" "$@"'
project_file="$XDG_STATE_HOME/wardos/welcome-project"
mkdir -p "$HOME/work/app" "$(dirname "$project_file")"
printf '%s\n' "$HOME/work/app" >"$project_file"
app="$HOME/work/app"
esc=$'\e'

# No baseline yet: asked once; a yes runs it in a terminal, then the agent starts.
export WARD_READY_OUT="  policy          OK    .ward/policy.yaml resolves
  baseline        ${esc}[38;5;245m—    ${esc}[0m not run; \`ward ready --baseline\` runs the accepted command once
  Overall  ready"
export WARDOS_MENU_CHOICE=$'Start Claude\nRun the baseline'
wardos-welcome agent
assert_logged "^ward ready $app --agent claude$"
assert_logged '^wardos-menu-select --prompt Baseline'
assert_logged "^wardos-launch run wardos-ready ward ready $app --agent claude --baseline$"
assert_logged "^wardos-launch run wardos-agent ward claude $app$"

# "Not now": nothing runs, the agent still starts.
: >"$MOCK_LOG"
export WARDOS_MENU_CHOICE=$'Start Codex\nNot now'
wardos-welcome agent
assert_logged '^wardos-menu-select --prompt Baseline'
assert_not_logged 'ready .*--baseline'
assert_logged "^wardos-launch run wardos-agent ward codex $app$"

# A stale baseline is offered again.
: >"$MOCK_LOG"
export WARD_READY_OUT="  baseline        STALE stale: last run red (exit 1) over tree 1a2b3c4d5e6f on 2026-10-05; the tree changed since (now 9f8e7d6c5b4a)
  Overall  ready"
export WARDOS_MENU_CHOICE=$'Start Claude\nRun the baseline'
wardos-welcome agent
assert_logged "^wardos-launch run wardos-ready ward ready $app --agent claude --baseline$"

# A current baseline, green or red, asks nothing: the agent starts straight away.
for current in "OK    green: exit 0 over tree 1a2b3c4d5e6f" "RED   exit 1 over tree 1a2b3c4d5e6f · 1 of 2 tests failed"; do
  : >"$MOCK_LOG"
  export WARD_READY_OUT="  baseline        $current
  Overall  ready, baseline failing"
  export WARDOS_MENU_CHOICE=$'Start Claude'
  wardos-welcome agent
  assert_not_logged '^wardos-menu-select --prompt Baseline'
  assert_not_logged 'ready .*--baseline'
  assert_logged "^wardos-launch run wardos-agent ward claude $app$"
done

# A blocking report keeps its own question and never offers the baseline.
: >"$MOCK_LOG"
export WARD_READY_EXIT=1
export WARD_READY_OUT="  baseline        —     not run
  Overall  setup required"
export WARDOS_MENU_CHOICE=$'Start Claude\nStart anyway'
wardos-welcome agent
assert_not_logged '^wardos-menu-select --prompt Baseline'
assert_not_logged 'ready .*--baseline'
assert_logged "^wardos-launch run wardos-agent ward claude $app$"
unset WARD_READY_EXIT WARD_READY_OUT

# The done card with a session: the four answers, each with its source, then the card.
: >"$MOCK_LOG"
export WARD_ANSWERS="$TMP/answers.json"
cat >"$WARD_ANSWERS" <<'JSON'
{"project":"/p","session":{"id":"sess_01TEST","live":true},"answers":[
 {"key":"reach","question":"What can the agent reach?","answer":"/work read-write · network restricted (dev)","source":"session sess_01TEST: its capability manifest","known":true,"details":[]},
 {"key":"credentials","question":"Which credentials can it use?","answer":"none: no credential was granted in this session","source":"CredentialGranted records in sess_01TEST's log","known":true,"details":[]},
 {"key":"changed","question":"What did it change?","answer":"2 paths: 1 added, 1 modified, 0 removed","source":"the entry snapshot against the worktree now","known":true,"details":["+ src/added.txt","~ src/parse.txt"]},
 {"key":"verified","question":"Is the current candidate verified?","answer":"no: nothing has been verified in this session","source":"the last verification record in sess_01TEST's log","known":true,"details":[]}
]}
JSON
export WARDOS_MENU_CHOICE=$'Done\nDone'
wardos-welcome "done"
assert_logged "^ward ready $app --answers --json$"
assert_logged '^wardos-menu-select --prompt .*sess_01TEST'
assert_logged '^What can the agent reach\? /work read-write'
assert_logged '^Which credentials can it use\? none'
assert_logged '^What did it change\? 2 paths'
assert_logged '^Is the current candidate verified\? no'
assert_logged 'from session sess_01TEST'
assert_logged '^notify-send -a WardOS .*Welcome to WardOS'
assert_file "$XDG_CONFIG_HOME/wardos/welcome-done"

# Without a session (the JSON says so, or nothing answers): no answers card.
rm -f "$XDG_CONFIG_HOME/wardos/welcome-done"
: >"$MOCK_LOG"
printf '%s\n' '{"project":"/p","session":null,"answers":[]}' >"$WARD_ANSWERS"
wardos-welcome "done"
assert_not_logged '^wardos-menu-select --prompt .*recorded'
assert_logged '^notify-send -a WardOS .*Welcome to WardOS'
: >"$MOCK_LOG"
unset WARD_ANSWERS
wardos-welcome "done"
assert_not_logged '^wardos-menu-select --prompt .*recorded'
assert_file "$XDG_CONFIG_HOME/wardos/welcome-done"
exit 0
