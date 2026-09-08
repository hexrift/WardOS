#!/usr/bin/env bash
# wardos-welcome: theme, keys, project, agent, done; each skippable, re-runnable one at a
# time, once as a whole (the marker), again with --again. Keys go through a terminal.
# shellcheck disable=SC2016  # mock bodies are shell text, expanded when the mock runs
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
for c in wardos-launch notify-send git; do mock "$c"; done
mock wardos-theme 'case "$1" in list) printf "ward-dark\nnord\n" ;; esac'
mock ward 'case "$*" in "vault list") printf "  ANTHROPIC_API_KEY   not set\n  OPENAI_API_KEY      set · vault\n" ;; esac'
marker="$XDG_CONFIG_HOME/wardos/welcome-done"
project_file="$XDG_STATE_HOME/wardos/welcome-project"
mkdir -p "$HOME/work/app" "$HOME/other"

wardos-welcome --help | grep -q '^Usage' || fail "--help prints the usage block"

# The whole walk: a theme, one key, a directory two levels down, Claude in it, the card.
export WARDOS_MENU_CHOICE=$'nord\nAnthropic\nContinue\nChoose a directory\nwork/\napp/\n· use this directory\nStart Claude\nDone'
out=$(wardos-welcome)
assert_logged '^wardos-theme list$'
assert_logged '^wardos-theme set nord$'
assert_logged '^ward vault list$'
assert_logged '^wardos-launch run wardos-vault ward vault set ANTHROPIC_API_KEY$'
assert_not_logged 'OPENAI_API_KEY$'
assert_logged "^wardos-launch run wardos-init ward init $HOME/work/app$"
assert_logged "^wardos-launch run wardos-agent ward claude $HOME/work/app$"
assert_logged '^notify-send -a WardOS .*trust bar'
grep -q 'trust bar' <<<"$out" || fail "the trust bar is explained on stdout too; got: $out"
assert_logged '^notify-send -a WardOS .*Welcome to WardOS.*Super \+ Space'
assert_file "$marker"
assert_eq "$(cat "$project_file")" "$HOME/work/app"
grep -q 'sk-' "$MOCK_LOG" && fail "no key value ever passes through a menu or a mock"

# Done once: a plain run does nothing; --again runs it all again.
: >"$MOCK_LOG"
wardos-welcome
[[ ! -s "$MOCK_LOG" ]] || fail "nothing runs after the marker; log: $(cat "$MOCK_LOG")"
export WARDOS_MENU_CHOICE=$'Skip\nContinue\nSkip\nSkip\nDone'
wardos-welcome --again
assert_logged '^wardos-theme list$'
assert_not_logged '^wardos-theme set'
assert_not_logged '^wardos-launch'

# Every step skipped, every menu cancelled: still ends, still marks done.
rm -f "$marker" "$project_file"
: >"$MOCK_LOG"
export WARDOS_MENU_CHOICE=""
wardos-welcome
assert_not_logged '^wardos-launch'
assert_file "$marker"

# One step at a time, any time, without touching the marker.
rm -f "$marker"
: >"$MOCK_LOG"
export WARDOS_MENU_CHOICE=$'OpenAI\nContinue'
wardos-welcome keys
assert_logged '^wardos-launch run wardos-vault ward vault set OPENAI_API_KEY$'
[[ ! -e "$marker" ]] || fail "a single step is not the whole walkthrough"
# Both keys in one visit: the menu comes back once after a key.
: >"$MOCK_LOG"
export WARDOS_MENU_CHOICE=$'Anthropic\nOpenAI'
wardos-welcome keys
assert_logged 'ward vault set ANTHROPIC_API_KEY$'
assert_logged 'ward vault set OPENAI_API_KEY$'
wardos-welcome nowhere 2>/dev/null && fail "an unknown step fails"

# Clone: the URL is typed, the clone and init run in one terminal window.
: >"$MOCK_LOG"
export WARDOS_MENU_CHOICE=$'Clone a repository\nhttps://github.com/hexrift/ward-demo.git'
wardos-welcome project
assert_logged "^wardos-launch run wardos-init wardos-welcome clone https://github.com/hexrift/ward-demo.git $HOME/ward-demo$"
assert_eq "$(cat "$project_file")" "$HOME/ward-demo"
wardos-welcome clone https://x/y.git "$HOME/y"
assert_logged "^git clone https://x/y.git $HOME/y$"
assert_logged "^ward init $HOME/y$"
# A repository already cloned is only initialised.
: >"$MOCK_LOG"
export WARDOS_MENU_CHOICE=$'Clone a repository\ngit@github.com:hexrift/other.git'
wardos-welcome project
assert_logged "^wardos-launch run wardos-init ward init $HOME/other$"
assert_not_logged 'clone'

# The picker: up, a typed path, a new directory.
: >"$MOCK_LOG"
export WARDOS_MENU_CHOICE=$'Choose a directory\n‹ up\n'"$HOME/work"$'\n+ new directory…\nnew-thing'
wardos-welcome project
assert_logged "^wardos-launch run wardos-init ward init $HOME/work/new-thing$"

# The agent step with no project remembered asks for one first.
rm -f "$project_file"
: >"$MOCK_LOG"
export WARDOS_MENU_CHOICE=$'Choose a directory\n· use this directory\nStart Codex'
wardos-welcome agent
assert_logged "^wardos-launch run wardos-init ward init $HOME$"
assert_logged "^wardos-launch run wardos-agent ward codex $HOME$"

# Missing tools are skipped, not fatal.
rm "$MOCK_DIR/wardos-theme" "$MOCK_DIR/ward"
: >"$MOCK_LOG"
export WARDOS_MENU_CHOICE=$'Skip\nSkip\nDone'
wardos-welcome --again 2>/dev/null
assert_not_logged '^wardos-launch'
assert_file "$marker"
exit 0
