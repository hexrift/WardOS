#!/usr/bin/env bash
# wardos-hint: the empty-workspace hint (#99). Landing on one of the three named
# workspaces (1 code, 2 agent, 3 web) with no window on it says what starts there and
# how; a workspace with a window, a free workspace (4–9) and a hint already shown this
# session send nothing. --watch follows Hyprland's event socket (socat) and hints on each
# workspace change the same way. Rendering is the existing notification path
# (wardos_notify → notify-send → mako), never a new surface.
# shellcheck disable=SC2016  # mock bodies are shell text, expanded when the mock runs
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
export WARDOS_HINT_SETTLE=0
mock notify-send
mock hyprctl 'case "$*" in "workspaces -j") printf "%s\n" "$HYPR_WORKSPACES" ;; esac'
export HYPR_WORKSPACES='[{"id":1,"name":"code","windows":1},{"id":2,"name":"agent","windows":0},{"id":3,"name":"web","windows":0}]'

wardos-hint --help | grep -q '^Usage' || fail "--help prints the usage block"
wardos-hint --help | grep -q -- '--watch' || fail "--help names --watch"

# The agent workspace, empty: the hint names the workspace and the two ways to start an
# agent there (the command centre's Start Claude, `ward claude` in a terminal).
wardos-hint 2
assert_logged '^notify-send -a WardOS .*Workspace 2.*agent'
assert_logged '^notify-send -a WardOS .*Super \+ Space.*Start Claude'
assert_logged '^notify-send -a WardOS .*ward claude'
grep -q '!' "$MOCK_LOG" && fail "no exclamation marks (design-language.md §9)"

# By name too: the web workspace names its launcher (the browser, web apps).
: >"$MOCK_LOG"
wardos-hint web
assert_logged '^notify-send -a WardOS .*Workspace 3.*web'
assert_logged '^notify-send -a WardOS .*Super \+ B'

# A workspace with a window on it gets no hint (code has one above).
: >"$MOCK_LOG"
wardos-hint 1
assert_logged '^hyprctl workspaces -j$'
assert_not_logged '^notify-send'

# Once per session: the agent hint was shown already, so nothing is sent again …
: >"$MOCK_LOG"
wardos-hint 2
assert_not_logged '^notify-send'
# … unless asked for.
wardos-hint --force 2
assert_logged '^notify-send -a WardOS .*Workspace 2'
# The session marker lives in XDG_RUNTIME_DIR, so a new login starts over.
assert_file "$XDG_RUNTIME_DIR/wardos/hint-shown-2"

# The code workspace, emptied: the hint names the editor and the terminal.
export HYPR_WORKSPACES='[{"id":1,"name":"code","windows":0},{"id":2,"name":"agent","windows":0},{"id":3,"name":"web","windows":0}]'
: >"$MOCK_LOG"
wardos-hint code
assert_logged '^notify-send -a WardOS .*Workspace 1.*code'
assert_logged '^notify-send -a WardOS .*Super \+ N'
assert_logged '^notify-send -a WardOS .*Super \+ Return'

# A free workspace has nothing to say; an unknown argument is an error.
: >"$MOCK_LOG"
wardos-hint 4
assert_not_logged '^notify-send'
wardos-hint nothing 2>/dev/null && fail "unknown workspace"
wardos-hint 2>/dev/null && fail "a workspace is required"

# A workspace hyprctl does not list (never created yet) counts as empty.
: >"$MOCK_LOG"
export HYPR_WORKSPACES='[{"id":1,"name":"code","windows":2}]'
wardos-hint --force 3
assert_logged '^notify-send -a WardOS .*Workspace 3'

# Without notify-send nothing fails (a plain terminal session).
rm "$MOCK_DIR/notify-send"
wardos-hint --force 2 || fail "no notify-send must not fail"

# --- --watch: Hyprland's event socket, one hint per empty workspace per session ---------
setup_env
export WARDOS_HINT_SETTLE=0
mock notify-send
mock hyprctl 'case "$*" in "workspaces -j") printf "%s\n" "$HYPR_WORKSPACES" ;; esac'
export HYPR_WORKSPACES='[{"id":1,"name":"code","windows":1},{"id":2,"name":"agent","windows":0},{"id":3,"name":"web","windows":0}]'
export HYPRLAND_INSTANCE_SIGNATURE=sig
# The socket's stream: workspacev2 carries ID,NAME; the plain workspace line and the
# unrelated events are ignored; the second visit to 2 is suppressed; 4 is free.
mock socat 'printf "%s\n" "workspacev2>>2,agent" "workspace>>agent" "openwindow>>5,2,foot,foot" \
  "workspacev2>>1,code" "workspacev2>>3,web" "workspacev2>>2,agent" "workspacev2>>4,4"'
wardos-hint --watch
assert_logged "^socat -u UNIX-CONNECT:$XDG_RUNTIME_DIR/hypr/sig/.socket2.sock -$"
[[ $(grep -c '^notify-send' "$MOCK_LOG") -eq 2 ]] ||
  fail "expected one hint for agent and one for web; log: $(cat "$MOCK_LOG")"
assert_logged '^notify-send -a WardOS .*Workspace 2'
assert_logged '^notify-send -a WardOS .*Workspace 3'
assert_not_logged '^notify-send -a WardOS .*Workspace 1'

# Without a Hyprland instance to follow the watch says so and fails.
unset HYPRLAND_INSTANCE_SIGNATURE
wardos-hint --watch 2>/dev/null && fail "--watch needs HYPRLAND_INSTANCE_SIGNATURE"
exit 0
