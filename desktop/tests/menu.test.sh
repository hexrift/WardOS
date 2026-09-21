#!/usr/bin/env bash
# wardos-menu: the tree of docs/desktop.md §Menu, each leaf running its wardos-* command.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
for c in wardos-capture wardos-toggle wardos-power wardos-setup wardos-install wardos-remove \
  wardos-update wardos-keys wardos-launch wardos-theme wardos-font gtk-launch foot; do
  mock "$c"
done
# Real ward-shell output (Command::shell, crates/ward-shell-core/src/launcher.rs): the command
# column is already a complete, ready-to-run command line, not a bare `ward …` invocation.
mock ward-shell 'printf "PROJECTS\tpayments-api\tfoot -D /p/payments-api\nAGENTS\tStart Claude\tfoot -D /p/payments-api -- ward claude\n"'

wardos-menu --help | grep -q '^Usage' || fail "--help prints the usage block"

# --list prints a level: the top level is what ward-shell says plus SYSTEM.
top=$(wardos-menu --list)
grep -q "^PROJECTS *payments-api$" <<<"$top" || fail "PROJECTS come from ward-shell; got: $top"
grep -q "^AGENTS *Start Claude$" <<<"$top" || fail "AGENTS come from ward-shell"
grep -q "^SYSTEM *Capture$" <<<"$top" || fail "SYSTEM section is static"
assert_logged '^ward-shell launcher --lines$'
for entry in Apps Capture Appearance Connect Install Remove Update Toggle Power Help; do
  grep -q "^SYSTEM *$entry$" <<<"$top" || fail "SYSTEM lacks $entry"
done

# Path arguments jump into the tree; a leaf runs its command.
wardos-menu system capture "Screenshot window"
assert_logged '^wardos-capture screenshot window$'
wardos-menu capture "Colour"
assert_logged '^wardos-capture color$'
wardos-menu toggle "Night light"
assert_logged '^wardos-toggle nightlight$'
wardos-menu power lock
assert_logged '^wardos-power lock$'
wardos-menu install development ruby
assert_logged '^wardos-launch run wardos-install wardos-install dev ruby$'
wardos-menu install service syncthing
assert_logged '^wardos-launch run wardos-install wardos-install service syncthing$'
wardos-menu remove "Web app"
assert_logged '^wardos-remove webapp$'
wardos-menu update configs
assert_logged '^wardos-update configs$'
wardos-menu connect "Power profile"
assert_logged '^wardos-setup power$'
wardos-menu help keys
assert_logged '^wardos-keys $'
wardos-menu help "Hyprland wiki"
assert_logged '^wardos-launch browser https://wiki.hyprland.org'
wardos-menu style "Light or dark" "Light"
assert_logged '^wardos-theme set ward-light$'
# Theme and font lists come from their commands; a family name with spaces stays one argument.
mock wardos-theme "case \"\$1\" in list) printf 'ward-dark\nnord\n' ;; esac"
mock wardos-font "case \"\$1\" in list) printf 'JetBrains Mono\nNoto Sans\n' ;; esac"
grep -qx nord <<<"$(wardos-menu --list appearance theme)" || fail "themes are listed"
wardos-menu appearance theme nord
assert_logged '^wardos-theme set nord$'
wardos-menu appearance font "Noto Sans"
assert_logged '^wardos-font set Noto Sans$'
# A leaf of ward-shell runs its already-complete command line directly — never re-wrapped in
# another terminal (#156: that produced `foot -e foot -D … -- ward claude`, a nested window).
wardos-menu agents "Start Claude"
assert_logged '^foot -D /p/payments-api -- ward claude$'
assert_not_logged '^wardos-launch terminal foot'
wardos-menu projects payments-api
assert_logged '^foot -D /p/payments-api$'

# Walking the tree through the picker: one answer per level.
export WARDOS_MENU_CHOICE=$'SYSTEM     Capture\nScreenshot output'
wardos-menu
assert_logged '^wardos-capture screenshot output$'

# Apps lists every .desktop, hidden ones excluded, and launches by id.
mkdir -p "$XDG_DATA_HOME/applications"
printf '[Desktop Entry]\nName=Firefox\nExec=firefox\n' >"$XDG_DATA_HOME/applications/org.mozilla.firefox.desktop"
printf '[Desktop Entry]\nName=Hidden\nNoDisplay=true\n' >"$XDG_DATA_HOME/applications/hidden.desktop"
apps=$(XDG_DATA_DIRS="$TMP/none" wardos-menu --list apps)
grep -qx Firefox <<<"$apps" || fail "Apps lists Firefox; got: $apps"
grep -q Hidden <<<"$apps" && fail "NoDisplay entries are hidden"
XDG_DATA_DIRS="$TMP/none" wardos-menu apps Firefox
assert_logged '^gtk-launch org.mozilla.firefox$'

# A .desktop id with shell metacharacters must not be eval'd as a second command (#172).
evil_id="pwn;touch pwned-marker"
printf '[Desktop Entry]\nName=Evil\nExec=true\n' >"$XDG_DATA_HOME/applications/$evil_id.desktop"
(cd "$TMP" && XDG_DATA_DIRS="$TMP/none" wardos-menu apps Evil)
[[ -e "$TMP/pwned-marker" ]] && fail "gtk-launch id was eval'd: shell injection created pwned-marker"
assert_logged "^gtk-launch $evil_id\$"

# Without ward-shell the AGENTS and SECURITY sections are the static list.
rm "$MOCK_DIR/ward-shell"
top=$(wardos-menu --list)
grep -q "^AGENTS *Start Claude$" <<<"$top" || fail "static AGENTS"
grep -q "^SECURITY *Verify current project$" <<<"$top" || fail "static SECURITY"
grep -q "^PROJECTS" <<<"$top" && fail "no PROJECTS without ward-shell"
wardos-menu security "Verify current project"
assert_logged '^wardos-launch terminal ward verify$'

# A fresh desktop: no live session, the walkthrough not done → "Start here" comes first.
mock wardos-welcome
marker="$XDG_CONFIG_HOME/wardos/welcome-done"
top=$(wardos-menu --list)
[[ "$(head -n1 <<<"$top")" =~ ^WELCOME\ +Start\ here$ ]] || fail "Start here is the first row; got: $top"
wardos-menu welcome "Start here"
assert_logged '^wardos-welcome $'
export WARDOS_MENU_CHOICE="WELCOME    Start here"
: >"$MOCK_LOG"
wardos-menu
assert_logged '^wardos-welcome $'
# A session (the shell lists a PROJECTS row) hides it; so does the marker.
mock ward-shell 'printf "AGENTS\tStart Claude\tward claude\n"'
grep -q "^WELCOME" <<<"$(wardos-menu --list)" || fail "no PROJECTS row is no session: Start here stays"
mock ward-shell 'printf "PROJECTS\tapp\tward open /p/app\nAGENTS\tStart Claude\tward claude\n"'
grep -q "^WELCOME" <<<"$(wardos-menu --list)" && fail "a live session hides Start here"
rm "$MOCK_DIR/ward-shell"
mkdir -p "$(dirname "$marker")" && : >"$marker"
grep -q "^WELCOME" <<<"$(wardos-menu --list)" && fail "the marker hides Start here"
# Help keeps the walkthrough reachable afterwards.
wardos-menu help welcome
assert_logged '^wardos-welcome --again$'
grep -qx Welcome <<<"$(wardos-menu --list help)" || fail "Help lists Welcome"

# An unknown path fails.
wardos-menu nowhere 2>/dev/null && fail "unknown path"
exit 0
