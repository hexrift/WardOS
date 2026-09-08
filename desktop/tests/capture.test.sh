#!/usr/bin/env bash
# wardos-capture: screenshots through grim/slurp/satty, recording toggle, colour picker.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
exec >/dev/null
# shellcheck disable=SC2016  # mock bodies are expanded when the mock runs
mock grim '[[ "${!#}" == - ]] || : >"${!#}"'
mock slurp 'echo "10,20 300x200"'
mock wl-copy
mock notify-send
mock wf-recorder
mock hyprpicker 'echo "#7fa1c3"'
# A runner without user-dirs.dirs: xdg-user-dir answers $HOME, which must not be used.
# shellcheck disable=SC2016
mock xdg-user-dir 'echo "$HOME"'
unset XDG_PICTURES_DIR XDG_VIDEOS_DIR
mock hyprctl "case \"\$*\" in 'activewindow -j') printf '{\"at\": [100, 50], \"size\": [640, 480], \"class\": \"foot\"}\n' ;; 'activeworkspace -j') printf '{\"monitor\": \"DP-1\"}\n' ;; esac"
shots="$HOME/Pictures/Screenshots"

wardos-capture --help | grep -q '^Usage' || fail "--help prints the usage block"

# Without satty: grim to a file, copied with wl-copy, a notification, the path remembered.
wardos-capture screenshot region
assert_logged '^slurp'
assert_logged "^grim -g 10,20 300x200 $shots/[0-9-]+_[0-9-]+\.png$"
assert_logged "^wl-copy"
assert_logged '^notify-send -a WardOS .*Screenshot'
assert_file "$XDG_STATE_HOME/wardos/last-screenshot"
assert_file "$(cat "$XDG_STATE_HOME/wardos/last-screenshot")"

wardos-capture screenshot window
assert_logged "^grim -g 100,50 640x480 $shots/"
wardos-capture screenshot output
assert_logged "^grim -o DP-1 $shots/"
# The default is a region.
: >"$MOCK_LOG"
wardos-capture screenshot
assert_logged '^grim -g 10,20 300x200'
# XDG_PICTURES_DIR wins over xdg-user-dir.
XDG_PICTURES_DIR="$TMP/pics" wardos-capture screenshot
assert_logged "^grim -g 10,20 300x200 $TMP/pics/Screenshots/"

# With satty: grim to stdout, satty annotates and saves.
mock satty 'cat >/dev/null'
: >"$MOCK_LOG"
wardos-capture screenshot region
assert_logged '^grim -g 10,20 300x200 -$'
assert_logged "^satty --filename - --output-filename $shots/.*\.png --copy-command wl-copy"

# record: the first call starts wf-recorder and keeps its pid, the second stops it.
mock wf-recorder 'sleep 30'
wardos-capture record region
assert_logged "^wf-recorder -g 10,20 300x200 -f $HOME/Videos/Screencasts/[0-9-]+_[0-9-]+\.mp4$"
assert_file "$XDG_STATE_HOME/wardos/record.pid"
pid=$(cat "$XDG_STATE_HOME/wardos/record.pid")
# A stopped mock may linger as a zombie when nothing reaps it here; that counts as stopped.
alive() { [[ "$(ps -o stat= -p "$1" 2>/dev/null)" =~ ^[^Z] ]]; }
alive "$pid" || fail "the recorder is running"
assert_logged '^notify-send -a WardOS .*Recording'
wardos-capture record
[[ ! -e "$XDG_STATE_HOME/wardos/record.pid" ]] || fail "the pid file is gone after a stop"
sleep 0.2
alive "$pid" && fail "the recorder was stopped"
assert_logged '^notify-send -a WardOS .*stopped'
wardos-capture record output
assert_logged '^wf-recorder -o DP-1 -f '
wardos-capture record

# A stale pid file (the recorder died) does not block a new recording.
echo 999999 >"$XDG_STATE_HOME/wardos/record.pid"
: >"$MOCK_LOG"
wardos-capture record region
assert_logged '^wf-recorder -g'
wardos-capture record

# color: hyprpicker -a copies, the notification shows the value.
wardos-capture color
assert_logged '^hyprpicker -a$'
assert_logged '^notify-send -a WardOS .*#7fa1c3'
