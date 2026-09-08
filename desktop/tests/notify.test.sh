#!/usr/bin/env bash
# wardos-notify: notify-send with the WardOS defaults; --done toasts; no exclamation marks.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
mock notify-send

wardos-notify --help | grep -q '^Usage' || fail "--help prints the usage block"

wardos-notify "Title" "Body"
assert_logged '^notify-send -a WardOS Title Body$'
wardos-notify "Title"
assert_logged '^notify-send -a WardOS Title $'
wardos-notify -u critical -i battery-low "Low"
assert_logged '^notify-send -a WardOS -u critical -i battery-low Low $'
# --done: the ✓ glyph of design-language.md §11, a short toast, "Finished" by default.
wardos-notify --done "Build"
assert_logged '^notify-send -a WardOS -t 3000 ✓ Build Finished$'
wardos-notify --done "Tests" "184/184"
assert_logged '^notify-send -a WardOS -t 3000 ✓ Tests 184/184$'
# §9: no exclamation marks, whoever wrote them.
wardos-notify "Done!" "Really!!"
assert_logged '^notify-send -a WardOS Done Really$'
wardos-notify 2>/dev/null && fail "a title is required"
exit 0
