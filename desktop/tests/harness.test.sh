#!/usr/bin/env bash
# The harness itself: mocks log their arguments and the menu backend answers from the env.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
mock notify-send
notify-send "hello" "world"
assert_logged '^notify-send hello world$'
assert_not_logged '^hyprctl'
