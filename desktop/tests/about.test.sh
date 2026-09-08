#!/usr/bin/env bash
# wardos-about: fastfetch with the WardOS configuration when present, else plain;
# wardos-version without fastfetch.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
mock fastfetch
mock wardos-version

wardos-about --help | grep -q '^Usage' || fail "--help prints the usage block"

wardos-about
assert_logged '^fastfetch $'
mkdir -p "$XDG_CONFIG_HOME/fastfetch"
: >"$XDG_CONFIG_HOME/fastfetch/config.jsonc"
wardos-about
assert_logged "^fastfetch --config $XDG_CONFIG_HOME/fastfetch/config.jsonc$"
rm "$MOCK_DIR/fastfetch"
wardos-about
assert_logged '^wardos-version $'
