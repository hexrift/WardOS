#!/usr/bin/env bash
# E1 (A3): the shipped desktop fuzzel config parses under the image's fuzzel grammar. Fedora 44
# ships fuzzel 1.14, where the old boolean `fuzzy=` and an empty `launch-prefix=` are rejected;
# `fuzzel --check-config` is the machine check that the shipped config is valid for that grammar.
#
# Gated: fuzzel is a Wayland binary not present on every CI runner or dev box. Where it is
# absent this test SKIPS (documenting the gap) rather than faking a pass — the CI `desktop`
# job installs fuzzel where the archive has it and runs this check there.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

shipped="$WARDOS_ROOT/config/fuzzel/fuzzel.ini"
assert_file "$shipped"

if ! command -v fuzzel >/dev/null 2>&1; then
  echo "skip fuzzel-config.test.sh: fuzzel not installed (run where fuzzel 1.14 is available; CI desktop job installs it)"
  exit 0
fi

# The [main] section includes the per-human RENDERED theme fragment. Provide a stub for it so
# `--check-config` validates the shipped config's own grammar without assuming a particular
# human's theme has been rendered — the runtime guarantees it exists (wardos-theme on first login
# and the desktop autostart), and the menus guard it in wardos-menu-select ([[ -f ]]).
theme_ini="$HOME/.config/wardos/theme/current/fuzzel.ini"
mkdir -p "$(dirname "$theme_ini")"
: >"$theme_ini"

if ! fuzzel --check-config --config "$shipped" >/dev/null 2>&1; then
  # Re-run without redirection so the grammar error is visible in the test output.
  fuzzel --check-config --config "$shipped" || true
  fail "fuzzel --check-config rejected the shipped config (see the error above)"
fi

echo "ok   fuzzel-config.test.sh internal assertions"
