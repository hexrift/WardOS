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

# `--check-config` only exists from fuzzel ~1.11; the image ships 1.14 (where the real check
# runs), but some CI archives (Ubuntu noble ships fuzzel 1.9.2) do not have the flag. On such
# a fuzzel the flag is an "invalid option", which must SKIP (documenting the gap) — NOT be
# misread as "the shipped config was rejected". Only a fuzzel that SUPPORTS the flag and then
# reports a real config error is a FAIL. Detect support from --help first.
if ! fuzzel --help 2>&1 | grep -q -- '--check-config'; then
  echo "skip fuzzel-config.test.sh: this fuzzel ($(fuzzel --version 2>&1 | head -n1)) has no --check-config (needs ~1.11+, e.g. the image's 1.14; some CI archives ship an older fuzzel — run the real check on the image)"
  exit 0
fi

# The [main] section includes the per-human RENDERED theme fragment. Provide a stub for it so
# `--check-config` validates the shipped config's own grammar without assuming a particular
# human's theme has been rendered — the runtime guarantees it exists (wardos-theme on first login
# and the desktop autostart), and the menus guard it in wardos-menu-select ([[ -f ]]).
theme_ini="$HOME/.config/wardos/theme/current/fuzzel.ini"
mkdir -p "$(dirname "$theme_ini")"
: >"$theme_ini"

out=$(fuzzel --check-config --config "$shipped" 2>&1) && rc=0 || rc=$?
if [[ $rc -ne 0 ]]; then
  # A getopt-style "invalid/unrecognized option" here means THIS fuzzel does not actually
  # support the flag after all (belt-and-suspenders past the --help probe) — skip, don't fail.
  if grep -qiE 'invalid option|unrecognized option' <<<"$out"; then
    echo "skip fuzzel-config.test.sh: fuzzel reports --check-config unsupported ($out)"
    exit 0
  fi
  # A supported flag that reports a real config error IS a failure. Show the error.
  echo "$out"
  fail "fuzzel --check-config rejected the shipped config (see the error above)"
fi

echo "ok   fuzzel-config.test.sh internal assertions"
