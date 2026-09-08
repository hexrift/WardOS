#!/usr/bin/env bash
# wardos-font: list (installed monospace + the sans candidates), current, set.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

fonts_conf="$XDG_CONFIG_HOME/wardos/fonts.conf"

mock fc-list 'printf "JetBrains Mono,JetBrains Mono NL\nCommit Mono\nDejaVu Sans Mono\n"'
# shellcheck disable=SC2016  # expanded when the mock runs
mock wardos-theme 'case $1 in current) echo ward-dark ;; esac'
mock notify-send

# --help prints the usage block.
wardos-font --help | grep -q '^wardos-font' || fail "--help should print usage"

# list: fc-list's monospace families (first name of each), then the fixed sans list.
listed=$(wardos-font list)
assert_logged '^fc-list :spacing=mono family$'
echo "$listed" | grep -qx 'JetBrains Mono' || fail "list lacks JetBrains Mono"
echo "$listed" | grep -qx 'Commit Mono' || fail "list lacks Commit Mono"
echo "$listed" | grep -qx 'Inter' || fail "list lacks the sans candidate Inter"
echo "$listed" | grep -qx 'Geist' || fail "list lacks the sans candidate Geist"
if echo "$listed" | grep -q 'JetBrains Mono NL'; then fail "list should keep one name per family"; fi

# current: the theme's defaults until something is set.
assert_eq "$(wardos-font current)" "sans=Inter
mono=JetBrains Mono"

# set <mono family>: writes mono=, re-renders the current theme and reloads.
wardos-font set "Commit Mono"
assert_file "$fonts_conf"
grep -qx 'mono=Commit Mono' "$fonts_conf" || fail "fonts.conf lacks mono=Commit Mono"
assert_logged '^wardos-theme render$'
assert_logged '^wardos-theme reload$'
assert_logged '^notify-send .*Font · Commit Mono$'
assert_eq "$(wardos-font current)" "sans=Inter
mono=Commit Mono"

# A name from the sans list sets sans and keeps mono.
wardos-font set Geist
grep -qx 'sans=Geist' "$fonts_conf" || fail "fonts.conf lacks sans=Geist"
grep -qx 'mono=Commit Mono' "$fonts_conf" || fail "set sans should keep mono"

# The class can be said explicitly.
wardos-font set sans "IBM Plex Sans"
wardos-font set mono "DejaVu Sans Mono"
assert_eq "$(wardos-font current)" "sans=IBM Plex Sans
mono=DejaVu Sans Mono"

# set without a name, and unknown verbs, fail.
if wardos-font set 2>/dev/null; then fail "set without a name should fail"; fi
if wardos-font frobnicate 2>/dev/null; then fail "unknown verb should fail"; fi
