#!/usr/bin/env bash
# wardos-version: the image from bootc status, ward and Hyprland versions.
# shellcheck disable=SC2016  # mock bodies are shell text, expanded when the mock runs
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
mock bootc 'case "$*" in "status --json") printf "%s\n" "{\"apiVersion\": \"org.containers.bootc/v1\", \"status\": {\"staged\": {\"image\": {\"image\": {\"image\": \"quay.io/hexrift/wardos:latest\"}, \"version\": \"42.20260908.0\"}}, \"booted\": {\"image\": {\"image\": {\"image\": \"quay.io/hexrift/wardos:latest\"}, \"version\": \"42.20260901.0\"}}}}" ;; esac'
mock ward 'echo "ward 0.6.0"'
mock Hyprland 'printf "Hyprland 0.49.0 built from branch at commit abc\nTag: v0.49.0\n"'

wardos-version --help | grep -q '^Usage' || fail "--help prints the usage block"

out=$(wardos-version)
grep -q '^Image  *quay.io/hexrift/wardos:latest$' <<<"$out" || fail "the booted image; got:
$out"
grep -q '^Version  *42.20260901.0$' <<<"$out" || fail "the booted version, not the staged one"
grep -q '^Staged  *42.20260908.0$' <<<"$out" || fail "a staged update is shown"
grep -q '^ward  *0.6.0$' <<<"$out" || fail "ward's version"
grep -q '^Hyprland  *0.49.0 built from branch at commit abc$' <<<"$out" || fail "Hyprland's first line"

rm "$MOCK_DIR/bootc" "$MOCK_DIR/ward" "$MOCK_DIR/Hyprland"
out=$(wardos-version)
grep -q '^Image  *not a bootc host$' <<<"$out" || fail "no bootc"
grep -q '^ward  *not installed$' <<<"$out" || fail "no ward"
