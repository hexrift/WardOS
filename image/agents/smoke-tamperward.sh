#!/usr/bin/env bash
set -euo pipefail

tamperward_bin=${TAMPERWARD_BIN:-/usr/bin/tamperward}
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
repo="$root/repo"
home="$root/home"
mkdir -p "$repo" "$home"

git -C "$repo" init -q
git -C "$repo" config user.email wardos-smoke@invalid
git -C "$repo" config user.name wardos-smoke
printf '%s\n' '{"name":"wardos-tamperward-smoke","private":true,"scripts":{"test":"true"}}' >"$repo/package.json"
git -C "$repo" add package.json
git -C "$repo" commit -qm baseline

HOME="$home" "$tamperward_bin" init --cwd "$repo" >/dev/null
test -s "$repo/.tamperward.yml"

git -C "$repo" add -A
git -C "$repo" -c core.hooksPath=/dev/null commit -qm "tamperward wiring"
HOME="$home" "$tamperward_bin" check --worktree --cwd "$repo" >/dev/null

help=$(HOME="$home" "$tamperward_bin" --help)
grep -Fq 'tamperward run' <<<"$help"
