#!/usr/bin/env bash
# Check that every name in image/packages.txt is a package in Fedora 42.
#
#   image/check-packages.sh [--file FILE] [--release N] [--dry-run]
#
# Strips comments from the manifest, asks `dnf repoquery` inside a
# quay.io/fedora/fedora:<release> container (docker, or podman when docker is absent;
# CONTAINER_RUNTIME= overrides) which of the names resolve, and fails listing every name
# that did not. Exact package names only: a name that dnf would accept as a "provides"
# still fails here, so the manifest stays honest. --dry-run prints the command.
# CI: verify.yml, job "image packages".
set -euo pipefail

usage() {
  sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
}

repo_root=$(cd "$(dirname "$0")/.." && pwd)
file=$repo_root/image/packages.txt
release=42
dry_run=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --file) file=$2; shift 2 ;;
    --file=*) file=${1#--file=}; shift ;;
    --release) release=$2; shift 2 ;;
    --release=*) release=${1#--release=}; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "check-packages.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! -f "$file" ]]; then
  echo "check-packages.sh: manifest not found: $file" >&2
  exit 1
fi
mapfile -t names < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$file" | sort -u)
if [[ ${#names[@]} -eq 0 ]]; then
  echo "check-packages.sh: $file names no packages" >&2
  exit 1
fi

runtime=${CONTAINER_RUNTIME:-}
if [[ -z "$runtime" ]]; then
  if command -v docker >/dev/null 2>&1; then
    runtime=docker
  elif command -v podman >/dev/null 2>&1; then
    runtime=podman
  else
    runtime=docker
  fi
fi

# The names are arguments of the inner shell, never interpolated into it. `%{name}\n`
# is what dnf5 (Fedora 41+) wants; dnf4 adds its own newline, hence the blank-line filter.
cmd=("$runtime" run --rm "quay.io/fedora/fedora:${release}"
  bash -c 'dnf -q repoquery --qf "%{name}\n" "$@"' --
  "${names[@]}")

printf 'check-packages.sh: %d names from %s; would run:\n  ' "${#names[@]}" "$file"
printf '%q ' "${cmd[@]}"
printf '\n'
if [[ $dry_run -eq 1 ]]; then
  exit 0
fi
if ! command -v "$runtime" >/dev/null 2>&1; then
  echo "check-packages.sh: $runtime is not installed; install docker or podman, or use --dry-run" >&2
  exit 1
fi

status=0
resolved=$("${cmd[@]}" 2>"${TMPDIR:-/tmp}/check-packages.err") || status=$?
mapfile -t missing < <(comm -23 <(printf '%s\n' "${names[@]}") <(printf '%s\n' "$resolved" | sed '/^$/d' | sort -u))

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "check-packages.sh: ${#missing[@]} of ${#names[@]} names do not exist in Fedora ${release}:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  echo "fix the names in $file (see image/README.md, \"Packages\")" >&2
  exit 1
fi
if [[ $status -ne 0 ]]; then
  echo "check-packages.sh: every name resolved but dnf exited with $status:" >&2
  cat "${TMPDIR:-/tmp}/check-packages.err" >&2
  exit "$status"
fi
echo "check-packages.sh: all ${#names[@]} names exist in Fedora ${release}"
