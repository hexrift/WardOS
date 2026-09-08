#!/usr/bin/env bash
# Check that every name in image/packages.txt is a package in the Fedora release the
# Containerfile pins (its FROM tag) plus the COPRs of image/coprs.txt.
#
#   image/check-packages.sh [--file FILE] [--coprs FILE] [--release N] [--dry-run]
#
# Strips comments from both manifests, then inside a quay.io/fedora/fedora:<release>
# container (docker, or podman when docker is absent; CONTAINER_RUNTIME= overrides)
# enables each COPR the way the Containerfile does (dnf5-plugins, `dnf copr enable`)
# and asks `dnf repoquery` which of the names resolve; fails listing every name that
# did not. Exact package names only: a name that dnf would accept as a "provides" still
# fails here, so the manifest stays honest. --dry-run prints the command.
# CI: verify.yml, job "image packages".
set -euo pipefail

usage() {
  sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
}

repo_root=$(cd "$(dirname "$0")/.." && pwd)
file=$repo_root/image/packages.txt
coprs_file=$repo_root/image/coprs.txt
# The release comes from the Containerfile's FROM line, so the check and the build
# cannot drift apart; --release overrides for a trial against another one.
release=$(sed -n 's|^FROM quay.io/fedora/fedora-bootc:\([0-9][0-9]*\)$|\1|p' "$repo_root/image/Containerfile" | head -n 1)
dry_run=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --file) file=$2; shift 2 ;;
    --file=*) file=${1#--file=}; shift ;;
    --coprs) coprs_file=$2; shift 2 ;;
    --coprs=*) coprs_file=${1#--coprs=}; shift ;;
    --release) release=$2; shift 2 ;;
    --release=*) release=${1#--release=}; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "check-packages.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

strip() { sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$1"; }

if [[ ! "$release" =~ ^[0-9]+$ ]]; then
  echo "check-packages.sh: no fedora-bootc:<release> FROM line in image/Containerfile; pass --release" >&2
  exit 1
fi
if [[ ! "$release" =~ ^[0-9]+$ ]]; then
  echo "check-packages.sh: no fedora-bootc:<release> FROM line in image/Containerfile; pass --release" >&2
  exit 1
fi
if [[ ! -f "$file" ]]; then
  echo "check-packages.sh: manifest not found: $file" >&2
  exit 1
fi
mapfile -t names < <(strip "$file" | sort -u)
if [[ ${#names[@]} -eq 0 ]]; then
  echo "check-packages.sh: $file names no packages" >&2
  exit 1
fi
coprs=()
if [[ -f "$coprs_file" ]]; then
  mapfile -t coprs < <(strip "$coprs_file")
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

# The inner script takes the COPR count, the COPRs, then the names, all as arguments,
# never interpolated. Everything but the repoquery result goes to stderr so stdout is
# exactly the resolved names. `%{name}\n` is what dnf5 (Fedora 41+) wants; dnf4 adds
# its own newline, hence the blank-line filter below.
# shellcheck disable=SC2016  # the $1/$@ are for the inner bash, expanded in the container
inner='set -e; n=$1; shift; if [ "$n" -gt 0 ]; then dnf -y -q install dnf5-plugins >&2; fi; while [ "$n" -gt 0 ]; do echo "copr enable $1" >&2; dnf -y -q copr enable "$1" >&2; shift; n=$((n - 1)); done; dnf -q repoquery --qf "%{name}\n" "$@"'
cmd=("$runtime" run --rm "quay.io/fedora/fedora:${release}"
  bash -c "$inner" -- "${#coprs[@]}")
if [[ ${#coprs[@]} -gt 0 ]]; then cmd+=("${coprs[@]}"); fi
cmd+=("${names[@]}")

printf 'check-packages.sh: %d names from %s, %d COPRs from %s; would run:\n  ' \
  "${#names[@]}" "$file" "${#coprs[@]}" "$coprs_file"
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
errlog="${TMPDIR:-/tmp}/check-packages.err"
resolved=$("${cmd[@]}" 2>"$errlog") || status=$?
mapfile -t missing < <(comm -23 <(printf '%s\n' "${names[@]}") <(printf '%s\n' "$resolved" | sed '/^$/d' | sort -u))

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "check-packages.sh: ${#missing[@]} of ${#names[@]} names do not exist in Fedora ${release} (COPRs: ${coprs[*]:-none}):" >&2
  printf '  %s\n' "${missing[@]}" >&2
  echo "fix the names in $file or add a COPR to $coprs_file (image/README.md, \"Packages\")" >&2
  if [[ $status -ne 0 ]]; then
    echo "dnf exited with $status; its stderr:" >&2
    cat "$errlog" >&2
  fi
  exit 1
fi
if [[ $status -ne 0 ]]; then
  echo "check-packages.sh: every name resolved but dnf exited with $status:" >&2
  cat "$errlog" >&2
  exit "$status"
fi
echo "check-packages.sh: all ${#names[@]} names exist in Fedora ${release} with COPRs: ${coprs[*]:-none}"
