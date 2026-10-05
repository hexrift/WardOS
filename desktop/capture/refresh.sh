#!/usr/bin/env bash
# Put a `desktop capture` run's GIF into assets/wardos-desktop.gif (issue #84,
# docs/desktop.md "The README animation"). No workflow writes to the repository: the
# run uploads the GIF in its wardos-desktop-capture artifact, and a maintainer brings it
# in with this and commits it in a pull request.
#
#   desktop/capture/refresh.sh [--ref REF | --run ID] [--repo OWNER/NAME] [--out PATH]
#
# --ref takes the newest successful run on that branch or tag (default: main); --run
# names one. --out writes somewhere other than assets/wardos-desktop.gif. Needs gh,
# logged in. Prints the old and new size; commits nothing.
set -euo pipefail

usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; }
die() {
  echo "refresh.sh: $*" >&2
  exit 1
}

root=$(cd "$(dirname "$0")/../.." && pwd)
ref=main
run=""
repo=()
out=$root/assets/wardos-desktop.gif
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref) ref=${2:?--ref needs a branch or tag}; shift 2 ;;
    --run) run=${2:?--run needs a run id}; shift 2 ;;
    --repo) repo=(--repo "${2:?--repo needs OWNER/NAME}"); shift 2 ;;
    --out) out=${2:?--out needs a path}; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) echo "refresh.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
command -v gh >/dev/null 2>&1 || die "gh is not installed"
[[ -z $run || $run =~ ^[0-9]+$ ]] || die "--run takes a numeric run id, not '$run'"

if [[ -z $run ]]; then
  run=$(gh run list "${repo[@]}" --workflow desktop-capture.yml --branch "$ref" --status success \
    --limit 1 --json databaseId --jq '.[0].databaseId // empty')
  [[ -n $run ]] || die "no successful desktop capture run on $ref"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
gh run download "$run" "${repo[@]}" --name wardos-desktop-capture --dir "$tmp"
gif=$tmp/wardos-desktop.gif
[[ -s $gif ]] || die "run $run's wardos-desktop-capture artifact has no wardos-desktop.gif"
[[ $(head -c 6 "$gif") == GIF89a ]] || die "run $run's wardos-desktop.gif is not a GIF"

old=0
if [[ -f $out ]]; then old=$(wc -c <"$out"); fi
mkdir -p "$(dirname "$out")"
cp "$gif" "$out"
echo "refresh.sh: $out from run $run: $old -> $(wc -c <"$out") bytes"
