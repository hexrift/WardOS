#!/usr/bin/env bash
# Regressions for check-multiarch-index.sh (issue #149, acceptance: "one
# architecture failing" is covered): a promoted index must actually carry
# both published platforms, not just satisfy `needs:`.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/check-multiarch-index.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Writes an index json listing the given "os/arch" pairs as manifests and
# prints its path.
index_with() {
  local path="$work/index-$$-$RANDOM.json"
  {
    printf '{"manifests":['
    local first=1 pair os arch
    for pair in "$@"; do
      os=${pair%/*}
      arch=${pair#*/}
      [[ $first == 1 ]] || printf ','
      first=0
      printf '{"platform":{"os":"%s","architecture":"%s"}}' "$os" "$arch"
    done
    printf ']}'
  } >"$path"
  printf '%s' "$path"
}

both="$(index_with linux/amd64 linux/arm64)"
expect_status 0 "both platforms present accepted" bash "$sut" "$both"

amd64_only="$(index_with linux/amd64)"
expect_status 1 "missing arm64 rejected (aarch64 build failed)" bash "$sut" "$amd64_only"

arm64_only="$(index_with linux/arm64)"
expect_status 1 "missing amd64 rejected (x86_64 build failed)" bash "$sut" "$arm64_only"

neither="$(index_with linux/386)"
expect_status 1 "neither published platform present rejected" bash "$sut" "$neither"

expect_status 1 "missing index file rejected" bash "$sut" "$work/does-not-exist.json"

echo "PASS check-multiarch-index.test.sh"
