#!/usr/bin/env bash
# Regressions for check-version.sh (issue #126): tag/version binding and safe,
# grammar-gated handling of the dispatch value.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/check-version.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A Cargo.toml whose [workspace.package] version is $1.
cargo_toml() {
  local ver=$1
  local path="$work/Cargo-$ver.toml"
  cat >"$path" <<EOF
[workspace]
members = ["a"]

[workspace.package]
version = "$ver"
edition = "2021"
EOF
  printf '%s' "$path"
}

ct="$(cargo_toml 0.6.0)"

# The tag naming exactly the workspace version is accepted.
expect_status 0 "matching tag accepted" bash "$sut" v0.6.0 "$ct"

# A tag that names a different version is rejected (wrong version).
expect_status 1 "wrong version rejected" bash "$sut" v0.6.1 "$ct"
expect_status 1 "wrong version (v10.6.0) rejected" bash "$sut" v10.6.0 "$ct"

# SemVer prerelease / build metadata tags bind to matching workspace versions.
ct_rc="$(cargo_toml 1.2.3-rc.1)"
expect_status 0 "prerelease tag accepted" bash "$sut" v1.2.3-rc.1 "$ct_rc"
ct_meta="$(cargo_toml 1.2.3+meta)"
expect_status 0 "build-metadata tag accepted" bash "$sut" v1.2.3+meta "$ct_meta"

# Grammar gate: shell-metacharacter-bearing dispatch values never execute and
# are rejected before the version comparison. The canary file must not appear.
canary="$work/pwned"
rm -f "$canary"
expect_status 1 "semicolon injection rejected" bash "$sut" "v0.6.0; touch $canary" "$ct"
expect_status 1 "command-substitution injection rejected" bash "$sut" "v0.6.0\$(touch $canary)" "$ct"
expect_status 1 "backtick injection rejected" bash "$sut" "v0.6.0\`touch $canary\`" "$ct"
[[ ! -e "$canary" ]] || fail "injection executed: '$canary' was created"
echo "ok   no injection executed"

# A tag with no v prefix, or an empty tag, is not a release tag.
expect_status 1 "non-v tag rejected" bash "$sut" 0.6.0 "$ct"
expect_status 1 "empty tag rejected" bash "$sut" "" "$ct"

# A missing Cargo.toml is an error, not a silent pass.
expect_status 1 "missing Cargo.toml rejected" bash "$sut" v0.6.0 "$work/nope.toml"

echo "PASS check-version.test.sh"
