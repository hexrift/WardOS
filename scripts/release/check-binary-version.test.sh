#!/usr/bin/env bash
# Regressions for check-binary-version.sh (issue #126): the packaged binary must
# report the release version as a whole token, compared literally so every valid
# Cargo SemVer works and no substring/adjacent version sneaks through.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/check-binary-version.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A fake `ward`-like binary that prints "ward <reported>" for `--version`.
fake_ward() {
  local reported=$1 path="$work/ward"
  cat >"$path" <<EOF
#!/usr/bin/env bash
[[ "\$1" == "--version" ]] && echo "ward $reported"
EOF
  chmod +x "$path"
  printf '%s' "$path"
}

# Valid SemVer forms: reported == expected is accepted for each.
expect_status 0 "plain semver accepted"        bash "$sut" 1.2.3        "$(fake_ward 1.2.3)"
expect_status 0 "prerelease semver accepted"   bash "$sut" 1.2.3-rc.1   "$(fake_ward 1.2.3-rc.1)"
expect_status 0 "build-metadata semver accepted" bash "$sut" 1.2.3+meta "$(fake_ward 1.2.3+meta)"

# Whole-token, literal match: expecting 1.2.3 must reject near-misses.
expect_status 1 "trailing-zero (1.2.30) rejected"  bash "$sut" 1.2.3 "$(fake_ward 1.2.30)"
expect_status 1 "different major (10.6.0) rejected" bash "$sut" 0.6.0 "$(fake_ward 10.6.0)"
expect_status 1 "substring (0.6.00) rejected"       bash "$sut" 0.6.0 "$(fake_ward 0.6.00)"
expect_status 1 "unrelated version rejected"        bash "$sut" 1.2.3 "$(fake_ward 9.9.9)"

# The token must stand alone even when the binary prints extra words.
expect_status 0 "token among extra words accepted" bash "$sut" 1.2.3 "$(
  p="$work/ward"; printf '#!/usr/bin/env bash\necho "ward 1.2.3 (deadbeef 2026-01-01)"\n' >"$p"; chmod +x "$p"; printf '%s' "$p")"

echo "PASS check-binary-version.test.sh"
