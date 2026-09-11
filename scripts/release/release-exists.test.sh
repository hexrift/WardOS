#!/usr/bin/env bash
# Regressions for release-exists.sh (issue #126): a release lookup must tell a
# clean 404 (no release -> create allowed) apart from any other failure
# (auth/API/network -> hard fail, create NOT authorized). A failed READ must
# never look like "no release exists".
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/release-exists.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

export GITHUB_REPOSITORY="hexrift/WardOS"

# A fake `gh api` steered by env:
#   FAKE_RC      exit status (default 0 = release exists)
#   FAKE_STDERR  text written to stderr (used to carry the "(HTTP 404)" marker)
fake_gh() {
  local path="$work/gh"
  cat >"$path" <<'EOF'
#!/usr/bin/env bash
[[ -n "${FAKE_STDERR:-}" ]] && printf '%s\n' "$FAKE_STDERR" >&2
exit "${FAKE_RC:-0}"
EOF
  chmod +x "$path"
  printf '%s' "$path"
}
GH="$(fake_gh)"
export GH

# Release exists: the probe succeeds -> exit 0 (caller reconciles/uploads).
expect_status 0 "an existing release is reported present" \
  env GH="$GH" FAKE_RC=0 bash "$sut" v1.2.3

# Clean 404: no release -> exit 2 (caller may create).
expect_status 2 "a clean 404 is not-found (create allowed)" \
  env GH="$GH" FAKE_RC=1 FAKE_STDERR='gh: Not Found (HTTP 404)' bash "$sut" v1.2.3

# Non-404 HTTP error (e.g. auth/5xx): hard fail -> exit 1, NOT not-found.
expect_status 1 "a 403 lookup error fails closed (not treated as not-found)" \
  env GH="$GH" FAKE_RC=1 FAKE_STDERR='gh: Must have admin rights (HTTP 403)' bash "$sut" v1.2.3

expect_status 1 "a 500 lookup error fails closed" \
  env GH="$GH" FAKE_RC=1 FAKE_STDERR='gh: Server Error (HTTP 500)' bash "$sut" v1.2.3

# Transport/network failure (no HTTP marker at all): hard fail -> exit 1.
expect_status 1 "a network failure fails closed" \
  env GH="$GH" FAKE_RC=1 FAKE_STDERR='error connecting to api.github.com: connection refused' bash "$sut" v1.2.3

# A missing repository env is an error, not a silent pass.
expect_status 1 "missing GITHUB_REPOSITORY rejected" \
  env -u GITHUB_REPOSITORY GH="$GH" FAKE_RC=0 bash "$sut" v1.2.3

echo "PASS release-exists.test.sh"
