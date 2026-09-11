#!/usr/bin/env bash
# Regressions for check-tag-commit.sh (issue #126): before publishing, an
# existing tag must resolve to the exact build commit -- INDEPENDENTLY of whether
# a GitHub Release exists yet. The flagged case (tag at a different commit, no
# release yet) must fail; an absent tag is fine (create binds it); a non-404
# lookup error fails closed.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/check-tag-commit.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

export GITHUB_REPOSITORY="hexrift/WardOS"
build_sha="1111111111111111111111111111111111111111"
other_sha="2222222222222222222222222222222222222222"
tag_obj_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# A fake `gh api` for the tag-ref and tag-object endpoints, steered by env:
#   FAKE_REF_RC      exit of the git/ref/tags/<tag> lookup (default 0)
#   FAKE_REF_STDERR  stderr for that lookup (carries the "(HTTP 404)" marker)
#   FAKE_OBJ_SHA     .object.sha of the ref
#   FAKE_OBJ_TYPE    .object.type of the ref (commit | tag)
#   FAKE_DEREF_SHA   .object.sha reached by dereferencing an annotated tag
fake_gh() {
  local path="$work/gh"
  cat >"$path" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
endpoint="" ; jq=""
shift  # drop "api"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --jq) jq="$2"; shift 2 ;;
    repos/*) endpoint="$1"; shift ;;
    *) shift ;;
  esac
done
case "$endpoint" in
  */git/ref/tags/*)
    [[ -n "${FAKE_REF_STDERR:-}" ]] && printf '%s\n' "$FAKE_REF_STDERR" >&2
    rc="${FAKE_REF_RC:-0}"
    [[ "$rc" -ne 0 ]] && exit "$rc"
    case "$jq" in
      .object.sha)  printf '%s\n' "${FAKE_OBJ_SHA:-}" ;;
      .object.type) printf '%s\n' "${FAKE_OBJ_TYPE:-commit}" ;;
    esac
    ;;
  */git/tags/*)
    printf '%s\n' "${FAKE_DEREF_SHA:-}"
    ;;
  *)
    echo "fake gh: unexpected endpoint: $endpoint" >&2; exit 99 ;;
esac
EOF
  chmod +x "$path"
  printf '%s' "$path"
}
GH="$(fake_gh)"
export GH

# Tag exists (lightweight) at the build commit -> pass.
expect_status 0 "lightweight tag at build commit passes" \
  env GH="$GH" FAKE_REF_RC=0 FAKE_OBJ_TYPE=commit FAKE_OBJ_SHA="$build_sha" \
  bash "$sut" v1.2.3 "$build_sha"

# Tag exists (annotated) and dereferences to the build commit -> pass.
expect_status 0 "annotated tag dereferencing to build commit passes" \
  env GH="$GH" FAKE_REF_RC=0 FAKE_OBJ_TYPE=tag FAKE_OBJ_SHA="$tag_obj_sha" FAKE_DEREF_SHA="$build_sha" \
  bash "$sut" v1.2.3 "$build_sha"

# The flagged case: tag exists at a DIFFERENT commit and no release exists yet
# -> must fail (create must not bind a new release to unrelated source).
expect_status 1 "tag at a different commit fails even with no release yet" \
  env GH="$GH" FAKE_REF_RC=0 FAKE_OBJ_TYPE=commit FAKE_OBJ_SHA="$other_sha" \
  bash "$sut" v1.2.3 "$build_sha"

# Annotated tag dereferencing to a different commit is also refused.
expect_status 1 "annotated tag at a different commit is refused" \
  env GH="$GH" FAKE_REF_RC=0 FAKE_OBJ_TYPE=tag FAKE_OBJ_SHA="$tag_obj_sha" FAKE_DEREF_SHA="$other_sha" \
  bash "$sut" v1.2.3 "$build_sha"

# Tag absent (clean 404) -> pass; the create path may bind it to the build commit.
expect_status 0 "absent tag (404) passes; create may bind it" \
  env GH="$GH" FAKE_REF_RC=1 FAKE_REF_STDERR='gh: Not Found (HTTP 404)' \
  bash "$sut" v1.2.3 "$build_sha"

# Non-404 ref lookup error -> fail closed, NOT treated as absent.
expect_status 1 "a non-404 tag-lookup error fails closed" \
  env GH="$GH" FAKE_REF_RC=1 FAKE_REF_STDERR='gh: Server Error (HTTP 500)' \
  bash "$sut" v1.2.3 "$build_sha"

# Missing repository env is an error, not a silent pass.
expect_status 1 "missing GITHUB_REPOSITORY rejected" \
  env -u GITHUB_REPOSITORY GH="$GH" FAKE_OBJ_SHA="$build_sha" \
  bash "$sut" v1.2.3 "$build_sha"

echo "PASS check-tag-commit.test.sh"
