#!/usr/bin/env bash
# Regression coverage for tamperward-signoff-doc.py (issue #320, PR #323 review).
#
# The checker used to try to decide "does this sentence claim a legacy
# label's SHA prefix is accepted" from prose with a regex negation
# heuristic. Three review rounds each supplied a paraphrase that defeated
# the current heuristic (a trailing "not full SHAs", a causal "because ...
# do not fit", and a fourth negating an unrelated earlier verb within
# lookback range) - proof the approach doesn't converge, not just three
# bugs to patch. The checker now enforces structure instead: the word
# "prefix" may only appear, in prose, inside one reviewed block in section
# 4.4, and that block's exact content is pinned by a SHA-256 hash. Any
# prefix-related claim anywhere else fails outright, regardless of
# wording; any edit inside the reviewed block - true or false - fails
# until a human updates the pinned hash. This suite exercises both halves
# of that mechanism, plus the version-pin guard from the same checker.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="$here/tamperward-signoff-doc.py"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fails=0

BLOCK_START="<!-- tamperward-prefix-guidance:reviewed-block:start -->"
BLOCK_END="<!-- tamperward-prefix-guidance:reviewed-block:end -->"

workflow_pinned_2_33_0() {
  cat >"$1" <<'EOF'
name: tamperward
jobs:
  tamperward:
    steps:
      - run: npx --yes tamperward@2.33.0 check --diff x
  tamperward-verify:
    steps:
      - run: npx --yes tamperward@2.33.0 verify --base x
EOF
}

# A minimal doc with a correctly-marked reviewed block. $1 = output path,
# $2 = the block's inner content (defaults to a real, correct paragraph).
doc_with_block() {
  local out=$1 block_content=${2:-$'\n* Legacy labels: a SHA `prefix` is rejected outright by this pinned CLI.\nSee `tamperward signoff-label` for the `tw1:` token that actually works.\n'}
  {
    echo "### 4.4 Out-of-band sign-off mechanics"
    echo
    echo "Generate a sign-off with \`tamperward signoff-label --rule verify --head <sha>\`"
    echo "(tamperward@2.33.0) and apply the resulting \`tw1:<digest>\` label."
    echo
    echo "$BLOCK_START"
    printf '%s' "$block_content"
    echo "$BLOCK_END"
  } >"$out"
}

block_sha256() {
  python3 -c '
import hashlib, sys
doc = open(sys.argv[1], encoding="utf-8").read()
s = doc.find(sys.argv[2]) + len(sys.argv[2])
e = doc.find(sys.argv[3])
print(hashlib.sha256(doc[s:e].encode("utf-8")).hexdigest())
' "$1" "$BLOCK_START" "$BLOCK_END"
}

run_checker() {
  # $1 = doc path, $2 = pinned sha256 (optional, defaults to the doc's own)
  local doc=$1 pin=${2:-}
  if [[ -z "$pin" ]]; then
    pin=$(block_sha256 "$doc")
  fi
  python3 "$checker" --workflow "$tmp/workflow.yml" --doc "$doc" --pinned-sha256 "$pin"
}

expect_pass() {
  local name=$1 doc=$2 pin=${3:-}
  if run_checker "$doc" "$pin" >"$tmp/out" 2>&1; then
    echo "ok - $name (correctly passed)"
  else
    echo "FAIL - $name: expected PASS, checker rejected a clean doc:" >&2
    cat "$tmp/out" >&2
    fails=$((fails + 1))
  fi
}

expect_fail() {
  local name=$1 doc=$2 must_mention=$3 pin=${4:-}
  if run_checker "$doc" "$pin" >"$tmp/out" 2>&1; then
    echo "FAIL - $name: expected the checker to reject this doc, but it passed" >&2
    fails=$((fails + 1))
  elif ! grep -qF "$must_mention" "$tmp/out"; then
    echo "FAIL - $name: checker rejected the doc but not for the expected reason" >&2
    echo "  expected output to mention: $must_mention" >&2
    cat "$tmp/out" >&2
    fails=$((fails + 1))
  else
    echo "ok - $name (correctly rejected: $must_mention)"
  fi
}

workflow_pinned_2_33_0 "$tmp/workflow.yml"

# --- Baseline: a correctly-marked, correctly-pinned doc passes ----------------
doc_with_block "$tmp/good.md"
expect_pass "clean doc: reviewed block present and hash matches" "$tmp/good.md"

# --- Missing markers entirely fails --------------------------------------------
cat >"$tmp/no_markers.md" <<'EOF'
### 4.4 Out-of-band sign-off mechanics

Ask a maintainer to sort it out somehow. Uses `tw1:` and `signoff-label`.
EOF
expect_fail "doc has no reviewed-block markers at all" "$tmp/no_markers.md" \
  "missing the \`$BLOCK_START\`"

# --- Any of the three review-round counterexamples, placed OUTSIDE the block, -
# --- fail on the location constraint - wording no longer matters --------------
n=0
for phrasing in \
  "Legacy labels permit abbreviated head prefixes." \
  "Legacy labels accept abbreviated head prefixes, not full SHAs." \
  "Legacy labels accept abbreviated head prefixes because full SHAs do not fit." \
  "Legacy labels do not require full SHAs and accept abbreviated head prefixes."
do
  doc="$tmp/outside_$((++n)).md"
  {
    doc_with_block "$doc"
    echo "" >>"$doc"
    echo "$phrasing" >>"$doc"
  }
  expect_fail "outside-block claim rejected regardless of phrasing: $phrasing" \
    "$doc" "outside the reviewed"
done

# --- The same false claim placed INSIDE the block fails on the content pin, --
# --- not on prose analysis - this is the case that defeated three rounds of --
# --- the old heuristic, and the new mechanism doesn't try to parse it at all -
{
  doc_with_block "$tmp/bad_inside.md" \
    $'\nLegacy labels do not require full SHAs and accept abbreviated head prefixes.\n'
}
expect_fail "false claim inside the block fails on the stale content pin" \
  "$tmp/bad_inside.md" "content changed" "$(block_sha256 "$tmp/good.md")"

# --- ANY edit inside the block fails until the hash is updated - even a true -
# --- correction, proving this isn't a truth-detector, just a change-detector -
{
  doc_with_block "$tmp/edited_inside.md" \
    $'\n* Legacy labels: a SHA `prefix` is rejected outright, even more clearly worded now.\n'
}
expect_fail "even a strictly-better rewording inside the block needs its pin bumped" \
  "$tmp/edited_inside.md" "content changed" "$(block_sha256 "$tmp/good.md")"

# --- Updating the pin alongside a content edit passes - the mechanism's job is
# --- "this was a reviewed, deliberate change", not "this text is true" -------
expect_pass "an edited block passes once its own new hash is supplied" \
  "$tmp/edited_inside.md"

# --- A prefix mention outside the block still fails even when the block's own
# --- pin is otherwise fine - the two checks are independent ------------------
{
  doc_with_block "$tmp/both.md"
  echo "" >>"$tmp/both.md"
  echo "A stray prefix mention here should still be caught." >>"$tmp/both.md"
}
expect_fail "outside-block mention still caught even with a matching pin" \
  "$tmp/both.md" "outside the reviewed"

# --- Version-pin guard (unchanged mechanism, still covered here) -------------
{
  doc_with_block "$tmp/stale.md"
  echo "" >>"$tmp/stale.md"
  echo "Historically this repository pinned tamperward@2.10.3." >>"$tmp/stale.md"
}
expect_fail "stale version alongside the current pin" "$tmp/stale.md" "stale tamperward version"

# --- Missing the canonical tw1:/signoff-label guidance entirely --------------
cat >"$tmp/missing_tw1.md" <<'EOF'
### 4.4 Out-of-band sign-off mechanics

<!-- tamperward-prefix-guidance:reviewed-block:start -->
* Ask a maintainer to sort it out somehow.
<!-- tamperward-prefix-guidance:reviewed-block:end -->
EOF
expect_fail "doc omits tw1:/signoff-label guidance entirely" "$tmp/missing_tw1.md" "missing 'tw1:'"

if [[ $fails -gt 0 ]]; then
  echo "tamperward-signoff-doc.test.sh: $fails case(s) failed" >&2
  exit 1
fi
echo "tamperward-signoff-doc.test.sh: PASS"
