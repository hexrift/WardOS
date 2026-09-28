#!/usr/bin/env bash
# Regression coverage for tamperward-signoff-doc.py (issue #320, PR #323 review).
#
# The checker used to try to decide "does this sentence claim a legacy
# label's SHA prefix is accepted" from prose with a regex negation
# heuristic. Three review rounds each supplied a paraphrase that defeated
# the current heuristic (a trailing "not full SHAs", a causal "because ...
# do not fit", and a fourth negating an unrelated earlier verb within
# lookback range). A fourth round then showed that scoping the *location*
# of reviewed content by the single word "prefix" has the same problem one
# level up: "legacy labels accept abbreviated head SHAs" carries the same
# meaning without that word, so it could be added right next to the
# reviewed bullets and never be flagged.
#
# The checker now pins section 4.4 in its entirety by content hash, rather
# than naming every word that could carry the meaning it's trying to
# contain. This suite exercises: the whole-section pin (an edit anywhere in
# the section, whatever it's worded as, fails until the hash is updated);
# the secondary word-based signal for content entirely outside the section;
# and the unrelated version-pin guard from the same checker.
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

# A minimal doc shaped like the real section: a heading, then the whole
# reviewed block (everything up to :end), then the next section's heading.
# $1 = output path, $2 = the block's inner content (a real, correct
# paragraph by default).
doc_with_section() {
  local out=$1
  local block_content=${2:-$'\nGenerate a sign-off with `tamperward signoff-label --rule verify --head <sha>`\n(tamperward@2.33.0) and apply the resulting `tw1:<digest>` label.\n\n* Legacy labels: a SHA `prefix` is rejected outright by this pinned CLI.\n'}
  {
    echo "### 4.4 Out-of-band sign-off mechanics"
    echo
    echo "$BLOCK_START"
    printf '%s' "$block_content"
    echo "$BLOCK_END"
    echo
    echo "## 5. What the dogfooding loop is expected to surface"
  } >"$out"
}

section_sha256() {
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
    pin=$(section_sha256 "$doc")
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
doc_with_section "$tmp/good.md"
expect_pass "clean doc: reviewed section present and hash matches" "$tmp/good.md"

# --- Missing markers entirely fails --------------------------------------------
cat >"$tmp/no_markers.md" <<'EOF'
### 4.4 Out-of-band sign-off mechanics

Ask a maintainer to sort it out somehow. Uses `tw1:` and `signoff-label`.
EOF
expect_fail "doc has no reviewed-block markers at all" "$tmp/no_markers.md" \
  "missing the \`$BLOCK_START\`"

# --- The exact review-round counterexample, appended INSIDE section 4.4 ------
# --- (right after the existing bullets, before :end) - this is the literal --
# --- reproduction from the review: a paraphrase with no word this checker ---
# --- could have listed, placed right next to already-reviewed guidance ------
{
  doc_with_section "$tmp/inside_wordless.md" \
    $'\n* Legacy labels: a SHA `prefix` is rejected outright by this pinned CLI.\nLegacy labels accept abbreviated head SHAs.\n'
}
expect_fail "wordless-of-prefix false claim inside the section fails on the pin" \
  "$tmp/inside_wordless.md" "content changed" "$(section_sha256 "$tmp/good.md")"

# --- Every prior counterexample, appended INSIDE the section, is caught the --
# --- same way - the whole-section pin doesn't care what changed or how ------
n=0
for phrasing in \
  "Legacy labels permit abbreviated head prefixes." \
  "Legacy labels accept abbreviated head prefixes, not full SHAs." \
  "Legacy labels accept abbreviated head prefixes because full SHAs do not fit." \
  "Legacy labels do not require full SHAs and accept abbreviated head prefixes."
do
  doc="$tmp/inside_$((++n)).md"
  doc_with_section "$doc" \
    "$(printf '\n* Legacy labels: a SHA `prefix` is rejected outright by this pinned CLI.\n%s\n' "$phrasing")"
  expect_fail "prior counterexample inside the section still fails on the pin: $phrasing" \
    "$doc" "content changed" "$(section_sha256 "$tmp/good.md")"
done

# --- ANY edit inside the section fails until the hash is updated - even a ----
# --- true correction, proving this is a change-detector, not a truth-detector
{
  doc_with_section "$tmp/edited_inside.md" \
    $'\nGenerate a sign-off with `tamperward signoff-label --rule verify --head <sha>`\n(tamperward@2.33.0) and apply the resulting `tw1:<digest>` label.\n\n* Legacy labels: a SHA `prefix` is rejected outright, even more clearly worded now.\n'
}
expect_fail "even a strictly-better rewording inside the section needs its pin bumped" \
  "$tmp/edited_inside.md" "content changed" "$(section_sha256 "$tmp/good.md")"

# --- Updating the pin alongside a content edit passes - the mechanism's job is
# --- "this was a reviewed, deliberate change", not "this text is true" -------
expect_pass "an edited section passes once its own new hash is supplied" \
  "$tmp/edited_inside.md"

# --- Secondary signal: "prefix" appearing truly outside section 4.4 (after ---
# --- its :end marker) is still flagged, independent of the section's own ----
# --- pin - documented as best-effort, not the load-bearing guarantee --------
{
  doc_with_section "$tmp/outside.md"
  echo "" >>"$tmp/outside.md"
  echo "A stray prefix mention out here should still be caught." >>"$tmp/outside.md"
}
expect_fail "a 'prefix' mention truly outside the section is still caught" \
  "$tmp/outside.md" "outside section 4.4"

# --- ...but that secondary signal is only a best-effort word match, not a ----
# --- guarantee: the same wordless-of-"prefix" claim, placed truly outside the
# --- section instead of right next to it, passes silently - the documented, --
# --- accepted residual scope boundary (see the module docstring) -------------
{
  doc_with_section "$tmp/outside_wordless.md"
  echo "" >>"$tmp/outside_wordless.md"
  echo "Legacy labels accept abbreviated head SHAs." >>"$tmp/outside_wordless.md"
}
expect_pass "documented residual gap: a wordless-of-prefix claim truly outside the section is not caught" \
  "$tmp/outside_wordless.md"

# --- Version-pin guard (unchanged mechanism, still covered here) -------------
{
  doc_with_section "$tmp/stale.md"
  echo "" >>"$tmp/stale.md"
  echo "Historically this repository pinned tamperward@2.10.3." >>"$tmp/stale.md"
}
expect_fail "stale version alongside the current pin" "$tmp/stale.md" "stale tamperward version"

# --- Missing the canonical tw1:/signoff-label guidance entirely --------------
cat >"$tmp/missing_tw1.md" <<EOF
### 4.4 Out-of-band sign-off mechanics

$BLOCK_START
* Ask a maintainer to sort it out somehow.
$BLOCK_END
EOF
expect_fail "doc omits tw1:/signoff-label guidance entirely" "$tmp/missing_tw1.md" "missing 'tw1:'"

if [[ $fails -gt 0 ]]; then
  echo "tamperward-signoff-doc.test.sh: $fails case(s) failed" >&2
  exit 1
fi
echo "tamperward-signoff-doc.test.sh: PASS"
