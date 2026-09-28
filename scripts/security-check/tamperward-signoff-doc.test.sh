#!/usr/bin/env bash
# Regression coverage for tamperward-signoff-doc.py (issue #320, PR #323 review).
#
# The checker exists to stop two specific mistakes from reappearing in
# docs/development-under-tamperward.md: a stale tamperward version sitting
# alongside the real pin, and any claim - exact wording or a paraphrase -
# that a legacy tamperward:allow:<rule>@<sha> label's abbreviated SHA prefix
# is accepted. Each case below builds a minimal fixture pair and asserts the
# checker's exit status, so a change that quietly stops enforcing either
# invariant fails a test rather than shipping silently.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="$here/tamperward-signoff-doc.py"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fails=0

# A workflow fixture pinning a single tamperward version, once per case.
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

good_doc() {
  cat >"$1" <<'EOF'
### 4.4 Out-of-band sign-off mechanics

Generate a sign-off with `tamperward signoff-label --rule verify --head <sha>`
(tamperward@2.33.0) and apply the resulting `tw1:<digest>` label. A legacy
`tamperward:allow:<rule>@<sha-prefix>` label's SHA prefix is rejected outright
by this pinned CLI once a full head is supplied - it is not accepted, and
cannot clear a check here. Do not rely on it.
EOF
}

run_checker() {
  python3 "$checker" --workflow "$tmp/workflow.yml" --doc "$1"
}

expect_pass() {
  local name=$1 doc=$2
  if run_checker "$doc" >"$tmp/out" 2>&1; then
    echo "ok - $name (correctly passed)"
  else
    echo "FAIL - $name: expected PASS, checker rejected a clean doc:" >&2
    cat "$tmp/out" >&2
    fails=$((fails + 1))
  fi
}

expect_fail() {
  local name=$1 doc=$2 must_mention=$3
  if run_checker "$doc" >"$tmp/out" 2>&1; then
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

# --- Baseline: the clean doc passes -------------------------------------------
good_doc "$tmp/good.md"
expect_pass "clean doc matching the pin, no prefix claim" "$tmp/good.md"

# --- Case (a): current pin alongside a stale one still fails ------------------
{
  good_doc "$tmp/stale.md"
  echo "" >>"$tmp/stale.md"
  echo "Historically this repository pinned tamperward@2.10.3." >>"$tmp/stale.md"
}
expect_fail "stale version alongside the current pin" "$tmp/stale.md" "stale tamperward version"

# --- Case (b): the exact original banned sentence still fails -----------------
{
  good_doc "$tmp/exact.md"
  echo "" >>"$tmp/exact.md"
  echo "tamperward's OOB-signoff matcher accepts any *prefix* of the head SHA that is at least 7 hex characters." >>"$tmp/exact.md"
}
expect_fail "exact original claim (accepts any *prefix* of the head SHA)" "$tmp/exact.md" "claiming a legacy label's SHA prefix is"

# --- Case (b'): a paraphrase of the same false claim still fails --------------
{
  good_doc "$tmp/paraphrase.md"
  echo "" >>"$tmp/paraphrase.md"
  echo "Legacy labels accept abbreviated head prefixes, so a short SHA is enough." >>"$tmp/paraphrase.md"
}
expect_fail "paraphrased claim (legacy labels accept abbreviated head prefixes)" \
  "$tmp/paraphrase.md" "claiming a legacy label's SHA prefix is"

# --- Case: missing the canonical tw1:/signoff-label guidance entirely ---------
cat >"$tmp/missing.md" <<'EOF'
### 4.4 Out-of-band sign-off mechanics

Ask a maintainer to sort it out somehow.
EOF
expect_fail "doc omits tw1:/signoff-label guidance entirely" "$tmp/missing.md" "missing 'tw1:'"

if [[ $fails -gt 0 ]]; then
  echo "tamperward-signoff-doc.test.sh: $fails case(s) failed" >&2
  exit 1
fi
echo "tamperward-signoff-doc.test.sh: PASS (5/5 cases)"
