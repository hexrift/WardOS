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

# --- Case (b''): "permit" is an acceptance verb too, not just "accept" --------
{
  good_doc "$tmp/permit.md"
  echo "" >>"$tmp/permit.md"
  echo "Legacy labels permit abbreviated head prefixes." >>"$tmp/permit.md"
}
expect_fail "paraphrased claim using 'permit' instead of 'accept'" \
  "$tmp/permit.md" "claiming a legacy label's SHA prefix is"

# --- Case (b'''): a negation elsewhere in the sentence must not suppress the --
# --- positive claim in its own clause (the bug the clause split exists for) --
{
  good_doc "$tmp/trailing_negation.md"
  echo "" >>"$tmp/trailing_negation.md"
  echo "Legacy labels accept abbreviated head prefixes, not full SHAs." >>"$tmp/trailing_negation.md"
}
expect_fail "claim true in its own clause despite a later, unrelated negation" \
  "$tmp/trailing_negation.md" "claiming a legacy label's SHA prefix is"

# --- Case (b''''): a causal clause ("because ... do not fit") puts an -------
# --- unrelated negation after the claim, same failure mode as (b'''), just ---
# --- via a causal conjunction instead of a comma ------------------------------
{
  good_doc "$tmp/causal_negation.md"
  echo "" >>"$tmp/causal_negation.md"
  echo "Legacy labels accept abbreviated head prefixes because full SHAs do not fit." >>"$tmp/causal_negation.md"
}
expect_fail "claim true in its own causal clause despite a later negation" \
  "$tmp/causal_negation.md" "claiming a legacy label's SHA prefix is"

# --- Case: a literal label name in backticks is code, not an English claim ---
# --- (guards the CODE_SPAN_RE stripping: "allow" inside `tamperward:allow:...` -
# --- must not itself read as the acceptance verb "allow") --------------------
{
  good_doc "$tmp/code_span.md"
  echo "" >>"$tmp/code_span.md"
  echo 'See `tamperward:allow:verify@<sha-prefix>` for the retired label shape.' >>"$tmp/code_span.md"
}
expect_pass "a literal label name in backticks is not an English 'allow' claim" "$tmp/code_span.md"

# --- Case: a claim explicitly marked mistaken in its own clause still passes -
# --- (the same pattern the real doc uses for its own historical quote) -------
{
  good_doc "$tmp/mistaken_premise.md"
  echo "" >>"$tmp/mistaken_premise.md"
  echo "Earlier guidance rested on the mistaken premise that oobToken accepted a prefix of the head SHA." >>"$tmp/mistaken_premise.md"
}
expect_pass "a claim marked mistaken in the same clause is not live guidance" "$tmp/mistaken_premise.md"

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
echo "tamperward-signoff-doc.test.sh: PASS (10/10 cases)"
