#!/usr/bin/env bash
# Regression coverage for protocol-window.py (issue #275).
#
# The checker compares the node protocol range ward-node serves (the
# WARD_NODE_PROTOCOL constant in crates/ward-node-protocol/src/lib.rs) with the
# compatibility window docs/compatibility.md promises external control planes
# (its `<!-- protocol-window: M.a-M.b -->` marker). Each case below builds a
# fixture source file and doc, then expects a PASS or a FAIL that names the
# expected reason.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="$here/protocol-window.py"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fails=0

# $1 = output path, $2 = the constant's arguments, e.g. "1, 0, 3".
source_with_range() {
  cat >"$1" <<EOF
/// The node protocol version currently implemented by this revision.
pub const WARD_NODE_PROTOCOL: SupportedProtocolRange = SupportedProtocolRange::valid($2);

pub const CAPABILITY_DISCOVERY_PROTOCOL: ProtocolVersion = ProtocolVersion::new(1, 1);
EOF
}

# $1 = output path, $2 = the marker line (verbatim; empty for none).
doc_with_marker() {
  {
    echo "# Node protocol compatibility"
    echo
    if [[ -n "$2" ]]; then
      echo "$2"
    fi
    echo
    echo "The node serves protocol 1.0 through 1.3."
  } >"$1"
}

run_checker() {
  python3 "$checker" --source "$1" --doc "$2"
}

expect_pass() {
  local name=$1 src=$2 doc=$3
  if run_checker "$src" "$doc" >"$tmp/out" 2>&1; then
    echo "ok - $name (correctly passed)"
  else
    echo "FAIL - $name: expected PASS, checker rejected it:" >&2
    cat "$tmp/out" >&2
    fails=$((fails + 1))
  fi
}

expect_fail() {
  local name=$1 src=$2 doc=$3 must_mention=$4
  if run_checker "$src" "$doc" >"$tmp/out" 2>&1; then
    echo "FAIL - $name: expected the checker to reject this, but it passed" >&2
    fails=$((fails + 1))
  elif ! grep -qF -- "$must_mention" "$tmp/out"; then
    echo "FAIL - $name: checker rejected it but not for the expected reason" >&2
    echo "  expected output to mention: $must_mention" >&2
    cat "$tmp/out" >&2
    fails=$((fails + 1))
  else
    echo "ok - $name (correctly rejected: $must_mention)"
  fi
}

source_with_range "$tmp/code-1.0-1.3.rs" "1, 0, 3"
source_with_range "$tmp/code-1.0-1.4.rs" "1, 0, 4"
doc_with_marker "$tmp/doc-1.0-1.3.md" "<!-- protocol-window: 1.0-1.3 -->"
doc_with_marker "$tmp/doc-1.0-1.4.md" "<!-- protocol-window: 1.0-1.4 -->"

# --- Code and doc agree ---------------------------------------------------------
expect_pass "code and doc both say 1.0-1.3" "$tmp/code-1.0-1.3.rs" "$tmp/doc-1.0-1.3.md"

# rustfmt may wrap the constant; the parse must not depend on one line.
cat >"$tmp/code-wrapped.rs" <<'EOF'
pub const WARD_NODE_PROTOCOL: SupportedProtocolRange =
    SupportedProtocolRange::valid(
        1,
        0,
        3,
    );
EOF
expect_pass "a wrapped constant still parses" "$tmp/code-wrapped.rs" "$tmp/doc-1.0-1.3.md"

# --- One side widened without the other ----------------------------------------
expect_fail "code widened to 1.4 without the doc" \
  "$tmp/code-1.0-1.4.rs" "$tmp/doc-1.0-1.3.md" "disagree"
expect_fail "doc widened to 1.4 without the code" \
  "$tmp/code-1.0-1.3.rs" "$tmp/doc-1.0-1.4.md" "disagree"

# A retired minor (window narrowed at the bottom) must also be documented.
source_with_range "$tmp/code-1.1-1.3.rs" "1, 1, 3"
expect_fail "code retired 1.0 without the doc" \
  "$tmp/code-1.1-1.3.rs" "$tmp/doc-1.0-1.3.md" "disagree"

# A major bump is a disagreement too.
source_with_range "$tmp/code-2.0-2.0.rs" "2, 0, 0"
expect_fail "code moved to major 2 without the doc" \
  "$tmp/code-2.0-2.0.rs" "$tmp/doc-1.0-1.3.md" "disagree"

# --- Missing or ambiguous markers ------------------------------------------------
doc_with_marker "$tmp/doc-none.md" ""
expect_fail "doc has no protocol-window marker" \
  "$tmp/code-1.0-1.3.rs" "$tmp/doc-none.md" "no protocol-window marker"

{
  doc_with_marker "$tmp/doc-twice.md" "<!-- protocol-window: 1.0-1.3 -->"
  echo "<!-- protocol-window: 1.0-1.4 -->" >>"$tmp/doc-twice.md"
}
expect_fail "doc has two protocol-window markers" \
  "$tmp/code-1.0-1.3.rs" "$tmp/doc-twice.md" "more than one protocol-window marker"

cat >"$tmp/code-none.rs" <<'EOF'
pub const CAPABILITY_DISCOVERY_PROTOCOL: ProtocolVersion = ProtocolVersion::new(1, 1);
EOF
expect_fail "source has no WARD_NODE_PROTOCOL constant" \
  "$tmp/code-none.rs" "$tmp/doc-1.0-1.3.md" "no WARD_NODE_PROTOCOL"

# --- Malformed markers and constants ---------------------------------------------
n=0
for marker in \
  "<!-- protocol-window: 1.x-1.3 -->" \
  "<!-- protocol-window: 1.0 -->" \
  "<!-- protocol-window: 1.0-2.3 -->" \
  "<!-- protocol-window: 1.3-1.0 -->" \
  "<!-- protocol-window: -->"
do
  doc="$tmp/doc-malformed-$((++n)).md"
  doc_with_marker "$doc" "$marker"
  expect_fail "malformed marker: $marker" "$tmp/code-1.0-1.3.rs" "$doc" "malformed"
done

source_with_range "$tmp/code-inverted.rs" "1, 3, 0"
expect_fail "inverted constant (min_minor > max_minor)" \
  "$tmp/code-inverted.rs" "$tmp/doc-1.0-1.3.md" "malformed"

source_with_range "$tmp/code-symbolic.rs" "1, 0, MAX_MINOR"
expect_fail "constant that is not three integer literals" \
  "$tmp/code-symbolic.rs" "$tmp/doc-1.0-1.3.md" "malformed"

if [[ $fails -gt 0 ]]; then
  echo "protocol-window.test.sh: $fails case(s) failed" >&2
  exit 1
fi
echo "protocol-window.test.sh: PASS"
