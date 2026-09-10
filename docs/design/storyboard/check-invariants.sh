#!/usr/bin/env bash
# Design-invariant guard for the Ward Field prototypes (ADR-0021, DESIGN.md).
# Fails if the implementation drifts from the specification. Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")"
files=(index.html ward-field.html wardos.html)
fail=0
bad() { echo "INVARIANT FAILED: $1" >&2; fail=1; }

for f in "${files[@]}"; do
  # No remote fonts / external asset URLs.
  grep -qiE 'googleapis|fonts\.gstatic|@import[^;]*https?:' "$f" && bad "$f imports remote fonts/assets"
  # No glassmorphism.
  grep -qi 'backdrop-filter' "$f" && bad "$f uses backdrop-filter (glass)"
  # No CSS gradients in chrome (canvas ctx.createRadialGradient in JS is allowed and does not match).
  grep -qE '(linear-gradient|radial-gradient)\(' "$f" && bad "$f uses a CSS gradient in chrome"
  # Reduced-motion path must exist.
  grep -q 'prefers-reduced-motion' "$f" || bad "$f has no prefers-reduced-motion path"
  # Room vocabulary: RESEARCH is retired; numbered ROOM UI is retired.
  grep -qi 'RESEARCH' "$f" && bad "$f still references the retired RESEARCH room"
  grep -qE 'ROOM 0[0-9]' "$f" && bad "$f still uses numbered ROOM UI"
  # The canonical rooms must be present.
  for r in BUILD VERIFY SHIP; do grep -q "$r" "$f" || bad "$f is missing room $r"; done
done

if [[ $fail -eq 0 ]]; then echo "design invariants: OK (${#files[@]} files)"; else exit 1; fi
