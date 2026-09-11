#!/usr/bin/env bash
# Fail a merge-authority run if agent attribution or an AI session link appears in
# PR metadata, commit messages, or added file content.
set -euo pipefail

c='Clau''de'
session_pat='claude[.](ai|com)/code/'"session"'_[A-Za-z0-9_-]+'
generated_pat="Generated[[:space:]]+(with|by).*${c}([[:space:]]+Code)?"
coauthor_pat="Co-Authored-By:[[:space:]]*${c}"
built_pat="Built[[:space:]]+using[[:space:]]+${c}[[:space:]]+on[[:space:]]+behalf[[:space:]]+of"
session_trailer_pat="${c}-Session:"
pat="(${session_pat}|${generated_pat}|${coauthor_pat}|${built_pat}|${session_trailer_pat})"

fail=0
scan() {
  local surface=$1 text=$2
  if printf '%s' "$text" | grep -Eiq "$pat"; then
    echo "::error::${surface} contains prohibited agent attribution or session metadata." >&2
    fail=1
  fi
}

scan "PR title/body" "${PR_TITLE:-}
${PR_BODY:-}"

base="${PR_BASE:-}"
head="${PR_HEAD:-HEAD}"
if [[ -n "$base" ]] && git cat-file -e "${base}^{commit}" 2>/dev/null && git cat-file -e "${head}^{commit}" 2>/dev/null; then
  commits="$(git log --format=%B "${base}..${head}" || true)"
  scan "commit message" "$commits"

  added="$(git diff "${base}...${head}" -- | grep -E '^\+' | grep -vE '^\+\+\+' || true)"
  scan "added repository content" "$added"
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

echo "agent-attribution guard: clean"
