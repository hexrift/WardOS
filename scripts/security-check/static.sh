#!/usr/bin/env bash
# Static security checks that do not need a build.
# Phase 0: verifies the documentation set that security claims depend on is present and
# that no private key material or credential-looking strings are committed.
set -euo pipefail

cd "$(dirname "$0")/../.."

required_docs=(
  docs/architecture.md
  docs/threat-model.md
  docs/security-model.md
  docs/snapshots-and-git.md
  docs/event-model.md
  docs/credential-broker.md
  docs/tamperward-integration.md
  docs/development-under-tamperward.md
  docs/design-language.md
  docs/performance.md
  docs/experiments.md
  docs/roadmap.md
  docs/repository-structure.md
  docs/decisions/README.md
)

status=0
for f in "${required_docs[@]}"; do
  if [[ ! -s "$f" ]]; then
    echo "static: missing required document: $f" >&2
    status=1
  fi
done

# No private key material in the repository.
if git grep -n -E -e '-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----' -- ':!scripts/security-check/static.sh' >/dev/null 2>&1; then
  echo "static: private key material found in repository" >&2
  status=1
fi

# No obvious long-lived credentials committed (heuristic; broker design forbids these).
if git grep -n -E -e 'ghp_[A-Za-z0-9]{36}' -e 'AKIA[0-9A-Z]{16}' -e 'sk-ant-[A-Za-z0-9_-]{20,}' -- ':!scripts/security-check/static.sh' >/dev/null 2>&1; then
  echo "static: credential-like string found in repository" >&2
  status=1
fi

if [[ $status -eq 0 ]]; then
  echo "static: PASS"
fi
exit $status
