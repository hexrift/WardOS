#!/usr/bin/env bash
# Prepare the repository for a dedicated WardOS release PR.
#
# Usage: scripts/release/prepare-version.sh <version>
#
# Ordinary feature/fix PRs are version-neutral. Run this helper only on a
# release branch immediately before opening the release PR.
set -euo pipefail

cd "$(dirname "$0")/../.."

raw="${1:?usage: scripts/release/prepare-version.sh <version>}"
version="${raw#v}"
semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'

if [[ ! "$version" =~ $semver_re ]]; then
  echo "prepare-version: not a valid SemVer version: '$raw'" >&2
  exit 1
fi

python3 - "$version" <<'PY'
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

version = sys.argv[1]
root = Path(".")

workspace_toml = root / "Cargo.toml"
workspace_text = workspace_toml.read_text()

section = re.search(
    r"(?ms)^\[workspace\.package\]\s*$.*?(?=^\[|\Z)",
    workspace_text,
)
if section is None:
    raise SystemExit("prepare-version: missing [workspace.package] in Cargo.toml")

block = section.group(0)
updated_block, count = re.subn(
    r'(?m)^(\s*version\s*=\s*")[^"]+(".*)$',
    rf'\g<1>{version}\g<2>',
    block,
    count=1,
)
if count != 1:
    raise SystemExit("prepare-version: expected exactly one workspace.package version")

workspace_text = (
    workspace_text[: section.start()]
    + updated_block
    + workspace_text[section.end() :]
)
workspace_toml.write_text(workspace_text)

with workspace_toml.open("rb") as handle:
    workspace = tomllib.load(handle)

members = workspace.get("workspace", {}).get("members", [])
workspace_names: set[str] = set()
manifest_paths: list[Path] = []

for member in members:
    manifest = root / member / "Cargo.toml"
    if not manifest.is_file():
        raise SystemExit(f"prepare-version: workspace member has no manifest: {manifest}")
    manifest_paths.append(manifest)
    with manifest.open("rb") as handle:
        data = tomllib.load(handle)
    name = data.get("package", {}).get("name")
    if not isinstance(name, str) or not name:
        raise SystemExit(f"prepare-version: workspace member has no package.name: {manifest}")
    workspace_names.add(name)

changed_requirements = 0
for manifest in manifest_paths:
    lines = manifest.read_text().splitlines(keepends=True)
    out: list[str] = []

    for line in lines:
        new_line = line
        if "path" in line and "version" in line and "=" in line:
            dependency_key = line.split("=", 1)[0].strip()
            package_match = re.search(r'\bpackage\s*=\s*"([^"]+)"', line)
            package_name = package_match.group(1) if package_match else dependency_key

            if package_name in workspace_names:
                new_line, replacements = re.subn(
                    r'(\bversion\s*=\s*")[^"]+(")',
                    rf'\g<1>{version}\g<2>',
                    line,
                    count=1,
                )
                changed_requirements += replacements

        out.append(new_line)

    manifest.write_text("".join(out))

print(
    f"prepare-version: set workspace version to {version}; "
    f"updated {changed_requirements} internal path dependency requirement(s)."
)
PY

# Let Cargo refresh only what the manifest edits require in Cargo.lock, then prove
# the resulting lockfile and workspace metadata are internally consistent.
cargo metadata --format-version 1 >/dev/null
cargo metadata --format-version 1 --locked >/dev/null

bash scripts/release/check-version.sh "v$version"

echo "prepare-version: ready for a dedicated release PR for v$version."
