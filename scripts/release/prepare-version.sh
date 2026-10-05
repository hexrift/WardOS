#!/usr/bin/env bash
# Prepare the repository for a dedicated WardOS release PR.
#
# Usage: scripts/release/prepare-version.sh <version> [--node <node-version>]
#
# Ordinary feature/fix PRs are version-neutral. Run this helper only on a
# release branch immediately before opening the release PR.
#
# <version> is the workspace version: the runtime, the image and every crate that
# inherits it. The node train (ward-node and ward-node-client) is versioned on its
# own (issue #275): --node sets it, in both crates and in every path requirement on
# them; without --node it is left as it is. Either way the node version is then
# checked for consistency and, when a previous release tag is reachable, against
# that release (scripts/release/node-version.sh): it must move exactly when the
# node's inputs moved.
set -euo pipefail

cd "$(dirname "$0")/../.."

usage="usage: scripts/release/prepare-version.sh <version> [--node <node-version>]"
raw=""
node_raw=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --node)
      [[ $# -ge 2 ]] || { echo "prepare-version: $usage" >&2; exit 1; }
      node_raw="$2"
      shift 2
      ;;
    --*)
      echo "prepare-version: unknown option '$1'; $usage" >&2
      exit 1
      ;;
    *)
      [[ -z "$raw" ]] || { echo "prepare-version: $usage" >&2; exit 1; }
      raw="$1"
      shift
      ;;
  esac
done
[[ -n "$raw" ]] || { echo "prepare-version: $usage" >&2; exit 1; }
version="${raw#v}"
semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'

if [[ ! "$version" =~ $semver_re ]]; then
  echo "prepare-version: not a valid SemVer version: '$raw'" >&2
  exit 1
fi
node_version=""
if [[ -n "$node_raw" ]]; then
  node_version="${node_raw#v}"
  if [[ ! "$node_version" =~ $semver_re ]]; then
    echo "prepare-version: not a valid SemVer node version: '$node_raw'" >&2
    exit 1
  fi
fi

python3 - "$version" "$node_version" <<'PY'
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

version = sys.argv[1]
node_version = sys.argv[2]
root = Path(".")
NODE_TRAIN = {"ward-node", "ward-node-client"}

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

node_manifests = {name for name in workspace_names if name in NODE_TRAIN}
if node_version and node_manifests != NODE_TRAIN:
    raise SystemExit(
        "prepare-version: --node needs both node crates in the workspace: "
        + ", ".join(sorted(NODE_TRAIN))
    )

changed_requirements = 0
changed_node_requirements = 0
changed_node_versions = 0
for manifest in manifest_paths:
    text = manifest.read_text()
    with manifest.open("rb") as handle:
        package_name_here = tomllib.load(handle)["package"]["name"]
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    in_package = False

    for line in lines:
        new_line = line
        stripped = line.strip()
        if stripped.startswith("["):
            in_package = stripped == "[package]"
        elif (
            in_package
            and node_version
            and package_name_here in NODE_TRAIN
            and re.match(r'^\s*version\s*=\s*"', line)
        ):
            new_line, replacements = re.subn(
                r'^(\s*version\s*=\s*")[^"]+(".*)$',
                rf'\g<1>{node_version}\g<2>',
                line,
                count=1,
            )
            changed_node_versions += replacements
        elif "path" in line and "version" in line and "=" in line:
            dependency_key = line.split("=", 1)[0].strip()
            package_match = re.search(r'\bpackage\s*=\s*"([^"]+)"', line)
            package_name = package_match.group(1) if package_match else dependency_key

            if package_name in NODE_TRAIN:
                if node_version:
                    new_line, replacements = re.subn(
                        r'(\bversion\s*=\s*")[^"]+(")',
                        rf'\g<1>{node_version}\g<2>',
                        line,
                        count=1,
                    )
                    changed_node_requirements += replacements
            elif package_name in workspace_names:
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
if node_version:
    if changed_node_versions != len(NODE_TRAIN):
        raise SystemExit(
            f"prepare-version: expected to set a literal version in {len(NODE_TRAIN)} node crates, "
            f"set {changed_node_versions}; the node crates must carry version = \"...\" of their own"
        )
    print(
        f"prepare-version: set node version to {node_version} in {changed_node_versions} crate(s); "
        f"updated {changed_node_requirements} requirement(s) on the node train."
    )
PY

# Let Cargo refresh only what the manifest edits require in Cargo.lock, then prove
# the resulting lockfile and workspace metadata are internally consistent.
cargo metadata --format-version 1 >/dev/null
cargo metadata --format-version 1 --locked >/dev/null

bash scripts/release/check-version.sh "v$version"

# The node train's version: consistent across its crates and, when the previous
# release is reachable, moved exactly with the node's inputs since it.
if [[ -f crates/ward-node/Cargo.toml ]]; then
  previous_release="$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || true)"
  if [[ -n "$previous_release" ]]; then
    node_version="$(bash scripts/release/node-version.sh --since "$previous_release")"
    echo "prepare-version: node version $node_version checked against $previous_release."
  else
    node_version="$(bash scripts/release/node-version.sh)"
    echo "prepare-version: node version $node_version is consistent; no previous release tag reachable to compare with."
  fi
fi

echo "prepare-version: ready for a dedicated release PR for v$version."
