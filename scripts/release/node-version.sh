#!/usr/bin/env bash
# The node train's version, and whether it moved with the node (issue #275).
#
# Usage: node-version.sh [--root <dir>] [--since <previous-release-ref>]
#
# The node train -- `ward-node` and `ward-node-client` (`ward-node-adapter`), the
# two crates the node tarball ships -- is versioned on its own, apart from the
# workspace version the runtime and the image carry. This script is the single
# reader of that version. Without `--since` it prints the node version after
# proving it is consistent: both crates carry the same literal SemVer `version`
# (not `version.workspace = true`), and every path dependency on either names it.
#
# With `--since <ref>` it also holds the version to the previous release: the node
# version must differ from the one at <ref> exactly when the node's inputs differ,
# and then be higher. The inputs are what the node binaries are built from:
#
#   - every workspace crate in the dependency closure of the two node crates,
#     without its tests/ and benches/ (Cargo.lock names the closure);
#   - every locked third-party package in that closure (name, version, source,
#     checksum), so a bumped dependency of the node counts and one only another
#     crate uses does not;
#   - rust-toolchain.toml and .cargo/config.toml;
#   - the [profile] table of the workspace manifest.
#
# Documents, release scripts, and the workspace version itself are not inputs: a
# release that only bumps the workspace version and ships the same node keeps the
# node version, and the same node version then names the same source. If <ref>
# had no node crate, any valid node version is accepted (the first node release).
# If its node crate inherited the workspace version, that is the version the node
# shipped under then, and the comparison is against it.
#
# Exit codes:
#   0  consistent (and, with --since, moved exactly with the node); the version is
#      printed on stdout.
#   1  usage, a missing or malformed manifest, an unknown ref, or a version that is
#      not SemVer or inherits the workspace version.
#   2  the node crates disagree, or a path requirement on one names another version.
#   3  the node's inputs changed since <ref> and the node version did not.
#   4  the node version changed since <ref> and nothing the node is built from did.
#   5  the node's inputs changed and the node version is not higher than at <ref>.
set -euo pipefail

root="."
since=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) root="${2:?--root needs a directory}"; shift 2 ;;
    --since) since="${2:?--since needs a ref}"; shift 2 ;;
    *) echo "node-version: unknown argument '$1'" >&2
       echo "usage: node-version.sh [--root <dir>] [--since <previous-release-ref>]" >&2
       exit 1 ;;
  esac
done

[[ -f "$root/Cargo.toml" ]] || { echo "node-version: no workspace manifest at '$root/Cargo.toml'" >&2; exit 1; }

python3 - "$root" "$since" <<'PY'
from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
since = sys.argv[2]

NODE_TRAIN = ("ward-node", "ward-node-client")
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


def refuse(code: int, message: str) -> None:
    print(f"node-version: {message}", file=sys.stderr)
    sys.exit(code)


def load_toml(text: str, what: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        refuse(1, f"{what} is not valid TOML: {error}")


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)


def show(ref: str, path: str) -> str | None:
    result = git("show", f"{ref}:{path}")
    return result.stdout if result.returncode == 0 else None


def semver_key(version: str):
    match = SEMVER.match(version)
    core = tuple(int(part) for part in match.group(1, 2, 3))
    prerelease = match.group(4)
    if prerelease is None:
        return (core, 1, ())
    identifiers = []
    for identifier in prerelease.split("."):
        if identifier.isdigit():
            identifiers.append((0, int(identifier), ""))
        else:
            identifiers.append((1, 0, identifier))
    return (core, 0, tuple(identifiers))


# --- the workspace at HEAD (working tree) -----------------------------------

workspace = load_toml((root / "Cargo.toml").read_text(), "Cargo.toml")
members = workspace.get("workspace", {}).get("members")
if not isinstance(members, list):
    refuse(1, "Cargo.toml has no [workspace] members")

manifests: dict[str, tuple[str, dict]] = {}
for member in members:
    path = root / member / "Cargo.toml"
    if not path.is_file():
        refuse(1, f"workspace member has no manifest: {member}/Cargo.toml")
    data = load_toml(path.read_text(), f"{member}/Cargo.toml")
    name = data.get("package", {}).get("name")
    if not isinstance(name, str) or not name:
        refuse(1, f"{member}/Cargo.toml has no package.name")
    manifests[name] = (member, data)

for crate in NODE_TRAIN:
    if crate not in manifests:
        refuse(1, f"the workspace has no '{crate}' crate; the node train is {', '.join(NODE_TRAIN)}")

versions: dict[str, str] = {}
for crate in NODE_TRAIN:
    member, data = manifests[crate]
    version = data["package"].get("version")
    if isinstance(version, dict):
        refuse(
            1,
            f"{member}/Cargo.toml inherits the workspace version; the node train is versioned "
            f"on its own: write version = \"<node version>\" (scripts/release/prepare-version.sh --node)",
        )
    if not isinstance(version, str) or not SEMVER.match(version):
        refuse(1, f"{member}/Cargo.toml: version '{version}' is not SemVer")
    versions[crate] = version

node_version = versions[NODE_TRAIN[0]]
for crate, version in versions.items():
    if version != node_version:
        refuse(
            2,
            f"the node crates disagree: {manifests[NODE_TRAIN[0]][0]} is {node_version}, "
            f"{manifests[crate][0]} is {version}; the node tarball ships both under one version",
        )


def dependency_tables(data: dict):
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        if isinstance(data.get(key), dict):
            yield data[key]
    for target in data.get("target", {}).values():
        if isinstance(target, dict):
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                if isinstance(target.get(key), dict):
                    yield target[key]


for name, (member, data) in manifests.items():
    for table in dependency_tables(data):
        for key, spec in table.items():
            if not isinstance(spec, dict) or "path" not in spec:
                continue
            package = spec.get("package", key)
            if package not in NODE_TRAIN:
                continue
            requirement = spec.get("version")
            if requirement != node_version:
                refuse(
                    2,
                    f"{member}/Cargo.toml requires {package} at version '{requirement}', "
                    f"but the node train is {node_version}",
                )

if not since:
    print(node_version)
    sys.exit(0)

# --- against the previous release --------------------------------------------

if git("rev-parse", "--verify", "--quiet", f"{since}^{{commit}}").returncode != 0:
    refuse(1, f"'{since}' is not a commit or tag of this repository")

node_member = manifests[NODE_TRAIN[0]][0]
previous_manifest = show(since, f"{node_member}/Cargo.toml")
if previous_manifest is None:
    print(
        f"node-version: {since} has no {node_member}; the first release with the node train "
        f"ships it as {node_version}",
        file=sys.stderr,
    )
    print(node_version)
    sys.exit(0)

previous_package = load_toml(previous_manifest, f"{since}:{node_member}/Cargo.toml").get("package", {})
previous_version = previous_package.get("version")
if isinstance(previous_version, dict):
    previous_workspace_text = show(since, "Cargo.toml")
    if previous_workspace_text is None:
        refuse(1, f"{since} has no Cargo.toml")
    previous_version = (
        load_toml(previous_workspace_text, f"{since}:Cargo.toml")
        .get("workspace", {})
        .get("package", {})
        .get("version")
    )
if not isinstance(previous_version, str) or not SEMVER.match(previous_version):
    refuse(1, f"{since}: the node's version '{previous_version}' is not SemVer")


def lock_closure(lock: dict) -> tuple[set[str], set[tuple]]:
    """The workspace crates and the locked third-party packages the node train pulls in."""
    packages = lock.get("package", [])
    by_name: dict[str, list[dict]] = {}
    for package in packages:
        by_name.setdefault(package["name"], []).append(package)

    def resolve(spec: str) -> dict | None:
        parts = spec.split(" ")
        candidates = by_name.get(parts[0], [])
        if len(parts) > 1:
            candidates = [p for p in candidates if p.get("version") == parts[1]]
        return candidates[0] if len(candidates) == 1 else None

    seen: set[tuple[str, str]] = set()
    stack = [p for crate in NODE_TRAIN for p in by_name.get(crate, [])]
    crates: set[str] = set()
    third_party: set[tuple] = set()
    while stack:
        package = stack.pop()
        key = (package["name"], package.get("version", ""))
        if key in seen:
            continue
        seen.add(key)
        if "source" in package:
            third_party.add((package["name"], package.get("version"), package["source"], package.get("checksum")))
        else:
            crates.add(package["name"])
        for spec in package.get("dependencies", []):
            dependency = resolve(spec)
            if dependency is not None:
                stack.append(dependency)
    return crates, third_party


lock_path = root / "Cargo.lock"
if not lock_path.is_file():
    refuse(1, "no Cargo.lock; the node's dependency closure is read from it")
head_crates, head_third_party = lock_closure(load_toml(lock_path.read_text(), "Cargo.lock"))
previous_lock_text = show(since, "Cargo.lock")
if previous_lock_text is None:
    refuse(1, f"{since} has no Cargo.lock")
_, previous_third_party = lock_closure(load_toml(previous_lock_text, f"{since}:Cargo.lock"))

changed: list[str] = []

def without_versions(data: dict) -> dict:
    """A manifest less the fields a release PR rewrites: its own version and the
    version requirement of every path dependency."""
    import copy

    data = copy.deepcopy(data)
    data.get("package", {}).pop("version", None)
    for table in dependency_tables(data):
        for spec in table.values():
            if isinstance(spec, dict) and "path" in spec:
                spec.pop("version", None)
    return data


for name in sorted(head_crates):
    if name not in manifests:
        refuse(1, f"Cargo.lock names workspace crate '{name}' that the manifest does not list")
    member, data = manifests[name]
    pathspecs = [
        member,
        f":(exclude){member}/Cargo.toml",
        f":(exclude){member}/tests",
        f":(exclude){member}/benches",
    ]
    if git("diff", "--quiet", since, "--", *pathspecs).returncode != 0:
        changed.append(f"crate {name} ({member}/)")
        continue
    previous_text = show(since, f"{member}/Cargo.toml")
    previous = load_toml(previous_text, f"{since}:{member}/Cargo.toml") if previous_text is not None else None
    if previous is None or without_versions(previous) != without_versions(data):
        changed.append(f"crate {name} ({member}/Cargo.toml)")

added = head_third_party - previous_third_party
removed = previous_third_party - head_third_party
if added or removed:
    names = sorted({f"{p[0]} {p[1]}" for p in added} | {f"{p[0]} {p[1]} (removed)" for p in removed})
    changed.append("locked dependencies of the node: " + ", ".join(names))

for path in ("rust-toolchain.toml", ".cargo/config.toml"):
    if git("diff", "--quiet", since, "--", path).returncode != 0:
        changed.append(path)

previous_workspace_text = show(since, "Cargo.toml")
previous_profile = (
    load_toml(previous_workspace_text, f"{since}:Cargo.toml").get("profile") if previous_workspace_text else None
)
if workspace.get("profile") != previous_profile:
    changed.append("the [profile] table of Cargo.toml")

if changed:
    summary = "; ".join(changed)
    if node_version == previous_version:
        refuse(
            3,
            f"the node changed since {since} but its version is still {node_version}: {summary}. "
            f"Bump it with scripts/release/prepare-version.sh <version> --node <node version>",
        )
    if semver_key(node_version) <= semver_key(previous_version):
        refuse(
            5,
            f"the node changed since {since} and its version went from {previous_version} to "
            f"{node_version}, which is not higher: {summary}",
        )
    print(f"node-version: the node changed since {since} ({summary}); {previous_version} -> {node_version}", file=sys.stderr)
elif node_version != previous_version:
    refuse(
        4,
        f"the node version went from {previous_version} to {node_version} but nothing the node is "
        f"built from changed since {since}; a release that ships the same node keeps its version",
    )
else:
    print(f"node-version: nothing the node is built from changed since {since}; the node stays {node_version}", file=sys.stderr)

print(node_version)
PY
