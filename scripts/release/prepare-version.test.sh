#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fixture="$tmp/repo"
mkdir -p "$fixture/scripts/release" "$fixture/crates/ward-a" "$fixture/crates/ward-b" "$tmp/bin"
cp "$repo_root/scripts/release/prepare-version.sh" "$fixture/scripts/release/"
cp "$repo_root/scripts/release/check-version.sh" "$fixture/scripts/release/"

cat >"$fixture/Cargo.toml" <<'EOF'
[workspace]
resolver = "2"
members = [
    "crates/ward-a",
    "crates/ward-b",
]

[workspace.package]
version = "0.18.1"
edition = "2024"
EOF

cat >"$fixture/crates/ward-a/Cargo.toml" <<'EOF'
[package]
name = "ward-a"
version.workspace = true
edition.workspace = true
EOF

cat >"$fixture/crates/ward-b/Cargo.toml" <<'EOF'
[package]
name = "ward-b"
version.workspace = true
edition.workspace = true

[dependencies]
ward-a = { path = "../ward-a", version = "0.18.0" }
serde = { version = "1", features = ["derive"] }
EOF

cat >"$tmp/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == "metadata" ]]
exit 0
EOF
chmod +x "$tmp/bin/cargo"

(
  cd "$fixture"
  PATH="$tmp/bin:$PATH" bash scripts/release/prepare-version.sh 0.19.0
)

grep -Fq 'version = "0.19.0"' "$fixture/Cargo.toml"
grep -Fq 'ward-a = { path = "../ward-a", version = "0.19.0" }' "$fixture/crates/ward-b/Cargo.toml"
grep -Fq 'serde = { version = "1", features = ["derive"] }' "$fixture/crates/ward-b/Cargo.toml"

before="$(sha256sum "$fixture/Cargo.toml" "$fixture/crates/ward-b/Cargo.toml")"
invalid_versions=(
  '01.2.3'
  '1.02.3'
  '1.2.03'
  '1.2.3-01'
  '1.2.3-alpha..1'
  '1.2.3+meta..build'
  '0.20.0;touch-pwned'
)

for invalid_version in "${invalid_versions[@]}"; do
  if (
    cd "$fixture"
    PATH="$tmp/bin:$PATH" bash scripts/release/prepare-version.sh "$invalid_version"
  ); then
    echo "prepare-version.test: invalid version unexpectedly accepted: $invalid_version" >&2
    exit 1
  fi
done

after="$(sha256sum "$fixture/Cargo.toml" "$fixture/crates/ward-b/Cargo.toml")"
[[ "$before" == "$after" ]]
[[ ! -e "$fixture/touch-pwned" ]]



### The node train (issue #275) ##################################################

# A workspace with the node crates: their own version is left alone by a release
# that does not name one, moved by --node, and the requirement on ward-node follows
# the node version, not the workspace's. It has the ward-agent crate too, whose shim
# the node tarball ships (issue #427) and node-version.sh counts among its inputs.
node_fixture="$tmp/node-repo"
mkdir -p "$node_fixture/scripts/release" "$node_fixture/crates/ward-a" "$node_fixture/crates/ward-agent" \
  "$node_fixture/crates/ward-node" "$node_fixture/crates/ward-node-client"
cp "$repo_root/scripts/release/prepare-version.sh" "$repo_root/scripts/release/check-version.sh" \
  "$repo_root/scripts/release/node-version.sh" "$node_fixture/scripts/release/"

cat >"$node_fixture/Cargo.toml" <<'EOF2'
[workspace]
resolver = "2"
members = [
    "crates/ward-a",
    "crates/ward-agent",
    "crates/ward-node",
    "crates/ward-node-client",
]

[workspace.package]
version = "0.18.1"
edition = "2024"
EOF2
cat >"$node_fixture/crates/ward-a/Cargo.toml" <<'EOF2'
[package]
name = "ward-a"
version.workspace = true
edition.workspace = true
EOF2
cat >"$node_fixture/crates/ward-agent/Cargo.toml" <<'EOF2'
[package]
name = "ward-agent"
version.workspace = true
edition.workspace = true

[dependencies]
ward-a = { path = "../ward-a", version = "0.18.0" }
EOF2
cat >"$node_fixture/crates/ward-node/Cargo.toml" <<'EOF2'
[package]
name = "ward-node"
version = "0.1.0"
edition.workspace = true

[dependencies]
ward-a = { path = "../ward-a", version = "0.18.0" }
EOF2
cat >"$node_fixture/crates/ward-node-client/Cargo.toml" <<'EOF2'
[package]
name = "ward-node-client"
version = "0.1.0"
edition.workspace = true

[dependencies]
ward-a = { path = "../ward-a", version = "0.18.0" }

[dev-dependencies]
ward-node = { path = "../ward-node", version = "0.1.0" }
EOF2

(
  cd "$node_fixture"
  PATH="$tmp/bin:$PATH" bash scripts/release/prepare-version.sh 0.19.0
)
grep -Fq 'version = "0.19.0"' "$node_fixture/Cargo.toml"
grep -Fq 'ward-a = { path = "../ward-a", version = "0.19.0" }' "$node_fixture/crates/ward-node/Cargo.toml"
grep -Fq 'ward-a = { path = "../ward-a", version = "0.19.0" }' "$node_fixture/crates/ward-node-client/Cargo.toml"
grep -Fxq 'version = "0.1.0"' "$node_fixture/crates/ward-node/Cargo.toml"
grep -Fxq 'version = "0.1.0"' "$node_fixture/crates/ward-node-client/Cargo.toml"
grep -Fq 'ward-node = { path = "../ward-node", version = "0.1.0" }' "$node_fixture/crates/ward-node-client/Cargo.toml"
echo "ok   a release without --node keeps the node version and its requirement"

(
  cd "$node_fixture"
  PATH="$tmp/bin:$PATH" bash scripts/release/prepare-version.sh 0.19.0 --node 0.2.0
)
grep -Fxq 'version = "0.2.0"' "$node_fixture/crates/ward-node/Cargo.toml"
grep -Fxq 'version = "0.2.0"' "$node_fixture/crates/ward-node-client/Cargo.toml"
grep -Fq 'ward-node = { path = "../ward-node", version = "0.2.0" }' "$node_fixture/crates/ward-node-client/Cargo.toml"
grep -Fq 'version = "0.19.0"' "$node_fixture/Cargo.toml"
echo "ok   --node moves both node crates and the requirement on ward-node"

before="$(sha256sum "$node_fixture"/Cargo.toml "$node_fixture"/crates/*/Cargo.toml)"
for invalid_node in '01.3.0' '0.3' '0.3.0;touch-pwned'; do
  if (
    cd "$node_fixture"
    PATH="$tmp/bin:$PATH" bash scripts/release/prepare-version.sh 0.19.0 --node "$invalid_node"
  ); then
    echo "prepare-version.test: invalid node version unexpectedly accepted: $invalid_node" >&2
    exit 1
  fi
done
if (cd "$node_fixture" && PATH="$tmp/bin:$PATH" bash scripts/release/prepare-version.sh 0.19.0 --bogus 1); then
  echo "prepare-version.test: unknown option unexpectedly accepted" >&2
  exit 1
fi
after="$(sha256sum "$node_fixture"/Cargo.toml "$node_fixture"/crates/*/Cargo.toml)"
[[ "$before" == "$after" ]]
[[ ! -e "$node_fixture/touch-pwned" ]]
echo "ok   an invalid node version or option changes nothing"

# The first fixture has no node crates: a release there needs no node version.
echo "prepare-version.test: PASS"
