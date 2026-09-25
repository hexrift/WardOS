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

echo "prepare-version.test: PASS"
