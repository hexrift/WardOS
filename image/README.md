# WardOS host image

The Fedora **bootc** image that is the WardOS host (ADR-0001, [`architecture.md` §12](../docs/architecture.md)).
This directory is Phase 6 of the [roadmap](../docs/roadmap.md), started: the image is
authored and lint-checked in CI, and it has **not yet been built or booted** on real
hardware. Experiment E-09 ([`experiments.md`](../docs/experiments.md)) is the validation;
until it is recorded, treat every "boots", "enrols", "rolls back" below as a plan.

## Layout

| Path | Ships as | Purpose |
| --- | --- | --- |
| `Containerfile` | the image | Two stages: build `ward`, `wardd`, `ward-agent`; layer them on `fedora-bootc` |
| `build.sh` | — | `podman build` wrapper; tags `localhost/wardos:<git describe>` and stamps the version label |
| `disk.sh` | — | `bootc-image-builder` wrapper; qcow2 for QEMU, ISO for installation |
| `sysctl.d/50-wardos.conf` | `/usr/lib/sysctl.d/` | Unprivileged user namespaces for `wardd`'s sandboxes |
| `tmpfiles.d/wardos.conf` | `/usr/lib/tmpfiles.d/` | Creates `/var/lib/wardos` at boot |
| `systemd/wardos-firstboot.service` | `/usr/lib/systemd/system/` | Runs `ward doctor` once, keeps the report |
| `boot/` | (plan) | How the image boots, updates and rolls back; UKI/systemd-boot plan |
| `secure-boot/` | (plan, CODEOWNERS) | Secure Boot chain and what signing would need |
| `keys/` | (plan, CODEOWNERS) | Public verification keys only; the rule that private material never enters the repo |

`../.containerignore` (mirrored as `.dockerignore`) keeps the build context to the Rust
workspace and `image/`; `../.hadolint.yaml` disables one hadolint rule, explained inside.

## What is in the image

Stage 1 builds the three host binaries with `cargo build --release --locked` on
`docker.io/library/rust:1.94.1`, the same channel as `rust-toolchain.toml`. Bump the
two together. The Rust image is Debian-based; its glibc is older than Fedora 42's, so the
binaries run on the host without a rebuild (glibc is forward compatible in that direction
only).

Stage 2 starts from `quay.io/fedora/fedora-bootc:42` and installs exactly:

```text
bubblewrap git curl python3 openssh-clients cargo rust podman
```

* `bubblewrap`: the sandbox builder (ADR-0002, ADR-0013).
* `git`, `openssh-clients`: worktrees, snapshots (ADR-0010), git over ssh through the broker.
* `curl`, `python3`: self-checks, `scripts/security-check`, hook adapters.
* `cargo`, `rust`: the trusted verifier ([`verify.rs`](../crates/ward-daemon/src/verify.rs))
  binds a host Rust toolchain read-only into Zone 2 for the 0.1 stand-in of a verifier
  image. ADR-0001 says toolchains never live on the host; this is the one, explicit,
  temporary exception, and it goes away when the verifier image (Phase 4, "still ahead")
  lands. It is the distro toolchain on `PATH`, not a `~/.rustup`; `Toolchains::detect`
  finds no rustup home and falls through to `/usr/bin`.
* `podman`: nested containers inside project environments (ADR-0005), unused until then.

Then the binaries go to `/usr/bin`, the three configuration files under `/usr/lib`, the
first-boot unit is enabled, and `bootc container lint` checks the result. Labels:
`org.wardos.version` (from `--build-arg WARDOS_VERSION`, which `build.sh` sets to
`git describe --tags --always`) and `containers.bootc=1`.

Not yet in the image, deliberately: Hyprland, Ward Shell, themes, the command centre, the
`tamperward` service, and the system-service `wardd` of ADR-0009 (today `wardd` is
per-session, spawned by `ward up`). They land as the desktop and daemon phases deliver.

### Base image tag

`fedora-bootc:42` pins the **current Fedora release**, not a digest. Two consequences:

1. Rebuilding on a later day gives a newer Fedora 42 content set; the image *digest* is
   what identifies a build and what evidence records (ADR-0001). CI will move to pinned
   digests (`@sha256:…`) with a renovate-style bump once E-09 has a baseline to compare.
2. A Fedora rebase (43, …) is an edit to `FROM` and a re-run of E-09, never an implicit
   change. `bootc` on installed hosts follows whatever tag their `bootc status` names.

The tag could not be verified from the authoring environment (no registry access); if it
does not resolve on the build host, `podman build` fails on the `FROM` line and nothing
else has run.

## Building on a Fedora host

Requirements: a Fedora (or any bootc-capable) host with `podman` ≥ 4.9, `git`, and root,
because `bootc-image-builder` reads root's container storage. Roughly 8 GB of free disk
for the build layers and the output image.

```sh
git clone https://github.com/hexrift/WardOS && cd WardOS
sudo ./image/build.sh                     # -> localhost/wardos:<git describe --tags --always>
sudo ./image/disk.sh --type qcow2         # -> image/out/qcow2/disk.qcow2
sudo ./image/disk.sh --type iso           # -> image/out/bootiso/install.iso
```

Both scripts print the exact command they are about to run; `--dry-run` prints it and
exits without needing podman. To see them:

```sh
./image/build.sh --dry-run
./image/disk.sh --type qcow2 --dry-run
```

`disk.sh --config users.toml` passes a bootc-image-builder configuration in; a minimal
one that creates the first user is:

```toml
[[customizations.user]]
name = "ward"
password = "change-me-on-first-login"
groups = ["wheel"]
```

`--rootfs` defaults to `btrfs` (ADR-0001; `/work` snapshots want it). The builder image is
`quay.io/centos-bootc/bootc-image-builder:latest`, overridable with
`BOOTC_IMAGE_BUILDER=`; pin it to a digest once E-09 records which version produced the
baseline.

### Boot-testing in QEMU

```sh
qemu-system-x86_64 -enable-kvm -m 4096 -cpu host \
  -drive file=image/out/qcow2/disk.qcow2,if=virtio,format=qcow2 \
  -bios /usr/share/edk2/ovmf/OVMF_CODE.fd -nographic
```

(UEFI firmware from the `edk2-ovmf` package; Secure Boot off in this configuration, see
[`secure-boot/`](secure-boot/README.md) for the variant with it on.)

## First boot: what to expect

1. `systemd-tmpfiles` creates `/var/lib/wardos` (mode 0755, root).
2. `wardos-firstboot.service` runs `/usr/bin/ward doctor` once and writes its report to
   `/var/lib/wardos/doctor.txt`; the unit is skipped on later boots while that file exists
   (delete it to re-run, or `systemctl start wardos-firstboot`). `ward doctor` is being
   added concurrently to this image; until it exists in the built binary the unit fails
   with "unknown subcommand", which is the correct, visible outcome.
3. `sysctl kernel.unprivileged_userns_clone` does not exist on Fedora kernels; the sysctl
   file marks it optional (`-`), so `systemd-sysctl` logs it and continues. Check with
   `sysctl user.max_user_namespaces` (non-zero) and `bwrap --unshare-all -- true`.
4. Verify the runtime: `ward selftest` should pass every group it passes on a Fedora
   development host; `ward doctor` (or `cat /var/lib/wardos/doctor.txt`) lists bubblewrap,
   cgroups v2, user namespaces, `cargo` on `PATH`, `podman`.
5. `bootc status` shows the booted image and its digest. Record both in the E-09 result.

Updates, switching between images, and rollback are documented in
[`boot/README.md`](boot/README.md).

## Checks that run without a build

CI (`verify.yml`, job "image lint") runs hadolint on `Containerfile` and shellcheck on
`image/*.sh`. Locally:

```sh
bash -n image/*.sh
shellcheck image/*.sh
hadolint image/Containerfile        # reads ../.hadolint.yaml
./image/build.sh --dry-run && ./image/disk.sh --type iso --dry-run
```

What no lint can check and E-09 must: that `fedora-bootc:42` and the package names
resolve, that `bootc container lint` is happy with the layer, that `systemctl enable`
inside the build creates the symlink, that `ward doctor` exits 0 on the host, and that
the qcow2 boots.
