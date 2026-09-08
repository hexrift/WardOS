# WardOS host image

The Fedora **bootc** image that is the WardOS host (ADR-0001, [`architecture.md` §12](../docs/architecture.md)),
with the desktop of [ADR-0016](../docs/decisions/ADR-0016-desktop-feature-set.md) in it.
This directory is Phase 6 of the [roadmap](../docs/roadmap.md), started: the image is
authored, lint-checked, package-checked and built in CI, and it has **not yet been
booted** on real hardware. Experiment E-09 ([`experiments.md`](../docs/experiments.md))
is the validation; until it is recorded, treat every "boots", "enrols", "rolls back"
below as a plan, and every line marked *unverified* as the first suspects when it does
not.

## Layout

| Path | Ships as | Purpose |
| --- | --- | --- |
| `Containerfile` | the image | Build or fetch the ward binaries; layer packages, binaries, desktop and configuration on `fedora-bootc` |
| `packages.txt` | — | Every package the host installs, one per line with the reason; the Containerfile and `desktop/install.sh` read it |
| `coprs.txt` | `/etc/yum.repos.d/_copr:*.repo` | The COPR repositories enabled before the install (Hyprland's ecosystem, lazygit); part of the trust set |
| `check-packages.sh` | — | Proves every name in `packages.txt` exists in the pinned Fedora release plus `coprs.txt` (`dnf repoquery` in a `fedora:<release>` container); CI job "image packages" |
| `install-desktop.sh` | — | Places `desktop/` into a root (`/` in the build, `/` from `desktop/install.sh`, a temp dir in tests) |
| `rootfs/usr/libexec/wardos-flathub` | `/usr/libexec/wardos-flathub` | Adds Flathub and installs `desktop/flatpaks.txt`, run once by `wardos-flathub.service` |
| `build.sh` | — | `podman build` wrapper; tags `localhost/wardos:<git describe>` and stamps the version label |
| `disk.sh` | — | `bootc-image-builder` wrapper; qcow2 for QEMU, ISO for installation; `--user`, `--luks` |
| `sysctl.d/50-wardos.conf` | `/usr/lib/sysctl.d/` | Unprivileged user namespaces for `wardd`'s sandboxes |
| `tmpfiles.d/wardos.conf` | `/usr/lib/tmpfiles.d/` | Creates `/var/lib/wardos` at boot |
| `systemd/wardos-firstboot.service` | `/usr/lib/systemd/system/` | Runs `ward doctor` once, keeps the report |
| `systemd/wardos-flathub.service` | `/usr/lib/systemd/system/` | Flathub remote and default applications, once, after the first boot with a network |
| `plymouth/wardos/` | `/usr/share/plymouth/themes/wardos/` | The boot splash: WARD on the ground colour |
| `boot/` | (plan) | How the image boots, updates and rolls back; UKI/systemd-boot plan |
| `secure-boot/` | (plan, CODEOWNERS) | Secure Boot chain and what signing would need |
| `keys/` | (plan, CODEOWNERS) | Public verification keys only; the rule that private material never enters the repo |

`../.containerignore` (mirrored as `.dockerignore`) keeps the build context to the Rust
workspace, `image/` and `desktop/` (minus its tests); `../.hadolint.yaml` disables one
hadolint rule, explained inside.

## What is in the image

Stage 1 provides the ward binaries, from a release tarball or a build of this checkout
([below](#where-the-binaries-come-from)). Stage 2 starts from
`quay.io/fedora/fedora-bootc:44` and installs every package of
[`packages.txt`](packages.txt): the runtime set (`bubblewrap git curl python3
openssh-clients cargo rust podman`, reasons in the file and in the next paragraph), the
Hyprland stack, the components that render the shell's surfaces until E-10 (Waybar,
fuzzel, mako, swayosd), capture tools, audio, Bluetooth, Wi-Fi, power, fingerprint and
FIDO2, printing, terminals and TUIs, Chromium, Firefox, Nautilus, Flatpak, podman and
friends, fonts, icon and GTK themes, and Plymouth.

On the runtime set: `bubblewrap` is the sandbox builder (ADR-0002, ADR-0013); `git` and
`openssh-clients` serve worktrees, snapshots (ADR-0010) and git over ssh through the
broker; `curl` and `python3` the self-checks, `scripts/security-check` and hook
adapters; `podman` nested containers inside project environments (ADR-0005). `cargo`
and `rust` are the one, explicit, temporary exception to ADR-0001's "no toolchain on the
host": the trusted verifier ([`verify.rs`](../crates/ward-daemon/src/verify.rs)) binds a
host Rust toolchain read-only into Zone 2 for the 0.1 stand-in of a verifier image, and
they go away when that image (Phase 4, "still ahead") lands. It is the distro toolchain
on `PATH`, not a `~/.rustup`; `Toolchains::detect` finds no rustup home and falls
through to `/usr/bin`.

Then, in this order: the binaries go to `/usr/bin`; `install-desktop.sh` places the
desktop tree ([below](#the-desktop-in-the-image)); the configuration files under
`/usr/lib`, the Flathub script and the Plymouth theme are copied; the two first-boot
units are enabled, the splash theme selected and the initramfs rebuilt; and `bootc
container lint` checks the result. Labels: `org.wardos.version` (from `--build-arg
WARDOS_VERSION`, which `build.sh` sets to `git describe --tags --always`) and
`containers.bootc=1`.

Not in the image, deliberately: the `tamperward` service and the system-service `wardd`
of ADR-0009 (today `wardd` is per-session, spawned by `ward up`); `mise` (not in
Fedora; `wardos-install dev` says so); the Flathub applications, which come at first
boot, not at build time, so the image stays what `dnf` and this repository produced.

### Packages

`packages.txt` is the one list. Rules: one name per line, a `# why` after it, blank lines
and comment lines ignored, exact Fedora package names (not "provides": `fd-find`,
`pipewire-pulseaudio`, not `fd` or `pipewire-pulse`). The Containerfile installs
`sed -e 's/#.*//' packages.txt | xargs dnf -y install`; `desktop/install.sh` reads the
same file for `dnf` or `rpm-ostree`.

CI is the source of truth for the names: `check-packages.sh` enables the COPRs and runs
`dnf repoquery` inside `quay.io/fedora/fedora:<release>` (the release read from the
Containerfile's `FROM` tag, so the check and the build cannot drift; docker on the
runner, podman locally when docker is absent) and fails listing every name that did not
resolve; a wrong name is a one-line fix there, and a name the check has not confirmed
yet carries `# unverified` until it has (none today: every name passed on Fedora 44 with
the three COPRs). `check-packages.sh --dry-run` prints the command without a container
runtime; `check-packages.sh --discover NAME...` asks the COPR API which projects carry
a name for the pinned release, which is how the COPRs below were chosen.

### COPRs

[`coprs.txt`](coprs.txt) lists COPR repositories, one `owner/project` per line with the
reason, and three things enable exactly that list the same way: the Containerfile
(`dnf5-plugins`, then `dnf copr enable` for each, before the install), `check-packages.sh`
(the same two commands in the check container, so the check sees what the build sees),
and `desktop/install.sh` (`dnf copr enable` on Workstation; on rpm-ostree, which has no
`copr` verb, the `.repo` file COPR serves is fetched into `/etc/yum.repos.d`).

A COPR is part of the image's trust set: its packages are built by the COPR's owner on
Fedora's build system, not by Fedora, and its repository file stays in the image so
`wardos-install package` layers from the same sources the image was built from. The
list is therefore short, every entry justified, and an entry is removed the day Fedora
packages the thing; it must build for the pinned release (the `fedora-<NN>-x86_64`
chroot), which the "image packages" job proves before the build runs.

Fedora retired Hyprland itself after 42 (on 44 without COPRs the check reports
`hyprland`, `hypridle`, `hyprlock`, `hyprpaper`, `hyprpicker`, `hyprpolkitagent`,
`hyprsunset`, `xdg-desktop-portal-hyprland`, `uwsm`, `satty`, `swayosd` and `lazygit`
missing), and `solopasha/hyprland`, the COPR everyone used, builds rawhide only now.
`check-packages.sh --discover NAME...` asks the COPR API which projects mention a name
and which of them build for the pinned release; the September 2026 run chose the
smallest trust set: `mineiro/hyprland` (the one repository that carries the whole
ecosystem, the successor of solopasha's), `erikreider/swayosd` (swayosd by its author)
and `atim/lazygit`. `pulsemixer` is not packaged anywhere useful; the image ships
`pavucontrol` and `wardos-setup audio` prefers pulsemixer when present.

### The desktop in the image

`install-desktop.sh SRC DESTDIR` places the [`desktop/`](../desktop) tree
([`docs/desktop.md` §Layout](../docs/desktop.md#layout)). The same script runs in the
image build (`SRC=/tmp/desktop`, `DESTDIR=/`) and from `desktop/install.sh` on an
existing Fedora, so the two installs cannot drift apart. Every part is optional: what
the tree does not contain yet is skipped.

| `desktop/…` | Installed at | Notes |
| --- | --- | --- |
| `bin/wardos-*` | `/usr/bin/` | mode 0755 |
| `lib/wardos.sh` | `/usr/lib/wardos/` | |
| `hyprland/*.conf` | `/usr/share/wardos/hypr/`, `/etc/xdg/hypr` → that directory | The directory is linked, not the file: `hyprland.conf` sources `./keybindings.conf` relative to the path it was read from |
| `config/<component>/` | `/usr/share/wardos/config/<component>/` | Copied to `~/.config` by `wardos-first-run`; re-applied by `wardos-refresh` |
| `config/{waybar,foot,mako,fuzzel,btop,fastfetch}/` | also `/etc/xdg/<component>` → the above | These read `XDG_CONFIG_DIRS`, so they work before any first-run copy; an existing real `/etc/xdg/<component>` (a Fedora that ships one) is filled, not replaced |
| `config/gtk/settings.ini` | also `/etc/xdg/gtk-3.0/settings.ini`, `/etc/xdg/gtk-4.0/settings.ini` | One file, two real directories (GTK reads `settings.ini` from `XDG_CONFIG_DIRS`; `gtk.css` only from the home directory, first-run's job) |
| `config/bash/profile.d-wardos.sh` | `/etc/profile.d/wardos.sh` | Session environment; starts `uwsm` on tty1 |
| `config/xcompose/XCompose` | `/usr/share/wardos/config/xcompose/` | Copied to `~/.XCompose` by first-run |
| `themes/` | `/usr/share/wardos/themes/` | TOML token files and backgrounds |
| `webapps/`, `tuis/`, `flatpaks.txt` | `/usr/share/wardos/` | Defaults for `wardos-webapp`, `wardos-tui`, `wardos-flathub` |
| `systemd/user/*` | `/usr/lib/systemd/user/` + `/usr/lib/systemd/user-preset/90-wardos.preset` | The preset enables every unit that has an `[Install]` section (a timer's service has none and is pulled in by its timer) |
| `systemd/system/getty@tty1.service.d/autologin.conf` | `/etc/systemd/system/getty@tty1.service.d/` | Autologin; `--no-autologin` skips it (what `desktop/install.sh` does unless told `--autologin`) |
| `shell/`, `theme/`, `tests/`, `install.sh` | — | Sources and tests never land on the host; the two crates are built in stage 1 |

`desktop/tests/install.test.sh` runs the script against a temp `DESTDIR` with a fake
tree of every kind of file and asserts on every row above.

### Autologin

The image logs `wardos` in on tty1 without a password (the getty drop-in) and
`/etc/profile.d/wardos.sh` starts Hyprland through `uwsm` there, so a machine boots
into the desktop; hyprlock, not the login prompt, is the lock. The user is not in the
image (bootc images carry no accounts): create it when making the disk,
`disk.sh --user wardos …` ([below](#users-and-luks)), or with your own config. A
different first user works too; then edit the drop-in's `--autologin` name in your
`/etc`, which bootc keeps across upgrades.

### Flathub and the default applications

Applications that are not in Fedora come from Flathub (ADR-0016: no `curl | sh`, no
AUR). `wardos-flathub.service` runs `/usr/libexec/wardos-flathub /usr/share/wardos/flatpaks.txt`
once after the first boot that has a network (`After=network-online.target`): it adds
the `flathub` remote and installs the ids in the list (`#` comments and blank lines
allowed). It never blocks login; `wardos-install app` works as soon as the remote
exists. Success writes `/var/lib/wardos/flathub.done`; a failed download leaves no
marker, shows in `systemctl --failed`, and retries on the next boot. Delete the marker
to re-run; `wardos-flathub /path/to/list` installs another list by hand.

### Plymouth

`plymouth/wardos/` is a Plymouth *script* theme: the Ward Dark ground (`#0E0F11`) fills
the screen, `WARD` sits in the middle in the text colour, a 2 px line in the muted
colour grows under it with boot progress, and the LUKS passphrase prompt is one line
of text plus one bullet per character on the same surface. No logo, no animation
([`design-language.md`](../docs/design-language.md) §2, §3). The build selects it with
`plymouth-set-default-theme wardos` when the script engine (`plymouth-plugin-script`)
is installed and falls back to `spinner` otherwise, then rebuilds the initramfs
(`dracut --no-hostonly --add ostree`, the way other bootc desktops do) because Plymouth
draws from the initramfs, not from the root filesystem. The "image build" job proves
the packages resolve, the theme is selected (`plymouth-set-default-theme` prints
`wardos` in the build log) and the dracut step runs; how the splash looks at boot is
E-09's to record.

### Base image tag

`fedora-bootc:44` pins the **current Fedora release**, not a digest. Two consequences:

1. Rebuilding on a later day gives a newer Fedora 44 content set; the image *digest* is
   what identifies a build and what evidence records (ADR-0001). CI will move to pinned
   digests (`@sha256:…`) with a renovate-style bump once E-09 has a baseline to compare.
2. A Fedora rebase (45, …) is an edit to `FROM` and a re-run of E-09, never an implicit
   change; the first one, 42 → 44 in September 2026, is recorded in ADR-0001's addendum
   (42 had reached end of life and the COPRs had dropped its chroot). `bootc` on
   installed hosts follows whatever tag their `bootc status` names.

## Where the binaries come from

The host stage copies the binaries from one of two stages, chosen with
`--build-arg WARDOS_SOURCE` (`image/build.sh --source`):

| Source | What happens | Use |
| --- | --- | --- |
| `release` (default) | downloads `wardos-<ver>-x86_64-linux.tar.gz` for `WARDOS_RELEASE` from the GitHub release and refuses to continue unless its SHA-256 matches `WARDOS_SHA256` (`build.sh` fetches the published checksum) | every image that leaves your machine: reproducible from a known, tested release |
| `builder` (`--source checkout`) | compiles this working tree with `docker.io/library/rust:1.94.1` (the channel of `rust-toolchain.toml`; bump both together), `--locked` | development images of unreleased changes; the "image build" CI job |

Five binaries: `ward`, `wardd`, `ward-agent` (required; the build fails without them),
`ward-shell` and `wardos-theme-render` (the shell's surfaces and the theme renderer).
The builder stage compiles all five (`desktop/shell`, `desktop/theme` are workspace
crates); the release stage copies the last two when the tarball has them, which
release tarballs from **v0.2** do (`release.yml` packages five from now on)
and earlier releases do not: an image built from one has the desktop's packages and
configuration but no shell surfaces, and `ls -l /usr/bin/ward*` in the build log says
which arrived. The Rust image is Debian-based; its glibc is older than Fedora 44's, so
the binaries run on the host without a rebuild.

The tools and the image therefore have separate cadences: `vX.Y.Z` tags release the
tools; images carry the release they embed in `org.wardos.version` plus the build's
`git describe`, and are tagged by date when published (`wardos:2026.09`).

## Building on a Fedora host

Requirements: a Fedora (or any bootc-capable) host with `podman` ≥ 4.9, `git`, and root,
because `bootc-image-builder` reads root's container storage. Roughly 12 GB of free
disk for the build layers (the desktop's packages are most of it) and the output image.

```sh
git clone https://github.com/hexrift/WardOS && cd WardOS
sudo ./image/build.sh                                        # -> localhost/wardos:<git describe>
sudo ./image/disk.sh --type qcow2 --user wardos --password …  # -> image/out/qcow2/disk.qcow2
sudo ./image/disk.sh --type iso --user wardos --luks          # -> image/out/bootiso/install.iso
```

Both scripts print the exact command they are about to run; `--dry-run` prints it and
exits without needing podman:

```sh
./image/build.sh --dry-run
./image/disk.sh --type qcow2 --user wardos --password x --dry-run
```

`--rootfs` defaults to `btrfs` (ADR-0001; `/work` snapshots want it). The builder image is
`quay.io/centos-bootc/bootc-image-builder:latest`, overridable with
`BOOTC_IMAGE_BUILDER=`; pin it to a digest once E-09 records which version produced the
baseline.

### Users and LUKS

`disk.sh --user NAME` writes a bootc-image-builder config (`<output>/config.toml`, mode
0600, printed with the password redacted) that creates the first user in `wheel`, with
`--password PW` (or `WARDOS_PASSWORD` in the environment, which keeps it out of `ps`)
and/or `--ssh-key FILE`; one of the two is required, or nobody could use `sudo`. The
desktop's autologin expects `wardos`. `--config FILE` passes your own TOML instead
(the two are exclusive); a minimal one:

```toml
[[customizations.user]]
name = "wardos"
password = "change-me-on-first-login"
groups = ["wheel"]
```

`disk.sh --type iso --luks` gives full-disk encryption. The blueprint that
bootc-image-builder consumes knows `plain`, `lvm` and `btrfs` partitions and nothing
encrypted (`osbuild/blueprint`, `disk_customizations.go`), so a qcow2 cannot be
encrypted by the builder and `disk.sh` refuses `--luks` for it; the installer ISO can,
through an Anaconda kickstart that `disk.sh` generates:

```text
zerombr
clearpart --all --initlabel --disklabel=gpt
autopart --noswap --type=btrfs --encrypted
network --bootproto=dhcp --device=link --activate --onboot=on
lang en_US.UTF-8 / keyboard us / timezone UTC --utc / rootpw --lock
user --name=wardos --groups=wheel --password=… --plaintext
reboot
```

`autopart --encrypted` without `--passphrase` makes Anaconda ask for one during the
installation, so no passphrase is ever written to a file (*unverified* until E-09; the
generated file says so). bootc-image-builder refuses `[[customizations.user]]` next to a
custom kickstart, which is why the user becomes a kickstart `user` line in this mode.
At boot the passphrase is typed on the Plymouth surface.

### Boot-testing in QEMU

```sh
qemu-system-x86_64 -enable-kvm -m 4096 -cpu host \
  -drive file=image/out/qcow2/disk.qcow2,if=virtio,format=qcow2 \
  -bios /usr/share/edk2/ovmf/OVMF_CODE.fd -nographic
```

(UEFI firmware from the `edk2-ovmf` package; Secure Boot off in this configuration, see
[`secure-boot/`](secure-boot/README.md) for the variant with it on.) Hyprland needs a
display; use `-device virtio-vga-gl -display gtk,gl=on` instead of `-nographic` to see
the desktop.

### The published image: skip the build

Every merge to `main` that passes the image build pushes the result to
`ghcr.io/hexrift/wardos` (`:latest` and `:<short sha>`). A machine that only wants a
disk never builds anything:

```sh
sudo WARDOS_PASSWORD='choose-one' image/disk.sh --type qcow2 --user wardos \
  --image ghcr.io/hexrift/wardos:latest
```

`disk.sh` pulls a registry reference it does not have and hands it to
bootc-image-builder; five to ten minutes later the qcow2 is there. An installed WardOS
follows the same reference: `bootc switch ghcr.io/hexrift/wardos:latest` once, then
`wardos-update` (`bootc upgrade`) tracks every merge. Building locally is for changing
the image, not for using it.

Build time, when you do build: the Containerfile keeps its steps few because every step
commits a multi-gigabyte layer (about fifteen seconds each even for a one-file copy);
`dnf` installs with `install_weak_deps=False`, so the image holds only what
`packages.txt` names; and `build.sh` passes `--format docker` so the Containerfile's
`pipefail` shell is honoured under podman too. Compiling the tools is the slow part of a
checkout build (five to ten minutes); `--source release` downloads them instead.

### Disk images from CI

Nobody needs a Fedora box to get a WardOS disk. The `disk` workflow
([`.github/workflows/disk.yml`](../.github/workflows/disk.yml)) runs `build.sh` and
`disk.sh` on a GitHub runner, where bootc-image-builder has the privileged podman it
needs, and publishes the result:

* **By hand**: Actions → *disk* → *Run workflow*. Choose `qcow2`, `iso` or `both`, the
  binaries (`checkout` compiles this commit, `release` takes the published tarball of
  `--release`), the first user (`wardos`, which the autologin expects) and, for the ISO,
  `luks`. The disks appear as the run's `wardos-disks` artifact for 14 days, with a
  `SHA256SUMS`.
* **On every published release**: both disks are built from that release's tarball and
  attached to the release as `wardos-<version>-x86_64.qcow2.zst` and `.iso.zst`
  (zstd-compressed to stay under GitHub's 2 GiB asset cap; `zstd -d` restores them).

The first user's password in these disks is `wardos`. Change it at first login
(`passwd`); the ISO with `luks` additionally asks for the disk passphrase during the
install. The same job runs `check-packages.sh --arch aarch64 --discover` so the log says
whether the COPRs the image depends on also build for aarch64, the prerequisite for an
Apple-silicon image.

**On a Mac.** Docker Desktop can build the container image
(`docker build -f image/Containerfile --platform linux/amd64 -t wardos .`) and run it for
a look around, but cannot make the disk: bootc-image-builder needs loop devices and a
privileged Linux podman, which Docker Desktop's VM does not provide, and on Apple silicon
it would build arm64 only. Download the qcow2 from CI instead and boot it in
[UTM](https://mac.getutm.app) as an x86_64 machine (emulated on Apple silicon, so slow;
native on an Intel Mac), or write the ISO to a USB stick for a PC.

## First boot: what to expect

1. `systemd-tmpfiles` creates `/var/lib/wardos` (mode 0755, root).
2. `wardos-firstboot.service` runs `/usr/bin/ward doctor` once and writes its report to
   `/var/lib/wardos/doctor.txt`; the unit is skipped on later boots while that file exists
   (delete it to re-run, or `systemctl start wardos-firstboot`).
3. `wardos-flathub.service` waits for the network, adds Flathub and installs the default
   applications in the background ([above](#flathub-and-the-default-applications)).
4. tty1 logs `wardos` in and `uwsm` starts Hyprland; `wardos-first-run` copies the
   configs, asks for a theme, runs `ward doctor` and shows the keys.
   `bootc container lint` ran clean at the end of the build (10 checks, no warnings
   once the install-time caches and logs under `/var`, `/run` and `/tmp` are swept).
5. `sysctl kernel.unprivileged_userns_clone` does not exist on Fedora kernels; the sysctl
   file marks it optional (`-`), so `systemd-sysctl` logs it and continues. Check with
   `sysctl user.max_user_namespaces` (non-zero) and `bwrap --unshare-all -- true`.
6. Verify the runtime: `ward selftest` should pass every group it passes on a Fedora
   development host; `ward doctor` (or `cat /var/lib/wardos/doctor.txt`) lists bubblewrap,
   cgroups v2, user namespaces, `cargo` on `PATH`, `podman`.
7. `bootc status` shows the booted image and its digest. Record both in the E-09 result.

Updates (`bootc upgrade`, which `wardos-update` wraps), switching between images, and
rollback (`bootc rollback`: the previous deployment stays until the next upgrade, the
Fedora way of Omarchy's snapper snapshots) are documented in
[`boot/README.md`](boot/README.md).

## The desktop on an existing Fedora

[`desktop/install.sh`](../desktop/install.sh) applies the same desktop to a Fedora 44
that is already installed: Workstation (`dnf`), Silverblue and Kinoite (`rpm-ostree
install`, layered, active after a reboot). See [`docs/install.md`](../docs/install.md),
"Desktop".

## Checks that run without a boot

CI runs, on every pull request and push (`verify.yml`):

| Job | What |
| --- | --- |
| `image lint` | hadolint on `Containerfile`, shellcheck (`--severity=style`) on `image/*.sh`, the dry-runs of `build.sh`, `disk.sh` (plain and `--luks --user`), `check-packages.sh`, and `install-desktop.sh --help` |
| `image packages` | `check-packages.sh`: every name in `packages.txt` exists in the pinned Fedora release (plus `coprs.txt`) |
| `desktop scripts` | `desktop/tests/run.sh`, which includes `install.test.sh` (install-desktop, desktop/install.sh, wardos-flathub, check-packages.sh, disk.sh) |

and, in `image.yml` on `main` and on pull requests that touch `image/`, `desktop/`, the
crates or `Cargo.lock`: `image build`, the real `docker build` with the checkout's
binaries, followed by a look inside (`/usr/bin/ward*`, `/usr/share/wardos`, the user
preset, `/etc/xdg/hypr`, the enabled units, the Plymouth theme) and `bootc container
lint`. It is the check that catches a package name that exists but conflicts, a
`dracut` flag that does not, or a desktop file the installer mishandles.

Locally:

```sh
bash -n image/*.sh && shellcheck --severity=style image/*.sh
hadolint image/Containerfile        # reads ../.hadolint.yaml
./image/check-packages.sh           # needs docker or podman and the network
bash desktop/tests/run.sh
docker build -f image/Containerfile --build-arg WARDOS_SOURCE=builder -t wardos:ci .
```

What no check can do and E-09 must: that the qcow2 boots, that `getty@tty1` logs the
user in and `uwsm` brings Hyprland up, that the Plymouth theme is the early one, that
Anaconda asks for the LUKS passphrase, that `ward doctor` exits 0 on the host.
