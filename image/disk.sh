#!/usr/bin/env bash
# Turn a built WardOS image into a bootable disk with bootc-image-builder.
#
#   image/disk.sh --type qcow2|raw|iso [--image NAME] [--output DIR] [--rootfs FS]
#                 [--arch x86_64|aarch64] [--user NAME [--password PW] [--ssh-key FILE]]
#                 [--luks | --no-luks] [--config FILE] [--dry-run]
#
# Defaults: image localhost/wardos:<git describe --tags --always>, output ./image/out,
# rootfs btrfs (ADR-0001), arch this machine's. --user writes a bootc-image-builder
# config that creates the first user (wheel; the greeter's default user is `wardos`)
# with --password (or WARDOS_PASSWORD in the environment, which keeps it out of `ps`)
# and/or --ssh-key. The installer ISO encrypts the disk unless told --no-luks
# (ADR-0017): a kickstart asks Anaconda for full-disk encryption, the passphrase typed
# at install time. A `raw` image is a whole-disk image you write to a USB stick and
# boot a machine from: it runs WardOS entirely off the stick and never touches the
# machine's own disk, which is the way to try WardOS on real hardware without an
# install (see image/README.md). A qcow2 and a raw image are never encrypted (the
# builder cannot; --luks on either is
# refused). --config passes your own TOML instead. --arch names the disk's architecture
# (bootc-image-builder --target-arch; the image must have been built for it): native on
# a matching host, which is how CI builds the aarch64 disks, and experimental across
# (qcow2 only, needs qemu-user). Must run as root: the builder is a privileged container
# that reads root's container storage and writes the disk image. See image/README.md,
# "Users and LUKS".
set -euo pipefail

usage() {
  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
}

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

podman_bin=${PODMAN:-podman}
# Pinned builder image; bump deliberately (image/README.md, "bootc-image-builder").
builder=${BOOTC_IMAGE_BUILDER:-quay.io/centos-bootc/bootc-image-builder:latest}
type=""
image=""
output="$repo_root/image/out"
rootfs="btrfs"
arch=""
config=""
user=""
password=${WARDOS_PASSWORD:-}
ssh_key=""
# "" until the flags are read: the type's default (iso: on); 1 for --luks, 0 for --no-luks.
luks=""
dry_run=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --type) type=$2; shift 2 ;;
    --type=*) type=${1#--type=}; shift ;;
    --image) image=$2; shift 2 ;;
    --image=*) image=${1#--image=}; shift ;;
    --output) output=$2; shift 2 ;;
    --output=*) output=${1#--output=}; shift ;;
    --rootfs) rootfs=$2; shift 2 ;;
    --rootfs=*) rootfs=${1#--rootfs=}; shift ;;
    --arch) arch=$2; shift 2 ;;
    --arch=*) arch=${1#--arch=}; shift ;;
    --config) config=$2; shift 2 ;;
    --config=*) config=${1#--config=}; shift ;;
    --user) user=$2; shift 2 ;;
    --user=*) user=${1#--user=}; shift ;;
    --password) password=$2; shift 2 ;;
    --password=*) password=${1#--password=}; shift ;;
    --ssh-key) ssh_key=$2; shift 2 ;;
    --ssh-key=*) ssh_key=${1#--ssh-key=}; shift ;;
    --luks) luks=1; shift ;;
    --no-luks) luks=0; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "disk.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$type" in
  qcow2 | raw | iso) ;;
  "") echo "disk.sh: --type qcow2|raw|iso is required" >&2; exit 2 ;;
  *) echo "disk.sh: unsupported --type '$type' (qcow2, raw or iso)" >&2; exit 2 ;;
esac

if [[ -z "$image" ]]; then
  image="localhost/wardos:$(git describe --tags --always 2>/dev/null || echo dev)"
fi

# The disk's architecture, in bootc-image-builder's spelling (amd64, arm64). On a host
# of that architecture the flag changes nothing; on another it is the builder's
# experimental cross path (qemu-user, no ISO: "cannot build iso for different target
# arches yet"), so the ISO is refused here with the reason rather than deep in the run.
target_arch=()
case "$arch" in
  "") ;;
  x86_64) target_arch=(--target-arch amd64) ;;
  aarch64) target_arch=(--target-arch arm64) ;;
  *) echo "disk.sh: --arch must be x86_64 or aarch64 (got '$arch')" >&2; exit 2 ;;
esac
if [[ -n "$arch" && "$arch" != "$(uname -m)" && "$type" == iso ]]; then
  echo "disk.sh: bootc-image-builder cannot build an ISO for another architecture; build the $arch ISO on an $arch host (CI's disk workflow does)" >&2
  exit 2
fi

if [[ -n "$config" && ! -f "$config" ]]; then
  echo "disk.sh: config file not found: $config" >&2
  exit 1
fi
if [[ -n "$config" && ( -n "$user" || "$luks" == 1 ) ]]; then
  echo "disk.sh: --config carries its own users and partitioning; drop it or drop --user/--luks" >&2
  exit 2
fi
if [[ -z "$luks" ]]; then
  # Encrypted by default where encryption is possible (ADR-0017): the installer ISO,
  # unless a --config brings its own partitioning. --no-luks is the explicit opt-out.
  if [[ "$type" == iso && -z "$config" ]]; then luks=1; else luks=0; fi
fi
if [[ -n "$ssh_key" && ! -f "$ssh_key" ]]; then
  echo "disk.sh: ssh key file not found: $ssh_key" >&2
  exit 1
fi
if [[ -n "$user" && -z "$password" && -z "$ssh_key" ]]; then
  echo "disk.sh: --user needs --password (or WARDOS_PASSWORD) or --ssh-key, or nobody can use sudo" >&2
  exit 2
fi
if [[ -n "$user" ]]; then
  # A pre-created account is a dev/specialised convenience, NOT the production model
  # (ADR-0027): consumer/hardware images ship WITHOUT --user and create the real user at
  # first boot (provisioning), so they carry no shared credential.
  echo "disk.sh: WARNING --user bakes a pre-created account ('$user') into the image; this is" >&2
  echo "         for development/unattended installs only. Omit --user for a production image," >&2
  echo "         which is unprovisioned and creates its user at first boot (ADR-0027)." >&2
fi
if [[ $luks -eq 1 && "$type" != iso ]]; then
  # The bootc-image-builder blueprint knows plain, lvm and btrfs partitions and nothing
  # encrypted; disk encryption is Anaconda's job, so it is only reachable through the
  # installer ISO's kickstart.
  echo "disk.sh: --luks needs --type iso (bootc-image-builder cannot encrypt a qcow2; the installer can)" >&2
  exit 2
fi

# --- the generated bootc-image-builder config -------------------------------------------
# bootc-image-builder refuses [[customizations.user]] next to a custom kickstart, so with
# --luks the user is a kickstart `user` line instead; without it, the builder's own user
# customization does the same job on both output types.
write_config() {
  local key=""
  if [[ -n "$ssh_key" ]]; then key=$(<"$ssh_key"); fi
  echo "# Generated by image/disk.sh; do not commit (it may hold a password)."
  if [[ $luks -eq 1 ]]; then
    echo "[customizations.installer.kickstart]"
    echo 'contents = """'
    echo "# Full-disk encryption: autopart --encrypted without --passphrase makes Anaconda"
    echo "# ask for one during the installation (unverified until E-09)."
    echo "zerombr"
    echo "clearpart --all --initlabel --disklabel=gpt"
    echo "autopart --noswap --type=${rootfs} --encrypted"
    echo "network --bootproto=dhcp --device=link --activate --onboot=on"
    echo "lang en_US.UTF-8"
    echo "keyboard us"
    echo "timezone UTC --utc"
    echo "rootpw --lock"
    if [[ -n "$user" ]]; then
      local line="user --name=${user} --groups=wheel"
      if [[ -n "$password" ]]; then line+=" --password=${password} --plaintext"; fi
      echo "$line"
      if [[ -n "$key" ]]; then echo "sshkey --username=${user} \"${key}\""; fi
    fi
    echo "reboot"
    echo '"""'
  elif [[ -n "$user" ]]; then
    echo "[[customizations.user]]"
    echo "name = \"${user}\""
    if [[ -n "$password" ]]; then echo "password = \"${password}\""; fi
    if [[ -n "$key" ]]; then echo "key = \"${key}\""; fi
    echo 'groups = ["wheel"]'
  fi
}

generated=""
if [[ -n "$user" || $luks -eq 1 ]]; then
  mkdir -p "$output"
  generated="$output/config.toml"
  (umask 077 && write_config >"$generated")
  config=$generated
fi

# A terminal only when there is one: CI has no tty, and podman refuses -t without it.
tty_flag=()
if [[ -t 0 ]]; then tty_flag=(-t); fi
cmd=("$podman_bin" run --rm -i "${tty_flag[@]}"
  --privileged
  --security-opt label=type:unconfined_t
  --volume "${output}:/output"
  --volume /var/lib/containers/storage:/var/lib/containers/storage)
if [[ -n "$config" ]]; then
  cmd+=(--volume "$(realpath "$config"):/config.toml:ro")
fi
cmd+=("$builder"
  --type "$type"
  --rootfs "$rootfs"
  "${target_arch[@]}")
if [[ -n "$config" ]]; then
  cmd+=(--config /config.toml)
fi
cmd+=("$image")

if [[ "$type" == iso ]]; then
  if [[ $luks -eq 1 ]]; then
    echo "disk.sh: full-disk encryption on (the installer asks for the passphrase; --no-luks opts out)"
  else
    echo "disk.sh: full-disk encryption off"
  fi
fi
printf 'disk.sh: would run (output in %s):\n  mkdir -p %q\n  ' "$output" "$output"
printf '%q ' "${cmd[@]}"
printf '\n'
if [[ -n "$generated" ]]; then
  echo "disk.sh: wrote $generated (mode 0600):"
  # Never echo the password; the file has it.
  (password='********' && write_config) | sed 's/^/  /'
fi

if [[ $dry_run -eq 1 ]]; then
  exit 0
fi

if ! command -v "$podman_bin" >/dev/null 2>&1; then
  echo "disk.sh: $podman_bin is not installed; install podman or re-run with --dry-run" >&2
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "disk.sh: bootc-image-builder needs root (sudo $0 ...)" >&2
  exit 1
fi
if ! "$podman_bin" image exists "$image"; then
  # A registry reference (ghcr.io/hexrift/wardos:latest, the image CI publishes on
  # every merge) is pulled; a local name has to come from image/build.sh.
  if [[ "$image" == */*.*/* || "$image" == ghcr.io/* ]]; then
    echo "disk.sh: pulling $image"
    "$podman_bin" pull "$image"
  else
    echo "disk.sh: image $image is not in root's container storage; run sudo image/build.sh first" >&2
    exit 1
  fi
fi

mkdir -p "$output"
"${cmd[@]}"

# bootc-image-builder writes as root. Hand the disks back to whoever ran sudo, so the
# QEMU command in the README works without a second sudo or a chown by hand.
if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
  chown -R "$SUDO_UID:$SUDO_GID" "$output"
fi

# Say where the disk landed and, for a raw image, that flashing it to a USB and
# booting that USB never touches the machine's own disk (unlike the installer ISO).
case "$type" in
  qcow2) echo "disk.sh: $output/qcow2/disk.qcow2 (boot in QEMU; see image/README.md)" ;;
  raw)
    # bootc-image-builder writes raw to <output>/image/disk.raw; give it a clear name.
    if [[ -f "$output/image/disk.raw" ]]; then
      mkdir -p "$output/raw"
      mv -f "$output/image/disk.raw" "$output/raw/wardos.raw"
      rmdir "$output/image" 2>/dev/null || true
      [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]] && chown -R "$SUDO_UID:$SUDO_GID" "$output/raw"
    fi
    echo "disk.sh: $output/raw/wardos.raw"
    echo "disk.sh: a whole-disk image. Write it to a USB stick and boot the machine"
    echo "disk.sh: from that USB: WardOS runs off the stick and boots straight to the"
    echo "disk.sh: desktop, with no installer. Booted from USB it marks every internal"
    echo "disk.sh: disk read-only (wardos-usb-guard), so nothing on the stick can"
    echo "disk.sh: format or repartition the machine's own disk. To flash (this ERASES"
    echo "disk.sh: the USB, not the internal disk):"
    echo "disk.sh:   lsblk -o NAME,SIZE,MODEL,TRAN            # Linux: the USB is TRAN=usb"
    echo "disk.sh:   sudo dd if=$output/raw/wardos.raw of=/dev/sdX bs=4M status=progress oflag=direct conv=fsync"
    echo "disk.sh:   # macOS: diskutil list; diskutil unmountDisk /dev/diskN;"
    echo "disk.sh:   #        sudo dd if=$output/raw/wardos.raw of=/dev/rdiskN bs=4m"
    ;;
  iso)
    echo "disk.sh: $output/bootiso/install.iso"
    echo "disk.sh: THIS IS AN INSTALLER. Booting it and proceeding ERASES the target"
    echo "disk.sh: machine's internal disk. To try WardOS without installing, build a"
    echo "disk.sh: --type raw image and boot it from USB, or a --type qcow2 image in QEMU."
    ;;
esac
