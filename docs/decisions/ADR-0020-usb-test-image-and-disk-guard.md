# ADR-0020 — A USB test image, and a boot-time guard so trying WardOS cannot erase a disk

## Decision
WardOS ships three image kinds, and the way to *try* it never reformats a disk:

* `qcow2` — a VM disk, boots in QEMU or UTM, touches nothing on the real machine.
* `raw` — a whole-disk image written to a USB stick; the machine boots WardOS from the
  stick and its internal disk is left alone. It boots straight to the desktop and
  carries no installer.
* `iso` — the Anaconda installer, which erases and reformats the target disk. It is for
  committing a machine to WardOS, not for trying it.

`image/disk.sh --type raw` builds the USB image (output `image/out/raw/wardos.raw`),
the `disk.yml` workflow builds and publishes it for people without a Linux host, and
every `disk.sh` run and the docs say plainly which image installs and which does not.

A boot-time service, `wardos-usb-guard`, is defence in depth: when WardOS is booted
from removable media it identifies the boot disk and marks every *internal* disk
read-only (`blockdev --setro`), so nothing running off the stick — a stray `dd`, a
mistaken installer — can format or repartition the machine's own disk. It refuses to
act unless it can name the boot disk with confidence (setting the wrong device
read-only would break the running system), leaves other removable media writable, and
is inert on an installed host (booted from a fixed disk). It is a guard, not a wall:
root can undo it, and it reduces the blast radius of a mistake rather than making one
impossible.

## Context
A user who wanted to *try* WardOS was pointed at the installer ISO and lost the Fedora
install on their laptop: the ISO's kickstart runs `clearpart --all` and
`autopart --encrypted`, and nothing upstream of the boot distinguished "try it" from
"install it". The project had a VM path (`qcow2`) but no way to try WardOS on real
hardware without installing, and the only hardware image was the destructive installer.
The failure was not the user's: the safe option did not exist and the dangerous one was
presented as the way to see WardOS on a laptop.

## Consequences
* `image/disk.sh` gains `--type raw`; its per-type output names the file and says, for
  `raw`, that booting the USB does not touch the internal disk, and for `iso`, that it
  is an installer that erases the target disk.
* `image/rootfs/usr/libexec/wardos-usb-guard` and `wardos-usb-guard.service` are in the
  image and enabled; the service is safe on an installed host (it does nothing there).
* `docs/install.md`, `image/README.md` and the README lead with the non-destructive
  options and mark the installer as destructive; `image/README.md` has a table of the
  three kinds.
* `disk.yml` accepts `type=raw` and publishes `wardos-<tag>-<arch>.raw` so a USB image
  can be downloaded rather than built.

## Alternatives considered
* **A true live/ephemeral image (squashfs, overlay-to-RAM) that writes nothing at all.**
  Stronger, and worth doing later, but a larger change (a live compose, not a bootc
  disk); the `raw`-from-USB image already gives a non-destructive hardware trial now.
* **Refusing to build the ISO at all.** The installer is a legitimate final step; the
  fix is to stop presenting it as the way to *try* WardOS, not to remove it.
* **Only documentation.** Necessary but not sufficient: the guard means that even when
  the docs are ignored, running WardOS from a stick will not silently reformat a disk.
