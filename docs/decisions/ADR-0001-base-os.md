# ADR-0001 — Base operating system: Fedora-derived bootc image

## Decision
WardOS is built as a **bootc** (bootable OCI container) image derived from the Fedora
bootc base, using the stable ostree-backed deployment in Phase 6 and evaluating the
composefs/sealed-image backend in Phase 7. Boot chain: Fedora shim → systemd-boot → UKI.
Host filesystem: Btrfs. Developer toolchains are never installed in the host image.

## Alternatives
1. **Fedora Atomic / bootc** (selected).
2. **NixOS** (declarative, reproducible, generations-based rollback).
3. **Arch-derived** (Omarchy's route: mutable pacman host, fast, huge package pool).
4. **Custom immutable image** (own build system, e.g. mkosi-produced images with
   systemd-sysupdate, A/B partitions).

## Advantages
- OCI is the delivery format: the same tooling builds, signs, scans and distributes the
  host image and the tool layers; `bootc upgrade`/`rollback` are atomic by construction.
- Fedora's shim is Microsoft-signed: Secure Boot stays on during installation without
  key enrolment, which the brief requires.
- Fresh kernels (namespaces, Landlock ABI, cgroup features, fanotify, eBPF) and
  first-class rootless Podman/crun, composefs, systemd-cryptenroll, UKI tooling.
- Hyprland is in Fedora's official repositories; community bootc+Hyprland images exist as
  prior art.
- Sealed images (UKI + composefs + fs-verity + Secure Boot) are an active bootc track,
  aligned with Phase 7 goals.

## Disadvantages
- bootc's composefs backend is experimental (mid-2026); sealed images need care.
- Fedora release cadence (~6 months) means base rebases twice a year; ABI churn.
- Less "hackable" than Arch: users cannot `pacman -S` on the host, which is intended but
  is a marketing cost against Omarchy's audience.
- NVIDIA proprietary drivers require layered builds and signing with a WardOS key
  (deferred; AMD reference hardware first).

## Security consequences
- Immutable, signed root; rollback; measured boot path available.
- Host attack surface is fixed and auditable per image digest; the digest appears in
  evidence.
- Toolchains in project environments (Zone 3) rather than the host means a compromised
  toolchain never touches Zone 0.

## Performance consequences
- Image-based install can stream a prebuilt filesystem (Phase 8), which is the only
  credible route to < 45 s installs with FDE.
- composefs + fs-verity has small read overhead; Btrfs snapshot path enables O(1) entry
  snapshots for `/work`.
- Boot time is dominated by initramfs + LUKS unlock; UKI + systemd-boot keeps it lean.

## Why selected
NixOS gives the best reproducibility but Secure Boot requires custom key enrolment
(lanzaboote), the module system is a steep on-ramp for the target user, and its container
story is orthogonal to how WardOS wants to ship tool layers. Arch-derived gives the best
package pool and Omarchy-like install speed but has no signed shim path, no atomic
updates, and invites host mutation, which contradicts §3 of the brief. A custom image
system would reinvent bootc. Fedora bootc is the only option that satisfies immutable +
atomic + signed + rollback + Secure-Boot-on + OCI delivery today.

## How it will be validated
E-09: build, install with FDE on the reference desktop and one laptop with Secure Boot
enabled, break an update, confirm automatic rollback (RT-001/002), record boot and resume
times, and test the sealed backend in parallel. Re-open this ADR if E-09 fails.

## Addendum 2026-09: base rebased from Fedora 42 to Fedora 44

The image pinned `quay.io/fedora/fedora-bootc:42` from its first draft. By September
2026 Fedora 42 had reached end of life (May 2026) and the COPR repositories the Hyprland
ecosystem came from had dropped their `fedora-42-x86_64` chroot, which the new "image
packages" CI job reported the first time it ran for real (`dnf copr enable`: "Chroot
not found in the given Copr project (fedora-42-x86_64)"). Per this ADR's rule that a
rebase is a deliberate edit of `FROM` and never an implicit change, the edit is made
here, once, to the current release, 44: `image/Containerfile` pins `fedora-bootc:44`,
`image/check-packages.sh`, `desktop/install.sh` and the tests read the release from
that `FROM` line so nothing else has to be kept in step, and `image/coprs.txt` starts
empty again in the first attempt; the check then showed that Fedora had retired
Hyprland itself after 42, so three COPRs came back for exactly what 44 lacks
(`mineiro/hyprland` for the ecosystem, `erikreider/swayosd` from swayosd's author,
`atim/lazygit`), chosen by `check-packages.sh --discover` from the projects that build
for 44. Each COPR is part of the image's trust set: its builds are the owner's, not
Fedora's, and the repository file stays in the image; the list is kept short, every
entry justified in `image/coprs.txt`, and an entry leaves the day Fedora packages the
thing. E-09 runs against 44.
Lesson recorded: a pinned release needs a calendar; the next rebase is due before 44's
end of life, and the "image packages" job is the alarm if it is missed.
