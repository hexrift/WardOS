# How the WardOS image boots, updates and rolls back

Status: **planned, unvalidated.** Everything below describes the bootc mechanisms the
image relies on and the order WardOS intends to adopt them. Experiment E-09 in
[`experiments.md`](../../docs/experiments.md) turns each item into a recorded result;
until then nothing here has been exercised on a WardOS build. Sections are marked with
what they rest on: **bootc (stable)** for behaviour the Fedora bootc project documents
and ships today, **planned (E-09)** for the parts WardOS still has to prove.

## 1. What is on disk — bootc (stable)

A bootc system is an OCI image deployed onto a disk. The installer (`bootc install` inside
`bootc-image-builder`, which `../disk.sh` drives) lays out:

```text
ESP           FAT, EFI/fedora/{shimx64.efi,grubx64.efi} today; systemd-boot later (§3)
/boot         kernel + initramfs per deployment (bootc "bootupd" managed)
/             the image, stored as an ostree commit; read-only except:
  /etc        3-way merged across upgrades (image defaults ⊕ local changes)
  /var        persistent, never touched by upgrades; /var/lib/wardos lives here
```

Phase 6 uses the **ostree backend**: every deployment is an ostree commit derived from the
image's layers, hard-linked into a content store, so two deployments share unchanged
files. `/usr` is read-only at runtime, which is why every WardOS file in the image goes
under `/usr/lib/...` and state goes to `/var/lib/wardos` (created by tmpfiles, not baked
in; `bootc container lint` rejects `/var` content in an image).

`bootc status` prints the booted, staged and rollback deployments with their image
references and digests. The digest is the identity WardOS records in evidence
(ADR-0001, security consequences).

## 2. Boot chain today — bootc (stable)

```text
UEFI firmware  ─▶  shim (Fedora, Microsoft-signed)  ─▶  GRUB2 (Fedora-signed)
               ─▶  kernel + initramfs (Fedora-signed kernel)  ─▶  ostree root  ─▶  systemd
```

This is what `bootc-image-builder` installs from a Fedora bootc image with no extra
configuration, and it is what Secure Boot validates on the reference hardware without any
key enrolment: each stage's signature chains back to the Microsoft UEFI CA through shim's
embedded Fedora certificate. ADR-0001 chose Fedora over NixOS and Arch on exactly this
point.

## 3. Boot chain target — planned (E-09, Phase 7)

```text
UEFI  ─▶  shim  ─▶  systemd-boot  ─▶  UKI (kernel + initramfs + cmdline, one signed PE)
      ─▶  root (composefs + fs-verity, sealed)  ─▶  LUKS2 data volume (TPM2 + recovery key)
```

What changes and what has to be true for it:

| Step | Mechanism | Depends on | State |
| --- | --- | --- | --- |
| systemd-boot instead of GRUB | `bootc install --bootloader`/bootupd systemd-boot support; `systemd-boot` package in the image | bootupd's systemd-boot path being stable on Fedora 42+ | planned |
| UKI | `dracut --uefi` or `kernel-install` with `layout=uki` producing `/usr/lib/modules/<ver>/vmlinuz.efi` (bootc "UKI mode") | bootc's UKI support (tracked upstream as "sealed images") | planned |
| Signed UKI | the UKI signed with a WardOS key enrolled via shim's MOK, or Fedora's signed UKI variants | [`../secure-boot/`](../secure-boot/README.md) | planned |
| composefs root with fs-verity | bootc `composefs` backend (`bootc install --composefs-backend`, experimental) | upstream stabilisation; E-09 measures it in parallel with the stable backend | evaluate |
| Btrfs root filesystem | `bootc-image-builder --rootfs btrfs` (the `../disk.sh` default) | nothing new; snapshots for `/work` (ADR-0010) want it | stable |

Phase 6 ships on the GRUB + ostree chain of §2 and is acceptable without any of the rows
above. Phase 7's acceptance ("Secure Boot stays on throughout installation", RT-001/002)
is what makes them mandatory.

## 4. Updating — bootc (stable)

```sh
sudo bootc upgrade              # fetch the new image for the current reference, stage it
sudo bootc upgrade --apply      # same, then reboot into it
sudo bootc status               # booted / staged / rollback deployments
```

`bootc upgrade` pulls the image the host was installed from (or switched to, §5), writes
a new deployment next to the running one and marks it to boot next. The running system
is untouched until reboot; `/etc` is merged, `/var` is left alone. If the fetch fails
half way, nothing has changed.

WardOS wraps this later as `ward system upgrade` so the observer can show the digest
change as an event; until then the plain command is the interface.

## 5. Switching images — bootc (stable)

```sh
sudo bootc switch quay.io/hexrift/wardos:0.1       # follow a different reference
sudo bootc switch --transport containers-storage localhost/wardos:<tag>   # a local build
```

`switch` changes which image reference `bootc upgrade` follows and stages it like an
upgrade. The second form is how a freshly built image is tried on a running WardOS
without pushing it anywhere; the first is how a released image will be adopted. Signature
verification of the pulled image (`containers-policy.json`, sigstore) is part of the
Phase 7 signed-updates item and is not configured yet.

## 6. Rollback — bootc (stable) and planned (E-09)

Manual, available today:

```sh
sudo bootc rollback && sudo systemctl reboot     # boot the previous deployment next
```

Automatic, planned: **boot counting.** systemd-boot (§3) and `bootc` support
`boot-complete.target`: a deployment that fails to reach it a configured number of times
is skipped in favour of the previous one. WardOS's `wardos-firstboot.service` is a
candidate signal for "this deployment works" (ward doctor exit 0 → boot-complete), the
rest is the `ward system rollback` command of Phase 7. RT-001/RT-002 in the security
tests are the acceptance: a deliberately broken update rolls back without user action.

Until boot counting is in, the E-09 method is: break an update on purpose (e.g. an image
whose `ward doctor` exits 1 and whose unit is `Type=oneshot` with `FailureAction=reboot`
in a test variant), confirm that `bootc rollback` from the recovery shell works, and
record boot and resume times.

## 7. Full-disk encryption with TPM2 — planned (E-09, Phase 7)

The roadmap's target: LUKS2 data volume unlocked by the TPM2 with a PCR policy, plus a
recovery key. The steps, as they will be run on the reference hardware:

```sh
# 1. Install with an encrypted root: bootc-image-builder config
#    [customizations.disk] ... or install with `bootc install to-disk --luks` (planned).
# 2. On first boot, with Secure Boot on and the UKI in place:
sudo systemd-cryptenroll /dev/disk/by-partlabel/root \
     --tpm2-device=auto \
     --tpm2-pcrs=7            # Secure Boot state (stable chain, §2)
#    with UKI (§3) extend to: --tpm2-pcrs=7+11  (11 = the UKI's measured sections)
sudo systemd-cryptenroll /dev/disk/by-partlabel/root --recovery-key   # print, keep offline
# 3. crypttab: root  UUID=...  none  tpm2-device=auto
```

PCR 7 binds to the Secure Boot policy (turning it off, or enrolling a foreign key,
changes the value and forces the recovery key), PCR 11 to the specific UKI measurement,
which is what makes a downgrade or a tampered kernel unable to unlock the volume.
Whether Fedora 42's `bootc-image-builder` can produce the encrypted layout directly, or
E-09 has to encrypt during a manual `bootc install to-disk`, is one of the questions the
experiment answers. **None of this has been run on a WardOS image.**

## 8. Files in this directory

None yet beyond this README. When §3 lands, this is where the systemd-boot loader entries
(`loader.conf`, `entries/`) and the UKI build configuration (`ukify.conf` or the
`kernel-install` drop-ins) go, copied into `/usr/lib/` by the `Containerfile`. Signing
configuration is in `../secure-boot/`, public keys in `../keys/`.
