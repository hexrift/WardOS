# Secure Boot for the WardOS image

Status: **planned, unvalidated** (Phase 7, experiment E-09). This directory is a
CODEOWNERS surface (`.github/CODEOWNERS`): anything that lands here is reviewed by a
human, because it decides what the reference hardware will execute before the kernel.

## What Secure Boot means for WardOS

The brief's requirement is that Secure Boot stays **on** through installation and every
update. ADR-0001 picked Fedora so that this needs no key enrolment: Fedora's `shim` is
signed by the Microsoft UEFI CA, and shim carries Fedora's certificate, which signs GRUB
and the kernel. The image built by `../Containerfile` inherits all of that from
`fedora-bootc`; Phase 6 adds nothing to the chain.

```text
Microsoft UEFI CA  ─signs─▶  shim  ─embeds Fedora CA, verifies─▶  GRUB2 / systemd-boot
                                                                  kernel / UKI
```

## Where WardOS has to sign something itself

Only two planned components are not Fedora-signed:

1. **The UKI** (`../boot/README.md` §3). Fedora signs its kernels, but a UKI is a new PE
   file that bundles the kernel with WardOS's initramfs and command line. Options, in
   order of preference, all to be tested in E-09:
   * Fedora's own signed UKI variants (`kernel-uki-virt`), if their initramfs is enough.
     No WardOS key at all.
   * A WardOS-signed UKI with the WardOS certificate enrolled through shim's **MOK**
     (Machine Owner Key) list: `mokutil --import wardos-uki.der` at install, one
     confirmation in the MokManager screen on the next boot. Secure Boot stays on;
     Microsoft's CA stays in `db`; the WardOS key is trusted by shim only.
   * A WardOS key enrolled in the firmware `db` directly. Rejected for the product (needs
     Setup Mode on every device); acceptable for a CI runner.
2. **Out-of-tree kernel modules** (NVIDIA, ADR-0001 disadvantages). Same MOK key, `akmods`
   style signing; deferred, AMD reference hardware first.

Everything else the host runs after the kernel is checked by other means: the image by
its digest and (Phase 7) its sigstore signature at `bootc upgrade` time, the root
filesystem by fs-verity when the composefs backend is adopted.

## What will live here

| File | Purpose | Contains secrets? |
| --- | --- | --- |
| `README.md` | this | no |
| `mok/wardos-uki.der` (planned) | the certificate enrolled into MOK; a copy of `../keys/` | no, public |
| `sign.sh` (planned) | `sbsign --key <path outside the repo> --cert ../keys/... vmlinuz.efi`; reads the private key from a path or a PKCS#11 URI given on the command line, never from the tree | no |
| `enroll.md` (planned) | the exact `mokutil` and MokManager steps, with screenshots, as recorded on the reference laptop | no |
| `test-qemu.md` (planned) | booting the qcow2 under OVMF with Secure Boot enabled (`OVMF_CODE.secboot.fd`, enrolled Microsoft certs) | no |

The private signing key is never in the repository, never in CI secrets for the merge
gate, and never on a developer laptop as a file: the plan is an HSM or a YubiKey
(PKCS#11) held by the release owner, with a documented, offline-stored backup.
`scripts/security-check/static.sh` already fails the build if a PEM private key block is
committed anywhere; that check is the tripwire, not the policy.

## How E-09 validates this

On the reference desktop and one reference laptop, with Secure Boot **on** from the
factory state:

1. Install from the ISO produced by `../disk.sh --type iso`. Must succeed with the stock
   Fedora chain (no MOK, nothing enrolled).
2. `mokutil --sb-state` reports enabled after first boot; `bootc status` names the image.
3. Switch to a UKI build; enrol the WardOS certificate via MOK; reboot; confirm the UKI
   boots, `mokutil --sb-state` still enabled, and `systemd-cryptenroll --tpm2-pcrs=7+11`
   unlocks the LUKS volume without the recovery key.
4. Replace the UKI with an unsigned one: the firmware must refuse it and the previous
   deployment must boot (rollback, `../boot/README.md` §6).

Results go into `docs/experiments.md` under E-09 and, per ADR-0001, a failure re-opens the
base-OS decision with data rather than being worked around here.
