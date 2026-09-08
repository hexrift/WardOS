# Public keys for the WardOS image

Status: **empty, by design, until Phase 7.** This directory is a CODEOWNERS surface: a
human reviews every change, and a change here is a change to what WardOS machines trust.

## The rule

**Only public material enters this directory, ever.** No private keys, no PKCS#12
bundles, no encrypted private keys ("it has a passphrase" is not an exception), no
key-derivation seeds, no recovery keys, no TPM blobs. Private material lives on the
release owner's hardware token or HSM and in one documented offline backup; see
[`../secure-boot/README.md`](../secure-boot/README.md).

`scripts/security-check/static.sh` fails the verify job if any `-----BEGIN ... PRIVATE
KEY-----` block appears anywhere in the tree. That is a tripwire for accidents, not the
control: the control is that the key is never a file on a developer machine to begin with.

## What will be here

| File (planned) | Format | Verifies |
| --- | --- | --- |
| `wardos-uki.der`, `wardos-uki.pem` | X.509 certificate | the WardOS-signed UKI, enrolled into shim's MOK on install (`mokutil --import`) |
| `wardos-modules.der` | X.509 certificate | out-of-tree kernel modules, if WardOS ever ships any (deferred) |
| `wardos-image.pub` | sigstore/cosign public key, or the Fulcio identity if keyless signing is chosen | the OCI image at `bootc upgrade`/`switch` time, referenced from the image's `/etc/containers/policy.json` |
| `SHA256SUMS` | text | fingerprints of every file above, so a reviewer can compare them with the ones printed at the release announcement |

Each file arrives with the commit that starts using it: the certificate together with
the `Containerfile` change that copies it into `/usr/share/wardos/keys/` and the policy
that references it. A key that nothing in the image references is not merged.

## Rotation

A key rotation is a normal pull request touching this directory, `../secure-boot/`, and
the image, plus a note in `docs/decisions/` if the trust model changes (for example moving
from a WardOS MOK certificate to Fedora's signed UKIs, which would *remove* files here).
The old public key stays in git history; the old private key is destroyed and the
destruction recorded in the release notes.
