# Release manifest format

This is the machine-readable manifest format decided in
[ADR-0028](decisions/ADR-0028-release-provenance-and-trusted-updates.md) §4, and the
generator that produces it: [`scripts/release/generate-manifest.sh`](../scripts/release/generate-manifest.sh).

This document covers the manifest format and its generator only. It does not cover
signing, attestation, or update verification — see "What this is not" below and
issue [#148](https://github.com/hexrift/WardOS/issues/148) for the rest of that
work's status.

## Generating a manifest

```
generate-manifest.sh <tag> <commit> <dist-dir> [image-ref]
```

- `<tag>` — the release tag, e.g. `v1.2.3` (same grammar `check-version.sh` enforces).
- `<commit>` — the full 40-character source commit the release was built from (what
  `check-tag-commit.sh` already binds the tag to).
- `<dist-dir>` — the directory holding the release's `*.tar.gz` artifacts and their
  `*.tar.gz.sha256` sidecars, exactly as `check-assets.sh` already validates them
  before upload.
- `[image-ref]` — optional OCI/bootc image reference for this release, e.g.
  `quay.io/hexrift/wardos:v1.2.3`. Omitted when a release has no image counterpart.

The manifest is printed to stdout as JSON. The generator does not write, upload, sign
or attest anything; it only assembles and validates fields already available once a
release's artifacts exist.

Every input is validated before any output is produced. An artifact whose name
doesn't carry this manifest's own version, a tarball with no checksum sidecar (or a
sidecar with no matching tarball), or a sidecar whose recorded digest doesn't match
the artifact's actual bytes are all refused with a specific, actionable message —
never silently dropped from the manifest or silently trusted. See
[`generate-manifest.test.sh`](../scripts/release/generate-manifest.test.sh) for the
full set of fixtures this covers.

## Schema (version 1)

```jsonc
{
  "schema_version": 1,
  "tag": "v1.2.3",
  "version": "1.2.3",
  "source_commit": "<40-hex-character commit sha>",
  "generated_at": "<UTC ISO-8601 timestamp>",
  "artifacts": [
    {
      "name": "wardos-1.2.3-x86_64-linux.tar.gz",
      "architecture": "x86_64",
      "digest": "sha256:<hex>",
      "size_bytes": 12345678
    }
  ],
  "image": {
    "bootc_reference": "quay.io/hexrift/wardos:v1.2.3" // or null
  },
  "provenance": {
    "status": "unavailable",
    "attestation_ref": null,
    "builder": null,
    "note": "No provenance attestation is generated or verified yet (ADR-0028, issue #148). This release remains checksum-only for publisher/workflow identity purposes."
  },
  "compatibility": {
    "rollback_supported": true,
    "min_upgrade_from": null,
    "notes": "The anti-rollback floor (ADR-0028 §5) is enforced by the update verifier at install/update time, not recorded per-release here."
  }
}
```

`artifacts` is sorted by `name` so that two runs over identical inputs produce
byte-identical manifests, independent of filesystem/glob ordering.

## What this is not

This manifest's `provenance` object is an explicit, honest placeholder, not partial
signing. `status` is always `"unavailable"` and `attestation_ref`/`builder` are always
`null` until the release workflow actually generates a real attestation and the
installer/updater actually verifies it — per ADR-0028's own "Scope of the
implementation," a manifest generator existing here must not be read as, or produce
output that implies, existing releases are signed. Once real provenance exists, this
schema's `provenance` object is where it is expected to be recorded — filling in
`status`, `attestation_ref` (the SLSA/in-toto provenance reference from ADR-0028 §4)
and `builder` (the toolchain metadata *derived from* that attestation, per the ADR — not
a hand-written copy) is a follow-up change to this generator, not a schema break.

Also not covered here, and tracked separately under issue #148:

- Actually wiring this generator into `.github/workflows/release.yml` and publishing
  the manifest as a release asset.
- Generating or verifying the provenance attestation itself (Sigstore/cosign,
  workflow-identity OIDC policy).
- The installer/update verifier that reads a manifest and a real attestation and
  decides whether to stage an update (ADR-0028 §5's state machine).
- Boot-chain / Secure Boot integration, which ADR-0028 §6 keeps a separate trust
  boundary from release/artifact provenance.

Current published releases remain checksum-only, as ADR-0028's own last line requires
until the workflow emits, and the installer verifies, real provenance evidence.
