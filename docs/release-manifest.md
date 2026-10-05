# Release manifest format

This is the machine-readable manifest format decided in
[ADR-0028](decisions/ADR-0028-release-provenance-and-trusted-updates.md) §4, and the
generator that produces it: [`scripts/release/generate-manifest.sh`](../scripts/release/generate-manifest.sh).

This document covers the manifest format, its generator, and how a release publishes
and an operator verifies it. It does not cover signing, attestation, or update
verification — see "What this is not" below and issue
[#148](https://github.com/hexrift/WardOS/issues/148) for the rest of that work's
status.

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
release's artifacts exist. Two environment variables exist for the release workflow
and the tests: `GENERATE_MANIFEST_NOW` pins `generated_at` (the workflow sets it to
the source commit's committer time, see below), and
`GENERATE_MANIFEST_COMPATIBILITY_DOC` names the compatibility document the protocol
window is read from (default: the repository's `docs/compatibility.md`, found
relative to the script).

Every input is validated before any output is produced. An artifact whose name
doesn't carry this manifest's own version or one of the two release trains
(`wardos-<version>-<arch>-linux.tar.gz`, the runtime, and
`ward-node-<version>-<arch>-linux.tar.gz`, the node; issue #275), a tarball with no
checksum sidecar (or a sidecar with no matching tarball), or a sidecar whose recorded
digest doesn't match the artifact's actual bytes are all refused with a specific,
actionable message — never silently dropped from the manifest or silently trusted. So
is a compatibility document whose protocol-window marker is absent, duplicated or
malformed: the window is never guessed or defaulted. See
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
      "name": "ward-node-1.2.3-x86_64-linux.tar.gz",
      "component": "ward-node",
      "architecture": "x86_64",
      "digest": "sha256:<hex>",
      "size_bytes": 1234567
    },
    {
      "name": "wardos-1.2.3-x86_64-linux.tar.gz",
      "component": "wardos",
      "architecture": "x86_64",
      "digest": "sha256:<hex>",
      "size_bytes": 12345678
    }
  ],
  "node_protocol_window": {
    "major": 1,
    "min_minor": 0,
    "max_minor": 3
  },
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
byte-identical manifests, independent of filesystem/glob ordering. `component` is the
release train the artifact belongs to, taken from its name: `wardos` for the runtime
tarball, `ward-node` for the node tarball
([node-release-readiness.md](node-release-readiness.md) §2).

`node_protocol_window` is the `ward-node` protocol window the release serves
([compatibility.md](compatibility.md) §1; issue #275), in the shape of the `supported`
range a node answers a `hello` with: one `major`, and the minors `min_minor` through
`max_minor`. It is read from the `<!-- protocol-window: M.a-M.b -->` marker of
`docs/compatibility.md` at the release commit — the same marker
`scripts/security-check/protocol-window.py` holds equal to `WARD_NODE_PROTOCOL` on
every pull request — never from a second hand-maintained copy, so the manifest, the
document and the code of a release name one window. A control plane can compare the
field against the range it offers before it connects (compatibility.md §3).

## The published manifest

The release workflow (`.github/workflows/release.yml`, job `release`) generates the
manifest only after `check-release-set.sh` has verified the complete artifact set, from
that verified `dist/` directory, so the manifest can never name an artifact that was not
checked. It attaches two more assets to the release, next to the tarballs:

| Asset | Carries |
| --- | --- |
| `wardos-<version>-manifest.json` | the manifest above |
| `wardos-<version>-manifest.json.sha256` | `sha256sum`'s line for it, like every tarball's sidecar |

`generated_at` of a published manifest is the source commit's committer time, not the
run's clock: a retry of the release workflow at the same commit must reproduce every
asset byte for byte (ADR-0028 §4), and the manifest is reconciled like the tarballs by
`download-published.sh` and `check-assets.sh` — identical is a no-op, different bytes
are refused before anything is overwritten.

To verify a release from its manifest, download the assets into one directory and run:

```
sha256sum -c wardos-<version>-manifest.json.sha256
jq -r '.artifacts[] | (.digest | sub("^sha256:"; "")) + "  " + .name' \
  wardos-<version>-manifest.json | sha256sum -c
```

The first line checks the manifest against its sidecar; the second checks every
artifact the manifest names against the digest it records, and `sha256sum -c` fails on
an artifact that is missing or does not match. `source_commit` must equal the commit
the release's tag resolves to (`git rev-parse <tag>^{commit}`). Like the `.sha256`
sidecars, this proves the bytes are the ones CI attached, not who built them: see the
next section.

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

- Generating or verifying the provenance attestation itself (Sigstore/cosign,
  workflow-identity OIDC policy).
- The installer/update verifier that reads a manifest and a real attestation and
  decides whether to stage an update (ADR-0028 §5's state machine).
- Boot-chain / Secure Boot integration, which ADR-0028 §6 keeps a separate trust
  boundary from release/artifact provenance.

Current published releases remain checksum-only, as ADR-0028's own last line requires
until the workflow emits, and the installer verifies, real provenance evidence.
