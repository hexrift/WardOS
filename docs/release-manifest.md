# Release manifest format

This is the machine-readable manifest format decided in
[ADR-0028](decisions/ADR-0028-release-provenance-and-trusted-updates.md) §4, and the
generator that produces it: [`scripts/release/generate-manifest.sh`](../scripts/release/generate-manifest.sh).

This document covers the manifest format, its generator, how a release publishes and
signs it, and how an operator verifies that signature offline with
[`scripts/release/verify-manifest.sh`](../scripts/release/verify-manifest.sh). It does
not cover a provenance attestation for the tarballs or the image, or update
verification — see "What the signature proves, and what it does not" below and issue
[#148](https://github.com/hexrift/WardOS/issues/148) for the rest of that work's
status.

## Generating a manifest

```
generate-manifest.sh [--node-version <node-version>] <tag> <commit> <dist-dir> [image-ref]
```

- `--node-version` — the node train's own version (issue #275), which names the node
  tarball and is recorded under `components` and on the node artifact. The release
  workflow passes the version its `version` job proved against the previous release
  with `scripts/release/node-version.sh`; without the option the generator reads this
  checkout's node version through the same script.
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
doesn't carry its train's version for this manifest or one of the two release trains
(`wardos-<version>-<arch>-linux.tar.gz`, the runtime under the release version, and
`ward-node-<node-version>-<arch>-linux.tar.gz`, the node under the node version;
issue #275), a tarball with no
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
  "components": {
    "wardos": { "version": "1.2.3" },
    "ward-node": { "version": "0.3.0" }
  },
  "artifacts": [
    {
      "name": "ward-node-0.3.0-x86_64-linux.tar.gz",
      "component": "ward-node",
      "version": "0.3.0",
      "architecture": "x86_64",
      "digest": "sha256:<hex>",
      "size_bytes": 1234567
    },
    {
      "name": "wardos-1.2.3-x86_64-linux.tar.gz",
      "component": "wardos",
      "version": "1.2.3",
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
    "note": "No SLSA provenance attestation is generated or verified yet (ADR-0028, issue #148). The release workflow signs this manifest keyless after generating it, when its run is on the release tag; the Sigstore bundle is the sibling asset wardos-1.2.3-manifest.json.sigstore.json, verified offline by scripts/release/verify-manifest.sh (docs/release-manifest.md). The tarballs are bound to this manifest by digest only."
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
([node-release-readiness.md](node-release-readiness.md) §2); `version` is that train's
version, which the name carries. `components` names both trains' versions once: the
top-level `version` is the release's (the runtime's, the image's and the tag's), and
`components["ward-node"].version` is the node train's own
([compatibility.md](compatibility.md) §6; issue #275), which may stay the same across
releases that change nothing the node is built from. `image/build.sh` reads the node
tarball a release carries from here.

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
checked. It then signs the manifest — keyless, with `cosign sign-blob --bundle` under
the run's own GitHub Actions OIDC identity (the job holds `id-token: write` for that
alone) — and attaches three more assets to the release, next to the tarballs:

| Asset | Carries |
| --- | --- |
| `wardos-<version>-manifest.json` | the manifest above |
| `wardos-<version>-manifest.json.sha256` | `sha256sum`'s line for it, like every tarball's sidecar |
| `wardos-<version>-manifest.json.sigstore.json` | the Sigstore bundle of the manifest's signature: the Fulcio certificate naming the signing workflow and ref, the signature, and the Rekor transparency-log entry, in the format `cosign verify-blob --bundle` reads offline |

The signature is made only when the run is on the release tag (`refs/tags/<tag>`),
because that ref is part of the identity the certificate carries and the only kind of
ref the pinned policy accepts (ADR-0028 §2; below). A `workflow_dispatch` run from a
branch — the run that creates the tag in CONTRIBUTING.md's release steps — publishes
the manifest unsigned and says so in its log; running `release.yml` again on the tag
(`gh workflow run release.yml --ref <tag> -f version=<tag>`) signs it and uploads the
bundle. Pushing the tag instead runs the workflow on it once, signing in the same run.
Before anything is published, the release job runs the verifier below on its own fresh
signature, so a policy that does not match what the workflow actually produces fails
the job on the runner rather than every user's check. Releases published before the
signing step existed (v0.4.1 and earlier) carry no bundle; the verifier reports
`provenance-missing` for them, and `install.sh` installs them checksum-only and says so
([install.md](install.md) §1).

`generated_at` of a published manifest is the source commit's committer time, not the
run's clock: a retry of the release workflow at the same commit must reproduce every
asset byte for byte (ADR-0028 §4), and the manifest is reconciled like the tarballs by
`download-published.sh` and `check-assets.sh` — identical is a no-op, different bytes
are refused before anything is overwritten. The bundle is the one asset that is never
byte-compared: a keyless signature differs on every run that signs (its own
certificate, Rekor entry and timestamp) even over identical manifest bytes. The rule
`check-assets.sh` applies, with its tests: a bundle this run produced is uploaded with
`--clobber` exactly when its manifest is already published byte-identical or not yet
published; a manifest whose bytes differ refuses the whole run, bundle included; and a
published bundle is left alone by a run that did not sign. A replaced bundle is a
second valid signature over the same bytes, nothing more.

## Verifying a release

Download the manifest, its sidecar and its bundle, and whichever tarballs you intend
to install, into one directory, and run the verifier from a checkout of the repository
at the release tag:

```
gh release download <tag> --pattern 'wardos-<version>-manifest.json*' --pattern '*-<arch>-linux.tar.gz*'
scripts/release/verify-manifest.sh wardos-<version>-manifest.json \
  wardos-<version>-manifest.json.sigstore.json --tag <tag>
```

The verifier needs `cosign` (v3, the version the workflow signs with), `jq` and
`sha256sum`, and no Rust toolchain. It checks, in this order and stopping at the first
failure: that those tools are present; that the manifest parses and names a `v<semver>`
release tag (the one `--tag` expects, and the one its own file name says); that the
bundle exists; that the signature verifies for the OIDC issuer
`https://token.actions.githubusercontent.com` and the exact identity
`https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/tags/<tag>`,
derived from the manifest's own `tag`; that the manifest's `.sha256`, when present
beside it, agrees; and that every artifact present beside the manifest hashes to the
digest the signed manifest records (and its own `.sha256`, when present, agrees). An
artifact the manifest names but that is not beside it is reported and skipped, unless
`--require-artifacts` makes its absence a failure. The identity is passed to cosign as
an exact string, never a pattern, so a certificate for another tag, a branch, a pull
request, another workflow or a literal `v*` cannot match the way a wildcard would — the
same reconstruction [`crates/ward-release-verify`](../crates/ward-release-verify)
performs for the update path, whose tests hold the script's three pinned literals equal
to the crate's constants. `--identity-policy repository=<owner/repo>` (also `issuer=`
and `workflow=`) exists for a fork verifying its own releases, not for making a WardOS
release pass; `--trusted-root <file>` hands cosign a Sigstore trusted root on a machine
that cannot refresh its TUF cache.

The last line is one of ADR-0028's states, and the exit code names the cause:

| Exit | Last line | Meaning |
| --- | --- | --- |
| 0 | `state=provenance-verified` | signed by the release workflow on this tag; every artifact present matches |
| 2 | `cause=usage`, `cause=malformed-manifest` | bad arguments, or a manifest that is unreadable, not JSON, or whose `tag` is not a release tag |
| 3 | `state=verifier-unavailable cause=cosign-missing` | `cosign` (or `jq`, `sha256sum`) is not installed; nothing was verified |
| 4 | `cause=provenance-missing` | the bundle is absent or not JSON |
| 5 | `cause=issuer-mismatch` | a valid signature whose certificate another OIDC issuer issued |
| 6 | `cause=identity-mismatch` | a valid signature by another repository, workflow, ref or tag |
| 7 | `cause=manifest-altered` | the bundle does not verify these manifest bytes under any identity |
| 8 | `cause=digest-mismatch` | the `.sha256` sidecar, or an artifact beside the manifest, disagrees with the signed manifest |
| 9 | `cause=incomplete-set` | `--require-artifacts` and a named artifact is absent |
| 10 | `cause=wrong-release` | the manifest names another release than `--tag`, or than its file name |
| 11 | `state=verifier-unavailable cause=trusted-root-unavailable` | cosign could not load the Sigstore trusted root (`cosign initialize`, or `--trusted-root`) |

A signature failure is classified by re-running cosign, not by reading its message: the
pinned check decides pass or fail, and on failure the bundle is re-checked against any
identity and any issuer — if that fails too, the signature does not cover these bytes
(7); if it passes, the bytes are intact and a third run with the pinned issuer alone
tells identity (6) from issuer (5). Every run is a bundle verification against cosign's
cached trusted root; nothing contacts Rekor or Fulcio.

Without the script, the same signature check is one command, and the three strings it
pins are the whole policy:

```
cosign verify-blob --bundle wardos-<version>-manifest.json.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity 'https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/tags/<tag>' \
  wardos-<version>-manifest.json
```

followed by the digest checks, which need no signature at all:

```
sha256sum -c wardos-<version>-manifest.json.sha256
jq -r '.artifacts[] | (.digest | sub("^sha256:"; "")) + "  " + .name' \
  wardos-<version>-manifest.json | sha256sum -c
```

`source_commit` must equal the commit the release's tag resolves to
(`git rev-parse <tag>^{commit}`). The verifier itself reaches you through the
repository — clone it at the tag, or read the one-command form above and type it; the
tarballs do not carry `scripts/`. `install.sh` does the same on your behalf: it fetches
`scripts/release/verify-manifest.sh` at the release tag (through the contents API when a
token is set), the channel the installer itself arrives through rather than the tarball
it is about to check, runs it with `--tag` beside the downloaded manifest, bundle and
tarball, keeps its cause and exit code on a refusal, and installs checksum-only, saying
so, when the verifier cannot run or the release has no bundle ([install.md](install.md)
§1; `--require-provenance` refuses instead). ADR-0028's "Trust roots and bootstrap"
keeps shipping the verifier and the Sigstore trusted root on the image, and a first-trust
step for the downloaded installer, as open work.

## What the signature proves, and what it does not

A pass proves that these manifest bytes were produced by `.github/workflows/release.yml`
of `hexrift/WardOS`, running on the `v*` tag the manifest names, with a certificate
Fulcio issued against GitHub Actions' OIDC token and an entry in Rekor — and that the
tarballs beside it are the bytes that workflow run hashed into the manifest. Each
tarball is bound to the signed manifest by its digest, and trusted exactly that far.

It does not prove that the tarballs were built reproducibly from `source_commit`, or
what the build's inputs were: that is the SLSA provenance attestation of ADR-0028
§1/§4, which the `provenance` object still reports as `unavailable` — `status`,
`attestation_ref` and `builder` are filled in only when a real attestation exists, and
since the manifest is signed after it is generated, nothing in it can reference its own
bundle. The tarballs and the OCI image are not signed individually (ADR-0028 §3 for
them is open), and the image is not covered by the manifest's signature at all. `install.sh`
runs the verifier and reports ADR-0028 §5's states up to `provenance-verified`
([install.md](install.md) §1); the image's release stage and `desktop/bin/wardos-update`
do not yet, so the image and update paths remain checksum-only until the rest of that
state machine is wired (issue #148), and a `provenance-verified` manifest says nothing
about the boot chain (ADR-0028 §6). The signing step runs for the first time on the
first `v*` tag released after it landed; until that release exists, no published
release is signed.
