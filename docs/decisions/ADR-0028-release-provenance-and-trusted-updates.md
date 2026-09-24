# ADR-0028 — Release provenance and trusted update verification

Status: Proposed — implementation begins in [#148](https://github.com/hexrift/WardOS/issues/148)

## Context

WardOS currently publishes release artifacts with SHA-256 checksums. A checksum
proves that the downloaded bytes match the bytes named by the release, but it does
not by itself prove which workflow produced them, which source revision was built,
or whether the artifact is appropriate for the requested architecture. The current
install path therefore remains explicitly unsigned.

Phase 7 also needs a trust story for image and update artifacts. That story must
cover the release tarball, disk/image outputs, and OCI image digests without
silently conflating artifact provenance with the separate Secure Boot / UKI chain.

## Decision

WardOS will use workflow-bound, keyless provenance as the primary release trust
mechanism, with a portable Sigstore bundle for artifacts that must be verified
outside the GitHub release UI or API.

1. The release workflow will generate a provenance attestation for every
   published artifact and OCI digest. The attestation is bound to the immutable
   source commit, release tag, repository, workflow identity, target architecture,
   and artifact digest.
2. The release trust policy will pin the expected repository and release workflow.
   Verification must reject a valid signature from an unexpected repository,
   workflow, ref, or artifact identity; “any valid signature” is not an acceptable
   policy.
3. A detached artifact will carry or reference a Sigstore bundle when the GitHub
   attestation cannot be retrieved during verification. The bundle is a transport
   format for the same identity policy, not a second unscoped trust root.
4. Each release will publish a machine-readable manifest containing at least:
   source commit, immutable tag, artifact name and digest, target architecture,
   image/bootc reference where applicable, builder/toolchain metadata, provenance
   reference, and compatibility/rollback metadata.
5. The update state machine will expose these distinct results:
   `downloaded` → `digest-checked` → `provenance-verified` → `staged` → `booted`.
   A failed or missing provenance check is a visible verification failure and
   blocks staging; it must never be reported as “no update”.
6. Artifact provenance is separate from Secure Boot. A verified release artifact
   does not claim that its UKI, bootloader, TPM policy, or platform key chain is
   verified. Those controls remain part of the Phase 7 boot-chain work.
7. The first implementation will not place a long-lived private signing key in
   this repository or on a developer workstation. Keyless workflow identity and
   transparency evidence are preferred; emergency recovery and policy rotation
   must be documented before they are automated.

## Verification contract

The verifier must check, in order:

1. the complete artifact set and expected architecture;
2. the cryptographic digest of every artifact;
3. the provenance signature/bundle and transparency evidence;
4. the repository, workflow, source commit, release ref, artifact name, and
   digest against the WardOS trust policy;
5. compatibility and rollback metadata before staging.

The verifier must make the reason for rejection actionable. In particular,
missing provenance, an identity mismatch, an expired/invalid bundle, a digest
mismatch, and an unsupported architecture are separate failure causes.

## Acceptance cases

The implementation is complete only when automated tests cover at least:

| Case | Expected result |
| --- | --- |
| Untouched release with matching policy | Provenance verified; staging allowed |
| One byte changed after download | Digest failure; staging blocked |
| Valid signature from another repository/workflow | Identity failure; staging blocked |
| Valid artifact for another architecture | Compatibility failure; staging blocked |
| Missing or incomplete artifact set | Completeness failure; staging blocked |
| Missing bundle/attestation | Provenance failure; staging blocked |
| Offline verification with a cached valid bundle | Provenance verified if policy and evidence are valid |
| Failed boot after a verified update | Existing rollback path remains visible and usable |

## Scope of the implementation

This ADR is the design slice for #148. Follow-up changes should be split so that
the release workflow, manifest format, installer/update verifier, and boot-chain
integration can each be tested independently. The first code PR must not claim
that existing releases are signed until the release workflow has emitted and the
installer has verified the new evidence.

## Alternatives considered

### A project-held signing key

This gives a familiar offline signature but creates a high-value long-lived secret,
requires rotation and secure release-hosting procedures, and does not inherently
prove which workflow built an artifact. It may be revisited for an offline or
air-gapped distribution channel, but is not the default.

### Checksums only

Checksums remain useful for byte-integrity checks and are retained, but they do not
provide publisher or workflow identity and are insufficient for trusted updates.

### Secure Boot as the only release proof

Secure Boot can establish a platform boot chain, but it does not replace release
provenance for tarballs, OCI images, or artifacts consumed before boot. The two
chains must be verified separately and reported separately.

## Consequences

This adds release metadata and a policy-verification dependency to the install and
update paths. It also makes failed verification more visible and may reject an
artifact that previously installed with only a checksum. In return, a user can
distinguish byte integrity, publisher/workflow identity, update compatibility, and
boot health instead of receiving one ambiguous “verified” result.

## Validation

The release workflow should test the manifest and attestation against a fixture
release, while installer/update tests should exercise the acceptance cases above
with valid, altered, mismatched, missing, and offline evidence. Documentation must
continue to say that current releases are checksum-only until those tests pass in
the published workflow.
