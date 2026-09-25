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
   policy. Concretely, for GitHub Actions keyless signing the policy pins the OIDC
   issuer `https://token.actions.githubusercontent.com`, the signing identity (SAN)
   `https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/tags/v*`,
   and a source ref that is a `v*` release tag — never a branch, a pull request, or
   a workflow other than `release.yml`. These exact claims are what an “identity
   mismatch” rejection is tested against.
3. A detached artifact will carry or reference a Sigstore bundle when the GitHub
   attestation cannot be retrieved during verification. The bundle is a transport
   format for the same identity policy, not a second unscoped trust root.
4. Each release will publish a machine-readable manifest containing at least:
   source commit, immutable tag, artifact name and digest, target architecture,
   image/bootc reference where applicable, builder/toolchain metadata, provenance
   reference, and compatibility/rollback metadata. The builder/toolchain metadata
   is the SLSA provenance predicate itself (or fields derived from it), not a
   hand-written copy that could disagree with the attestation. The published
   assets a manifest names are immutable once released: a re-run of the release
   workflow at the same tag must reproduce byte-identical assets and refuse to
   overwrite differing bytes (the release workflow already enforces this today
   via `scripts/release/download-published.sh` + `check-assets.sh`), so the
   manifest and its attestation cannot be silently repointed at new bytes under a
   published tag.
5. The update state machine will expose these distinct results:
   `downloaded` → `digest-checked` → `provenance-verified` → `staged` → `booted`
   → `health-checked` → `committed`, with `rolled-back` as the terminal state of a
   boot that failed its health check. A failed or missing provenance check is a
   visible verification failure and blocks staging; it must never be reported as
   “no update”. Verification also enforces an anti-rollback floor: an update whose
   version is lower than the currently committed one is refused even when its
   signature and identity are valid, unless the user explicitly overrides it — a
   validly signed older release still carries whatever was fixed since.
6. Artifact provenance is separate from Secure Boot. A verified release artifact
   does not claim that its UKI, bootloader, TPM policy, or platform key chain is
   verified. Those controls remain part of the Phase 7 boot-chain work. For the
   OCI image and `bootc` update path specifically, verification uses the image's
   own `/etc/containers/policy.json` sigstore policy (the mechanism already
   sketched in [`image/keys/README.md`](../../image/keys/README.md) and
   [`image/boot/README.md`](../../image/boot/README.md)) rather than a second,
   parallel verifier, and it binds to the resolved image digest, never to a
   mutable tag such as `:latest` — the two must not describe different trust
   policies that can drift apart.
7. The first implementation will not place a long-lived private signing key in
   this repository or on a developer workstation. Keyless workflow identity and
   transparency evidence are preferred; emergency recovery and policy rotation
   must be documented before they are automated.

**Implementation note (§2, §5):** the pinned identity-policy matching described in
point 2 above, and the anti-rollback floor described in point 5 and in the
verification contract's step 5 below, are implemented as pure, offline,
unit-tested decision logic in [`crates/ward-release-verify`](../../crates/ward-release-verify)
(issue #148). That crate decides whether already-extracted, already-cryptographically-verified
claims satisfy this policy, and separately whether a candidate version must be
refused as a downgrade; it does not retrieve or cryptographically verify a real
attestation, call Sigstore/cosign/Fulcio/Rekor, make any network/OIDC call, or wire
either decision into `.github/workflows/release.yml`, `install.sh`, or
`desktop/bin/wardos-update`. Point 4's manifest format is implemented separately by
`scripts/release/generate-manifest.sh`. This ADR's own status stays Proposed until
enough of the verification contract below is real, wired together, and tested
end-to-end.

## Verification contract

The verifier must check, in order:

1. the complete artifact set and expected architecture;
2. the cryptographic digest of every artifact;
3. the provenance signature/bundle and transparency evidence;
4. the repository, workflow, source commit, release ref, artifact name, and
   digest against the WardOS trust policy — for the OCI path, that the attested
   digest is the one the tag resolved to, not the tag string;
5. the anti-rollback floor (§5): the candidate version is not lower than the
   committed one, absent an explicit override;
6. compatibility and rollback metadata before staging.

The verifier must make the reason for rejection actionable. In particular,
missing provenance, an identity mismatch, an expired/invalid bundle, a digest
mismatch, an unsupported architecture, and a refused downgrade are separate
failure causes.

### Trust roots and bootstrap

Two roots must exist before any of the checks above can run, and the ADR treats
their distribution as part of the design, not an implementation detail:

- **The Sigstore trusted root** (the Fulcio and Rekor keys) is what makes an
  offline check meaningful. It ships on the image, is refreshed through
  Sigstore's own TUF-based update mechanism, and a stale or missing root is its
  own distinct, actionable failure — never a silent pass. Offline verification
  succeeds only against a cached bundle *and* a still-valid trusted root.
- **The verifier and its policy themselves** reach the user before any release
  can be checked: they ship on the image, and for the tarball install path
  (`install.sh`, itself downloaded) the guide documents a first-trust step
  (`gh attestation verify`, or the shipped verifier) rather than assuming the
  downloaded script can vouch for itself.

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
| Validly signed release older than the committed one | Downgrade refused; staging blocked absent explicit override |
| OCI tag repointed to a different (unattested) digest | Identity/digest failure; staging blocked |
| Offline verification with a cached valid bundle | Provenance verified if policy and evidence are valid |
| Offline verification with a stale/absent Sigstore trusted root | Distinct trusted-root failure; not a silent pass |
| Failed boot after a verified update | Health check fails; state reaches `rolled-back`, existing rollback path visible and usable |

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
