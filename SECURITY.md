# Security Policy

## Reporting a vulnerability

Report suspected sandbox escapes, verifier-independence failures, credential leaks,
evidence-integrity failures, and anything else that would weaken a guarantee in
[`docs/security-model.md`](docs/security-model.md) **privately**, through GitHub's
private vulnerability reporting on this repository (*Security → Report a vulnerability*).
Please do not open a public issue for an unfixed vulnerability.

The most useful reports include a reproducible hostile workload (a script the sandbox or
the verifier should have stopped, in the style of the `ward selftest` probes), the WardOS
version (`ward --version`, or the image digest from `bootc status`), and what you expected
the policy or verifier to do instead.

You will get an acknowledgement within a week. Fixes ship as a patch release with the
release notes naming the class of issue; credit is given unless you ask otherwise.

## Scope of claims

WardOS makes only the guarantees listed in `docs/security-model.md`, each backed by a
threat-model row and a security test. Explicit non-guarantees are listed there and are
reproduced in every release announcement. Design-level findings against the threat model
or the security model are welcome as ordinary issues.

## Supported versions

The latest release and `ghcr.io/hexrift/wardos:latest` receive fixes. Earlier releases
do not.

This file is human-review-only (see `docs/development-under-tamperward.md`).
