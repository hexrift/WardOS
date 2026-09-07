# Security Policy

WardOS is in Phase 0 (architecture). There is no software to report vulnerabilities
against yet. Design-level findings against the threat model or security model are welcome
as issues or private reports to the maintainers of `hexrift/WardOS`.

## Scope of claims

WardOS makes only the guarantees listed in `docs/security-model.md`, each backed by a
threat-model row and a security test. Explicit non-guarantees are listed there and must
be reproduced in any release announcement.

## Disclosure

From Phase 1, report suspected sandbox escapes, verifier-independence failures,
credential leaks, or evidence-integrity failures privately to the maintainers before
public disclosure. Reports that include a reproducible hostile workload in the format of
`security-tests/workloads/` are the most useful.

This file is human-review-only (see `docs/development-under-tamperward.md`).
