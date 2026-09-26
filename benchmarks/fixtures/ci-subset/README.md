# `ci-subset` fixture

Pinned fixture for the CI-measurable subset of `ward benchmark` (issue #150).
A minimal `ward`-initialised project: offline network policy, no containers,
and a `.tamperward/config.yml` whose verify command is `true` — so the
`verifier_spawn` metric times sandbox start and candidate preparation for a
tiny tree, not a real build.

Used for: `sandbox_start`, `ward_status`, `verifier_spawn`.

Do not add real source files here beyond what's needed to keep the fixture a
valid, tiny project; the point is a small, deterministic, pinned tree so
numbers are comparable across runs and revisions.
