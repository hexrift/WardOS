# `benchmarks/`

Pinned fixtures for `ward benchmark` (`crate ward-bench`, issue #150,
`docs/performance.md` §5). Run from the repository root:

```sh
cargo build --release -p ward-cli
./target/release/ward benchmark --json report.json
```

`--samples`/`--warm-up` default to `docs/performance.md` §3's own methodology
(20 timed runs after 3 discarded warm-ups). `--fixtures <dir>` points at a
fixtures root other than `benchmarks/fixtures` when needed (rarely).

To compare two revisions: build and run `ward benchmark --json` at each
revision (same fixtures, same host) and diff the two JSON files' `metrics[]`
by `id`. Each report's own `environment` block records what it ran on
(`wardos_version`, `git_commit`, kernel, CPU count, CI or not) — treat two
reports from different `environment`s as not directly comparable.

## Fixtures

* `fixtures/ci-subset/` — a minimal `ward`-initialised project (offline
  network, no containers, a no-op `.tamperward/config.yml` verify command).
  Used for `sandbox_start`, `ward_status` and `verifier_spawn`.
* `fixtures/snapshot-digest/` — a pinned, deterministic ~220-file tree
  (`tree/`, `generate.py` regenerates it). Used for `snapshot_digest_*` and
  `snapshot_capture_*`.

Fixtures are checked into git so numbers stay comparable across machines and
over time (`docs/performance.md` §3: "fixed image digest"). Do not regenerate
`snapshot-digest/tree/` casually — a changed fixture makes historical numbers
incomparable; if it ever needs to change, say so in the commit that does it.

## Scope

This is the CI-measurable subset only: no reference hardware, no real
compositor/desktop session. See `docs/performance.md` §5 for exactly which
`docs/performance.md` §2 budgets this covers and which remain
`not_implemented` (compositor-dependent: #84; hardware-dependent: #99).
No pass/fail regression gate — measure and publish first (#150).
