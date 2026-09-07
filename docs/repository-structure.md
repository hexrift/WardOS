# Repository Structure

Status: Phase 0 proposal. Directories are created when their first real content lands;
this document is the plan, not a promise of empty folders.

```text
wardos/
├── README.md
├── SECURITY.md                    # disclosure policy; human-review-only
├── .tamperward.yml                # guards the judge (tests, verify, CI, fixtures, hooks)
├── .github/
│   ├── CODEOWNERS                 # human-review-only surfaces
│   └── workflows/                 # protected: TamperWard gate, Security CI (QEMU), perf CI
│
├── docs/
│   ├── architecture.md
│   ├── threat-model.md            # human-review-only
│   ├── security-model.md          # human-review-only
│   ├── snapshots-and-git.md
│   ├── event-model.md
│   ├── credential-broker.md
│   ├── tamperward-integration.md
│   ├── development-under-tamperward.md
│   ├── design-language.md
│   ├── performance.md
│   ├── experiments.md
│   ├── roadmap.md
│   ├── repository-structure.md
│   └── decisions/                 # ADR-NNNN-*.md
│
├── crates/                        # Rust workspace (Phase 1+)
│   ├── ward-cli/                  # `ward` binary; thin client
│   ├── ward-daemon/               # `wardd`: sessions, sandbox builder, network, broker glue
│   ├── ward-agent/                # in-sandbox PID 1 shim, helpers, hook adapters
│   ├── ward-events/               # typed events, envelope, hash chain, wire format
│   ├── ward-observer/             # `ward watch` TUI, replay renderer, shared view models
│   ├── ward-policy/               # policy schema, three-layer merge, capability manifest   (CODEOWNERS)
│   ├── ward-credentials/          # broker, grants, backends, proxy injection rules        (CODEOWNERS)
│   ├── ward-verifier/             # verifier broker, manifest, runner protocol             (CODEOWNERS)
│   ├── ward-snapshot/             # CAS, manifest, capture (btrfs / frozen-copy), materialise
│   ├── ward-proxy/                # egress proxy: allowlist, private-range deny, injection
│   ├── ward-sandbox/              # OCI spec generation, crun driver, cgroup/netns plumbing
│   └── ward-bench/                # `ward benchmark`
│
├── desktop/                       # Ward Shell (Rust, layer-shell), Hyprland config, themes
│   ├── shell/
│   ├── hyprland/
│   └── themes/                    # ward-dark, ward-light, ward-graphite, ward-high-contrast
│
├── image/                         # bootc Containerfile, build manifests
│   ├── Containerfile
│   ├── boot/                      # UKI/systemd-boot config                                (CODEOWNERS via secure-boot/)
│   ├── secure-boot/               #                                                         (CODEOWNERS)
│   └── keys/                      # public keys only; private material never in repo       (CODEOWNERS)
│
├── installer/
│   ├── crypto/                    # LUKS/TPM enrolment                                      (CODEOWNERS)
│   ├── security/
│   ├── dag/                       # Phase 8 scheduler
│   └── tests/                     # protected
│
├── runtime/                       # portable runtime: compose files, images for non-WardOS hosts
│   └── tests/                     # protected
│
├── integration/
│   └── tamperward/                # Zone 1 adapter, socket protocol, demo wiring
│       └── tests/                 # protected
│
├── security-tests/                # protected: hostile workloads ST-001..025, RT-*, golden/
│   ├── workloads/
│   ├── golden/
│   ├── fixtures/expected/
│   └── README.md                  # dogfooding findings
│
├── benchmarks/                    # ward-bench suites, reference records, CI thresholds
├── hardware/                      # reference matrix, per-device reports
├── experiments/                   # throwaway spikes E-01..E-12, each with RESULT.md
├── scripts/
│   ├── verify/                    # protected: tamperward.sh and delegates
│   └── security-check/            # protected: static.sh, tamperward-integration.sh
└── examples/
    └── ward-demo/                 # launch demo: failing tests + tempting shortcut
```

## Deviations from the brief and why

| Change | Reason |
| --- | --- |
| Added `crates/ward-proxy`, `crates/ward-sandbox`, `crates/ward-bench` | Egress proxy and sandbox construction are security-critical and benefit from crate boundaries and separate fuzzing; benchmarking needs a binary |
| Added `experiments/` | Spike code must never be mistaken for production code or protected surfaces |
| Added `scripts/verify`, `scripts/security-check`, `.tamperward.yml`, `CODEOWNERS` | Required by the development-under-TamperWard model |
| Added `docs/decisions/` and several topic docs | The brief asks for decision records with a fixed template; splitting by topic keeps each reviewable |

## Workspace conventions (from Phase 1)

* One Cargo workspace; `rust-toolchain.toml` pinned (protected).
* `#![forbid(unsafe_code)]` by default; crates needing `unsafe` (`ward-sandbox`,
  `ward-agent`, eBPF loader) document every block in `UNSAFE.md`.
* `clippy -D warnings`, `cargo deny` (licenses, advisories), `cargo fmt --check` in the
  protected verify script.
* Integration and security tests never run against the developer's real home: they run
  in a throwaway user or a VM.
