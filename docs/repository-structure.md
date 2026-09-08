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

## As built (Phase 1–3)

The workspace today has eight crates; the planned `ward-observer`, `ward-credentials`,
`ward-verifier` and `ward-bench` crates have not been split out yet because their
current code is small enough to live where it is used. Where each planned
responsibility lives now:

| Crate | Modules | Planned home |
| --- | --- | --- |
| `ward-events` | `event`, `ids`, `text`, `origin`, `chain`, `wire`, `log` | as planned |
| `ward-policy` | `policy`, `capability`, `merge`, `default`, `ids` | as planned (CODEOWNERS) |
| `ward-snapshot` | `cas`, `manifest`, `capture`, `materialize`, `meta`, `ignore`, `backend` | as planned |
| `ward-sandbox` | OCI spec generation and the typed seccomp profile | as planned |
| `ward-proxy` | `proxy`, `policy`, `addr`, `hosts`, `http`, `resolve`, `gateway`, `secret`, `observer` | as planned; `gateway` is the credential injection of `ward-credentials` |
| `ward-agent` | `cli`, `landlock`, `seccomp`, `privs`, `supervise`, `relay`, `hook` | as planned; `hook` is the hook adapter |
| `ward-daemon` | `session`, `control`, `daemon`, `sandbox`, `egress`, `gateway`, `hooks`, `verify`, `selftest`, `watch`, `agents`, `render`, `describe`, `snapshot`, `ids` | `gateway` → `ward-credentials`; `verify` → `ward-verifier`; `render` → `ward-observer` |
| `ward-cli` | `main`, `replay` | as planned; `replay` → `ward-observer` |

`wardd` is a per-session daemon (ADR-0015): `ward up` spawns `wardd serve`, which owns
the session log and serves `sessions/<id>/control.sock` (`control` is the protocol and
the two sinks, `daemon` the server); `ward stop` ends it. Sandboxes, proxies and hook
listeners still run in the `ward` process (ADR-0013), with the per-launch sockets
(`proxy.sock`, `hooks.sock`) living in a short-lived run directory, and every command
falls back to writing the log in-process when no daemon answers. The system-service
`wardd` of ADR-0009 (one supervisor for all sessions, its own uid) is still ahead.
`unsafe_code` is forbidden workspace-wide; no crate has needed an exception so far, so
there is no `UNSAFE.md` yet.

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
