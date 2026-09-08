# Architecture Decision Records

Every major decision uses the same template:

```text
Decision · Alternatives · Advantages · Disadvantages · Security consequences ·
Performance consequences · Why selected · How it will be validated
```

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](ADR-0001-base-os.md) | Base OS: Fedora-derived bootc image | Accepted, pending E-09 |
| [0002](ADR-0002-sandbox-runtime.md) | Agent sandbox: rootless OCI container via crun from a `wardd`-generated spec | Accepted, pending E-01/E-06 |
| [0003](ADR-0003-inner-hardening.md) | Inner hardening: Landlock + final seccomp applied by `ward-agent` | Accepted |
| [0004](ADR-0004-verifier-isolation.md) | Verifier: disposable Zone 2 environment, namespaces now, microVM evaluated | Accepted, pending E-03 |
| [0005](ADR-0005-nested-containers.md) | Project containers: nested rootless Podman inside the sandbox | Proposed, pending E-04 |
| [0006](ADR-0006-network.md) | Network: per-session netns, nftables fail-closed, `ward-proxy` egress | Accepted |
| [0007](ADR-0007-desktop-and-shell.md) | Desktop: Hyprland; Ward Shell in Rust with a layer-shell toolkit chosen by E-10 | Accepted (compositor), Proposed (toolkit) |
| [0008](ADR-0008-credential-broker.md) | Credentials: broker with proxy injection first, minted tokens second | Accepted, pending E-07 |
| [0009](ADR-0009-language-and-process-model.md) | Rust for all WardOS-owned services; single `wardd` process in 0.1 | Accepted |
| [0010](ADR-0010-snapshots-and-git.md) | Frozen state: content-addressed Ward Snapshots independent of `.git` | Accepted, pending E-02 |
| [0011](ADR-0011-event-capture.md) | Event capture: eBPF exec + fanotify + proxy log; hooks are claims | Accepted, pending E-05 |
| [0012](ADR-0012-observer.md) | Observer: TUI first, shared event API, Ward Shell panel later | Accepted |
| [0013](ADR-0013-phase1-runtime.md) | Phase 1 runtime: in-process session, bubblewrap backend, bridged ids | Accepted |
