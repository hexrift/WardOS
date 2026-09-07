# ADR-0005 — Project containers: nested rootless Podman inside the sandbox

## Decision (proposed, pending E-04)
Agents run project containers (compose stacks, build containers) with **rootless Podman
inside the agent sandbox**, using nested user namespaces, native overlayfs in userns,
and the sandbox's existing network namespace. The host container engine socket is never
exposed. `docker` and `docker compose` commands are provided by podman's compatibility
layer.

## Alternatives
- Mount the host Docker/Podman socket (rejected outright).
- A `ward` container broker exposing a restricted create/run/logs API.
- Docker-in-Docker style privileged nesting (rejected).
- Run project services as sandbox-native processes only (no containers).

## Advantages
- Zero new privileged API surface; escapes from a nested container land inside the
  outer sandbox.
- Existing developer workflows (`docker compose up`) work unchanged.

## Disadvantages
- Nested userns depth 2, overlayfs-in-userns and `/dev/fuse` availability all vary by
  kernel; image storage inside `/env` costs disk.
- Some stacks need `CAP_NET_BIND_SERVICE` or specific sysctls; handled by policy
  (`ask`).

## Security consequences
- Strong: outer boundary unchanged. Nested runtime bugs are contained.
- Image pulls go through `ward-proxy` and are logged.

## Performance consequences
- Nested overlay is slightly slower than host overlay; image layers cached in `/env`
  persist across sessions.

## Why selected (provisionally)
A broker is a large, security-sensitive component whose API would need to grow to cover
compose semantics. Nesting reuses existing primitives (principle 9). If E-04 shows it
unworkable for common stacks, the broker is designed in Phase 2.

## How it will be validated
E-04 with three real compose stacks; ST-004/013/014 executed from inside a nested
container.
