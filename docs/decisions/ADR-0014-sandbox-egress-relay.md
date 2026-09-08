# ADR-0014 — Sandbox egress: proxy over a bind-mounted Unix socket with an in-sandbox relay

## Decision
In the Phase 1/2 (bubblewrap) runtime, the session's `ward-proxy` listens on a
**Unix-domain socket** owned by the supervisor. That socket file is bind-mounted into
the sandbox, whose network namespace is otherwise fully isolated (`--unshare-net`,
loopback only). Inside the sandbox, `ward-agent` runs a tiny **relay** that listens on
the sandbox's own loopback (`127.0.0.1:3128`) and forwards each connection to the
bind-mounted socket. The agent is configured with `HTTP_PROXY`/`HTTPS_PROXY` pointing at
that loopback port. Policy, allowlisting, DNS pinning and the observer all stay in the
proxy on the host side.

## Alternatives
1. Do not unshare the network; rely on proxy environment variables only.
2. Privileged netns plumbing now: veth pair + nftables redirect to the host proxy
   (ADR-0006's production design).
3. Run the proxy *inside* the sandbox namespace.
4. Unix socket + in-sandbox relay (selected).

## Advantages
- Enforcement by construction: with the netns unshared, the bind-mounted socket is the
  *only* path out; a process that ignores `HTTPS_PROXY` simply has no route. No
  nftables or root privileges are required, so it runs in nested and CI environments.
- The proxy keeps host-side DNS and the pinned-connect path; nothing policy-relevant
  runs in Zone 3.
- This is the mechanism Claude Code's own Linux sandbox uses (bubblewrap plus a socat
  relay), so agent compatibility is known-good.

## Disadvantages
- Only proxy-aware protocols work (HTTP CONNECT/forward). Raw TCP/UDP from the sandbox
  is impossible by design; tools that need them wait for ADR-0006's veth path.
- One extra hop and one relay thread per connection inside the sandbox.
- The relay runs in Zone 3 and is therefore untrusted: it can only *reach* the socket,
  it cannot widen what the proxy allows.

## Security consequences
- Guarantee G3 holds without root: the socket is the sole egress and every request is
  policy-checked on the host side; private ranges and rebinding are denied there.
- The socket is mode 0600 to the supervisor's uid mapping so other host processes
  cannot use the session's egress.
- A compromised sandbox can open the socket at will; it gains nothing beyond the
  session's allowlist, and every attempt is a `NetworkRequested`/`NetworkDenied`
  record.

## Performance consequences
- Loopback relay plus Unix socket adds well under a millisecond per connection; no
  effect on the warm-start budget.

## Why selected
Option 1 is not enforcement. Option 2 needs `CAP_NET_ADMIN` and cannot run in the
nested/CI environments the prototype must run in; it remains the production-host path
of ADR-0006 and nothing here conflicts with it. Option 3 would put DNS resolution and
the policy engine inside the untrusted namespace. Option 4 keeps enforcement and
policy on the host with no privilege, at the cost of proxy-only egress, which is what
coding agents need.

## How it will be validated
- `ward-proxy` Unix-listener integration test (CONNECT through the socket to a loopback
  echo server).
- `ward-agent` relay test: a sandboxed client reaches an allowlisted host only via
  the relay; a direct connect fails with no route (ST-011 extended).
- `ward claude` end-to-end: the only successful egress in the session log is to the
  allowlisted API hosts (Phase 2 gate in `docs/agent-integration.md`).
