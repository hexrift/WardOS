# ADR-0006 — Network: per-session netns, nftables fail-closed, `ward-proxy` egress

## Decision
Each session gets a network namespace connected by a veth pair to a `wardd`-managed
bridge. nftables on the host side drops everything from the session except traffic to
`ward-proxy` and `ward-dns`. `ward-proxy` (Rust, part of `wardd`) implements the
allowlist by hostname/SNI, denies private, link-local, ULA and metadata ranges after
resolution, pins resolved addresses per connection, injects credentials for granted
tuples, and emits one event per connection. Modes: `offline`, `localhost-only`,
`package-registries`, `development`, `custom`, `unrestricted` (explicit approval, shown
as `NET OPEN`).

## Alternatives
- pasta/slirp4netns user-mode networking with its own filtering.
- No netns; host network with per-uid nftables rules.
- Transparent TLS-interception proxy for all traffic.
- eBPF-based egress filtering on the cgroup (`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`).

## Advantages
- Fail-closed in the kernel: if the proxy is down, nothing leaves.
- Hostname-level policy is what users understand (`github.com`), not IP lists.
- Proxy is the natural place for credential injection and per-request evidence.

## Disadvantages
- Tools must honour proxy environment variables or the sandbox must transparently
  redirect port 443/80 to the proxy (nftables `dnat` in the netns); both are provided,
  with transparent redirect as the default so non-proxy-aware tools still work.
- SNI-based allowlisting is defeated by ECH; when ECH is present the proxy requires
  explicit CONNECT with a hostname.

## Security consequences
- Private-network pivoting blocked at two layers. DNS rebinding blocked by pinning.
- TLS is not intercepted for allowlisted hosts (end-to-end); it is terminated by the proxy
  only for injected hosts, using the system trust store, and this is shown in the bar.

## Performance consequences
- One extra hop on localhost; negligible for developer traffic. Connection setup adds
  < 1 ms.

## Why selected
cgroup-eBPF filtering is attractive (no proxy hop) and may be added for IP-level
enforcement, but hostname policy and credential injection need a proxy anyway. User-mode
networking (pasta) is slower and puts policy in a less auditable place.

## How it will be validated
ST-011 (private-network bypass suite incl. IPv6, rebinding, IP literals, CONNECT abuse),
ST-022, E-08 (agent compatibility).
