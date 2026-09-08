//! `ward-proxy` — the session egress proxy, the only way out of a `WardOS`
//! sandbox (architecture §7, ADR-0006, threat-model rows 10 and 21, objective O3).
//!
//! nftables makes this proxy the sole egress path; this crate decides *what*
//! may pass. It speaks two proxy forms — `CONNECT host:port` (an opaque tunnel,
//! TLS is never intercepted) and absolute-URI plain-HTTP forwarding — and applies
//! a [`NetworkCapability`] on top of structural
//! denies that no mode can lift:
//!
//! * private (RFC 1918, CGNAT), loopback (unless `LocalhostOnly`), link-local,
//!   unique-local, multicast, reserved and cloud-metadata destinations are
//!   refused — see [`addr`];
//! * raw IP literals are refused unless the mode is `Unrestricted` and the
//!   address is public (or loopback under `LocalhostOnly`);
//! * every address a name resolves to is checked, and the connection is made
//!   only to an address that was checked (**pinning**), so a DNS answer that
//!   later flips to a private address gains nothing — see [`policy`].
//!
//! Every decision is reported through an [`Observer`] so `wardd` can record
//! `NetworkRequested` / `NetworkDenied` events. Denials answer `403` with a
//! fixed body that never reveals the allowlist.
//!
//! **Gateway routes** ([`GatewayRoute`], ADR-0008 delivery A) let the sandbox
//! call its model API through `http://127.0.0.1:3128/anthropic` with a
//! placeholder token: the proxy rewrites the request to the real HTTPS
//! upstream (policy-checked and pinned like any other destination) and
//! injects the real credential, a [`Secret`] that is unprintable by type. A
//! route's [`scope`](GatewayRoute::scope) (path prefixes, read or write) is
//! where a `CredentialScope` is enforced: an out-of-scope request is `403`
//! before any upstream connection.
//!
//! # Layout
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`addr`] | Structural address classification (`classify`, `AddrClass`) |
//! | [`hosts`] | Built-in allowlists and case-insensitive / wildcard host matching |
//! | [`policy`] | `Policy`: mode + structural denies, two-stage evaluation, pinning |
//! | [`resolve`] | `Resolver` trait, `SystemResolver`, `StaticResolver` |
//! | [`http`] | Bounded, strict request parsing; origin-form rewrite; body framing |
//! | [`secret`] | `Secret`: no `Display`, redacted `Debug`, zeroed on drop |
//! | [`gateway`] | `GatewayRoute`: prefix match, credential scope, rewrite + injection, TLS upstream |
//! | [`observer`] | `Observer`, `Decision`, `NullObserver` |
//! | [`proxy`] | `Config`, `Proxy::spawn`, `Handle`, the thread-per-connection relay |
//!
//! The crate uses only the standard library's blocking I/O: one thread per
//! connection, bounded by `Config::max_connections`. TLS for gateway
//! upstreams is `rustls` with the `ring` backend and the host trust store.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::module_name_repetitions
)]

pub mod addr;
pub mod error;
pub mod gateway;
pub mod hosts;
pub mod http;
pub mod observer;
pub mod policy;
pub mod proxy;
pub mod resolve;
pub mod secret;

pub use addr::AddrClass;
pub use error::Error;
pub use gateway::{GatewayRoute, ScopeDenial};
pub use http::{Header, Host, Method, ParseError, Parsed, Request, Target};
pub use observer::{Decision, NullObserver, Observer};
pub use policy::{Denial, Pinned, Policy};
pub use proxy::{Config, Handle, PAUSED_BODY, Proxy};
pub use resolve::{Resolver, StaticResolver, SystemResolver};
pub use secret::Secret;
pub use ward_policy::NetworkCapability;
