//! Egress policy: a [`NetworkCapability`] plus the structural deny ranges.
//!
//! Evaluation has two stages. [`Policy::check_host`] runs before resolution
//! and decides whether the *name* may be looked up at all; [`Policy::check_addr`]
//! runs on **every** resolved address. [`Policy::evaluate`] ties them together
//! and returns the pinned address set the caller must connect to — the proxy
//! never resolves a name a second time on the connect path, which is what
//! defeats DNS rebinding.

use std::fmt;
use std::net::IpAddr;

use ward_policy::NetworkCapability;

use crate::addr::{self, AddrClass};
use crate::hosts;
use crate::http::{Host, Target};
use crate::resolve::Resolver;

/// Why a destination was refused. Deliberately free of allowlist contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Denial {
    /// The session is offline.
    Offline,
    /// The host is not on this session's allowlist.
    NotAllowlisted,
    /// IP literals are only accepted in `Unrestricted` (public) or for loopback.
    IpLiteral,
    /// A resolved (or literal) address falls in a structural deny range.
    Address(AddrClass),
    /// `LocalhostOnly` and the destination is not loopback.
    NotLoopback,
    /// The name did not resolve to any address.
    Unresolvable,
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offline => f.write_str("session network mode is offline"),
            Self::NotAllowlisted => f.write_str("host is not on the session allowlist"),
            Self::IpLiteral => f.write_str("IP literal destinations are not permitted"),
            Self::Address(class) => write!(f, "destination is a {}", class.label()),
            Self::NotLoopback => f.write_str("only loopback destinations are permitted"),
            Self::Unresolvable => f.write_str("host did not resolve"),
        }
    }
}

/// A resolved and fully checked destination, ready to connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    /// Every address, all of which passed [`Policy::check_addr`].
    pub addrs: Vec<IpAddr>,
    /// Destination port.
    pub port: u16,
}

/// The session's egress policy.
#[derive(Debug, Clone)]
pub struct Policy {
    capability: NetworkCapability,
    allow_loopback: bool,
}

impl Policy {
    /// Policy for `capability` with the structural denies applied.
    pub fn new(capability: NetworkCapability) -> Self {
        Self {
            capability,
            allow_loopback: false,
        }
    }

    /// Permit loopback destinations regardless of mode. Test builds only.
    #[cfg(feature = "test-loopback")]
    #[must_use]
    pub fn allow_loopback(mut self, allow: bool) -> Self {
        self.allow_loopback = allow;
        self
    }

    /// The capability this policy enforces.
    pub fn capability(&self) -> &NetworkCapability {
        &self.capability
    }

    /// Does the mode permit loopback destinations?
    pub fn permits_loopback(&self) -> bool {
        self.allow_loopback || matches!(self.capability, NetworkCapability::LocalhostOnly)
    }

    /// Stage one: may this host be resolved and attempted at all?
    pub fn check_host(&self, target: &Target) -> Result<(), Denial> {
        use NetworkCapability as N;
        match (&self.capability, &target.host) {
            (N::Offline, _) => Err(Denial::Offline),
            (_, Host::Ip(ip)) if ip.is_loopback() && self.permits_loopback() => Ok(()),
            // Unrestricted defers entirely to the address stage.
            (N::Unrestricted, _) => Ok(()),
            (_, Host::Ip(_)) => Err(Denial::IpLiteral),
            (N::LocalhostOnly, Host::Name(n)) => {
                allow_if(hosts::is_localhost_name(n), Denial::NotAllowlisted)
            }
            (N::Registries, Host::Name(n)) => allow_if(
                hosts::any_matches(hosts::REGISTRY_HOSTS.iter().copied(), n),
                Denial::NotAllowlisted,
            ),
            (N::Development, Host::Name(n)) => {
                let all = hosts::REGISTRY_HOSTS
                    .iter()
                    .chain(hosts::DEVELOPMENT_HOSTS)
                    .copied();
                allow_if(hosts::any_matches(all, n), Denial::NotAllowlisted)
            }
            (N::Custom(set), Host::Name(n)) => allow_if(
                hosts::any_matches(set.iter().map(String::as_str), n),
                Denial::NotAllowlisted,
            ),
        }
    }

    /// Stage two: may this concrete address be connected to?
    pub fn check_addr(&self, ip: IpAddr) -> Result<(), Denial> {
        match addr::classify(ip) {
            Some(AddrClass::Loopback) if self.permits_loopback() => Ok(()),
            Some(class) => Err(Denial::Address(class)),
            None if matches!(self.capability, NetworkCapability::LocalhostOnly) => {
                Err(Denial::NotLoopback)
            }
            None => Ok(()),
        }
    }

    /// Full evaluation: host check, resolution, then a check of every address.
    ///
    /// Any single bad address denies the whole request, so a rebinding answer
    /// of `[public, private]` is refused rather than "just using the public one".
    pub fn evaluate(&self, resolver: &dyn Resolver, target: &Target) -> Result<Pinned, Denial> {
        self.check_host(target)?;
        let pinned = Self::pin(resolver, target)?;
        for ip in &pinned.addrs {
            self.check_addr(*ip)?;
        }
        Ok(pinned)
    }

    /// Evaluation for a gateway upstream: the host, not the sandbox, chose the
    /// destination when it configured the route, so the allowlist and address
    /// classes do not apply. `offline` still means offline.
    pub fn evaluate_gateway(
        &self,
        resolver: &dyn Resolver,
        target: &Target,
    ) -> Result<Pinned, Denial> {
        if matches!(self.capability, NetworkCapability::Offline) {
            return Err(Denial::Offline);
        }
        Self::pin(resolver, target)
    }

    fn pin(resolver: &dyn Resolver, target: &Target) -> Result<Pinned, Denial> {
        let addrs = match &target.host {
            Host::Ip(ip) => vec![*ip],
            Host::Name(name) => resolver.resolve(name).unwrap_or_default(),
        };
        if addrs.is_empty() {
            return Err(Denial::Unresolvable);
        }
        Ok(Pinned {
            addrs,
            port: target.port,
        })
    }
}

fn allow_if(cond: bool, otherwise: Denial) -> Result<(), Denial> {
    if cond { Ok(()) } else { Err(otherwise) }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::resolve::StaticResolver;
    use std::collections::BTreeSet;

    const PUBLIC: &str = "93.184.216.34";
    const PUBLIC6: &str = "2606:2800:21f:cb07:6820:80da:af6b:8b2c";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn name(host: &str, port: u16) -> Target {
        Target {
            host: Host::Name(host.to_owned()),
            port,
        }
    }

    fn literal(s: &str, port: u16) -> Target {
        Target {
            host: Host::Ip(ip(s)),
            port,
        }
    }

    fn resolver() -> StaticResolver {
        StaticResolver::new()
            .with("github.com", [ip(PUBLIC), ip(PUBLIC6)])
            .with("pypi.org", [ip(PUBLIC)])
            .with("api.anthropic.com", [ip(PUBLIC)])
            .with("app.example.com", [ip(PUBLIC)])
            .with("localhost", [ip("127.0.0.1"), ip("::1")])
            .with("rebind.evil", [ip(PUBLIC), ip("10.0.0.5")])
            .with("meta.evil", [ip("169.254.169.254")])
            .with("mapped.evil", [ip("::ffff:192.168.1.1")])
            .with("nowhere.evil", [])
    }

    fn custom(hosts: &[&str]) -> NetworkCapability {
        NetworkCapability::Custom(
            hosts
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<BTreeSet<_>>(),
        )
    }

    fn eval(cap: NetworkCapability, target: &Target) -> Result<Pinned, Denial> {
        Policy::new(cap).evaluate(&resolver(), target)
    }

    #[test]
    fn offline_denies_everything() {
        let cap = NetworkCapability::Offline;
        assert_eq!(
            eval(cap.clone(), &name("github.com", 443)),
            Err(Denial::Offline)
        );
        assert_eq!(
            eval(cap.clone(), &name("localhost", 80)),
            Err(Denial::Offline)
        );
        assert_eq!(eval(cap, &literal("127.0.0.1", 80)), Err(Denial::Offline));
    }

    #[test]
    fn localhost_only_allows_loopback_only() {
        let cap = NetworkCapability::LocalhostOnly;
        assert!(eval(cap.clone(), &name("localhost", 3000)).is_ok());
        assert!(eval(cap.clone(), &literal("127.0.0.1", 3000)).is_ok());
        assert!(eval(cap.clone(), &literal("::1", 3000)).is_ok());
        assert_eq!(
            eval(cap.clone(), &name("github.com", 443)),
            Err(Denial::NotAllowlisted)
        );
        assert_eq!(
            eval(cap.clone(), &literal(PUBLIC, 443)),
            Err(Denial::IpLiteral)
        );
        assert_eq!(
            eval(cap.clone(), &literal("10.0.0.1", 443)),
            Err(Denial::IpLiteral)
        );
        // Even a name that resolves publicly is refused at the address stage.
        let p = Policy::new(cap);
        assert_eq!(p.check_addr(ip(PUBLIC)), Err(Denial::NotLoopback));
    }

    #[test]
    fn registries_allow_only_registry_hosts() {
        let cap = NetworkCapability::Registries;
        assert!(eval(cap.clone(), &name("pypi.org", 443)).is_ok());
        assert_eq!(
            eval(cap.clone(), &name("github.com", 443)),
            Err(Denial::NotAllowlisted)
        );
        assert_eq!(
            eval(cap.clone(), &name("localhost", 80)),
            Err(Denial::NotAllowlisted)
        );
        assert_eq!(eval(cap, &literal(PUBLIC, 443)), Err(Denial::IpLiteral));
    }

    #[test]
    fn development_adds_vcs_and_model_hosts() {
        let cap = NetworkCapability::Development;
        assert!(eval(cap.clone(), &name("pypi.org", 443)).is_ok());
        assert!(eval(cap.clone(), &name("github.com", 443)).is_ok());
        assert!(eval(cap.clone(), &name("api.anthropic.com", 443)).is_ok());
        assert_eq!(
            eval(cap, &name("app.example.com", 443)),
            Err(Denial::NotAllowlisted)
        );
    }

    #[test]
    fn custom_allows_exactly_the_set_with_wildcards() {
        let cap = custom(&["github.com", "*.example.com"]);
        assert!(eval(cap.clone(), &name("github.com", 443)).is_ok());
        assert!(eval(cap.clone(), &name("app.example.com", 443)).is_ok());
        assert_eq!(
            eval(cap.clone(), &name("pypi.org", 443)),
            Err(Denial::NotAllowlisted)
        );
        assert_eq!(eval(cap, &literal(PUBLIC, 443)), Err(Denial::IpLiteral));
        // A bare `*` is not a wildcard for "everything".
        assert_eq!(
            eval(custom(&["*"]), &name("github.com", 443)),
            Err(Denial::NotAllowlisted)
        );
    }

    #[test]
    fn custom_localhost_still_denies_loopback_without_test_flag() {
        assert_eq!(
            eval(custom(&["localhost"]), &name("localhost", 80)),
            Err(Denial::Address(AddrClass::Loopback))
        );
    }

    #[cfg(feature = "test-loopback")]
    #[test]
    fn test_loopback_flag_permits_loopback_in_custom_mode() {
        let p = Policy::new(custom(&["localhost"])).allow_loopback(true);
        assert!(p.evaluate(&resolver(), &name("localhost", 80)).is_ok());
        assert!(p.evaluate(&resolver(), &literal("127.0.0.1", 80)).is_ok());
        assert_eq!(
            p.evaluate(&resolver(), &literal("10.0.0.1", 80)),
            Err(Denial::IpLiteral)
        );
    }

    #[test]
    fn unrestricted_allows_public_only() {
        let cap = NetworkCapability::Unrestricted;
        assert!(eval(cap.clone(), &name("app.example.com", 443)).is_ok());
        assert!(eval(cap.clone(), &literal(PUBLIC, 443)).is_ok());
        assert!(eval(cap.clone(), &literal(PUBLIC6, 443)).is_ok());
        assert_eq!(
            eval(cap.clone(), &literal("10.0.0.1", 443)),
            Err(Denial::Address(AddrClass::Private))
        );
        assert_eq!(
            eval(cap.clone(), &literal("127.0.0.1", 443)),
            Err(Denial::Address(AddrClass::Loopback))
        );
        assert_eq!(
            eval(cap.clone(), &literal("169.254.169.254", 80)),
            Err(Denial::Address(AddrClass::CloudMetadata))
        );
        assert_eq!(
            eval(cap.clone(), &literal("fd00:ec2::254", 80)),
            Err(Denial::Address(AddrClass::CloudMetadata))
        );
        assert_eq!(
            eval(cap.clone(), &literal("::ffff:10.1.1.1", 80)),
            Err(Denial::Address(AddrClass::Private))
        );
        assert_eq!(
            eval(cap, &name("localhost", 80)),
            Err(Denial::Address(AddrClass::Loopback))
        );
    }

    #[test]
    fn rebinding_answer_with_any_private_address_is_denied() {
        let cap = NetworkCapability::Unrestricted;
        assert_eq!(
            eval(cap.clone(), &name("rebind.evil", 443)),
            Err(Denial::Address(AddrClass::Private))
        );
        assert_eq!(
            eval(cap.clone(), &name("meta.evil", 80)),
            Err(Denial::Address(AddrClass::CloudMetadata))
        );
        assert_eq!(
            eval(cap.clone(), &name("mapped.evil", 80)),
            Err(Denial::Address(AddrClass::Private))
        );
        assert_eq!(
            eval(cap.clone(), &name("nowhere.evil", 80)),
            Err(Denial::Unresolvable)
        );
        assert_eq!(
            eval(cap, &name("unknown.invalid", 80)),
            Err(Denial::Unresolvable)
        );
    }

    #[test]
    fn evaluate_pins_every_checked_address() {
        let pinned = eval(NetworkCapability::Development, &name("github.com", 22)).unwrap();
        assert_eq!(pinned.addrs, vec![ip(PUBLIC), ip(PUBLIC6)]);
        assert_eq!(pinned.port, 22);
    }

    #[test]
    fn denial_messages_never_name_hosts() {
        for d in [
            Denial::Offline,
            Denial::NotAllowlisted,
            Denial::IpLiteral,
            Denial::Address(AddrClass::Private),
            Denial::NotLoopback,
            Denial::Unresolvable,
        ] {
            let msg = d.to_string();
            assert!(!msg.contains("github") && !msg.contains('.'), "{msg}");
        }
    }

    #[test]
    fn gateway_upstream_ignores_allowlist_but_not_offline() {
        let localhost = Policy::new(NetworkCapability::LocalhostOnly);
        let target = name("api.anthropic.com", 443);
        assert_eq!(
            localhost.evaluate(&resolver(), &target),
            Err(Denial::NotAllowlisted)
        );
        let pinned = localhost.evaluate_gateway(&resolver(), &target).unwrap();
        assert_eq!(pinned.addrs, vec![ip(PUBLIC)]);
        assert_eq!(
            Policy::new(NetworkCapability::Offline).evaluate_gateway(&resolver(), &target),
            Err(Denial::Offline)
        );
        assert_eq!(
            localhost.evaluate_gateway(&resolver(), &name("nx.invalid", 443)),
            Err(Denial::Unresolvable)
        );
    }
}
