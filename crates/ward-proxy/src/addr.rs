//! Structural address classification: which destination addresses are never
//! public, regardless of policy mode (architecture §7, threat-model row 10).
//!
//! Every IPv6 address that embeds an IPv4 address (IPv4-mapped, IPv4-compatible,
//! NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) is classified by the embedded IPv4
//! address as well, so a private IPv4 target cannot be smuggled inside IPv6.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The AWS/GCP/Azure instance-metadata endpoint (IPv4).
pub const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
/// The AWS instance-metadata endpoint (IPv6).
pub const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254);

/// Why an address is not a public destination. Ordered roughly by specificity:
/// the most specific match is reported so events name the real danger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddrClass {
    /// `169.254.169.254` or `fd00:ec2::254`.
    CloudMetadata,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// `0.0.0.0`, `::`.
    Unspecified,
    /// RFC 1918 (`10/8`, `172.16/12`, `192.168/16`) and CGNAT `100.64/10`.
    Private,
    /// `169.254.0.0/16`, `fe80::/10`, site-local `fec0::/10`.
    LinkLocal,
    /// IPv6 unique-local `fc00::/7`.
    UniqueLocal,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// Broadcast, `0.0.0.0/8`, `240.0.0.0/4`, documentation and benchmark
    /// ranges — never routable on the public internet.
    Reserved,
}

impl AddrClass {
    /// Short, stable label for event reasons.
    pub const fn label(self) -> &'static str {
        match self {
            Self::CloudMetadata => "cloud metadata endpoint",
            Self::Loopback => "loopback",
            Self::Unspecified => "unspecified address",
            Self::Private => "private range",
            Self::LinkLocal => "link-local range",
            Self::UniqueLocal => "unique-local range",
            Self::Multicast => "multicast",
            Self::Reserved => "reserved range",
        }
    }
}

/// Classify `ip`. `None` means the address is a public unicast destination.
pub fn classify(ip: IpAddr) -> Option<AddrClass> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// `true` when `ip` is a public unicast address.
pub fn is_public(ip: IpAddr) -> bool {
    classify(ip).is_none()
}

fn classify_v4(ip: Ipv4Addr) -> Option<AddrClass> {
    let [a, b, _, _] = ip.octets();
    if ip == METADATA_V4 {
        Some(AddrClass::CloudMetadata)
    } else if ip.is_loopback() {
        Some(AddrClass::Loopback)
    } else if ip.is_unspecified() {
        Some(AddrClass::Unspecified)
    } else if ip.is_private() || (a == 100 && (64..128).contains(&b)) {
        Some(AddrClass::Private)
    } else if ip.is_link_local() {
        Some(AddrClass::LinkLocal)
    } else if ip.is_multicast() {
        Some(AddrClass::Multicast)
    } else if a == 0
        || ip.is_broadcast()
        || ip.is_documentation()
        || a >= 240
        || (a == 198 && (b == 18 || b == 19))
    {
        Some(AddrClass::Reserved)
    } else {
        None
    }
}

fn classify_v6(ip: Ipv6Addr) -> Option<AddrClass> {
    if ip == METADATA_V6 {
        return Some(AddrClass::CloudMetadata);
    }
    if ip.is_loopback() {
        return Some(AddrClass::Loopback);
    }
    if ip.is_unspecified() {
        return Some(AddrClass::Unspecified);
    }
    if let Some(v4) = embedded_v4(ip) {
        return classify_v4(v4);
    }
    let seg = ip.segments();
    if seg[0] & 0xfe00 == 0xfc00 {
        Some(AddrClass::UniqueLocal)
    } else if seg[0] & 0xffc0 == 0xfe80 || seg[0] & 0xffc0 == 0xfec0 {
        Some(AddrClass::LinkLocal)
    } else if ip.is_multicast() {
        Some(AddrClass::Multicast)
    } else if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        Some(AddrClass::Reserved)
    } else {
        None
    }
}

/// The IPv4 address carried inside an IPv6 transition address, if any.
/// Callers must rule out `::` and `::1` first; both look IPv4-compatible.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = ip.segments();
    let last_two = |s: [u16; 8]| Ipv4Addr::from(((u32::from(s[6])) << 16) | u32::from(s[7]));
    if let Some(v4) = ip.to_ipv4_mapped() {
        Some(v4)
    } else if seg[..6] == [0, 0, 0, 0, 0, 0] {
        // IPv4-compatible `::a.b.c.d` (deprecated, but still parsed by libc).
        Some(last_two(seg))
    } else if seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        // NAT64 well-known prefix.
        Some(last_two(seg))
    } else if seg[0] == 0x2002 {
        // 6to4: the IPv4 address sits in segments 1..3.
        Some(Ipv4Addr::from(
            (u32::from(seg[1]) << 16) | u32::from(seg[2]),
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_addresses_pass() {
        for s in [
            "93.184.216.34",
            "1.1.1.1",
            "2606:4700::1111",
            "2a00:1450:4001::1",
        ] {
            assert_eq!(classify(ip(s)), None, "{s}");
            assert!(is_public(ip(s)));
        }
    }

    #[test]
    fn every_deny_range_is_classified() {
        use AddrClass::{
            CloudMetadata, LinkLocal, Loopback, Multicast, Private, Reserved, UniqueLocal,
            Unspecified,
        };
        let cases = [
            ("169.254.169.254", CloudMetadata),
            ("fd00:ec2::254", CloudMetadata),
            ("127.0.0.1", Loopback),
            ("127.255.255.254", Loopback),
            ("::1", Loopback),
            ("0.0.0.0", Unspecified),
            ("::", Unspecified),
            ("10.0.0.1", Private),
            ("172.16.0.1", Private),
            ("172.31.255.255", Private),
            ("192.168.1.1", Private),
            ("100.64.0.1", Private),
            ("169.254.1.1", LinkLocal),
            ("fe80::1", LinkLocal),
            ("fec0::1", LinkLocal),
            ("fc00::1", UniqueLocal),
            ("fd12:3456::1", UniqueLocal),
            ("224.0.0.1", Multicast),
            ("239.255.255.250", Multicast),
            ("ff02::1", Multicast),
            ("0.1.2.3", Reserved),
            ("255.255.255.255", Reserved),
            ("240.0.0.1", Reserved),
            ("192.0.2.1", Reserved),
            ("198.18.0.1", Reserved),
            ("2001:db8::1", Reserved),
        ];
        for (s, expected) in cases {
            assert_eq!(classify(ip(s)), Some(expected), "{s}");
        }
    }

    #[test]
    fn ipv6_transition_addresses_are_classified_by_embedded_ipv4() {
        let cases = [
            ("::ffff:127.0.0.1", AddrClass::Loopback),
            ("::ffff:10.0.0.1", AddrClass::Private),
            ("::ffff:169.254.169.254", AddrClass::CloudMetadata),
            ("::ffff:192.168.0.1", AddrClass::Private),
            ("::10.0.0.1", AddrClass::Private),
            ("64:ff9b::a00:1", AddrClass::Private),
            ("64:ff9b::7f00:1", AddrClass::Loopback),
            ("2002:c0a8:0001::1", AddrClass::Private),
            ("2002:a9fe:a9fe::1", AddrClass::CloudMetadata),
        ];
        for (s, expected) in cases {
            assert_eq!(classify(ip(s)), Some(expected), "{s}");
        }
        assert_eq!(classify(ip("::ffff:93.184.216.34")), None);
        assert_eq!(classify(ip("2002:5db8:d822::1")), None);
    }

    #[test]
    fn non_public_but_not_in_deny_list_is_still_denied() {
        // 172.32.0.0 is just outside 172.16/12 and is public.
        assert_eq!(classify(ip("172.32.0.1")), None);
        // 100.128.0.0 is just outside CGNAT and is public.
        assert_eq!(classify(ip("100.128.0.1")), None);
    }
}
