//! Hostname and host-pattern validation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ward_policy::hostname::{intersect, is_subset};
use ward_policy::{HostPattern, HostSet, PolicyError, ServiceId};

fn set(names: &[&str]) -> HostSet {
    names
        .iter()
        .map(|n| HostPattern::parse(n).unwrap())
        .collect()
}

#[test]
fn accepts_valid_hostnames() {
    for ok in [
        "github.com",
        "registry.npmjs.org",
        "localhost",
        "a.b.c.d.e.example",
        "xn--bcher-kva.example",
        "host-with-dash.example.com",
        "123.example.com",
    ] {
        let p = HostPattern::parse(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        assert!(!p.is_wildcard());
        assert_eq!(p.to_string(), ok);
    }
}

#[test]
fn normalises_case() {
    let p = HostPattern::parse("Registry.NPMJS.Org").unwrap();
    assert_eq!(p.host(), "registry.npmjs.org");
    assert!(p.matches_host("REGISTRY.npmjs.org"));
}

#[test]
fn accepts_leading_wildcard_only() {
    let p = HostPattern::parse("*.githubusercontent.com").unwrap();
    assert!(p.is_wildcard());
    assert_eq!(p.to_string(), "*.githubusercontent.com");
    for bad in [
        "*",
        "*.com",
        "foo.*.com",
        "*foo.com",
        "**.example.com",
        "a.*",
    ] {
        let err = HostPattern::parse(bad).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidHostname { .. }),
            "{bad}: {err}"
        );
    }
}

#[test]
fn rejects_ip_literals() {
    for bad in [
        "10.0.0.1",
        "127.0.0.1",
        "::1",
        "2001:db8::1",
        "192.168.1.1",
        "1.2.3.4",
    ] {
        let err = HostPattern::parse(bad).unwrap_err();
        assert!(matches!(err, PolicyError::InvalidHostname { .. }), "{bad}");
    }
}

#[test]
fn rejects_malformed_names() {
    let long_label = format!("{}.com", "a".repeat(64));
    let long_name = format!("{}.com", ["abcdefghij"; 30].join("."));
    for bad in [
        "",
        " github.com",
        "github.com ",
        "github.com.",
        "-github.com",
        "github-.com",
        "git hub.com",
        "github..com",
        "münchen.de",
        "under_score.com",
        "http://github.com",
        long_label.as_str(),
        long_name.as_str(),
    ] {
        let err = HostPattern::parse(bad).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidHostname { .. }),
            "{bad:?}"
        );
    }
}

#[test]
fn matches_host_semantics() {
    let exact = HostPattern::parse("api.github.com").unwrap();
    assert!(exact.matches_host("api.github.com"));
    assert!(exact.matches_host("api.github.com."));
    assert!(!exact.matches_host("github.com"));
    assert!(!exact.matches_host("evil-api.github.com"));

    let wild = HostPattern::parse("*.github.com").unwrap();
    assert!(wild.matches_host("api.github.com"));
    assert!(wild.matches_host("a.b.github.com"));
    assert!(
        !wild.matches_host("github.com"),
        "bare suffix is not matched"
    );
    assert!(!wild.matches_host("evilgithub.com"));
    assert!(!wild.matches_host("github.com.evil"));
}

#[test]
fn covers_semantics() {
    let wild = HostPattern::parse("*.example.com").unwrap();
    let deeper = HostPattern::parse("*.sub.example.com").unwrap();
    let exact = HostPattern::parse("api.example.com").unwrap();
    let other = HostPattern::parse("api.example.org").unwrap();
    assert!(wild.covers(&exact));
    assert!(wild.covers(&deeper));
    assert!(wild.covers(&wild));
    assert!(!deeper.covers(&wild));
    assert!(!exact.covers(&wild));
    assert!(!wild.covers(&other));
    assert!(!wild.covers(&HostPattern::parse("example.com").unwrap()));
    assert!(!HostPattern::parse("*.xample.com").unwrap().covers(&exact));
}

#[test]
fn intersection_and_subset() {
    let a = set(&["*.example.com", "github.com", "pypi.org"]);
    let b = set(&[
        "api.example.com",
        "*.sub.example.com",
        "github.com",
        "crates.io",
    ]);
    let i = intersect(&a, &b);
    assert_eq!(
        i,
        set(&["api.example.com", "*.sub.example.com", "github.com"])
    );
    assert!(is_subset(&i, &a));
    assert!(is_subset(&i, &b));
    assert!(!is_subset(&a, &b));
    assert!(is_subset(&HostSet::new(), &a));
    assert_eq!(intersect(&a, &HostSet::new()), HostSet::new());
    assert_eq!(intersect(&a, &a), a);
}

#[test]
fn host_pattern_serde_round_trip() {
    let p = HostPattern::parse("*.Example.COM").unwrap();
    let yaml = serde_yaml::to_string(&p).unwrap();
    assert_eq!(yaml.trim(), "'*.example.com'");
    let back: HostPattern = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(back, p);
    assert!(serde_yaml::from_str::<HostPattern>("10.0.0.1").is_err());
}

#[test]
fn service_id_star_matching() {
    let cloud = ServiceId::new("cloud-*").unwrap();
    assert!(cloud.is_pattern());
    assert!(cloud.matches("cloud-aws"));
    assert!(cloud.matches("cloud-"));
    assert!(cloud.matches("cloud-*"));
    assert!(!cloud.matches("cloud"));
    assert!(!cloud.matches("xcloud-aws"));
    let any = ServiceId::new("*").unwrap();
    assert!(any.matches("anything"));
    assert!(any.matches(""));
    let mid = ServiceId::new("a*b*c").unwrap();
    assert!(mid.matches("abc"));
    assert!(mid.matches("aXXbYYc"));
    assert!(!mid.matches("ab"));
    let exact = ServiceId::new("github").unwrap();
    assert!(!exact.is_pattern());
    assert!(exact.matches("github"));
    assert!(!exact.matches("github-enterprise"));
}
