//! Built-in host allowlists and hostname matching.
//!
//! Matching is case-insensitive on ASCII (DNS names are). A pattern of the form
//! `*.example.com` matches any name with at least one label before
//! `.example.com`; it never matches `example.com` itself.

/// Package registries reachable in `NetworkCapability::Registries`.
pub const REGISTRY_HOSTS: &[&str] = &[
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "index.crates.io",
    "static.crates.io",
    "proxy.golang.org",
];

/// VCS hosts and model APIs added by `NetworkCapability::Development`
/// (on top of [`REGISTRY_HOSTS`]).
pub const DEVELOPMENT_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
];

/// Does `host` match the allowlist entry `pattern`?
///
/// Both sides are compared ASCII case-insensitively after stripping one
/// trailing dot from `host` (a fully-qualified spelling of the same name).
pub fn matches(pattern: &str, host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // `*.example.com` needs `<label>.example.com`.
        host.len() > suffix.len() + 1
            && host.is_char_boundary(host.len() - suffix.len() - 1)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

/// Does any entry in `patterns` match `host`?
pub fn any_matches<'a, I>(patterns: I, host: &str) -> bool
where
    I: IntoIterator<Item = &'a str>,
{
    patterns.into_iter().any(|p| matches(p, host))
}

/// Is `host` the loopback name `localhost` or a subdomain of it (RFC 6761)?
pub fn is_localhost_name(host: &str) -> bool {
    matches("localhost", host) || matches("*.localhost", host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_is_case_insensitive() {
        assert!(matches("github.com", "github.com"));
        assert!(matches("github.com", "GitHub.COM"));
        assert!(matches("GitHub.com", "github.com"));
        assert!(matches("github.com", "github.com."));
        assert!(!matches("github.com", "api.github.com"));
        assert!(!matches("github.com", "github.co"));
        assert!(!matches("github.com", "evilgithub.com"));
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        assert!(matches("*.example.com", "a.example.com"));
        assert!(matches("*.example.com", "A.B.Example.COM"));
        assert!(matches("*.example.com", "a.example.com."));
        assert!(!matches("*.example.com", "example.com"));
        assert!(!matches("*.example.com", ".example.com"));
        assert!(!matches("*.example.com", "notexample.com"));
        assert!(!matches("*.example.com", "example.com.evil.net"));
        assert!(!matches("*.example.com", "com"));
    }

    #[test]
    fn builtin_lists_are_disjoint_and_lowercase() {
        for h in REGISTRY_HOSTS.iter().chain(DEVELOPMENT_HOSTS) {
            assert_eq!(*h, h.to_ascii_lowercase());
            assert!(!h.contains('*'));
        }
        for h in DEVELOPMENT_HOSTS {
            assert!(!REGISTRY_HOSTS.contains(h));
        }
    }

    #[test]
    fn any_matches_scans_all_patterns() {
        let set = ["a.com", "*.b.org"];
        assert!(any_matches(set, "x.b.org"));
        assert!(any_matches(set, "A.COM"));
        assert!(!any_matches(set, "b.org"));
    }

    #[test]
    fn localhost_names() {
        assert!(is_localhost_name("localhost"));
        assert!(is_localhost_name("LOCALHOST"));
        assert!(is_localhost_name("dev.localhost"));
        assert!(!is_localhost_name("localhost.evil.com"));
        assert!(!is_localhost_name("notlocalhost"));
    }
}
