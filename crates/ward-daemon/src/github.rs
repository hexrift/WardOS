//! The GitHub adapter of the credential broker (ADR-0008, `credential-broker.md` §4):
//! the token stays on the host, git and API traffic leave through gateway routes,
//! and the manifest's `credentials.github` rule decides whether, and for which
//! repository, the grant is made.

use std::path::Path;
use std::process::Command;

use ward_policy::{CapabilityManifest, CredentialRule, CredentialScope, RepoSelector, ServiceId};

use crate::error::Result;
use crate::gateway::{Gateway, GatewaySpec};
use crate::sandbox::RELAY_ADDR;

/// Service name in policy and the log.
pub const SERVICE: &str = "github";
/// Host variable (and vault file name) holding the token.
pub const KEY_ENV: &str = "GITHUB_TOKEN";

/// Git over HTTPS: `https://github.com/<owner>/<repo>` behind `/github`.
pub const GIT: GatewaySpec = GatewaySpec {
    service: SERVICE,
    prefix: "/github",
    upstream: ("github.com", 443),
    header: "authorization",
    value_prefix: "",
    basic_user: Some("x-access-token"),
    strip: &["authorization"],
    key_env: KEY_ENV,
    base_url_env: "",
    base_path: "",
    placeholder_env: "",
};

/// The REST API behind `/github-api`; tools honour `GITHUB_API_URL`.
pub const API: GatewaySpec = GatewaySpec {
    service: SERVICE,
    prefix: "/github-api",
    upstream: ("api.github.com", 443),
    header: "authorization",
    value_prefix: "Bearer ",
    basic_user: None,
    strip: &["authorization"],
    key_env: KEY_ENV,
    base_url_env: "GITHUB_API_URL",
    base_path: "",
    placeholder_env: "GITHUB_TOKEN",
};

/// Git config seeded into the sandbox so `github.com` remotes go through the relay.
#[must_use]
pub fn gitconfig() -> String {
    format!(
        "[url \"http://{RELAY_ADDR}/github/\"]\n\tinsteadOf = https://github.com/\n\tinsteadOf = git@github.com:\n"
    )
}

/// Where the seeded git config lives inside the sandbox.
pub const GITCONFIG_PATH: &str = "/home/agent/.gitconfig";

/// What the policy decided for this launch.
#[derive(Debug)]
pub enum Grant {
    /// Routes to add, with the repositories and permissions they are scoped to.
    Granted {
        /// The gateways.
        gateways: Vec<Gateway>,
        /// `owner/repo` selectors the grant covers.
        repos: Vec<String>,
        /// Whether `contents:write` is included.
        write: bool,
    },
    /// The rule is `ask` and the user did not pass `--grant github`.
    Ask,
    /// The rule is `deny`.
    Denied,
    /// The session is offline.
    Offline,
    /// No token on the host.
    NoKey,
    /// The scope names the current repository but the worktree has no GitHub remote.
    NoRemote,
}

/// Decide the grant for this launch: the manifest's rule, the user's explicit
/// request (`--grant github`), the worktree's remote, and the host token.
pub fn grant(
    manifest: &CapabilityManifest,
    worktree: &Path,
    state: &Path,
    requested: bool,
) -> Result<Grant> {
    if matches!(manifest.network, ward_policy::NetworkCapability::Offline) {
        return Ok(Grant::Offline);
    }
    let scope = match manifest.credentials.get(&ServiceId(SERVICE.to_owned())) {
        None | Some(CredentialRule::Deny) => return Ok(Grant::Denied),
        Some(CredentialRule::Ask(_)) if !requested => return Ok(Grant::Ask),
        Some(CredentialRule::Ask(scope) | CredentialRule::Allow(scope)) => scope,
    };
    let Some(repos) = repositories(scope, worktree) else {
        return Ok(Grant::NoRemote);
    };
    let write = scope.permissions.contains("contents:write");
    let permissions: Vec<String> = scope.permissions.iter().cloned().collect();
    let (git_paths, api_paths) = scope_paths(&repos);
    let mut gateways = Vec::new();
    for (spec, paths) in [(&GIT, git_paths), (&API, api_paths)] {
        match Gateway::resolve(spec, state)? {
            Some(g) => gateways.push(
                g.with_permissions(permissions.clone())
                    .map_route(|r| r.scope(paths, write)),
            ),
            None => return Ok(Grant::NoKey),
        }
    }
    Ok(Grant::Granted {
        gateways,
        repos,
        write,
    })
}

/// The `owner/repo` list a scope resolves to; `None` when it needs the current
/// repository and the worktree has none on GitHub. An empty scope means any.
fn repositories(scope: &CredentialScope, worktree: &Path) -> Option<Vec<String>> {
    scope
        .repositories
        .iter()
        .map(|sel| match sel {
            RepoSelector::Named(name) => Some(name.clone()),
            RepoSelector::CurrentRepository => origin_repo(worktree),
        })
        .collect()
}

/// `owner/repo` of the worktree's `origin` remote when it points at GitHub.
#[must_use]
pub fn origin_repo(worktree: &Path) -> Option<String> {
    let out = Command::new("git")
        .args([
            "-C",
            &worktree.to_string_lossy(),
            "config",
            "--get",
            "remote.origin.url",
        ])
        .output()
        .ok()?;
    repo_from_remote(String::from_utf8_lossy(&out.stdout).trim())
}

/// `owner/repo` from an HTTPS or SSH GitHub remote URL.
#[must_use]
pub fn repo_from_remote(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))
        .or_else(|| url.strip_prefix("git@github.com:"))
        .or_else(|| url.strip_prefix("ssh://git@github.com/"))?;
    let rest = rest.trim_end_matches('/').trim_end_matches(".git");
    let (owner, repo) = rest.split_once('/')?;
    let ok = |s: &str| {
        !s.is_empty()
            && s.bytes().any(|b| b != b'.')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    };
    (ok(owner) && ok(repo) && !repo.contains('/')).then(|| format!("{owner}/{repo}"))
}

/// Path prefixes (after the route prefix) the git and API routes may serve for `repos`.
#[must_use]
pub fn scope_paths(repos: &[String]) -> (Vec<String>, Vec<String>) {
    let git = repos
        .iter()
        .flat_map(|r| [format!("/{r}"), format!("/{r}.git")])
        .collect();
    let api = repos.iter().map(|r| format!("/repos/{r}")).collect();
    (git, api)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::collections::BTreeSet;
    use ward_policy::NetworkCapability;

    #[test]
    fn remote_urls_reduce_to_owner_repo() {
        for url in [
            "https://github.com/hexrift/WardOS",
            "https://github.com/hexrift/WardOS.git",
            "git@github.com:hexrift/WardOS.git",
            "ssh://git@github.com/hexrift/WardOS/",
        ] {
            assert_eq!(
                repo_from_remote(url).as_deref(),
                Some("hexrift/WardOS"),
                "{url}"
            );
        }
        assert_eq!(repo_from_remote("https://gitlab.com/a/b"), None);
        assert_eq!(repo_from_remote("https://github.com/only"), None);
        assert_eq!(repo_from_remote("https://github.com/a/b/c"), None);
        assert_eq!(repo_from_remote("https://github.com/../x"), None);
    }

    #[test]
    fn scope_paths_cover_git_and_api_forms() {
        let (git, api) = scope_paths(&["hexrift/WardOS".to_owned()]);
        assert_eq!(git, vec!["/hexrift/WardOS", "/hexrift/WardOS.git"]);
        assert_eq!(api, vec!["/repos/hexrift/WardOS"]);
    }

    #[test]
    fn gitconfig_rewrites_github_remotes_to_the_relay() {
        let cfg = gitconfig();
        assert!(cfg.contains("[url \"http://127.0.0.1:3128/github/\"]"));
        assert!(cfg.contains("insteadOf = https://github.com/"));
        assert!(cfg.contains("insteadOf = git@github.com:"));
    }

    fn manifest_with(rule: CredentialRule) -> CapabilityManifest {
        let mut m = ward_policy::default_manifest();
        m.network = NetworkCapability::LocalhostOnly;
        m.credentials.insert(ServiceId(SERVICE.to_owned()), rule);
        m
    }

    #[test]
    fn policy_rule_gates_the_grant() {
        let state = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        let w = repo.path();
        assert!(matches!(
            grant(&manifest_with(CredentialRule::Deny), w, state.path(), true).unwrap(),
            Grant::Denied
        ));
        let scope = CredentialScope {
            repositories: BTreeSet::from([RepoSelector::Named("hexrift/WardOS".into())]),
            permissions: BTreeSet::from(["contents:read".to_owned()]),
        };
        let ask = manifest_with(CredentialRule::Ask(scope.clone()));
        assert!(matches!(
            grant(&ask, w, state.path(), false).unwrap(),
            Grant::Ask
        ));
        // Asked for, but no token anywhere: NoKey rather than a silent skip.
        std::fs::create_dir_all(state.path().join("vault")).unwrap();
        if std::env::var_os(KEY_ENV).is_none() {
            assert!(matches!(
                grant(&ask, w, state.path(), true).unwrap(),
                Grant::NoKey
            ));
        }
        std::fs::write(state.path().join("vault").join(KEY_ENV), "ghp_test\n").unwrap();
        match grant(&ask, w, state.path(), true).unwrap() {
            Grant::Granted {
                gateways,
                repos,
                write,
            } => {
                assert_eq!(gateways.len(), 2);
                assert_eq!(repos, vec!["hexrift/WardOS"]);
                assert!(!write);
                assert_eq!(gateways[0].permissions, vec!["contents:read"]);
                let dbg = format!("{:?}", gateways[0].route);
                assert!(
                    dbg.contains("/hexrift/WardOS.git") && dbg.contains("write: false"),
                    "{dbg}"
                );
                assert!(!dbg.contains("ghp_test"), "{dbg}");
                assert!(gateways[1].env.contains(&(
                    "GITHUB_API_URL".into(),
                    "http://127.0.0.1:3128/github-api".into()
                )));
                assert!(gateways[0].env.is_empty(), "the git route needs no env");
            }
            other => panic!("{other:?}"),
        }
        // Current-repository scope with no GitHub remote in the worktree.
        let current = manifest_with(CredentialRule::Allow(CredentialScope {
            repositories: BTreeSet::from([RepoSelector::CurrentRepository]),
            permissions: BTreeSet::from(["contents:write".to_owned()]),
        }));
        assert!(matches!(
            grant(&current, w, state.path(), false).unwrap(),
            Grant::NoRemote
        ));
        let mut offline = current;
        offline.network = NetworkCapability::Offline;
        assert!(matches!(
            grant(&offline, w, state.path(), true).unwrap(),
            Grant::Offline
        ));
    }
}
