//! The GitHub adapter of the credential broker (ADR-0008, `credential-broker.md` §4):
//! the token stays on the host, git and API traffic leave through gateway routes,
//! and the manifest's `credentials.github` rule decides whether, and for which
//! repository, the grant is made.

use std::path::Path;

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
    /// The scope names the current repository but the session has no pinned
    /// GitHub remote for it (see [`pinned_origin_repo`]).
    NoRemote,
}

/// Decide the grant for this launch: the manifest's rule, the user's explicit
/// request (`--grant github`), the repository pinned for the session
/// (`current_repo`, see [`pinned_origin_repo`]), and the host token.
///
/// `current_repo` is never re-derived from the live worktree here — it is
/// whatever the caller fixed at session start, so a `.git/config` edit made
/// after that (by the agent, mid-session) cannot change what a
/// `RepoSelector::CurrentRepository` grant scopes to. See issue #196.
pub fn grant(
    manifest: &CapabilityManifest,
    current_repo: Option<&str>,
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
    let Some(repos) = repositories(scope, current_repo) else {
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
/// repository and none is pinned for the session. An empty scope means any.
fn repositories(scope: &CredentialScope, current_repo: Option<&str>) -> Option<Vec<String>> {
    scope
        .repositories
        .iter()
        .map(|sel| match sel {
            RepoSelector::Named(name) => Some(name.clone()),
            RepoSelector::CurrentRepository => current_repo.map(str::to_owned),
        })
        .collect()
}

/// `owner/repo` of `origin`, read from the *entry* snapshot's captured
/// `.git/config` under `state`'s CAS rather than from the live worktree
/// (issue #196).
///
/// The entry snapshot is written once by the host, before the sandbox
/// exists, and — like every snapshot — is immutable and unreachable from it
/// (security-model G5). Reading `remote.origin.url` from it instead of
/// shelling out to `git -C <worktree> config --get remote.origin.url`
/// against the live, agent-writable worktree means a `git remote set-url
/// origin …` (or a hand edit of `.git/config`) the agent makes after the
/// session starts cannot change what `RepoSelector::CurrentRepository`
/// resolves to for the rest of the session — the same trust boundary the
/// snapshot capturer already draws around a tampered `.git/HEAD`
/// (`ward-snapshot/src/capture.rs`, `read_git_context`). `None` when the
/// CAS, the snapshot id, the file, or the `[remote "origin"]` stanza is
/// missing — callers treat that as "no remote", never fall back to the live
/// worktree.
#[must_use]
pub fn pinned_origin_repo(state: &Path, entry_snapshot: &str) -> Option<String> {
    let store = ward_snapshot::SnapshotStore::open(state.join("cas")).ok()?;
    let id: ward_snapshot::SnapshotId = entry_snapshot.parse().ok()?;
    let bytes = store.cat(id, Path::new(".git/config")).ok()?;
    let url = origin_url_from_gitconfig(&String::from_utf8_lossy(&bytes))?;
    repo_from_remote(url.trim())
}

/// The `url` value of the `[remote "origin"]` stanza in `.git/config` text.
///
/// A small hand-rolled reader rather than a shell-out to `git config -f`:
/// enforcement-path code never shells out (security-model §5), and this only
/// ever needs the one stanza from bytes the host already holds in the CAS.
/// Not a general git-config parser (no `include`, no multi-file precedence);
/// a section or key this can't find yields `None`, not a guess.
fn origin_url_from_gitconfig(text: &str) -> Option<String> {
    let mut in_origin_section = false;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_origin_section = name.trim() == "remote \"origin\"";
            continue;
        }
        if !in_origin_section {
            continue;
        }
        let Some(rest) = line.strip_prefix("url") else {
            continue;
        };
        if let Some(value) = rest.trim_start().strip_prefix('=') {
            return Some(value.trim().trim_matches('"').to_owned());
        }
    }
    None
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
        assert!(matches!(
            grant(
                &manifest_with(CredentialRule::Deny),
                None,
                state.path(),
                true
            )
            .unwrap(),
            Grant::Denied
        ));
        let scope = CredentialScope {
            repositories: BTreeSet::from([RepoSelector::Named("hexrift/WardOS".into())]),
            permissions: BTreeSet::from(["contents:read".to_owned()]),
        };
        let ask = manifest_with(CredentialRule::Ask(scope.clone()));
        assert!(matches!(
            grant(&ask, None, state.path(), false).unwrap(),
            Grant::Ask
        ));
        // Asked for, but no token anywhere: NoKey rather than a silent skip.
        std::fs::create_dir_all(state.path().join("vault")).unwrap();
        if std::env::var_os(KEY_ENV).is_none() {
            assert!(matches!(
                grant(&ask, None, state.path(), true).unwrap(),
                Grant::NoKey
            ));
        }
        std::fs::write(state.path().join("vault").join(KEY_ENV), "ghp_test\n").unwrap();
        // A `Named` selector needs no pinned repository at all: `current_repo` is
        // `None` throughout, and the grant still resolves to the named repo.
        match grant(&ask, None, state.path(), true).unwrap() {
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
        // Current-repository scope with no repository pinned for the session.
        let current = manifest_with(CredentialRule::Allow(CredentialScope {
            repositories: BTreeSet::from([RepoSelector::CurrentRepository]),
            permissions: BTreeSet::from(["contents:write".to_owned()]),
        }));
        assert!(matches!(
            grant(&current, None, state.path(), false).unwrap(),
            Grant::NoRemote
        ));
        // Current-repository scope with a pinned repository resolves to it.
        match grant(&current, Some("hexrift/WardOS"), state.path(), true).unwrap() {
            Grant::Granted { repos, write, .. } => {
                assert_eq!(repos, vec!["hexrift/WardOS"]);
                assert!(write);
            }
            other => panic!("{other:?}"),
        }
        let mut offline = current;
        offline.network = NetworkCapability::Offline;
        assert!(matches!(
            grant(&offline, Some("hexrift/WardOS"), state.path(), true).unwrap(),
            Grant::Offline
        ));
    }

    #[test]
    fn gitconfig_url_is_read_from_the_origin_remote_stanza_only() {
        let text = "[core]\n\trepositoryformatversion = 0\n[remote \"upstream\"]\n\turl = https://github.com/someone-else/decoy.git\n[remote \"origin\"]\n\turl = https://github.com/hexrift/WardOS.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n";
        assert_eq!(
            origin_url_from_gitconfig(text).as_deref(),
            Some("https://github.com/hexrift/WardOS.git")
        );
    }

    #[test]
    fn gitconfig_with_no_origin_remote_yields_none() {
        assert_eq!(origin_url_from_gitconfig(""), None);
        assert_eq!(
            origin_url_from_gitconfig(
                "[remote \"upstream\"]\n\turl = https://github.com/a/b.git\n"
            ),
            None
        );
        // A bare `url` key outside any `[remote "origin"]` section must not match.
        assert_eq!(
            origin_url_from_gitconfig("url = https://github.com/a/b.git\n"),
            None
        );
    }

    #[test]
    fn pinned_origin_repo_reads_the_entry_snapshots_config_not_the_live_worktree() {
        use ward_snapshot::{CaptureOptions, SnapshotRole, SnapshotStore};

        let state = tempfile::tempdir().unwrap();
        let worktree = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(worktree.path().join(".git")).unwrap();
        std::fs::write(
            worktree.path().join(".git/config"),
            "[remote \"origin\"]\n\turl = https://github.com/hexrift/WardOS.git\n",
        )
        .unwrap();

        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let entry = store
            .store_snapshot(
                worktree.path(),
                SnapshotRole::Entry,
                CaptureOptions::default(),
            )
            .unwrap();

        // The pinned value matches what was true at capture time.
        assert_eq!(
            pinned_origin_repo(state.path(), &entry.to_string()).as_deref(),
            Some("hexrift/WardOS")
        );

        // An agent-style tamper of the *live* worktree after the snapshot was
        // taken — exactly `git remote set-url origin <attacker-repo>` — must not
        // change what the already-captured entry snapshot resolves to.
        std::fs::write(
            worktree.path().join(".git/config"),
            "[remote \"origin\"]\n\turl = https://github.com/attacker/evil.git\n",
        )
        .unwrap();
        assert_eq!(
            pinned_origin_repo(state.path(), &entry.to_string()).as_deref(),
            Some("hexrift/WardOS"),
            "a live .git/config edit redirected a repo pinned at session start"
        );
    }

    #[test]
    fn pinned_origin_repo_is_none_when_the_snapshot_has_no_git_config() {
        use ward_snapshot::{CaptureOptions, SnapshotRole, SnapshotStore};

        let state = tempfile::tempdir().unwrap();
        let worktree = tempfile::tempdir().unwrap();
        std::fs::write(worktree.path().join("README.md"), "demo\n").unwrap();

        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let entry = store
            .store_snapshot(
                worktree.path(),
                SnapshotRole::Entry,
                CaptureOptions::default(),
            )
            .unwrap();
        assert_eq!(pinned_origin_repo(state.path(), &entry.to_string()), None);
        // A nonsense snapshot id, or an empty/uninitialised CAS, is also `None`,
        // never a panic or a fallback to something else.
        assert_eq!(pinned_origin_repo(state.path(), "not-a-snapshot-id"), None);
        let empty_state = tempfile::tempdir().unwrap();
        assert_eq!(
            pinned_origin_repo(empty_state.path(), &entry.to_string()),
            None
        );
    }
}
