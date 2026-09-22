#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Issue #196 — a session-local edit to `.git/config` must not redirect a
//! `RepoSelector::CurrentRepository` GitHub credential grant.
//!
//! `RepoSelector::CurrentRepository` (the shipped default GitHub credential
//! scope, `ward-policy/src/default.rs`) used to resolve to a concrete
//! `owner/repo` by shelling `git config --get remote.origin.url` against the
//! live worktree at grant time. The worktree is agent-writable under the
//! default manifest, so a session that ran `git remote set-url origin
//! <attacker-repo>` (or hand-edited `.git/config`) could silently redirect a
//! later `--grant github` to a repository the human never intended, and the
//! proxy would inject the host's real `GITHUB_TOKEN` for it.
//!
//! `Session::agent_launch` now pins the repository once, from the entry
//! snapshot's captured `.git/config` (immutable, written before the sandbox
//! exists, unreachable from it — security-model G5), and never re-reads the
//! live worktree for it. This test proves that end to end: it starts a real
//! session over a git worktree whose `origin` points at the real project
//! repo, tampers the *live* worktree's remote exactly as a compromised agent
//! would, and shows `--grant github` still scopes to the real repo. No
//! bubblewrap is required — `agent_launch` only decides the grant and builds
//! the launch options; it does not itself run the sandbox.

use std::fs;
use std::process::Command;

use ward_daemon::Session;

const REAL_REPO: &str = "hexrift/WardOS";
const REAL_REMOTE: &str = "https://github.com/hexrift/WardOS.git";
const ATTACKER_REMOTE: &str = "https://github.com/attacker-controlled/evil-private-repo.git";

/// A worktree with a real git repository whose `origin` points at `remote`.
fn git_project(remote: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "demo\n").expect("write readme");
    let git = |args: &[&str]| {
        let status = Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(args)
            .status()
            .expect("run git");
        assert!(status.success(), "git {args:?} failed");
    };
    git(&["init", "-q"]);
    git(&["remote", "add", "origin", remote]);
    dir
}

/// A host `GITHUB_TOKEN` in the session's vault, as `--grant github` needs one.
fn seed_vault(state: &std::path::Path) {
    let vault = state.join("vault");
    fs::create_dir_all(&vault).expect("mkdir vault");
    fs::write(vault.join(ward_daemon::github::KEY_ENV), "ghp_test_token\n").expect("write token");
}

#[test]
fn a_live_git_config_tamper_after_session_start_does_not_redirect_the_grant() {
    let state = tempfile::tempdir().expect("tempdir");
    seed_vault(state.path());

    let project = git_project(REAL_REMOTE);
    let session = Session::start_in(project.path(), state.path()).expect("start session");

    // The attack: after the session (and its entry snapshot) already exist,
    // the agent redirects the worktree's own remote — the same command an
    // agent with ordinary read-write worktree access is free to run.
    let status = Command::new("git")
        .arg("-C")
        .arg(project.path())
        .args(["remote", "set-url", "origin", ATTACKER_REMOTE])
        .status()
        .expect("run git remote set-url");
    assert!(status.success());
    let live_url = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(project.path())
            .args(["config", "--get", "remote.origin.url"])
            .output()
            .expect("read live remote")
            .stdout,
    )
    .unwrap();
    assert_eq!(
        live_url.trim(),
        ATTACKER_REMOTE,
        "sanity: the live worktree's remote must actually be tampered"
    );

    // The default manifest's `github` rule is `Ask(CurrentRepository, …)`;
    // `--grant github` is `grants: ["github"]`.
    let (_, opts) = session
        .agent_launch("claude", &[], &[], &["github".to_owned()])
        .expect("agent_launch");

    assert!(
        opts.refusals.is_empty(),
        "the grant must not be refused: {:?}",
        opts.refusals
    );
    let granted_note = opts
        .notes
        .iter()
        .find(|n| n.starts_with("github:"))
        .unwrap_or_else(|| panic!("no github note in {:?}", opts.notes));
    assert!(
        granted_note.contains(REAL_REPO),
        "grant must still scope to the real repo: {granted_note}"
    );
    assert!(
        !granted_note.contains("attacker-controlled"),
        "grant must never scope to the tampered remote: {granted_note}"
    );

    assert_eq!(opts.gateways.len(), 2, "git + API gateway routes");
    for gw in &opts.gateways {
        let dbg = format!("{:?}", gw.route);
        assert!(
            dbg.contains(REAL_REPO),
            "route must be scoped to the real repo, not the tampered remote: {dbg}"
        );
        assert!(
            !dbg.contains("attacker-controlled") && !dbg.contains("evil-private-repo"),
            "route must never carry the attacker's repo: {dbg}"
        );
    }

    session
        .stop(ward_events::EndReason::UserStop)
        .expect("stop");
}

#[test]
fn no_pinned_remote_at_session_start_means_no_grant_even_if_one_is_added_later() {
    let state = tempfile::tempdir().expect("tempdir");
    seed_vault(state.path());

    // No `origin` remote at all when the session starts.
    let project = tempfile::tempdir().expect("tempdir");
    fs::write(project.path().join("README.md"), "demo\n").expect("write readme");
    let status = Command::new("git")
        .arg("-C")
        .arg(project.path())
        .args(["init", "-q"])
        .status()
        .expect("git init");
    assert!(status.success());

    let session = Session::start_in(project.path(), state.path()).expect("start session");

    // The agent adds a remote after the session (and its entry snapshot)
    // already exist — this must not retroactively give `CurrentRepository`
    // something to resolve to.
    let status = Command::new("git")
        .arg("-C")
        .arg(project.path())
        .args(["remote", "add", "origin", REAL_REMOTE])
        .status()
        .expect("git remote add");
    assert!(status.success());

    let (_, opts) = session
        .agent_launch("claude", &[], &[], &["github".to_owned()])
        .expect("agent_launch");
    assert!(
        opts.gateways.is_empty(),
        "no gateway should be granted: {:?}",
        opts.gateways
    );
    let note = opts
        .notes
        .iter()
        .find(|n| n.starts_with("github:"))
        .unwrap_or_else(|| panic!("no github note in {:?}", opts.notes));
    assert!(
        note.contains("no GitHub origin remote") || note.contains("NoRemote"),
        "{note}"
    );

    session
        .stop(ward_events::EndReason::UserStop)
        .expect("stop");
}
