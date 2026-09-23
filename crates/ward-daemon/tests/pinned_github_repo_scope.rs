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
//! `Session::start_in` now resolves the repository once, at session start,
//! from the live worktree (`github::resolve_origin_repo`), and persists it in
//! `SessionMeta::origin_repo` — `Session::agent_launch` reads that persisted
//! value and never re-reads `.git` itself. This test proves that end to end:
//! it starts a real session over a git worktree whose `origin` points at the
//! real project repo, tampers the *live* worktree's remote exactly as a
//! compromised agent would, and shows `--grant github` still scopes to the
//! real repo. No bubblewrap is required — `agent_launch` only decides the
//! grant and builds the launch options; it does not itself run the sandbox.

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

/// A helper to run `git` in `dir`, asserting success.
fn git_in(dir: &std::path::Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .expect("run git");
    assert!(status.success(), "git -C {} {args:?} failed", dir.display());
}

#[test]
fn a_linked_worktree_created_with_git_worktree_add_resolves_the_main_repos_origin() {
    // `.git` inside a linked worktree is not a directory but a `gitdir: <path>`
    // pointer file naming a private directory under the main repo's own
    // `.git/worktrees/<name>`, whose `commondir` file points back at the main
    // repo's `.git` for `config` — a real, common layout `resolve_origin_repo`
    // must handle, not a contrived one.
    let state = tempfile::tempdir().expect("tempdir");
    seed_vault(state.path());

    let main_repo = git_project(REAL_REMOTE);
    git_in(
        main_repo.path(),
        &["config", "user.email", "test@example.com"],
    );
    git_in(main_repo.path(), &["config", "user.name", "Test"]);
    git_in(
        main_repo.path(),
        &["commit", "--allow-empty", "-q", "-m", "init"],
    );

    let linked_parent = tempfile::tempdir().expect("tempdir");
    let worktree_path = linked_parent.path().join("wt");
    git_in(
        main_repo.path(),
        &[
            "worktree",
            "add",
            "-q",
            worktree_path.to_str().expect("utf8 path"),
            "-b",
            "feature-x",
        ],
    );
    assert!(
        fs::symlink_metadata(worktree_path.join(".git"))
            .expect(".git in linked worktree")
            .is_file(),
        "sanity: a linked worktree's own `.git` must be a `gitdir:` pointer file, not a directory"
    );

    let session = Session::start_in(&worktree_path, state.path()).expect("start session");
    let (_, opts) = session
        .agent_launch("claude", &[], &[], &["github".to_owned()])
        .expect("agent_launch");
    assert!(
        opts.refusals.is_empty(),
        "the grant must not be refused: {:?}",
        opts.refusals
    );
    let note = opts
        .notes
        .iter()
        .find(|n| n.starts_with("github:"))
        .unwrap_or_else(|| panic!("no github note in {:?}", opts.notes));
    assert!(
        note.contains(REAL_REPO),
        "a linked worktree must still resolve the main repository's origin: {note}"
    );

    session
        .stop(ward_events::EndReason::UserStop)
        .expect("stop");
}

#[test]
fn a_submodule_checkout_resolves_its_own_origin_via_its_gitdir_pointer() {
    // A submodule's private git directory (under the superproject's
    // `.git/modules/<name>`) keeps `config` directly — no `commondir`
    // indirection, unlike a linked worktree — the other real `gitdir:` shape
    // `resolve_origin_repo` must handle.
    const SUBMODULE_REPO: &str = "hexrift/libfoo";
    const SUBMODULE_GITHUB_REMOTE: &str = "https://github.com/hexrift/libfoo.git";

    let state = tempfile::tempdir().expect("tempdir");
    seed_vault(state.path());

    // A local upstream the submodule can actually be cloned from; its remote
    // is rewritten to a `github.com` URL afterward so the resolved origin is
    // the one under test, not this test's local filesystem plumbing.
    let submodule_upstream = tempfile::tempdir().expect("tempdir");
    fs::write(submodule_upstream.path().join("README.md"), "demo\n").expect("write readme");
    git_in(submodule_upstream.path(), &["init", "-q"]);
    git_in(
        submodule_upstream.path(),
        &["config", "user.email", "test@example.com"],
    );
    git_in(submodule_upstream.path(), &["config", "user.name", "Test"]);
    git_in(submodule_upstream.path(), &["add", "README.md"]);
    git_in(submodule_upstream.path(), &["commit", "-q", "-m", "init"]);

    let superproject = git_project(REAL_REMOTE);
    git_in(
        superproject.path(),
        &["config", "user.email", "test@example.com"],
    );
    git_in(superproject.path(), &["config", "user.name", "Test"]);
    git_in(
        superproject.path(),
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            submodule_upstream.path().to_str().expect("utf8 path"),
            "libfoo",
        ],
    );
    let submodule_path = superproject.path().join("libfoo");
    git_in(
        &submodule_path,
        &["remote", "set-url", "origin", SUBMODULE_GITHUB_REMOTE],
    );
    assert!(
        fs::symlink_metadata(submodule_path.join(".git"))
            .expect(".git in submodule checkout")
            .is_file(),
        "sanity: a submodule checkout's own `.git` must be a `gitdir:` pointer file, not a directory"
    );

    let session = Session::start_in(&submodule_path, state.path()).expect("start session");
    let (_, opts) = session
        .agent_launch("claude", &[], &[], &["github".to_owned()])
        .expect("agent_launch");
    assert!(
        opts.refusals.is_empty(),
        "the grant must not be refused: {:?}",
        opts.refusals
    );
    let note = opts
        .notes
        .iter()
        .find(|n| n.starts_with("github:"))
        .unwrap_or_else(|| panic!("no github note in {:?}", opts.notes));
    assert!(
        note.contains(SUBMODULE_REPO),
        "a submodule checkout must resolve its own origin, not the superproject's: {note}"
    );

    session
        .stop(ward_events::EndReason::UserStop)
        .expect("stop");
}
