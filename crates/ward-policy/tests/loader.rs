//! Loading the three layers from disk.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;

use ward_policy::{
    Decision, FsAccess, LoadError, MAX_POLICY_FILE_BYTES, NetworkMode, ServiceId, default_policy,
    load_layers,
};

fn write(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    fs::write(&p, body).unwrap();
    p
}

#[test]
fn missing_everything_yields_builtin_defaults_and_empty_lower_layers() {
    let tmp = tempfile::tempdir().unwrap();
    let layers = load_layers(&tmp.path().join("nope"), None, None).unwrap();
    assert_eq!(layers.system, default_policy().unwrap());
    assert!(layers.user.is_empty());
    assert!(layers.project.is_empty());
    assert!(layers.sources.system_files.is_empty());
    assert_eq!(layers.sources.user_file, None);
    assert_eq!(layers.sources.project_file, None);
}

#[test]
fn absent_user_and_project_files_are_empty_policies() {
    let tmp = tempfile::tempdir().unwrap();
    let layers = load_layers(
        tmp.path(),
        Some(&tmp.path().join("user.yaml")),
        Some(&tmp.path().join("project.yaml")),
    )
    .unwrap();
    assert!(layers.user.is_empty());
    assert!(layers.project.is_empty());
}

#[test]
fn system_dir_files_overlay_in_sorted_order() {
    let tmp = tempfile::tempdir().unwrap();
    let sys = tmp.path().join("policy.d");
    fs::create_dir(&sys).unwrap();
    write(
        &sys,
        "50-b.yaml",
        "agent:\n  filesystem:\n    repo: read\n  secrets:\n    extra: allow\n",
    );
    write(
        &sys,
        "10-a.yaml",
        "agent:\n  filesystem:\n    repo: write\n  network:\n    mode: offline\n",
    );
    write(
        &sys,
        "90-c.yml",
        "agent:\n  network:\n    mode: package-registries\n",
    );
    write(&sys, "README.md", "not a policy");
    write(
        &sys,
        ".hidden.yaml",
        "agent:\n  containers:\n    allow: false\n",
    );
    let layers = load_layers(&sys, None, None).unwrap();
    let names: Vec<String> = layers
        .sources
        .system_files
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["10-a.yaml", "50-b.yaml", "90-c.yml"]);
    let s = &layers.system;
    assert_eq!(
        s.agent.filesystem.as_ref().unwrap().repo,
        Some(FsAccess::Read)
    );
    assert_eq!(
        s.agent.network.as_ref().unwrap().mode,
        NetworkMode::PackageRegistries
    );
    let secrets = s.agent.secrets.as_ref().unwrap();
    assert_eq!(
        secrets[&ServiceId::new("extra").unwrap()].decision,
        Decision::Allow
    );
    assert_eq!(
        secrets[&ServiceId::new("github").unwrap()].decision,
        Decision::Ask,
        "defaults retained"
    );
    assert!(s.agent.containers.unwrap().allow, "hidden file ignored");
}

#[test]
fn user_and_project_files_are_read() {
    let tmp = tempfile::tempdir().unwrap();
    let user = write(
        tmp.path(),
        "user.yaml",
        "agent:\n  containers:\n    allow: false\n",
    );
    let project = write(tmp.path(), "project.yaml", "observer:\n  default: quiet\n");
    let layers = load_layers(&tmp.path().join("none"), Some(&user), Some(&project)).unwrap();
    assert!(!layers.user.agent.containers.unwrap().allow);
    assert_eq!(
        layers.project.observer.default,
        Some(ward_policy::ObserverLevel::Quiet)
    );
    assert_eq!(layers.sources.user_file.as_deref(), Some(user.as_path()));
    assert_eq!(
        layers.sources.project_file.as_deref(),
        Some(project.as_path())
    );
}

#[test]
fn invalid_project_file_is_an_error_with_path() {
    let tmp = tempfile::tempdir().unwrap();
    let project = write(
        tmp.path(),
        "project.yaml",
        "agent:\n  filesystem:\n    host: allow\n",
    );
    let err = load_layers(&tmp.path().join("none"), None, Some(&project)).unwrap_err();
    match err {
        LoadError::Policy { path, source } => {
            assert_eq!(path, project);
            assert!(matches!(
                source,
                ward_policy::PolicyError::HostFilesystemNotDeny(_)
            ));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn oversized_file_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let mut body = String::from("# padding\n");
    while (body.len() as u64) <= MAX_POLICY_FILE_BYTES {
        body.push_str("# 0123456789012345678901234567890123456789\n");
    }
    let project = write(tmp.path(), "project.yaml", &body);
    let err = load_layers(&tmp.path().join("none"), None, Some(&project)).unwrap_err();
    assert!(
        matches!(err, LoadError::TooLarge { limit, .. } if limit == MAX_POLICY_FILE_BYTES),
        "{err}"
    );
    // Exactly at the cap is fine.
    body.truncate(usize::try_from(MAX_POLICY_FILE_BYTES).unwrap());
    let project = write(tmp.path(), "project2.yaml", &body);
    load_layers(&tmp.path().join("none"), None, Some(&project)).unwrap();
}

#[cfg(unix)]
#[test]
fn symlinked_policy_file_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let target = write(tmp.path(), "real.yaml", "observer:\n  default: live\n");
    let link = tmp.path().join("project.yaml");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let err = load_layers(&tmp.path().join("none"), None, Some(&link)).unwrap_err();
    assert!(matches!(err, LoadError::Symlink { .. }), "{err}");
    // Also inside the system directory.
    let sys = tmp.path().join("policy.d");
    fs::create_dir(&sys).unwrap();
    std::os::unix::fs::symlink(&target, sys.join("10-link.yaml")).unwrap();
    let err = load_layers(&sys, None, None).unwrap_err();
    assert!(matches!(err, LoadError::Symlink { .. }), "{err}");
}

#[test]
fn directory_as_policy_file_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("project.yaml");
    fs::create_dir(&dir).unwrap();
    let err = load_layers(&tmp.path().join("none"), None, Some(&dir)).unwrap_err();
    assert!(matches!(err, LoadError::NotRegularFile { .. }), "{err}");
}

#[test]
fn invalid_system_file_fails_the_whole_load() {
    let tmp = tempfile::tempdir().unwrap();
    let sys = tmp.path().join("policy.d");
    fs::create_dir(&sys).unwrap();
    write(&sys, "10-ok.yaml", "observer:\n  default: quiet\n");
    write(
        &sys,
        "20-bad.yaml",
        "agent:\n  network:\n    mode: development\n    deny_private_networks: false\n",
    );
    let err = load_layers(&sys, None, None).unwrap_err();
    assert!(matches!(err, LoadError::Policy { .. }), "{err}");
}

#[test]
fn non_utf8_policy_file_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project.yaml");
    fs::write(&project, [0xff, 0xfe, b'a']).unwrap();
    let err = load_layers(&tmp.path().join("none"), None, Some(&project)).unwrap_err();
    assert!(matches!(err, LoadError::Io { .. }), "{err}");
}
