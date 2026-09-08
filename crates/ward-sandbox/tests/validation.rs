//! Privilege-free validation of the generated OCI spec, plus a crun-guarded
//! acceptance check that skips gracefully where crun cannot run.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use ward_sandbox::seccomp::{Action, Profile};
use ward_sandbox::{CrunRuntime, IdMap, Runtime, SandboxSpec};

fn sample() -> SandboxSpec {
    SandboxSpec::new("/host/project", "/host/env", "rootfs")
        .with_hostname("ward-test")
        .with_id_maps(
            IdMap {
                base: 200_000,
                count: 1000,
            },
            IdMap {
                base: 300_000,
                count: 1000,
            },
        )
}

fn strings(v: &Value, ptr: &str) -> Vec<String> {
    v.pointer(ptr)
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn spec_encodes_namespaces_caps_and_privileges() {
    let oci = sample().to_oci().unwrap();

    let mut ns: Vec<String> = oci
        .pointer("/linux/namespaces")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|n| n["type"].as_str().unwrap().to_string())
        .collect();
    ns.sort();
    assert_eq!(
        ns,
        ["cgroup", "ipc", "mount", "network", "pid", "user", "uts"]
    );

    for set in [
        "bounding",
        "effective",
        "inheritable",
        "permitted",
        "ambient",
    ] {
        let caps = oci
            .pointer(&format!("/process/capabilities/{set}"))
            .unwrap();
        assert_eq!(caps.as_array().unwrap().len(), 0, "{set} must be empty");
    }

    assert_eq!(oci["process"]["noNewPrivileges"], Value::Bool(true));
    assert_eq!(oci["root"]["readonly"], Value::Bool(true));
    assert_eq!(oci["root"]["path"], "rootfs");
}

#[test]
fn spec_maps_ids_and_limits() {
    let oci = sample().to_oci().unwrap();

    let uid = &oci["linux"]["uidMappings"][0];
    assert_eq!(uid["containerID"], 0);
    assert_eq!(uid["hostID"], 200_000);
    assert_eq!(uid["size"], 1000);
    assert_eq!(oci["linux"]["gidMappings"][0]["hostID"], 300_000);

    let unified = &oci["linux"]["resources"]["unified"];
    assert_eq!(unified["cpu.weight"], "100");
    assert_eq!(unified["memory.max"], "4294967296");
    assert_eq!(unified["pids.max"], "512");
}

#[test]
fn spec_mounts_worktree_env_tmp_home_and_only_named_devices() {
    let oci = sample().to_oci().unwrap();
    let mounts = oci["mounts"].as_array().unwrap();
    let by_dest = |dest: &str| mounts.iter().find(|m| m["destination"] == dest).cloned();

    let work = by_dest("/work").expect("/work mount");
    assert_eq!(work["source"], "/host/project");
    assert_eq!(work["type"], "bind");
    let work_opts = strings(&work, "/options");
    assert!(work_opts.contains(&"rw".to_string()) && work_opts.contains(&"nodev".to_string()));

    assert_eq!(by_dest("/env").unwrap()["source"], "/host/env");
    assert_eq!(by_dest("/tmp").unwrap()["type"], "tmpfs");
    assert_eq!(by_dest("/home/agent").unwrap()["type"], "tmpfs");

    let devices: Vec<String> = mounts
        .iter()
        .filter(|m| {
            let d = m["destination"].as_str().unwrap();
            d.starts_with("/dev/") && m["type"] == "bind"
        })
        .map(|m| m["destination"].as_str().unwrap().to_string())
        .collect();
    let mut devices = devices;
    devices.sort();
    assert_eq!(
        devices,
        [
            "/dev/null",
            "/dev/random",
            "/dev/tty",
            "/dev/urandom",
            "/dev/zero"
        ]
    );
}

#[test]
fn seccomp_denies_every_required_syscall() {
    let profile = Profile::baseline();
    assert_eq!(profile.default_action, Action::Allow);

    let required = [
        "mount",
        "umount2",
        "move_mount",
        "pivot_root",
        "ptrace",
        "bpf",
        "keyctl",
        "add_key",
        "kexec_load",
        "reboot",
        "init_module",
        "finit_module",
        "delete_module",
        "userfaultfd",
        "io_uring_setup",
    ];
    let denied = profile.denied_names();
    for name in required {
        assert!(denied.contains(&name), "seccomp must deny {name}");
    }

    let action_of = |name: &str| {
        profile
            .syscalls
            .iter()
            .find(|s| s.names.iter().any(|n| n == name))
            .map(|s| s.action)
            .unwrap()
    };
    assert_eq!(action_of("kexec_load"), Action::KillProcess);
    assert_eq!(action_of("reboot"), Action::KillProcess);
    assert_eq!(action_of("io_uring_setup"), Action::Errno);
    assert_eq!(action_of("mount"), Action::Errno);
}

#[test]
fn write_config_emits_parsable_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample().write_config(dir.path()).unwrap();
    assert_eq!(path.file_name().unwrap(), "config.json");
    let parsed: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(parsed["ociVersion"], "1.0.2");
}

/// If crun is available, it must accept our spec structurally. crun validates
/// `config.json` before touching cgroups, so a config-load error means the spec
/// is malformed; any later error (cgroups, rootfs) means the spec was accepted.
/// Skips when crun cannot run at all.
#[test]
fn crun_accepts_generated_spec() {
    let runtime = CrunRuntime::default();
    if !runtime.is_available() {
        eprintln!("skipping: crun not available");
        return;
    }

    let bundle = tempfile::tempdir().unwrap();
    std::fs::create_dir(bundle.path().join("rootfs")).unwrap();
    let spec = SandboxSpec::new(bundle.path(), bundle.path(), "rootfs");
    spec.write_config(bundle.path()).unwrap();

    let id = format!("ward-spec-check-{}", std::process::id());
    match runtime.create(&id, bundle.path()) {
        Ok(()) => {
            let _ = runtime.delete(&id, true);
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                !msg.contains("config.json"),
                "crun rejected the spec schema: {msg}"
            );
        }
    }
}
