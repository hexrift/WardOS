//! Typed OCI runtime-spec builder for the agent sandbox (architecture §6).
//!
//! [`SandboxSpec`] captures the `WardOS` choices as data; [`SandboxSpec::to_oci`]
//! renders them into a `crun`-compatible `config.json` value.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{Result, SandboxError};
use crate::seccomp::Profile;

/// OCI spec version emitted.
const OCI_VERSION: &str = "1.0.2";

/// A contiguous host id range mapped into the user namespace.
///
/// Container ids `0..count` map to host ids `base..base+count`; the agent runs
/// as an unprivileged id inside that never reaches host uid 0.
#[derive(Debug, Clone, Copy)]
pub struct IdMap {
    /// First host (sub)uid/(sub)gid of the range.
    pub base: u32,
    /// Number of ids mapped.
    pub count: u32,
}

/// cgroups v2 resource caps applied to the session scope.
#[derive(Debug, Clone, Copy)]
pub struct CgroupLimits {
    /// `cpu.weight` (1..=10000; 100 is the default share).
    pub cpu_weight: u32,
    /// `memory.max` in bytes.
    pub memory_max: u64,
    /// `pids.max` process count.
    pub pids_max: u32,
}

impl Default for CgroupLimits {
    fn default() -> Self {
        Self {
            cpu_weight: 100,
            memory_max: 4 * 1024 * 1024 * 1024,
            pids_max: 512,
        }
    }
}

/// Declarative description of one agent sandbox.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    /// UTS hostname inside the sandbox.
    pub hostname: String,
    /// Host rootfs directory (mounted read-only).
    pub root_path: PathBuf,
    /// Host project worktree, bind-mounted rw at `/work`.
    pub worktree: PathBuf,
    /// Host project-environment dir, bind-mounted rw at `/env`.
    pub env_dir: PathBuf,
    /// Sandbox `$HOME` (a tmpfs mount point inside).
    pub home: String,
    /// uid range mapped into the user namespace.
    pub uid_map: IdMap,
    /// gid range mapped into the user namespace.
    pub gid_map: IdMap,
    /// uid the agent process runs as inside the sandbox.
    pub process_uid: u32,
    /// gid the agent process runs as inside the sandbox.
    pub process_gid: u32,
    /// Command executed as PID 1 (normally `ward-agent`).
    pub args: Vec<String>,
    /// cgroups v2 limits.
    pub limits: CgroupLimits,
    /// cgroup v2 path for the session scope.
    pub cgroups_path: String,
}

impl SandboxSpec {
    /// A sandbox for `worktree`/`env_dir` rooted at `root_path`, with `WardOS` defaults.
    #[must_use]
    pub fn new(
        worktree: impl Into<PathBuf>,
        env_dir: impl Into<PathBuf>,
        root_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            hostname: "ward-sandbox".to_string(),
            root_path: root_path.into(),
            worktree: worktree.into(),
            env_dir: env_dir.into(),
            home: "/home/agent".to_string(),
            uid_map: IdMap {
                base: 100_000,
                count: 65_536,
            },
            gid_map: IdMap {
                base: 100_000,
                count: 65_536,
            },
            process_uid: 1000,
            process_gid: 1000,
            args: vec!["/bin/true".to_string()],
            limits: CgroupLimits::default(),
            cgroups_path: "/ward.slice/ward-sandbox.scope".to_string(),
        }
    }

    /// Set the UTS hostname.
    #[must_use]
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = hostname.into();
        self
    }

    /// Set the PID 1 command line.
    #[must_use]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Set the subuid/subgid base and range for both maps.
    #[must_use]
    pub fn with_id_maps(mut self, uid: IdMap, gid: IdMap) -> Self {
        self.uid_map = uid;
        self.gid_map = gid;
        self
    }

    /// Set the cgroups v2 limits.
    #[must_use]
    pub fn with_limits(mut self, limits: CgroupLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Render this spec to an OCI runtime-spec JSON value.
    ///
    /// # Errors
    /// Returns [`SandboxError::Serialize`] if the typed spec cannot be encoded.
    pub fn to_oci(&self) -> Result<serde_json::Value> {
        Ok(serde_json::to_value(self.build())?)
    }

    /// Write the rendered spec to `dir/config.json`.
    ///
    /// # Errors
    /// Returns [`SandboxError::Serialize`] on encoding failure or
    /// [`SandboxError::Io`] if the file cannot be written.
    pub fn write_config(&self, dir: impl AsRef<Path>) -> Result<PathBuf> {
        let path = dir.as_ref().join("config.json");
        let json = serde_json::to_vec_pretty(&self.build())?;
        std::fs::write(&path, json).map_err(|source| SandboxError::Io {
            path: path.clone(),
            source,
        })?;
        Ok(path)
    }

    fn build(&self) -> Oci {
        Oci {
            version: OCI_VERSION.to_string(),
            hostname: self.hostname.clone(),
            root: Root {
                path: self.root_path.display().to_string(),
                readonly: true,
            },
            process: Process {
                terminal: false,
                user: User {
                    uid: self.process_uid,
                    gid: self.process_gid,
                },
                args: self.args.clone(),
                env: vec![
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                    format!("HOME={}", self.home),
                    "TERM=xterm".to_string(),
                ],
                cwd: "/work".to_string(),
                capabilities: Capabilities::empty(),
                no_new_privileges: true,
            },
            mounts: self.mounts(),
            linux: Linux {
                namespaces: NAMESPACES
                    .iter()
                    .map(|t| Namespace {
                        ns_type: (*t).to_string(),
                    })
                    .collect(),
                uid_mappings: vec![id_mapping(self.uid_map)],
                gid_mappings: vec![id_mapping(self.gid_map)],
                resources: Resources {
                    unified: self.unified_limits(),
                },
                cgroups_path: self.cgroups_path.clone(),
                seccomp: Profile::baseline(),
            },
        }
    }

    fn unified_limits(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("cpu.weight".to_string(), self.limits.cpu_weight.to_string());
        m.insert("memory.max".to_string(), self.limits.memory_max.to_string());
        m.insert("pids.max".to_string(), self.limits.pids_max.to_string());
        m
    }

    fn mounts(&self) -> Vec<Mount> {
        let mut mounts = vec![
            Mount::fs("/proc", "proc", "proc", &[]),
            Mount::fs(
                "/dev",
                "tmpfs",
                "tmpfs",
                &["nosuid", "strictatime", "mode=755", "size=65536k"],
            ),
            Mount::fs(
                "/dev/pts",
                "devpts",
                "devpts",
                &[
                    "nosuid",
                    "noexec",
                    "newinstance",
                    "ptmxmode=0666",
                    "mode=0620",
                ],
            ),
            Mount::fs(
                "/dev/shm",
                "tmpfs",
                "shm",
                &["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"],
            ),
            Mount::fs(
                "/sys",
                "sysfs",
                "sysfs",
                &["nosuid", "noexec", "nodev", "ro"],
            ),
            Mount::fs(
                "/sys/fs/cgroup",
                "cgroup",
                "cgroup",
                &["nosuid", "noexec", "nodev", "relatime", "ro"],
            ),
        ];
        // Only these device nodes are exposed (architecture §6 devices row).
        for dev in [
            "/dev/null",
            "/dev/zero",
            "/dev/random",
            "/dev/urandom",
            "/dev/tty",
        ] {
            mounts.push(Mount::bind(dev, dev, &["bind", "nosuid", "noexec"]));
        }
        // Writable working surfaces.
        mounts.push(Mount::bind(
            "/work",
            &self.worktree.display().to_string(),
            &["rbind", "nosuid", "nodev", "rw"],
        ));
        mounts.push(Mount::bind(
            "/env",
            &self.env_dir.display().to_string(),
            &["rbind", "nosuid", "nodev", "rw"],
        ));
        mounts.push(Mount::fs(
            "/tmp",
            "tmpfs",
            "tmpfs",
            &["nosuid", "nodev", "mode=1777", "size=1073741824"],
        ));
        mounts.push(Mount::fs(
            &self.home,
            "tmpfs",
            "tmpfs",
            &["nosuid", "nodev", "mode=0700", "size=536870912"],
        ));
        mounts
    }
}

const NAMESPACES: [&str; 7] = ["user", "mount", "pid", "network", "ipc", "uts", "cgroup"];

fn id_mapping(map: IdMap) -> IdMapping {
    IdMapping {
        container_id: 0,
        host_id: map.base,
        size: map.count,
    }
}

#[derive(Serialize)]
struct Oci {
    #[serde(rename = "ociVersion")]
    version: String,
    hostname: String,
    root: Root,
    process: Process,
    mounts: Vec<Mount>,
    linux: Linux,
}

#[derive(Serialize)]
struct Root {
    path: String,
    readonly: bool,
}

#[derive(Serialize)]
struct Process {
    terminal: bool,
    user: User,
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
    capabilities: Capabilities,
    #[serde(rename = "noNewPrivileges")]
    no_new_privileges: bool,
}

#[derive(Serialize)]
struct User {
    uid: u32,
    gid: u32,
}

#[derive(Serialize)]
struct Capabilities {
    bounding: Vec<String>,
    effective: Vec<String>,
    inheritable: Vec<String>,
    permitted: Vec<String>,
    ambient: Vec<String>,
}

impl Capabilities {
    fn empty() -> Self {
        Self {
            bounding: vec![],
            effective: vec![],
            inheritable: vec![],
            permitted: vec![],
            ambient: vec![],
        }
    }
}

#[derive(Serialize)]
struct Mount {
    destination: String,
    #[serde(rename = "type")]
    fs_type: String,
    source: String,
    options: Vec<String>,
}

impl Mount {
    fn fs(destination: &str, fs_type: &str, source: &str, options: &[&str]) -> Self {
        Self {
            destination: destination.to_string(),
            fs_type: fs_type.to_string(),
            source: source.to_string(),
            options: options.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn bind(destination: &str, source: &str, options: &[&str]) -> Self {
        Self {
            destination: destination.to_string(),
            fs_type: "bind".to_string(),
            source: source.to_string(),
            options: options.iter().map(|s| (*s).to_string()).collect(),
        }
    }
}

#[derive(Serialize)]
struct Linux {
    namespaces: Vec<Namespace>,
    #[serde(rename = "uidMappings")]
    uid_mappings: Vec<IdMapping>,
    #[serde(rename = "gidMappings")]
    gid_mappings: Vec<IdMapping>,
    resources: Resources,
    #[serde(rename = "cgroupsPath")]
    cgroups_path: String,
    seccomp: Profile,
}

#[derive(Serialize)]
struct Namespace {
    #[serde(rename = "type")]
    ns_type: String,
}

#[derive(Serialize)]
struct IdMapping {
    #[serde(rename = "containerID")]
    container_id: u32,
    #[serde(rename = "hostID")]
    host_id: u32,
    size: u32,
}

#[derive(Serialize)]
struct Resources {
    unified: BTreeMap<String, String>,
}
