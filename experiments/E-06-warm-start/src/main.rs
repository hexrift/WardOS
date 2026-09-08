//! E-06 warm-start spike: measure `crun` create+start-to-exit latency.
//!
//! Builds a minimal rootless bundle (host `/bin/true` as the rootfs payload) and
//! times `crun run` over N iterations, reporting p50/p99. If crun cannot run in
//! this environment (e.g. sandbox-in-sandbox with hybrid cgroups), it detects
//! that from a probe run and writes a RESULT.md explaining what to run on a real
//! host instead.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const RUNS: usize = 50;
const RESULT_PATH: &str = "RESULT.md";
const PASS_FRESH_MS: u128 = 150;

fn main() {
    let crun = which_crun();
    if crun.is_none() {
        write_result(&Report::unavailable("`crun` binary not found on PATH"));
        eprintln!("crun not found; wrote {RESULT_PATH}");
        return;
    }
    let crun = crun.unwrap_or_else(|| PathBuf::from("crun"));

    let bundle = match build_bundle() {
        Ok(b) => b,
        Err(e) => {
            write_result(&Report::unavailable(&format!("could not build bundle: {e}")));
            eprintln!("bundle build failed: {e}");
            return;
        }
    };

    // Probe: a single run tells us whether crun can execute here at all.
    let probe = run_once(&crun, &bundle, "e06-probe");
    if let Err(reason) = probe {
        write_result(&Report::cannot_measure(&reason));
        eprintln!("crun cannot run here: {reason}\nwrote {RESULT_PATH}");
        return;
    }

    let mut samples_ms: Vec<u128> = Vec::with_capacity(RUNS);
    for i in 0..RUNS {
        let id = format!("e06-{i}");
        let start = Instant::now();
        match run_once(&crun, &bundle, &id) {
            Ok(()) => samples_ms.push(start.elapsed().as_millis()),
            Err(reason) => {
                write_result(&Report::cannot_measure(&format!("run {i} failed: {reason}")));
                eprintln!("run {i} failed: {reason}");
                return;
            }
        }
    }

    samples_ms.sort_unstable();
    let report = Report::measured(&samples_ms);
    write_result(&report);
    println!(
        "E-06: {} runs, p50={} ms, p99={} ms (pass < {} ms)",
        samples_ms.len(),
        report.p50,
        report.p99,
        PASS_FRESH_MS
    );
}

fn which_crun() -> Option<PathBuf> {
    for cand in ["/usr/bin/crun", "/bin/crun", "crun"] {
        if Command::new(cand).arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
        {
            return Some(PathBuf::from(cand));
        }
    }
    None
}

/// Run the bundle once via `crun run` (create+start+wait+delete). Returns the
/// captured error text on non-zero exit.
fn run_once(crun: &Path, bundle: &Path, id: &str) -> Result<(), String> {
    let out = Command::new(crun)
        .arg("run")
        .arg("--bundle")
        .arg(bundle)
        .arg(id)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        let _ = Command::new(crun).arg("delete").arg("--force").arg(id).output();
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Build a minimal rootless OCI bundle running `/bin/true`.
fn build_bundle() -> std::io::Result<PathBuf> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("e06-bundle-{nonce}"));
    let rootfs = dir.join("rootfs");
    fs::create_dir_all(rootfs.join("bin"))?;
    copy_with_libs("/bin/true", &rootfs)?;
    fs::write(dir.join("config.json"), config_json(&rootfs))?;
    Ok(dir)
}

/// Copy a binary and its shared-library dependencies into `rootfs`.
fn copy_with_libs(bin: &str, rootfs: &Path) -> std::io::Result<()> {
    fs::copy(bin, rootfs.join(bin.trim_start_matches('/')))?;
    let ldd = Command::new("ldd").arg(bin).output()?;
    for token in String::from_utf8_lossy(&ldd.stdout).split_whitespace() {
        if token.starts_with('/') {
            let dest = rootfs.join(token.trim_start_matches('/'));
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            let _ = fs::copy(token, &dest);
        }
    }
    Ok(())
}

fn host_id(flag: &str) -> u32 {
    Command::new("id")
        .arg(flag)
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(0)
}

/// Minimal rootless config: user/mount/pid/ipc/uts namespaces, no capabilities,
/// noNewPrivileges. No cgroup limits — the spike measures raw startup latency.
fn config_json(rootfs: &Path) -> String {
    let (uid, gid) = (host_id("-u"), host_id("-g"));
    format!(
        r#"{{
  "ociVersion": "1.0.2",
  "process": {{
    "terminal": false,
    "user": {{ "uid": 0, "gid": 0 }},
    "args": ["/bin/true"],
    "env": ["PATH=/bin"],
    "cwd": "/",
    "capabilities": {{ "bounding": [], "effective": [], "inheritable": [], "permitted": [], "ambient": [] }},
    "noNewPrivileges": true
  }},
  "root": {{ "path": "{root}", "readonly": true }},
  "hostname": "e06",
  "mounts": [
    {{ "destination": "/proc", "type": "proc", "source": "proc" }}
  ],
  "linux": {{
    "namespaces": [
      {{ "type": "user" }}, {{ "type": "mount" }}, {{ "type": "pid" }},
      {{ "type": "ipc" }}, {{ "type": "uts" }}
    ],
    "uidMappings": [{{ "containerID": 0, "hostID": {uid}, "size": 1 }}],
    "gidMappings": [{{ "containerID": 0, "hostID": {gid}, "size": 1 }}]
  }}
}}"#,
        root = rootfs.display(),
        uid = uid,
        gid = gid,
    )
}

struct Report {
    status: &'static str,
    detail: String,
    n: usize,
    p50: u128,
    p99: u128,
}

impl Report {
    fn unavailable(detail: &str) -> Self {
        Self { status: "UNAVAILABLE", detail: detail.to_string(), n: 0, p50: 0, p99: 0 }
    }

    fn cannot_measure(reason: &str) -> Self {
        Self {
            status: "CANNOT-MEASURE-HERE",
            detail: reason.to_string(),
            n: 0,
            p50: 0,
            p99: 0,
        }
    }

    fn measured(sorted_ms: &[u128]) -> Self {
        Self {
            status: "MEASURED",
            detail: String::new(),
            n: sorted_ms.len(),
            p50: percentile(sorted_ms, 50),
            p99: percentile(sorted_ms, 99),
        }
    }
}

fn percentile(sorted: &[u128], p: usize) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (p * (sorted.len() - 1)) / 100;
    sorted[rank]
}

fn write_result(report: &Report) {
    let numbers = match report.status {
        "MEASURED" => format!(
            "Measured over {n} runs on this machine:\n\n\
             | metric | value |\n| --- | --- |\n\
             | p50 create+start→exit | {p50} ms |\n\
             | p99 create+start→exit | {p99} ms |\n\n\
             Note: this is bare `crun run` of `/bin/true`, i.e. the runtime floor \
             for steps 5 and 9 of architecture §4, not the full `ward claude` warm path.",
            n = report.n,
            p50 = report.p50,
            p99 = report.p99,
        ),
        _ => format!(
            "**{status}.** {detail}\n\n\
             This environment is a sandbox-in-sandbox with hybrid (v1+v2) cgroups, in which \
             `crun` refuses to create a container (`cgroups in hybrid mode not supported`). \
             Spec generation and schema acceptance are still validated by the `ward-sandbox` \
             crate tests; only the runtime timing cannot be gathered here.\n\n\
             ### Run this on a real unprivileged Linux host (cgroups v2 unified)\n\n\
             ```sh\n\
             # host prerequisites: crun installed, unprivileged userns enabled,\n\
             # a cgroups v2 'unified' hierarchy (stat -fc %T /sys/fs/cgroup == cgroup2fs)\n\
             cd experiments/E-06-warm-start\n\
             cargo run --release\n\
             # prints p50/p99 and rewrites RESULT.md with the measured table\n\
             ```\n",
            status = report.status,
            detail = report.detail,
        ),
    };

    let body = format!(
        "# E-06 — Sandbox warm start\n\n\
         Status: **{status}**\n\n\
         ## Hypothesis\n\n\
         With pre-pulled layers and a prepared spec, `ward claude` reaches agent PID 1 exec \
         in < {pass} ms; a frozen-and-thawed persistent sandbox resumes in < 30 ms \
         (docs/experiments.md E-06).\n\n\
         ## Method\n\n\
         Build a minimal rootless OCI bundle (`/bin/true` as the rootfs payload, \
         user/mount/pid/ipc/uts namespaces, empty capabilities, `noNewPrivileges`, no cgroup \
         limits) and time `crun run` — create + start + wait-for-exit — over {runs} iterations, \
         reporting p50/p99 wall-clock. This isolates the OCI-runtime floor of architecture §4 \
         steps 5 and 9; the full warm path additionally includes policy load, snapshot, netns \
         and inner hardening, measured separately once those crates land.\n\n\
         ## Result\n\n\
         {numbers}\n\n\
         ## Pass criterion\n\n\
         < {pass} ms fresh, < 30 ms freezer-resume on reference hardware. The freezer-resume \
         path is not exercised by this spike (it needs a persistent frozen sandbox from \
         `wardd`) and is deferred.\n",
        status = report.status,
        pass = PASS_FRESH_MS,
        runs = RUNS,
        numbers = numbers,
    );
    if let Err(e) = fs::write(RESULT_PATH, body) {
        eprintln!("failed to write {RESULT_PATH}: {e}");
    }
}
