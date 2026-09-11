//! `ward verify`: a disposable Zone 2 verifier (ADR-0004, 0.1 namespace form).
//!
//! The candidate is a snapshot, materialised from the CAS into a scratch tree; the
//! verification config and every protected path come from the *entry* snapshot, so
//! an agent that edits a protected test only changes what the verifier overwrites.
//! The command runs in a bare sandbox with no egress and the host toolchains bound
//! read-only, and the parsed result is what the session records.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use ward_events::VerifySummary;
use ward_snapshot::{CaptureOptions, EntryType, SnapshotId, SnapshotRole, SnapshotStore};

use crate::error::{Error, Result};
use crate::sandbox::{Launch, StdioMode};

/// Where the project keeps its `TamperWard` config.
pub const CONFIG_PATH: &str = ".tamperward/config.yml";
/// Mount point of the verifier toolchains inside the sandbox.
const TOOLCHAIN_ROOT: &str = "/run/verifier";

/// Per-process counter that gives every `prepare` call a fresh, private scratch tree, so
/// no verifier run can inherit a symlink or altered file from an earlier one (#122).
static SCRATCH_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The parts of `.tamperward/config.yml` the verifier needs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct Config {
    /// Paths only the verifier may decide about.
    #[serde(default)]
    pub protected: Protected,
    /// What to run.
    #[serde(default)]
    pub verify: VerifyCommand,
}

/// Protected surfaces.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct Protected {
    /// Worktree-relative test files (or `dir/` prefixes).
    #[serde(default)]
    pub tests: Vec<String>,
}

/// The verification command.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct VerifyCommand {
    /// Shell command run at the root of the candidate tree.
    #[serde(default)]
    pub command: String,
    /// Wall-clock budget in seconds; the verifier is killed past it.
    #[serde(default = "default_budget_secs")]
    pub budget_secs: u64,
}

impl Default for VerifyCommand {
    fn default() -> Self {
        Self {
            command: String::new(),
            budget_secs: default_budget_secs(),
        }
    }
}

const fn default_budget_secs() -> u64 {
    600
}

/// Captured output kept in the result document; the rest is dropped with a marker.
pub const MAX_OUTPUT_BYTES: usize = 1 << 20;

impl Config {
    /// Parse the config; an empty command is a configuration error.
    pub fn parse(yaml: &str) -> Result<Self> {
        let config: Self = serde_yaml::from_str(yaml)
            .map_err(|e| Error::Project(format!("{CONFIG_PATH}: {e}")))?;
        if config.verify.command.trim().is_empty() {
            return Err(Error::Project(format!(
                "{CONFIG_PATH}: verify.command is empty"
            )));
        }
        Ok(config)
    }
}

/// A verification prepared but not yet run.
pub struct Verification {
    /// The candidate snapshot.
    pub candidate: SnapshotId,
    /// Config as read from the entry snapshot.
    pub config: Config,
    /// BLAKE3 of the config bytes.
    pub manifest_hash: [u8; 32],
    /// Protected paths whose candidate bytes differed from pristine and were replaced.
    pub restored: Vec<String>,
    /// The materialised tree the command runs over.
    pub scratch: PathBuf,
}

/// How the worktree is captured as a candidate. The shell digests the worktree
/// with the same options (ADR-0019 decision 1), so the id it computes is the
/// one a `VerificationPassed` record names and `VERIFY ✓` means "this tree".
#[must_use]
pub fn candidate_options() -> CaptureOptions {
    CaptureOptions::default()
}

/// Snapshot the worktree as the candidate, then build the verifier tree under
/// `scratch_root`: the candidate with every protected path taken from `entry`.
pub fn prepare(
    store: &SnapshotStore,
    worktree: &Path,
    entry: SnapshotId,
    scratch_root: &Path,
) -> Result<Verification> {
    let snap = |e: ward_snapshot::SnapshotError| Error::Snapshot(e.to_string());
    let candidate = store
        .store_snapshot(worktree, SnapshotRole::Candidate, candidate_options())
        .map_err(snap)?;
    let yaml = store
        .cat(entry, Path::new(CONFIG_PATH))
        .map_err(|_| Error::Project(format!("{CONFIG_PATH} missing from the entry snapshot")))?;
    let config = Config::parse(&String::from_utf8_lossy(&yaml))?;
    let manifest_hash = *blake3::hash(&yaml).as_bytes();

    // A fresh, private destination created *exclusively*: `fresh_scratch` makes a brand-new
    // empty directory with `create_dir` (which fails if the path already exists) and tries
    // another name on collision, so materialisation always writes into a directory proven
    // empty — no verifier run can inherit a symlink or altered file a previous one left, even
    // after a daemon restart or PID reuse (the name carries a nanosecond clock) (#122).
    let scratch = fresh_scratch(scratch_root, &candidate.digest().to_hex()[..12])?;
    store.materialize(candidate, &scratch).map_err(snap)?;

    // Restoration is driven by the ENTRY snapshot's manifest — its kind, content and mode —
    // never by what the candidate materialised: a candidate that turned a protected file into
    // a symlink cannot make us follow it, and a protected entry symlink is restored as a
    // symlink rather than flattened into a regular file holding its target bytes (#122).
    let entry_manifest = store.manifest(entry).map_err(snap)?;
    let entry_by_path: std::collections::HashMap<&[u8], &ward_snapshot::Entry> = entry_manifest
        .entries()
        .iter()
        .map(|e| (e.path.as_slice(), e))
        .collect();
    let mut restored = Vec::new();
    for rel in protected_files(store, entry, candidate, &config.protected.tests)? {
        let rel = &rel;
        // Resolve the destination inside `scratch` WITHOUT following any candidate symlink:
        // every ancestor is proven — or created — as a real directory, and the leaf is
        // inspected with a non-following lstat. Otherwise a candidate could symlink a
        // protected file, or its parent, to a host path and make this overlay read or write
        // outside the verifier tree with the daemon's authority, before the sandbox starts.
        let target = overlay_dest(&scratch, rel)?;
        let leaf = std::fs::symlink_metadata(&target).ok();
        match entry_by_path.get(rel.as_bytes()) {
            // A protected regular file: restore its exact bytes AND mode. Equal bytes with a
            // candidate-altered mode is not "already correct", so the mode is compared too.
            Some(ent) if ent.kind == EntryType::File => {
                let bytes = store.cat(entry, Path::new(rel)).map_err(snap)?;
                let mode = ent.mode & 0o7777;
                if let Some(m) = &leaf {
                    if m.file_type().is_file()
                        && m.permissions().mode() & 0o7777 == mode
                        && std::fs::read(&target).ok().as_deref() == Some(bytes.as_slice())
                    {
                        continue;
                    }
                    remove_planted(&target, m)?;
                }
                std::fs::write(&target, &bytes).map_err(|e| Error::io(&target, e))?;
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode))
                    .map_err(|e| Error::io(&target, e))?;
            }
            // A protected symlink: restore it AS a symlink to the entry's stored target,
            // never followed and never flattened into a regular file.
            Some(ent) if ent.kind == EntryType::Symlink => {
                let link = store.cat(entry, Path::new(rel)).map_err(snap)?;
                if let Some(m) = &leaf {
                    if m.file_type().is_symlink()
                        && std::fs::read_link(&target)
                            .is_ok_and(|t| t.as_os_str().as_bytes() == link.as_slice())
                    {
                        continue;
                    }
                    remove_planted(&target, m)?;
                }
                std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(&link), &target)
                    .map_err(|e| Error::io(&target, e))?;
            }
            // The entry carries this protected path as a directory, submodule or an
            // unsupported node: it is not a restorable leaf, so fail closed rather than guess.
            Some(_) => {
                return Err(Error::Project(format!(
                    "protected path {rel:?} is not a file or symlink in the entry snapshot"
                )));
            }
            // Candidate-only: the entry has no such protected path, so nothing may stand in
            // for it — remove any candidate copy, a real file or a planted symlink/directory,
            // unlinked in place and never followed.
            None => match &leaf {
                Some(m) => remove_planted(&target, m)?,
                None => continue,
            },
        }
        restored.push(rel.clone());
    }
    Ok(Verification {
        candidate,
        config,
        manifest_hash,
        restored,
        scratch,
    })
}

/// The overlay destination for `rel` inside `scratch`, with every ancestor proven — or,
/// when missing, created — as a real directory, and no candidate symlink ever followed.
/// A candidate that replaced an ancestor with a symlink (or any non-directory) is the
/// #122 escape, so preparation is refused here and the verifier fails closed rather than
/// writing trusted bytes through the link. The leaf itself is returned untouched; the
/// caller inspects it with a non-following `symlink_metadata`.
fn overlay_dest(scratch: &Path, rel: &str) -> Result<PathBuf> {
    let mut cur = scratch.to_path_buf();
    let segs: Vec<&str> = rel.split('/').collect();
    for (i, seg) in segs.iter().enumerate() {
        if seg.is_empty() || *seg == "." || *seg == ".." {
            return Err(Error::Project(format!("unsafe protected path {rel:?}")));
        }
        cur.push(seg);
        if i + 1 == segs.len() {
            break; // the leaf is the caller's to inspect and replace, never followed here
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_dir() => {} // a real directory: safe to descend
            Ok(_) => {
                return Err(Error::Project(format!(
                    "unsafe protected path {rel:?}: {} is not a real directory in the candidate",
                    cur.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&cur).map_err(|e| Error::io(&cur, e))?;
            }
            Err(e) => return Err(Error::io(&cur, e)),
        }
    }
    Ok(cur)
}

/// Remove a candidate-planted entry inside scratch without following it: a symlink or a
/// regular file is unlinked in place (never its target), a directory is removed whole.
/// `meta` must come from a non-following `symlink_metadata`.
fn remove_planted(path: &Path, meta: &std::fs::Metadata) -> Result<()> {
    let r = if meta.file_type().is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    r.map_err(|e| Error::io(path, e))
}

/// A brand-new, private scratch directory under `root`. The name carries the candidate
/// `tag`, the pid, a nanosecond clock and a per-process counter, so it does not repeat even
/// across a daemon restart or PID reuse; [`create_fresh_dir`] then makes it *exclusively*,
/// so materialisation always writes into a directory proven empty (#122).
fn fresh_scratch(root: &Path, tag: &str) -> Result<PathBuf> {
    let pid = std::process::id();
    let tag = tag.to_owned();
    create_fresh_dir(
        root,
        std::iter::repeat_with(move || {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let seq = SCRATCH_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            format!("verify-{tag}-{pid}-{nanos}-{seq}")
        }),
    )
}

/// Create the first of `names` under `root` that does not already exist, with `create_dir`
/// (never `create_dir_all`), so the returned directory is genuinely new and empty and a
/// leftover a previous run planted at any candidate name is skipped rather than reused
/// (#122). Bounded to the first 64 names so an all-colliding iterator cannot spin forever.
fn create_fresh_dir(root: &Path, names: impl Iterator<Item = String>) -> Result<PathBuf> {
    std::fs::create_dir_all(root).map_err(|e| Error::io(root, e))?;
    for name in names.take(64) {
        let dir = root.join(name);
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {} // taken: try the next name
            Err(e) => return Err(Error::io(&dir, e)),
        }
    }
    Err(Error::Project(
        "could not create a fresh verifier scratch directory".to_owned(),
    ))
}

/// Expand `protected.tests` into the files the verifier restores, in manifest order
/// with no duplicates. A `dir/`, `dir/**` or `dir/*` entry, or one naming a directory
/// in either snapshot, means every file under it: those in the entry snapshot (restored
/// to their pristine bytes) and those only in the candidate (removed, so a test added
/// beside the protected ones cannot stand in for them). Anything else is one file.
fn protected_files(
    store: &SnapshotStore,
    entry: SnapshotId,
    candidate: SnapshotId,
    patterns: &[String],
) -> Result<Vec<String>> {
    let snap = |e: ward_snapshot::SnapshotError| Error::Snapshot(e.to_string());
    let manifests = [
        store.manifest(entry).map_err(snap)?,
        store.manifest(candidate).map_err(snap)?,
    ];
    let files: Vec<&str> = manifests
        .iter()
        .flat_map(ward_snapshot::Manifest::entries)
        .filter(|e| e.kind == EntryType::File)
        .filter_map(|e| std::str::from_utf8(&e.path).ok())
        .collect();
    let dirs: Vec<&str> = manifests
        .iter()
        .flat_map(ward_snapshot::Manifest::entries)
        .filter(|e| e.kind == EntryType::Dir)
        .filter_map(|e| std::str::from_utf8(&e.path).ok())
        .collect();
    // Every symlink path in either snapshot. Under a protected directory these must be
    // enumerated alongside the files, so the manifest-driven overlay reaches them: an entry
    // symlink is restored to its exact stored target — a candidate that keeps the path a
    // symlink but redirects it cannot slip candidate-controlled content past the verifier —
    // and a candidate-only symlink stand-in is removed (#122). Restoration decides per path
    // from the entry manifest, so listing entry and candidate symlinks together is safe.
    let links: Vec<&str> = manifests
        .iter()
        .flat_map(ward_snapshot::Manifest::entries)
        .filter(|e| e.kind == EntryType::Symlink)
        .filter_map(|e| std::str::from_utf8(&e.path).ok())
        .collect();
    let mut out: Vec<String> = Vec::new();
    for pattern in patterns {
        let stem = pattern
            .strip_suffix("/**")
            .or_else(|| pattern.strip_suffix("/*"))
            .or_else(|| pattern.strip_suffix('/'))
            .map(|s| s.trim_end_matches('/'));
        let dir = match stem {
            Some(d) => Some(d),
            None if dirs.contains(&pattern.as_str()) => Some(pattern.as_str()),
            None => None,
        };
        let matched: Vec<&str> = match dir {
            Some(d) => {
                let prefix = format!("{d}/");
                files
                    .iter()
                    .chain(links.iter())
                    .copied()
                    .filter(|f| f.starts_with(&prefix))
                    .collect()
            }
            None => vec![pattern.as_str()],
        };
        for f in matched {
            if !out.iter().any(|o| o == f) {
                out.push(f.to_owned());
            }
        }
    }
    Ok(out)
}

/// What the verifier produced.
pub struct Outcome {
    /// Whether the command succeeded.
    pub passed: bool,
    /// Counts parsed from the output.
    pub summary: VerifySummary,
    /// Combined stdout and stderr.
    pub output: String,
    /// BLAKE3 of `output`: the result document's hash in the log.
    pub result_hash: [u8; 32],
}

/// Run the verification command over the prepared tree, offline, with the host
/// toolchains read-only.
pub fn execute(v: &Verification) -> Result<Outcome> {
    let argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        v.config.verify.command.clone(),
    ];
    let mut launch = Launch::new(&v.scratch, argv)
        .stdio(StdioMode::Capture)
        .budget(Duration::from_secs(v.config.verify.budget_secs));
    for (k, val) in Toolchains::detect().env() {
        launch = launch.env(k, val);
    }
    launch = Toolchains::detect().mount(launch);
    let out = launch.run()?;
    let mut output = cap(format!("{}{}", out.stdout, out.stderr));
    if out.timed_out {
        use std::fmt::Write as _;
        let _ = write!(
            output,
            "\nverifier budget of {}s exceeded; killed\n",
            v.config.verify.budget_secs
        );
    }
    let mut summary = parse_summary(&output);
    summary.steps_total = 1;
    summary.duration = out.duration;
    let passed = out.code == Some(0) && !out.timed_out;
    if passed {
        summary.steps_passed = 1;
    } else {
        summary.steps_failed = 1;
    }
    Ok(Outcome {
        passed,
        summary,
        result_hash: *blake3::hash(output.as_bytes()).as_bytes(),
        output,
    })
}

/// Keep the first [`MAX_OUTPUT_BYTES`] of `output` (on a char boundary) with a marker.
fn cap(mut output: String) -> String {
    if output.len() > MAX_OUTPUT_BYTES {
        let mut end = MAX_OUTPUT_BYTES;
        while !output.is_char_boundary(end) {
            end -= 1;
        }
        output.truncate(end);
        output.push_str("\n[verifier output truncated]\n");
    }
    output
}

/// Per-test counts from `cargo test` style result lines
/// (`test result: ok. 3 passed; 1 failed; ...`); zero when the runner prints none.
#[must_use]
pub fn parse_summary(output: &str) -> VerifySummary {
    let mut summary = VerifySummary::default();
    for line in output.lines().filter(|l| l.starts_with("test result:")) {
        for part in line.split(';') {
            let mut words = part.split_whitespace().rev();
            let (Some(kind), Some(n)) = (words.next(), words.next()) else {
                continue;
            };
            let Ok(n) = n.parse::<u64>() else {
                continue;
            };
            match kind {
                "passed" => summary.tests_run += n,
                "failed" => {
                    summary.tests_run += n;
                    summary.tests_failed += n;
                }
                _ => {}
            }
        }
    }
    summary
}

/// Host toolchains the verifier gets read-only, the 0.1 stand-in for a verifier
/// image: a Rust toolchain from `$RUSTUP_HOME`/`~/.rustup` and `$CARGO_HOME`/`~/.cargo`
/// (binaries and registry only; the cargo home itself is a private tmpfs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Toolchains {
    rustup: Option<PathBuf>,
    cargo: Option<PathBuf>,
}

impl Toolchains {
    /// Look the toolchains up on this host.
    #[must_use]
    pub fn detect() -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let find = |var: &str, dot: &str| {
            std::env::var_os(var)
                .map(PathBuf::from)
                .or_else(|| home.as_ref().map(|h| h.join(dot)))
                .filter(|p| p.is_dir())
        };
        Self {
            rustup: find("RUSTUP_HOME", ".rustup"),
            cargo: find("CARGO_HOME", ".cargo"),
        }
    }

    /// Whether a Rust toolchain is available to the verifier.
    #[must_use]
    pub fn has_rust(&self) -> bool {
        self.rustup.is_some() && self.cargo.is_some()
    }

    /// Environment inside the verifier.
    #[must_use]
    pub fn env(&self) -> Vec<(String, String)> {
        let mut env = vec![("HOME".to_owned(), "/tmp".to_owned())];
        let mut path = String::new();
        if self.rustup.is_some() {
            env.push(("RUSTUP_HOME".into(), format!("{TOOLCHAIN_ROOT}/rustup")));
        }
        if self.cargo.is_some() {
            env.push(("CARGO_HOME".into(), format!("{TOOLCHAIN_ROOT}/cargo")));
            path.push_str(TOOLCHAIN_ROOT);
            path.push_str("/cargo/bin:");
        }
        path.push_str("/usr/local/bin:/usr/bin:/bin");
        env.push(("PATH".into(), path));
        env
    }

    /// Add the mounts to `launch`.
    #[must_use]
    pub fn mount(&self, mut launch: Launch) -> Launch {
        if let Some(rustup) = &self.rustup {
            launch = launch.ro_bind(rustup, format!("{TOOLCHAIN_ROOT}/rustup"));
        }
        if let Some(cargo) = &self.cargo {
            launch = launch.tmpfs(format!("{TOOLCHAIN_ROOT}/cargo"));
            for sub in ["bin", "registry"] {
                let dir = cargo.join(sub);
                if dir.is_dir() {
                    launch = launch.ro_bind(dir, format!("{TOOLCHAIN_ROOT}/cargo/{sub}"));
                }
            }
        }
        launch
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn config_needs_a_command_and_reads_protected_tests() {
        let c = Config::parse(
            "version: 1\nprotected:\n  tests:\n    - tests/security_expiry.rs\nverify:\n  command: cargo test --all-targets\n",
        )
        .unwrap();
        assert_eq!(c.protected.tests, vec!["tests/security_expiry.rs"]);
        assert_eq!(c.verify.command, "cargo test --all-targets");
        assert_eq!(c.verify.budget_secs, 600, "default budget");
        let b = Config::parse("verify:\n  command: true\n  budget_secs: 7\n").unwrap();
        assert_eq!(b.verify.budget_secs, 7);
        assert!(Config::parse("version: 1\n").is_err());
        assert!(Config::parse("verify:\n  command: '  '\n").is_err());
    }

    #[test]
    fn summary_sums_cargo_result_lines() {
        let out = "running 2 tests\n\
                   test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured\n\
                   test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured\n\
                   error: test failed";
        let s = parse_summary(out);
        assert_eq!((s.tests_run, s.tests_failed), (3, 1));
        assert_eq!(parse_summary("no runner output").tests_run, 0);
    }

    #[test]
    fn output_is_capped_on_a_char_boundary_with_a_marker() {
        let long = "é".repeat(MAX_OUTPUT_BYTES);
        let capped = cap(long);
        assert!(capped.ends_with("[verifier output truncated]\n"));
        assert!(capped.len() <= MAX_OUTPUT_BYTES + 40);
        assert_eq!(cap("short".into()), "short");
    }

    #[test]
    fn budget_fails_a_verifier_that_outruns_it() {
        if !crate::sandbox::available() {
            eprintln!("skipping: bubblewrap not available");
            return;
        }
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let w = work.path();
        std::fs::create_dir_all(w.join(".tamperward")).unwrap();
        std::fs::write(
            w.join(CONFIG_PATH),
            "verify:\n  command: sleep 5\n  budget_secs: 1\n",
        )
        .unwrap();
        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let entry = store
            .store_snapshot(w, SnapshotRole::Entry, CaptureOptions::default())
            .unwrap();
        let v = prepare(&store, w, entry, state.path()).unwrap();
        let out = execute(&v).unwrap();
        assert!(!out.passed);
        assert!(
            out.output.contains("budget of 1s exceeded"),
            "{}",
            out.output
        );
        assert!(out.summary.duration < std::time::Duration::from_secs(4));
    }

    #[test]
    fn toolchain_env_puts_cargo_first_on_a_private_path() {
        let t = Toolchains {
            rustup: Some("/root/.rustup".into()),
            cargo: Some("/root/.cargo".into()),
        };
        let env = t.env();
        assert!(env.contains(&("RUSTUP_HOME".into(), "/run/verifier/rustup".into())));
        assert!(env.contains(&("CARGO_HOME".into(), "/run/verifier/cargo".into())));
        let path = env.iter().find(|(k, _)| k == "PATH").unwrap();
        assert!(path.1.starts_with("/run/verifier/cargo/bin:"));
        assert!(!path.1.contains("/root"));
        assert_eq!(Toolchains::default().env().len(), 2, "HOME and PATH only");
    }

    #[test]
    fn prepare_restores_every_file_under_a_protected_directory() {
        // `ward init` writes `tests/` as the protected entry. Editing one test, deleting
        // another and adding a third must all be undone in the verifier tree.
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let w = work.path();
        std::fs::create_dir_all(w.join(".tamperward")).unwrap();
        std::fs::create_dir_all(w.join("tests/nested")).unwrap();
        std::fs::write(
            w.join(CONFIG_PATH),
            "protected:\n  tests:\n    - tests/\nverify:\n  command: true\n",
        )
        .unwrap();
        std::fs::write(w.join("tests/a.rs"), "strict a").unwrap();
        std::fs::write(w.join("tests/nested/b.rs"), "strict b").unwrap();
        std::fs::write(w.join("src.rs"), "v1").unwrap();
        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let entry = store
            .store_snapshot(w, SnapshotRole::Entry, CaptureOptions::default())
            .unwrap();

        std::fs::write(w.join("tests/a.rs"), "lenient").unwrap();
        std::fs::remove_file(w.join("tests/nested/b.rs")).unwrap();
        std::fs::write(w.join("tests/c.rs"), "planted").unwrap();
        std::fs::write(w.join("src.rs"), "v2").unwrap();
        let v = prepare(&store, w, entry, state.path()).unwrap();
        assert_eq!(
            v.restored,
            vec!["tests/a.rs", "tests/nested/b.rs", "tests/c.rs"]
        );
        assert_eq!(
            std::fs::read_to_string(v.scratch.join("tests/a.rs")).unwrap(),
            "strict a"
        );
        assert_eq!(
            std::fs::read_to_string(v.scratch.join("tests/nested/b.rs")).unwrap(),
            "strict b"
        );
        assert!(!v.scratch.join("tests/c.rs").exists());
        assert_eq!(
            std::fs::read_to_string(v.scratch.join("src.rs")).unwrap(),
            "v2"
        );
    }

    #[test]
    fn protected_directory_spellings_all_mean_every_file_under_it() {
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let w = work.path();
        std::fs::create_dir_all(w.join("tests")).unwrap();
        std::fs::write(w.join("tests/a.rs"), "a").unwrap();
        std::fs::write(w.join("tests.rs"), "not under tests/").unwrap();
        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let id = store
            .store_snapshot(w, SnapshotRole::Entry, CaptureOptions::default())
            .unwrap();
        for spelling in ["tests", "tests/", "tests/*", "tests/**"] {
            let files = protected_files(&store, id, id, &[spelling.to_owned()]).unwrap();
            assert_eq!(files, vec!["tests/a.rs"], "{spelling}");
        }
        // A plain file, listed twice, is one file; an absent one is kept so the
        // verifier can remove a planted copy.
        let files = protected_files(
            &store,
            id,
            id,
            &[
                "tests.rs".to_owned(),
                "tests.rs".to_owned(),
                "gone.rs".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(files, vec!["tests.rs", "gone.rs"]);
    }

    #[test]
    fn prepare_overlays_protected_paths_from_the_entry_snapshot() {
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let w = work.path();
        std::fs::create_dir_all(w.join(".tamperward")).unwrap();
        std::fs::create_dir_all(w.join("tests")).unwrap();
        std::fs::write(
            w.join(CONFIG_PATH),
            "protected:\n  tests: [tests/judge.txt]\nverify:\n  command: true\n",
        )
        .unwrap();
        std::fs::write(w.join("tests/judge.txt"), "strict").unwrap();
        std::fs::write(w.join("src.txt"), "v1").unwrap();
        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let entry = store
            .store_snapshot(w, SnapshotRole::Entry, CaptureOptions::default())
            .unwrap();

        // The agent weakens the judge and changes the code; the verifier sees the
        // code change and the pristine judge.
        std::fs::write(w.join("tests/judge.txt"), "lenient").unwrap();
        std::fs::write(w.join("src.txt"), "v2").unwrap();
        let v = prepare(&store, w, entry, state.path()).unwrap();
        assert_eq!(v.restored, vec!["tests/judge.txt"]);
        assert_eq!(
            std::fs::read_to_string(v.scratch.join("tests/judge.txt")).unwrap(),
            "strict"
        );
        assert_eq!(
            std::fs::read_to_string(v.scratch.join("src.txt")).unwrap(),
            "v2"
        );
        assert_ne!(v.candidate, entry);

        // A config edit in the worktree does not reach the verifier either.
        std::fs::write(w.join(CONFIG_PATH), "verify:\n  command: false\n").unwrap();
        let v = prepare(&store, w, entry, state.path()).unwrap();
        assert_eq!(v.config.verify.command, "true");
    }

    #[test]
    fn prepare_does_not_follow_a_candidate_symlinked_protected_file() {
        // The candidate replaces a protected file with a symlink to a host file outside
        // the verifier tree. The overlay must restore the pristine bytes into scratch as
        // a real file and never write through the link to the host (#122).
        let state = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let canary = outside.path().join("canary");
        std::fs::write(&canary, "DO NOT TOUCH").unwrap();

        let work = tempfile::tempdir().unwrap();
        let w = work.path();
        std::fs::create_dir_all(w.join(".tamperward")).unwrap();
        std::fs::create_dir_all(w.join("tests")).unwrap();
        std::fs::write(
            w.join(CONFIG_PATH),
            "protected:\n  tests: [tests/judge.txt]\nverify:\n  command: true\n",
        )
        .unwrap();
        std::fs::write(w.join("tests/judge.txt"), "strict").unwrap();
        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let entry = store
            .store_snapshot(w, SnapshotRole::Entry, CaptureOptions::default())
            .unwrap();

        // Candidate: the judge is now a symlink pointing at the host canary.
        std::fs::remove_file(w.join("tests/judge.txt")).unwrap();
        std::os::unix::fs::symlink(&canary, w.join("tests/judge.txt")).unwrap();
        let v = prepare(&store, w, entry, state.path()).unwrap();

        // The overlay wrote a real file inside scratch, and the host canary is untouched.
        assert_eq!(std::fs::read_to_string(&canary).unwrap(), "DO NOT TOUCH");
        let leaf = std::fs::symlink_metadata(v.scratch.join("tests/judge.txt")).unwrap();
        assert!(
            leaf.file_type().is_file(),
            "the planted symlink must be replaced by a real file, not followed"
        );
        assert_eq!(
            std::fs::read_to_string(v.scratch.join("tests/judge.txt")).unwrap(),
            "strict"
        );
    }

    #[test]
    fn prepare_refuses_a_candidate_symlinked_parent_directory() {
        // The candidate replaces the protected file's parent directory with a symlink to a
        // host directory. Preparation must fail closed rather than resolve the leaf through
        // the link and write pristine bytes into the host tree (#122).
        let state = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("host")).unwrap();
        let canary = outside.path().join("host/judge.txt");
        std::fs::write(&canary, "DO NOT TOUCH").unwrap();

        let work = tempfile::tempdir().unwrap();
        let w = work.path();
        std::fs::create_dir_all(w.join(".tamperward")).unwrap();
        std::fs::create_dir_all(w.join("tests")).unwrap();
        std::fs::write(
            w.join(CONFIG_PATH),
            "protected:\n  tests: [tests/judge.txt]\nverify:\n  command: true\n",
        )
        .unwrap();
        std::fs::write(w.join("tests/judge.txt"), "strict").unwrap();
        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let entry = store
            .store_snapshot(w, SnapshotRole::Entry, CaptureOptions::default())
            .unwrap();

        // Candidate: the whole tests/ directory is a symlink to a host directory.
        std::fs::remove_file(w.join("tests/judge.txt")).unwrap();
        std::fs::remove_dir(w.join("tests")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("host"), w.join("tests")).unwrap();

        let r = prepare(&store, w, entry, state.path());
        assert!(r.is_err(), "a symlinked protected ancestor must be refused");
        assert_eq!(std::fs::read_to_string(&canary).unwrap(), "DO NOT TOUCH");
    }

    #[test]
    fn prepare_removes_a_candidate_only_protected_symlink_without_following_it() {
        // Under a protected directory, the candidate plants a test that is a symlink to a
        // host file. The entry has no such file, so it must be removed (the link unlinked,
        // never its target) so a planted stand-in cannot survive into the verifier (#122).
        let state = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let canary = outside.path().join("canary");
        std::fs::write(&canary, "DO NOT TOUCH").unwrap();

        let work = tempfile::tempdir().unwrap();
        let w = work.path();
        std::fs::create_dir_all(w.join(".tamperward")).unwrap();
        std::fs::create_dir_all(w.join("tests")).unwrap();
        std::fs::write(
            w.join(CONFIG_PATH),
            "protected:\n  tests: [tests/]\nverify:\n  command: true\n",
        )
        .unwrap();
        std::fs::write(w.join("tests/keep.txt"), "keep").unwrap();
        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let entry = store
            .store_snapshot(w, SnapshotRole::Entry, CaptureOptions::default())
            .unwrap();

        // Candidate: a planted test that is a symlink to the host canary.
        std::os::unix::fs::symlink(&canary, w.join("tests/planted.txt")).unwrap();
        let v = prepare(&store, w, entry, state.path()).unwrap();

        assert!(
            v.restored.contains(&"tests/planted.txt".to_string()),
            "the planted symlink is a candidate-only protected file and must be restored/removed"
        );
        assert!(
            std::fs::symlink_metadata(v.scratch.join("tests/planted.txt")).is_err(),
            "the planted symlink must be gone from scratch"
        );
        assert_eq!(std::fs::read_to_string(&canary).unwrap(), "DO NOT TOUCH");
        assert_eq!(
            std::fs::read_to_string(v.scratch.join("tests/keep.txt")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn prepare_uses_a_fresh_scratch_directory_each_run() {
        // The same candidate digest twice must not share a scratch tree, so a second run
        // cannot inherit a symlink or altered file the first left behind (#122).
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let w = work.path();
        std::fs::create_dir_all(w.join(".tamperward")).unwrap();
        std::fs::write(w.join(CONFIG_PATH), "verify:\n  command: true\n").unwrap();
        std::fs::write(w.join("src.txt"), "v1").unwrap();
        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let entry = store
            .store_snapshot(w, SnapshotRole::Entry, CaptureOptions::default())
            .unwrap();
        let a = prepare(&store, w, entry, state.path()).unwrap();
        let b = prepare(&store, w, entry, state.path()).unwrap();
        assert_ne!(
            a.scratch, b.scratch,
            "each prepare must get its own scratch tree"
        );
        assert!(a.scratch.is_dir() && b.scratch.is_dir());
    }

    #[test]
    fn prepare_restores_a_protected_entry_symlink_as_a_symlink_not_a_file() {
        // The entry snapshot has a protected path that is a symlink; the candidate replaces
        // it with a regular file whose bytes equal the link target. Restoration must recreate
        // it AS a symlink to the entry's stored target — never flatten the target bytes into
        // a regular file, and never follow it (#122). The target is dangling on purpose.
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let w = work.path();
        std::fs::create_dir_all(w.join(".tamperward")).unwrap();
        std::fs::create_dir_all(w.join("tests")).unwrap();
        std::fs::write(
            w.join(CONFIG_PATH),
            "protected:\n  tests: [tests/link]\nverify:\n  command: true\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("../secret-target", w.join("tests/link")).unwrap();
        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let entry = store
            .store_snapshot(w, SnapshotRole::Entry, CaptureOptions::default())
            .unwrap();

        // Candidate: the symlink is now a regular file whose contents equal the link target.
        std::fs::remove_file(w.join("tests/link")).unwrap();
        std::fs::write(w.join("tests/link"), "../secret-target").unwrap();
        let v = prepare(&store, w, entry, state.path()).unwrap();

        assert_eq!(v.restored, vec!["tests/link"]);
        let leaf = std::fs::symlink_metadata(v.scratch.join("tests/link")).unwrap();
        assert!(
            leaf.file_type().is_symlink(),
            "a protected entry symlink must be restored as a symlink, not a regular file"
        );
        assert_eq!(
            std::fs::read_link(v.scratch.join("tests/link")).unwrap(),
            std::path::Path::new("../secret-target")
        );
    }

    #[test]
    fn prepare_restores_a_protected_file_mode_even_when_bytes_match() {
        // The candidate leaves a protected file's bytes intact but changes its mode. Equal
        // bytes with a candidate-controlled mode is not "already correct": the entry's mode
        // must be restored, so the overlay does not take the `continue` path here (#122).
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let w = work.path();
        std::fs::create_dir_all(w.join(".tamperward")).unwrap();
        std::fs::create_dir_all(w.join("tests")).unwrap();
        std::fs::write(
            w.join(CONFIG_PATH),
            "protected:\n  tests: [tests/run.sh]\nverify:\n  command: true\n",
        )
        .unwrap();
        std::fs::write(w.join("tests/run.sh"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            w.join("tests/run.sh"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let entry = store
            .store_snapshot(w, SnapshotRole::Entry, CaptureOptions::default())
            .unwrap();

        // Candidate: same bytes, but the executable bit is dropped.
        std::fs::set_permissions(
            w.join("tests/run.sh"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let v = prepare(&store, w, entry, state.path()).unwrap();

        assert_eq!(v.restored, vec!["tests/run.sh"]);
        let mode = std::fs::symlink_metadata(v.scratch.join("tests/run.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o755,
            "the entry's mode must be restored, not the candidate's"
        );
    }

    #[test]
    fn create_fresh_dir_skips_a_pre_existing_planted_directory() {
        // A directory a previous run left at a candidate name — here with a planted symlink
        // inside — must be skipped, not reused or followed: create_fresh_dir tries the next
        // name and returns a genuinely new, empty directory, and the external canary the
        // plant points at is never touched (#122).
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let canary = outside.path().join("canary");
        std::fs::write(&canary, "DO NOT TOUCH").unwrap();
        let root = tmp.path().join("scratchroot");
        std::fs::create_dir_all(&root).unwrap();
        let planted = root.join("a");
        std::fs::create_dir(&planted).unwrap();
        std::os::unix::fs::symlink(&canary, planted.join("link")).unwrap();

        let got = create_fresh_dir(
            &root,
            ["a".to_owned(), "a".to_owned(), "b".to_owned()].into_iter(),
        )
        .unwrap();
        assert_eq!(got, root.join("b"));
        assert!(
            got.is_dir() && std::fs::read_dir(&got).unwrap().next().is_none(),
            "the returned scratch is a fresh, empty directory"
        );
        assert_eq!(std::fs::read_to_string(&canary).unwrap(), "DO NOT TOUCH");
        assert!(
            std::fs::symlink_metadata(planted.join("link"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the planted directory and its symlink are left untouched, never followed"
        );
    }

    #[test]
    fn prepare_restores_an_entry_symlink_reached_through_a_directory_pattern() {
        // A protected DIRECTORY pattern must also cover entry symlinks under it: a candidate
        // that keeps the path a symlink but redirects its target must not slip
        // candidate-controlled content past the verifier — the entry's exact target is
        // restored (#122). Covers a live and a dangling entry symlink, both redirected.
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let w = work.path();
        std::fs::create_dir_all(w.join(".tamperward")).unwrap();
        std::fs::create_dir_all(w.join("tests")).unwrap();
        std::fs::write(
            w.join(CONFIG_PATH),
            "protected:\n  tests: [tests/]\nverify:\n  command: true\n",
        )
        .unwrap();
        std::fs::write(w.join("tests/keep.rs"), "keep").unwrap();
        std::os::unix::fs::symlink("pristine-target", w.join("tests/link")).unwrap();
        std::os::unix::fs::symlink("/does/not/exist", w.join("tests/dead")).unwrap();
        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let entry = store
            .store_snapshot(w, SnapshotRole::Entry, CaptureOptions::default())
            .unwrap();

        // Candidate: keep both as symlinks but redirect their targets to attacker content.
        std::fs::remove_file(w.join("tests/link")).unwrap();
        std::os::unix::fs::symlink("evil-target", w.join("tests/link")).unwrap();
        std::fs::remove_file(w.join("tests/dead")).unwrap();
        std::os::unix::fs::symlink("/tmp/evil", w.join("tests/dead")).unwrap();
        let v = prepare(&store, w, entry, state.path()).unwrap();

        assert!(v.restored.contains(&"tests/link".to_string()));
        assert!(v.restored.contains(&"tests/dead".to_string()));
        let link = v.scratch.join("tests/link");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            std::path::Path::new("pristine-target"),
            "the entry's target is restored, not the candidate's redirect"
        );
        assert_eq!(
            std::fs::read_link(v.scratch.join("tests/dead")).unwrap(),
            std::path::Path::new("/does/not/exist"),
            "a dangling entry symlink is restored through the directory pattern too"
        );
    }
}
