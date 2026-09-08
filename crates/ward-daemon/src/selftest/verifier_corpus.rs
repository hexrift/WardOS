//! ST-029: a corpus of hostile *verifier* repositories, run through the real
//! verifier (`crate::verify`) and asserted to be contained.
//!
//! `ward verify` runs a project's own `verify.command` over the candidate
//! snapshot, in the same disposable bubblewrap sandbox a session launch uses but
//! with *no egress socket* and the host toolchains bound read-only, and with every
//! protected path overlaid from the trusted entry snapshot. The command stands in
//! for hostile repository content the trusted command happens to execute (a build
//! script, a test harness, a planted file). Each fixture below attempts one attack
//! and is judged like every other self-test probe: [`Verdict::Denied`] when the
//! sandbox contained it, [`Verdict::Reached`] when it escaped, and
//! [`Verdict::CannotMeasure`] when this host cannot enforce the guarantee (E-06's
//! `CANNOT-MEASURE-HERE`, never a false pass).
//!
//! Where feasible each row also *demonstrates the attack would succeed without the
//! guard* — the host canary is readable from the harness but not through the
//! verifier, the weakened test would pass but the overlaid one runs instead — the
//! way the ST-018 test tears an unfrozen capture.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ward_snapshot::{CaptureOptions, SnapshotId, SnapshotRole, SnapshotStore};

use super::{ProbeResult, Verdict};
use crate::error::{Error, Result};
use crate::verify::{self, Outcome, Verification};

/// The stable row names, in run order. Kept in one place so the CLI group table
/// and the CI reproduction test agree on the catalogue.
pub const CORPUS: &[&str] = &[
    "ST-029 network-egress",
    "ST-029 read-host-path",
    "ST-029 write-outside-scratch",
    "ST-029 no-persistence",
    "ST-029 runaway-budget",
    "ST-029 resource-cgroup",
    "ST-029 protected-test-overlay",
    "ST-029 exit-code-authority",
    "ST-029 symlink-host-escape",
];

/// Run the hostile verifier corpus. Every repository is built under a private
/// temp base with its own content-addressed store; nothing touches the caller's
/// worktree or state. Without bubblewrap every row is `CANNOT-MEASURE-HERE`.
pub fn selftest_verifier_corpus() -> Result<Vec<ProbeResult>> {
    if !crate::sandbox::available() {
        let why = "bubblewrap is not available on this host, so the verifier cannot run";
        return Ok(CORPUS
            .iter()
            .map(|&name| ProbeResult {
                name,
                verdict: Verdict::CannotMeasure(why.into()),
            })
            .collect());
    }
    let h = Harness::new()?;
    let out = vec![
        row("ST-029 network-egress", network_egress(&h)?),
        row("ST-029 read-host-path", read_host_path(&h)?),
        row("ST-029 write-outside-scratch", write_outside_scratch(&h)?),
        row("ST-029 no-persistence", no_persistence(&h)?),
        row("ST-029 runaway-budget", runaway_budget(&h)?),
        row("ST-029 resource-cgroup", resource_cgroup(&h)?),
        row("ST-029 protected-test-overlay", protected_test_overlay(&h)?),
        row("ST-029 exit-code-authority", exit_code_authority(&h)?),
        row("ST-029 symlink-host-escape", symlink_host_escape(&h)?),
    ];
    h.cleanup();
    Ok(out)
}

fn row(name: &'static str, verdict: Verdict) -> ProbeResult {
    ProbeResult { name, verdict }
}

// ---- the attacks -----------------------------------------------------------

/// A raw TCP connection out of the verifier reaches no route: the verify sandbox
/// is `--unshare-net` with loopback only and, unlike a session launch, gets no
/// egress socket at all.
fn network_egress(h: &Harness) -> Result<Verdict> {
    let command = "echo probe=ready; \
        if command -v bash >/dev/null 2>&1; then \
          if timeout 3 bash -c 'exec 3<>/dev/tcp/8.8.8.8/53' 2>/dev/null; \
            then echo egress=reached; else echo egress=denied; fi; \
        else echo bash=no; fi";
    let facts = h.facts("network-egress", command, &[], 60)?;
    if let Some(v) = not_ready(&facts) {
        return Ok(v);
    }
    if facts.get("bash").map(String::as_str) == Some("no") {
        return Ok(Verdict::CannotMeasure(
            "no bash in the verifier sandbox to open a raw socket".into(),
        ));
    }
    Ok(match facts.get("egress").map(String::as_str) {
        Some("denied") => Verdict::Denied,
        Some("reached") => {
            Verdict::Reached("a raw TCP connection left the verifier sandbox".into())
        }
        _ => Verdict::CannotMeasure("the probe reported no `egress`".into()),
    })
}

/// No host path outside the worktree is readable: the host canary, the CAS, the
/// entry state, `/etc/shadow` and `$HOME` are simply never mounted. The harness
/// proves the canary *is* there by reading it directly.
fn read_host_path(h: &Harness) -> Result<Verdict> {
    let canary = h.canary_file.to_string_lossy();
    let cas = h.base.join("cas");
    let command = format!(
        "echo probe=ready; found=; \
         for p in '{canary}' '{cas}' /etc/shadow \"$HOME/.bashrc\"; do \
           if [ -r \"$p\" ]; then found=\"$found $p\"; fi; done; \
         echo \"found=${{found:-none}}\"",
        cas = cas.display()
    );
    // The attack would succeed without containment: the canary is real and holds
    // its secret. If the harness cannot read it, the row cannot be measured.
    if std::fs::read_to_string(&h.canary_file).ok().as_deref() != Some(h.secret.as_str()) {
        return Ok(Verdict::CannotMeasure(
            "the host canary could not be staged".into(),
        ));
    }
    let facts = h.facts("read-host-path", &command, &[], 60)?;
    if let Some(v) = not_ready(&facts) {
        return Ok(v);
    }
    Ok(match facts.get("found").map(String::as_str) {
        Some("none") => Verdict::Denied,
        Some(list) => Verdict::Reached(format!("a host path was readable:{list}")),
        None => Verdict::CannotMeasure("the probe reported no `found`".into()),
    })
}

/// No write reaches a host path outside the disposable scratch tree. The read-only
/// system binds reject writes, and every other host location is simply not mounted,
/// so a write aimed at one lands nowhere on the host (writes to the sandbox's own
/// ephemeral tmpfs root do not count — they vanish with the sandbox). The harness
/// proves those host paths are real and writable from outside the sandbox.
fn write_outside_scratch(h: &Harness) -> Result<Verdict> {
    // Two real, writable host directories outside any scratch tree.
    let targets = [h.base.join("pwn-base"), h.canary_dir.join("pwn-secret")];
    for t in &targets {
        let _ = std::fs::remove_file(t);
    }
    let mut attempts = String::new();
    for t in &targets {
        let _ = write!(attempts, "echo x > '{}' 2>/dev/null || true; ", t.display());
    }
    let command = format!(
        "echo probe=ready; \
         if (echo x > /usr/bin/ward_st029) 2>/dev/null; then echo usr=written; rm -f /usr/bin/ward_st029; else echo usr=readonly; fi; \
         {attempts}echo done=yes"
    );
    let facts = h.facts("write-outside", &command, &[], 60)?;
    if let Some(v) = not_ready(&facts) {
        return Ok(v);
    }
    // The read-only system bind must reject the write, or isolation is degraded.
    if facts.get("usr").map(String::as_str) != Some("readonly") {
        return Ok(Verdict::Reached(
            "a read-only system bind (/usr) accepted a write".into(),
        ));
    }
    // The demonstration: those host paths are writable from the harness itself,
    // so their absence after the run is the containment, not a bad target.
    let reachable: Vec<&PathBuf> = targets.iter().filter(|t| t.exists()).collect();
    for t in &targets {
        let _ = std::fs::remove_file(t);
    }
    if reachable.is_empty() {
        Ok(Verdict::Denied)
    } else {
        Ok(Verdict::Reached(format!(
            "a host path outside the scratch tree was written: {reachable:?}"
        )))
    }
}

/// A write from inside the verifier reaches neither the user's worktree nor the
/// immutable CAS: the command runs over a disposable materialised copy, and the
/// worktree is never bound in. The second verify starts from the same pristine
/// bytes, so nothing persists between runs.
fn no_persistence(h: &Harness) -> Result<Verdict> {
    let command = "echo probe=ready; echo PWNED > /work/PWNED; echo mutated > /work/tracked.txt; echo done=yes";
    let worktree = h.build_repo(
        "no-persistence",
        command,
        600,
        &[("tracked.txt", b"pristine\n", false)],
    )?;
    let entry = h.snapshot_entry(&worktree)?;
    let (v1, f1) = h.prepare_and_run(&worktree, entry, "no-persistence-1")?;
    if let Some(v) = not_ready(&f1) {
        discard(&v1);
        return Ok(v);
    }
    // The user's worktree is untouched: the run is over a copy.
    let worktree_after = std::fs::read(worktree.join("tracked.txt")).unwrap_or_default();
    let worktree_has_pwned = worktree.join("PWNED").exists();
    // The immutable entry snapshot still holds the pristine bytes.
    let entry_bytes = h.store.cat(entry, Path::new("tracked.txt")).ok();
    discard(&v1);
    // A second verify of the same tree starts from the pristine bytes: inspect the
    // freshly materialised tree *before* the command runs, so we see what run two
    // inherits, not what its own command writes.
    let v2 = h.prepare_only(&worktree, entry, "no-persistence-2")?;
    let second_pwned = v2.scratch.join("PWNED").exists();
    let second_tracked = std::fs::read(v2.scratch.join("tracked.txt")).unwrap_or_default();
    discard(&v2);

    if worktree_after != b"pristine\n" || worktree_has_pwned {
        return Ok(Verdict::Reached(
            "a verifier write reached the user's worktree".into(),
        ));
    }
    if entry_bytes.as_deref() != Some(b"pristine\n") {
        return Ok(Verdict::Reached(
            "a verifier write reached the immutable entry snapshot".into(),
        ));
    }
    if second_pwned || second_tracked != b"pristine\n" {
        return Ok(Verdict::Reached(
            "a write from the first verify persisted into the second".into(),
        ));
    }
    Ok(Verdict::Denied)
}

/// A command that never exits is stopped by the wall-clock budget; the host is
/// not hung. A one-second budget bounds an infinite loop.
fn runaway_budget(h: &Harness) -> Result<Verdict> {
    let command = "echo probe=ready; while true; do :; done";
    let (v, out) = h.build_and_run("runaway-budget", command, 1, &[])?;
    let facts = parse_facts(&out.output);
    discard(&v);
    if not_ready(&facts).is_some() {
        return Ok(Verdict::CannotMeasure(
            "the runaway command did not start".into(),
        ));
    }
    if out.passed {
        return Ok(Verdict::Reached(
            "the runaway command was not stopped by the budget".into(),
        ));
    }
    if out.output.contains("budget of 1s exceeded") {
        Ok(Verdict::Denied)
    } else {
        Ok(Verdict::CannotMeasure(format!(
            "the command failed but not by the budget: {}",
            out.output.lines().last().unwrap_or_default()
        )))
    }
}

/// A fork bomb or memory hog is bounded only if a memory/pid cgroup limit is in
/// force. The 0.1 bubblewrap backend manages no cgroup (ADR-0002 selects `crun`
/// for the production host, which does), so this host reports the observed limits
/// as `CANNOT-MEASURE-HERE` rather than running a destructive workload.
fn resource_cgroup(h: &Harness) -> Result<Verdict> {
    let command = "echo probe=ready; \
        echo \"mem=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown)\"; \
        echo \"pids=$(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo unknown)\"";
    let facts = h.facts("resource-cgroup", command, &[], 60)?;
    if let Some(v) = not_ready(&facts) {
        return Ok(v);
    }
    let mem = facts.get("mem").map_or("unknown", String::as_str);
    let pids = facts.get("pids").map_or("unknown", String::as_str);
    let finite = |s: &str| s.parse::<u64>().is_ok();
    if finite(mem) && finite(pids) {
        Ok(Verdict::Denied)
    } else {
        Ok(Verdict::CannotMeasure(format!(
            "this backend (bubblewrap) enforces no memory/pid cgroup limit \
             (memory.max={mem}, pids.max={pids}); the production crun runtime does"
        )))
    }
}

/// A protected test weakened in the worktree does not run: the verifier overlays
/// the trusted bytes from the entry snapshot. The strict test still fails, so the
/// weakened one never grants a pass.
fn protected_test_overlay(h: &Harness) -> Result<Verdict> {
    // Entry: a strict guard that fails (the real tests do not pass), and a config
    // that protects it and runs it.
    let config = "protected:\n  tests: [tests/guard.sh]\nverify:\n  command: sh tests/guard.sh\n  budget_secs: 60\n";
    let worktree = h.base.join("repos").join("protected-test-overlay");
    std::fs::create_dir_all(worktree.join("tests")).map_err(|e| Error::io(&worktree, e))?;
    write(
        &worktree,
        ".tamperward/config.yml",
        config.as_bytes(),
        false,
    )?;
    write(
        &worktree,
        "tests/guard.sh",
        b"echo probe=ready\nexit 1\n",
        true,
    )?;
    let entry = h.snapshot_entry(&worktree)?;
    // The agent weakens the guard to pass unconditionally.
    write(
        &worktree,
        "tests/guard.sh",
        b"echo probe=ready\nexit 0\n",
        true,
    )?;
    let (v, out) = h.prepare_and_run_outcome(&worktree, entry, "protected-test-overlay")?;
    // The overlay wins: the scratch guard is the strict bytes, not the weakened
    // ones the agent wrote (the demonstration that the attack would otherwise pass).
    let scratch_guard = std::fs::read(v.scratch.join("tests/guard.sh")).unwrap_or_default();
    let restored = v.restored.iter().any(|r| r == "tests/guard.sh");
    let facts = parse_facts(&out.output);
    discard(&v);
    if not_ready(&facts).is_some() {
        return Ok(Verdict::CannotMeasure("the guard did not run".into()));
    }
    if scratch_guard != b"echo probe=ready\nexit 1\n" || !restored {
        return Ok(Verdict::Reached(
            "the verifier ran the worktree's weakened test, not the trusted one".into(),
        ));
    }
    if out.passed {
        Ok(Verdict::Reached(
            "the weakened test granted a pass despite the overlay".into(),
        ))
    } else {
        Ok(Verdict::Denied)
    }
}

/// A repository cannot forge a pass through its output: the verdict is the
/// command's exit code and timeout, never text it prints. A fake `cargo test`
/// summary is parsed into the counts yet a non-zero exit still fails.
fn exit_code_authority(h: &Harness) -> Result<Verdict> {
    let command = "echo probe=ready; \
        echo 'test result: ok. 999 passed; 0 failed; 0 ignored; 0 measured'; \
        exit 1";
    let (v, out) = h.build_and_run("exit-code-authority", command, 60, &[])?;
    let facts = parse_facts(&out.output);
    let parsed = out.summary.tests_run;
    discard(&v);
    if not_ready(&facts).is_some() {
        return Ok(Verdict::CannotMeasure("the command did not run".into()));
    }
    // The parser did read the printed summary (999), proving the row exercises the
    // path, but the exit code is authoritative.
    if parsed != 999 {
        return Ok(Verdict::CannotMeasure(format!(
            "the summary parser read {parsed} tests, not the printed 999"
        )));
    }
    if out.passed {
        Ok(Verdict::Reached(
            "a printed success line forged a pass over a non-zero exit".into(),
        ))
    } else {
        Ok(Verdict::Denied)
    }
}

/// A symlink pointing at a host path is neutralised: the snapshot captures it as a
/// symlink, `materialize` writes it as a symlink (never following it), and inside
/// the mount namespace the absolute target resolves to nothing. The harness proves
/// the target really holds the canary.
fn symlink_host_escape(h: &Harness) -> Result<Verdict> {
    let target = &h.canary_dir;
    let base = h
        .canary_file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("host-canary.txt");
    let worktree = h.base.join("repos").join("symlink-host-escape");
    std::fs::create_dir_all(&worktree).map_err(|e| Error::io(&worktree, e))?;
    write(
        &worktree,
        ".tamperward/config.yml",
        b"verify:\n  command: sh verify.sh\n  budget_secs: 60\n",
        false,
    )?;
    let script = format!(
        "echo probe=ready; \
         echo \"link=$(readlink escape 2>/dev/null || echo none)\"; \
         if cat 'escape/{base}' 2>/dev/null; then echo escaped=yes; else echo escaped=no; fi"
    );
    write(&worktree, "verify.sh", script.as_bytes(), false)?;
    let link = worktree.join("escape");
    std::os::unix::fs::symlink(target, &link).map_err(|e| Error::io(&link, e))?;

    if std::fs::read_to_string(&h.canary_file).ok().as_deref() != Some(h.secret.as_str()) {
        return Ok(Verdict::CannotMeasure(
            "the host canary could not be staged".into(),
        ));
    }
    let entry = h.snapshot_entry(&worktree)?;
    let (v, out) = h.prepare_and_run_outcome(&worktree, entry, "symlink-host-escape")?;
    // `materialize` wrote a symlink, not a copy of the host directory's content.
    let scratch_link = v.scratch.join("escape");
    let is_symlink = scratch_link
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    let facts = parse_facts(&out.output);
    discard(&v);
    if let Some(v) = not_ready(&facts) {
        return Ok(v);
    }
    if !is_symlink {
        return Ok(Verdict::Reached(
            "materialize dereferenced the symlink into the scratch tree".into(),
        ));
    }
    if out.output.contains(&h.secret) {
        return Ok(Verdict::Reached(
            "the symlink reached the host canary through the mount namespace".into(),
        ));
    }
    Ok(match facts.get("escaped").map(String::as_str) {
        Some("no") => Verdict::Denied,
        Some("yes") => Verdict::Reached("the symlink resolved to the host target".into()),
        _ => Verdict::CannotMeasure("the probe reported no `escaped`".into()),
    })
}

// ---- the harness -----------------------------------------------------------

/// A private base directory with its own content-addressed store and a host
/// canary staged outside every worktree.
struct Harness {
    base: PathBuf,
    store: SnapshotStore,
    canary_dir: PathBuf,
    canary_file: PathBuf,
    secret: String,
}

impl Harness {
    fn new() -> Result<Self> {
        let base = std::env::temp_dir().join(format!("ward-st029-{}", super::canary_suffix()));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&base)
            .map_err(|e| Error::io(&base, e))?;
        let store = SnapshotStore::open(base.join("cas")).map_err(|e| snap(&e))?;
        let canary_dir = base.join("secret");
        std::fs::create_dir_all(&canary_dir).map_err(|e| Error::io(&canary_dir, e))?;
        let secret = format!("ward-st029-secret-{}", super::canary_suffix());
        let canary_file = canary_dir.join("host-canary.txt");
        std::fs::write(&canary_file, &secret).map_err(|e| Error::io(&canary_file, e))?;
        Ok(Self {
            base,
            store,
            canary_dir,
            canary_file,
            secret,
        })
    }

    /// Build a one-command repository with any extra files, snapshot it as the
    /// entry, prepare and run it, and return the parsed facts of its output.
    fn facts(
        &self,
        name: &str,
        command: &str,
        files: &[(&str, &[u8], bool)],
        budget: u64,
    ) -> Result<Facts> {
        let (v, out) = self.build_and_run(name, command, budget, files)?;
        let facts = parse_facts(&out.output);
        discard(&v);
        Ok(facts)
    }

    /// Build, snapshot, prepare and run, returning the verification (to inspect
    /// the scratch tree) and the outcome.
    fn build_and_run(
        &self,
        name: &str,
        command: &str,
        budget: u64,
        files: &[(&str, &[u8], bool)],
    ) -> Result<(Verification, Outcome)> {
        let worktree = self.build_repo(name, command, budget, files)?;
        let entry = self.snapshot_entry(&worktree)?;
        self.prepare_and_run_outcome(&worktree, entry, name)
    }

    /// Write a `.tamperward/config.yml` running `command`, plus `files`.
    fn build_repo(
        &self,
        name: &str,
        command: &str,
        budget: u64,
        files: &[(&str, &[u8], bool)],
    ) -> Result<PathBuf> {
        let worktree = self.base.join("repos").join(name);
        std::fs::create_dir_all(&worktree).map_err(|e| Error::io(&worktree, e))?;
        write(
            &worktree,
            ".tamperward/config.yml",
            verify_config(command, budget).as_bytes(),
            false,
        )?;
        for (rel, bytes, exec) in files {
            write(&worktree, rel, bytes, *exec)?;
        }
        Ok(worktree)
    }

    fn snapshot_entry(&self, worktree: &Path) -> Result<SnapshotId> {
        self.store
            .store_snapshot(worktree, SnapshotRole::Entry, CaptureOptions::default())
            .map_err(|e| snap(&e))
    }

    fn prepare_and_run(
        &self,
        worktree: &Path,
        entry: SnapshotId,
        scratch: &str,
    ) -> Result<(Verification, Facts)> {
        let (v, out) = self.prepare_and_run_outcome(worktree, entry, scratch)?;
        let facts = parse_facts(&out.output);
        Ok((v, facts))
    }

    fn prepare_and_run_outcome(
        &self,
        worktree: &Path,
        entry: SnapshotId,
        scratch: &str,
    ) -> Result<(Verification, Outcome)> {
        let v = self.prepare_only(worktree, entry, scratch)?;
        let out = verify::execute(&v)?;
        Ok((v, out))
    }

    /// Materialise the verifier tree without running its command, to inspect what
    /// a run starts from.
    fn prepare_only(
        &self,
        worktree: &Path,
        entry: SnapshotId,
        scratch: &str,
    ) -> Result<Verification> {
        let scratch_root = self.base.join("scratch").join(scratch);
        std::fs::create_dir_all(&scratch_root).map_err(|e| Error::io(&scratch_root, e))?;
        verify::prepare(&self.store, worktree, entry, &scratch_root)
    }

    fn cleanup(self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// Remove a run's scratch tree, exactly as `Session::verify` does.
fn discard(v: &Verification) {
    let _ = std::fs::remove_dir_all(&v.scratch);
}

fn snap(e: &ward_snapshot::SnapshotError) -> Error {
    Error::Snapshot(e.to_string())
}

/// A `.tamperward/config.yml` whose `verify.command` is `command`, as a YAML block
/// scalar so a command that contains colons, quotes or `#` is passed verbatim.
fn verify_config(command: &str, budget: u64) -> String {
    let mut yaml = String::from("verify:\n  command: |\n");
    for line in command.lines() {
        yaml.push_str("    ");
        yaml.push_str(line);
        yaml.push('\n');
    }
    let _ = writeln!(yaml, "  budget_secs: {budget}");
    yaml
}

/// Write `bytes` to `dir/rel`, creating parents, with an executable bit if asked.
fn write(dir: &Path, rel: &str, bytes: &[u8], exec: bool) -> Result<()> {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    std::fs::write(&path, bytes).map_err(|e| Error::io(&path, e))?;
    if exec {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| Error::io(&path, e))?;
    }
    Ok(())
}

/// Facts a probe printed, one `key=value` per line.
type Facts = BTreeMap<String, String>;

fn parse_facts(output: &str) -> Facts {
    output
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

/// `CannotMeasure` if the command never printed its readiness marker.
fn not_ready(facts: &Facts) -> Option<Verdict> {
    if facts.get("probe").map(String::as_str) == Some("ready") {
        None
    } else {
        Some(Verdict::CannotMeasure(
            "the verify command did not run in the sandbox".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn facts(pairs: &[(&str, &str)]) -> Facts {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn facts_parse_and_readiness() {
        let f = parse_facts("probe=ready\nnoise\nfound= /etc/shadow \n");
        assert_eq!(f.get("probe").unwrap(), "ready");
        assert_eq!(f.get("found").unwrap(), "/etc/shadow");
        assert!(not_ready(&f).is_none());
        assert!(matches!(
            not_ready(&facts(&[("x", "y")])),
            Some(Verdict::CannotMeasure(_))
        ));
    }

    #[test]
    fn corpus_names_are_unique_and_all_st029() {
        let mut seen = std::collections::BTreeSet::new();
        for name in CORPUS {
            assert!(name.starts_with("ST-029 "), "{name}");
            assert!(seen.insert(*name), "duplicate {name}");
        }
        assert_eq!(seen.len(), 9);
    }

    #[test]
    fn without_bubblewrap_every_row_cannot_measure() {
        if crate::sandbox::available() {
            eprintln!("skipping: bubblewrap is available, so this path is not taken");
            return;
        }
        let rows = selftest_verifier_corpus().unwrap();
        let names: Vec<&str> = rows.iter().map(|r| r.name).collect();
        assert_eq!(names, CORPUS);
        assert!(
            rows.iter()
                .all(|r| matches!(r.verdict, Verdict::CannotMeasure(_)))
        );
    }
}
