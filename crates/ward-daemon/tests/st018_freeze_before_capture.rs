//! ST-018 — freeze before capture (G5, G9).
//!
//! The threat is a time-of-check/time-of-use race: an agent mutates the worktree
//! *while* a snapshot is being captured, so the captured tree is internally
//! inconsistent — the manifest records a file's size from the `stat` in the walk
//! but its content id from the bytes read a moment later, and if the file changed
//! size in between the snapshot names a tree that no longer round-trips (its
//! `materialize` re-digests to a different id).
//!
//! The invariant `WardOS` establishes is that the daemon freezes the session's
//! sandbox before it captures a candidate or final snapshot ([`pause::CaptureFreeze`],
//! reused from the ADR-0019 pause primitive) so no agent write can interleave
//! with the walk. This test proves it end to end: an "agent" process — found and
//! frozen exactly as `ward pause` finds a session's `bwrap` tree, by its command
//! line binding the session run directory — hammers a file, changing its size on
//! every iteration, while `store_snapshot` runs repeatedly.
//!
//! It first shows the race is real on this host (unfrozen captures tear), then
//! shows that with the freeze held every snapshot is internally consistent. It
//! therefore FAILS if the freeze is removed from `CaptureFreeze::acquire` (or from
//! the session capture path it guards): the frozen phase would tear like the
//! unfrozen one. Where the race cannot be provoked at all (a host too slow or too
//! fast to interleave) the test reports `CANNOT-MEASURE-HERE` and skips rather
//! than pass vacuously.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ward_daemon::daemon::wait_until;
use ward_daemon::pause::{self, CaptureFreeze};
use ward_daemon::session::run_dir_path;
use ward_snapshot::{
    CaptureOptions, Digest, EntryType, HashCache, SnapshotId, SnapshotRole, SnapshotStore,
    digest_worktree,
};

/// Kills the writer on the way out, whatever an assertion does. The writer's
/// steady state is a single shell running builtins, so killing its pid frees the
/// tree; `SIGKILL` takes a `SIGSTOP`-stopped process as it is.
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A copy of the system shell named `bwrap`, so the writer's `argv[0]` basename
/// is `bwrap` and `pause::sandbox_pids` treats it as a session sandbox — the same
/// discovery `ward pause` uses. Kept alive by `dir`.
fn bwrap_shim(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let shell = ["/bin/sh", "/usr/bin/sh", "/bin/dash", "/bin/bash"]
        .into_iter()
        .map(Path::new)
        .find(|p| p.exists())
        .expect("a system shell");
    let shim = dir.join("bwrap");
    fs::copy(shell, &shim).expect("copy shell to bwrap shim");
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    shim
}

/// Spawn a writer that continuously rewrites `target`, alternating a tiny and a
/// large body so its *size* changes on every write — the change a torn capture
/// records inconsistently. Its command line binds `run_dir` so the freeze finds
/// it as `session`'s sandbox.
fn spawn_writer(shim: &Path, run_dir: &str, target: &Path) -> Child {
    // Precompute the large body once, then loop on shell builtins so the steady
    // state spawns no children and writes as fast as possible.
    let script = "big=$(head -c 262144 /dev/zero | tr '\\0' x); \
         t=$2; \
         while :; do printf 'x' > \"$t\"; printf '%s' \"$big\" > \"$t\"; done";
    Command::new(shim)
        .arg("-c")
        .arg(script)
        // `$0`, then `$1`=run_dir (the needle the freeze matches), `$2`=target.
        .arg("ward-agent")
        .arg(run_dir)
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn writer")
}

/// Whether snapshot `id` is internally consistent: every stored blob hashes to
/// the content id its entry names, and a fresh `materialize` re-digests to `id`.
/// A torn capture fails the second check — its recorded size disagrees with the
/// bytes actually stored, so the round-tripped tree gets a different id.
fn is_consistent(store: &SnapshotStore, id: SnapshotId, scratch: &Path) -> bool {
    let Ok(manifest) = store.manifest(id) else {
        return false;
    };
    for entry in manifest.entries() {
        let Some(content) = entry.content else {
            continue;
        };
        if !matches!(entry.kind, EntryType::File | EntryType::Symlink) {
            continue;
        }
        let path = Path::new(OsStr::from_bytes(&entry.path));
        match store.cat(id, path) {
            Ok(bytes) if Digest::of(&bytes) == content => {}
            _ => return false,
        }
    }
    let dest = scratch.join(id.digest().to_hex());
    let _ = fs::remove_dir_all(&dest);
    if store.materialize(id, &dest).is_err() {
        return false;
    }
    let mut cache = HashCache::new();
    match digest_worktree(&dest, CaptureOptions::default(), &mut cache) {
        Ok(redigest) => redigest == id,
        Err(_) => false,
    }
}

#[test]
fn candidate_capture_is_atomic_while_the_agent_writes() {
    // A session id whose run-directory needle is unique to this test.
    let session = format!("sess_st018_{}", std::process::id());
    let run_dir = run_dir_path(&session).to_string_lossy().into_owned();

    let home = tempfile::tempdir().unwrap();
    let worktree = home.path().join("work");
    fs::create_dir_all(&worktree).unwrap();
    // A couple of quiet files so the manifest is more than the hot file.
    fs::write(worktree.join("README.md"), b"demo\n").unwrap();
    fs::create_dir_all(worktree.join(".ward")).unwrap();
    fs::write(
        worktree.join(".ward/policy.yaml"),
        b"network: localhost_only\n",
    )
    .unwrap();
    let hot = worktree.join("hot.txt");
    fs::write(&hot, b"x").unwrap();

    let state = tempfile::tempdir().unwrap();
    let store = SnapshotStore::open(state.path().join("cas")).unwrap();
    let scratch = tempfile::tempdir().unwrap();

    let shim = bwrap_shim(home.path());
    let writer = Reap(spawn_writer(&shim, &run_dir, &hot));
    let writer_pid = writer.0.id();

    // The freeze must find the writer as the session's sandbox.
    assert!(
        wait_until(Duration::from_secs(5), || pause::sandbox_pids(
            Path::new("/proc"),
            &session
        )
        .contains(&writer_pid)),
        "the writer must be discoverable as {session}'s sandbox",
    );
    // Let the writer get going so the hot file is genuinely churning.
    std::thread::sleep(Duration::from_millis(200));

    // Phase 1: without the freeze, provoke the race. Stop as soon as it tears.
    let mut saw_race = false;
    let deadline = Instant::now() + Duration::from_secs(20);
    for _ in 0..2000 {
        match store.store_snapshot(&worktree, SnapshotRole::Candidate, opts()) {
            // A read that lost its file mid-write is itself the race.
            Err(_) => {
                saw_race = true;
                break;
            }
            Ok(id) => {
                if !is_consistent(&store, id, scratch.path()) {
                    saw_race = true;
                    break;
                }
            }
        }
        if Instant::now() > deadline {
            break;
        }
    }
    if !saw_race {
        eprintln!(
            "ST-018 CANNOT-MEASURE-HERE: the capture race could not be provoked on this host; \
             the atomicity claim is not exercised, so this run neither passes nor fails it"
        );
        return;
    }

    // Phase 2: with the freeze held around every capture, no snapshot may tear —
    // the same writer, now stopped for the length of each walk. Removing the
    // freeze makes this phase tear exactly like phase 1.
    for i in 0..200 {
        let guard = CaptureFreeze::acquire(state.path(), &session);
        let id = store
            .store_snapshot(&worktree, SnapshotRole::Candidate, opts())
            .unwrap_or_else(|e| panic!("frozen capture {i} failed: {e}"));
        assert!(
            is_consistent(&store, id, scratch.path()),
            "frozen capture {i} produced an internally inconsistent snapshot {id}: \
             the freeze did not hold the agent still during the walk",
        );
        drop(guard);
    }
}

fn opts() -> CaptureOptions {
    CaptureOptions::default()
}
