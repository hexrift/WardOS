//! The CI-measurable subset (#150): sandbox start, `ward status`, verifier
//! spawn, and snapshot/digest work. Each metric calls straight into
//! `ward-daemon`/`ward-snapshot`'s public API — the same code paths `ward
//! run`/`ward status`/`ward verify` use — rather than shelling out, so a
//! failure points at a real function instead of CLI plumbing, and no daemon
//! process or terminal is needed.

use std::path::Path;
use std::time::Duration;

use ward_snapshot::{CaptureOptions, HashCache, SnapshotRole, SnapshotStore};

use crate::report::{Metric, Stats};
use crate::rusage::{SelfIo, Usage, Who};
use crate::stats::{Samples, time_iterations, warm_up};

/// How many timed samples a "warm" measurement takes, matching
/// `docs/performance.md` §3 ("warm = median of 20 runs after 3 discarded
/// warm-ups").
pub const DEFAULT_SAMPLES: usize = 20;
/// How many discarded warm-up runs precede a "warm" measurement.
pub const DEFAULT_WARM_UP: usize = 3;

fn to_anyhow<E: std::fmt::Display>(e: E) -> anyhow::Error {
    anyhow::anyhow!(e.to_string())
}

/// Build [`Samples`] from timed wall-clock durations plus an optional
/// self-process rusage/IO before-and-after pair.
fn self_samples(
    durations: Vec<Duration>,
    cpu: Option<(Usage, Usage)>,
    io: Option<(SelfIo, SelfIo)>,
) -> Samples {
    let mut s = Samples {
        durations,
        ..Default::default()
    };
    if let Some((before, after)) = cpu {
        let d = after.since(&before);
        s.cpu_user = Some(d.utime);
        s.cpu_sys = Some(d.stime);
        s.max_rss_kb = after.max_rss_kb;
    }
    if let Some((before, after)) = io {
        let d = after.since(&before);
        s.io_read_bytes = Some(d.read_bytes);
        s.io_write_bytes = Some(d.write_bytes);
    }
    s
}

/// Build [`Samples`] from timed wall-clock durations plus an optional
/// reaped-children rusage before-and-after pair. I/O is left unset: reading
/// a short-lived child's own `/proc/<pid>/io` races its exit, and this pass
/// does not add the extra plumbing (a wrapper that reads it just before
/// `wait`) to do it safely.
fn child_samples(durations: Vec<Duration>, cpu: Option<(Usage, Usage)>) -> Samples {
    let mut s = Samples {
        durations,
        ..Default::default()
    };
    if let Some((before, after)) = cpu {
        let d = after.since(&before);
        s.cpu_user = Some(d.utime);
        s.cpu_sys = Some(d.stime);
        s.max_rss_kb = after.max_rss_kb;
    }
    s
}

/// Sandboxed command start latency: `Session::run(["/bin/true"])`, the exact
/// code path `ward run -- true` takes (proxy/hook socket setup, inotify
/// watch, bubblewrap spawn), without a daemon or CLI process. Comparable to
/// the `ward run -- true` row in `docs/performance.md`'s "Measured so far"
/// table.
#[must_use]
pub fn sandbox_start(
    fixtures_root: &Path,
    state: &Path,
    warm_up_count: usize,
    samples: usize,
) -> Metric {
    let id = "sandbox_start";
    let description = "`ward run -- true`: sandbox start (bubblewrap) + proxy/hook \
        sockets + inotify watch, daemon-free";
    let budget_row = Some("Agent sandbox warm start");
    let budget_ms = Some(150.0);
    if !ward_daemon::sandbox::available() {
        return Metric::unsupported(
            id,
            description,
            budget_row,
            budget_ms,
            "bubblewrap is not installed, or cannot create a user namespace on this \
             host (ward_daemon::sandbox::available() returned false); a GitHub \
             Actions ubuntu runner normally allows unprivileged user namespaces and \
             should measure this — see docs/performance.md §5",
        );
    }
    let fixture = fixtures_root.join("ci-subset");
    let result = (|| -> anyhow::Result<Samples> {
        let mut session = ward_daemon::Session::start_in(&fixture, state).map_err(to_anyhow)?;
        let argv = vec!["/bin/true".to_string()];
        let mut run = || session.run(&argv).map(|_| ()).map_err(to_anyhow);
        warm_up(warm_up_count, &mut run)?;
        let cpu_before = Usage::read(Who::Children);
        let durations = time_iterations(samples, &mut run)?;
        let cpu_after = Usage::read(Who::Children);
        Ok(child_samples(durations, cpu_before.zip(cpu_after)))
    })();
    finish(
        &MetricMeta {
            id,
            description,
            budget_row,
            budget_ms,
            fixture: "ci-subset",
            run_kind: "warm",
            warm_up: warm_up_count,
        },
        result,
    )
}

/// `ward status` first-render latency: current-session lookup plus
/// `render::status_panel`, no daemon required (the same lookup `ward
/// status` does when no daemon is serving the session).
#[must_use]
pub fn ward_status(
    fixtures_root: &Path,
    state: &Path,
    warm_up_count: usize,
    samples: usize,
) -> Metric {
    let id = "ward_status";
    let description = "`ward status`: SessionMeta::current lookup + status-panel render";
    let budget_row = Some("`ward status`");
    let budget_ms = Some(10.0);
    let fixture = fixtures_root.join("ci-subset");
    let result = (|| -> anyhow::Result<Samples> {
        let mut session = ward_daemon::Session::start_in(&fixture, state).map_err(to_anyhow)?;
        session.persist_current().map_err(to_anyhow)?;
        session.sync().map_err(to_anyhow)?;
        let mut run = || -> anyhow::Result<()> {
            let meta = ward_daemon::SessionMeta::current(&fixture, state)
                .map_err(to_anyhow)?
                .ok_or_else(|| anyhow::anyhow!("no current session recorded"))?;
            let panel = ward_daemon::render::status_panel(
                &meta.id,
                &fixture.display().to_string(),
                &meta.entry_snapshot,
                &meta.manifest,
            );
            std::hint::black_box(&panel);
            std::hint::black_box(ward_daemon::daemon::serving(state, &meta.id));
            Ok(())
        };
        warm_up(warm_up_count, &mut run)?;
        let cpu_before = Usage::read(Who::SelfProcess);
        let io_before = SelfIo::read();
        let durations = time_iterations(samples, &mut run)?;
        let cpu_after = Usage::read(Who::SelfProcess);
        let io_after = SelfIo::read();
        Ok(self_samples(
            durations,
            cpu_before.zip(cpu_after),
            io_before.zip(io_after),
        ))
    })();
    finish(
        &MetricMeta {
            id,
            description,
            budget_row,
            budget_ms,
            fixture: "ci-subset",
            run_kind: "warm",
            warm_up: warm_up_count,
        },
        result,
    )
}

/// Verifier spawn latency proxy: `Session::verify()` with a trivial `true`
/// verify command over a tiny fixture — the same candidate-capture +
/// materialise + sandbox-spawn path `ward verify` uses, minus a real
/// build/test run. Not an isolated PID1-exec timestamp (`docs/performance.md`
/// §2's "excluding materialisation of large trees" carve-out does not apply
/// here since the fixture is tiny, so the two are close together, but this
/// is call-to-completion of a no-op command, analogous to how the
/// `sandbox_start` metric and the existing `ward run -- true` measurement
/// both use a trivial command as their proxy).
#[must_use]
pub fn verifier_spawn(
    fixtures_root: &Path,
    state: &Path,
    warm_up_count: usize,
    samples: usize,
) -> Metric {
    let id = "verifier_spawn";
    let description = "`ward verify` with a no-op verify command: candidate capture + \
        materialise + sandbox spawn, proxy for verifier startup";
    let budget_row = Some("Verification startup");
    let budget_ms = Some(500.0);
    if !ward_daemon::sandbox::available() {
        return Metric::unsupported(
            id,
            description,
            budget_row,
            budget_ms,
            "bubblewrap is not installed, or cannot create a user namespace on this \
             host (ward_daemon::sandbox::available() returned false); see \
             docs/performance.md §5",
        );
    }
    let fixture = fixtures_root.join("ci-subset");
    let result = (|| -> anyhow::Result<Samples> {
        let mut session = ward_daemon::Session::start_in(&fixture, state).map_err(to_anyhow)?;
        let mut run = || session.verify().map(|_| ()).map_err(to_anyhow);
        warm_up(warm_up_count, &mut run)?;
        let cpu_before = Usage::read(Who::Children);
        let durations = time_iterations(samples, &mut run)?;
        let cpu_after = Usage::read(Who::Children);
        Ok(child_samples(durations, cpu_before.zip(cpu_after)))
    })();
    finish(
        &MetricMeta {
            id,
            description,
            budget_row,
            budget_ms,
            fixture: "ci-subset",
            run_kind: "warm",
            warm_up: warm_up_count,
        },
        result,
    )
}

/// Pure digest work (walk + BLAKE3 hash, no CAS writes) over the pinned
/// `snapshot-digest` fixture: one cold (single first-run) sample and one
/// warm (median of `samples` after `warm_up` discarded) sample, mirroring
/// the cold/warm split `docs/experiments.md`'s E-02 uses.
#[must_use]
pub fn snapshot_digest(fixtures_root: &Path, warm_up: usize, samples: usize) -> (Metric, Metric) {
    let fixture = fixtures_root.join("snapshot-digest").join("tree");
    let description = "ward_snapshot::digest_worktree: walk + BLAKE3 hash, no CAS writes";
    let cold = digest_once("snapshot_digest_cold", description, &fixture, 0, 1, "cold");
    let warm = digest_once(
        "snapshot_digest_warm",
        description,
        &fixture,
        warm_up,
        samples,
        "warm",
    );
    (cold, warm)
}

fn digest_once(
    id: &str,
    description: &str,
    fixture: &Path,
    warm_up_count: usize,
    samples: usize,
    run_kind: &'static str,
) -> Metric {
    let result = (|| -> anyhow::Result<Samples> {
        // A fresh cache each call: this measures repeated cold-cache digest
        // work (OS page cache warm), not the incremental path.
        let mut run = || {
            let mut cache = HashCache::new();
            ward_snapshot::digest_worktree(fixture, CaptureOptions::default(), &mut cache)
                .map(|_| ())
                .map_err(to_anyhow)
        };
        warm_up(warm_up_count, &mut run)?;
        let cpu_before = Usage::read(Who::SelfProcess);
        let io_before = SelfIo::read();
        let durations = time_iterations(samples, &mut run)?;
        let cpu_after = Usage::read(Who::SelfProcess);
        let io_after = SelfIo::read();
        Ok(self_samples(
            durations,
            cpu_before.zip(cpu_after),
            io_before.zip(io_after),
        ))
    })();
    finish(
        &MetricMeta {
            id,
            description,
            budget_row: None,
            budget_ms: None,
            fixture: "snapshot-digest",
            run_kind,
            warm_up: warm_up_count,
        },
        result,
    )
}

/// Full capture (walk + hash + CAS write) over the pinned `snapshot-digest`
/// fixture, cold (fresh CAS) and warm (already-populated CAS, so writes
/// dedup but the walk and hash still run in full).
#[must_use]
pub fn snapshot_capture(fixtures_root: &Path, warm_up: usize, samples: usize) -> (Metric, Metric) {
    let fixture = fixtures_root.join("snapshot-digest").join("tree");
    let description = "SnapshotStore::capture: walk + hash + content-addressed store write";
    let cold_cas = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            let m = Metric::unsupported(
                "snapshot_capture_cold",
                description,
                None,
                None,
                &format!("could not create a scratch CAS directory: {e}"),
            );
            return (
                m,
                Metric::unsupported(
                    "snapshot_capture_warm",
                    description,
                    None,
                    None,
                    "skipped: cold run's scratch directory failed first",
                ),
            );
        }
    };
    let cold = capture_run(
        "snapshot_capture_cold",
        description,
        &fixture,
        cold_cas.path(),
        0,
        1,
        "cold",
    );
    let warm_cas = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            return (
                cold,
                Metric::unsupported(
                    "snapshot_capture_warm",
                    description,
                    None,
                    None,
                    &format!("could not create a scratch CAS directory: {e}"),
                ),
            );
        }
    };
    let warm = capture_run(
        "snapshot_capture_warm",
        description,
        &fixture,
        warm_cas.path(),
        warm_up,
        samples,
        "warm",
    );
    (cold, warm)
}

fn capture_run(
    id: &str,
    description: &str,
    fixture: &Path,
    cas_root: &Path,
    warm_up_count: usize,
    samples: usize,
    run_kind: &'static str,
) -> Metric {
    let result = (|| -> anyhow::Result<Samples> {
        let store = SnapshotStore::open(cas_root).map_err(to_anyhow)?;
        let mut run = || {
            store
                .store_snapshot(fixture, SnapshotRole::Candidate, CaptureOptions::default())
                .map(|_| ())
                .map_err(to_anyhow)
        };
        warm_up(warm_up_count, &mut run)?;
        let cpu_before = Usage::read(Who::SelfProcess);
        let io_before = SelfIo::read();
        let durations = time_iterations(samples, &mut run)?;
        let cpu_after = Usage::read(Who::SelfProcess);
        let io_after = SelfIo::read();
        Ok(self_samples(
            durations,
            cpu_before.zip(cpu_after),
            io_before.zip(io_after),
        ))
    })();
    finish(
        &MetricMeta {
            id,
            description,
            budget_row: None,
            budget_ms: None,
            fixture: "snapshot-digest",
            run_kind,
            warm_up: warm_up_count,
        },
        result,
    )
}

/// The parts of a [`Metric`] that are fixed before it runs, bundled so
/// [`finish`] does not need a long positional argument list.
struct MetricMeta<'a> {
    id: &'a str,
    description: &'a str,
    budget_row: Option<&'a str>,
    budget_ms: Option<f64>,
    fixture: &'a str,
    run_kind: &'static str,
    warm_up: usize,
}

/// Turn a metric closure's result into a [`Metric`]: `Measured` on success,
/// `Unsupported` (with the error) on failure. A metric that cannot complete
/// even once is reported as unmeasured rather than silently dropped (#150
/// acceptance).
fn finish(meta: &MetricMeta<'_>, result: anyhow::Result<Samples>) -> Metric {
    match result {
        Ok(s) => Metric::measured(
            meta.id,
            meta.description,
            meta.budget_row,
            meta.budget_ms,
            Stats::from_samples(meta.fixture, meta.run_kind, meta.warm_up, &s),
        ),
        Err(e) => Metric::unsupported(
            meta.id,
            meta.description,
            meta.budget_row,
            meta.budget_ms,
            &format!("{e:#}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::report::MetricStatus;

    fn fixtures_root() -> std::path::PathBuf {
        // crates/ward-bench -> repo root -> benchmarks/fixtures
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crates/ward-bench has a workspace root two levels up")
            .join("benchmarks")
            .join("fixtures")
    }

    #[test]
    fn snapshot_digest_measures_on_the_pinned_fixture() {
        let (cold, warm) = snapshot_digest(&fixtures_root(), 1, 3);
        assert_eq!(cold.status, MetricStatus::Measured, "{cold:?}");
        assert_eq!(warm.status, MetricStatus::Measured, "{warm:?}");
        let cold_stats = cold.stats.expect("measured");
        assert_eq!(cold_stats.samples, 1);
        let warm_stats = warm.stats.expect("measured");
        assert_eq!(warm_stats.samples, 3);
        assert!(warm_stats.p50_ms >= 0.0);
    }

    #[test]
    fn snapshot_capture_measures_on_the_pinned_fixture() {
        let (cold, warm) = snapshot_capture(&fixtures_root(), 1, 3);
        assert_eq!(cold.status, MetricStatus::Measured, "{cold:?}");
        assert_eq!(warm.status, MetricStatus::Measured, "{warm:?}");
    }

    #[test]
    fn ward_status_measures_without_a_daemon() {
        let tmp_state = tempfile::tempdir().expect("tempdir");
        let m = ward_status(&fixtures_root(), tmp_state.path(), 1, 3);
        assert_eq!(m.status, MetricStatus::Measured, "{m:?}");
        let got = m.stats.expect("measured");
        assert_eq!(got.samples, 3);
    }

    /// Sandbox-dependent metrics degrade to `Unsupported` with a reason
    /// rather than panicking or erroring the whole run when bubblewrap is
    /// unavailable — exercised directly regardless of whether this host
    /// happens to have bubblewrap, since both outcomes must be handled.
    #[test]
    fn sandbox_start_never_panics_either_way() {
        let state = tempfile::tempdir().expect("tempdir");
        let m = sandbox_start(&fixtures_root(), state.path(), 0, 1);
        assert!(matches!(
            m.status,
            MetricStatus::Measured | MetricStatus::Unsupported
        ));
        if m.status == MetricStatus::Unsupported {
            assert!(m.unmeasured_reason.is_some());
        }
    }

    #[test]
    fn verifier_spawn_never_panics_either_way() {
        let state = tempfile::tempdir().expect("tempdir");
        let m = verifier_spawn(&fixtures_root(), state.path(), 0, 1);
        assert!(matches!(
            m.status,
            MetricStatus::Measured | MetricStatus::Unsupported
        ));
        if m.status == MetricStatus::Unsupported {
            assert!(m.unmeasured_reason.is_some());
        }
    }
}
