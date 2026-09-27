//! The versioned JSON report and its human-readable rendering (#150 item 4).

use serde::Serialize;

use crate::stats::Samples;

/// Bumped whenever a field is removed or its meaning changes; additive
/// fields do not require a bump. Consumers should reject a report whose
/// `schema_version` they do not recognise rather than guess.
pub const SCHEMA_VERSION: u32 = 1;

/// Top-level report: one run of `ward benchmark`.
#[derive(Debug, Serialize)]
pub struct Report {
    /// See [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Always `"ward-bench"`; kept explicit in the JSON so a report is
    /// self-describing without relying on the file name.
    pub tool: &'static str,
    /// This crate's own version (`CARGO_PKG_VERSION`), i.e. the runner's
    /// version, distinct from `environment.wardos_version`.
    pub tool_version: &'static str,
    /// RFC 3339 UTC timestamp of when this report was generated.
    pub generated_at: String,
    /// Image/source and runtime metadata (#150 item 2).
    pub environment: Environment,
    /// One entry per metric this tool knows about — implemented and
    /// measured, implemented but unsupported on this host (e.g. no
    /// bubblewrap), or not implemented in this pass at all (hardware- or
    /// compositor-dependent). Never silently omitted (#150 acceptance).
    pub metrics: Vec<Metric>,
}

/// Reproducibility metadata (`docs/performance.md` §4), narrowed to what a
/// CI runner can actually report — no fixed reference hardware, firmware or
/// thermal state here; that record is for the hardware subset (#84/#99).
#[derive(Debug, Serialize)]
pub struct Environment {
    /// The `WardOS` workspace version (`workspace.package.version`).
    pub wardos_version: String,
    /// `git rev-parse HEAD`, when this is a git checkout and the command
    /// succeeds; `None` otherwise (e.g. a source tarball).
    pub git_commit: Option<String>,
    /// Whether the working tree had uncommitted changes when this ran
    /// (`git status --porcelain` non-empty). `None` when unknown.
    pub git_dirty: Option<bool>,
    /// `std::env::consts::OS` (e.g. `"linux"`).
    pub os: &'static str,
    /// `std::env::consts::ARCH` (e.g. `"x86_64"`).
    pub arch: &'static str,
    /// `uname -r`, when readable.
    pub kernel_release: Option<String>,
    /// Logical CPU count (`std::thread::available_parallelism`).
    pub cpu_count: usize,
    /// Cargo profile the runner itself was built with (`"debug"` or
    /// `"release"`) — timings from a debug build are not comparable to a
    /// release build's, so this is always recorded alongside the numbers.
    pub build_profile: &'static str,
    /// Whether a recognised CI environment variable was set
    /// (`CI`/`GITHUB_ACTIONS`).
    pub ci: bool,
    /// The CI runner's reported OS image, when `RUNNER_OS`/`ImageOS` (GitHub
    /// Actions) is set; `None` locally.
    pub ci_runner_os: Option<String>,
}

/// Whether a metric produced real numbers or is being reported as
/// unmeasured, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricStatus {
    /// Ran successfully; `stats` is populated.
    Measured,
    /// Implemented, but a prerequisite this host lacks (e.g. bubblewrap)
    /// kept it from running.
    Unsupported,
    /// Not implemented in this pass at all (needs the reference rig or a
    /// real compositor/desktop session) — see `docs/performance.md` §1/§2
    /// and issues #84/#99.
    NotImplemented,
}

/// One row: either a budget from `docs/performance.md` §2 this tool measured
/// (`stats: Some`), or one it explicitly could not, with a reason (#150
/// acceptance: "CI ... identifies unsupported metrics as unmeasured").
#[derive(Debug, Serialize)]
pub struct Metric {
    /// Stable identifier, e.g. `"sandbox_start"`. Matches the CLI's `--only`
    /// filter and is meant to be diffed across revisions/runs.
    pub id: String,
    /// One-line human description.
    pub description: String,
    /// The exact `docs/performance.md` §2 budget row name this corresponds
    /// to, when there is one.
    pub budget_row: Option<String>,
    /// The budget's own target latency in milliseconds, when §2 states one
    /// as a plain number (a handful are hardware-only wall-clock durations
    /// like "boot to login" that this omits rather than mis-parse).
    pub budget_ms: Option<f64>,
    /// Whether this metric ran successfully, was implemented but unrunnable
    /// here, or is not implemented in this pass at all.
    pub status: MetricStatus,
    /// Present exactly when `status != Measured`.
    pub unmeasured_reason: Option<String>,
    /// Present exactly when `status == Measured`.
    pub stats: Option<Stats>,
}

/// The measured numbers for one metric (#150 item 4: "sample counts,
/// p50/p99, CPU/RSS and I/O work where measurable").
#[derive(Debug, Serialize)]
pub struct Stats {
    /// Pinned fixture this metric ran against, e.g. `"ci-subset"`.
    pub fixture: String,
    /// `"cold"` (single first-run sample) or `"warm"` (median of `samples`
    /// after `warm_up_discarded` discarded runs) — `docs/performance.md` §3.
    pub run_kind: &'static str,
    /// Number of timed samples (excludes discarded warm-ups).
    pub samples: usize,
    /// Number of warm-up runs discarded before timing began.
    pub warm_up_discarded: usize,
    /// Median wall-clock duration, milliseconds.
    pub p50_ms: f64,
    /// 99th-percentile wall-clock duration, milliseconds.
    pub p99_ms: f64,
    /// Mean wall-clock duration, milliseconds.
    pub mean_ms: f64,
    /// Minimum observed wall-clock duration, milliseconds.
    pub min_ms: f64,
    /// Maximum observed wall-clock duration, milliseconds.
    pub max_ms: f64,
    /// Mean CPU time (user + sys) per sample, milliseconds, when available.
    pub cpu_ms_per_sample: Option<f64>,
    /// Peak RSS observed by the end of this metric's runs, kilobytes. A
    /// high-water mark, not a per-run figure — see [`crate::rusage`].
    pub max_rss_kb: Option<i64>,
    /// Bytes read from storage across the timed runs (self-process metrics
    /// only; `None` for metrics that spawn a sandboxed child).
    pub io_read_bytes: Option<u64>,
    /// Bytes written to storage across the timed runs.
    pub io_write_bytes: Option<u64>,
}

impl Stats {
    /// Build a report [`Stats`] row from a raw [`Samples`] batch.
    #[must_use]
    pub fn from_samples(
        fixture: &str,
        run_kind: &'static str,
        warm_up_discarded: usize,
        s: &Samples,
    ) -> Self {
        Self {
            fixture: fixture.to_string(),
            run_kind,
            samples: s.count(),
            warm_up_discarded,
            p50_ms: s.p50_ms().unwrap_or(0.0),
            p99_ms: s.p99_ms().unwrap_or(0.0),
            mean_ms: s.mean_ms().unwrap_or(0.0),
            min_ms: s.min_ms().unwrap_or(0.0),
            max_ms: s.max_ms().unwrap_or(0.0),
            cpu_ms_per_sample: s.cpu_ms_per_sample(),
            max_rss_kb: s.max_rss_kb,
            io_read_bytes: s.io_read_bytes,
            io_write_bytes: s.io_write_bytes,
        }
    }
}

impl Metric {
    /// A metric that ran and produced numbers.
    #[must_use]
    pub fn measured(
        id: &str,
        description: &str,
        budget_row: Option<&str>,
        budget_ms: Option<f64>,
        stats: Stats,
    ) -> Self {
        Self {
            id: id.to_string(),
            description: description.to_string(),
            budget_row: budget_row.map(str::to_string),
            budget_ms,
            status: MetricStatus::Measured,
            unmeasured_reason: None,
            stats: Some(stats),
        }
    }

    /// A metric this tool implements but could not run here (missing
    /// prerequisite).
    #[must_use]
    pub fn unsupported(
        id: &str,
        description: &str,
        budget_row: Option<&str>,
        budget_ms: Option<f64>,
        reason: &str,
    ) -> Self {
        Self {
            id: id.to_string(),
            description: description.to_string(),
            budget_row: budget_row.map(str::to_string),
            budget_ms,
            status: MetricStatus::Unsupported,
            unmeasured_reason: Some(reason.to_string()),
            stats: None,
        }
    }

    /// A `docs/performance.md` §2 budget this pass does not implement at
    /// all (compositor/hardware-dependent).
    #[must_use]
    pub fn not_implemented(
        id: &str,
        description: &str,
        budget_row: &str,
        budget_ms: Option<f64>,
        reason: &str,
    ) -> Self {
        Self {
            id: id.to_string(),
            description: description.to_string(),
            budget_row: Some(budget_row.to_string()),
            budget_ms,
            status: MetricStatus::NotImplemented,
            unmeasured_reason: Some(reason.to_string()),
            stats: None,
        }
    }
}

/// Render `report` as the concise human table `docs/performance.md` §5
/// describes (real numbers this time, not the illustrative mockup).
#[must_use]
pub fn human_report(report: &Report) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "ward-bench {} — {}",
        report.tool_version, report.generated_at
    );
    let _ = writeln!(
        out,
        "wardos {} · {} {} · kernel {} · {} vCPU · {} build{}",
        report.environment.wardos_version,
        report.environment.os,
        report.environment.arch,
        report
            .environment
            .kernel_release
            .as_deref()
            .unwrap_or("unknown"),
        report.environment.cpu_count,
        report.environment.build_profile,
        if report.environment.ci { " · CI" } else { "" },
    );
    if let Some(commit) = &report.environment.git_commit {
        let dirty = matches!(report.environment.git_dirty, Some(true));
        let _ = writeln!(
            out,
            "commit {commit}{}",
            if dirty { " (dirty)" } else { "" }
        );
    }
    out.push('\n');
    let _ = writeln!(
        out,
        "{:<24} {:>9} {:>9} {:>7} {:>9} notes",
        "metric", "p50", "p99", "n", "status"
    );
    for m in &report.metrics {
        if let (MetricStatus::Measured, Some(s)) = (&m.status, &m.stats) {
            let budget = m.budget_ms.map_or_else(String::new, |b| {
                if s.p50_ms > b {
                    format!(" (budget {b:.0} ms, OVER)")
                } else {
                    format!(" (budget {b:.0} ms)")
                }
            });
            let _ = writeln!(
                out,
                "{:<24} {:>7.2}ms {:>7.2}ms {:>7} {:>9} {}{}",
                m.id, s.p50_ms, s.p99_ms, s.samples, "measured", s.run_kind, budget
            );
        } else {
            let status = match m.status {
                MetricStatus::Unsupported => "unsupported",
                MetricStatus::NotImplemented => "not-impl",
                MetricStatus::Measured => unreachable!("handled above"),
            };
            let _ = writeln!(
                out,
                "{:<24} {:>9} {:>9} {:>7} {:>9} {}",
                m.id,
                "—",
                "—",
                "—",
                status,
                m.unmeasured_reason.as_deref().unwrap_or(""),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn env() -> Environment {
        Environment {
            wardos_version: "0.0.0".into(),
            git_commit: None,
            git_dirty: None,
            os: "linux",
            arch: "x86_64",
            kernel_release: None,
            cpu_count: 1,
            build_profile: "debug",
            ci: false,
            ci_runner_os: None,
        }
    }

    #[test]
    fn json_round_trips_through_serde_value() {
        let report = Report {
            schema_version: SCHEMA_VERSION,
            tool: "ward-bench",
            tool_version: "0.0.0",
            generated_at: "2026-01-01T00:00:00Z".into(),
            environment: env(),
            metrics: vec![Metric::unsupported(
                "sandbox_start",
                "d",
                Some("Agent sandbox warm start"),
                Some(150.0),
                "no bubblewrap",
            )],
        };
        let v = serde_json::to_value(&report).expect("serialises");
        assert_eq!(v["schema_version"], SCHEMA_VERSION);
        assert_eq!(v["metrics"][0]["status"], "unsupported");
        assert_eq!(v["metrics"][0]["unmeasured_reason"], "no bubblewrap");
    }

    #[test]
    fn human_report_marks_unmeasured_rows_without_omitting_them() {
        let report = Report {
            schema_version: SCHEMA_VERSION,
            tool: "ward-bench",
            tool_version: "0.0.0",
            generated_at: "2026-01-01T00:00:00Z".into(),
            environment: env(),
            metrics: vec![
                Metric::not_implemented(
                    "launcher_visible",
                    "d",
                    "Launcher visible",
                    Some(16.0),
                    "needs a real compositor (#84)",
                ),
                Metric::measured(
                    "ward_status",
                    "d",
                    Some("`ward status`"),
                    Some(10.0),
                    Stats::from_samples("ci-subset", "warm", 3, &Samples::default()),
                ),
            ],
        };
        let text = human_report(&report);
        assert!(text.contains("launcher_visible"));
        assert!(text.contains("not-impl"));
        assert!(text.contains("needs a real compositor"));
        assert!(text.contains("ward_status"));
    }
}
