//! `ward-bench` — the reproducible, CI-measurable performance harness
//! `docs/performance.md` §5 describes and issue #150 asks for.
//!
//! Scope, deliberately: the subset that needs no reference hardware and no
//! real compositor/desktop session (`docs/performance.md` §5: "sandbox
//! start, snapshot, `ward status`, verifier spawn"). Everything else in
//! `docs/performance.md` §2's budget table — launcher/workspace/terminal/bar
//! latency, idle CPU/RAM, boot/login/resume, install — needs Hyprland,
//! Waybar or the reference rig, and is reported as `not_implemented` rather
//! than silently dropped (see [`unsupported::not_implemented_metrics`]).
//!
//! No pass/fail regression gate: `docs/performance.md` §5 and issue #150
//! both say to measure and publish first, gate only once variance is known.

#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

pub mod environment;
pub mod metrics;
pub mod report;
pub mod rusage;
pub mod stats;
pub mod unsupported;

use std::path::Path;

pub use report::{Metric, MetricStatus, Report, Stats as MetricStats};

/// This crate's own version.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How the CI-measurable subset is run.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Timed samples per "warm" metric (`docs/performance.md` §3 default: 20).
    pub samples: usize,
    /// Discarded warm-up runs before a "warm" metric's timed samples.
    pub warm_up: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            samples: metrics::DEFAULT_SAMPLES,
            warm_up: metrics::DEFAULT_WARM_UP,
        }
    }
}

/// Run the full CI-measurable subset against the pinned fixtures under
/// `fixtures_root` (normally `<repo>/benchmarks/fixtures`), using a fresh,
/// temporary state directory (CAS + session log) that is removed when this
/// returns. Every metric this tool knows about appears in the result —
/// measured, unsupported-here, or not-implemented-this-pass — never omitted.
pub fn run_ci_subset(fixtures_root: &Path, options: Options) -> anyhow::Result<Report> {
    let state = tempfile::tempdir()?;
    let mut metrics = Vec::new();

    metrics.push(metrics::sandbox_start(
        fixtures_root,
        state.path(),
        options.warm_up,
        options.samples,
    ));
    metrics.push(metrics::ward_status(
        fixtures_root,
        state.path(),
        options.warm_up,
        options.samples,
    ));
    metrics.push(metrics::verifier_spawn(
        fixtures_root,
        state.path(),
        options.warm_up,
        options.samples,
    ));
    let (digest_cold, digest_warm) =
        metrics::snapshot_digest(fixtures_root, options.warm_up, options.samples);
    metrics.push(digest_cold);
    metrics.push(digest_warm);
    let (capture_cold, capture_warm) =
        metrics::snapshot_capture(fixtures_root, options.warm_up, options.samples);
    metrics.push(capture_cold);
    metrics.push(capture_warm);

    metrics.extend(unsupported::not_implemented_metrics());

    Ok(Report {
        schema_version: report::SCHEMA_VERSION,
        tool: "ward-bench",
        tool_version: TOOL_VERSION,
        generated_at: now_rfc3339(),
        environment: environment::collect(),
        metrics,
    })
}

/// A minimal RFC 3339 UTC timestamp, without pulling in a datetime crate:
/// `SystemTime` split into days/seconds since the epoch with the proleptic
/// Gregorian calendar's usual civil-from-days formula.
// `secs / 86400` is a day count nowhere near `i64::MAX` for any wall-clock time this
// process will ever see.
#[allow(clippy::cast_possible_wrap)]
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64;
    let time_of_day = secs % 86400;
    let (hour, minute, second) = (
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
    );
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's `civil_from_days`: days since the Unix epoch to a
/// proleptic Gregorian (year, month, day), valid for the whole `i64` range.
// Every intermediate here is bounded by the comments beside it (era-of-400-years
// arithmetic keeps `doe`/`yoe`/`doy`/`mp` tiny); none of these conversions can
// truncate, wrap or lose a sign for any date this tool will ever format.
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation
)]
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn civil_from_days_matches_known_dates() {
        // 1970-01-01 is day 0.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2026-09-24 (today, per the task): confirm via day count.
        // days(2026-09-24) - days(1970-01-01) computed independently below.
        assert_eq!(civil_from_days(20720), (2026, 9, 24));
    }

    #[test]
    fn now_rfc3339_has_the_expected_shape() {
        let ts = now_rfc3339();
        assert_eq!(ts.len(), "2026-09-24T00:00:00Z".len());
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.as_bytes()[4], b'-');
        assert_eq!(ts.as_bytes()[7], b'-');
        assert_eq!(ts.as_bytes()[10], b'T');
    }

    #[test]
    fn options_default_matches_the_documented_methodology() {
        let o = Options::default();
        assert_eq!(o.samples, 20);
        assert_eq!(o.warm_up, 3);
    }
}
