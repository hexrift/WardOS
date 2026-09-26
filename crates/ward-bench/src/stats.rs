//! Sampling, percentile and resource-usage helpers shared by every metric.
//!
//! Methodology follows `docs/performance.md` §3: percentiles are p50/p99,
//! "warm" is the median of N runs after a fixed number of discarded
//! warm-up runs, and "cold" is a single first-run sample.

use std::time::{Duration, Instant};

/// A batch of wall-clock samples for one metric, plus resource usage totals
/// covering exactly the timed (non-warm-up) samples.
#[derive(Clone, Debug, Default)]
pub struct Samples {
    /// Wall-clock duration of each timed run, in the order they ran.
    pub durations: Vec<Duration>,
    /// User CPU time consumed across all timed runs (self or children,
    /// depending on what the metric measured), if available on this OS.
    pub cpu_user: Option<Duration>,
    /// System CPU time consumed across all timed runs.
    pub cpu_sys: Option<Duration>,
    /// Peak resident set size observed by the end of the timed runs, in
    /// kilobytes. This is a high-water mark (see [`crate::rusage`]), not a
    /// per-run figure, and — for child-process metrics — a high-water mark
    /// across every child this process has reaped so far, not isolated to
    /// this metric alone.
    pub max_rss_kb: Option<i64>,
    /// Bytes read from disk across the timed runs, if available (Linux,
    /// self-process metrics only).
    pub io_read_bytes: Option<u64>,
    /// Bytes written to disk across the timed runs, if available.
    pub io_write_bytes: Option<u64>,
}

impl Samples {
    /// Number of timed samples (excludes discarded warm-ups).
    #[must_use]
    pub fn count(&self) -> usize {
        self.durations.len()
    }

    /// The p50 (median) wall-clock duration in milliseconds, or `None` when
    /// there are no samples.
    #[must_use]
    pub fn p50_ms(&self) -> Option<f64> {
        percentile_ms(&self.durations, 0.50)
    }

    /// The p99 wall-clock duration in milliseconds.
    #[must_use]
    pub fn p99_ms(&self) -> Option<f64> {
        percentile_ms(&self.durations, 0.99)
    }

    /// Mean wall-clock duration in milliseconds.
    #[must_use]
    // A sample count in the thousands at most, nowhere near f64's 52-bit mantissa limit.
    #[allow(clippy::cast_precision_loss)]
    pub fn mean_ms(&self) -> Option<f64> {
        if self.durations.is_empty() {
            return None;
        }
        let total: f64 = self.durations.iter().map(Duration::as_secs_f64).sum();
        Some(total / self.durations.len() as f64 * 1000.0)
    }

    /// Minimum wall-clock duration in milliseconds.
    #[must_use]
    pub fn min_ms(&self) -> Option<f64> {
        self.durations
            .iter()
            .min()
            .map(|d| d.as_secs_f64() * 1000.0)
    }

    /// Maximum wall-clock duration in milliseconds.
    #[must_use]
    pub fn max_ms(&self) -> Option<f64> {
        self.durations
            .iter()
            .max()
            .map(|d| d.as_secs_f64() * 1000.0)
    }

    /// Mean CPU time per sample (user + sys), in milliseconds, when rusage
    /// was available and at least one sample ran.
    #[must_use]
    // A sample count in the thousands at most, nowhere near f64's 52-bit mantissa limit.
    #[allow(clippy::cast_precision_loss)]
    pub fn cpu_ms_per_sample(&self) -> Option<f64> {
        let n = self.count();
        if n == 0 {
            return None;
        }
        let user = self.cpu_user.map_or(0.0, |d| d.as_secs_f64());
        let sys = self.cpu_sys.map_or(0.0, |d| d.as_secs_f64());
        if self.cpu_user.is_none() && self.cpu_sys.is_none() {
            return None;
        }
        Some((user + sys) / n as f64 * 1000.0)
    }
}

/// The `q`-th percentile (0.0..=1.0) of `durations`, in milliseconds, using
/// nearest-rank on the sorted samples. `None` for an empty slice.
// `q` is always in 0.0..=1.0 and `sorted.len()` is a sample count in the thousands at
// most, so the rank this computes is always in-range, non-negative and far below
// `usize`'s width; the float round-trip cannot truncate, wrap or lose the sign here.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn percentile_ms(durations: &[Duration], q: f64) -> Option<f64> {
    if durations.is_empty() {
        return None;
    }
    let mut sorted: Vec<Duration> = durations.to_vec();
    sorted.sort_unstable();
    let rank = ((q * sorted.len() as f64).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    Some(sorted[rank].as_secs_f64() * 1000.0)
}

/// Run `count` discarded warm-up iterations of `f`. Callers that also
/// capture resource usage around the timed samples must call this
/// *before* reading their "before" snapshot — a metric's warm-up runs are
/// real work (page cache fills, allocator warm-up) that must not land
/// inside the CPU/RSS/IO delta a timed [`time_iterations`] call reports,
/// even though they are deliberately excluded from its wall-clock
/// durations. `f` returning `Err` aborts the batch, matching
/// [`time_iterations`].
pub fn warm_up<F, T, E>(count: usize, mut f: F) -> Result<(), E>
where
    F: FnMut() -> Result<T, E>,
{
    for _ in 0..count {
        f()?;
    }
    Ok(())
}

/// Run `samples` timed iterations of `f`, returning their wall-clock
/// durations. Does not include a warm-up: callers that want discarded
/// warm-up runs call [`warm_up`] first, before capturing any "before"
/// resource-usage snapshot they mean to pair with this call's samples. `f`
/// returning `Err` aborts the whole batch (a metric that cannot even
/// complete once is reported as unsupported by the caller, not partially
/// measured).
pub fn time_iterations<F, T, E>(samples: usize, mut f: F) -> Result<Vec<Duration>, E>
where
    F: FnMut() -> Result<T, E>,
{
    let mut out = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        f()?;
        out.push(start.elapsed());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn percentile_of_empty_is_none() {
        assert_eq!(percentile_ms(&[], 0.50), None);
    }

    #[test]
    fn median_of_five_is_the_middle_sample() {
        let d: Vec<Duration> = [1, 2, 3, 4, 5]
            .iter()
            .map(|ms| Duration::from_millis(*ms))
            .collect();
        assert_eq!(percentile_ms(&d, 0.50), Some(3.0));
    }

    #[test]
    fn p99_of_small_samples_is_the_max() {
        let d: Vec<Duration> = [1, 2, 3]
            .iter()
            .map(|ms| Duration::from_millis(*ms))
            .collect();
        assert_eq!(percentile_ms(&d, 0.99), Some(3.0));
    }

    #[test]
    fn samples_report_none_when_empty() {
        let s = Samples::default();
        assert_eq!(s.count(), 0);
        assert_eq!(s.p50_ms(), None);
        assert_eq!(s.p99_ms(), None);
        assert_eq!(s.mean_ms(), None);
        assert_eq!(s.min_ms(), None);
        assert_eq!(s.max_ms(), None);
    }

    #[test]
    fn warm_up_then_time_iterations_counts_each_phase_separately() {
        let calls = std::cell::Cell::new(0usize);
        let mut run = || -> Result<(), ()> {
            calls.set(calls.get() + 1);
            Ok(())
        };
        warm_up(3, &mut run).unwrap();
        assert_eq!(
            calls.get(),
            3,
            "warm-up runs happen, discarding nothing counted"
        );
        let result = time_iterations(5, &mut run);
        assert_eq!(result.unwrap().len(), 5);
        assert_eq!(
            calls.get(),
            8,
            "warm-up and timed calls both ran, once each"
        );
    }

    #[test]
    fn warm_up_propagates_the_first_error() {
        let result: Result<(), &'static str> = warm_up(3, || Err::<(), _>("boom"));
        assert_eq!(result, Err("boom"));
    }

    #[test]
    fn time_iterations_propagates_the_first_error() {
        let result: Result<Vec<Duration>, &'static str> =
            time_iterations(3, || Err::<(), _>("boom"));
        assert_eq!(result, Err("boom"));
    }
}
