//! CPU, peak-RSS and I/O snapshots, for the "CPU/RSS and I/O work where
//! measurable" part of #150 item 4.
//!
//! This workspace forbids `unsafe` code (`workspace.lints.rust.unsafe_code =
//! "forbid"`), so this reads `/proc/self/stat`/`/proc/self/status` rather
//! than calling `getrusage(2)` through `libc` directly. `utime`/`stime`/
//! `cutime`/`cstime` are cumulative for the process (or its reaped
//! children), so a before/after difference is a valid sum over exactly the
//! iterations run in between; `VmHWM` is a high-water mark, not cumulative,
//! so it is never diffed — only read as "the peak observed by this point"
//! (documented on [`crate::stats::Samples::max_rss_kb`]). Linux-only; other
//! platforms get `None` everywhere below and metrics report their CPU/RSS/IO
//! fields as unavailable rather than fail.

use std::time::Duration;

fn ticks_to_duration(ticks: u64, ticks_per_second: u64) -> Option<Duration> {
    if ticks_per_second == 0 {
        return None;
    }

    let whole_seconds = ticks / ticks_per_second;
    let remainder = ticks % ticks_per_second;
    let nanos = u128::from(remainder)
        .saturating_mul(1_000_000_000)
        / u128::from(ticks_per_second);
    Some(
        Duration::from_secs(whole_seconds)
            + Duration::from_nanos(u64::try_from(nanos).ok()?),
    )
}

#[cfg(target_os = "linux")]
fn clock_ticks_per_second() -> Option<u64> {
    let ticks = rustix::param::clock_ticks_per_second();
    (ticks > 0).then_some(ticks)
}

/// One usage reading: cumulative CPU time and a peak-RSS high-water mark.
#[derive(Clone, Copy, Debug, Default)]
pub struct Usage {
    /// Cumulative user CPU time.
    pub utime: Duration,
    /// Cumulative system CPU time.
    pub stime: Duration,
    /// Peak resident set size observed so far, in kilobytes. Only ever
    /// populated for [`Who::SelfProcess`] (`/proc/self/status`'s `VmHWM` has
    /// no equivalent aggregate for reaped children).
    pub max_rss_kb: Option<i64>,
}

/// Which process(es) to read usage for.
#[derive(Clone, Copy, Debug)]
pub enum Who {
    /// This process only.
    SelfProcess,
    /// This process's reaped children (`cutime`/`cstime` in
    /// `/proc/self/stat`, updated as each child is `wait`ed on).
    Children,
}

impl Usage {
    /// Read current usage for `who`. `None` off Linux, or if `/proc` cannot
    /// be read (e.g. a restricted container) — a measurement tool degrades
    /// gracefully rather than failing the whole run over optional numbers.
    #[must_use]
    pub fn read(who: Who) -> Option<Self> {
        read_usage(who)
    }

    /// `self - earlier` for the CPU fields (saturating at zero); `max_rss_kb`
    /// is copied from `self` unchanged (it is a high-water mark, never a
    /// delta — see the module doc comment).
    #[must_use]
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            utime: self.utime.saturating_sub(earlier.utime),
            stime: self.stime.saturating_sub(earlier.stime),
            max_rss_kb: self.max_rss_kb,
        }
    }
}

#[cfg(target_os = "linux")]
fn read_usage(who: Who) -> Option<Usage> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // Field 2 (`comm`) is parenthesised and may itself contain spaces or
    // parens, so split on the *last* ')' and treat what follows as
    // whitespace-separated fields starting at field 3 (`state`).
    let after_comm = stat.rsplit_once(')').map(|(_, rest)| rest)?;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // `fields[i]` is original field `i + 3`: state=3 is fields[0], so
    // utime(14)=fields[11], stime(15)=fields[12], cutime(16)=fields[13],
    // cstime(17)=fields[14].
    let ticks = |idx: usize| -> Option<u64> { fields.get(idx)?.parse().ok() };
    let ticks_per_second = clock_ticks_per_second()?;
    let (utime, stime) = match who {
        Who::SelfProcess => (ticks(11)?, ticks(12)?),
        Who::Children => (ticks(13)?, ticks(14)?),
    };
    let max_rss_kb = match who {
        Who::SelfProcess => vm_hwm_kb(),
        Who::Children => None,
    };
    Some(Usage {
        utime: ticks_to_duration(utime, ticks_per_second)?,
        stime: ticks_to_duration(stime, ticks_per_second)?,
        max_rss_kb,
    })
}

#[cfg(target_os = "linux")]
fn vm_hwm_kb() -> Option<i64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            // e.g. "    12345 kB"
            let digits: String = rest.chars().filter(char::is_ascii_digit).collect();
            return digits.parse().ok();
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn read_usage(_who: Who) -> Option<Usage> {
    None
}

/// The counters this tool reads from `/proc/self/io` (Linux-only; see
/// `proc(5)`). `read_bytes`/`write_bytes` are the kernel's own account of
/// storage I/O, which is what item 4 asks for ("I/O work where
/// measurable") — closer to real disk traffic than `rchar`/`wchar`, which
/// also count cached reads and buffered writes never flushed.
#[derive(Clone, Copy, Debug, Default)]
pub struct SelfIo {
    /// Bytes actually read from storage.
    pub read_bytes: u64,
    /// Bytes actually written to storage.
    pub write_bytes: u64,
}

impl SelfIo {
    /// Read `/proc/self/io` for this process. `None` off Linux, or if the
    /// file cannot be read (e.g. a restricted container).
    #[must_use]
    pub fn read() -> Option<Self> {
        read_proc_self_io()
    }

    /// `self - earlier`, saturating at zero.
    #[must_use]
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            read_bytes: self.read_bytes.saturating_sub(earlier.read_bytes),
            write_bytes: self.write_bytes.saturating_sub(earlier.write_bytes),
        }
    }
}

#[cfg(target_os = "linux")]
fn read_proc_self_io() -> Option<SelfIo> {
    let text = std::fs::read_to_string("/proc/self/io").ok()?;
    let mut io = SelfIo::default();
    for line in text.lines() {
        let (key, val) = line.split_once(':')?;
        let val: u64 = val.trim().parse().ok()?;
        match key {
            "read_bytes" => io.read_bytes = val,
            "write_bytes" => io.write_bytes = val,
            _ => {}
        }
    }
    Some(io)
}

#[cfg(not(target_os = "linux"))]
fn read_proc_self_io() -> Option<SelfIo> {
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn self_usage_reads_something_on_linux() {
        let u = Usage::read(Who::SelfProcess).expect("/proc/self/stat should be readable in CI");
        assert!(u.max_rss_kb.unwrap_or(0) >= 0);
    }

    #[test]
    fn tick_conversion_uses_the_reported_runtime_rate() {
        assert_eq!(
            ticks_to_duration(250, 250),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            ticks_to_duration(125, 250),
            Some(Duration::from_millis(500))
        );
        assert_eq!(ticks_to_duration(1, 0), None);
    }

    #[test]
    fn since_saturates_rather_than_underflows() {
        let earlier = Usage {
            utime: Duration::from_millis(50),
            stime: Duration::from_millis(50),
            max_rss_kb: Some(100),
        };
        let later = Usage {
            utime: Duration::from_millis(10),
            stime: Duration::from_millis(10),
            max_rss_kb: Some(90),
        };
        let delta = later.since(&earlier);
        assert_eq!(delta.utime, Duration::ZERO);
        assert_eq!(delta.stime, Duration::ZERO);
        assert_eq!(delta.max_rss_kb, Some(90));
    }

    #[test]
    fn io_since_saturates() {
        let earlier = SelfIo {
            read_bytes: 100,
            write_bytes: 100,
        };
        let later = SelfIo {
            read_bytes: 50,
            write_bytes: 150,
        };
        let delta = later.since(&earlier);
        assert_eq!(delta.read_bytes, 0);
        assert_eq!(delta.write_bytes, 50);
    }
}
