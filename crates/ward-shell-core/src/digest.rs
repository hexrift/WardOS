//! Coalescing rapid worktree-dirty triggers into a bounded number of scans
//! (#138 item 3, a smaller first slice of #138): a segment that never shows
//! freshness must never digest the tree at all, and a segment that does must
//! not re-digest once per record in a burst — but a real change must never be
//! silently dropped, whether it lands before a scan starts, while one is
//! already thought to be running, or between two quiet ticks.
//!
//! [`DigestGate`] is the state machine a follower drives; it knows nothing
//! about the worktree or the digest itself, only when another scan is owed.
//! [`DigestGate::mark_dirty`] records that the tree may have changed;
//! [`DigestGate::poll`] decides whether *now* is the moment to actually scan,
//! given the minimum interval between scan starts and whether the caller
//! wants an unconditional opportunity regardless of that interval (a quiet
//! tick, which must always be able to catch an edit made outside the sandbox
//! that no record ever reports — `docs/desktop.md`'s "the shell's bar").

use std::time::{Duration, Instant};

/// What [`DigestGate::poll`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Nothing to do: no trigger is pending, or the debounce interval has not
    /// elapsed since the last scan started.
    Wait,
    /// Start a scan now. The caller runs it and then calls
    /// [`DigestGate::finish`] once it completes.
    Scan,
}

/// Gates worktree digests behind a minimum interval between scans, without
/// ever losing a real invalidation. A caller with nothing to show for
/// freshness (a segment [`crate::trust::SegmentName::needs_freshness`] says
/// `false` for) simply never constructs or drives one.
#[derive(Clone, Debug, Default)]
pub struct DigestGate {
    /// A dirty trigger has arrived since the last scan started and has not
    /// yet been covered by a finished scan.
    dirty: bool,
    /// A scan [`DigestGate::poll`] started is thought to still be running
    /// ([`DigestGate::finish`] not yet called for it).
    scanning: bool,
    /// A dirty trigger arrived while `scanning` was true: the in-flight scan
    /// began before that trigger, so it cannot be assumed to cover it.
    dirty_during_scan: bool,
    /// When the last scan started, for the debounce interval.
    last_scan: Option<Instant>,
}

impl DigestGate {
    /// A gate with nothing pending and no scan yet run.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A trigger that may mean the worktree changed (a record arrived, or the
    /// caller otherwise knows the tree may be dirty). If a scan is currently
    /// in flight, the trigger is remembered separately so it survives that
    /// scan's [`DigestGate::finish`] even though the scan started before it
    /// and so cannot be trusted to have covered it.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
        if self.scanning {
            self.dirty_during_scan = true;
        }
    }

    /// Decide whether to scan now. `force` makes a scan happen unconditionally
    /// — the quiet-tick safety net — regardless of pending dirt or the
    /// interval; otherwise a scan starts only once something is dirty *and*
    /// at least `interval` has passed since the last scan started, so a burst
    /// of dirty triggers inside one interval collapses into a single scan.
    /// Returning [`Decision::Scan`] marks the gate as scanning: the caller
    /// must call [`DigestGate::finish`] once that scan completes.
    pub fn poll(&mut self, now: Instant, interval: Duration, force: bool) -> Decision {
        let elapsed = self
            .last_scan
            .is_none_or(|started| now.saturating_duration_since(started) >= interval);
        if force || (self.dirty && elapsed) {
            self.dirty = false;
            self.dirty_during_scan = false;
            self.scanning = true;
            self.last_scan = Some(now);
            Decision::Scan
        } else {
            Decision::Wait
        }
    }

    /// The scan [`DigestGate::poll`] started has finished. If a dirty trigger
    /// landed while it ran, that scan cannot be trusted to have covered it:
    /// the gate stays dirty and its interval clock is cleared, so the very
    /// next [`DigestGate::poll`] scans again immediately rather than waiting
    /// out a clock that started before the change it needs to cover.
    pub fn finish(&mut self) {
        self.scanning = false;
        if self.dirty_during_scan {
            self.dirty = true;
            self.dirty_during_scan = false;
            self.last_scan = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERVAL: Duration = Duration::from_millis(200);

    #[test]
    fn nothing_dirty_and_no_force_waits() {
        let mut gate = DigestGate::new();
        assert_eq!(gate.poll(Instant::now(), INTERVAL, false), Decision::Wait);
    }

    #[test]
    fn a_single_dirty_trigger_scans_once_with_the_interval_elapsed() {
        let mut gate = DigestGate::new();
        let t0 = Instant::now();
        gate.mark_dirty();
        assert_eq!(gate.poll(t0, INTERVAL, false), Decision::Scan);
        gate.finish();
        // Nothing new is dirty: the very next poll waits, even well past the
        // interval, since there is nothing left to cover.
        assert_eq!(
            gate.poll(t0 + INTERVAL * 10, INTERVAL, false),
            Decision::Wait
        );
    }

    /// (b) a burst of rapid dirty triggers coalesces into a bounded number of
    /// scans, not one per event.
    #[test]
    fn a_burst_of_dirty_triggers_inside_one_interval_coalesces_into_one_scan() {
        let mut gate = DigestGate::new();
        let t0 = Instant::now();
        let mut scans = 0;
        for ms in 0..50u64 {
            gate.mark_dirty();
            if gate.poll(t0 + Duration::from_millis(ms), INTERVAL, false) == Decision::Scan {
                scans += 1;
                gate.finish();
            }
        }
        assert_eq!(
            scans, 1,
            "fifty triggers inside one interval must not be fifty scans"
        );
        // Past the interval a fresh dirty trigger scans again: debouncing
        // coalesces a burst, it does not swallow later, genuine change.
        gate.mark_dirty();
        assert_eq!(gate.poll(t0 + INTERVAL, INTERVAL, false), Decision::Scan);
    }

    /// (c) an invalidation that arrives during an in-flight scan is never
    /// lost: the scan either covers it (it arrived before the scan started)
    /// or a follow-up scan is guaranteed (it arrived after).
    #[test]
    fn a_dirty_trigger_during_an_in_flight_scan_earns_a_follow_up() {
        let mut gate = DigestGate::new();
        let t0 = Instant::now();
        gate.mark_dirty();
        assert_eq!(gate.poll(t0, INTERVAL, false), Decision::Scan);
        // While that scan is still in flight (poll started it, finish() has
        // not been called yet), another change lands.
        gate.mark_dirty();
        // The scan completes without having seen the second trigger.
        gate.finish();
        // The very next opportunity must scan again, immediately — not wait
        // out the interval from the first scan's start, which would let the
        // second change sit unreported for a full interval, and not silently
        // drop it either.
        assert_eq!(
            gate.poll(t0 + Duration::from_millis(1), INTERVAL, false),
            Decision::Scan,
            "a trigger that arrived mid-scan must not be lost"
        );
    }

    /// A trigger that arrives *before* a scan starts is simply covered by
    /// that scan: no follow-up is owed once it finishes clean.
    #[test]
    fn a_trigger_covered_by_its_own_scan_does_not_force_a_follow_up() {
        let mut gate = DigestGate::new();
        let t0 = Instant::now();
        gate.mark_dirty();
        assert_eq!(gate.poll(t0, INTERVAL, false), Decision::Scan);
        gate.finish();
        assert_eq!(
            gate.poll(t0 + Duration::from_millis(1), INTERVAL, false),
            Decision::Wait,
            "the scan that just ran covered the only pending trigger"
        );
    }

    /// The quiet-tick safety net: `force` always scans, so an edit made
    /// outside the sandbox (no record, nothing marked dirty) is still caught.
    #[test]
    fn force_scans_every_time_regardless_of_dirt_or_interval() {
        let mut gate = DigestGate::new();
        let t0 = Instant::now();
        assert_eq!(gate.poll(t0, INTERVAL, true), Decision::Scan);
        gate.finish();
        assert_eq!(
            gate.poll(t0, INTERVAL, true),
            Decision::Scan,
            "every tick, not just the first"
        );
    }

    /// A dirty trigger that arrives after a scan has already finished clean
    /// starts its own fresh interval, not the finished scan's.
    #[test]
    fn a_later_trigger_after_a_clean_finish_waits_out_its_own_interval() {
        let mut gate = DigestGate::new();
        let t0 = Instant::now();
        gate.mark_dirty();
        assert_eq!(gate.poll(t0, INTERVAL, false), Decision::Scan);
        gate.finish();
        let t1 = t0 + Duration::from_millis(50);
        gate.mark_dirty();
        assert_eq!(
            gate.poll(t1, INTERVAL, false),
            Decision::Wait,
            "the interval since the first scan has not elapsed yet"
        );
        assert_eq!(gate.poll(t1 + INTERVAL, INTERVAL, false), Decision::Scan);
    }
}
