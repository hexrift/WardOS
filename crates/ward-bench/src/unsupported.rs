//! The `docs/performance.md` §2 budget rows this pass does not implement at
//! all — compositor- or reference-hardware-dependent (#84/#99), or out of
//! this issue's CI-measurable subset (#150 items 2-5). Acceptance requires
//! these to show up as unmeasured, not be silently dropped from the report.

use crate::report::Metric;

/// One [`Metric::not_implemented`] row per remaining `docs/performance.md`
/// §2 budget not covered by [`crate::metrics`].
#[must_use]
pub fn not_implemented_metrics() -> Vec<Metric> {
    vec![
        Metric::not_implemented(
            "launcher_visible",
            "key event to first frame with content, via compositor timestamp",
            "Launcher visible",
            Some(16.0),
            "needs a real Hyprland/Waybar compositor session; see #84",
        ),
        Metric::not_implemented(
            "workspace_response",
            "key event to frame, workspace switch",
            "Workspace response",
            Some(8.0),
            "needs a real compositor session; see #84",
        ),
        Metric::not_implemented(
            "terminal_visible",
            "key to first prompt frame",
            "Terminal visible",
            Some(50.0),
            "needs a real compositor session; see #84",
        ),
        Metric::not_implemented(
            "bar_state_update",
            "event timestamp to frame, budget is 1 frame not a fixed ms figure",
            "Bar state update",
            None,
            "needs a real compositor session (Waybar); see #84",
        ),
        Metric::not_implemented(
            "observer_event_propagation",
            "kernel/proxy timestamp to subscriber receive (producer-to-subscriber \
             latency, #150 item 4's second half)",
            "Observer event propagation",
            Some(25.0),
            "needs a live subscriber over a real event stream; not implemented this \
             pass (judged not cheap to add safely alongside the rest of this subset)",
        ),
        Metric::not_implemented(
            "project_warm_resume",
            "cd + `ward status` to READY",
            "Project environment warm resume",
            Some(300.0),
            "not in this pass's CI-measurable subset; see #150 item 2",
        ),
        Metric::not_implemented(
            "entry_snapshot_stall_btrfs",
            "agent-visible freeze to thaw on a 200k-file Btrfs worktree",
            "Entry snapshot stall (Btrfs path)",
            Some(100.0),
            "needs a Btrfs-backed host and the E-02-scale fixture (200k files, 1 GiB); \
             this environment and typical CI runners have no Btrfs (see \
             docs/experiments.md E-02)",
        ),
        Metric::not_implemented(
            "idle_shell_cpu",
            "60 s average, no agent",
            "Idle shell CPU",
            None,
            "needs a real desktop session; see #84/#99",
        ),
        Metric::not_implemented(
            "idle_ram",
            "desktop ready, no agent, after login + 60 s",
            "Idle RAM",
            None,
            "needs a real desktop session; see #84/#99",
        ),
        Metric::not_implemented(
            "boot_to_login",
            "firmware handoff to greeter, reference NVMe hardware",
            "Boot to login",
            Some(4000.0),
            "needs the reference rig and a real boot; see #99",
        ),
        Metric::not_implemented(
            "login_to_desktop_ready",
            "greeter to desktop ready",
            "Login to desktop ready",
            Some(500.0),
            "needs the reference rig and a real boot; see #99",
        ),
        Metric::not_implemented(
            "resume_from_suspend",
            "suspend to unlocked-usable",
            "Resume from suspend to unlocked-usable",
            Some(1000.0),
            "needs the reference rig; see #99",
        ),
        Metric::not_implemented(
            "install",
            "ISO boot to first reboot into installed system",
            "Install (Phase 8 target)",
            Some(45000.0),
            "installer performance work is Phase 8, after correctness \
             (docs/performance.md §6); not implemented",
        ),
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::report::MetricStatus;

    #[test]
    fn every_row_is_marked_not_implemented_with_a_reason() {
        for m in not_implemented_metrics() {
            assert_eq!(m.status, MetricStatus::NotImplemented);
            assert!(m.unmeasured_reason.is_some(), "{} has no reason", m.id);
            assert!(m.stats.is_none());
        }
    }

    #[test]
    fn ids_are_unique() {
        let metrics = not_implemented_metrics();
        let mut ids: Vec<&str> = metrics.iter().map(|m| m.id.as_str()).collect();
        ids.sort_unstable();
        let mut deduped = ids.clone();
        deduped.dedup();
        assert_eq!(ids.len(), deduped.len(), "duplicate metric id");
    }
}
