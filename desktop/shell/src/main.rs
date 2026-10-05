//! `ward-shell` — the Ward Shell (ADR-0007), as a text dump until E-10 picks
//! the layer-shell toolkit, and as the feed of the components that draw it
//! meanwhile (ADR-0016): Waybar reads `bar --waybar`, fuzzel reads
//! `launcher --lines`.
//!
//! Each subcommand is one surface of `docs/design-language.md`: the trust bar
//! (§6), the session panel (§6), the command centre (§13), the observer (§8)
//! and the semantic settings (§14), plus the verify panel of ADR-0019. The
//! shell is a client of the session daemon like `ward watch` (ADR-0015): it
//! asks for the session's description and catches up with its event stream
//! over the control socket, derives every surface in [`ward_shell_core`], and
//! prints it. It has no privileged access. The one thing it reads besides the
//! stream is the worktree, which it digests with the snapshot crate's
//! incremental hash cache (never capturing) so the verify segment can compare
//! the tree with the candidate the last verdict named: `VERIFY ✓` only while
//! they are the same bytes, `VERIFY ~ STALE` as soon as they are not. With no
//! session, or no daemon serving it, the text surfaces print [`NO_SESSION`],
//! one line saying what to do next, and `bar --waybar` the empty module (the
//! mark alone, dim).
//!
//! `bar --waybar --follow`, the mode Waybar's six trust-bar segments each run
//! as their own process, tries the shared per-session worker ([`worker`],
//! #138 item 2) before falling back to subscribing and digesting itself: one
//! process keeps the one cache and the one daemon subscription all six
//! segments used to keep independently, and every segment process becomes a
//! thin relay of whatever that worker already computed.

#![allow(clippy::missing_errors_doc, clippy::doc_markdown)]

mod worker;

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use ward_daemon::client::{self, WatchEnd, WatchUpdate};
use ward_daemon::ids::{ev_snapshot, snap_snapshot};
use ward_daemon::session::state_root;
use ward_daemon::verify::candidate_options;
use ward_events::EventRecord;
use ward_shell_core::{
    Decision, DigestGate, Header, Launcher, LineContext, Model, Module, SegmentName, SessionCard,
    SessionDescription, Settings, TrustBar, authority_panel, counters_text, panel_text, quote,
    session_panel, verify_panel,
};
use ward_snapshot::{
    CaptureOptions, CaptureStats, HashCache, Manifest, ManifestDiff, SnapshotStore,
};

/// The catch-up's defensive fallback: how long to wait for the daemon's
/// replay-complete marker (#138 item 1) before falling back to the old
/// silence rule. The marker is expected on every real subscription, so this
/// is generous headroom for a wedged connection, not the common path.
const SETTLE_MS: u64 = 250;

/// How often `bar --follow` re-reads the worktree when the stream is quiet:
/// an edit made outside the sandbox (the user's editor) is a change no record
/// reports, and it must turn `VERIFY ✓` into `VERIFY ~ STALE` all the same.
/// [`worker`] uses this same cadence for the one worktree it digests on
/// behalf of every segment.
pub(crate) const TICK_MS: u64 = 2000;

/// The minimum time between two record-triggered digests (#138 item 3): a
/// burst of records collapses into a bounded number of scans instead of one
/// per record. A quiet tick always digests regardless of this interval — it
/// is the safety net that catches an edit made outside the sandbox, which
/// leaves no record for a burst to coalesce.
pub(crate) const DIGEST_DEBOUNCE: Duration = Duration::from_millis(250);

/// What the text surfaces say with no session: calm, and the two ways to get
/// one (the command centre, or `ward init` then `ward claude` in a terminal),
/// rather than a bare `no session`.
const NO_SESSION: &str = "No agent session. Super + Space → Start Claude, or `ward init` then `ward claude` in a terminal.";

#[derive(Parser)]
#[command(name = "ward-shell", version, about = "The Ward Shell, printed")]
struct Cli {
    /// Project directory whose current session to show (default: current).
    #[arg(long, global = true)]
    dir: Option<PathBuf>,
    /// Milliseconds to wait for the daemon's replay-complete marker before
    /// falling back to silence (#138 item 1).
    #[arg(long, global = true, default_value_t = SETTLE_MS)]
    settle_ms: u64,
    #[command(subcommand)]
    surface: Option<Surface>,
}

#[derive(Subcommand)]
enum Surface {
    /// The trust bar (default).
    Bar {
        /// Waybar custom-module JSON (`return-type: json`) instead of text.
        #[arg(long)]
        waybar: bool,
        /// One segment only: mark, session, project, agent, network,
        /// credentials, observer, tamperward, verify or daemon.
        #[arg(long, requires = "waybar")]
        segment: Option<SegmentName>,
        /// Keep the daemon subscription open and print a new line whenever the
        /// JSON changes. A connection lost without the daemon confirming the
        /// log sealed reconnects from the last confirmed sequence and prints
        /// the bar's `unknown` state meanwhile (#138 item 5); exits 0 once
        /// the log is genuinely sealed, or once reconnect attempts run out.
        #[arg(long, requires = "waybar")]
        follow: bool,
        /// Milliseconds between re-reads of the worktree while following and
        /// the stream is quiet (default: `TICK_MS`, 2000). The shared worker
        /// (#138 item 2) always runs on that default cadence — it cannot
        /// honour a caller-chosen one, since it serves every connected
        /// segment at once — so naming this explicitly bypasses the worker
        /// and subscribes directly, the one way to actually get a different
        /// tick; leaving it unset is what lets `--follow` use the worker.
        #[arg(long, requires = "follow")]
        tick_ms: Option<u64>,
    },
    /// The trust bar and the session panel behind its agent segment.
    Session,
    /// The trust bar and the verify panel behind its verify segment: the
    /// verified candidate, when, the worktree's digest now, what changed, and
    /// what the verifier found.
    VerifyPanel,
    /// The current agent authority (ADR-0019) behind the network and grants
    /// segments: filesystem, network, every temporary grant with its scope
    /// and lifetime, and the standing denials.
    AuthorityPanel,
    /// The command centre, optionally filtered as if `query` had been typed.
    Launcher {
        /// Typed text.
        #[arg(long, default_value = "")]
        query: String,
        /// dmenu lines, `SECTION<TAB>label<TAB>command`, for fuzzel.
        #[arg(long)]
        lines: bool,
    },
    /// The agent activity panel: the newest rows and the counters.
    Observer {
        /// Rows to show.
        #[arg(long, default_value_t = 20)]
        rows: usize,
    },
    /// Agent Access and Advanced, read-only.
    Settings,
    /// The keyboard-first session switcher (#141 item 3): every live session,
    /// each with its project, agent state (paused included), pending
    /// approvals and verification freshness, so a keyboard user can identify
    /// a session before switching to it. Each line's command is bound to that
    /// one session's immutable id (`ward session select <id>`), never to
    /// "whichever session is selected at the time you press enter".
    Switcher {
        /// dmenu lines, `SECTION<TAB>label<TAB>command`, for fuzzel.
        #[arg(long)]
        lines: bool,
    },
    /// The shared per-session projection worker (#138 item 2): subscribes to
    /// the daemon once, keeps one cache, and serves every Waybar segment's
    /// JSON from it over a local socket instead of each `bar --waybar
    /// --follow` process subscribing and digesting on its own. Run by
    /// `wardos-shell-worker.service`, not meant to be typed by a person —
    /// hidden from `--help` accordingly.
    #[command(hide = true)]
    Worker,
}

/// A session as the shell sees it: its facts and its stream so far. Shared
/// with [`worker`] (#138 item 2), which keeps exactly one of these per
/// session instead of one per Waybar segment process.
pub(crate) struct Snapshot {
    pub(crate) description: SessionDescription,
    pub(crate) header: Header,
    pub(crate) model: Model,
}

/// The worktree reader behind the verify segment (ADR-0019 decision 1): a
/// hash cache that stays warm across re-reads, and the session CAS the change
/// count is diffed against. It never writes: the digest is the id the tree
/// *would* get, computed the way `ward verify` captures a candidate.
pub(crate) struct Digester {
    cache: HashCache,
    store: Option<SnapshotStore>,
}

impl Digester {
    pub(crate) fn new() -> Self {
        Self {
            cache: HashCache::new(),
            store: SnapshotStore::open(state_root().join("cas")).ok(),
        }
    }

    /// Digest `s`'s worktree and tell the model. A tree that cannot be read
    /// marks freshness unavailable — the current-tree (green) indication is
    /// withdrawn while the historical verdict stays (#136) — and says why once
    /// on stderr. Both outcomes are applied through the observation generation
    /// captured before the (possibly slow) digest, so a result — success or
    /// failure — that lost a race to a newer change is dropped rather than
    /// clobbering it.
    pub(crate) fn observe(&mut self, s: &mut Snapshot) {
        let opts = CaptureOptions {
            incremental: true,
            ..candidate_options()
        };
        let mut stats = CaptureStats::default();
        let generation = s.model.observation_gen();
        let worktree = &s.description.worktree;
        match ward_snapshot::digest_manifest(worktree, opts, &mut self.cache, &mut stats) {
            Ok(manifest) => {
                let changes = self.changes(s, &manifest);
                s.model
                    .observe_if_current(generation, ev_snapshot(manifest.id()), changes);
            }
            Err(e) => {
                s.model.mark_freshness_unavailable(generation);
                eprintln!("ward-shell: {}: {e}", worktree.display());
            }
        }
    }

    /// Manifest entries that differ between the verified candidate and the
    /// tree now: `0` when the ids agree, the diff against the stored candidate
    /// manifest otherwise, `None` when nothing was verified or the CAS does
    /// not hold the candidate.
    fn changes(&self, s: &Snapshot, current: &Manifest) -> Option<u64> {
        let candidate = snap_snapshot(s.model.state.verification.candidate()?);
        if candidate == current.id() {
            return Some(0);
        }
        let stored = self.store.as_ref()?.manifest(candidate).ok()?;
        let diff = ManifestDiff::between(&stored, current);
        Some((diff.added.len() + diff.removed.len() + diff.changed.len()) as u64)
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    #[cfg(feature = "gui")]
    eprintln!("ward-shell: gui: toolkit pending E-10; printing the text surfaces");
    // `--dir` unset is what every real Waybar segment and the worker itself
    // both do (`config.jsonc`'s six `exec` lines never pass it): the common
    // case the worker relay path is for. An explicit `--dir` names a
    // specific project's session, which the desktop-wide worker does not
    // parameterise by, so a caller that passed one keeps subscribing for
    // itself ([`may_use_worker`] below), exactly as before this change.
    let dir_given = cli.dir.is_some();
    let dir = cli.dir.unwrap_or_else(|| PathBuf::from("."));
    let settle = Duration::from_millis(cli.settle_ms);
    let surface = cli.surface.unwrap_or(Surface::Bar {
        waybar: false,
        segment: None,
        follow: false,
        tick_ms: None,
    });
    let result = match surface {
        Surface::Bar {
            waybar: true,
            segment,
            follow,
            tick_ms,
        } => waybar(
            &dir,
            settle,
            segment,
            follow,
            Duration::from_millis(tick_ms.unwrap_or(TICK_MS)),
            may_use_worker(dir_given, tick_ms),
        ),
        Surface::Launcher { query, lines: true } => launcher_lines(&dir, settle, &query),
        Surface::Switcher { lines } => switcher(settle, lines),
        Surface::Worker => worker::run(&dir, &state_root(), settle),
        surface => text(&dir, settle, surface),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ward-shell: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Print one text surface, or [`NO_SESSION`]. The surfaces that show the
/// verify segment read the worktree first; the launcher, the observer and the
/// settings do not show it and stay within their latency budget on any tree.
fn text(dir: &Path, settle: Duration, surface: Surface) -> ward_daemon::Result<()> {
    let mut snapshot = load(dir, settle)?;
    if let Some(s) = snapshot.as_mut()
        && matches!(
            surface,
            Surface::Bar { .. } | Surface::Session | Surface::VerifyPanel
        )
    {
        Digester::new().observe(s);
    }
    print!("{}", surface_text(snapshot.as_ref(), surface));
    Ok(())
}

/// The text of a surface for a session, or the no-session line without one.
fn surface_text(snapshot: Option<&Snapshot>, surface: Surface) -> String {
    match snapshot {
        Some(snapshot) => render(snapshot, surface),
        None => format!("{NO_SESSION}\n"),
    }
}

/// Whether `bar --waybar --follow` may ask the shared worker (#138 item 2)
/// instead of subscribing for itself. Two things rule it out, each because
/// the worker cannot honour what the caller asked for: an explicit `--dir`
/// names a specific project's session, which the desktop-wide worker does
/// not parameterise by (it always follows [`locate`]'s own default, "."); an
/// explicit `--tick-ms` asks for a worktree re-read cadence, but the worker
/// runs one cadence ([`TICK_MS`]) for every segment it serves at once and
/// cannot honour a caller-chosen one. Silently relaying the worker's fixed
/// cadence instead of the requested one would make `--tick-ms` — a
/// documented, tested CLI option — a silent no-op once a worker happens to
/// be running (review finding 2 on #331); bypassing the worker in that case
/// keeps `--tick-ms` working exactly as it always has, through the
/// unconditional direct-subscription path below.
fn may_use_worker(dir_given: bool, tick_ms: Option<u64>) -> bool {
    !dir_given && tick_ms.is_none()
}

/// `bar --waybar`: the module's JSON, once or on every change. Only a segment
/// whose text or tone depends on freshness ([`SegmentName::needs_freshness`]:
/// the whole bar, since it carries the verify segment, or `--segment verify`
/// itself) ever digests the worktree (#138 item 3) — every other segment is
/// derived from the event stream alone, so a follower rendering `agent` or
/// `network` never touches the worktree at all. When one does, the worktree
/// is digested before the first line and, while following, debounced behind
/// [`DIGEST_DEBOUNCE`] on each record (a burst collapses into a bounded
/// number of scans, never one per record) and unconditionally on every quiet
/// `tick`, so the verify segment answers for the tree as it is without
/// silently dropping a real change: [`DigestGate`] guarantees every
/// invalidation is either covered by the scan it lands before or earns a
/// follow-up scan. A record withdraws freshness the instant it lands
/// ([`Model::invalidate_freshness`]), even though its digest may still be
/// waiting out the debounce interval, so the trust bar never keeps showing a
/// confirmed match with evidence the tree may already differ; the socket is
/// polled at least as often as that interval so the deadline itself gets a
/// digest without needing another record.
///
/// With `--follow` and `may_worker` ([`may_use_worker`]), this first tries
/// [`worker::relay_from_worker`] (#138 item 2): the shared worker, when one
/// answers, already keeps the one cache and the one subscription this
/// function's own logic below would otherwise duplicate per segment, so a
/// live worker means this process never opens its own connection to the
/// daemon or digests the worktree itself at all — it just copies the
/// worker's lines to stdout. Everything below only ever runs when there is no
/// worker to ask (not installed, mid-restart, an explicit `--dir`, or an
/// explicit `--tick-ms`), which is also exactly what always ran before this
/// change.
fn waybar(
    dir: &Path,
    settle: Duration,
    segment: Option<SegmentName>,
    follow: bool,
    tick: Duration,
    may_worker: bool,
) -> ward_daemon::Result<()> {
    if follow && may_worker && worker::relay_from_worker(&state_root(), segment)? {
        return Ok(());
    }
    let Some(socket) = locate(dir)? else {
        return emit(&Module::none(segment));
    };
    let Some(mut snapshot) = load_from(&socket, settle)? else {
        return emit(&Module::none(segment));
    };
    let needs_freshness = segment.is_none_or(SegmentName::needs_freshness);
    let mut digester = needs_freshness.then(Digester::new);
    let gate = DigestGate::new();
    if let Some(d) = digester.as_mut() {
        d.observe(&mut snapshot);
    }
    let last = module(&snapshot, segment);
    emit(&last)?;
    if !follow || snapshot.model.sealed {
        return Ok(());
    }
    // While a segment digests, poll the socket at least as often as the
    // debounce interval, so a pending dirty gate is rescanned at its own
    // deadline rather than only when the next record happens to arrive or
    // the much longer quiet-tick safety net (`tick`) elapses. `force` stays
    // reserved for that safety net (an edit made outside the sandbox, which
    // leaves no record to debounce) and is decided against wall-clock time
    // since the last real scan, independent of this finer polling grain.
    let poll_tick = if needs_freshness {
        tick.min(DIGEST_DEBOUNCE)
    } else {
        tick
    };
    follow_loop(
        &socket, snapshot, segment, digester, gate, poll_tick, tick, last, emit,
    )?;
    Ok(())
}

/// How the `--follow` loop reconnects once the daemon connection is lost
/// without a confirmed seal (#138 item 5): a handful of quick attempts,
/// each from the last *confirmed* sequence rather than replaying the whole
/// session again, before giving up and letting Waybar's own
/// `restart-interval` (`desktop/config/waybar/config.jsonc`) relaunch the
/// process — a full, symmetric fallback (a fresh process, a fresh full
/// replay), not the common path a short daemon hiccup takes.
const RECONNECT_ATTEMPTS: u32 = 5;
/// How long `follow_loop` waits between reconnect attempts.
const RECONNECT_DELAY: Duration = Duration::from_millis(100);

/// `bar --waybar --follow`'s loop: stream `socket` from wherever `snapshot`
/// left off, applying every record or tick and calling `emit` whenever the
/// rendered module changes. A connection lost without the daemon confirming
/// the log sealed (`WatchEnd::Closed`) is not the log ending — #138 item 5's
/// distinction from a genuine `WatchEnd::Sealed` — so this reconnects from
/// the last confirmed sequence instead of returning, marking the model
/// disconnected ([`Model::mark_disconnected`]) the moment a connect fails, a
/// drop is noticed, or a fresh connection is opened but not yet caught up, so
/// the very next emitted module already reads the bar's `unknown` state.
///
/// Review 5337489166 of #329, finding 2: the model is cleared back to
/// connected ([`Model::mark_connected`]) only once the daemon's own
/// replay-complete boundary confirms this subscription's backlog is fully
/// applied ([`client::watch_records_ticking`]'s [`WatchUpdate::CaughtUp`],
/// driven by `Response::CaughtUp`), or once a confirmed seal arrives first — never
/// merely because `client::connect` (which only completes `Ping`) succeeded.
/// `Subscribe` has not even been sent at that point, so the projection is
/// still whatever it was before the drop; showing it as live then would be
/// exactly the stale-shown-as-current bug ADR-0019's fail-closed rule exists
/// to prevent. The same review's finding 3: [`RECONNECT_ATTEMPTS`] bounds
/// only a *consecutive* run of failures — `attempts` resets to zero at that
/// same catch-up boundary, a confirmed live handover, not on every bare
/// `connect()` — so a long-lived bar that keeps recovering from isolated,
/// separated daemon restarts never exhausts its budget just because time has
/// passed; and a transport failure anywhere in the Ping→Subscribe race or the
/// subsequent read (e.g. a daemon that answers `Ping` and then closes before
/// `Subscribe`) is folded into this same disconnected/retry path rather than
/// aborting the loop outright via a bare `?` while the last emitted module
/// still reads live.
///
/// Returns the final snapshot once the log is genuinely sealed, or once
/// [`RECONNECT_ATTEMPTS`] consecutive reconnect attempts have all failed in a
/// row (Waybar's `restart-interval` is the fallback then).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn follow_loop(
    socket: &Path,
    mut snapshot: Snapshot,
    segment: Option<SegmentName>,
    mut digester: Option<Digester>,
    mut gate: DigestGate,
    poll_tick: Duration,
    tick: Duration,
    mut last: Module,
    mut emit: impl FnMut(&Module) -> ward_daemon::Result<()>,
) -> ward_daemon::Result<Snapshot> {
    let mut next_seq = snapshot.model.records.last().map_or(0, |r| r.seq + 1);
    let mut last_force = Instant::now();
    let mut attempts = 0u32;
    loop {
        let subscriber = match client::connect(socket) {
            Ok(s) => s,
            Err(e) => {
                snapshot.model.mark_disconnected();
                let now = module(&snapshot, segment);
                if now != last {
                    emit(&now)?;
                    last = now;
                }
                if attempts >= RECONNECT_ATTEMPTS {
                    return Err(e);
                }
                attempts += 1;
                std::thread::sleep(RECONNECT_DELAY);
                continue;
            }
        };
        // `connect` only completed `Ping`: `Subscribe` has not been sent yet
        // and this subscription's backlog has not reached the daemon's own
        // `CaughtUp` boundary, so the model stays in its disconnected/unknown
        // state (a no-op if a prior failure already set it) until that
        // boundary — or a confirmed seal — says otherwise (finding 2). No
        // emit here: the render already reads `unknown` from whichever branch
        // got the loop here, and the common, no-real-drop path below reaches
        // `on_caught_up` before anything is ever shown.
        snapshot.model.mark_disconnected();
        let mut failed = None;
        let result = client::watch_records_ticking(subscriber, next_seq, poll_tick, |watched| {
            let rec = match watched {
                WatchUpdate::Record(rec) => {
                    next_seq = rec.seq + 1;
                    Some(*rec)
                }
                WatchUpdate::Tick => None,
                WatchUpdate::CaughtUp => {
                    // The daemon's own confirmation that this subscription's
                    // backlog is fully applied: only now is the projection
                    // current, so only now does the bar leave `unknown` and
                    // the consecutive-failure streak reset (finding 3) — a
                    // confirmed live handover, not merely a successful
                    // `connect()`.
                    attempts = 0;
                    snapshot.model.mark_connected();
                    let now = module(&snapshot, segment);
                    if now != last {
                        if let Err(e) = emit(&now) {
                            failed = Some(e);
                        }
                        last = now;
                    }
                    return;
                }
            };
            let at = Instant::now();
            let force = rec.is_none() && at.duration_since(last_force) >= tick;
            let scanned = observe_event(
                &mut snapshot,
                digester.as_mut(),
                &mut gate,
                rec,
                at,
                DIGEST_DEBOUNCE,
                force,
            );
            if scanned {
                last_force = at;
            }
            let now = module(&snapshot, segment);
            if now != last {
                if let Err(e) = emit(&now) {
                    failed = Some(e);
                }
                last = now;
            }
        });
        let end = match result {
            Ok(end) => end,
            Err(e) => {
                // A transport failure anywhere between `Ping` and `Subscribe`
                // or in the subscription's own read path (finding 3): folded
                // into the same disconnected/retry path a clean `Closed` end
                // takes, rather than aborting the whole loop here via a bare
                // `?` while the last emitted module still reads live/unknown
                // from before this attempt. An `emit` failure from inside the
                // closures above is the caller's own I/O (e.g. a broken
                // stdout pipe) and takes priority: that one is never retried.
                if let Some(e) = failed {
                    return Err(e);
                }
                snapshot.model.mark_disconnected();
                let now = module(&snapshot, segment);
                if now != last {
                    emit(&now)?;
                    last = now;
                }
                if attempts >= RECONNECT_ATTEMPTS {
                    return Err(e);
                }
                attempts += 1;
                std::thread::sleep(RECONNECT_DELAY);
                continue;
            }
        };
        if let Some(e) = failed {
            return Err(e);
        }
        // `watch_records_ticking` only ever ends on `Closed` or `Sealed`
        // (its replay-complete `CaughtUp` marker is now surfaced live, as
        // `WatchUpdate::CaughtUp` in the closure above, rather than only at
        // the end of the stream), but `WatchEnd::CaughtUp` is matched here
        // too rather than assumed unreachable — fail closed on the
        // connection state even if that ever changes, instead of risking a
        // panic in an unattended background process.
        match end {
            WatchEnd::Sealed { .. } => {
                snapshot.model.seal();
                let now = module(&snapshot, segment);
                if now != last {
                    emit(&now)?;
                }
                return Ok(snapshot);
            }
            WatchEnd::Closed { .. } | WatchEnd::CaughtUp { .. } => {
                snapshot.model.mark_disconnected();
                let now = module(&snapshot, segment);
                if now != last {
                    emit(&now)?;
                    last = now;
                }
                if attempts >= RECONNECT_ATTEMPTS {
                    return Ok(snapshot);
                }
                attempts += 1;
                std::thread::sleep(RECONNECT_DELAY);
            }
        }
    }
}

/// One step of the follow loop: apply `event` (a record, or `None` for a
/// wake-up with nothing new) to `snapshot`, then — only when `digester` is
/// `Some`, i.e. the segment being rendered needs freshness — decide through
/// `gate` whether to digest the worktree now. A record marks the gate dirty
/// and withdraws freshness at once (`Model::invalidate_freshness`): the
/// digest itself may be debounced, but the trust bar must never keep
/// claiming a confirmed match with evidence the tree may already differ,
/// even for the interval before that debounced digest runs. `force` is the
/// caller's decision that the quiet-tick safety net is due (an edit made
/// outside the sandbox, which leaves no record to debounce) — independent of
/// how often this function is called, which may be much more often than
/// that, so the debounce deadline itself still gets serviced. Returns
/// whether a scan actually ran, for tests. Factored out of the `--follow`
/// closure so it is testable without a socket; [`worker`]'s own session loop
/// reuses it too, unchanged.
pub(crate) fn observe_event(
    snapshot: &mut Snapshot,
    digester: Option<&mut Digester>,
    gate: &mut DigestGate,
    event: Option<EventRecord>,
    now: Instant,
    interval: Duration,
    force: bool,
) -> bool {
    let had_record = event.is_some();
    if let Some(rec) = event {
        snapshot.model.apply(rec);
    }
    let Some(digester) = digester else {
        return false;
    };
    if had_record {
        gate.mark_dirty();
        snapshot.model.invalidate_freshness();
    }
    if gate.poll(now, interval, force) == Decision::Scan {
        digester.observe(snapshot);
        gate.finish();
        true
    } else {
        false
    }
}

/// The whole bar or one segment of `s`, at the current instant.
fn module(s: &Snapshot, segment: Option<SegmentName>) -> Module {
    module_at(s, segment, now_unix_ms())
}

/// The whole bar or one segment of `s`, at a caller-given instant: what
/// [`module`] delegates to with its own fresh [`now_unix_ms`], and what
/// [`worker`] calls once per publish with one shared instant for every
/// segment (#138 item 2's "same session id and state generation" acceptance
/// criterion) instead of each segment computing its own.
pub(crate) fn module_at(s: &Snapshot, segment: Option<SegmentName>, now_unix_ms: u64) -> Module {
    match segment {
        Some(name) => Module::segment(&s.description, &s.header, &s.model, name, now_unix_ms),
        None => Module::bar(&s.description, &s.header, &s.model, now_unix_ms),
    }
}

/// One JSON line, flushed, since a reader waits on it.
fn emit(module: &Module) -> ward_daemon::Result<()> {
    let line = serde_json::to_string(module)
        .map_err(|e| ward_daemon::Error::Events(format!("waybar json: {e}")))?;
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}")
        .and_then(|()| out.flush())
        .map_err(|e| ward_daemon::Error::Io {
            path: PathBuf::from("<stdout>"),
            source: e,
        })
}

/// `launcher --lines`: the matching rows as `SECTION<TAB>label<TAB>command`.
/// Without a session the fixed rows remain, with the given directory as the
/// project.
fn launcher_lines(dir: &Path, settle: Duration, query: &str) -> ward_daemon::Result<()> {
    let state = state_root();
    let snapshot = load(dir, settle)?;
    let (cards, worktree) = match &snapshot {
        Some(s) => (
            vec![SessionCard::new(&s.description, &s.model)],
            s.description.worktree.clone(),
        ),
        None => (
            Vec::new(),
            dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf()),
        ),
    };
    let mut launcher = Launcher::new(&cards);
    launcher.set_query(query);
    let ctx = LineContext {
        worktree: &worktree,
        state: &state,
    };
    for line in launcher.lines(&ctx) {
        println!("{line}");
    }
    Ok(())
}

/// `ward-shell switcher [--lines]` (#141 item 3): every live session, digested
/// so its verify segment is current, each on its own line. `●` marks the
/// desktop's current shared selection; every other line's command is bound to
/// that line's own session id (`ward session select <id>`, quoted), so
/// choosing one always selects the session you read, never whichever session
/// happens to be selected — or newest, or gone — by the time you press enter.
///
/// The shared selection and each line's pending-approval count both come
/// from one [`ward_daemon::registry::snapshot`] call (#141 item 2) instead
/// of this function's former separate `selection::current` read and a
/// second per-session `Pending` request on top of `load_from`'s own
/// connection; [`switcher_binding`] does the actual join, by session id.
/// The session *list* itself still comes from
/// [`ward_daemon::daemon::live_sessions`], deliberately not from
/// `registry.entries`: the registry drops a session whose own, separate
/// probe connection hit a disconnect (registry.rs's module doc, "a session
/// whose daemon does not answer... is simply left out"), and a keyboard
/// switcher listing "every live session" should not flicker a session out
/// of the list over a transient hiccup on a connection this function does
/// not otherwise need — `load_from`'s own connection right below is what
/// decides whether a line is shown, exactly as before.
fn switcher(settle: Duration, lines: bool) -> ward_daemon::Result<()> {
    let state = state_root();
    let registry = ward_daemon::registry::snapshot(&state, settle);
    let live = ward_daemon::daemon::live_sessions(&state)?;
    if live.is_empty() {
        if !lines {
            print!("{NO_SESSION}");
        }
        return Ok(());
    }
    let mut digester = Digester::new();
    for meta in &live {
        let socket = ward_daemon::session::session_dir(&state, &meta.id)
            .join(ward_daemon::control::SOCKET_NAME);
        let Some(mut snapshot) = load_from(&socket, settle)? else {
            continue;
        };
        digester.observe(&mut snapshot);
        let (pending, is_selected) = switcher_binding(&registry, &meta.id);
        let label = switcher_label(&snapshot, pending, is_selected);
        if lines {
            println!("SESSIONS\t{label}\tward session select {}", quote(&meta.id));
        } else {
            println!("{label}");
        }
    }
    Ok(())
}

/// One live session's pending-approval count and whether it is the
/// desktop's current selection, joined from `registry` by session id (#141
/// item 2, review 5336575691 finding 1) — never by position: `live_sessions`
/// and `registry.entries` are two separate listings (`registry::snapshot`'s
/// own fresh scan, then [`switcher`]'s own separate `live_sessions` call a
/// moment later) that are not guaranteed to agree on order, or even on
/// membership, so a positional pairing could silently attach one session's
/// count or selection mark to another. `0`/`false` for a session
/// `registry.entries` has no matching entry for — the same gap
/// [`switcher`]'s doc comment already accepts.
fn switcher_binding(registry: &ward_daemon::registry::Registry, session: &str) -> (usize, bool) {
    let pending = registry
        .entries
        .iter()
        .find(|e| e.session == session)
        .map_or(0, |e| e.pending_approvals);
    let is_selected = registry.selection.session.as_deref() == Some(session);
    (pending, is_selected)
}

/// One switcher line: the project, the agent segment's text (which already
/// reads `PAUSED` in its own tone when the session is paused), how many
/// approvals are pending, and the verify segment's text — the same facts the
/// bar shows for the selected session, just for every live one at once.
fn switcher_label(snapshot: &Snapshot, pending: usize, selected: bool) -> String {
    let bar = TrustBar::new(&snapshot.header, &snapshot.model, now_unix_ms());
    let agent = bar
        .segment(SegmentName::Agent)
        .map_or_else(String::new, |s| s.text);
    let verify = bar
        .segment(SegmentName::Verify)
        .map_or_else(String::new, |s| s.text);
    let project = SessionCard::new(&snapshot.description, &snapshot.model).project;
    let mark = if selected { "●" } else { " " };
    let pending = match pending {
        0 => "no approvals pending".to_owned(),
        1 => "1 approval pending".to_owned(),
        n => format!("{n} approvals pending"),
    };
    format!("{mark} {project}  {agent}  {pending}  {verify}")
}

/// What [`locate_quietly`] found: the session's control socket, or the
/// reason there is none to show — which [`locate`] prints at once for the
/// one-shot surfaces, and [`worker`] prints only when it changes, since it
/// asks again every few seconds for as long as the desktop has no session.
pub(crate) enum Located {
    /// The control socket of the session to show.
    Session(PathBuf),
    /// No session for the directory and none live anywhere: the daemon's own
    /// explanation, the text `locate` would have printed.
    NoSession(String),
}

/// The control socket of the session the shell shows: `dir`'s current one,
/// else the newest one a daemon serves (the bar runs from home, not a
/// project); `None` when there is neither (the reason goes to stderr). Also
/// [`worker`]'s own way of finding the session to serve, with the same `dir`
/// default ("."), so the two agree.
pub(crate) fn locate(dir: &Path) -> ward_daemon::Result<Option<PathBuf>> {
    match locate_quietly(dir)? {
        Located::Session(socket) => Ok(Some(socket)),
        Located::NoSession(reason) => {
            eprintln!("ward-shell: {reason}");
            Ok(None)
        }
    }
}

/// [`locate`] without the stderr line: the caller decides whether the reason
/// there is no session is worth saying this time.
pub(crate) fn locate_quietly(dir: &Path) -> ward_daemon::Result<Located> {
    match client::desktop_socket(dir, &state_root(), None) {
        Ok(socket) => Ok(Located::Session(socket)),
        Err(ward_daemon::Error::Project(reason)) => Ok(Located::NoSession(reason)),
        Err(e) => Err(e),
    }
}

/// The current session of `dir` through its daemon, or `None` when there is no
/// session or nothing serves it.
fn load(dir: &Path, settle: Duration) -> ward_daemon::Result<Option<Snapshot>> {
    match locate(dir)? {
        Some(socket) => load_from(&socket, settle),
        None => Ok(None),
    }
}

/// The session behind `socket`: its description and its stream so far, or
/// `None` when nothing serves it. [`worker`] uses this to build the one
/// [`Snapshot`] it shares.
pub(crate) fn load_from(socket: &Path, settle: Duration) -> ward_daemon::Result<Option<Snapshot>> {
    let Ok(mut sink) = client::connect(socket) else {
        eprintln!("ward-shell: {}", client::NO_DAEMON);
        return Ok(None);
    };
    let description = client::describe(&mut sink)?;
    drop(sink);
    // A subscription is served on its own connection.
    let subscriber = client::connect(socket)?;
    let mut model = Model::new(false);
    let end = client::catch_up(subscriber, 0, settle, |rec| model.apply(rec))?;
    // #138 item 5: only the daemon's own confirmed `Sealed` means the
    // session ended; a catch-up connection that was merely cut off
    // (`WatchEnd::Closed`, e.g. the daemon crashed or restarted mid-reply)
    // is this viewer's uncertainty, never a claim the log is done —
    // rendered as `TrustBar`'s `unknown` state, not `SEALED`.
    match end {
        WatchEnd::CaughtUp { .. } => {}
        WatchEnd::Sealed { .. } => model.seal(),
        WatchEnd::Closed { .. } => model.mark_disconnected(),
    }
    Ok(Some(Snapshot {
        header: Header::from_description(&description),
        description,
        model,
    }))
}

/// The text of one surface.
fn render(s: &Snapshot, surface: Surface) -> String {
    let bar = TrustBar::new(&s.header, &s.model, now_unix_ms()).text();
    match surface {
        Surface::Bar { .. } => format!("{bar}\n"),
        Surface::Session => {
            let panel = session_panel(&s.description, &s.model, now_unix_ms());
            format!("{bar}\n\n{}", panel_text(&panel))
        }
        Surface::VerifyPanel => {
            let panel = verify_panel(&s.description, &s.model, now_unix_ms());
            format!("{bar}\n\n{}", panel_text(&panel))
        }
        // `model.authority` is kept incrementally rather than rescanned from
        // `model.records` here (#138 item 4), so a session-scoped grant stays
        // visible even once the record that created it has aged out of
        // `model.records`.
        Surface::AuthorityPanel => format!(
            "{bar}\n\n{}",
            panel_text(&authority_panel(
                &s.description,
                &s.model.authority,
                now_unix_ms()
            ))
        ),
        Surface::Launcher { query, .. } => {
            let card = SessionCard::new(&s.description, &s.model);
            let mut launcher = Launcher::new(&[card]);
            launcher.set_query(query);
            launcher.text()
        }
        Surface::Observer { rows } => {
            let mut text = String::new();
            for cells in s.model.visible_rows(rows) {
                let _ = writeln!(text, "{}  {:<5} {}", cells.time, cells.verb, cells.subject);
            }
            text.push('\n');
            text.push_str(&counters_text(&s.model.counters));
            text.push('\n');
            text
        }
        Surface::Settings => Settings::from_description(&s.description).text(),
        // Multi-session, so it never goes through the single-session `load`
        // this function's caller (`text`) is built on; `main` dispatches it
        // to `switcher` directly instead.
        Surface::Switcher { .. } => {
            unreachable!("Surface::Switcher is dispatched in main(), not through text()/render()")
        }
        // Not a text surface at all: `main` dispatches it to `worker::run`
        // directly instead.
        Surface::Worker => {
            unreachable!("Surface::Worker is dispatched in main(), not through text()/render()")
        }
    }
}

pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn the_cli_parses_and_defaults_to_the_bar() {
        Cli::command().debug_assert();
        let cli = Cli::parse_from(["ward-shell"]);
        assert!(cli.surface.is_none());
        assert_eq!(cli.settle_ms, SETTLE_MS);
        let cli = Cli::parse_from(["ward-shell", "launcher", "--query", "pay", "--dir", "/p"]);
        assert!(matches!(
            cli.surface,
            Some(Surface::Launcher { query, lines: false }) if query == "pay"
        ));
        assert_eq!(cli.dir.as_deref(), Some(Path::new("/p")));
        let cli = Cli::parse_from(["ward-shell", "launcher", "--lines"]);
        assert!(matches!(
            cli.surface,
            Some(Surface::Launcher { lines: true, .. })
        ));
        let cli = Cli::parse_from(["ward-shell", "switcher"]);
        assert!(matches!(
            cli.surface,
            Some(Surface::Switcher { lines: false })
        ));
        let cli = Cli::parse_from(["ward-shell", "switcher", "--lines"]);
        assert!(matches!(
            cli.surface,
            Some(Surface::Switcher { lines: true })
        ));
    }

    #[test]
    fn waybar_flags_parse_and_need_waybar() {
        let cli = Cli::parse_from([
            "ward-shell",
            "bar",
            "--waybar",
            "--segment",
            "agent",
            "--follow",
        ]);
        assert!(matches!(
            cli.surface,
            Some(Surface::Bar {
                waybar: true,
                segment: Some(SegmentName::Agent),
                follow: true,
                tick_ms: None,
            })
        ));
        assert!(Cli::try_parse_from(["ward-shell", "bar", "--segment", "agent"]).is_err());
        assert!(Cli::try_parse_from(["ward-shell", "bar", "--follow"]).is_err());
        let cli = Cli::parse_from([
            "ward-shell",
            "bar",
            "--waybar",
            "--follow",
            "--tick-ms",
            "500",
        ]);
        assert!(matches!(
            cli.surface,
            Some(Surface::Bar {
                tick_ms: Some(500),
                ..
            })
        ));
        assert!(
            Cli::try_parse_from(["ward-shell", "bar", "--waybar", "--tick-ms", "500"]).is_err(),
            "a tick is a follow's"
        );
        assert!(matches!(
            Cli::parse_from(["ward-shell", "verify-panel"]).surface,
            Some(Surface::VerifyPanel)
        ));
        let err = Cli::try_parse_from(["ward-shell", "bar", "--waybar", "--segment", "clock"])
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("unknown segment `clock`"), "{err}");
    }

    /// Review finding 2 on #331: a live shared worker runs one fixed cadence
    /// ([`TICK_MS`]) for every segment it serves, so it must never be asked
    /// on behalf of a caller who named a different one explicitly — that
    /// would silently turn a documented, tested `--tick-ms` into a no-op the
    /// moment a worker happens to be running. `waybar`'s own dispatch is
    /// `follow && may_worker && worker::relay_from_worker(..)`: a boolean
    /// short-circuit, so whether the worker is ever asked at all reduces
    /// entirely to this function's result — proving it here, without a
    /// socket, is a complete proof for every caller of `waybar`, the same
    /// reasoning `observe_event`'s own doc comment gives for being factored
    /// out ("testable without a socket"). [`worker::tests`] separately
    /// proves `relay_from_worker` correctly relays a real listening worker's
    /// lines once it *is* asked, so together these cover both halves of the
    /// behaviour: the decision, and what the decision gates.
    #[test]
    fn the_worker_is_asked_only_with_no_explicit_dir_and_no_explicit_tick() {
        assert!(
            may_use_worker(false, None),
            "the common case: no --dir, no --tick-ms"
        );
        assert!(
            !may_use_worker(true, None),
            "an explicit --dir names a session the desktop-wide worker doesn't serve"
        );
        assert!(
            !may_use_worker(false, Some(TICK_MS)),
            "even a --tick-ms equal to the worker's own default must still bypass it: \
             the caller asked for a specific cadence explicitly, not 'whatever the default is'"
        );
        assert!(
            !may_use_worker(false, Some(500)),
            "a --tick-ms the worker cannot honour must bypass it"
        );
        assert!(!may_use_worker(true, Some(500)), "both reasons at once");
    }

    #[test]
    fn a_project_without_a_session_gets_the_next_step_not_an_error() {
        #![allow(clippy::unwrap_used)]
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            load(dir.path(), Duration::from_millis(10)),
            Ok(None)
        ));
        assert!(matches!(locate(dir.path()), Ok(None)));
        // Every text surface says the same calm thing, and what to do about it.
        for surface in [
            Surface::Bar {
                waybar: false,
                segment: None,
                follow: false,
                tick_ms: None,
            },
            Surface::Session,
            Surface::VerifyPanel,
            Surface::AuthorityPanel,
            Surface::Observer { rows: 3 },
            Surface::Settings,
        ] {
            let text = surface_text(None, surface);
            assert_eq!(
                text,
                "No agent session. Super + Space → Start Claude, or `ward init` then `ward claude` in a terminal.\n"
            );
            assert!(!text.contains("no session"));
        }
    }

    #[test]
    fn switcher_label_names_the_project_agent_state_pending_count_and_marks_the_selection() {
        let s = snapshot_on(Path::new("/home/dev/payments-api"), &[]);
        let label = switcher_label(&s, 0, false);
        assert!(label.starts_with("  payments-api  "), "{label}");
        assert!(label.contains("no approvals pending"), "{label}");

        let selected = switcher_label(&s, 1, true);
        assert!(selected.starts_with("● payments-api  "), "{selected}");
        assert!(selected.contains("1 approval pending"), "{selected}");

        let many = switcher_label(&s, 3, false);
        assert!(many.contains("3 approvals pending"), "{many}");
    }

    /// Review 5336575691 of #328, finding 1: `switcher_binding` joins
    /// `live_sessions` to `registry.entries`/`registry.selection` by session
    /// id, not by position — `registry.entries` here is deliberately in the
    /// opposite order a caller iterating `live_sessions` would encounter
    /// these two ids, so a positional pairing (rather than a real lookup)
    /// would attach `sess_a`'s count to `sess_b` and mark the wrong row
    /// selected.
    #[test]
    fn switcher_binding_joins_by_session_id_not_position() {
        use ward_daemon::registry::{Registry, RegistryEntry, VerificationState};
        use ward_daemon::selection::Selection;

        fn entry(session: &str, pending: usize) -> RegistryEntry {
            RegistryEntry {
                session: session.to_owned(),
                project: PathBuf::from("/tmp/proj"),
                agent: None,
                agent_state: None,
                pending_approvals: pending,
                verification: VerificationState::NeverRun,
            }
        }

        let registry = Registry {
            // Reverse of the order a `live_sessions` scan would give
            // `switcher`: `sess_b` first, `sess_a` second.
            entries: vec![entry("sess_b", 5), entry("sess_a", 1)],
            selection: Selection {
                session: Some("sess_a".to_owned()),
                generation: 1,
            },
        };

        assert_eq!(switcher_binding(&registry, "sess_a"), (1, true));
        assert_eq!(switcher_binding(&registry, "sess_b"), (5, false));
        // A live session the registry has no entry for at all (its own
        // separate probe connection hit a disconnect): the documented `0`/
        // not-selected fallback, not an error and not another session's
        // values.
        assert_eq!(switcher_binding(&registry, "sess_c"), (0, false));
    }

    /// A described session on a worktree, with its stream so far.
    #[allow(clippy::unwrap_used)]
    fn snapshot_on(worktree: &Path, events: &[ward_events::WardEvent]) -> Snapshot {
        use ward_events::{Chain, Origin, SessionId, Timestamp};
        use ward_policy::{Policy, merge};
        let manifest = merge(
            &Policy::default(),
            &Policy::default(),
            &Policy::default(),
            ward_policy::SessionId("sess_01J8ZK3Q9X7VY2".to_owned()),
            ward_policy::ProjectId("proj_x".to_owned()),
        );
        let description = SessionDescription {
            session: "sess_01J8ZK3Q9X7VY2".to_owned(),
            project: "proj_x".to_owned(),
            worktree: worktree.to_path_buf(),
            started_unix_ms: 0,
            agent: None,
            entry_snapshot: format!("blake3:{}", "ab".repeat(32)),
            policy_hash: manifest.policy_hash.to_hex(),
            manifest,
        };
        let mut model = Model::new(false);
        let mut chain = Chain::genesis(
            SessionId::from_u128(7),
            ward_events::Blake3Hash::from_bytes([1; 32]),
        );
        for (i, event) in events.iter().enumerate() {
            let rec = chain
                .append(
                    Origin::Verifier,
                    event.clone(),
                    Timestamp::mono(Duration::from_secs(i as u64)),
                )
                .unwrap();
            model.apply(rec);
        }
        Snapshot {
            header: Header::from_description(&description),
            description,
            model,
        }
    }

    fn passed(candidate: ward_snapshot::SnapshotId) -> ward_events::WardEvent {
        ward_events::WardEvent::VerificationPassed {
            candidate: ev_snapshot(candidate),
            summary: ward_events::VerifySummary {
                steps_total: 1,
                steps_passed: 1,
                steps_failed: 0,
                tests_run: 3,
                tests_failed: 0,
                duration: Duration::from_secs(1),
            },
            result_hash: ward_events::Blake3Hash::from_bytes([2; 32]),
        }
    }

    #[test]
    fn the_verify_segment_follows_the_worktree_by_content() {
        #![allow(clippy::unwrap_used)]
        // A worktree with a candidate stored in a CAS, as `ward verify` leaves it.
        let work = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("lib.rs"), "fn f() {}\n").unwrap();
        std::fs::write(work.path().join("README.md"), "# x\n").unwrap();
        let store = SnapshotStore::open(state.path().join("cas")).unwrap();
        let candidate = store
            .store_snapshot(
                work.path(),
                ward_snapshot::SnapshotRole::Candidate,
                candidate_options(),
            )
            .unwrap();
        let mut digester = Digester {
            cache: HashCache::new(),
            store: Some(store),
        };

        // Verified, and the tree is the candidate: green, and the panel says 0 changes.
        let mut s = snapshot_on(work.path(), &[passed(candidate)]);
        digester.observe(&mut s);
        let bar = TrustBar::new(&s.header, &s.model, now_unix_ms());
        let verify = bar.segment(SegmentName::Verify).unwrap();
        assert_eq!(
            verify.text,
            format!("VERIFY ✓ {}", &candidate.digest().to_hex()[..8])
        );
        assert_eq!(verify.tone, ward_shell_core::Tone::Ok);
        let text = render(&s, Surface::VerifyPanel);
        assert!(text.contains("Changes              0\n"), "{text}");
        assert!(text.contains("Tests                3/3\n"), "{text}");

        // One edit and one new file: stale, and the panel counts two entries.
        std::fs::write(work.path().join("lib.rs"), "fn f() { g() }\n").unwrap();
        std::fs::write(work.path().join("new.rs"), "").unwrap();
        digester.observe(&mut s);
        let bar = TrustBar::new(&s.header, &s.model, now_unix_ms());
        let verify = bar.segment(SegmentName::Verify).unwrap();
        assert_eq!(verify.text, "VERIFY ~ STALE");
        assert_eq!(verify.tone, ward_shell_core::Tone::Warn);
        let text = render(&s, Surface::VerifyPanel);
        assert!(text.contains("Changes              2 entries\n"), "{text}");
        assert!(
            text.starts_with(&format!("{}\n\nVerify\n", bar.text())),
            "{text}"
        );

        // Undo both: the bytes are the candidate's again, so it is verified again.
        std::fs::write(work.path().join("lib.rs"), "fn f() {}\n").unwrap();
        std::fs::remove_file(work.path().join("new.rs")).unwrap();
        digester.observe(&mut s);
        assert!(
            TrustBar::new(&s.header, &s.model, now_unix_ms())
                .segment(SegmentName::Verify)
                .unwrap()
                .text
                .starts_with("VERIFY ✓ ")
        );

        // Without the CAS the state is still decided (by digest), only the
        // count is unknown; a worktree that cannot be read changes nothing.
        digester.store = None;
        std::fs::write(work.path().join("lib.rs"), "fn f() { g() }\n").unwrap();
        digester.observe(&mut s);
        let text = render(&s, Surface::VerifyPanel);
        assert!(text.contains("VERIFY ~ STALE"), "{text}");
        assert!(text.contains("Changes              unknown\n"), "{text}");
        let before = s.model.worktree;
        s.description.worktree = work.path().join("gone");
        digester.observe(&mut s);
        assert_eq!(s.model.worktree, before);
    }

    /// A harmless record, one per call, so a burst of "dirty" triggers can be
    /// fed to [`observe_event`] without caring what it says.
    #[allow(clippy::unwrap_used)]
    fn note(chain: &mut ward_events::Chain, i: u64) -> ward_events::EventRecord {
        chain
            .append(
                ward_events::Origin::Wardd,
                ward_events::WardEvent::AgentClaim {
                    kind: ward_events::ClaimKind::Note,
                    payload: ward_events::PayloadText::new("tick"),
                },
                ward_events::Timestamp::mono(Duration::from_millis(i)),
            )
            .unwrap()
    }

    /// (a) #138 item 3: a segment that does not display freshness (`waybar()`
    /// passes `digester: None` for it, per [`SegmentName::needs_freshness`])
    /// must never trigger a worktree digest — not on load, not on a record,
    /// not on a tick — however many triggers arrive and however much the
    /// worktree changes underneath.
    #[test]
    fn a_non_freshness_segment_never_triggers_a_digest() {
        #![allow(clippy::unwrap_used)]
        use ward_events::{Blake3Hash, Chain, SessionId};
        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("a.rs"), "fn a() {}\n").unwrap();
        let mut s = snapshot_on(work.path(), &[]);
        let mut gate = DigestGate::new();
        let mut chain = Chain::genesis(SessionId::from_u128(7), Blake3Hash::from_bytes([1; 32]));
        let t0 = Instant::now();
        // A record, then a tick, alternating, well past any debounce
        // interval each time — nothing here should ever be enough to scan
        // when there is no digester at all.
        for i in 0..6u64 {
            std::fs::write(work.path().join("a.rs"), format!("fn a() {{ {i} }}\n")).unwrap();
            let event = if i % 2 == 0 {
                Some(note(&mut chain, i))
            } else {
                None
            };
            let force = event.is_none();
            let scanned = observe_event(
                &mut s,
                None,
                &mut gate,
                event,
                t0 + Duration::from_secs(i),
                DIGEST_DEBOUNCE,
                force,
            );
            assert!(!scanned, "no digester means no scan, ever (i={i})");
        }
        assert!(
            s.model.worktree.is_none(),
            "freshness was never observed: no digest ever ran"
        );
    }

    /// (b) #138 item 3: a burst of rapid dirty triggers for a segment that
    /// *does* need freshness collapses into a bounded number of scans, not
    /// one per record.
    #[test]
    fn a_burst_of_rapid_dirty_triggers_coalesces_into_a_bounded_number_of_scans() {
        #![allow(clippy::unwrap_used)]
        use ward_events::{Blake3Hash, Chain, SessionId};
        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("a.rs"), "fn a() {}\n").unwrap();
        let mut s = snapshot_on(work.path(), &[]);
        let mut digester = Digester {
            cache: HashCache::new(),
            store: None,
        };
        let mut gate = DigestGate::new();
        let mut chain = Chain::genesis(SessionId::from_u128(7), Blake3Hash::from_bytes([1; 32]));
        let t0 = Instant::now();
        let mut scans = 0u32;
        // Thirty records, all inside one debounce interval.
        for i in 0..30u64 {
            let rec = note(&mut chain, i);
            if observe_event(
                &mut s,
                Some(&mut digester),
                &mut gate,
                Some(rec),
                t0 + Duration::from_millis(i),
                DIGEST_DEBOUNCE,
                false,
            ) {
                scans += 1;
            }
        }
        assert_eq!(
            scans, 1,
            "thirty records inside one interval must not be thirty scans"
        );
        assert!(s.model.worktree.is_some(), "the burst was still observed");

        // Past the interval, a fresh record scans again: coalescing a burst
        // must never mean a later, genuine change goes unnoticed forever.
        let rec = note(&mut chain, 30);
        let scanned = observe_event(
            &mut s,
            Some(&mut digester),
            &mut gate,
            Some(rec),
            t0 + DIGEST_DEBOUNCE,
            DIGEST_DEBOUNCE,
            false,
        );
        assert!(scanned, "a record past the debounce interval scans again");
        assert_eq!(scans + u32::from(scanned), 2);
    }

    /// A quiet tick always scans (the safety net for an edit made outside the
    /// sandbox, which leaves no record), even immediately after a
    /// record-triggered scan already ran — a tick is never itself debounced.
    #[test]
    fn a_quiet_tick_always_scans_even_right_after_a_record_scan() {
        #![allow(clippy::unwrap_used)]
        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("a.rs"), "fn a() {}\n").unwrap();
        let mut s = snapshot_on(work.path(), &[]);
        let mut digester = Digester {
            cache: HashCache::new(),
            store: None,
        };
        let mut gate = DigestGate::new();
        let t0 = Instant::now();
        gate.mark_dirty();
        assert!(observe_event(
            &mut s,
            Some(&mut digester),
            &mut gate,
            None,
            t0,
            DIGEST_DEBOUNCE,
            true,
        ));
        assert!(
            observe_event(
                &mut s,
                Some(&mut digester),
                &mut gate,
                None,
                t0,
                DIGEST_DEBOUNCE,
                true,
            ),
            "a forced tick scans unconditionally, not just the first one"
        );
    }

    /// Review finding on #213: debouncing the digest must never let the trust
    /// bar keep claiming a confirmed match once a record gives explicit
    /// evidence the tree may have changed, and the debounce deadline itself —
    /// not only another record or the unrelated quiet-tick safety net — must
    /// still get the deferred digest run.
    #[test]
    fn a_dirty_trigger_withdraws_green_immediately_and_is_rescanned_by_its_own_deadline() {
        #![allow(clippy::unwrap_used)]
        use ward_events::{Blake3Hash, Chain, SessionId};
        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("a.rs"), "fn a() {}\n").unwrap();
        let cas = tempfile::tempdir().unwrap();
        let store = SnapshotStore::open(cas.path().join("cas")).unwrap();
        let candidate = store
            .store_snapshot(
                work.path(),
                ward_snapshot::SnapshotRole::Candidate,
                candidate_options(),
            )
            .unwrap();
        let mut digester = Digester {
            cache: HashCache::new(),
            store: Some(store),
        };
        let mut gate = DigestGate::new();
        let mut s = snapshot_on(work.path(), &[passed(candidate)]);
        let mut chain = Chain::genesis(SessionId::from_u128(9), Blake3Hash::from_bytes([3; 32]));
        let t0 = Instant::now();

        // A first record-triggered scan while the tree still matches: green,
        // and the gate now has a real last-scan baseline for the interval
        // below (mirroring the real bar's pre-loop digest plus at least one
        // record already having gone through the gate).
        assert!(observe_event(
            &mut s,
            Some(&mut digester),
            &mut gate,
            Some(note(&mut chain, 0)),
            t0,
            DIGEST_DEBOUNCE,
            false,
        ));
        assert!(
            TrustBar::new(&s.header, &s.model, now_unix_ms())
                .segment(SegmentName::Verify)
                .unwrap()
                .text
                .starts_with("VERIFY \u{2713} "),
            "setup: must start green"
        );

        // Edit the tree, then feed a record inside the debounce interval:
        // the digest itself is deferred...
        std::fs::write(work.path().join("a.rs"), "fn a() { changed() }\n").unwrap();
        let scanned = observe_event(
            &mut s,
            Some(&mut digester),
            &mut gate,
            Some(note(&mut chain, 1)),
            t0 + Duration::from_millis(1),
            DIGEST_DEBOUNCE,
            false,
        );
        assert!(
            !scanned,
            "the digest itself is debounced, still inside the interval"
        );
        // ...but green must already be withdrawn: the trust bar must not
        // keep asserting a confirmed match with evidence the tree may have
        // changed, before that debounced digest ever runs.
        assert_ne!(
            TrustBar::new(&s.header, &s.model, now_unix_ms())
                .segment(SegmentName::Verify)
                .unwrap()
                .tone,
            ward_shell_core::Tone::Ok,
            "green must be withdrawn the instant a change might have landed"
        );

        // At the debounce deadline, with no further record — a fine-grained
        // wake-up, not a record and not the unrelated quiet-tick safety net
        // (force stays false) — the pending dirty generation must still be
        // rescanned.
        let scanned = observe_event(
            &mut s,
            Some(&mut digester),
            &mut gate,
            None,
            t0 + DIGEST_DEBOUNCE,
            DIGEST_DEBOUNCE,
            false,
        );
        assert!(
            scanned,
            "the debounce deadline itself must be scanned, not only another record or a forced tick"
        );
        assert_eq!(
            TrustBar::new(&s.header, &s.model, now_unix_ms())
                .segment(SegmentName::Verify)
                .unwrap()
                .text,
            "VERIFY ~ STALE",
            "the deferred digest must now reflect the real edit"
        );
    }

    /// The number `docs/desktop.md` states. `WARD_DIGEST_DIR=<tree>` measures
    /// another worktree instead (`cargo test -p ward-shell a_warm_digest --
    /// --nocapture`).
    #[test]
    fn a_warm_digest_of_the_demo_is_within_the_bar_budget() {
        #![allow(clippy::unwrap_used)]
        let demo = std::env::var_os("WARD_DIGEST_DIR").map_or_else(
            || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/ward-demo"),
            PathBuf::from,
        );
        let opts = CaptureOptions {
            incremental: true,
            ..candidate_options()
        };
        let mut cache = HashCache::new();
        let mut stats = CaptureStats::default();
        let cold = std::time::Instant::now();
        let first = ward_snapshot::digest_manifest(&demo, opts, &mut cache, &mut stats).unwrap();
        let cold = cold.elapsed();
        let warm = std::time::Instant::now();
        let second = ward_snapshot::digest_manifest(&demo, opts, &mut cache, &mut stats).unwrap();
        let warm = warm.elapsed();
        assert_eq!(first, second);
        eprintln!(
            "{} digest: cold {} µs, warm {} µs ({} files, {} cached)",
            demo.display(),
            cold.as_micros(),
            warm.as_micros(),
            stats.files_total / 2,
            stats.files_cached
        );
        assert!(
            warm < Duration::from_millis(50),
            "warm digest took {warm:?}"
        );
    }

    /// A fake daemon for `load_from` tests (#138 item 5): every connection
    /// answers `Ping`→`Ok` and `Describe`→a fixed description; a
    /// `Subscribe { from_seq }` streams `log` from `from_seq`, then, only
    /// when `seal` is `true`, an explicit `Response::Sealed` — with `seal:
    /// false` the connection is simply dropped once the backlog is sent,
    /// exactly the shape a daemon crash or restart mid-catch-up leaves
    /// (never a confirmed end). Serves exactly two connections: `load_from`
    /// opens one for `Describe` (and drops it) and a second for the
    /// subscription.
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn fake_catch_up_daemon(
        log: Vec<ward_events::EventRecord>,
        seal: bool,
    ) -> (tempfile::TempDir, PathBuf) {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::{UnixListener, UnixStream};
        use ward_daemon::control::{Request, Response, SOCKET_NAME};
        use ward_events::{Blake3Hash, Chain, SessionId};
        use ward_policy::{Policy, merge};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        let head = Chain::genesis(SessionId::from_u128(17), Blake3Hash::from_bytes([4; 32])).head();
        let manifest = merge(
            &Policy::default(),
            &Policy::default(),
            &Policy::default(),
            ward_policy::SessionId("sess_fake".to_owned()),
            ward_policy::ProjectId("proj_fake".to_owned()),
        );
        let description = SessionDescription {
            session: "sess_fake".to_owned(),
            project: "proj_fake".to_owned(),
            worktree: PathBuf::from("/tmp/fake"),
            started_unix_ms: 0,
            agent: None,
            entry_snapshot: format!("blake3:{}", "ab".repeat(32)),
            policy_hash: manifest.policy_hash.to_hex(),
            manifest,
        };
        std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                let mut writer = stream.try_clone().unwrap();
                let reply = |writer: &mut UnixStream, r: &Response| {
                    let mut b = serde_json::to_vec(r).unwrap();
                    b.push(b'\n');
                    writer.write_all(&b).unwrap();
                };
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    let request: Request = serde_json::from_str(&line).unwrap();
                    match request {
                        Request::Ping => reply(&mut writer, &Response::Ok),
                        Request::Describe => reply(
                            &mut writer,
                            &Response::Description(serde_json::to_value(&description).unwrap()),
                        ),
                        Request::Subscribe { from_seq } => {
                            for rec in log.iter().filter(|r| r.seq >= from_seq) {
                                reply(&mut writer, &Response::Record(Box::new(rec.clone())));
                            }
                            if seal {
                                reply(&mut writer, &Response::Sealed { head, ended: None });
                            }
                            break;
                        }
                        other => panic!("unexpected request in a catch-up test: {other:?}"),
                    }
                }
            }
        });
        (dir, socket)
    }

    /// #138 item 5, `load_from`'s slice of the same bug: a catch-up
    /// connection cut off before the daemon ever confirms `CaughtUp` or
    /// `Sealed` is this viewer's own uncertainty, not proof the log ended —
    /// `load_from` must render the model `connected: false`, never
    /// `sealed: true` (a claim about the daemon's state that connection
    /// never made). A daemon that does confirm the seal is still `sealed`.
    #[test]
    fn load_from_marks_disconnected_not_sealed_when_catch_up_is_merely_cut_off() {
        #![allow(clippy::unwrap_used)]
        use ward_events::{Blake3Hash, Chain, SessionId};

        let mut chain = Chain::genesis(SessionId::from_u128(19), Blake3Hash::from_bytes([5; 32]));
        let log = vec![note(&mut chain, 0)];

        let (_dir, socket) = fake_catch_up_daemon(log.clone(), false);
        let snapshot = load_from(&socket, Duration::from_millis(200))
            .unwrap()
            .unwrap();
        assert!(
            !snapshot.model.sealed,
            "the daemon never confirmed a seal on this connection"
        );
        assert!(
            !snapshot.model.connected,
            "a catch-up connection that was merely cut off is not a live connection either"
        );

        let (_dir, socket) = fake_catch_up_daemon(log, true);
        let snapshot = load_from(&socket, Duration::from_millis(200))
            .unwrap()
            .unwrap();
        assert!(snapshot.model.sealed, "this one did confirm the seal");
    }

    /// A minimal fake daemon for `follow_loop` reconnect tests (#138 item
    /// 5): every connection answers `Ping`→`Ok`, then `Subscribe { from_seq
    /// }` by streaming `log`'s records from `from_seq` onward. Every
    /// connection but the last then drops without confirming a seal (a
    /// daemon crash/restart mid-stream); the last one replies
    /// `Response::Sealed` before dropping. `connections` fixes exactly how
    /// many connections the test expects — a real socket, but no sleeps
    /// stand between one connection ending and the next being ready to
    /// `accept()`, so the only real time in the test is `follow_loop`'s own
    /// bounded reconnect backoff. Returns the `from_seq` each connection's
    /// `Subscribe` actually asked for, oldest first, so a test can assert a
    /// reconnect asked from the last confirmed sequence rather than replaying
    /// from zero.
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn fake_reconnect_daemon(
        log: Vec<ward_events::EventRecord>,
        connections: usize,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        std::thread::JoinHandle<Vec<u64>>,
    ) {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::{UnixListener, UnixStream};
        use ward_daemon::control::{Request, Response, SOCKET_NAME};
        use ward_events::{Blake3Hash, Chain, SessionId};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        let head = Chain::genesis(SessionId::from_u128(13), Blake3Hash::from_bytes([9; 32])).head();
        let handle = std::thread::spawn(move || {
            let mut seen_from_seq = Vec::new();
            for i in 0..connections {
                let (stream, _) = listener.accept().unwrap();
                let mut writer = stream.try_clone().unwrap();
                let reply = |writer: &mut UnixStream, r: &Response| {
                    let mut b = serde_json::to_vec(r).unwrap();
                    b.push(b'\n');
                    writer.write_all(&b).unwrap();
                };
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    let request: Request = serde_json::from_str(&line).unwrap();
                    match request {
                        Request::Ping => reply(&mut writer, &Response::Ok),
                        Request::Subscribe { from_seq } => {
                            seen_from_seq.push(from_seq);
                            let matching: Vec<_> =
                                log.iter().filter(|r| r.seq >= from_seq).collect();
                            let last_connection = i + 1 == connections;
                            // Every connection but the last replays only the
                            // next one record before dropping — the crash
                            // this test means to simulate happens mid-stream,
                            // not after the whole backlog was already sent
                            // (which would leave nothing left to prove a
                            // reconnect resumes from, rather than repeats).
                            let to_send = if last_connection {
                                &matching[..]
                            } else {
                                &matching[..matching.len().min(1)]
                            };
                            for rec in to_send {
                                reply(&mut writer, &Response::Record(Box::new((*rec).clone())));
                            }
                            if last_connection {
                                reply(&mut writer, &Response::Sealed { head, ended: None });
                            }
                            break;
                        }
                        other => panic!("unexpected request in a reconnect test: {other:?}"),
                    }
                }
                // Every connection but the last drops here without a seal:
                // `stream`/`writer` go out of scope, closing the socket, the
                // same shape an unattended daemon crash or restart leaves.
            }
            seen_from_seq
        });
        (dir, socket, handle)
    }

    /// #138 item 5, core claim: a connection lost mid-`--follow` without a
    /// confirmed seal reconnects from the last *confirmed* sequence, never
    /// from zero, and the bar reads the `unknown` state for the gap rather
    /// than silently keeping the last live render or falsely claiming
    /// `SEALED`.
    #[test]
    fn follow_loop_reconnects_from_the_last_confirmed_sequence_not_from_zero() {
        #![allow(clippy::unwrap_used)]
        use ward_events::{Blake3Hash, Chain, SessionId};

        let work = tempfile::tempdir().unwrap();
        let mut s = snapshot_on(work.path(), &[]);
        let mut chain = Chain::genesis(SessionId::from_u128(11), Blake3Hash::from_bytes([2; 32]));
        let records = vec![
            note(&mut chain, 0),
            note(&mut chain, 1),
            note(&mut chain, 2),
        ];
        // Record 0 is already confirmed before `follow_loop` starts — this
        // is what `load_from`'s own catch-up would already have applied —
        // so the very first subscribe must ask from seq 1, and the
        // reconnect after the drop must ask from seq 2: never from 0.
        s.model.apply(records[0].clone());
        let last = module(&s, None);

        let (_dir, socket, server) = fake_reconnect_daemon(records, 2);

        let emitted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = std::sync::Arc::clone(&emitted);
        let result = follow_loop(
            &socket,
            s,
            None,
            None,
            DigestGate::new(),
            Duration::from_millis(20),
            Duration::from_secs(3600),
            last,
            move |m: &Module| {
                recorded.lock().unwrap().push(m.clone());
                Ok(())
            },
        )
        .unwrap();

        let seen_from_seq = server.join().unwrap();
        assert_eq!(
            seen_from_seq,
            vec![1, 2],
            "the reconnect must ask from the last confirmed sequence, not replay from zero"
        );
        assert!(
            result.model.sealed,
            "the second connection did confirm a seal"
        );
        let emitted = emitted.lock().unwrap();
        assert!(
            emitted
                .iter()
                .any(|m| m.class.first().map(String::as_str) == Some("unknown")),
            "the drop must render the bar's unknown state promptly, not stay silent: {emitted:?}"
        );
        assert!(
            emitted
                .last()
                .is_some_and(|m| m.class.first().map(String::as_str) == Some("sealed")),
            "the confirmed seal is the last word, not unknown: {emitted:?}"
        );
    }

    /// #138 item 5: reconnect attempts are bounded, not a tight or infinite
    /// loop — a socket nothing has ever answered on fails closed (rendering
    /// `unknown` along the way) within a small, fixed number of attempts,
    /// never hanging.
    #[test]
    fn follow_loop_gives_up_after_bounded_reconnect_attempts_when_nothing_answers() {
        #![allow(clippy::unwrap_used, clippy::panic)]
        // Deliberately never bound: every `client::connect` on this path
        // fails immediately and identically, with no race between a real
        // daemon's listener closing and this test's own retries (a fake
        // daemon that serves one connection and then vanishes would race
        // its own thread teardown against the client's next attempt).
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(ward_daemon::control::SOCKET_NAME);

        let work = tempfile::tempdir().unwrap();
        let s = snapshot_on(work.path(), &[]);
        let last = module(&s, None);
        let emitted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = std::sync::Arc::clone(&emitted);

        let started = Instant::now();
        let result = follow_loop(
            &socket,
            s,
            None,
            None,
            DigestGate::new(),
            Duration::from_millis(20),
            Duration::from_secs(3600),
            last,
            move |m: &Module| {
                recorded.lock().unwrap().push(m.clone());
                Ok(())
            },
        );
        let elapsed = started.elapsed();
        let Err(err) = result else {
            panic!("a socket nothing has ever answered on must not succeed");
        };

        assert_eq!(err.to_string(), client::NO_DAEMON);
        assert!(
            elapsed < Duration::from_secs(2),
            "bounded backoff must fail closed quickly, not hang: {elapsed:?}"
        );
        let emitted = emitted.lock().unwrap();
        assert!(
            emitted
                .iter()
                .any(|m| m.class.first().map(String::as_str) == Some("unknown")),
            "the never-connected state must render as unknown, not stay silent: {emitted:?}"
        );
    }

    /// Like [`fake_reconnect_daemon`], but the *last* connection also proves
    /// the #138 item 5 catch-up boundary (review 5337489166 of #329, finding
    /// 2): after replaying its own backlog it pauses for real wall-clock
    /// time (`hold`) — a daemon slow to drain a backlog, or simply time
    /// passing — before sending the daemon's own explicit `Response::CaughtUp`
    /// and then `Response::Sealed`. Every earlier connection behaves exactly
    /// as [`fake_reconnect_daemon`]'s: one record, then drop without
    /// confirming anything (a crash mid-stream).
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn fake_catchup_pause_daemon(
        log: Vec<ward_events::EventRecord>,
        connections: usize,
        hold: Duration,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        std::thread::JoinHandle<Vec<u64>>,
    ) {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::{UnixListener, UnixStream};
        use ward_daemon::control::{Request, Response, SOCKET_NAME};
        use ward_events::{Blake3Hash, Chain, SessionId};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        let head = Chain::genesis(SessionId::from_u128(23), Blake3Hash::from_bytes([7; 32])).head();
        let handle = std::thread::spawn(move || {
            let mut seen_from_seq = Vec::new();
            for i in 0..connections {
                let (stream, _) = listener.accept().unwrap();
                let mut writer = stream.try_clone().unwrap();
                let reply = |writer: &mut UnixStream, r: &Response| {
                    let mut b = serde_json::to_vec(r).unwrap();
                    b.push(b'\n');
                    writer.write_all(&b).unwrap();
                };
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    let request: Request = serde_json::from_str(&line).unwrap();
                    match request {
                        Request::Ping => reply(&mut writer, &Response::Ok),
                        Request::Subscribe { from_seq } => {
                            seen_from_seq.push(from_seq);
                            let matching: Vec<_> =
                                log.iter().filter(|r| r.seq >= from_seq).collect();
                            let last_connection = i + 1 == connections;
                            if last_connection {
                                // The backlog in two halves with a real pause
                                // between them — mid-backlog, not just
                                // mid-connect — so a test reading the emitted
                                // classes through that pause can prove the
                                // model never renders live while it waits.
                                let mid = matching.len() / 2;
                                for rec in &matching[..mid] {
                                    reply(&mut writer, &Response::Record(Box::new((*rec).clone())));
                                }
                                std::thread::sleep(hold);
                                for rec in &matching[mid..] {
                                    reply(&mut writer, &Response::Record(Box::new((*rec).clone())));
                                }
                                let next_seq = matching.last().map_or(from_seq, |r| r.seq + 1);
                                reply(&mut writer, &Response::CaughtUp { next_seq });
                                reply(&mut writer, &Response::Sealed { head, ended: None });
                            } else {
                                // Every connection but the last replays only
                                // the next one record before dropping, the
                                // same crash-mid-stream shape as
                                // `fake_reconnect_daemon`.
                                for rec in &matching[..matching.len().min(1)] {
                                    reply(&mut writer, &Response::Record(Box::new((*rec).clone())));
                                }
                            }
                            break;
                        }
                        other => panic!("unexpected request in a catch-up pause test: {other:?}"),
                    }
                }
            }
            seen_from_seq
        });
        (dir, socket, handle)
    }

    /// Review 5337489166 of #329, finding 2: a connection lost mid-`--follow`
    /// and then reconnected must not render `live` again until the daemon's
    /// own `CaughtUp` boundary confirms the backlog this reconnect asked for
    /// is fully applied — never merely because `client::connect` (which only
    /// completes `Ping`) succeeded. The reconnect here pauses for real
    /// wall-clock time mid-backlog before that boundary arrives, so a
    /// premature `live` would be directly observable if `follow_loop` ever
    /// cleared `unknown` too early.
    #[test]
    fn follow_loop_never_renders_live_before_the_reconnect_reaches_caught_up() {
        #![allow(clippy::unwrap_used)]
        use ward_events::{Blake3Hash, Chain, SessionId};

        let work = tempfile::tempdir().unwrap();
        let mut s = snapshot_on(work.path(), &[]);
        let mut chain = Chain::genesis(SessionId::from_u128(29), Blake3Hash::from_bytes([11; 32]));
        let records = vec![
            note(&mut chain, 0),
            note(&mut chain, 1),
            note(&mut chain, 2),
            note(&mut chain, 3),
        ];
        s.model.apply(records[0].clone());
        let last = module(&s, None);
        assert_eq!(
            last.class.first().map(String::as_str),
            Some("live"),
            "sanity: the run starts live, before any drop"
        );

        let (_dir, socket, server) =
            fake_catchup_pause_daemon(records, 2, Duration::from_millis(200));

        let emitted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = std::sync::Arc::clone(&emitted);
        let result = follow_loop(
            &socket,
            s,
            None,
            None,
            DigestGate::new(),
            Duration::from_millis(20),
            Duration::from_secs(3600),
            last,
            move |m: &Module| {
                recorded.lock().unwrap().push(m.clone());
                Ok(())
            },
        )
        .unwrap();

        let seen_from_seq = server.join().unwrap();
        assert_eq!(
            seen_from_seq,
            vec![1, 2],
            "the reconnect must resume from the last confirmed sequence"
        );
        assert!(result.model.sealed, "the last connection confirmed a seal");
        // Every record was applied exactly once: none skipped by the
        // reconnect's resume point, none replayed twice by it either.
        assert_eq!(result.model.counters.claims, 4);

        let emitted = emitted.lock().unwrap();
        let classes: Vec<&str> = emitted
            .iter()
            .map(|m| m.class.first().map_or("", String::as_str))
            .collect();
        let mut deduped = classes.clone();
        deduped.dedup();
        assert_eq!(
            deduped,
            vec!["unknown", "live", "sealed"],
            "must read unknown for the whole reconnect-and-replay, live only once caught \
             up, and never a live frame in between: {classes:?}"
        );
    }

    /// A fake daemon serving `cycles` connections, each a *successful*
    /// reconnect (review 5337489166 of #329, finding 3): every connection
    /// answers `Ping`, then `Subscribe` with nothing new (a quiet,
    /// already-caught-up session) followed by the daemon's own
    /// `Response::CaughtUp`, then drops without a seal — the same shape a
    /// daemon restart between otherwise healthy periods leaves, repeated more
    /// times than [`RECONNECT_ATTEMPTS`] bounds a single *consecutive* run of
    /// failures. The last connection also sends `Response::Sealed` so the
    /// test ends deterministically.
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn fake_many_successful_reconnects_daemon(
        cycles: usize,
    ) -> (tempfile::TempDir, PathBuf, std::thread::JoinHandle<usize>) {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::{UnixListener, UnixStream};
        use ward_daemon::control::{Request, Response, SOCKET_NAME};
        use ward_events::{Blake3Hash, Chain, SessionId};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        let head =
            Chain::genesis(SessionId::from_u128(31), Blake3Hash::from_bytes([13; 32])).head();
        let handle = std::thread::spawn(move || {
            let mut seen = 0usize;
            for i in 0..cycles {
                let (stream, _) = listener.accept().unwrap();
                let mut writer = stream.try_clone().unwrap();
                let reply = |writer: &mut UnixStream, r: &Response| {
                    let mut b = serde_json::to_vec(r).unwrap();
                    b.push(b'\n');
                    writer.write_all(&b).unwrap();
                };
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    let request: Request = serde_json::from_str(&line).unwrap();
                    match request {
                        Request::Ping => reply(&mut writer, &Response::Ok),
                        Request::Subscribe { from_seq } => {
                            seen += 1;
                            reply(&mut writer, &Response::CaughtUp { next_seq: from_seq });
                            if i + 1 == cycles {
                                reply(&mut writer, &Response::Sealed { head, ended: None });
                            }
                            break;
                        }
                        other => panic!("unexpected request: {other:?}"),
                    }
                }
            }
            seen
        });
        (dir, socket, handle)
    }

    /// Review 5337489166 of #329, finding 3: the reconnect budget bounds a
    /// *consecutive* run of failures, not the whole process's lifetime — a
    /// confirmed catch-up resets it. More separated, individually-successful
    /// reconnects than [`RECONNECT_ATTEMPTS`] must not exhaust it; a bar that
    /// keeps recovering from isolated daemon restarts must not give up on the
    /// next one just because time (and other, unrelated restarts) has
    /// passed.
    #[test]
    fn follow_loop_survives_more_successful_reconnects_than_the_retry_budget() {
        #![allow(clippy::unwrap_used, clippy::panic)]
        let work = tempfile::tempdir().unwrap();
        let s = snapshot_on(work.path(), &[]);
        let last = module(&s, None);

        let cycles = usize::try_from(RECONNECT_ATTEMPTS).unwrap() + 3;
        let (_dir, socket, server) = fake_many_successful_reconnects_daemon(cycles);

        let result = follow_loop(
            &socket,
            s,
            None,
            None,
            DigestGate::new(),
            Duration::from_millis(5),
            Duration::from_secs(3600),
            last,
            |_m: &Module| Ok(()),
        );

        let seen = server.join().unwrap();
        assert_eq!(
            seen, cycles,
            "every one of the separated reconnects must be tried, not just the first \
             {RECONNECT_ATTEMPTS}"
        );
        let result = result
            .unwrap_or_else(|e| panic!("must not give up on isolated, successful reconnects: {e}"));
        assert!(result.model.sealed, "the last connection confirmed a seal");
    }

    /// A fake daemon serving `count` connections that each answer `Ping` and
    /// then close before ever seeing `Subscribe` — the shape review
    /// 5337489166 of #329, finding 3 calls out explicitly: a daemon gone in
    /// the narrow window between completing `Ping` (which `client::connect`
    /// blocks on) and the subscription actually reaching it.
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn fake_close_before_subscribe_daemon(
        count: usize,
    ) -> (tempfile::TempDir, PathBuf, std::thread::JoinHandle<usize>) {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;
        use ward_daemon::control::{Request, Response, SOCKET_NAME};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        let handle = std::thread::spawn(move || {
            let mut served = 0usize;
            for _ in 0..count {
                let (stream, _) = listener.accept().unwrap();
                served += 1;
                let mut writer = stream.try_clone().unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                let request: Request = serde_json::from_str(&line).unwrap();
                assert!(
                    matches!(request, Request::Ping),
                    "expected Ping first, got {request:?}"
                );
                let mut b = serde_json::to_vec(&Response::Ok).unwrap();
                b.push(b'\n');
                writer.write_all(&b).unwrap();
                // `reader`/`writer` are dropped here, closing the connection
                // before `Subscribe` is ever read or answered.
            }
            served
        });
        (dir, socket, handle)
    }

    /// Review 5337489166 of #329, finding 3: a daemon that answers `Ping`
    /// and then closes before `Subscribe`, repeated consecutively, must still
    /// be bounded by [`RECONNECT_ATTEMPTS`] — the same "fail closed, not
    /// hang" contract [`follow_loop_gives_up_after_bounded_reconnect_attempts_when_nothing_answers`]
    /// proves for a connect that never even completes `Ping`, but exercised
    /// through the read/subscribe path instead so a transport failure there
    /// cannot quietly bypass the bound via a bare `?`.
    #[test]
    fn follow_loop_gives_up_after_bounded_consecutive_failures_even_when_ping_answers() {
        #![allow(clippy::unwrap_used, clippy::panic)]
        let work = tempfile::tempdir().unwrap();
        let s = snapshot_on(work.path(), &[]);
        let last = module(&s, None);
        let emitted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = std::sync::Arc::clone(&emitted);

        // Exactly enough connections to answer every attempt `follow_loop`
        // will make (the first, plus `RECONNECT_ATTEMPTS` retries) and not
        // one more: if it ever tried an extra connection, `accept()` would
        // have nothing left to answer it, the same "must fail closed, not
        // hang" shape the unreachable-socket test above proves.
        let count = usize::try_from(RECONNECT_ATTEMPTS).unwrap() + 1;
        let (_dir, socket, server) = fake_close_before_subscribe_daemon(count);

        let started = Instant::now();
        let result = follow_loop(
            &socket,
            s,
            None,
            None,
            DigestGate::new(),
            Duration::from_millis(20),
            Duration::from_secs(3600),
            last,
            move |m: &Module| {
                recorded.lock().unwrap().push(m.clone());
                Ok(())
            },
        );
        let elapsed = started.elapsed();
        assert!(
            result.is_err(),
            "a daemon that never once answers Subscribe must eventually be given up on"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "bounded backoff must fail closed quickly, not hang: {elapsed:?}"
        );
        assert_eq!(
            server.join().unwrap(),
            count,
            "every bounded attempt must actually be tried — not fewer (giving up too \
             early) and not more (the budget not actually bounded)"
        );
        let emitted = emitted.lock().unwrap();
        assert!(
            emitted
                .iter()
                .any(|m| m.class.first().map(String::as_str) == Some("unknown")),
            "must render unknown along the way, not stay silent: {emitted:?}"
        );
    }

    /// [`fake_close_before_subscribe_daemon`], but after `bad_connections`
    /// such connections a final, good one actually answers `Subscribe`:
    /// replays `log`, then `Response::CaughtUp`, then `Response::Sealed`.
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn fake_close_before_subscribe_then_recover_daemon(
        log: Vec<ward_events::EventRecord>,
        bad_connections: usize,
    ) -> (tempfile::TempDir, PathBuf) {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::{UnixListener, UnixStream};
        use ward_daemon::control::{Request, Response, SOCKET_NAME};
        use ward_events::{Blake3Hash, Chain, SessionId};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        let head =
            Chain::genesis(SessionId::from_u128(37), Blake3Hash::from_bytes([17; 32])).head();
        std::thread::spawn(move || {
            for _ in 0..bad_connections {
                let (stream, _) = listener.accept().unwrap();
                let mut writer = stream.try_clone().unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                let request: Request = serde_json::from_str(&line).unwrap();
                assert!(matches!(request, Request::Ping));
                let mut b = serde_json::to_vec(&Response::Ok).unwrap();
                b.push(b'\n');
                writer.write_all(&b).unwrap();
                // Dropped here, without ever reading `Subscribe`.
            }
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let reply = |writer: &mut UnixStream, r: &Response| {
                let mut b = serde_json::to_vec(r).unwrap();
                b.push(b'\n');
                writer.write_all(&b).unwrap();
            };
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                let request: Request = serde_json::from_str(&line).unwrap();
                match request {
                    Request::Ping => reply(&mut writer, &Response::Ok),
                    Request::Subscribe { from_seq } => {
                        let mut next_seq = from_seq;
                        for rec in log.iter().filter(|r| r.seq >= from_seq) {
                            next_seq = rec.seq + 1;
                            reply(&mut writer, &Response::Record(Box::new(rec.clone())));
                        }
                        reply(&mut writer, &Response::CaughtUp { next_seq });
                        reply(&mut writer, &Response::Sealed { head, ended: None });
                        break;
                    }
                    other => panic!("unexpected request: {other:?}"),
                }
            }
        });
        (dir, socket)
    }

    /// Review 5337489166 of #329, finding 3: a daemon closing between `Ping`
    /// and `Subscribe` must be folded into the ordinary disconnect/retry
    /// path, not abort `follow_loop` outright — it recovers on the next
    /// connection exactly as a real daemon coming back up would.
    #[test]
    fn follow_loop_recovers_after_the_daemon_closes_between_ping_and_subscribe() {
        #![allow(clippy::unwrap_used, clippy::panic)]
        use ward_events::{Blake3Hash, Chain, SessionId};

        let work = tempfile::tempdir().unwrap();
        let mut s = snapshot_on(work.path(), &[]);
        let mut chain = Chain::genesis(SessionId::from_u128(41), Blake3Hash::from_bytes([19; 32]));
        let records = vec![note(&mut chain, 0), note(&mut chain, 1)];
        s.model.apply(records[0].clone());
        let last = module(&s, None);

        let (_dir, socket) = fake_close_before_subscribe_then_recover_daemon(records, 2);

        let result = follow_loop(
            &socket,
            s,
            None,
            None,
            DigestGate::new(),
            Duration::from_millis(20),
            Duration::from_secs(3600),
            last,
            |_m: &Module| Ok(()),
        )
        .unwrap_or_else(|e| {
            panic!(
                "a daemon that recovers after closing before Subscribe must not abort \
                 the loop outright: {e}"
            )
        });

        assert!(
            result.model.sealed,
            "the recovered connection confirmed a seal"
        );
        assert_eq!(result.model.counters.claims, 2);
    }

    #[test]
    fn the_empty_module_is_the_waybar_none_state() {
        #![allow(clippy::unwrap_used)]
        let none = serde_json::to_string(&Module::none(Some(SegmentName::Agent))).unwrap();
        assert_eq!(none, r#"{"text":"","tooltip":"","class":["none"]}"#);
        let mark = serde_json::to_string(&Module::none(Some(SegmentName::Mark))).unwrap();
        assert_eq!(
            mark,
            r#"{"text":"WARD","tooltip":"no session","class":["dim"]}"#
        );
    }
}
