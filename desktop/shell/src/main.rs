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

#![allow(clippy::missing_errors_doc, clippy::doc_markdown)]

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use ward_daemon::client::{self, WatchEnd};
use ward_daemon::ids::{ev_snapshot, snap_snapshot};
use ward_daemon::session::state_root;
use ward_daemon::verify::candidate_options;
use ward_shell_core::{
    Header, Launcher, LineContext, Model, Module, SegmentName, SessionCard, SessionDescription,
    Settings, TrustBar, counters_text, panel_text, session_panel, verify_panel,
};
use ward_snapshot::{
    CaptureOptions, CaptureStats, HashCache, Manifest, ManifestDiff, SnapshotStore,
};

/// How long the catch-up waits for one more record before calling the log
/// caught up with.
const SETTLE_MS: u64 = 250;

/// How often `bar --follow` re-reads the worktree when the stream is quiet:
/// an edit made outside the sandbox (the user's editor) is a change no record
/// reports, and it must turn `VERIFY ✓` into `VERIFY ~ STALE` all the same.
const TICK_MS: u64 = 2000;

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
    /// Milliseconds of silence after which the stream counts as caught up with.
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
        /// JSON changes; exit 0 when the daemon closes the stream.
        #[arg(long, requires = "waybar")]
        follow: bool,
        /// Milliseconds between re-reads of the worktree while following and
        /// the stream is quiet.
        #[arg(long, requires = "follow", default_value_t = TICK_MS)]
        tick_ms: u64,
    },
    /// The trust bar and the session panel behind its agent segment.
    Session,
    /// The trust bar and the verify panel behind its verify segment: the
    /// verified candidate, when, the worktree's digest now, what changed, and
    /// what the verifier found.
    VerifyPanel,
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
}

/// A session as the shell sees it: its facts and its stream so far.
struct Snapshot {
    description: SessionDescription,
    header: Header,
    model: Model,
}

/// The worktree reader behind the verify segment (ADR-0019 decision 1): a
/// hash cache that stays warm across re-reads, and the session CAS the change
/// count is diffed against. It never writes: the digest is the id the tree
/// *would* get, computed the way `ward verify` captures a candidate.
struct Digester {
    cache: HashCache,
    store: Option<SnapshotStore>,
}

impl Digester {
    fn new() -> Self {
        Self {
            cache: HashCache::new(),
            store: SnapshotStore::open(state_root().join("cas")).ok(),
        }
    }

    /// Digest `s`'s worktree and tell the model. A tree that cannot be read
    /// leaves the model as it was and says why once on stderr.
    fn observe(&mut self, s: &mut Snapshot) {
        let opts = CaptureOptions {
            incremental: true,
            ..candidate_options()
        };
        let mut stats = CaptureStats::default();
        let worktree = &s.description.worktree;
        match ward_snapshot::digest_manifest(worktree, opts, &mut self.cache, &mut stats) {
            Ok(manifest) => {
                let changes = self.changes(s, &manifest);
                s.model
                    .observe_worktree(ev_snapshot(manifest.id()), changes);
            }
            Err(e) => eprintln!("ward-shell: {}: {e}", worktree.display()),
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
    let dir = cli.dir.unwrap_or_else(|| PathBuf::from("."));
    let settle = Duration::from_millis(cli.settle_ms);
    let surface = cli.surface.unwrap_or(Surface::Bar {
        waybar: false,
        segment: None,
        follow: false,
        tick_ms: TICK_MS,
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
            Duration::from_millis(tick_ms),
        ),
        Surface::Launcher { query, lines: true } => launcher_lines(&dir, settle, &query),
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

/// `bar --waybar`: the module's JSON, once or on every change. The worktree is
/// digested before the first line and, while following, on every record and
/// on every quiet `tick`, so the verify segment answers for the tree as it is.
fn waybar(
    dir: &Path,
    settle: Duration,
    segment: Option<SegmentName>,
    follow: bool,
    tick: Duration,
) -> ward_daemon::Result<()> {
    let Some(socket) = locate(dir)? else {
        return emit(&Module::none(segment));
    };
    let Some(mut snapshot) = load_from(&socket, settle)? else {
        return emit(&Module::none(segment));
    };
    let mut digester = Digester::new();
    digester.observe(&mut snapshot);
    let mut last = module(&snapshot, segment);
    emit(&last)?;
    if !follow || snapshot.model.sealed {
        return Ok(());
    }
    // Waybar reads line by line: print only when the module changes. The
    // stream continues where the catch-up stopped; the daemon closing it means
    // the log is sealed (or the daemon is gone), and that is the last line.
    let from_seq = snapshot.model.records.last().map_or(0, |r| r.seq + 1);
    let subscriber = client::connect(&socket)?;
    let mut failed = None;
    client::watch_records_ticking(subscriber, from_seq, tick, |rec| {
        if let Some(rec) = rec {
            snapshot.model.apply(rec);
        }
        digester.observe(&mut snapshot);
        let now = module(&snapshot, segment);
        if now != last {
            if let Err(e) = emit(&now) {
                failed = Some(e);
            }
            last = now;
        }
    })?;
    if let Some(e) = failed {
        return Err(e);
    }
    snapshot.model.seal();
    let now = module(&snapshot, segment);
    if now != last {
        emit(&now)?;
    }
    Ok(())
}

/// The whole bar or one segment of `s`.
fn module(s: &Snapshot, segment: Option<SegmentName>) -> Module {
    match segment {
        Some(name) => Module::segment(&s.description, &s.header, &s.model, name, now_unix_ms()),
        None => Module::bar(&s.description, &s.header, &s.model, now_unix_ms()),
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

/// The control socket of the session the shell shows: `dir`'s current one,
/// else the newest one a daemon serves (the bar runs from home, not a
/// project); `None` when there is neither (the reason goes to stderr).
fn locate(dir: &Path) -> ward_daemon::Result<Option<PathBuf>> {
    match client::desktop_socket(dir, &state_root(), None) {
        Ok(socket) => Ok(Some(socket)),
        Err(ward_daemon::Error::Project(reason)) => {
            eprintln!("ward-shell: {reason}");
            Ok(None)
        }
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
/// `None` when nothing serves it.
fn load_from(socket: &Path, settle: Duration) -> ward_daemon::Result<Option<Snapshot>> {
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
    if !matches!(end, WatchEnd::Quiet { .. }) {
        model.seal();
    }
    Ok(Some(Snapshot {
        header: Header::from_description(&description),
        description,
        model,
    }))
}

/// The text of one surface.
fn render(s: &Snapshot, surface: Surface) -> String {
    let bar = TrustBar::new(&s.header, &s.model).text();
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
    }
}

fn now_unix_ms() -> u64 {
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
                tick_ms: TICK_MS,
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
            Some(Surface::Bar { tick_ms: 500, .. })
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
                tick_ms: TICK_MS,
            },
            Surface::Session,
            Surface::VerifyPanel,
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
        let bar = TrustBar::new(&s.header, &s.model);
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
        let bar = TrustBar::new(&s.header, &s.model);
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
            TrustBar::new(&s.header, &s.model)
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
