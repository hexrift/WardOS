//! Per-component acknowledgement for pause, resume and stop (#145 item 3).
//!
//! A pause holds four things: the sandbox processes, the egress proxy, the
//! approvals and credential mediation. The freeze is confirmed by reading
//! `/proc` back ([`crate::pause::settle_outcome`]); the other three were
//! assumed. Now each is confirmed in turn, with a bounded wait and a result —
//! acknowledged, timed out or an error with its reason — and the daemon records
//! `SessionPaused` only when the freeze *and* every component confirmed. When
//! one did not, the terminal record is `SessionPauseUnsettled` and its `reason`
//! names the component ([`unconfirmed_reason`]), so every reader of the log —
//! the CLI, the trust bar, a restarted daemon — can say what is uncertain.
//!
//! * **The egress proxy** lives in the `ward` process that launched the sandbox
//!   (ADR-0013), so it is reached through files, like the pause marker itself
//!   and the revoke protocol ([`crate::revoke`]). Each egress registers itself
//!   under `sessions/<id>/proxies/` ([`Registration`]) with its current state
//!   and rewrites it every time the marker flips its paused flag. The daemon
//!   confirms the proxy component by waiting, up to [`ACK_TIMEOUT`], until every
//!   registration whose process is still alive reads the wanted state. A
//!   registration whose process is gone is stale and not required.
//! * **Approvals** and **credentials** are the daemon's own
//!   ([`crate::approvals::Approvals`]), so their confirmation is an immediate
//!   read-back: the hold is applied and every open question's decision clock
//!   stands still; no grant is still exercisable (`Active`) while held, and none
//!   is still `Suspended` once released.
//!
//! The components are confirmed in [`Component::HOLD_ORDER`] on a pause and in
//! the reverse order on a resume. The daemon acts (writes the marker, holds the
//! approvals) and then asks; the [`Acknowledger`] only confirms, so a test can
//! stand in a deterministic one ([`Acknowledger`] is a trait) for the components
//! no real process can be made to fail on demand.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use ward_events::{LogReader, WardEvent};

use crate::approvals::{Approvals, RevokeState};
use crate::error::{Error, Result};
use crate::session::session_dir;

/// Directory holding one registration per running egress, under `sessions/<id>/`.
pub const PROXIES_DIR: &str = "proxies";

/// How long the daemon waits for a component's acknowledgement before it
/// records the hold as unconfirmed: the same bound a revoke waits on the same
/// egress for ([`crate::revoke::ACK_TIMEOUT`]), well under the control socket's
/// read timeout.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(2);

/// How often the daemon re-reads the registrations while waiting: the cadence
/// the egress polls the marker at.
pub const POLL: Duration = Duration::from_millis(50);

/// The state an egress registration reads while its proxy forwards.
pub const RUNNING: &str = "running";
/// The state an egress registration reads while its proxy refuses as paused.
pub const PAUSED: &str = "paused";

/// A component that must hold for a pause to be confirmed, besides the freeze.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    /// Every egress proxy of the session: refuses new traffic and injects no credential.
    Proxy,
    /// The daemon's approvals: no answer taken, no clock running, no new prompt.
    Approvals,
    /// Credential mediation: no grant exercisable, none newly granted.
    Credentials,
}

impl Component {
    /// The order a pause confirms the components in: the proxy first, since the
    /// marker that pauses it is what closes the network, then the approvals,
    /// then the grants they carry. A resume releases in the reverse order.
    pub const HOLD_ORDER: [Self; 3] = [Self::Proxy, Self::Approvals, Self::Credentials];

    /// The components in the order a resume releases them.
    pub fn release_order() -> impl Iterator<Item = Self> {
        Self::HOLD_ORDER.into_iter().rev()
    }

    /// The component's name in records and messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proxy => "egress proxy",
            Self::Approvals => "approvals",
            Self::Credentials => "credentials",
        }
    }

    /// The component [`as_str`](Self::as_str) names, if any.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::HOLD_ORDER
            .into_iter()
            .find(|c| c.as_str() == name.trim())
    }
}

/// Which transition a component is asked to confirm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The component holds (a pause, a hold for a stop, a stop).
    Held,
    /// The component is released (a resume).
    Released,
}

/// What a component answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The component confirmed the transition.
    Acknowledged,
    /// Nothing confirmed within the bound.
    TimedOut {
        /// The bound that expired.
        after: Duration,
    },
    /// The component is in the wrong state, or could not be asked.
    Error(String),
}

/// One component's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Acknowledgement {
    /// Which component.
    pub component: Component,
    /// What it answered.
    pub outcome: Outcome,
}

impl Acknowledgement {
    /// Whether the component confirmed.
    #[must_use]
    pub fn confirmed(&self) -> bool {
        self.outcome == Outcome::Acknowledged
    }

    /// `egress proxy (no acknowledgement within 2s)`: the component and why it
    /// is unconfirmed; the bare name when it confirmed.
    #[must_use]
    pub fn text(&self) -> String {
        match &self.outcome {
            Outcome::Acknowledged => self.component.as_str().to_owned(),
            Outcome::TimedOut { after } => format!(
                "{} (no acknowledgement within {}s)",
                self.component.as_str(),
                after.as_secs()
            ),
            Outcome::Error(reason) => format!("{} ({reason})", self.component.as_str()),
        }
    }
}

/// What a component's confirmation reads from.
pub struct Site<'a> {
    /// The state root.
    pub state: &'a Path,
    /// The session.
    pub session: &'a str,
    /// The daemon's approvals, which carry the grants too.
    pub approvals: &'a Approvals,
}

/// Confirms one component's transition. The daemon has already acted when it
/// asks; the answer is a read-back, bounded in time.
pub trait Acknowledger: Send {
    /// Confirm `component` has reached `phase` at `site`.
    fn confirm(&mut self, component: Component, phase: Phase, site: &Site<'_>) -> Outcome;
}

/// Confirm every component for `phase`, in hold order for [`Phase::Held`] and
/// release order for [`Phase::Released`]; every component is asked, so the
/// result names each one.
pub fn collect(
    acknowledger: &mut dyn Acknowledger,
    phase: Phase,
    site: &Site<'_>,
) -> Vec<Acknowledgement> {
    let order: Vec<Component> = match phase {
        Phase::Held => Component::HOLD_ORDER.to_vec(),
        Phase::Released => Component::release_order().collect(),
    };
    order
        .into_iter()
        .map(|component| Acknowledgement {
            component,
            outcome: acknowledger.confirm(component, phase, site),
        })
        .collect()
}

/// The first component that did not confirm, if any.
#[must_use]
pub fn first_unconfirmed(acks: &[Acknowledgement]) -> Option<&Acknowledgement> {
    acks.iter().find(|a| !a.confirmed())
}

/// The separator between a hold record's reason and the component it names.
pub const UNCONFIRMED_MARK: &str = " - unconfirmed: ";

/// The `reason` a `SessionPauseUnsettled` record carries when `ack` did not
/// confirm: the caller's reason, then [`UNCONFIRMED_MARK`] and
/// [`Acknowledgement::text`]. The reason is shortened first so the component
/// always fits within the record's bound.
#[must_use]
pub fn unconfirmed_reason(reason: &str, ack: &Acknowledgement) -> String {
    let suffix = format!("{UNCONFIRMED_MARK}{}", ack.text());
    let room = ward_events::ShortText::MAX_BYTES.saturating_sub(suffix.len());
    let mut head = reason.to_owned();
    while head.len() > room {
        head.pop();
    }
    format!("{head}{suffix}")
}

/// The component an [`unconfirmed_reason`] names, and the text after it. A
/// reason the log sanitised into a directional isolate (`ward_events::text`,
/// for non-ASCII input) is read through the isolate.
#[must_use]
pub fn unconfirmed_in(reason: &str) -> Option<(Component, &str)> {
    let (_, tail) = reason.rsplit_once(UNCONFIRMED_MARK)?;
    let tail = tail.trim_matches(|c| c == ward_events::text::FSI || c == ward_events::text::PDI);
    let name = tail.split(" (").next().unwrap_or(tail);
    Component::parse(name).map(|c| (c, tail))
}

/// `sessions/<id>/proxies/`.
#[must_use]
pub fn proxies_dir(state: &Path, session: &str) -> PathBuf {
    session_dir(state, session).join(PROXIES_DIR)
}

static SERIAL: AtomicU64 = AtomicU64::new(0);

/// One running egress's entry under [`PROXIES_DIR`]: `<pid>.<n>`, holding the
/// proxy's state ([`RUNNING`] or [`PAUSED`]) and the owning process's start
/// time, so a registration a killed process left behind is told from a live
/// one whose pid was reused.
#[derive(Debug)]
pub struct Registration {
    path: PathBuf,
    started: String,
}

impl Registration {
    /// Register the calling process's egress in `dir` with its initial state.
    pub fn register(dir: &Path, paused: bool) -> Result<Self> {
        fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
        let pid = std::process::id();
        let started = start_time(Path::new("/proc"), pid).unwrap_or_default();
        let registration = Self {
            path: dir.join(format!("{pid}.{}", SERIAL.fetch_add(1, Ordering::Relaxed))),
            started,
        };
        registration.set(paused)?;
        Ok(registration)
    }

    /// Record the proxy's current state.
    pub fn set(&self, paused: bool) -> Result<()> {
        let state = if paused { PAUSED } else { RUNNING };
        fs::write(&self.path, format!("{state}\n{}\n", self.started))
            .map_err(|e| Error::io(&self.path, e))
    }

    /// Remove the registration: the egress has stopped.
    pub fn remove(&self) {
        let _ = fs::remove_file(&self.path);
    }

    /// Where the registration is written.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// The `starttime` field of `/proc/<pid>/stat`, as written.
pub(crate) fn start_time(proc: &Path, pid: u32) -> Option<String> {
    let stat = fs::read_to_string(proc.join(pid.to_string()).join("stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19).map(str::to_owned)
}

/// The state of every live registration in `dir`: a registration whose
/// process is gone, or whose pid now belongs to a process started at another
/// time, is stale and removed. A registration with no state yet (mid-write)
/// reads as an empty state, which matches nothing.
fn live_states(dir: &Path, proc: &Path) -> Result<Vec<String>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(dir, e)),
    };
    let mut states = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(dir, e))?;
        let path = entry.path();
        let text = fs::read_to_string(&path).unwrap_or_default();
        let mut lines = text.lines();
        let state = lines.next().unwrap_or_default().to_owned();
        let started = lines.next().unwrap_or_default();
        let pid = entry
            .file_name()
            .to_str()
            .and_then(|n| n.split('.').next())
            .and_then(|p| p.parse::<u32>().ok());
        let alive = pid.is_some_and(|pid| start_time(proc, pid).as_deref() == Some(started));
        if alive {
            states.push(state);
        } else {
            let _ = fs::remove_file(&path);
        }
    }
    Ok(states)
}

/// Wait up to `bound` until every live egress of `session` reads the state
/// `phase` asks for.
fn confirm_proxies(state: &Path, session: &str, phase: Phase, bound: Duration) -> Outcome {
    let dir = proxies_dir(state, session);
    let wanted = match phase {
        Phase::Held => PAUSED,
        Phase::Released => RUNNING,
    };
    let deadline = Instant::now() + bound;
    loop {
        match live_states(&dir, Path::new("/proc")) {
            Err(e) => return Outcome::Error(e.to_string()),
            Ok(states) if states.iter().all(|s| s == wanted) => return Outcome::Acknowledged,
            Ok(_) => {}
        }
        if Instant::now() >= deadline {
            return Outcome::TimedOut { after: bound };
        }
        std::thread::sleep(POLL);
    }
}

/// Read back whether the approvals hold (or run) as `phase` asks: the hold flag
/// itself, and every open question's decision clock with it.
fn confirm_approvals(approvals: &Approvals, phase: Phase) -> Outcome {
    let held = phase == Phase::Held;
    if approvals.paused() != held {
        return Outcome::Error(if held {
            "hold not applied".to_owned()
        } else {
            "hold not released".to_owned()
        });
    }
    let lagging = approvals
        .pending()
        .iter()
        .filter(|a| a.countdown.is_some_and(|c| c.held != held))
        .count();
    if lagging == 0 {
        Outcome::Acknowledged
    } else {
        Outcome::Error(format!(
            "{lagging} decision clock(s) still {}",
            if held { "running" } else { "held" }
        ))
    }
}

/// Read back that no grant is exercisable while held, and none is still
/// suspended once released.
fn confirm_credentials(approvals: &Approvals, phase: Phase) -> Outcome {
    let (wrong, word) = match phase {
        Phase::Held => (RevokeState::Active, "active"),
        Phase::Released => (RevokeState::Suspended, "suspended"),
    };
    let lagging = approvals
        .grants()
        .iter()
        .filter(|g| g.revoke_state == wrong)
        .count();
    if lagging == 0 {
        Outcome::Acknowledged
    } else {
        Outcome::Error(format!("{lagging} grant(s) still {word}"))
    }
}

/// The real components: the registrations on disk, bounded by [`ACK_TIMEOUT`],
/// and the daemon's own approvals.
#[derive(Debug)]
pub struct Live {
    bound: Duration,
}

impl Live {
    /// Bounded by [`ACK_TIMEOUT`].
    #[must_use]
    pub const fn new() -> Self {
        Self { bound: ACK_TIMEOUT }
    }

    /// Bounded by `bound` instead.
    #[must_use]
    pub const fn bounded(bound: Duration) -> Self {
        Self { bound }
    }
}

impl Default for Live {
    fn default() -> Self {
        Self::new()
    }
}

impl Acknowledger for Live {
    fn confirm(&mut self, component: Component, phase: Phase, site: &Site<'_>) -> Outcome {
        match component {
            Component::Proxy => confirm_proxies(site.state, site.session, phase, self.bound),
            Component::Approvals => confirm_approvals(site.approvals, phase),
            Component::Credentials => confirm_credentials(site.approvals, phase),
        }
    }
}

/// What the log at `log_path` says is unconfirmed about the session's current
/// hold, if anything: the component an unsettled pause names, the processes it
/// could not confirm stopped, or what a refused stop could not confirm ended.
/// `None` when the last hold record is confirmed, released, or there is none.
pub fn unconfirmed_detail(log_path: &Path) -> Result<Option<String>> {
    let mut detail = None;
    for record in LogReader::open(log_path)
        .map_err(|e| Error::Events(e.to_string()))?
        .map_while(std::result::Result::ok)
    {
        detail = match &record.event {
            WardEvent::SessionPauseUnsettled {
                reason, pending, ..
            } => Some(unsettled_detail(reason.as_str(), *pending)),
            WardEvent::WorkloadsTerminated {
                pending,
                barrier_confirmed,
                ..
            } if *pending > 0 || !*barrier_confirmed => Some(if *pending > 0 {
                format!("{pending} process(es) not confirmed ended")
            } else {
                "membership barrier unconfirmed".to_owned()
            }),
            WardEvent::SessionPaused { .. }
            | WardEvent::SessionResumed { .. }
            | WardEvent::WorkloadsTerminated { .. }
            | WardEvent::SessionEnded { .. } => None,
            _ => detail,
        };
    }
    Ok(detail)
}

/// What a `SessionPauseUnsettled { reason, pending }` leaves unconfirmed, in
/// words: the component its reason names, else its pending processes.
#[must_use]
pub fn unsettled_detail(reason: &str, pending: u32) -> String {
    match unconfirmed_in(reason) {
        Some((_, text)) => text.to_owned(),
        None => format!("{pending} process(es) not confirmed stopped"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn timed_out(component: Component) -> Acknowledgement {
        Acknowledgement {
            component,
            outcome: Outcome::TimedOut { after: ACK_TIMEOUT },
        }
    }

    #[test]
    fn the_components_hold_in_order_and_release_in_reverse() {
        assert_eq!(
            Component::HOLD_ORDER,
            [
                Component::Proxy,
                Component::Approvals,
                Component::Credentials
            ]
        );
        assert_eq!(
            Component::release_order().collect::<Vec<_>>(),
            [
                Component::Credentials,
                Component::Approvals,
                Component::Proxy
            ]
        );
        for c in Component::HOLD_ORDER {
            assert_eq!(Component::parse(c.as_str()), Some(c));
        }
        assert_eq!(Component::parse("freezer"), None);
    }

    #[test]
    fn an_unconfirmed_reason_names_the_component_and_parses_back() {
        let ack = timed_out(Component::Proxy);
        let reason = unconfirmed_reason("looks wrong", &ack);
        assert_eq!(
            reason,
            "looks wrong - unconfirmed: egress proxy (no acknowledgement within 2s)"
        );
        assert_eq!(
            unconfirmed_in(&reason),
            Some((
                Component::Proxy,
                "egress proxy (no acknowledgement within 2s)"
            ))
        );
        let errored = Acknowledgement {
            component: Component::Approvals,
            outcome: Outcome::Error("hold not applied".into()),
        };
        assert_eq!(
            unconfirmed_in(&unconfirmed_reason("", &errored)),
            Some((Component::Approvals, "approvals (hold not applied)"))
        );
        assert_eq!(unconfirmed_in("looks wrong"), None);
        assert_eq!(unconfirmed_in("x - unconfirmed: freezer (nope)"), None);
        let isolated = ward_events::ShortText::new(&unconfirmed_reason("größer", &ack));
        assert_eq!(
            unconfirmed_in(isolated.as_str()),
            Some((
                Component::Proxy,
                "egress proxy (no acknowledgement within 2s)"
            )),
            "{isolated:?}"
        );
        assert_eq!(
            unsettled_detail("looks wrong", 2),
            "2 process(es) not confirmed stopped"
        );
        assert_eq!(
            unsettled_detail(&reason, 0),
            "egress proxy (no acknowledgement within 2s)"
        );
    }

    #[test]
    fn a_long_reason_is_shortened_so_the_component_still_fits_the_record() {
        let long = "x".repeat(400);
        let reason = unconfirmed_reason(&long, &timed_out(Component::Credentials));
        assert!(reason.len() <= ward_events::ShortText::MAX_BYTES);
        let text = ward_events::ShortText::new(&reason);
        assert_eq!(
            unconfirmed_in(text.as_str()).map(|(c, _)| c),
            Some(Component::Credentials)
        );
    }

    #[test]
    fn collect_asks_every_component_in_phase_order_and_finds_the_first_unconfirmed() {
        struct Script(Vec<(Component, Phase)>);
        impl Acknowledger for Script {
            fn confirm(&mut self, component: Component, phase: Phase, _: &Site<'_>) -> Outcome {
                self.0.push((component, phase));
                if component == Component::Approvals {
                    Outcome::Error("hold not applied".into())
                } else {
                    Outcome::Acknowledged
                }
            }
        }
        let approvals = Approvals::new();
        let dir = tempfile::tempdir().unwrap();
        let site = Site {
            state: dir.path(),
            session: "sess_acks",
            approvals: &approvals,
        };
        let mut script = Script(Vec::new());
        let held = collect(&mut script, Phase::Held, &site);
        assert_eq!(
            first_unconfirmed(&held).map(|a| a.component),
            Some(Component::Approvals)
        );
        let released = collect(&mut script, Phase::Released, &site);
        assert_eq!(released.len(), 3);
        assert_eq!(
            script.0,
            [
                (Component::Proxy, Phase::Held),
                (Component::Approvals, Phase::Held),
                (Component::Credentials, Phase::Held),
                (Component::Credentials, Phase::Released),
                (Component::Approvals, Phase::Released),
                (Component::Proxy, Phase::Released),
            ]
        );
        assert_eq!(first_unconfirmed(&[]), None);
    }

    #[test]
    fn a_registration_is_live_while_its_process_runs_and_stale_once_it_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let proxies = dir.path().join(PROXIES_DIR);
        let registration = Registration::register(&proxies, false).unwrap();
        assert!(registration.path().exists());
        let proc = Path::new("/proc");
        assert_eq!(live_states(&proxies, proc).unwrap(), [RUNNING]);
        registration.set(true).unwrap();
        assert_eq!(live_states(&proxies, proc).unwrap(), [PAUSED]);

        let stale = proxies.join("4000000.0");
        fs::write(&stale, format!("{RUNNING}\n1\n")).unwrap();
        assert_eq!(
            live_states(&proxies, proc).unwrap(),
            [PAUSED],
            "a registration of a pid that does not run is not required"
        );
        assert!(!stale.exists(), "and is pruned");

        let reused = proxies.join(format!("{}.99", std::process::id()));
        fs::write(&reused, format!("{RUNNING}\n1\n")).unwrap();
        assert_eq!(
            live_states(&proxies, proc).unwrap(),
            [PAUSED],
            "a live pid started at another time is a reused pid, not this egress"
        );
        assert!(!reused.exists());

        registration.remove();
        assert!(live_states(&proxies, proc).unwrap().is_empty());
        assert!(
            live_states(&dir.path().join("absent"), proc)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_proxy_component_confirms_when_every_live_egress_reads_the_wanted_state() {
        let dir = tempfile::tempdir().unwrap();
        let session = "sess_proxy_ack";
        let proxies = proxies_dir(dir.path(), session);
        let bound = Duration::from_millis(150);
        assert_eq!(
            confirm_proxies(dir.path(), session, Phase::Held, bound),
            Outcome::Acknowledged,
            "no egress registered: nothing to wait for"
        );
        let registration = Registration::register(&proxies, false).unwrap();
        let started = Instant::now();
        assert_eq!(
            confirm_proxies(dir.path(), session, Phase::Held, bound),
            Outcome::TimedOut { after: bound }
        );
        assert!(started.elapsed() >= bound);
        assert_eq!(
            confirm_proxies(dir.path(), session, Phase::Released, bound),
            Outcome::Acknowledged
        );
        let late = Registration::register(&proxies, false).unwrap();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            late.set(true).unwrap();
        });
        registration.set(true).unwrap();
        assert_eq!(
            confirm_proxies(dir.path(), session, Phase::Held, Duration::from_secs(2)),
            Outcome::Acknowledged,
            "a late egress is waited for"
        );
    }

    #[test]
    fn the_approvals_and_credentials_components_read_the_hold_back() {
        let approvals = Approvals::new();
        assert_eq!(
            confirm_approvals(&approvals, Phase::Held),
            Outcome::Error("hold not applied".into())
        );
        assert_eq!(
            confirm_approvals(&approvals, Phase::Released),
            Outcome::Acknowledged
        );
        approvals.set_paused(true);
        assert_eq!(
            confirm_approvals(&approvals, Phase::Held),
            Outcome::Acknowledged
        );
        assert_eq!(
            confirm_approvals(&approvals, Phase::Released),
            Outcome::Error("hold not released".into())
        );
        assert_eq!(
            confirm_credentials(&approvals, Phase::Held),
            Outcome::Acknowledged,
            "no grant at all is nothing exercisable"
        );
        assert_eq!(
            confirm_credentials(&approvals, Phase::Released),
            Outcome::Acknowledged
        );
    }

    #[test]
    fn a_live_acknowledger_asks_the_right_component() {
        let approvals = Approvals::new();
        approvals.set_paused(true);
        let dir = tempfile::tempdir().unwrap();
        let site = Site {
            state: dir.path(),
            session: "sess_live",
            approvals: &approvals,
        };
        let mut live = Live::bounded(Duration::from_millis(50));
        let acks = collect(&mut live, Phase::Held, &site);
        assert!(acks.iter().all(Acknowledgement::confirmed), "{acks:?}");
        assert_eq!(Live::default().bound, ACK_TIMEOUT);
        assert_eq!(
            Acknowledgement {
                component: Component::Proxy,
                outcome: Outcome::Acknowledged
            }
            .text(),
            "egress proxy"
        );
    }

    #[test]
    fn the_logs_unconfirmed_detail_follows_the_last_hold_record() {
        use crate::control::Sink as _;
        use ward_events::{Blake3Hash, PauseMethod, SessionId, ShortText};
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.log");
        let mut log = crate::control::LocalLog::create(
            &log_path,
            SessionId::from_u128(5),
            Blake3Hash::from_bytes([1; 32]),
            std::time::SystemTime::now(),
        )
        .unwrap();
        let mut append = |event: WardEvent| {
            log.append(
                ward_events::Origin::Wardd,
                event,
                std::time::SystemTime::now(),
            )
            .unwrap();
        };
        assert_eq!(unconfirmed_detail(&log_path).unwrap(), None);
        append(WardEvent::SessionPauseUnsettled {
            method: PauseMethod::Sigstop,
            reason: ShortText::new(&unconfirmed_reason("x", &timed_out(Component::Proxy))),
            pending: 0,
        });
        assert_eq!(
            unconfirmed_detail(&log_path).unwrap().as_deref(),
            Some("egress proxy (no acknowledgement within 2s)")
        );
        append(WardEvent::SessionResumed {
            paused_for: Duration::from_secs(1),
        });
        assert_eq!(unconfirmed_detail(&log_path).unwrap(), None);
        append(WardEvent::SessionPauseUnsettled {
            method: PauseMethod::Sigstop,
            reason: ShortText::new("x"),
            pending: 3,
        });
        assert_eq!(
            unconfirmed_detail(&log_path).unwrap().as_deref(),
            Some("3 process(es) not confirmed stopped")
        );
        append(WardEvent::WorkloadsTerminated {
            ended: 1,
            pending: 2,
            barrier_confirmed: true,
        });
        assert_eq!(
            unconfirmed_detail(&log_path).unwrap().as_deref(),
            Some("2 process(es) not confirmed ended")
        );
        append(WardEvent::WorkloadsTerminated {
            ended: 0,
            pending: 0,
            barrier_confirmed: false,
        });
        assert_eq!(
            unconfirmed_detail(&log_path).unwrap().as_deref(),
            Some("membership barrier unconfirmed")
        );
        append(WardEvent::WorkloadsTerminated {
            ended: 0,
            pending: 0,
            barrier_confirmed: true,
        });
        assert_eq!(unconfirmed_detail(&log_path).unwrap(), None);
        assert!(unconfirmed_detail(&dir.path().join("missing.log")).is_err());
    }
}
