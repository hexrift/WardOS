//! Custody of a launch's provider leases (#267): the one place that renews a
//! lease and pushes its revocation to the provider.
//!
//! A [`HeldLease`] is a lease together with the provider that issued it and
//! the [`LeaseDeadline`] its proxy route is bound to. A [`LeaseKeeper`] holds
//! every lease of one launch and acts on them:
//!
//! * **renewal** — a lease configured to renew is renewed once a third of its
//!   current period is left, through [`renew_within_bounds`]: never past the
//!   original maximum, never with a wider scope; the route's deadline moves
//!   only on a renewal the rules accepted, so a failed or refused renewal
//!   leaves the lease to run out on time (fail closed);
//! * **expiry** — at the deadline the route already refuses; the keeper then
//!   revokes the lease at the provider too;
//! * **withdrawal** — when the grant is revoked (the egress withdrew its route
//!   on `ward session revoke`), when the session pauses (the route is
//!   withdrawn on the spot: a provider lease does not survive a pause), and
//!   when the launch ends (which a `ward stop` causes), the lease is revoked at
//!   the provider.
//!
//! Every outcome — renewed, renewal refused, revoked at the provider, revoke
//! unconfirmed with the degraded state's name, not revocable at the source —
//! is reported through the keeper's notifier as a [`LeaseNote`] keyed by the
//! grant id, which the session daemon keeps in the grant's history. Provider
//! calls never run on an egress thread or under the keeper's lock: the egress
//! only marks what must happen, and the keeper's own worker (or
//! [`LeaseKeeper::finish`], on the launch's thread) makes the calls, each
//! bounded by the provider's timeout.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ward_proxy::LeaseDeadline;

use super::{
    BindingViolation, CredentialProvider, Lease, ProviderError, Revocation, renew_within_bounds,
};
use crate::control::{LeaseNote, LeaseRetire};
use crate::egress::CredentialWatch;

/// The longest the worker sleeps between looks, whatever is due.
const IDLE: Duration = Duration::from_secs(60);

/// The shortest wait before retrying a renewal that failed.
const RETRY: Duration = Duration::from_secs(1);

/// A lease in custody: its provider, the deadline its route is bound to, and
/// whether it is still live (`None` once withdrawn).
pub struct HeldLease {
    provider: Arc<dyn CredentialProvider>,
    renew: bool,
    deadline: LeaseDeadline,
    lease: Mutex<Option<Lease>>,
    /// Cleared the moment the lease is withdrawn; read without the lease's
    /// lock so an egress thread never waits on it.
    live: AtomicBool,
}

impl fmt::Debug for HeldLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeldLease")
            .field("provider", &self.provider.name())
            .field("renew", &self.renew)
            .field("deadline", &self.deadline)
            .field("lease", &*lock(&self.lease))
            .field("live", &self.is_live())
            .finish()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl HeldLease {
    /// Take `lease` from `provider` into custody; `renew` renews it while the
    /// launch runs.
    #[must_use]
    pub fn new(provider: Arc<dyn CredentialProvider>, lease: Lease, renew: bool) -> Arc<Self> {
        Arc::new(Self {
            provider,
            renew,
            deadline: LeaseDeadline::at(lease.expires_at),
            lease: Mutex::new(Some(lease)),
            live: AtomicBool::new(true),
        })
    }

    /// The deadline the proxy route is bound to.
    #[must_use]
    pub fn deadline(&self) -> LeaseDeadline {
        self.deadline.clone()
    }

    /// The provider's name.
    #[must_use]
    pub fn provider_name(&self) -> &str {
        self.provider.name()
    }

    /// A copy of the live lease, `None` once withdrawn.
    #[must_use]
    pub fn lease(&self) -> Option<Lease> {
        lock(&self.lease).clone()
    }

    /// How long the lease has left now (zero once withdrawn or run out).
    #[must_use]
    pub fn remaining(&self) -> Duration {
        lock(&self.lease)
            .as_ref()
            .map_or(Duration::ZERO, |l| l.remaining(SystemTime::now()))
    }

    /// Withdraw the lease and revoke it at the provider, once: the route's
    /// deadline is moved to the epoch first, so nothing injects it while the
    /// provider is asked. `None` when it was already withdrawn.
    pub(crate) fn withdraw(&self) -> Option<Result<Revocation, ProviderError>> {
        self.live.store(false, Ordering::SeqCst);
        self.deadline.set(UNIX_EPOCH);
        let lease = lock(&self.lease).take()?;
        Some(self.provider.revoke(&lease))
    }

    /// Whether the lease has not been withdrawn.
    fn is_live(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }

    /// Renew at `now` within the rules; the deadline moves only on success,
    /// and never for a lease withdrawn while the provider was asked. The
    /// lease's lock is not held across the provider call.
    fn renew_at(&self, now: SystemTime) -> Option<Result<SystemTime, ProviderError>> {
        let lease = self.lease()?;
        let outcome = renew_within_bounds(&*self.provider, &lease, now);
        let mut guard = lock(&self.lease);
        Some(outcome.and_then(|renewed| {
            if guard.is_none() || !self.is_live() {
                return Err(ProviderError::Binding(BindingViolation::ZeroTtl));
            }
            let until = renewed.expires_at;
            self.deadline.set(until);
            *guard = Some(renewed);
            Ok(until)
        }))
    }
}

impl Drop for HeldLease {
    /// A lease nothing holds any more is not left alive at the provider: one
    /// issued for a launch that never started is revoked here (the keeper
    /// has already withdrawn every lease a launch held, so this is a no-op
    /// for those).
    fn drop(&mut self) {
        let _ = self.withdraw();
    }
}

/// Why a lease is being withdrawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Withdrawal {
    /// `ward session revoke` withdrew the grant's route.
    Revoked,
    /// The session paused: credentials are suspended, and a provider lease is
    /// revoked rather than held across the pause.
    Suspended,
    /// The launch ended (its command finished, failed, or was stopped).
    LaunchEnded,
    /// The lease ran out.
    Expired,
}

impl Withdrawal {
    fn retire(self) -> LeaseRetire {
        match self {
            Self::Expired => LeaseRetire::Expired,
            Self::Revoked | Self::Suspended | Self::LaunchEnded => LeaseRetire::Revoked,
        }
    }

    fn text(self) -> &'static str {
        match self {
            Self::Revoked => "grant revoked",
            Self::Suspended => "session paused",
            Self::LaunchEnded => "launch ended",
            Self::Expired => "lease expired",
        }
    }
}

/// The note text for a withdrawal's provider outcome.
#[must_use]
pub fn withdrawal_text(
    provider: &str,
    why: Withdrawal,
    outcome: &Result<Revocation, ProviderError>,
) -> String {
    let what = match outcome {
        Ok(Revocation::Confirmed) => "revoked at the provider".to_owned(),
        Ok(Revocation::NotRevocable) => {
            "static secret, not revocable at the source; route withdrawn".to_owned()
        }
        Err(e) => format!("revoke unconfirmed ({})", e.state_name()),
    };
    format!("provider {provider}: {what} ({})", why.text())
}

struct Entry {
    held: Arc<HeldLease>,
    grant: Option<u64>,
    pending: Option<Withdrawal>,
    renew_after: Option<SystemTime>,
}

/// Where the keeper reports outcomes: the session daemon, in production.
pub type Notify = Arc<dyn Fn(LeaseNote) + Send + Sync>;

struct Inner {
    entries: Mutex<Vec<Entry>>,
    changed: Condvar,
    stop: AtomicBool,
    notify: Mutex<Option<Notify>>,
}

impl Inner {
    fn note(&self, note: LeaseNote) {
        let notify = lock(&self.notify).clone();
        if let Some(notify) = notify {
            notify(note);
        }
    }

    /// Do whatever is due at `now`; the next instant anything will be.
    fn tick(&self, now: SystemTime) -> SystemTime {
        // Decide under the lock, act outside it.
        let work: Vec<(Arc<HeldLease>, Option<u64>, Option<Withdrawal>)> = {
            let mut entries = lock(&self.entries);
            entries
                .iter_mut()
                .filter_map(|e| {
                    if !e.held.is_live() {
                        e.pending = None;
                        return None;
                    }
                    if let Some(why) = e.pending.take() {
                        return Some((Arc::clone(&e.held), e.grant, Some(why)));
                    }
                    if e.held.deadline.expired_at(now) {
                        return Some((Arc::clone(&e.held), e.grant, Some(Withdrawal::Expired)));
                    }
                    let due = e.held.renew && e.renew_after.is_none_or(|t| now >= t) && {
                        let lease = e.held.lease()?;
                        lease.remaining(now) <= lease.ttl() / 3
                    };
                    due.then(|| (Arc::clone(&e.held), e.grant, None))
                })
                .collect()
        };
        for (held, grant, why) in work {
            match why {
                Some(why) => self.withdraw(&held, grant, why),
                None => self.renew(&held, grant, now),
            }
        }
        self.next_due(now)
    }

    fn withdraw(&self, held: &HeldLease, grant: Option<u64>, why: Withdrawal) {
        if let Some(outcome) = held.withdraw()
            && let Some(id) = grant
        {
            self.note(LeaseNote {
                id,
                text: withdrawal_text(held.provider_name(), why, &outcome),
                retire: Some(why.retire()),
                expires_at_unix_ms: None,
            });
        }
    }

    fn renew(&self, held: &Arc<HeldLease>, grant: Option<u64>, now: SystemTime) {
        let Some(outcome) = held.renew_at(now) else {
            return;
        };
        let (text, expires) = match &outcome {
            Ok(until) => (
                format!("provider {}: renewed", held.provider_name()),
                Some(unix_ms(*until)),
            ),
            Err(ProviderError::Binding(BindingViolation::PastMaxTtl)) => (
                format!(
                    "provider {}: renewal refused (max ttl reached)",
                    held.provider_name()
                ),
                None,
            ),
            Err(e) => (
                format!(
                    "provider {}: renewal failed ({})",
                    held.provider_name(),
                    e.state_name()
                ),
                None,
            ),
        };
        {
            let mut entries = lock(&self.entries);
            if let Some(e) = entries.iter_mut().find(|e| Arc::ptr_eq(&e.held, held)) {
                e.renew_after = match &outcome {
                    Ok(_) => None,
                    // Nothing more to ask for: the lease runs out at its max.
                    Err(ProviderError::Binding(_)) => {
                        Some(held.lease().map_or(now, |l| l.max_expires_at))
                    }
                    Err(_) => Some(now + RETRY.max(held.remaining() / 2)),
                };
            }
        }
        if let Some(id) = grant {
            self.note(LeaseNote {
                id,
                text,
                retire: None,
                expires_at_unix_ms: expires,
            });
        }
    }

    /// The next instant a deadline or a renewal falls due, at most [`IDLE`]
    /// from `now`.
    fn next_due(&self, now: SystemTime) -> SystemTime {
        let entries = lock(&self.entries);
        entries
            .iter()
            .filter_map(|e| {
                let lease = e.held.lease()?;
                let deadline = e.held.deadline.get();
                let renew = e.held.renew.then(|| {
                    let at = lease.expires_at - lease.ttl() / 3;
                    e.renew_after.map_or(at, |t| t.max(at))
                });
                Some(renew.map_or(deadline, |r| r.min(deadline)))
            })
            .chain(std::iter::once(now + IDLE))
            .min()
            .unwrap_or(now + IDLE)
    }
}

impl CredentialWatch for Inner {
    fn withdrawn(&self, grant_id: u64) {
        let mut entries = lock(&self.entries);
        let mut any = false;
        for e in entries.iter_mut().filter(|e| e.grant == Some(grant_id)) {
            // The egress repeats this while the revoke marker stands; a lease
            // already withdrawn has nothing left to do.
            if e.pending.is_none() && e.held.is_live() {
                e.pending = Some(Withdrawal::Revoked);
                any = true;
            }
        }
        drop(entries);
        if any {
            self.changed.notify_all();
        }
    }

    fn paused(&self, withdraw_route: &dyn Fn(u64)) {
        let mut entries = lock(&self.entries);
        for e in entries.iter_mut() {
            if !e.held.is_live() || e.pending.is_some() {
                continue;
            }
            // Nothing injects it from here on, before the provider is asked.
            e.held.deadline.set(UNIX_EPOCH);
            if let Some(id) = e.grant {
                withdraw_route(id);
            }
            e.pending = Some(Withdrawal::Suspended);
        }
        drop(entries);
        self.changed.notify_all();
    }
}

/// Every provider lease of one launch.
pub struct LeaseKeeper {
    inner: Arc<Inner>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl fmt::Debug for LeaseKeeper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaseKeeper")
            .field("leases", &lock(&self.inner.entries).len())
            .finish_non_exhaustive()
    }
}

impl LeaseKeeper {
    /// Custody of `leases`, not yet bound to grants or started.
    #[must_use]
    pub fn new(leases: Vec<Arc<HeldLease>>) -> Self {
        let entries = leases
            .into_iter()
            .map(|held| Entry {
                held,
                grant: None,
                pending: None,
                renew_after: None,
            })
            .collect();
        Self {
            inner: Arc::new(Inner {
                entries: Mutex::new(entries),
                changed: Condvar::new(),
                stop: AtomicBool::new(false),
                notify: Mutex::new(None),
            }),
            worker: Mutex::new(None),
        }
    }

    /// Whether there is nothing in custody.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        lock(&self.inner.entries).is_empty()
    }

    /// Record that `held` was granted under `grant` (the daemon-minted id).
    pub fn bind(&self, held: &Arc<HeldLease>, grant: Option<u64>) {
        let mut entries = lock(&self.inner.entries);
        if let Some(e) = entries.iter_mut().find(|e| Arc::ptr_eq(&e.held, held)) {
            e.grant = grant;
        }
    }

    /// The egress hook: withdrawals and pauses reach the keeper through it.
    #[must_use]
    pub fn watch(&self) -> Arc<dyn CredentialWatch> {
        self.inner.clone()
    }

    /// Report outcomes through `notify` and start the worker that renews,
    /// expires and revokes. Calling it again only replaces the notifier.
    pub fn start(&self, notify: Notify) {
        *lock(&self.inner.notify) = Some(notify);
        let mut worker = lock(&self.worker);
        if worker.is_some() || self.is_empty() {
            return;
        }
        let inner = Arc::clone(&self.inner);
        *worker = Some(std::thread::spawn(move || {
            while !inner.stop.load(Ordering::Acquire) {
                let now = SystemTime::now();
                let next = inner.tick(now);
                let wait = next.duration_since(SystemTime::now()).unwrap_or_default();
                let entries = lock(&inner.entries);
                if inner.stop.load(Ordering::Acquire) {
                    break;
                }
                let pending = entries.iter().any(|e| e.pending.is_some());
                if !pending && !wait.is_zero() {
                    let _ = inner
                        .changed
                        .wait_timeout(entries, wait)
                        .unwrap_or_else(PoisonError::into_inner);
                }
            }
        }));
    }

    /// Do what is due at `now` (the worker's step, for a caller that drives
    /// the clock itself); returns when anything is next due.
    pub fn tick(&self, now: SystemTime) -> SystemTime {
        self.inner.tick(now)
    }

    /// Stop the worker and withdraw every lease still live — a withdrawal
    /// already asked for keeps its own reason, the rest take `why` — revoking
    /// each at the provider. Idempotent.
    pub fn finish(&self, why: Withdrawal) {
        self.inner.stop.store(true, Ordering::Release);
        self.inner.changed.notify_all();
        let worker = lock(&self.worker).take();
        if let Some(worker) = worker {
            let _ = worker.join();
        }
        let work: Vec<(Arc<HeldLease>, Option<u64>, Withdrawal)> = lock(&self.inner.entries)
            .iter_mut()
            .map(|e| {
                (
                    Arc::clone(&e.held),
                    e.grant,
                    e.pending.take().unwrap_or(why),
                )
            })
            .collect();
        for (held, grant, why) in work {
            self.inner.withdraw(&held, grant, why);
        }
    }
}

impl Drop for LeaseKeeper {
    fn drop(&mut self) {
        self.finish(Withdrawal::LaunchEnded);
    }
}

fn unix_ms(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::credentials::{
        DegradedState, Health, LeaseRequest, LeaseScope, LeasedSecret, bind_issued,
    };

    /// A provider that records calls and answers as scripted.
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        revoke_fails: AtomicBool,
        renew_adds: Mutex<Option<Duration>>,
    }

    impl CredentialProvider for Fake {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn issue(&self, _: &LeaseRequest) -> Result<Lease, ProviderError> {
            unreachable!()
        }
        fn renew(&self, lease: &Lease, increment: Duration) -> Result<Lease, ProviderError> {
            lock(&self.calls).push(format!("renew {}", increment.as_secs()));
            match *lock(&self.renew_adds) {
                Some(d) => Ok(lease.clone().renewed_until(lease.expires_at + d)),
                None => Err(ProviderError::degraded(DegradedState::Unreachable, "down")),
            }
        }
        fn revoke(&self, _: &Lease) -> Result<Revocation, ProviderError> {
            lock(&self.calls).push("revoke".into());
            if self.revoke_fails.load(Ordering::SeqCst) {
                Err(ProviderError::degraded(DegradedState::TimedOut, "slow"))
            } else {
                Ok(Revocation::Confirmed)
            }
        }
        fn health(&self) -> Health {
            Health::Healthy
        }
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn held(fake: &Arc<Fake>, issued: u64, ttl: u64, max: u64, renew: bool) -> Arc<HeldLease> {
        held_at(fake, at(issued), ttl, max, renew)
    }

    fn held_at(
        fake: &Arc<Fake>,
        issued: SystemTime,
        ttl: u64,
        max: u64,
        renew: bool,
    ) -> Arc<HeldLease> {
        let request = LeaseRequest {
            session: "sess".into(),
            service: "svc".into(),
            scope: LeaseScope::default(),
            ttl: Duration::from_secs(ttl),
            max_ttl: Duration::from_secs(max),
            audience: "up.example".into(),
        };
        let lease = Lease::new(
            "fake",
            &request,
            LeasedSecret::new("value"),
            Some(LeasedSecret::new("handle")),
            issued,
            Duration::from_secs(ttl),
        );
        let provider: Arc<dyn CredentialProvider> = fake.clone();
        HeldLease::new(provider, bind_issued(&request, lease).unwrap(), renew)
    }

    fn recorder() -> (Notify, Arc<Mutex<Vec<LeaseNote>>>) {
        let notes = Arc::new(Mutex::new(Vec::new()));
        let sink = notes.clone();
        (Arc::new(move |n| lock(&sink).push(n)), notes)
    }

    #[test]
    fn renewal_moves_the_route_deadline_until_the_max_then_stops() {
        let fake = Arc::new(Fake::default());
        *lock(&fake.renew_adds) = Some(Duration::from_secs(600));
        let lease = held(&fake, 1000, 60, 100, true);
        let keeper = LeaseKeeper::new(vec![lease.clone()]);
        keeper.bind(&lease, Some(7));
        let (notify, notes) = recorder();
        *lock(&keeper.inner.notify) = Some(notify);

        // Not yet due: two thirds of the period are left.
        assert_eq!(keeper.tick(at(1010)), at(1040));
        assert!(lock(&fake.calls).is_empty());
        // Due: renewed to the max (1100), never the 600 s the provider offered.
        keeper.tick(at(1045));
        assert_eq!(lease.deadline().get(), at(1100));
        assert_eq!(lock(&fake.calls).as_slice(), ["renew 55"]);
        assert_eq!(lock(&notes)[0].text, "provider fake: renewed");
        assert_eq!(lock(&notes)[0].expires_at_unix_ms, Some(1_100_000));
        // At the max: refused without asking the provider, noted once.
        keeper.tick(at(1090));
        assert_eq!(lock(&fake.calls).len(), 1);
        assert!(
            lock(&notes)[1]
                .text
                .contains("renewal refused (max ttl reached)")
        );
        keeper.tick(at(1095));
        assert_eq!(lock(&notes).len(), 2);
        // At the deadline: withdrawn and revoked at the provider as expired.
        keeper.tick(at(1100));
        assert_eq!(lock(&fake.calls).last().unwrap(), "revoke");
        let last = lock(&notes).last().cloned().unwrap();
        assert_eq!(last.retire, Some(LeaseRetire::Expired));
        assert_eq!(
            last.text,
            "provider fake: revoked at the provider (lease expired)"
        );
        assert!(lease.lease().is_none());
        keeper.finish(Withdrawal::LaunchEnded);
        assert_eq!(
            lock(&fake.calls).iter().filter(|c| *c == "revoke").count(),
            1
        );
    }

    #[test]
    fn a_failed_renewal_never_extends_and_is_retried_later() {
        let fake = Arc::new(Fake::default());
        let lease = held(&fake, 1000, 90, 900, true);
        let keeper = LeaseKeeper::new(vec![lease.clone()]);
        keeper.bind(&lease, Some(3));
        let (notify, notes) = recorder();
        *lock(&keeper.inner.notify) = Some(notify);
        let next = keeper.tick(at(1060));
        assert_eq!(lease.deadline().get(), at(1090), "unchanged");
        assert_eq!(
            lock(&notes)[0].text,
            "provider fake: renewal failed (unreachable)"
        );
        assert!(next > at(1060) && next <= at(1090), "{next:?}");
        // Retried no sooner than the backoff.
        keeper.tick(at(1060));
        assert_eq!(lock(&fake.calls).len(), 1);
    }

    #[test]
    fn a_revoked_grant_or_a_pause_is_pushed_to_the_provider_and_noted() {
        let fake = Arc::new(Fake::default());
        let now = SystemTime::now();
        let a = held_at(&fake, now, 3600, 3600, false);
        let b = held_at(&fake, now, 3600, 3600, false);
        let unbound = held_at(&fake, now, 3600, 3600, false);
        let keeper = LeaseKeeper::new(vec![a.clone(), b.clone(), unbound.clone()]);
        keeper.bind(&a, Some(1));
        keeper.bind(&b, Some(2));
        let (notify, notes) = recorder();
        *lock(&keeper.inner.notify) = Some(notify);
        let watch = keeper.watch();

        // The egress withdrew route 1: only marked, revoked on the next step.
        watch.withdrawn(1);
        watch.withdrawn(1);
        watch.withdrawn(99);
        assert!(lock(&fake.calls).is_empty());
        keeper.tick(SystemTime::now());
        assert_eq!(lock(&fake.calls).as_slice(), ["revoke"]);
        assert!(a.lease().is_none());
        assert_eq!(lock(&notes)[0].id, 1);
        assert_eq!(lock(&notes)[0].retire, Some(LeaseRetire::Revoked));
        assert!(lock(&notes)[0].text.ends_with("(grant revoked)"));
        // The egress keeps repeating it while the marker stands: nothing more
        // to do, and nothing left pending for the worker to spin on.
        watch.withdrawn(1);
        assert!(
            lock(&keeper.inner.entries)
                .iter()
                .all(|e| e.pending.is_none())
        );

        // A pause withdraws every remaining route at once, then revokes.
        fake.revoke_fails.store(true, Ordering::SeqCst);
        let withdrawn = Mutex::new(Vec::new());
        watch.paused(&|id| lock(&withdrawn).push(id));
        assert_eq!(lock(&withdrawn).as_slice(), [2]);
        assert!(b.deadline().expired_at(SystemTime::now()));
        assert!(unbound.deadline().expired_at(SystemTime::now()));
        keeper.finish(Withdrawal::LaunchEnded);
        assert_eq!(lock(&fake.calls).len(), 3, "b and the unbound lease");
        let b_note = lock(&notes).iter().find(|n| n.id == 2).cloned().unwrap();
        assert_eq!(
            b_note.text,
            "provider fake: revoke unconfirmed (timed-out) (session paused)"
        );
        assert_eq!(
            lock(&notes).len(),
            2,
            "an unbound lease has no grant to note"
        );
    }

    #[test]
    fn the_worker_acts_on_a_withdrawal_and_finish_revokes_the_rest_once() {
        let fake = Arc::new(Fake::default());
        let now = SystemTime::now();
        let a = held_at(&fake, now, 3600, 3600, false);
        let b = held_at(&fake, now, 3600, 3600, false);
        let keeper = LeaseKeeper::new(vec![a.clone(), b.clone()]);
        keeper.bind(&a, Some(1));
        keeper.bind(&b, Some(2));
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = Mutex::new(tx);
        keeper.start(Arc::new(move |n| {
            let _ = lock(&tx).send(n);
        }));
        keeper.watch().withdrawn(1);
        let note = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!((note.id, note.retire), (1, Some(LeaseRetire::Revoked)));
        keeper.finish(Withdrawal::LaunchEnded);
        let note = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(note.id, 2);
        assert!(note.text.ends_with("(launch ended)"));
        drop(keeper);
        assert_eq!(lock(&fake.calls).len(), 2, "each revoked exactly once");
        assert!(format!("{a:?}").contains("HeldLease"));
        assert!(!format!("{a:?}").contains("value"));
    }

    #[test]
    fn outcome_texts_name_the_provider_the_result_and_the_reason() {
        assert_eq!(
            withdrawal_text(
                "bao",
                Withdrawal::LaunchEnded,
                &Ok(Revocation::NotRevocable)
            ),
            "provider bao: static secret, not revocable at the source; route withdrawn \
             (launch ended)"
        );
        let empty = LeaseKeeper::new(Vec::new());
        assert!(empty.is_empty());
        empty.start(Arc::new(|_| {}));
        assert!(lock(&empty.worker).is_none(), "nothing to keep, no thread");
    }
}
