//! Approvals held by the daemon (ADR-0016, `docs/design-language.md` §10).
//!
//! When the hook adapter would answer `ask`, the answer is no longer handed
//! straight to the agent's own prompt: the `ward` process asks the session
//! daemon to hold it ([`Request::Hold`](crate::control::Request::Hold)), the
//! daemon registers a pending [`Approval`], the desktop shows it, and only an
//! answer over the control socket
//! ([`Request::Approve`](crate::control::Request::Approve)) or the timeout
//! releases it. Deny is the default on timeout, and when the session ends
//! with the question open.
//!
//! [`Approvals`] is the hold itself: the pending set, the answers, the
//! `allow-session` memory, the credentials the launch granted, and the wait.
//! While the session is paused (ADR-0019 §3, [`Approvals::set_paused`]) the
//! hold is held in turn: no timeout runs, no answer is taken, and a question
//! that arrives waits like the rest. Each question's decision time is one
//! clock (#146 item 4) that the timeout is enforced from and that
//! [`Approvals::pending`] / [`Approvals::approvals`] report as its
//! [`Countdown`], held while paused, so the desktop shows the daemon's own
//! figure rather than guessing one. It knows nothing about sockets or the
//! log; the daemon appends the `CapabilityRequested` / `CapabilityDecided`
//! records around it ([`requested_event`], [`decided_event`]), which is how
//! the log, a subscriber and `ward replay` see the same question and the same
//! answer. An approval's id is the sequence number of its request record, so
//! the stream carries the id by construction.
//!
//! An approval separates the agent's claim from Ward's authority (ADR-0019,
//! decision 2). [`Approval::claim`] is what the agent asked for, verbatim;
//! [`Approval::authority`] is what the policy and the credential rules grant if
//! the user says yes, derived by the daemon ([`Deriver`]) from the session's
//! manifest, the credentials it granted and the paths TamperWard protects,
//! never from the agent's text. Temporary authority stays visible while it
//! exists (decision 4): [`Approvals::grants`] lists every `allow-session`
//! answer and every credential the proxy injects, for `ward session grants`
//! and the shell's authority panel.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::str::FromStr;
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use ward_events::{
    CapabilityKind, CapabilityRequest, Decision, DecisionSource, GrantScope, ShortText, WardEvent,
};
use ward_policy::{AccessMode, CapabilityManifest, CredentialRule, RepoSelector, ServiceId};
use ward_proxy::{Host, Policy, Target};

use crate::error::{Error, Result};
use crate::github;
use crate::hooks::{HookDecision, HookResponse, PROTECTED_REASON, is_protected};
use crate::render::network_text;

/// The default hold before an unanswered approval is denied, in seconds
/// (`WARD_APPROVAL_TIMEOUT_SECS` overrides it for the sessions a shell starts).
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// One question waiting for the user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    /// The sequence number of the `CapabilityRequested` record that asked.
    pub id: u64,
    /// The tool the agent wants to use (`Write`, `WebFetch`, …).
    pub tool: String,
    /// Its target as the hook sent it (the URL, the path, the command): the
    /// key an `allow-session` is remembered under.
    pub summary: String,
    /// What the agent asked for, in its own words: the tool and its target,
    /// verbatim. Shown labelled as the agent's, never as a fact.
    pub claim: String,
    /// What Ward will allow if the user says yes, derived by the daemon.
    pub authority: Authority,
    /// When, milliseconds since the Unix epoch.
    pub requested_at_unix_ms: u64,
    /// Its decision clock, as the daemon's own copy has it at the moment
    /// the daemon answers (#146 item 4): filled in only on the copies
    /// [`Approvals::pending`] and [`Approvals::approvals`] hand out for a
    /// question that is still open and whose clock is armed; `None`
    /// everywhere else (a decided question, a record in the history, a
    /// question built by [`Approval::new`]). Absent from the JSON when
    /// `None`, and read as `None` when absent, so a client and a daemon on
    /// either side of this field still understand each other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub countdown: Option<Countdown>,
}

impl Approval {
    /// A question about `tool` on `summary`, with the authority the daemon
    /// derived for it.
    #[must_use]
    pub fn new(
        id: u64,
        tool: &str,
        summary: &str,
        authority: Authority,
        requested_at_unix_ms: u64,
    ) -> Self {
        Self {
            id,
            tool: tool.to_owned(),
            summary: summary.to_owned(),
            claim: format!("{tool} {summary}"),
            authority,
            requested_at_unix_ms,
            countdown: None,
        }
    }

    /// The three blocks of `docs/design-language.md` §10, as text: the
    /// destination, the agent's claim labelled as such, and what Ward will
    /// allow.
    #[must_use]
    pub fn blocks(&self) -> String {
        use std::fmt::Write as _;
        let mut s = format!(
            "DESTINATION\n  {}\n\nREQUESTED BY AGENT\n  {}\n\nWARD WILL ALLOW\n",
            self.authority.destination, self.claim
        );
        for (label, value) in self.authority.rows() {
            let _ = writeln!(s, "  {label:<12} {value}");
        }
        s
    }

    /// The grant an `allow-session` answer to this question makes, with the
    /// stable id the caller minted for it (`State::next_grant_id`, #140).
    #[must_use]
    pub fn session_grant(&self, granted_at_unix_ms: u64, id: u64) -> Grant {
        Grant {
            id,
            kind: GrantKind::Approval,
            label: format!("{} {}", self.tool, self.authority.destination),
            scope: self.authority.scope(),
            lifetime: Lifetime::Session,
            granted_at_unix_ms,
        }
    }
}

/// How long a grant lasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lifetime {
    /// This one request.
    Once,
    /// Until the session ends.
    Session,
    /// Until the launch that made it ends (a proxy route): confirmed still
    /// running, or cleanly retired at its terminal record.
    Launch,
    /// Tied to a launch whose owning connection closed without ever
    /// producing a terminal record (`CommandFinished`/`LaunchAborted`) —
    /// the client process was killed, crashed, or the socket was otherwise
    /// severed. `wardd` has no teardown handle into the client-side egress
    /// proxy (it runs inside the client's own process, not the daemon's), so
    /// a bare disconnect cannot establish whether the route this grant
    /// scoped actually ended. This is the honest middle ground between the
    /// two false claims: reporting it as plain `Launch` would claim it is
    /// still confirmed running, and retiring it (as `f5d5c19` tried, and was
    /// reverted for in `0198c95`) would claim it is confirmed safe. Neither
    /// is supportable from an EOF alone (#140, PR #197 review round 3), and
    /// this is a terminal answer in its own right: nothing resolves it back
    /// to `Launch` or forward to retired.
    LaunchUnknown,
}

impl Lifetime {
    /// The word on the wire and on the panel.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Session => "session",
            Self::Launch => "launch",
            Self::LaunchUnknown => "launch (disconnected)",
        }
    }
}

/// What Ward will allow if the user says yes (ADR-0019, decision 2). Every
/// field is derived by the daemon from the manifest, the credential rules, the
/// credentials granted so far and the protected paths; the agent's text only
/// ever contributes the sanitised destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authority {
    /// Why Ward asks (`step-through: pause before network`).
    pub rule: String,
    /// The sanitised target: the host of a URL, the path, the program of a
    /// command.
    pub destination: String,
    /// The proxy's verdict on the destination (`reachable · restricted (dev)`,
    /// `refused · host is not on the session allowlist`), or `none`.
    pub network: String,
    /// `GET` for a fetch, `read` or `write` for a file (with the mount's or
    /// TamperWard's refusal when there is one), `exec` for a command.
    pub method: String,
    /// The credential the proxy injects for the destination and its scope
    /// (`GitHub · contents:read, issues:read`), or `none`.
    pub credential: String,
    /// The repository a credential rule scopes the grant to.
    pub repository: Option<String>,
    /// Filled per decision: `once` or `session`; unset while the question is
    /// open, since the answer chooses it.
    pub lifetime: Option<Lifetime>,
}

impl Authority {
    /// An authority that says nothing beyond the tool: `none` in every row.
    /// What a hold carries when nothing derived it (a test, a fake daemon).
    #[must_use]
    pub fn none(rule: &str, destination: &str) -> Self {
        Self {
            rule: rule.to_owned(),
            destination: destination.to_owned(),
            network: "none".to_owned(),
            method: "none".to_owned(),
            credential: "none".to_owned(),
            repository: None,
            lifetime: None,
        }
    }

    /// The rows of the `WARD WILL ALLOW` block, in order.
    #[must_use]
    pub fn rows(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Network", self.network.clone()),
            ("Method", self.method.clone()),
            ("Credential", self.credential.clone()),
            (
                "Repository",
                self.repository.clone().unwrap_or_else(|| "none".to_owned()),
            ),
            (
                "Lifetime",
                self.lifetime.map_or_else(
                    || "once (allow) · session (allow-session)".to_owned(),
                    |l| l.as_str().to_owned(),
                ),
            ),
            ("Rule", self.rule.clone()),
        ]
    }

    /// One line of what is granted, for the grants list: the method, the
    /// network verdict when there is one, the credential when there is one.
    #[must_use]
    pub fn scope(&self) -> String {
        let mut parts = vec![self.method.clone()];
        if self.network != "none" {
            parts.push(self.network.clone());
        }
        if self.credential != "none" {
            parts.push(self.credential.clone());
        }
        parts.join(" · ")
    }
}

/// A credential the launch granted: the proxy injects it for `hosts`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    /// The daemon-minted id this credential's [`Grant`] carries (#140):
    /// stable for the life of the grant, unique within the session, never
    /// reused. `ward session revoke <id>` addresses a grant by this value
    /// alone — never by label, which two simultaneous grants can share.
    pub id: u64,
    /// The service (`github`).
    pub service: String,
    /// The upstream hosts the routes cover.
    pub hosts: Vec<String>,
    /// The permissions recorded in the grant.
    pub permissions: Vec<String>,
    /// When, milliseconds since the Unix epoch.
    pub granted_at_unix_ms: u64,
    /// An opaque key identifying the launch whose routes this credential was
    /// injected for, when the daemon could attribute it to one; `None` for a
    /// credential granted outside a tracked launch (a test, a fixture). This
    /// is *not* the client-supplied `Pid` on `CommandStarted`/`CommandFinished`
    /// — that value is chosen independently by each `Session` (every freshly
    /// opened session starts allocating from the same small range) and can
    /// collide between two genuinely concurrent launches, which would merge
    /// their credentials and let one launch's end retire the other's grant
    /// too. The daemon mints this key itself, scoped to the connection that
    /// started the launch, so it cannot collide (PR #197 review, finding 2).
    /// [`Approvals::retire_launch`] removes every credential recorded under a
    /// given key once that launch's terminal record (`CommandFinished` or
    /// `LaunchAborted`) lands, so the grant does not outlive the route it was
    /// scoped to (#140). When the connection instead closes with no terminal
    /// record ever landing for it, [`Approvals::mark_launch_unknown`] is
    /// called on the key instead: the credential stays, but reports as
    /// [`Lifetime::LaunchUnknown`] rather than [`Lifetime::Launch`].
    pub launch_key: Option<u64>,
}

impl Credential {
    /// `GitHub · contents:read, issues:read`.
    #[must_use]
    pub fn text(&self) -> String {
        format!(
            "{} · {}",
            service_name(&self.service),
            self.permissions.join(", ")
        )
    }
}

/// The product name of a service id, for the user.
#[must_use]
pub fn service_name(service: &str) -> String {
    match service {
        "github" => "GitHub".to_owned(),
        other => other.to_owned(),
    }
}

/// What kind of temporary authority a grant is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantKind {
    /// An `allow-session` answer.
    Approval,
    /// A credential the proxy injects (`--grant`).
    Credential,
}

/// One piece of temporary authority the session holds (ADR-0019, decision 4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// The daemon-minted id `ward session revoke <id>` addresses this grant
    /// by (#140): unique within the session, stable until the grant is
    /// retired, revoked or the session ends. Never reused.
    pub id: u64,
    /// Which kind.
    pub kind: GrantKind,
    /// `Write /work/src/lib.rs`, `GitHub`.
    pub label: String,
    /// What it grants: the method and the verdicts, or the permissions and
    /// hosts.
    pub scope: String,
    /// How long it lasts.
    pub lifetime: Lifetime,
    /// When, milliseconds since the Unix epoch.
    pub granted_at_unix_ms: u64,
}

impl Grant {
    /// The grant as one line: id, label, scope, lifetime.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "{}   {}   {}   {}",
            self.id,
            self.label,
            self.scope,
            self.lifetime.as_str()
        )
    }
}

/// What [`Approvals::revoke`] removed (#140).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevokedGrant {
    /// A credential the proxy had injected, by its raw service id (`github`
    /// — not [`service_name`]'s display form, which [`Approvals::grants`]
    /// shows instead): the caller records `CredentialRevoked` for it.
    Credential {
        /// The service id.
        service: String,
    },
    /// An `allow-session` answer, already removed from `remembered`; nothing
    /// further for the caller to do.
    Approval,
}

/// Derives an [`Authority`] for a question: the session's manifest, the
/// repository its `current_repository` selector means, and the paths
/// TamperWard protects. Fixed for the session; the credentials granted so far
/// are passed per question.
#[derive(Clone, Debug)]
pub struct Deriver {
    manifest: CapabilityManifest,
    repository: Option<String>,
    protected: Vec<String>,
}

impl Deriver {
    /// A deriver over `manifest`, with the worktree's GitHub repository (when
    /// it has one) and the protected paths.
    #[must_use]
    pub fn new(
        manifest: CapabilityManifest,
        repository: Option<String>,
        protected: Vec<String>,
    ) -> Self {
        Self {
            manifest,
            repository,
            protected,
        }
    }

    /// What Ward will allow for `tool` on `summary`, asked for `rule`, given
    /// the `credentials` the launch granted.
    #[must_use]
    pub fn derive(
        &self,
        tool: &str,
        summary: &str,
        rule: &str,
        credentials: &[Credential],
    ) -> Authority {
        let none = || "none".to_owned();
        let (destination, network, method, credential, repository) = match capability_kind(tool) {
            CapabilityKind::Network if tool == "WebSearch" => (
                "web search".to_owned(),
                "model API only".to_owned(),
                "GET".to_owned(),
                none(),
                None,
            ),
            CapabilityKind::Network => {
                let host = host_of(summary);
                let (credential, repository) = self.credential_for(&host, credentials);
                let reach = self.reach(&host);
                (host, reach, "GET".to_owned(), credential, repository)
            }
            CapabilityKind::FileWrite => {
                let path = path_of(summary);
                let method = if is_protected(&self.protected, summary) {
                    format!("write · refused ({PROTECTED_REASON})")
                } else {
                    self.file_method("write", &path, AccessMode::ReadWrite)
                };
                (path, none(), method, none(), None)
            }
            CapabilityKind::FileRead => {
                let path = path_of(summary);
                let method = self.file_method("read", &path, AccessMode::ReadOnly);
                (path, none(), method, none(), None)
            }
            CapabilityKind::Exec => {
                let (credential, repository) = self.credentials_text(credentials);
                (
                    program_of(summary),
                    format!(
                        "{} · through the proxy",
                        network_text(&self.manifest.network)
                    ),
                    "exec".to_owned(),
                    credential,
                    repository,
                )
            }
            // A hook tool only ever stands for the four kinds above or none.
            CapabilityKind::Other
            | CapabilityKind::Credential
            | CapabilityKind::Device
            | CapabilityKind::NestedContainer => {
                (tool.to_owned(), none(), "other".to_owned(), none(), None)
            }
        };
        Authority {
            rule: rule.to_owned(),
            destination,
            network,
            method,
            credential,
            repository,
            lifetime: None,
        }
    }

    /// The proxy's verdict on `host`, as the proxy itself decides it.
    fn reach(&self, host: &str) -> String {
        let target = Target {
            host: host
                .parse()
                .map_or_else(|_| Host::Name(host.to_owned()), Host::Ip),
            port: 443,
        };
        match Policy::new(self.manifest.network.clone()).check_host(&target) {
            Ok(()) => format!("reachable · {}", network_text(&self.manifest.network)),
            Err(denial) => format!("refused · {denial}"),
        }
    }

    /// `read` or `write` on `path`, refused when the mount does not give
    /// `needed`; only the worktree is a mount the policy narrows.
    fn file_method(&self, verb: &str, path: &str, needed: AccessMode) -> String {
        let under_work = path == "/work" || path.starts_with("/work/");
        if under_work && self.manifest.filesystem.worktree < needed {
            let mode = match self.manifest.filesystem.worktree {
                AccessMode::ReadOnly => "read-only",
                AccessMode::None | AccessMode::ReadWrite => "not mounted",
            };
            format!("{verb} · refused (/work is {mode})")
        } else {
            verb.to_owned()
        }
    }

    /// The credential the proxy injects for `host` and the repository it is
    /// scoped to: a granted one first, else what the rule would grant and
    /// why it has not.
    fn credential_for(&self, host: &str, credentials: &[Credential]) -> (String, Option<String>) {
        if let Some(c) = credentials
            .iter()
            .find(|c| c.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)))
        {
            return (c.text(), self.repository_for(&c.service));
        }
        match service_for_host(host) {
            Some(service) => self.rule_text(service),
            None => ("none".to_owned(), None),
        }
    }

    /// Every credential the launch granted, for a command that could use any.
    fn credentials_text(&self, credentials: &[Credential]) -> (String, Option<String>) {
        if credentials.is_empty() {
            return ("none".to_owned(), None);
        }
        let text = credentials
            .iter()
            .map(Credential::text)
            .collect::<Vec<_>>()
            .join("; ");
        let repository = credentials
            .iter()
            .find_map(|c| self.repository_for(&c.service));
        (text, repository)
    }

    /// What the manifest's rule for `service` says, when nothing was granted.
    fn rule_text(&self, service: &str) -> (String, Option<String>) {
        let name = service_name(service);
        match self
            .manifest
            .credentials
            .get(&ServiceId(service.to_owned()))
        {
            None => ("none".to_owned(), None),
            Some(CredentialRule::Deny) => (format!("none ({service}: denied by policy)"), None),
            Some(CredentialRule::Ask(scope)) => (
                format!(
                    "{name} · {} · not granted (--grant {service})",
                    permissions(&scope.permissions)
                ),
                self.repository_for(service),
            ),
            Some(CredentialRule::Allow(scope)) => (
                format!(
                    "{name} · {} · not granted this launch",
                    permissions(&scope.permissions)
                ),
                self.repository_for(service),
            ),
        }
    }

    /// The repositories the rule for `service` scopes a grant to, resolved
    /// against the worktree.
    fn repository_for(&self, service: &str) -> Option<String> {
        let scope = match self
            .manifest
            .credentials
            .get(&ServiceId(service.to_owned()))?
        {
            CredentialRule::Ask(scope) | CredentialRule::Allow(scope) => scope,
            CredentialRule::Deny => return None,
        };
        let repos: Vec<String> = scope
            .repositories
            .iter()
            .map(|sel| match sel {
                RepoSelector::Named(name) => name.clone(),
                RepoSelector::CurrentRepository => self
                    .repository
                    .clone()
                    .unwrap_or_else(|| "current repository (no GitHub remote)".to_owned()),
            })
            .collect();
        (!repos.is_empty()).then(|| repos.join(", "))
    }
}

fn permissions(set: &std::collections::BTreeSet<String>) -> String {
    if set.is_empty() {
        "no permissions".to_owned()
    } else {
        set.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

/// The service whose gateway routes carry `host`.
fn service_for_host(host: &str) -> Option<&'static str> {
    [github::GIT.upstream.0, github::API.upstream.0]
        .iter()
        .any(|h| h.eq_ignore_ascii_case(host))
        .then_some(github::SERVICE)
}

/// Longest destination shown, in characters.
const DESTINATION_MAX: usize = 120;

fn cap(text: &str) -> String {
    if text.chars().count() <= DESTINATION_MAX {
        text.to_owned()
    } else {
        let mut s: String = text.chars().take(DESTINATION_MAX).collect();
        s.push('…');
        s
    }
}

/// The host of a URL, lowercased, without scheme, userinfo, port, path or
/// trailing dot; `(no host)` when there is none.
#[must_use]
pub fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or_default()
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, port)| {
            if port.chars().all(|c| c.is_ascii_digit()) {
                h
            } else {
                authority
            }
        })
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        "(no host)".to_owned()
    } else {
        cap(&host)
    }
}

/// The path as the sandbox sees it: `./` prefixes dropped, a relative path
/// placed under `/work`.
#[must_use]
pub fn path_of(summary: &str) -> String {
    let mut path = summary.trim();
    while let Some(rest) = path.strip_prefix("./") {
        path = rest;
    }
    if path.is_empty() {
        "(no path)".to_owned()
    } else if path.starts_with('/') {
        cap(path)
    } else {
        cap(&format!("/work/{path}"))
    }
}

/// The program a command runs: its first word that is not an environment
/// assignment.
#[must_use]
pub fn program_of(command: &str) -> String {
    command
        .split_whitespace()
        .find(|w| !w.contains('='))
        .map_or_else(|| "(no command)".to_owned(), cap)
}

/// The user's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalDecision {
    /// This once.
    Allow,
    /// This, and the same tool on the same target, for the rest of the session.
    AllowSession,
    /// No.
    Deny,
}

impl ApprovalDecision {
    /// The word on the command line and the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AllowSession => "allow-session",
            Self::Deny => "deny",
        }
    }
}

impl FromStr for ApprovalDecision {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "allow" => Ok(Self::Allow),
            "allow-session" => Ok(Self::AllowSession),
            "deny" => Ok(Self::Deny),
            other => Err(format!(
                "unknown decision `{other}` (one of allow, allow-session, deny)"
            )),
        }
    }
}

impl std::fmt::Display for ApprovalDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a held approval was released.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// The user answered.
    Answered(ApprovalDecision),
    /// An earlier `allow-session` for the same tool and target covered it.
    Remembered,
    /// Nobody answered in time.
    TimedOut,
    /// The session ended with the question still open (#146): released as
    /// denied, and — unlike before #146 — given its own terminal
    /// `CapabilityDecided` record ([`decided_event`]) before anything that
    /// follows can seal the log, so the request is never silently dropped
    /// from the persistent record.
    Closed,
}

impl Outcome {
    /// What the hook tells the agent: allow or deny, and why.
    #[must_use]
    pub fn response(self) -> HookResponse {
        let (decision, reason) = match self {
            Self::Answered(ApprovalDecision::Allow) => {
                (HookDecision::Allow, "approval: allowed once")
            }
            Self::Answered(ApprovalDecision::AllowSession) => {
                (HookDecision::Allow, "approval: allowed for the session")
            }
            Self::Remembered => (HookDecision::Allow, "approval: allowed for the session"),
            Self::Answered(ApprovalDecision::Deny) => (HookDecision::Deny, "approval: denied"),
            Self::TimedOut => (HookDecision::Deny, "approval: timed out"),
            Self::Closed => (HookDecision::Deny, "approval: session ended"),
        };
        HookResponse {
            decision,
            reason: reason.to_owned(),
        }
    }
}

/// How much decision time an open approval has left before the daemon denies
/// it (#146 item 4), read from the same [`Clock`] [`Approvals::wait`]
/// enforces — never a figure a client derives from when it first saw the
/// question. A snapshot: true at the moment the daemon answered; a client
/// that shows it later shows it as of then.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Countdown {
    /// Decision time left, milliseconds. Stands still while `held`.
    pub remaining_ms: u64,
    /// The whole decision time the question was given, milliseconds: what a
    /// progress line measures `remaining_ms` against.
    pub timeout_ms: u64,
    /// The clock is held: the session is paused (ADR-0019 §3), no time
    /// counts against the question, and no answer is taken until resume.
    pub held: bool,
}

impl Countdown {
    /// The remaining time in words, for a terminal, `ward session pending`
    /// and the inbox, which have no progress line to draw: `42 s left,
    /// then denied`, or `held while paused · 42 s left once resumed`. Whole
    /// seconds, rounded up, so `0 s` is only ever said when none is left.
    #[must_use]
    pub fn text(&self) -> String {
        let secs = self.remaining_ms.div_ceil(1000);
        if self.held {
            format!("held while paused · {secs} s left once resumed")
        } else {
            format!("{secs} s left, then denied")
        }
    }
}

/// One question's decision clock (#146 item 4): the time it has left, and
/// since when that has been running down. The single account of an
/// approval's remaining time — [`Approvals::wait`] times out on it and
/// [`Countdown`] reports it — so what the desktop shows is what the daemon
/// enforces. Pure: every method takes `now`, so it is tested without
/// sleeping.
#[derive(Clone, Copy, Debug)]
struct Clock {
    /// The whole decision time the question was given.
    timeout: Duration,
    /// Time left as of `running_since` (or, while held, simply time left).
    left: Duration,
    /// When the clock last started running down; `None` while held.
    running_since: Option<Instant>,
}

impl Clock {
    /// A clock of `timeout`, started at `now` — or held from the start, when
    /// the session is already paused.
    fn start(timeout: Duration, now: Instant, paused: bool) -> Self {
        Self {
            timeout,
            left: timeout,
            running_since: (!paused).then_some(now),
        }
    }

    /// Time left at `now`.
    fn remaining(&self, now: Instant) -> Duration {
        match self.running_since {
            Some(since) => self
                .left
                .saturating_sub(now.saturating_duration_since(since)),
            None => self.left,
        }
    }

    /// Stop the clock at `now`, keeping what is left. Idempotent.
    fn hold(&mut self, now: Instant) {
        if self.running_since.is_some() {
            self.left = self.remaining(now);
            self.running_since = None;
        }
    }

    /// Start the clock again at `now` from what was left. Idempotent.
    fn run(&mut self, now: Instant) {
        if self.running_since.is_none() {
            self.running_since = Some(now);
        }
    }

    /// The wire form at `now`.
    fn countdown(&self, now: Instant) -> Countdown {
        Countdown {
            remaining_ms: millis(self.remaining(now)),
            timeout_ms: millis(self.timeout),
            held: self.running_since.is_none(),
        }
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// One held question and its answer, once there is one.
#[derive(Debug)]
struct Held {
    approval: Approval,
    answer: Option<ApprovalDecision>,
    /// Its decision clock: armed by [`Approvals::register_with_timeout`],
    /// or else by the first [`Approvals::wait`] on it; `None` until then.
    clock: Option<Clock>,
}

impl Held {
    /// A copy of the question with its countdown at `now` filled in, when it
    /// is still open and its clock is armed.
    fn shown(&self, now: Instant) -> Approval {
        let mut approval = self.approval.clone();
        if self.answer.is_none() {
            approval.countdown = self.clock.map(|c| c.countdown(now));
        }
        approval
    }
}

/// One approval as `ward session approvals` shows it (#146 item 1): the
/// question, and either still open (`outcome: None`) or how it was finally
/// released. The daemon's own authoritative account — independent of
/// whether a desktop notification for it was ever seen, answered from,
/// or dismissed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// The question.
    pub approval: Approval,
    /// `None` while it is still pending.
    pub outcome: Option<Outcome>,
    /// When the outcome was reached, milliseconds since the Unix epoch;
    /// `None` while it is still pending.
    pub decided_at_unix_ms: Option<u64>,
}

impl ApprovalRecord {
    /// This approval's current state, one word, for `ward session approvals`
    /// and a persistent inbox panel: `pending`, `allowed`, `allowed-session`,
    /// `denied`, `timed-out`, or `session-ended`.
    #[must_use]
    pub const fn state_word(&self) -> &'static str {
        match self.outcome {
            None => "pending",
            Some(Outcome::Answered(ApprovalDecision::Allow)) => "allowed",
            Some(Outcome::Answered(ApprovalDecision::AllowSession) | Outcome::Remembered) => {
                "allowed-session"
            }
            Some(Outcome::Answered(ApprovalDecision::Deny)) => "denied",
            Some(Outcome::TimedOut) => "timed-out",
            Some(Outcome::Closed) => "session-ended",
        }
    }

    /// One line: state, id, tool, destination — `ward session approvals`'s
    /// plain-text row — then, for an open question, its remaining decision
    /// time ([`Countdown::text`], #146 item 4).
    #[must_use]
    pub fn line(&self) -> String {
        let line = format!(
            "{:<15} {:>4}  {}  {}",
            self.state_word(),
            self.approval.id,
            self.approval.tool,
            self.approval.authority.destination,
        );
        match self.approval.countdown {
            Some(countdown) => format!("{line}  ({})", countdown.text()),
            None => line,
        }
    }
}

/// How many decided approvals [`Approvals::approvals`] keeps once they leave
/// `held`, oldest dropped first. Bounds an otherwise-unbounded long session's
/// memory; the event log is the durable, unbounded record (`ward replay`) —
/// this is only the daemon's own live view for a client that missed or
/// dismissed a notification and asks later, while the session is still up.
pub const HISTORY_CAP: usize = 200;

#[derive(Debug, Default)]
struct State {
    held: Vec<Held>,
    /// The grant an `allow-session` made, by the `(tool, summary)` it covers.
    remembered: BTreeMap<(String, String), Grant>,
    /// The credentials the launches granted, one per service and scope.
    credentials: Vec<Credential>,
    /// The next id [`State::next_grant_id`] mints (#140): monotonic for the
    /// life of the session, so a grant id is never reused even after its
    /// grant is retired or revoked — an id a caller once saw always means
    /// the one grant it was minted for, or nothing.
    next_grant_id: u64,
    /// Launch keys whose owning connection closed without ever producing a
    /// terminal record: [`Approvals::grants`] reports every credential
    /// recorded under one of these as [`Lifetime::LaunchUnknown`] rather than
    /// [`Lifetime::Launch`] (see [`Approvals::mark_launch_unknown`]).
    unknown_launches: BTreeSet<u64>,
    closed: bool,
    /// The session is paused: timeouts stand still and answers are refused.
    paused: bool,
    /// Every approval that left `held` with an outcome, oldest first, capped
    /// at [`HISTORY_CAP`]. `Outcome::Remembered` never enters `held` (`hold`
    /// answers it before registering a question at all — see `ward session
    /// grants` for that authority instead) so it never appears here either.
    history: VecDeque<ApprovalRecord>,
    /// The real outcome [`Approvals::close`] gave an id it drained straight
    /// from `held`, held here for that id's own still-in-flight
    /// [`Approvals::wait`] call to hand back — so a hold connection that was
    /// about to collect a genuine answer, but lost the race to a concurrent
    /// `close`, still learns its real answer instead of a fabricated
    /// [`Outcome::Closed`] (review of #218, finding 1). [`Approvals::take_recorded`]
    /// separately checks and clears the same entry to tell that same caller
    /// whether `close` already appended this id's terminal record for it, so
    /// it is never appended a second time. Also where `close` leaves a
    /// tombstone for an id it instead claimed out of `unclaimed` (below) —
    /// same contract either way: present means someone else already has (or,
    /// since that someone is always still holding the one lock that can seal
    /// the log at the time, is about to have) appended this id's terminal
    /// record. An id neither map has anything for was either never
    /// registered, was already collected by an earlier call to `wait`, or is
    /// `Outcome::Remembered` (which never enters `held` at all): `take_recorded`
    /// returning `false` there matches this method's behaviour from before
    /// either map existed.
    handoff: BTreeMap<u64, Outcome>,
    /// An id `wait` itself just settled — removed from `held`, recorded in
    /// `history` — but whose terminal record has not yet been appended,
    /// because the caller (`hold` in `daemon.rs`) has not yet reacquired the
    /// `Served` lock needed to append anything. Before this existed, that gap
    /// was invisible to a concurrent `close` (`Served::close_pending_approvals`,
    /// run for a `Stop`/`Seal` on another connection): `close` only ever
    /// looked at `held`, which `wait` had already emptied for this id, so
    /// `close` correctly concluded "nothing to do here" and let the log seal
    /// with no terminal record for an approval that had, in truth, already
    /// been decided (review of #218, finding 2 — the "wait before terminal
    /// append" window; finding 1's `close`-before-`wait` window above is a
    /// different interleaving of the same two operations). `close` now also
    /// claims every entry left here — under the same lock that flips
    /// `closed` — and appends it itself before the log can seal, leaving a
    /// tombstone in `handoff` exactly as it does for an id it drains straight
    /// from `held`; [`Approvals::take_recorded`] removes an entry here on the
    /// ordinary, non-racing path (nothing else has touched this id) to claim
    /// it for its own caller's append instead. Whichever of the two —
    /// `take_recorded`'s caller or `close` — reaches the one lock relevant to
    /// each (respectively `Served`'s, held for the whole check-then-append;
    /// and `Served`'s again, held for `close_pending_approvals`'s whole
    /// claim-then-append-then-seal) first is the one that actually appends;
    /// the other finds its entry already gone (or a tombstone already in
    /// `handoff`) and does nothing further.
    unclaimed: BTreeMap<u64, (Approval, Outcome)>,
}

impl State {
    /// Mint the next grant id (#140): starts at 1, strictly increasing, never
    /// reused for the life of the session.
    fn next_grant_id(&mut self) -> u64 {
        self.next_grant_id += 1;
        self.next_grant_id
    }

    /// Record `approval`'s outcome in the bounded history, evicting the
    /// oldest entry first when full.
    fn record_history(&mut self, approval: Approval, outcome: Outcome, at_unix_ms: u64) {
        if self.history.len() >= HISTORY_CAP {
            self.history.pop_front();
        }
        self.history.push_back(ApprovalRecord {
            approval,
            outcome: Some(outcome),
            decided_at_unix_ms: Some(at_unix_ms),
        });
    }
}

/// The daemon's hold: what is pending, what was answered, what is remembered,
/// what the proxy injects.
#[derive(Debug, Default)]
pub struct Approvals {
    state: Mutex<State>,
    changed: Condvar,
}

impl Approvals {
    /// An empty hold.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether an earlier `allow-session` covers `tool` on `summary`.
    #[must_use]
    pub fn remembered(&self, tool: &str, summary: &str) -> bool {
        self.lock()
            .remembered
            .contains_key(&(tool.to_owned(), summary.to_owned()))
    }

    /// A credential the launch granted for `host` with `permissions`,
    /// attributed to `launch_key` (the daemon's own opaque id for the launch
    /// this grant fell under, when it could tell one); a second route of the
    /// same service, permissions and launch adds its host rather than making
    /// a second grant.
    pub fn record_credential(
        &self,
        service: &str,
        host: &str,
        permissions: Vec<String>,
        launch_key: Option<u64>,
        granted_at_unix_ms: u64,
    ) {
        let mut state = self.lock();
        if let Some(c) = state.credentials.iter_mut().find(|c| {
            c.service == service && c.permissions == permissions && c.launch_key == launch_key
        }) {
            if !c.hosts.iter().any(|h| h == host) {
                c.hosts.push(host.to_owned());
            }
            return;
        }
        let id = state.next_grant_id();
        state.credentials.push(Credential {
            id,
            service: service.to_owned(),
            hosts: vec![host.to_owned()],
            permissions,
            granted_at_unix_ms,
            launch_key,
        });
    }

    /// Retire every credential granted for launch `key` (the same opaque id
    /// [`record_credential`](Self::record_credential) was called with):
    /// called once that launch's route is closed (its terminal record —
    /// `CommandFinished` or `LaunchAborted` — lands), so a launch-scoped
    /// grant does not keep showing as active authority once the launch it
    /// was scoped to has ended (#140). A credential with no launch attributed
    /// (`launch_key: None`) is never touched here.
    pub fn retire_launch(&self, key: u64) {
        let mut state = self.lock();
        state.credentials.retain(|c| c.launch_key != Some(key));
        // Nothing can still be reporting `LaunchUnknown` for a credential
        // that is gone; keeping the key around would only ever be dead
        // weight (this only ever fires here if a terminal record somehow
        // still lands for a launch already marked unknown — ordinarily it
        // cannot, since its owning connection is closed for good, but there
        // is no reason to leave the marker stale if it does).
        state.unknown_launches.remove(&key);
    }

    /// Mark launch `key` as no longer able to report: its owning connection
    /// closed before a terminal record (`CommandFinished`/`LaunchAborted`)
    /// ever landed, so `wardd` cannot say whether the route this launch's
    /// grant was scoped to actually ended (#140, PR #197 review round 3).
    /// The credential is *not* retired here — that would claim the route is
    /// confirmed to have ended, which a bare disconnect cannot support (the
    /// mistake `f5d5c19` made and `0198c95` reverted) — and it is not left
    /// reporting as plain [`Lifetime::Launch`] either, which would just as
    /// wrongly claim the launch is still confirmed running. From this call
    /// on, [`grants`](Self::grants) reports every credential recorded under
    /// `key` as [`Lifetime::LaunchUnknown`]: a legitimate, terminal answer in
    /// its own right, not a state anything here tries to resolve further.
    pub fn mark_launch_unknown(&self, key: u64) {
        self.lock().unknown_launches.insert(key);
    }

    /// The credentials granted so far, in grant order.
    #[must_use]
    pub fn credentials(&self) -> Vec<Credential> {
        self.lock().credentials.clone()
    }

    /// Every temporary grant the session holds, oldest first: the credentials
    /// the proxy injects and the `allow-session` answers.
    #[must_use]
    pub fn grants(&self) -> Vec<Grant> {
        let state = self.lock();
        let mut grants: Vec<Grant> = state
            .credentials
            .iter()
            .map(|c| Grant {
                id: c.id,
                kind: GrantKind::Credential,
                label: service_name(&c.service),
                scope: format!("{} · {}", c.permissions.join(", "), c.hosts.join(", ")),
                lifetime: match c.launch_key {
                    Some(key) if state.unknown_launches.contains(&key) => Lifetime::LaunchUnknown,
                    _ => Lifetime::Launch,
                },
                granted_at_unix_ms: c.granted_at_unix_ms,
            })
            .chain(state.remembered.values().cloned())
            .collect();
        // Order by when the grant was made; on a tie (the same millisecond, common
        // in tests and fast paths) an allow-session answer comes before an injected
        // credential, the order in which the two actually happen.
        grants.sort_by_key(|g| {
            let kind_rank = match g.kind {
                GrantKind::Approval => 0,
                GrantKind::Credential => 1,
            };
            (g.granted_at_unix_ms, kind_rank)
        });
        grants
    }

    /// Revoke the grant `id` names (`ward session revoke <id>`, #140 items
    /// 4-6): removes it from what [`grants`](Self::grants) reports from this
    /// call on. `None` when no live grant has this id — already revoked,
    /// retired by its launch ending, or never minted.
    ///
    /// For a credential the proxy injected, the caller (`Served::revoke` in
    /// `daemon.rs`) still has to record `CredentialRevoked` itself: this
    /// method only owns the in-memory authority view, not the event log, the
    /// same split `retire_launch` and `mark_launch_unknown` already draw. An
    /// `allow-session` answer has no audit event of its own yet — removing it
    /// from `remembered` is the whole of what revoking it does; a later pass
    /// can add one if `ward replay` needs to show it (#140's own "Related"
    /// notes this is UX-shaped follow-up, not a safety gap: the grant is
    /// gone from live authority the moment this returns either way).
    pub fn revoke(&self, id: u64) -> Option<RevokedGrant> {
        let mut state = self.lock();
        if let Some(pos) = state.credentials.iter().position(|c| c.id == id) {
            let removed = state.credentials.remove(pos);
            return Some(RevokedGrant::Credential {
                service: removed.service,
            });
        }
        if let Some(key) = state
            .remembered
            .iter()
            .find(|(_, g)| g.id == id)
            .map(|(key, _)| key.clone())
        {
            state.remembered.remove(&key);
            return Some(RevokedGrant::Approval);
        }
        None
    }

    /// Register a question. Refused once the session has ended. Its decision
    /// clock is armed by the first [`wait`](Self::wait) on it; until then it
    /// reports no [`Countdown`].
    pub fn register(&self, approval: Approval) -> Result<()> {
        self.register_at(approval, None, Instant::now())
    }

    /// Register a question with its decision clock of `timeout` armed at
    /// once (#146 item 4), so a client listing it the moment it is asked —
    /// before its hold connection has reached [`wait`](Self::wait) — already
    /// sees its countdown. What the daemon's own `Request::Hold` uses.
    pub fn register_with_timeout(&self, approval: Approval, timeout: Duration) -> Result<()> {
        self.register_at(approval, Some(timeout), Instant::now())
    }

    fn register_at(
        &self,
        approval: Approval,
        timeout: Option<Duration>,
        now: Instant,
    ) -> Result<()> {
        let mut state = self.lock();
        if state.closed {
            return Err(Error::Daemon("approval: session ended".into()));
        }
        let paused = state.paused;
        state.held.push(Held {
            approval,
            answer: None,
            clock: timeout.map(|t| Clock::start(t, now, paused)),
        });
        drop(state);
        self.changed.notify_all();
        Ok(())
    }

    /// Wait for the answer to `id` until its decision clock runs out, then
    /// forget the question. The clock is the one
    /// [`register_with_timeout`](Self::register_with_timeout) armed, or else
    /// one of `timeout` armed here. The answer stays remembered when it was
    /// `allow-session`. Time spent paused does not count against the
    /// timeout: [`set_paused`](Self::set_paused) holds the clock where it
    /// stood and resume runs it on from there (#146 item 4), so a pause
    /// neither spends nor refunds decision time.
    pub fn wait(&self, id: u64, timeout: Duration) -> Outcome {
        let mut state = self.lock();
        loop {
            let Some(index) = state.held.iter().position(|h| h.approval.id == id) else {
                // Not (or no longer) held. `close` drains every entry it
                // finds still in `held` — answered or not — under the same
                // lock that flips `closed` (review of #218, finding 1), so
                // by the time anything observes `id` missing from `held`,
                // `close` (if it is what took it) has already recorded its
                // real outcome in `handoff` and appended its terminal
                // record. Hand that same real outcome back rather than a
                // fabricated `Closed`, so the caller (and, through it, the
                // agent) learns what actually happened to its question. An
                // id `handoff` has nothing for was either never registered
                // or was already collected by an earlier call to this
                // method (exercised directly by tests): `Closed` there
                // matches this method's behaviour from before `handoff`
                // existed.
                return state.handoff.get(&id).copied().unwrap_or(Outcome::Closed);
            };
            if let Some(answer) = state.held[index].answer {
                let held = state.held.remove(index);
                let outcome = Outcome::Answered(answer);
                if answer == ApprovalDecision::AllowSession {
                    let id = state.next_grant_id();
                    let grant = held.approval.session_grant(now_unix_ms(), id);
                    state.remembered.insert(
                        (held.approval.tool.clone(), held.approval.summary.clone()),
                        grant,
                    );
                }
                let now = now_unix_ms();
                state.record_history(held.approval.clone(), outcome, now);
                // Settled, but not yet appended (review of #218, finding 2):
                // left here for `close` to claim and append itself if a
                // concurrent `Stop`/`Seal` reaches the log-sealing lock
                // before this call's own caller does — see `unclaimed`'s doc
                // comment.
                state
                    .unclaimed
                    .insert(held.approval.id, (held.approval, outcome));
                return outcome;
            }
            // The question's own clock (#146 item 4), shared with what
            // `pending`/`approvals` report. Before it existed this loop kept
            // its own `remaining`, charged only when it woke while running:
            // a pause woke it into the branch below without charging the
            // time run since its previous wake, so a pause and resume handed
            // that time back. `set_paused` now holds the clock itself, under
            // this same lock, at the instant the pause lands.
            let now = Instant::now();
            let paused = state.paused;
            let clock = *state.held[index]
                .clock
                .get_or_insert_with(|| Clock::start(timeout, now, paused));
            if paused {
                // Held in turn: wake on any change; the clock stands still.
                state = self
                    .changed
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            let remaining = clock.remaining(now);
            if remaining.is_zero() {
                let held = state.held.remove(index);
                let now = now_unix_ms();
                state.record_history(held.approval.clone(), Outcome::TimedOut, now);
                // Same settled-but-not-yet-appended gap as the answered
                // branch above; the timeout path is exposed to exactly the
                // same #218 finding-2 window.
                state
                    .unclaimed
                    .insert(held.approval.id, (held.approval, Outcome::TimedOut));
                return Outcome::TimedOut;
            }
            state = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Answer `id`. Unknown ids (never asked, already released) are an error;
    /// a second answer to the same open question is too, and so is an
    /// answer to a question whose decision clock has already run out.
    pub fn answer(&self, id: u64, decision: ApprovalDecision) -> Result<()> {
        // The clock is read only once the lock is held (review of #225,
        // second round, finding 1): an answer that blocks on this lock
        // across the deadline — behind the timed-out waiter, or any other
        // caller — is judged at the moment it can actually take effect,
        // not by a timestamp taken before it queued for the lock.
        self.answer_with(id, decision, Instant::now)
    }

    /// [`answer`](Self::answer) judged at a fixed `now`: the deterministic
    /// seam the clock tests drive.
    #[cfg(test)]
    fn answer_at(&self, id: u64, decision: ApprovalDecision, now: Instant) -> Result<()> {
        self.answer_with(id, decision, || now)
    }

    /// `now` is called under the approvals lock, never before it, so the
    /// expiry check below compares the clock with the time at which this
    /// answer is actually serialised against `wait`.
    fn answer_with(
        &self,
        id: u64,
        decision: ApprovalDecision,
        now: impl FnOnce() -> Instant,
    ) -> Result<()> {
        let mut state = self.lock();
        let now = now();
        if state.paused {
            return Err(Error::Daemon(format!(
                "approval {id}: paused by ward; resume the session to answer"
            )));
        }
        let held = state
            .held
            .iter_mut()
            .find(|h| h.approval.id == id)
            .ok_or_else(|| Error::Daemon(format!("approval {id}: not pending")))?;
        if held.answer.is_some() {
            return Err(Error::Daemon(format!("approval {id}: already answered")));
        }
        // Its decision time is spent: the question is already denied, even
        // if its `wait` has not woken to say so yet (it only wakes once it
        // wins this same lock back, which an answering connection can beat
        // it to; or, for a clock armed at registration, it may not have
        // started waiting at all). Refused here, under the lock `wait`
        // settles under, so an answer can never overtake an expired clock.
        // Nothing is recorded: the question stays in `held` untouched, and
        // its own `wait` settles it as `TimedOut` exactly once, through the
        // same `history`/`unclaimed` path as any other timeout (#218).
        if held.clock.is_some_and(|c| c.remaining(now).is_zero()) {
            return Err(Error::Daemon(format!(
                "approval {id}: timed out; its decision time ran out"
            )));
        }
        held.answer = Some(decision);
        drop(state);
        self.changed.notify_all();
        Ok(())
    }

    /// The open questions, oldest first, each with its [`Countdown`] once its
    /// clock is armed.
    #[must_use]
    pub fn pending(&self) -> Vec<Approval> {
        self.pending_at(Instant::now())
    }

    fn pending_at(&self, now: Instant) -> Vec<Approval> {
        self.lock()
            .held
            .iter()
            .filter(|h| h.answer.is_none())
            .map(|h| h.shown(now))
            .collect()
    }

    /// Every approval this session has asked that is either still open,
    /// still awaiting its own `Request::Hold` connection's collection, or
    /// still within the bounded history, oldest asked first (#146 item 1):
    /// `ward session approvals`, and the desktop's persistent inbox, read
    /// this instead of `pending` so a request is not lost from view the
    /// moment its notification is missed or dismissed. An approval already
    /// answered but not yet collected by its own `Request::Hold` connection
    /// (the narrow, ordinary window between `answer` and that connection's
    /// `wait` — see `answer`) still shows here, as pending: it is still in
    /// `held`, and nothing has turned its answer into a terminal record
    /// yet. It moves to the bounded history, with its real outcome, exactly
    /// once — whichever of that connection's own `wait` or a concurrent
    /// `close` collects it first (review of #218, finding 1: there is no
    /// window in which it is neither pending nor decided).
    ///
    /// Sorted by `(requested_at_unix_ms, approval.id)`: two requests can
    /// legitimately share a millisecond timestamp, and an approval's own id
    /// — the sequence number of the `CapabilityRequested` record that asked
    /// it — is assigned in true request order regardless, so it is the
    /// exact tie-breaker a plain sort by timestamp alone is missing (review
    /// of #218, finding 2).
    ///
    /// A still-open question carries its [`Countdown`] (#146 item 4) once its
    /// clock is armed; one already answered but not yet collected does not,
    /// since its clock no longer decides anything.
    #[must_use]
    pub fn approvals(&self) -> Vec<ApprovalRecord> {
        self.approvals_at(Instant::now())
    }

    fn approvals_at(&self, now: Instant) -> Vec<ApprovalRecord> {
        let state = self.lock();
        let mut records: Vec<ApprovalRecord> = state
            .held
            .iter()
            .map(|h| ApprovalRecord {
                approval: h.shown(now),
                outcome: None,
                decided_at_unix_ms: None,
            })
            .chain(state.history.iter().cloned())
            .collect();
        records.sort_by_key(|r| (r.approval.requested_at_unix_ms, r.approval.id));
        records
    }

    /// The session ended: every question still in `held` — whether still
    /// open, or already answered but not yet collected by its own
    /// `Request::Hold` connection — is drained here with its real outcome
    /// and returned, oldest first, so the caller can give each one its
    /// terminal record (`decided_event`) before anything that follows can
    /// seal the log (#146) — once sealed, no record can follow it. No new
    /// question is taken from here on (`register` already refuses once
    /// `closed`).
    ///
    /// Before the review of #218 this left an already-answered entry in
    /// `held` for its own connection to record later, on the reasoning that
    /// `wait` already gives an answer priority over `closed`. That handoff
    /// raced Stop/Seal sealing the log first: nothing made "the hold
    /// connection notices and appends" and "the log seals" mutually
    /// exclusive, so the real record could be dropped on the floor entirely
    /// (finding 1). Draining and recording *every* entry here instead,
    /// under the one lock that also flips `closed`, makes settlement atomic
    /// with respect to a concurrent `wait`: whichever of the two reaches a
    /// given entry first is the only one that ever will, so there is
    /// exactly one terminal record, and it is always appended (by the
    /// caller, from what this returns) before the seal. The drained
    /// entry's own blocked `wait` call, if there is one, is handed this
    /// same real outcome back through `handoff` — never a fabricated
    /// `Outcome::Closed` for a question that was genuinely answered — and
    /// `take_recorded` tells whichever caller collects it not to append the
    /// terminal record a second time.
    ///
    /// That closed finding 1's race (`close` beats a still-blocked `wait` to
    /// a given entry) but left a second, narrower one open (finding 2): a
    /// `wait` that had *already* settled an id — removed it from `held`,
    /// recorded its real outcome in `history` — before this call ever ran,
    /// so it was never in `held` for this call to drain in the first place.
    /// Nothing here saw that id at all, so it could conclude "nothing left
    /// to do" and let the log seal while that id's terminal record was still
    /// unappended, if its own caller (`hold` in `daemon.rs`) had not yet won
    /// back the lock it needs to append it. This call now also claims every
    /// entry `wait` left in `unclaimed` (see its own doc comment) — id and
    /// all, no `held` involved — and returns those alongside the ones just
    /// drained from `held`, so the caller appends them too, here, before the
    /// seal. `record_history` is *not* called again for these: `wait`
    /// already recorded the real outcome the moment it settled; only the
    /// append was still outstanding. A tombstone goes into `handoff` for
    /// each all the same, so a `take_recorded` call that reaches its own
    /// entry after this one already claimed it correctly finds it already
    /// spoken for.
    pub fn close(&self) -> Vec<(Approval, Outcome)> {
        let mut state = self.lock();
        state.closed = true;
        let now = now_unix_ms();
        let drained = std::mem::take(&mut state.held);
        let mut released = Vec::with_capacity(drained.len());
        for held in drained {
            let outcome = match held.answer {
                Some(answer) => Outcome::Answered(answer),
                None => Outcome::Closed,
            };
            if let Outcome::Answered(ApprovalDecision::AllowSession) = outcome {
                let id = state.next_grant_id();
                let grant = held.approval.session_grant(now, id);
                state.remembered.insert(
                    (held.approval.tool.clone(), held.approval.summary.clone()),
                    grant,
                );
            }
            state.record_history(held.approval.clone(), outcome, now);
            state.handoff.insert(held.approval.id, outcome);
            released.push((held.approval, outcome));
        }
        // Claim every id a concurrent `wait` had already settled but not yet
        // appended (review of #218, finding 2) — the "wait before terminal
        // append" window `held` alone cannot reveal, since `wait` already
        // removed the entry from there before this call ever ran.
        for (id, (approval, outcome)) in std::mem::take(&mut state.unclaimed) {
            state.handoff.insert(id, outcome);
            released.push((approval, outcome));
        }
        drop(state);
        self.changed.notify_all();
        released
    }

    /// Whether `id`'s terminal record was already appended by a concurrent
    /// `close` (review of #218, findings 1 and 2): checked, and cleared so
    /// it is consulted at most once. Must be called by its caller
    /// (`hold` in `daemon.rs`) only while already holding the `Served` lock,
    /// with the resulting append (when this returns `false`) performed
    /// before that same lock is released — the same lock `close_pending_approvals`
    /// needs for its own claim-then-append-then-seal — so this check and
    /// `close`'s own claiming are mutually exclusive with each other and
    /// with the seal that follows: whichever of the two reaches the lock
    /// first is the one that actually appends `id`'s terminal record, and
    /// the log can never seal having appended neither (finding 2; calling
    /// this before acquiring that lock, as `hold` did before the review of
    /// #218's second round, reopens exactly that gap even with `unclaimed`
    /// in place, since `close` would still see nothing to claim).
    ///
    /// `true` when a tombstone is already in `handoff` — a concurrent
    /// `close` drained this id straight from `held` (finding 1) or claimed
    /// it out of `unclaimed` after `wait` had already settled it (finding
    /// 2); either way its terminal record is already appended (or, since
    /// `close` always finishes appending everything it claims before
    /// releasing the very lock this method is called under, is about to be,
    /// strictly before any seal that follows). `false` otherwise: this also
    /// claims (removes) any `unclaimed` entry for `id`, so a `close` that
    /// runs after this returns finds nothing left to claim — the caller
    /// must append it now, same as before either map existed for any id
    /// neither ever had anything for (`Outcome::Remembered`, which never
    /// enters `held` or `unclaimed` at all).
    pub fn take_recorded(&self, id: u64) -> bool {
        let mut state = self.lock();
        if state.handoff.remove(&id).is_some() {
            return true;
        }
        state.unclaimed.remove(&id);
        false
    }

    /// Pause or resume the hold (ADR-0019 §3): paused, pending questions stay
    /// pending with their timeouts stopped, answers are refused, and new
    /// questions wait like the rest. Every armed clock is held where it
    /// stands the instant the pause lands, and runs on from there on resume
    /// (#146 item 4), so the [`Countdown`] a client reads while paused says
    /// `held` and does not move.
    pub fn set_paused(&self, paused: bool) {
        self.set_paused_at(paused, Instant::now());
    }

    fn set_paused_at(&self, paused: bool, now: Instant) {
        let mut state = self.lock();
        state.paused = paused;
        for clock in state.held.iter_mut().filter_map(|h| h.clock.as_mut()) {
            if paused {
                clock.hold(now);
            } else {
                clock.run(now);
            }
        }
        drop(state);
        self.changed.notify_all();
    }

    /// Whether the hold is paused.
    #[must_use]
    pub fn paused(&self) -> bool {
        self.lock().paused
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn now_unix_ms() -> u64 {
    crate::control::unix_ms(std::time::SystemTime::now())
}

/// The capability a hook tool stands for: writes, reads, the network, a
/// command, or something else.
#[must_use]
pub fn capability_kind(tool: &str) -> CapabilityKind {
    match tool {
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => CapabilityKind::FileWrite,
        "Read" | "Grep" | "Glob" | "LS" => CapabilityKind::FileRead,
        "WebFetch" | "WebSearch" => CapabilityKind::Network,
        "Bash" => CapabilityKind::Exec,
        _ => CapabilityKind::Other,
    }
}

fn capability(tool: &str, summary: &str) -> CapabilityRequest {
    CapabilityRequest {
        kind: capability_kind(tool),
        target: ShortText::new(&format!("{tool} {summary}")),
    }
}

/// The record that asks: `CapabilityRequested` with the tool and target and
/// the hook's reason.
#[must_use]
pub fn requested_event(tool: &str, summary: &str, reason: &str) -> WardEvent {
    WardEvent::CapabilityRequested {
        cap: capability(tool, summary),
        reason: Some(ShortText::new(reason)),
    }
}

/// The record that answers: `CapabilityDecided`, by the user (with the
/// grant's scope), by the timeout, or — since #146 — by the session ending
/// with the question still open. Every [`Outcome`] now produces one; the
/// caller for `Outcome::Closed` (`Served::close_pending_approvals`) appends
/// it before the log can seal, so this is no longer dropped as it was before
/// #146.
#[must_use]
pub fn decided_event(tool: &str, summary: &str, outcome: Outcome) -> WardEvent {
    let (decision, by, grant) = match outcome {
        Outcome::Answered(ApprovalDecision::Allow) => (
            Decision::Allow,
            DecisionSource::User,
            Some(GrantScope::Once),
        ),
        Outcome::Answered(ApprovalDecision::AllowSession) | Outcome::Remembered => (
            Decision::Allow,
            DecisionSource::User,
            Some(GrantScope::Session),
        ),
        Outcome::Answered(ApprovalDecision::Deny) => (Decision::Deny, DecisionSource::User, None),
        Outcome::TimedOut => (Decision::Deny, DecisionSource::Timeout, None),
        Outcome::Closed => (Decision::Deny, DecisionSource::SessionEnded, None),
    };
    WardEvent::CapabilityDecided {
        cap: capability(tool, summary),
        decision,
        by,
        grant,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::sync::Arc;

    fn authority() -> Authority {
        Authority {
            rule: "step-through: pause before writes".into(),
            destination: "/work/src/lib.rs".into(),
            network: "none".into(),
            method: "write".into(),
            credential: "none".into(),
            repository: None,
            lifetime: None,
        }
    }

    fn approval(id: u64) -> Approval {
        Approval::new(
            id,
            "Write",
            "/work/src/lib.rs",
            authority(),
            1_700_000_000_000,
        )
    }

    /// The default manifest (development network, GitHub `ask` scoped to the
    /// current repository with `contents:read, issues:read`) over a worktree
    /// whose origin is `hexrift/WardOS`, with one protected test file.
    fn deriver() -> Deriver {
        Deriver::new(
            ward_policy::default_manifest(),
            Some("hexrift/WardOS".into()),
            vec!["tests/security_expiry.rs".into()],
        )
    }

    fn github_credential() -> Credential {
        Credential {
            id: 1,
            service: "github".into(),
            hosts: vec!["github.com".into(), "api.github.com".into()],
            permissions: vec!["contents:read".into(), "issues:read".into()],
            granted_at_unix_ms: 1,
            launch_key: None,
        }
    }

    #[test]
    fn a_fetch_to_a_host_with_a_credential_rule_derives_the_rule_and_the_grant_state() {
        let d = deriver();
        let url = "https://API.GitHub.com/repos/hexrift/WardOS/issues/381";
        let rule = "step-through: pause before network";
        let a = d.derive("WebFetch", url, rule, &[]);
        assert_eq!(a.destination, "api.github.com", "the host, sanitised");
        assert_eq!(a.network, "reachable · restricted (dev)");
        assert_eq!(a.method, "GET");
        assert_eq!(
            a.credential,
            "GitHub · contents:read, issues:read · not granted (--grant github)"
        );
        assert_eq!(a.repository.as_deref(), Some("hexrift/WardOS"));
        assert_eq!(a.lifetime, None, "the answer chooses it");
        assert_eq!(a.rule, rule);
        // Once the launch granted the credential, the proxy injects it.
        let granted = d.derive("WebFetch", url, rule, &[github_credential()]);
        assert_eq!(granted.credential, "GitHub · contents:read, issues:read");
        assert_eq!(granted.repository.as_deref(), Some("hexrift/WardOS"));
        // The claim is the agent's text; the authority never repeats it.
        let approval = Approval::new(7, "WebFetch", url, a, 5);
        assert_eq!(approval.claim, format!("WebFetch {url}"));
        assert!(!approval.authority.destination.contains("issues/381"));
        let blocks = approval.blocks();
        assert!(
            blocks.starts_with(
                "DESTINATION\n  api.github.com\n\nREQUESTED BY AGENT\n  WebFetch https://API.GitHub.com/repos/hexrift/WardOS/issues/381\n\nWARD WILL ALLOW\n  Network      reachable · restricted (dev)\n  Method       GET\n"
            ),
            "{blocks}"
        );
        assert!(
            blocks.contains("  Repository   hexrift/WardOS\n  Lifetime     once (allow) · session (allow-session)\n  Rule         step-through: pause before network\n"),
            "{blocks}"
        );
    }

    #[test]
    fn a_fetch_to_a_host_without_a_credential_rule_reports_the_proxys_verdict_and_no_credential() {
        let d = deriver();
        let a = d.derive("WebFetch", "https://example.org/data.json", "r", &[]);
        assert_eq!(a.destination, "example.org");
        assert_eq!(a.network, "refused · host is not on the session allowlist");
        assert_eq!(a.credential, "none");
        assert_eq!(a.repository, None);
        let a = d.derive("WebFetch", "https://index.crates.io/config.json", "r", &[]);
        assert_eq!(a.network, "reachable · restricted (dev)");
        assert_eq!(a.credential, "none");
        // A denied rule says so; an offline session refuses everything.
        let mut manifest = ward_policy::default_manifest();
        manifest
            .credentials
            .insert(ServiceId("github".into()), CredentialRule::Deny);
        manifest.network = ward_policy::NetworkCapability::Offline;
        let d = Deriver::new(manifest, None, vec![]);
        let a = d.derive("WebFetch", "https://github.com/hexrift/WardOS", "r", &[]);
        assert_eq!(a.network, "refused · session network mode is offline");
        assert_eq!(a.credential, "none (github: denied by policy)");
        // A search runs at the model API, not at a host of the agent's choosing.
        let a = deriver().derive("WebSearch", "wardos", "r", &[]);
        assert_eq!(
            (a.destination.as_str(), a.network.as_str()),
            ("web search", "model API only")
        );
    }

    #[test]
    fn a_write_to_a_protected_path_is_refused_in_the_authority_and_a_plain_write_is_not() {
        let d = deriver();
        let a = d.derive("Write", "tests/security_expiry.rs", "r", &[]);
        assert_eq!(a.destination, "/work/tests/security_expiry.rs");
        assert_eq!(
            a.method,
            "write · refused (protected by TamperWard policy: tests)"
        );
        assert_eq!(
            (a.network.as_str(), a.credential.as_str()),
            ("none", "none")
        );
        let a = d.derive("Edit", "./src/lib.rs", "r", &[]);
        assert_eq!(a.destination, "/work/src/lib.rs");
        assert_eq!(a.method, "write");
        let a = d.derive("Read", "/work/Cargo.toml", "r", &[]);
        assert_eq!(a.method, "read");
        // A read-only worktree refuses the write, whatever the agent says.
        let mut manifest = ward_policy::default_manifest();
        manifest.filesystem.worktree = AccessMode::ReadOnly;
        let a = Deriver::new(manifest, None, vec![]).derive("Write", "/work/x.rs", "r", &[]);
        assert_eq!(a.method, "write · refused (/work is read-only)");
    }

    #[test]
    fn a_command_shows_the_program_the_proxy_and_every_granted_credential() {
        let d = deriver();
        let a = d.derive("Bash", "RUST_LOG=debug cargo test -- --nocapture", "r", &[]);
        assert_eq!(a.destination, "cargo");
        assert_eq!(a.method, "exec");
        assert_eq!(a.network, "restricted (dev) · through the proxy");
        assert_eq!(a.credential, "none");
        let a = d.derive("Bash", "git push", "r", &[github_credential()]);
        assert_eq!(a.destination, "git");
        assert_eq!(a.credential, "GitHub · contents:read, issues:read");
        assert_eq!(a.repository.as_deref(), Some("hexrift/WardOS"));
        let a = d.derive("Task", "{\"prompt\":\"x\"}", "r", &[]);
        assert_eq!(
            (a.destination.as_str(), a.method.as_str()),
            ("Task", "other")
        );
    }

    #[test]
    fn destinations_are_sanitised_hosts_paths_and_programs() {
        assert_eq!(
            host_of("https://user:pw@API.GitHub.com:443/x?y#z"),
            "api.github.com"
        );
        assert_eq!(host_of("http://[::1]:8080/"), "::1");
        assert_eq!(host_of("example.org."), "example.org");
        assert_eq!(host_of("https:///x"), "(no host)");
        let long = format!("https://{}.example", "a".repeat(200));
        assert!(host_of(&long).ends_with('…'));
        assert_eq!(host_of(&long).chars().count(), DESTINATION_MAX + 1);
        assert_eq!(path_of("././src/lib.rs"), "/work/src/lib.rs");
        assert_eq!(path_of("/tmp/x"), "/tmp/x");
        assert_eq!(path_of("  "), "(no path)");
        assert_eq!(program_of("A=1 B=2 make -j"), "make");
        assert_eq!(program_of(""), "(no command)");
        assert_eq!(service_name("github"), "GitHub");
        assert_eq!(service_name("ssh-signing"), "ssh-signing");
    }

    #[test]
    fn grants_list_the_credentials_injected_and_the_allow_session_answers() {
        let approvals = Approvals::new();
        assert!(approvals.grants().is_empty());
        let perms = || vec!["contents:read".to_owned(), "issues:read".to_owned()];
        approvals.record_credential("github", "github.com", perms(), None, 1);
        approvals.record_credential("github", "api.github.com", perms(), None, 2);
        approvals.record_credential("github", "api.github.com", perms(), None, 3);
        assert_eq!(
            approvals.credentials(),
            [Credential {
                id: 1,
                service: "github".into(),
                hosts: vec!["github.com".into(), "api.github.com".into()],
                permissions: perms(),
                granted_at_unix_ms: 1,
                launch_key: None,
            }],
            "one credential per service and scope, its hosts merged"
        );
        approvals.register(approval(1)).unwrap();
        approvals.answer(1, ApprovalDecision::AllowSession).unwrap();
        approvals.wait(1, Duration::ZERO);
        let grants = approvals.grants();
        assert_eq!(grants.len(), 2);
        assert_eq!(grants[0].kind, GrantKind::Credential);
        assert_eq!(grants[0].label, "GitHub");
        assert_eq!(
            grants[0].scope,
            "contents:read, issues:read · github.com, api.github.com"
        );
        assert_eq!(grants[0].lifetime, Lifetime::Launch);
        assert_eq!(grants[1].kind, GrantKind::Approval);
        assert_eq!(grants[1].label, "Write /work/src/lib.rs");
        assert_eq!(grants[1].scope, "write");
        assert_eq!(grants[1].lifetime, Lifetime::Session);
        assert!(grants[1].granted_at_unix_ms >= 1_700_000_000_000);
        assert_ne!(grants[0].id, grants[1].id, "each grant has its own id");
        assert_eq!(
            grants[0].line(),
            format!(
                "{}   GitHub   contents:read, issues:read · github.com, api.github.com   launch",
                grants[0].id
            )
        );
        assert_eq!(
            serde_json::to_string(&Lifetime::Session).unwrap(),
            "\"session\""
        );
        assert_eq!(
            serde_json::to_string(&GrantKind::Credential).unwrap(),
            "\"credential\""
        );
        // An `allow` once is not a grant.
        approvals.register(approval(2)).unwrap();
        approvals.answer(2, ApprovalDecision::Allow).unwrap();
        approvals.wait(2, Duration::ZERO);
        assert_eq!(approvals.grants().len(), 2);
    }

    #[test]
    fn retiring_a_launch_drops_only_its_own_credentials() {
        // #140: a launch-scoped credential must not keep showing as active
        // authority once the launch it was granted for has ended.
        let approvals = Approvals::new();
        let perms = || vec!["contents:read".to_owned()];
        approvals.record_credential("github", "github.com", perms(), Some(2), 1);
        // A second, concurrent launch grants the same service and scope: it
        // must stay its own credential, not merge with pid 2's.
        approvals.record_credential("github", "github.com", perms(), Some(3), 2);
        // A credential the daemon could not attribute to a launch (none
        // observed): never retired by a launch ending.
        approvals.record_credential("npm", "registry.npmjs.org", perms(), None, 3);
        assert_eq!(approvals.credentials().len(), 3);

        approvals.retire_launch(2);
        let remaining = approvals.credentials();
        assert_eq!(remaining.len(), 2, "{remaining:?}");
        assert!(remaining.iter().all(|c| c.launch_key != Some(2)));
        assert!(
            remaining.iter().any(|c| c.launch_key == Some(3)),
            "the other launch's credential is untouched: {remaining:?}"
        );
        assert!(
            remaining.iter().any(|c| c.launch_key.is_none()),
            "an unattributed credential is never retired: {remaining:?}"
        );

        // Retiring a pid that never granted anything is a no-op.
        approvals.retire_launch(99);
        assert_eq!(approvals.credentials().len(), 2);

        approvals.retire_launch(3);
        assert_eq!(
            approvals.credentials(),
            [Credential {
                id: 3,
                service: "npm".into(),
                hosts: vec!["registry.npmjs.org".into()],
                permissions: perms(),
                granted_at_unix_ms: 3,
                launch_key: None,
            }]
        );
    }

    #[test]
    fn revoke_removes_a_credential_by_id_and_records_nothing_else() {
        let approvals = Approvals::new();
        let perms = || vec!["contents:read".to_owned()];
        approvals.record_credential("github", "github.com", perms(), None, 1);
        approvals.record_credential("npm", "registry.npmjs.org", perms(), None, 2);
        let grants = approvals.grants();
        assert_eq!(grants.len(), 2);
        let github_id = grants
            .iter()
            .find(|g| g.label == "GitHub")
            .expect("github grant")
            .id;
        let npm_id = grants
            .iter()
            .find(|g| g.label == "npm")
            .expect("npm grant")
            .id;
        assert_ne!(github_id, npm_id);

        assert_eq!(
            approvals.revoke(github_id),
            Some(RevokedGrant::Credential {
                service: "github".into()
            })
        );
        let remaining = approvals.grants();
        assert_eq!(remaining.len(), 1, "{remaining:?}");
        assert_eq!(remaining[0].id, npm_id);

        // Already gone: revoking it again finds nothing.
        assert_eq!(approvals.revoke(github_id), None);
        // Never minted: same answer.
        assert_eq!(approvals.revoke(999), None);
    }

    #[test]
    fn revoke_removes_a_remembered_allow_session_grant_by_id() {
        let approvals = Approvals::new();
        approvals.register(approval(1)).unwrap();
        approvals.answer(1, ApprovalDecision::AllowSession).unwrap();
        approvals.wait(1, Duration::ZERO);
        assert!(approvals.remembered("Write", "/work/src/lib.rs"));
        let id = approvals.grants()[0].id;

        assert_eq!(approvals.revoke(id), Some(RevokedGrant::Approval));
        assert!(approvals.grants().is_empty());
        assert!(
            !approvals.remembered("Write", "/work/src/lib.rs"),
            "revoking the remembered answer stops it from auto-approving again"
        );
    }

    #[test]
    fn decisions_parse_print_and_serialise_as_their_words() {
        for (word, decision) in [
            ("allow", ApprovalDecision::Allow),
            ("allow-session", ApprovalDecision::AllowSession),
            ("deny", ApprovalDecision::Deny),
        ] {
            assert_eq!(word.parse::<ApprovalDecision>(), Ok(decision));
            assert_eq!(decision.to_string(), word);
            assert_eq!(
                serde_json::to_string(&decision).unwrap(),
                format!("\"{word}\"")
            );
        }
        let err = "yes".parse::<ApprovalDecision>().unwrap_err();
        assert_eq!(
            err,
            "unknown decision `yes` (one of allow, allow-session, deny)"
        );
    }

    #[test]
    fn an_answer_releases_the_hold_with_the_users_decision() {
        let approvals = Arc::new(Approvals::new());
        approvals.register(approval(3)).unwrap();
        assert_eq!(approvals.pending(), [approval(3)]);
        let waiter = {
            let approvals = Arc::clone(&approvals);
            std::thread::spawn(move || approvals.wait(3, Duration::from_secs(5)))
        };
        // The question stays pending until answered.
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(approvals.pending().len(), 1);
        approvals.answer(3, ApprovalDecision::Allow).unwrap();
        assert_eq!(
            waiter.join().unwrap(),
            Outcome::Answered(ApprovalDecision::Allow)
        );
        assert!(approvals.pending().is_empty(), "released");
        assert!(!approvals.remembered("Write", "/work/src/lib.rs"));
        let err = approvals.answer(3, ApprovalDecision::Deny).unwrap_err();
        assert_eq!(err.to_string(), "daemon: approval 3: not pending");
    }

    #[test]
    fn a_timeout_denies_and_forgets_the_question() {
        let approvals = Approvals::new();
        approvals.register(approval(1)).unwrap();
        let started = Instant::now();
        assert_eq!(
            approvals.wait(1, Duration::from_millis(50)),
            Outcome::TimedOut
        );
        assert!(started.elapsed() >= Duration::from_millis(50));
        assert!(approvals.pending().is_empty());
        assert_eq!(
            approvals.wait(1, Duration::from_millis(10)),
            Outcome::Closed,
            "waiting on a question that is gone"
        );
    }

    #[test]
    fn allow_session_is_remembered_for_the_same_tool_and_target() {
        let approvals = Approvals::new();
        approvals.register(approval(1)).unwrap();
        approvals.answer(1, ApprovalDecision::AllowSession).unwrap();
        assert_eq!(
            approvals.wait(1, Duration::from_secs(1)),
            Outcome::Answered(ApprovalDecision::AllowSession)
        );
        assert!(approvals.remembered("Write", "/work/src/lib.rs"));
        assert!(
            !approvals.remembered("Edit", "/work/src/lib.rs"),
            "same tool"
        );
        assert!(
            !approvals.remembered("Write", "/work/src/main.rs"),
            "same path"
        );
        // An answered question is no longer pending, and cannot be answered twice.
        approvals.register(approval(2)).unwrap();
        approvals.answer(2, ApprovalDecision::Deny).unwrap();
        assert!(approvals.pending().is_empty());
        assert_eq!(
            approvals
                .answer(2, ApprovalDecision::Allow)
                .unwrap_err()
                .to_string(),
            "daemon: approval 2: already answered"
        );
        assert_eq!(
            approvals.wait(2, Duration::ZERO),
            Outcome::Answered(ApprovalDecision::Deny)
        );
    }

    #[test]
    fn closing_releases_every_open_question_and_refuses_new_ones() {
        let approvals = Arc::new(Approvals::new());
        approvals.register(approval(1)).unwrap();
        let waiter = {
            let approvals = Arc::clone(&approvals);
            std::thread::spawn(move || approvals.wait(1, Duration::from_secs(5)))
        };
        std::thread::sleep(Duration::from_millis(20));
        // `close` itself hands back what it released, with each one's real
        // outcome, so the daemon can give each one its own terminal record
        // before the log can seal (#146) — it does not need to wait for
        // `wait`'s own thread to notice.
        assert_eq!(approvals.close(), [(approval(1), Outcome::Closed)]);
        assert_eq!(waiter.join().unwrap(), Outcome::Closed);
        assert!(approvals.pending().is_empty());
        let err = approvals.register(approval(2)).unwrap_err();
        assert_eq!(err.to_string(), "daemon: approval: session ended");
        // `close` recorded the release in the bounded history too, so a late
        // `ward session approvals` still shows how it ended.
        let record = approvals
            .approvals()
            .into_iter()
            .find(|r| r.approval.id == 1)
            .expect("released approval is in the history");
        assert_eq!(record.outcome, Some(Outcome::Closed));
        assert!(record.decided_at_unix_ms.is_some());
    }

    #[test]
    fn closing_hands_an_uncollected_answer_its_real_outcome_exactly_once() {
        // Review of #218, finding 1: a question already answered but not
        // yet collected by its own `wait` must not be sealed with no
        // terminal record (the old behaviour here — `close` left it alone
        // entirely and trusted the hold connection to record it later —
        // raced Stop/Seal sealing the log first). `close` now drains it
        // like any other held entry, with its real answer, so the caller
        // can append the true terminal record before the log seals.
        let approvals = Approvals::new();
        approvals.register(approval(1)).unwrap();
        approvals.answer(1, ApprovalDecision::Allow).unwrap();
        assert_eq!(
            approvals.close(),
            [(approval(1), Outcome::Answered(ApprovalDecision::Allow))],
            "close hands back the real answer, not Outcome::Closed, so the \
             caller can append the true terminal record before sealing"
        );
        // The listing already shows it decided, correctly, the moment
        // `close` returns — not still pending, and not vanished.
        let record = approvals
            .approvals()
            .into_iter()
            .find(|r| r.approval.id == 1)
            .expect("released approval is in the combined view");
        assert_eq!(
            record.outcome,
            Some(Outcome::Answered(ApprovalDecision::Allow))
        );
        // The connection that registered it still gets its real answer when
        // it finally collects, never a fabricated session-ended.
        assert_eq!(
            approvals.wait(1, Duration::ZERO),
            Outcome::Answered(ApprovalDecision::Allow),
            "its own wait still discovers the real answer, from the handoff"
        );
        // `close` already appended (through its caller) this id's terminal
        // record: the collecting caller must be told not to append a
        // second one.
        assert!(
            approvals.take_recorded(1),
            "close already recorded id 1's terminal record"
        );
        assert!(
            !approvals.take_recorded(1),
            "consulted once: a second check finds nothing left to take"
        );
    }

    #[test]
    fn the_approvals_view_lists_pending_and_bounded_history_by_request_order() {
        let approvals = Approvals::new();
        assert!(approvals.approvals().is_empty());
        // Distinct request times, so the combined view's sort has something
        // to order by (the shared `approval()` helper below always uses the
        // same one).
        let first = Approval::new(1, "Write", "/work/a.rs", authority(), 10);
        let second = Approval::new(2, "Write", "/work/b.rs", authority(), 20);
        approvals.register(first).unwrap();
        approvals.register(second).unwrap();
        approvals.answer(1, ApprovalDecision::Deny).unwrap();
        assert_eq!(
            approvals.wait(1, Duration::ZERO),
            Outcome::Answered(ApprovalDecision::Deny)
        );
        let records = approvals.approvals();
        assert_eq!(records.len(), 2, "{records:?}");
        assert_eq!(records[0].approval.id, 1, "decided, but asked first");
        assert_eq!(
            records[0].outcome,
            Some(Outcome::Answered(ApprovalDecision::Deny))
        );
        assert!(records[0].decided_at_unix_ms.is_some());
        assert_eq!(records[1].approval.id, 2, "still pending");
        assert_eq!(records[1].outcome, None);
        assert!(records[1].decided_at_unix_ms.is_none());
    }

    #[test]
    fn the_approvals_view_breaks_a_requested_at_tie_by_approval_id() {
        // Review of #218, finding 2: two requests can legitimately share a
        // millisecond timestamp. The approval's own id — the sequence
        // number of the `CapabilityRequested` record that asked it — is
        // assigned in true request order regardless, and must be the
        // tie-breaker; a sort on the timestamp alone, with pending entries
        // built before history entries, would otherwise place a later
        // pending request ahead of an earlier decided one whenever they
        // tie.
        let approvals = Approvals::new();
        let same_ms = 1_700_000_000_000;
        let earlier = Approval::new(1, "Write", "/work/a.rs", authority(), same_ms);
        let later = Approval::new(2, "Write", "/work/b.rs", authority(), same_ms);
        // Decide the *later* one first and leave the earlier one pending, so
        // a sort that only looked at `requested_at_unix_ms` (with pending
        // entries listed before history entries, both at the same
        // timestamp) would place id 2 ahead of id 1 — the wrong order.
        approvals.register(later).unwrap();
        approvals.answer(2, ApprovalDecision::Deny).unwrap();
        assert_eq!(
            approvals.wait(2, Duration::ZERO),
            Outcome::Answered(ApprovalDecision::Deny)
        );
        approvals.register(earlier).unwrap();
        let records = approvals.approvals();
        assert_eq!(records.len(), 2, "{records:?}");
        assert_eq!(records[0].approval.id, 1, "the true, earlier request");
        assert_eq!(records[1].approval.id, 2, "the true, later request");
    }

    #[test]
    fn the_decided_history_is_bounded_oldest_dropped_first() {
        // A fresh hold: only decided approvals in play, so the count is
        // exactly the history's, with nothing left pending to add to it.
        let approvals = Approvals::new();
        for id in 0..HISTORY_CAP as u64 + 5 {
            let a = Approval::new(id, "Write", "/work/x.rs", authority(), id);
            approvals.register(a).unwrap();
            approvals.answer(id, ApprovalDecision::Deny).unwrap();
            assert_eq!(
                approvals.wait(id, Duration::ZERO),
                Outcome::Answered(ApprovalDecision::Deny)
            );
        }
        let records = approvals.approvals();
        assert_eq!(records.len(), HISTORY_CAP, "{}", records.len());
        assert_eq!(
            records.first().unwrap().approval.id,
            5,
            "the oldest five were evicted"
        );
        assert_eq!(records.last().unwrap().approval.id, HISTORY_CAP as u64 + 4);
    }

    #[test]
    fn a_paused_hold_stops_the_clock_refuses_answers_and_keeps_questions() {
        let approvals = Arc::new(Approvals::new());
        approvals.register(approval(1)).unwrap();
        approvals.set_paused(true);
        assert!(approvals.paused());
        let waiter = {
            let approvals = Arc::clone(&approvals);
            std::thread::spawn(move || approvals.wait(1, Duration::from_millis(80)))
        };
        // Well past the timeout, the question is still pending: paused time
        // does not count.
        std::thread::sleep(Duration::from_millis(200));
        assert!(!waiter.is_finished());
        // Armed by `wait` while already paused, the clock has never run: it
        // reports its whole decision time, held (#146 item 4).
        let mut held = approval(1);
        held.countdown = Some(Countdown {
            remaining_ms: 80,
            timeout_ms: 80,
            held: true,
        });
        assert_eq!(approvals.pending(), [held]);
        let err = approvals.answer(1, ApprovalDecision::Allow).unwrap_err();
        assert_eq!(
            err.to_string(),
            "daemon: approval 1: paused by ward; resume the session to answer"
        );
        // A question that arrives while paused waits like the rest.
        approvals.register(approval(2)).unwrap();
        assert_eq!(approvals.pending().len(), 2);
        approvals.set_paused(false);
        approvals.answer(1, ApprovalDecision::Allow).unwrap();
        assert_eq!(
            waiter.join().unwrap(),
            Outcome::Answered(ApprovalDecision::Allow)
        );
        // Resumed, the clock runs again from where it stood.
        let started = Instant::now();
        assert_eq!(
            approvals.wait(2, Duration::from_millis(50)),
            Outcome::TimedOut
        );
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    /// The countdown the daemon reports (#146 item 4), driven entirely through
    /// the `_at` seams with instants made up from one base: nothing here
    /// sleeps or depends on how fast the machine is.
    #[test]
    fn a_countdown_runs_down_is_held_while_paused_and_runs_on_from_where_it_stood() {
        let approvals = Approvals::new();
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let countdown = |approvals: &Approvals, now: Instant| {
            let pending = approvals.pending_at(now);
            let view = approvals.approvals_at(now);
            assert_eq!(pending.len(), 1);
            assert_eq!(
                view[0].approval.countdown, pending[0].countdown,
                "the inbox and the notification read the same clock"
            );
            pending[0].countdown.expect("armed")
        };
        approvals
            .register_at(approval(1), Some(Duration::from_secs(60)), t0)
            .unwrap();
        let running = |remaining_ms| Countdown {
            remaining_ms,
            timeout_ms: 60_000,
            held: false,
        };
        let held = |remaining_ms| Countdown {
            remaining_ms,
            timeout_ms: 60_000,
            held: true,
        };
        assert_eq!(countdown(&approvals, t0), running(60_000));
        assert_eq!(countdown(&approvals, at(10)), running(50_000));
        // Paused 15 s in: held at 45 s, however long the pause lasts.
        approvals.set_paused_at(true, at(15));
        assert_eq!(countdown(&approvals, at(15)), held(45_000));
        assert_eq!(countdown(&approvals, at(500)), held(45_000));
        // A second pause signal changes nothing (idempotent hold).
        approvals.set_paused_at(true, at(600));
        assert_eq!(countdown(&approvals, at(700)), held(45_000));
        // Resumed at 1000 s: runs on from 45 s, not from 60 s.
        approvals.set_paused_at(false, at(1000));
        assert_eq!(countdown(&approvals, at(1000)), running(45_000));
        assert_eq!(countdown(&approvals, at(1040)), running(5_000));
        assert_eq!(countdown(&approvals, at(1045)), running(0));
        assert_eq!(
            countdown(&approvals, at(9999)),
            running(0),
            "never below zero"
        );

        // A question asked while paused starts held, with its whole time.
        let approvals = Approvals::new();
        approvals.set_paused_at(true, t0);
        approvals
            .register_at(approval(2), Some(Duration::from_secs(60)), at(5))
            .unwrap();
        assert_eq!(countdown(&approvals, at(100)), held(60_000));
        approvals.set_paused_at(false, at(200));
        assert_eq!(countdown(&approvals, at(230)), running(30_000));
    }

    /// The countdown is what `wait` enforces, not a separate estimate: a
    /// pause and resume after a question's time has all run out does not
    /// hand any of it back. Before #146 item 4, `wait` kept its own
    /// `remaining` and never charged the time run between its last wake and
    /// a pause, so a pause refilled it. No sleep: the clock is spent through
    /// the seams, so `wait` finds nothing left the moment it looks.
    #[test]
    fn a_pause_neither_spends_nor_refunds_the_time_wait_enforces() {
        let approvals = Approvals::new();
        let t0 = Instant::now();
        approvals
            .register_at(approval(1), Some(Duration::from_secs(60)), t0)
            .unwrap();
        // All 60 s ran before the pause landed; the resume refunds nothing.
        approvals.set_paused_at(true, t0 + Duration::from_secs(60));
        approvals.set_paused_at(false, t0 + Duration::from_secs(60));
        let started = Instant::now();
        assert_eq!(
            approvals.wait(1, Duration::from_secs(60)),
            Outcome::TimedOut,
            "the armed clock decides, not wait's own `timeout`"
        );
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "denied at once, not after a fresh 60 s"
        );
        assert_eq!(approvals.approvals()[0].outcome, Some(Outcome::TimedOut));
    }

    /// Review of #225, finding 1: a question whose clock is already spent
    /// before its `wait` ever runs cannot be approved in that gap. Before the
    /// fix `answer` never looked at the clock, so this was accepted and
    /// `wait` then returned `Answered(Allow)` for a question the daemon's own
    /// countdown already read as zero. No sleep: a zero-length clock is spent
    /// the instant it is armed.
    #[test]
    fn an_answer_to_a_question_whose_clock_ran_out_before_wait_is_refused() {
        let approvals = Approvals::new();
        approvals
            .register_with_timeout(approval(1), Duration::ZERO)
            .unwrap();
        let err = approvals.answer(1, ApprovalDecision::Allow).unwrap_err();
        assert_eq!(
            err.to_string(),
            "daemon: approval 1: timed out; its decision time ran out"
        );
        // Refused, not recorded: `wait` settles it as the timeout it is,
        // through the one ordinary path, exactly once.
        assert_eq!(
            approvals.wait(1, Duration::from_secs(60)),
            Outcome::TimedOut
        );
        let view = approvals.approvals();
        assert_eq!(view.len(), 1, "one terminal record, no more");
        assert_eq!(view[0].outcome, Some(Outcome::TimedOut));
        assert!(!approvals.take_recorded(1), "its own caller appends it");
        assert!(approvals.close().is_empty(), "nothing left for close");
        assert!(!approvals.remembered("Write", "/work/src/lib.rs"));
    }

    /// Review of #225, finding 1, the deadline race: at a real (non-zero)
    /// deadline, the connection answering can win the approvals lock before
    /// the timed-out waiter wakes and takes it back. Modelled
    /// deterministically: the answer lands, through the `_at` seam, exactly
    /// at the clock's deadline, while the waiter has not yet run. It must
    /// lose: `wait` then denies it as timed out. One tick before the
    /// deadline, the same answer is still accepted, so the line is drawn at
    /// the deadline itself and not before it.
    #[test]
    fn an_answer_racing_the_timeout_at_the_deadline_cannot_win() {
        let timeout = Duration::from_secs(60);
        // Asked a whole timeout ago, so the deadline is now: the real clock
        // `wait` reads is already at or past it, and it settles at once.
        let t0 = Instant::now()
            .checked_sub(timeout)
            .expect("the monotonic clock is past one minute");
        let deadline = t0 + timeout;
        let approvals = Approvals::new();
        approvals
            .register_at(approval(1), Some(timeout), t0)
            .unwrap();
        approvals
            .register_at(approval(2), Some(timeout), t0)
            .unwrap();

        // At the deadline: refused, however the lock race falls.
        let err = approvals
            .answer_at(1, ApprovalDecision::AllowSession, deadline)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "daemon: approval 1: timed out; its decision time ran out"
        );
        // One millisecond before it: still answerable.
        approvals
            .answer_at(
                2,
                ApprovalDecision::Allow,
                t0 + Duration::from_millis(59_999),
            )
            .unwrap();

        let started = Instant::now();
        assert_eq!(approvals.wait(1, timeout), Outcome::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the waiter finds the clock spent, not a fresh minute"
        );
        assert_eq!(
            approvals.wait(2, timeout),
            Outcome::Answered(ApprovalDecision::Allow)
        );
        // The refused allow-session left no grant behind.
        assert!(!approvals.remembered("Write", "/work/src/lib.rs"));
        // Exactly one terminal record each, handed to their own callers.
        let outcomes: Vec<_> = approvals
            .approvals()
            .into_iter()
            .map(|r| (r.approval.id, r.outcome))
            .collect();
        assert_eq!(
            outcomes,
            [
                (1, Some(Outcome::TimedOut)),
                (2, Some(Outcome::Answered(ApprovalDecision::Allow))),
            ]
        );
        assert!(!approvals.take_recorded(1));
        assert!(!approvals.take_recorded(2));
        assert!(approvals.close().is_empty());
        // Gone now: a late answer is the ordinary `not pending`.
        let err = approvals.answer(1, ApprovalDecision::Allow).unwrap_err();
        assert_eq!(err.to_string(), "daemon: approval 1: not pending");
    }

    /// Review of #225, second round, finding 1: the lock ordering, not the
    /// deadline value `an_answer_racing_the_timeout_at_the_deadline_cannot_win`
    /// pins. The public `answer` used to read `Instant::now()` *before*
    /// taking the approvals lock, so an answer entered before the deadline
    /// that then blocked on that lock (behind the timed-out waiter, or any
    /// other caller) until after the deadline was still judged by its stale,
    /// pre-lock timestamp and accepted.
    ///
    /// Review of #225, fifth round, finding 1: the fourth round's version of
    /// this test still spawned a thread and raced a 500 ms `recv_timeout`
    /// against it — generous, but still a scheduling assumption, so a
    /// reverted implementation could in principle send before the lock and
    /// still have the outer thread not observe it in time. This drops
    /// threading entirely. `answer_with` takes the approvals lock *before*
    /// calling its clock closure, so a closure that runs on this same test
    /// thread, mid-call, can prove the lock is already held by calling
    /// `try_lock` on the same `Mutex` — `std::sync::Mutex` has no concept of
    /// same-thread reentrancy, so `try_lock` from the thread already holding
    /// it deterministically reports `WouldBlock`, never `Ok`. A regression
    /// that read the clock before locking would let this same `try_lock`
    /// succeed, catching it immediately with no thread, channel, or timeout
    /// involved.
    #[test]
    fn answer_with_reads_its_clock_only_once_the_lock_is_held() {
        let timeout = Duration::from_secs(60);
        // Asked a whole timeout ago (the trick `an_answer_racing_the_timeout_
        // at_the_deadline_cannot_win` already uses): the real clock is
        // already past its deadline from this point on, so `wait` below
        // settles at once instead of genuinely blocking for 60 s, and the
        // closure can just report the real `Instant::now()` whenever it
        // happens to run rather than a fabricated value.
        let t0 = Instant::now()
            .checked_sub(timeout)
            .expect("the monotonic clock is past one minute");
        let approvals = Approvals::new();
        approvals
            .register_at(approval(1), Some(timeout), t0)
            .unwrap();

        let err = approvals
            .answer_with(1, ApprovalDecision::Allow, || {
                assert!(
                    matches!(
                        approvals.state.try_lock(),
                        Err(std::sync::TryLockError::WouldBlock)
                    ),
                    "the clock must not be read before the lock is acquired"
                );
                Instant::now()
            })
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "daemon: approval 1: timed out; its decision time ran out"
        );
        // Refused, not recorded: its own `wait` settles it once, as the
        // timeout it is.
        assert_eq!(approvals.wait(1, timeout), Outcome::TimedOut);
        let view = approvals.approvals();
        assert_eq!(view.len(), 1, "one terminal record, no more");
        assert_eq!(view[0].outcome, Some(Outcome::TimedOut));
        assert!(!approvals.take_recorded(1));
        assert!(approvals.close().is_empty());
    }

    #[test]
    fn only_an_open_question_with_an_armed_clock_carries_a_countdown() {
        let approvals = Approvals::new();
        let t0 = Instant::now();
        // Registered without a clock: nothing to report until `wait` arms one.
        approvals.register_at(approval(1), None, t0).unwrap();
        assert_eq!(approvals.pending_at(t0)[0].countdown, None);
        // Armed, then answered but not yet collected: still listed as
        // pending in the view, but its clock no longer decides anything.
        approvals
            .register_at(approval(2), Some(Duration::from_secs(60)), t0)
            .unwrap();
        approvals.answer(2, ApprovalDecision::Deny).unwrap();
        let view = approvals.approvals_at(t0);
        let two = view.iter().find(|r| r.approval.id == 2).unwrap();
        assert_eq!(two.outcome, None);
        assert_eq!(two.approval.countdown, None);
        // Collected: the history keeps the question, never a countdown.
        assert_eq!(
            approvals.wait(2, Duration::from_secs(60)),
            Outcome::Answered(ApprovalDecision::Deny)
        );
        let view = approvals.approvals_at(t0);
        let two = view.iter().find(|r| r.approval.id == 2).unwrap();
        assert!(two.outcome.is_some());
        assert_eq!(two.approval.countdown, None);
        assert_eq!(
            two.approval,
            approval(2),
            "the stored question is untouched"
        );
    }

    #[test]
    fn a_countdown_travels_as_json_only_when_there_is_one_and_reads_as_words() {
        let mut open = approval(1);
        let json = serde_json::to_string(&open).unwrap();
        assert!(!json.contains("countdown"), "absent when None: {json}");
        assert_eq!(serde_json::from_str::<Approval>(&json).unwrap(), open);
        open.countdown = Some(Countdown {
            remaining_ms: 41_001,
            timeout_ms: 60_000,
            held: false,
        });
        let json = serde_json::to_string(&open).unwrap();
        assert!(
            json.ends_with(
                r#","countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}"#
            ),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<Approval>(&json).unwrap(), open);
        // Whole seconds, rounded up: `0 s` only when none is left.
        let words = |remaining_ms, held| {
            Countdown {
                remaining_ms,
                timeout_ms: 60_000,
                held,
            }
            .text()
        };
        assert_eq!(words(41_001, false), "42 s left, then denied");
        assert_eq!(words(1, false), "1 s left, then denied");
        assert_eq!(words(0, false), "0 s left, then denied");
        assert_eq!(
            words(45_000, true),
            "held while paused · 45 s left once resumed"
        );
        // The inbox's plain-text row carries it after the destination.
        let record = ApprovalRecord {
            approval: open,
            outcome: None,
            decided_at_unix_ms: None,
        };
        assert!(
            record.line().ends_with("  (42 s left, then denied)"),
            "{}",
            record.line()
        );
    }

    #[test]
    fn outcomes_become_hook_responses_and_log_records() {
        let cases = [
            (
                Outcome::Answered(ApprovalDecision::Allow),
                HookDecision::Allow,
                "approval: allowed once",
                (
                    Decision::Allow,
                    DecisionSource::User,
                    Some(GrantScope::Once),
                ),
            ),
            (
                Outcome::Answered(ApprovalDecision::AllowSession),
                HookDecision::Allow,
                "approval: allowed for the session",
                (
                    Decision::Allow,
                    DecisionSource::User,
                    Some(GrantScope::Session),
                ),
            ),
            (
                Outcome::Remembered,
                HookDecision::Allow,
                "approval: allowed for the session",
                (
                    Decision::Allow,
                    DecisionSource::User,
                    Some(GrantScope::Session),
                ),
            ),
            (
                Outcome::Answered(ApprovalDecision::Deny),
                HookDecision::Deny,
                "approval: denied",
                (Decision::Deny, DecisionSource::User, None),
            ),
            (
                Outcome::TimedOut,
                HookDecision::Deny,
                "approval: timed out",
                (Decision::Deny, DecisionSource::Timeout, None),
            ),
            (
                // Since #146: the session ending with the question open now
                // gets its own terminal record too, distinguishable from a
                // timeout by `DecisionSource::SessionEnded` — it used to be
                // dropped with no record at all (`decided_event` returned
                // `None`).
                Outcome::Closed,
                HookDecision::Deny,
                "approval: session ended",
                (Decision::Deny, DecisionSource::SessionEnded, None),
            ),
        ];
        for (outcome, decision, reason, (want_decision, want_by, want_grant)) in cases {
            let response = outcome.response();
            assert_eq!(response.decision, decision, "{outcome:?}");
            assert_eq!(response.reason, reason, "{outcome:?}");
            match decided_event("Write", "/work/src/lib.rs", outcome) {
                WardEvent::CapabilityDecided {
                    cap,
                    decision,
                    by,
                    grant,
                } => {
                    assert_eq!(cap.kind, CapabilityKind::FileWrite);
                    assert_eq!(cap.target.as_str(), "Write /work/src/lib.rs");
                    assert_eq!(decision, want_decision, "{outcome:?}");
                    assert_eq!(by, want_by, "{outcome:?}");
                    assert_eq!(grant, want_grant, "{outcome:?}");
                }
                other => panic!("{outcome:?}: {other:?}"),
            }
        }
        match requested_event(
            "WebFetch",
            "api.github.com",
            "step-through: pause before network",
        ) {
            WardEvent::CapabilityRequested { cap, reason } => {
                assert_eq!(cap.kind, CapabilityKind::Network);
                assert_eq!(cap.target.as_str(), "WebFetch api.github.com");
                assert_eq!(
                    reason.unwrap().as_str(),
                    "step-through: pause before network"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(capability_kind("Bash"), CapabilityKind::Exec);
        assert_eq!(capability_kind("Read"), CapabilityKind::FileRead);
        assert_eq!(capability_kind("Task"), CapabilityKind::Other);
    }
}
