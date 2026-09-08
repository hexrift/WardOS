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
//! that arrives waits like the rest. It knows nothing about sockets or the
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

use std::collections::BTreeMap;
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

    /// The grant an `allow-session` answer to this question makes.
    #[must_use]
    pub fn session_grant(&self, granted_at_unix_ms: u64) -> Grant {
        Grant {
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
    /// Until the launch that made it ends (a proxy route).
    Launch,
}

impl Lifetime {
    /// The word on the wire and on the panel.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Session => "session",
            Self::Launch => "launch",
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
    /// The service (`github`).
    pub service: String,
    /// The upstream hosts the routes cover.
    pub hosts: Vec<String>,
    /// The permissions recorded in the grant.
    pub permissions: Vec<String>,
    /// When, milliseconds since the Unix epoch.
    pub granted_at_unix_ms: u64,
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
    /// The grant as one line: label, scope, lifetime.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "{}   {}   {}",
            self.label,
            self.scope,
            self.lifetime.as_str()
        )
    }
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The user answered.
    Answered(ApprovalDecision),
    /// An earlier `allow-session` for the same tool and target covered it.
    Remembered,
    /// Nobody answered in time.
    TimedOut,
    /// The session ended with the question open.
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

/// One held question and its answer, once there is one.
#[derive(Debug)]
struct Held {
    approval: Approval,
    answer: Option<ApprovalDecision>,
}

#[derive(Debug, Default)]
struct State {
    held: Vec<Held>,
    /// The grant an `allow-session` made, by the `(tool, summary)` it covers.
    remembered: BTreeMap<(String, String), Grant>,
    /// The credentials the launches granted, one per service and scope.
    credentials: Vec<Credential>,
    closed: bool,
    /// The session is paused: timeouts stand still and answers are refused.
    paused: bool,
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

    /// A credential the launch granted for `host` with `permissions`; a second
    /// route of the same service and permissions adds its host.
    pub fn record_credential(
        &self,
        service: &str,
        host: &str,
        permissions: Vec<String>,
        granted_at_unix_ms: u64,
    ) {
        let mut state = self.lock();
        if let Some(c) = state
            .credentials
            .iter_mut()
            .find(|c| c.service == service && c.permissions == permissions)
        {
            if !c.hosts.iter().any(|h| h == host) {
                c.hosts.push(host.to_owned());
            }
            return;
        }
        state.credentials.push(Credential {
            service: service.to_owned(),
            hosts: vec![host.to_owned()],
            permissions,
            granted_at_unix_ms,
        });
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
                kind: GrantKind::Credential,
                label: service_name(&c.service),
                scope: format!("{} · {}", c.permissions.join(", "), c.hosts.join(", ")),
                lifetime: Lifetime::Launch,
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

    /// Register a question. Refused once the session has ended.
    pub fn register(&self, approval: Approval) -> Result<()> {
        let mut state = self.lock();
        if state.closed {
            return Err(Error::Daemon("approval: session ended".into()));
        }
        state.held.push(Held {
            approval,
            answer: None,
        });
        drop(state);
        self.changed.notify_all();
        Ok(())
    }

    /// Wait up to `timeout` for the answer to `id`, then forget the question.
    /// The answer stays remembered when it was `allow-session`. Time spent
    /// paused does not count against the timeout.
    pub fn wait(&self, id: u64, timeout: Duration) -> Outcome {
        let mut remaining = timeout;
        let mut last = Instant::now();
        let mut state = self.lock();
        loop {
            let Some(index) = state.held.iter().position(|h| h.approval.id == id) else {
                return Outcome::Closed;
            };
            if let Some(answer) = state.held[index].answer {
                let held = state.held.remove(index);
                if answer == ApprovalDecision::AllowSession {
                    let grant = held.approval.session_grant(now_unix_ms());
                    state
                        .remembered
                        .insert((held.approval.tool, held.approval.summary), grant);
                }
                return Outcome::Answered(answer);
            }
            if state.closed {
                state.held.remove(index);
                return Outcome::Closed;
            }
            if state.paused {
                // Held in turn: wake on any change, and count none of this time.
                state = self
                    .changed
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
                last = Instant::now();
                continue;
            }
            let now = Instant::now();
            remaining = remaining.saturating_sub(now - last);
            last = now;
            if remaining.is_zero() {
                state.held.remove(index);
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
    /// a second answer to the same open question is too.
    pub fn answer(&self, id: u64, decision: ApprovalDecision) -> Result<()> {
        let mut state = self.lock();
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
        held.answer = Some(decision);
        drop(state);
        self.changed.notify_all();
        Ok(())
    }

    /// The open questions, oldest first.
    #[must_use]
    pub fn pending(&self) -> Vec<Approval> {
        self.lock()
            .held
            .iter()
            .filter(|h| h.answer.is_none())
            .map(|h| h.approval.clone())
            .collect()
    }

    /// The session ended: every open question is released as denied, and no
    /// new one is taken.
    pub fn close(&self) {
        self.lock().closed = true;
        self.changed.notify_all();
    }

    /// Pause or resume the hold (ADR-0019 §3): paused, pending questions stay
    /// pending with their timeouts stopped, answers are refused, and new
    /// questions wait like the rest.
    pub fn set_paused(&self, paused: bool) {
        self.lock().paused = paused;
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

/// The record that answers: `CapabilityDecided` by the user (with the grant's
/// scope) or by the timeout. A question the session's end released has no
/// record: the log is sealed by then.
#[must_use]
pub fn decided_event(tool: &str, summary: &str, outcome: Outcome) -> Option<WardEvent> {
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
        Outcome::Closed => return None,
    };
    Some(WardEvent::CapabilityDecided {
        cap: capability(tool, summary),
        decision,
        by,
        grant,
    })
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
            service: "github".into(),
            hosts: vec!["github.com".into(), "api.github.com".into()],
            permissions: vec!["contents:read".into(), "issues:read".into()],
            granted_at_unix_ms: 1,
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
        approvals.record_credential("github", "github.com", perms(), 1);
        approvals.record_credential("github", "api.github.com", perms(), 2);
        approvals.record_credential("github", "api.github.com", perms(), 3);
        assert_eq!(
            approvals.credentials(),
            [Credential {
                service: "github".into(),
                hosts: vec!["github.com".into(), "api.github.com".into()],
                permissions: perms(),
                granted_at_unix_ms: 1,
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
        assert_eq!(
            grants[0].line(),
            "GitHub   contents:read, issues:read · github.com, api.github.com   launch"
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
        approvals.close();
        assert_eq!(waiter.join().unwrap(), Outcome::Closed);
        assert!(approvals.pending().is_empty());
        let err = approvals.register(approval(2)).unwrap_err();
        assert_eq!(err.to_string(), "daemon: approval: session ended");
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
        assert_eq!(approvals.pending(), [approval(1)]);
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

    #[test]
    fn outcomes_become_hook_responses_and_log_records() {
        let cases = [
            (
                Outcome::Answered(ApprovalDecision::Allow),
                HookDecision::Allow,
                "approval: allowed once",
                Some((
                    Decision::Allow,
                    DecisionSource::User,
                    Some(GrantScope::Once),
                )),
            ),
            (
                Outcome::Answered(ApprovalDecision::AllowSession),
                HookDecision::Allow,
                "approval: allowed for the session",
                Some((
                    Decision::Allow,
                    DecisionSource::User,
                    Some(GrantScope::Session),
                )),
            ),
            (
                Outcome::Remembered,
                HookDecision::Allow,
                "approval: allowed for the session",
                Some((
                    Decision::Allow,
                    DecisionSource::User,
                    Some(GrantScope::Session),
                )),
            ),
            (
                Outcome::Answered(ApprovalDecision::Deny),
                HookDecision::Deny,
                "approval: denied",
                Some((Decision::Deny, DecisionSource::User, None)),
            ),
            (
                Outcome::TimedOut,
                HookDecision::Deny,
                "approval: timed out",
                Some((Decision::Deny, DecisionSource::Timeout, None)),
            ),
            (
                Outcome::Closed,
                HookDecision::Deny,
                "approval: session ended",
                None,
            ),
        ];
        for (outcome, decision, reason, record) in cases {
            let response = outcome.response();
            assert_eq!(response.decision, decision, "{outcome:?}");
            assert_eq!(response.reason, reason, "{outcome:?}");
            let event = decided_event("Write", "/work/src/lib.rs", outcome);
            match (event, record) {
                (None, None) => {}
                (
                    Some(WardEvent::CapabilityDecided {
                        cap,
                        decision,
                        by,
                        grant,
                    }),
                    Some((want_decision, want_by, want_grant)),
                ) => {
                    assert_eq!(cap.kind, CapabilityKind::FileWrite);
                    assert_eq!(cap.target.as_str(), "Write /work/src/lib.rs");
                    assert_eq!(decision, want_decision, "{outcome:?}");
                    assert_eq!(by, want_by, "{outcome:?}");
                    assert_eq!(grant, want_grant, "{outcome:?}");
                }
                (event, record) => panic!("{outcome:?}: {event:?} vs {record:?}"),
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
