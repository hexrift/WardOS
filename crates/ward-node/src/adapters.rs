//! Agent adapters hosted on admitted workloads (#279, ADR-0036).
//!
//! A node started with `--agent-adapter <id>` ([`crate::execution::NodeExecution::with_agent_adapters`])
//! runs a workload whose envelope names that adapter ([`ward_node_protocol::WorkloadAdapter`])
//! through the adapter contract of `ward-agent-adapter`: the launch is
//! [`ward_agent_adapter::catalogue::launch`] of the adapter's id over the admitted argv, the
//! same builder `ward-daemon`'s sessions use, so the program runs with the adapter's fixed
//! arguments, its non-secret environment and its settings files, and nothing else. A
//! launch spec cannot name a mount, a network rule, a credential, a working directory or a
//! variable the node owns; the sandbox, the attempt's proxy and allowlist, its leased
//! credentials, its holds, its action channel and its limits are built from the capability
//! manifest exactly as for any workload, whichever adapter runs.
//!
//! What a hosted adapter adds, beside the workspace in the attempt's private directory
//! `<task-root>/<task>/<attempt>.adapter/` (mode 0700, [`adapter_dir_beside`]):
//!
//! * its settings files, written there mode 0600 and bound read-only at their path under
//!   the sandbox home;
//! * for an adapter whose capability document declares semantic events (Claude Code), the
//!   attempt's hook socket ([`AttemptHooks`]), bound at [`ward_launch::HOOK_SOCKET`] and
//!   named by `WARD_SOCKET`: one contract-1.0 [`SemanticEventLine`] per connection, read
//!   within [`MAX_HOOK_LINE_BYTES`] and [`HOOK_READ_DEADLINE`], answered with one
//!   [`ApprovalAnswer`] `allow`, and queued as an `AgentClaim` the registry appends with
//!   origin `agent`, at most [`MAX_ATTEMPT_CLAIMS`] per attempt and the rest counted for
//!   one `ObservationsDropped` marker. A malformed line is answered with nothing. A hookless
//!   adapter gets no socket: it has less to say, and nothing else.
//!
//! The answer is steering, never authority: nothing the node enforces reads a claim, so
//! an agent that claims an approval has gained nothing the sandbox, the proxy or a hold
//! refuses. The node's own approval is the hold (ADR-0035). Each attempt also records one
//! `agent_adapter` binding ([`AttemptAdapter::binding_event`]) right after its launch
//! record, with origin `agent`: metadata, never identity or authority.
//!
//! On a node with the operator's `ward-agent` shim ([`crate::shim`], ADR-0037) the attempt
//! runs under it, so a command hook such as Claude Code's `ward-agent hook` reaches the
//! socket; a hook's `PermissionRequest` is answered and recorded like any other line, never
//! bridged onto the action channel, since the approval the node enforces is the hold.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nix::sys::socket::{Shutdown as SocketShutdown, shutdown};
use thiserror::Error;
use ward_agent_adapter::catalogue::{self, AdapterLaunch, AdapterLaunchError};
use ward_agent_adapter::{
    ApprovalAnswer, ApprovalDecision, BindingClaim, ProviderId, SemanticEvent, SemanticEventLine,
};
use ward_events::{ClaimKind, ObserverSource, PayloadText, WardEvent};
use ward_node_protocol::{AdapterCapabilities, TaskBinding, TaskWorkload};

use crate::evidence::private_dir;

/// Suffix of an attempt's adapter directory, beside its workspace.
pub const ADAPTER_SUFFIX: &str = ".adapter";

/// File name of the hook socket inside an attempt's adapter directory.
pub const HOOK_SOCKET_FILE: &str = "hooks.sock";

/// Claims one attempt records; past it they are counted for one `ObservationsDropped`.
pub const MAX_ATTEMPT_CLAIMS: usize = 256;

/// Connections one hook socket serves at once; a further one is closed unread.
pub const MAX_HOOK_CONNECTIONS: usize = 8;

/// Longest hook line, newline excluded.
pub const MAX_HOOK_LINE_BYTES: usize = 4096;

/// How long a hook connection may take to send its line.
pub const HOOK_READ_DEADLINE: Duration = Duration::from_secs(5);

/// The reason every hook answer carries.
pub const HOOK_ANSWER_REASON: &str = "recorded by ward-node as a claim";

const ACCEPT_RETRY: Duration = Duration::from_millis(10);
const ANSWER_TIMEOUT: Duration = Duration::from_secs(1);

/// Why an attempt's adapter could not be prepared.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// The directory, a settings file or the hook socket could not be created.
    #[error("adapter I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The directory is not a private directory.
    #[error("adapter directory is not a private directory")]
    InsecurePath,
}

/// The adapter directory of `binding` under the task root `root`:
/// `<root>/<task>/<attempt>.adapter`.
#[must_use]
pub fn adapter_dir(root: &Path, binding: TaskBinding) -> PathBuf {
    root.join(binding.task().to_string())
        .join(format!("{}{ADAPTER_SUFFIX}", binding.attempt()))
}

/// The adapter directory beside the attempt workspace `workspace`.
#[must_use]
pub fn adapter_dir_beside(workspace: &Path) -> Option<PathBuf> {
    let attempt = workspace.file_name()?.to_str()?;
    Some(workspace.with_file_name(format!("{attempt}{ADAPTER_SUFFIX}")))
}

/// The launch of the adapter `workload` names, built from its argv by the shared
/// catalogue; `None` for a workload that names none.
#[must_use]
pub fn workload_launch(
    workload: &TaskWorkload,
) -> Option<Result<AdapterLaunch, AdapterLaunchError>> {
    let adapter = workload.adapter()?;
    Some(catalogue::launch(
        adapter.id().as_str(),
        workload.argv().args(),
    ))
}

/// Whether a node hosting `hosted` can run `workload`: it names no adapter, or one the node
/// hosts whose launch can be built from its argv.
#[must_use]
pub fn honours(hosted: Option<AdapterCapabilities>, workload: &TaskWorkload) -> bool {
    match workload.adapter() {
        None => true,
        Some(adapter) => {
            hosted.is_some_and(|hosted| hosted.hosts_id(adapter.id().as_str()))
                && workload_launch(workload).is_some_and(|launch| launch.is_ok())
        }
    }
}

/// The evidence record of an adapter binding: `AgentClaim { Note }` whose payload is
/// `{"agent_adapter":{…}}`, appended with origin `agent`.
#[must_use]
pub fn binding_event(launch: &AdapterLaunch) -> WardEvent {
    let claim = BindingClaim {
        agent_adapter: launch.binding().clone(),
    };
    let json = serde_json::to_string(&claim).unwrap_or_default();
    WardEvent::AgentClaim {
        kind: ClaimKind::Note,
        payload: PayloadText::new(&json),
    }
}

/// The claim a hook line records, spelled as a session records it: a tool event is a
/// `ToolUse` claim `"<hook> <tool> <summary> → allow"` (`PostToolUse` without the
/// answer), `SessionStart` and `Stop` a `Note` naming the hook.
#[must_use]
pub fn claim_event(line: &SemanticEventLine) -> WardEvent {
    let hook = line.hook().as_str();
    let (kind, text) = match line.tool() {
        Some(tool) => {
            let summary = line.summary().unwrap_or_default();
            let text = if line.hook() == SemanticEvent::PostToolUse {
                format!("{hook} {tool} {summary}")
            } else {
                format!("{hook} {tool} {summary} → allow")
            };
            (ClaimKind::ToolUse, text)
        }
        None => (ClaimKind::Note, hook.to_owned()),
    };
    WardEvent::AgentClaim {
        kind,
        payload: PayloadText::new(&text),
    }
}

/// The marker for `dropped` claims an attempt could not record.
#[must_use]
pub fn overflow_marker(dropped: u64) -> WardEvent {
    WardEvent::ObservationsDropped {
        source: ObserverSource::Hook,
        dropped,
        capacity: u64::try_from(MAX_ATTEMPT_CLAIMS).unwrap_or(u64::MAX),
    }
}

/// One attempt's adapter: its launch, its seeded settings files and its hook socket.
#[derive(Debug)]
pub struct AttemptAdapter {
    launch: AdapterLaunch,
    seeds: Vec<(PathBuf, String)>,
    hooks: Option<AttemptHooks>,
    dir: PathBuf,
}

impl AttemptAdapter {
    /// Prepare `launch` in the private directory `dir`: write its settings files and, for
    /// an adapter that declares semantic events, listen on its hook socket.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] when the directory is not private or a file or the socket
    /// cannot be created; nothing is left behind.
    pub fn start(dir: &Path, launch: AdapterLaunch) -> Result<Self, AdapterError> {
        private_dir(dir).map_err(|error| match error {
            crate::evidence::EvidenceError::Io(error) => AdapterError::Io(error),
            _ => AdapterError::InsecurePath,
        })?;
        let mut adapter = Self {
            launch,
            seeds: Vec::new(),
            hooks: None,
            dir: dir.to_path_buf(),
        };
        for (index, settings) in adapter.launch.spec().settings().iter().enumerate() {
            let file = dir.join(format!("settings-{index}"));
            let mut handle = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&file)?;
            handle.write_all(settings.content.as_bytes())?;
            handle.sync_all()?;
            adapter.seeds.push((file, settings.path.clone()));
        }
        if !adapter.launch.document().events().is_empty() {
            adapter.hooks = Some(AttemptHooks::start(dir)?);
        }
        Ok(adapter)
    }

    /// The command line the sandbox runs.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        self.launch.argv()
    }

    /// The adapter's environment.
    #[must_use]
    pub fn env(&self) -> Vec<(String, String)> {
        self.launch
            .spec()
            .env()
            .iter()
            .map(|var| (var.name.clone(), var.value.clone()))
            .collect()
    }

    /// The adapter's provider, if it names one: metadata the node points a base URL at only
    /// for a provider the manifest grants a credential for ([`crate::shim::relay_env`]).
    #[must_use]
    pub fn provider(&self) -> Option<&str> {
        self.launch.spec().provider().map(ProviderId::as_str)
    }

    /// The settings files: each host file and the sandbox path it is bound at, read-only.
    #[must_use]
    pub fn seeds(&self) -> &[(PathBuf, String)] {
        &self.seeds
    }

    /// The hook socket's host path; `None` for a hookless adapter.
    #[must_use]
    pub fn hook_socket(&self) -> Option<&Path> {
        self.hooks.as_ref().map(AttemptHooks::socket)
    }

    /// The hook socket; `None` for a hookless adapter.
    #[must_use]
    pub const fn hooks(&self) -> Option<&AttemptHooks> {
        self.hooks.as_ref()
    }

    /// The binding's evidence record.
    #[must_use]
    pub fn binding_event(&self) -> WardEvent {
        binding_event(&self.launch)
    }

    /// The attempt has ended: close the hook socket, append what it queued through
    /// `claim`, remove the directory, and return how many claims could not be recorded.
    pub fn finish(&self, claim: &mut dyn FnMut(WardEvent) -> bool) -> u64 {
        let dropped = self.hooks.as_ref().map_or(0, |hooks| hooks.finish(claim));
        let _ = std::fs::remove_dir_all(&self.dir);
        dropped
    }
}

impl Drop for AttemptAdapter {
    fn drop(&mut self) {
        drop(self.hooks.take());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// An attempt's hook socket (see the module docs).
#[derive(Debug)]
pub struct AttemptHooks {
    shared: Arc<Shared>,
    accept: Mutex<Option<JoinHandle<()>>>,
    _dir: File,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    listener: UnixListener,
    socket: PathBuf,
}

#[derive(Debug, Default)]
struct State {
    queue: Vec<WardEvent>,
    accepted: usize,
    dropped: u64,
    connections: usize,
    closed: bool,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn shut(&self, state: &mut State) {
        state.closed = true;
        // A shut-down listening socket wakes a blocked accept with an error.
        let _ = shutdown(self.listener.as_raw_fd(), SocketShutdown::Both);
        let _ = std::fs::remove_file(&self.socket);
    }

    /// Queue `line`'s claim, within the attempt's bound; false once the socket closed.
    fn queue(&self, line: &SemanticEventLine) -> bool {
        let mut state = self.lock();
        if state.closed {
            return false;
        }
        if state.accepted < MAX_ATTEMPT_CLAIMS {
            state.accepted += 1;
            state.queue.push(claim_event(line));
        } else {
            state.dropped = state.dropped.saturating_add(1);
        }
        true
    }

    fn flush(state: &mut State, claim: &mut dyn FnMut(WardEvent) -> bool) {
        for event in std::mem::take(&mut state.queue) {
            if !claim(event) {
                state.dropped = state.dropped.saturating_add(1);
            }
        }
    }
}

impl AttemptHooks {
    /// Listen on [`HOOK_SOCKET_FILE`] in the private directory `dir`.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] when the socket cannot be bound.
    pub fn start(dir: &Path) -> Result<Self, AdapterError> {
        let held = File::open(dir)?;
        let bind = PathBuf::from(format!(
            "/proc/self/fd/{}/{HOOK_SOCKET_FILE}",
            held.as_raw_fd()
        ));
        let socket = dir.join(HOOK_SOCKET_FILE);
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&bind)?;
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            listener: listener.try_clone()?,
            socket,
        });
        let accepting = Arc::clone(&shared);
        let accept = std::thread::Builder::new()
            .name("ward-node-hooks".to_owned())
            .spawn(move || accept_loop(&accepting, &listener))?;
        Ok(Self {
            shared,
            accept: Mutex::new(Some(accept)),
            _dir: held,
        })
    }

    /// Host path of the socket the sandbox binds at [`ward_launch::HOOK_SOCKET`].
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.shared.socket
    }

    /// Whether claims are queued for the registry.
    #[must_use]
    pub fn due(&self) -> bool {
        !self.shared.lock().queue.is_empty()
    }

    /// Append the queued claims through `claim`, oldest first; a claim it refuses is
    /// counted as dropped.
    pub fn flush(&self, claim: &mut dyn FnMut(WardEvent) -> bool) {
        Shared::flush(&mut self.shared.lock(), claim);
    }

    /// Close the socket, append what it queued through `claim` and return, once, how many
    /// claims could not be recorded.
    pub fn finish(&self, claim: &mut dyn FnMut(WardEvent) -> bool) -> u64 {
        let mut state = self.shared.lock();
        if !state.closed {
            self.shared.shut(&mut state);
        }
        Shared::flush(&mut state, claim);
        std::mem::take(&mut state.dropped)
    }
}

impl Drop for AttemptHooks {
    fn drop(&mut self) {
        {
            let mut state = self.shared.lock();
            if !state.closed {
                self.shared.shut(&mut state);
            }
        }
        if let Some(accept) = self
            .accept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = accept.join();
        }
    }
}

fn accept_loop(shared: &Arc<Shared>, listener: &UnixListener) {
    loop {
        let accepted = listener.accept();
        let mut state = shared.lock();
        if state.closed {
            return;
        }
        let Ok((stream, _)) = accepted else {
            drop(state);
            std::thread::sleep(ACCEPT_RETRY);
            continue;
        };
        if state.connections >= MAX_HOOK_CONNECTIONS {
            state.dropped = state.dropped.saturating_add(1);
            continue;
        }
        state.connections += 1;
        drop(state);
        let serving = Arc::clone(shared);
        let spawned = std::thread::Builder::new()
            .name("ward-node-hook".to_owned())
            .spawn(move || {
                serve(&serving, stream);
                serving.lock().connections -= 1;
            });
        if spawned.is_err() {
            shared.lock().connections -= 1;
        }
    }
}

/// Serve one connection: one line in, its claim queued, one answer out; nothing for a line
/// outside the contract.
fn serve(shared: &Shared, mut stream: UnixStream) {
    let Some(line) = read_line(&stream, Instant::now() + HOOK_READ_DEADLINE) else {
        return;
    };
    let Ok(line) = serde_json::from_slice::<SemanticEventLine>(&line) else {
        return;
    };
    if !shared.queue(&line) {
        return;
    }
    let answer = ApprovalAnswer {
        decision: ApprovalDecision::Allow,
        reason: HOOK_ANSWER_REASON.to_owned(),
    };
    if let Ok(mut json) = serde_json::to_vec(&answer) {
        json.push(b'\n');
        let _ = stream.set_write_timeout(Some(ANSWER_TIMEOUT));
        let _ = stream.write_all(&json);
    }
}

/// One newline-terminated line of at most [`MAX_HOOK_LINE_BYTES`], read before
/// `deadline`; `None` otherwise.
fn read_line(mut stream: &UnixStream, deadline: Instant) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        stream.set_read_timeout(Some(left)).ok()?;
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        line.extend_from_slice(&chunk[..read]);
        if let Some(end) = line.iter().position(|byte| *byte == b'\n') {
            if end > MAX_HOOK_LINE_BYTES {
                return None;
            }
            line.truncate(end);
            return Some(line);
        }
        if line.len() > MAX_HOOK_LINE_BYTES {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::PermissionsExt;

    use ward_events::{Blake3Hash, SnapshotId};
    use ward_node_protocol::{
        CapabilityManifestBytes, HostedAdapter, WorkloadAdapter, WorkloadArgv,
    };

    use super::*;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(ToString::to_string).collect()
    }

    fn workload(argv: &[&str], adapter: Option<&str>) -> TaskWorkload {
        let workload = TaskWorkload::new(
            WorkloadArgv::new(s(argv)).unwrap(),
            CapabilityManifestBytes::new(br#"{"network":"offline"}"#.to_vec()).unwrap(),
            SnapshotId::new(Blake3Hash::from_bytes([1; 32])),
            1000,
        )
        .unwrap();
        match adapter {
            Some(id) => workload
                .with_adapter(WorkloadAdapter::new(
                    ward_agent_adapter::AdapterId::new(id).unwrap(),
                ))
                .unwrap(),
            None => workload,
        }
    }

    fn private(dir: &Path) -> PathBuf {
        let path = dir.join("exec.adapter");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn exchange(socket: &Path, line: &[u8]) -> String {
        let mut stream = UnixStream::connect(socket).unwrap();
        stream.write_all(line).unwrap();
        let mut answer = String::new();
        let _ = BufReader::new(stream).read_line(&mut answer);
        answer
    }

    #[test]
    fn a_node_honours_only_an_adapter_it_hosts_and_can_launch() {
        let hosted = AdapterCapabilities::hosting([HostedAdapter::Codex, HostedAdapter::Process]);
        assert!(honours(None, &workload(&["sh"], None)));
        assert!(honours(
            hosted,
            &workload(&["codex", "exec"], Some("codex"))
        ));
        assert!(honours(
            hosted,
            &workload(&["/work/agent"], Some("process"))
        ));
        assert!(!honours(
            hosted,
            &workload(&["claude"], Some("claude-code"))
        ));
        assert!(!honours(hosted, &workload(&["gemini"], Some("gemini-cli"))));
        assert!(!honours(None, &workload(&["codex"], Some("codex"))));
        assert!(
            !honours(
                hosted,
                &workload(&["codex", "--model", "a\u{7}"], Some("codex"))
            ),
            "a launch whose binding cannot be recorded is not hosted"
        );
        assert!(workload_launch(&workload(&["sh"], None)).is_none());
    }

    #[test]
    fn every_adapter_launch_differs_only_in_command_environment_and_settings() {
        let dir = tempfile::tempdir().unwrap();
        let claude = AttemptAdapter::start(
            &private(dir.path()),
            workload_launch(&workload(&["/opt/claude", "-p", "x"], Some("claude-code")))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claude.argv(), s(&["/opt/claude", "-p", "x"]));
        let [(file, path)] = claude.seeds() else {
            panic!("one settings file")
        };
        assert_eq!(path, "/home/agent/.claude/settings.json");
        assert_eq!(
            std::fs::read_to_string(file).unwrap(),
            catalogue::claude_code_settings()
        );
        assert_eq!(
            std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(claude.hook_socket().unwrap().exists());
        for (name, _) in claude.env() {
            assert!(
                !ward_agent_adapter::launch::is_reserved_env(&name),
                "{name}"
            );
        }

        let other = tempfile::tempdir().unwrap();
        let codex = AttemptAdapter::start(
            &private(other.path()),
            workload_launch(&workload(&["codex"], Some("codex")))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(codex.seeds().is_empty());
        assert!(
            codex.hook_socket().is_none(),
            "a hookless adapter gets no socket"
        );
        assert_eq!(
            codex.env(),
            [("CODEX_HOME".to_owned(), "/home/agent/.codex".to_owned())]
        );
        let adapter_dir = claude.dir.clone();
        drop(claude);
        assert!(!adapter_dir.exists(), "the directory goes with the attempt");
        assert!(
            AttemptAdapter::start(
                &dir.path().join("missing/deeper"),
                workload_launch(&workload(&["codex"], Some("codex")))
                    .unwrap()
                    .unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn the_binding_is_an_agent_note_carrying_the_contracts_binding() {
        let launch = workload_launch(&workload(&["codex", "-m", "o4"], Some("codex")))
            .unwrap()
            .unwrap();
        let WardEvent::AgentClaim { kind, payload } = binding_event(&launch) else {
            panic!("a claim")
        };
        assert_eq!(kind, ClaimKind::Note);
        let claim: BindingClaim = serde_json::from_str(payload.content()).unwrap();
        assert_eq!(claim.agent_adapter, *launch.binding());
        assert_eq!(claim.agent_adapter.model(), Some("o4"));
    }

    #[test]
    fn a_hook_line_is_queued_as_a_claim_and_answered_allow() {
        let dir = tempfile::tempdir().unwrap();
        let hooks = AttemptHooks::start(&private(dir.path())).unwrap();
        let answer = exchange(
            hooks.socket(),
            br#"{"hook":"PreToolUse","tool":"Write","summary":"/work/a.rs"}
"#,
        );
        let answer: ApprovalAnswer = serde_json::from_str(answer.trim()).unwrap();
        assert_eq!(answer.decision, ApprovalDecision::Allow);
        assert_eq!(answer.reason, HOOK_ANSWER_REASON);
        exchange(
            hooks.socket(),
            b"{\"hook\":\"PostToolUse\",\"tool\":\"Write\",\"summary\":\"/work/a.rs\"}\n",
        );
        exchange(hooks.socket(), b"{\"hook\":\"Stop\"}\n");
        assert!(hooks.due());
        let mut recorded = Vec::new();
        hooks.flush(&mut |event| {
            recorded.push(event);
            true
        });
        let texts: Vec<(ClaimKind, String)> = recorded
            .iter()
            .map(|event| match event {
                WardEvent::AgentClaim { kind, payload } => (*kind, payload.content().to_owned()),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            texts,
            [
                (
                    ClaimKind::ToolUse,
                    "PreToolUse Write /work/a.rs → allow".to_owned()
                ),
                (
                    ClaimKind::ToolUse,
                    "PostToolUse Write /work/a.rs".to_owned()
                ),
                (ClaimKind::Note, "Stop".to_owned()),
            ]
        );
        assert!(!hooks.due());
        assert_eq!(hooks.finish(&mut |_| true), 0);
        assert!(!hooks.socket().exists());
        assert!(UnixStream::connect(hooks.socket()).is_err());
    }

    #[test]
    fn a_line_outside_the_contract_gets_nothing_and_records_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let hooks = AttemptHooks::start(&private(dir.path())).unwrap();
        for line in [
            &b"not json\n"[..],
            b"{\"hook\":\"PreToolUse\"}\n",
            b"{\"hook\":\"Notification\"}\n",
            b"{\"hook\":\"Stop\",\"decision\":\"allow\"}\n",
            b"{\"request\":\"answer\",\"action\":1,\"decision\":\"approved\"}\n",
            b"{\"hook\":\"Stop\"}",
        ] {
            let mut stream = UnixStream::connect(hooks.socket()).unwrap();
            stream.write_all(line).unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            let mut answer = Vec::new();
            stream.read_to_end(&mut answer).unwrap();
            assert!(answer.is_empty(), "{}", String::from_utf8_lossy(line));
        }
        let mut long = vec![b'x'; MAX_HOOK_LINE_BYTES + 1];
        long.push(b'\n');
        assert!(exchange(hooks.socket(), &long).is_empty());
        assert!(!hooks.due());
    }

    #[test]
    fn claims_past_the_bound_and_refused_appends_are_counted_once() {
        let dir = tempfile::tempdir().unwrap();
        let hooks = AttemptHooks::start(&private(dir.path())).unwrap();
        for _ in 0..MAX_ATTEMPT_CLAIMS + 3 {
            exchange(hooks.socket(), b"{\"hook\":\"SessionStart\"}\n");
        }
        let mut appended = 0;
        hooks.flush(&mut |_| {
            appended += 1;
            appended % 2 == 0
        });
        assert_eq!(appended, MAX_ATTEMPT_CLAIMS);
        let dropped = hooks.finish(&mut |_| true);
        assert_eq!(dropped, 3 + u64::try_from(MAX_ATTEMPT_CLAIMS / 2).unwrap());
        assert_eq!(hooks.finish(&mut |_| true), 0, "counted once");
        assert_eq!(
            overflow_marker(dropped),
            WardEvent::ObservationsDropped {
                source: ObserverSource::Hook,
                dropped,
                capacity: 256
            }
        );
    }
}
