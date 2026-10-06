//! Local ward-node service.
//!
//! The service negotiates the node protocol, then serves exactly one request per
//! connection:
//!
//! * at protocol 1.1, read-only node capability discovery;
//! * at protocol 1.2, read-only discovery or one task lifecycle request against
//!   the node-owned [`task::TaskRegistry`]. Only `create` and `inspect` are
//!   implemented; every other verb is refused explicitly (see [`task`]);
//! * at protocol 1.3, the same, plus the `admit` verb. A service built with
//!   [`NodeService::with_admission`] verifies the signed envelope against its trusted
//!   issuers, its node id, its clock and its durable state, and moves the task
//!   `Created → Ready` (see [`admit`]); it then advertises `admit` in 1.3 capability
//!   discovery. Without admission, `admit` is refused as unsupported.
//! * at protocol 1.3, a service built with [`NodeService::with_execution`] also starts,
//!   pauses, resumes, stops, revokes and seals admitted tasks in an offline sandbox over a
//!   node-allocated workspace, reaps them on a node-owned thread and records `exited` with
//!   a receipt (see [`task`] and [`execution`]). It advertises `start`, `stop`, `pause`
//!   and `revoke` together in 1.3 capability discovery (`resume` comes with `pause` and
//!   `seal` with execution; the document has no flag for either); any other 1.3 node
//!   advertises none of them. 1.1 and 1.2 documents are unchanged, and a 1.2 connection is
//!   refused every one of these verbs as unsupported.
//!   Only such a node also advertises, at 1.3, the isolation its execution enforces: the
//!   namespace sandbox and its user namespace, the offline network and the
//!   content-addressed snapshot store — and `network.proxy_allowlist` only when its
//!   execution honours a `network.custom` manifest through a per-attempt egress proxy
//!   ([`egress`]), which is what makes `admit` accept one.
//! * at protocol 1.3, a service whose execution returns output
//!   ([`execution::NodeExecution::with_output_return`]) also serves the read-only `result`
//!   request for an ended attempt admitted with an `output` grant: its bounded stdout,
//!   stderr and declared workspace files, as the reaper collected and stored them
//!   ([`output`]), and advertises `output` in 1.3 capability discovery. Any other node
//!   refuses the grant `unsupported_grant` at `admit` and `result` as unsupported.
//! * at protocol 1.3, a service whose execution offers the action channel
//!   ([`execution::NodeExecution::with_action_channel`]) gives an attempt admitted with an
//!   `actions` grant its own channel into the sandbox ([`actions`]), serves the read-only
//!   `actions` listing of its pending requests and the mutating `answer`, and advertises
//!   `actions` in 1.3 capability discovery. Any other node refuses the grant
//!   `unsupported_grant` at `admit` and both requests as unsupported. One that also holds
//!   approval-gated capabilities ([`execution::NodeExecution::with_approval_hold`], #415)
//!   refuses each capability a manifest's `hold` names in the attempt's egress proxy until
//!   the control plane approves the request the node opens for it on first use, and
//!   advertises `actions.hold`.
//! * at protocol 1.3, a service whose execution hosts agent adapters
//!   ([`execution::NodeExecution::with_agent_adapters`], `--agent-adapter`, ADR-0036) runs
//!   a workload naming one of them through the shared adapter contract ([`adapters`]):
//!   the same sandbox, proxy, credentials and holds as any workload, the adapter's command
//!   line, environment and settings, its hook lines recorded as agent-origin claims, and
//!   its binding recorded as metadata; it advertises `adapters`. Any other node refuses
//!   such a workload `unsupported_grant` at `admit`. One that also has the operator's
//!   `ward-agent` shim ([`execution::NodeExecution::with_agent_shim`], `--agent-shim`,
//!   ADR-0037) runs those attempts under it ([`shim`]): command hooks that reach the hook
//!   socket and, behind an egress proxy, a loopback relay to it, with the provider's base
//!   URL on the relay only for a provider the manifest grants a credential for. Such a node
//!   runs every other attempt behind an egress proxy under the shim as well, so a plain
//!   workload's stock HTTP clients reach its allowlist and credential routes through the
//!   relay (#267).
//!
//! * at protocol 1.3, a service whose execution runs attempts in cgroups
//!   ([`cgroup`], `--cgroup-root`) honours a manifest's `resources` limits, records what
//!   each attempt used and advertises `resources`; one whose execution bounds how many
//!   attempts run at once ([`scheduling`], `--max-running`) refuses a `start` past the
//!   bound or below its headroom floors `capacity_exhausted` and advertises `scheduling`,
//!   read live. Any other node advertises neither and refuses every `resources` grant
//!   `unsupported_grant`.
//!
//! A service built with admission keeps its task registry durable under the node state
//! directory ([`records`]) and recovers it before it serves (see [`task`]), so a restart
//! forgets no task, receipt or applied operation and never re-runs an attempt that may
//! have been executing.
//!
//! A service built with execution is the single writer of one hash-chained evidence log
//! per attempt it admits, beside the attempt's workspace under its task root
//! ([`evidence`]); a restart reconciles every recovered attempt's log before it serves.
//!
//! The durable records answer, offline, who delegated what authority to which task and
//! when ([`audit`]): `ward-node audit` reads a task's record and, given the task root,
//! cross-checks it against the attempt's evidence log.
//!
//! A connection's request (handshake and request line) must arrive within
//! [`REQUEST_TIMEOUT`]; its answer is written within [`ANSWER_TIMEOUT`] of being ready, so
//! a `stop` or `start` whose bounded work outlasts the request deadline is still answered.
//!
//! Every accepted connection is gated by its peer credentials before a byte of it is
//! read ([`peer`]): the node's own uid and the uids its operator listed are served, any
//! other peer is closed with nothing sent. The socket itself is private (0600) unless the
//! operator shares it with a group (0660), see [`SocketAccess`].
//!
//! An operator may also serve the same protocol over TCP with mutual TLS ([`tls`],
//! `--listen-tls`, ADR-0038): TLS 1.3 only, a client certificate chained to the operator's
//! client CA (and optionally pinned) in place of the peer-credential gate, never in place
//! of an issuer signature. Handshakes run on threads of their own; requests from either
//! listener are still served one at a time.
//!
//! `stream` stays unsupported. Serving a lifecycle request never waits on a running
//! workload.

#![forbid(unsafe_code)]

pub mod actions;
pub mod adapters;
pub mod admission;
pub mod admit;
pub mod audit;
pub mod cgroup;
pub mod credentials;
pub mod egress;
pub mod evidence;
pub mod execution;
pub mod issuer;
pub mod output;
pub mod peer;
pub mod records;
pub mod scheduling;
pub mod shim;
pub mod state;
pub mod task;
#[cfg(test)]
mod test_support;
pub mod tls;
pub mod workspace;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use nix::unistd::{Gid, Uid};
use thiserror::Error;
use ward_node_protocol::{
    ActionCapabilities, AdapterCapabilities, CapabilityDiscoveryContext, CredentialCapabilities,
    HandshakeRequest, HandshakeResponse, LifecycleCapabilities, NamespaceCapabilities,
    NodeCapabilities, OutputCapabilities, SupportedProtocolRange, TaskLifecycleContext,
    TaskResultRequest, WARD_NODE_PROTOCOL, negotiate, supports_task_admission,
    supports_task_lifecycle,
};

use crate::admit::NodeAdmission;
use crate::execution::NodeExecution;
use crate::peer::{ClientGroup, ClientUids, PeerGate};
use crate::records::TaskRecordError;
use crate::task::{MAX_NODE_TASKS, TaskRegistry};
use crate::tls::TlsListener;

/// Maximum bytes in one node-protocol JSON request, excluding the terminating newline.
pub const MAX_REQUEST_LINE_BYTES: usize = 64 * 1024;

/// Absolute bound, from accept, on reading one request: the handshake line, the
/// handshake answer and the request line must all complete within it. Partial progress
/// never extends it, so a slow or idle client cannot hold the single-threaded server for
/// longer.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on writing a request's answer, counted from the moment the answer is ready.
///
/// The work a verb does between reading its request and answering is bounded by the
/// verb itself, not by [`REQUEST_TIMEOUT`]: `stop` waits at most its stop timeout
/// ([`execution::DEFAULT_STOP_TIMEOUT`]) and `start` materialises a size-bounded snapshot
/// and then waits at most its spawn timeout ([`execution::DEFAULT_SPAWN_TIMEOUT`]); every
/// other verb answers at once. A verb that takes longer than [`REQUEST_TIMEOUT`] is
/// therefore still answered.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);

/// Local ward-node protocol failure.
#[derive(Debug, Error)]
pub enum NodeServiceError {
    /// Local socket I/O failed.
    #[error("ward-node I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// First request was not a valid handshake.
    #[error("ward-node handshake is invalid")]
    MalformedHandshake,
    /// Capability request did not satisfy the negotiated protocol context.
    #[error("ward-node capability request is invalid")]
    MalformedCapabilityRequest,
    /// Task lifecycle request was malformed or not bound to the negotiated protocol.
    #[error("ward-node task lifecycle request is invalid")]
    MalformedLifecycleRequest,
    /// A request exceeded the fixed wire bound.
    #[error("ward-node request exceeds the maximum line size")]
    RequestTooLarge,
    /// The peer closed a connection before the required request arrived.
    #[error("ward-node connection closed before request completed")]
    UnexpectedEof,
    /// Trusted startup capability configuration is invalid for discovery.
    #[error("ward-node capability configuration is invalid")]
    InvalidCapabilities,
    /// JSON response serialization failed.
    #[error("ward-node response serialization failed")]
    Serialization,
    /// Administrative socket parent directory is accessible to another Unix identity.
    #[error("ward-node socket parent directory must be private (mode 0700 or stricter)")]
    InsecureSocketDirectory,
    /// With a client group, the socket parent directory is not owned by that group, is
    /// writable by it, or is accessible to others.
    #[error(
        "ward-node socket parent directory must be owned by group {group} with mode 0750 or stricter"
    )]
    InsecureSharedSocketDirectory {
        /// The client group the directory must be owned by.
        group: u32,
    },
    /// The request was not read within [`REQUEST_TIMEOUT`], or its answer not written
    /// within [`ANSWER_TIMEOUT`].
    #[error("ward-node connection exceeded its deadline")]
    ConnectionDeadlineExceeded,
    /// The node task registry lock was poisoned by an earlier panic.
    #[error("ward-node task registry is unavailable")]
    TaskRegistryUnavailable,
    /// The durable task records could not be recovered at start.
    #[error("ward-node task records could not be recovered: {0}")]
    TaskRecords(#[from] TaskRecordError),
}

/// Local node service for handshake, capability discovery and the task registry.
///
/// Clones share one task registry, so a task created on one connection is visible to
/// every later connection served by any clone.
#[allow(clippy::struct_excessive_bools)] // one flag per operator-enabled capability
#[derive(Clone)]
pub struct NodeService {
    capabilities: NodeCapabilities,
    supported: SupportedProtocolRange,
    admits: bool,
    executes: bool,
    network_allowlist: bool,
    output_return: bool,
    action_channel: bool,
    approval_hold: bool,
    credentials: bool,
    agent_adapters: Option<AdapterCapabilities>,
    tasks: Arc<Mutex<TaskRegistry>>,
}

impl NodeService {
    /// Create a service bound to trusted node-owned capabilities.
    ///
    /// # Errors
    ///
    /// Returns `InvalidCapabilities` if the capability document is not valid for
    /// capability discovery in this build.
    pub fn new(capabilities: NodeCapabilities) -> Result<Self, NodeServiceError> {
        CapabilityDiscoveryContext::new(capabilities.protocol())
            .map_err(|_| NodeServiceError::InvalidCapabilities)?;
        Ok(Self {
            capabilities,
            supported: WARD_NODE_PROTOCOL,
            admits: false,
            executes: false,
            network_allowlist: false,
            output_return: false,
            action_channel: false,
            approval_hold: false,
            credentials: false,
            agent_adapters: None,
            tasks: Arc::new(Mutex::new(TaskRegistry::default())),
        })
    }

    /// Create a service that admits signed envelopes through `admission` (protocol 1.3),
    /// recovering its task registry from the node state directory.
    ///
    /// # Errors
    ///
    /// Returns `InvalidCapabilities` if the capability document is not valid for
    /// capability discovery in this build, and `TaskRecords` if the task records cannot
    /// be recovered.
    pub fn with_admission(
        capabilities: NodeCapabilities,
        admission: NodeAdmission,
    ) -> Result<Self, NodeServiceError> {
        CapabilityDiscoveryContext::new(capabilities.protocol())
            .map_err(|_| NodeServiceError::InvalidCapabilities)?;
        Ok(Self {
            capabilities,
            supported: WARD_NODE_PROTOCOL,
            admits: true,
            executes: false,
            network_allowlist: false,
            output_return: false,
            action_channel: false,
            approval_hold: false,
            credentials: false,
            agent_adapters: None,
            tasks: Arc::new(Mutex::new(TaskRegistry::with_admission(
                MAX_NODE_TASKS,
                admission,
            )?)),
        })
    }

    /// Create a service that admits signed envelopes through `admission` and executes
    /// admitted tasks through `execution` (protocol 1.3), recovering its task registry from
    /// the node state directory.
    ///
    /// # Errors
    ///
    /// Returns `InvalidCapabilities` if the capability document is not valid for
    /// capability discovery in this build, and `TaskRecords` if the task records cannot
    /// be recovered.
    pub fn with_execution(
        capabilities: NodeCapabilities,
        admission: NodeAdmission,
        execution: NodeExecution,
    ) -> Result<Self, NodeServiceError> {
        CapabilityDiscoveryContext::new(capabilities.protocol())
            .map_err(|_| NodeServiceError::InvalidCapabilities)?;
        let network_allowlist = execution.honours_network_allowlist();
        let output_return = execution.honours_output_return();
        let action_channel = execution.honours_action_channel();
        let approval_hold = execution.honours_approval_hold();
        let credentials = execution.honours_credentials();
        let agent_adapters = execution.agent_adapters();
        Ok(Self {
            capabilities,
            supported: WARD_NODE_PROTOCOL,
            admits: true,
            executes: true,
            network_allowlist,
            output_return,
            action_channel,
            approval_hold,
            credentials,
            agent_adapters,
            tasks: Arc::new(Mutex::new(TaskRegistry::with_execution(
                MAX_NODE_TASKS,
                admission,
                execution,
            )?)),
        })
    }

    /// Serve exactly one local protocol connection.
    ///
    /// The first request must be a handshake. Rejected handshakes receive a bounded
    /// machine-readable response and close. A connection accepted at the capability
    /// negotiated protocol may issue one read-only capability-discovery request; a
    /// connection accepted at 1.2 or later may instead issue one lifecycle request. The
    /// connection then closes.
    ///
    /// The handshake, its answer and the request line must complete within
    /// [`REQUEST_TIMEOUT`] of the call. The request's answer is then written within
    /// [`ANSWER_TIMEOUT`] of being ready, however long the verb's own bounded work took.
    ///
    /// A lifecycle request is applied to the registry before its response is written, so
    /// a `create` whose client disconnects before reading the response still took effect;
    /// the client recovers by replaying the same operation id or by inspecting.
    ///
    /// # Errors
    ///
    /// Returns an explicit bounded protocol/I/O error. No error path falls back to the
    /// per-session ward-daemon control protocol.
    pub fn serve_connection(&self, stream: UnixStream) -> Result<(), NodeServiceError> {
        self.serve_connection_with_lifetime(stream, REQUEST_TIMEOUT)
    }

    fn serve_connection_with_lifetime<S: Connection>(
        &self,
        stream: S,
        request_timeout: Duration,
    ) -> Result<(), NodeServiceError> {
        let deadline = deadline_after(request_timeout)?;

        let mut reader = BufReader::new(stream);

        let handshake_line = read_request_line(&mut reader, deadline)?;
        let handshake = serde_json::from_str::<HandshakeRequest>(&handshake_line)
            .map_err(|_| NodeServiceError::MalformedHandshake)?;
        let HandshakeRequest::Hello { protocol: peer } = handshake;
        let response = negotiate(self.supported, peer);
        write_json_line(reader.get_mut(), &response, deadline)?;

        let HandshakeResponse::Accepted { protocol } = response else {
            return Ok(());
        };

        if !ward_node_protocol::supports_capability_discovery(protocol) {
            return Ok(());
        }

        let request_line = read_request_line(&mut reader, deadline)?;
        if serde_json::from_str::<serde_json::Value>(&request_line)
            .is_ok_and(|value| value["request"] == "capabilities")
        {
            return self.serve_capabilities(reader.get_mut(), protocol, &request_line);
        }
        if supports_task_lifecycle(protocol) {
            return self.serve_lifecycle(reader.get_mut(), protocol, &request_line);
        }
        Err(NodeServiceError::MalformedCapabilityRequest)
    }

    fn serve_capabilities(
        &self,
        stream: &mut impl Connection,
        protocol: ward_node_protocol::ProtocolVersion,
        request_line: &str,
    ) -> Result<(), NodeServiceError> {
        let context = CapabilityDiscoveryContext::new(protocol)
            .map_err(|_| NodeServiceError::MalformedCapabilityRequest)?;
        context
            .decode_request(request_line)
            .map_err(|_| NodeServiceError::MalformedCapabilityRequest)?;
        let configured = self.capabilities;
        let mut isolation = configured.isolation();
        let mut network = configured.network();
        let mut credentials = configured.credentials();
        let mut snapshots = configured.snapshots();
        let mut output = OutputCapabilities::NONE;
        let mut resources = None;
        let mut scheduling = None;
        let mut actions = ActionCapabilities::NONE;
        let mut adapters = None;
        let lifecycle = if supports_task_admission(protocol) {
            isolation.namespaces = NamespaceCapabilities {
                sandbox: self.executes,
                user_namespace: self.executes,
            };
            network.offline = self.executes;
            network.proxy_allowlist = self.executes && self.network_allowlist;
            credentials = CredentialCapabilities {
                proxy_injection: self.executes && self.credentials,
                scoped_http_gateway: self.executes && self.credentials,
            };
            snapshots.content_addressed = self.executes;
            output = OutputCapabilities {
                stdio: self.executes && self.output_return,
                files: self.executes && self.output_return,
            };
            if self.executes {
                let tasks = self
                    .tasks
                    .lock()
                    .map_err(|_| NodeServiceError::TaskRegistryUnavailable)?;
                resources = tasks.resource_capabilities();
                scheduling = tasks.scheduling();
            }
            if self.executes {
                adapters = self.agent_adapters;
            }
            if self.executes && self.action_channel {
                actions = ActionCapabilities {
                    hold: self.approval_hold,
                    ..ActionCapabilities::CEILINGS
                };
            }
            LifecycleCapabilities {
                admit: self.admits,
                start: self.executes,
                stop: self.executes,
                pause: self.executes,
                revoke: self.executes,
            }
        } else {
            LifecycleCapabilities {
                admit: false,
                start: false,
                ..configured.lifecycle()
            }
        };
        let capabilities = NodeCapabilities::new(
            protocol,
            configured.architecture(),
            configured.capacity(),
            isolation,
            network,
            credentials,
            snapshots,
            configured.verifier(),
            lifecycle,
        )
        .and_then(|capabilities| capabilities.with_output(output))
        .and_then(|capabilities| capabilities.with_resources(resources))
        .and_then(|capabilities| capabilities.with_scheduling(scheduling))
        .and_then(|capabilities| capabilities.with_actions(actions))
        .and_then(|capabilities| capabilities.with_adapters(adapters))
        .map_err(|_| NodeServiceError::InvalidCapabilities)?;
        let response = context
            .response(capabilities)
            .map_err(|_| NodeServiceError::InvalidCapabilities)?;
        write_answer(stream, &response)
    }

    fn serve_lifecycle(
        &self,
        stream: &mut impl Connection,
        protocol: ward_node_protocol::ProtocolVersion,
        request_line: &str,
    ) -> Result<(), NodeServiceError> {
        let context = TaskLifecycleContext::new(protocol)
            .map_err(|_| NodeServiceError::MalformedLifecycleRequest)?;
        let named = serde_json::from_str::<serde_json::Value>(request_line)
            .ok()
            .and_then(|value| value["request"].as_str().map(str::to_owned));
        if matches!(named.as_deref(), Some("actions" | "answer")) {
            let request = context
                .decode_actions_request(request_line)
                .map_err(|_| NodeServiceError::MalformedLifecycleRequest)?;
            let response = TaskRegistry::actions(&self.tasks, context, request)
                .map_err(|_| NodeServiceError::TaskRegistryUnavailable)?;
            return write_answer(stream, &response);
        }
        if named.as_deref() == Some("result") {
            let TaskResultRequest::Result { binding, .. } = context
                .decode_result_request(request_line)
                .map_err(|_| NodeServiceError::MalformedLifecycleRequest)?;
            let response = TaskRegistry::result(&self.tasks, context, binding)
                .map_err(|_| NodeServiceError::TaskRegistryUnavailable)?;
            return write_answer(stream, &response);
        }
        let request = context
            .decode_request(request_line)
            .map_err(|_| NodeServiceError::MalformedLifecycleRequest)?;
        let response = TaskRegistry::serve(&self.tasks, context, request)
            .map_err(|_| NodeServiceError::TaskRegistryUnavailable)?;
        write_answer(stream, &response)
    }
}

/// Who may reach the node's socket and who is served on it.
///
/// Without a client group the socket is created mode 0600 in a directory that must be
/// mode 0700 or stricter, so only the node's own uid can connect. With one, the socket is
/// created mode 0660 owned by that group in a directory that must be owned by the same
/// group with mode 0750 or stricter, so the group's members can connect too. Either way
/// every connection is then gated by its peer credentials ([`peer::PeerGate`]): the
/// node's own uid and the listed client uids are served, any other peer is closed with
/// nothing sent. This is the local boundary; the remote one is [`tls`].
#[derive(Debug)]
pub struct SocketAccess {
    group: Option<Gid>,
    gate: PeerGate,
}

impl SocketAccess {
    /// A private socket served to the node's own uid alone.
    #[must_use]
    pub fn private() -> Self {
        Self::new(None, ClientUids::empty())
    }

    /// A socket shared with `group`, if any, and served to the node's own uid and
    /// `clients`.
    #[must_use]
    pub fn new(group: Option<ClientGroup>, clients: ClientUids) -> Self {
        Self {
            group: group.map(ClientGroup::gid),
            gate: PeerGate::new(Uid::effective(), clients),
        }
    }
}

/// Serve the node protocol on a Unix socket at `socket` under `access`, forever.
///
/// A connection the gate refuses is closed before any of it is read and the refusal is
/// reported on stderr, rate-limited per uid; nothing about it reaches the peer.
///
/// Connections are handled sequentially. That deliberately caps active protocol handlers
/// at one instead of allocating an unbounded thread per client.
///
/// # Errors
///
/// Returns if the listener cannot be created/configured. Existing socket paths are never
/// removed automatically.
pub fn serve_local(
    socket: &Path,
    service: &NodeService,
    access: SocketAccess,
) -> Result<(), NodeServiceError> {
    serve_node(socket, service, access, None)
}

/// [`serve_local`], and with `remote` also the same protocol over mutual TLS on its
/// listener ([`tls::TlsListener`]), forever.
///
/// TLS handshakes run on threads of their own, at most [`tls::MAX_TLS_CONNECTIONS`] at
/// once, so a slow or hostile TCP peer never holds the socket. A request from either
/// listener is served only while no other one is, exactly as the socket alone serves
/// them: one at a time.
///
/// # Errors
///
/// Returns if the socket cannot be created/configured or the TLS thread cannot be
/// started. Existing socket paths are never removed automatically.
pub fn serve_node(
    socket: &Path,
    service: &NodeService,
    mut access: SocketAccess,
    remote: Option<TlsListener>,
) -> Result<(), NodeServiceError> {
    let listener = bind_local(socket, access.group)?;
    let serving = Arc::new(Mutex::new(()));
    if let Some(remote) = remote {
        let addr = remote.local_addr()?;
        tls::spawn(remote, service.clone(), Arc::clone(&serving))?;
        let _ = writeln!(
            std::io::stderr().lock(),
            "ward-node: serving the node protocol over mutual TLS on {addr}"
        );
    }

    for connection in listener.incoming() {
        let stream = connection?;
        match access.gate.admit(&stream, Instant::now()) {
            Ok(()) => {
                let _one_at_a_time = one_at_a_time(&serving);
                let _ = service.serve_connection(stream);
            }
            Err(refusal) => {
                drop(stream);
                if let Some(line) = refusal.report() {
                    let _ = writeln!(std::io::stderr().lock(), "{line}");
                }
            }
        }
    }

    Ok(())
}

/// The lock that keeps protocol handlers to one at a time across listeners. A handler
/// that panicked held no registry state of its own, so a poisoned lock is still a lock.
pub(crate) fn one_at_a_time(serving: &Mutex<()>) -> MutexGuard<'_, ()> {
    serving.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A byte stream the node serves the protocol on: the Unix socket, or a TLS session over
/// TCP. Its read and write bounds are what the request and answer deadlines set.
pub(crate) trait Connection: Read + Write {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}

impl Connection for UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_write_timeout(self, timeout)
    }
}

impl<C: Connection + ?Sized> Connection for &mut C {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        (**self).set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        (**self).set_write_timeout(timeout)
    }
}

impl NodeService {
    /// Serve exactly one protocol connection on `stream`, as [`Self::serve_connection`]
    /// does on the socket.
    pub(crate) fn serve_stream(&self, stream: impl Connection) -> Result<(), NodeServiceError> {
        self.serve_connection_with_lifetime(stream, REQUEST_TIMEOUT)
    }
}

fn bind_local(socket: &Path, group: Option<Gid>) -> Result<UnixListener, NodeServiceError> {
    let parent = socket
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = std::fs::metadata(parent)?;
    let mode = metadata.permissions().mode();
    match group {
        None if !metadata.is_dir() || mode & 0o077 != 0 => {
            return Err(NodeServiceError::InsecureSocketDirectory);
        }
        Some(gid) if !metadata.is_dir() || mode & 0o027 != 0 || metadata.gid() != gid.as_raw() => {
            return Err(NodeServiceError::InsecureSharedSocketDirectory {
                group: gid.as_raw(),
            });
        }
        _ => {}
    }

    let listener = UnixListener::bind(socket)?;
    match group {
        None => std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?,
        Some(gid) => {
            std::os::unix::fs::chown(socket, None, Some(gid.as_raw()))?;
            std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660))?;
        }
    }
    Ok(listener)
}

fn read_request_line<S: Connection>(
    reader: &mut BufReader<S>,
    deadline: Instant,
) -> Result<String, NodeServiceError> {
    let mut bytes = Vec::new();

    loop {
        let remaining = remaining_until(deadline)?;
        reader.get_mut().set_read_timeout(Some(remaining))?;

        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if is_timeout(&error) => {
                return Err(NodeServiceError::ConnectionDeadlineExceeded);
            }
            Err(error) => return Err(NodeServiceError::Io(error)),
        };

        if available.is_empty() {
            return if bytes.is_empty() {
                Err(NodeServiceError::UnexpectedEof)
            } else {
                Err(NodeServiceError::MalformedHandshake)
            };
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if bytes.len().saturating_add(take) > MAX_REQUEST_LINE_BYTES + 1 {
            return Err(NodeServiceError::RequestTooLarge);
        }

        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);

        if newline.is_some() {
            break;
        }
    }

    if !bytes.ends_with(b"\n") {
        return Err(NodeServiceError::MalformedHandshake);
    }

    bytes.pop();
    if bytes.ends_with(b"\r") {
        bytes.pop();
    }
    if bytes.len() > MAX_REQUEST_LINE_BYTES {
        return Err(NodeServiceError::RequestTooLarge);
    }

    String::from_utf8(bytes).map_err(|_| NodeServiceError::MalformedHandshake)
}

fn write_json_line(
    writer: &mut impl Connection,
    value: &impl serde::Serialize,
    deadline: Instant,
) -> Result<(), NodeServiceError> {
    let remaining = remaining_until(deadline)?;
    writer.set_write_timeout(Some(remaining))?;
    let mut line = serde_json::to_vec(value).map_err(|_| NodeServiceError::Serialization)?;
    line.push(b'\n');
    writer.write_all(&line).map_err(map_timeout)?;
    writer.flush().map_err(map_timeout)?;
    Ok(())
}

fn write_answer(
    writer: &mut impl Connection,
    value: &impl serde::Serialize,
) -> Result<(), NodeServiceError> {
    write_json_line(writer, value, deadline_after(ANSWER_TIMEOUT)?)
}

fn deadline_after(timeout: Duration) -> Result<Instant, NodeServiceError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or(NodeServiceError::ConnectionDeadlineExceeded)
}

fn remaining_until(deadline: Instant) -> Result<Duration, NodeServiceError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(NodeServiceError::ConnectionDeadlineExceeded)
}

fn is_timeout(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

fn map_timeout(error: std::io::Error) -> NodeServiceError {
    if is_timeout(&error) {
        NodeServiceError::ConnectionDeadlineExceeded
    } else {
        NodeServiceError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    use ward_events::{ExecutionAttemptId, LeaseId, TaskId};
    use ward_node_protocol::{
        CapabilityDiscoveryContext, CredentialCapabilities, ExecutionBackendCapabilities,
        HandshakeRequest, HandshakeResponse, IsolationCapabilities, LifecycleCapabilities,
        NamespaceCapabilities, NetworkCapabilities, NodeArchitecture, NodeCapabilities,
        NodeCapacity, ProtocolRejectionReason, ProtocolVersion, SnapshotCapabilities,
        SupportedProtocolRange, VerifierCapabilities, WARD_NODE_PROTOCOL,
    };
    use ward_node_protocol::{
        OperationId, TaskBinding, TaskLifecycleContext, TaskLifecycleRejectionReason,
        TaskLifecycleRequest, TaskLifecycleResponse, TaskLifecycleState,
    };

    use super::*;

    fn capabilities() -> NodeCapabilities {
        NodeCapabilities::new(
            ProtocolVersion::new(1, 1),
            NodeArchitecture::X86_64,
            NodeCapacity::new(8, 16 * 1024 * 1024 * 1024).unwrap(),
            IsolationCapabilities {
                namespaces: NamespaceCapabilities {
                    sandbox: true,
                    user_namespace: true,
                },
                backends: ExecutionBackendCapabilities::default(),
            },
            NetworkCapabilities {
                offline: true,
                proxy_allowlist: true,
            },
            CredentialCapabilities {
                proxy_injection: true,
                scoped_http_gateway: true,
            },
            SnapshotCapabilities {
                content_addressed: true,
                diff: true,
                read: true,
            },
            VerifierCapabilities { isolated: true },
            LifecycleCapabilities {
                pause: true,
                stop: true,
                revoke: true,
                admit: false,
                start: false,
            },
        )
        .unwrap()
    }

    fn line(stream: &mut UnixStream) -> String {
        let reader_stream = stream.try_clone().unwrap();
        let mut reader = BufReader::new(reader_stream);
        let mut value = String::new();
        reader.read_line(&mut value).unwrap();
        value
    }

    #[test]
    fn admin_socket_requires_private_parent_and_is_mode_six_hundred() {
        let private = tempfile::tempdir().unwrap();
        std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = private.path().join("node.sock");
        let listener = bind_local(&socket, None).unwrap();
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(listener);

        let exposed = tempfile::tempdir().unwrap();
        std::fs::set_permissions(exposed.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            bind_local(&exposed.path().join("node.sock"), None),
            Err(NodeServiceError::InsecureSocketDirectory)
        ));
    }

    #[test]
    fn a_shared_admin_socket_is_mode_0660_in_a_directory_owned_by_the_group() {
        let gid = Gid::effective();
        let shared = tempfile::tempdir().unwrap();
        std::os::unix::fs::chown(shared.path(), None, Some(gid.as_raw())).unwrap();
        std::fs::set_permissions(shared.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        let socket = shared.path().join("node.sock");
        let listener = bind_local(&socket, Some(gid)).unwrap();
        let metadata = std::fs::metadata(&socket).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
        assert_eq!(metadata.gid(), gid.as_raw());
        drop(listener);

        let other_group = Gid::from_raw(gid.as_raw().wrapping_add(1));
        assert!(matches!(
            bind_local(&shared.path().join("other.sock"), Some(other_group)),
            Err(NodeServiceError::InsecureSharedSocketDirectory { group }) if group == other_group.as_raw()
        ));
        for loose in [0o770, 0o755, 0o751, 0o705] {
            std::fs::set_permissions(shared.path(), std::fs::Permissions::from_mode(loose))
                .unwrap();
            assert!(
                matches!(
                    bind_local(&shared.path().join("other.sock"), Some(gid)),
                    Err(NodeServiceError::InsecureSharedSocketDirectory { group }) if group == gid.as_raw()
                ),
                "mode {loose:o}"
            );
        }
        std::fs::set_permissions(shared.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(bind_local(&shared.path().join("other.sock"), Some(gid)).unwrap());
        drop(bind_local(&shared.path().join("third.sock"), None).unwrap());

        let error = NodeServiceError::InsecureSharedSocketDirectory { group: 7 };
        assert!(error.to_string().contains("group 7"));
        assert!(SocketAccess::private().group.is_none());
        assert_eq!(
            SocketAccess::new(Some(ClientGroup::parse("0").unwrap()), ClientUids::empty()).group,
            Some(Gid::from_raw(0))
        );
    }

    #[test]
    fn one_one_client_receives_capabilities_bound_to_negotiated_protocol() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || service.serve_connection(server));

        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 1, 1).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();

        let accepted: HandshakeResponse = serde_json::from_str(line(&mut client).trim()).unwrap();
        assert_eq!(
            accepted,
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 1),
            }
        );

        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 1)).unwrap();
        writeln!(
            client,
            "{}",
            serde_json::to_string(&context.request()).unwrap()
        )
        .unwrap();

        let response = line(&mut client);
        assert!(context.decode_response(response.trim()).is_ok());
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn one_zero_handshake_succeeds_but_capability_discovery_is_unavailable() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || service.serve_connection(server));

        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 0, 0).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();

        let response: HandshakeResponse = serde_json::from_str(line(&mut client).trim()).unwrap();
        assert_eq!(
            response,
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 0),
            }
        );
        assert_eq!(line(&mut client), "");
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn major_and_disjoint_minor_ranges_are_rejected_fail_closed() {
        for (peer, reason) in [
            (
                SupportedProtocolRange::new(2, 0, 1).unwrap(),
                ProtocolRejectionReason::MajorVersionMismatch,
            ),
            (
                SupportedProtocolRange::new(1, 4, 5).unwrap(),
                ProtocolRejectionReason::NoCommonMinor,
            ),
        ] {
            let service = NodeService::new(capabilities()).unwrap();
            let (mut client, server) = UnixStream::pair().unwrap();
            let worker = std::thread::spawn(move || service.serve_connection(server));

            let hello = HandshakeRequest::Hello { protocol: peer };
            writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();

            let response: HandshakeResponse =
                serde_json::from_str(line(&mut client).trim()).unwrap();
            assert_eq!(
                response,
                HandshakeResponse::Rejected {
                    reason,
                    supported: WARD_NODE_PROTOCOL,
                }
            );
            worker.join().unwrap().unwrap();
        }
    }

    /// Send `hello` for `peer` and, in the same write, a well-formed 1.2 `create`, as a
    /// client that ignores the handshake answer would. Returns the handshake response
    /// and whatever the node wrote after it.
    fn skewed_hello_then_create(
        service: &NodeService,
        peer: SupportedProtocolRange,
    ) -> (HandshakeResponse, String) {
        let worker_service = service.clone();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || worker_service.serve_connection(server));

        let hello = HandshakeRequest::Hello { protocol: peer };
        let create = lifecycle_context().create(OperationId::new(1).unwrap(), lifecycle_binding());
        let lines = format!(
            "{}\n{}\n",
            serde_json::to_string(&hello).unwrap(),
            serde_json::to_string(&create).unwrap()
        );
        client.write_all(lines.as_bytes()).unwrap();

        let mut reader = BufReader::new(client);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        let mut rest = String::new();
        reader.read_line(&mut rest).unwrap();
        worker.join().unwrap().unwrap();
        (serde_json::from_str(response.trim()).unwrap(), rest)
    }

    #[test]
    fn protocol_skew_outside_the_served_window_is_rejected_fail_closed() {
        let window = WARD_NODE_PROTOCOL;
        let (major, min, max) = (window.major(), window.min_minor(), window.max_minor());
        let range = |major, lo, hi| SupportedProtocolRange::new(major, lo, hi).unwrap();
        for (peer, reason) in [
            // A newer control plane that only speaks minors this node does not serve yet.
            (
                range(major, max + 1, max + 1),
                ProtocolRejectionReason::NoCommonMinor,
            ),
            (
                range(major, max + 1, u16::MAX),
                ProtocolRejectionReason::NoCommonMinor,
            ),
            // The node's own minors under another major, above and below.
            (
                range(major + 1, min, max),
                ProtocolRejectionReason::MajorVersionMismatch,
            ),
            (
                range(major - 1, min, max),
                ProtocolRejectionReason::MajorVersionMismatch,
            ),
        ] {
            let service = NodeService::new(capabilities()).unwrap();
            let (response, rest) = skewed_hello_then_create(&service, peer);
            assert_eq!(
                response,
                HandshakeResponse::Rejected {
                    reason,
                    supported: WARD_NODE_PROTOCOL,
                },
                "peer {peer:?}"
            );
            assert_eq!(rest, "", "nothing is served after a rejection: {peer:?}");
            assert!(service.tasks.lock().unwrap().is_empty(), "peer {peer:?}");
        }
    }

    #[test]
    fn a_peer_offering_only_retired_minors_is_rejected_fail_closed() {
        // A node whose window starts at 1.2 has no overlap with a 1.0-1.1 peer: it
        // rejects rather than degrading to a minor it does not serve.
        let mut service = NodeService::new(capabilities()).unwrap();
        service.supported =
            SupportedProtocolRange::new(1, 2, WARD_NODE_PROTOCOL.max_minor()).unwrap();
        let (response, rest) =
            skewed_hello_then_create(&service, SupportedProtocolRange::new(1, 0, 1).unwrap());
        assert_eq!(
            response,
            HandshakeResponse::Rejected {
                reason: ProtocolRejectionReason::NoCommonMinor,
                supported: service.supported,
            }
        );
        assert_eq!(rest, "");
        assert!(service.tasks.lock().unwrap().is_empty());
    }

    #[test]
    fn a_newer_peer_that_still_offers_the_nodes_max_minor_negotiates_down_to_it() {
        let max = WARD_NODE_PROTOCOL.max_minor();
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || service.serve_connection(server));

        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, max, max + 5).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        assert_eq!(
            serde_json::from_str::<HandshakeResponse>(line(&mut client).trim()).unwrap(),
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, max),
            }
        );
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeServiceError::UnexpectedEof)
        ));
    }

    #[test]
    fn malformed_or_oversized_first_request_fails_closed() {
        for payload in [
            "{not-json}\n".to_owned(),
            format!("{}\n", "x".repeat(MAX_REQUEST_LINE_BYTES + 1)),
        ] {
            let service = NodeService::new(capabilities()).unwrap();
            let (mut client, server) = UnixStream::pair().unwrap();
            let worker = std::thread::spawn(move || service.serve_connection(server));

            client.write_all(payload.as_bytes()).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();

            assert!(worker.join().unwrap().is_err());
        }
    }

    #[test]
    fn slow_drip_cannot_extend_the_absolute_connection_deadline() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let started = Instant::now();
        let worker = std::thread::spawn(move || {
            service.serve_connection_with_lifetime(server, Duration::from_millis(120))
        });

        client.write_all(b"{").unwrap();
        std::thread::sleep(Duration::from_millis(70));
        client.write_all(b"{").unwrap();

        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeServiceError::ConnectionDeadlineExceeded)
        ));
        assert!(
            started.elapsed() < Duration::from_millis(190),
            "partial progress must not reset the 120 ms absolute deadline"
        );
    }

    #[test]
    fn handshake_and_capability_request_share_one_absolute_deadline() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            service.serve_connection_with_lifetime(server, Duration::from_millis(100))
        });

        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 1, 1).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        let _: HandshakeResponse = serde_json::from_str(line(&mut client).trim()).unwrap();

        std::thread::sleep(Duration::from_millis(120));

        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeServiceError::ConnectionDeadlineExceeded)
        ));
    }

    #[test]
    fn malformed_capability_request_fails_closed_after_valid_handshake() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || service.serve_connection(server));

        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 1, 1).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        let _: HandshakeResponse = serde_json::from_str(line(&mut client).trim()).unwrap();

        writeln!(client, "{{not-json").unwrap();
        let _ = client.shutdown(std::net::Shutdown::Write);

        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeServiceError::MalformedCapabilityRequest)
        ));
        assert_eq!(line(&mut client), "");
    }

    #[test]
    fn oversized_capability_request_fails_closed_after_valid_handshake() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || service.serve_connection(server));

        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 1, 1).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        let _: HandshakeResponse = serde_json::from_str(line(&mut client).trim()).unwrap();

        let payload = format!("{}\n", "x".repeat(MAX_REQUEST_LINE_BYTES + 1));
        let _ = client.write_all(payload.as_bytes());
        let _ = client.shutdown(std::net::Shutdown::Write);

        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeServiceError::RequestTooLarge)
        ));
        assert_eq!(line(&mut client), "");
    }

    fn lifecycle_binding() -> TaskBinding {
        TaskBinding::new(
            TaskId::from_u128(7),
            ExecutionAttemptId::from_u128(8),
            LeaseId::from_u128(9),
        )
    }

    fn lifecycle_context() -> TaskLifecycleContext {
        TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap()
    }

    /// Open a connection, negotiate 1.2 and return the client end plus the server worker.
    fn lifecycle_connection(
        service: &NodeService,
    ) -> (
        UnixStream,
        std::thread::JoinHandle<Result<(), NodeServiceError>>,
    ) {
        let service = service.clone();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || service.serve_connection(server));

        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 2, 2).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        assert_eq!(
            serde_json::from_str::<HandshakeResponse>(line(&mut client).trim()).unwrap(),
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 2),
            }
        );
        (client, worker)
    }

    #[test]
    fn one_two_client_discovers_capabilities_without_registering_a_task() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, worker) = lifecycle_connection(&service);
        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 2)).unwrap();
        writeln!(
            client,
            "{}",
            serde_json::to_string(&context.request()).unwrap()
        )
        .unwrap();

        let response = context.decode_response(line(&mut client).trim()).unwrap();
        let ward_node_protocol::CapabilityDiscoveryResponse::Capabilities {
            capabilities: observed,
        } = response;
        assert_eq!(observed.protocol(), ProtocolVersion::new(1, 2));
        assert_eq!(observed.architecture(), service.capabilities.architecture());
        assert_eq!(observed.capacity(), service.capabilities.capacity());
        assert_eq!(observed.isolation(), service.capabilities.isolation());
        assert_eq!(observed.network(), service.capabilities.network());
        assert_eq!(observed.credentials(), service.capabilities.credentials());
        assert_eq!(observed.snapshots(), service.capabilities.snapshots());
        assert_eq!(observed.verifier(), service.capabilities.verifier());
        assert_eq!(observed.lifecycle(), service.capabilities.lifecycle());
        worker.join().unwrap().unwrap();
        assert!(service.tasks.lock().unwrap().is_empty());
    }

    #[test]
    fn one_two_capability_request_with_one_one_version_fails_closed() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, worker) = lifecycle_connection(&service);
        let one_one = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 1)).unwrap();
        writeln!(
            client,
            "{}",
            serde_json::to_string(&one_one.request()).unwrap()
        )
        .unwrap();

        assert!(matches!(
            worker.join().unwrap(),
            Err(NodeServiceError::MalformedCapabilityRequest)
        ));
        assert_eq!(line(&mut client), "");
        assert!(service.tasks.lock().unwrap().is_empty());
    }

    /// One lifecycle request on its own 1.2 connection; returns the decoded response.
    #[allow(clippy::needless_pass_by_value)]
    fn lifecycle_round_trip(
        service: &NodeService,
        request: TaskLifecycleRequest,
    ) -> TaskLifecycleResponse {
        let (mut client, worker) = lifecycle_connection(service);
        writeln!(client, "{}", serde_json::to_string(&request).unwrap()).unwrap();
        let response = lifecycle_context()
            .decode_response(line(&mut client).trim())
            .unwrap();
        worker.join().unwrap().unwrap();
        response
    }

    #[test]
    fn one_two_create_registers_a_node_task_that_a_later_connection_inspects() {
        let service = NodeService::new(capabilities()).unwrap();
        let ctx = lifecycle_context();
        let binding = lifecycle_binding();
        let operation = OperationId::new(1).unwrap();

        assert_eq!(
            lifecycle_round_trip(&service, ctx.inspect(binding)),
            ctx.rejected(None, binding, TaskLifecycleRejectionReason::TaskNotFound)
        );
        assert_eq!(
            lifecycle_round_trip(&service, ctx.create(operation, binding)),
            ctx.accepted(operation, binding, TaskLifecycleState::Created)
        );
        assert_eq!(
            lifecycle_round_trip(&service, ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Created)
        );
    }

    #[test]
    fn one_two_start_is_refused_over_the_socket_and_the_task_stays_created() {
        let service = NodeService::new(capabilities()).unwrap();
        let ctx = lifecycle_context();
        let binding = lifecycle_binding();
        let create = OperationId::new(1).unwrap();
        let start = OperationId::new(2).unwrap();

        lifecycle_round_trip(&service, ctx.create(create, binding));
        assert_eq!(
            lifecycle_round_trip(&service, ctx.start(start, binding)),
            ctx.rejected(
                Some(start),
                binding,
                TaskLifecycleRejectionReason::UnsupportedOperation
            )
        );
        assert_eq!(
            lifecycle_round_trip(&service, ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Created)
        );
    }

    #[test]
    fn create_applies_even_if_the_client_disconnects_before_reading_and_replays() {
        let service = NodeService::new(capabilities()).unwrap();
        let ctx = lifecycle_context();
        let binding = lifecycle_binding();
        let operation = OperationId::new(1).unwrap();

        let (mut client, worker) = lifecycle_connection(&service);
        writeln!(
            client,
            "{}",
            serde_json::to_string(&ctx.create(operation, binding)).unwrap()
        )
        .unwrap();
        client.shutdown(std::net::Shutdown::Both).unwrap();
        drop(client);
        let _ = worker.join().unwrap();

        assert_eq!(
            lifecycle_round_trip(&service, ctx.create(operation, binding)),
            ctx.accepted(operation, binding, TaskLifecycleState::Created)
        );
    }

    #[test]
    fn malformed_or_wrong_version_lifecycle_request_fails_closed_without_registering() {
        let service = NodeService::new(capabilities()).unwrap();
        let binding = lifecycle_binding();
        let operation = OperationId::new(1).unwrap();
        let wrong_version = serde_json::to_string(&TaskLifecycleRequest::Create {
            protocol: ProtocolVersion::new(1, 1),
            operation_id: operation,
            binding,
        })
        .unwrap();

        for payload in ["{not-json".to_owned(), wrong_version] {
            let (mut client, worker) = lifecycle_connection(&service);
            writeln!(client, "{payload}").unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(matches!(
                worker.join().unwrap(),
                Err(NodeServiceError::MalformedLifecycleRequest)
            ));
            assert_eq!(line(&mut client), "");
        }

        let ctx = lifecycle_context();
        assert_eq!(
            lifecycle_round_trip(&service, ctx.inspect(binding)),
            ctx.rejected(None, binding, TaskLifecycleRejectionReason::TaskNotFound)
        );
    }

    /// Open a connection, negotiate 1.3 and return the client end plus the server worker.
    fn admission_connection(
        service: &NodeService,
    ) -> (
        UnixStream,
        std::thread::JoinHandle<Result<(), NodeServiceError>>,
    ) {
        let service = service.clone();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || service.serve_connection(server));

        let hello = HandshakeRequest::Hello {
            protocol: WARD_NODE_PROTOCOL,
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        assert_eq!(
            serde_json::from_str::<HandshakeResponse>(line(&mut client).trim()).unwrap(),
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 3),
            }
        );
        (client, worker)
    }

    #[test]
    fn one_three_admit_is_refused_over_the_socket_and_the_task_stays_created() {
        let service = NodeService::new(capabilities()).unwrap();
        let ctx = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let binding = lifecycle_binding();
        let create = OperationId::new(1).unwrap();
        let admit = OperationId::new(2).unwrap();

        lifecycle_round_trip(&service, lifecycle_context().create(create, binding));

        let (mut client, worker) = admission_connection(&service);
        let request = crate::test_support::admit(ctx, admit, binding);
        writeln!(client, "{}", serde_json::to_string(&request).unwrap()).unwrap();
        assert_eq!(
            ctx.decode_response(line(&mut client).trim()).unwrap(),
            ctx.rejected(
                Some(admit),
                binding,
                TaskLifecycleRejectionReason::UnsupportedOperation
            )
        );
        worker.join().unwrap().unwrap();

        let (mut client, worker) = admission_connection(&service);
        writeln!(
            client,
            "{}",
            serde_json::to_string(&ctx.inspect(binding)).unwrap()
        )
        .unwrap();
        assert_eq!(
            ctx.decode_response(line(&mut client).trim()).unwrap(),
            ctx.inspected(binding, TaskLifecycleState::Created)
        );
        worker.join().unwrap().unwrap();
        assert_eq!(service.tasks.lock().unwrap().len(), 1);
    }

    #[test]
    fn one_two_connection_refuses_admit_like_an_unknown_request() {
        let service = NodeService::new(capabilities()).unwrap();
        let binding = lifecycle_binding();
        let admit = crate::test_support::admit(
            TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap(),
            OperationId::new(2).unwrap(),
            binding,
        );
        let one_three = serde_json::to_string(&admit).unwrap();
        let claiming_one_two = one_three.replace(r#""minor":3"#, r#""minor":2"#);
        let unknown = one_three.replace(r#""request":"admit""#, r#""request":"unknown""#);

        for payload in [one_three, claiming_one_two, unknown] {
            let (mut client, worker) = lifecycle_connection(&service);
            writeln!(client, "{payload}").unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(matches!(
                worker.join().unwrap(),
                Err(NodeServiceError::MalformedLifecycleRequest)
            ));
            assert_eq!(line(&mut client), "");
        }
        assert!(service.tasks.lock().unwrap().is_empty());
    }

    #[test]
    fn one_three_client_discovers_the_same_capabilities() {
        let service = NodeService::new(capabilities()).unwrap();
        let (mut client, worker) = admission_connection(&service);
        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        writeln!(
            client,
            "{}",
            serde_json::to_string(&context.request()).unwrap()
        )
        .unwrap();

        let response = context.decode_response(line(&mut client).trim()).unwrap();
        let ward_node_protocol::CapabilityDiscoveryResponse::Capabilities {
            capabilities: observed,
        } = response;
        assert_eq!(observed.protocol(), ProtocolVersion::new(1, 3));
        assert_eq!(
            observed.lifecycle(),
            LifecycleCapabilities {
                stop: false,
                start: false,
                pause: false,
                revoke: false,
                ..service.capabilities.lifecycle()
            },
            "a 1.3 node without execution advertises none of start, stop, pause or revoke"
        );
        assert_eq!(
            observed.isolation(),
            IsolationCapabilities {
                namespaces: NamespaceCapabilities::default(),
                ..service.capabilities.isolation()
            },
            "a 1.3 node without execution advertises no execution sandbox"
        );
        worker.join().unwrap().unwrap();
        assert!(service.tasks.lock().unwrap().is_empty());
    }

    #[test]
    fn capability_discovery_at_one_one_is_unchanged_by_the_task_registry() {
        let service = NodeService::new(capabilities()).unwrap();
        let ctx = lifecycle_context();
        let binding = lifecycle_binding();
        lifecycle_round_trip(&service, ctx.create(OperationId::new(1).unwrap(), binding));

        let (mut client, server) = UnixStream::pair().unwrap();
        let discovery_service = service.clone();
        let worker = std::thread::spawn(move || discovery_service.serve_connection(server));
        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 1, 1).unwrap(),
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        let _: HandshakeResponse = serde_json::from_str(line(&mut client).trim()).unwrap();
        let discovery = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 1)).unwrap();
        writeln!(
            client,
            "{}",
            serde_json::to_string(&discovery.request()).unwrap()
        )
        .unwrap();
        assert!(discovery.decode_response(line(&mut client).trim()).is_ok());
        worker.join().unwrap().unwrap();
    }

    struct LocalNode {
        _dir: tempfile::TempDir,
        socket: std::path::PathBuf,
        service: NodeService,
        worker: std::thread::JoinHandle<()>,
    }

    impl LocalNode {
        /// Bind a real private socket and serve exactly `connections` connections.
        fn serve(service: NodeService, connections: usize) -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let socket = dir.path().join("node.sock");
            let listener = bind_local(&socket, None).unwrap();
            let served = service.clone();
            let worker = std::thread::spawn(move || {
                for connection in listener.incoming().take(connections) {
                    served.serve_connection(connection.unwrap()).unwrap();
                }
            });
            Self {
                _dir: dir,
                socket,
                service,
                worker,
            }
        }

        /// One request on its own connection negotiated at `protocol`; the raw response.
        fn request(&self, protocol: SupportedProtocolRange, request: &str) -> String {
            let mut client = UnixStream::connect(&self.socket).unwrap();
            let hello = HandshakeRequest::Hello { protocol };
            writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
            let mut reader = BufReader::new(client.try_clone().unwrap());
            let mut accepted = String::new();
            reader.read_line(&mut accepted).unwrap();
            assert!(matches!(
                serde_json::from_str::<HandshakeResponse>(accepted.trim()).unwrap(),
                HandshakeResponse::Accepted { .. }
            ));
            writeln!(client, "{request}").unwrap();
            let mut response = String::new();
            reader.read_line(&mut response).unwrap();
            response.trim().to_owned()
        }

        fn lifecycle(&self, request: &TaskLifecycleRequest) -> TaskLifecycleResponse {
            let ctx = admission_context();
            let raw = self.request(WARD_NODE_PROTOCOL, &serde_json::to_string(request).unwrap());
            ctx.decode_response(&raw).unwrap()
        }

        fn join(self) {
            self.worker.join().unwrap();
        }
    }

    fn admission_context() -> TaskLifecycleContext {
        TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
    }

    fn admitting_service(state: &std::path::Path) -> NodeService {
        let clock = crate::test_support::FixedClock::at(crate::test_support::NOW);
        NodeService::with_admission(
            capabilities(),
            crate::test_support::node_admission(state, &clock),
        )
        .unwrap()
    }

    #[test]
    fn one_three_admit_over_the_local_socket_moves_the_task_to_ready() {
        let state = tempfile::tempdir().unwrap();
        let node = LocalNode::serve(admitting_service(&state.path().join("state")), 5);
        let ctx = admission_context();
        let binding = lifecycle_binding();
        let create = OperationId::new(1).unwrap();
        let admit = OperationId::new(2).unwrap();
        let envelope = ward_node_protocol::TaskAdmissionEnvelope::new(
            crate::test_support::envelope_input(binding),
        )
        .unwrap();
        let request = crate::test_support::signed_admit(ctx, admit, binding, &envelope);

        assert_eq!(
            node.lifecycle(&ctx.create(create, binding)),
            ctx.accepted(create, binding, TaskLifecycleState::Created)
        );
        let accepted = node.lifecycle(&request);
        assert_eq!(
            accepted,
            ctx.accepted(admit, binding, TaskLifecycleState::Ready)
        );
        assert_eq!(
            node.lifecycle(&ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Ready)
        );
        assert_eq!(node.lifecycle(&request), accepted);
        assert_eq!(
            node.lifecycle(&ctx.start(OperationId::new(3).unwrap(), binding)),
            ctx.rejected(
                Some(OperationId::new(3).unwrap()),
                binding,
                TaskLifecycleRejectionReason::UnsupportedOperation
            )
        );
        assert_eq!(
            node.service
                .tasks
                .lock()
                .unwrap()
                .admitted(binding)
                .unwrap()
                .envelope(),
            &envelope
        );
        node.join();
    }

    #[test]
    fn one_three_refused_admit_over_the_local_socket_leaves_the_task_created() {
        let state = tempfile::tempdir().unwrap();
        let node = LocalNode::serve(admitting_service(&state.path().join("state")), 3);
        let ctx = admission_context();
        let binding = lifecycle_binding();
        let admit = OperationId::new(2).unwrap();
        let json = ward_node_protocol::AdmissionEnvelopeJson::encode(
            &ward_node_protocol::TaskAdmissionEnvelope::new(crate::test_support::envelope_input(
                binding,
            ))
            .unwrap(),
        )
        .unwrap();
        let proof = crate::test_support::sign(&json, &crate::test_support::other_keypair());

        node.lifecycle(&ctx.create(OperationId::new(1).unwrap(), binding));
        assert_eq!(
            node.lifecycle(&ctx.admit(admit, binding, json, proof).unwrap()),
            ctx.rejected(
                Some(admit),
                binding,
                TaskLifecycleRejectionReason::AuthorityDenied
            )
        );
        assert_eq!(
            node.lifecycle(&ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Created)
        );
        node.join();
    }

    #[test]
    fn capability_discovery_advertises_admit_only_at_one_three_with_admission() {
        let state = tempfile::tempdir().unwrap();
        let admitting = LocalNode::serve(admitting_service(&state.path().join("state")), 3);
        let plain = LocalNode::serve(NodeService::new(capabilities()).unwrap(), 3);

        for minor in [1, 2] {
            let protocol = SupportedProtocolRange::new(1, minor, minor).unwrap();
            let request = serde_json::to_string(
                &CapabilityDiscoveryContext::new(ProtocolVersion::new(1, minor))
                    .unwrap()
                    .request(),
            )
            .unwrap();
            let advertised = admitting.request(protocol, &request);
            assert_eq!(advertised, plain.request(protocol, &request));
            assert!(
                advertised.ends_with(r#""lifecycle":{"pause":true,"stop":true,"revoke":true}}}"#),
                "{advertised}"
            );
        }

        let one_three = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let request = serde_json::to_string(&one_three.request()).unwrap();
        for (node, admit) in [(&admitting, true), (&plain, false)] {
            let raw = node.request(WARD_NODE_PROTOCOL, &request);
            let ward_node_protocol::CapabilityDiscoveryResponse::Capabilities {
                capabilities: observed,
            } = one_three.decode_response(&raw).unwrap();
            assert_eq!(observed.lifecycle().admit, admit, "{raw}");
        }
        admitting.join();
        plain.join();
    }

    struct Executing {
        _dir: tempfile::TempDir,
        root: std::path::PathBuf,
        service: NodeService,
        launcher: crate::test_support::FakeLauncher,
        snapshot: ward_events::SnapshotId,
    }

    fn executing_service() -> Executing {
        executing_service_with(capabilities(), crate::execution::DEFAULT_STOP_TIMEOUT)
    }

    fn executing_service_with(configured: NodeCapabilities, stop_timeout: Duration) -> Executing {
        executing_service_built(configured, stop_timeout, false, false, false)
    }

    fn executing_service_with_actions() -> Executing {
        executing_service_built(
            capabilities(),
            crate::execution::DEFAULT_STOP_TIMEOUT,
            false,
            false,
            true,
        )
    }

    fn executing_service_enforcing_a_network_allowlist() -> Executing {
        executing_service_built(
            capabilities(),
            crate::execution::DEFAULT_STOP_TIMEOUT,
            true,
            false,
            false,
        )
    }

    fn executing_service_returning_output() -> Executing {
        executing_service_built(
            capabilities(),
            crate::execution::DEFAULT_STOP_TIMEOUT,
            false,
            true,
            false,
        )
    }

    fn executing_service_brokering(network_allowlist: bool) -> Executing {
        executing_service_configured(
            capabilities(),
            crate::execution::DEFAULT_STOP_TIMEOUT,
            (network_allowlist, false, false, false),
            Some(Arc::new(
                crate::credentials::NodeCredentials::parse(crate::test_support::CREDENTIALS)
                    .unwrap(),
            )),
        )
    }

    fn executing_service_built(
        configured: NodeCapabilities,
        stop_timeout: Duration,
        network_allowlist: bool,
        output_return: bool,
        action_channel: bool,
    ) -> Executing {
        executing_service_configured(
            configured,
            stop_timeout,
            (network_allowlist, output_return, action_channel, false),
            None,
        )
    }

    fn executing_service_configured(
        configured: NodeCapabilities,
        stop_timeout: Duration,
        (network_allowlist, output_return, action_channel, approval_hold): (bool, bool, bool, bool),
        credentials: Option<Arc<crate::credentials::NodeCredentials>>,
    ) -> Executing {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let clock = crate::test_support::FixedClock::at(crate::test_support::NOW);
        let admission = crate::test_support::node_admission(&state, &clock);
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("hello.txt"), b"hello").unwrap();
        let snapshots = crate::workspace::open_snapshot_store(&state).unwrap();
        let snapshot = crate::workspace::import_snapshot(&snapshots, &project).unwrap();
        let launcher = crate::test_support::FakeLauncher::new();
        let execution = NodeExecution::new(
            crate::workspace::TaskRoot::open(&dir.path().join("tasks")).unwrap(),
            snapshots,
            Arc::new(launcher.clone()),
        )
        .with_stop_timeout(stop_timeout)
        .with_network_allowlist(network_allowlist)
        .with_output_return(output_return)
        .with_action_channel(action_channel)
        .with_approval_hold(approval_hold)
        .with_credentials(credentials);
        let service = NodeService::with_execution(configured, admission, execution).unwrap();
        Executing {
            root: dir.path().join("tasks"),
            _dir: dir,
            service,
            launcher,
            snapshot,
        }
    }

    #[test]
    fn capability_discovery_advertises_start_and_stop_together_only_with_execution() {
        let state = tempfile::tempdir().unwrap();
        let executing = executing_service();
        let executing_node = LocalNode::serve(executing.service.clone(), 3);
        let admitting = LocalNode::serve(admitting_service(&state.path().join("state")), 1);
        let plain = LocalNode::serve(NodeService::new(capabilities()).unwrap(), 2);

        for minor in [1, 2] {
            let protocol = SupportedProtocolRange::new(1, minor, minor).unwrap();
            let request = serde_json::to_string(
                &CapabilityDiscoveryContext::new(ProtocolVersion::new(1, minor))
                    .unwrap()
                    .request(),
            )
            .unwrap();
            assert_eq!(
                executing_node.request(protocol, &request),
                plain.request(protocol, &request),
                "1.{minor} documents are unchanged by execution"
            );
        }

        let one_three = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let request = serde_json::to_string(&one_three.request()).unwrap();
        for (node, executes) in [(&executing_node, true), (&admitting, false)] {
            let raw = node.request(WARD_NODE_PROTOCOL, &request);
            let ward_node_protocol::CapabilityDiscoveryResponse::Capabilities {
                capabilities: observed,
            } = one_three.decode_response(&raw).unwrap();
            let lifecycle = observed.lifecycle();
            assert_eq!(lifecycle.start, executes, "{raw}");
            assert_eq!(lifecycle.stop, executes, "{raw}");
            assert!(lifecycle.admit, "{raw}");
            assert_eq!(lifecycle.pause, executes, "{raw}");
            assert_eq!(lifecycle.revoke, executes, "{raw}");
        }
        executing_node.join();
        admitting.join();
        plain.join();
    }

    #[test]
    fn one_three_start_and_stop_over_the_local_socket() {
        let executing = executing_service();
        let node = LocalNode::serve(executing.service.clone(), 7);
        let ctx = admission_context();
        let binding = lifecycle_binding();
        let mut input = crate::test_support::envelope_input(binding);
        input.workload = ward_node_protocol::TaskWorkload::new(
            input.workload.argv().clone(),
            input.workload.capability_manifest().clone(),
            executing.snapshot,
            60_000,
        )
        .unwrap();
        let envelope = ward_node_protocol::TaskAdmissionEnvelope::new(input).unwrap();
        let start = OperationId::new(3).unwrap();
        let stop = OperationId::new(4).unwrap();

        node.lifecycle(&ctx.create(OperationId::new(1).unwrap(), binding));
        node.lifecycle(&crate::test_support::signed_admit(
            ctx,
            OperationId::new(2).unwrap(),
            binding,
            &envelope,
        ));
        assert_eq!(
            node.lifecycle(&ctx.start(start, binding)),
            ctx.accepted(start, binding, TaskLifecycleState::Running)
        );
        assert_eq!(
            node.lifecycle(&ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Running)
        );
        assert_eq!(
            node.lifecycle(&ctx.stop(stop, binding)),
            ctx.accepted(stop, binding, TaskLifecycleState::Stopped)
        );
        assert_eq!(
            node.lifecycle(&ctx.inspect(binding)),
            ctx.inspected_with_outcome(
                binding,
                TaskLifecycleState::Stopped,
                ward_node_protocol::TaskExecutionOutcome::Failed
            )
            .unwrap()
        );
        assert_eq!(
            node.lifecycle(&ctx.stop(stop, binding)),
            ctx.accepted(stop, binding, TaskLifecycleState::Stopped)
        );
        assert_eq!(executing.launcher.stopped(), 1);
        node.join();
    }

    /// One request on its own connection negotiated at `protocol`, whose request deadline
    /// is `request_timeout`; the raw response line and how serving ended.
    fn exchange(
        service: &NodeService,
        protocol: SupportedProtocolRange,
        request: &str,
        request_timeout: Duration,
    ) -> (String, Result<(), NodeServiceError>) {
        let service = service.clone();
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            service.serve_connection_with_lifetime(server, request_timeout)
        });
        let hello = HandshakeRequest::Hello { protocol };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        assert!(matches!(
            serde_json::from_str::<HandshakeResponse>(line(&mut client).trim()).unwrap(),
            HandshakeResponse::Accepted { .. }
        ));
        writeln!(client, "{request}").unwrap();
        let response = line(&mut client);
        (response.trim().to_owned(), worker.join().unwrap())
    }

    fn runnable_admit(executing: &Executing, binding: TaskBinding) -> TaskLifecycleRequest {
        let mut input = crate::test_support::envelope_input(binding);
        input.workload = ward_node_protocol::TaskWorkload::new(
            input.workload.argv().clone(),
            input.workload.capability_manifest().clone(),
            executing.snapshot,
            60_000,
        )
        .unwrap();
        let envelope = ward_node_protocol::TaskAdmissionEnvelope::new(input).unwrap();
        crate::test_support::signed_admit(
            admission_context(),
            OperationId::new(2).unwrap(),
            binding,
            &envelope,
        )
    }

    #[test]
    fn a_stop_whose_reap_outlasts_the_request_deadline_still_gets_its_answer() {
        let executing = executing_service_with(capabilities(), Duration::from_secs(10));
        let ctx = admission_context();
        let binding = lifecycle_binding();
        let request_timeout = Duration::from_millis(100);
        let lifecycle = |request: &TaskLifecycleRequest| {
            let (raw, served) = exchange(
                &executing.service,
                WARD_NODE_PROTOCOL,
                &serde_json::to_string(request).unwrap(),
                request_timeout,
            );
            (ctx.decode_response(&raw), served)
        };
        let start = OperationId::new(3).unwrap();
        let stop = OperationId::new(4).unwrap();

        lifecycle(&ctx.create(OperationId::new(1).unwrap(), binding))
            .1
            .unwrap();
        lifecycle(&runnable_admit(&executing, binding)).1.unwrap();
        assert_eq!(
            lifecycle(&ctx.start(start, binding)).0.unwrap(),
            ctx.accepted(start, binding, TaskLifecycleState::Running)
        );

        executing
            .launcher
            .set_on_stop(crate::test_support::FakeStop::Ignore);
        let launcher = executing.launcher.clone();
        let reap_after = request_timeout * 4;
        let release = std::thread::spawn(move || {
            std::thread::sleep(reap_after);
            launcher.set_on_stop(crate::test_support::FakeStop::Honour);
        });
        let asked = Instant::now();
        let (answer, served) = lifecycle(&ctx.stop(stop, binding));
        assert!(asked.elapsed() >= reap_after, "the reap was not slow");
        release.join().unwrap();
        assert_eq!(
            answer.expect("a slow stop is answered, not closed"),
            ctx.accepted(stop, binding, TaskLifecycleState::Stopped)
        );
        served.unwrap();
        assert_eq!(executing.launcher.stopped(), 1);
    }

    fn conservative_capabilities() -> NodeCapabilities {
        NodeCapabilities::new(
            ProtocolVersion::new(1, 1),
            NodeArchitecture::X86_64,
            NodeCapacity::new(8, 16 * 1024 * 1024 * 1024).unwrap(),
            IsolationCapabilities::default(),
            NetworkCapabilities::default(),
            CredentialCapabilities::default(),
            SnapshotCapabilities::default(),
            VerifierCapabilities::default(),
            LifecycleCapabilities::default(),
        )
        .unwrap()
    }

    fn discovered(service: &NodeService, minor: u16) -> (String, NodeCapabilities) {
        let context = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, minor)).unwrap();
        let (raw, served) = exchange(
            service,
            SupportedProtocolRange::new(1, minor, minor).unwrap(),
            &serde_json::to_string(&context.request()).unwrap(),
            REQUEST_TIMEOUT,
        );
        served.unwrap();
        let ward_node_protocol::CapabilityDiscoveryResponse::Capabilities { capabilities } =
            context.decode_response(&raw).unwrap();
        (raw, capabilities)
    }

    #[test]
    fn an_executing_node_advertises_the_isolation_it_enforces_only_at_one_three() {
        let executing = executing_service_with(
            conservative_capabilities(),
            crate::execution::DEFAULT_STOP_TIMEOUT,
        );
        let state = tempfile::tempdir().unwrap();
        let clock = crate::test_support::FixedClock::at(crate::test_support::NOW);
        let admitting = NodeService::with_admission(
            conservative_capabilities(),
            crate::test_support::node_admission(&state.path().join("state"), &clock),
        )
        .unwrap();
        let plain = NodeService::new(conservative_capabilities()).unwrap();

        let observed = discovered(&executing.service, 3).1;
        assert_eq!(
            observed.isolation(),
            IsolationCapabilities {
                namespaces: NamespaceCapabilities {
                    sandbox: true,
                    user_namespace: true,
                },
                backends: ExecutionBackendCapabilities::default(),
            }
        );
        assert_eq!(
            observed.network(),
            NetworkCapabilities {
                offline: true,
                proxy_allowlist: false,
            }
        );
        assert_eq!(
            observed.snapshots(),
            SnapshotCapabilities {
                content_addressed: true,
                diff: false,
                read: false,
            }
        );
        assert_eq!(observed.credentials(), CredentialCapabilities::default());
        assert_eq!(observed.verifier(), VerifierCapabilities::default());
        assert!(observed.lifecycle().start && observed.lifecycle().stop);

        for service in [&admitting, &plain] {
            let observed = discovered(service, 3).1;
            assert_eq!(observed.isolation(), IsolationCapabilities::default());
            assert_eq!(observed.network(), NetworkCapabilities::default());
            assert_eq!(observed.snapshots(), SnapshotCapabilities::default());
        }

        for minor in [1, 2] {
            let (raw, observed) = discovered(&executing.service, minor);
            assert_eq!(raw, discovered(&plain, minor).0, "1.{minor}");
            assert_eq!(observed.isolation(), IsolationCapabilities::default());
            assert_eq!(observed.network(), NetworkCapabilities::default());
            assert_eq!(observed.snapshots(), SnapshotCapabilities::default());
        }
    }

    #[test]
    fn proxy_allowlist_is_advertised_only_by_an_executing_node_enforcing_one_at_one_three() {
        let enforcing = executing_service_enforcing_a_network_allowlist();
        let executing = executing_service();
        let observed = discovered(&enforcing.service, 3).1;
        assert_eq!(
            observed.network(),
            NetworkCapabilities {
                offline: true,
                proxy_allowlist: true,
            }
        );
        assert!(
            !discovered(&executing.service, 3)
                .1
                .network()
                .proxy_allowlist
        );
        for minor in [1, 2] {
            assert_eq!(
                discovered(&enforcing.service, minor).0,
                discovered(&executing.service, minor).0,
                "1.{minor}"
            );
            assert_eq!(
                discovered(&enforcing.service, minor).1.network(),
                capabilities().network()
            );
        }
    }

    #[test]
    fn a_node_that_does_not_execute_never_advertises_execution_isolation_at_one_three() {
        let state = tempfile::tempdir().unwrap();
        let clock = crate::test_support::FixedClock::at(crate::test_support::NOW);
        let admitting = NodeService::with_admission(
            capabilities(),
            crate::test_support::node_admission(&state.path().join("state"), &clock),
        )
        .unwrap();
        let observed = discovered(&admitting, 3).1;
        assert_eq!(
            observed.isolation().namespaces,
            NamespaceCapabilities::default()
        );
        assert!(!observed.network().offline);
        assert!(!observed.snapshots().content_addressed);
        assert_eq!(
            observed.isolation().backends,
            capabilities().isolation().backends
        );
        assert_eq!(observed.credentials(), CredentialCapabilities::default());
        assert_eq!(
            discovered(&admitting, 1).1.credentials(),
            capabilities().credentials()
        );
        assert_eq!(observed.verifier(), capabilities().verifier());
        assert_eq!(
            discovered(&admitting, 1).1.isolation(),
            capabilities().isolation()
        );
    }

    #[test]
    fn capability_discovery_advertises_pause_and_revoke_only_at_one_three_with_execution() {
        let executing = executing_service();
        let base = capabilities();
        let configured = NodeCapabilities::new(
            base.protocol(),
            base.architecture(),
            base.capacity(),
            base.isolation(),
            base.network(),
            base.credentials(),
            base.snapshots(),
            base.verifier(),
            LifecycleCapabilities::default(),
        )
        .unwrap();
        let state = tempfile::tempdir().unwrap();
        let clock = crate::test_support::FixedClock::at(crate::test_support::NOW);
        let quiet = NodeService::with_execution(
            configured,
            crate::test_support::node_admission(&state.path().join("state"), &clock),
            NodeExecution::new(
                crate::workspace::TaskRoot::open(&state.path().join("tasks")).unwrap(),
                crate::workspace::open_snapshot_store(&state.path().join("state")).unwrap(),
                Arc::new(executing.launcher.clone()),
            ),
        )
        .unwrap();
        let node = LocalNode::serve(quiet, 3);
        for minor in [1, 2] {
            let protocol = SupportedProtocolRange::new(1, minor, minor).unwrap();
            let request = serde_json::to_string(
                &CapabilityDiscoveryContext::new(ProtocolVersion::new(1, minor))
                    .unwrap()
                    .request(),
            )
            .unwrap();
            assert!(
                node.request(protocol, &request)
                    .ends_with(r#""lifecycle":{"pause":false,"stop":false,"revoke":false}}}"#),
                "1.{minor} documents are unchanged by execution"
            );
        }
        let one_three = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let raw = node.request(
            WARD_NODE_PROTOCOL,
            &serde_json::to_string(&one_three.request()).unwrap(),
        );
        assert!(
            raw.ends_with(
                r#""lifecycle":{"pause":true,"stop":true,"revoke":true,"admit":true,"start":true}}}"#
            ),
            "{raw}"
        );
        node.join();
    }

    fn one_three_round_trip(
        service: &NodeService,
        request: &TaskLifecycleRequest,
    ) -> TaskLifecycleResponse {
        let (mut client, worker) = admission_connection(service);
        writeln!(client, "{}", serde_json::to_string(request).unwrap()).unwrap();
        let response = admission_context()
            .decode_response(line(&mut client).trim())
            .unwrap();
        worker.join().unwrap().unwrap();
        response
    }

    #[test]
    fn a_transition_whose_client_disconnects_is_applied_whole_or_not_at_all() {
        let executing = executing_service();
        let service = &executing.service;
        let ctx = admission_context();
        let binding = lifecycle_binding();
        let mut input = crate::test_support::envelope_input(binding);
        input.workload = ward_node_protocol::TaskWorkload::new(
            input.workload.argv().clone(),
            input.workload.capability_manifest().clone(),
            executing.snapshot,
            60_000,
        )
        .unwrap();
        let envelope = ward_node_protocol::TaskAdmissionEnvelope::new(input).unwrap();
        one_three_round_trip(service, &ctx.create(OperationId::new(1).unwrap(), binding));
        one_three_round_trip(
            service,
            &crate::test_support::signed_admit(
                ctx,
                OperationId::new(2).unwrap(),
                binding,
                &envelope,
            ),
        );
        let start = OperationId::new(3).unwrap();
        assert_eq!(
            one_three_round_trip(service, &ctx.start(start, binding)),
            ctx.accepted(start, binding, TaskLifecycleState::Running)
        );
        crate::test_support::eventually(|| executing.launcher.waiting() == 1);

        let pause = OperationId::new(5).unwrap();
        let request = serde_json::to_string(&ctx.pause(pause, binding)).unwrap();
        let (mut client, worker) = admission_connection(service);
        client
            .write_all(&request.as_bytes()[..request.len() / 2])
            .unwrap();
        client.shutdown(std::net::Shutdown::Both).unwrap();
        drop(client);
        assert!(worker.join().unwrap().is_err());
        assert_eq!(
            one_three_round_trip(service, &ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Running),
            "a request cut off before its newline is never applied"
        );
        assert_eq!(executing.launcher.freezes(), 0);

        let (mut client, worker) = admission_connection(service);
        writeln!(client, "{request}").unwrap();
        client.shutdown(std::net::Shutdown::Both).unwrap();
        drop(client);
        let _ = worker.join().unwrap();
        assert_eq!(
            one_three_round_trip(service, &ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Paused),
            "a complete request is applied whole although nobody read the answer"
        );
        assert_eq!(
            one_three_round_trip(service, &ctx.pause(pause, binding)),
            ctx.accepted(pause, binding, TaskLifecycleState::Paused)
        );
        assert_eq!(executing.launcher.freezes(), 1);

        let revoke = OperationId::new(6).unwrap();
        let (mut client, worker) = admission_connection(service);
        writeln!(
            client,
            "{}",
            serde_json::to_string(&ctx.revoke(revoke, binding)).unwrap()
        )
        .unwrap();
        client.shutdown(std::net::Shutdown::Both).unwrap();
        drop(client);
        let _ = worker.join().unwrap();
        assert_eq!(
            one_three_round_trip(service, &ctx.revoke(revoke, binding)),
            ctx.accepted(revoke, binding, TaskLifecycleState::Revoked)
        );
        assert_eq!(executing.launcher.stopped(), 1);
        assert!(
            service
                .tasks
                .lock()
                .unwrap()
                .admission()
                .unwrap()
                .state()
                .revocation(binding.lease())
                .is_some()
        );
    }

    #[test]
    fn protocol_state_is_connection_local() {
        let service = NodeService::new(capabilities()).unwrap();

        let (mut rejected_client, rejected_server) = UnixStream::pair().unwrap();
        let rejected_service = service.clone();
        let rejected =
            std::thread::spawn(move || rejected_service.serve_connection(rejected_server));
        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(2, 0, 0).unwrap(),
        };
        writeln!(
            rejected_client,
            "{}",
            serde_json::to_string(&hello).unwrap()
        )
        .unwrap();
        let _: HandshakeResponse = serde_json::from_str(line(&mut rejected_client).trim()).unwrap();
        rejected.join().unwrap().unwrap();

        let (mut accepted_client, accepted_server) = UnixStream::pair().unwrap();
        let accepted = std::thread::spawn(move || service.serve_connection(accepted_server));
        let hello = HandshakeRequest::Hello {
            protocol: SupportedProtocolRange::new(1, 1, 1).unwrap(),
        };
        writeln!(
            accepted_client,
            "{}",
            serde_json::to_string(&hello).unwrap()
        )
        .unwrap();
        assert!(matches!(
            serde_json::from_str::<HandshakeResponse>(line(&mut accepted_client).trim()).unwrap(),
            HandshakeResponse::Accepted { .. }
        ));
        accepted_client.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(accepted.join().unwrap().is_err());
    }

    #[test]
    fn output_is_advertised_only_by_an_executing_node_returning_it_at_one_three() {
        let returning = executing_service_returning_output();
        let executing = executing_service();
        let (raw, observed) = discovered(&returning.service, 3);
        assert_eq!(
            observed.output(),
            ward_node_protocol::OutputCapabilities {
                stdio: true,
                files: true,
            }
        );
        assert!(
            raw.contains(r#""output":{"stdio":true,"files":true}"#),
            "{raw}"
        );
        let (raw, observed) = discovered(&executing.service, 3);
        assert_eq!(
            observed.output(),
            ward_node_protocol::OutputCapabilities::NONE
        );
        assert!(!raw.contains("output"), "{raw}");
        for minor in [1, 2] {
            assert_eq!(
                discovered(&returning.service, minor).0,
                discovered(&executing.service, minor).0,
                "1.{minor}"
            );
        }
        let state = tempfile::tempdir().unwrap();
        let admitting = admitting_service(&state.path().join("state"));
        assert!(!discovered(&admitting, 3).0.contains("output"));
    }

    /// The reaper stores an attempt's output before it records the attempt's end, and a
    /// result is answered only once the end is recorded.
    fn until_the_attempt_has_ended(service: &NodeService, result_line: &str) {
        crate::test_support::eventually(|| {
            let (raw, _) = exchange(service, WARD_NODE_PROTOCOL, result_line, REQUEST_TIMEOUT);
            !raw.contains(r#""reason":"invalid_state""#)
        });
    }

    #[test]
    fn a_result_request_over_the_local_socket_returns_the_stored_output_or_a_typed_refusal() {
        let returning = executing_service_returning_output();
        let node = LocalNode::serve(returning.service.clone(), 5);
        let context = TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let binding = TaskBinding::new(
            TaskId::from_u128(7),
            ExecutionAttemptId::from_u128(8),
            LeaseId::from_u128(9),
        );
        let result_line = serde_json::to_string(&context.result(binding).unwrap()).unwrap();
        let decode = |raw: &str| context.decode_result_response(raw).unwrap();

        assert_eq!(
            decode(&node.request(WARD_NODE_PROTOCOL, &result_line)),
            context.result_rejected(binding, TaskLifecycleRejectionReason::TaskNotFound)
        );
        assert_eq!(
            node.lifecycle(&context.create(OperationId::new(1).unwrap(), binding)),
            context.accepted(
                OperationId::new(1).unwrap(),
                binding,
                TaskLifecycleState::Created
            )
        );
        let mut input = crate::test_support::envelope_input(binding);
        crate::test_support::with_manifest(
            &mut input,
            crate::test_support::output_manifest(8, &["out.txt"], 64),
        );
        input.workload = ward_node_protocol::TaskWorkload::new(
            input.workload.argv().clone(),
            input.workload.capability_manifest().clone(),
            returning.snapshot,
            input.workload.wall_clock_budget_ms(),
        )
        .unwrap();
        let envelope = ward_node_protocol::TaskAdmissionEnvelope::new(input).unwrap();
        assert_eq!(
            node.lifecycle(&crate::test_support::signed_admit(
                context,
                OperationId::new(2).unwrap(),
                binding,
                &envelope
            )),
            context.accepted(
                OperationId::new(2).unwrap(),
                binding,
                TaskLifecycleState::Ready
            )
        );
        returning.launcher.set_stdio(b"hello world", b"");
        assert_eq!(
            node.lifecycle(&context.start(OperationId::new(3).unwrap(), binding)),
            context.accepted(
                OperationId::new(3).unwrap(),
                binding,
                TaskLifecycleState::Running
            )
        );
        crate::test_support::eventually(|| returning.launcher.waiting() == 1);
        let workspace = returning
            .root
            .join(binding.task().to_string())
            .join(binding.attempt().to_string());
        std::fs::write(workspace.join("out.txt"), b"bye").unwrap();
        returning
            .launcher
            .exit(crate::execution::WorkloadExit::Exited { code: Some(0) });
        until_the_attempt_has_ended(&returning.service, &result_line);
        let raw = node.request(WARD_NODE_PROTOCOL, &result_line);
        assert!(
            raw.starts_with(r#"{"response":"result","protocol":{"major":1,"minor":3},"binding":"#),
            "{raw}"
        );
        match decode(&raw) {
            ward_node_protocol::TaskResultResponse::Result { state, output, .. } => {
                assert_eq!(state, TaskLifecycleState::Exited);
                assert_eq!(output.stdout().content(), b"hello wo");
                assert_eq!(output.stdout().dropped(), 3);
                assert!(matches!(
                    &output.files()[0].status,
                    ward_node_protocol::OutputFileStatus::Returned { content, .. } if content == b"bye"
                ));
            }
            other @ ward_node_protocol::TaskResultResponse::Rejected { .. } => {
                panic!("{other:?}")
            }
        }
        node.join();
        // At 1.2 the verb is unknown: the connection closes with no answer.
        let one_two = SupportedProtocolRange::new(1, 2, 2).unwrap();
        let early = result_line.replace(r#""minor":3"#, r#""minor":2"#);
        let (raw, served) = exchange(&returning.service, one_two, &early, REQUEST_TIMEOUT);
        assert_eq!(raw, "");
        assert!(matches!(
            served,
            Err(NodeServiceError::MalformedLifecycleRequest)
        ));
    }

    fn executing_service_scheduling(
        scheduling: Option<crate::scheduling::SchedulingLimits>,
        resources: Option<crate::cgroup::ResourceEnforcement>,
    ) -> Executing {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let clock = crate::test_support::FixedClock::at(crate::test_support::NOW);
        let admission = crate::test_support::node_admission(&state, &clock);
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("hello.txt"), b"hello").unwrap();
        let snapshots = crate::workspace::open_snapshot_store(&state).unwrap();
        let snapshot = crate::workspace::import_snapshot(&snapshots, &project).unwrap();
        let launcher = crate::test_support::FakeLauncher::new();
        let execution = NodeExecution::new(
            crate::workspace::TaskRoot::open(&dir.path().join("tasks")).unwrap(),
            snapshots,
            Arc::new(launcher.clone()),
        )
        .with_scheduling(scheduling)
        .with_resource_enforcement(resources);
        let service = NodeService::with_execution(capabilities(), admission, execution).unwrap();
        Executing {
            root: dir.path().join("tasks"),
            _dir: dir,
            service,
            launcher,
            snapshot,
        }
    }

    #[test]
    fn scheduling_and_resources_are_advertised_only_when_configured_and_only_at_one_three() {
        let plain = executing_service_scheduling(None, None);
        let (raw, served) = discovered(&plain.service, 3);
        assert!(
            !raw.contains("scheduling") && !raw.contains("resources"),
            "{raw}"
        );
        assert_eq!((served.scheduling(), served.resources()), (None, None));

        let enforces = ward_node_protocol::ResourceCapabilities {
            cpu: true,
            memory: false,
            pids: true,
        };
        let loaded = executing_service_scheduling(
            crate::scheduling::SchedulingLimits::new(25, 0, 0),
            Some(crate::cgroup::ResourceEnforcement::new(
                enforces,
                NodeCapacity::new(4, 1 << 33).unwrap(),
            )),
        );
        let (raw, served) = discovered(&loaded.service, 3);
        assert!(
            raw.contains(r#""resources":{"cpu":true,"memory":false,"pids":true},"scheduling":{"max_running":25,"running":0,"#),
            "{raw}"
        );
        assert_eq!(served.resources(), Some(enforces));
        let scheduling = served.scheduling().unwrap();
        assert_eq!((scheduling.max_running, scheduling.running), (25, 0));
        assert!(scheduling.memory_available_bytes > 0);
        for minor in [1, 2] {
            let (raw, served) = discovered(&loaded.service, minor);
            assert!(
                !raw.contains("scheduling") && !raw.contains("resources"),
                "{raw}"
            );
            assert_eq!((served.scheduling(), served.resources()), (None, None));
        }
        let _ = (&loaded.root, &loaded.launcher, loaded.snapshot);
    }

    #[test]
    fn credentials_are_advertised_only_by_a_node_brokering_them_behind_its_allowlist_at_one_three()
    {
        let brokering = executing_service_brokering(true);
        let unenforced = executing_service_brokering(false);
        let allowlisting = executing_service_enforcing_a_network_allowlist();
        let (raw, observed) = discovered(&brokering.service, 3);
        assert_eq!(
            observed.credentials(),
            ward_node_protocol::CredentialCapabilities {
                proxy_injection: true,
                scoped_http_gateway: true,
            }
        );
        assert!(
            raw.contains(r#""credentials":{"proxy_injection":true,"scoped_http_gateway":true}"#),
            "{raw}"
        );
        for other in [&unenforced, &allowlisting] {
            let (raw, observed) = discovered(&other.service, 3);
            assert_eq!(
                observed.credentials(),
                ward_node_protocol::CredentialCapabilities::default()
            );
            assert!(
                raw.contains(
                    r#""credentials":{"proxy_injection":false,"scoped_http_gateway":false}"#
                ),
                "{raw}"
            );
        }
        for minor in [1, 2] {
            assert_eq!(
                discovered(&brokering.service, minor).0,
                discovered(&allowlisting.service, minor).0,
                "1.{minor}"
            );
        }
    }

    fn executing_service_holding(network_allowlist: bool, action_channel: bool) -> Executing {
        executing_service_configured(
            capabilities(),
            crate::execution::DEFAULT_STOP_TIMEOUT,
            (network_allowlist, false, action_channel, true),
            None,
        )
    }

    #[test]
    fn the_hold_is_advertised_only_with_the_channel_and_the_allowlist_and_admitted_only_then() {
        let holding = executing_service_holding(true, true);
        let (raw, observed) = discovered(&holding.service, 3);
        assert!(observed.actions().hold);
        assert!(
            raw.contains(r#""actions":{"approval":true,"decision":true,"max_pending":8,"max_total":64,"max_wait_secs":3600,"hold":true}"#),
            "{raw}"
        );
        for minor in [1, 2] {
            assert!(
                !discovered(&holding.service, minor).0.contains("hold"),
                "1.{minor}"
            );
        }
        let channel_only = executing_service_holding(false, true);
        let (raw, observed) = discovered(&channel_only.service, 3);
        assert!(!observed.actions().hold);
        assert!(!raw.contains("hold"), "{raw}");
        let allowlist_only = executing_service_holding(true, false);
        let (raw, observed) = discovered(&allowlist_only.service, 3);
        assert_eq!(
            observed.actions(),
            ward_node_protocol::ActionCapabilities::NONE
        );
        assert!(!raw.contains("hold"), "{raw}");
        let unflagged = executing_service_built(
            capabilities(),
            crate::execution::DEFAULT_STOP_TIMEOUT,
            true,
            false,
            true,
        );
        assert_eq!(
            discovered(&unflagged.service, 3).1.actions(),
            ward_node_protocol::ActionCapabilities::CEILINGS
        );
    }

    #[test]
    fn actions_are_advertised_only_by_an_executing_node_with_the_channel_at_one_three() {
        let channel = executing_service_with_actions();
        let executing = executing_service();
        let (raw, observed) = discovered(&channel.service, 3);
        assert_eq!(
            observed.actions(),
            ward_node_protocol::ActionCapabilities::CEILINGS
        );
        assert!(
            raw.contains(r#""actions":{"approval":true,"decision":true,"max_pending":8,"max_total":64,"max_wait_secs":3600}"#),
            "{raw}"
        );
        let (raw, observed) = discovered(&executing.service, 3);
        assert_eq!(
            observed.actions(),
            ward_node_protocol::ActionCapabilities::NONE
        );
        assert!(!raw.contains("actions"), "{raw}");
        for minor in [1, 2] {
            assert_eq!(
                discovered(&channel.service, minor).0,
                discovered(&executing.service, minor).0,
                "1.{minor}"
            );
        }
        let state = tempfile::tempdir().unwrap();
        assert!(
            !discovered(&admitting_service(&state.path().join("state")), 3)
                .0
                .contains("actions")
        );
    }

    fn actions_admit(
        executing: &Executing,
        binding: TaskBinding,
        manifest: ward_node_protocol::CapabilityManifestBytes,
    ) -> TaskLifecycleRequest {
        let mut input = crate::test_support::envelope_input(binding);
        input.workload = ward_node_protocol::TaskWorkload::new(
            input.workload.argv().clone(),
            manifest,
            executing.snapshot,
            60_000,
        )
        .unwrap();
        crate::test_support::signed_admit(
            admission_context(),
            OperationId::new(2).unwrap(),
            binding,
            &ward_node_protocol::TaskAdmissionEnvelope::new(input).unwrap(),
        )
    }

    fn actions_manifest(max_pending: u32) -> ward_node_protocol::CapabilityManifestBytes {
        crate::test_support::actions_manifest(max_pending, 8, 600)
    }

    /// Send `request` (a lifecycle or actions request) on its own connection at 1.3.
    fn served(service: &NodeService, request: &impl serde::Serialize) -> String {
        let (raw, served) = exchange(
            service,
            WARD_NODE_PROTOCOL,
            &serde_json::to_string(request).unwrap(),
            REQUEST_TIMEOUT,
        );
        served.unwrap();
        raw
    }

    fn actions_of(
        service: &NodeService,
        binding: TaskBinding,
    ) -> ward_node_protocol::TaskActionsResponse {
        let context = admission_context();
        context
            .decode_actions_response(&served(service, &context.actions(binding).unwrap()))
            .unwrap()
    }

    fn pending_of(
        service: &NodeService,
        binding: TaskBinding,
        count: usize,
    ) -> Vec<ward_node_protocol::PendingAction> {
        let mut found = Vec::new();
        crate::test_support::eventually(|| {
            found = match actions_of(service, binding) {
                ward_node_protocol::TaskActionsResponse::Actions { pending, .. } => pending,
                other => panic!("{other:?}"),
            };
            found.len() == count
        });
        found
    }

    fn answer(
        service: &NodeService,
        operation: u64,
        binding: TaskBinding,
        action: u32,
        decision: ward_node_protocol::ActionDecision,
    ) -> ward_node_protocol::TaskActionsResponse {
        let context = admission_context();
        let request = context
            .answer(
                OperationId::new(operation).unwrap(),
                binding,
                action,
                decision,
                None,
            )
            .unwrap();
        context
            .decode_actions_response(&served(service, &request))
            .unwrap()
    }

    fn started_with_actions(
        executing: &Executing,
        binding: TaskBinding,
        max_pending: u32,
    ) -> (UnixStream, BufReader<UnixStream>) {
        let context = admission_context();
        let accepted = |raw: String| context.decode_response(&raw).unwrap();
        assert!(matches!(
            accepted(served(
                &executing.service,
                &context.create(OperationId::new(1).unwrap(), binding)
            )),
            TaskLifecycleResponse::Accepted { .. }
        ));
        assert_eq!(
            accepted(served(
                &executing.service,
                &actions_admit(executing, binding, actions_manifest(max_pending))
            )),
            context.accepted(
                OperationId::new(2).unwrap(),
                binding,
                TaskLifecycleState::Ready
            )
        );
        assert_eq!(
            accepted(served(
                &executing.service,
                &context.start(OperationId::new(3).unwrap(), binding)
            )),
            context.accepted(
                OperationId::new(3).unwrap(),
                binding,
                TaskLifecycleState::Running
            )
        );
        let launch = executing.launcher.launches().pop().unwrap();
        let socket = launch
            .action_socket()
            .expect("the launch binds the channel")
            .to_path_buf();
        assert_eq!(
            socket,
            crate::actions::actions_dir(&executing.root, binding)
                .join(crate::actions::ACTION_SOCKET_FILE)
        );
        let stream = UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        (stream, reader)
    }

    fn channel_reply(reader: &mut BufReader<UnixStream>) -> ward_node_protocol::ActionReply {
        let mut text = String::new();
        reader.read_line(&mut text).unwrap();
        ward_node_protocol::ActionReply::decode(text.trim_end()).unwrap()
    }

    fn action_records(executing: &Executing, binding: TaskBinding) -> Vec<ward_events::WardEvent> {
        crate::evidence::verify(
            &crate::evidence::evidence_dir(&executing.root, binding),
            binding,
        )
        .unwrap()
        .records()
        .iter()
        .map(|record| record.event.clone())
        .filter(|event| {
            matches!(
                event,
                ward_events::WardEvent::NodeActionRequested { .. }
                    | ward_events::WardEvent::NodeActionAnswered { .. }
                    | ward_events::WardEvent::NodeActionRefused { .. }
                    | ward_events::WardEvent::NodeAttemptEnded { .. }
                    | ward_events::WardEvent::NodeAttemptIntervened { .. }
            )
        })
        .collect()
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_workload_request_is_listed_answered_relayed_and_recorded_over_the_local_socket() {
        use ward_events::{NodeActionDecision, WardEvent};
        use ward_node_protocol::{ActionDecision, ActionRejectionReason, TaskActionsResponse};
        let executing = executing_service_with_actions();
        let binding = TaskBinding::new(
            TaskId::from_u128(7),
            ExecutionAttemptId::from_u128(8),
            LeaseId::from_u128(9),
        );
        let context = admission_context();
        assert!(matches!(
            actions_of(&executing.service, binding),
            TaskActionsResponse::Rejected {
                operation_id: None,
                reason: ActionRejectionReason::TaskNotFound,
                ..
            }
        ));
        let (mut workload, mut replies) = started_with_actions(&executing, binding, 2);
        writeln!(
            workload,
            r#"{{"id":"deploy-1","kind":"approval","summary":"deploy to staging","detail":"3 services"}}"#
        )
        .unwrap();
        let pending = pending_of(&executing.service, binding, 1);
        assert_eq!(pending[0].action(), 1);
        assert_eq!(pending[0].id().as_str(), "deploy-1");
        assert_eq!(pending[0].summary(), "deploy to staging");
        assert_eq!(pending[0].detail(), "3 services");
        match actions_of(&executing.service, binding) {
            TaskActionsResponse::Actions { state, .. } => {
                assert_eq!(state, TaskLifecycleState::Running);
            }
            other => panic!("{other:?}"),
        }

        assert_eq!(
            answer(&executing.service, 10, binding, 1, ActionDecision::Approved),
            context.answered(
                OperationId::new(10).unwrap(),
                binding,
                1,
                ActionDecision::Approved
            )
        );
        let reply = channel_reply(&mut replies);
        assert_eq!(reply.id().as_str(), "deploy-1");
        assert_eq!(reply.decision(), ActionDecision::Approved);
        assert_eq!(
            answer(&executing.service, 10, binding, 1, ActionDecision::Approved),
            context.answered(
                OperationId::new(10).unwrap(),
                binding,
                1,
                ActionDecision::Approved
            ),
            "a replay is idempotent"
        );
        assert_eq!(
            answer(&executing.service, 11, binding, 1, ActionDecision::Denied),
            context.actions_rejected(
                Some(OperationId::new(11).unwrap()),
                binding,
                ActionRejectionReason::AlreadyAnswered
            )
        );
        assert_eq!(
            answer(&executing.service, 12, binding, 9, ActionDecision::Denied),
            context.actions_rejected(
                Some(OperationId::new(12).unwrap()),
                binding,
                ActionRejectionReason::UnknownRequest
            )
        );
        assert_eq!(
            answer(&executing.service, 10, binding, 1, ActionDecision::Denied),
            context.actions_rejected(
                Some(OperationId::new(10).unwrap()),
                binding,
                ActionRejectionReason::StaleOperation
            )
        );
        let wrong = TaskBinding::new(
            binding.task(),
            ExecutionAttemptId::from_u128(99),
            binding.lease(),
        );
        assert_eq!(
            answer(&executing.service, 13, wrong, 1, ActionDecision::Denied),
            context.actions_rejected(
                Some(OperationId::new(13).unwrap()),
                wrong,
                ActionRejectionReason::AttemptMismatch
            )
        );

        // A pause keeps a second request pending; an answer after resume is delivered.
        writeln!(
            workload,
            r#"{{"id":"pick","kind":"decision","summary":"use the cache?","detail":""}}"#
        )
        .unwrap();
        assert_eq!(pending_of(&executing.service, binding, 1)[0].action(), 2);
        assert!(matches!(
            context
                .decode_response(&served(
                    &executing.service,
                    &context.pause(OperationId::new(4).unwrap(), binding)
                ))
                .unwrap(),
            TaskLifecycleResponse::Accepted {
                state: TaskLifecycleState::Paused,
                ..
            }
        ));
        match actions_of(&executing.service, binding) {
            TaskActionsResponse::Actions { state, pending, .. } => {
                assert_eq!(state, TaskLifecycleState::Paused);
                assert_eq!(pending.len(), 1, "paused, still pending");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            context
                .decode_response(&served(
                    &executing.service,
                    &context.resume(OperationId::new(5).unwrap(), binding)
                ))
                .unwrap(),
            TaskLifecycleResponse::Accepted {
                state: TaskLifecycleState::Running,
                ..
            }
        ));
        assert_eq!(
            answer(&executing.service, 14, binding, 2, ActionDecision::Denied),
            context.answered(
                OperationId::new(14).unwrap(),
                binding,
                2,
                ActionDecision::Denied
            )
        );
        assert_eq!(
            channel_reply(&mut replies).decision(),
            ActionDecision::Denied
        );

        // A stop while a request is pending answers it cancelled and records it before the end.
        writeln!(
            workload,
            r#"{{"id":"third","kind":"approval","summary":"one more","detail":""}}"#
        )
        .unwrap();
        pending_of(&executing.service, binding, 1);
        assert!(matches!(
            context
                .decode_response(&served(
                    &executing.service,
                    &context.stop(OperationId::new(6).unwrap(), binding)
                ))
                .unwrap(),
            TaskLifecycleResponse::Accepted {
                state: TaskLifecycleState::Stopped,
                ..
            }
        ));
        assert_eq!(
            channel_reply(&mut replies).decision(),
            ActionDecision::Cancelled
        );
        assert_eq!(
            answer(&executing.service, 15, binding, 3, ActionDecision::Approved),
            context.actions_rejected(
                Some(OperationId::new(15).unwrap()),
                binding,
                ActionRejectionReason::InvalidState
            )
        );
        assert_eq!(
            answer(&executing.service, 14, binding, 2, ActionDecision::Denied),
            context.answered(
                OperationId::new(14).unwrap(),
                binding,
                2,
                ActionDecision::Denied
            ),
            "a replay is answered after the attempt ended too"
        );
        match actions_of(&executing.service, binding) {
            TaskActionsResponse::Actions { state, pending, .. } => {
                assert_eq!(state, TaskLifecycleState::Stopped);
                assert!(pending.is_empty());
            }
            other => panic!("{other:?}"),
        }
        let records = action_records(&executing, binding);
        let decisions: Vec<(u32, NodeActionDecision, Option<u64>)> = records
            .iter()
            .filter_map(|event| match event {
                WardEvent::NodeActionAnswered {
                    action,
                    decision,
                    operation,
                    ..
                } => Some((*action, *decision, *operation)),
                _ => None,
            })
            .collect();
        assert_eq!(
            decisions,
            [
                (1, NodeActionDecision::Approved, Some(10)),
                (2, NodeActionDecision::Denied, Some(14)),
                (3, NodeActionDecision::Cancelled, None),
            ]
        );
        assert!(matches!(
            records.last(),
            Some(WardEvent::NodeAttemptEnded { .. })
        ));
        assert!(matches!(
            records[0],
            WardEvent::NodeActionRequested { action: 1, .. }
        ));
        let raw = std::fs::read(
            crate::evidence::evidence_dir(&executing.root, binding)
                .join(crate::evidence::EVIDENCE_LOG),
        )
        .unwrap();
        for text in [&b"deploy to staging"[..], b"3 services", b"use the cache?"] {
            assert!(
                !raw.windows(text.len()).any(|window| window == text),
                "the log never carries the text"
            );
        }
        assert!(
            !crate::actions::actions_dir(&executing.root, binding)
                .join(crate::actions::ACTION_SOCKET_FILE)
                .exists()
        );
    }

    #[test]
    fn a_node_without_the_channel_refuses_the_grant_and_the_requests() {
        use ward_node_protocol::{ActionRejectionReason, TaskActionsResponse};
        let executing = executing_service();
        let binding = TaskBinding::new(
            TaskId::from_u128(7),
            ExecutionAttemptId::from_u128(8),
            LeaseId::from_u128(9),
        );
        let context = admission_context();
        assert!(matches!(
            context
                .decode_response(&served(
                    &executing.service,
                    &context.create(OperationId::new(1).unwrap(), binding)
                ))
                .unwrap(),
            TaskLifecycleResponse::Accepted { .. }
        ));
        assert_eq!(
            context
                .decode_response(&served(
                    &executing.service,
                    &actions_admit(&executing, binding, actions_manifest(1))
                ))
                .unwrap(),
            context.rejected(
                Some(OperationId::new(2).unwrap()),
                binding,
                TaskLifecycleRejectionReason::UnsupportedGrant
            )
        );
        assert!(matches!(
            actions_of(&executing.service, binding),
            TaskActionsResponse::Rejected {
                reason: ActionRejectionReason::UnsupportedOperation,
                ..
            }
        ));
        assert!(matches!(
            answer(
                &executing.service,
                3,
                binding,
                1,
                ward_node_protocol::ActionDecision::Approved
            ),
            TaskActionsResponse::Rejected {
                reason: ActionRejectionReason::UnsupportedOperation,
                ..
            }
        ));
        // At 1.2 the requests are unknown: the connection closes with no answer.
        let one_two = SupportedProtocolRange::new(1, 2, 2).unwrap();
        let early = serde_json::to_string(&context.actions(binding).unwrap())
            .unwrap()
            .replace(r#""minor":3"#, r#""minor":2"#);
        let (raw, served) = exchange(&executing.service, one_two, &early, REQUEST_TIMEOUT);
        assert_eq!(raw, "");
        assert!(matches!(
            served,
            Err(NodeServiceError::MalformedLifecycleRequest)
        ));
        let (raw, served) = exchange(
            &executing.service,
            WARD_NODE_PROTOCOL,
            r#"{"request":"answer","protocol":{"major":1,"minor":3}}"#,
            REQUEST_TIMEOUT,
        );
        assert_eq!(raw, "");
        assert!(matches!(
            served,
            Err(NodeServiceError::MalformedLifecycleRequest)
        ));
    }
}
