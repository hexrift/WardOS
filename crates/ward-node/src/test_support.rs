#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ring::signature::{Ed25519KeyPair, KeyPair};
use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::{
    AgentId, Blake3Hash, DelegationId, ExecutionAttemptId, LeaseId, NodeId, PrincipalId, SessionId,
    SnapshotId, TaskId,
};
use ward_node_protocol::{
    AdmissionEnvelopeJson, AdmissionVersion, CapabilityManifest, CapabilityManifestBytes,
    HostAllowlist, IssuerProof, IssuerSignature, NetworkGrant, OperationId, TaskAdmissionAuthority,
    TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput, TaskBinding, TaskLifecycleContext,
    TaskLifecycleRequest, TaskWorkload, WorkloadArgv,
};

use crate::admit::{NodeAdmission, NodeClock};
use crate::issuer::{IssuerPublicKey, TrustedIssuer, TrustedIssuers};
use crate::state::NodeState;

/// Deterministic seed of the trusted test issuer key.
pub const ISSUER_SEED: [u8; 32] = [7; 32];

/// Deterministic seed of an issuer key the node does not trust.
pub const OTHER_SEED: [u8; 32] = [8; 32];

/// The principal the trusted test issuer key is bound to, and that test leases name.
pub const ISSUER: PrincipalId = PrincipalId::from_u128(2);

/// The node identity every admission test runs as.
pub const NODE: NodeId = NodeId::from_u128(4);

/// A time at which the default test envelope and lease are both valid.
pub const NOW: u64 = 5_000;

pub fn issuer_keypair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&ISSUER_SEED).unwrap()
}

pub fn other_keypair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&OTHER_SEED).unwrap()
}

pub fn issuer_public_key() -> IssuerPublicKey {
    IssuerPublicKey::from_bytes(issuer_keypair().public_key().as_ref().try_into().unwrap())
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

pub fn lifecycle_binding() -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(7),
        ExecutionAttemptId::from_u128(8),
        LeaseId::from_u128(9),
    )
}

pub fn trusted_root_lease() -> AuthorityLease {
    root_lease(lifecycle_binding(), 1_000, 9_000)
}

pub fn root_lease(binding: TaskBinding, issued_at: u64, expires_at: u64) -> AuthorityLease {
    root_lease_issued_by(binding, ISSUER, issued_at, expires_at)
}

pub fn root_lease_issued_by(
    binding: TaskBinding,
    issuer: PrincipalId,
    issued_at: u64,
    expires_at: u64,
) -> AuthorityLease {
    AuthorityLease::root(
        AuthorityLeaseInput {
            id: binding.lease(),
            delegation_id: DelegationId::from_u128(6),
            issuer,
            subject: AgentId::from_u128(3),
            task: binding.task(),
            grants: GrantSet::new([CapabilityGrant::new(
                CapabilityName::new("repo.read").unwrap(),
                ResourceRef::new("repo:hexrift/WardOS").unwrap(),
                true,
            )])
            .unwrap(),
            issued_at_unix_ms: issued_at,
            expires_at_unix_ms: expires_at,
            version: LeaseVersion::new(1).unwrap(),
        },
        issued_at,
        EmptyAuthorityPolicy::Reject,
    )
    .unwrap()
}

/// A valid envelope input for `binding`, addressed to [`NODE`], signed-ready.
pub fn envelope_input(binding: TaskBinding) -> TaskAdmissionEnvelopeInput {
    envelope_input_issued_by(binding, ISSUER)
}

/// [`envelope_input`] whose root lease names `issuer` as its issuing principal.
pub fn envelope_input_issued_by(
    binding: TaskBinding,
    issuer: PrincipalId,
) -> TaskAdmissionEnvelopeInput {
    let lease = root_lease_issued_by(binding, issuer, 1_000, 9_000);
    TaskAdmissionEnvelopeInput {
        binding,
        agent: AgentId::from_u128(3),
        node: NODE,
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new())
            .unwrap(),
        workload: TaskWorkload::new(
            WorkloadArgv::new(vec!["cargo".to_owned(), "test".to_owned()]).unwrap(),
            CapabilityManifestBytes::new(br#"{"network":"offline"}"#.to_vec()).unwrap(),
            SnapshotId::new(Blake3Hash::from_bytes([0x11; 32])),
            600_000,
        )
        .unwrap(),
        issued_at_unix_ms: 2_000,
        expires_at_unix_ms: 8_000,
        version: AdmissionVersion::new(1).unwrap(),
    }
}

/// A manifest asking for allowlisted egress, which no node honours yet.
pub fn network_manifest() -> CapabilityManifestBytes {
    CapabilityManifestBytes::encode(&CapabilityManifest::new(NetworkGrant::Custom(
        HostAllowlist::new(vec!["github.com".to_owned(), "*.crates.io".to_owned()]).unwrap(),
    )))
    .unwrap()
}

/// Replace the manifest of `input`'s workload, keeping everything else.
pub fn with_manifest(input: &mut TaskAdmissionEnvelopeInput, manifest: CapabilityManifestBytes) {
    input.workload = TaskWorkload::new(
        input.workload.argv().clone(),
        manifest,
        input.workload.snapshot(),
        input.workload.wall_clock_budget_ms(),
    )
    .unwrap();
}

pub fn sign(json: &AdmissionEnvelopeJson, key_pair: &Ed25519KeyPair) -> IssuerProof {
    IssuerProof::new(
        Blake3Hash::hash(key_pair.public_key().as_ref()),
        IssuerSignature::from_bytes(key_pair.sign(json.as_bytes()).as_ref().try_into().unwrap()),
    )
}

/// An `admit` for `envelope`, signed by the trusted test issuer.
pub fn signed_admit(
    context: TaskLifecycleContext,
    operation_id: OperationId,
    binding: TaskBinding,
    envelope: &TaskAdmissionEnvelope,
) -> TaskLifecycleRequest {
    let json = AdmissionEnvelopeJson::encode(envelope).unwrap();
    let proof = sign(&json, &issuer_keypair());
    context.admit(operation_id, binding, json, proof).unwrap()
}

/// A settable test clock.
#[derive(Clone, Debug)]
pub struct FixedClock(Arc<AtomicU64>);

impl FixedClock {
    pub fn at(now_unix_ms: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now_unix_ms)))
    }

    pub fn set(&self, now_unix_ms: u64) {
        self.0.store(now_unix_ms, Ordering::SeqCst);
    }
}

impl NodeClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Admission for [`NODE`] trusting only the test issuer key, bound to [`ISSUER`], with
/// state under `dir`.
pub fn node_admission(dir: &Path, clock: &FixedClock) -> NodeAdmission {
    NodeAdmission::new(
        TrustedIssuers::new([TrustedIssuer::new(issuer_public_key(), ISSUER)]),
        NodeState::open(dir, NODE).unwrap(),
        Box::new(clock.clone()),
    )
}

pub fn admit(
    context: TaskLifecycleContext,
    operation_id: OperationId,
    binding: TaskBinding,
) -> TaskLifecycleRequest {
    context
        .admit(
            operation_id,
            binding,
            AdmissionEnvelopeJson::encode(&admission_envelope(binding)).unwrap(),
            IssuerProof::new(
                Blake3Hash::from_bytes([0x22; 32]),
                IssuerSignature::from_bytes([0x33; 64]),
            ),
        )
        .unwrap()
}

fn admission_envelope(binding: TaskBinding) -> TaskAdmissionEnvelope {
    let lease = AuthorityLease::root(
        AuthorityLeaseInput {
            id: binding.lease(),
            delegation_id: DelegationId::from_u128(6),
            issuer: PrincipalId::from_u128(2),
            subject: AgentId::from_u128(3),
            task: binding.task(),
            grants: GrantSet::new([CapabilityGrant::new(
                CapabilityName::new("repo.read").unwrap(),
                ResourceRef::new("repo:hexrift/WardOS").unwrap(),
                false,
            )])
            .unwrap(),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 9_000,
            version: LeaseVersion::new(1).unwrap(),
        },
        2_000,
        EmptyAuthorityPolicy::Reject,
    )
    .unwrap();

    TaskAdmissionEnvelope::new(TaskAdmissionEnvelopeInput {
        binding,
        agent: AgentId::from_u128(3),
        node: NodeId::from_u128(4),
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new())
            .unwrap(),
        workload: TaskWorkload::new(
            WorkloadArgv::new(vec!["cargo".to_owned(), "test".to_owned()]).unwrap(),
            CapabilityManifestBytes::new(br#"{"network":"offline"}"#.to_vec()).unwrap(),
            SnapshotId::new(Blake3Hash::from_bytes([0x11; 32])),
            600_000,
        )
        .unwrap(),
        issued_at_unix_ms: 2_000,
        expires_at_unix_ms: 8_000,
        version: AdmissionVersion::new(1).unwrap(),
    })
    .unwrap()
}

/// What the next [`FakeLauncher`] launch does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeSpawn {
    /// Spawn a fake workload.
    Spawn,
    /// Refuse cleanly: nothing spawned.
    Refuse,
    /// Fail ambiguously: something may have started.
    Ambiguous,
}

/// How a fake workload answers a stop request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeStop {
    /// The kill ends it.
    Honour,
    /// It had already exited on its own before the kill landed.
    ExitedFirst(crate::execution::WorkloadExit),
    /// It cannot be confirmed reaped: keep waiting.
    Ignore,
}

/// Whether a fake freeze or thaw is confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeFreeze {
    /// The host confirms it.
    Confirm,
    /// It cannot be confirmed: a freeze is continued back, a thaw leaves the tree stopped.
    Unconfirmed,
}

#[derive(Debug)]
struct FakeState {
    spawn: FakeSpawn,
    on_stop: FakeStop,
    on_freeze: FakeFreeze,
    on_thaw: FakeFreeze,
    frozen: bool,
    freezes: usize,
    thaws: usize,
    exit: Option<crate::execution::WorkloadExit>,
    launches: Vec<crate::execution::LaunchRequest>,
    waiting: usize,
    stopped: usize,
    reaped: usize,
    survivors: Vec<crate::execution::WorkloadProcess>,
    blocked_on_launch: Option<std::path::PathBuf>,
}

/// A deterministic launcher: workloads end only when the test says so, or on stop.
#[derive(Clone, Debug)]
pub struct FakeLauncher(Arc<(std::sync::Mutex<FakeState>, std::sync::Condvar)>);

/// The host pid every fake workload reports.
pub const FAKE_PID: u32 = 4242;

/// The host process every fake workload reports it runs as.
pub fn fake_process() -> crate::execution::WorkloadProcess {
    crate::execution::WorkloadProcess::new(FAKE_PID, 77, "fake-boot".to_owned())
}

impl FakeLauncher {
    pub fn new() -> Self {
        Self(Arc::new((
            std::sync::Mutex::new(FakeState {
                spawn: FakeSpawn::Spawn,
                on_stop: FakeStop::Honour,
                on_freeze: FakeFreeze::Confirm,
                on_thaw: FakeFreeze::Confirm,
                frozen: false,
                freezes: 0,
                thaws: 0,
                exit: None,
                launches: Vec::new(),
                waiting: 0,
                stopped: 0,
                reaped: 0,
                survivors: Vec::new(),
                blocked_on_launch: None,
            }),
            std::sync::Condvar::new(),
        )))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.0.0.lock().unwrap()
    }

    pub fn set_spawn(&self, spawn: FakeSpawn) {
        self.state().spawn = spawn;
    }

    pub fn set_on_stop(&self, on_stop: FakeStop) {
        self.state().on_stop = on_stop;
        self.0.1.notify_all();
    }

    pub fn set_on_freeze(&self, on_freeze: FakeFreeze) {
        self.state().on_freeze = on_freeze;
    }

    pub fn set_on_thaw(&self, on_thaw: FakeFreeze) {
        self.state().on_thaw = on_thaw;
    }

    /// Whether the fake workload's tree is currently held stopped.
    pub fn frozen(&self) -> bool {
        self.state().frozen
    }

    /// Freeze attempts made.
    pub fn freezes(&self) -> usize {
        self.state().freezes
    }

    /// Thaw attempts made.
    pub fn thaws(&self) -> usize {
        self.state().thaws
    }

    /// Let the running fake workload end on its own with `exit`.
    pub fn exit(&self, exit: crate::execution::WorkloadExit) {
        self.state().exit = Some(exit);
        self.0.1.notify_all();
    }

    pub fn launches(&self) -> Vec<crate::execution::LaunchRequest> {
        self.state().launches.clone()
    }

    /// Workloads currently being waited on by a reaper.
    pub fn waiting(&self) -> usize {
        self.state().waiting
    }

    /// Workloads a stop request ended.
    pub fn stopped(&self) -> usize {
        self.state().stopped
    }

    /// Workloads whose wait has returned.
    pub fn reaped(&self) -> usize {
        self.state().reaped
    }

    /// Survivors of a restart the registry asked this launcher to end.
    pub fn survivors(&self) -> Vec<crate::execution::WorkloadProcess> {
        self.state().survivors.clone()
    }

    /// While spawning the next workload, also create the directory `path`.
    pub fn block_on_launch(&self, path: std::path::PathBuf) {
        self.state().blocked_on_launch = Some(path);
    }
}

impl crate::execution::TaskLauncher for FakeLauncher {
    fn launch(
        &self,
        request: &crate::execution::LaunchRequest,
    ) -> Result<Box<dyn crate::execution::RunningWorkload>, crate::execution::SpawnError> {
        let mut state = self.state();
        state.launches.push(request.clone());
        if let Some(path) = state.blocked_on_launch.take() {
            std::fs::create_dir_all(path).unwrap();
        }
        match state.spawn {
            FakeSpawn::Spawn => Ok(Box::new(FakeWorkload(self.clone()))),
            FakeSpawn::Refuse => Err(crate::execution::SpawnError::Refused),
            FakeSpawn::Ambiguous => Err(crate::execution::SpawnError::Ambiguous),
        }
    }

    fn end_survivor(&self, process: &crate::execution::WorkloadProcess) {
        self.state().survivors.push(process.clone());
    }
}

struct FakeWorkload(FakeLauncher);

/// The fake workload's freezer: records attempts and answers as configured.
#[derive(Debug)]
struct FakeFreezer(FakeLauncher);

impl crate::execution::WorkloadFreezer for FakeFreezer {
    fn freeze(&self) -> Result<(), crate::execution::FreezeUnconfirmed> {
        let mut state = self.0.state();
        state.freezes += 1;
        match state.on_freeze {
            FakeFreeze::Confirm => {
                state.frozen = true;
                Ok(())
            }
            FakeFreeze::Unconfirmed => {
                state.frozen = false;
                Err(crate::execution::FreezeUnconfirmed)
            }
        }
    }

    fn thaw(&self) -> Result<(), crate::execution::FreezeUnconfirmed> {
        let mut state = self.0.state();
        state.thaws += 1;
        match state.on_thaw {
            FakeFreeze::Confirm => {
                state.frozen = false;
                Ok(())
            }
            FakeFreeze::Unconfirmed => Err(crate::execution::FreezeUnconfirmed),
        }
    }
}

impl crate::execution::RunningWorkload for FakeWorkload {
    fn pid(&self) -> u32 {
        FAKE_PID
    }

    fn process(&self) -> Option<crate::execution::WorkloadProcess> {
        Some(fake_process())
    }

    fn freezer(&self) -> Arc<dyn crate::execution::WorkloadFreezer> {
        Arc::new(FakeFreezer(self.0.clone()))
    }

    fn wait(
        self: Box<Self>,
        stop: &crate::execution::StopSignal,
    ) -> crate::execution::WorkloadExit {
        let (lock, ready) = &*self.0.0;
        let mut state = lock.lock().unwrap();
        state.waiting += 1;
        let exit = loop {
            if let Some(exit) = state.exit.take() {
                break exit;
            }
            if stop.is_requested() {
                match state.on_stop {
                    FakeStop::Honour => {
                        state.stopped += 1;
                        break crate::execution::WorkloadExit::Stopped;
                    }
                    FakeStop::ExitedFirst(exit) => break exit,
                    FakeStop::Ignore => {}
                }
            }
            state = ready
                .wait_timeout(state, std::time::Duration::from_millis(5))
                .unwrap()
                .0;
        };
        state.waiting -= 1;
        state.reaped += 1;
        exit
    }
}

/// Poll until `done` holds, failing after a generous bound.
pub fn eventually(mut done: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !done() {
        assert!(std::time::Instant::now() < deadline, "condition never held");
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// Write a revocation store of distinct operator facts that fills
/// [`crate::state::MAX_STATE_FILE_BYTES`] as far as whole records allow, as an operator
/// edit made while the node is stopped; returns how many facts it holds.
pub fn fill_revocations(state_dir: &Path) -> usize {
    let record = |index: usize| {
        format!(
            r#"{{"lease":"{}","revoked_at_unix_ms":1000,"reason":"operator"}}"#,
            ward_events::LeaseId::from_u128(u128::try_from(index).unwrap() + 1_000)
        )
    };
    let (head, tail) = (r#"{"format":1,"revocations":["#, "]}");
    let each = record(0).len() + 1;
    let max = usize::try_from(crate::state::MAX_STATE_FILE_BYTES).unwrap();
    let count = (max - head.len() - tail.len() + 1) / each;
    let records: Vec<String> = (0..count).map(record).collect();
    let file = format!("{head}{}{tail}", records.join(","));
    assert!(file.len() <= max && file.len() + each > max);
    std::fs::write(state_dir.join(crate::state::REVOCATIONS_FILE), file).unwrap();
    count
}
