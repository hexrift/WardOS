//! The institution-owned inputs of an admission envelope (node-integration.md §7).
//!
//! [`EnvelopeInput`] is the envelope of §7.1 with one difference for the writer's benefit:
//! the capability manifest is given as the manifest object itself (`{"network":"offline"}`)
//! rather than as hash and hex bytes, and may be left out, which means `offline`. Nothing
//! else has a default: the binding, agent, node, session, lease and lineage, argv, snapshot,
//! budget, validity window and version are the control plane's to supply. [`EnvelopeInput::build`]
//! refuses every out-of-bound value of §7.3, and a lease that does not bind this binding's
//! task and lease or this agent, before anything is signed.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use ward_events::{AgentId, NodeId, SessionId, SnapshotId};
use ward_node_protocol::{
    AdmissionEnvelopeJson, AdmissionVersion, CapabilityManifest, CapabilityManifestBytes,
    NetworkGrant, TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput,
    TaskAdmissionError, TaskBinding, TaskWorkload, WorkloadArgv,
};

/// Why an envelope input could not become an envelope. Every case refuses before signing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum EnvelopeError {
    /// A value is outside the bounds of §7.3.
    #[error("admission envelope input is out of bounds: {0}")]
    Admission(#[from] TaskAdmissionError),
    /// The lease's `id` is not the binding's lease.
    #[error("the lease is not the binding's lease")]
    LeaseNotBound,
    /// The lease's `task` is not the binding's task.
    #[error("the lease is bound to another task")]
    LeaseTaskMismatch,
    /// The lease's `subject` is not the envelope's agent.
    #[error("the lease's subject is not the envelope's agent")]
    AgentNotSubject,
}

/// The manifest every workload runs under today: `{"network":"offline"}` (§7.5).
///
/// # Errors
///
/// Returns a [`TaskAdmissionError`] only if the manifest grammar changed under it.
pub fn offline_manifest() -> Result<CapabilityManifestBytes, TaskAdmissionError> {
    CapabilityManifestBytes::encode(&CapabilityManifest::new(NetworkGrant::Offline))
}

/// What runs: §7.1 `workload`, with the manifest as its object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadInput {
    /// The program and its arguments, resolved on the sandbox `PATH`.
    pub argv: Vec<String>,
    /// The capability manifest as its JSON object; `None` means `{"network":"offline"}`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "manifest_from_object",
        serialize_with = "manifest_as_object"
    )]
    pub capability_manifest: Option<CapabilityManifestBytes>,
    /// The snapshot id `ward-node snapshot import` printed (§2.4).
    pub snapshot: SnapshotId,
    /// The mandatory wall-clock budget in milliseconds.
    pub wall_clock_budget_ms: u64,
}

fn manifest_from_object<'de, D>(
    deserializer: D,
) -> Result<Option<CapabilityManifestBytes>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(object) = Option::<serde_json::Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    let bytes = serde_json::to_vec(&object).map_err(D::Error::custom)?;
    CapabilityManifestBytes::new(bytes)
        .map(Some)
        .map_err(D::Error::custom)
}

#[allow(clippy::ref_option)]
fn manifest_as_object<S>(
    manifest: &Option<CapabilityManifestBytes>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match manifest {
        Some(manifest) => manifest.manifest().serialize(serializer),
        None => serializer.serialize_none(),
    }
}

/// The envelope of §7.1 as the control plane writes it, before it is bounded and signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeInput {
    /// Exact task, execution attempt and lease.
    pub binding: TaskBinding,
    /// The agent whose authority applies; must be the lease's subject.
    pub agent: AgentId,
    /// The audience node.
    pub node: NodeId,
    /// The session recorded in the receipt.
    pub session: SessionId,
    /// The lease and its lineage, nearest parent first.
    pub authority: TaskAdmissionAuthority,
    /// What runs.
    pub workload: WorkloadInput,
    /// Inclusive issue time in Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Exclusive expiry in Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// The per-task version, strictly above every version the node accepted for the task.
    pub version: u64,
}

impl EnvelopeInput {
    /// Bound every value and build the envelope to sign.
    ///
    /// # Errors
    ///
    /// Returns an [`EnvelopeError`] for any value outside §7.3, an envelope that would not
    /// fit the wire, or a lease that does not bind this task, lease and agent.
    pub fn build(self) -> Result<TaskAdmissionEnvelope, EnvelopeError> {
        let lease = self.authority.lease();
        if lease.id() != self.binding.lease() {
            return Err(EnvelopeError::LeaseNotBound);
        }
        if lease.task() != self.binding.task() {
            return Err(EnvelopeError::LeaseTaskMismatch);
        }
        if lease.subject() != self.agent {
            return Err(EnvelopeError::AgentNotSubject);
        }
        let manifest = match self.workload.capability_manifest {
            Some(manifest) => manifest,
            None => offline_manifest()?,
        };
        let workload = TaskWorkload::new(
            WorkloadArgv::new(self.workload.argv)?,
            manifest,
            self.workload.snapshot,
            self.workload.wall_clock_budget_ms,
        )?;
        let envelope = TaskAdmissionEnvelope::new(TaskAdmissionEnvelopeInput {
            binding: self.binding,
            agent: self.agent,
            node: self.node,
            session: self.session,
            authority: self.authority,
            workload,
            issued_at_unix_ms: self.issued_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            version: AdmissionVersion::new(self.version)?,
        })?;
        AdmissionEnvelopeJson::encode(&envelope)?;
        Ok(envelope)
    }
}
