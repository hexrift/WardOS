//! Resource limits and node load (#260, the first single-node slice): the optional
//! `resources` grant of the capability manifest, the capability document's `resources`
//! section (what a node can enforce through a per-attempt cgroup) and its `scheduling`
//! section (how many attempts the node runs at once, how many run now, and the memory and
//! disk headroom below which it refuses to start another).
//!
//! Everything here is additive within protocol 1.3. A manifest without `resources` and a
//! capability document of a node that runs no attempt in a cgroup and bounds nothing are
//! byte for byte what they were. A node that cannot enforce a requested limit refuses the
//! grant `unsupported_grant` at `admit`, and a node of an earlier revision fails to decode
//! a manifest that carries it (`authority_denied`), so no node ever runs a workload under
//! less than the limits its manifest asked for.
//!
//! Limits are cgroup v2 limits on the attempt's whole process tree: `cpu_millis` is CPU
//! time per second of wall clock in thousandths of one CPU (`cpu.max`), `memory_bytes` is
//! the memory the tree may use, tmpfs included, with no swap (`memory.max`,
//! `memory.swap.max`), and `pids` is how many processes and threads may exist in it at once
//! (`pids.max`).

use std::fmt::{Display, Formatter};
use std::num::NonZeroU64;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::NodeCapacity;

/// Ceiling on the `pids` limit a node honours: a manifest asking for more is refused
/// `unsupported_grant`. The CPU and memory ceilings are the host's own: at most one
/// thousand `cpu_millis` per logical CPU and at most the host's memory, both as the
/// capability document's `capacity` reports them.
pub const MAX_RESOURCE_PIDS: u64 = 65_536;

/// Why a resources grant is outside the grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceError {
    /// The grant names no limit; no limits is spelled by leaving `resources` out.
    Empty,
    /// A limit is zero.
    Zero,
}

impl Display for ResourceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "resources grant names no limit",
            Self::Zero => "resources grant limit is zero",
        })
    }
}

impl std::error::Error for ResourceError {}

/// The `resources` grant of a capability manifest: the limits the node must enforce on
/// the attempt's process tree. Each limit is optional and at least one is present; an
/// absent limit is not bounded by the grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ResourceGrant {
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_millis: Option<NonZeroU64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory_bytes: Option<NonZeroU64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pids: Option<NonZeroU64>,
}

impl ResourceGrant {
    /// A grant of the given limits.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceError::Empty`] when no limit is given and [`ResourceError::Zero`]
    /// for a zero limit.
    pub fn new(
        cpu_millis: Option<u64>,
        memory_bytes: Option<u64>,
        pids: Option<u64>,
    ) -> Result<Self, ResourceError> {
        if cpu_millis.is_none() && memory_bytes.is_none() && pids.is_none() {
            return Err(ResourceError::Empty);
        }
        let positive = |limit: Option<u64>| {
            limit
                .map(|value| NonZeroU64::new(value).ok_or(ResourceError::Zero))
                .transpose()
        };
        Ok(Self {
            cpu_millis: positive(cpu_millis)?,
            memory_bytes: positive(memory_bytes)?,
            pids: positive(pids)?,
        })
    }

    /// CPU time per second of wall clock, in thousandths of one CPU.
    #[must_use]
    pub fn cpu_millis(&self) -> Option<u64> {
        self.cpu_millis.map(NonZeroU64::get)
    }

    /// Memory the process tree may use, in bytes, with no swap.
    #[must_use]
    pub fn memory_bytes(&self) -> Option<u64> {
        self.memory_bytes.map(NonZeroU64::get)
    }

    /// Processes and threads that may exist in the tree at once.
    #[must_use]
    pub fn pids(&self) -> Option<u64> {
        self.pids.map(NonZeroU64::get)
    }

    /// Whether a node of `capacity` honours these limits: at most 1 000 `cpu_millis` per
    /// logical CPU, at most the host's memory and at most [`MAX_RESOURCE_PIDS`].
    #[must_use]
    pub fn within_ceilings(&self, capacity: NodeCapacity) -> bool {
        let cpu_ceiling = u64::from(capacity.logical_cpus()).saturating_mul(1000);
        self.cpu_millis().is_none_or(|cpu| cpu <= cpu_ceiling)
            && self
                .memory_bytes()
                .is_none_or(|memory| memory <= capacity.memory_bytes())
            && self.pids().is_none_or(|pids| pids <= MAX_RESOURCE_PIDS)
    }
}

/// The wire form of a resources grant: exactly one JSON object (an array is refused) whose
/// fields are the known limits, each at most once and never `null`.
pub(crate) struct ResourceGrantWire {
    cpu_millis: Option<u64>,
    memory_bytes: Option<u64>,
    pids: Option<u64>,
}

impl<'de> Deserialize<'de> for ResourceGrantWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Fields;

        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = ResourceGrantWire;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a resources object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<ResourceGrantWire, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut wire = ResourceGrantWire {
                    cpu_millis: None,
                    memory_bytes: None,
                    pids: None,
                };
                while let Some(key) = map.next_key::<String>()? {
                    let slot = match key.as_str() {
                        "cpu_millis" => &mut wire.cpu_millis,
                        "memory_bytes" => &mut wire.memory_bytes,
                        "pids" => &mut wire.pids,
                        _ => return Err(A::Error::custom("unknown resources field")),
                    };
                    if slot.is_some() {
                        return Err(A::Error::custom("repeated resources field"));
                    }
                    *slot = Some(map.next_value::<u64>()?);
                }
                Ok(wire)
            }
        }

        deserializer.deserialize_map(Fields)
    }
}

impl TryFrom<ResourceGrantWire> for ResourceGrant {
    type Error = ResourceError;

    fn try_from(wire: ResourceGrantWire) -> Result<Self, ResourceError> {
        Self::new(wire.cpu_millis, wire.memory_bytes, wire.pids)
    }
}

impl<'de> Deserialize<'de> for ResourceGrant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_from(ResourceGrantWire::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Which limits a node enforces on an attempt's process tree (the `resources` section of
/// the capability document). The section is present exactly when the node runs every
/// attempt in a cgroup of its own and records what the attempt used; each flag says
/// whether the node can also bound that resource.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCapabilities {
    /// `cpu_millis` is enforced (`cpu.max`).
    pub cpu: bool,
    /// `memory_bytes` is enforced (`memory.max`, with no swap).
    pub memory: bool,
    /// `pids` is enforced (`pids.max`).
    pub pids: bool,
}

impl ResourceCapabilities {
    /// Whether every limit `grant` names is one this node enforces.
    #[must_use]
    pub const fn enforces(self, grant: &ResourceGrant) -> bool {
        (grant.cpu_millis.is_none() || self.cpu)
            && (grant.memory_bytes.is_none() || self.memory)
            && (grant.pids.is_none() || self.pids)
    }
}

/// How much a node runs at once and the headroom it keeps (the `scheduling` section of the
/// capability document), read when the document is served. Present exactly when the node
/// bounds how many attempts execute at once; a `start` that would pass `max_running`, or
/// that finds available memory or disk below its floor, is refused `capacity_exhausted`
/// with the task still `ready`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulingCapabilities {
    /// How many attempts may execute at once.
    pub max_running: u32,
    /// How many attempts execute now: started and not yet reaped, paused ones included.
    pub running: u32,
    /// Available memory below which `start` is refused; `0` when there is no floor.
    pub memory_floor_bytes: u64,
    /// Available memory now (`MemAvailable`).
    pub memory_available_bytes: u64,
    /// Available disk under the task root below which `start` is refused; `0` when there
    /// is no floor.
    pub disk_floor_bytes: u64,
    /// Available disk under the task root now.
    pub disk_available_bytes: u64,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::{CapabilityManifest, CapabilityManifestBytes, NetworkGrant, TaskAdmissionError};

    fn decode(json: &str) -> Result<CapabilityManifest, TaskAdmissionError> {
        CapabilityManifest::decode_json(json.as_bytes())
    }

    #[test]
    fn a_resources_grant_names_at_least_one_positive_limit_and_nothing_else() {
        let manifest = decode(
            r#"{"network":"offline","resources":{"cpu_millis":500,"memory_bytes":67108864,"pids":64}}"#,
        )
        .unwrap();
        let grant = manifest.resources().unwrap();
        assert_eq!(grant.cpu_millis(), Some(500));
        assert_eq!(grant.memory_bytes(), Some(64 * 1024 * 1024));
        assert_eq!(grant.pids(), Some(64));

        let pids_only = decode(r#"{"network":"offline","resources":{"pids":16}}"#).unwrap();
        let grant = pids_only.resources().unwrap();
        assert_eq!(
            (grant.cpu_millis(), grant.memory_bytes(), grant.pids()),
            (None, None, Some(16))
        );
        assert_eq!(
            decode(r#"{"network":"offline"}"#).unwrap().resources(),
            None,
            "no resources field, no limits asked for"
        );

        for bad in [
            r#"{"network":"offline","resources":{}}"#,
            r#"{"network":"offline","resources":{"pids":0}}"#,
            r#"{"network":"offline","resources":{"cpu_millis":0}}"#,
            r#"{"network":"offline","resources":{"memory_bytes":0}}"#,
            r#"{"network":"offline","resources":{"pids":null}}"#,
            r#"{"network":"offline","resources":null}"#,
            r#"{"network":"offline","resources":{"pids":-1}}"#,
            r#"{"network":"offline","resources":{"pids":1.5}}"#,
            r#"{"network":"offline","resources":{"pids":"16"}}"#,
            r#"{"network":"offline","resources":{"disk_bytes":1}}"#,
            r#"{"network":"offline","resources":{"pids":1,"pids":2}}"#,
            r#"{"network":"offline","resources":[1]}"#,
        ] {
            assert!(
                matches!(
                    decode(bad),
                    Err(TaskAdmissionError::MalformedManifest
                        | TaskAdmissionError::MalformedResourceGrant)
                ),
                "{bad} must fail decoding"
            );
        }
    }

    #[test]
    fn a_resources_grant_round_trips_in_one_spelling_and_leaves_other_manifests_unchanged() {
        let grant = ResourceGrant::new(Some(250), None, Some(32)).unwrap();
        let manifest = CapabilityManifest::new(NetworkGrant::Offline).with_resources(grant);
        let bytes = CapabilityManifestBytes::encode(&manifest).unwrap();
        assert_eq!(
            bytes.bytes(),
            br#"{"network":"offline","resources":{"cpu_millis":250,"pids":32}}"#
        );
        assert_eq!(bytes.manifest(), &manifest);
        assert_eq!(
            CapabilityManifestBytes::encode(&CapabilityManifest::new(NetworkGrant::Offline))
                .unwrap()
                .bytes(),
            br#"{"network":"offline"}"#,
            "a manifest without resources is byte for byte what it was"
        );
        assert_eq!(
            ResourceGrant::new(None, None, None),
            Err(ResourceError::Empty)
        );
        assert_eq!(
            ResourceGrant::new(Some(0), None, None),
            Err(ResourceError::Zero)
        );
    }

    #[test]
    fn a_grant_is_within_ceilings_only_below_the_host_and_the_pid_ceiling() {
        let capacity = crate::NodeCapacity::new(4, 8 * 1024 * 1024 * 1024).unwrap();
        let grant = |cpu, memory, pids| ResourceGrant::new(cpu, memory, pids).unwrap();
        assert!(
            grant(
                Some(4000),
                Some(8 * 1024 * 1024 * 1024),
                Some(MAX_RESOURCE_PIDS)
            )
            .within_ceilings(capacity)
        );
        assert!(!grant(Some(4001), None, None).within_ceilings(capacity));
        assert!(!grant(None, Some(8 * 1024 * 1024 * 1024 + 1), None).within_ceilings(capacity));
        assert!(!grant(None, None, Some(MAX_RESOURCE_PIDS + 1)).within_ceilings(capacity));
    }

    #[test]
    fn a_node_enforces_a_grant_only_with_every_controller_it_names() {
        let all = ResourceCapabilities {
            cpu: true,
            memory: true,
            pids: true,
        };
        let pids_only = ResourceCapabilities {
            cpu: false,
            memory: false,
            pids: true,
        };
        let grant = ResourceGrant::new(Some(100), None, Some(8)).unwrap();
        assert!(all.enforces(&grant));
        assert!(!pids_only.enforces(&grant));
        assert!(pids_only.enforces(&ResourceGrant::new(None, None, Some(8)).unwrap()));
        assert!(
            !ResourceCapabilities::default()
                .enforces(&ResourceGrant::new(None, Some(1), None).unwrap())
        );
    }

    #[test]
    fn the_scheduling_section_is_strict_and_reports_the_running_bound() {
        let scheduling = SchedulingCapabilities {
            max_running: 8,
            running: 3,
            memory_floor_bytes: 1024,
            memory_available_bytes: 4096,
            disk_floor_bytes: 0,
            disk_available_bytes: 8192,
        };
        let json = serde_json::to_string(&scheduling).unwrap();
        assert_eq!(
            json,
            r#"{"max_running":8,"running":3,"memory_floor_bytes":1024,"memory_available_bytes":4096,"disk_floor_bytes":0,"disk_available_bytes":8192}"#
        );
        assert_eq!(
            serde_json::from_str::<SchedulingCapabilities>(&json).unwrap(),
            scheduling
        );
        assert!(
            serde_json::from_str::<SchedulingCapabilities>(
                &json.replace(r#""running":3"#, r#""running":3,"queued":0"#)
            )
            .is_err()
        );
    }
}
