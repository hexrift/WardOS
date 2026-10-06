//! Isolation levels and the manifest's isolation floor (#263, ADR-0039), additive within
//! protocol 1.3.
//!
//! A node runs an attempt on a Capsule backend at one [`IsolationLevel`]; the levels are
//! ordered by what they guarantee (`sandbox` < `container` < `microvm` < `vm`), each
//! guaranteeing everything the levels below it do. The capability manifest may name the
//! minimum an attempt needs ([`IsolationGrant`]):
//!
//! ```json
//! {"network":"offline","isolation":{"minimum":"microvm"}}
//! ```
//!
//! `minimum` is the only field and is `container`, `microvm` or `vm`. Absent, the minimum
//! is `sandbox`, which is spelled only by leaving the field out, so every manifest without
//! it is byte for byte what it was. Which levels a node offers is the capability document's
//! existing `isolation` section ([`IsolationCapabilities::offers`]); a node with no backend
//! the placement rule allows refuses the manifest at `admit`, and a node of an earlier
//! revision fails to decode it, so no node runs an attempt with less than its floor.

use std::fmt::{Display, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::IsolationCapabilities;

/// How strongly a Capsule backend isolates an attempt, ordered by what it guarantees.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IsolationLevel {
    /// Namespaces over the shared host kernel; the workspace the only writable host path.
    Sandbox,
    /// The sandbox's namespaces with a mandatory seccomp filter, no capabilities, its own
    /// root filesystem and cgroup, over the shared host kernel.
    Container,
    /// A guest kernel of its own behind hardware virtualisation and a minimal device model.
    Microvm,
    /// A guest kernel of its own on a full emulated machine the workload may administer.
    Vm,
}

impl IsolationLevel {
    /// Every level, weakest first.
    pub const ALL: [Self; 4] = [Self::Sandbox, Self::Container, Self::Microvm, Self::Vm];

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sandbox => "sandbox",
            Self::Container => "container",
            Self::Microvm => "microvm",
            Self::Vm => "vm",
        }
    }
}

impl Display for IsolationLevel {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Why an isolation floor is outside the grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsolationError {
    /// The floor names `sandbox`, which is spelled by leaving `isolation` out.
    ImplicitMinimum,
}

impl Display for IsolationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ImplicitMinimum => {
                "an isolation floor of sandbox is spelled by leaving isolation out"
            }
        })
    }
}

impl std::error::Error for IsolationError {}

/// The `isolation` field of a capability manifest: the weakest level the attempt may run
/// at, above `sandbox`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct IsolationGrant {
    minimum: IsolationLevel,
}

impl IsolationGrant {
    /// A floor of `minimum`.
    ///
    /// # Errors
    ///
    /// Returns [`IsolationError::ImplicitMinimum`] for `sandbox`, the floor of every
    /// manifest without the field.
    pub const fn new(minimum: IsolationLevel) -> Result<Self, IsolationError> {
        match minimum {
            IsolationLevel::Sandbox => Err(IsolationError::ImplicitMinimum),
            _ => Ok(Self { minimum }),
        }
    }

    /// The weakest level the attempt may run at.
    #[must_use]
    pub const fn minimum(self) -> IsolationLevel {
        self.minimum
    }
}

/// The wire form of an isolation floor: exactly one JSON object (an array is refused)
/// whose only field is `minimum`, present once and never `null`.
pub(crate) struct IsolationGrantWire {
    minimum: IsolationLevel,
}

impl<'de> Deserialize<'de> for IsolationGrantWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Fields;

        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = IsolationGrantWire;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an isolation object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<IsolationGrantWire, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut minimum = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key != "minimum" {
                        return Err(A::Error::custom("unknown isolation field"));
                    }
                    if minimum.is_some() {
                        return Err(A::Error::custom("repeated isolation field"));
                    }
                    minimum = Some(map.next_value::<IsolationLevel>()?);
                }
                minimum
                    .map(|minimum| IsolationGrantWire { minimum })
                    .ok_or_else(|| A::Error::custom("isolation names no minimum"))
            }
        }

        deserializer.deserialize_map(Fields)
    }
}

impl TryFrom<IsolationGrantWire> for IsolationGrant {
    type Error = IsolationError;

    fn try_from(wire: IsolationGrantWire) -> Result<Self, IsolationError> {
        Self::new(wire.minimum)
    }
}

impl<'de> Deserialize<'de> for IsolationGrant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_from(IsolationGrantWire::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl IsolationCapabilities {
    /// Whether the node offers a backend at exactly `level`: `namespaces.sandbox` for
    /// `sandbox`, `backends.container`, `backends.microvm` and `backends.vm` for the
    /// others.
    #[must_use]
    pub const fn offers(self, level: IsolationLevel) -> bool {
        match level {
            IsolationLevel::Sandbox => self.namespaces.sandbox,
            IsolationLevel::Container => self.backends.container,
            IsolationLevel::Microvm => self.backends.microvm,
            IsolationLevel::Vm => self.backends.vm,
        }
    }

    /// The same capabilities also offering a backend at `level`.
    #[must_use]
    pub const fn offering(mut self, level: IsolationLevel) -> Self {
        match level {
            IsolationLevel::Sandbox => self.namespaces.sandbox = true,
            IsolationLevel::Container => self.backends.container = true,
            IsolationLevel::Microvm => self.backends.microvm = true,
            IsolationLevel::Vm => self.backends.vm = true,
        }
        self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::{
        CapabilityManifest, CapabilityManifestBytes, ExecutionBackendCapabilities,
        NamespaceCapabilities, NetworkGrant, TaskAdmissionError,
    };

    fn decode(json: &str) -> Result<CapabilityManifest, TaskAdmissionError> {
        CapabilityManifest::decode_json(json.as_bytes())
    }

    #[test]
    fn isolation_levels_are_ordered_by_what_they_guarantee_and_spelled_as_the_document_spells_them()
    {
        assert!(IsolationLevel::Sandbox < IsolationLevel::Container);
        assert!(IsolationLevel::Container < IsolationLevel::Microvm);
        assert!(IsolationLevel::Microvm < IsolationLevel::Vm);
        let mut sorted = IsolationLevel::ALL;
        sorted.sort();
        assert_eq!(sorted, IsolationLevel::ALL);
        for (level, spelling) in
            IsolationLevel::ALL
                .into_iter()
                .zip(["sandbox", "container", "microvm", "vm"])
        {
            assert_eq!(level.as_str(), spelling);
            assert_eq!(level.to_string(), spelling);
            assert_eq!(
                serde_json::to_string(&level).unwrap(),
                format!("\"{spelling}\"")
            );
            assert_eq!(
                serde_json::from_str::<IsolationLevel>(&format!("\"{spelling}\"")).unwrap(),
                level
            );
        }
        for bad in [r#""Sandbox""#, r#""micro_vm""#, r#""kvm""#, "null", "1"] {
            assert!(
                serde_json::from_str::<IsolationLevel>(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_floor_names_one_level_above_sandbox_and_round_trips_in_one_spelling() {
        for level in [
            IsolationLevel::Container,
            IsolationLevel::Microvm,
            IsolationLevel::Vm,
        ] {
            let grant = IsolationGrant::new(level).unwrap();
            assert_eq!(grant.minimum(), level);
            let manifest = CapabilityManifest::new(NetworkGrant::Offline).with_isolation(grant);
            let bytes = CapabilityManifestBytes::encode(&manifest).unwrap();
            assert_eq!(
                bytes.bytes(),
                format!(r#"{{"network":"offline","isolation":{{"minimum":"{level}"}}}}"#)
                    .as_bytes()
            );
            assert_eq!(bytes.manifest(), &manifest);
            assert_eq!(bytes.manifest().isolation(), Some(grant));
            assert_eq!(bytes.manifest().minimum_isolation(), level);
            assert_eq!(
                decode(&format!(
                    r#"{{ "isolation" : {{ "minimum" : "{level}" }}, "network" : "offline" }}"#
                ))
                .unwrap(),
                manifest
            );
        }
        let plain = decode(r#"{"network":"offline"}"#).unwrap();
        assert_eq!(plain.isolation(), None);
        assert_eq!(plain.minimum_isolation(), IsolationLevel::Sandbox);
        assert_eq!(
            CapabilityManifestBytes::encode(&plain).unwrap().bytes(),
            br#"{"network":"offline"}"#,
            "a manifest without a floor is byte for byte what it was"
        );
        assert_eq!(
            IsolationGrant::new(IsolationLevel::Sandbox),
            Err(IsolationError::ImplicitMinimum)
        );
    }

    #[test]
    fn a_floor_outside_the_grammar_fails_manifest_decoding() {
        assert_eq!(
            decode(r#"{"network":"offline","isolation":{"minimum":"sandbox"}}"#),
            Err(TaskAdmissionError::MalformedIsolation(
                IsolationError::ImplicitMinimum
            ))
        );
        for bad in [
            r#"{"network":"offline","isolation":{}}"#,
            r#"{"network":"offline","isolation":null}"#,
            r#"{"network":"offline","isolation":"microvm"}"#,
            r#"{"network":"offline","isolation":["microvm"]}"#,
            r#"{"network":"offline","isolation":{"minimum":null}}"#,
            r#"{"network":"offline","isolation":{"minimum":"kvm"}}"#,
            r#"{"network":"offline","isolation":{"minimum":"MicroVM"}}"#,
            r#"{"network":"offline","isolation":{"minimum":2}}"#,
            r#"{"network":"offline","isolation":{"minimum":"vm","maximum":"vm"}}"#,
            r#"{"network":"offline","isolation":{"minimum":"vm","minimum":"vm"}}"#,
            r#"{"network":"offline","isolation":{"minimum":"vm"},"isolation":{"minimum":"vm"}}"#,
            r#"{"network":"offline","isolation":{"backend":"bubblewrap"}}"#,
        ] {
            assert_eq!(
                decode(bad),
                Err(TaskAdmissionError::MalformedManifest),
                "{bad}"
            );
        }
        assert_eq!(
            TaskAdmissionError::MalformedIsolation(IsolationError::ImplicitMinimum).to_string(),
            "capability manifest isolation floor is invalid"
        );
        assert_eq!(
            IsolationError::ImplicitMinimum.to_string(),
            "an isolation floor of sandbox is spelled by leaving isolation out"
        );
    }

    #[test]
    fn the_capability_document_offers_a_level_through_its_existing_isolation_flags() {
        let none = IsolationCapabilities::default();
        for level in IsolationLevel::ALL {
            assert!(!none.offers(level), "{level}");
            let one = none.offering(level);
            for other in IsolationLevel::ALL {
                assert_eq!(one.offers(other), other == level, "{level} offers {other}");
            }
        }
        assert_eq!(
            none.offering(IsolationLevel::Sandbox),
            IsolationCapabilities {
                namespaces: NamespaceCapabilities {
                    sandbox: true,
                    user_namespace: false,
                },
                backends: ExecutionBackendCapabilities::default(),
                stronger_placement: false,
            }
        );
        assert_eq!(
            serde_json::to_string(&none.offering(IsolationLevel::Container)).unwrap(),
            r#"{"namespaces":{"sandbox":false,"user_namespace":false},"backends":{"container":true,"microvm":false,"vm":false}}"#,
            "a node placing every attempt at its floor says nothing more"
        );
        let stronger = IsolationCapabilities {
            stronger_placement: true,
            ..none.offering(IsolationLevel::Container)
        };
        let wire = serde_json::to_string(&stronger).unwrap();
        assert_eq!(
            wire,
            r#"{"namespaces":{"sandbox":false,"user_namespace":false},"backends":{"container":true,"microvm":false,"vm":false},"stronger_placement":true}"#
        );
        assert_eq!(
            serde_json::from_str::<IsolationCapabilities>(&wire).unwrap(),
            stronger
        );
        for bad in [
            r#"{"namespaces":{"sandbox":false,"user_namespace":false},"backends":{"container":true,"microvm":false,"vm":false},"stronger_placement":"yes"}"#,
            r#"{"namespaces":{"sandbox":false,"user_namespace":false},"backends":{"container":true,"microvm":false,"vm":false},"placement":"stronger"}"#,
        ] {
            assert!(
                serde_json::from_str::<IsolationCapabilities>(bad).is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            none.offering(IsolationLevel::Microvm).backends,
            ExecutionBackendCapabilities {
                container: false,
                microvm: true,
                vm: false,
            }
        );
    }
}
