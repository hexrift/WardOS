//! Approval holds (#415, ADR-0035; #332 stage 3): a manifest marks capabilities it grants
//! as held until the control plane approves them, additive within protocol 1.3.
//!
//! The manifest's optional `hold` field names hosts of its own `network.custom` and
//! services of its own `credentials`:
//!
//! ```json
//! {"network":{"custom":["deploy.example.com","artifacts.example.com"]},
//!  "credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":600}],
//!  "actions":{"kinds":["approval"],"max_pending":1,"max_total":1,"wait_secs":300},
//!  "hold":{"hosts":["deploy.example.com"],"services":["artifacts"]}}
//! ```
//!
//! The grammar holds 1 to [`MAX_HOLDS`] capabilities, none twice, each host exactly one of
//! the manifest's `network.custom` patterns and each service one of its `credentials`, and
//! needs an `actions` grant naming `approval`: the node asks through the attempt's action
//! channel. A manifest outside it fails decoding. A node honours the field only when its
//! capability document's `actions` section carries `hold`.
//!
//! The node, not the workload, opens the approval request: the first request the attempt's
//! proxy sees for a held capability opens one `approval` request on the channel, under the
//! id [`hold_request_id`] and with the capability in the listing's `hold` field
//! ([`HeldCapability`]), and the proxy refuses the capability until that request is
//! answered `approved`.

use std::fmt::{Display, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::actions::{ActionId, ActionKind};
use crate::admission::{HostAllowlist, is_host_pattern};
use crate::credentials::{CredentialGrants, is_service};

/// Most capabilities one manifest may hold.
pub const MAX_HOLDS: usize = 8;

/// Why a `hold` is outside its grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoldError {
    /// No capability held, more than [`MAX_HOLDS`], an empty list, one named twice, or a
    /// host or service outside its grammar.
    InvalidHold,
    /// A held host is not one of the manifest's `network.custom` patterns.
    HostNotGranted,
    /// A held service is not one of the manifest's `credentials`.
    ServiceNotGranted,
    /// The manifest has no `actions` grant naming `approval`, so nothing could ask.
    ApprovalNotGranted,
}

impl Display for HoldError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidHold => "hold is invalid",
            Self::HostNotGranted => "a held host is not a network.custom pattern of the manifest",
            Self::ServiceNotGranted => "a held service is not a credential of the manifest",
            Self::ApprovalNotGranted => "a hold needs an actions grant naming approval",
        })
    }
}

impl std::error::Error for HoldError {}

/// One held capability: a `network.custom` pattern (`{"host":…}`) or a credential service
/// (`{"service":…}`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HeldCapability {
    /// Every request to a host the pattern covers.
    Host(String),
    /// Every request on the service's credential route.
    Service(String),
}

impl HeldCapability {
    /// A held host pattern.
    ///
    /// # Errors
    ///
    /// Returns [`HoldError::InvalidHold`] outside the allowlist's pattern grammar.
    pub fn host(pattern: impl Into<String>) -> Result<Self, HoldError> {
        let pattern = pattern.into();
        if !is_host_pattern(&pattern) {
            return Err(HoldError::InvalidHold);
        }
        Ok(Self::Host(pattern))
    }

    /// A held credential service.
    ///
    /// # Errors
    ///
    /// Returns [`HoldError::InvalidHold`] outside `[a-z][a-z0-9-]{0,31}`.
    pub fn service(name: impl Into<String>) -> Result<Self, HoldError> {
        let name = name.into();
        if !is_service(&name) {
            return Err(HoldError::InvalidHold);
        }
        Ok(Self::Service(name))
    }

    /// The summary of the approval request the node opens for it.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Host(pattern) => format!("network {pattern}"),
            Self::Service(name) => format!("credential {name}"),
        }
    }

    /// The detail of the approval request the node opens for it.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Host(pattern) => {
                format!("the node refuses requests to {pattern} until this is approved")
            }
            Self::Service(name) => {
                format!("the node injects no {name} credential until this is approved")
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum HeldCapabilityWire {
    Host(String),
    Service(String),
}

impl Serialize for HeldCapability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.clone() {
            Self::Host(pattern) => HeldCapabilityWire::Host(pattern),
            Self::Service(name) => HeldCapabilityWire::Service(name),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HeldCapability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match HeldCapabilityWire::deserialize(deserializer)? {
            HeldCapabilityWire::Host(pattern) => Self::host(pattern),
            HeldCapabilityWire::Service(name) => Self::service(name),
        }
        .map_err(D::Error::custom)
    }
}

/// The id of the approval request the node opens for the held capability at `index` (from
/// 0, hosts first, then services, in manifest order): `hold:1`, `hold:2`, … These ids are
/// the node's in an attempt with a hold; a workload request under one is refused
/// `duplicate_id`.
#[must_use]
pub fn hold_request_id(index: usize) -> ActionId {
    ActionId::node(format!("hold:{}", index + 1))
}

/// The manifest's `hold`: the hosts and services the node holds until approved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HoldGrant {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hosts: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    services: Vec<String>,
}

impl HoldGrant {
    /// A hold on `hosts` and `services`.
    ///
    /// # Errors
    ///
    /// Returns [`HoldError::InvalidHold`] for nothing held, more than [`MAX_HOLDS`], a
    /// repeated entry, or a host or service outside its grammar.
    pub fn new(hosts: Vec<String>, services: Vec<String>) -> Result<Self, HoldError> {
        let repeated = |list: &[String]| {
            list.iter()
                .enumerate()
                .any(|(index, entry)| list[..index].contains(entry))
        };
        let count = hosts.len() + services.len();
        if count == 0
            || count > MAX_HOLDS
            || repeated(&hosts)
            || repeated(&services)
            || !hosts.iter().all(|host| is_host_pattern(host))
            || !services.iter().all(|service| is_service(service))
        {
            return Err(HoldError::InvalidHold);
        }
        Ok(Self { hosts, services })
    }

    /// The held host patterns, in the order given.
    #[must_use]
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// The held services, in the order given.
    #[must_use]
    pub fn services(&self) -> &[String] {
        &self.services
    }

    /// Every held capability: hosts first, then services, each in the order given; the
    /// index of one is what [`hold_request_id`] numbers.
    #[must_use]
    pub fn held(&self) -> Vec<HeldCapability> {
        self.hosts
            .iter()
            .cloned()
            .map(HeldCapability::Host)
            .chain(self.services.iter().cloned().map(HeldCapability::Service))
            .collect()
    }

    /// Hold the grant to the manifest it is part of: every host one of `allowlist`'s
    /// patterns, every service one of `credentials`, and `approval` among `kinds`.
    ///
    /// # Errors
    ///
    /// The [`HoldError`] for the first failed rule.
    pub fn within(
        &self,
        allowlist: Option<&HostAllowlist>,
        credentials: Option<&CredentialGrants>,
        kinds: Option<&[ActionKind]>,
    ) -> Result<(), HoldError> {
        if !self
            .hosts
            .iter()
            .all(|host| allowlist.is_some_and(|allowlist| allowlist.patterns().contains(host)))
        {
            return Err(HoldError::HostNotGranted);
        }
        if !self.services.iter().all(|service| {
            credentials.is_some_and(|credentials| {
                credentials
                    .grants()
                    .iter()
                    .any(|grant| grant.service() == service)
            })
        }) {
            return Err(HoldError::ServiceNotGranted);
        }
        if !kinds.is_some_and(|kinds| kinds.contains(&ActionKind::Approval)) {
            return Err(HoldError::ApprovalNotGranted);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HoldGrantWire {
    #[serde(default, deserialize_with = "deserialize_present_list")]
    hosts: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_present_list")]
    services: Option<Vec<String>>,
}

fn deserialize_present_list<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer).map(Some)
}

impl TryFrom<HoldGrantWire> for HoldGrant {
    type Error = HoldError;

    fn try_from(wire: HoldGrantWire) -> Result<Self, HoldError> {
        if wire.hosts.as_ref().is_some_and(Vec::is_empty)
            || wire.services.as_ref().is_some_and(Vec::is_empty)
        {
            return Err(HoldError::InvalidHold);
        }
        Self::new(
            wire.hosts.unwrap_or_default(),
            wire.services.unwrap_or_default(),
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::{CapabilityManifestBytes, TaskAdmissionError};

    const ACTIONS: &str =
        r#""actions":{"kinds":["approval"],"max_pending":1,"max_total":1,"wait_secs":60}"#;

    fn decode(raw: &str) -> Result<CapabilityManifestBytes, TaskAdmissionError> {
        CapabilityManifestBytes::new(raw.as_bytes().to_vec())
    }

    fn manifest(hold: &str) -> String {
        format!(
            r#"{{"network":{{"custom":["deploy.example.com","*.wild.example","artifacts.example.com"]}},{ACTIONS},"credentials":[{{"service":"artifacts","host":"artifacts.example.com","ttl_secs":60}}],"hold":{hold}}}"#
        )
    }

    fn refused(raw: &str) -> TaskAdmissionError {
        decode(raw).unwrap_err()
    }

    #[test]
    fn a_hold_decodes_round_trips_and_lists_hosts_before_services() {
        let raw = manifest(
            r#"{"hosts":["deploy.example.com","*.wild.example"],"services":["artifacts"]}"#,
        );
        let decoded = decode(&raw).unwrap();
        let hold = decoded.manifest().hold().unwrap();
        assert_eq!(hold.hosts(), ["deploy.example.com", "*.wild.example"]);
        assert_eq!(hold.services(), ["artifacts"]);
        assert_eq!(
            hold.held(),
            vec![
                HeldCapability::Host("deploy.example.com".to_owned()),
                HeldCapability::Host("*.wild.example".to_owned()),
                HeldCapability::Service("artifacts".to_owned()),
            ]
        );
        let encoded = CapabilityManifestBytes::encode(decoded.manifest()).unwrap();
        assert_eq!(encoded.bytes(), raw.as_bytes());

        let hosts_only = manifest(r#"{"hosts":["deploy.example.com"]}"#);
        let decoded = decode(&hosts_only).unwrap();
        assert!(decoded.manifest().hold().unwrap().services().is_empty());
        let encoded = CapabilityManifestBytes::encode(decoded.manifest()).unwrap();
        assert_eq!(encoded.bytes(), hosts_only.as_bytes());
        assert!(
            decode(r#"{"network":"offline"}"#)
                .unwrap()
                .manifest()
                .hold()
                .is_none()
        );
    }

    #[test]
    fn a_hold_outside_the_grammar_fails_decoding() {
        let malformed = TaskAdmissionError::MalformedHold(HoldError::InvalidHold);
        for hold in [
            "{}",
            r#"{"hosts":[]}"#,
            r#"{"services":[]}"#,
            r#"{"hosts":["deploy.example.com","deploy.example.com"]}"#,
            r#"{"services":["artifacts","artifacts"]}"#,
            r#"{"hosts":["Deploy.example.com"]}"#,
            r#"{"services":["Artifacts"]}"#,
        ] {
            assert_eq!(refused(&manifest(hold)), malformed, "{hold}");
        }
        for hold in [
            r#"{"hosts":["deploy.example.com"],"other":[]}"#,
            r#"{"hosts":"deploy.example.com"}"#,
            r#"{"hosts":null}"#,
            "[]",
            "null",
        ] {
            assert!(decode(&manifest(hold)).is_err(), "{hold}");
        }
        let many: Vec<String> = (0..=MAX_HOLDS)
            .map(|i| format!("h{i}.example.com"))
            .collect();
        let quoted = |list: &[String]| {
            list.iter()
                .map(|host| format!("\"{host}\""))
                .collect::<Vec<_>>()
                .join(",")
        };
        let raw = format!(
            r#"{{"network":{{"custom":[{}]}},{ACTIONS},"hold":{{"hosts":[{}]}}}}"#,
            quoted(&many),
            quoted(&many)
        );
        assert_eq!(refused(&raw), malformed);
        let raw = format!(
            r#"{{"network":{{"custom":[{}]}},{ACTIONS},"hold":{{"hosts":[{}]}}}}"#,
            quoted(&many),
            quoted(&many[..MAX_HOLDS])
        );
        assert_eq!(
            decode(&raw)
                .unwrap()
                .manifest()
                .hold()
                .unwrap()
                .held()
                .len(),
            MAX_HOLDS
        );
    }

    #[test]
    fn a_hold_names_only_what_its_manifest_grants_and_needs_an_approval_channel() {
        assert_eq!(
            refused(&manifest(r#"{"hosts":["other.example.com"]}"#)),
            TaskAdmissionError::MalformedHold(HoldError::HostNotGranted)
        );
        assert_eq!(
            refused(&manifest(r#"{"hosts":["x.wild.example"]}"#)),
            TaskAdmissionError::MalformedHold(HoldError::HostNotGranted),
            "a host is held by its exact pattern, not by a name the pattern covers"
        );
        assert_eq!(
            refused(&manifest(r#"{"services":["other"]}"#)),
            TaskAdmissionError::MalformedHold(HoldError::ServiceNotGranted)
        );
        assert_eq!(
            refused(&format!(
                r#"{{"network":"offline",{ACTIONS},"hold":{{"hosts":["deploy.example.com"]}}}}"#
            )),
            TaskAdmissionError::MalformedHold(HoldError::HostNotGranted)
        );
        assert_eq!(
            refused(
                r#"{"network":{"custom":["deploy.example.com"]},"hold":{"hosts":["deploy.example.com"]}}"#
            ),
            TaskAdmissionError::MalformedHold(HoldError::ApprovalNotGranted)
        );
        assert_eq!(
            refused(
                r#"{"network":{"custom":["deploy.example.com"]},"actions":{"kinds":["decision"],"max_pending":1,"max_total":1,"wait_secs":60},"hold":{"hosts":["deploy.example.com"]}}"#
            ),
            TaskAdmissionError::MalformedHold(HoldError::ApprovalNotGranted)
        );
    }

    #[test]
    fn a_held_capability_has_one_wire_spelling_and_the_node_names_its_requests() {
        let host = HeldCapability::host("deploy.example.com").unwrap();
        assert_eq!(
            serde_json::to_string(&host).unwrap(),
            r#"{"host":"deploy.example.com"}"#
        );
        let service = HeldCapability::service("artifacts").unwrap();
        assert_eq!(
            serde_json::to_string(&service).unwrap(),
            r#"{"service":"artifacts"}"#
        );
        for raw in [
            r#"{"host":"deploy.example.com"}"#,
            r#"{"service":"artifacts"}"#,
        ] {
            let decoded: HeldCapability = serde_json::from_str(raw).unwrap();
            assert_eq!(serde_json::to_string(&decoded).unwrap(), raw);
        }
        for raw in [
            r#"{"host":"UPPER.example"}"#,
            r#"{"service":"Bad"}"#,
            r#"{"port":1}"#,
            r#"{"host":"a.example","service":"b"}"#,
            r#""host""#,
        ] {
            assert!(
                serde_json::from_str::<HeldCapability>(raw).is_err(),
                "{raw}"
            );
        }
        assert_eq!(HeldCapability::host("BAD"), Err(HoldError::InvalidHold));
        assert_eq!(HeldCapability::service("9x"), Err(HoldError::InvalidHold));
        assert_eq!(host.summary(), "network deploy.example.com");
        assert_eq!(service.summary(), "credential artifacts");
        assert!(host.detail().contains("deploy.example.com"));
        assert!(service.detail().contains("artifacts"));
        assert_eq!(hold_request_id(0).as_str(), "hold:1");
        assert_eq!(hold_request_id(MAX_HOLDS - 1).as_str(), "hold:8");
        assert_eq!(HoldError::InvalidHold.to_string(), "hold is invalid");
        for error in [
            HoldError::HostNotGranted,
            HoldError::ServiceNotGranted,
            HoldError::ApprovalNotGranted,
        ] {
            assert!(!error.to_string().is_empty());
        }
    }
}
