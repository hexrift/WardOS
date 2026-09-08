//! Semantic settings (`docs/design-language.md` §14): what the agent may reach,
//! in the user's words, as a read-only view of the capability manifest.
//!
//! Namespaces, seccomp, cgroups and mounts are never shown. Nothing here can be
//! changed from the shell: the manifest is fixed for the session's lifetime
//! (ST-007), and changing policy for the next session is an edit to `.ward/`
//! that the shell hands to `ward`. The "Advanced" rows show the effective
//! manifest hash; the policy layer that produced each line is not yet recorded
//! by the merge, so it is not shown.

use std::fmt::Write as _;

use ward_daemon::describe::SessionDescription;
use ward_daemon::render::{Tone, network_tone, observer_text};
use ward_policy::{AccessMode, CapabilityManifest, ContainerCapability, CredentialRule};

/// One labelled, coloured, read-only line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The label, in sans.
    pub label: String,
    /// The value, in sans for words and mono for identifiers.
    pub value: String,
    /// The value's colour role: green where nothing is reachable, amber where
    /// something is, red where everything is.
    pub tone: Tone,
}

impl Row {
    /// A row.
    pub fn new(label: impl Into<String>, value: impl Into<String>, tone: Tone) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            tone,
        }
    }
}

/// The settings view: the "Agent Access" group of §14 and the "Advanced" group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Repository, Internet, Private network, Host files, one row per
    /// credential rule, Containers, Observer.
    pub agent_access: Vec<Row>,
    /// Manifest hash, ids, snapshot, agent image.
    pub advanced: Vec<Row>,
}

impl Settings {
    /// The settings of a described session.
    #[must_use]
    pub fn from_description(d: &SessionDescription) -> Self {
        let m = &d.manifest;
        let advanced = vec![
            Row::new("Manifest hash", d.policy_hash.clone(), Tone::Dim),
            Row::new("Session", d.session.clone(), Tone::Dim),
            Row::new("Project", d.project.clone(), Tone::Dim),
            Row::new("Entry snapshot", d.entry_snapshot.clone(), Tone::Dim),
            Row::new("Agent image", m.agent_image.0.clone(), Tone::Dim),
        ];
        Self {
            agent_access: agent_access(m),
            advanced,
        }
    }

    /// The §14 layout as text: each group's heading and its aligned rows.
    #[must_use]
    pub fn text(&self) -> String {
        let mut s = String::from("Agent Access\n\n");
        s.push_str(&rows_text(&self.agent_access));
        s.push_str("\nAdvanced\n\n");
        s.push_str(&rows_text(&self.advanced));
        s
    }
}

/// The "Agent Access" rows of a manifest.
#[must_use]
pub fn agent_access(m: &CapabilityManifest) -> Vec<Row> {
    let mut rows = vec![
        Row::new(
            "Repository",
            repository_text(m.filesystem.worktree),
            repository_tone(m),
        ),
        Row::new("Internet", internet_text(m), network_tone(&m.network)),
        private_network(m),
        host_files(m),
    ];
    for (service, rule) in &m.credentials {
        let (value, tone) = match rule {
            CredentialRule::Deny => ("Denied", Tone::Ok),
            CredentialRule::Ask(_) => ("Ask", Tone::Warn),
            CredentialRule::Allow(_) => ("Allowed", Tone::Warn),
        };
        rows.push(Row::new(
            format!("{} credentials", service_label(&service.0)),
            value,
            tone,
        ));
    }
    let (containers, tone) = match m.containers {
        ContainerCapability::None => ("Denied", Tone::Ok),
        ContainerCapability::NestedRootless => ("Nested, rootless", Tone::Warn),
    };
    rows.push(Row::new("Containers", containers, tone));
    rows.push(Row::new(
        "Observer",
        capitalise(observer_text(m.observer)),
        Tone::Ink,
    ));
    rows
}

fn repository_text(mode: AccessMode) -> &'static str {
    match mode {
        AccessMode::ReadWrite => "Read & Write",
        AccessMode::ReadOnly => "Read only",
        AccessMode::None => "Denied",
    }
}

/// Writing the repository is the point of a session: neutral, not a warning.
fn repository_tone(m: &CapabilityManifest) -> Tone {
    match m.filesystem.worktree {
        AccessMode::ReadWrite => Tone::Ink,
        AccessMode::ReadOnly | AccessMode::None => Tone::Ok,
    }
}

fn internet_text(m: &CapabilityManifest) -> String {
    use ward_policy::NetworkCapability as N;
    match &m.network {
        N::Offline => "Denied".to_owned(),
        N::LocalhostOnly => "Localhost only".to_owned(),
        N::Registries => "Package registries".to_owned(),
        N::Development => "Restricted".to_owned(),
        N::Custom(hosts) => format!("Restricted ({} hosts)", hosts.len()),
        N::Unrestricted => "Allowed".to_owned(),
    }
}

/// Private ranges are denied structurally by every mode; the row is derived
/// from the manifest's own invariant rather than written down, so a mode that
/// ever changed that would show up here.
fn private_network(m: &CapabilityManifest) -> Row {
    if m.network.permits_private_ranges() {
        Row::new("Private network", "Allowed", Tone::Deny)
    } else {
        Row::new("Private network", "Denied", Tone::Ok)
    }
}

/// The sandbox sees no host path; extra in-sandbox mounts are the one way more
/// than the fixed set is reachable.
fn host_files(m: &CapabilityManifest) -> Row {
    let extra = m.filesystem.extra.len();
    if extra == 0 {
        Row::new("Host files", "Denied", Tone::Ok)
    } else {
        Row::new("Host files", format!("{extra} extra mounts"), Tone::Warn)
    }
}

/// `github` → `GitHub`, `ssh-signing` → `SSH signing`, `cloud-*` → `Cloud`,
/// otherwise the id with dashes as spaces and any wildcard dropped.
#[must_use]
pub fn service_label(service: &str) -> String {
    let known = match service {
        "github" => "GitHub",
        "ssh-signing" => "SSH signing",
        "cloud-*" => "Cloud",
        "npm-publish" => "npm publish",
        "pypi-publish" => "PyPI publish",
        _ => "",
    };
    if known.is_empty() {
        let bare = service.trim_end_matches('*').trim_end_matches('-');
        capitalise(&bare.replace('-', " "))
    } else {
        known.to_owned()
    }
}

fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// Rows aligned in two columns, the label padded to the longest.
#[must_use]
pub fn rows_text(rows: &[Row]) -> String {
    let width = rows
        .iter()
        .map(|r| r.label.chars().count())
        .max()
        .unwrap_or(0);
    let mut s = String::new();
    for r in rows {
        let _ = writeln!(s, "{:<width$}   {}", r.label, r.value);
    }
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::trust::fixtures::description;
    use std::collections::BTreeMap;
    use ward_policy::{CredentialScope, NetworkCapability, ObserverMode, ServiceId};

    fn value(rows: &[Row], label: &str) -> (String, Tone) {
        let row = rows.iter().find(|r| r.label == label).unwrap();
        (row.value.clone(), row.tone)
    }

    #[test]
    fn the_default_manifest_reads_as_the_design_names_it() {
        let d = description(NetworkCapability::Development);
        let s = Settings::from_description(&d);
        let rows = &s.agent_access;
        assert_eq!(
            value(rows, "Repository"),
            ("Read & Write".to_owned(), Tone::Ink)
        );
        assert_eq!(
            value(rows, "Internet"),
            ("Restricted".to_owned(), Tone::Warn)
        );
        assert_eq!(
            value(rows, "Private network"),
            ("Denied".to_owned(), Tone::Ok)
        );
        assert_eq!(value(rows, "Host files"), ("Denied".to_owned(), Tone::Ok));
        assert_eq!(
            value(rows, "GitHub credentials"),
            ("Ask".to_owned(), Tone::Warn)
        );
        assert_eq!(
            value(rows, "Cloud credentials"),
            ("Denied".to_owned(), Tone::Ok)
        );
        assert_eq!(
            value(rows, "SSH signing credentials"),
            ("Ask".to_owned(), Tone::Warn),
            "§14: SSH credentials  Ask"
        );
        assert_eq!(
            value(rows, "Containers"),
            ("Nested, rootless".to_owned(), Tone::Warn),
            "the default allows nested rootless containers"
        );
        assert_eq!(value(rows, "Observer"), ("Live".to_owned(), Tone::Ink));
        // Every credential rule in the manifest has a row, and nothing else does.
        let credential_rows = rows
            .iter()
            .filter(|r| r.label.ends_with(" credentials"))
            .count();
        assert_eq!(credential_rows, d.manifest.credentials.len());

        assert_eq!(s.advanced[0].label, "Manifest hash");
        assert_eq!(s.advanced[0].value, d.policy_hash);
        assert_eq!(s.advanced[0].value.len(), 64);
        assert_eq!(value(&s.advanced, "Entry snapshot").0, d.entry_snapshot);
        assert_eq!(
            value(&s.advanced, "Agent image").0,
            d.manifest.agent_image.0
        );

        let text = s.text();
        assert!(text.starts_with("Agent Access\n\nRepository "), "{text}");
        let line = |label: &str| {
            text.lines()
                .find(|l| l.starts_with(label))
                .map(str::to_owned)
                .unwrap()
        };
        assert!(line("Private network").ends_with("   Denied"), "{text}");
        assert!(line("Manifest hash").ends_with(&d.policy_hash), "{text}");
        // Labels of a group are padded to one column.
        let values_at: Vec<usize> = text
            .lines()
            .filter(|l| l.ends_with("Denied"))
            .map(|l| l.find("Denied").unwrap())
            .collect();
        assert!(values_at.windows(2).all(|w| w[0] == w[1]), "{text}");
        assert!(text.contains("\nAdvanced\n\nManifest hash"), "{text}");
        // No implementation vocabulary leaks into the view.
        for word in ["seccomp", "namespace", "cgroup", "mount", "/work"] {
            assert!(!text.contains(word), "{word} in {text}");
        }
    }

    #[test]
    fn internet_follows_the_network_ladder_with_its_trust_tone() {
        use NetworkCapability as N;
        let custom = N::Custom(["a.example".to_owned(), "b.example".to_owned()].into());
        let cases = [
            (N::Offline, "Denied", Tone::Ok),
            (N::LocalhostOnly, "Localhost only", Tone::Warn),
            (N::Registries, "Package registries", Tone::Warn),
            (N::Development, "Restricted", Tone::Warn),
            (custom, "Restricted (2 hosts)", Tone::Warn),
            (N::Unrestricted, "Allowed", Tone::Deny),
        ];
        for (network, text, tone) in cases {
            let rows = agent_access(&description(network.clone()).manifest);
            assert_eq!(
                value(&rows, "Internet"),
                (text.to_owned(), tone),
                "{network:?}"
            );
            assert_eq!(
                value(&rows, "Private network"),
                ("Denied".to_owned(), Tone::Ok),
                "{network:?}: private ranges are structural"
            );
        }
    }

    #[test]
    fn widening_the_manifest_turns_rows_amber() {
        let mut d = description(NetworkCapability::Offline);
        let m = &mut d.manifest;
        m.filesystem.worktree = AccessMode::ReadOnly;
        m.filesystem
            .extra
            .insert("/data".into(), AccessMode::ReadOnly);
        m.containers = ContainerCapability::NestedRootless;
        m.observer = ObserverMode::Quiet;
        let mut credentials = BTreeMap::new();
        credentials.insert(
            ServiceId("github".to_owned()),
            CredentialRule::Allow(CredentialScope::default()),
        );
        credentials.insert(ServiceId("my-registry-*".to_owned()), CredentialRule::Deny);
        m.credentials = credentials;
        let rows = agent_access(m);
        assert_eq!(
            value(&rows, "Repository"),
            ("Read only".to_owned(), Tone::Ok)
        );
        assert_eq!(
            value(&rows, "Host files"),
            ("1 extra mounts".to_owned(), Tone::Warn)
        );
        assert_eq!(
            value(&rows, "Containers"),
            ("Nested, rootless".to_owned(), Tone::Warn)
        );
        assert_eq!(value(&rows, "Observer"), ("Quiet".to_owned(), Tone::Ink));
        assert_eq!(
            value(&rows, "GitHub credentials"),
            ("Allowed".to_owned(), Tone::Warn)
        );
        assert_eq!(value(&rows, "My registry credentials").1, Tone::Ok);
        m.filesystem.worktree = AccessMode::None;
        assert_eq!(
            value(&agent_access(m), "Repository"),
            ("Denied".to_owned(), Tone::Ok)
        );
    }

    #[test]
    fn service_labels_read_as_product_names() {
        assert_eq!(service_label("github"), "GitHub");
        assert_eq!(service_label("ssh-signing"), "SSH signing");
        assert_eq!(service_label("cloud-*"), "Cloud");
        assert_eq!(service_label("npm-publish"), "npm publish");
        assert_eq!(service_label("pypi-publish"), "PyPI publish");
        assert_eq!(service_label("acme-vault"), "Acme vault");
        assert_eq!(service_label("acme-*"), "Acme");
        assert_eq!(service_label(""), "");
    }
}
