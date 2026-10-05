//! Who delegated what authority to which task and when, answered from the node's own
//! durable records (#259, ADR-0030 §6).
//!
//! `ward-node audit --state-dir <dir> <task_…> [--attempt <exec_…>] [--task-root <dir>]
//! [--json]` reads the task's record ([`crate::records`]) and reports the authority the
//! `admit` that took effect verified: the principal, or the agent, that delegated the
//! lease the binding names; the agent holding it; the task; the lease's validity and
//! grants; its lineage, root first; and the issuer key, envelope version, node time and
//! operation of the admission. It then reports the attempt's recorded state and receipt
//! outcome and, with `--task-root`, the attempt's evidence log ([`crate::evidence`]): the
//! log must verify and its `NodeAttemptAdmitted` record for the admit operation must
//! agree with the record on binding, session, envelope digest, issuer key id and version,
//! or the output says that the evidence disagrees with the record and the command exits
//! non-zero.
//!
//! The audit guesses nothing. A record that is absent, unreadable, malformed or oversized
//! is an error; an `--attempt` other than the one the record holds is an error; a record
//! written before authority facts were recorded says so and reports the admission's
//! operation, envelope digest, issuer key id and session; a task never admitted says so.
//! A `ready` task recovered by a restart has forgotten its admission (§6.4) and reads as
//! never admitted until it is admitted again; an attempt that was started keeps its chain
//! for as long as its record exists.
//!
//! The JSON form carries `"schema":1` and the same facts under stable names; every time is
//! in Unix milliseconds, every id in its prefixed form and every hash in lowercase hex.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;
use ward_events::{
    Blake3Hash, EventRecord, ExecutionAttemptId, LeaseId, SessionId, TaskId, WardEvent,
};
use ward_node_protocol::{TaskBinding, TaskExecutionOutcome};

use crate::evidence::{EVIDENCE_LOG, EvidenceError, evidence_dir, verify};
use crate::records::{
    AdmitRecord, AuthorityRecord, RecordedLease, RecordedState, TASKS_DIR, TaskRecord,
    TaskRecordError, TaskStore,
};

/// The schema of the JSON form.
pub const AUDIT_SCHEMA: u32 = 1;

/// Why a task could not be audited.
#[derive(Debug, Error)]
pub enum AuditError {
    /// The state directory holds no task records.
    #[error("no task records under {}", .0.display())]
    NoRecords(PathBuf),
    /// The record could not be opened or is not a valid record.
    #[error(transparent)]
    Records(#[from] TaskRecordError),
    /// The task has no record.
    #[error("task {0} has no record")]
    NoRecord(TaskId),
    /// The record holds another attempt than the one asked for.
    #[error(
        "attempt {requested} is not the attempt recorded for task {task}, which holds {recorded}"
    )]
    AttemptMismatch {
        /// The task.
        task: TaskId,
        /// The attempt asked for.
        requested: ExecutionAttemptId,
        /// The attempt the record holds.
        recorded: ExecutionAttemptId,
    },
}

/// The audit of one task's current attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TaskAudit {
    schema: u32,
    task: TaskId,
    attempt: ExecutionAttemptId,
    lease: LeaseId,
    state: RecordedState,
    receipt: Option<TaskExecutionOutcome>,
    pub(crate) admitted: Option<AdmittedAudit>,
    pub(crate) evidence: Option<EvidenceAudit>,
}

/// The `admit` that took effect, and the authority it verified when that was recorded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdmittedAudit {
    operation: u64,
    envelope: Blake3Hash,
    issuer_key: Blake3Hash,
    session: SessionId,
    pub(crate) authority: Option<AuthorityRecord>,
}

/// The attempt's evidence log, as found under the task root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EvidenceAudit {
    log: PathBuf,
    verified: Option<EvidenceSummary>,
    disagreement: Option<String>,
}

/// A verified evidence log in brief.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EvidenceSummary {
    records: u64,
    head: Blake3Hash,
    sealed: bool,
}

/// Audit the current attempt of `task` from the records under `state_dir`, checking it is
/// `attempt` when one is named and cross-checking its evidence log when `task_root` is
/// given.
///
/// # Errors
///
/// Returns [`AuditError`] when there are no records, the record is absent or invalid, or
/// it holds another attempt than `attempt`. Evidence that disagrees is not an error: it is
/// reported in the audit ([`TaskAudit::evidence_agrees`]).
pub fn audit(
    state_dir: &Path,
    task: TaskId,
    attempt: Option<ExecutionAttemptId>,
    task_root: Option<&Path>,
) -> Result<TaskAudit, AuditError> {
    let tasks = state_dir.join(TASKS_DIR);
    if std::fs::symlink_metadata(&tasks).is_err() {
        return Err(AuditError::NoRecords(tasks));
    }
    let record = TaskStore::open(state_dir)?
        .read(task)?
        .ok_or(AuditError::NoRecord(task))?;
    if let Some(requested) = attempt
        && requested != record.binding.attempt()
    {
        return Err(AuditError::AttemptMismatch {
            task,
            requested,
            recorded: record.binding.attempt(),
        });
    }
    Ok(TaskAudit::of(&record, task_root))
}

impl TaskAudit {
    fn of(record: &TaskRecord, task_root: Option<&Path>) -> Self {
        Self {
            schema: AUDIT_SCHEMA,
            task: record.binding.task(),
            attempt: record.binding.attempt(),
            lease: record.binding.lease(),
            state: record.state,
            receipt: record.outcome,
            admitted: record.admitted.as_ref().map(AdmittedAudit::of),
            evidence: task_root
                .map(|root| EvidenceAudit::of(root, record.binding, record.admitted.as_ref())),
        }
    }

    /// Whether the evidence log, if it was checked, agrees with the record.
    #[must_use]
    pub fn evidence_agrees(&self) -> bool {
        self.evidence
            .as_ref()
            .is_none_or(|evidence| evidence.disagreement.is_none())
    }
}

impl AdmittedAudit {
    fn of(admitted: &AdmitRecord) -> Self {
        Self {
            operation: admitted.operation_id.get(),
            envelope: admitted.envelope,
            issuer_key: admitted.proof.issuer_key_id(),
            session: admitted.session,
            authority: admitted.authority.clone(),
        }
    }
}

impl EvidenceAudit {
    fn of(root: &Path, binding: TaskBinding, admitted: Option<&AdmitRecord>) -> Self {
        let dir = evidence_dir(root, binding);
        let log = dir.join(EVIDENCE_LOG);
        match verify(&dir, binding) {
            Ok(evidence) => Self {
                log,
                verified: Some(EvidenceSummary {
                    records: evidence.head().next_seq,
                    head: evidence.head().hash,
                    sealed: evidence.is_sealed(),
                }),
                disagreement: compare(admitted, binding, evidence.records()),
            },
            Err(EvidenceError::Absent) => Self {
                log,
                verified: None,
                disagreement: admitted.map(|_| {
                    "the attempt has no evidence log, yet its record holds an admission".to_owned()
                }),
            },
            Err(error) => Self {
                log,
                verified: None,
                disagreement: Some(error.to_string()),
            },
        }
    }
}

fn compare(
    admitted: Option<&AdmitRecord>,
    binding: TaskBinding,
    records: &[EventRecord],
) -> Option<String> {
    let Some(admit) = admitted else {
        return records
            .iter()
            .any(|record| matches!(record.event, WardEvent::NodeAttemptAdmitted { .. }))
            .then(|| "the evidence log records an admission the record does not hold".to_owned());
    };
    let operation = admit.operation_id.get();
    for record in records {
        let WardEvent::NodeAttemptAdmitted {
            task,
            attempt,
            lease,
            session,
            operation: recorded,
            envelope,
            issuer_key,
            version,
        } = &record.event
        else {
            continue;
        };
        if *recorded != operation {
            continue;
        }
        let mut differences = Vec::new();
        if (*task, *attempt, *lease) != (binding.task(), binding.attempt(), binding.lease()) {
            differences.push("binding");
        }
        if *session != admit.session {
            differences.push("session");
        }
        if *envelope != admit.envelope {
            differences.push("envelope digest");
        }
        if *issuer_key != admit.proof.issuer_key_id() {
            differences.push("issuer key id");
        }
        if admit
            .authority
            .as_ref()
            .is_some_and(|authority| authority.version != *version)
        {
            differences.push("version");
        }
        return (!differences.is_empty()).then(|| {
            format!(
                "the NodeAttemptAdmitted record of operation {operation} differs from the \
                 record in {}",
                differences.join(", ")
            )
        });
    }
    Some(format!(
        "the evidence log has no NodeAttemptAdmitted record for operation {operation}"
    ))
}

impl fmt::Display for TaskAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.admitted {
            None => writeln!(
                formatter,
                "task {} attempt {} was never admitted",
                self.task, self.attempt
            )?,
            Some(admitted) => match &admitted.authority {
                None => writeln!(
                    formatter,
                    "task {} attempt {} was admitted before authority facts were recorded \
                     (operation {}, envelope {}, key {}, session {})",
                    self.task,
                    self.attempt,
                    admitted.operation,
                    admitted.envelope,
                    admitted.issuer_key,
                    admitted.session
                )?,
                Some(authority) => {
                    write_chain(formatter, self.task, admitted, authority)?;
                }
            },
        }
        write!(
            formatter,
            "attempt {}: state {}, receipt {}",
            self.attempt,
            self.state,
            self.receipt.map_or("none", outcome_text)
        )?;
        match &self.evidence {
            None => write!(formatter, ", evidence not checked")?,
            Some(evidence) => write_evidence(formatter, evidence)?,
        }
        writeln!(formatter)
    }
}

fn write_chain(
    formatter: &mut fmt::Formatter<'_>,
    task: TaskId,
    admitted: &AdmittedAudit,
    authority: &AuthorityRecord,
) -> fmt::Result {
    let lease = &authority.lease;
    match (lease.delegated_by, lease.parent_lease) {
        (Some(agent), Some(parent)) => writeln!(
            formatter,
            "agent {agent} delegated lease {} (delegation {}) to agent {} for task {task} at \
             {}, expires {}, under principal {} from lease {parent}",
            lease.lease,
            lease.delegation,
            lease.subject,
            unix_ms_text(lease.issued_at_unix_ms),
            unix_ms_text(lease.expires_at_unix_ms),
            lease.issuer
        )?,
        _ => writeln!(
            formatter,
            "principal {} delegated lease {} (delegation {}) to agent {} for task {task} at \
             {}, expires {}",
            lease.issuer,
            lease.lease,
            lease.delegation,
            lease.subject,
            unix_ms_text(lease.issued_at_unix_ms),
            unix_ms_text(lease.expires_at_unix_ms)
        )?,
    }
    writeln!(formatter, "grants: {}", grants_text(lease))?;
    if authority.lineage.is_empty() {
        writeln!(formatter, "lineage: none (root lease)")?;
    } else {
        writeln!(formatter, "lineage, root first:")?;
        for ancestor in authority.lineage.iter().rev() {
            writeln!(
                formatter,
                "  lease {} (delegation {}) from {} to agent {}, valid {} to {}, grants: {}",
                ancestor.lease,
                ancestor.delegation,
                ancestor.delegated_by.map_or_else(
                    || format!("principal {}", ancestor.issuer),
                    |agent| format!("agent {agent}")
                ),
                ancestor.subject,
                unix_ms_text(ancestor.issued_at_unix_ms),
                unix_ms_text(ancestor.expires_at_unix_ms),
                grants_text(ancestor)
            )?;
        }
    }
    writeln!(
        formatter,
        "admitted by key {} as version {} at {} (operation {}); envelope {} valid {} to {}, \
         session {}",
        admitted.issuer_key,
        authority.version,
        unix_ms_text(authority.admitted_at_unix_ms),
        admitted.operation,
        admitted.envelope,
        unix_ms_text(authority.issued_at_unix_ms),
        unix_ms_text(authority.expires_at_unix_ms),
        admitted.session
    )
}

fn write_evidence(formatter: &mut fmt::Formatter<'_>, evidence: &EvidenceAudit) -> fmt::Result {
    write!(formatter, ", evidence {}: ", evidence.log.display())?;
    if let Some(verified) = &evidence.verified {
        write!(
            formatter,
            "{} {}, head {}, {}",
            verified.records,
            if verified.records == 1 {
                "record"
            } else {
                "records"
            },
            verified.head,
            if verified.sealed {
                "sealed"
            } else {
                "not sealed"
            }
        )?;
    }
    match (&evidence.verified, &evidence.disagreement) {
        (None, None) => write!(formatter, "absent"),
        (Some(_), None) => Ok(()),
        (Some(_), Some(disagreement)) => {
            write!(
                formatter,
                "; evidence disagrees with the record: {disagreement}"
            )
        }
        (None, Some(disagreement)) => {
            write!(
                formatter,
                "evidence disagrees with the record: {disagreement}"
            )
        }
    }
}

fn grants_text(lease: &RecordedLease) -> String {
    lease
        .grants
        .as_slice()
        .iter()
        .map(|grant| {
            format!(
                "{} on {}{}",
                grant.capability().as_str(),
                grant.resource().as_str(),
                if grant.delegable() {
                    " (delegable)"
                } else {
                    ""
                }
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

const fn outcome_text(outcome: TaskExecutionOutcome) -> &'static str {
    match outcome {
        TaskExecutionOutcome::Completed => "completed",
        TaskExecutionOutcome::Failed => "failed",
        TaskExecutionOutcome::Unknown => "unknown",
    }
}

/// `unix_ms` as an RFC 3339 UTC timestamp with millisecond precision.
#[must_use]
pub fn unix_ms_text(unix_ms: u64) -> String {
    let millis = unix_ms % 1_000;
    let seconds = unix_ms / 1_000;
    let days = seconds / 86_400;
    let second_of_day = seconds % 86_400;
    let (hour, minute, second) = (
        second_of_day / 3_600,
        second_of_day % 3_600 / 60,
        second_of_day % 60,
    );
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn unix_milliseconds_read_as_utc_timestamps() {
        for (unix_ms, text) in [
            (0, "1970-01-01T00:00:00.000Z"),
            (5_000, "1970-01-01T00:00:05.000Z"),
            (951_782_400_000, "2000-02-29T00:00:00.000Z"),
            (1_767_225_600_000, "2026-01-01T00:00:00.000Z"),
            (1_791_201_600_000, "2026-10-05T12:00:00.000Z"),
            (1_893_452_399_999, "2029-12-31T22:59:59.999Z"),
            (1_893_456_000_000, "2030-01-01T00:00:00.000Z"),
            (253_402_300_799_999, "9999-12-31T23:59:59.999Z"),
        ] {
            assert_eq!(unix_ms_text(unix_ms), text);
        }
        assert!(unix_ms_text(u64::MAX).ends_with("T14:25:51.615Z"));
    }
}
