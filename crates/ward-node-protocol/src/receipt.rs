//! Bounded task receipt types for a governed execution boundary.

use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};
use ward_events::SessionId;

use crate::TaskBinding;

const MAX_TASK_RECEIPT_BYTES: usize = 512;

/// Reported outcome of one task execution attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskExecutionOutcome {
    /// The task attempt completed.
    Completed,
    /// The task attempt failed.
    Failed,
    /// The task attempt may have produced an effect that cannot be confirmed.
    Unknown,
}

/// A bounded report correlated to one task binding and one node session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TaskExecutionReceipt {
    binding: TaskBinding,
    session: SessionId,
    outcome: TaskExecutionOutcome,
}

impl TaskExecutionReceipt {
    /// The exact task, attempt, and authority lease reported by this receipt.
    #[must_use]
    pub const fn binding(self) -> TaskBinding {
        self.binding
    }

    /// The node session that reported this receipt.
    #[must_use]
    pub const fn session(self) -> SessionId {
        self.session
    }

    /// The reported execution outcome.
    #[must_use]
    pub const fn outcome(self) -> TaskExecutionOutcome {
        self.outcome
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskExecutionReceiptWire {
    binding: TaskBinding,
    session: SessionId,
    outcome: TaskExecutionOutcome,
}

/// Expected identity for creating or decoding one task receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskReceiptContext {
    binding: TaskBinding,
    session: SessionId,
}

impl TaskReceiptContext {
    /// Bind the receipt to the exact task attempt and node session.
    #[must_use]
    pub const fn new(binding: TaskBinding, session: SessionId) -> Self {
        Self { binding, session }
    }

    /// The expected task binding.
    #[must_use]
    pub const fn binding(self) -> TaskBinding {
        self.binding
    }

    /// The expected node session.
    #[must_use]
    pub const fn session(self) -> SessionId {
        self.session
    }

    /// Build a receipt for this task attempt and session.
    #[must_use]
    pub const fn receipt(self, outcome: TaskExecutionOutcome) -> TaskExecutionReceipt {
        TaskExecutionReceipt {
            binding: self.binding,
            session: self.session,
            outcome,
        }
    }

    /// Decode a receipt only if its task binding and session match this context.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for malformed data or a mismatched identity.
    pub fn decode(self, json: &str) -> Result<TaskExecutionReceipt, TaskReceiptError> {
        if json.len() > MAX_TASK_RECEIPT_BYTES {
            return Err(TaskReceiptError::MalformedMessage);
        }
        let wire: TaskExecutionReceiptWire =
            serde_json::from_str(json).map_err(|_| TaskReceiptError::MalformedMessage)?;
        if wire.binding != self.binding {
            return Err(TaskReceiptError::BindingMismatch);
        }
        if wire.session != self.session {
            return Err(TaskReceiptError::SessionMismatch);
        }
        Ok(self.receipt(wire.outcome))
    }
}

/// Why an inbound task receipt was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskReceiptError {
    /// The receipt is not valid bounded wire data.
    MalformedMessage,
    /// The task, attempt, or authority lease differs from the expected binding.
    BindingMismatch,
    /// The node session differs from the expected session.
    SessionMismatch,
}

impl Display for TaskReceiptError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedMessage => formatter.write_str("task receipt is invalid"),
            Self::BindingMismatch => formatter.write_str("task receipt binding does not match"),
            Self::SessionMismatch => formatter.write_str("task receipt session does not match"),
        }
    }
}

impl std::error::Error for TaskReceiptError {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use ward_events::{ExecutionAttemptId, LeaseId, SessionId, TaskId};

    use super::*;
    use crate::TaskBinding;

    fn context() -> TaskReceiptContext {
        TaskReceiptContext::new(
            TaskBinding::new(
                TaskId::from_u128(1),
                ExecutionAttemptId::from_u128(2),
                LeaseId::from_u128(3),
            ),
            SessionId::from_u128(4),
        )
    }

    #[test]
    fn receipt_round_trip_preserves_exact_binding_session_and_outcome() {
        let context = context();
        for outcome in [
            TaskExecutionOutcome::Completed,
            TaskExecutionOutcome::Failed,
            TaskExecutionOutcome::Unknown,
        ] {
            let receipt = context.receipt(outcome);
            let json = serde_json::to_string(&receipt).unwrap();
            assert_eq!(context.decode(&json).unwrap(), receipt);
            assert_eq!(receipt.binding(), context.binding());
            assert_eq!(receipt.session(), context.session());
            assert_eq!(receipt.outcome(), outcome);
        }
    }

    #[test]
    fn receipt_decode_rejects_a_different_task_attempt_lease_or_session() {
        let context = context();
        let json =
            serde_json::to_string(&context.receipt(TaskExecutionOutcome::Completed)).unwrap();
        for binding in [
            TaskBinding::new(
                TaskId::from_u128(5),
                context.binding().attempt(),
                context.binding().lease(),
            ),
            TaskBinding::new(
                context.binding().task(),
                ExecutionAttemptId::from_u128(5),
                context.binding().lease(),
            ),
            TaskBinding::new(
                context.binding().task(),
                context.binding().attempt(),
                LeaseId::from_u128(5),
            ),
        ] {
            assert_eq!(
                TaskReceiptContext::new(binding, context.session()).decode(&json),
                Err(TaskReceiptError::BindingMismatch)
            );
        }
        assert_eq!(
            TaskReceiptContext::new(context.binding(), SessionId::from_u128(5)).decode(&json),
            Err(TaskReceiptError::SessionMismatch)
        );
    }

    #[test]
    fn receipt_decode_rejects_unknown_fields_invalid_ids_and_outcomes() {
        let context = context();
        let valid = serde_json::to_value(context.receipt(TaskExecutionOutcome::Completed)).unwrap();
        let mut unknown = valid.clone();
        unknown["raw_response"] = serde_json::json!("unbounded");
        let mut bad_id = valid.clone();
        bad_id["binding"]["task"] = serde_json::json!("other-task");
        let mut bad_outcome = valid;
        bad_outcome["outcome"] = serde_json::json!("possibly_completed");

        for value in [unknown, bad_id, bad_outcome] {
            assert_eq!(
                context.decode(&value.to_string()),
                Err(TaskReceiptError::MalformedMessage)
            );
        }
        assert_eq!(
            context.decode(&" ".repeat(MAX_TASK_RECEIPT_BYTES + 1)),
            Err(TaskReceiptError::MalformedMessage)
        );
    }
}
