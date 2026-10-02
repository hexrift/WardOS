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
    }
}
