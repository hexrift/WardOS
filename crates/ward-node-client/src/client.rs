//! A typed client over the node protocol: handshake (node-integration.md §4), capability
//! discovery (§5), the lifecycle verbs (§6) and the read-only `result` request (§6.6), one
//! connection per request.
//!
//! The client offers the window [`PROTOCOL_WINDOW`]: from the first version with signed
//! admission (1.3) up to the highest version this revision of `ward-node-protocol`
//! implements. [`Client::connect`] negotiates once and refuses, with a typed error, a node
//! that offers nothing in that window or accepts a version below 1.3; every later request
//! must be accepted at exactly the negotiated version. Every answer is decoded strictly by
//! the protocol crate and checked against the request it answers (binding and operation
//! id), so a response for another task or operation is never mistaken for this one.

use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ward_node_protocol::{
    AttemptOutput, CapabilityDiscoveryContext, CapabilityDiscoveryResponse, HandshakeRequest,
    HandshakeResponse, MAX_RESULT_RESPONSE_BYTES, NodeCapabilities, OperationId,
    ProtocolRejectionReason, ProtocolVersion, SupportedProtocolRange, TASK_ADMISSION_PROTOCOL,
    TaskBinding, TaskExecutionOutcome, TaskLifecycleContext, TaskLifecycleRejectionReason,
    TaskLifecycleRequest, TaskLifecycleResponse, TaskLifecycleState, TaskResultResponse,
    WARD_NODE_PROTOCOL, supports_task_admission,
};

use crate::issuer::SignedEnvelope;
use crate::transport::{Exchange, Transport, TransportError};

/// The protocol window this client offers: 1.3 up to the protocol crate's maximum.
pub const PROTOCOL_WINDOW: SupportedProtocolRange = match SupportedProtocolRange::new(
    WARD_NODE_PROTOCOL.major(),
    TASK_ADMISSION_PROTOCOL.minor(),
    WARD_NODE_PROTOCOL.max_minor(),
) {
    Ok(window) => window,
    Err(_) => WARD_NODE_PROTOCOL,
};

/// The protocol window this client offers (see [`PROTOCOL_WINDOW`]).
#[must_use]
pub const fn protocol_window() -> SupportedProtocolRange {
    PROTOCOL_WINDOW
}

/// A node protocol request kind, as the client names it in errors and reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verb {
    /// Capability discovery (§5).
    Capabilities,
    /// `create`.
    Create,
    /// `admit`.
    Admit,
    /// `start`.
    Start,
    /// `pause`.
    Pause,
    /// `resume`.
    Resume,
    /// `stop`.
    Stop,
    /// `revoke`.
    Revoke,
    /// `seal`.
    Seal,
    /// `inspect`.
    Inspect,
    /// `result` (§6.6).
    Result,
}

impl Verb {
    /// The wire spelling of the verb.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capabilities => "capabilities",
            Self::Create => "create",
            Self::Admit => "admit",
            Self::Start => "start",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Stop => "stop",
            Self::Revoke => "revoke",
            Self::Seal => "seal",
            Self::Inspect => "inspect",
            Self::Result => "result",
        }
    }
}

impl Display for Verb {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The node's answer to a mutating verb.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Applied {
    /// The operation took effect, or had already taken effect (a replay, §6.3); `state` is
    /// the task's current state.
    Accepted {
        /// The task's state after the operation.
        state: TaskLifecycleState,
    },
    /// The node refused the operation and changed nothing.
    Rejected {
        /// The typed refusal (§8.3).
        reason: TaskLifecycleRejectionReason,
    },
}

/// The node's answer to `inspect`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Inspection {
    /// The task's current state and, once its attempt has ended, its receipt outcome (§9).
    Inspected {
        /// The task's state.
        state: TaskLifecycleState,
        /// The receipt outcome of an `exited`, `stopped`, `revoked` or `sealed` task.
        outcome: Option<TaskExecutionOutcome>,
    },
    /// The node refused the inspection.
    Rejected {
        /// The typed refusal (§8.3).
        reason: TaskLifecycleRejectionReason,
    },
}

/// The node's answer to `result` (§6.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resulted {
    /// The ended attempt's bounded output, with the state it was read in.
    Result {
        /// The task's state: `exited`, `stopped`, `revoked` or `sealed`.
        state: TaskLifecycleState,
        /// The output.
        output: AttemptOutput,
    },
    /// The node refused the request.
    Rejected {
        /// The typed refusal (§8.3).
        reason: TaskLifecycleRejectionReason,
    },
}

/// Why a request did not get a usable answer. Every case fails closed.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The connection failed or was closed outside the protocol.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The handshake answer was not a handshake response.
    #[error("the node's handshake answer is malformed")]
    MalformedHandshake,
    /// The node offers no version in the client's window (§4).
    #[error("the node rejected the handshake ({reason:?}); it supports {}.{}-{}.{}", supported.major(), supported.min_minor(), supported.major(), supported.max_minor())]
    HandshakeRejected {
        /// The node's stable rejection reason.
        reason: ProtocolRejectionReason,
        /// The window the node serves.
        supported: SupportedProtocolRange,
    },
    /// The node accepted a version without signed admission.
    #[error("the node accepted protocol {}.{}, below the 1.3 this client needs", accepted.major(), accepted.minor())]
    ProtocolTooOld {
        /// The version the node accepted.
        accepted: ProtocolVersion,
    },
    /// The node accepted a version this client does not implement.
    #[error("the node accepted protocol {}.{}, which this client does not implement", accepted.major(), accepted.minor())]
    ProtocolUnsupported {
        /// The version the node accepted.
        accepted: ProtocolVersion,
    },
    /// A later connection negotiated another version than the first.
    #[error("the node negotiated protocol {}.{} after {}.{} was agreed", accepted.major(), accepted.minor(), expected.major(), expected.minor())]
    ProtocolChanged {
        /// The version negotiated at connect time.
        expected: ProtocolVersion,
        /// The version this connection was accepted at.
        accepted: ProtocolVersion,
    },
    /// The node closed the connection without answering: the request was malformed or
    /// too slow, and a mutating verb may still have taken effect (§10).
    #[error(
        "the node closed the connection without answering `{verb}`: unknown whether it took effect"
    )]
    NoResponse {
        /// The request that got no answer.
        verb: Verb,
    },
    /// The answer line did not decode as a response at the negotiated version.
    #[error("the node's answer to `{verb}` is malformed")]
    MalformedResponse {
        /// The request the answer was for.
        verb: Verb,
    },
    /// The answer names another binding, operation or response kind than the request.
    #[error("the node's answer to `{verb}` does not match the request")]
    ResponseMismatch {
        /// The request the answer was for.
        verb: Verb,
    },
    /// A request could not be encoded.
    #[error("a node request could not be encoded")]
    Encoding,
}

/// A connected node client bound to one negotiated protocol version.
#[derive(Debug)]
pub struct Client<T: Transport> {
    transport: T,
    hello: String,
    negotiated: ProtocolVersion,
    lifecycle: TaskLifecycleContext,
    discovery: CapabilityDiscoveryContext,
}

impl<T: Transport> Client<T> {
    /// Negotiate the protocol with the node behind `transport`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::HandshakeRejected`] when the node offers nothing in
    /// [`PROTOCOL_WINDOW`], [`ClientError::ProtocolTooOld`] when it accepts a version
    /// below 1.3, and a transport error when it cannot be reached.
    pub fn connect(transport: T) -> Result<Self, ClientError> {
        let hello = serde_json::to_string(&HandshakeRequest::Hello {
            protocol: PROTOCOL_WINDOW,
        })
        .map_err(|_| ClientError::Encoding)?;
        let negotiated = accepted_version(&transport.handshake(&hello)?)?;
        let lifecycle = TaskLifecycleContext::new(negotiated).map_err(|_| {
            ClientError::ProtocolUnsupported {
                accepted: negotiated,
            }
        })?;
        let discovery = CapabilityDiscoveryContext::new(negotiated).map_err(|_| {
            ClientError::ProtocolUnsupported {
                accepted: negotiated,
            }
        })?;
        Ok(Self {
            transport,
            hello,
            negotiated,
            lifecycle,
            discovery,
        })
    }

    /// The negotiated protocol version.
    #[must_use]
    pub const fn protocol(&self) -> ProtocolVersion {
        self.negotiated
    }

    /// The transport this client speaks over.
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Give the transport back.
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Read the node's capability document (§5).
    ///
    /// # Errors
    ///
    /// Returns a [`ClientError`] when the node cannot be reached or answers outside the
    /// protocol.
    pub fn capabilities(&self) -> Result<NodeCapabilities, ClientError> {
        let request =
            serde_json::to_string(&self.discovery.request()).map_err(|_| ClientError::Encoding)?;
        let response = self.send(Verb::Capabilities, &request)?;
        match self.discovery.decode_response(&response) {
            Ok(CapabilityDiscoveryResponse::Capabilities { capabilities }) => Ok(capabilities),
            Err(_) => Err(ClientError::MalformedResponse {
                verb: Verb::Capabilities,
            }),
        }
    }

    /// `create` the binding (§6.1).
    ///
    /// # Errors
    ///
    /// Returns a [`ClientError`] when the node cannot be reached or answers outside the
    /// protocol; a typed refusal is `Ok(Applied::Rejected)`.
    pub fn create(
        &self,
        binding: TaskBinding,
        operation: OperationId,
    ) -> Result<Applied, ClientError> {
        self.mutate(
            Verb::Create,
            binding,
            operation,
            &self.lifecycle.create(operation, binding),
        )
    }

    /// `admit` the signed envelope (§6.1, §7), sending exactly the bytes that were signed.
    ///
    /// # Errors
    ///
    /// Returns a [`ClientError`] when the node cannot be reached or answers outside the
    /// protocol; a typed refusal is `Ok(Applied::Rejected)`.
    pub fn admit(
        &self,
        binding: TaskBinding,
        operation: OperationId,
        envelope: &SignedEnvelope,
    ) -> Result<Applied, ClientError> {
        let request = self
            .lifecycle
            .admit(
                operation,
                binding,
                envelope.envelope_json.clone(),
                envelope.proof,
            )
            .map_err(|_| ClientError::Encoding)?;
        self.mutate(Verb::Admit, binding, operation, &request)
    }

    /// `start` the admitted attempt (§6.1).
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub fn start(
        &self,
        binding: TaskBinding,
        operation: OperationId,
    ) -> Result<Applied, ClientError> {
        self.mutate(
            Verb::Start,
            binding,
            operation,
            &self.lifecycle.start(operation, binding),
        )
    }

    /// `pause` the running attempt (§6.1).
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub fn pause(
        &self,
        binding: TaskBinding,
        operation: OperationId,
    ) -> Result<Applied, ClientError> {
        self.mutate(
            Verb::Pause,
            binding,
            operation,
            &self.lifecycle.pause(operation, binding),
        )
    }

    /// `resume` the paused attempt (§6.1).
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub fn resume(
        &self,
        binding: TaskBinding,
        operation: OperationId,
    ) -> Result<Applied, ClientError> {
        self.mutate(
            Verb::Resume,
            binding,
            operation,
            &self.lifecycle.resume(operation, binding),
        )
    }

    /// `stop` the attempt (§6.1).
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub fn stop(
        &self,
        binding: TaskBinding,
        operation: OperationId,
    ) -> Result<Applied, ClientError> {
        self.mutate(
            Verb::Stop,
            binding,
            operation,
            &self.lifecycle.stop(operation, binding),
        )
    }

    /// `revoke` the attempt's lease and end it (§6.1).
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub fn revoke(
        &self,
        binding: TaskBinding,
        operation: OperationId,
    ) -> Result<Applied, ClientError> {
        self.mutate(
            Verb::Revoke,
            binding,
            operation,
            &self.lifecycle.revoke(operation, binding),
        )
    }

    /// `seal` the ended attempt (§6.1).
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub fn seal(
        &self,
        binding: TaskBinding,
        operation: OperationId,
    ) -> Result<Applied, ClientError> {
        self.mutate(
            Verb::Seal,
            binding,
            operation,
            &self.lifecycle.seal(operation, binding),
        )
    }

    /// `inspect` the task (§6.1, §9).
    ///
    /// # Errors
    ///
    /// Returns a [`ClientError`] when the node cannot be reached or answers outside the
    /// protocol; a typed refusal is `Ok(Inspection::Rejected)`.
    pub fn inspect(&self, binding: TaskBinding) -> Result<Inspection, ClientError> {
        let request = serde_json::to_string(&self.lifecycle.inspect(binding))
            .map_err(|_| ClientError::Encoding)?;
        let response = self.send(Verb::Inspect, &request)?;
        match self.lifecycle.decode_response(&response) {
            Ok(TaskLifecycleResponse::Inspected {
                binding: answered,
                state,
                outcome,
                ..
            }) if answered == binding => Ok(Inspection::Inspected { state, outcome }),
            Ok(TaskLifecycleResponse::Rejected {
                operation_id: None,
                binding: answered,
                reason,
                ..
            }) if answered == binding => Ok(Inspection::Rejected { reason }),
            Ok(_) => Err(ClientError::ResponseMismatch {
                verb: Verb::Inspect,
            }),
            Err(_) => Err(ClientError::MalformedResponse {
                verb: Verb::Inspect,
            }),
        }
    }

    /// `result`: the bounded output of an ended attempt admitted with an `output` grant
    /// (§6.6), read within `MAX_RESULT_RESPONSE_BYTES` rather than the lifecycle line bound.
    ///
    /// # Errors
    ///
    /// Returns a [`ClientError`] when the node cannot be reached or answers outside the
    /// protocol; a typed refusal is `Ok(Resulted::Rejected)`.
    pub fn result(&self, binding: TaskBinding) -> Result<Resulted, ClientError> {
        let request = self
            .lifecycle
            .result(binding)
            .map_err(|_| ClientError::Encoding)?;
        let request = serde_json::to_string(&request).map_err(|_| ClientError::Encoding)?;
        let response = self.send_bounded(Verb::Result, &request, MAX_RESULT_RESPONSE_BYTES)?;
        match self.lifecycle.decode_result_response(&response) {
            Ok(TaskResultResponse::Result {
                binding: answered,
                state,
                output,
                ..
            }) if answered == binding => Ok(Resulted::Result { state, output }),
            Ok(TaskResultResponse::Rejected {
                binding: answered,
                reason,
                ..
            }) if answered == binding => Ok(Resulted::Rejected { reason }),
            Ok(_) => Err(ClientError::ResponseMismatch { verb: Verb::Result }),
            Err(_) => Err(ClientError::MalformedResponse { verb: Verb::Result }),
        }
    }

    fn mutate(
        &self,
        verb: Verb,
        binding: TaskBinding,
        operation: OperationId,
        request: &TaskLifecycleRequest,
    ) -> Result<Applied, ClientError> {
        let request = serde_json::to_string(request).map_err(|_| ClientError::Encoding)?;
        let response = self.send(verb, &request)?;
        match self.lifecycle.decode_response(&response) {
            Ok(TaskLifecycleResponse::Accepted {
                operation_id,
                binding: answered,
                state,
                ..
            }) if operation_id == operation && answered == binding => {
                Ok(Applied::Accepted { state })
            }
            Ok(TaskLifecycleResponse::Rejected {
                operation_id: Some(operation_id),
                binding: answered,
                reason,
                ..
            }) if operation_id == operation && answered == binding => {
                Ok(Applied::Rejected { reason })
            }
            Ok(_) => Err(ClientError::ResponseMismatch { verb }),
            Err(_) => Err(ClientError::MalformedResponse { verb }),
        }
    }

    fn send(&self, verb: Verb, request: &str) -> Result<String, ClientError> {
        self.send_bounded(verb, request, crate::transport::MAX_LINE_BYTES)
    }

    fn send_bounded(
        &self,
        verb: Verb,
        request: &str,
        response_bound: usize,
    ) -> Result<String, ClientError> {
        let Exchange {
            handshake,
            response,
        } = self
            .transport
            .exchange_with_response_bound(&self.hello, request, response_bound)?;
        let accepted = accepted_version(&handshake)?;
        if accepted != self.negotiated {
            return Err(ClientError::ProtocolChanged {
                expected: self.negotiated,
                accepted,
            });
        }
        response.ok_or(ClientError::NoResponse { verb })
    }
}

fn accepted_version(handshake: &str) -> Result<ProtocolVersion, ClientError> {
    match serde_json::from_str::<HandshakeResponse>(handshake) {
        Ok(HandshakeResponse::Accepted { protocol }) => {
            if supports_task_admission(protocol) {
                Ok(protocol)
            } else {
                Err(ClientError::ProtocolTooOld { accepted: protocol })
            }
        }
        Ok(HandshakeResponse::Rejected { reason, supported }) => {
            Err(ClientError::HandshakeRejected { reason, supported })
        }
        Err(_) => Err(ClientError::MalformedHandshake),
    }
}
