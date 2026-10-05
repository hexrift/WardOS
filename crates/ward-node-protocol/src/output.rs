//! Bounded result return (#332 stage 2, the result half): the `output` grant of the
//! capability manifest, the `output` section of the capability document, and the
//! read-only `result` request that returns an ended attempt's captured stdout, stderr
//! and declared workspace files.
//!
//! Everything here is additive within protocol 1.3. A manifest without `output` and a
//! capability document of a node that returns no output are byte for byte what they
//! were; a node that does not honour the grant refuses it `unsupported_grant` at `admit`,
//! and a node of an earlier revision fails to decode a manifest that carries it
//! (`authority_denied`), so no node ever runs a workload whose output it will not return.
//!
//! Content travels as standard base64 with padding (`content_base64`); every count is a
//! byte count; digests are `BLAKE3-256` as lowercase hex. The grammar bounds what a
//! manifest may ask for; the node's ceilings ([`MAX_OUTPUT_STDIO_BYTES`],
//! [`MAX_OUTPUT_FILES_BYTES`]) bound what it honours.

use std::fmt::{Display, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ward_events::Blake3Hash;

use crate::{
    OperationId, ProtocolVersion, TaskBinding, TaskLifecycleContext, TaskLifecycleError,
    TaskLifecycleRejectionReason, TaskLifecycleState, supports_task_admission,
};

/// Ceiling on the bytes of each of stdout and stderr a node returns: a manifest asking
/// for more is refused `unsupported_grant`.
pub const MAX_OUTPUT_STDIO_BYTES: u64 = 1024 * 1024;

/// Ceiling on the bytes of file content a node returns inline across every declared
/// file: a manifest asking for more is refused `unsupported_grant`.
pub const MAX_OUTPUT_FILES_BYTES: u64 = 8 * 1024 * 1024;

/// Maximum number of files one manifest may declare (a grammar bound).
pub const MAX_OUTPUT_FILES: usize = 64;

/// Maximum bytes of one declared file path (a grammar bound).
pub const MAX_OUTPUT_PATH_BYTES: usize = 255;

/// A declared file larger than this is neither returned nor digested: the node reports
/// it `too_large` with its size, so a workload cannot make the node hash without bound.
pub const MAX_OUTPUT_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Upper bound on one `result` response line: every ceiling above, base64-encoded, with
/// room for the metadata.
pub const MAX_RESULT_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Why an output grant or a result document is outside the grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputError {
    /// The manifest declares more than [`MAX_OUTPUT_FILES`] files.
    TooManyFiles,
    /// A declared path is empty, absolute, has a `.` or `..` or empty component, a byte
    /// outside `a-z A-Z 0-9 . _ - /`, or more than [`MAX_OUTPUT_PATH_BYTES`] bytes.
    InvalidPath,
    /// The same path is declared twice.
    DuplicatePath,
    /// A result document's counts, flags, digests or content do not agree, or exceed the
    /// ceilings.
    MalformedResult,
}

impl Display for OutputError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::TooManyFiles => "output grant declares too many files",
            Self::InvalidPath => "output grant path is invalid",
            Self::DuplicatePath => "output grant path is repeated",
            Self::MalformedResult => "result document is invalid",
        })
    }
}

impl std::error::Error for OutputError {}

/// One declared workspace path: relative to the workspace root, in the grammar of
/// [`OutputError::InvalidPath`], so a signed path has one spelling and never names a
/// parent, the root or anything outside the workspace.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct OutputPath(String);

impl OutputPath {
    /// Validate a declared path.
    ///
    /// # Errors
    ///
    /// Returns [`OutputError::InvalidPath`] for anything outside the grammar.
    pub fn new(path: impl Into<String>) -> Result<Self, OutputError> {
        let path = path.into();
        if path.is_empty() || path.len() > MAX_OUTPUT_PATH_BYTES {
            return Err(OutputError::InvalidPath);
        }
        let allowed = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-');
        for component in path.split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return Err(OutputError::InvalidPath);
            }
            if !component.bytes().all(allowed) {
                return Err(OutputError::InvalidPath);
            }
        }
        Ok(Self(path))
    }

    /// The path as declared.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for OutputPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// The `output` grant of a capability manifest: what of the attempt's output the
/// control plane asks the node to return.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OutputGrant {
    stdio_bytes: u64,
    files: Vec<OutputPath>,
    files_bytes: u64,
}

impl OutputGrant {
    /// A grant of the first `stdio_bytes` bytes of each of stdout and stderr, and of the
    /// declared `files` up to `files_bytes` of content in all.
    ///
    /// # Errors
    ///
    /// Returns [`OutputError::TooManyFiles`] past [`MAX_OUTPUT_FILES`] and
    /// [`OutputError::DuplicatePath`] for a path declared twice.
    pub fn new(
        stdio_bytes: u64,
        files: Vec<OutputPath>,
        files_bytes: u64,
    ) -> Result<Self, OutputError> {
        if files.len() > MAX_OUTPUT_FILES {
            return Err(OutputError::TooManyFiles);
        }
        for (index, path) in files.iter().enumerate() {
            if files[..index].contains(path) {
                return Err(OutputError::DuplicatePath);
            }
        }
        Ok(Self {
            stdio_bytes,
            files,
            files_bytes,
        })
    }

    /// Bytes of each stream to return, head first.
    #[must_use]
    pub const fn stdio_bytes(&self) -> u64 {
        self.stdio_bytes
    }

    /// The declared files, in the order given.
    #[must_use]
    pub fn files(&self) -> &[OutputPath] {
        &self.files
    }

    /// Bytes of file content to return inline, across every file.
    #[must_use]
    pub const fn files_bytes(&self) -> u64 {
        self.files_bytes
    }

    /// Whether a node whose ceilings are [`MAX_OUTPUT_STDIO_BYTES`] and
    /// [`MAX_OUTPUT_FILES_BYTES`] can honour this grant.
    #[must_use]
    pub const fn within_ceilings(&self) -> bool {
        self.stdio_bytes <= MAX_OUTPUT_STDIO_BYTES && self.files_bytes <= MAX_OUTPUT_FILES_BYTES
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutputGrantWire {
    stdio_bytes: u64,
    files: Vec<OutputPath>,
    files_bytes: u64,
}

impl TryFrom<OutputGrantWire> for OutputGrant {
    type Error = OutputError;

    fn try_from(wire: OutputGrantWire) -> Result<Self, OutputError> {
        Self::new(wire.stdio_bytes, wire.files, wire.files_bytes)
    }
}

/// What of an attempt's output a node returns (the `output` section of the capability
/// document). Absent from the document when both are `false`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputCapabilities {
    /// The node returns the workload's stdout and stderr up to the granted budget.
    pub stdio: bool,
    /// The node returns declared workspace files up to the granted budget.
    pub files: bool,
}

impl OutputCapabilities {
    /// Nothing is returned.
    pub const NONE: Self = Self {
        stdio: false,
        files: false,
    };

    /// Whether anything is returned.
    #[must_use]
    pub const fn any(self) -> bool {
        self.stdio || self.files
    }
}

/// One captured stream: the head the node kept and how many bytes it dropped past it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutputStream {
    content: Vec<u8>,
    dropped: u64,
}

impl OutputStream {
    /// The first `content.len()` bytes of the stream, with `dropped` bytes not returned.
    ///
    /// # Errors
    ///
    /// Returns [`OutputError::MalformedResult`] when the content exceeds
    /// [`MAX_OUTPUT_STDIO_BYTES`].
    pub fn new(content: Vec<u8>, dropped: u64) -> Result<Self, OutputError> {
        if u64::try_from(content.len()).is_ok_and(|len| len <= MAX_OUTPUT_STDIO_BYTES) {
            Ok(Self { content, dropped })
        } else {
            Err(OutputError::MalformedResult)
        }
    }

    /// The returned bytes.
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// Bytes the workload wrote past the returned head.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Whether anything was dropped.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.dropped > 0
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputStreamWire {
    bytes: u64,
    truncated: bool,
    dropped: u64,
    content_base64: String,
}

impl Serialize for OutputStream {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        OutputStreamWire {
            bytes: self.content.len() as u64,
            truncated: self.truncated(),
            dropped: self.dropped,
            content_base64: base64::encode(&self.content),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OutputStream {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = OutputStreamWire::deserialize(deserializer)?;
        let content = base64::decode(&wire.content_base64)
            .ok_or_else(|| D::Error::custom(OutputError::MalformedResult))?;
        if wire.bytes != content.len() as u64 || wire.truncated != (wire.dropped > 0) {
            return Err(D::Error::custom(OutputError::MalformedResult));
        }
        Self::new(content, wire.dropped).map_err(D::Error::custom)
    }
}

/// Why a declared file was not returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFileSkip {
    /// The workspace has no such path.
    Missing,
    /// The path is a symlink, a directory or another non-regular file; nothing was
    /// followed or read.
    NotARegularFile,
    /// The file is larger than [`MAX_OUTPUT_FILE_BYTES`]; it was neither read nor digested.
    TooLarge,
}

/// What the node found at a declared path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputFileStatus {
    /// The file, returned whole: its size, `BLAKE3-256` digest and content.
    Returned {
        /// The file's size, equal to the content's length.
        size: u64,
        /// `BLAKE3-256` of the content.
        digest: Blake3Hash,
        /// The content.
        content: Vec<u8>,
    },
    /// The file did not fit the remaining content budget: its size and digest only.
    DigestOnly {
        /// The file's size.
        size: u64,
        /// `BLAKE3-256` of the file.
        digest: Blake3Hash,
    },
    /// Not returned, and why.
    Skipped(OutputFileSkip),
}

/// One declared file as the node reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputFile {
    /// The path as declared.
    pub path: OutputPath,
    /// What was found there.
    pub status: OutputFileStatus,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputFileWire {
    path: OutputPath,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    digest: Option<Blake3Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    truncated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    skipped: Option<OutputFileSkip>,
}

impl Serialize for OutputFile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let path = self.path.clone();
        let wire = match &self.status {
            OutputFileStatus::Returned {
                size,
                digest,
                content,
            } => OutputFileWire {
                path,
                size: Some(*size),
                digest: Some(*digest),
                truncated: Some(false),
                content_base64: Some(base64::encode(content)),
                skipped: None,
            },
            OutputFileStatus::DigestOnly { size, digest } => OutputFileWire {
                path,
                size: Some(*size),
                digest: Some(*digest),
                truncated: Some(true),
                content_base64: None,
                skipped: None,
            },
            OutputFileStatus::Skipped(skip) => OutputFileWire {
                path,
                size: None,
                digest: None,
                truncated: None,
                content_base64: None,
                skipped: Some(*skip),
            },
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OutputFile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = OutputFileWire::deserialize(deserializer)?;
        let malformed = || D::Error::custom(OutputError::MalformedResult);
        let status = match (
            wire.size,
            wire.digest,
            wire.truncated,
            wire.content_base64,
            wire.skipped,
        ) {
            (Some(size), Some(digest), Some(false), Some(content), None) => {
                let content = base64::decode(&content).ok_or_else(malformed)?;
                if size != content.len() as u64 || size > MAX_OUTPUT_FILES_BYTES {
                    return Err(malformed());
                }
                OutputFileStatus::Returned {
                    size,
                    digest,
                    content,
                }
            }
            (Some(size), Some(digest), Some(true), None, None) => {
                OutputFileStatus::DigestOnly { size, digest }
            }
            (None, None, None, None, Some(skip)) => OutputFileStatus::Skipped(skip),
            _ => return Err(malformed()),
        };
        Ok(Self {
            path: wire.path,
            status,
        })
    }
}

/// The bounded result of an ended attempt, as `result` returns it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct AttemptOutput {
    stdout: OutputStream,
    stderr: OutputStream,
    files: Vec<OutputFile>,
}

impl AttemptOutput {
    /// A result of the two streams and the declared files, in declaration order.
    ///
    /// # Errors
    ///
    /// Returns [`OutputError::TooManyFiles`] past [`MAX_OUTPUT_FILES`],
    /// [`OutputError::DuplicatePath`] for a repeated path and
    /// [`OutputError::MalformedResult`] when the returned content exceeds
    /// [`MAX_OUTPUT_FILES_BYTES`] in all.
    pub fn new(
        stdout: OutputStream,
        stderr: OutputStream,
        files: Vec<OutputFile>,
    ) -> Result<Self, OutputError> {
        if files.len() > MAX_OUTPUT_FILES {
            return Err(OutputError::TooManyFiles);
        }
        let mut inline: u64 = 0;
        for (index, file) in files.iter().enumerate() {
            if files[..index].iter().any(|other| other.path == file.path) {
                return Err(OutputError::DuplicatePath);
            }
            if let OutputFileStatus::Returned { content, .. } = &file.status {
                inline = inline.saturating_add(content.len() as u64);
            }
        }
        if inline > MAX_OUTPUT_FILES_BYTES {
            return Err(OutputError::MalformedResult);
        }
        Ok(Self {
            stdout,
            stderr,
            files,
        })
    }

    /// The captured stdout.
    #[must_use]
    pub const fn stdout(&self) -> &OutputStream {
        &self.stdout
    }

    /// The captured stderr.
    #[must_use]
    pub const fn stderr(&self) -> &OutputStream {
        &self.stderr
    }

    /// The declared files, in declaration order.
    #[must_use]
    pub fn files(&self) -> &[OutputFile] {
        &self.files
    }

    /// Whether a stream was truncated or a file returned digest-only.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.stdout.truncated()
            || self.stderr.truncated()
            || self
                .files
                .iter()
                .any(|file| matches!(file.status, OutputFileStatus::DigestOnly { .. }))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptOutputWire {
    stdout: OutputStream,
    stderr: OutputStream,
    files: Vec<OutputFile>,
}

impl<'de> Deserialize<'de> for AttemptOutput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AttemptOutputWire::deserialize(deserializer)?;
        Self::new(wire.stdout, wire.stderr, wire.files).map_err(D::Error::custom)
    }
}

/// The read-only `result` request: the bounded output of an ended attempt. Protocol 1.3
/// and later; built and decoded through [`TaskLifecycleContext`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum TaskResultRequest {
    /// Return the attempt's captured output.
    Result {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// The task/attempt/lease this request applies to.
        binding: TaskBinding,
    },
}

#[derive(Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
enum TaskResultRequestWire {
    Result {
        protocol: ProtocolVersion,
        binding: TaskBinding,
    },
}

/// The answer to `result`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskResultResponse {
    /// The attempt's bounded output, with the state it was read in.
    Result {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// The task/attempt/lease this response applies to.
        binding: TaskBinding,
        /// The task's current state: `exited`, `stopped`, `revoked` or `sealed`.
        state: TaskLifecycleState,
        /// The output.
        output: AttemptOutput,
    },
    /// The request was refused; spelled exactly as a lifecycle refusal, with a `null`
    /// operation id.
    Rejected {
        /// The negotiated protocol version this message is bound to.
        protocol: ProtocolVersion,
        /// The task/attempt/lease this response applies to.
        binding: TaskBinding,
        /// Why.
        reason: TaskLifecycleRejectionReason,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case", deny_unknown_fields)]
enum TaskResultResponseWire {
    Result {
        protocol: ProtocolVersion,
        binding: TaskBinding,
        state: TaskLifecycleState,
        output: AttemptOutput,
    },
    Rejected {
        protocol: ProtocolVersion,
        operation_id: Option<OperationId>,
        binding: TaskBinding,
        reason: TaskLifecycleRejectionReason,
    },
}

impl Serialize for TaskResultResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let wire = match self {
            Self::Result {
                protocol,
                binding,
                state,
                output,
            } => {
                if !supports_result(*protocol, *state) {
                    return Err(serde::ser::Error::custom(
                        TaskLifecycleError::UnsupportedByProtocol,
                    ));
                }
                TaskResultResponseWire::Result {
                    protocol: *protocol,
                    binding: *binding,
                    state: *state,
                    output: output.clone(),
                }
            }
            Self::Rejected {
                protocol,
                binding,
                reason,
            } => TaskResultResponseWire::Rejected {
                protocol: *protocol,
                operation_id: None,
                binding: *binding,
                reason: *reason,
            },
        };
        wire.serialize(serializer)
    }
}

/// Whether a `result` at `protocol` may carry output for a task in `state`: at 1.3 and
/// later, for an ended task.
const fn supports_result(protocol: ProtocolVersion, state: TaskLifecycleState) -> bool {
    supports_task_admission(protocol)
        && matches!(
            state,
            TaskLifecycleState::Exited
                | TaskLifecycleState::Stopped
                | TaskLifecycleState::Revoked
                | TaskLifecycleState::Sealed
        )
}

impl TaskLifecycleContext {
    /// Build a [`TaskResultRequest`] bound to this context's protocol.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleError::UnsupportedByProtocol`] before protocol 1.3.
    pub const fn result(
        self,
        binding: TaskBinding,
    ) -> Result<TaskResultRequest, TaskLifecycleError> {
        if !supports_task_admission(self.protocol()) {
            return Err(TaskLifecycleError::UnsupportedByProtocol);
        }
        Ok(TaskResultRequest::Result {
            protocol: self.protocol(),
            binding,
        })
    }

    /// Decode a wire-format `result` request bound to this context's exact protocol.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleError::MalformedMessage`] if `json` is not a `result`
    /// request or the context predates 1.3, and
    /// [`TaskLifecycleError::ProtocolMismatch`] if it names another protocol version.
    pub fn decode_result_request(
        self,
        json: &str,
    ) -> Result<TaskResultRequest, TaskLifecycleError> {
        if !supports_task_admission(self.protocol()) {
            return Err(TaskLifecycleError::MalformedMessage);
        }
        let TaskResultRequestWire::Result { protocol, binding } =
            serde_json::from_str::<TaskResultRequestWire>(json)
                .map_err(|_| TaskLifecycleError::MalformedMessage)?;
        if protocol != self.protocol() {
            return Err(TaskLifecycleError::ProtocolMismatch);
        }
        Ok(TaskResultRequest::Result { protocol, binding })
    }

    /// Build a [`TaskResultResponse::Result`] bound to this context's protocol.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleError::UnsupportedByProtocol`] before protocol 1.3, or for
    /// a state that has not ended.
    pub fn result_response(
        self,
        binding: TaskBinding,
        state: TaskLifecycleState,
        output: AttemptOutput,
    ) -> Result<TaskResultResponse, TaskLifecycleError> {
        if !supports_result(self.protocol(), state) {
            return Err(TaskLifecycleError::UnsupportedByProtocol);
        }
        Ok(TaskResultResponse::Result {
            protocol: self.protocol(),
            binding,
            state,
            output,
        })
    }

    /// Build a [`TaskResultResponse::Rejected`] bound to this context's protocol.
    #[must_use]
    pub const fn result_rejected(
        self,
        binding: TaskBinding,
        reason: TaskLifecycleRejectionReason,
    ) -> TaskResultResponse {
        TaskResultResponse::Rejected {
            protocol: self.protocol(),
            binding,
            reason,
        }
    }

    /// Decode a wire-format `result` response bound to this context's exact protocol.
    ///
    /// # Errors
    ///
    /// Returns [`TaskLifecycleError::MalformedMessage`] if `json` does not decode, carries
    /// output for a state that has not ended, or the context predates 1.3, and
    /// [`TaskLifecycleError::ProtocolMismatch`] if it names another protocol version.
    pub fn decode_result_response(
        self,
        json: &str,
    ) -> Result<TaskResultResponse, TaskLifecycleError> {
        if !supports_task_admission(self.protocol()) {
            return Err(TaskLifecycleError::MalformedMessage);
        }
        let wire = serde_json::from_str::<TaskResultResponseWire>(json)
            .map_err(|_| TaskLifecycleError::MalformedMessage)?;
        let response = match wire {
            TaskResultResponseWire::Result {
                protocol,
                binding,
                state,
                output,
            } => {
                if !supports_result(protocol, state) {
                    return Err(TaskLifecycleError::MalformedMessage);
                }
                TaskResultResponse::Result {
                    protocol,
                    binding,
                    state,
                    output,
                }
            }
            TaskResultResponseWire::Rejected {
                protocol,
                operation_id: None,
                binding,
                reason,
            } => TaskResultResponse::Rejected {
                protocol,
                binding,
                reason,
            },
            TaskResultResponseWire::Rejected {
                operation_id: Some(_),
                ..
            } => return Err(TaskLifecycleError::MalformedMessage),
        };
        let protocol = match response {
            TaskResultResponse::Result { protocol, .. }
            | TaskResultResponse::Rejected { protocol, .. } => protocol,
        };
        if protocol != self.protocol() {
            return Err(TaskLifecycleError::ProtocolMismatch);
        }
        Ok(response)
    }
}

/// Standard base64 (RFC 4648 §4) with padding, strict on decode: no whitespace, no
/// missing padding, no non-canonical trailing bits.
pub mod base64 {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Encode `bytes`.
    #[must_use]
    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let word = chunk.iter().enumerate().fold(0u32, |word, (index, byte)| {
                word | u32::from(*byte) << (16 - 8 * index)
            });
            let digits = chunk.len() + 1;
            for index in 0..4 {
                if index < digits {
                    let sextet = ((word >> (18 - 6 * index)) & 0x3f) as usize;
                    out.push(char::from(ALPHABET[sextet]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    const fn value(digit: u8) -> Option<u32> {
        match digit {
            b'A'..=b'Z' => Some((digit - b'A') as u32),
            b'a'..=b'z' => Some((digit - b'a') as u32 + 26),
            b'0'..=b'9' => Some((digit - b'0') as u32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    /// Decode `text`; `None` for anything that is not the canonical encoding of some bytes.
    #[must_use]
    pub fn decode(text: &str) -> Option<Vec<u8>> {
        let bytes = text.as_bytes();
        if !bytes.len().is_multiple_of(4) {
            return None;
        }
        let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
        for (index, quad) in bytes.chunks(4).enumerate() {
            let last = index + 1 == bytes.len() / 4;
            let padding = quad
                .iter()
                .rev()
                .take_while(|digit| **digit == b'=')
                .count();
            if padding > 2 || (padding > 0 && !last) {
                return None;
            }
            let mut word = 0u32;
            for digit in &quad[..4 - padding] {
                word = word << 6 | value(*digit)?;
            }
            word <<= 6 * u32::try_from(padding).ok()?;
            let kept = 3 - padding;
            let decoded = word.to_be_bytes();
            if decoded[1 + kept..].iter().any(|byte| *byte != 0) {
                return None;
            }
            out.extend_from_slice(&decoded[1..=kept]);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use ward_events::{ExecutionAttemptId, LeaseId, TaskId};

    use super::*;
    use crate::{CapabilityManifest, CapabilityManifestBytes, NetworkGrant, TaskAdmissionError};

    fn binding() -> TaskBinding {
        TaskBinding::new(
            TaskId::from_u128(7),
            ExecutionAttemptId::from_u128(8),
            LeaseId::from_u128(9),
        )
    }

    fn one_three() -> TaskLifecycleContext {
        TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
    }

    fn one_two() -> TaskLifecycleContext {
        TaskLifecycleContext::new(ProtocolVersion::new(1, 2)).unwrap()
    }

    fn grant() -> OutputGrant {
        OutputGrant::new(
            4096,
            vec![
                OutputPath::new("out/report.json").unwrap(),
                OutputPath::new("big.bin").unwrap(),
            ],
            2048,
        )
        .unwrap()
    }

    fn output() -> AttemptOutput {
        AttemptOutput::new(
            OutputStream::new(b"hello\n".to_vec(), 0).unwrap(),
            OutputStream::new(b"warn".to_vec(), 12).unwrap(),
            vec![
                OutputFile {
                    path: OutputPath::new("out/report.json").unwrap(),
                    status: OutputFileStatus::Returned {
                        size: 2,
                        digest: Blake3Hash::hash(b"{}"),
                        content: b"{}".to_vec(),
                    },
                },
                OutputFile {
                    path: OutputPath::new("big.bin").unwrap(),
                    status: OutputFileStatus::DigestOnly {
                        size: 3000,
                        digest: Blake3Hash::hash(b"big"),
                    },
                },
                OutputFile {
                    path: OutputPath::new("missing.txt").unwrap(),
                    status: OutputFileStatus::Skipped(OutputFileSkip::Missing),
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn base64_matches_rfc_4648_vectors_and_decodes_strictly() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64::encode(plain.as_bytes()), encoded);
            assert_eq!(base64::decode(encoded).unwrap(), plain.as_bytes());
        }
        assert_eq!(base64::encode(&[0xff, 0x00, 0xfe]), "/wD+");
        assert_eq!(base64::decode("/wD+").unwrap(), [0xff, 0x00, 0xfe]);
        for bad in [
            "Zg", "Zg=", "Zg===", "Zm=v", "Zh==", "Zg==Zg==", "Zm 9v", "Zm9v\n", "!!!!",
        ] {
            assert_eq!(base64::decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn output_paths_are_relative_single_spelling_and_never_escape() {
        for ok in ["a", "out/report.json", "a/b/c-d_e.f", "A.B", "1"] {
            assert_eq!(OutputPath::new(ok).unwrap().as_str(), ok);
        }
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "./a",
            "a/.",
            "a//b",
            "a/",
            "a b",
            "a\\b",
            "a\0b",
            "ünïcode",
            "a:b",
            "a*b",
        ] {
            assert_eq!(
                OutputPath::new(bad),
                Err(OutputError::InvalidPath),
                "{bad:?}"
            );
        }
        let long = "a".repeat(MAX_OUTPUT_PATH_BYTES);
        assert!(OutputPath::new(long.clone()).is_ok());
        assert_eq!(
            OutputPath::new(format!("{long}b")),
            Err(OutputError::InvalidPath)
        );
    }

    #[test]
    fn output_grants_are_bounded_in_count_and_free_of_repeats() {
        let path = |index: usize| OutputPath::new(format!("f{index}")).unwrap();
        assert!(OutputGrant::new(0, Vec::new(), 0).is_ok());
        assert!(OutputGrant::new(1, (0..MAX_OUTPUT_FILES).map(path).collect(), 1).is_ok());
        assert_eq!(
            OutputGrant::new(1, (0..=MAX_OUTPUT_FILES).map(path).collect(), 1),
            Err(OutputError::TooManyFiles)
        );
        assert_eq!(
            OutputGrant::new(1, vec![path(1), path(2), path(1)], 1),
            Err(OutputError::DuplicatePath)
        );
        assert!(grant().within_ceilings());
        assert!(
            !OutputGrant::new(MAX_OUTPUT_STDIO_BYTES + 1, Vec::new(), 0)
                .unwrap()
                .within_ceilings()
        );
        assert!(
            !OutputGrant::new(0, Vec::new(), MAX_OUTPUT_FILES_BYTES + 1)
                .unwrap()
                .within_ceilings()
        );
        assert!(
            OutputGrant::new(MAX_OUTPUT_STDIO_BYTES, Vec::new(), MAX_OUTPUT_FILES_BYTES)
                .unwrap()
                .within_ceilings()
        );
    }

    #[test]
    fn a_manifest_may_carry_an_output_grant_and_keeps_its_bytes_without_one() {
        let offline =
            CapabilityManifestBytes::encode(&CapabilityManifest::new(NetworkGrant::Offline))
                .unwrap();
        assert_eq!(offline.bytes(), br#"{"network":"offline"}"#);
        assert_eq!(offline.manifest().output(), None);

        let with_output = CapabilityManifest::new(NetworkGrant::Offline).with_output(grant());
        let bytes = CapabilityManifestBytes::encode(&with_output).unwrap();
        assert_eq!(
            bytes.bytes(),
            br#"{"network":"offline","output":{"stdio_bytes":4096,"files":["out/report.json","big.bin"],"files_bytes":2048}}"#
        );
        assert_eq!(bytes.manifest().output(), Some(&grant()));
        assert_eq!(bytes.manifest(), &with_output);

        let decoded = CapabilityManifest::decode_json(
            br#"{"output":{"files_bytes":2048,"files":["out/report.json","big.bin"],"stdio_bytes":4096},"network":"offline"}"#,
        )
        .unwrap();
        assert_eq!(decoded, with_output);
    }

    #[test]
    fn an_output_grant_outside_the_grammar_fails_manifest_decoding() {
        for bad in [
            r#"{"network":"offline","output":{"stdio_bytes":1,"files":["../x"],"files_bytes":1}}"#,
            r#"{"network":"offline","output":{"stdio_bytes":1,"files":["/etc/passwd"],"files_bytes":1}}"#,
            r#"{"network":"offline","output":{"stdio_bytes":1,"files":["a","a"],"files_bytes":1}}"#,
            r#"{"network":"offline","output":{"stdio_bytes":1,"files":[]}}"#,
            r#"{"network":"offline","output":{"stdio_bytes":-1,"files":[],"files_bytes":1}}"#,
            r#"{"network":"offline","output":{"stdio_bytes":1,"files":[],"files_bytes":1,"globs":true}}"#,
            r#"{"network":"offline","output":null}"#,
            r#"{"network":"offline","output":"all"}"#,
        ] {
            let error = CapabilityManifest::decode_json(bad.as_bytes()).unwrap_err();
            assert!(
                matches!(
                    error,
                    TaskAdmissionError::MalformedManifest
                        | TaskAdmissionError::MalformedOutputGrant(_)
                ),
                "{bad}: {error:?}"
            );
        }
        let many = (0..=MAX_OUTPUT_FILES)
            .map(|index| format!("\"f{index}\""))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            CapabilityManifest::decode_json(
                format!(r#"{{"network":"offline","output":{{"stdio_bytes":1,"files":[{many}],"files_bytes":1}}}}"#)
                    .as_bytes()
            ),
            Err(TaskAdmissionError::MalformedOutputGrant(
                OutputError::TooManyFiles
            ))
        );
    }

    #[test]
    fn streams_and_files_have_a_stable_wire_and_decode_strictly() {
        let json = serde_json::to_string(&output()).unwrap();
        assert_eq!(
            json,
            format!(
                r#"{{"stdout":{{"bytes":6,"truncated":false,"dropped":0,"content_base64":"aGVsbG8K"}},"stderr":{{"bytes":4,"truncated":true,"dropped":12,"content_base64":"d2Fybg=="}},"files":[{{"path":"out/report.json","size":2,"digest":"{}","truncated":false,"content_base64":"e30="}},{{"path":"big.bin","size":3000,"digest":"{}","truncated":true}},{{"path":"missing.txt","skipped":"missing"}}]}}"#,
                Blake3Hash::hash(b"{}").to_hex(),
                Blake3Hash::hash(b"big").to_hex()
            )
        );
        assert_eq!(
            serde_json::from_str::<AttemptOutput>(&json).unwrap(),
            output()
        );
        assert!(output().truncated());
        assert!(!AttemptOutput::default().truncated());

        let digest = Blake3Hash::hash(b"{}").to_hex();
        for bad in [
            // bytes disagree with the content
            r#"{"stdout":{"bytes":5,"truncated":false,"dropped":0,"content_base64":"aGVsbG8K"},"stderr":{"bytes":0,"truncated":false,"dropped":0,"content_base64":""},"files":[]}"#.to_owned(),
            // truncated disagrees with dropped
            r#"{"stdout":{"bytes":6,"truncated":true,"dropped":0,"content_base64":"aGVsbG8K"},"stderr":{"bytes":0,"truncated":false,"dropped":0,"content_base64":""},"files":[]}"#.to_owned(),
            // not base64
            r#"{"stdout":{"bytes":6,"truncated":false,"dropped":0,"content_base64":"aGVsbG8"},"stderr":{"bytes":0,"truncated":false,"dropped":0,"content_base64":""},"files":[]}"#.to_owned(),
            // a returned file whose size disagrees with its content
            format!(r#"{{"stdout":{{"bytes":0,"truncated":false,"dropped":0,"content_base64":""}},"stderr":{{"bytes":0,"truncated":false,"dropped":0,"content_base64":""}},"files":[{{"path":"a","size":3,"digest":"{digest}","truncated":false,"content_base64":"e30="}}]}}"#),
            // a skipped file that also carries a digest
            format!(r#"{{"stdout":{{"bytes":0,"truncated":false,"dropped":0,"content_base64":""}},"stderr":{{"bytes":0,"truncated":false,"dropped":0,"content_base64":""}},"files":[{{"path":"a","digest":"{digest}","skipped":"missing"}}]}}"#),
            // digest-only with content
            format!(r#"{{"stdout":{{"bytes":0,"truncated":false,"dropped":0,"content_base64":""}},"stderr":{{"bytes":0,"truncated":false,"dropped":0,"content_base64":""}},"files":[{{"path":"a","size":2,"digest":"{digest}","truncated":true,"content_base64":"e30="}}]}}"#),
            // a path outside the grammar
            r#"{"stdout":{"bytes":0,"truncated":false,"dropped":0,"content_base64":""},"stderr":{"bytes":0,"truncated":false,"dropped":0,"content_base64":""},"files":[{"path":"../a","skipped":"missing"}]}"#.to_owned(),
            // the same path twice
            r#"{"stdout":{"bytes":0,"truncated":false,"dropped":0,"content_base64":""},"stderr":{"bytes":0,"truncated":false,"dropped":0,"content_base64":""},"files":[{"path":"a","skipped":"missing"},{"path":"a","skipped":"missing"}]}"#.to_owned(),
            // an unknown field
            r#"{"stdout":{"bytes":0,"truncated":false,"dropped":0,"content_base64":""},"stderr":{"bytes":0,"truncated":false,"dropped":0,"content_base64":""},"files":[],"exit_code":0}"#.to_owned(),
        ] {
            assert!(serde_json::from_str::<AttemptOutput>(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn streams_and_results_refuse_content_past_the_ceilings() {
        let stdio_ceiling = usize::try_from(MAX_OUTPUT_STDIO_BYTES).unwrap();
        assert!(OutputStream::new(vec![0; stdio_ceiling], 0).is_ok());
        assert_eq!(
            OutputStream::new(vec![0; stdio_ceiling + 1], 0),
            Err(OutputError::MalformedResult)
        );
        let returned = |path: &str, size: usize| OutputFile {
            path: OutputPath::new(path).unwrap(),
            status: OutputFileStatus::Returned {
                size: size as u64,
                digest: Blake3Hash::hash(&[]),
                content: vec![0; size],
            },
        };
        let half = usize::try_from(MAX_OUTPUT_FILES_BYTES).unwrap() / 2;
        assert!(
            AttemptOutput::new(
                OutputStream::default(),
                OutputStream::default(),
                vec![returned("a", half), returned("b", half)]
            )
            .is_ok()
        );
        assert_eq!(
            AttemptOutput::new(
                OutputStream::default(),
                OutputStream::default(),
                vec![returned("a", half), returned("b", half + 1)]
            ),
            Err(OutputError::MalformedResult)
        );
        assert_eq!(
            AttemptOutput::new(
                OutputStream::default(),
                OutputStream::default(),
                vec![returned("a", 1), returned("a", 1)]
            ),
            Err(OutputError::DuplicatePath)
        );
    }

    #[test]
    fn result_requests_are_one_three_features_with_a_stable_wire() {
        let request = one_three().result(binding()).unwrap();
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            json,
            r#"{"request":"result","protocol":{"major":1,"minor":3},"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"}}"#
        );
        assert_eq!(one_three().decode_result_request(&json).unwrap(), request);
        assert_eq!(
            one_two().result(binding()),
            Err(TaskLifecycleError::UnsupportedByProtocol)
        );
        assert_eq!(
            one_two().decode_result_request(&json),
            Err(TaskLifecycleError::MalformedMessage)
        );
        assert_eq!(
            one_three().decode_result_request(&json.replace(r#""minor":3"#, r#""minor":2"#)),
            Err(TaskLifecycleError::ProtocolMismatch)
        );
        for bad in [
            json.replace("result", "inspect"),
            json.replace("}}", r#"},"from_seq":1}"#),
            json.replace(r#""request":"result","#, ""),
        ] {
            assert_eq!(
                one_three().decode_result_request(&bad),
                Err(TaskLifecycleError::MalformedMessage),
                "{bad}"
            );
        }
    }

    #[test]
    fn result_responses_are_one_three_features_for_ended_states_with_a_stable_wire() {
        let response = one_three()
            .result_response(binding(), TaskLifecycleState::Exited, output())
            .unwrap();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.starts_with(
            r#"{"response":"result","protocol":{"major":1,"minor":3},"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"},"state":"exited","output":{"stdout":"#
        ));
        assert_eq!(one_three().decode_result_response(&json).unwrap(), response);
        assert_eq!(
            one_two().decode_result_response(&json),
            Err(TaskLifecycleError::MalformedMessage)
        );
        assert_eq!(
            one_three().decode_result_response(&json.replace(r#""minor":3"#, r#""minor":2"#)),
            Err(TaskLifecycleError::MalformedMessage),
            "a result bound to 1.2 is not representable"
        );
        for state in [
            TaskLifecycleState::Created,
            TaskLifecycleState::Ready,
            TaskLifecycleState::Running,
            TaskLifecycleState::Paused,
        ] {
            assert_eq!(
                one_three().result_response(binding(), state, output()),
                Err(TaskLifecycleError::UnsupportedByProtocol)
            );
            assert_eq!(
                one_three().decode_result_response(&json.replace(
                    r#""state":"exited""#,
                    &format!(
                        r#""state":"{}""#,
                        serde_json::to_string(&state).unwrap().trim_matches('"')
                    )
                )),
                Err(TaskLifecycleError::MalformedMessage)
            );
        }
        for state in [
            TaskLifecycleState::Stopped,
            TaskLifecycleState::Revoked,
            TaskLifecycleState::Sealed,
        ] {
            assert!(
                one_three()
                    .result_response(binding(), state, output())
                    .is_ok()
            );
        }

        let rejected =
            one_three().result_rejected(binding(), TaskLifecycleRejectionReason::InvalidState);
        let json = serde_json::to_string(&rejected).unwrap();
        assert_eq!(
            json,
            r#"{"response":"rejected","protocol":{"major":1,"minor":3},"operation_id":null,"binding":{"task":"task_00000000000000000000000007","attempt":"exec_00000000000000000000000008","lease":"lease_00000000000000000000000009"},"reason":"invalid_state"}"#
        );
        assert_eq!(one_three().decode_result_response(&json).unwrap(), rejected);
        assert_eq!(
            one_three().decode_result_response(&json.replace("null", "4")),
            Err(TaskLifecycleError::MalformedMessage)
        );
        assert_eq!(
            one_three().decode_result_response(&json.replace(r#""minor":3"#, r#""minor":2"#)),
            Err(TaskLifecycleError::ProtocolMismatch)
        );
        // A lifecycle decoder never takes a result for an inspection, and vice versa.
        let result_json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            one_three().decode_response(&result_json),
            Err(TaskLifecycleError::MalformedMessage)
        );
        let inspected =
            serde_json::to_string(&one_three().inspected(binding(), TaskLifecycleState::Exited))
                .unwrap();
        assert_eq!(
            one_three().decode_result_response(&inspected),
            Err(TaskLifecycleError::MalformedMessage)
        );
    }
}
