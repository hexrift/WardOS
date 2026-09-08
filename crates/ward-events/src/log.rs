//! Append-only, hash-chained session log over a `std::fs::File` (`event-model.md` §5).
//!
//! * The file is opened `O_APPEND` and created with mode `0600`.
//! * Records are written as wire frames (see [`crate::wire`]).
//! * The writer verifies chain linkage of every record it appends, so a caller that
//!   hands it records out of order or from another session is refused before anything
//!   touches the disk.
//! * The reader verifies the chain incrementally and stops at the first bad record.
//! * fsync behaviour is pluggable through [`FsyncDecider`]; the default
//!   [`FsyncPolicy`] syncs immediately on critical events and otherwise at most every
//!   250 ms, as the design document specifies.

use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::chain::{ChainError, ChainHead, ChainVerifier, EventRecord};
use crate::ids::{Blake3Hash, SessionId};
use crate::wire::{self, WireError};

/// Name of the sealed-head file written beside `events.log`.
pub const HEAD_FILE_NAME: &str = "HEAD";

/// Errors from the log writer and reader.
#[derive(Debug, Error)]
pub enum LogError {
    /// Filesystem I/O failed.
    #[error("log I/O failed: {0}")]
    Io(#[from] io::Error),
    /// A frame could not be encoded or decoded.
    #[error(transparent)]
    Wire(WireError),
    /// The chain is broken.
    #[error(transparent)]
    Chain(#[from] ChainError),
    /// The file ends with an incomplete frame (e.g. a crash mid-write).
    #[error("log has an incomplete frame at byte offset {offset}")]
    TruncatedTail {
        /// Offset of the incomplete frame.
        offset: u64,
    },
    /// The log has no records, so its session and genesis are unknown.
    #[error("log is empty")]
    Empty,
    /// The `HEAD` file could not be parsed.
    #[error("malformed HEAD file: {0}")]
    MalformedHead(String),
}

impl From<WireError> for LogError {
    fn from(e: WireError) -> Self {
        match e {
            WireError::Io(io) => LogError::Io(io),
            WireError::Chain(c) => LogError::Chain(c),
            other => LogError::Wire(other),
        }
    }
}

/// Decides whether the log must be fsynced after a record has been written.
pub trait FsyncDecider {
    /// Called after `record` has been written. `since_last_sync` is the time elapsed since
    /// the previous fsync (or since the writer was opened).
    fn should_sync(&mut self, record: &EventRecord, since_last_sync: Duration) -> bool;
}

/// Built-in fsync policies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsyncPolicy {
    /// Never fsync automatically (tests, benchmarks). [`LogWriter::sync`] still works.
    Never,
    /// fsync after every record.
    Always,
    /// fsync after critical records only ([`crate::event::EventKind::is_critical`]).
    Critical,
    /// fsync after critical records, and otherwise once the given interval has elapsed
    /// since the last sync. The design default is 250 ms.
    CriticalOrInterval(Duration),
}

impl FsyncPolicy {
    /// The design default: critical events immediately, everything else within 250 ms.
    pub const DEFAULT: Self = Self::CriticalOrInterval(Duration::from_millis(250));
}

impl Default for FsyncPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl FsyncDecider for FsyncPolicy {
    fn should_sync(&mut self, record: &EventRecord, since_last_sync: Duration) -> bool {
        match *self {
            FsyncPolicy::Never => false,
            FsyncPolicy::Always => true,
            FsyncPolicy::Critical => record.event.is_critical(),
            FsyncPolicy::CriticalOrInterval(interval) => {
                record.event.is_critical() || since_last_sync >= interval
            }
        }
    }
}

/// Append-only writer for one session's `events.log`.
pub struct LogWriter {
    file: File,
    path: PathBuf,
    verifier: ChainVerifier,
    decider: Box<dyn FsyncDecider + Send>,
    last_sync: Instant,
    dirty: bool,
}

impl std::fmt::Debug for LogWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogWriter")
            .field("path", &self.path)
            .field("head", &self.verifier.head())
            .field("dirty", &self.dirty)
            .finish_non_exhaustive()
    }
}

fn open_append(path: &Path, create_new: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.append(true).create_new(create_new);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

impl LogWriter {
    /// Creates a new, empty log for a chain at `head` (normally `Chain::genesis(..).head()`).
    ///
    /// # Errors
    /// [`LogError::Io`] if the file exists or cannot be created.
    pub fn create(
        path: impl AsRef<Path>,
        head: ChainHead,
        policy: impl FsyncDecider + Send + 'static,
    ) -> Result<Self, LogError> {
        let path = path.as_ref().to_path_buf();
        let file = open_append(&path, true)?;
        Ok(Self {
            file,
            path,
            verifier: ChainVerifier::from_head(head),
            decider: Box::new(policy),
            last_sync: Instant::now(),
            dirty: false,
        })
    }

    /// Opens an existing log for appending, first reading and verifying every record in
    /// it to recover the chain head.
    ///
    /// # Errors
    /// Any [`LogError`] from verification (including [`LogError::TruncatedTail`] for a
    /// half-written final frame, which the caller must repair explicitly), or I/O errors.
    pub fn open(
        path: impl AsRef<Path>,
        policy: impl FsyncDecider + Send + 'static,
    ) -> Result<Self, LogError> {
        let path = path.as_ref().to_path_buf();
        let head = LogReader::open(&path)?.verify_all()?;
        let file = open_append(&path, false)?;
        Ok(Self {
            file,
            path,
            verifier: ChainVerifier::from_head(head),
            decider: Box::new(policy),
            last_sync: Instant::now(),
            dirty: false,
        })
    }

    /// Appends `record`, which must be the next record of this log's chain.
    ///
    /// # Errors
    /// [`LogError::Chain`] if the record does not continue the chain (nothing is
    /// written), [`LogError::Wire`] if it cannot be encoded, [`LogError::Io`] on write or
    /// fsync failure.
    pub fn append(&mut self, record: &EventRecord) -> Result<(), LogError> {
        // Verify on a copy so a rejected record leaves our head untouched even though
        // `push` already guarantees that.
        let mut next = self.verifier.clone();
        next.push(record)?;
        let frame = wire::encode_record(record)?;
        self.file.write_all(&frame)?;
        self.verifier = next;
        self.dirty = true;
        let elapsed = self.last_sync.elapsed();
        if self.decider.should_sync(record, elapsed) {
            self.sync()?;
        }
        Ok(())
    }

    /// Forces an fsync.
    ///
    /// # Errors
    /// [`LogError::Io`].
    pub fn sync(&mut self) -> Result<(), LogError> {
        self.file.sync_data()?;
        self.last_sync = Instant::now();
        self.dirty = false;
        Ok(())
    }

    /// fsyncs if there is unsynced data and at least `interval` has passed since the last
    /// sync. Intended to be driven by a periodic timer in `wardd`.
    ///
    /// # Errors
    /// [`LogError::Io`].
    pub fn sync_if_due(&mut self, interval: Duration) -> Result<bool, LogError> {
        if self.dirty && self.last_sync.elapsed() >= interval {
            self.sync()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// The verified head of everything written so far.
    #[must_use]
    pub const fn head(&self) -> ChainHead {
        self.verifier.head()
    }

    /// Whether there is data written but not yet fsynced.
    #[must_use]
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Path of the log file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Seals the log: fsyncs, writes the chain head to `HEAD` beside the log, and makes
    /// both files read-only. Returns the sealed head.
    ///
    /// # Errors
    /// [`LogError::Io`].
    pub fn seal(mut self) -> Result<ChainHead, LogError> {
        self.sync()?;
        let head = self.head();
        let head_path = head_file_path(&self.path);
        {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o400);
            }
            let mut f = opts.open(&head_path)?;
            f.write_all(format_head(&head).as_bytes())?;
            f.sync_all()?;
        }
        set_read_only(&self.path)?;
        set_read_only(&head_path)?;
        if let Some(dir) = self.path.parent() {
            File::open(dir)?.sync_all()?;
        }
        Ok(head)
    }
}

fn set_read_only(path: &Path) -> io::Result<()> {
    let mut perms = std::fs::metadata(path)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o400);
    }
    #[cfg(not(unix))]
    perms.set_readonly(true);
    std::fs::set_permissions(path, perms)
}

/// Path of the `HEAD` file for a given log path.
#[must_use]
pub fn head_file_path(log_path: &Path) -> PathBuf {
    log_path.with_file_name(HEAD_FILE_NAME)
}

/// Renders a head as the `HEAD` file text: four `key=value` lines.
#[must_use]
pub fn format_head(head: &ChainHead) -> String {
    format!(
        "session={}\ngenesis=blake3:{}\nnext_seq={}\nhash=blake3:{}\n",
        head.session, head.genesis, head.next_seq, head.hash
    )
}

/// Parses `HEAD` file text produced by [`format_head`].
///
/// # Errors
/// [`LogError::MalformedHead`] if any line is missing or malformed.
pub fn parse_head(text: &str) -> Result<ChainHead, LogError> {
    let mut session = None;
    let mut genesis = None;
    let mut next_seq = None;
    let mut hash = None;
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| LogError::MalformedHead(line.to_owned()))?;
        let bad = || LogError::MalformedHead(line.to_owned());
        match key {
            "session" => session = Some(value.parse::<SessionId>().map_err(|_| bad())?),
            "genesis" => genesis = Some(value.parse::<Blake3Hash>().map_err(|_| bad())?),
            "next_seq" => next_seq = Some(value.parse::<u64>().map_err(|_| bad())?),
            "hash" => hash = Some(value.parse::<Blake3Hash>().map_err(|_| bad())?),
            _ => return Err(LogError::MalformedHead(line.to_owned())),
        }
    }
    match (session, genesis, next_seq, hash) {
        (Some(session), Some(genesis), Some(next_seq), Some(hash)) => Ok(ChainHead {
            session,
            genesis,
            next_seq,
            hash,
        }),
        _ => Err(LogError::MalformedHead("missing field".to_owned())),
    }
}

/// Reads and verifies a session log incrementally.
///
/// The first record's `prev` is taken as the genesis hash; compare
/// [`ChainHead::genesis`] against the expected manifest hash after reading.
pub struct LogReader {
    reader: BufReader<File>,
    verifier: Option<ChainVerifier>,
    offset: u64,
    finished: bool,
}

impl std::fmt::Debug for LogReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogReader")
            .field("offset", &self.offset)
            .field("head", &self.head())
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl LogReader {
    /// Opens a log for reading.
    ///
    /// # Errors
    /// [`LogError::Io`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LogError> {
        let file = File::open(path)?;
        Ok(Self {
            reader: BufReader::new(file),
            verifier: None,
            offset: 0,
            finished: false,
        })
    }

    /// Reads and verifies the next record. Returns `Ok(None)` at a clean end of file.
    /// After any error the reader yields nothing further.
    ///
    /// # Errors
    /// [`LogError::TruncatedTail`] for an incomplete final frame, [`LogError::Chain`] for
    /// a broken chain, [`LogError::Wire`] for a malformed frame, [`LogError::Io`].
    pub fn next_record(&mut self) -> Result<Option<EventRecord>, LogError> {
        if self.finished {
            return Ok(None);
        }
        match self.read_one() {
            Ok(Some(r)) => Ok(Some(r)),
            Ok(None) => {
                self.finished = true;
                Ok(None)
            }
            Err(e) => {
                self.finished = true;
                Err(e)
            }
        }
    }

    fn read_one(&mut self) -> Result<Option<EventRecord>, LogError> {
        let frame = match wire::read_frame(&mut self.reader) {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(None),
            Err(WireError::Truncated { .. }) => {
                return Err(LogError::TruncatedTail {
                    offset: self.offset,
                });
            }
            Err(e) => return Err(e.into()),
        };
        let frame_len = u64::try_from(frame.header.frame_len()).unwrap_or(u64::MAX);
        let record = frame.into_record()?;
        let verifier = self.verifier.get_or_insert_with(|| {
            ChainVerifier::from_head(ChainHead {
                session: record.session,
                genesis: record.prev,
                next_seq: record.seq,
                hash: record.prev,
            })
        });
        verifier.push(&record)?;
        self.offset = self.offset.saturating_add(frame_len);
        Ok(Some(record))
    }

    /// The verified head so far, once at least one record has been read.
    #[must_use]
    pub fn head(&self) -> Option<ChainHead> {
        self.verifier.as_ref().map(ChainVerifier::head)
    }

    /// Byte offset just past the last successfully verified frame.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Reads and verifies every remaining record, returning the final head.
    ///
    /// # Errors
    /// As [`next_record`](Self::next_record); [`LogError::Empty`] if there are no records.
    pub fn verify_all(mut self) -> Result<ChainHead, LogError> {
        while self.next_record()?.is_some() {}
        self.head().ok_or(LogError::Empty)
    }
}

impl Iterator for LogReader {
    type Item = Result<EventRecord, LogError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_record().transpose()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::{Read, Seek, SeekFrom};

    use super::*;
    use crate::chain::{Chain, Timestamp};
    use crate::event::{AgentState, EndReason, WardEvent};
    use crate::origin::Origin;

    fn session() -> SessionId {
        SessionId::from_u128(77)
    }

    fn manifest() -> Blake3Hash {
        Blake3Hash::hash(b"manifest-77")
    }

    fn write_log(dir: &Path, n: u64, policy: FsyncPolicy) -> (PathBuf, Chain, Vec<EventRecord>) {
        let path = dir.join("events.log");
        let mut chain = Chain::genesis(session(), manifest());
        let mut w = LogWriter::create(&path, chain.head(), policy).unwrap();
        let mut records = Vec::new();
        for i in 0..n {
            let r = chain
                .append(
                    Origin::Wardd,
                    WardEvent::AgentStateChanged {
                        state: AgentState::Working,
                    },
                    Timestamp::mono(Duration::from_millis(i)),
                )
                .unwrap();
            w.append(&r).unwrap();
            records.push(r);
        }
        assert_eq!(w.head(), chain.head());
        (path, chain, records)
    }

    #[test]
    fn write_then_read_verifies_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (path, chain, records) = write_log(dir.path(), 5, FsyncPolicy::Never);
        let read: Vec<EventRecord> = LogReader::open(&path)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(read, records);
        let head = LogReader::open(&path).unwrap().verify_all().unwrap();
        assert_eq!(head, chain.head());
        assert_eq!(head.genesis, manifest());
    }

    #[test]
    fn empty_log_reads_as_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.log");
        let w = LogWriter::create(
            &path,
            Chain::genesis(session(), manifest()).head(),
            FsyncPolicy::Never,
        )
        .unwrap();
        assert!(!w.is_dirty());
        drop(w);
        let mut r = LogReader::open(&path).unwrap();
        assert!(r.next_record().unwrap().is_none());
        assert!(r.head().is_none());
        assert!(matches!(
            LogReader::open(&path).unwrap().verify_all(),
            Err(LogError::Empty)
        ));
    }

    #[test]
    fn writer_refuses_out_of_order_and_foreign_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.log");
        let mut chain = Chain::genesis(session(), manifest());
        let mut w = LogWriter::create(&path, chain.head(), FsyncPolicy::Always).unwrap();
        let r0 = chain
            .append(
                Origin::Wardd,
                WardEvent::AgentStateChanged {
                    state: AgentState::Idle,
                },
                Timestamp::default(),
            )
            .unwrap();
        let r1 = chain
            .append(
                Origin::Wardd,
                WardEvent::AgentStateChanged {
                    state: AgentState::Working,
                },
                Timestamp::default(),
            )
            .unwrap();
        assert!(matches!(
            w.append(&r1),
            Err(LogError::Chain(ChainError::Gap { .. }))
        ));
        w.append(&r0).unwrap();
        assert!(matches!(
            w.append(&r0),
            Err(LogError::Chain(ChainError::Replay { .. }))
        ));
        let mut foreign = r1.clone();
        foreign.session = SessionId::from_u128(1);
        assert!(matches!(
            w.append(&foreign),
            Err(LogError::Chain(ChainError::SessionMismatch { .. }))
        ));
        w.append(&r1).unwrap();
        assert_eq!(w.head().next_seq, 2);
        // Only the two good records made it to disk.
        assert_eq!(LogReader::open(&path).unwrap().count(), 2);
    }

    #[test]
    fn reopen_recovers_head_and_continues() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut chain, _) = write_log(dir.path(), 3, FsyncPolicy::Critical);
        let mut w = LogWriter::open(&path, FsyncPolicy::DEFAULT).unwrap();
        assert_eq!(w.head(), chain.head());
        let r = chain
            .append(
                Origin::User,
                WardEvent::SessionEnded {
                    reason: EndReason::UserStop,
                    final_snapshot: None,
                },
                Timestamp::default(),
            )
            .unwrap();
        w.append(&r).unwrap();
        assert!(!w.is_dirty(), "critical event must have been synced");
        let head = LogReader::open(&path).unwrap().verify_all().unwrap();
        assert_eq!(head.next_seq, 4);
        assert_eq!(head.hash, r.hash);
    }

    #[test]
    fn tampered_byte_on_disk_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _, _) = write_log(dir.path(), 3, FsyncPolicy::Never);
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).unwrap();
        // Flip a byte inside the second frame's payload (past its header).
        let first_len = wire::peek_header(&bytes).unwrap().frame_len();
        let target = first_len + wire::HEADER_LEN + 20;
        bytes[target] ^= 0xff;
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&bytes).unwrap();
        let mut r = LogReader::open(&path).unwrap();
        assert!(r.next_record().unwrap().is_some());
        let err = r.next_record().unwrap_err();
        assert!(
            matches!(err, LogError::Chain(_) | LogError::Wire(_)),
            "{err}"
        );
        // After an error the reader yields nothing more.
        assert!(r.next_record().unwrap().is_none());
        assert!(LogWriter::open(&path, FsyncPolicy::Never).is_err());
    }

    #[test]
    fn deleted_middle_record_is_a_gap() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _, records) = write_log(dir.path(), 3, FsyncPolicy::Never);
        let frames: Vec<Vec<u8>> = records
            .iter()
            .map(|r| wire::encode_record(r).unwrap())
            .collect();
        std::fs::write(&path, [frames[0].clone(), frames[2].clone()].concat()).unwrap();
        let errs: Vec<_> = LogReader::open(&path)
            .unwrap()
            .filter_map(Result::err)
            .collect();
        assert_eq!(errs.len(), 1);
        assert!(matches!(
            errs[0],
            LogError::Chain(ChainError::Gap {
                expected: 1,
                found: 2
            })
        ));
    }

    #[test]
    fn truncated_tail_is_reported_with_offset() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _, _) = write_log(dir.path(), 2, FsyncPolicy::Never);
        let bytes = std::fs::read(&path).unwrap();
        let first_len = wire::peek_header(&bytes).unwrap().frame_len();
        std::fs::write(&path, &bytes[..bytes.len() - 3]).unwrap();
        let mut r = LogReader::open(&path).unwrap();
        assert!(r.next_record().unwrap().is_some());
        let err = r.next_record().unwrap_err();
        assert!(matches!(err, LogError::TruncatedTail { offset } if offset == first_len as u64));
        assert_eq!(r.offset(), first_len as u64);
    }

    #[test]
    fn seal_writes_head_and_makes_files_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.log");
        let mut chain = Chain::genesis(session(), manifest());
        let mut w = LogWriter::create(&path, chain.head(), FsyncPolicy::Never).unwrap();
        let r = chain
            .append(
                Origin::Wardd,
                WardEvent::AgentStateChanged {
                    state: AgentState::Finished,
                },
                Timestamp::default(),
            )
            .unwrap();
        w.append(&r).unwrap();
        assert!(w.is_dirty());
        let head = w.seal().unwrap();
        assert_eq!(head, chain.head());
        let head_text = std::fs::read_to_string(head_file_path(&path)).unwrap();
        assert_eq!(parse_head(&head_text).unwrap(), head);
        assert!(std::fs::metadata(&path).unwrap().permissions().readonly());
        assert!(
            std::fs::metadata(head_file_path(&path))
                .unwrap()
                .permissions()
                .readonly()
        );
        assert!(matches!(
            parse_head("nonsense"),
            Err(LogError::MalformedHead(_))
        ));
        assert!(matches!(
            parse_head("session=sess_x\n"),
            Err(LogError::MalformedHead(_))
        ));
        assert!(matches!(parse_head(""), Err(LogError::MalformedHead(_))));
    }

    #[test]
    fn fsync_policies_decide_as_documented() {
        let mut chain = Chain::genesis(session(), manifest());
        let plain = chain
            .append(
                Origin::Wardd,
                WardEvent::AgentStateChanged {
                    state: AgentState::Idle,
                },
                Timestamp::default(),
            )
            .unwrap();
        let critical = chain
            .append(
                Origin::Wardd,
                WardEvent::SessionEnded {
                    reason: EndReason::Timeout,
                    final_snapshot: None,
                },
                Timestamp::default(),
            )
            .unwrap();
        let ms = Duration::from_millis;
        assert!(!FsyncPolicy::Never.should_sync(&critical, ms(10_000)));
        assert!(FsyncPolicy::Always.should_sync(&plain, ms(0)));
        assert!(FsyncPolicy::Critical.should_sync(&critical, ms(0)));
        assert!(!FsyncPolicy::Critical.should_sync(&plain, ms(10_000)));
        let mut default = FsyncPolicy::DEFAULT;
        assert!(default.should_sync(&critical, ms(0)));
        assert!(!default.should_sync(&plain, ms(100)));
        assert!(default.should_sync(&plain, ms(250)));
        assert_eq!(FsyncPolicy::default(), FsyncPolicy::DEFAULT);
    }

    #[test]
    fn custom_fsync_hook_and_sync_if_due() {
        struct CountingHook(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl FsyncDecider for CountingHook {
            fn should_sync(&mut self, _: &EventRecord, _: Duration) -> bool {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                false
            }
        }
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.log");
        let mut chain = Chain::genesis(session(), manifest());
        let mut w = LogWriter::create(&path, chain.head(), CountingHook(calls.clone())).unwrap();
        let r = chain
            .append(
                Origin::Wardd,
                WardEvent::AgentStateChanged {
                    state: AgentState::Idle,
                },
                Timestamp::default(),
            )
            .unwrap();
        w.append(&r).unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(w.is_dirty());
        assert!(!w.sync_if_due(Duration::from_secs(3600)).unwrap());
        assert!(w.sync_if_due(Duration::ZERO).unwrap());
        assert!(!w.is_dirty());
        assert!(!w.sync_if_due(Duration::ZERO).unwrap(), "nothing dirty");
        assert_eq!(w.path(), path);
    }

    #[test]
    fn create_refuses_to_clobber_and_uses_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let (path, chain, _) = write_log(dir.path(), 1, FsyncPolicy::Never);
        assert!(matches!(
            LogWriter::create(&path, chain.head(), FsyncPolicy::Never),
            Err(LogError::Io(_))
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
