//! File transfer (PNP-010): what the client sees of a transfer, what is stored about it, and
//! the tasks that move the bytes.
//!
//! The protocol itself is `parolnet-transfer` (sans-I/O). Here:
//!
//! - [`TransferInfo`] / [`TransferState`]: a transfer as a UI shows it.
//! - `StoredTransfer`: what the encrypted store keeps so that a transfer survives a lost
//!   connection and an app restart: the offer with its file key, the phase, the control
//!   message still to be sent, and for a received file the number of records that are
//!   safely on disk.
//! - One worker task per running transfer. It owns the file and the `parolnet-transfer`
//!   state machine, reads or writes one 64 KiB record at a time (a file is never held in
//!   memory), and reports to the core. The core hands it each new channel.
//! - `forward_events`: the connection's event pump. Messages of a transfer channel go to
//!   its worker through a small bounded queue, so a slow disk holds the connection's reader
//!   back instead of filling memory.

use std::collections::{HashMap, HashSet};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};

use bytes::BytesMut;
use parolnet_rtc::{DataSender, RtcEvent};
use parolnet_transfer::{
    BUFFER_HIGH, BUFFER_LOW, CHUNK_SIZE, FileHasher, FileKey, MAX_RECORD_FAILURES, Offer, Phase,
    RESERVED_LABEL_PREFIX, Received, Receiver, Role, Sender, TransferId, numbered_file_name,
    sanitize_file_name,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;
use zeroize::Zeroize as _;

pub use parolnet_transfer::{CancelReason, DEFAULT_MAX_ACCEPT_SIZE};

use crate::Direction;
use crate::engine::Input;

/// Where a transfer is, for a UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// Offered; the receiver has not answered.
    Offered,
    /// Accepted, and waiting: for a direct connection, or for its turn.
    Waiting,
    /// Records are flowing.
    Active,
    /// The whole file arrived and verified.
    Complete,
    /// The receiver declined.
    Declined,
    /// Stopped for good, by the contact (`by_peer`) or on this device.
    Cancelled { by_peer: bool, reason: CancelReason },
}

impl TransferState {
    pub fn is_over(self) -> bool {
        matches!(
            self,
            TransferState::Complete | TransferState::Declined | TransferState::Cancelled { .. }
        )
    }
}

/// A transfer as the UI shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferInfo {
    /// 32 hex digits.
    pub id: String,
    pub peer_id: String,
    /// `Sent`: this device offers the file. `Received`: it was offered to us.
    pub direction: Direction,
    /// The file's name, safe to show and to use as a file name (never a path).
    pub name: String,
    pub size: u64,
    /// The sender's claim; may be empty.
    pub mime: String,
    pub state: TransferState,
    /// Bytes sent to, or received from, the contact so far.
    pub bytes_done: u64,
    /// Our latest message about this transfer (the offer, our answer, a cancel) is still on
    /// this device, waiting for a verified direct connection.
    pub pending: bool,
    /// The file on this device: what is being sent, or (once complete) what was received.
    pub path: Option<PathBuf>,
    pub created_ms: u64,
}

/// The control message a transfer still owes the contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PendingControl {
    Offer,
    Accept,
    Decline,
    Cancel(u8),
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum StoredPhase {
    Offered,
    Accepted,
    Complete,
    Declined,
    Cancelled,
}

impl StoredPhase {
    pub(crate) fn phase(self) -> Phase {
        match self {
            StoredPhase::Offered => Phase::Offered,
            StoredPhase::Accepted => Phase::Accepted,
            StoredPhase::Complete => Phase::Complete,
            StoredPhase::Declined => Phase::Declined,
            StoredPhase::Cancelled => Phase::Cancelled,
        }
    }
}

/// What the store keeps of a transfer (in the encrypted database, with the rest of the
/// engine's settings). The file key is erased when the transfer is over and wiped from
/// memory when the record is dropped; `Debug` does not show it.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredTransfer {
    /// 32 hex digits.
    pub id: String,
    pub peer_id: String,
    /// We are the sender.
    pub outgoing: bool,
    pub phase: StoredPhase,
    /// The name as offered (shown and stored only through `sanitize_file_name`).
    pub name: String,
    pub size: u64,
    pub mime: String,
    /// Hex.
    pub sha256: String,
    /// Hex; `None` once the transfer is over.
    pub key: Option<String>,
    /// Sender: the file being sent. Receiver: the received file, once complete.
    pub path: Option<PathBuf>,
    /// Sender: the file's modification time when it was offered.
    pub mtime_ms: Option<u64>,
    /// Receiver: records safely on disk in the part file.
    pub next: u32,
    pub pending: Option<PendingControl>,
    /// How it was cancelled: by the contact?, the reason code.
    pub cancelled: Option<(bool, u8)>,
    pub created_ms: u64,
    pub updated_ms: u64,
}

impl Drop for StoredTransfer {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl std::fmt::Debug for StoredTransfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredTransfer")
            .field("id", &self.id)
            .field("outgoing", &self.outgoing)
            .field("phase", &self.phase)
            .field("size", &self.size)
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl StoredTransfer {
    pub(crate) fn role(&self) -> Role {
        if self.outgoing {
            Role::Sender
        } else {
            Role::Receiver
        }
    }

    pub(crate) fn transfer_id(&self) -> Option<TransferId> {
        self.id.parse().ok()
    }

    /// The transfer is over: forget the key.
    pub(crate) fn finish(&mut self, phase: StoredPhase) {
        self.phase = phase;
        self.key.zeroize();
        self.key = None;
    }

    /// There is something to do with this contact once a verified connection exists.
    pub(crate) fn wants_connection(&self) -> bool {
        self.pending.is_some() || self.phase == StoredPhase::Accepted
    }

    /// The offer as the protocol crate takes it. `None` when the stored record is damaged
    /// or the key is gone.
    pub(crate) fn offer(&self) -> Option<Offer> {
        let mut key = [0u8; 32];
        hex::decode_to_slice(self.key.as_ref()?, &mut key).ok()?;
        let mut sha256 = [0u8; 32];
        hex::decode_to_slice(&self.sha256, &mut sha256).ok()?;
        let offer = Offer {
            id: self.transfer_id()?,
            name: self.name.clone(),
            size: self.size,
            mime: self.mime.clone(),
            sha256,
            key: FileKey::from_bytes(key),
        };
        key.zeroize();
        Some(offer)
    }

    pub(crate) fn info(&self, active: bool, bytes_done: u64) -> TransferInfo {
        let state = match self.phase {
            StoredPhase::Offered => TransferState::Offered,
            StoredPhase::Accepted if active => TransferState::Active,
            StoredPhase::Accepted => TransferState::Waiting,
            StoredPhase::Complete => TransferState::Complete,
            StoredPhase::Declined => TransferState::Declined,
            StoredPhase::Cancelled => {
                let (by_peer, code) = self.cancelled.unwrap_or((false, 0));
                TransferState::Cancelled {
                    by_peer,
                    reason: CancelReason::from_code(code),
                }
            }
        };
        TransferInfo {
            id: self.id.clone(),
            peer_id: self.peer_id.clone(),
            direction: if self.outgoing {
                Direction::Sent
            } else {
                Direction::Received
            },
            name: sanitize_file_name(&self.name),
            size: self.size,
            mime: self.mime.clone(),
            state,
            bytes_done: if self.phase == StoredPhase::Complete {
                self.size
            } else {
                bytes_done.min(self.size)
            },
            pending: self.pending.is_some(),
            path: self.path.clone(),
            created_ms: self.created_ms,
        }
    }
}

/// Fault injection for this crate's integration tests. Never in a shipped build.
#[cfg(feature = "test-hooks")]
pub mod test_hooks {
    use std::sync::atomic::{AtomicU32, Ordering};

    static SKIP: AtomicU32 = AtomicU32::new(0);
    static CORRUPT: AtomicU32 = AtomicU32::new(0);
    static CORRUPTED: AtomicU32 = AtomicU32::new(0);

    /// Let the next `skip` records any sender in this process seals through, then flip a
    /// bit in each of the `count` records after them (as something on the path would).
    pub fn corrupt_records(skip: u32, count: u32) {
        SKIP.store(skip, Ordering::SeqCst);
        CORRUPT.store(count, Ordering::SeqCst);
        CORRUPTED.store(0, Ordering::SeqCst);
    }

    /// Records corrupted since the last [`corrupt_records`].
    pub fn corrupted() -> u32 {
        CORRUPTED.load(Ordering::SeqCst)
    }

    pub(crate) fn maybe_corrupt(record: &mut [u8]) {
        if SKIP
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return;
        }
        if CORRUPT
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            let at = record.len() / 2;
            record[at] ^= 0x04;
            CORRUPTED.fetch_add(1, Ordering::SeqCst);
        }
    }
}

// ── Offering: hash the file without holding it ────────────────────

/// What `offer_file` learns about the file before the offer is made.
pub(crate) struct Hashed {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub mtime_ms: Option<u64>,
    pub sha256: [u8; 32],
}

fn mtime_ms(meta: &std::fs::Metadata) -> Option<u64> {
    let t = meta.modified().ok()?;
    Some(t.duration_since(UNIX_EPOCH).ok()?.as_millis() as u64)
}

/// Read the file once, in 1 MiB pieces, for its SHA-256 (PNP-010-MUST-005). Blocking.
pub(crate) fn hash_file(path: &Path) -> std::io::Result<Hashed> {
    use std::io::Read as _;
    let path = path.canonicalize()?;
    let mut file = std::fs::File::open(&path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut hasher = FileHasher::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let size = hasher.len();
    if size != meta.len() {
        return Err(std::io::Error::other("the file changed while it was read"));
    }
    Ok(Hashed {
        path,
        name,
        size,
        mtime_ms: mtime_ms(&meta),
        sha256: hasher.finalize(),
    })
}

/// Where a received file's records are kept until it is complete.
pub(crate) fn part_path(downloads: &Path, id: &str) -> PathBuf {
    downloads.join(format!("{id}.part"))
}

// ── The connection's event pump ───────────────────────────────────

/// Messages of one transfer channel waiting for its worker. Small: 16 × 64 KiB.
const CHANNEL_QUEUE: usize = 16;

/// What a worker hears from its channel. The queue closing means the channel closed.
pub(crate) enum ChannelEvent {
    Message(BytesMut),
    BufferedLow,
}

/// A channel for a worker to run an attempt on.
pub(crate) struct Attachment {
    pub dc: usize,
    pub data: DataSender,
    pub rx: mpsc::Receiver<ChannelEvent>,
}

/// Pump one connection's events to the core. Channels under `pn-` are announced with a
/// queue of their own (`Input::FileChannel`) and their messages go there, waiting for room:
/// the core decides whether a worker reads the queue or the channel is closed.
pub(crate) async fn forward_events(
    mut events: mpsc::Receiver<RtcEvent>,
    input: mpsc::UnboundedSender<Input>,
    peer: String,
    epoch: u64,
) {
    let mut queues: HashMap<usize, mpsc::Sender<ChannelEvent>> = HashMap::new();
    // Channels whose queue nobody reads any more: their messages are dropped here.
    let mut dead: HashSet<usize> = HashSet::new();
    while let Some(event) = events.recv().await {
        let event = match event {
            RtcEvent::DataChannelOpen { id, label } if label.starts_with(RESERVED_LABEL_PREFIX) => {
                let (tx, rx) = mpsc::channel(CHANNEL_QUEUE);
                queues.insert(id, tx);
                Input::FileChannel {
                    peer: peer.clone(),
                    epoch,
                    dc: id,
                    label,
                    rx,
                }
            }
            RtcEvent::DataChannelMessage { id, payload } if queues.contains_key(&id) => {
                if queues[&id]
                    .send(ChannelEvent::Message(payload))
                    .await
                    .is_err()
                {
                    queues.remove(&id);
                    dead.insert(id);
                }
                continue;
            }
            RtcEvent::DataChannelMessage { id, .. } if dead.contains(&id) => continue,
            RtcEvent::DataChannelBufferedLow { id } => {
                if let Some(tx) = queues.get(&id) {
                    let _ = tx.try_send(ChannelEvent::BufferedLow);
                }
                continue;
            }
            RtcEvent::DataChannelClose { id } => {
                queues.remove(&id);
                dead.remove(&id);
                continue;
            }
            event => Input::Rtc {
                peer: peer.clone(),
                epoch,
                event,
            },
        };
        if input.send(event).is_err() {
            return;
        }
    }
}

// ── Workers ───────────────────────────────────────────────────────

pub(crate) enum WorkerCmd {
    /// A channel is open: run an attempt on it.
    Attach(Attachment),
    /// Stop. `discard`: the transfer is over without a file; remove what was stored.
    Stop { discard: bool },
}

/// What a worker tells the core.
#[derive(Debug)]
pub(crate) enum WorkerEvent {
    /// Bytes moved so far. `checkpoint` (receiver): this many records are safely on disk.
    Progress { bytes: u64, checkpoint: Option<u32> },
    /// The attempt's channel is finished with; `progressed`: it moved at least one record.
    AttemptEnded { progressed: bool },
    /// Receiver: every record arrived, the hash verified, the file is at `path`.
    Received { path: PathBuf },
    /// The transfer cannot go on: cancel it with this reason.
    Failed {
        reason: CancelReason,
        detail: String,
    },
}

/// The sender waits this long for the receiver's RESUME on a new channel (the receiver may
/// be reading back what it stored before a restart).
const RESUME_TIMEOUT: Duration = Duration::from_secs(120);
/// Progress reports to the UI.
const PROGRESS_EVERY: Duration = Duration::from_millis(200);
/// The receiver makes its records durable and records the count this often …
const CHECKPOINT_EVERY: Duration = Duration::from_secs(1);
/// … or after this many bytes.
const CHECKPOINT_BYTES: u64 = 16 << 20;

type Report = Box<dyn Fn(WorkerEvent) + Send + Sync>;

/// How an attempt ended.
enum Outcome {
    /// The channel is done with; wait for another.
    Ended {
        progressed: bool,
    },
    /// The core said stop.
    Stop {
        discard: bool,
    },
    /// The core is gone (shutdown): keep what is stored.
    Shutdown,
    /// Receiver: all records are stored.
    AllStored,
    /// A newer channel for the same transfer replaces this one.
    Superseded(Attachment),
    Fatal(CancelReason, String),
}

pub(crate) struct SendJob {
    pub id: TransferId,
    pub size: u64,
    pub key: FileKey,
    pub path: PathBuf,
    pub mtime_ms: Option<u64>,
}

/// The sending worker: serves every channel the receiver opens until told to stop.
pub(crate) async fn run_sender(
    job: SendJob,
    mut ctl: mpsc::UnboundedReceiver<WorkerCmd>,
    report: Report,
) {
    let mut sender = Sender::new(job.id, job.size, job.key.clone());
    let mut waiting: Option<Attachment> = None;
    loop {
        let attachment = match waiting.take() {
            Some(a) => a,
            None => match ctl.recv().await {
                Some(WorkerCmd::Attach(a)) => a,
                Some(WorkerCmd::Stop { .. }) | None => return,
            },
        };
        let dc = attachment.dc;
        let data = attachment.data.clone();
        let outcome = send_attempt(&job, &mut sender, attachment, &mut ctl, &report).await;
        sender.end_attempt();
        match outcome {
            Outcome::Ended { progressed } => {
                let _ = data.close_channel(dc);
                report(WorkerEvent::AttemptEnded { progressed });
            }
            Outcome::Superseded(newer) => {
                let _ = data.close_channel(dc);
                waiting = Some(newer);
            }
            Outcome::Fatal(reason, detail) => {
                let _ = data.close_channel(dc);
                report(WorkerEvent::Failed { reason, detail });
                return;
            }
            Outcome::Stop { .. } | Outcome::Shutdown | Outcome::AllStored => {
                let _ = data.close_channel(dc);
                return;
            }
        }
    }
}

/// The file is still the one that was offered (PNP-010-SHOULD-004).
async fn open_unchanged(job: &SendJob) -> Result<tokio::fs::File, String> {
    let file = tokio::fs::File::open(&job.path)
        .await
        .map_err(|e| format!("the file cannot be opened: {e}"))?;
    let meta = file
        .metadata()
        .await
        .map_err(|e| format!("the file cannot be read: {e}"))?;
    if meta.len() != job.size || (job.mtime_ms.is_some() && mtime_ms(&meta) != job.mtime_ms) {
        return Err("the file changed after it was offered".into());
    }
    Ok(file)
}

async fn send_attempt(
    job: &SendJob,
    sender: &mut Sender,
    mut ch: Attachment,
    ctl: &mut mpsc::UnboundedReceiver<WorkerCmd>,
    report: &Report,
) -> Outcome {
    // The receiver speaks first. (A buffered-amount event of the new channel may come before.)
    let resume = loop {
        let first = tokio::select! {
            m = tokio::time::timeout(RESUME_TIMEOUT, ch.rx.recv()) => m,
            cmd = ctl.recv() => return stop_or_shutdown(cmd),
        };
        match first {
            Ok(Some(ChannelEvent::Message(m))) => break m,
            Ok(Some(ChannelEvent::BufferedLow)) => {}
            Ok(None) | Err(_) => return Outcome::Ended { progressed: false },
        }
    };
    let Ok(start) = sender.begin(&resume, parolnet_transfer::random_bytes()) else {
        return Outcome::Ended { progressed: false };
    };
    let mut file = match open_unchanged(job).await {
        Ok(f) => f,
        Err(detail) => return Outcome::Fatal(CancelReason::Unavailable, detail),
    };
    let Some((offset, _)) = sender.next_chunk() else {
        return Outcome::Ended { progressed: false };
    };
    if let Err(e) = file.seek(SeekFrom::Start(offset)).await {
        return Outcome::Fatal(CancelReason::Unavailable, e.to_string());
    }
    let _ = ch.data.set_buffered_low(ch.dc, BUFFER_LOW as u32);
    if ch.data.send(ch.dc, start).await.is_err() {
        return Outcome::Ended { progressed: false };
    }
    // Where the receiver is: what it has stored, not what an earlier attempt had sent.
    report(WorkerEvent::Progress {
        bytes: sender.sent_bytes(),
        checkpoint: None,
    });

    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut progressed = false;
    let mut last_report = Instant::now();
    while let Some((_, len)) = sender.next_chunk() {
        // Anything the receiver says after RESUME is out of place (PNP-010-MUST-020); a
        // closed queue is a closed channel.
        loop {
            match ch.rx.try_recv() {
                Ok(ChannelEvent::BufferedLow) => {}
                Ok(ChannelEvent::Message(_)) | Err(mpsc::error::TryRecvError::Disconnected) => {
                    return Outcome::Ended { progressed };
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
            }
        }
        match ctl.try_recv() {
            Ok(cmd) => return stop_or_shutdown(Some(cmd)),
            Err(mpsc::error::TryRecvError::Disconnected) => return Outcome::Shutdown,
            Err(mpsc::error::TryRecvError::Empty) => {}
        }
        if let Err(e) = file.read_exact(&mut chunk[..len]).await {
            return Outcome::Fatal(
                CancelReason::Unavailable,
                format!("the file cannot be read: {e}"),
            );
        }
        #[cfg_attr(not(feature = "test-hooks"), allow(unused_mut))]
        let Ok(mut record) = sender.seal(&chunk[..len]) else {
            return Outcome::Ended { progressed };
        };
        #[cfg(feature = "test-hooks")]
        test_hooks::maybe_corrupt(&mut record);
        let buffered = match ch.data.send(ch.dc, record).await {
            Ok(buffered) => buffered,
            Err(err) => {
                tracing::debug!(%err, "a record was not sent; the attempt is over");
                return Outcome::Ended { progressed };
            }
        };
        progressed = true;
        if last_report.elapsed() >= PROGRESS_EVERY {
            last_report = Instant::now();
            report(WorkerEvent::Progress {
                bytes: sender.sent_bytes(),
                checkpoint: None,
            });
        }
        if buffered > BUFFER_HIGH {
            // Backpressure (PNP-010-SHOULD-001): wait for the low mark. The event wakes
            // the loop (it may be one from an earlier crossing, or be missed altogether);
            // the amount decides.
            loop {
                tokio::select! {
                    ev = ch.rx.recv() => match ev {
                        Some(ChannelEvent::BufferedLow) => {}
                        Some(ChannelEvent::Message(_)) | None => {
                            return Outcome::Ended { progressed };
                        }
                    },
                    cmd = ctl.recv() => return stop_or_shutdown(cmd),
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                }
                match ch.data.buffered_amount(ch.dc).await {
                    Ok(amount) if amount <= BUFFER_LOW => break,
                    Ok(_) => {}
                    Err(_) => return Outcome::Ended { progressed },
                }
            }
        }
    }
    chunk.zeroize();
    report(WorkerEvent::Progress {
        bytes: sender.sent_bytes(),
        checkpoint: None,
    });
    // Everything is on its way. The transfer is complete when the receiver says so
    // (PNP-010-MUST-023); until then the channel stays open for the tail to be delivered.
    loop {
        tokio::select! {
            ev = ch.rx.recv() => match ev {
                Some(ChannelEvent::BufferedLow) => {}
                Some(ChannelEvent::Message(_)) | None => return Outcome::Ended { progressed },
            },
            cmd = ctl.recv() => return stop_or_shutdown(cmd),
        }
    }
}

fn stop_or_shutdown(cmd: Option<WorkerCmd>) -> Outcome {
    match cmd {
        Some(WorkerCmd::Stop { discard }) => Outcome::Stop { discard },
        // A second channel for the same transfer supersedes this one (PNP-010 §5.1).
        Some(WorkerCmd::Attach(newer)) => Outcome::Superseded(newer),
        None => Outcome::Shutdown,
    }
}

pub(crate) struct ReceiveJob {
    pub offer: Offer,
    /// Where the records are kept until the file is complete.
    pub part: PathBuf,
    /// Where the finished file goes.
    pub downloads: PathBuf,
    /// Records the store says are safely in `part`.
    pub next: u32,
}

/// The receiving worker: stores what every attempt brings and finishes with the hash check.
pub(crate) async fn run_receiver(
    job: ReceiveJob,
    mut ctl: mpsc::UnboundedReceiver<WorkerCmd>,
    report: Report,
) {
    let (mut receiver, mut file) = match open_part(&job).await {
        Ok(x) => x,
        Err(detail) => {
            let _ = tokio::fs::remove_file(&job.part).await;
            report(WorkerEvent::Failed {
                reason: CancelReason::Storage,
                detail,
            });
            return;
        }
    };
    if receiver.next_record() != job.next {
        // Less was on disk than the store believed: say so before asking for more.
        report(WorkerEvent::Progress {
            bytes: receiver.stored_bytes(),
            checkpoint: Some(receiver.next_record()),
        });
    }
    let mut waiting: Option<Attachment> = None;
    loop {
        let outcome = if receiver.is_complete() {
            Outcome::AllStored
        } else {
            let attachment = match waiting.take() {
                Some(a) => a,
                None => match ctl.recv().await {
                    Some(WorkerCmd::Attach(a)) => a,
                    Some(WorkerCmd::Stop { discard }) => {
                        if discard {
                            let _ = tokio::fs::remove_file(&job.part).await;
                        }
                        return;
                    }
                    None => return,
                },
            };
            let dc = attachment.dc;
            let data = attachment.data.clone();
            let outcome =
                receive_attempt(&mut receiver, &mut file, attachment, &mut ctl, &report).await;
            receiver.end_attempt();
            // After the last record the channel stays open until the core has sent
            // `complete`: the sender hears that before it sees the channel close.
            if !matches!(outcome, Outcome::AllStored) {
                let _ = data.close_channel(dc);
            }
            outcome
        };
        match outcome {
            Outcome::Ended { progressed } => {
                // What arrived is made durable before the count is recorded.
                if let Err(e) = sync(&mut file).await {
                    fail_storage(&job, &report, e).await;
                    return;
                }
                report(WorkerEvent::Progress {
                    bytes: receiver.stored_bytes(),
                    checkpoint: Some(receiver.next_record()),
                });
                if receiver.record_failures() >= MAX_RECORD_FAILURES {
                    // PNP-010-SHOULD-005.
                    let _ = tokio::fs::remove_file(&job.part).await;
                    report(WorkerEvent::Failed {
                        reason: CancelReason::Integrity,
                        detail: "records keep failing authentication".into(),
                    });
                    return;
                }
                report(WorkerEvent::AttemptEnded { progressed });
            }
            Outcome::AllStored => {
                if let Err(e) = sync(&mut file).await {
                    fail_storage(&job, &report, e).await;
                    return;
                }
                drop(file);
                // PNP-010-MUST-022: the hash of everything stored, in constant time.
                if receiver.finish().is_err() {
                    let _ = tokio::fs::remove_file(&job.part).await;
                    report(WorkerEvent::Failed {
                        reason: CancelReason::Integrity,
                        detail: "the received file does not match the offer's hash".into(),
                    });
                    return;
                }
                match place(&job).await {
                    Ok(path) => report(WorkerEvent::Received { path }),
                    Err(e) => fail_storage(&job, &report, e).await,
                }
                return;
            }
            Outcome::Stop { discard } => {
                drop(file);
                if discard {
                    let _ = tokio::fs::remove_file(&job.part).await;
                }
                return;
            }
            Outcome::Shutdown => {
                let _ = sync(&mut file).await;
                return;
            }
            Outcome::Superseded(newer) => waiting = Some(newer),
            Outcome::Fatal(reason, detail) => {
                drop(file);
                let _ = tokio::fs::remove_file(&job.part).await;
                report(WorkerEvent::Failed { reason, detail });
                return;
            }
        }
    }
}

async fn fail_storage(job: &ReceiveJob, report: &Report, e: std::io::Error) {
    let _ = tokio::fs::remove_file(&job.part).await;
    report(WorkerEvent::Failed {
        reason: CancelReason::Storage,
        detail: format!("the file cannot be stored: {e}"),
    });
}

async fn sync(file: &mut tokio::fs::File) -> std::io::Result<()> {
    file.flush().await?;
    file.sync_data().await
}

/// Open (or create) the part file, cut it back to whole records the store vouches for, and
/// read that part back into the hash (PNP-010-MUST-025).
async fn open_part(job: &ReceiveJob) -> Result<(Receiver, tokio::fs::File), String> {
    let err = |e: std::io::Error| format!("the part file cannot be used: {e}");
    tokio::fs::create_dir_all(&job.downloads)
        .await
        .map_err(err)?;
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&job.part).await.map_err(err)?;
    let len = file.metadata().await.map_err(err)?.len();
    // Never more than the store recorded as durable, never more than is there.
    let on_disk = (len / CHUNK_SIZE as u64).min(u64::from(u32::MAX)) as u32;
    let complete_on_disk = len >= job.offer.size;
    let next = if complete_on_disk {
        job.next
    } else {
        job.next.min(on_disk)
    };
    let mut receiver = Receiver::resume_at(&job.offer, next).map_err(|e| e.to_string())?;
    let keep = receiver.stored_bytes();
    file.set_len(keep).await.map_err(err)?;
    file.seek(SeekFrom::Start(0)).await.map_err(err)?;
    let mut buf = vec![0u8; 1 << 20];
    let mut left = keep;
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        file.read_exact(&mut buf[..want]).await.map_err(err)?;
        receiver
            .absorb_stored(&buf[..want])
            .map_err(|e| e.to_string())?;
        left -= want as u64;
    }
    buf.zeroize();
    Ok((receiver, file))
}

async fn receive_attempt(
    receiver: &mut Receiver,
    file: &mut tokio::fs::File,
    mut ch: Attachment,
    ctl: &mut mpsc::UnboundedReceiver<WorkerCmd>,
    report: &Report,
) -> Outcome {
    let Ok(resume) = receiver.begin(parolnet_transfer::random_bytes()) else {
        return Outcome::Ended { progressed: false };
    };
    if ch.data.send(ch.dc, resume).await.is_err() {
        return Outcome::Ended { progressed: false };
    }
    let mut progressed = false;
    let mut last_report = Instant::now();
    let mut last_checkpoint = Instant::now();
    let mut since_checkpoint = 0u64;
    loop {
        let event = tokio::select! {
            ev = ch.rx.recv() => ev,
            cmd = ctl.recv() => return stop_or_shutdown(cmd),
        };
        let message = match event {
            Some(ChannelEvent::Message(m)) => m,
            Some(ChannelEvent::BufferedLow) => continue,
            None => return Outcome::Ended { progressed },
        };
        let (mut data, last) = match receiver.on_message(&message) {
            Ok(Received::Started) => continue,
            Ok(Received::Chunk { data, last, .. }) => (data, last),
            // A record that does not verify, or anything out of place: nothing of it is
            // stored and the attempt is over (PNP-010-MUST-013, -019, -020).
            Err(_) => return Outcome::Ended { progressed },
        };
        // Records arrive in order and the file is only ever appended to.
        let written = file.write_all(&data).await;
        data.zeroize();
        if let Err(e) = written {
            return Outcome::Fatal(
                CancelReason::Storage,
                format!("the file cannot be stored: {e}"),
            );
        }
        progressed = true;
        since_checkpoint += CHUNK_SIZE as u64;
        if last {
            return Outcome::AllStored;
        }
        if since_checkpoint >= CHECKPOINT_BYTES || last_checkpoint.elapsed() >= CHECKPOINT_EVERY {
            // PNP-010-SHOULD-002: durable first, then counted.
            if let Err(e) = sync(file).await {
                return Outcome::Fatal(
                    CancelReason::Storage,
                    format!("the file cannot be stored: {e}"),
                );
            }
            since_checkpoint = 0;
            last_checkpoint = Instant::now();
            last_report = last_checkpoint;
            report(WorkerEvent::Progress {
                bytes: receiver.stored_bytes(),
                checkpoint: Some(receiver.next_record()),
            });
        } else if last_report.elapsed() >= PROGRESS_EVERY {
            last_report = Instant::now();
            report(WorkerEvent::Progress {
                bytes: receiver.stored_bytes(),
                checkpoint: None,
            });
        }
    }
}

/// Move the verified part file to its name in the downloads directory, never replacing a
/// file that is there (PNP-010-MUST-034).
async fn place(job: &ReceiveJob) -> std::io::Result<PathBuf> {
    let name = sanitize_file_name(&job.offer.name);
    for n in 0..10_000 {
        let candidate = job.downloads.join(numbered_file_name(&name, n));
        // Reserve the name; only a name nobody has is taken.
        let reserved = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
            .await;
        match reserved {
            Ok(_) => {
                tokio::fs::rename(&job.part, &candidate).await?;
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("no free file name"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored() -> StoredTransfer {
        StoredTransfer {
            id: "00112233445566778899aabbccddeeff".into(),
            peer_id: "p".into(),
            outgoing: false,
            phase: StoredPhase::Accepted,
            name: "../../evil\u{202e}gpj.exe".into(),
            size: 100,
            mime: "image/jpeg".into(),
            sha256: "11".repeat(32),
            key: Some("22".repeat(32)),
            path: None,
            mtime_ms: None,
            next: 0,
            pending: Some(PendingControl::Accept),
            cancelled: None,
            created_ms: 1,
            updated_ms: 1,
        }
    }

    #[test]
    fn a_stored_transfer_gives_back_its_offer_and_hides_its_key() {
        let t = stored();
        let offer = t.offer().unwrap();
        assert_eq!(offer.key, FileKey::from_bytes([0x22; 32]));
        assert_eq!(offer.sha256, [0x11; 32]);
        assert_eq!(offer.id.to_string(), t.id);
        assert!(!format!("{t:?}").contains("2222"));
        // The name shown and used is never the offered path.
        let info = t.info(true, 50);
        assert_eq!(info.name, "evilgpj.exe");
        assert_eq!(info.state, TransferState::Active);
        assert!(info.pending);
        assert_eq!(t.info(false, 500).bytes_done, 100);
        assert_eq!(t.info(false, 0).state, TransferState::Waiting);
    }

    #[test]
    fn a_finished_transfer_has_no_key() {
        let mut t = stored();
        t.cancelled = Some((true, 2));
        t.finish(StoredPhase::Cancelled);
        assert!(t.key.is_none());
        assert!(t.offer().is_none());
        assert_eq!(
            t.info(false, 0).state,
            TransferState::Cancelled {
                by_peer: true,
                reason: CancelReason::Integrity
            }
        );
        assert!(t.info(false, 0).state.is_over());
    }

    #[test]
    fn stored_transfers_survive_serialization() {
        let t = stored();
        let mut bytes = Vec::new();
        ciborium::into_writer(&t, &mut bytes).unwrap();
        let back: StoredTransfer = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.offer(), t.offer());
        assert_eq!(back.pending, t.pending);
        assert_eq!(back.phase, t.phase);
    }

    #[test]
    fn hashing_reads_the_file_in_pieces() {
        let dir = std::env::temp_dir().join(format!("pn-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("three-megabytes.bin");
        let data: Vec<u8> = (0..3_000_001u32).map(|i| (i % 253) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let hashed = hash_file(&path).unwrap();
        let mut h = FileHasher::new();
        h.update(&data);
        assert_eq!(hashed.sha256, h.finalize());
        assert_eq!(hashed.size, data.len() as u64);
        assert_eq!(hashed.name, "three-megabytes.bin");
        assert!(hash_file(&dir).is_err());
        assert!(hash_file(&dir.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
