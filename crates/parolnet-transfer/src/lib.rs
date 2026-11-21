//! # parolnet-transfer
//!
//! File transfer between two ParolNet peers (PNP-010), as a sans-I/O library: no sockets, no
//! files, no clock, no async runtime. The native client core (`parolnet-app`) and the web
//! client (through `parolnet-wasm`) drive the same state machines.
//!
//! - [`Control`]: the `FILE_TRANSFER` messages (`msg_type` 0x15) that travel inside the
//!   end-to-end encrypted session: the [`Offer`] (id, name, size, MIME type, SHA-256 of the
//!   plaintext and a fresh 256-bit [`FileKey`]), accept, decline, cancel and complete.
//! - [`Frame`]: what flows on the transfer's own data channel `pn-file/<id>`: RESUME (the
//!   receiver names the next record it needs), START (the sender's salt for this attempt)
//!   and the sealed records.
//! - [`Sender`] and [`Receiver`]: the two ends. Records are sealed with ChaCha20-Poly1305 in
//!   the STREAM construction under a key derived for each attempt, so a record that is
//!   altered, reordered, replayed from another attempt, or a stream that is cut short,
//!   fails at that record. The receiver's last step compares the SHA-256 of everything it
//!   stored with the offer's, in constant time.
//! - [`sanitize_file_name`], [`OfferLimiter`] and the constants of PNP-010 §8.
//!
//! Key material ([`FileKey`], the per-attempt record keys) is wiped on drop and never shown
//! by `Debug`. All cryptography is pure Rust.

mod control;
mod frame;
mod limits;
mod name;
mod policy;
mod receiver;
mod sender;
mod stream;

pub use control::{CancelReason, Control, FileKey, Offer, TransferId};
pub use frame::Frame;
pub use limits::OfferLimiter;
pub use name::sanitize_file_name;
pub use policy::{
    ChannelAdmission, Phase, Role, Transition, admit_channel, admit_offer, numbered_file_name,
    on_control,
};
pub use receiver::{Received, Receiver};
pub use sender::Sender;
pub use stream::{FileHasher, record_count, record_len};

/// PNP-001 §3.4 message type of every [`Control`] message.
pub const MSG_TYPE_FILE_TRANSFER: u8 = 0x15;
/// Version of the [`Control`] messages this crate writes and accepts.
pub const CONTROL_VERSION: u64 = 1;
/// Data-channel labels under this prefix are reserved for ParolNet (PNP-010 §5.1).
pub const RESERVED_LABEL_PREFIX: &str = "pn-";
/// A transfer's data channel is `pn-file/<32 lower-case hex digits of its id>`.
pub const CHANNEL_LABEL_PREFIX: &str = "pn-file/";
/// The largest message on a transfer channel: 64 KiB, what every WebRTC stack accepts.
pub const MESSAGE_MAX: usize = 65_536;
/// Poly1305 tag length.
pub const TAG_SIZE: usize = 16;
/// Plaintext bytes of every record but the last: a RECORD frame is then exactly 64 KiB.
pub const CHUNK_SIZE: usize = MESSAGE_MAX - 1 - TAG_SIZE;
/// The largest file the protocol carries (1 TiB).
pub const MAX_FILE_SIZE: u64 = 1 << 40;
/// The largest offer a client accepts unless its user set another limit (4 GiB).
pub const DEFAULT_MAX_ACCEPT_SIZE: u64 = 4 << 30;
/// Longest file name in an offer, in UTF-8 bytes.
pub const NAME_MAX: usize = 255;
/// Longest MIME type in an offer, in bytes.
pub const MIME_MAX: usize = 127;
/// Largest encoded [`Control`] body.
pub const CONTROL_MAX: usize = 1024;
/// Transfer channels open at once on one connection, per direction.
pub const MAX_CONCURRENT_PER_CONNECTION: usize = 4;
/// Offers from one contact that may wait for the user's answer.
pub const MAX_PENDING_OFFERS_PER_PEER: usize = 16;
/// Offers accepted from one contact in a burst; one more every [`OFFER_REFILL_MS`].
pub const OFFER_BURST: u32 = 10;
pub const OFFER_REFILL_MS: u64 = 6_000;
/// The sender pauses above this many buffered bytes on the channel …
pub const BUFFER_HIGH: usize = 4 << 20;
/// … and continues at or below this many.
pub const BUFFER_LOW: usize = 1 << 20;
/// The sender never lets more than this many bytes sit in the channel's buffer.
pub const BUFFER_MAX: usize = 16 << 20;
/// Attempts in a row that end on a record that does not verify before the receiver gives
/// the transfer up.
pub const MAX_RECORD_FAILURES: u32 = 3;
/// Unfinished transfers are dropped after this long without progress (30 days).
pub const TRANSFER_MAX_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// What can go wrong. No variant carries key material or file contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransferError {
    /// A control message that is not a well-formed PNP-010 message.
    #[error("malformed file-transfer message: {0}")]
    Control(&'static str),
    /// An offer whose fields are outside the protocol's limits.
    #[error("invalid offer: {0}")]
    Offer(&'static str),
    /// A channel message that is not a RESUME, START or RECORD frame.
    #[error("malformed channel frame")]
    Frame,
    /// A well-formed frame that this end must not receive now.
    #[error("unexpected channel frame")]
    Unexpected,
    /// A record that does not authenticate at its position, or has the wrong length.
    #[error("a record failed authentication")]
    Record,
    /// The chunk handed to the sender is not the one the stream needs next.
    #[error("the chunk does not match the stream position")]
    Chunk,
    /// The received file's SHA-256 is not the one in the offer.
    #[error("the received file does not match the offer's hash")]
    HashMismatch,
    /// The stored prefix handed back after a restart does not match the record count.
    #[error("the stored part does not match the resume position")]
    Prefix,
}

/// Cryptographically strong random bytes from the operating system (salts, nonces, ids).
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand_core::RngCore as _;
    let mut out = [0u8; N];
    rand_core::OsRng.fill_bytes(&mut out);
    out
}
