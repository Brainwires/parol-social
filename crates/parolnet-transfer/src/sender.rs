//! The sending end of a transfer (PNP-010 §6.3).

use crate::stream::{AttemptCipher, record_count, record_len};
use crate::{CHUNK_SIZE, FileKey, Frame, TAG_SIZE, TransferError, TransferId};

/// The sender of one file, across every attempt. It does no I/O: the caller reads the file
/// and writes to the channel.
///
/// For each channel the receiver opens: feed its first message to [`Sender::begin`], send
/// the START frame it returns, then until [`Sender::next_chunk`] gives `None` read that
/// chunk from the file and send what [`Sender::seal`] makes of it.
pub struct Sender {
    id: TransferId,
    size: u64,
    key: FileKey,
    attempt: Option<Attempt>,
}

struct Attempt {
    cipher: AttemptCipher,
    next: u32,
}

impl Sender {
    pub fn new(id: TransferId, size: u64, key: FileKey) -> Sender {
        Sender {
            id,
            size,
            key,
            attempt: None,
        }
    }

    /// Start an attempt from the receiver's RESUME frame, with a `salt` of 16 fresh random
    /// bytes ([`crate::random_bytes`]). Returns the START frame to send. Any earlier
    /// attempt is over. An error (not a RESUME frame, or a record the file does not have)
    /// means: close the channel.
    pub fn begin(&mut self, message: &[u8], salt: [u8; 16]) -> Result<Vec<u8>, TransferError> {
        self.attempt = None;
        let Frame::Resume { next, nonce } = Frame::parse(message)? else {
            return Err(TransferError::Unexpected);
        };
        if next >= record_count(self.size) {
            return Err(TransferError::Unexpected);
        }
        self.attempt = Some(Attempt {
            cipher: AttemptCipher::derive(&self.key, &self.id, next, &salt, &nonce),
            next,
        });
        Ok(Frame::Start { next, salt }.encode())
    }

    /// The part of the file the stream needs next, as `(offset, length)`; `None` when no
    /// attempt is running or its last record has been sealed.
    pub fn next_chunk(&self) -> Option<(u64, usize)> {
        let next = self.attempt.as_ref()?.next;
        let len = record_len(self.size, next)?;
        Some((u64::from(next) * CHUNK_SIZE as u64, len))
    }

    /// Seal the chunk [`Sender::next_chunk`] asked for into a RECORD frame.
    pub fn seal(&mut self, chunk: &[u8]) -> Result<Vec<u8>, TransferError> {
        let attempt = self.attempt.as_mut().ok_or(TransferError::Unexpected)?;
        let len = record_len(self.size, attempt.next).ok_or(TransferError::Unexpected)?;
        if chunk.len() != len {
            return Err(TransferError::Chunk);
        }
        let last = attempt.next + 1 == record_count(self.size);
        let mut out = Vec::with_capacity(1 + len + TAG_SIZE);
        out.push(0x03);
        attempt.cipher.seal(attempt.next, last, chunk, &mut out);
        attempt.next += 1;
        Ok(out)
    }

    /// Every record of the running attempt has been sealed.
    pub fn is_finished(&self) -> bool {
        self.attempt
            .as_ref()
            .is_some_and(|a| a.next == record_count(self.size))
    }

    /// Plaintext bytes sealed up to now in the running attempt (for progress).
    pub fn sent_bytes(&self) -> u64 {
        self.attempt.as_ref().map_or(0, |a| {
            (u64::from(a.next) * CHUNK_SIZE as u64).min(self.size)
        })
    }

    /// The channel closed: forget the attempt (and its key).
    pub fn end_attempt(&mut self) {
        self.attempt = None;
    }
}
