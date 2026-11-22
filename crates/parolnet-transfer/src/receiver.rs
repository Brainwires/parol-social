//! The receiving end of a transfer (PNP-010 §6.4, §7).

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::stream::{AttemptCipher, record_count, record_len};
use crate::{CHUNK_SIZE, FileKey, Frame, Offer, TransferError, TransferId};

/// What a channel message meant to the receiver.
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    /// The sender's START: records follow.
    Started,
    /// The next record's plaintext, to be stored at `offset`. After the one with `last`
    /// set, store it and call [`Receiver::finish`].
    Chunk {
        offset: u64,
        data: Vec<u8>,
        last: bool,
    },
}

/// The receiver of one file, across every attempt and (with [`Receiver::resume_at`]) across
/// restarts. It does no I/O: the caller stores the chunks and writes to the channel.
///
/// For each attempt: open the channel, send [`Receiver::begin`]'s RESUME frame, feed every
/// message to [`Receiver::on_message`]. An error means: discard that message, close the
/// channel, and (while [`Receiver::record_failures`] allows) try again on a new one.
pub struct Receiver {
    id: TransferId,
    size: u64,
    key: FileKey,
    sha256: [u8; 32],
    /// The next record needed.
    next: u32,
    /// SHA-256 over the plaintext of records `0..next`.
    hasher: Sha256,
    hashed: u64,
    attempt: Option<Attempt>,
    failures: u32,
}

enum Attempt {
    /// RESUME sent with this nonce; START not seen yet.
    Waiting {
        nonce: [u8; 16],
    },
    Running(AttemptCipher),
}

impl Receiver {
    /// A transfer that has stored nothing yet.
    pub fn new(offer: &Offer) -> Receiver {
        Receiver {
            id: offer.id,
            size: offer.size,
            key: offer.key.clone(),
            sha256: offer.sha256,
            next: 0,
            hasher: Sha256::new(),
            hashed: 0,
            attempt: None,
            failures: 0,
        }
    }

    /// A transfer picked up after a restart, with records `0..next` in durable storage.
    /// Feed those stored bytes, in order, to [`Receiver::absorb_stored`] before
    /// [`Receiver::begin`] (or, when every record is there, [`Receiver::finish`]): the final
    /// hash covers them.
    pub fn resume_at(offer: &Offer, next: u32) -> Result<Receiver, TransferError> {
        if next > record_count(offer.size) {
            return Err(TransferError::Prefix);
        }
        let mut receiver = Receiver::new(offer);
        receiver.next = next;
        Ok(receiver)
    }

    /// Plaintext already stored (see [`Receiver::resume_at`]).
    pub fn absorb_stored(&mut self, bytes: &[u8]) -> Result<(), TransferError> {
        let total = self.hashed + bytes.len() as u64;
        if total > self.stored_bytes() {
            return Err(TransferError::Prefix);
        }
        self.hasher.update(bytes);
        self.hashed = total;
        Ok(())
    }

    /// The next record this end needs: what RESUME says.
    pub fn next_record(&self) -> u32 {
        self.next
    }

    /// Plaintext bytes of the records received so far.
    pub fn stored_bytes(&self) -> u64 {
        (u64::from(self.next) * CHUNK_SIZE as u64).min(self.size)
    }

    /// Every record has arrived (the hash may still be unchecked: [`Receiver::finish`]).
    pub fn is_complete(&self) -> bool {
        self.next == record_count(self.size)
    }

    /// Attempts in a row that ended on a record that did not verify. At
    /// [`crate::MAX_RECORD_FAILURES`] the transfer is given up (cancel, reason integrity).
    pub fn record_failures(&self) -> u32 {
        self.failures
    }

    /// Start an attempt on a newly opened channel with a `nonce` of 16 fresh random bytes.
    /// Returns the RESUME frame to send first. Any earlier attempt is over.
    pub fn begin(&mut self, nonce: [u8; 16]) -> Result<Vec<u8>, TransferError> {
        self.attempt = None;
        if self.is_complete() {
            return Err(TransferError::Unexpected);
        }
        if self.hashed != self.stored_bytes() {
            return Err(TransferError::Prefix);
        }
        self.attempt = Some(Attempt::Waiting { nonce });
        Ok(Frame::Resume {
            next: self.next,
            nonce,
        }
        .encode())
    }

    /// Handle one channel message of the running attempt.
    pub fn on_message(&mut self, message: &[u8]) -> Result<Received, TransferError> {
        let result = self.handle(message);
        if result.is_err() {
            self.attempt = None;
        }
        result
    }

    fn handle(&mut self, message: &[u8]) -> Result<Received, TransferError> {
        let frame = Frame::parse(message)?;
        match (self.attempt.as_ref(), frame) {
            (Some(Attempt::Waiting { nonce }), Frame::Start { next, salt }) => {
                if next != self.next {
                    return Err(TransferError::Unexpected);
                }
                let cipher = AttemptCipher::derive(&self.key, &self.id, next, &salt, nonce);
                self.attempt = Some(Attempt::Running(cipher));
                Ok(Received::Started)
            }
            (Some(Attempt::Running(cipher)), Frame::Record(sealed)) => {
                let count = record_count(self.size);
                let Some(expected) = record_len(self.size, self.next) else {
                    // A record after the last one.
                    return Err(TransferError::Unexpected);
                };
                let last = self.next + 1 == count;
                let opened = cipher.open(self.next, last, sealed).and_then(|data| {
                    if data.len() == expected {
                        Ok(data)
                    } else {
                        Err(TransferError::Record)
                    }
                });
                let data = match opened {
                    Ok(data) => data,
                    Err(e) => {
                        self.failures += 1;
                        return Err(e);
                    }
                };
                self.failures = 0;
                let offset = u64::from(self.next) * CHUNK_SIZE as u64;
                self.hasher.update(&data);
                self.hashed += data.len() as u64;
                self.next += 1;
                Ok(Received::Chunk { offset, data, last })
            }
            _ => Err(TransferError::Unexpected),
        }
    }

    /// The channel closed: forget the attempt (and its key).
    pub fn end_attempt(&mut self) {
        self.attempt = None;
    }

    /// The final check, once every record is stored: the SHA-256 of the whole plaintext
    /// against the offer's, in constant time. On [`TransferError::HashMismatch`] the stored
    /// data must be deleted and never shown to the user as the file.
    pub fn finish(&self) -> Result<(), TransferError> {
        if !self.is_complete() || self.hashed != self.size {
            return Err(TransferError::Unexpected);
        }
        let digest: [u8; 32] = self.hasher.clone().finalize().into();
        if bool::from(digest.ct_eq(&self.sha256)) {
            Ok(())
        } else {
            Err(TransferError::HashMismatch)
        }
    }
}
