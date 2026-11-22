//! Frames on a transfer's data channel (PNP-010 §5.2): binary messages whose first byte is
//! the frame type.

use crate::{MESSAGE_MAX, TAG_SIZE, TransferError};

const RESUME: u8 = 0x01;
const START: u8 = 0x02;
const RECORD: u8 = 0x03;
/// A RESUME or START frame: type, record index, 16 random bytes.
const HANDSHAKE_LEN: usize = 1 + 4 + 16;

/// One message on a `pn-file/<id>` channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// Receiver → sender, first on every channel: the next record the receiver needs and
    /// its nonce for this attempt.
    Resume { next: u32, nonce: [u8; 16] },
    /// Sender → receiver: the record the stream starts at (the receiver's `next`) and the
    /// sender's salt for this attempt.
    Start { next: u32, salt: [u8; 16] },
    /// Sender → receiver: one sealed record, ciphertext followed by the tag.
    Record(&'a [u8]),
}

impl<'a> Frame<'a> {
    /// Parse a channel message. Anything that is not exactly one well-formed frame is an
    /// error: unknown type, wrong length, a message above 64 KiB.
    pub fn parse(message: &'a [u8]) -> Result<Frame<'a>, TransferError> {
        let (&kind, body) = message.split_first().ok_or(TransferError::Frame)?;
        if message.len() > MESSAGE_MAX {
            return Err(TransferError::Frame);
        }
        match kind {
            RESUME | START if message.len() == HANDSHAKE_LEN => {
                let (index, random) = body.split_at(4);
                let next = u32::from_be_bytes(index.try_into().map_err(|_| TransferError::Frame)?);
                let random: [u8; 16] = random.try_into().map_err(|_| TransferError::Frame)?;
                Ok(if kind == RESUME {
                    Frame::Resume {
                        next,
                        nonce: random,
                    }
                } else {
                    Frame::Start { next, salt: random }
                })
            }
            RECORD if body.len() >= TAG_SIZE => Ok(Frame::Record(body)),
            _ => Err(TransferError::Frame),
        }
    }

    /// The channel message for this frame.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Frame::Resume { next, nonce } => handshake(RESUME, *next, nonce),
            Frame::Start { next, salt } => handshake(START, *next, salt),
            Frame::Record(sealed) => {
                let mut out = Vec::with_capacity(1 + sealed.len());
                out.push(RECORD);
                out.extend_from_slice(sealed);
                out
            }
        }
    }
}

fn handshake(kind: u8, next: u32, random: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HANDSHAKE_LEN);
    out.push(kind);
    out.extend_from_slice(&next.to_be_bytes());
    out.extend_from_slice(random);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let resume = Frame::Resume {
            next: 0x0102_0304,
            nonce: [5; 16],
        };
        let bytes = resume.encode();
        assert_eq!(bytes.len(), 21);
        assert_eq!(&bytes[..5], &[1, 1, 2, 3, 4]);
        assert_eq!(Frame::parse(&bytes).unwrap(), resume);

        let start = Frame::Start {
            next: 7,
            salt: [6; 16],
        };
        assert_eq!(Frame::parse(&start.encode()).unwrap(), start);

        let sealed = [9u8; 40];
        let record = Frame::Record(&sealed);
        assert_eq!(Frame::parse(&record.encode()).unwrap(), record);
    }

    #[test]
    fn malformed_frames_are_refused() {
        assert_eq!(Frame::parse(&[]), Err(TransferError::Frame));
        assert_eq!(Frame::parse(&[0x00; 21]), Err(TransferError::Frame));
        assert_eq!(Frame::parse(&[0x04; 21]), Err(TransferError::Frame));
        assert_eq!(Frame::parse(&[0x01; 20]), Err(TransferError::Frame));
        assert_eq!(Frame::parse(&[0x02; 22]), Err(TransferError::Frame));
        // A record shorter than its tag.
        assert_eq!(Frame::parse(&[0x03; 16]), Err(TransferError::Frame));
        assert!(Frame::parse(&[0x03; 17]).is_ok());
        assert!(Frame::parse(&vec![0x03; MESSAGE_MAX]).is_ok());
        assert_eq!(
            Frame::parse(&vec![0x03; MESSAGE_MAX + 1]),
            Err(TransferError::Frame)
        );
    }
}
