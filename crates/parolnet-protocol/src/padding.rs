//! Message padding to fixed bucket sizes (PNP-001 Section 3.6).
//!
//! All messages are padded to one of: 256, 1024, 4096, or 16384 bytes.
//! This prevents an observer from distinguishing message types by length.

use crate::{PaddingStrategy, ProtocolError, BUCKET_SIZES};

/// Standard bucket-based padding strategy.
///
/// Pads messages to the smallest bucket size that fits, using
/// cryptographically random padding bytes.
pub struct BucketPadding;

impl PaddingStrategy for BucketPadding {
    fn pad(&self, _plaintext: &[u8]) -> Vec<u8> {
        todo!("Bucket padding implementation")
    }

    fn unpad(&self, _padded: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        todo!("Bucket unpadding implementation")
    }
}

/// Select the smallest bucket size that can contain the given data length.
pub fn select_bucket(data_len: usize) -> Option<usize> {
    BUCKET_SIZES.iter().copied().find(|&size| size >= data_len)
}
