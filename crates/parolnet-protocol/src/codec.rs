//! CBOR codec for wire protocol types (PNP-001 Section 3.8).
//!
//! Rules:
//! - All CBOR encoding MUST use definite-length encoding
//! - Map keys MUST be text strings in lexicographic order
//! - Implementations MUST reject duplicate map keys
//! - Implementations MUST ignore unknown map keys (forward compatibility)

use crate::{ProtocolCodec, ProtocolError, envelope::Envelope};

/// Standard CBOR codec using ciborium.
pub struct CborCodec;

impl ProtocolCodec for CborCodec {
    fn encode(&self, _envelope: &Envelope) -> Result<Vec<u8>, ProtocolError> {
        todo!("CBOR envelope encoding")
    }

    fn decode(&self, _bytes: &[u8]) -> Result<Envelope, ProtocolError> {
        todo!("CBOR envelope decoding")
    }
}
