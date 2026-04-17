//! CBOR codec for wire protocol types (PNP-001 Section 3.8).
//!
//! Rules:
//! - All CBOR encoding MUST use definite-length encoding
//! - Map keys MUST be text strings in lexicographic order
//! - Implementations MUST reject duplicate map keys
//! - Implementations MUST ignore unknown map keys (forward compatibility)

use crate::envelope::{CleartextHeader, Envelope};
use crate::{ProtocolCodec, ProtocolError};
use std::collections::{HashSet, VecDeque};

/// Replay cache to prevent nonce reuse / replay attacks.
///
/// Stores up to `capacity` nonces, evicting the oldest when full.
pub struct ReplayCache {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl ReplayCache {
    /// Create a new replay cache with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Check if a nonce has been seen before. If not, insert it and return `true`.
    /// Returns `false` if the nonce was already in the cache (replay detected).
    pub fn check_and_insert(&mut self, nonce: &[u8; 32]) -> bool {
        if self.seen.contains(nonce) {
            return false;
        }

        // Evict oldest entries when at capacity
        while self.seen.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }

        self.seen.insert(*nonce);
        self.order.push_back(*nonce);
        true
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new(10_000)
    }
}

/// Standard CBOR codec using ciborium.
pub struct CborCodec;

/// Serialize a cleartext header to CBOR bytes (PNP-001 §3.2, MUST-002).
///
/// These bytes are also used as AEAD additional-authenticated-data by the
/// envelope helpers to bind the cleartext header into the session AEAD tag
/// (PNP-001-MUST-007).
pub fn encode_header(header: &CleartextHeader) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = Vec::new();
    ciborium::into_writer(header, &mut buf)
        .map_err(|e| ProtocolError::CborEncode(e.to_string()))?;
    Ok(buf)
}

/// Maximum header size in bytes (prevents DoS via oversized CBOR headers).
const MAX_HEADER_SIZE: usize = 512;

/// Deserialize a cleartext header from CBOR bytes.
pub fn decode_header(bytes: &[u8]) -> Result<CleartextHeader, ProtocolError> {
    if bytes.len() > MAX_HEADER_SIZE {
        return Err(ProtocolError::CborDecode(format!(
            "header too large: {} bytes exceeds maximum {}",
            bytes.len(),
            MAX_HEADER_SIZE
        )));
    }

    let header: CleartextHeader =
        ciborium::from_reader(bytes).map_err(|e| ProtocolError::CborDecode(e.to_string()))?;

    if header.version != 1 {
        return Err(ProtocolError::InvalidVersion {
            expected: 1,
            got: header.version,
        });
    }

    Ok(header)
}

impl ProtocolCodec for CborCodec {
    /// Serialize an `Envelope` to its CBOR byte sequence.
    ///
    /// The caller is responsible for sizing `envelope.padding` such that the
    /// resulting CBOR bytes land on a bucket boundary — see the envelope
    /// helpers in `parolnet-core` for the iterative sizing procedure.
    fn encode(&self, envelope: &Envelope) -> Result<Vec<u8>, ProtocolError> {
        let mut buf = Vec::new();
        ciborium::into_writer(envelope, &mut buf)
            .map_err(|e| ProtocolError::CborEncode(e.to_string()))?;
        Ok(buf)
    }

    /// Deserialize an `Envelope` from on-wire bytes.
    ///
    /// Per PNP-001-MUST-036, the wire-level bucket check MUST be applied to
    /// the raw frame before calling this method. `decode` accepts any
    /// CBOR-valid envelope bytes; bucket validation is the caller's concern.
    fn decode(&self, bytes: &[u8]) -> Result<Envelope, ProtocolError> {
        ciborium::from_reader::<Envelope, _>(bytes)
            .map_err(|e| ProtocolError::CborDecode(e.to_string()))
    }
}

/// Compute the CBOR-encoded size of an Envelope without materializing the
/// bytes when possible. Always returns the exact encoded length.
pub fn encoded_envelope_len(envelope: &Envelope) -> Result<usize, ProtocolError> {
    let mut buf = Vec::new();
    ciborium::into_writer(envelope, &mut buf)
        .map_err(|e| ProtocolError::CborEncode(e.to_string()))?;
    Ok(buf.len())
}
