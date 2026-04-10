//! Onion routing: layer encryption/decryption (PNP-004 Section 5.2).

use crate::RelayError;

/// Encrypt a payload with multiple onion layers (OP side).
///
/// For a 3-hop circuit, encrypts 3 times:
/// first with hop 3's key, then hop 2's, then hop 1's.
pub fn onion_encrypt(
    _payload: &[u8],
    _hop_keys: &[[u8; 32]],
    _hop_nonces: &[[u8; 12]],
) -> Result<Vec<u8>, RelayError> {
    todo!("Onion layer encryption")
}

/// Peel one onion layer (relay side).
pub fn onion_peel(
    _encrypted: &[u8],
    _key: &[u8; 32],
    _nonce: &[u8; 12],
) -> Result<Vec<u8>, RelayError> {
    todo!("Onion layer peeling")
}
