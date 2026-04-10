//! Double Ratchet protocol implementation.
//!
//! Provides forward secrecy and future secrecy for ongoing message encryption.
//! Initialized from the shared secret produced by X3DH (PNP-002).
//!
//! Each message uses a unique key derived through the ratchet chain.

use crate::{CryptoError, RatchetHeader, RatchetSession, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// State for an active Double Ratchet session.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DoubleRatchetSession {
    /// Root key — ratcheted on each DH ratchet step.
    root_key: [u8; 32],
    /// Current sending chain key.
    send_chain_key: [u8; 32],
    /// Current receiving chain key.
    recv_chain_key: [u8; 32],
    /// Message number in current sending chain.
    send_message_number: u32,
    /// Message number in current receiving chain.
    recv_message_number: u32,
    /// Number of messages in previous sending chain.
    previous_chain_length: u32,
    // TODO: DH ratchet keypairs, skipped message keys cache
}

impl DoubleRatchetSession {
    /// Initialize a new Double Ratchet session from X3DH shared secret.
    ///
    /// - `shared_secret`: The SK from X3DH key agreement.
    /// - `remote_ratchet_key`: The initial ratchet public key from the responder.
    /// - `is_initiator`: Whether this peer initiated the X3DH handshake.
    pub fn initialize(
        _shared_secret: SharedSecret,
        _remote_ratchet_key: &[u8; 32],
        _is_initiator: bool,
    ) -> Result<Self, CryptoError> {
        todo!("Double Ratchet initialization from X3DH SK")
    }
}

impl RatchetSession for DoubleRatchetSession {
    fn encrypt(
        &mut self,
        _plaintext: &[u8],
    ) -> Result<(RatchetHeader, Vec<u8>), CryptoError> {
        todo!("Double Ratchet encrypt")
    }

    fn decrypt(
        &mut self,
        _header: &RatchetHeader,
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        todo!("Double Ratchet decrypt")
    }
}
